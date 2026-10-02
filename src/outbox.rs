//! Durable, target-bound anchor intents, separate from the audit chain.
use std::path::{Path, PathBuf};

use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

use crate::anchor::{prepare_anchor, publish_prepared, Anchor, AnchorOptions, PreparedAnchor};
use crate::s3::{Client, Provider};
use crate::{Error, Result};

/// An independently durable SQLite store. One source and one target per outbox.
pub struct Outbox {
    conn: Connection,
    source: PathBuf,
}

impl Outbox {
    /// Open a dedicated database. Existing audit/foreign databases are rejected.
    pub fn open(path: &Path, source: &Path) -> Result<Self> {
        let source = std::fs::canonicalize(source).map_err(crate::error::io(source))?;
        if path.exists() {
            let destination = std::fs::canonicalize(path).map_err(crate::error::io(path))?;
            if destination == source || same_file(&destination, &source)? {
                return Err(Error::Invalid(
                    "source audit file cannot be the outbox".into(),
                ));
            }
        }
        let mut conn = Connection::open(path)?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.execute_batch("PRAGMA synchronous=FULL;")?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let foreign: i64 = tx.query_row(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name NOT IN ('outbox_meta','anchor_intents','anchor_outcomes') AND name NOT LIKE 'sqlite_%'",
            [], |r| r.get(0),
        )?;
        if foreign != 0 {
            return Err(Error::Invalid(
                "outbox must be a dedicated database, not an audit or foreign database".into(),
            ));
        }
        tx.execute_batch(
            "CREATE TABLE IF NOT EXISTS outbox_meta (id INTEGER PRIMARY KEY CHECK(id=1), source TEXT NOT NULL, target TEXT);
             CREATE TABLE IF NOT EXISTS anchor_intents (key TEXT PRIMARY KEY, request TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS anchor_outcomes (key TEXT PRIMARY KEY REFERENCES anchor_intents(key), state TEXT NOT NULL CHECK(state IN ('pending','unresolved','rejected','confirmed')));
             CREATE TRIGGER IF NOT EXISTS immutable_intents_update BEFORE UPDATE ON anchor_intents BEGIN SELECT RAISE(ABORT, 'immutable anchor intent'); END;
             CREATE TRIGGER IF NOT EXISTS immutable_intents_delete BEFORE DELETE ON anchor_intents BEGIN SELECT RAISE(ABORT, 'immutable anchor intent'); END;"
        )?;
        let source_name = source
            .to_str()
            .ok_or_else(|| Error::Invalid("source path must be UTF-8".into()))?;
        tx.execute(
            "INSERT OR IGNORE INTO outbox_meta(id,source) VALUES(1,?1)",
            [source_name],
        )?;
        let stored: String =
            tx.query_row("SELECT source FROM outbox_meta WHERE id=1", [], |r| {
                r.get(0)
            })?;
        if stored != source_name {
            return Err(Error::Invalid(
                "outbox belongs to a different source audit file".into(),
            ));
        }
        tx.commit()?;
        let journal: String = conn.query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0))?;
        conn.execute_batch("PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;")?;
        if journal != "wal" {
            return Err(Error::Invalid("outbox requires SQLite WAL mode".into()));
        }
        Ok(Self { conn, source })
    }

    fn bind_target(&mut self, client: &Client) -> Result<()> {
        let identity = client.target_identity();
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "UPDATE outbox_meta SET target=?1 WHERE id=1 AND target IS NULL",
            [&identity],
        )?;
        let stored: String =
            tx.query_row("SELECT target FROM outbox_meta WHERE id=1", [], |r| {
                r.get(0)
            })?;
        if stored != identity {
            return Err(Error::Invalid("outbox target mismatch: use the original endpoint, bucket, region and addressing mode".into()));
        }
        tx.commit()?;
        Ok(())
    }

    /// Retry pending/unresolved requests with their original bytes and expiry.
    /// Credentials are supplied fresh by the caller; target changes are rejected.
    pub fn reconcile(&mut self, client: &Client) -> Result<()> {
        self.bind_target(client)?;
        let requests: Vec<String> = self.conn.prepare(
            "SELECT request FROM anchor_intents JOIN anchor_outcomes USING(key) WHERE state IN ('pending','unresolved') ORDER BY key"
        )?.query_map([], |r| r.get(0))?.collect::<std::result::Result<_, _>>()?;
        for request in requests {
            let prepared = decode(&request)?;
            self.publish(client, &prepared)?;
        }
        Ok(())
    }

    /// Reconcile first, verify the current head, commit its intent, then publish.
    pub fn anchor_head(
        &mut self,
        source: &Path,
        client: &Client,
        options: AnchorOptions,
        provider: Provider,
    ) -> Result<Anchor> {
        if std::fs::canonicalize(source).map_err(crate::error::io(source))? != self.source {
            return Err(Error::Invalid(
                "outbox belongs to a different source".into(),
            ));
        }
        if !options.only_if_absent {
            return Err(Error::Invalid(
                "durable anchors require conditional, write-once uploads".into(),
            ));
        }
        self.reconcile(client)?;
        let prepared = prepare_anchor(source, options, provider)?;
        let prepared = self.store(prepared)?;
        self.publish(client, &prepared)
    }

    fn store(&mut self, prepared: PreparedAnchor) -> Result<PreparedAnchor> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing: Option<String> = tx
            .query_row(
                "SELECT request FROM anchor_intents WHERE key=?1",
                [&prepared.anchor.key],
                |r| r.get(0),
            )
            .optional()?;
        let prepared = if let Some(request) = existing {
            let old = decode(&request)?;
            if old.anchor.chain != prepared.anchor.chain
                || old.anchor.format != prepared.anchor.format
                || old.anchor.seq != prepared.anchor.seq
                || old.anchor.digest != prepared.anchor.digest
                || old.anchor.provider != prepared.anchor.provider
                || old.lock != prepared.lock
                || old.retain_days != prepared.retain_days
            {
                return Err(Error::Invalid(
                    "immutable anchor key conflicts with checkpoint or retention configuration"
                        .into(),
                ));
            }
            old
        } else {
            let request =
                serde_json::to_string(&prepared).map_err(|e| Error::Invalid(e.to_string()))?;
            tx.execute(
                "INSERT INTO anchor_intents(key,request) VALUES(?1,?2)",
                params![prepared.anchor.key, request],
            )?;
            tx.execute(
                "INSERT INTO anchor_outcomes(key,state) VALUES(?1,'pending')",
                [&prepared.anchor.key],
            )?;
            prepared
        };
        tx.commit()?;
        Ok(prepared)
    }

    fn publish(&mut self, client: &Client, prepared: &PreparedAnchor) -> Result<Anchor> {
        let result = publish_prepared(client, prepared, true);
        let state = match &result {
            Ok(_) => "confirmed",
            Err(Error::UploadUncertain { .. } | Error::AnchorUnconfirmed { .. }) => "unresolved",
            Err(_) => "rejected",
        };
        // A failed outcome commit leaves the previous actionable state intact.
        if !matches!(
            self.conn.execute(
                "UPDATE anchor_outcomes SET state=?1 WHERE key=?2",
                params![state, prepared.anchor.key],
            ),
            Ok(1)
        ) {
            return match result {
                Err(error @ Error::UploadUncertain { .. }) => Err(error),
                _ => Err(Error::AnchorUnconfirmed { key: prepared.anchor.key.clone(), detail: "remote attempt completed but durable outcome could not be recorded; reconcile the outbox".into() }),
            };
        }
        result
    }
}

fn decode(request: &str) -> Result<PreparedAnchor> {
    serde_json::from_str(request)
        .map_err(|e| Error::Invalid(format!("invalid durable intent: {e}")))
}

fn same_file(a: &Path, b: &Path) -> Result<bool> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let a = std::fs::metadata(a).map_err(crate::error::io(a))?;
        let b = std::fs::metadata(b).map_err(crate::error::io(b))?;
        Ok(a.dev() == b.dev() && a.ino() == b.ino())
    }
    #[cfg(not(unix))]
    {
        Ok(a == b)
    }
}
