//! Database identity, explicit schema revisions, and transactional legacy adoption.
//! These labels describe compatibility; they are not tamper-evidence or trusted heads.

use crate::{Error, Result};
use rusqlite::{Connection, OpenFlags, OptionalExtension};
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::Path;

pub const AUDIT_APPLICATION_ID: i64 = 0x4e53544f; // NSTO
pub const OUTBOX_APPLICATION_ID: i64 = 0x4e534f42; // NSOB
pub const AUDIT_SCHEMA_REVISION: i64 = 1;
pub const OUTBOX_SCHEMA_REVISION: i64 = 1;

/// Historical outbox layout. Versioning adds metadata without rewriting intents.
pub const OUTBOX_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS outbox_meta (id INTEGER PRIMARY KEY CHECK(id=1), source TEXT NOT NULL, target TEXT);
CREATE TABLE IF NOT EXISTS anchor_intents (key TEXT PRIMARY KEY, request TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS anchor_outcomes (key TEXT PRIMARY KEY REFERENCES anchor_intents(key), state TEXT NOT NULL CHECK(state IN ('pending','unresolved','rejected','confirmed')));
CREATE TRIGGER IF NOT EXISTS immutable_intents_update BEFORE UPDATE ON anchor_intents BEGIN SELECT RAISE(ABORT, 'immutable anchor intent'); END;
CREATE TRIGGER IF NOT EXISTS immutable_intents_delete BEFORE DELETE ON anchor_intents BEGIN SELECT RAISE(ABORT, 'immutable anchor intent'); END;";

const METADATA_SCHEMA: &str = "
CREATE TABLE nostoi_schema_meta (
    id INTEGER PRIMARY KEY CHECK(id=1),
    component TEXT NOT NULL,
    schema_revision INTEGER NOT NULL,
    record_format TEXT NOT NULL,
    created_by_version TEXT NOT NULL,
    last_migrated_by_version TEXT NOT NULL,
    adopted_legacy INTEGER NOT NULL CHECK(adopted_legacy IN (0,1))
) STRICT;";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Component {
    Audit,
    Outbox,
}

impl Component {
    fn name(self) -> &'static str {
        match self {
            Self::Audit => "nostoi-audit-store",
            Self::Outbox => "nostoi-anchor-outbox",
        }
    }
    fn id(self) -> i64 {
        match self {
            Self::Audit => AUDIT_APPLICATION_ID,
            Self::Outbox => OUTBOX_APPLICATION_ID,
        }
    }
    fn revision(self) -> i64 {
        match self {
            Self::Audit => AUDIT_SCHEMA_REVISION,
            Self::Outbox => OUTBOX_SCHEMA_REVISION,
        }
    }
    fn format(self) -> &'static str {
        match self {
            Self::Audit => "nostoi-v1",
            Self::Outbox => "nostoi-prepared-anchor-v1",
        }
    }
    fn ddl(self) -> &'static str {
        match self {
            Self::Audit => crate::sqlite::SCHEMA,
            Self::Outbox => OUTBOX_SCHEMA,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct SchemaInfo {
    pub component: String,
    pub application_id: i64,
    /// Zero denotes an unversioned historical layout; readers do not stamp it.
    pub schema_revision: i64,
    pub supported_revision: i64,
    /// Current write format; adopted outboxes can contain legacy request envelopes.
    pub record_format: String,
    pub created_by_version: Option<String>,
    pub last_migrated_by_version: Option<String>,
    pub legacy_unversioned: bool,
    pub adopted_legacy: bool,
}

type Objects = BTreeMap<String, (String, String)>;
type Column = (String, String, i64, Option<String>, i64, i64);

fn objects(conn: &Connection) -> Result<Objects> {
    let mut stmt = conn.prepare("SELECT name,type,sql FROM sqlite_master WHERE type IN ('table','trigger','view') AND name NOT LIKE 'sqlite_%'")?;
    let rows = stmt.query_map([], |row| Ok((row.get(0)?, (row.get(1)?, row.get(2)?))))?;
    Ok(rows.collect::<std::result::Result<_, _>>()?)
}

fn reference(component: Component) -> Result<(Connection, Objects)> {
    let reference = Connection::open_in_memory()?;
    reference.execute_batch(component.ddl())?;
    let expected = objects(&reference)?;
    Ok((reference, expected))
}

/// Normalize SQL spelling outside quoted literals; preserve literal contents.
fn normalized(sql: &str) -> String {
    let mut quote = None;
    sql.chars()
        .filter_map(|c| {
            if quote == Some(c) {
                quote = None;
                return Some(c);
            }
            if quote.is_none() && matches!(c, '\'' | '"' | '`') {
                quote = Some(c);
                return Some(c);
            }
            if quote.is_some() {
                Some(c)
            } else if c.is_whitespace() || c == ';' {
                None
            } else {
                Some(c.to_ascii_lowercase())
            }
        })
        .collect()
}

fn columns(conn: &Connection, name: &str) -> Result<Vec<Column>> {
    // Names originate only from the constant reference schema, never user input.
    let mut stmt = conn.prepare(&format!("PRAGMA table_xinfo({name})"))?;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get(1)?,
            row.get(2)?,
            row.get(3)?,
            row.get(4)?,
            row.get(5)?,
            row.get(6)?,
        ))
    })?;
    Ok(rows.collect::<std::result::Result<_, _>>()?)
}

/// All persistent writes are deferred until the caller's preflight checks pass.
pub(crate) fn check(conn: &Connection, component: Component, writable: bool) -> Result<SchemaInfo> {
    let id: i64 = conn.query_row("PRAGMA application_id", [], |row| row.get(0))?;
    let revision: i64 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if id != 0 && id != component.id() {
        return Err(Error::Invalid(format!(
            "database application_id {id:#x} does not identify {}",
            component.name()
        )));
    }
    if revision != 0 && revision != component.revision() {
        return Err(Error::UnsupportedSchema {
            component: component.name(),
            found: revision.to_string(),
            supported: component.revision().to_string(),
        });
    }
    if (id == 0) != (revision == 0) {
        return Err(Error::Invalid(
            "inconsistent database identity and schema revision".into(),
        ));
    }
    let actual = objects(conn)?;
    let legacy = revision == 0;
    if legacy && actual.contains_key("nostoi_schema_meta") {
        return Err(Error::Invalid(
            "unversioned database contains inconsistent schema metadata".into(),
        ));
    }
    let (reference, expected) = reference(component)?;
    let new = actual.is_empty();
    if new && (!writable || !legacy) {
        return Err(Error::Invalid("database has no recognized schema".into()));
    }
    if !new {
        for (name, (kind, sql)) in &expected {
            let Some((actual_kind, actual_sql)) = actual.get(name) else {
                // Readers need the data tables, not enforcement triggers.
                if !writable && kind == "trigger" {
                    continue;
                }
                return Err(Error::Invalid(format!("missing schema object {name}")));
            };
            if actual_kind != kind {
                return Err(Error::Invalid(format!("incompatible schema object {name}")));
            }
            if writable && normalized(actual_sql) != normalized(sql) {
                return Err(Error::Invalid(format!(
                    "unrecognized schema definition for {name}"
                )));
            }
            if kind == "table" && columns(conn, name)? != columns(&reference, name)? {
                return Err(Error::Invalid(format!("incompatible columns in {name}")));
            }
        }
        if writable
            && actual.iter().any(|(name, (kind, _))| {
                matches!(kind.as_str(), "table" | "view")
                    && !expected.contains_key(name)
                    && name != "nostoi_schema_meta"
            })
        {
            return Err(Error::Invalid(
                "database contains unrelated tables; refusing schema adoption".into(),
            ));
        }
    }
    let mut info = SchemaInfo {
        component: component.name().into(),
        application_id: id,
        schema_revision: revision,
        supported_revision: component.revision(),
        record_format: component.format().into(),
        created_by_version: None,
        last_migrated_by_version: None,
        legacy_unversioned: legacy,
        adopted_legacy: false,
    };
    if !legacy {
        let Some((kind, sql)) = actual.get("nostoi_schema_meta") else {
            return Err(Error::Invalid(
                "versioned database is missing schema metadata".into(),
            ));
        };
        let meta_reference = Connection::open_in_memory()?;
        meta_reference.execute_batch(METADATA_SCHEMA)?;
        let meta_sql = objects(&meta_reference)?
            .remove("nostoi_schema_meta")
            .unwrap()
            .1;
        if kind != "table" || normalized(sql) != normalized(&meta_sql) {
            return Err(Error::Invalid("incompatible schema metadata table".into()));
        }
        let row = conn.query_row("SELECT component,schema_revision,record_format,created_by_version,last_migrated_by_version,adopted_legacy FROM nostoi_schema_meta WHERE id=1", [], |r|
            Ok((r.get::<_,String>(0)?,r.get::<_,i64>(1)?,r.get::<_,String>(2)?,r.get::<_,String>(3)?,r.get::<_,String>(4)?,r.get::<_,i64>(5)?))).optional()?;
        let Some((name, stored_revision, format, created, migrated, adopted)) = row else {
            return Err(Error::Invalid("schema metadata row is missing".into()));
        };
        let count: i64 =
            conn.query_row("SELECT count(*) FROM nostoi_schema_meta", [], |r| r.get(0))?;
        if name != component.name()
            || stored_revision != revision
            || format != component.format()
            || count != 1
            || created.is_empty()
            || migrated.is_empty()
            || !matches!(adopted, 0 | 1)
        {
            return Err(Error::Invalid(
                "schema metadata disagrees with database identity/revision".into(),
            ));
        }
        info.created_by_version = (created != "unknown").then_some(created);
        info.last_migrated_by_version = Some(migrated);
        info.adopted_legacy = adopted == 1;
    }
    Ok(info)
}

/// Called only inside an IMMEDIATE transaction; header, DDL and labels commit together.
pub(crate) fn initialize(conn: &Connection, component: Component) -> Result<()> {
    if conn.is_autocommit() {
        return Err(Error::Invalid(
            "schema migration requires a transaction".into(),
        ));
    }
    let info = check(conn, component, true)?;
    if !info.legacy_unversioned {
        return Ok(());
    }
    let adopted = !objects(conn)?.is_empty();
    conn.execute_batch(component.ddl())?;
    conn.execute_batch(METADATA_SCHEMA)?;
    conn.execute(
        "INSERT INTO nostoi_schema_meta VALUES(1,?1,?2,?3,?4,?5,?6)",
        rusqlite::params![
            component.name(),
            component.revision(),
            component.format(),
            if adopted {
                "unknown"
            } else {
                env!("CARGO_PKG_VERSION")
            },
            env!("CARGO_PKG_VERSION"),
            i64::from(adopted)
        ],
    )?;
    conn.pragma_update(None, "application_id", component.id())?;
    conn.pragma_update(None, "user_version", component.revision())?;
    Ok(())
}

/// Inspect a Nostoi database without migration or writes to metadata.
pub fn inspect(path: &Path) -> Result<SchemaInfo> {
    let mut conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let tx = conn.transaction()?;
    let id: i64 = tx.query_row("PRAGMA application_id", [], |r| r.get(0))?;
    let actual = objects(&tx)?;
    let component = match id {
        AUDIT_APPLICATION_ID => Component::Audit,
        OUTBOX_APPLICATION_ID => Component::Outbox,
        0 if actual.contains_key("nostoi_records") => Component::Audit,
        0 if actual.contains_key("outbox_meta") => Component::Outbox,
        _ => {
            return Err(Error::Invalid(
                "not a recognized Nostoi-owned database".into(),
            ))
        }
    };
    check(&tx, component, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migration_header_and_metadata_roll_back_together() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(crate::sqlite::SCHEMA).unwrap();
        {
            let tx = conn
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .unwrap();
            initialize(&tx, Component::Audit).unwrap();
            assert_eq!(
                check(&tx, Component::Audit, false).unwrap().schema_revision,
                1
            );
            // Simulate abort before the caller's final commit.
        }
        let info = check(&conn, Component::Audit, false).unwrap();
        assert_eq!(info.application_id, 0);
        assert_eq!(info.schema_revision, 0);
        assert!(info.legacy_unversioned);
        assert!(!objects(&conn).unwrap().contains_key("nostoi_schema_meta"));
    }
}
