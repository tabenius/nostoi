//! Anchor a chain head to S3-compatible storage.
//!
//! An anchor writes the last verified head of a Nostoi chain to a write-once
//! object. That external copy lets you detect tail truncation or a fully
//! rewritten chain, because nothing inside the chain can be rewritten without
//! breaking its links, but an attacker who controls the store can still rewrite
//! the whole thing and its digests.
//!
//! ## Provider differences
//!
//! * **AWS S3 Object Lock:** set per object via `x-amz-object-lock-mode` and
//!   `x-amz-object-lock-retain-until-date`. With `COMPLIANCE` mode no one,
//!   including the account root, can overwrite or delete the object or shorten
//!   its retention. AWS requires a checksum header when a retention period is
//!   supplied, so the client includes `x-amz-sdk-checksum-algorithm: SHA256` and
//!   `x-amz-checksum-sha256`.
//! * **Cloudflare R2:** does not support S3 Object Lock headers. Instead it has
//!   native **bucket locks** (prefix rules with age/date/indefinite). The
//!   retention is enforced server-side by a bucket lock on the prefix (for
//!   example `heads/`). The anchor therefore writes an object under that prefix
//!   with `If-None-Match: *` (write-once) and does **not** send lock headers;
//!   the bucket lock must be configured out of band. If you ask this module to
//!   apply an object lock against R2, it returns an error rather than silently
//!   failing to lock.

use serde::{Deserialize, Serialize};
use std::path::Path;
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime, UtcOffset};

use crate::error::{Error, Result};
use crate::s3::{Client, LockMode as S3LockMode, ObjectLock, Provider, PutOptions};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockMode {
    Governance,
    Compliance,
}

impl From<LockMode> for S3LockMode {
    fn from(mode: LockMode) -> Self {
        match mode {
            LockMode::Governance => S3LockMode::Governance,
            LockMode::Compliance => S3LockMode::Compliance,
        }
    }
}

#[derive(Clone, Debug)]
pub struct AnchorOptions {
    /// The S3 key to write (for example `heads/audit.jsonl.json`). If empty, a
    /// key is generated from the chain name, sequence and digest.
    pub key: String,
    /// The format name recorded in the anchor (e.g. `nostoi-v1`).
    pub format: String,
    /// Optional identifier for the chain (e.g. a path or logical name).
    pub chain_id: String,
    /// Write the anchor only if the key does not already exist.
    pub only_if_absent: bool,
    /// Object lock to apply (AWS S3 only). For R2, this must be `None` unless
    /// the bucket lock is managed elsewhere and you explicitly want no headers;
    /// the safest is to require `None` when targeting R2 with object locks.
    pub lock: Option<LockMode>,
    /// When locking, retain until `now + retain_days` (UTC). Ignored if `lock`
    /// is `None`.
    pub retain_days: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Anchor {
    pub v: String,
    pub chain: String,
    pub format: String,
    pub seq: u64,
    pub digest: String,
    pub anchored_at: String,
    pub provider: String,
    pub key: String,
    pub mode: Option<String>,
    pub retain_until: Option<String>,
}

/// Write an anchor for the head of `chain_path` to S3/R2.
pub fn anchor_head(
    chain_path: &Path,
    client: &Client,
    options: AnchorOptions,
    provider: Provider,
) -> Result<Anchor> {
    let report = crate::verify(chain_path, None)?;
    if let Some(problem) = report.problem {
        return Err(Error::Broken(problem));
    }
    if options.lock.is_some() && !(1..=36500).contains(&options.retain_days) {
        return Err(Error::Invalid(
            "retain-days must be between 1 and 36500".into(),
        ));
    }
    if !options.key.is_empty()
        && (options.key.starts_with('/')
            || options.key.chars().any(char::is_control)
            || options
                .key
                .split('/')
                .any(|part| part == ".." || part == "."))
    {
        return Err(Error::Invalid(
            "anchor key must not contain control characters or dot path segments".into(),
        ));
    }
    let head = report
        .head
        .clone()
        .ok_or_else(|| Error::Invalid("chain has no head to anchor (zero records)".into()))?;
    let anchored_at = OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .map_err(|e| Error::S3(e.to_string()))?;
    let chain_id = if options.chain_id.is_empty() {
        chain_path.display().to_string()
    } else {
        options.chain_id.clone()
    };
    let key = if options.key.is_empty() {
        generate_key(&chain_id, head.seq, &head.digest)
    } else {
        options.key.clone()
    };

    let mut lock_applied: Option<(String, String)> = None;
    if let Some(mode) = options.lock {
        if provider == Provider::R2 {
            return Err(Error::S3(
                "R2 does not support S3 Object Lock headers; configure a bucket lock \
                 rule on the prefix instead (or set lock=None)"
                    .into(),
            ));
        }
        let retain_until = anchored_at + Duration::days(options.retain_days);
        lock_applied = Some((
            mode.as_str().to_string(),
            retain_until
                .to_offset(UtcOffset::UTC)
                .format(&Rfc3339)
                .map_err(|error| Error::S3(format!("retain-until: {error}")))?,
        ));
    }

    let anchor = Anchor {
        v: "nostoi-anchor-v1".into(),
        chain: chain_id.clone(),
        format: report.format,
        seq: head.seq,
        digest: head.digest.clone(),
        anchored_at: anchored_at
            .to_offset(UtcOffset::UTC)
            .format(&Rfc3339)
            .map_err(|error| Error::S3(format!("timestamp: {error}")))?,
        provider: match provider {
            Provider::S3 => "s3".to_string(),
            Provider::R2 => "r2".to_string(),
        },
        key: key.clone(),
        mode: lock_applied.as_ref().map(|m| m.0.clone()),
        retain_until: lock_applied.as_ref().map(|m| m.1.clone()),
    };

    let body = serde_json::to_vec_pretty(&anchor)
        .map_err(|error| Error::S3(format!("serialize anchor: {error}")))?;
    let put_options = PutOptions {
        content_type: "application/json; charset=utf-8".to_string(),
        lock: match (provider, options.lock) {
            (Provider::S3, Some(mode)) => {
                let retain_until = anchored_at + Duration::days(options.retain_days);
                Some(ObjectLock {
                    mode: mode.into(),
                    retain_until,
                })
            }
            _ => None,
        },
        only_if_absent: options.only_if_absent,
    };
    let result = client.put_object(&key, &body, &put_options)?;
    let anchor = if result.existed {
        let existing: Anchor = serde_json::from_str(&client.get_object(&key)?)
            .map_err(|e| Error::S3(format!("existing anchor is invalid: {e}")))?;
        if existing.v != anchor.v
            || existing.chain != anchor.chain
            || existing.format != anchor.format
            || existing.seq != anchor.seq
            || existing.digest != anchor.digest
            || existing.key != anchor.key
        {
            return Err(Error::S3(
                "existing object anchors a different chain or head".into(),
            ));
        }
        existing
    } else {
        anchor
    };
    if let Some(lock) = &put_options.lock {
        let retention = client.get_object_retention(&key)?.ok_or_else(|| {
            Error::S3("anchor uploaded, but Object Lock retention was not returned".into())
        })?;
        let retain_until = OffsetDateTime::parse(&retention.retain_until, &Rfc3339)
            .map_err(|e| Error::S3(format!("invalid retention timestamp: {e}")))?;
        if retention.mode != lock.mode.as_str() || retain_until < lock.retain_until {
            return Err(Error::S3(
                "anchor uploaded, but Object Lock retention does not meet the request".into(),
            ));
        }
    }
    Ok(anchor)
}

impl LockMode {
    fn as_str(self) -> &'static str {
        match self {
            LockMode::Governance => "GOVERNANCE",
            LockMode::Compliance => "COMPLIANCE",
        }
    }
}

/// Generate a deterministic, unambiguous key when the caller does not supply one.
/// It includes the sequence to make it trivially sortable by head position.
fn generate_key(chain_id: &str, seq: u64, digest: &str) -> String {
    let path = std::path::Path::new(chain_id);
    let base = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(chain_id)
        .to_string();
    // Sanitize
    let mut slug = String::with_capacity(base.len());
    for ch in base.chars() {
        match ch {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '.' | '_' | '-' => slug.push(ch),
            _ => slug.push('_'),
        }
    }
    while slug.contains("__") {
        slug = slug.replace("__", "_");
    }
    slug = slug.trim_matches('_').to_string();
    if slug.is_empty() {
        slug = "chain".to_string();
    }
    let orig_hash6 = {
        use sha2::Digest;
        let h = sha2::Sha256::digest(chain_id.as_bytes());
        hex::encode(&h[..3]) // 6 hex chars
    };
    if slug.len() > 40 {
        slug.truncate(40);
    }
    let prefix: String = digest.chars().take(10).collect();
    format!("heads/{slug}-{orig_hash6}-{seq:08x}-{prefix}.json")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn broken_chain_is_never_anchored() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        crate::append(
            &path,
            crate::Draft {
                actor: None,
                kind: "test",
                subject: None,
                body: serde_json::json!({}),
                at: None,
            },
        )
        .unwrap();
        use std::io::Write;
        writeln!(
            std::fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .unwrap(),
            "broken"
        )
        .unwrap();
        let client = Client::new(
            "http://127.0.0.1:1",
            "bucket",
            "auto",
            true,
            crate::s3::Credentials {
                access_key: "test".into(),
                secret_key: "test".into(),
                session_token: None,
            },
        )
        .unwrap();
        let result = anchor_head(
            &path,
            &client,
            AnchorOptions {
                key: String::new(),
                format: "nostoi-v1".into(),
                chain_id: String::new(),
                only_if_absent: true,
                lock: None,
                retain_days: 365,
            },
            Provider::S3,
        );
        assert!(matches!(result, Err(Error::Broken(_))));
    }

    #[test]
    fn generate_key_is_stable_and_sortable() {
        let key = generate_key("/home/xyzzy/src/audit.jsonl", 17, "287fc641d0fb79efdc4b");
        assert!(key.contains("audit.jsonl"));
        let key2 = generate_key("audit", 1, "abc1234567");
        assert!(key2.starts_with("heads/audit"));
    }
}
