//! Network compartment: anchor a chain head to S3-compatible storage.
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

pub const PREPARED_ANCHOR_V1: &str = "nostoi-prepared-anchor-v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
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

/// What a checkpoint commits to, independent of where it is stored.
///
/// A destination that is compromised can be made to say anything, so the value
/// of a second destination is that it commits to the same tuple. `provider`,
/// `key` and the retention fields describe the copy, not the claim.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CheckpointIdentity {
    pub chain: String,
    pub format: String,
    pub seq: u64,
    pub digest: String,
}

/// A fully checked local chain containing the trusted remote checkpoint.
#[derive(Clone, Debug, Serialize)]
pub struct VerifiedAnchor {
    pub anchor: Anchor,
    pub local_head: nostoi_core::Head,
    pub verified_records: u64,
}

impl Anchor {
    /// The identity this checkpoint commits to.
    pub fn identity(&self) -> CheckpointIdentity {
        CheckpointIdentity {
            chain: self.chain.clone(),
            format: self.format.clone(),
            seq: self.seq,
            digest: self.digest.clone(),
        }
    }

    /// Reject a checkpoint that could not have been produced by this code.
    pub fn validate_shape(&self) -> Result<()> {
        if self.v != "nostoi-anchor-v1"
            || self.seq == 0
            || self.digest.len() != 64
            || !self
                .digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(Error::AnchorMismatch(
                "unsupported or malformed remote checkpoint".into(),
            ));
        }
        Ok(())
    }
}

/// Fetch the explicitly selected trusted object and compare its checkpoint
/// against the local chain. The caller supplies the expected logical identity;
/// neither the local path nor remote JSON is allowed to choose it implicitly.
///
/// This verifies content, not the bucket's retention policy. The endpoint,
/// bucket and key must identify an independently trusted retained checkpoint.
/// A valid local suffix after that checkpoint is allowed and verified as well.
pub fn verify_anchor(
    chain_path: &Path,
    client: &Client,
    key: &str,
    expected_chain: &str,
) -> Result<VerifiedAnchor> {
    if key.is_empty() || expected_chain.trim().is_empty() {
        return Err(Error::Invalid(
            "remote verification requires an explicit key and chain ID".into(),
        ));
    }
    let anchor: Anchor = serde_json::from_str(&client.get_object(key)?)
        .map_err(|e| Error::AnchorMismatch(format!("invalid remote anchor: {e}")))?;
    verify_checkpoint(chain_path, anchor, key, expected_chain)
}

/// Compare a locally held checkpoint against the chain, without fetching
/// anything. [`verify_anchor`] fetches the object and then calls this.
///
/// This verifies content, not the storage policy: retention is enforced by the
/// provider's object lock, not by anything here.
pub fn verify_checkpoint(
    chain_path: &Path,
    anchor: Anchor,
    key: &str,
    expected_chain: &str,
) -> Result<VerifiedAnchor> {
    anchor.validate_shape()?;
    if anchor.chain != expected_chain || anchor.key != key {
        return Err(Error::AnchorMismatch(
            "remote chain identity or key does not match the expected checkpoint".into(),
        ));
    }
    let verification = nostoi_core::verify_streaming(chain_path, None, Some(anchor.seq))?;
    let report = verification.report;
    if let Some(problem) = report.problem {
        return Err(Error::AnchorMismatch(format!(
            "local chain does not verify: {problem}"
        )));
    }
    if anchor.format != report.format {
        return Err(Error::AnchorMismatch(
            "remote and local formats differ".into(),
        ));
    }
    let local_head = report.head.ok_or_else(|| {
        Error::AnchorMismatch("local chain is empty: trusted history is missing".into())
    })?;
    if local_head.seq < anchor.seq {
        return Err(Error::AnchorMismatch(format!(
            "local tail is truncated: head {} precedes trusted checkpoint {}",
            local_head.seq, anchor.seq
        )));
    }
    let checkpoint = verification
        .checkpoint
        .ok_or_else(|| Error::AnchorMismatch("trusted checkpoint position is missing".into()))?;
    if checkpoint.digest != anchor.digest {
        return Err(Error::AnchorMismatch(
            "local history differs from the trusted checkpoint (rewrite or wrong chain)".into(),
        ));
    }
    Ok(VerifiedAnchor {
        anchor,
        local_head,
        verified_records: report.verified,
    })
}

/// Write an anchor for the head of `chain_path` to S3/R2.
pub fn anchor_head(
    chain_path: &Path,
    client: &Client,
    options: AnchorOptions,
    provider: Provider,
) -> Result<Anchor> {
    let prepared = prepare_anchor(chain_path, options, provider)?;
    publish_prepared(client, &prepared, false)
}

/// Immutable checkpoint and upload parameters, without credentials or signatures.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedAnchor {
    /// Missing only in historical persisted envelopes; those bytes are not rewritten.
    #[serde(
        default,
        deserialize_with = "prepared_version",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) v: Option<String>,
    pub(crate) anchor: Anchor,
    pub(crate) body: Vec<u8>,
    pub(crate) only_if_absent: bool,
    pub(crate) lock: Option<LockMode>,
    pub(crate) retain_days: i64,
}

fn prepared_version<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<String>, D::Error> {
    String::deserialize(deserializer).map(Some)
}

impl PreparedAnchor {
    /// Check internal consistency before trusting a deserialized request.
    /// This detects inconsistent intents, not a complete malicious rewrite.
    pub(crate) fn validate(&self, durable: bool) -> Result<()> {
        if self.v.as_deref().is_some_and(|v| v != PREPARED_ANCHOR_V1) {
            return Err(Error::UnsupportedSchema {
                component: "prepared anchor request",
                found: self.v.as_deref().unwrap().chars().take(128).collect(),
                supported: PREPARED_ANCHOR_V1.into(),
            });
        }
        let invalid = |detail: &str| Error::Invalid(format!("invalid prepared anchor: {detail}"));
        let anchor = &self.anchor;
        if durable && !self.only_if_absent {
            return Err(invalid("durable requests must be conditional"));
        }
        if anchor.v != "nostoi-anchor-v1"
            || anchor.seq == 0
            || anchor.digest.len() != 64
            || !anchor
                .digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || !nostoi_core::format::Format::ALL
                .iter()
                .any(|format| format.name() == anchor.format)
        {
            return Err(invalid("unsupported schema/format or malformed checkpoint"));
        }
        if anchor.chain.trim().is_empty() || anchor.chain.chars().any(char::is_control) {
            return Err(invalid("empty or invalid chain identity"));
        }
        if anchor.key.is_empty()
            || anchor.key.starts_with('/')
            || anchor.key.chars().any(char::is_control)
            || anchor
                .key
                .split('/')
                .any(|part| part == "." || part == "..")
        {
            return Err(invalid("empty or unsafe object key"));
        }
        if !matches!(anchor.provider.as_str(), "s3" | "r2") {
            return Err(invalid("unsupported provider"));
        }
        let anchored_at = OffsetDateTime::parse(&anchor.anchored_at, &Rfc3339)
            .map_err(|_| invalid("invalid checkpoint timestamp"))?;
        match self.lock {
            Some(mode) => {
                if anchor.provider != "s3"
                    || anchor.mode.as_deref() != Some(mode.as_str())
                    || !(1..=36500).contains(&self.retain_days)
                {
                    return Err(invalid(
                        "inconsistent provider, lock mode or retention duration",
                    ));
                }
                let deadline = anchor
                    .retain_until
                    .as_deref()
                    .ok_or_else(|| invalid("missing retention deadline"))?;
                let deadline = OffsetDateTime::parse(deadline, &Rfc3339)
                    .map_err(|_| invalid("invalid retention deadline"))?;
                if anchored_at.checked_add(Duration::days(self.retain_days)) != Some(deadline) {
                    return Err(invalid(
                        "retention deadline differs from timestamp plus retain-days",
                    ));
                }
            }
            None => {
                if anchor.mode.is_some() || anchor.retain_until.is_some() || self.retain_days != 0 {
                    return Err(invalid(
                        "retention metadata present without a requested lock",
                    ));
                }
            }
        }
        let expected = serde_json::to_vec_pretty(anchor)
            .map_err(|_| invalid("cannot serialize checkpoint"))?;
        if self.body != expected {
            return Err(invalid(
                "payload bytes differ from the serialized checkpoint",
            ));
        }
        Ok(())
    }

    fn check_expiry(&self) -> Result<()> {
        if self.lock.is_some() {
            let deadline = self
                .anchor
                .retain_until
                .as_deref()
                .ok_or_else(|| Error::Invalid("missing retention deadline".into()))?;
            let parsed = OffsetDateTime::parse(deadline, &Rfc3339)
                .map_err(|e| Error::Invalid(e.to_string()))?;
            if parsed <= OffsetDateTime::now_utc() {
                return Err(Error::AnchorExpired {
                    key: self.anchor.key.clone(),
                    retain_until: deadline.to_string(),
                });
            }
        }
        Ok(())
    }
}

/// Verify the entire chain and prepare a request without network effects.
pub fn prepare_anchor(
    chain_path: &Path,
    options: AnchorOptions,
    provider: Provider,
) -> Result<PreparedAnchor> {
    prepare_anchor_at(chain_path, options, provider, OffsetDateTime::now_utc())
}

/// As [`prepare_anchor`], with the checkpoint timestamp supplied by the caller.
///
/// A fan-out pins one timestamp for the whole batch, so every destination's
/// checkpoint describes the same instant and can be compared field by field.
pub fn prepare_anchor_at(
    chain_path: &Path,
    options: AnchorOptions,
    provider: Provider,
    anchored_at: OffsetDateTime,
) -> Result<PreparedAnchor> {
    let report = nostoi_core::verify(chain_path, None)?;
    prepare_from_report(chain_path, &report, options, provider, anchored_at)
}

/// Prepare from a verification that has already been computed.
///
/// Publishing to N destinations then costs one chain verification rather than
/// N: the expensive part is proven once and reused. The caller is responsible
/// for having verified the same chain file this report describes.
pub fn prepare_from_report(
    chain_path: &Path,
    report: &nostoi_core::Report,
    options: AnchorOptions,
    provider: Provider,
    anchored_at: OffsetDateTime,
) -> Result<PreparedAnchor> {
    if let Some(problem) = &report.problem {
        return Err(Error::Broken(problem.clone()));
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
    let anchored_at = anchored_at
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
        format: report.format.clone(),
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
    Ok(PreparedAnchor {
        v: Some(PREPARED_ANCHOR_V1.into()),
        anchor,
        body,
        only_if_absent: options.only_if_absent,
        lock: options.lock,
        retain_days: if options.lock.is_some() {
            options.retain_days
        } else {
            0
        },
    })
}

/// Publish the original bytes and deadline. Conditional objects are never overwritten.
pub fn publish_prepared(client: &Client, prepared: &PreparedAnchor, exact: bool) -> Result<Anchor> {
    prepared.validate(false)?;
    prepared.check_expiry()?;
    let anchor = prepared.anchor.clone();
    let key = anchor.key.clone();
    let put_options = PutOptions {
        content_type: "application/json; charset=utf-8".to_string(),
        lock: match prepared.lock {
            Some(mode) => {
                let retain_until = OffsetDateTime::parse(
                    anchor
                        .retain_until
                        .as_deref()
                        .ok_or_else(|| Error::Invalid("missing retention deadline".into()))?,
                    &Rfc3339,
                )
                .map_err(|e| Error::Invalid(e.to_string()))?;
                Some(ObjectLock {
                    mode: mode.into(),
                    retain_until,
                })
            }
            _ => None,
        },
        only_if_absent: prepared.only_if_absent,
    };
    let unconfirmed = |detail: String| Error::AnchorUnconfirmed {
        key: key.clone(),
        detail,
    };
    let existing_body = match client.put_object(&key, &prepared.body, &put_options) {
        Ok(result) if result.existed => Some(
            client
                .get_object(&key)
                .map_err(|e| unconfirmed(e.to_string()))?,
        ),
        Ok(_) => None,
        Err(error @ Error::UploadUncertain { .. }) if prepared.only_if_absent => {
            // All receipts may have been lost. Read the deterministic key once
            // before reporting uncertainty; never overwrite it to "repair" it.
            match client.get_object(&key) {
                Ok(body) => Some(body),
                Err(_) => return Err(error),
            }
        }
        Err(error) => return Err(error),
    };
    let anchor = if let Some(body) = existing_body {
        if exact && body.as_bytes() != prepared.body {
            return Err(unconfirmed(
                "existing object differs from the durable request bytes".into(),
            ));
        }
        let existing: Anchor = serde_json::from_str(&body)
            .map_err(|e| unconfirmed(format!("existing anchor is invalid: {e}")))?;
        if existing.v != anchor.v
            || existing.chain != anchor.chain
            || existing.format != anchor.format
            || existing.seq != anchor.seq
            || existing.digest != anchor.digest
            || existing.key != anchor.key
        {
            return Err(unconfirmed(
                "existing object anchors a different chain or head".into(),
            ));
        }
        existing
    } else {
        anchor
    };
    if let Some(lock) = &put_options.lock {
        let retention = client
            .get_object_retention(&key)
            .map_err(|e| unconfirmed(e.to_string()))?
            .ok_or_else(|| {
                unconfirmed("anchor uploaded, but Object Lock retention was not returned".into())
            })?;
        let retain_until = OffsetDateTime::parse(&retention.retain_until, &Rfc3339)
            .map_err(|e| unconfirmed(format!("invalid retention timestamp: {e}")))?;
        if retention.mode != lock.mode.as_str() || retain_until < lock.retain_until {
            return Err(unconfirmed(
                "anchor uploaded, but Object Lock retention does not meet the request".into(),
            ));
        }
        // A request that expired during reconciliation must not become a fresh
        // assurance merely because the server returned its historical deadline.
        prepared.check_expiry()?;
        if retain_until <= OffsetDateTime::now_utc() {
            return Err(unconfirmed("Object Lock retention has expired".into()));
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
    fn checkpoint_verification_rejects_broken_prefix_and_suffix() {
        for broken_seq in [1, 3] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("audit.jsonl");
            let mut records = Vec::new();
            let mut previous = nostoi_core::GENESIS.to_owned();
            for seq in 1..=3 {
                let record = nostoi_core::format::nostoi_record(
                    seq,
                    &previous,
                    "2026-01-01T00:00:00Z",
                    None,
                    "test",
                    None,
                    serde_json::json!({}),
                )
                .unwrap();
                previous = record["digest"].as_str().unwrap().to_owned();
                records.push(record);
            }
            let anchor = Anchor {
                v: "nostoi-anchor-v1".into(),
                chain: "trusted".into(),
                format: "nostoi-v1".into(),
                seq: 2,
                digest: records[1]["digest"].as_str().unwrap().into(),
                anchored_at: "2026-01-01T00:00:00Z".into(),
                provider: "s3".into(),
                key: "heads/test".into(),
                mode: None,
                retain_until: None,
            };
            records[broken_seq - 1]["kind"] = serde_json::json!("tampered");
            let text: String = records
                .iter()
                .map(|r| format!("{}\n", nostoi_core::canonical::to_string(r)))
                .collect();
            std::fs::write(&path, text).unwrap();
            let result = verify_checkpoint(&path, anchor, "heads/test", "trusted");
            assert!(
                matches!(result, Err(Error::AnchorMismatch(detail)) if detail.contains(&format!("record {broken_seq} was altered")))
            );
        }
    }

    #[test]
    fn broken_chain_is_never_anchored() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        nostoi_core::append(
            &path,
            nostoi_core::Draft {
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
