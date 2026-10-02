//! Publishing one checkpoint to several independent destinations.
//!
//! A single destination means a single answer to the question "was this chain
//! rewritten?". Two destinations that are not under the same administration
//! mean the attacker has to control both, and two destinations that disagree
//! mean something is already wrong. Neither property needs a new protocol: the
//! checkpoint format, the write-once upload and the recovery contract are the
//! ones already in use, applied N times.
//!
//! Three rules make that hold, and the code here is arranged around them.
//!
//! * **One verification per batch.** The chain is proven once and each
//!   destination's request is prepared from that single report, so cost does
//!   not grow with the number of destinations.
//! * **One timestamp per batch.** Every checkpoint says `anchored_at` at the
//!   same instant, so a disagreement between destinations is about the chain
//!   and never about clock skew.
//! * **Isolation, not all-or-nothing.** A destination that is down, refused or
//!   ambiguous is reported as such and the rest still publish. The caller
//!   decides what a partial result means; this module never hides one.
//!
//! Verification is the mirror image and deliberately stricter. It requires the
//! destinations to *agree* before it trusts any of them: if two destinations
//! commit to different `(chain, format, seq, digest)` tuples that is a
//! conflict, not a majority vote. A destination that cannot be read is reported
//! as unverified rather than counted as agreement.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use time::OffsetDateTime;

use crate::anchor::{
    prepare_from_report, verify_checkpoint, Anchor, AnchorOptions, CheckpointIdentity, LockMode,
    VerifiedAnchor,
};
use crate::s3::{Client, Credentials, Provider};
use crate::{Error, Result};

/// One destination in a fan-out.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Target {
    /// Stable short name. Also names this destination's outbox file, so it is
    /// restricted to characters that are safe in a filename.
    pub name: String,
    /// Endpoint URL, for example `https://s3.us-west-2.amazonaws.com`.
    pub endpoint: String,
    /// Bucket that holds the checkpoints.
    pub bucket: String,
    /// Region, or `auto` for providers that do not use one.
    #[serde(default = "auto_region")]
    pub region: String,
    /// Use path-style addressing; forced on for R2.
    #[serde(default)]
    pub path_style: bool,
    /// Which locking model this destination offers.
    ///
    /// Detected from the endpoint host by default. Set it when detection cannot
    /// see the truth: a bucket behind a custom domain or a private R2 endpoint
    /// is served as an ordinary S3 host, and asking for an object lock there
    /// would send headers the service silently ignores.
    #[serde(default)]
    pub provider: Option<Provider>,
    /// `governance` or `compliance`. Omit for providers without object lock
    /// (R2), where retention comes from a bucket lock configured out of band.
    #[serde(default, deserialize_with = "lock_from_config")]
    pub lock: Option<LockMode>,
    /// Days to retain when `lock` is set.
    #[serde(default = "default_retain_days")]
    pub retain_days: i64,
    /// Subdirectory of the credentials directory holding this destination's key.
    ///
    /// Independent destinations should have independent credentials: that is
    /// what stops one compromised credential from reaching two destinations.
    #[serde(default)]
    pub credentials: Option<String>,
}

fn auto_region() -> String {
    "auto".to_string()
}

/// Accept the lock mode case-insensitively from a configuration file.
///
/// The enum's own serde names are fixed by the durable outbox format, so the
/// friendlier `governance`/`compliance` spelling belongs here rather than on the
/// type.
fn lock_from_config<'de, D>(deserializer: D) -> std::result::Result<Option<LockMode>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Raw {
        Mode(LockMode),
        Text(String),
    }
    match Option::<Raw>::deserialize(deserializer)? {
        None => Ok(None),
        Some(Raw::Mode(mode)) => Ok(Some(mode)),
        Some(Raw::Text(text)) => match text.to_ascii_lowercase().as_str() {
            "governance" => Ok(Some(LockMode::Governance)),
            "compliance" => Ok(Some(LockMode::Compliance)),
            other => Err(serde::de::Error::custom(format!(
                "lock must be governance or compliance, got {other:?}"
            ))),
        },
    }
}

fn default_retain_days() -> i64 {
    365
}

impl Target {
    /// Which locking model this destination offers: the configured one, or the
    /// one detected from the endpoint host.
    pub fn provider(&self) -> Provider {
        self.provider
            .unwrap_or_else(|| Provider::detect(&self.endpoint))
    }

    /// The client for this destination.
    pub fn client(&self, credentials: Credentials) -> Result<Client> {
        let provider = self.provider();
        Client::new(
            &self.endpoint,
            &self.bucket,
            &self.region,
            self.path_style || provider == Provider::R2,
            credentials,
        )
    }
}

/// A set of destinations and the checkpoint identity they share.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Fanout {
    /// Chain identity recorded in every checkpoint. Empty means the chain path,
    /// which matches what a single-destination run would record.
    #[serde(default)]
    pub chain_id: String,
    /// Explicit object key. Empty means one generated from the chain identity,
    /// sequence and digest, which is then identical across destinations.
    #[serde(default)]
    pub key: String,
    /// Format name recorded in the checkpoint.
    #[serde(default = "default_format")]
    pub format: String,
    pub targets: Vec<Target>,
}

fn default_format() -> String {
    "nostoi-v1".to_string()
}

impl Fanout {
    /// Read a fan-out configuration from JSON.
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path).map_err(crate::error::io(path))?;
        let config: Self = serde_json::from_str(&text)
            .map_err(|e| Error::Invalid(format!("invalid target file {}: {e}", path.display())))?;
        config.validate()?;
        Ok(config)
    }

    /// Check everything that would otherwise fail halfway through a publish.
    pub fn validate(&self) -> Result<()> {
        if self.targets.is_empty() {
            return Err(Error::Invalid("a fan-out needs at least one target".into()));
        }
        let mut names = BTreeSet::new();
        for target in &self.targets {
            validate_name(&target.name)?;
            if !names.insert(target.name.clone()) {
                return Err(Error::Invalid(format!(
                    "duplicate target name {:?}",
                    target.name
                )));
            }
            crate::s3::check_endpoint(&target.endpoint)?;
            if target.bucket.is_empty() {
                return Err(Error::Invalid(format!(
                    "target {:?} has no bucket",
                    target.name
                )));
            }
            if target.lock.is_some() && !(1..=36500).contains(&target.retain_days) {
                return Err(Error::Invalid(format!(
                    "target {:?}: retain-days must be between 1 and 36500",
                    target.name
                )));
            }
            if let Some(sub) = &target.credentials {
                validate_name(sub)?;
            }
        }
        Ok(())
    }

    /// One path per destination, so a destination's recovery state cannot block
    /// or corrupt another's.
    pub fn outbox_paths(&self, outbox_dir: &Path) -> Vec<(String, PathBuf)> {
        self.targets
            .iter()
            .map(|target| {
                (
                    target.name.clone(),
                    outbox_dir.join(format!("{}.sqlite", target.name)),
                )
            })
            .collect()
    }
}

/// A name that is safe to use as a filename, because it becomes one.
///
/// Anything else could escape the outbox directory, which would let a
/// configuration file decide which database gets opened.
fn validate_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 64
        || name.starts_with('.')
        || name
            .chars()
            .any(|c| !(c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.'))
    {
        return Err(Error::Invalid(format!(
            "{name:?} is not a usable target name: use 1-64 characters from \
             A-Z a-z 0-9 - _ . and do not start with a dot"
        )));
    }
    Ok(())
}

/// What happened at one destination.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PublishState {
    /// The object was written and its retention read back as requested.
    Confirmed,
    /// The key already held this exact checkpoint. Publishing again is a no-op.
    AlreadyAnchored,
    /// The upload may or may not have landed. The durable intent survives; retry.
    Unresolved,
    /// The destination refused, or could not be configured. Nothing was written.
    Rejected,
}

/// One destination's publish result.
#[derive(Clone, Debug, Serialize)]
pub struct TargetPublish {
    pub name: String,
    pub provider: Provider,
    pub key: String,
    pub seq: u64,
    pub digest: String,
    /// Whether this destination had an outbox to recover through.
    pub durable: bool,
    pub state: PublishState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Publish one checkpoint to every destination, reporting each separately.
///
/// The chain is verified once before any destination is contacted, so a broken
/// chain fails the whole batch without touching the network. After that,
/// destinations are independent: one failing never stops the others.
#[cfg(feature = "sqlite")]
pub fn publish(
    chain_path: &Path,
    config: &Fanout,
    credentials_dir: Option<&Path>,
    outbox_dir: Option<&Path>,
) -> Result<Vec<TargetPublish>> {
    config.validate()?;
    let report = nostoi_core::verify(chain_path, None)?;
    if let Some(problem) = &report.problem {
        return Err(Error::Broken(problem.clone()));
    }
    // One instant for the whole batch: destinations must differ about the chain,
    // never about when they were asked.
    let anchored_at = OffsetDateTime::now_utc();

    let mut results = Vec::with_capacity(config.targets.len());
    for (target, outbox) in config.targets.iter().zip(outboxes(config, outbox_dir)) {
        results.push(publish_one(
            chain_path,
            &report,
            config,
            target,
            anchored_at,
            credentials_dir,
            outbox,
        ));
    }
    Ok(results)
}

/// As [`publish`], without durability. An interrupted upload cannot then be
/// retried with its exact bytes, so a lost receipt stays a lost receipt.
#[cfg(not(feature = "sqlite"))]
pub fn publish(
    chain_path: &Path,
    config: &Fanout,
    credentials_dir: Option<&Path>,
    _outbox_dir: Option<&Path>,
) -> Result<Vec<TargetPublish>> {
    config.validate()?;
    let report = nostoi_core::verify(chain_path, None)?;
    if let Some(problem) = &report.problem {
        return Err(Error::Broken(problem.clone()));
    }
    let anchored_at = OffsetDateTime::now_utc();
    let mut results = Vec::with_capacity(config.targets.len());
    for target in &config.targets {
        results.push(publish_one(
            chain_path,
            &report,
            config,
            target,
            anchored_at,
            credentials_dir,
            None,
        ));
    }
    Ok(results)
}

/// Each destination's outbox path, or `None` for every one of them.
///
/// A destination either has its own durable outbox or none of them do: mixing the
/// two would mean some destinations could be retried with their exact bytes after
/// a crash while others could not, and the report says `durable` per destination
/// so the operator has to read it. `nostoi-anchor --outbox-dir` therefore applies
/// to all of them.
#[cfg(feature = "sqlite")]
fn outboxes(config: &Fanout, outbox_dir: Option<&Path>) -> Vec<Option<PathBuf>> {
    match outbox_dir {
        Some(dir) => config
            .outbox_paths(dir)
            .into_iter()
            .map(|(_, path)| Some(path))
            .collect(),
        None => vec![None; config.targets.len()],
    }
}

#[allow(clippy::too_many_arguments)]
fn publish_one(
    chain_path: &Path,
    report: &nostoi_core::Report,
    config: &Fanout,
    target: &Target,
    anchored_at: OffsetDateTime,
    credentials_dir: Option<&Path>,
    outbox: Option<PathBuf>,
) -> TargetPublish {
    let provider = target.provider();
    let mut result = TargetPublish {
        name: target.name.clone(),
        provider,
        key: config.key.clone(),
        seq: 0,
        digest: String::new(),
        durable: outbox.is_some(),
        state: PublishState::Rejected,
        detail: None,
    };

    let client = match credentials_for(target, credentials_dir)
        .and_then(|credentials| target.client(credentials))
    {
        Ok(client) => client,
        Err(error) => {
            result.detail = Some(error.to_string());
            return result;
        }
    };
    let options = AnchorOptions {
        key: config.key.clone(),
        format: config.format.clone(),
        chain_id: chain_of(config, chain_path),
        only_if_absent: true,
        lock: target.lock,
        retain_days: if target.lock.is_some() {
            target.retain_days
        } else {
            0
        },
    };
    let prepared = match prepare_from_report(chain_path, report, options, provider, anchored_at) {
        Ok(prepared) => prepared,
        Err(error) => {
            result.detail = Some(error.to_string());
            return result;
        }
    };
    result.key = prepared.anchor.key.clone();
    result.seq = prepared.anchor.seq;
    result.digest = prepared.anchor.digest.clone();
    let requested_anchored_at = prepared.anchor.anchored_at.clone();

    let outcome = match outbox {
        #[cfg(feature = "sqlite")]
        Some(path) => crate::outbox::Outbox::open(&path, chain_path)
            .and_then(|mut outbox| outbox.publish_prepared(chain_path, &client, prepared)),
        _ => crate::anchor::publish_prepared(&client, &prepared, true),
    };
    match outcome {
        Ok(anchor) => {
            result.key = anchor.key;
            result.seq = anchor.seq;
            result.digest = anchor.digest;
            result.state = PublishState::Confirmed;
            if anchor.anchored_at != requested_anchored_at {
                // A key that already held this checkpoint keeps its original
                // timestamp: that is the point of a write-once object.
                result.state = PublishState::AlreadyAnchored;
            }
            result
        }
        Err(error @ (Error::UploadUncertain { .. } | Error::AnchorUnconfirmed { .. })) => {
            result.state = PublishState::Unresolved;
            result.detail = Some(error.to_string());
            result
        }
        Err(error) => {
            result.state = PublishState::Rejected;
            result.detail = Some(error.to_string());
            result
        }
    }
}

fn chain_of(config: &Fanout, chain_path: &Path) -> String {
    if config.chain_id.is_empty() {
        chain_path.display().to_string()
    } else {
        config.chain_id.clone()
    }
}

/// Read one destination's credentials.
///
/// With no credentials directory the process environment is used, which is what
/// a single-destination run does today. With one, two layouts are accepted:
///
/// * `<dir>/<sub>/aws-access-key-id`, for an operator who exposes a prepared
///   directory;
/// * `<dir>/<sub>-aws-access-key-id`, which is what systemd's `LoadCredential=`
///   can produce, since a credential ID has to be a plain filename.
///
/// A destination that names a `credentials` subdirectory never falls back to the
/// unprefixed files: that would silently hand it the credential belonging to
/// some other destination, or a shared one, which is the thing per-destination
/// credentials exist to prevent. Either way the secrets arrive as files only
/// this service can read, never in arguments.
pub fn credentials_for(target: &Target, credentials_dir: Option<&Path>) -> Result<Credentials> {
    let Some(root) = credentials_dir else {
        return Credentials::from_env();
    };
    let unreadable = |detail: String| {
        Error::Invalid(format!(
            "{detail}; looked for {}",
            layouts(root, target).join(", ")
        ))
    };

    // A directory per destination.
    if let Some(sub) = &target.credentials {
        let dir = root.join(sub);
        if dir.is_dir() {
            return Ok(Credentials {
                access_key: read_credential(&dir, "aws-access-key-id").map_err(|detail| {
                    unreadable(format!("credential for {:?}: {detail}", target.name))
                })?,
                secret_key: read_credential(&dir, "aws-secret-access-key").map_err(|detail| {
                    unreadable(format!("credential for {:?}: {detail}", target.name))
                })?,
                session_token: read_credential(&dir, "aws-session-token").ok(),
            });
        }
    }

    // Flat files, prefixed with this destination's name. A destination that did
    // not name a subdirectory may also use the unprefixed files, which is how a
    // single-destination unit loads one credential set.
    let prefix = target
        .credentials
        .clone()
        .unwrap_or_else(|| target.name.clone());
    for prefix in if target.credentials.is_some() {
        vec![prefix]
    } else {
        vec![prefix, String::new()]
    } {
        let name = |file: &str| {
            if prefix.is_empty() {
                file.to_string()
            } else {
                format!("{prefix}-{file}")
            }
        };
        if let (Ok(access_key), Ok(secret_key)) = (
            read_credential(root, &name("aws-access-key-id")),
            read_credential(root, &name("aws-secret-access-key")),
        ) {
            return Ok(Credentials {
                access_key,
                secret_key,
                session_token: read_credential(root, &name("aws-session-token")).ok(),
            });
        }
    }

    Err(unreadable(format!(
        "no credential for destination {:?}",
        target.name
    )))
}

/// The paths that would have supplied this destination's credential.
fn layouts(root: &Path, target: &Target) -> Vec<String> {
    let mut paths = Vec::new();
    if let Some(sub) = &target.credentials {
        paths.push(format!("{}/{sub}/aws-access-key-id", root.display()));
        paths.push(format!("{}/{sub}-aws-access-key-id", root.display()));
    } else {
        paths.push(format!(
            "{}/{}-aws-access-key-id",
            root.display(),
            target.name
        ));
        paths.push(format!("{}/aws-access-key-id", root.display()));
    }
    paths
}

/// Read one credential file, trimming the newline a text file ends with.
fn read_credential(dir: &Path, name: &str) -> std::result::Result<String, String> {
    let path = dir.join(name);
    let value = std::fs::read_to_string(&path)
        .map_err(|error| format!("cannot read {} ({error})", path.display()))?;
    let value = value.trim_end_matches(['\n', '\r']).to_string();
    if value.is_empty() {
        return Err(format!("credential {} is empty", path.display()));
    }
    Ok(value)
}

/// How one destination answered during verification.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "state", rename_all = "kebab-case")]
pub enum ReadState {
    /// The destination holds a well-formed checkpoint.
    Agreed { identity: CheckpointIdentity },
    /// The destination holds a checkpoint that commits to something else.
    Conflict { identity: CheckpointIdentity },
    /// The checkpoint could not be read or parsed.
    Unusable { detail: String },
}

/// One destination's answer.
#[derive(Clone, Debug, Serialize)]
pub struct TargetRead {
    pub name: String,
    pub provider: Provider,
    pub key: String,
    pub result: ReadState,
}

/// The result of asking every destination for its checkpoint.
#[derive(Clone, Debug, Serialize)]
pub struct FanoutVerification {
    pub key: String,
    pub per_target: Vec<TargetRead>,
    /// The one identity every readable destination agreed on, if any.
    pub agreed: Option<CheckpointIdentity>,
    /// Destinations that could not be read. They neither confirm nor conflict.
    pub unusable: Vec<String>,
    /// Destinations that disagreed, and what they claimed.
    pub conflicts: Vec<String>,
    /// Present when the local chain was checked against the agreed identity.
    pub verified: Option<VerifiedAnchor>,
}

impl FanoutVerification {
    /// Whether this verification may be relied on.
    ///
    /// True when the local chain matched a checkpoint and no destination
    /// contradicted another. It does not mean every destination was reachable:
    /// see [`FanoutVerification::unusable`] for the assurance that was not
    /// obtained.
    pub fn is_ok(&self) -> bool {
        self.conflicts.is_empty() && self.verified.is_some()
    }
}

/// Fetch the checkpoint from every destination and check them against each other
/// and the local chain.
///
/// Destinations must agree before any of them is trusted, because a compromised
/// destination can be made to return anything; two of them saying different
/// things is a conflict rather than a majority to be resolved. The local chain
/// is verified once, against the agreed identity.
pub fn verify(
    chain_path: &Path,
    config: &Fanout,
    credentials_dir: Option<&Path>,
) -> Result<FanoutVerification> {
    config.validate()?;
    if config.key.is_empty() {
        return Err(Error::Invalid(
            "fan-out verification requires an explicit key: it cannot choose a trusted \\
             checkpoint for you"
                .into(),
        ));
    }
    let key = config.key.clone();
    let mut per_target = Vec::with_capacity(config.targets.len());
    let mut agreed: Option<CheckpointIdentity> = None;
    let mut unusable = Vec::new();
    let mut conflicts = Vec::new();
    let mut witness: Option<Anchor> = None;

    for target in &config.targets {
        let provider = target.provider();
        let read = credentials_for(target, credentials_dir)
            .and_then(|credentials| target.client(credentials)?.get_object(&key));
        let entry = match read {
            Ok(body) => match serde_json::from_str::<Anchor>(&body) {
                Ok(anchor) => match anchor.validate_shape() {
                    Ok(()) => {
                        let identity = anchor.identity();
                        match &agreed {
                            None => {
                                agreed = Some(identity.clone());
                                witness = Some(anchor);
                            }
                            Some(previous) if *previous == identity => {}
                            Some(_) => conflicts.push(format!(
                                "{}: chain={} format={} seq={} digest={}",
                                target.name,
                                identity.chain,
                                identity.format,
                                identity.seq,
                                identity.digest
                            )),
                        }
                        TargetRead {
                            name: target.name.clone(),
                            provider,
                            key: key.clone(),
                            result: ReadState::Agreed { identity },
                        }
                    }
                    Err(error) => {
                        let detail = error.to_string();
                        unusable.push(format!("{}: {detail}", target.name));
                        TargetRead {
                            name: target.name.clone(),
                            provider,
                            key: key.clone(),
                            result: ReadState::Unusable { detail },
                        }
                    }
                },
                Err(error) => {
                    let detail = format!("stored object is not a checkpoint: {error}");
                    unusable.push(format!("{}: {detail}", target.name));
                    TargetRead {
                        name: target.name.clone(),
                        provider,
                        key: key.clone(),
                        result: ReadState::Unusable { detail },
                    }
                }
            },
            Err(error) => {
                let detail = error.to_string();
                unusable.push(format!("{}: {detail}", target.name));
                TargetRead {
                    name: target.name.clone(),
                    provider,
                    key: key.clone(),
                    result: ReadState::Unusable { detail },
                }
            }
        };
        per_target.push(entry);
    }

    let verified = match (&agreed, &witness) {
        (Some(_), Some(anchor)) => {
            // Keep going on failure: a disagreement between destinations is
            // reported even when the local chain also fails to match.
            verify_checkpoint(
                chain_path,
                anchor.clone(),
                &key,
                &chain_of(config, chain_path),
            )
            .ok()
        }
        _ => None,
    };

    Ok(FanoutVerification {
        key,
        per_target,
        agreed,
        unusable,
        conflicts,
        verified,
    })
}

/// Convenience for callers that only need the exit status.
pub fn is_ok(results: &[TargetPublish]) -> bool {
    results.iter().all(|r| {
        matches!(
            r.state,
            PublishState::Confirmed | PublishState::AlreadyAnchored
        )
    })
}
