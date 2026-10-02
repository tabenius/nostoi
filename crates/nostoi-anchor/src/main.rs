//! Command-line tool to anchor a Nostoi chain head to S3/R2.
//!
//! One destination, or several at once from a target file. The fan-out path
//! exists because one destination is one answer to "was this chain rewritten?",
//! and that destination is usually one vendor and one account.
use clap::Parser;
use nostoi_anchor::anchor::{AnchorOptions, LockMode};
use nostoi_anchor::fanout::{self, Fanout, PublishState};
use nostoi_anchor::s3::{Client, Credentials, Provider};
use nostoi_anchor::Error;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[derive(Parser, Debug)]
#[command(
    name = "nostoi-anchor",
    about = "Anchor a chain head to S3-compatible storage (S3 Object Lock or R2 bucket locks)",
    after_help = "\
Destinations:
  --endpoint/--bucket address one destination. --targets addresses several from a
  JSON file, which is how an anchor stops depending on a single vendor: every
  destination must agree before verification trusts any of them.

Exit codes:
  0  every destination confirmed, or verification succeeded
  1  usage or configuration error, or verification did not succeed
  2  an upload may have landed; its durable intent survives, retry it
  3  an object is stored but its identity or retention is unconfirmed
  4  destinations disagreed about the chain, or verification needed a key it did not get

Examples:
  nostoi-anchor audit.sqlite --endpoint https://s3.us-west-2.amazonaws.com \\
    --bucket checkpoints --region us-west-2 --lock compliance

  nostoi-anchor audit.sqlite --targets anchors.json --outbox-dir /var/lib/nostoi/outbox

  nostoi-anchor audit.sqlite --targets anchors.json --verify --key heads/....json
"
)]
struct Args {
    /// Path to the chain to anchor (JSONL or SQLite).
    chain: PathBuf,
    /// Verify the local chain against an existing trusted remote checkpoint.
    /// Requires --key and --chain-id; does not upload an object.
    #[arg(long, conflicts_with = "lock")]
    verify: bool,
    /// Durable SQLite anchor outbox, separate from the audit chain.
    #[cfg(feature = "sqlite")]
    #[arg(long, conflicts_with = "verify")]
    outbox: Option<PathBuf>,
    /// S3 endpoint, e.g. https://s3.us-west-2.amazonaws.com or https://<account>.r2.cloudflarestorage.com
    #[arg(long)]
    endpoint: String,
    /// Bucket name
    #[arg(long)]
    bucket: String,
    /// AWS region (use 'auto' for R2)
    #[arg(long, default_value = "auto")]
    region: String,
    /// Use path-style URLs (needed for some local S3 emulators)
    #[arg(long)]
    path_style: bool,
    /// Object key to write; if empty, one is generated from the chain
    #[arg(long, default_value = "")]
    key: String,
    /// Chain identifier to record in the anchor (defaults to chain path)
    #[arg(long, default_value = "")]
    chain_id: String,
    /// Format name to record (e.g. nostoi-v1)
    #[arg(long, default_value = "nostoi-v1")]
    format: String,
    /// Only write if the key does not already exist (If-None-Match: *)
    #[arg(long, default_value_t = true)]
    only_if_absent: bool,
    /// Apply an object lock: governance or compliance (S3 only; forbidden on R2)
    #[arg(long)]
    lock: Option<String>,
    /// Days to retain when locking
    #[arg(long, default_value_t = 365)]
    retain_days: i64,
    /// Publish to several destinations from a JSON target file instead of
    /// --endpoint/--bucket. See docs/ANCHOR-FANOUT.md.
    #[arg(long)]
    targets: Option<PathBuf>,
    /// Directory of durable outboxes, one per destination (<name>.sqlite).
    /// Without it an interrupted upload cannot be retried with its exact bytes.
    #[cfg(feature = "sqlite")]
    #[arg(long, requires = "targets")]
    outbox_dir: Option<PathBuf>,
    /// systemd Credentials= directory holding the access key, secret and
    /// optional session token. In a fan-out each destination may name its own
    /// subdirectory, so one credential cannot reach two destinations.
    #[arg(long)]
    credentials_dir: Option<PathBuf>,
    /// Print the result as JSON
    #[arg(long, default_value_t = true)]
    json: bool,
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err((error, code)) => {
            eprintln!("nostoi-anchor: {error}");
            code
        }
    }
}

type Failure = (Error, ExitCode);

fn run() -> Result<ExitCode, Failure> {
    let args = Args::parse();
    match &args.targets {
        Some(path) => run_fanout(&args, path),
        None => run_single(&args),
    }
}

fn fail(error: Error) -> Failure {
    let code = match error {
        Error::UploadUncertain { .. } => ExitCode::from(2),
        Error::AnchorUnconfirmed { .. } => ExitCode::from(3),
        _ => ExitCode::FAILURE,
    };
    (error, code)
}

/// One destination, addressed directly.
fn run_single(args: &Args) -> Result<ExitCode, Failure> {
    let credentials = load_credentials(args.credentials_dir.as_deref()).map_err(fail)?;
    let provider = Provider::detect(&args.endpoint);
    let client = Client::new(
        &args.endpoint,
        &args.bucket,
        &args.region,
        args.path_style || provider == Provider::R2,
        credentials,
    )
    .map_err(fail)?;

    if args.verify {
        let result =
            nostoi_anchor::anchor::verify_anchor(&args.chain, &client, &args.key, &args.chain_id)
                .map_err(fail)?;
        println!(
            "{}",
            serde_json::to_string_pretty(&result).map_err(|e| fail(Error::S3(e.to_string())))?
        );
        return Ok(ExitCode::SUCCESS);
    }

    let lock_mode = parse_lock(args.lock.as_deref()).map_err(fail)?;
    let options = AnchorOptions {
        key: args.key.clone(),
        format: args.format.clone(),
        chain_id: args.chain_id.clone(),
        only_if_absent: args.only_if_absent,
        lock: lock_mode,
        retain_days: args.retain_days,
    };

    #[cfg(feature = "sqlite")]
    let anchor = if let Some(path) = &args.outbox {
        nostoi_anchor::outbox::Outbox::open(path, &args.chain)
            .map_err(fail)?
            .anchor_head(&args.chain, &client, options, provider)
            .map_err(fail)?
    } else {
        nostoi_anchor::anchor::anchor_head(&args.chain, &client, options, provider).map_err(fail)?
    };
    #[cfg(not(feature = "sqlite"))]
    let anchor = nostoi_anchor::anchor::anchor_head(&args.chain, &client, options, provider)
        .map_err(fail)?;

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&anchor)
                .map_err(|error| fail(Error::S3(format!("serialize: {error}"))))?
        );
    } else {
        println!(
            "anchored seq={} digest={} key={}",
            anchor.seq, anchor.digest, anchor.key
        );
    }
    Ok(ExitCode::SUCCESS)
}

/// Several destinations from one target file.
fn run_fanout(args: &Args, path: &Path) -> Result<ExitCode, Failure> {
    let mut config = Fanout::load(path).map_err(fail)?;
    // An explicit flag wins over the file, so an operator can point a stored
    // configuration at a different chain without editing it.
    if !args.chain_id.is_empty() {
        config.chain_id = args.chain_id.clone();
    }
    if !args.key.is_empty() {
        config.key = args.key.clone();
    }
    if args.verify {
        return verify_fanout(args, config);
    }

    #[cfg(feature = "sqlite")]
    let outbox_dir = args.outbox_dir.as_deref();
    #[cfg(not(feature = "sqlite"))]
    let outbox_dir: Option<&Path> = None;

    let results = fanout::publish(
        &args.chain,
        &config,
        args.credentials_dir.as_deref(),
        outbox_dir,
    )
    .map_err(fail)?;

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&results).map_err(|e| fail(Error::S3(e.to_string())))?
        );
    } else {
        print_publish_table(&results);
    }
    Ok(match worst_state(&results) {
        PublishState::Confirmed | PublishState::AlreadyAnchored => ExitCode::SUCCESS,
        PublishState::Unresolved => ExitCode::from(2),
        PublishState::Rejected => ExitCode::from(3),
    })
}

fn verify_fanout(args: &Args, config: Fanout) -> Result<ExitCode, Failure> {
    let result =
        fanout::verify(&args.chain, &config, args.credentials_dir.as_deref()).map_err(fail)?;
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&result).map_err(|e| fail(Error::S3(e.to_string())))?
        );
    } else {
        print_verification(&result);
    }
    Ok(if !result.conflicts.is_empty() {
        // Not a local-chain problem, so a distinct code: this one means the
        // destinations themselves are telling different stories.
        ExitCode::from(4)
    } else if result.is_ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

fn worst_state(results: &[fanout::TargetPublish]) -> PublishState {
    let rank = |state: &PublishState| match state {
        PublishState::Confirmed | PublishState::AlreadyAnchored => 0,
        PublishState::Unresolved => 1,
        PublishState::Rejected => 2,
    };
    results
        .iter()
        .map(|result| rank(&result.state))
        .max()
        .map_or(PublishState::Confirmed, |worst| {
            results
                .iter()
                .find(|result| rank(&result.state) == worst)
                .map_or(PublishState::Confirmed, |result| result.state)
        })
}

fn print_publish_table(results: &[fanout::TargetPublish]) {
    println!(
        "{:<16} {:<8} {:<16} {:<10} KEY",
        "TARGET", "PROVIDER", "STATE", "DURABLE"
    );
    for result in results {
        println!(
            "{:<16} {:<8} {:<16} {:<10} {}",
            result.name,
            serde_json::to_value(result.provider)
                .ok()
                .and_then(|value| value.as_str().map(str::to_string))
                .unwrap_or_default(),
            serde_json::to_value(result.state)
                .ok()
                .and_then(|value| value.as_str().map(str::to_string))
                .unwrap_or_default(),
            if result.durable { "yes" } else { "no" },
            result.key
        );
        if let Some(detail) = &result.detail {
            println!("  {}\n", indent(detail, 18));
        }
    }
    let confirmed = results
        .iter()
        .filter(|result| {
            matches!(
                result.state,
                PublishState::Confirmed | PublishState::AlreadyAnchored
            )
        })
        .count();
    println!(
        "\n{confirmed} of {} destinations confirmed at seq={}",
        results.len(),
        results
            .first()
            .map(|result| result.seq)
            .filter(|seq| *seq > 0)
            .map(|seq| seq.to_string())
            .unwrap_or_else(|| "none".to_string())
    );
    if results.iter().any(|result| !result.durable) {
        println!(
            "warning: some destinations had no outbox, so an interrupted upload there \
             cannot be retried with its exact bytes"
        );
    }
}

fn print_verification(result: &nostoi_anchor::fanout::FanoutVerification) {
    use nostoi_anchor::fanout::ReadState;
    println!("{:<16} {:<8} ANSWER", "TARGET", "PROVIDER");
    for read in &result.per_target {
        let answer = match &read.result {
            ReadState::Agreed { identity } => format!(
                "seq={} digest={}",
                identity.seq,
                &identity.digest[..identity.digest.len().min(16)]
            ),
            ReadState::Conflict { identity } => format!(
                "CONFLICT: seq={} digest={}",
                identity.seq,
                &identity.digest[..identity.digest.len().min(16)]
            ),
            ReadState::Unusable { detail } => format!("unusable: {}", first_line(detail)),
        };
        println!(
            "{:<16} {:<8} {}",
            read.name,
            provider_name(read.provider),
            answer
        );
    }
    if let Some(identity) = &result.agreed {
        println!(
            "\nagreed checkpoint: chain={} format={} seq={} digest={}",
            identity.chain, identity.format, identity.seq, identity.digest
        );
    }
    match &result.verified {
        Some(verified) => println!(
            "local chain verified: {} records, head seq={} digest={}",
            verified.verified_records, verified.local_head.seq, verified.local_head.digest
        ),
        None => println!("local chain: NOT verified against any agreed checkpoint"),
    }
    if !result.unusable.is_empty() {
        println!(
            "\nwarning: {} destination(s) could not be read, so this rests on fewer \
             destinations than configured:",
            result.unusable.len()
        );
        for detail in &result.unusable {
            println!("  {}", first_line(detail));
        }
    }
    if !result.conflicts.is_empty() {
        println!("\nCONFLICT: destinations disagree about the chain:");
        for detail in &result.conflicts {
            println!("  {}", first_line(detail));
        }
    }
}

fn provider_name(provider: Provider) -> String {
    match provider {
        Provider::S3 => "s3".to_string(),
        Provider::R2 => "r2".to_string(),
    }
}

fn parse_lock(value: Option<&str>) -> Result<Option<LockMode>, Error> {
    value
        .map(|lock| match lock.to_ascii_lowercase().as_str() {
            "governance" => Ok(LockMode::Governance),
            "compliance" => Ok(LockMode::Compliance),
            other => Err(Error::Invalid(format!(
                "lock must be governance or compliance, got {other}"
            ))),
        })
        .transpose()
}

fn load_credentials(dir: Option<&Path>) -> Result<Credentials, Error> {
    match dir {
        Some(_) => fanout::credentials_for(
            &fanout::Target {
                name: "default".to_string(),
                endpoint: String::new(),
                bucket: String::new(),
                region: String::new(),
                path_style: false,
                provider: None,
                lock: None,
                retain_days: 0,
                credentials: None,
            },
            dir,
        ),
        None => Credentials::from_env(),
    }
}

fn first_line(text: &str) -> &str {
    text.lines().next().unwrap_or(text)
}

fn indent(text: &str, spaces: usize) -> String {
    let pad = " ".repeat(spaces);
    text.lines()
        .map(|line| format!("{pad}{line}"))
        .collect::<Vec<_>>()
        .join("\n")
}
