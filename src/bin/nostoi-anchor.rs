//! Command-line tool to anchor a Nostoi chain head to S3/R2.
use clap::Parser;
use nostoi::anchor::{AnchorOptions, LockMode};
use nostoi::s3::{Client, Credentials, Provider};
use nostoi::Error;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser, Debug)]
#[command(
    name = "nostoi-anchor",
    about = "Anchor a chain head to S3-compatible storage (S3 Object Lock or R2 bucket locks)"
)]
struct Args {
    /// Path to the chain to anchor (JSONL or SQLite).
    chain: PathBuf,
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
    /// Print the anchor as JSON
    #[arg(long, default_value_t = true)]
    json: bool,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("nostoi-anchor: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Error> {
    let args = Args::parse();
    let credentials = Credentials::from_env()?;
    let provider = Provider::detect(&args.endpoint);
    let client = Client::new(
        &args.endpoint,
        &args.bucket,
        &args.region,
        args.path_style || provider == Provider::R2,
        credentials,
    )?;

    let lock_mode = args
        .lock
        .as_deref()
        .map(|l| match l.to_ascii_lowercase().as_str() {
            "governance" => Ok(LockMode::Governance),
            "compliance" => Ok(LockMode::Compliance),
            other => Err(Error::Invalid(format!(
                "lock must be governance or compliance, got {other}"
            ))),
        })
        .transpose()?;

    let options = AnchorOptions {
        key: args.key,
        format: args.format,
        chain_id: args.chain_id,
        only_if_absent: args.only_if_absent,
        lock: lock_mode,
        retain_days: args.retain_days,
    };

    let anchor = nostoi::anchor::anchor_head(&args.chain, &client, options, provider)?;
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&anchor)
                .map_err(|error| Error::S3(format!("serialize: {error}")))?,
        );
    } else {
        println!(
            "anchored seq={} digest={} key={}",
            anchor.seq, anchor.digest, anchor.key
        );
    }
    Ok(())
}
