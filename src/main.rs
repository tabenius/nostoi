//! `nostoi`: verify, append to, stream and browse tamper-evident audit chains.
//!
//! Exit status: 0 when every chain verifies, 1 when one is broken (or would be
//! extended while broken), 2 on any other error (unreadable file, bad input).

use clap::{Parser, Subcommand};
use nostoi::{Draft, Entry, Format, Report};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

#[derive(Parser)]
#[command(
    name = "nostoi",
    version,
    about = "Tamper-evident audit chains: verify, append, stream and browse them",
    long_about = "Tamper-evident audit chains: verify, append, stream and browse them.\n\n\
        Reads nostoi-v1 (JSONL or SQLite), WeftMark's ledger.jsonl (weftmark-ledger-v1) \
        and Ephor's audit database (kagp-audit-v1); writes nostoi-v1.\n\n\
        Exit status: 0 intact, 1 broken, 2 error."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Verify chains; name the first record that does not fit
    Verify {
        #[arg(required = true)]
        paths: Vec<PathBuf>,
        /// Format (default: detected): nostoi-v1, weftmark-ledger-v1, kagp-audit-v1
        #[arg(long)]
        format: Option<Format>,
        /// One JSON report per line
        #[arg(long)]
        json: bool,
    },
    /// Append a nostoi-v1 record (JSONL, or the SQLite store for .sqlite/.db)
    Append {
        path: PathBuf,
        /// What happened, e.g. tool.call, task.claim, skill.run
        #[arg(long)]
        kind: String,
        /// Who: an agent, person or service, e.g. agent:claude
        #[arg(long)]
        actor: Option<String>,
        /// What it is about: a Change Set, session, run…
        #[arg(long)]
        subject: Option<String>,
        /// The record body: a JSON object, @FILE, or - for stdin
        #[arg(long, default_value = "{}")]
        body: String,
        /// Timestamp (RFC 3339; default now)
        #[arg(long)]
        at: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Print the verified head (position and digest), to anchor elsewhere
    Head {
        path: PathBuf,
        #[arg(long)]
        format: Option<Format>,
        #[arg(long)]
        json: bool,
    },
    /// List a chain's records, or show one in full
    Show {
        path: PathBuf,
        /// Position of the record to show in full
        seq: Option<u64>,
        #[arg(long)]
        format: Option<Format>,
        #[arg(long)]
        json: bool,
    },
    /// Stream verified records as JSON lines; --follow waits for new ones
    Log {
        path: PathBuf,
        #[arg(long)]
        format: Option<Format>,
        /// Keep running and print records as they are appended
        #[arg(short, long)]
        follow: bool,
        /// Polling interval for --follow, in milliseconds
        #[arg(long, default_value_t = 1000)]
        interval: u64,
        /// Start after this position
        #[arg(long, default_value_t = 0)]
        after: u64,
    },
    /// Browse a chain in the terminal
    #[cfg(feature = "tui")]
    Tui {
        path: PathBuf,
        #[arg(long)]
        format: Option<Format>,
    },
    /// List the formats Nostoi reads
    Formats,
}

fn main() -> ExitCode {
    match run(Cli::parse().command) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("nostoi: {error}");
            ExitCode::from(2)
        }
    }
}

fn run(command: Command) -> Result<ExitCode, String> {
    match command {
        Command::Verify {
            paths,
            format,
            json,
        } => {
            let mut broken = false;
            let mut failed = false;
            for path in &paths {
                match nostoi::verify(path, format) {
                    Ok(report) => {
                        broken |= !report.ok;
                        if json {
                            println!("{}", report_json(path, &report));
                        } else {
                            print_report(path, &report);
                        }
                    }
                    Err(error) => {
                        failed = true;
                        if json {
                            println!(
                                "{}",
                                json!({"path": path, "ok": false, "error": error.to_string()})
                            );
                        } else {
                            eprintln!("✗ {}: {error}", path.display());
                        }
                    }
                }
            }
            Ok(exit(failed, broken))
        }
        Command::Append {
            path,
            kind,
            actor,
            subject,
            body,
            at,
            json,
        } => {
            let body = read_body(&body)?;
            let draft = Draft {
                actor: actor.as_deref(),
                kind: &kind,
                subject: subject.as_deref(),
                body,
                at,
            };
            match nostoi::append(&path, draft) {
                Ok(entry) => {
                    if json {
                        println!("{}", json!({"seq": entry.seq, "digest": entry.digest}));
                    } else {
                        println!("{} {}", entry.seq, entry.digest);
                    }
                    Ok(ExitCode::SUCCESS)
                }
                Err(nostoi::Error::Broken(problem)) => {
                    eprintln!(
                        "nostoi: {}: not appended, the chain is broken: {problem}",
                        path.display()
                    );
                    Ok(ExitCode::from(1))
                }
                Err(error) => Err(error.to_string()),
            }
        }
        Command::Head { path, format, json } => {
            let report = nostoi::verify(&path, format).map_err(|e| e.to_string())?;
            if !report.ok {
                if json {
                    println!("{}", report_json(&path, &report));
                } else {
                    print_report(&path, &report);
                }
                return Ok(ExitCode::from(1));
            }
            match (&report.head, json) {
                (Some(head), true) => println!(
                    "{}",
                    json!({"seq": head.seq, "digest": head.digest, "format": report.format})
                ),
                (Some(head), false) => println!("{} {}", head.seq, head.digest),
                (None, true) => println!(
                    "{}",
                    json!({"seq": 0, "digest": nostoi::GENESIS, "format": report.format})
                ),
                (None, false) => println!("0 {}", nostoi::GENESIS),
            }
            Ok(ExitCode::SUCCESS)
        }
        Command::Show {
            path,
            seq,
            format,
            json,
        } => {
            let loaded = nostoi::open(&path, format).map_err(|e| e.to_string())?;
            let report = loaded.verify();
            let trusted = report.verified;
            match seq {
                Some(seq) => {
                    let entry = loaded
                        .entries
                        .iter()
                        .find(|e| e.seq == seq)
                        .ok_or_else(|| format!("no record {seq}"))?;
                    let verdict = if seq <= trusted {
                        "verified"
                    } else {
                        "NOT verified"
                    };
                    if json {
                        println!(
                            "{}",
                            json!({"seq": seq, "verified": seq <= trusted, "record": entry.record})
                        );
                    } else {
                        println!("record {seq} ({verdict})");
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&entry.record).unwrap_or_default()
                        );
                    }
                }
                None => {
                    for entry in &loaded.entries {
                        if json {
                            println!("{}", entry_json(entry, entry.seq <= trusted));
                        } else {
                            println!("{}", entry_line(entry, entry.seq <= trusted));
                        }
                    }
                    if !json {
                        print_report(&path, &report);
                    }
                }
            }
            Ok(if report.ok {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            })
        }
        Command::Log {
            path,
            format,
            follow,
            interval,
            after,
        } => log(&path, format, follow, interval, after),
        #[cfg(feature = "tui")]
        Command::Tui { path, format } => {
            nostoi::tui::run(&path, format).map_err(|e| e.to_string())?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Formats => {
            for format in Format::ALL {
                println!("{:<20} {}", format.name(), format.describe());
            }
            Ok(ExitCode::SUCCESS)
        }
    }
}

/// Print verified records after `after` as JSON lines; with `follow`, keep
/// polling. A record is printed only once the chain up to it verifies, and a
/// break ends the stream (exit 1): a consumer never receives an unverified
/// record.
fn log(
    path: &Path,
    format: Option<Format>,
    follow: bool,
    interval: u64,
    after: u64,
) -> Result<ExitCode, String> {
    let mut printed = after;
    let stdout = std::io::stdout();
    loop {
        let loaded = match nostoi::open(path, format) {
            Ok(loaded) => loaded,
            Err(error) if follow && !path.exists() => {
                let _ = error;
                std::thread::sleep(Duration::from_millis(interval));
                continue;
            }
            Err(error) => return Err(error.to_string()),
        };
        let report = loaded.verify();
        let mut out = stdout.lock();
        let from = printed;
        for entry in loaded
            .entries
            .iter()
            .filter(|e| e.seq > from && e.seq <= report.verified)
        {
            if writeln!(out, "{}", entry_json(entry, true)).is_err() {
                return Ok(ExitCode::SUCCESS); // the reader went away
            }
            printed = entry.seq;
        }
        let _ = out.flush();
        drop(out);
        if let Some(problem) = &report.problem {
            // A trailing partial line may be a write in progress: wait for it.
            let in_progress = matches!(problem, nostoi::Problem::Unreadable { at, .. } if *at == report.records + 1);
            if !(follow && in_progress) {
                eprintln!("nostoi: {}: {problem}", path.display());
                return Ok(ExitCode::from(1));
            }
        }
        if !follow {
            return Ok(ExitCode::SUCCESS);
        }
        std::thread::sleep(Duration::from_millis(interval));
    }
}

fn read_body(body: &str) -> Result<Value, String> {
    let text = if body == "-" {
        let mut text = String::new();
        std::io::stdin()
            .read_to_string(&mut text)
            .map_err(|e| format!("stdin: {e}"))?;
        text
    } else if let Some(file) = body.strip_prefix('@') {
        std::fs::read_to_string(file).map_err(|e| format!("{file}: {e}"))?
    } else {
        body.to_string()
    };
    serde_json::from_str(&text).map_err(|e| format!("--body is not JSON: {e}"))
}

fn exit(failed: bool, broken: bool) -> ExitCode {
    if failed {
        ExitCode::from(2)
    } else if broken {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

fn report_json(path: &Path, report: &Report) -> Value {
    let mut value = serde_json::to_value(report).unwrap_or_default();
    value["path"] = json!(path);
    if let Some(problem) = &report.problem {
        value["message"] = json!(problem.to_string());
    }
    value
}

fn print_report(path: &Path, report: &Report) {
    match &report.problem {
        None => println!(
            "✓ {} ({}): {} records intact, head {}",
            path.display(),
            report.format,
            report.records,
            report
                .head
                .as_ref()
                .map_or("(empty)".to_string(), |h| format!("{} {}", h.seq, h.digest)),
        ),
        Some(problem) => println!(
            "✗ {} ({}): {problem}; {}",
            path.display(),
            report.format,
            nostoi::chain::intact(report.verified),
        ),
    }
}

fn entry_json(entry: &Entry, verified: bool) -> Value {
    json!({
        "seq": entry.seq,
        "at": entry.at,
        "actor": entry.actor,
        "kind": entry.kind,
        "subject": entry.subject,
        "digest": entry.digest,
        "verified": verified,
        "record": entry.record,
    })
}

fn entry_line(entry: &Entry, verified: bool) -> String {
    format!(
        "{} {:>6}  {:<24}  {:<18}  {:<28}  {}  {}",
        if verified { "✓" } else { "✗" },
        entry.seq,
        entry.at.as_deref().unwrap_or("-"),
        entry.actor.as_deref().unwrap_or("-"),
        entry.kind,
        entry.subject.as_deref().unwrap_or("-"),
        entry.digest.get(..12).unwrap_or(&entry.digest),
    )
}
