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
        and Ephor's audit database (ephor-audit-v1); writes nostoi-v1.\n\n\
        Exit status: 0 intact, 1 broken, 2 error."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Inspect audit/outbox database schema metadata without migrating it
    #[cfg(feature = "sqlite")]
    Schema {
        path: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Verify chains; name the first record that does not fit
    Verify {
        #[arg(required = true)]
        paths: Vec<PathBuf>,
        /// Format (default: detected): nostoi-v1, weftmark-ledger-v1, ephor-audit-v1
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
    /// Sign a statement about the current head with ssh-keygen -Y sign
    ///
    /// Attesting is a human step: a passphrase-protected key needs a terminal,
    /// an agent, or no passphrase. Nothing signs unattended.
    Attest {
        path: PathBuf,
        /// Private key to sign with; never passed to a shell
        #[arg(long, default_value = "~/.ssh/id_ed25519")]
        key: PathBuf,
        /// Identity to record, matching an allowed_signers entry
        #[arg(long)]
        principal: String,
        /// Chain identity to record (default: the chain path)
        #[arg(long, default_value = "")]
        chain_id: String,
        /// Format (default: detected)
        #[arg(long)]
        format: Option<Format>,
        /// Signing namespace, which scopes the signature to this use of the key
        #[arg(long, default_value = nostoi::attestation::DEFAULT_NAMESPACE)]
        namespace: String,
        /// The remote checkpoint this head was also anchored at
        #[arg(long)]
        anchor_key: Option<String>,
        /// ssh-keygen to use
        #[arg(long, default_value = nostoi::attest::DEFAULT_PROGRAM)]
        program: PathBuf,
        /// Human label for what is being attested; signed into the document
        #[arg(long)]
        title: Option<String>,
        /// What is being attested beyond the position: a digest or a short
        /// description; signed into the document
        #[arg(long)]
        manifest: Option<String>,
        /// Who is attesting, in their own words. Signing this publishes it
        /// permanently, so leave it out unless linking the name is the point.
        #[arg(long)]
        author: Option<String>,
        /// Write a portable bundle here as well: document, signature and the
        /// fingerprint to pin, in one file to publish or hand over
        #[arg(long)]
        bundle: Option<PathBuf>,
        /// A note to put in the bundle for whoever reads it
        #[arg(long)]
        note: Option<String>,
        /// Sign and report, but do not write the sidecars
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        json: bool,
    },
    /// Check a bundle's signature and its pinned key, with no chain
    ///
    /// What a receiver does when a bundle arrives. Does not answer whether the
    /// document matches a local chain; use verify-attestation for that.
    VerifyBundle {
        path: PathBuf,
        /// An allowed_signers file naming --principal
        #[arg(long)]
        allowed_signers: PathBuf,
        /// The signing identity to verify
        #[arg(long)]
        principal: String,
        /// The key fingerprint to pin, SHA256:...
        #[arg(long)]
        fingerprint: Option<String>,
        /// The signing namespace the signature must have been made in
        #[arg(long, default_value = nostoi::attestation::DEFAULT_NAMESPACE)]
        namespace: String,
        /// ssh-keygen to use
        #[arg(long, default_value = nostoi::attest::DEFAULT_PROGRAM)]
        program: PathBuf,
        /// A file of revoked SHA256 fingerprints, one per line. A revoked key is
        /// refused even when it is the pinned one.
        #[arg(long)]
        revoked: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Check an attestation's signature, its pinned key, and the chain
    ///
    /// Fails closed: a missing attestation, a bad signature, an unpinned key or a
    /// chain that no longer matches all fail.
    VerifyAttestation {
        path: PathBuf,
        /// An allowed_signers file naming --principal
        #[arg(long)]
        allowed_signers: PathBuf,
        /// The signing identity to verify
        #[arg(long)]
        principal: String,
        /// The key fingerprint to pin, SHA256:...
        #[arg(long)]
        fingerprint: Option<String>,
        /// Signing namespace the signature must have been made in
        #[arg(long, default_value = nostoi::attestation::DEFAULT_NAMESPACE)]
        namespace: String,
        /// ssh-keygen to use
        #[arg(long, default_value = nostoi::attest::DEFAULT_PROGRAM)]
        program: PathBuf,
        /// A file of revoked SHA256 fingerprints, one per line. A revoked key is
        /// refused even when it is the pinned one.
        #[arg(long)]
        revoked: Option<PathBuf>,
        /// Rewrite the document in canonical form, once the signature has been
        /// checked against it. Only ever touches formatting.
        #[arg(long)]
        canonicalize: bool,
        #[arg(long)]
        json: bool,
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
        #[cfg(feature = "sqlite")]
        Command::Schema { path, json } => {
            let info = nostoi::schema::inspect(&path).map_err(|e| e.to_string())?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string(&info).map_err(|e| e.to_string())?
                );
            } else {
                println!(
                    "{}: {} schema {} (supported {}), application_id {:#x}, format {}{}",
                    path.display(),
                    info.component,
                    info.schema_revision,
                    info.supported_revision,
                    info.application_id,
                    info.record_format,
                    if info.legacy_unversioned {
                        " [legacy, unversioned]"
                    } else {
                        ""
                    }
                );
            }
            Ok(ExitCode::SUCCESS)
        }
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
                    json!({"seq": head.seq, "digest": head.digest, "format": report.format,
                           "attestation": attestation_json(&path, &report)})
                ),
                (Some(head), false) => println!("{} {}", head.seq, head.digest),
                (None, true) => println!(
                    "{}",
                    json!({"seq": 0, "digest": nostoi::GENESIS, "format": report.format})
                ),
                (None, false) => println!("0 {}", nostoi::GENESIS),
            }
            if !json {
                println!("  {}", attestation_summary(&path, &report));
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
        Command::Attest {
            path,
            key,
            principal,
            chain_id,
            format,
            namespace,
            anchor_key,
            title,
            manifest,
            author,
            bundle,
            note,
            program,
            dry_run,
            json,
        } => attest(
            &path,
            AttestOptions {
                key: &key,
                principal: &principal,
                chain_id: &chain_id,
                format,
                namespace: &namespace,
                anchor_key,
                title,
                manifest,
                author,
                bundle,
                note,
                program: &program,
                dry_run,
                json,
            },
        ),
        Command::VerifyBundle {
            path,
            allowed_signers,
            principal,
            fingerprint,
            namespace,
            program,
            revoked,
            json,
        } => verify_bundle(
            &path,
            VerifyOptions {
                allowed_signers: &allowed_signers,
                principal: &principal,
                fingerprint: fingerprint.as_deref(),
                namespace: &namespace,
                program: &program,
                revoked: revoked.as_deref(),
                canonicalize: false,
                json,
            },
        ),
        Command::VerifyAttestation {
            path,
            allowed_signers,
            principal,
            fingerprint,
            namespace,
            program,
            revoked,
            canonicalize,
            json,
        } => verify_attestation(
            &path,
            VerifyOptions {
                allowed_signers: &allowed_signers,
                principal: &principal,
                fingerprint: fingerprint.as_deref(),
                namespace: &namespace,
                program: &program,
                revoked: revoked.as_deref(),
                canonicalize,
                json,
            },
        ),
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

/// The attestation as JSON, for the read-only commands.
///
/// `signature` is reported as unchecked on purpose: these commands are not given
/// an allowed-signers file, so `nostoi verify-attestation` remains the only way to
/// establish that a signature is good.
fn attestation_json(path: &Path, report: &Report) -> Value {
    match nostoi::attest::present(path) {
        Some(read) => {
            let attestation = read.attestation;
            let head = report.head.as_ref().map(|head| head.seq).unwrap_or(0);
            json!({
                "present": true,
                "signature": "unchecked",
                "document": attestation.digest().ok(),
                "chain": attestation.chain,
                "format": attestation.format,
                "seq": attestation.seq,
                "digest": attestation.digest,
                "anchored_at": attestation.anchored_at,
                "principal": attestation.principal,
                "fingerprint": attestation.fingerprint,
                "anchor_key": attestation.anchor_key,
                "covers_head": attestation.seq == head,
                "canonical_form": read.document.canonicality.is_canonical(),
            })
        }
        None => json!({
            "present": false,
            "signature": "unchecked",
            "missing": nostoi::attestation::Sidecars::for_chain(path).missing_description(),
        }),
    }
}

fn report_json(path: &Path, report: &Report) -> Value {
    let mut value = serde_json::to_value(report).unwrap_or_default();
    value["path"] = json!(path);
    if let Some(problem) = &report.problem {
        value["message"] = json!(problem.to_string());
    }
    value["attestation"] = attestation_json(path, report);
    value
}

/// A short description of a chain's attestation, for the read-only commands.
fn attestation_summary(path: &Path, report: &Report) -> String {
    nostoi::attest::summary(path, report.head.as_ref().map_or(0, |head| head.seq))
}

/// The options `attest` takes, gathered for the same reason as
/// [`VerifyOptions`].
struct AttestOptions<'a> {
    key: &'a Path,
    principal: &'a str,
    chain_id: &'a str,
    format: Option<Format>,
    namespace: &'a str,
    anchor_key: Option<String>,
    title: Option<String>,
    manifest: Option<String>,
    author: Option<String>,
    bundle: Option<PathBuf>,
    note: Option<String>,
    program: &'a Path,
    dry_run: bool,
    json: bool,
}

/// `nostoi attest`: sign the current head and report what to install.
fn attest(path: &Path, options: AttestOptions<'_>) -> Result<ExitCode, String> {
    let AttestOptions {
        key,
        principal,
        chain_id,
        format,
        namespace,
        anchor_key,
        title,
        manifest,
        author,
        bundle,
        note,
        program,
        dry_run,
        json,
    } = options;
    let mut signer = nostoi::attest::Signer::new(
        nostoi::attest::expand_home(key).map_err(|e| e.to_string())?,
        principal,
    );
    signer.namespace = namespace.to_string();
    signer.program = program.to_path_buf();
    let signed = nostoi::attest::sign(path, chain_id, format, &signer, anchor_key)
        .map_err(|e| e.to_string())?;
    let signed = if title.is_some() || manifest.is_some() || author.is_some() {
        let described = nostoi::attestation::Described {
            title,
            manifest,
            author,
        };
        nostoi::attest::with_description(signed, described).map_err(|e| e.to_string())?
    } else {
        signed
    };
    let bundle_path = match &bundle {
        Some(bundle_path) => {
            let bundle =
                nostoi::attest::bundle(&signed, namespace, note).map_err(|e| e.to_string())?;
            nostoi::attest::write_bundle(bundle_path, &bundle).map_err(|e| e.to_string())?;
            Some(bundle_path.clone())
        }
        None => None,
    };

    let sidecars = if dry_run {
        None
    } else {
        Some(nostoi::attest::write(path, &signed).map_err(|e| e.to_string())?)
    };
    let attestation = &signed.attestation;
    if json {
        println!(
            "{}",
            json!({
                "seq": attestation.seq,
                "digest": attestation.digest,
                "chain": attestation.chain,
                "format": attestation.format,
                "anchored_at": attestation.anchored_at,
                "principal": attestation.principal,
                "fingerprint": attestation.fingerprint,
                "document": attestation.digest().ok(),
                "anchor_key": attestation.anchor_key,
                "namespace": namespace,
                "written": sidecars.as_ref().map(|s| s.document.display().to_string()),
                "signature": sidecars.as_ref().map(|s| s.signature.display().to_string()),
                "replaced_seq": signed.replaced.as_ref().map(|old| old.seq),
                "allowed_signers_line": signed.allowed_signers_line,
                "title": signed.attestation.title,
                "manifest": signed.attestation.manifest,
                "author": signed.attestation.author,
                "bundle": bundle_path.as_ref().map(|p| p.display().to_string()),
                "dry_run": dry_run,
            })
        );
    } else {
        println!(
            "attested seq={} digest={} by {} with key {}",
            attestation.seq, attestation.digest, attestation.principal, attestation.fingerprint
        );
        println!("  timestamp {}", attestation.anchored_at);
        match &sidecars {
            Some(paths) => {
                println!("  document   {}", paths.document.display());
                println!("  signature  {}", paths.signature.display());
            }
            None => println!("  dry run: nothing written"),
        }
        for (label, value) in [
            ("title", &signed.attestation.title),
            ("manifest", &signed.attestation.manifest),
            ("author", &signed.attestation.author),
        ] {
            if let Some(value) = value {
                println!("  {label:<10} {value}");
            }
        }
        if let Some(bundle_path) = &bundle_path {
            println!(
                "\nbundle {} carries the document, the signature and the fingerprint to pin.\n\
                 Publish it where it cannot be retracted: a signature proves authorship, \
                 not when.",
                bundle_path.display()
            );
        }
        if let Some(replaced) = &signed.replaced {
            println!(
                "  replaced an attestation of seq={} signed by {}",
                replaced.seq, replaced.principal
            );
        }
        println!("\nadd this line to your allowed_signers file:");
        println!("  {}", signed.allowed_signers_line);
        let pin = format!(" --fingerprint {}", attestation.fingerprint);
        println!(
            "\nthen check it: nostoi verify-attestation {} --allowed-signers FILE \
             --principal {}{}",
            path.display(),
            attestation.principal,
            pin
        );
        println!(
            "pin that fingerprint somewhere the host cannot rewrite, and publish the \
             signature somewhere it cannot be retracted: a signature proves authorship, \
             not when."
        );
    }
    Ok(ExitCode::SUCCESS)
}

/// `nostoi verify-bundle`: check a bundle's signature and pinned key.
///
/// No chain is involved, so this answers "is this a genuine attestation by a key I
/// trust, and what does it claim" — which is the question a receiver has when a
/// bundle arrives. The document is printed so it can be read without opening the
/// file, and its digest so it can be cited.
fn verify_bundle(path: &Path, options: VerifyOptions<'_>) -> Result<ExitCode, String> {
    let (fingerprint, json) = (options.fingerprint, options.json);
    let bundle = nostoi::attest::read_bundle(path).map_err(|e| e.to_string())?;
    let verifier = options.verifier()?;

    match nostoi::attest::verify_bundle(&bundle, &verifier) {
        Ok(checked) => {
            let document = &checked.bundle.document;
            if json {
                println!(
                    "{}",
                    json!({
                        "path": path,
                        "ok": true,
                        "signature": "verified",
                        "bundle": checked.bundle.v,
                        "namespace": checked.bundle.namespace,
                        "principal": document.principal,
                        "fingerprint": checked.fingerprint,
                        "anchored_at": document.anchored_at,
                        "chain": document.chain,
                        "format": document.format,
                        "seq": document.seq,
                        "digest": document.digest,
                        "anchor_key": document.anchor_key,
                        "title": document.title,
                        "manifest": document.manifest,
                        "author": document.author,
                        "note": checked.bundle.note,
                        "document_digest": document.digest,
                        "signed_bytes": String::from_utf8_lossy(&checked.canonical_bytes),
                    })
                );
            } else {
                println!(
                    "✓ {}: bundle verified, signed by {} with key {}",
                    path.display(),
                    document.principal,
                    checked.fingerprint
                );
                println!("  attested {} at {}", document.chain, document.anchored_at);
                println!(
                    "  position seq={} digest={}",
                    document.seq,
                    &document.digest[..document.digest.len().min(16)]
                );
                for (label, value) in [
                    ("title", &document.title),
                    ("manifest", &document.manifest),
                    ("author", &document.author),
                    ("anchor", &document.anchor_key),
                ] {
                    if let Some(value) = value {
                        println!("  {label:<9} {value}");
                    }
                }
                if let Some(note) = &checked.bundle.note {
                    println!("  note      {note}");
                }
                println!(
                    "\n  this bundle says nothing about a local chain; run \
                     verify-attestation once you have one"
                );
            }
            if fingerprint.is_none() {
                eprintln!(
                    "  note: no --fingerprint was pinned, so the allowed_signers file is the \
                     only trust anchor"
                );
            }
            Ok(ExitCode::SUCCESS)
        }
        Err(error) => {
            if json {
                println!(
                    "{}",
                    json!({"path": path, "ok": false, "signature": "refused",
                           "error": error.to_string()})
                );
            } else {
                eprintln!("✗ {}: {error}", path.display());
            }
            Ok(ExitCode::from(1))
        }
    }
}

/// The options `verify-attestation` takes, gathered for the same reason.
struct VerifyOptions<'a> {
    allowed_signers: &'a Path,
    principal: &'a str,
    fingerprint: Option<&'a str>,
    namespace: &'a str,
    program: &'a Path,
    revoked: Option<&'a Path>,
    canonicalize: bool,
    json: bool,
}

impl VerifyOptions<'_> {
    /// The verifier, with revocations applied.
    fn verifier(&self) -> Result<nostoi::attest::Verifier, String> {
        let mut verifier = nostoi::attest::Verifier::new(self.allowed_signers, self.principal);
        verifier.namespace = self.namespace.to_string();
        verifier.program = self.program.to_path_buf();
        verifier.fingerprint = self.fingerprint.map(str::to_string);
        if let Some(path) = self.revoked {
            let revoked = nostoi::attest::Revocations::read(path).map_err(|e| e.to_string())?;
            verifier = verifier.revoking(revoked);
        }
        Ok(verifier)
    }
}

/// `nostoi verify-attestation`: signature, pinned key and chain, failing closed.
fn verify_attestation(path: &Path, options: VerifyOptions<'_>) -> Result<ExitCode, String> {
    let canonicalize = options.canonicalize;
    let json = options.json;
    let fingerprint = options.fingerprint;
    let verifier = options.verifier()?;

    match nostoi::attest::verify(path, &verifier) {
        Ok(checked) => {
            // Repair once, before printing, so a write never hides inside a
            // serialization and the report describes what it just did.
            let repaired = match canonicalize && !checked.document.canonicality.is_canonical() {
                true => Some(
                    nostoi::attest::canonicalize(path, &checked.document)
                        .map_err(|e| e.to_string())?,
                ),
                false => None,
            };
            let signed_bytes = checked
                .attestation
                .canonical_bytes()
                .ok()
                .and_then(|bytes| String::from_utf8(bytes).ok());
            if json {
                println!(
                    "{}",
                    json!({
                        "path": path,
                        "ok": true,
                        "signature": "verified",
                        "coverage": match checked.coverage {
                            nostoi::attestation::Coverage::Current => json!("current"),
                            nostoi::attestation::Coverage::Stale { ahead_by } => {
                                json!({"stale": true, "ahead_by": ahead_by})
                            }
                            other => json!({ "unusable": format!("{other:?}") }),
                        },
                        "principal": checked.attestation.principal,
                        "fingerprint": checked.attestation.fingerprint,
                        "anchored_at": checked.attestation.anchored_at,
                        "seq": checked.attestation.seq,
                        "digest": checked.attestation.digest,
                        "head": checked.head,
                        "anchor_key": checked.attestation.anchor_key,
                        "canonical_form": checked.document.canonicality.is_canonical(),
                        "canonicalized": repaired,
                        "signed_bytes": signed_bytes,
                    })
                );
            } else {
                println!(
                    "✓ {}: signature verified, signed by {} with key {}",
                    path.display(),
                    checked.attestation.principal,
                    checked.attestation.fingerprint
                );
                println!(
                    "  attested seq={} at {}",
                    checked.attestation.seq, checked.attestation.anchored_at
                );
                match checked.coverage {
                    nostoi::attestation::Coverage::Current => {
                        println!("  covers the current head")
                    }
                    nostoi::attestation::Coverage::Stale { ahead_by } => println!(
                        "  the chain has advanced {ahead_by} record(s) since; the attestation \
                         still covers the intact prefix it names"
                    ),
                    other => println!("  coverage: {other:?}"),
                }
                if let Some(key) = &checked.attestation.anchor_key {
                    println!("  also anchored at {key}");
                }
                // Formatting is never a security failure, so it is a note rather
                // than an error, and repairable.
                if !checked.document.canonicality.is_canonical() {
                    println!(
                        "  note: the document is formatted, not canonical; the signature \
                         covers the same content either way"
                    );
                    match repaired {
                        Some(true) => {
                            println!("  rewrote it in canonical form; the signature still applies")
                        }
                        Some(false) => println!("  already canonical"),
                        None => println!(
                            "  fix with: nostoi verify-attestation {} --canonicalize",
                            path.display()
                        ),
                    }
                }
                // Print what was actually verified, so it can be diffed against
                // what the operator believes they signed.
                match &signed_bytes {
                    Some(bytes) => println!("\n  signed bytes:\n{bytes}"),
                    None => println!("\n  signed bytes: <could not be recomputed>"),
                }
            }
            // A stale attestation is a pass with a caveat, not a failure.
            Ok(ExitCode::SUCCESS)
        }
        Err(error) => {
            if json {
                println!(
                    "{}",
                    json!({"path": path, "ok": false, "signature": "refused",
                           "error": error.to_string()})
                );
            } else {
                eprintln!("✗ {}: {error}", path.display());
                if fingerprint.is_none() {
                    eprintln!(
                        "  note: no --fingerprint was pinned, so the allowed_signers file is \
                         the only trust anchor; pin the fingerprint to refuse a substituted key"
                    );
                }
            }
            Ok(ExitCode::from(1))
        }
    }
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
    println!("  {}", attestation_summary(path, report));
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
