//! Long-lived writer: read the kernel ring buffer at `/dev/kmsg` and append
//! each record to a Nostoi SQLite store.
//!
//! This is the daemon half of the `/dev/kmsg` attachment — the transport loop,
//! which is deployment-specific. The reusable halves live in the library:
//! [`nostoi::kmsg`] parses the ring buffer, and
//! [`nostoi::sqlite::Store::open_verified`] is the long-lived writer that
//! verifies the chain once and then appends in O(log n).
//!
//! Reading `/dev/kmsg` does not consume records for anyone else
//! (`Documentation/ABI/testing/dev-kmsg`), so this runs alongside journald and
//! rsyslog without disturbing them. The device is `crw-r--r--`, so no
//! capability is needed. Because the reader holds the fd open, the kernel
//! reports every overwritten record with `-EPIPE`, and the 64-bit sequence
//! numbers say exactly how many were lost — that loss is written into the chain
//! as its own record rather than disappearing.
//!
//! Crash safety: every append commits with `synchronous=FULL`, so killing this
//! process never leaves a half-written record. The reader is safe to run
//! single-ingestor per store; a sidecar lock prevents competing readers from
//! duplicating messages. SQLite itself handles other appenders safely.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread::sleep;
use std::time::Duration;

use clap::Parser;
use nostoi::kmsg::{self, Event, Record};
use nostoi::{sqlite, Draft, Error};
use rusqlite::OptionalExtension;
use serde_json::{json, Map, Value};

#[derive(Parser, Debug)]
#[command(
    name = "kmsg-nostoi",
    about = "Append the Linux kernel ring buffer to a Nostoi SQLite chain"
)]
struct Args {
    /// SQLite store to append to (created and verified if missing).
    store: PathBuf,

    /// Kernel device (or saved complete-record fixture for replay testing).
    #[arg(long, default_value = "/dev/kmsg")]
    source: PathBuf,

    /// Boot identity file; the default is the kernel's per-boot UUID.
    #[arg(long, default_value = "/proc/sys/kernel/random/boot_id")]
    boot_id_file: PathBuf,

    /// Read everything currently buffered, then exit.
    #[arg(long)]
    once: bool,

    /// Poll interval when the buffer is empty, in milliseconds.
    #[arg(long, default_value_t = 250, value_parser = clap::value_parser!(u64).range(1..=1000))]
    poll_ms: u64,

    /// The actor name recorded on every entry.
    #[arg(long, default_value = "host:kmsg")]
    actor: String,

    /// Also echo each appended entry as a JSON line on stdout.
    #[arg(long)]
    print: bool,
}

fn main() -> ExitCode {
    let args = Args::parse();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("kmsg-nostoi: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: &Args) -> Result<(), Error> {
    let shutdown = Arc::new(AtomicBool::new(false));
    let _signals = ShutdownSignals::install(Arc::clone(&shutdown))?;
    let boot_id = std::fs::read_to_string(&args.boot_id_file)
        .map_err(|source| Error::Io {
            path: args.boot_id_file.display().to_string(),
            source,
        })?
        .trim()
        .to_string();
    if boot_id.len() != 36
        || !boot_id.bytes().enumerate().all(|(index, byte)| {
            if [8, 13, 18, 23].contains(&index) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
    {
        return Err(Error::Invalid("boot ID must be a UUID".into()));
    }
    let mut writer = Writer::open(&args.store, &args.actor)?;
    let lock_path = std::fs::canonicalize(&args.store).map_err(|source| Error::Io {
        path: args.store.display().to_string(),
        source,
    })?;
    let mut lock_path = lock_path.into_os_string();
    lock_path.push(".kmsg.lock");
    let _lease = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .map_err(|source| Error::Io {
            path: lock_path.to_string_lossy().into(),
            source,
        })?;
    _lease
        .try_lock()
        .map_err(|e| Error::Invalid(format!("another kmsg ingestor may own this store: {e}")))?;
    let previous = writer.checkpoint()?;
    let source = args.source.display().to_string();
    let resume_seq = previous
        .as_ref()
        .filter(|checkpoint| {
            checkpoint.boot_id.as_deref() == Some(&boot_id)
                && checkpoint.source.as_deref() == Some(&source)
        })
        .and_then(|checkpoint| checkpoint.kernel_seq);
    writer.boot_id = boot_id.clone();
    writer.source = source.clone();
    let mut reader =
        kmsg::Reader::open_path(&args.source).map_err(|error| to_nostoi(error, &args.source))?;
    if let Some(previous) = &previous {
        let reason = if previous.boot_id.as_deref() != Some(&boot_id) {
            "boot_changed_or_legacy_checkpoint"
        } else if previous.source.as_deref() != Some(&source) {
            "source_changed"
        } else if previous.clean_stop {
            "clean_restart"
        } else {
            "unclean_restart"
        };
        writer.marker(
            "kmsg.coverage.gap",
            json!({"reason":reason,
            "previous_boot_id":previous.boot_id, "previous_kmsg_seq":previous.kernel_seq,
            "resuming_after":resume_seq, "lost":null}),
        )?;
    }
    writer.marker(
        "kmsg.reader.start",
        json!({ "pid": std::process::id(), "last_kmsg_seq":resume_seq }),
    )?;
    let mut last_committed = resume_seq;
    let mut first_new = true;
    while !shutdown.load(Ordering::Relaxed) {
        match reader.next_event() {
            Ok(Event::Record(record)) => {
                let _ = reader.take_lost();
                if resume_seq.is_some_and(|seq| record.seq <= seq) {
                    continue;
                }
                if last_committed.is_some_and(|seq| record.seq <= seq) {
                    writer.marker("kmsg.coverage.gap", json!({"reason":"sequence_regressed",
                        "previous_kmsg_seq":last_committed, "observed_kmsg_seq":record.seq, "lost":null}))?;
                    return Err(Error::Invalid(
                        "kernel sequence regressed within one boot".into(),
                    ));
                }
                let lost = last_committed
                    .map_or(0, |seq| record.seq.saturating_sub(seq).saturating_sub(1));
                if first_new && last_committed.is_none() && record.seq > 0 {
                    writer.marker(
                        "kmsg.coverage.gap",
                        json!({"reason":"retained_buffer_starts_late",
                        "first_kmsg_seq":record.seq, "lost":null}),
                    )?;
                }
                if lost > 0 {
                    writer.append(
                        "kmsg.loss",
                        json!({ "lost": lost, "before_kmsg_seq": record.seq,
                            "previous_kmsg_seq":last_committed,
                            "reason":if first_new { "restart_buffer_gap" } else { "sequence_gap" } }),
                        args.print,
                    )?;
                }
                writer.append("kmsg.line", body(&record), args.print)?;
                last_committed = Some(record.seq);
                first_new = false;
            }
            Ok(Event::Overrun) => {
                // The count is not known yet; take_lost() picks it up from the
                // sequence gap on the next record.
                writer.append(
                    "kmsg.overrun",
                    json!({ "last_kmsg_seq": reader.last_seq(), "lost": null }),
                    args.print,
                )?;
            }
            Ok(Event::Empty) => {
                if args.once {
                    break;
                }
                sleep(Duration::from_millis(args.poll_ms));
            }
            Err(error @ kmsg::Error::Io(_)) => return Err(to_nostoi(error, &args.source)),
            Err(kmsg::Error::Malformed(reason)) => {
                // Never drop a line silently: record why it could not be read.
                writer.append("kmsg.unparsable", json!({ "reason": reason }), args.print)?;
            }
        }
    }

    writer.marker(
        "kmsg.reader.stop",
        json!({ "last_kmsg_seq":last_committed,
        "reason":if shutdown.load(Ordering::Relaxed) { "signal" } else { "drained" },
        "overrun_unresolved":reader.has_pending_overrun() }),
    )?;
    Ok(())
}

/// A record's chained body: the kernel's header fields plus its message and
/// continuation context, so a reader can rebuild the original line.
fn body(record: &Record) -> Value {
    let context: Map<String, Value> = record
        .context
        .iter()
        .map(|(key, value)| (key.clone(), Value::String(value.clone())))
        .collect();
    json!({
        "prio": record.prio,
        "facility": record.prio >> 3,
        "severity": record.prio & 0x7,
        "kmsg_seq": record.seq,
        "usec": record.usec,
        "flag": record.flag.to_string(),
        "message": record.message,
        "context": Value::Object(context),
    })
}

/// A verified, long-lived store. Re-verifies and retries once if another writer
/// moves the head underneath it, so a competing append is rejected loudly rather
/// than silently forking the chain.
struct Writer {
    store: sqlite::Store,
    actor: String,
    boot_id: String,
    source: String,
}

impl Writer {
    fn open(path: &std::path::Path, actor: &str) -> Result<Self, Error> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|source| Error::Io {
                    path: parent.display().to_string(),
                    source,
                })?;
            }
        }
        let store = sqlite::Store::open_verified(path)?;
        Ok(Self {
            store,
            actor: actor.to_string(),
            boot_id: String::new(),
            source: String::new(),
        })
    }

    fn append(&mut self, kind: &str, mut body: Value, print: bool) -> Result<(), Error> {
        body["boot_id"] = json!(self.boot_id);
        body["source"] = json!(self.source);
        let draft = Draft {
            actor: Some(self.actor.as_str()),
            kind,
            subject: Some("kernel"),
            body,
            at: None,
        };
        let entry = self.store.append(draft)?;
        if print {
            println!(
                "{}",
                serde_json::to_string(&json!({
                    "seq": entry.seq,
                    "kind": entry.kind,
                    "digest": entry.digest,
                }))
                .unwrap_or_default()
            );
        }
        Ok(())
    }

    fn marker(&mut self, kind: &str, body: Value) -> Result<(), Error> {
        // Markers are coverage records, not data to pipe.
        self.append(kind, body, false)
    }

    fn checkpoint(&self) -> Result<Option<Checkpoint>, Error> {
        let record: Option<String> = self.store.connection().query_row(
            "SELECT record FROM nostoi_records WHERE json_extract(record, '$.actor') = ?1
             AND json_extract(record, '$.kind') IN ('kmsg.line', 'kmsg.reader.start', 'kmsg.reader.stop')
             ORDER BY seq DESC LIMIT 1", [&self.actor], |row| row.get(0)).optional()?;
        record
            .map(|text| {
                let record: Value =
                    serde_json::from_str(&text).map_err(|e| Error::Invalid(e.to_string()))?;
                let body = &record["body"];
                Ok(Checkpoint {
                    boot_id: body["boot_id"].as_str().map(str::to_owned),
                    source: body["source"].as_str().map(str::to_owned),
                    kernel_seq: body["kmsg_seq"]
                        .as_u64()
                        .or_else(|| body["last_kmsg_seq"].as_u64()),
                    clean_stop: record["kind"] == "kmsg.reader.stop",
                })
            })
            .transpose()
    }
}

struct Checkpoint {
    boot_id: Option<String>,
    source: Option<String>,
    kernel_seq: Option<u64>,
    clean_stop: bool,
}

struct ShutdownSignals(Vec<signal_hook::SigId>);

impl ShutdownSignals {
    fn install(flag: Arc<AtomicBool>) -> Result<Self, Error> {
        let mut signals = Self(Vec::new());
        for signal in [signal_hook::consts::SIGTERM, signal_hook::consts::SIGINT] {
            let id = signal_hook::flag::register(signal, Arc::clone(&flag))
                .map_err(|e| Error::Invalid(format!("install shutdown handler: {e}")))?;
            signals.0.push(id);
        }
        Ok(signals)
    }
}

impl Drop for ShutdownSignals {
    fn drop(&mut self) {
        for id in self.0.drain(..) {
            signal_hook::low_level::unregister(id);
        }
    }
}

fn to_nostoi(error: kmsg::Error, path: &std::path::Path) -> Error {
    match error {
        kmsg::Error::Io(source) => Error::Io {
            path: path.display().to_string(),
            source,
        },
        kmsg::Error::Malformed(reason) => Error::Invalid(reason),
    }
}
