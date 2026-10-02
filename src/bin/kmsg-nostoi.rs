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
//! single-writer only; if another process appends, the store re-opens and
//! re-verifies rather than forking the chain.

use std::path::PathBuf;
use std::process::ExitCode;
use std::thread::sleep;
use std::time::Duration;

use clap::Parser;
use nostoi::kmsg::{self, Event, Record};
use nostoi::{sqlite, Draft, Error};
use serde_json::{json, Map, Value};

#[derive(Parser, Debug)]
#[command(
    name = "kmsg-nostoi",
    about = "Append the Linux kernel ring buffer to a Nostoi SQLite chain"
)]
struct Args {
    /// SQLite store to append to (created and verified if missing).
    store: PathBuf,

    /// Read everything currently buffered, then exit.
    #[arg(long)]
    once: bool,

    /// Poll interval when the buffer is empty, in milliseconds.
    #[arg(long, default_value_t = 250)]
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
    let mut writer = Writer::open(&args.store, &args.actor)?;
    writer.marker(
        "kmsg.reader.start",
        json!({ "source": "/dev/kmsg", "pid": std::process::id() }),
    )?;

    let mut reader = kmsg::Reader::open().map_err(to_nostoi)?;
    loop {
        match reader.next_event() {
            Ok(Event::Record(record)) => {
                let lost = reader.take_lost();
                if lost > 0 {
                    writer.append(
                        "kmsg.loss",
                        json!({ "lost": lost, "before_kmsg_seq": record.seq }),
                        args.print,
                    )?;
                }
                writer.append("kmsg.line", body(&record), args.print)?;
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
            Err(error @ kmsg::Error::Io(_)) => return Err(to_nostoi(error)),
            Err(kmsg::Error::Malformed(reason)) => {
                // Never drop a line silently: record why it could not be read.
                writer.append("kmsg.unparsable", json!({ "reason": reason }), args.print)?;
            }
        }
    }

    writer.marker("kmsg.reader.stop", json!({ "source": "/dev/kmsg" }))?;
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
        })
    }

    fn append(&mut self, kind: &str, body: Value, print: bool) -> Result<(), Error> {
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
}

fn to_nostoi(error: kmsg::Error) -> Error {
    match error {
        kmsg::Error::Io(source) => Error::Io {
            path: "/dev/kmsg".to_string(),
            source,
        },
        kmsg::Error::Malformed(reason) => Error::Invalid(reason),
    }
}
