//! Reading the kernel log ring buffer at `/dev/kmsg`.
//!
//! The kernel's `Documentation/ABI/testing/dev-kmsg` defines the record format
//! and, importantly, the concurrency rules this module relies on:
//!
//! > The first read() directly following an open() always returns first
//! > message in the buffer; there is no kernel-internal persistent state; many
//! > readers can concurrently open the device and read from it, without
//! > affecting other readers.
//!
//! > Unlike the classic syslog() interface, the 64 bit record sequence numbers
//! > allow to calculate the amount of lost messages, in case the buffer gets
//! > overwritten.
//!
//! > In case messages get overwritten in the circular buffer while the device is
//! > kept open, the next read() will return -EPIPE, and the seek position be
//! > updated to the next available record.
//!
//! So a reader of `/dev/kmsg` cannot disturb journald, rsyslog or any other
//! reader, and it can detect exactly how many records it missed rather than
//! losing them silently. That is a stronger position than reading the journal,
//! where journald's own rate limiting drops records before any reader sees them
//! and no later reader can tell that it happened.
//!
//! Record format, from the same document:
//!
//! ```text
//! <priority>,<sequence>,<monotonic usec>,<flag>;<text>\n
//!  key=value\n            <- continuation lines, indented by one space
//! ```
//!
//! ```text
//! 7,160,424069,-;pci_root PNP0A03:00: host bridge window [io 0x0000-0x0cf7] (ignored)
//  SUBSYSTEM=acpi
//!  DEVICE=+acpi:PNP0A03:00
//! ```
//!
//! Text is escaped by the kernel: non-printable characters and `\` itself are
//! written as C-style `\xNN`, so a message is always plain ASCII and needs no
//! further unescaping to be chained.

use std::fs::File;
use std::io::Read;
use std::os::unix::io::AsRawFd;
use std::os::unix::io::RawFd;

/// One record from the ring buffer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    /// Syslog priority, including the facility in the low three bits.
    pub prio: u32,
    /// The kernel's 64-bit sequence number, monotonic across the buffer.
    pub seq: u64,
    /// Microseconds since boot, as recorded by the kernel.
    pub usec: u64,
    /// `-` for a complete record, `+` when continued lines follow.
    pub flag: char,
    /// The message text, with continuation lines removed.
    pub message: String,
    /// `key=value` pairs from the record's continuation lines.
    pub context: Vec<(String, String)>,
}

/// Why a record could not be read.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The bytes are not a `/dev/kmsg` record.
    #[error("not a kmsg record: {0}")]
    Malformed(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Parse one record: a header line plus any continuation lines.
///
/// Returns [`Error::Malformed`] when there is no `prio,seq,usec,flag;` prefix.
/// Fields after `flag` and before `;` are ignored, because the ABI says future
/// versions may add them and that unknown fields should be ignored gracefully.
pub fn parse(bytes: &[u8]) -> Result<Record> {
    let text = String::from_utf8_lossy(bytes);
    let (prefix, rest) = text
        .split_once(';')
        .ok_or_else(|| Error::Malformed(format!("no ';' in {:?}", truncate(&text))))?;
    let mut fields = prefix.split(',');

    let prio = field(&mut fields, "prio")?
        .parse::<u32>()
        .map_err(|_| Error::Malformed("prio is not a number".into()))?;
    let seq = field(&mut fields, "seq")?
        .parse::<u64>()
        .map_err(|_| Error::Malformed("seq is not a number".into()))?;
    let usec = field(&mut fields, "usec")?
        .parse::<u64>()
        .map_err(|_| Error::Malformed("usec is not a number".into()))?;
    let flag_text = field(&mut fields, "flag")?;
    let flag = flag_text.chars().next().unwrap_or('-');

    let mut lines = rest.split('\n');
    let message = lines.next().unwrap_or("").to_string();
    let mut context = Vec::new();
    for line in lines {
        // A continuation line is indented by one space. Anything else ends the
        // record: the ABI says records arrive whole, never in fragments.
        let Some(pair) = line.strip_prefix(' ') else {
            break;
        };
        if let Some((key, value)) = pair.trim().split_once('=') {
            context.push((key.to_string(), value.to_string()));
        }
    }

    Ok(Record {
        prio,
        seq,
        usec,
        flag,
        message,
        context,
    })
}

fn field<'a>(fields: &mut impl Iterator<Item = &'a str>, name: &'static str) -> Result<&'a str> {
    fields
        .next()
        .ok_or_else(|| Error::Malformed(format!("missing {name} field")))
}

fn truncate(text: &str) -> &str {
    const MAX: usize = 80;
    if text.len() <= MAX {
        return text;
    }
    let mut end = MAX;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

/// Split a buffer into records: each header line plus the indented lines that
/// belong to it. A `/dev/kmsg` read returns one record at a time, but reading a
/// fixture or a saved buffer yields several at once.
pub fn split_records(bytes: &[u8]) -> Vec<&[u8]> {
    let mut records: Vec<&[u8]> = Vec::new();
    let mut start: Option<usize> = None;
    let mut cursor = 0usize;

    for line in bytes.split_inclusive(|byte| *byte == b'\n') {
        let is_continuation = line.first() == Some(&b' ');
        match (is_continuation, start) {
            (true, Some(_)) => cursor += line.len(),
            _ => {
                if let Some(begin) = start {
                    records.push(&bytes[begin..cursor]);
                }
                start = Some(cursor);
                cursor += line.len();
            }
        }
    }
    if let Some(begin) = start {
        records.push(&bytes[begin..cursor]);
    }
    records.into_iter().filter(|r| !r.is_empty()).collect()
}

/// What a reader read, including the loss the kernel reported.
#[derive(Debug)]
pub enum Event {
    /// A record was read.
    Record(Record),
    /// The ring buffer overwrote records while the fd was open. The kernel
    /// returns `-EPIPE` and moves the read position to the oldest surviving
    /// record, so this arrives before the next [`Event::Record`]. The count is
    /// filled in once that next record's sequence number is known.
    Overrun,
    /// No record was available (`O_NONBLOCK` returned `EAGAIN`).
    Empty,
}

/// A reader over the kernel log ring buffer.
///
/// Opening and reading `/dev/kmsg` does not consume records for anyone else, so
/// this may run alongside journald and any syslog daemon. The reader holds the
/// device open, which is what makes `-EPIPE` overrun reporting work: a reader
/// that reopened per record would silently miss the gap.
pub struct Reader {
    file: File,
    buffer: Vec<u8>,
    last_seq: Option<u64>,
    /// Records parsed from the last read but not yet handed out. A read from the
    /// character device returns one record; a read from a fixture returns many.
    pending: std::collections::VecDeque<Record>,
    /// Kernel sequence numbers skipped since the last record handed out. Filled
    /// from sequence-number gaps, which the ABI says are exact.
    lost: u64,
    /// An overrun (-EPIPE) occurred but we haven't accounted for its gap yet.
    overrun_pending: bool,
}

impl Reader {
    /// Open `/dev/kmsg`. Read access is enough: the device is `crw-r--r--`, so
    /// no capability is required.
    pub fn open() -> Result<Self> {
        Self::open_path("/dev/kmsg")
    }

    /// Open a specific path. Used by tests to read a fixture.
    pub fn open_path(path: impl AsRef<std::path::Path>) -> Result<Self> {
        use std::os::unix::fs::OpenOptionsExt;
        // Non-blocking, so a drained buffer returns EAGAIN instead of parking
        // the thread in read(2).
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(path)?;
        Ok(Self {
            file,
            buffer: vec![0; 65536],
            last_seq: None,
            pending: std::collections::VecDeque::new(),
            lost: 0,
            overrun_pending: false,
        })
    }

    /// The last kernel sequence number this reader saw.
    pub fn last_seq(&self) -> Option<u64> {
        self.last_seq
    }

    /// Kernel sequence numbers skipped since this was last reset.
    ///
    /// This counts records the ring buffer overwrote, which the 64-bit sequence
    /// numbers make exact. `-EPIPE` is the kernel's own signal that a gap
    /// happened; a gap is also visible in the numbers themselves, and both are
    /// folded in here.
    pub fn take_lost(&mut self) -> u64 {
        std::mem::take(&mut self.lost)
    }

    /// An overrun was observed and no subsequent sequence has resolved it yet.
    pub fn has_pending_overrun(&self) -> bool {
        self.overrun_pending
    }

    /// Read the next event.
    ///
    /// `EPIPE` becomes [`Event::Overrun`]: the buffer overwrote records while
    /// this fd was open. `EAGAIN` becomes [`Event::Empty`].
    pub fn next_event(&mut self) -> Result<Event> {
        self.next_event_with(read_at)
    }

    fn next_event_with(
        &mut self,
        mut read: impl FnMut(&mut File, &mut [u8]) -> std::io::Result<usize>,
    ) -> Result<Event> {
        if let Some(record) = self.pending.pop_front() {
            return Ok(self.emit(record));
        }
        let count = loop {
            match read(&mut self.file, &mut self.buffer) {
                Ok(count) => break count,
                // /dev/kmsg returns EINVAL (not a partial record) when the
                // destination cannot hold the record. Retry with a bounded buffer.
                Err(error)
                    if error.raw_os_error() == Some(libc::EINVAL)
                        && self.buffer.len() < 1024 * 1024 =>
                {
                    self.buffer.resize(self.buffer.len() * 2, 0);
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) if error.raw_os_error() == Some(libc::EPIPE) => {
                    self.overrun_pending = true;
                    return Ok(Event::Overrun);
                }
                Err(error) if is_would_block(&error) => return Ok(Event::Empty),
                Err(error) => return Err(error.into()),
            }
        };
        if count == 0 {
            return Ok(Event::Empty);
        }
        for bytes in split_records(&self.buffer[..count]) {
            self.pending.push_back(parse(bytes)?);
        }
        match self.pending.pop_front() {
            Some(record) => Ok(self.emit(record)),
            None => Ok(Event::Empty),
        }
    }

    /// Record the sequence gap, remember the new last seq, and hand the record
    /// back.
    fn emit(&mut self, record: Record) -> Event {
        if let Some(previous) = self.last_seq {
            let gap = record.seq.saturating_sub(previous).saturating_sub(1);
            self.lost = self.lost.saturating_add(gap);
        }
        self.overrun_pending = false;
        self.last_seq = Some(record.seq);
        Event::Record(record)
    }

    /// The raw descriptor, for callers that need `poll` on it.
    pub fn as_raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}

fn is_would_block(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    )
}

/// A single `read(2)`, returning whatever the device gave us. The kernel
/// returns exactly one record per read, so no loop is needed.
fn read_at(file: &mut File, buffer: &mut [u8]) -> std::io::Result<usize> {
    file.read(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn injected_overrun_survives_empty_read_until_next_record() {
        let mut reader = Reader::open_path("/dev/null").unwrap();
        reader.last_seq = Some(10);
        assert!(matches!(
            reader
                .next_event_with(|_, _| Err(std::io::Error::from_raw_os_error(libc::EPIPE)))
                .unwrap(),
            Event::Overrun
        ));
        assert!(reader.overrun_pending);
        assert!(matches!(
            reader
                .next_event_with(|_, _| Err(std::io::Error::from_raw_os_error(libc::EAGAIN)))
                .unwrap(),
            Event::Empty
        ));
        assert!(reader.overrun_pending);
        assert!(matches!(
            reader
                .next_event_with(|_, buffer| {
                    let bytes = b"6,50,1,-;after overrun\n";
                    buffer[..bytes.len()].copy_from_slice(bytes);
                    Ok(bytes.len())
                })
                .unwrap(),
            Event::Record(_)
        ));
        assert_eq!(reader.take_lost(), 39);
        assert!(!reader.overrun_pending);
    }

    #[test]
    fn small_buffer_grows_without_consuming_record() {
        let mut reader = Reader::open_path("/dev/null").unwrap();
        let mut attempts = 0;
        let event = reader
            .next_event_with(|_, buffer| {
                attempts += 1;
                if buffer.len() < 128 * 1024 {
                    return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
                }
                let bytes = b"6,1,1,-;large record\n";
                buffer[..bytes.len()].copy_from_slice(bytes);
                Ok(bytes.len())
            })
            .unwrap();
        assert!(matches!(event, Event::Record(_)));
        assert_eq!(attempts, 2);
        assert_eq!(reader.buffer.len(), 128 * 1024);
    }

    #[test]
    fn invalid_read_is_bounded_by_buffer_ceiling() {
        let mut reader = Reader::open_path("/dev/null").unwrap();
        let mut attempts = 0;
        let result = reader.next_event_with(|_, _| {
            attempts += 1;
            Err(std::io::Error::from_raw_os_error(libc::EINVAL))
        });
        assert!(
            matches!(result, Err(Error::Io(error)) if error.raw_os_error() == Some(libc::EINVAL))
        );
        assert_eq!(reader.buffer.len(), 1024 * 1024);
        assert_eq!(attempts, 5);
    }

    #[test]
    fn interrupted_read_retries_before_returning_empty() {
        let mut reader = Reader::open_path("/dev/null").unwrap();
        let mut attempts = 0;
        let result = reader
            .next_event_with(|_, _| {
                attempts += 1;
                Err(std::io::Error::from_raw_os_error(if attempts == 1 {
                    libc::EINTR
                } else {
                    libc::EAGAIN
                }))
            })
            .unwrap();
        assert!(matches!(result, Event::Empty));
        assert_eq!(attempts, 2);
    }

    #[test]
    fn overrun_gap_is_counted_once() {
        let file = File::open("/dev/null").unwrap();
        let mut reader = Reader {
            file,
            buffer: vec![0; 65536],
            last_seq: Some(10),
            pending: Default::default(),
            lost: 0,
            overrun_pending: true,
        };
        reader.emit(parse(b"6,50,0,-;next\n").unwrap());
        assert_eq!(reader.take_lost(), 39);
        assert!(!reader.overrun_pending);
        reader.emit(parse(b"6,51,0,-;next\n").unwrap());
        assert_eq!(reader.take_lost(), 0);
    }

    const SAMPLE: &[u8] = b"7,160,424069,-;pci_root PNP0A03:00: host bridge window [io  0x0000-0x0cf7] (ignored)\n SUBSYSTEM=acpi\n DEVICE=+acpi:PNP0A03:00\n6,339,5140900,-;NET: Registered protocol family 10\n30,340,5690716,-;udevd[80]: starting version 181\n";

    #[test]
    fn parses_a_record_with_context() {
        let record = parse(split_records(SAMPLE)[0]).expect("record parses");
        assert_eq!(record.prio, 7);
        assert_eq!(record.seq, 160);
        assert_eq!(record.usec, 424069);
        assert_eq!(record.flag, '-');
        assert!(record.message.starts_with("pci_root PNP0A03:00"));
        assert_eq!(
            record.context,
            vec![
                ("SUBSYSTEM".to_string(), "acpi".to_string()),
                ("DEVICE".to_string(), "+acpi:PNP0A03:00".to_string()),
            ]
        );
    }

    #[test]
    fn splits_records_and_keeps_continuations_attached() {
        let records = split_records(SAMPLE);
        assert_eq!(records.len(), 3);
        let first = parse(records[0]).unwrap();
        assert_eq!(first.seq, 160);
        assert_eq!(first.context.len(), 2);
        assert_eq!(parse(records[1]).unwrap().seq, 339);
        assert_eq!(parse(records[2]).unwrap().seq, 340);
    }

    #[test]
    fn ignores_unknown_fields_before_the_semicolon() {
        // The ABI allows future fields between flag and ';'.
        let record = parse(b"6,339,5140900,-,extra,fields;hello").unwrap();
        assert_eq!(record.seq, 339);
        assert_eq!(record.message, "hello");
    }

    #[test]
    fn keeps_the_flag() {
        assert_eq!(parse(b"3,1634,90211234,+;continued").unwrap().flag, '+');
    }

    #[test]
    fn rejects_bytes_that_are_not_a_record() {
        assert!(parse(b"no semicolon here").is_err());
        assert!(parse(b"x,1,2,-;bad prio").is_err());
        assert!(parse(b"1,2,3").is_err());
    }

    #[test]
    fn reads_a_fixture_end_to_end() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fixture");
        std::fs::write(&path, SAMPLE).unwrap();
        let mut reader = Reader::open_path(&path).expect("fixture opens");
        let mut seqs = Vec::new();
        while let Ok(Event::Record(record)) = reader.next_event() {
            seqs.push(record.seq);
        }
        assert_eq!(seqs, vec![160, 339, 340]);
        assert_eq!(reader.last_seq(), Some(340));
    }

    #[test]
    fn counts_lost_records_from_sequence_numbers() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fixture");
        std::fs::write(&path, b"1,10,0,-;a\n2,50,0,-;b\n").unwrap();
        let mut reader = Reader::open_path(&path).unwrap();
        assert!(matches!(reader.next_event().unwrap(), Event::Record(_)));
        match reader.next_event().unwrap() {
            Event::Record(record) => assert_eq!(record.seq, 50),
            other => panic!("expected a record, got {other:?}"),
        }
        // 11..=49 were skipped: the exact loss the 64-bit sequence numbers
        // expose, and the same thing -EPIPE would have signalled.
        assert_eq!(reader.take_lost(), 39);
        assert_eq!(reader.take_lost(), 0);
    }
}
