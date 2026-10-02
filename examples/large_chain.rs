//! Fresh-process large-chain measurements. See docs/LARGE-CHAIN-BENCHMARKS.md.
use nostoi::{canonical, format, sqlite::Store, Draft, Format, GENESIS};
use serde_json::{json, Value};
use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

type Result<T> = std::result::Result<T, Box<dyn Error>>;
const AT: &str = "2026-01-01T00:00:00Z";

struct Options {
    mode: String,
    target: PathBuf,
    backend: String,
    api: String,
    count: usize,
    payload: usize,
    batch: usize,
}

impl Options {
    fn parse() -> Result<Self> {
        let mut args = std::env::args().skip(1);
        let mode = args.next().ok_or("expected seed|verify|startup|append")?;
        let mut options = Self {
            mode,
            target: PathBuf::new(),
            backend: "sqlite".into(),
            api: "public".into(),
            count: 1000,
            payload: 256,
            batch: 1000,
        };
        while let Some(key) = args.next() {
            let value = args.next().ok_or("missing option value")?;
            match key.as_str() {
                "--target" => options.target = value.into(),
                "--backend" => options.backend = value,
                "--api" => options.api = value,
                "--count" => options.count = value.parse()?,
                "--payload" => options.payload = value.parse()?,
                "--batch" => options.batch = value.parse()?,
                _ => return Err(format!("unknown option {key}").into()),
            }
        }
        if options.target.as_os_str().is_empty()
            || !matches!(
                options.mode.as_str(),
                "seed" | "verify" | "startup" | "append"
            )
            || !matches!(options.backend.as_str(), "sqlite" | "jsonl")
            || !matches!(options.api.as_str(), "public" | "loaded")
            || options.count == 0
            || options.batch == 0
        {
            return Err(
                "invalid options: explicit --target and positive count/batch required".into(),
            );
        }
        if matches!(options.mode.as_str(), "startup" | "append") && options.backend != "sqlite" {
            return Err("startup/append measure the persistent native SQLite Store only".into());
        }
        Ok(options)
    }

    fn path(&self) -> PathBuf {
        self.target.join(format!("chain.{}", self.backend))
    }
}

fn draft(payload: usize) -> Draft<'static> {
    Draft {
        actor: Some("host:benchmark"),
        kind: "benchmark.record",
        subject: Some("fixture"),
        body: json!({"message": "x".repeat(payload)}),
        at: Some(AT.into()),
    }
}

fn peak_rss_kib() -> Result<u64> {
    // Linux process high-water mark: includes parsing/allocator and SQLite cache.
    let status = fs::read_to_string("/proc/self/status")?;
    Ok(status
        .lines()
        .find_map(|line| line.strip_prefix("VmHWM:"))
        .ok_or("Linux VmHWM unavailable")?
        .split_whitespace()
        .next()
        .ok_or("missing VmHWM value")?
        .parse()?)
}

fn bytes(path: &Path) -> u64 {
    fs::metadata(path).map(|m| m.len()).unwrap_or(0)
}

fn sizes(path: &Path) -> Value {
    json!({"file_bytes": bytes(path),
        "wal_bytes": bytes(&PathBuf::from(format!("{}-wal", path.display()))),
        "shm_bytes": bytes(&PathBuf::from(format!("{}-shm", path.display())))})
}

fn pragmas(store: &Store) -> Result<Value> {
    let conn = store.connection();
    let journal: String = conn.query_row("PRAGMA journal_mode", [], |r| r.get(0))?;
    let synchronous: i64 = conn.query_row("PRAGMA synchronous", [], |r| r.get(0))?;
    if journal != "wal" || synchronous != 2 {
        return Err("benchmark requires WAL and synchronous FULL (2)".into());
    }
    Ok(json!({"journal_mode": journal, "synchronous": synchronous,
        "wal_autocheckpoint_pages": conn.query_row("PRAGMA wal_autocheckpoint", [], |r| r.get::<_, i64>(0))?,
        "page_size": conn.query_row("PRAGMA page_size", [], |r| r.get::<_, i64>(0))?,
        "cache_size": conn.query_row("PRAGMA cache_size", [], |r| r.get::<_, i64>(0))?,
        "sqlite_version": rusqlite::version()}))
}

fn checkpoint(store: &Store) -> Result<Value> {
    // Outside append timings; PASSIVE does not truncate the allocated WAL.
    let start = Instant::now();
    let (busy, log, done) =
        store
            .connection()
            .query_row("PRAGMA wal_checkpoint(PASSIVE)", [], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, i64>(2)?,
                ))
            })?;
    Ok(
        json!({"busy": busy, "log_frames": log, "checkpointed_frames": done,
        "elapsed_ms": start.elapsed().as_secs_f64() * 1000.0}),
    )
}

fn seed(options: &Options) -> Result<Value> {
    // A new child directory is required: never truncate or reuse operator files.
    fs::create_dir(&options.target)?;
    let jsonl_path = options.target.join("chain.jsonl");
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&jsonl_path)?;
    let mut writer = BufWriter::new(file);
    let sqlite_path = options.target.join("chain.sqlite");
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&sqlite_path)?;
    let store = Store::open(&sqlite_path)?;
    let settings = pragmas(&store)?;
    let conn = store.connection(); // Library schema, triggers and digest UDF registered.
    let start = Instant::now();
    let mut previous = GENESIS.to_owned();
    for first in (1..=options.count).step_by(options.batch) {
        let tx = conn.unchecked_transaction()?;
        {
            let mut insert = tx.prepare(
                "INSERT INTO nostoi_records(seq, previous, digest, record) VALUES (?1, ?2, ?3, ?4)",
            )?;
            for seq in first..=options.count.min(first.saturating_add(options.batch - 1)) {
                let d = draft(options.payload);
                let record = format::nostoi_record(
                    seq as u64, &previous, AT, d.actor, d.kind, d.subject, d.body,
                )?;
                let digest = record["digest"].as_str().ok_or("missing digest")?;
                let text = canonical::to_string(&record);
                insert.execute(rusqlite::params![seq as i64, previous, digest, text])?;
                writeln!(writer, "{text}")?;
                previous = digest.to_owned();
            }
        }
        tx.commit()?;
    }
    writer.flush()?;
    writer.get_ref().sync_all()?;
    let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
    let cp = checkpoint(&store)?;
    let before_close = sizes(&sqlite_path);
    drop(store);
    Ok(
        json!({"rows": options.count, "batch_records": options.batch,
        "elapsed_ms": elapsed_ms, "sqlite_settings": settings, "checkpoint": cp,
        "sqlite_before_close": before_close, "sqlite_after_close": sizes(&sqlite_path),
        "jsonl": sizes(&jsonl_path), "head_digest": previous}),
    )
}

fn verify(options: &Options) -> Result<Value> {
    let path = options.path();
    let start = Instant::now();
    let report = if options.api == "loaded" {
        nostoi::open(&path, Some(Format::Nostoi))?.verify()
    } else {
        nostoi::verify(&path, Some(Format::Nostoi))?
    };
    let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
    if !report.ok {
        return Err(format!("verification failed: {report:?}").into());
    }
    Ok(json!({"elapsed_ms": elapsed_ms, "report": report, "sizes": sizes(&path)}))
}

fn startup_or_append(options: &Options) -> Result<Value> {
    let path = options.path();
    // Avoid Store::open creating a missing operator target during measurement.
    if !path.is_file() {
        return Err("measurement requires an existing seeded chain.sqlite".into());
    }
    let before_open = sizes(&path);
    let start = Instant::now();
    let mut store = Store::open_verified(&path)?;
    let startup_ms = start.elapsed().as_secs_f64() * 1000.0;
    let initial_rows = store.head().ok_or("missing verified head")?.0;
    let settings = pragmas(&store)?;
    let startup_peak = peak_rss_kib()?;
    let mut result = json!({"startup_ms": startup_ms, "startup_peak_rss_kib": startup_peak,
        "initial_rows": initial_rows, "sqlite_settings": settings, "before_open": before_open});
    if options.mode == "append" {
        let mut samples = Vec::with_capacity(options.count);
        let before = sizes(&path);
        let mut wal_max = 0;
        let elapsed = Instant::now();
        for _ in 0..options.count {
            let d = draft(options.payload); // Payload construction outside timed append.
            let start = Instant::now();
            store.append(d)?; // Native one-record FULL commit; no enclosing transaction.
            samples.push(start.elapsed().as_secs_f64() * 1000.0);
            wal_max = wal_max.max(bytes(&PathBuf::from(format!("{}-wal", path.display()))));
        }
        let elapsed_ms = elapsed.elapsed().as_secs_f64() * 1000.0;
        samples.sort_by(f64::total_cmp);
        let percentile = |p: usize| samples[(samples.len() * p).div_ceil(100) - 1];
        result["append"] = json!({"samples": samples.len(), "elapsed_ms": elapsed_ms,
            "sum_append_ms": samples.iter().sum::<f64>(),
            "p50_ms": percentile(50), "p95_ms": percentile(95), "p99_ms": percentile(99),
            "max_ms": samples[samples.len()-1], "before": before, "after": sizes(&path),
            "wal_max_observed_bytes": wal_max, "final_rows": store.head().unwrap().0});
        result["checkpoint"] = checkpoint(&store)?;
        result["after_checkpoint"] = sizes(&path);
    }
    drop(store);
    result["after_close"] = sizes(&path);
    Ok(result)
}

fn run() -> Result<()> {
    let options = Options::parse()?;
    let mut result = match options.mode.as_str() {
        "seed" => seed(&options)?,
        "verify" => verify(&options)?,
        _ => startup_or_append(&options)?,
    };
    result["mode"] = json!(options.mode);
    result["backend"] = json!(if options.mode == "seed" {
        "both"
    } else {
        &options.backend
    });
    result["api"] = json!(options.api);
    result["target"] = json!(options.target);
    result["payload_message_bytes"] = json!(options.payload);
    result["peak_rss_kib"] = json!(peak_rss_kib()?);
    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("large_chain: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bulk_fixture_matches_backends_and_refuses_existing_target() -> Result<()> {
        let parent = tempfile::tempdir()?;
        let options = Options {
            mode: "seed".into(),
            target: parent.path().join("fixture"),
            backend: "sqlite".into(),
            api: "public".into(),
            count: 7,
            payload: 256,
            batch: 3, // Includes an incomplete final batch.
        };
        seed(&options)?;
        let sqlite_path = options.target.join("chain.sqlite");
        let jsonl_path = options.target.join("chain.jsonl");
        let jsonl_bytes = fs::read(&jsonl_path)?;
        let sql = nostoi::verify(&sqlite_path, None)?;
        let lines = nostoi::verify(&jsonl_path, None)?;
        assert!(sql.ok && lines.ok);
        assert_eq!(serde_json::to_value(sql)?, serde_json::to_value(lines)?);
        assert!(seed(&options).is_err());
        assert_eq!(fs::read(&jsonl_path)?, jsonl_bytes);
        let mut store = Store::open_verified(&sqlite_path)?;
        assert_eq!(store.head().unwrap().0, 7);
        store.append(draft(256))?;
        assert_eq!(store.head().unwrap().0, 8);
        assert!(store
            .connection()
            .execute("DELETE FROM nostoi_records", [])
            .is_err());
        drop(store);
        assert!(nostoi::verify(&sqlite_path, None)?.ok);
        Ok(())
    }

    #[test]
    fn missing_measurement_target_is_not_created() -> Result<()> {
        let parent = tempfile::tempdir()?;
        let options = Options {
            mode: "append".into(),
            target: parent.path().join("absent"),
            backend: "sqlite".into(),
            api: "public".into(),
            count: 1,
            payload: 256,
            batch: 1,
        };
        assert!(startup_or_append(&options).is_err());
        assert!(!options.target.exists());
        Ok(())
    }
}
