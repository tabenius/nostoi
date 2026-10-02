//! Measure how append cost scales, JSONL vs the SQLite store.
use nostoi::{sqlite, Draft};
use serde_json::json;
use std::path::Path;
use std::time::Instant;

fn draft<'a>(i: usize) -> Draft<'a> {
    Draft {
        actor: Some("host:test"),
        kind: "kmsg.line",
        subject: Some("kernel"),
        body: json!({"prio":6,"usec":i,"message":format!("kernel line {i}")}),
        at: None,
    }
}

fn main() {
    // Use a fresh directory; never remove an operator's existing database.
    // Pass a disk-backed parent directory for meaningful FULL-sync timings.
    let dir = match std::env::args().nth(1) {
        Some(parent) => tempfile::tempdir_in(parent).unwrap(),
        None => tempfile::tempdir().unwrap(),
    };
    let dir = dir.path().display().to_string();

    println!("== JSONL append (nostoi::append) ==");
    let jsonl = format!("{dir}/scale.jsonl");
    let mut last = 0usize;
    for mark in [500usize, 1000, 2000] {
        let t = Instant::now();
        for i in (last + 1)..=mark {
            nostoi::append(Path::new(&jsonl), draft(i)).unwrap();
        }
        let dt = t.elapsed().as_secs_f64();
        let window = mark - last;
        println!(
            "  {:5} total: {:7.3}s  per_append: {:.4} ms",
            mark,
            dt,
            dt / window as f64 * 1000.0
        );
        last = mark;
    }

    for (label, verified) in [
        ("Store::open (re-verifies every append)", false),
        ("Store::open_verified (verify once)", true),
    ] {
        println!("== SQLite {label} ==");
        let sq = format!("{dir}/scale-{verified}.sqlite");
        let mut store = if verified {
            sqlite::Store::open_verified(Path::new(&sq)).unwrap()
        } else {
            sqlite::Store::open(Path::new(&sq)).unwrap()
        };
        let mut last = 0usize;
        let marks: &[usize] = if verified {
            &[500, 1000, 2000, 4000, 10000, 20000]
        } else {
            &[500, 1000, 2000, 4000]
        };
        for &mark in marks {
            let t = Instant::now();
            for i in (last + 1)..=mark {
                store.append(draft(i)).unwrap();
            }
            let dt = t.elapsed().as_secs_f64();
            let window = mark - last;
            println!(
                "  {:5} total: {:7.3}s  per_append: {:.4} ms",
                mark,
                dt,
                dt / window as f64 * 1000.0
            );
            last = mark;
        }
        drop(store);
        let t = Instant::now();
        let reopened = sqlite::Store::open_verified(Path::new(&sq)).unwrap();
        println!(
            "  full streaming startup verification: {:.3} ms, head {}",
            t.elapsed().as_secs_f64() * 1000.0,
            reopened.head().unwrap().0
        );
    }
}
