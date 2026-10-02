//! Optional Minotaur host projection. Never probes or controls from a browser.
use std::io::Read;
use std::path::Path;

pub fn read() -> String {
    match std::env::var_os("RAGBAZ_RUNTIME_STATUS") {
        Some(path) => load(Path::new(&path)),
        None => "Runtime not configured; set RAGBAZ_RUNTIME_STATUS to Minotaur's snapshot.\nNative evidence and human review do not require Ephor.".into(),
    }
}

fn load(path: &Path) -> String {
    let result = (|| -> Option<String> {
        let file = std::fs::File::open(path).ok()?;
        if !file.metadata().ok()?.is_file() {
            return None;
        }
        let mut bytes = Vec::new();
        file.take(1024 * 1024 + 1).read_to_end(&mut bytes).ok()?;
        if bytes.len() > 1024 * 1024 {
            return None;
        }
        let data: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
        if data.get("schema")?.as_str()? != "ragbaz.runtime-status.v1" {
            return None;
        }
        let stamp = data.get("observed_unix")?.as_u64()?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_secs();
        let status = if stamp > now {
            "clock-skew"
        } else if now - stamp > 120 {
            "stale"
        } else {
            "current"
        };
        let lines = data.get("summary")?.as_array()?;
        if lines.len() > 1024 {
            return None;
        }
        let mut text = format!("Runtime snapshot: {status} (observations, not authority)\n");
        for line in lines {
            for c in line.as_str()?.chars() {
                text.push(if c.is_control() { ' ' } else { c });
            }
            text.push('\n');
        }
        Some(text)
    })();
    result.unwrap_or_else(|| {
        "Runtime snapshot unavailable or invalid; optional components are unknown.".into()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reports_stale_and_rejects_bad_schema() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("status.json");
        std::fs::write(&path, r#"{"schema":"ragbaz.runtime-status.v1","observed_unix":1,"summary":["minotaur: enabled-but-not-running"]}"#).unwrap();
        let text = load(&path);
        assert!(text.contains("stale"));
        assert!(text.contains("enabled-but-not-running"));
        std::fs::write(&path, "{}").unwrap();
        assert!(load(&path).contains("invalid"));
    }
}
