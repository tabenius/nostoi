use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::PyErr;
use std::path::PathBuf;

fn error(e: impl std::fmt::Display) -> PyErr {
    PyValueError::new_err(e.to_string())
}

/// Errors from a function that touches storage keep their own Python type.
///
/// A missing file is not a malformed argument, and `except FileNotFoundError` is
/// what a caller writes, so io and sqlite failures become OSError while
/// everything else stays ValueError. Flattening all of them into one type would
/// make "the file is not there" indistinguishable from "the file is wrong".
fn chain_error(e: nostoi_core::Error) -> PyErr {
    match e {
        nostoi_core::Error::Io { source, .. } => PyErr::from(source),
        // rusqlite has no PyErr conversion of its own; its messages describe a
        // storage failure, so OSError is the honest type.
        nostoi_core::Error::Sqlite(source) => PyErr::from(std::io::Error::other(source)),
        other => PyValueError::new_err(other.to_string()),
    }
}

/// The same rule for the facade's error type, which carries the storage and
/// remote-fetch failures the core does not have.
fn store_error(e: nostoi::Error) -> PyErr {
    match e {
        nostoi::Error::Io { source, .. } => PyErr::from(source),
        nostoi::Error::Sqlite(source) => PyErr::from(std::io::Error::other(source)),
        other => PyValueError::new_err(other.to_string()),
    }
}

#[pyfunction]
fn canonical_json(json: &str) -> PyResult<String> {
    nostoi::portable::canonical_json(json).map_err(error)
}

#[pyfunction]
#[pyo3(signature = (jsonl, format=None))]
fn verify_jsonl(jsonl: &str, format: Option<&str>) -> PyResult<String> {
    nostoi::portable::verify_jsonl(jsonl, format).map_err(error)
}

#[pyfunction]
#[pyo3(signature = (path, format=None))]
fn verify(path: PathBuf, format: Option<&str>) -> PyResult<String> {
    let format = format
        .map(str::parse)
        .transpose()
        .map_err(PyValueError::new_err)?;
    let report = nostoi::verify(&path, format).map_err(store_error)?;
    serde_json::to_string(&report).map_err(|e| PyValueError::new_err(e.to_string()))
}

#[pyfunction]
#[pyo3(signature = (path, kind, body_json, actor=None, subject=None, at=None))]
fn append(
    path: PathBuf,
    kind: &str,
    body_json: &str,
    actor: Option<&str>,
    subject: Option<&str>,
    at: Option<String>,
) -> PyResult<String> {
    let body = serde_json::from_str(body_json).map_err(|e| PyValueError::new_err(e.to_string()))?;
    let entry = nostoi::append(
        &path,
        nostoi::Draft {
            kind,
            body,
            actor,
            subject,
            at,
        },
    )
    .map_err(store_error)?;
    Ok(nostoi::canonical::to_string(&entry.record))
}

#[pyfunction]
#[pyo3(signature = (jsonl, kind, body_json, at, actor=None, subject=None))]
fn append_jsonl(
    jsonl: &str,
    kind: &str,
    body_json: &str,
    at: String,
    actor: Option<&str>,
    subject: Option<&str>,
) -> PyResult<String> {
    let body = serde_json::from_str(body_json).map_err(|e| PyValueError::new_err(e.to_string()))?;
    nostoi::portable::append_jsonl(
        jsonl,
        nostoi::Draft {
            kind,
            body,
            actor,
            subject,
            at: Some(at),
        },
    )
    .map_err(error)
}

/// The canonical bytes an attestation document's signature covers, and their digest.
///
/// No filesystem and no `ssh-keygen`: this is the portable half, so a Python caller
/// can check that a document it was handed is well formed and reproduce exactly
/// what was signed. Checking the *signature* needs `ssh-keygen`; checking the
/// document against a chain does not.
#[pyfunction]
fn attestation_canonical_bytes(document_json: &str) -> PyResult<String> {
    let attestation: nostoi_core::attestation::Attestation = serde_json::from_str(document_json)
        .map_err(|error| PyValueError::new_err(format!("invalid attestation: {error}")))?;
    attestation.validate().map_err(chain_error)?;
    let bytes = attestation.canonical_bytes().map_err(chain_error)?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// Check an attestation document against a chain, returning a JSON report.
///
/// Reports rather than raises for the interesting outcomes, the way `verify_jsonl`
/// reports a broken chain instead of raising: "this attestation is stale" is an
/// answer, not an exception. A malformed document or a chain that does not match
/// is an exception, because those are mistakes rather than findings.
#[pyfunction]
#[pyo3(signature = (path, document_json, format=None))]
fn verify_attestation(
    path: PathBuf,
    document_json: &str,
    format: Option<&str>,
) -> PyResult<String> {
    let attestation: nostoi_core::attestation::Attestation = serde_json::from_str(document_json)
        .map_err(|error| PyValueError::new_err(format!("invalid attestation: {error}")))?;
    attestation.validate().map_err(chain_error)?;
    let format = format
        .map(str::parse)
        .transpose()
        .map_err(PyValueError::new_err)?;
    let checked =
        nostoi_core::attestation::check(&path, &attestation, format).map_err(chain_error)?;
    let report = serde_json::json!({
        "ok": true,
        // Always "unchecked": this function has no allowed-signers file, so it
        // cannot have verified the signature and must not imply that it did.
        "signature": "unchecked",
        "chain": attestation.chain,
        "format": attestation.format,
        "seq": attestation.seq,
        "digest": attestation.digest,
        "anchored_at": attestation.anchored_at,
        "principal": attestation.principal,
        "fingerprint": attestation.fingerprint,
        "anchor_key": attestation.anchor_key,
        "title": attestation.title,
        "manifest": attestation.manifest,
        "author": attestation.author,
        "document_digest": attestation.digest().ok(),
        "coverage": match checked.coverage {
            nostoi_core::attestation::Coverage::Current => serde_json::json!("current"),
            nostoi_core::attestation::Coverage::Stale { ahead_by } => {
                serde_json::json!({"stale": true, "ahead_by": ahead_by})
            }
            nostoi_core::attestation::Coverage::Truncated => serde_json::json!("truncated"),
            nostoi_core::attestation::Coverage::Rewritten => serde_json::json!("rewritten"),
            nostoi_core::attestation::Coverage::Empty => serde_json::json!("empty"),
        },
        "covers_head": checked.covers_head(),
        "head": checked.head,
    });
    serde_json::to_string(&report).map_err(error)
}

#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(canonical_json, m)?)?;
    m.add_function(wrap_pyfunction!(verify_jsonl, m)?)?;
    m.add_function(wrap_pyfunction!(append_jsonl, m)?)?;
    m.add_function(wrap_pyfunction!(verify, m)?)?;
    m.add_function(wrap_pyfunction!(append, m)?)?;
    m.add_function(wrap_pyfunction!(attestation_canonical_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(verify_attestation, m)?)?;
    Ok(())
}
