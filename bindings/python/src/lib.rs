use pyo3::exceptions::{PyOSError, PyValueError};
use pyo3::prelude::*;
use std::path::PathBuf;

fn error(e: nostoi::Error) -> PyErr {
    match e {
        nostoi::Error::Io { .. } => PyOSError::new_err(e.to_string()),
        _ => PyValueError::new_err(e.to_string()),
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
    let report = nostoi::verify(&path, format).map_err(error)?;
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
    .map_err(error)?;
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

#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(canonical_json, m)?)?;
    m.add_function(wrap_pyfunction!(verify_jsonl, m)?)?;
    m.add_function(wrap_pyfunction!(append_jsonl, m)?)?;
    m.add_function(wrap_pyfunction!(verify, m)?)?;
    m.add_function(wrap_pyfunction!(append, m)?)?;
    Ok(())
}
