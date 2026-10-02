use crate::chain::Problem;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
    #[cfg(feature = "sqlite")]
    #[error("{0}")]
    Sqlite(#[from] rusqlite::Error),
    /// An S3/R2 anchor request failed.
    #[cfg(feature = "s3")]
    #[error("s3: {0}")]
    S3(String),
    /// A PUT may have reached storage, but no definitive receipt was obtained.
    #[cfg(feature = "s3")]
    #[error("s3: upload outcome unknown for {key}: {detail}")]
    UploadUncertain { key: String, detail: String },
    /// Object data was stored/found but its identity or retention is unconfirmed.
    #[cfg(feature = "s3")]
    #[error("s3: object {key} may already be stored; verification failed: {detail}")]
    AnchorUnconfirmed { key: String, detail: String },
    /// The original requested Object Lock deadline has elapsed; no renewal is implicit.
    #[cfg(feature = "s3")]
    #[error("anchor intent {key} expired at {retain_until}; publish under a new immutable key with a new deadline")]
    AnchorExpired { key: String, retain_until: String },
    #[cfg(feature = "s3")]
    #[error("external anchor verification failed: {0}")]
    AnchorMismatch(String),
    #[error("{0}")]
    Invalid(String),
    /// Refused to extend a chain that does not verify.
    #[error("the chain is broken, so nothing was appended: {0}")]
    Broken(Problem),
}

pub type Result<T> = std::result::Result<T, Error>;

pub(crate) fn io(path: &std::path::Path) -> impl FnOnce(std::io::Error) -> Error + '_ {
    move |source| Error::Io {
        path: path.display().to_string(),
        source,
    }
}
