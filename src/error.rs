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
