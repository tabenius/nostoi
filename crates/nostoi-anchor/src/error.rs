use nostoi_core::Problem;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Core(nostoi_core::Error),
    #[error("{path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
    #[cfg(feature = "sqlite")]
    #[error("{0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("s3: {0}")]
    S3(String),
    #[error("s3: upload outcome unknown for {key}: {detail}")]
    UploadUncertain { key: String, detail: String },
    #[error("s3: object {key} may already be stored; verification failed: {detail}")]
    AnchorUnconfirmed { key: String, detail: String },
    /// The original requested Object Lock deadline has elapsed; no renewal is implicit.
    #[error("anchor intent {key} expired at {retain_until}; publish under a new immutable key with a new deadline")]
    AnchorExpired { key: String, retain_until: String },
    #[error("external anchor verification failed: {0}")]
    AnchorMismatch(String),
    #[error("{0}")]
    Invalid(String),
    #[error("unsupported schema for {component}: found {found:?}, supported {supported}")]
    UnsupportedSchema {
        component: &'static str,
        found: String,
        supported: String,
    },
    #[error("the chain is broken, so nothing was appended: {0}")]
    Broken(Problem),
}

impl From<nostoi_core::Error> for Error {
    fn from(error: nostoi_core::Error) -> Self {
        match error {
            nostoi_core::Error::Io { path, source } => Self::Io { path, source },
            nostoi_core::Error::Invalid(detail) => Self::Invalid(detail),
            nostoi_core::Error::Broken(problem) => Self::Broken(problem),
            nostoi_core::Error::UnsupportedSchema {
                component,
                found,
                supported,
            } => Self::UnsupportedSchema {
                component,
                found,
                supported,
            },
            #[cfg(feature = "sqlite")]
            nostoi_core::Error::Sqlite(error) => Self::Sqlite(error),
            // Core SQLite may be feature-unified by another workspace member.
            #[allow(unreachable_patterns)]
            other => Self::Core(other),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
pub(crate) fn io(path: &std::path::Path) -> impl FnOnce(std::io::Error) -> Error + '_ {
    move |source| Error::Io {
        path: path.display().to_string(),
        source,
    }
}
