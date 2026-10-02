use nostoi_core::Problem;

/// The error type of the `nostoi` facade.
///
/// The variants are the ones this crate has always exposed, so existing
/// `match` arms keep working. Compartment errors from `nostoi-core` and
/// `nostoi-anchor` convert into it, which is what makes `?` work across a
/// facade function that returns [`Result`].
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
    #[error("unsupported schema for {component}: found {found:?}, supported {supported}")]
    UnsupportedSchema {
        component: &'static str,
        found: String,
        supported: String,
    },
    /// Refused to extend a chain that does not verify.
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
            #[allow(unreachable_patterns)]
            other => Self::Invalid(other.to_string()),
        }
    }
}

#[cfg(feature = "s3")]
impl From<nostoi_anchor::Error> for Error {
    fn from(error: nostoi_anchor::Error) -> Self {
        match error {
            nostoi_anchor::Error::Io { path, source } => Self::Io { path, source },
            #[cfg(feature = "sqlite")]
            nostoi_anchor::Error::Sqlite(error) => Self::Sqlite(error),
            nostoi_anchor::Error::S3(detail) => Self::S3(detail),
            nostoi_anchor::Error::UploadUncertain { key, detail } => {
                Self::UploadUncertain { key, detail }
            }
            nostoi_anchor::Error::AnchorUnconfirmed { key, detail } => {
                Self::AnchorUnconfirmed { key, detail }
            }
            nostoi_anchor::Error::AnchorExpired { key, retain_until } => {
                Self::AnchorExpired { key, retain_until }
            }
            nostoi_anchor::Error::AnchorMismatch(detail) => Self::AnchorMismatch(detail),
            nostoi_anchor::Error::Invalid(detail) => Self::Invalid(detail),
            nostoi_anchor::Error::Broken(problem) => Self::Broken(problem),
            nostoi_anchor::Error::UnsupportedSchema {
                component,
                found,
                supported,
            } => Self::UnsupportedSchema {
                component,
                found,
                supported,
            },
            other => Self::Invalid(other.to_string()),
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
