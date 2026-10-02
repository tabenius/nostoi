#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The bytes are not a `/dev/kmsg` record.
    #[error("not a kmsg record: {0}")]
    Malformed(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
