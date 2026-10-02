//! # Nostoi anchor
//!
//! The network checkpoint compartment: publish a verified chain head to
//! S3-compatible storage, verify it again later, and recover interrupted
//! publications from a durable outbox. It knows nothing about the CLI or about
//! kernel log ingestion, and it needs no credentials beyond the scope the
//! deployment gives it.
//!
//! - [`prepare_anchor`] computes a write-once checkpoint without any network
//!   access, so the exact bytes that will be PUT can be stored first.
//! - [`anchor`] publishes a checkpoint; [`outbox`] makes that publication
//!   crash-safe by writing the request before it is attempted.
//! - [`verify_checkpoint`] compares a local chain against a trusted remote
//!   checkpoint and names the first sequence that no longer fits.
//!
//! [`fanout`] publishes one checkpoint to several independent destinations and
//! requires them to agree before trusting any of them.
//!
//! See [`anchor`] for provider differences (AWS S3 Object Lock and Cloudflare R2
//! bucket locks) and [`outbox`] for the recovery contract.

pub mod anchor;
mod error;
pub mod fanout;
#[cfg(feature = "sqlite")]
pub mod outbox;
pub mod s3;
pub use error::{Error, Result};
