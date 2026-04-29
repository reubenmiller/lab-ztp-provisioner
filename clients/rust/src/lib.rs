//! ZTP Agent — Rust implementation, library component.
//!
//! All protocol modules are exposed here so integration tests and any future
//! library consumers can import them directly.

pub mod appliers;
pub mod ble;
pub mod canonical;
pub mod clock;
pub mod encrypt;
pub mod enroll;
pub mod facts;
pub mod identity;
pub mod logging;
pub mod mdns;
pub mod sign;
pub mod transport;
pub mod wire;

/// Shared error type for the whole crate.
pub type Error = Box<dyn std::error::Error + Send + Sync>;
/// Shared result type for the whole crate.
pub type Result<T> = std::result::Result<T, Error>;
