#![doc = include_str!("../README.md")]
#![warn(missing_docs, unused_crate_dependencies)]

mod crypto;
mod handshake;
mod msg;

pub mod listener;
pub mod stream;

// Export server related modules
pub use listener::{BlazeAccept, BlazeListener, BlazeServerContext, Certificate, RsaPrivateKey};
// Export stream
pub use stream::BlazeStream;
