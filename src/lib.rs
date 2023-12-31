#![doc = include_str!("../README.md")]
#![warn(missing_docs, unused_crate_dependencies)]

mod crypto;
mod handshake;
mod msg;

pub mod data;

/// Module containing stream related logic
pub mod stream;

/// Re-export all stream types
pub use stream::*;
