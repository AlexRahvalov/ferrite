//! Named Binary Tag (NBT) serialization and deserialization.

use thiserror::Error;

/// Errors produced while reading or writing NBT data.
#[derive(Debug, Error)]
pub enum NbtError {
    /// Unexpected end of input while decoding an NBT payload.
    #[error("unexpected end of NBT input")]
    UnexpectedEof,
}
