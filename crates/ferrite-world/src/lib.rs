//! World representation, chunk storage, and Anvil format support.

use ferrite_nbt::NbtError;
use thiserror::Error;

/// Errors produced by world storage and chunk operations.
#[derive(Debug, Error)]
pub enum WorldError {
    /// Underlying NBT decoding or encoding error.
    #[error("NBT error: {0}")]
    Nbt(#[from] NbtError),
}
