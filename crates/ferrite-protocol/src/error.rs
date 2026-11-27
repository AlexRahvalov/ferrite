//! Protocol encoding and decoding error types.

use thiserror::Error;

/// Errors returned by protocol codecs and packet parsers.
#[derive(Debug, Error)]
pub enum ProtocolError {
    /// Input buffer ended before the expected field could be read.
    #[error("unexpected end of packet input")]
    UnexpectedEof,

    /// VarInt exceeded the maximum allowed 5-byte length.
    #[error("VarInt exceeds 5 bytes")]
    VarIntTooLong,

    /// Length prefix was negative.
    #[error("negative length prefix: {0}")]
    NegativeLength(i32),

    /// Packet body exceeded [`crate::MAX_PACKET_LEN`].
    #[error("packet length {len} exceeds maximum {max}")]
    PacketTooLarge { len: usize, max: usize },

    /// String length exceeded the protocol maximum for that field.
    #[error("string length {len} exceeds maximum {max}")]
    StringTooLong { len: usize, max: usize },

    /// String payload was not valid UTF-8.
    #[error("invalid UTF-8 in protocol string: {0}")]
    InvalidUtf8(#[from] std::str::Utf8Error),

    /// Handshake contained an unrecognized next-state intent value.
    #[error("invalid handshake intent: {0}")]
    InvalidIntent(i32),

    /// Packet had unread bytes remaining after decoding.
    #[error("packet had {0} trailing unread bytes")]
    TrailingBytes(usize),

    /// JSON serialization or deserialization failed.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}
