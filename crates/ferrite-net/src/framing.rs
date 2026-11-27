//! Uncompressed VarInt wire-frame reading and writing.

use std::time::Duration;

use ferrite_protocol::codec::{decode_varint_prefix, MAX_VARINT_BYTES};
use ferrite_protocol::{Packet, ProtocolError, MAX_PACKET_LEN};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::NetError;

/// Exact raw wire frame (`Length | PacketID | Payload`) read from a stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireFrame {
    /// Complete wire bytes including the VarInt length prefix.
    pub raw: Vec<u8>,
    pub(crate) header_len: usize,
}

impl WireFrame {
    /// Returns the packet body slice (`PacketID | Payload`) after the length prefix.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.raw[self.header_len..]
    }
}

/// Reads a single uncompressed VarInt-framed packet from `reader`, preserving raw wire bytes.
///
/// Returns `Ok(None)` on clean EOF between frames.
pub async fn read_wire_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<Option<WireFrame>, NetError> {
    read_wire_frame_bounded(reader, MAX_PACKET_LEN).await
}

/// Reads a single uncompressed VarInt-framed packet with an explicit `max_body_len` bound.
pub async fn read_wire_frame_bounded<R: AsyncRead + Unpin>(
    reader: &mut R,
    max_body_len: usize,
) -> Result<Option<WireFrame>, NetError> {
    let max_allowed = max_body_len.min(MAX_PACKET_LEN);
    let mut prefix = [0u8; MAX_VARINT_BYTES];
    let mut prefix_len = 0;

    let frame_len = loop {
        let mut byte = [0u8; 1];
        let read = reader.read(&mut byte).await?;
        if read == 0 {
            if prefix_len == 0 {
                return Ok(None);
            }
            return Err(NetError::Protocol(ProtocolError::UnexpectedEof));
        }

        prefix[prefix_len] = byte[0];
        prefix_len += 1;

        if let Some((raw_len, _)) = decode_varint_prefix(&prefix[..prefix_len])? {
            if raw_len < 0 {
                return Err(NetError::Protocol(ProtocolError::NegativeLength(raw_len)));
            }
            let len = raw_len as usize;
            if len > max_allowed {
                return Err(NetError::Protocol(ProtocolError::PacketTooLarge {
                    len,
                    max: max_allowed,
                }));
            }
            break len;
        }
    };

    let initial_cap = (prefix_len + frame_len).min(8192);
    let mut raw = Vec::with_capacity(initial_cap);
    raw.extend_from_slice(&prefix[..prefix_len]);
    reader.take(frame_len as u64).read_to_end(&mut raw).await?;
    if raw.len() != prefix_len + frame_len {
        return Err(NetError::Protocol(ProtocolError::UnexpectedEof));
    }
    Ok(Some(WireFrame {
        raw,
        header_len: prefix_len,
    }))
}

/// Reads a single uncompressed VarInt-framed packet body from `reader`.
///
/// Returns `Ok(None)` on clean EOF between frames.
pub async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Option<Vec<u8>>, NetError> {
    Ok(read_wire_frame(reader)
        .await?
        .map(|frame| frame.body().to_vec()))
}

/// Writes a packet as a length-prefixed frame and flushes `writer`.
pub async fn write_packet<W: AsyncWrite + Unpin, P: Packet>(
    writer: &mut W,
    packet: &P,
) -> Result<(), NetError> {
    let frame = packet.to_frame()?;
    writer.write_all(&frame).await?;
    writer.flush().await?;
    Ok(())
}

pub(crate) async fn write_packet_timed<W: AsyncWrite + Unpin, P: Packet>(
    writer: &mut W,
    packet: &P,
    write_timeout: Duration,
) -> Result<(), NetError> {
    tokio::time::timeout(write_timeout, write_packet(writer, packet))
        .await
        .map_err(|_| NetError::WriteTimeout(write_timeout))?
}
