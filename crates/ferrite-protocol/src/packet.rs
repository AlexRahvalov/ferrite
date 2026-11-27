//! Packet trait, connection states, and Stage 1 (Handshake + Status) packets.

use crate::codec::{
    encode_frame, read_i64, read_string, read_u16, read_varint, write_i64, write_string, write_u16,
    write_varint,
};
use crate::ProtocolError;

/// Maximum UTF-16 code units allowed in the handshake server address field.
pub const MAX_SERVER_ADDRESS_LEN: usize = 255;

/// Maximum UTF-16 code units allowed in the status response JSON string.
pub const MAX_STATUS_JSON_LEN: usize = 32_767;

/// Connection protocol state machine states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Handshaking,
    Status,
    Login,
    Configuration,
    Play,
}

/// Requested next state sent in the Handshake packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Intent {
    /// Server list ping / status query (`1`).
    Status = 1,
    /// Player login (`2`).
    Login = 2,
    /// Server transfer (`3`).
    // TODO(verify): Confirm transfer intent behavior and restrictions in 26.3.
    Transfer = 3,
}

impl TryFrom<i32> for Intent {
    type Error = ProtocolError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Status),
            2 => Ok(Self::Login),
            3 => Ok(Self::Transfer),
            other => Err(ProtocolError::InvalidIntent(other)),
        }
    }
}

/// Common interface for serializable protocol packets.
pub trait Packet: Sized {
    /// Wire packet ID within its connection state and direction.
    const ID: i32;

    /// Appends this packet's payload (without length prefix or packet ID) to `out`.
    fn encode(&self, out: &mut Vec<u8>) -> Result<(), ProtocolError>;

    /// Decodes this packet's payload from `input`, advancing the slice.
    fn decode(input: &mut &[u8]) -> Result<Self, ProtocolError>;

    /// Encodes this packet as a complete length-prefixed wire frame.
    fn to_frame(&self) -> Result<Vec<u8>, ProtocolError> {
        let mut payload = Vec::new();
        self.encode(&mut payload)?;
        encode_frame(Self::ID, &payload)
    }
}

/// Decodes a packet and fails if any unread trailing bytes remain.
pub fn decode_exact<P: Packet>(mut payload: &[u8]) -> Result<P, ProtocolError> {
    let packet = P::decode(&mut payload)?;
    if !payload.is_empty() {
        return Err(ProtocolError::TrailingBytes(payload.len()));
    }
    Ok(packet)
}

/// Client-to-server Handshake packet (`0x00` in [`ConnectionState::Handshaking`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakePacket {
    pub protocol_version: i32,
    pub server_address: String,
    pub server_port: u16,
    pub next_state: Intent,
}

impl Packet for HandshakePacket {
    const ID: i32 = 0x00;

    fn encode(&self, out: &mut Vec<u8>) -> Result<(), ProtocolError> {
        write_varint(self.protocol_version, out);
        write_string(&self.server_address, MAX_SERVER_ADDRESS_LEN, out)?;
        write_u16(self.server_port, out);
        write_varint(self.next_state as i32, out);
        Ok(())
    }

    fn decode(input: &mut &[u8]) -> Result<Self, ProtocolError> {
        let protocol_version = read_varint(input)?;
        let server_address = read_string(input, MAX_SERVER_ADDRESS_LEN)?;
        let server_port = read_u16(input)?;
        let next_state = Intent::try_from(read_varint(input)?)?;
        Ok(Self {
            protocol_version,
            server_address,
            server_port,
            next_state,
        })
    }
}

/// Client-to-server Status Request packet (`0x00` in [`ConnectionState::Status`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StatusRequestPacket;

impl Packet for StatusRequestPacket {
    const ID: i32 = 0x00;

    fn encode(&self, _out: &mut Vec<u8>) -> Result<(), ProtocolError> {
        Ok(())
    }

    fn decode(_input: &mut &[u8]) -> Result<Self, ProtocolError> {
        Ok(Self)
    }
}

/// Server-to-client Status Response packet (`0x00` in [`ConnectionState::Status`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusResponsePacket {
    pub json: String,
}

impl Packet for StatusResponsePacket {
    const ID: i32 = 0x00;

    fn encode(&self, out: &mut Vec<u8>) -> Result<(), ProtocolError> {
        write_string(&self.json, MAX_STATUS_JSON_LEN, out)
    }

    fn decode(input: &mut &[u8]) -> Result<Self, ProtocolError> {
        let json = read_string(input, MAX_STATUS_JSON_LEN)?;
        Ok(Self { json })
    }
}

/// Client-to-server Ping Request packet (`0x01` in [`ConnectionState::Status`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PingRequestPacket {
    pub timestamp: i64,
}

impl Packet for PingRequestPacket {
    const ID: i32 = 0x01;

    fn encode(&self, out: &mut Vec<u8>) -> Result<(), ProtocolError> {
        write_i64(self.timestamp, out);
        Ok(())
    }

    fn decode(input: &mut &[u8]) -> Result<Self, ProtocolError> {
        let timestamp = read_i64(input)?;
        Ok(Self { timestamp })
    }
}

/// Server-to-client Pong Response packet (`0x01` in [`ConnectionState::Status`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PongResponsePacket {
    pub timestamp: i64,
}

impl Packet for PongResponsePacket {
    const ID: i32 = 0x01;

    fn encode(&self, out: &mut Vec<u8>) -> Result<(), ProtocolError> {
        write_i64(self.timestamp, out);
        Ok(())
    }

    fn decode(input: &mut &[u8]) -> Result<Self, ProtocolError> {
        let timestamp = read_i64(input)?;
        Ok(Self { timestamp })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PROTOCOL_VERSION;

    fn assert_roundtrip<P: Packet + PartialEq + std::fmt::Debug>(packet: &P) {
        let mut payload = Vec::new();
        packet.encode(&mut payload).unwrap();
        let decoded: P = decode_exact(&payload).unwrap();
        assert_eq!(&decoded, packet);
    }

    #[test]
    fn handshake_packet_roundtrip() {
        let packet = HandshakePacket {
            protocol_version: PROTOCOL_VERSION,
            server_address: "localhost".to_owned(),
            server_port: 25565,
            next_state: Intent::Status,
        };
        assert_roundtrip(&packet);
    }

    #[test]
    fn handshake_rejects_invalid_intent() {
        let mut payload = Vec::new();
        write_varint(PROTOCOL_VERSION, &mut payload);
        write_string("localhost", MAX_SERVER_ADDRESS_LEN, &mut payload).unwrap();
        write_u16(25565, &mut payload);
        write_varint(99, &mut payload);

        assert!(matches!(
            decode_exact::<HandshakePacket>(&payload),
            Err(ProtocolError::InvalidIntent(99))
        ));
    }

    #[test]
    fn status_request_packet_roundtrip() {
        assert_roundtrip(&StatusRequestPacket);
        assert!(matches!(
            decode_exact::<StatusRequestPacket>(&[0x00]),
            Err(ProtocolError::TrailingBytes(1))
        ));
    }

    #[test]
    fn status_response_packet_roundtrip() {
        let packet = StatusResponsePacket {
            json: r#"{"version":{"name":"26.3","protocol":777}}"#.to_owned(),
        };
        assert_roundtrip(&packet);
    }

    #[test]
    fn ping_request_packet_roundtrip() {
        assert_roundtrip(&PingRequestPacket {
            timestamp: 1_732_700_000_123,
        });
    }

    #[test]
    fn pong_response_packet_roundtrip() {
        assert_roundtrip(&PongResponsePacket {
            timestamp: -42_000_001,
        });
    }
}
