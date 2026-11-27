//! Wire protocol codecs, packet definitions, and connection states for Ferrite.
//!
//! Target protocol: Java Edition 26.3 (protocol version 777).

pub mod codec;
pub mod error;
pub mod packet;
pub mod status;

pub use error::ProtocolError;
pub use packet::{
    decode_exact, ConnectionState, HandshakePacket, Intent, Packet, PingRequestPacket,
    PongResponsePacket, StatusRequestPacket, StatusResponsePacket,
};
pub use status::{Description, PlayerSample, PlayersInfo, ServerStatus, VersionInfo};

/// Target game version string reported in server list status.
pub const GAME_VERSION: &str = "26.3";

/// Target network protocol version for Java Edition 26.3.
///
/// Source: community protocol version table (wiki.vg / Minecraft Wiki) and
/// verified empirically against an official 26.3 client handshake (`protocol_version=777`).
pub const PROTOCOL_VERSION: i32 = 777;

/// Maximum uncompressed packet body length (2 MiB - 1, fits in a 3-byte VarInt).
pub const MAX_PACKET_LEN: usize = 2_097_151;
