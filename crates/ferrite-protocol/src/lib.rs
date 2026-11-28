//! Wire protocol codecs, packet definitions, and connection states for Ferrite.
//!
//! Target protocol: Java Edition 26.3 (protocol version 777).

pub mod codec;
pub mod config_data;
pub mod error;
pub mod login;
pub mod packet;
pub mod status;
pub mod uuid;

pub use config_data::{
    ConfigDataError, ConfigurationData, KnownPackEntry, RegistrySkeleton, TagGroupEntry,
    TagRegistryEntry,
};
pub use error::ProtocolError;
pub use login::{
    LoginAcknowledgedPacket, LoginDisconnectPacket, LoginProperty, LoginStartPacket,
    LoginSuccessPacket,
};
pub use packet::{
    decode_exact, ConnectionState, HandshakePacket, Intent, Packet, PingRequestPacket,
    PongResponsePacket, StatusRequestPacket, StatusResponsePacket,
};
pub use status::{Description, PlayerSample, PlayersInfo, ServerStatus, VersionInfo};
pub use uuid::{offline_uuid, Uuid};

/// Target game version string reported in server list status.
pub const GAME_VERSION: &str = "26.3";

/// Target network protocol version for Java Edition 26.3.
///
/// Source: community protocol version table (wiki.vg / Minecraft Wiki) and
/// verified empirically against an official 26.3 client handshake (`protocol_version=777`).
pub const PROTOCOL_VERSION: i32 = 777;

/// Maximum uncompressed packet body length (2 MiB - 1, fits in a 3-byte VarInt).
pub const MAX_PACKET_LEN: usize = 2_097_151;
