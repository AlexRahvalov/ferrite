//! Server List Ping (SLP) JSON status payload model.

use serde::{Deserialize, Serialize};

use crate::{ProtocolError, StatusResponsePacket};

/// Top-level JSON structure returned in [`StatusResponsePacket`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerStatus {
    pub version: VersionInfo,
    pub players: PlayersInfo,
    pub description: Description,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub favicon: Option<String>,
    // TODO(verify): Confirm whether 26.3 clients expect `enforcesSecureChat` in SLP JSON.
    #[serde(rename = "enforcesSecureChat", skip_serializing_if = "Option::is_none")]
    pub enforces_secure_chat: Option<bool>,
}

/// Server version metadata in the status response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionInfo {
    pub name: String,
    pub protocol: i32,
}

/// Online/maximum player counts and optional sample list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlayersInfo {
    pub max: u32,
    pub online: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sample: Vec<PlayerSample>,
}

/// Single entry in the status player sample hover list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlayerSample {
    pub name: String,
    pub id: String,
}

/// Text component for server description (MOTD).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Description {
    pub text: String,
}

impl ServerStatus {
    /// Serializes this status payload into a [`StatusResponsePacket`].
    pub fn into_packet(&self) -> Result<StatusResponsePacket, ProtocolError> {
        let json = serde_json::to_string(self)?;
        Ok(StatusResponsePacket { json })
    }

    /// Deserializes a [`StatusResponsePacket`] JSON payload into [`ServerStatus`].
    pub fn from_packet(packet: &StatusResponsePacket) -> Result<Self, ProtocolError> {
        Ok(serde_json::from_str(&packet.json)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{GAME_VERSION, PROTOCOL_VERSION};

    #[test]
    fn status_json_roundtrip() {
        let status = ServerStatus {
            version: VersionInfo {
                name: GAME_VERSION.to_owned(),
                protocol: PROTOCOL_VERSION,
            },
            players: PlayersInfo {
                max: 100,
                online: 0,
                sample: Vec::new(),
            },
            description: Description {
                text: "Ferrite Server".to_owned(),
            },
            favicon: None,
            enforces_secure_chat: None,
        };

        let packet = status.into_packet().unwrap();
        let parsed: ServerStatus = serde_json::from_str(&packet.json).unwrap();
        assert_eq!(parsed, status);
    }
}
