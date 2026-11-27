//! Login-state packets (Stage 2, Step 1 — offline mode).
//!
//! Protocol sources:
//! - `PrismarineJS/minecraft-data` PR #1301 (`data/pc/26.3/protocol.json`, `login` section, MIT license).
//! - Community protocol wiki (`Java Edition protocol/Packets#Login`).
//! - `Login Start` (`0x00`), `Login Success` (`0x02`, including trailing `session_id: UUID`),
//!   and `Login Acknowledged` (`0x03`) empirically verified against an official 26.3 client (`protocol 777`).

use crate::codec::{
    read_bool, read_string, read_uuid, read_varint, write_bool, write_string, write_uuid,
    write_varint,
};
use crate::{Description, Packet, ProtocolError, Uuid};

/// Maximum UTF-16 code units allowed in a player username (`String(16)`).
pub const MAX_USERNAME_LEN: usize = 16;

/// Maximum UTF-16 code units allowed in a login disconnect JSON reason (`String(262144)`).
pub const MAX_DISCONNECT_REASON_LEN: usize = 262_144;

/// Maximum number of profile properties allowed in `Login Success`.
pub const MAX_LOGIN_PROPERTIES: usize = 16;

/// Maximum UTF-16 code units allowed in a profile property name (`String(64)`).
pub const MAX_PROPERTY_NAME_LEN: usize = 64;

/// Maximum UTF-16 code units allowed in a profile property value (`String(32767)`).
pub const MAX_PROPERTY_VALUE_LEN: usize = 32_767;

/// Maximum UTF-16 code units allowed in a profile property signature (`String(1024)`).
pub const MAX_PROPERTY_SIGNATURE_LEN: usize = 1_024;

/// Client-to-server `Login Start` packet (`0x00` in [`crate::ConnectionState::Login`]).
///
/// Wire layout (`pc/26.1/protocol.json` -> `login.toServer.packet_login_start`):
/// 1. `username`: `String(16)`
/// 2. `player_uuid`: `UUID` (16 bytes big-endian)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginStartPacket {
    pub username: String,
    pub player_uuid: Uuid,
}

impl Packet for LoginStartPacket {
    const ID: i32 = 0x00;

    fn encode(&self, out: &mut Vec<u8>) -> Result<(), ProtocolError> {
        write_string(&self.username, MAX_USERNAME_LEN, out)?;
        write_uuid(self.player_uuid, out);
        Ok(())
    }

    fn decode(input: &mut &[u8]) -> Result<Self, ProtocolError> {
        let username = read_string(input, MAX_USERNAME_LEN)?;
        let player_uuid = read_uuid(input)?;
        Ok(Self {
            username,
            player_uuid,
        })
    }
}

/// Server-to-client `Disconnect (login)` packet (`0x00` in [`crate::ConnectionState::Login`]).
///
/// Wire layout (`PrismarineJS/minecraft-data` PR #1301 `data/pc/26.3/protocol.json`
/// -> `login.toClient.packet_disconnect`):
/// 1. `reason_json`: `String(262144)` (JSON Text Component)
// TODO(verify): Confirm empirically on an official 26.3 client that Login Disconnect (`0x00`)
// still parses a JSON string rather than an NBT text component.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginDisconnectPacket {
    pub reason_json: String,
}

impl LoginDisconnectPacket {
    /// Builds a [`LoginDisconnectPacket`] with a JSON text component `{"text": ...}`.
    pub fn from_text(text: &str) -> Result<Self, ProtocolError> {
        let reason_json = serde_json::to_string(&Description {
            text: text.to_owned(),
        })?;
        Ok(Self { reason_json })
    }
}

impl Packet for LoginDisconnectPacket {
    const ID: i32 = 0x00;

    fn encode(&self, out: &mut Vec<u8>) -> Result<(), ProtocolError> {
        write_string(&self.reason_json, MAX_DISCONNECT_REASON_LEN, out)
    }

    fn decode(input: &mut &[u8]) -> Result<Self, ProtocolError> {
        let reason_json = read_string(input, MAX_DISCONNECT_REASON_LEN)?;
        Ok(Self { reason_json })
    }
}

/// Single profile property entry inside [`LoginSuccessPacket`].
///
/// Wire layout (`pc/26.1/protocol.json` -> `login.toClient.packet_success.properties`):
/// 1. `name`: `String(64)`
/// 2. `value`: `String(32767)`
/// 3. `signature`: `Option<String(1024)>` (`Boolean` presence flag + optional `String`)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginProperty {
    pub name: String,
    pub value: String,
    pub signature: Option<String>,
}

/// Server-to-client `Login Success` packet (`0x02` in [`crate::ConnectionState::Login`]).
///
/// Wire layout (`PrismarineJS/minecraft-data` PR #1301 `data/pc/26.3/protocol.json`
/// -> `login.toClient.packet_success`, MIT license; empirically verified against official
/// 26.3 client via receipt of `Login Acknowledged` `0x03`):
/// 1. `uuid`: `UUID` (16 bytes big-endian)
/// 2. `username`: `String(16)`
/// 3. `properties`: `VarInt` length + `LoginProperty` elements
/// 4. `session_id`: `UUID` (16 bytes big-endian)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginSuccessPacket {
    pub uuid: Uuid,
    pub username: String,
    pub properties: Vec<LoginProperty>,
    /// Connection session identifier appended in 26.3 (`PrismarineJS/minecraft-data` PR #1301).
    // TODO(verify): Confirm whether non-zero session UUID is required by 26.3 in Play/chat states.
    pub session_id: Uuid,
}

impl Packet for LoginSuccessPacket {
    const ID: i32 = 0x02;

    fn encode(&self, out: &mut Vec<u8>) -> Result<(), ProtocolError> {
        if self.properties.len() > MAX_LOGIN_PROPERTIES {
            return Err(ProtocolError::ArrayTooLong {
                len: self.properties.len(),
                max: MAX_LOGIN_PROPERTIES,
            });
        }
        let count =
            i32::try_from(self.properties.len()).map_err(|_| ProtocolError::ArrayTooLong {
                len: self.properties.len(),
                max: MAX_LOGIN_PROPERTIES,
            })?;

        write_uuid(self.uuid, out);
        write_string(&self.username, MAX_USERNAME_LEN, out)?;
        write_varint(count, out);
        for prop in &self.properties {
            write_string(&prop.name, MAX_PROPERTY_NAME_LEN, out)?;
            write_string(&prop.value, MAX_PROPERTY_VALUE_LEN, out)?;
            match &prop.signature {
                Some(sig) => {
                    write_bool(true, out);
                    write_string(sig, MAX_PROPERTY_SIGNATURE_LEN, out)?;
                }
                None => write_bool(false, out),
            }
        }
        write_uuid(self.session_id, out);
        Ok(())
    }

    fn decode(input: &mut &[u8]) -> Result<Self, ProtocolError> {
        let uuid = read_uuid(input)?;
        let username = read_string(input, MAX_USERNAME_LEN)?;
        let raw_count = read_varint(input)?;
        if raw_count < 0 {
            return Err(ProtocolError::NegativeLength(raw_count));
        }
        let count = raw_count as usize;
        if count > MAX_LOGIN_PROPERTIES {
            return Err(ProtocolError::ArrayTooLong {
                len: count,
                max: MAX_LOGIN_PROPERTIES,
            });
        }

        let mut properties = Vec::with_capacity(count);
        for _ in 0..count {
            let name = read_string(input, MAX_PROPERTY_NAME_LEN)?;
            let value = read_string(input, MAX_PROPERTY_VALUE_LEN)?;
            let has_sig = read_bool(input)?;
            let signature = if has_sig {
                Some(read_string(input, MAX_PROPERTY_SIGNATURE_LEN)?)
            } else {
                None
            };
            properties.push(LoginProperty {
                name,
                value,
                signature,
            });
        }

        let session_id = read_uuid(input)?;

        Ok(Self {
            uuid,
            username,
            properties,
            session_id,
        })
    }
}

/// Client-to-server `Login Acknowledged` packet (`0x03` in [`crate::ConnectionState::Login`]).
///
/// Wire layout (`pc/26.1/protocol.json` -> `login.toServer.packet_login_acknowledged`):
/// empty payload. Transitions the connection to [`crate::ConnectionState::Configuration`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LoginAcknowledgedPacket;

impl Packet for LoginAcknowledgedPacket {
    const ID: i32 = 0x03;

    fn encode(&self, _out: &mut Vec<u8>) -> Result<(), ProtocolError> {
        Ok(())
    }

    fn decode(_input: &mut &[u8]) -> Result<Self, ProtocolError> {
        Ok(Self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{decode_exact, offline_uuid};

    fn assert_roundtrip<P: Packet + PartialEq + std::fmt::Debug>(packet: &P) {
        let mut buf = Vec::new();
        packet.encode(&mut buf).unwrap();
        let decoded: P = decode_exact(&buf).unwrap();
        assert_eq!(&decoded, packet);
    }

    #[test]
    fn login_start_roundtrip() {
        let packet = LoginStartPacket {
            username: "TestPlayer".to_owned(),
            player_uuid: offline_uuid("TestPlayer"),
        };
        assert_roundtrip(&packet);
    }

    #[test]
    fn login_disconnect_roundtrip() {
        let packet = LoginDisconnectPacket::from_text("Server closed").unwrap();
        assert_roundtrip(&packet);
        assert_eq!(packet.reason_json, r#"{"text":"Server closed"}"#);
    }

    #[test]
    fn login_success_roundtrip_empty_and_with_properties() {
        let empty = LoginSuccessPacket {
            uuid: offline_uuid("TestPlayer"),
            username: "TestPlayer".to_owned(),
            properties: Vec::new(),
            session_id: Uuid::default(),
        };
        assert_roundtrip(&empty);

        let with_props = LoginSuccessPacket {
            uuid: offline_uuid("TestPlayer"),
            username: "TestPlayer".to_owned(),
            properties: vec![
                LoginProperty {
                    name: "textures".to_owned(),
                    value: "eyJ0ZXh0dXJlcyI6e319".to_owned(),
                    signature: Some("sig_base64".to_owned()),
                },
                LoginProperty {
                    name: "unsigned_prop".to_owned(),
                    value: "val".to_owned(),
                    signature: None,
                },
            ],
            session_id: offline_uuid("Session"),
        };
        assert_roundtrip(&with_props);
    }

    #[test]
    fn login_acknowledged_roundtrip_and_trailing_check() {
        assert_roundtrip(&LoginAcknowledgedPacket);
        assert!(matches!(
            decode_exact::<LoginAcknowledgedPacket>(&[0x01]),
            Err(ProtocolError::TrailingBytes(1))
        ));
    }
}
