//! Per-connection protocol state machine (Handshaking, Status, and offline Login).

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use ferrite_protocol::codec::decode_frame;
use ferrite_protocol::{
    decode_exact, offline_uuid, ConnectionState, HandshakePacket, Intent, LoginAcknowledgedPacket,
    LoginDisconnectPacket, LoginStartPacket, LoginSuccessPacket, Packet, PingRequestPacket,
    PongResponsePacket, ServerStatus, StatusRequestPacket, Uuid, GAME_VERSION, PROTOCOL_VERSION,
};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::capture::{sanitize_login_start_wire_frame, save_fixture_once};
use crate::framing::{read_wire_frame_bounded, write_packet_timed};
use crate::{NetError, MAX_PRE_CONFIG_FRAME_LEN};

/// Internal connection phase enforcing strict packet ordering within each state.
#[derive(Debug, Clone)]
enum SessionPhase {
    Handshaking,
    Status {
        received_request: bool,
        client_protocol: i32,
    },
    LoginAwaitingStart {
        client_protocol: i32,
    },
    LoginAwaitingAck {
        username: String,
        uuid: Uuid,
    },
}

impl SessionPhase {
    const fn connection_state(&self) -> ConnectionState {
        match self {
            Self::Handshaking => ConnectionState::Handshaking,
            Self::Status { .. } => ConnectionState::Status,
            Self::LoginAwaitingStart { .. } | Self::LoginAwaitingAck { .. } => {
                ConnectionState::Login
            }
        }
    }

    const fn max_frame_len(&self) -> usize {
        match self {
            Self::Handshaking
            | Self::Status { .. }
            | Self::LoginAwaitingStart { .. }
            | Self::LoginAwaitingAck { .. } => MAX_PRE_CONFIG_FRAME_LEN,
        }
    }
}

/// Processes a single client stream through Handshake, Status, and offline Login states.
pub async fn handle_connection<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    status: Arc<ServerStatus>,
    io_timeout: Duration,
) -> Result<(), NetError> {
    handle_connection_with_timeouts(stream, status, io_timeout, io_timeout, None).await
}

/// Processes a single client stream, optionally saving incoming wire frames to `capture_dir`.
pub async fn handle_connection_with_capture<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    status: Arc<ServerStatus>,
    io_timeout: Duration,
    capture_dir: Option<&Path>,
) -> Result<(), NetError> {
    handle_connection_with_timeouts(stream, status, io_timeout, io_timeout, capture_dir).await
}

pub(crate) async fn handle_connection_with_timeouts<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    status: Arc<ServerStatus>,
    read_timeout: Duration,
    write_timeout: Duration,
    capture_dir: Option<&Path>,
) -> Result<(), NetError> {
    let mut phase = SessionPhase::Handshaking;

    loop {
        let max_len = phase.max_frame_len();
        let frame =
            tokio::time::timeout(read_timeout, read_wire_frame_bounded(&mut stream, max_len))
                .await
                .map_err(|_| NetError::ReadTimeout(read_timeout))??;

        let Some(wire_frame) = frame else {
            return match phase {
                SessionPhase::Handshaking | SessionPhase::Status { .. } => Ok(()),
                other => Err(NetError::ClientClosed(other.connection_state())),
            };
        };

        let (packet_id, payload) = decode_frame(wire_frame.body())?;

        match (&mut phase, packet_id) {
            (SessionPhase::Handshaking, HandshakePacket::ID) => {
                let handshake: HandshakePacket = decode_exact(payload)?;
                println!(
                    "handshake: protocol_version={}, address={}:{}, intent={:?}",
                    handshake.protocol_version,
                    handshake.server_address,
                    handshake.server_port,
                    handshake.next_state
                );
                if handshake.protocol_version == PROTOCOL_VERSION {
                    let fixture_name = match handshake.next_state {
                        Intent::Status => "c2s_handshake_status.bin",
                        Intent::Login => "c2s_handshake_login.bin",
                        Intent::Transfer => "c2s_handshake_transfer.bin",
                    };
                    save_fixture_once(capture_dir, fixture_name, &wire_frame.raw).await?;
                }
                match handshake.next_state {
                    Intent::Status => {
                        phase = SessionPhase::Status {
                            received_request: false,
                            client_protocol: handshake.protocol_version,
                        };
                    }
                    Intent::Login => {
                        phase = SessionPhase::LoginAwaitingStart {
                            client_protocol: handshake.protocol_version,
                        };
                    }
                    Intent::Transfer => return Err(NetError::UnsupportedIntent(Intent::Transfer)),
                }
            }
            (
                SessionPhase::Status {
                    received_request: received @ false,
                    client_protocol,
                },
                StatusRequestPacket::ID,
            ) => {
                let _request: StatusRequestPacket = decode_exact(payload)?;
                *received = true;
                if *client_protocol == PROTOCOL_VERSION {
                    save_fixture_once(capture_dir, "c2s_status_request.bin", &wire_frame.raw)
                        .await?;
                }
                let response = status.into_packet()?;
                write_packet_timed(&mut stream, &response, write_timeout).await?;
            }
            (
                SessionPhase::Status {
                    client_protocol, ..
                },
                PingRequestPacket::ID,
            ) => {
                let ping: PingRequestPacket = decode_exact(payload)?;
                if *client_protocol == PROTOCOL_VERSION {
                    save_fixture_once(capture_dir, "c2s_ping_request.bin", &wire_frame.raw).await?;
                }
                let pong = PongResponsePacket {
                    timestamp: ping.timestamp,
                };
                write_packet_timed(&mut stream, &pong, write_timeout).await?;
                let _ = tokio::time::timeout(write_timeout, stream.shutdown()).await;
                return Ok(());
            }
            (SessionPhase::LoginAwaitingStart { client_protocol }, LoginStartPacket::ID) => {
                let client_protocol = *client_protocol;
                let login_start: LoginStartPacket = decode_exact(payload)?;

                if client_protocol != PROTOCOL_VERSION {
                    let disconnect = LoginDisconnectPacket::from_text(&format!(
                        "Incompatible protocol {client_protocol} (expected {PROTOCOL_VERSION} for {GAME_VERSION})"
                    ))?;
                    write_packet_timed(&mut stream, &disconnect, write_timeout).await?;
                    let _ = tokio::time::timeout(write_timeout, stream.shutdown()).await;
                    return Err(NetError::IncompatibleProtocol {
                        client: client_protocol,
                        server: PROTOCOL_VERSION,
                    });
                }

                if capture_dir.is_some() {
                    let sanitized = sanitize_login_start_wire_frame(&wire_frame)?;
                    save_fixture_once(capture_dir, "c2s_login_start.bin", &sanitized).await?;
                }

                let uuid = offline_uuid(&login_start.username);
                println!(
                    "login start: username={}, client_uuid={}, offline_uuid={uuid}",
                    login_start.username, login_start.player_uuid
                );

                let success = LoginSuccessPacket {
                    uuid,
                    username: login_start.username.clone(),
                    properties: Vec::new(),
                    // TODO(verify): Zero UUID used as placeholder until offline sessionId semantics are verified.
                    session_id: Uuid::default(),
                };
                write_packet_timed(&mut stream, &success, write_timeout).await?;
                phase = SessionPhase::LoginAwaitingAck {
                    username: login_start.username,
                    uuid,
                };
            }
            (SessionPhase::LoginAwaitingAck { username, uuid }, LoginAcknowledgedPacket::ID) => {
                let _ack: LoginAcknowledgedPacket = decode_exact(payload)?;
                save_fixture_once(capture_dir, "c2s_login_acknowledged.bin", &wire_frame.raw)
                    .await?;
                println!(
                    "login acknowledged: username={username}, uuid={uuid} -> transitioning to Configuration"
                );
                // TODO(stub): Configuration state packet handling will be added in Stage 2, Step 2/3.
                return Err(NetError::UnsupportedState(ConnectionState::Configuration));
            }
            (current_phase, id) => {
                return Err(NetError::UnexpectedPacket {
                    state: current_phase.connection_state(),
                    id,
                });
            }
        }
    }
}
