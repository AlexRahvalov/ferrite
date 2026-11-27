//! Async TCP networking layer for Ferrite.

use std::future::Future;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use ferrite_protocol::codec::{decode_frame, decode_varint_prefix, MAX_VARINT_BYTES};
use ferrite_protocol::{
    decode_exact, offline_uuid, ConnectionState, HandshakePacket, Intent, LoginAcknowledgedPacket,
    LoginDisconnectPacket, LoginStartPacket, LoginSuccessPacket, Packet, PingRequestPacket,
    PongResponsePacket, ProtocolError, ServerStatus, StatusRequestPacket, Uuid, GAME_VERSION,
    MAX_PACKET_LEN, PROTOCOL_VERSION,
};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

/// Default per-frame read timeout for client connections.
pub const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// Default per-packet write timeout for client connections.
pub const DEFAULT_WRITE_TIMEOUT: Duration = Duration::from_secs(10);

/// Backoff pause between repeated `listener.accept()` errors (e.g. FD exhaustion).
pub const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(50);

/// Default maximum number of concurrent client connections.
pub const DEFAULT_MAX_CONNECTIONS: usize = 1024;

/// Maximum incoming packet body length permitted in Handshaking, Status, and Login states.
pub const MAX_PRE_CONFIG_FRAME_LEN: usize = 4096;

/// Maximum raw wire frame size (in bytes) written when `capture_dir` is enabled.
pub const MAX_CAPTURE_FRAME_BYTES: usize = 65_536;

/// Deterministic placeholder UUID written into captured `Login Start` fixtures
/// (`00010203-0405-0607-0809-0a0b0c0d0e0f`) so account UUIDs never touch disk.
pub const SANITIZED_FIXTURE_UUID: Uuid = Uuid::from_bytes([
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
]);

/// Runtime configuration for [`ServerListener`].
#[derive(Debug, Clone)]
pub struct NetConfig {
    /// Maximum time to wait for a complete incoming packet frame.
    pub read_timeout: Duration,
    /// Maximum time to wait for an outgoing packet frame write + flush.
    pub write_timeout: Duration,
    /// Maximum number of concurrent client connections accepted at once.
    pub max_connections: usize,
    /// Optional directory where raw incoming wire frames are saved once as `.bin` fixtures.
    pub capture_dir: Option<PathBuf>,
}

impl Default for NetConfig {
    fn default() -> Self {
        Self {
            read_timeout: DEFAULT_READ_TIMEOUT,
            write_timeout: DEFAULT_WRITE_TIMEOUT,
            max_connections: DEFAULT_MAX_CONNECTIONS,
            capture_dir: None,
        }
    }
}

/// Errors returned by the networking layer.
#[derive(Debug, Error)]
pub enum NetError {
    /// Underlying socket I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Protocol framing or packet decoding error.
    #[error("protocol error: {0}")]
    Protocol(#[from] ProtocolError),

    /// Client did not send a complete frame before the configured timeout.
    #[error("read timed out after {0:?}")]
    ReadTimeout(Duration),

    /// Outgoing frame write did not complete before the configured timeout.
    #[error("write timed out after {0:?}")]
    WriteTimeout(Duration),

    /// Client sent a packet ID not valid for the current connection state.
    #[error("unexpected packet ID {id:#04x} in state {state:?}")]
    UnexpectedPacket { state: ConnectionState, id: i32 },

    /// Client requested a handshake intent not yet implemented.
    #[error("handshake intent {0:?} is not yet supported")]
    UnsupportedIntent(Intent),

    /// Connection entered a protocol state not yet implemented.
    #[error("connection state {0:?} is not yet supported")]
    UnsupportedState(ConnectionState),

    /// Client attempted to log in with an incompatible protocol version.
    #[error("incompatible client protocol {client} (server expects {server})")]
    IncompatibleProtocol { client: i32, server: i32 },

    /// Client closed the TCP connection before completing the current state handshake.
    #[error("client closed connection (EOF) in state {0:?}")]
    ClientClosed(ConnectionState),
}

/// TCP server listener handling incoming client connections.
pub struct ServerListener {
    listener: TcpListener,
    status: Arc<ServerStatus>,
    config: NetConfig,
    connection_limit: Arc<Semaphore>,
}

impl ServerListener {
    /// Binds a TCP listener to `addr` with the given status payload and network limits.
    pub async fn bind(
        addr: &str,
        status: ServerStatus,
        config: NetConfig,
    ) -> Result<Self, NetError> {
        let listener = TcpListener::bind(addr).await?;
        let max_connections = config.max_connections.max(1);
        Ok(Self {
            listener,
            status: Arc::new(status),
            config: NetConfig {
                max_connections,
                ..config
            },
            connection_limit: Arc::new(Semaphore::new(max_connections)),
        })
    }

    /// Returns the local socket address the listener is bound to.
    pub fn local_addr(&self) -> Result<SocketAddr, NetError> {
        Ok(self.listener.local_addr()?)
    }

    /// Accepts connections until `shutdown` completes.
    pub async fn serve(self, shutdown: impl Future<Output = ()>) -> Result<(), NetError> {
        let listener = self.listener;
        serve_accept_loop(
            || async {
                let (stream, peer_addr) = listener.accept().await?;
                let _ = stream.set_nodelay(true);
                Ok((stream, peer_addr))
            },
            self.status,
            self.config,
            self.connection_limit,
            shutdown,
        )
        .await
    }
}

async fn serve_accept_loop<S, F, Fut>(
    mut accept_next: F,
    status: Arc<ServerStatus>,
    config: NetConfig,
    connection_limit: Arc<Semaphore>,
    shutdown: impl Future<Output = ()>,
) -> Result<(), NetError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    F: FnMut() -> Fut,
    Fut: Future<Output = std::io::Result<(S, SocketAddr)>>,
{
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            () = &mut shutdown => {
                break;
            }
            accepted = accept_next() => {
                let (stream, peer_addr) = match accepted {
                    Ok(pair) => pair,
                    Err(err) => {
                        eprintln!("failed to accept incoming connection: {err}");
                        tokio::select! {
                            () = &mut shutdown => break,
                            () = tokio::time::sleep(ACCEPT_ERROR_BACKOFF) => continue,
                        }
                    }
                };
                let Ok(permit) = Arc::clone(&connection_limit).try_acquire_owned() else {
                    eprintln!(
                        "connection limit ({}) reached, rejecting {peer_addr}",
                        config.max_connections
                    );
                    continue;
                };

                let status = Arc::clone(&status);
                let read_timeout = config.read_timeout;
                let write_timeout = config.write_timeout;
                let capture_dir = config.capture_dir.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Err(err) = handle_connection_with_timeouts(
                        stream,
                        status,
                        read_timeout,
                        write_timeout,
                        capture_dir.as_deref(),
                    )
                    .await
                    {
                        eprintln!("connection {peer_addr} closed with error: {err}");
                    }
                });
            }
        }
    }

    Ok(())
}

/// Exact raw wire frame (`Length | PacketID | Payload`) read from a stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireFrame {
    /// Complete wire bytes including the VarInt length prefix.
    pub raw: Vec<u8>,
    header_len: usize,
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

async fn write_packet_timed<W: AsyncWrite + Unpin, P: Packet>(
    writer: &mut W,
    packet: &P,
    write_timeout: Duration,
) -> Result<(), NetError> {
    tokio::time::timeout(write_timeout, write_packet(writer, packet))
        .await
        .map_err(|_| NetError::WriteTimeout(write_timeout))?
}

async fn save_fixture_once(
    capture_dir: Option<&Path>,
    filename: &str,
    raw: &[u8],
) -> Result<(), std::io::Error> {
    let Some(dir) = capture_dir else {
        return Ok(());
    };
    if raw.len() > MAX_CAPTURE_FRAME_BYTES {
        eprintln!(
            "skipping fixture {filename}: frame size {} exceeds limit {MAX_CAPTURE_FRAME_BYTES}",
            raw.len()
        );
        return Ok(());
    }
    tokio::fs::create_dir_all(dir).await?;
    let path = dir.join(filename);
    let mut file = match tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .await
    {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => return Ok(()),
        Err(err) => return Err(err),
    };
    file.write_all(raw).await?;
    file.flush().await?;
    println!(
        "captured wire fixture: {} ({} bytes)",
        path.display(),
        raw.len()
    );
    Ok(())
}

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

/// Builds a deterministic valid UTF-8 placeholder username of exact byte length `byte_len`
/// (`0..=48`) guaranteed to occupy at most `MAX_USERNAME_UTF16_UNITS` (`16`) UTF-16 code units.
fn build_sanitized_username_bytes(byte_len: usize) -> Vec<u8> {
    const MAX_UNITS: usize = 16;
    const THREE_BYTE_CHAR: &[u8] = "\u{2500}".as_bytes(); // 3 UTF-8 bytes, 1 BMP UTF-16 unit
    const TWO_BYTE_CHAR: &[u8] = "\u{00C4}".as_bytes(); // 2 UTF-8 bytes, 1 BMP UTF-16 unit

    let mut out = Vec::with_capacity(byte_len);
    let mut rem_bytes = byte_len;
    let mut rem_units = MAX_UNITS;

    while rem_bytes > rem_units && rem_units > 0 {
        if rem_bytes - rem_units >= 2 && rem_bytes >= 3 {
            out.extend_from_slice(THREE_BYTE_CHAR);
            rem_bytes -= 3;
            rem_units -= 1;
        } else if rem_bytes >= 2 {
            out.extend_from_slice(TWO_BYTE_CHAR);
            rem_bytes -= 2;
            rem_units -= 1;
        } else {
            break;
        }
    }

    out.extend(b"TestPlayer______".iter().copied().cycle().take(rem_bytes));
    out
}

/// Scrubs the username and player UUID bytes in-place inside a raw `Login Start` wire frame,
/// preserving all client-encoded VarInt prefixes and packet structure verbatim.
fn sanitize_login_start_wire_frame(frame: &WireFrame) -> Result<Vec<u8>, ProtocolError> {
    let body = frame.body();
    let Some((_packet_id, id_len)) = decode_varint_prefix(body)? else {
        return Err(ProtocolError::UnexpectedEof);
    };
    let after_id = frame
        .header_len
        .checked_add(id_len)
        .ok_or(ProtocolError::UnexpectedEof)?;
    if after_id > frame.raw.len() {
        return Err(ProtocolError::UnexpectedEof);
    }
    let Some((raw_name_len, name_prefix_len)) = decode_varint_prefix(&frame.raw[after_id..])?
    else {
        return Err(ProtocolError::UnexpectedEof);
    };
    if raw_name_len < 0 {
        return Err(ProtocolError::NegativeLength(raw_name_len));
    }
    let name_len = raw_name_len as usize;
    let name_start = after_id
        .checked_add(name_prefix_len)
        .ok_or(ProtocolError::UnexpectedEof)?;
    let name_end = name_start
        .checked_add(name_len)
        .ok_or(ProtocolError::UnexpectedEof)?;
    let uuid_end = name_end
        .checked_add(16)
        .ok_or(ProtocolError::UnexpectedEof)?;
    if frame.raw.len() < uuid_end {
        return Err(ProtocolError::UnexpectedEof);
    }
    if frame.raw.len() > uuid_end {
        return Err(ProtocolError::TrailingBytes(frame.raw.len() - uuid_end));
    }

    let mut sanitized = frame.raw.clone();
    let replacement = build_sanitized_username_bytes(name_len);
    sanitized[name_start..name_end].copy_from_slice(&replacement);
    sanitized[name_end..uuid_end].copy_from_slice(SANITIZED_FIXTURE_UUID.as_bytes());
    Ok(sanitized)
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

async fn handle_connection_with_timeouts<S: AsyncRead + AsyncWrite + Unpin>(
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

#[cfg(test)]
mod tests {
    use super::*;
    use ferrite_protocol::{
        Description, PlayersInfo, StatusResponsePacket, VersionInfo, GAME_VERSION, PROTOCOL_VERSION,
    };

    fn test_status() -> ServerStatus {
        ServerStatus {
            version: VersionInfo {
                name: GAME_VERSION.to_owned(),
                protocol: PROTOCOL_VERSION,
            },
            players: PlayersInfo {
                max: 20,
                online: 0,
                sample: Vec::new(),
            },
            description: Description {
                text: "Ferrite Test".to_owned(),
            },
            favicon: None,
            enforces_secure_chat: None,
        }
    }

    #[tokio::test]
    async fn full_server_list_ping_exchange() {
        let status = test_status();

        let (mut client, server) = tokio::io::duplex(4096);
        let server_status = Arc::new(status.clone());
        let server_task = tokio::spawn(async move {
            handle_connection(server, server_status, Duration::from_secs(5)).await
        });

        let handshake = HandshakePacket {
            protocol_version: PROTOCOL_VERSION,
            server_address: "localhost".to_owned(),
            server_port: 25565,
            next_state: Intent::Status,
        };
        write_packet(&mut client, &handshake).await.unwrap();
        write_packet(&mut client, &StatusRequestPacket)
            .await
            .unwrap();

        let status_body = read_frame(&mut client).await.unwrap().unwrap();
        let (status_id, status_payload) = decode_frame(&status_body).unwrap();
        assert_eq!(status_id, StatusResponsePacket::ID);
        let response: StatusResponsePacket = decode_exact(status_payload).unwrap();
        let parsed = ServerStatus::from_packet(&response).unwrap();
        assert_eq!(parsed, status);

        let ping_timestamp = 1_732_700_000_999;
        write_packet(
            &mut client,
            &PingRequestPacket {
                timestamp: ping_timestamp,
            },
        )
        .await
        .unwrap();

        let pong_body = read_frame(&mut client).await.unwrap().unwrap();
        let (pong_id, pong_payload) = decode_frame(&pong_body).unwrap();
        assert_eq!(pong_id, PongResponsePacket::ID);
        let pong: PongResponsePacket = decode_exact(pong_payload).unwrap();
        assert_eq!(pong.timestamp, ping_timestamp);

        server_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn read_timeout_closes_stalled_connection() {
        let (_client, server) = tokio::io::duplex(64);
        let result =
            handle_connection(server, Arc::new(test_status()), Duration::from_millis(20)).await;
        assert!(matches!(result, Err(NetError::ReadTimeout(_))));
    }

    #[tokio::test]
    async fn capture_dir_saves_raw_wire_frames() {
        let unique = format!(
            "ferrite-capture-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let dir = std::env::temp_dir().join(unique);

        let (mut client, server) = tokio::io::duplex(4096);
        let dir_for_task = dir.clone();
        let server_task = tokio::spawn(async move {
            handle_connection_with_capture(
                server,
                Arc::new(test_status()),
                Duration::from_secs(5),
                Some(&dir_for_task),
            )
            .await
        });

        let handshake = HandshakePacket {
            protocol_version: PROTOCOL_VERSION,
            server_address: "127.0.0.1".to_owned(),
            server_port: 25565,
            next_state: Intent::Status,
        };
        let expected_hs = handshake.to_frame().unwrap();
        let expected_req = StatusRequestPacket.to_frame().unwrap();
        let expected_ping = PingRequestPacket { timestamp: 42 }.to_frame().unwrap();

        client.write_all(&expected_hs).await.unwrap();
        client.write_all(&expected_req).await.unwrap();
        let _ = read_frame(&mut client).await.unwrap().unwrap();
        client.write_all(&expected_ping).await.unwrap();
        let _ = read_frame(&mut client).await.unwrap().unwrap();

        server_task.await.unwrap().unwrap();

        assert_eq!(
            tokio::fs::read(dir.join("c2s_handshake_status.bin"))
                .await
                .unwrap(),
            expected_hs
        );
        assert_eq!(
            tokio::fs::read(dir.join("c2s_status_request.bin"))
                .await
                .unwrap(),
            expected_req
        );
        assert_eq!(
            tokio::fs::read(dir.join("c2s_ping_request.bin"))
                .await
                .unwrap(),
            expected_ping
        );

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn offline_login_flow_reaches_configuration_and_sanitizes_capture() {
        let unique = format!(
            "ferrite-login-capture-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let dir = std::env::temp_dir().join(unique);

        let (mut client, server) = tokio::io::duplex(4096);
        let dir_for_task = dir.clone();
        let server_task = tokio::spawn(async move {
            handle_connection_with_capture(
                server,
                Arc::new(test_status()),
                Duration::from_secs(5),
                Some(&dir_for_task),
            )
            .await
        });

        let handshake = HandshakePacket {
            protocol_version: PROTOCOL_VERSION,
            server_address: "127.0.0.1".to_owned(),
            server_port: 25565,
            next_state: Intent::Login,
        };
        let real_uuid = Uuid::parse_str("069a79f4-44e9-4726-a5be-fca90e38aaf5").unwrap();
        let login_start = LoginStartPacket {
            username: "SecretNick12".to_owned(),
            player_uuid: real_uuid,
        };

        write_packet(&mut client, &handshake).await.unwrap();
        write_packet(&mut client, &login_start).await.unwrap();

        let success_body = read_frame(&mut client).await.unwrap().unwrap();
        let (success_id, success_payload) = decode_frame(&success_body).unwrap();
        assert_eq!(success_id, LoginSuccessPacket::ID);
        let success: LoginSuccessPacket = decode_exact(success_payload).unwrap();
        assert_eq!(success.username, "SecretNick12");
        assert_eq!(success.uuid, offline_uuid("SecretNick12"));
        assert!(success.properties.is_empty());
        assert_eq!(success.session_id, Uuid::default());

        let expected_ack = LoginAcknowledgedPacket.to_frame().unwrap();
        client.write_all(&expected_ack).await.unwrap();

        let result = server_task.await.unwrap();
        assert!(matches!(
            result,
            Err(NetError::UnsupportedState(ConnectionState::Configuration))
        ));

        let captured_start = tokio::fs::read(dir.join("c2s_login_start.bin"))
            .await
            .unwrap();
        assert!(
            !captured_start
                .windows(b"SecretNick12".len())
                .any(|w| w == b"SecretNick12"),
            "captured fixture must not contain real username"
        );
        assert!(
            !captured_start
                .windows(16)
                .any(|w| w == real_uuid.as_bytes()),
            "captured fixture must not contain real account UUID"
        );

        let mut slice = captured_start.as_slice();
        let body_len = ferrite_protocol::codec::read_varint(&mut slice).unwrap() as usize;
        assert_eq!(slice.len(), body_len);
        let (id, payload) = decode_frame(slice).unwrap();
        assert_eq!(id, LoginStartPacket::ID);
        let parsed_sanitized: LoginStartPacket = decode_exact(payload).unwrap();
        assert_eq!(parsed_sanitized.username, "TestPlayer__");
        assert_eq!(parsed_sanitized.player_uuid, SANITIZED_FIXTURE_UUID);

        let captured_ack = tokio::fs::read(dir.join("c2s_login_acknowledged.bin"))
            .await
            .unwrap();
        assert_eq!(captured_ack, expected_ack);

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn login_incompatible_protocol_sends_login_disconnect() {
        let (mut client, server) = tokio::io::duplex(4096);
        let server_task = tokio::spawn(async move {
            handle_connection(server, Arc::new(test_status()), Duration::from_secs(5)).await
        });

        write_packet(
            &mut client,
            &HandshakePacket {
                protocol_version: PROTOCOL_VERSION - 1,
                server_address: "127.0.0.1".to_owned(),
                server_port: 25565,
                next_state: Intent::Login,
            },
        )
        .await
        .unwrap();
        write_packet(
            &mut client,
            &LoginStartPacket {
                username: "Player".to_owned(),
                player_uuid: SANITIZED_FIXTURE_UUID,
            },
        )
        .await
        .unwrap();

        let body = read_frame(&mut client).await.unwrap().unwrap();
        let (id, payload) = decode_frame(&body).unwrap();
        assert_eq!(id, LoginDisconnectPacket::ID);
        let disconnect: LoginDisconnectPacket = decode_exact(payload).unwrap();
        assert!(disconnect.reason_json.contains("Incompatible protocol"));

        let result = server_task.await.unwrap();
        assert!(matches!(
            result,
            Err(NetError::IncompatibleProtocol {
                client: 776,
                server: PROTOCOL_VERSION
            })
        ));
    }

    #[tokio::test]
    async fn out_of_order_login_acknowledged_is_rejected() {
        let (mut client, server) = tokio::io::duplex(4096);
        let server_task = tokio::spawn(async move {
            handle_connection(server, Arc::new(test_status()), Duration::from_secs(5)).await
        });

        write_packet(
            &mut client,
            &HandshakePacket {
                protocol_version: PROTOCOL_VERSION,
                server_address: "127.0.0.1".to_owned(),
                server_port: 25565,
                next_state: Intent::Login,
            },
        )
        .await
        .unwrap();
        write_packet(&mut client, &LoginAcknowledgedPacket)
            .await
            .unwrap();

        let result = server_task.await.unwrap();
        assert!(matches!(
            result,
            Err(NetError::UnexpectedPacket {
                state: ConnectionState::Login,
                id: 0x03
            })
        ));
    }

    #[tokio::test]
    async fn pre_login_oversized_frame_is_rejected_without_2mib_wait() {
        let (mut client, server) = tokio::io::duplex(64);
        // Send 3-byte VarInt length header claiming 2_097_151 bytes in Handshaking state,
        // without sending body bytes. Pre-login cap must reject immediately as PacketTooLarge
        // instead of allocating 2 MiB and waiting for ReadTimeout.
        client.write_all(&[0xFF, 0xFF, 0x7F]).await.unwrap();

        let result =
            handle_connection(server, Arc::new(test_status()), Duration::from_secs(2)).await;
        assert!(
            matches!(
                result,
                Err(NetError::Protocol(ProtocolError::PacketTooLarge {
                    len: 2_097_151,
                    max: MAX_PRE_CONFIG_FRAME_LEN
                }))
            ),
            "expected immediate PacketTooLarge in Handshaking, got {result:?}"
        );
    }

    #[tokio::test]
    async fn write_timeout_closes_non_reading_client() {
        // 24-byte buffer fits incoming 17B Handshake + 2B StatusRequest (19B),
        // but blocks outgoing ~95B StatusResponse when the client never reads.
        let (mut client, server) = tokio::io::duplex(24);
        write_packet(
            &mut client,
            &HandshakePacket {
                protocol_version: PROTOCOL_VERSION,
                server_address: "127.0.0.1".to_owned(),
                server_port: 25565,
                next_state: Intent::Status,
            },
        )
        .await
        .unwrap();
        write_packet(&mut client, &StatusRequestPacket)
            .await
            .unwrap();

        let outcome = tokio::time::timeout(
            Duration::from_secs(2),
            handle_connection(server, Arc::new(test_status()), Duration::from_millis(30)),
        )
        .await;
        assert!(
            matches!(outcome, Ok(Err(NetError::WriteTimeout(_)))),
            "expected NetError::WriteTimeout instead of hanging indefinitely, got {outcome:?}"
        );
    }

    #[tokio::test]
    async fn accept_loop_survives_transient_accept_error() {
        let (mut client, server_stream) = tokio::io::duplex(4096);
        let mut step = 0usize;
        let mut second_stream = Some(server_stream);
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let mut shutdown_tx = Some(shutdown_tx);

        let serve_res = serve_accept_loop(
            move || {
                step += 1;
                let res = match step {
                    1 => Err(std::io::Error::from(std::io::ErrorKind::ConnectionAborted)),
                    2 => {
                        let s = second_stream.take().unwrap();
                        if let Some(tx) = shutdown_tx.take() {
                            let _ = tx.send(());
                        }
                        Ok((s, "127.0.0.1:50000".parse().unwrap()))
                    }
                    _ => Err(std::io::Error::other("unexpected extra accept call")),
                };
                std::future::ready(res)
            },
            Arc::new(test_status()),
            NetConfig::default(),
            Arc::new(Semaphore::new(8)),
            async move {
                let _ = shutdown_rx.await;
                // Yield once so the second accept iteration executes before shutdown wins.
                tokio::task::yield_now().await;
            },
        )
        .await;

        assert!(
            serve_res.is_ok(),
            "transient accept error must not terminate serve loop: {serve_res:?}"
        );

        write_packet(
            &mut client,
            &HandshakePacket {
                protocol_version: PROTOCOL_VERSION,
                server_address: "127.0.0.1".to_owned(),
                server_port: 25565,
                next_state: Intent::Status,
            },
        )
        .await
        .unwrap();
        write_packet(&mut client, &StatusRequestPacket)
            .await
            .unwrap();
        let reply = read_frame(&mut client).await.unwrap();
        assert!(
            reply.is_some(),
            "second connection after transient error must be served"
        );
    }

    #[tokio::test]
    async fn multibyte_utf8_username_sanitization_produces_valid_login_start_fixture() {
        let unique = format!(
            "ferrite-utf8-sanitize-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let dir = std::env::temp_dir().join(unique);

        let (mut client, server) = tokio::io::duplex(4096);
        let dir_for_task = dir.clone();
        let server_task = tokio::spawn(async move {
            handle_connection_with_capture(
                server,
                Arc::new(test_status()),
                Duration::from_secs(5),
                Some(&dir_for_task),
            )
            .await
        });

        // 9 Cyrillic characters = 18 UTF-8 bytes, 9 UTF-16 code units (<= 16 limit).
        let cyrillic_nick = "ИльяТестЯ";
        assert_eq!(cyrillic_nick.len(), 18);
        assert_eq!(cyrillic_nick.encode_utf16().count(), 9);
        let real_uuid = Uuid::parse_str("22fcfcab-696f-4c7e-a5ff-18fa660dcfe6").unwrap();

        write_packet(
            &mut client,
            &HandshakePacket {
                protocol_version: PROTOCOL_VERSION,
                server_address: "127.0.0.1".to_owned(),
                server_port: 25565,
                next_state: Intent::Login,
            },
        )
        .await
        .unwrap();
        write_packet(
            &mut client,
            &LoginStartPacket {
                username: cyrillic_nick.to_owned(),
                player_uuid: real_uuid,
            },
        )
        .await
        .unwrap();

        let _ = read_frame(&mut client).await.unwrap().unwrap();
        write_packet(&mut client, &LoginAcknowledgedPacket)
            .await
            .unwrap();
        let _ = server_task.await.unwrap();

        let captured = tokio::fs::read(dir.join("c2s_login_start.bin"))
            .await
            .unwrap();
        assert!(
            !captured
                .windows(cyrillic_nick.len())
                .any(|w| w == cyrillic_nick.as_bytes()),
            "real Cyrillic username must not appear in captured fixture"
        );
        let mut slice = captured.as_slice();
        let body_len = ferrite_protocol::codec::read_varint(&mut slice).unwrap() as usize;
        assert_eq!(slice.len(), body_len);
        let (id, payload) = decode_frame(slice).unwrap();
        assert_eq!(id, LoginStartPacket::ID);
        let parsed: LoginStartPacket =
            decode_exact(payload).expect("sanitized LoginStart fixture must remain protocol-valid");
        assert_eq!(parsed.username.len(), cyrillic_nick.len());
        assert_eq!(parsed.player_uuid, SANITIZED_FIXTURE_UUID);

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn fixture_capture_is_atomic_and_ignores_wrong_protocol_version() {
        let unique = format!(
            "ferrite-atomic-capture-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let dir = std::env::temp_dir().join(unique);

        // 1) Wrong-protocol Login attempt (776) must NOT poison c2s_handshake_login.bin or c2s_login_start.bin.
        {
            let (mut bad_client, bad_server) = tokio::io::duplex(4096);
            let dir_bad = dir.clone();
            let task = tokio::spawn(async move {
                handle_connection_with_capture(
                    bad_server,
                    Arc::new(test_status()),
                    Duration::from_secs(5),
                    Some(&dir_bad),
                )
                .await
            });
            write_packet(
                &mut bad_client,
                &HandshakePacket {
                    protocol_version: PROTOCOL_VERSION - 1,
                    server_address: "127.0.0.1".to_owned(),
                    server_port: 25565,
                    next_state: Intent::Login,
                },
            )
            .await
            .unwrap();
            write_packet(
                &mut bad_client,
                &LoginStartPacket {
                    username: "WrongVer".to_owned(),
                    player_uuid: SANITIZED_FIXTURE_UUID,
                },
            )
            .await
            .unwrap();
            let _ = read_frame(&mut bad_client).await.unwrap();
            let _ = task.await.unwrap();
        }

        // 2) Concurrent valid 777 Login connections racing on the same empty capture_dir
        // must all succeed without Windows sharing-violation I/O errors.
        let barrier = Arc::new(tokio::sync::Barrier::new(16));
        let mut handles = Vec::new();
        for _ in 0..16 {
            let b = Arc::clone(&barrier);
            let d = dir.clone();
            handles.push(tokio::spawn(async move {
                let (mut client, server) = tokio::io::duplex(4096);
                let srv = tokio::spawn(async move {
                    handle_connection_with_capture(
                        server,
                        Arc::new(test_status()),
                        Duration::from_secs(5),
                        Some(&d),
                    )
                    .await
                });
                b.wait().await;
                write_packet(
                    &mut client,
                    &HandshakePacket {
                        protocol_version: PROTOCOL_VERSION,
                        server_address: "127.0.0.1".to_owned(),
                        server_port: 25565,
                        next_state: Intent::Login,
                    },
                )
                .await
                .unwrap();
                write_packet(
                    &mut client,
                    &LoginStartPacket {
                        username: "Valid777".to_owned(),
                        player_uuid: SANITIZED_FIXTURE_UUID,
                    },
                )
                .await
                .unwrap();
                let _ = read_frame(&mut client).await.unwrap().unwrap();
                write_packet(&mut client, &LoginAcknowledgedPacket)
                    .await
                    .unwrap();
                srv.await.unwrap()
            }));
        }

        for h in handles {
            let res = h.await.unwrap();
            assert!(
                matches!(
                    res,
                    Err(NetError::UnsupportedState(ConnectionState::Configuration))
                ),
                "concurrent capture failed with unexpected I/O error: {res:?}"
            );
        }

        let hs_raw = tokio::fs::read(dir.join("c2s_handshake_login.bin"))
            .await
            .unwrap();
        let mut hs_slice = hs_raw.as_slice();
        let _ = ferrite_protocol::codec::read_varint(&mut hs_slice).unwrap();
        let (_, hs_payload) = decode_frame(hs_slice).unwrap();
        let hs: HandshakePacket = decode_exact(hs_payload).unwrap();
        assert_eq!(
            hs.protocol_version, PROTOCOL_VERSION,
            "captured fixture was poisoned by wrong-protocol client"
        );

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn repeated_accept_errors_back_off_instead_of_busy_spinning() {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let calls_for_loop = Arc::clone(&calls);
        let (early_stop_tx, early_stop_rx) = tokio::sync::oneshot::channel::<()>();
        let mut early_stop_tx = Some(early_stop_tx);

        serve_accept_loop(
            move || {
                let n = calls_for_loop.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                if n >= 200 {
                    if let Some(tx) = early_stop_tx.take() {
                        let _ = tx.send(());
                    }
                }
                std::future::ready(Err::<(tokio::io::DuplexStream, SocketAddr), _>(
                    std::io::Error::other("simulated EMFILE"),
                ))
            },
            Arc::new(test_status()),
            NetConfig::default(),
            Arc::new(Semaphore::new(8)),
            async move {
                tokio::select! {
                    _ = early_stop_rx => {}
                    () = tokio::time::sleep(Duration::from_millis(130)) => {}
                }
            },
        )
        .await
        .unwrap();

        let observed = calls.load(std::sync::atomic::Ordering::Relaxed);
        assert!(
            (1..=10).contains(&observed),
            "accept loop busy-spun without backoff: {observed} calls within 130ms"
        );
    }

    #[tokio::test]
    async fn malformed_login_start_does_not_panic_or_write_fixture() {
        // 1) Direct boundary tests on sanitize_login_start_wire_frame:
        // truncated UUID, trailing bytes, negative string length, and huge VarInt length.
        let truncated = WireFrame {
            raw: vec![0x05, 0x00, 0x03, b'a', b'b', b'c'],
            header_len: 1,
        };
        assert!(matches!(
            sanitize_login_start_wire_frame(&truncated),
            Err(ProtocolError::UnexpectedEof)
        ));

        let mut trailing_raw = LoginStartPacket {
            username: "Alice".to_owned(),
            player_uuid: SANITIZED_FIXTURE_UUID,
        }
        .to_frame()
        .unwrap();
        trailing_raw[0] += 1;
        trailing_raw.push(0xAA);
        let trailing = WireFrame {
            raw: trailing_raw,
            header_len: 1,
        };
        assert!(matches!(
            sanitize_login_start_wire_frame(&trailing),
            Err(ProtocolError::TrailingBytes(1))
        ));

        let huge_len = WireFrame {
            raw: vec![0x06, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x07],
            header_len: 1,
        };
        assert!(matches!(
            sanitize_login_start_wire_frame(&huge_len),
            Err(ProtocolError::UnexpectedEof)
        ));

        // 2) End-to-end connection with invalid UTF-8 username bytes and mismatched length:
        // must return ProtocolError cleanly without panicking and without writing c2s_login_start.bin.
        let unique = format!(
            "ferrite-malformed-login-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let dir = std::env::temp_dir().join(unique);

        let (mut client, server) = tokio::io::duplex(4096);
        let dir_for_task = dir.clone();
        let server_task = tokio::spawn(async move {
            handle_connection_with_capture(
                server,
                Arc::new(test_status()),
                Duration::from_secs(2),
                Some(&dir_for_task),
            )
            .await
        });

        write_packet(
            &mut client,
            &HandshakePacket {
                protocol_version: PROTOCOL_VERSION,
                server_address: "127.0.0.1".to_owned(),
                server_port: 25565,
                next_state: Intent::Login,
            },
        )
        .await
        .unwrap();

        // Raw LoginStart frame with invalid UTF-8 [0xFF, 0xFE, 0xFD] + 16-byte UUID (body len = 1 + 1 + 3 + 16 = 21).
        let mut bad_utf8_frame = vec![21u8, 0x00, 0x03, 0xFF, 0xFE, 0xFD];
        bad_utf8_frame.extend_from_slice(SANITIZED_FIXTURE_UUID.as_bytes());
        client.write_all(&bad_utf8_frame).await.unwrap();

        let res = server_task.await.unwrap();
        assert!(
            matches!(res, Err(NetError::Protocol(ProtocolError::InvalidUtf8(_)))),
            "expected InvalidUtf8 error, got {res:?}"
        );
        assert!(
            !tokio::fs::try_exists(dir.join("c2s_login_start.bin"))
                .await
                .unwrap(),
            "malformed LoginStart must never be written to capture_dir"
        );

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }
}
