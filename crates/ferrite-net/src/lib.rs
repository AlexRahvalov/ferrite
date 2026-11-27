//! Async TCP networking layer for Ferrite.

use std::future::Future;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use ferrite_protocol::codec::{decode_frame, decode_varint_prefix, MAX_VARINT_BYTES};
use ferrite_protocol::{
    decode_exact, ConnectionState, HandshakePacket, Intent, Packet, PingRequestPacket,
    PongResponsePacket, ProtocolError, ServerStatus, StatusRequestPacket, MAX_PACKET_LEN,
};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

/// Default per-frame read timeout for client connections.
pub const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// Default maximum number of concurrent client connections.
pub const DEFAULT_MAX_CONNECTIONS: usize = 1024;

/// Maximum raw wire frame size (in bytes) written when `capture_dir` is enabled.
pub const MAX_CAPTURE_FRAME_BYTES: usize = 65_536;

/// Runtime configuration for [`ServerListener`].
#[derive(Debug, Clone)]
pub struct NetConfig {
    /// Maximum time to wait for a complete incoming packet frame.
    pub read_timeout: Duration,
    /// Maximum number of concurrent client connections accepted at once.
    pub max_connections: usize,
    /// Optional directory where raw incoming wire frames are saved once as `.bin` fixtures.
    pub capture_dir: Option<PathBuf>,
}

impl Default for NetConfig {
    fn default() -> Self {
        Self {
            read_timeout: DEFAULT_READ_TIMEOUT,
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

    /// Client sent a packet ID not valid for the current connection state.
    #[error("unexpected packet ID {id:#04x} in state {state:?}")]
    UnexpectedPacket { state: ConnectionState, id: i32 },

    /// Client requested a handshake intent not yet implemented.
    #[error("handshake intent {0:?} is not yet supported")]
    UnsupportedIntent(Intent),
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
        tokio::pin!(shutdown);

        loop {
            tokio::select! {
                () = &mut shutdown => {
                    break;
                }
                accepted = self.listener.accept() => {
                    let (stream, peer_addr) = accepted?;
                    let Ok(permit) = Arc::clone(&self.connection_limit).try_acquire_owned() else {
                        eprintln!(
                            "connection limit ({}) reached, rejecting {peer_addr}",
                            self.config.max_connections
                        );
                        continue;
                    };

                    let status = Arc::clone(&self.status);
                    let read_timeout = self.config.read_timeout;
                    let capture_dir = self.config.capture_dir.clone();
                    tokio::spawn(async move {
                        let _permit = permit;
                        if let Err(err) = handle_connection_with_capture(
                            stream,
                            status,
                            read_timeout,
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
            if len > MAX_PACKET_LEN {
                return Err(NetError::Protocol(ProtocolError::PacketTooLarge {
                    len,
                    max: MAX_PACKET_LEN,
                }));
            }
            break len;
        }
    };

    let mut raw = vec![0u8; prefix_len + frame_len];
    raw[..prefix_len].copy_from_slice(&prefix[..prefix_len]);
    reader.read_exact(&mut raw[prefix_len..]).await?;
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
    if tokio::fs::try_exists(&path).await? {
        return Ok(());
    }
    tokio::fs::write(&path, raw).await?;
    println!(
        "captured wire fixture: {} ({} bytes)",
        path.display(),
        raw.len()
    );
    Ok(())
}

/// Processes a single client stream through Handshake and Status states.
pub async fn handle_connection<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    status: Arc<ServerStatus>,
    read_timeout: Duration,
) -> Result<(), NetError> {
    handle_connection_with_capture(stream, status, read_timeout, None).await
}

/// Processes a single client stream, optionally saving raw incoming wire frames to `capture_dir`.
pub async fn handle_connection_with_capture<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    status: Arc<ServerStatus>,
    read_timeout: Duration,
    capture_dir: Option<&Path>,
) -> Result<(), NetError> {
    let mut state = ConnectionState::Handshaking;

    loop {
        let frame = tokio::time::timeout(read_timeout, read_wire_frame(&mut stream))
            .await
            .map_err(|_| NetError::ReadTimeout(read_timeout))??;

        let Some(wire_frame) = frame else {
            return Ok(());
        };

        let (packet_id, payload) = decode_frame(wire_frame.body())?;

        match (state, packet_id) {
            (ConnectionState::Handshaking, HandshakePacket::ID) => {
                let handshake: HandshakePacket = decode_exact(payload)?;
                println!(
                    "handshake: protocol_version={}, address={}:{}, intent={:?}",
                    handshake.protocol_version,
                    handshake.server_address,
                    handshake.server_port,
                    handshake.next_state
                );
                let fixture_name = match handshake.next_state {
                    Intent::Status => "c2s_handshake_status.bin",
                    Intent::Login => "c2s_handshake_login.bin",
                    Intent::Transfer => "c2s_handshake_transfer.bin",
                };
                save_fixture_once(capture_dir, fixture_name, &wire_frame.raw).await?;
                match handshake.next_state {
                    Intent::Status => state = ConnectionState::Status,
                    other => return Err(NetError::UnsupportedIntent(other)),
                }
            }
            (ConnectionState::Status, StatusRequestPacket::ID) => {
                let _request: StatusRequestPacket = decode_exact(payload)?;
                save_fixture_once(capture_dir, "c2s_status_request.bin", &wire_frame.raw).await?;
                let response = status.into_packet()?;
                write_packet(&mut stream, &response).await?;
            }
            (ConnectionState::Status, PingRequestPacket::ID) => {
                let ping: PingRequestPacket = decode_exact(payload)?;
                save_fixture_once(capture_dir, "c2s_ping_request.bin", &wire_frame.raw).await?;
                let pong = PongResponsePacket {
                    timestamp: ping.timestamp,
                };
                write_packet(&mut stream, &pong).await?;
                return Ok(());
            }
            (current_state, id) => {
                return Err(NetError::UnexpectedPacket {
                    state: current_state,
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
}
