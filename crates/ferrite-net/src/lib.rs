//! Async TCP networking layer for Ferrite.

mod capture;
mod framing;
mod listener;
mod session;

use std::path::PathBuf;
use std::time::Duration;

use ferrite_protocol::{ConnectionState, Intent, ProtocolError};
use thiserror::Error;

pub use capture::{MAX_CAPTURE_FRAME_BYTES, SANITIZED_FIXTURE_UUID};
pub use framing::{read_frame, read_wire_frame, read_wire_frame_bounded, write_packet, WireFrame};
pub use listener::ServerListener;
pub use session::{handle_connection, handle_connection_with_capture};

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

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::Arc;

    use ferrite_protocol::codec::decode_frame;
    use ferrite_protocol::{
        decode_exact, offline_uuid, Description, HandshakePacket, LoginAcknowledgedPacket,
        LoginDisconnectPacket, LoginStartPacket, LoginSuccessPacket, Packet, PingRequestPacket,
        PlayersInfo, PongResponsePacket, ServerStatus, StatusRequestPacket, StatusResponsePacket,
        Uuid, VersionInfo, GAME_VERSION, PROTOCOL_VERSION,
    };
    use tokio::io::AsyncWriteExt;
    use tokio::sync::Semaphore;

    use super::*;
    use crate::capture::sanitize_login_start_wire_frame;
    use crate::listener::serve_accept_loop;

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
