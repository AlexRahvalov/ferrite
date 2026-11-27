//! Loopback-only TCP wire recorder and structural inspector for development.
//!
//! Forwarding is strictly primary and unmodified: if the passive frame parser
//! encounters an error or hits a size cap, recording stops with a log message
//! while raw TCP byte forwarding continues uninterrupted.

use std::fmt::Write as _;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use ferrite_protocol::codec::{decode_frame, decode_varint_prefix, read_varint, MAX_VARINT_BYTES};
use ferrite_protocol::{
    decode_exact, offline_uuid, ConnectionState, HandshakePacket, Intent, LoginAcknowledgedPacket,
    LoginSuccessPacket, Packet, MAX_PACKET_LEN,
};
use thiserror::Error;
use tokio::fs::File;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::Mutex;

/// Magic header written at the start of every `.rec` capture file (`"FREC"` + version 1).
pub const REC_MAGIC: [u8; 8] = *b"FREC\x01\x00\x00\x00";

/// Maximum size of a single recorded wire frame (2 MiB - 1).
pub const MAX_RECORD_FRAME_BYTES: usize = MAX_PACKET_LEN;

/// Maximum total size of a single `.rec` recording file (16 MiB).
pub const MAX_RECORD_FILE_BYTES: u64 = 16 * 1024 * 1024;

// Finish Configuration packet IDs in Configuration state (`0x03` in both directions,
// empty payload). Source: `PrismarineJS/minecraft-data` (`data/pc/26.1/protocol.json`, MIT)
// and empirically confirmed on live 26.3 (protocol 777) traffic (`Seq #43` S2C `0x03`,
// `Seq #44` C2S `0x03`).
const S2C_FINISH_CONFIG_ID: i32 = 0x03;
const C2S_FINISH_CONFIG_ID: i32 = 0x03;

// Login-state S2C IDs that indicate upstream server misconfiguration for plain recording.
const LOGIN_S2C_ENCRYPTION_REQUEST_ID: i32 = 0x01;
const LOGIN_S2C_SET_COMPRESSION_ID: i32 = 0x03;

/// Errors returned by configuration validation or `.rec` inspection.
#[derive(Debug, Error)]
pub enum RecorderError {
    /// Non-loopback bind or upstream address was supplied.
    #[error("refusing non-loopback socket address {0} (only 127.0.0.1 / ::1 allowed)")]
    NonLoopbackAddress(SocketAddr),

    /// Underlying I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// `.rec` file had an invalid header or truncated record.
    #[error("corrupt or truncated .rec file: {0}")]
    CorruptRecording(&'static str),
}

/// Validates that `addr` uses a loopback IP (`127.0.0.0/8` or `::1`).
pub fn ensure_loopback(addr: SocketAddr) -> Result<(), RecorderError> {
    if !addr.ip().is_loopback() {
        return Err(RecorderError::NonLoopbackAddress(addr));
    }
    Ok(())
}

/// Packet flow direction stored in `.rec` metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    C2S = 0,
    S2C = 1,
}

impl Direction {
    fn from_u8(value: u8) -> Result<Self, RecorderError> {
        match value {
            0 => Ok(Self::C2S),
            1 => Ok(Self::S2C),
            _ => Err(RecorderError::CorruptRecording("invalid direction byte")),
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::C2S => "C2S",
            Self::S2C => "S2C",
        }
    }
}

fn state_to_u8(state: ConnectionState) -> u8 {
    match state {
        ConnectionState::Handshaking => 0,
        ConnectionState::Status => 1,
        ConnectionState::Login => 2,
        ConnectionState::Configuration => 3,
        ConnectionState::Play => 4,
    }
}

fn state_from_u8(value: u8) -> Result<ConnectionState, RecorderError> {
    match value {
        0 => Ok(ConnectionState::Handshaking),
        1 => Ok(ConnectionState::Status),
        2 => Ok(ConnectionState::Login),
        3 => Ok(ConnectionState::Configuration),
        4 => Ok(ConnectionState::Play),
        _ => Err(RecorderError::CorruptRecording(
            "invalid connection state byte",
        )),
    }
}

/// Single parsed record from a `.rec` file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedEntry {
    pub seq: u64,
    pub direction: Direction,
    pub state: ConnectionState,
    pub raw_frame: Vec<u8>,
}

/// Shared per-connection state machine and `.rec` sink.
struct RecorderSink<W> {
    writer: W,
    bytes_written: u64,
    next_seq: u64,
    c2s_state: ConnectionState,
    s2c_state: ConnectionState,
    s2c_sent_finish_config: bool,
    stopped_reason: Option<String>,
}

impl<W: AsyncWrite + Unpin> RecorderSink<W> {
    async fn new(mut writer: W) -> Result<Self, std::io::Error> {
        writer.write_all(&REC_MAGIC).await?;
        writer.flush().await?;
        Ok(Self {
            writer,
            bytes_written: REC_MAGIC.len() as u64,
            next_seq: 0,
            c2s_state: ConnectionState::Handshaking,
            s2c_state: ConnectionState::Handshaking,
            s2c_sent_finish_config: false,
            stopped_reason: None,
        })
    }

    fn state_for(&self, dir: Direction) -> ConnectionState {
        match dir {
            Direction::C2S => self.c2s_state,
            Direction::S2C => self.s2c_state,
        }
    }

    fn stop(&mut self, reason: impl Into<String>) {
        if self.stopped_reason.is_none() {
            let msg = reason.into();
            eprintln!("recorder stopped: {msg} (raw TCP forwarding continues)");
            self.stopped_reason = Some(msg);
        }
    }

    async fn on_frame(&mut self, dir: Direction, raw_frame: &[u8], body: &[u8]) {
        if self.stopped_reason.is_some() {
            return;
        }

        let state = self.state_for(dir);
        if state == ConnectionState::Play {
            return;
        }

        let (packet_id, payload) = match decode_frame(body) {
            Ok(pair) => pair,
            Err(err) => {
                self.stop(format!(
                    "failed to decode packet ID on {} in {state:?}: {err}",
                    dir.as_str()
                ));
                return;
            }
        };

        let record_bytes = 8u64 + 1 + 1 + 4 + (raw_frame.len() as u64);
        if self.bytes_written.saturating_add(record_bytes) > MAX_RECORD_FILE_BYTES {
            self.stop(format!(
                "recording file limit ({MAX_RECORD_FILE_BYTES} bytes) reached"
            ));
            return;
        }

        let Ok(raw_len_u32) = u32::try_from(raw_frame.len()) else {
            self.stop("frame length overflowed u32");
            return;
        };

        let seq = self.next_seq;
        self.next_seq += 1;

        let mut header = [0u8; 14];
        header[0..8].copy_from_slice(&seq.to_be_bytes());
        header[8] = dir as u8;
        header[9] = state_to_u8(state);
        header[10..14].copy_from_slice(&raw_len_u32.to_be_bytes());

        if let Err(err) = self.write_record(&header, raw_frame).await {
            self.stop(format!("failed writing .rec file: {err}"));
            return;
        }
        self.bytes_written += record_bytes;

        println!(
            "rec #{seq:03} dir={} state={state:?} id={packet_id:#04x} payload_len={} raw_len={}",
            dir.as_str(),
            payload.len(),
            raw_frame.len()
        );

        self.advance_state(dir, state, packet_id, payload);
    }

    async fn write_record(&mut self, header: &[u8; 14], raw_frame: &[u8]) -> std::io::Result<()> {
        self.writer.write_all(header).await?;
        self.writer.write_all(raw_frame).await?;
        self.writer.flush().await
    }

    fn advance_state(
        &mut self,
        dir: Direction,
        state: ConnectionState,
        packet_id: i32,
        payload: &[u8],
    ) {
        match (dir, state, packet_id) {
            (Direction::C2S, ConnectionState::Handshaking, HandshakePacket::ID) => {
                match decode_exact::<HandshakePacket>(payload) {
                    Ok(hs) => {
                        let next = match hs.next_state {
                            Intent::Status => ConnectionState::Status,
                            Intent::Login | Intent::Transfer => ConnectionState::Login,
                        };
                        self.c2s_state = next;
                        self.s2c_state = next;
                    }
                    Err(err) => self.stop(format!("invalid Handshake payload: {err}")),
                }
            }
            (Direction::S2C, ConnectionState::Login, LOGIN_S2C_ENCRYPTION_REQUEST_ID) => {
                self.stop(
                    "upstream server sent Encryption Request (0x01); set online-mode=false in server.properties",
                );
            }
            (Direction::S2C, ConnectionState::Login, LOGIN_S2C_SET_COMPRESSION_ID) => {
                self.stop(
                    "upstream server sent Set Compression (0x03); set network-compression-threshold=-1 in server.properties",
                );
            }
            (Direction::C2S, ConnectionState::Login, LoginAcknowledgedPacket::ID) => {
                if payload.is_empty() {
                    self.c2s_state = ConnectionState::Configuration;
                    self.s2c_state = ConnectionState::Configuration;
                } else {
                    self.stop(format!(
                        "unexpected non-empty Login Acknowledged (0x03) payload ({} bytes)",
                        payload.len()
                    ));
                }
            }
            (Direction::S2C, ConnectionState::Configuration, S2C_FINISH_CONFIG_ID) => {
                if payload.is_empty() {
                    self.s2c_state = ConnectionState::Play;
                    self.s2c_sent_finish_config = true;
                    println!(
                        "recorder: observed empty S2C {packet_id:#04x} in Configuration -> S2C entered Play"
                    );
                } else {
                    self.stop(format!(
                        "S2C {packet_id:#04x} in Configuration had non-empty payload ({} bytes); Finish Configuration ID mismatch!",
                        payload.len()
                    ));
                }
            }
            (Direction::C2S, ConnectionState::Configuration, C2S_FINISH_CONFIG_ID)
                if self.s2c_sent_finish_config =>
            {
                if payload.is_empty() {
                    self.c2s_state = ConnectionState::Play;
                    println!(
                        "recorder: observed empty C2S {packet_id:#04x} in Configuration -> C2S entered Play (recording complete)"
                    );
                } else {
                    self.stop(format!(
                        "C2S {packet_id:#04x} in Configuration had non-empty payload ({} bytes); Acknowledge Finish Configuration ID differs from 26.1 schema!",
                        payload.len()
                    ));
                }
            }
            _ => {}
        }
    }
}

/// Incremental stream parser for a single half-connection (`C2S` or `S2C`).
struct FrameTap {
    dir: Direction,
    buf: Vec<u8>,
    active: bool,
}

impl FrameTap {
    fn new(dir: Direction) -> Self {
        Self {
            dir,
            buf: Vec::new(),
            active: true,
        }
    }

    async fn feed<W: AsyncWrite + Unpin>(&mut self, chunk: &[u8], sink: &Mutex<RecorderSink<W>>) {
        if !self.active {
            return;
        }

        {
            let guard = sink.lock().await;
            if guard.stopped_reason.is_some() || guard.state_for(self.dir) == ConnectionState::Play
            {
                self.active = false;
                self.buf.clear();
                return;
            }
        }

        if self.buf.len().saturating_add(chunk.len()) > MAX_RECORD_FRAME_BYTES + MAX_VARINT_BYTES {
            let mut guard = sink.lock().await;
            guard.stop(format!(
                "{} buffer exceeded MAX_RECORD_FRAME_BYTES ({MAX_RECORD_FRAME_BYTES})",
                self.dir.as_str()
            ));
            self.active = false;
            self.buf.clear();
            return;
        }

        self.buf.extend_from_slice(chunk);

        loop {
            let decoded = match decode_varint_prefix(&self.buf) {
                Ok(Some(pair)) => pair,
                Ok(None) => break,
                Err(err) => {
                    let mut guard = sink.lock().await;
                    guard.stop(format!(
                        "{} frame length VarInt error: {err}",
                        self.dir.as_str()
                    ));
                    self.active = false;
                    self.buf.clear();
                    break;
                }
            };

            let (raw_body_len, prefix_len) = decoded;
            if raw_body_len < 0 {
                let mut guard = sink.lock().await;
                guard.stop(format!(
                    "{} negative frame length: {raw_body_len}",
                    self.dir.as_str()
                ));
                self.active = false;
                self.buf.clear();
                break;
            }

            let body_len = raw_body_len as usize;
            if body_len > MAX_RECORD_FRAME_BYTES {
                let mut guard = sink.lock().await;
                guard.stop(format!(
                    "{} frame length {body_len} exceeds MAX_RECORD_FRAME_BYTES ({MAX_RECORD_FRAME_BYTES})",
                    self.dir.as_str()
                ));
                self.active = false;
                self.buf.clear();
                break;
            }

            let total_len = prefix_len + body_len;
            if self.buf.len() < total_len {
                break;
            }

            let raw_frame: Vec<u8> = self.buf.drain(..total_len).collect();
            let body = &raw_frame[prefix_len..];

            let mut guard = sink.lock().await;
            guard.on_frame(self.dir, &raw_frame, body).await;
            if guard.stopped_reason.is_some() || guard.state_for(self.dir) == ConnectionState::Play
            {
                self.active = false;
                self.buf.clear();
                break;
            }
        }
    }
}

async fn forward_and_tap<R, WOut, WRec>(
    mut reader: R,
    mut writer: WOut,
    dir: Direction,
    sink: Arc<Mutex<RecorderSink<WRec>>>,
) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    WOut: AsyncWrite + Unpin,
    WRec: AsyncWrite + Unpin,
{
    let mut tap = FrameTap::new(dir);
    let mut buf = vec![0u8; 16 * 1024];

    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            let _ = writer.shutdown().await;
            return Ok(());
        }

        // Forwarding is strictly primary: write to the peer socket BEFORE parsing.
        writer.write_all(&buf[..n]).await?;
        writer.flush().await?;

        tap.feed(&buf[..n], &sink).await;
    }
}

/// Proxies a single bidirectional connection between `client` and `upstream`,
/// recording Login + Configuration frames into `rec_writer`.
pub async fn proxy_session<C, U, W>(client: C, upstream: U, rec_writer: W) -> std::io::Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    U: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let sink = Arc::new(Mutex::new(RecorderSink::new(rec_writer).await?));
    let (client_read, client_write) = tokio::io::split(client);
    let (upstream_read, upstream_write) = tokio::io::split(upstream);

    let sink_c2s = Arc::clone(&sink);
    let c2s = tokio::spawn(async move {
        forward_and_tap(client_read, upstream_write, Direction::C2S, sink_c2s).await
    });

    let sink_s2c = Arc::clone(&sink);
    let s2c = tokio::spawn(async move {
        forward_and_tap(upstream_read, client_write, Direction::S2C, sink_s2c).await
    });

    let (r1, r2) = tokio::join!(c2s, s2c);
    r1.map_err(std::io::Error::other)??;
    r2.map_err(std::io::Error::other)??;
    Ok(())
}

/// Reads all [`RecordedEntry`] records from a `.rec` byte slice.
pub fn parse_recording(mut data: &[u8]) -> Result<Vec<RecordedEntry>, RecorderError> {
    if data.len() < REC_MAGIC.len() || data[..REC_MAGIC.len()] != REC_MAGIC {
        return Err(RecorderError::CorruptRecording(
            "missing FREC v1 magic header",
        ));
    }
    data = &data[REC_MAGIC.len()..];

    let mut entries = Vec::new();
    while !data.is_empty() {
        if data.len() < 14 {
            return Err(RecorderError::CorruptRecording("truncated record header"));
        }
        let seq = u64::from_be_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ]);
        let direction = Direction::from_u8(data[8])?;
        let state = state_from_u8(data[9])?;
        let raw_len = u32::from_be_bytes([data[10], data[11], data[12], data[13]]) as usize;
        data = &data[14..];

        if data.len() < raw_len {
            return Err(RecorderError::CorruptRecording("truncated frame bytes"));
        }
        let raw_frame = data[..raw_len].to_vec();
        data = &data[raw_len..];

        entries.push(RecordedEntry {
            seq,
            direction,
            state,
            raw_frame,
        });
    }

    Ok(entries)
}

/// Formats a strictly structural report for a `.rec` recording (IDs, lengths, order,
/// and `Login Success` field metadata) WITHOUT printing registry/tag payloads or usernames.
pub fn format_structural_report(entries: &[RecordedEntry]) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "Total recorded frames: {}", entries.len());
    let _ = writeln!(
        out,
        "{:<5} {:<4} {:<14} {:<8} {:<10} {:<11} Notes",
        "Seq", "Dir", "State", "ID", "RawBytes", "PayloadLen"
    );

    for entry in entries {
        let mut slice = entry.raw_frame.as_slice();
        let Ok(body_len) = read_varint(&mut slice) else {
            let _ = writeln!(
                out,
                "{:<5} {:<4} {:<14} {:<8} {:<10} {:<11} <invalid frame length VarInt>",
                entry.seq,
                entry.direction.as_str(),
                format!("{:?}", entry.state),
                "?",
                entry.raw_frame.len(),
                "?"
            );
            continue;
        };

        let Ok((packet_id, payload)) = decode_frame(slice) else {
            let _ = writeln!(
                out,
                "{:<5} {:<4} {:<14} {:<8} {:<10} {:<11} <invalid packet ID VarInt>",
                entry.seq,
                entry.direction.as_str(),
                format!("{:?}", entry.state),
                "?",
                entry.raw_frame.len(),
                body_len
            );
            continue;
        };

        let note = structural_note(entry.direction, entry.state, packet_id, payload);
        let _ = writeln!(
            out,
            "{:<5} {:<4} {:<14} {:#04x}     {:<10} {:<11} {}",
            entry.seq,
            entry.direction.as_str(),
            format!("{:?}", entry.state),
            packet_id,
            entry.raw_frame.len(),
            payload.len(),
            note
        );
    }

    out
}

fn structural_note(
    dir: Direction,
    state: ConnectionState,
    packet_id: i32,
    payload: &[u8],
) -> String {
    match (dir, state, packet_id) {
        (Direction::C2S, ConnectionState::Handshaking, HandshakePacket::ID) => {
            match decode_exact::<HandshakePacket>(payload) {
                Ok(hs) => format!(
                    "Handshake(protocol={}, port={}, intent={:?})",
                    hs.protocol_version, hs.server_port, hs.next_state
                ),
                Err(err) => format!("Handshake decode error: {err}"),
            }
        }
        (Direction::S2C, ConnectionState::Login, LoginSuccessPacket::ID) => {
            match decode_exact::<LoginSuccessPacket>(payload) {
                Ok(ls) => {
                    let expected_offline = offline_uuid(&ls.username);
                    let uuid_ver = ls.uuid.as_bytes()[6] >> 4;
                    let uuid_var = ls.uuid.as_bytes()[8] >> 6;
                    let sid_bytes = ls.session_id.as_bytes();
                    let sid_is_nil = sid_bytes.iter().all(|&b| b == 0);
                    let sid_ver = sid_bytes[6] >> 4;
                    let sid_var = sid_bytes[8] >> 6;
                    format!(
                        "LoginSuccess(username_len={}, uuid_v={uuid_ver}/var={uuid_var:#b}/matches_offline_v3={}, properties_len={}, session_id: is_nil={sid_is_nil}, equals_player_uuid={}, uuid_version={sid_ver}, uuid_variant={sid_var:#b})",
                        ls.username.len(),
                        ls.uuid == expected_offline,
                        ls.properties.len(),
                        ls.session_id == ls.uuid,
                    )
                }
                Err(err) => format!("LoginSuccess decode error: {err}"),
            }
        }
        _ => String::new(),
    }
}

/// Loads a `.rec` file from disk and returns its structural report string.
pub async fn inspect_file(path: &Path) -> Result<String, RecorderError> {
    let bytes = tokio::fs::read(path).await?;
    let entries = parse_recording(&bytes)?;
    Ok(format_structural_report(&entries))
}

/// Helper to create a new `.rec` file in `dir` for session `session_num`.
pub async fn create_recording_file(
    dir: &Path,
    session_num: u64,
) -> Result<(std::path::PathBuf, File), std::io::Error> {
    tokio::fs::create_dir_all(dir).await?;
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let path = dir.join(format!("session-{ts}-{session_num}.rec"));
    let file = File::create(&path).await?;
    Ok((path, file))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrite_protocol::codec::encode_frame;
    use ferrite_protocol::{LoginStartPacket, Uuid, PROTOCOL_VERSION};
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn loopback_guard_rejects_external_addresses() {
        let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 25566);
        assert!(ensure_loopback(local).is_ok());

        let all_interfaces = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 25566);
        assert!(matches!(
            ensure_loopback(all_interfaces),
            Err(RecorderError::NonLoopbackAddress(_))
        ));

        let external = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)), 25565);
        assert!(matches!(
            ensure_loopback(external),
            Err(RecorderError::NonLoopbackAddress(_))
        ));
    }

    #[tokio::test]
    async fn records_login_and_configuration_then_stops_at_play_while_forwarding() {
        let (mut client, proxy_client) = tokio::io::duplex(8192);
        let (proxy_upstream, mut upstream) = tokio::io::duplex(8192);
        let (rec_write, mut rec_read) = tokio::io::duplex(65_536);

        let proxy_task =
            tokio::spawn(
                async move { proxy_session(proxy_client, proxy_upstream, rec_write).await },
            );

        let hs = HandshakePacket {
            protocol_version: PROTOCOL_VERSION,
            server_address: "127.0.0.1".to_owned(),
            server_port: 25566,
            next_state: Intent::Login,
        }
        .to_frame()
        .unwrap();
        let login_start = LoginStartPacket {
            username: "SecretUser".to_owned(),
            player_uuid: offline_uuid("SecretUser"),
        }
        .to_frame()
        .unwrap();

        client.write_all(&hs).await.unwrap();
        client.write_all(&login_start).await.unwrap();

        let mut recv_buf = vec![0u8; hs.len() + login_start.len()];
        upstream.read_exact(&mut recv_buf).await.unwrap();
        assert_eq!(&recv_buf[..hs.len()], hs.as_slice());
        assert_eq!(&recv_buf[hs.len()..], login_start.as_slice());

        let session_uuid = Uuid::from_u128(0x1234_5678_9abc_4def_8000_0000_0000_0001);
        let login_success = LoginSuccessPacket {
            uuid: offline_uuid("SecretUser"),
            username: "SecretUser".to_owned(),
            properties: Vec::new(),
            session_id: session_uuid,
        }
        .to_frame()
        .unwrap();
        upstream.write_all(&login_success).await.unwrap();

        let mut client_recv = vec![0u8; login_success.len()];
        client.read_exact(&mut client_recv).await.unwrap();
        assert_eq!(client_recv, login_success);

        let login_ack = LoginAcknowledgedPacket.to_frame().unwrap();
        client.write_all(&login_ack).await.unwrap();
        let mut ack_recv = vec![0u8; login_ack.len()];
        upstream.read_exact(&mut ack_recv).await.unwrap();

        // Configuration: S2C registry-like frame (0x07) + S2C Finish Configuration (0x03)
        let secret_registry_frame = encode_frame(0x07, b"SECRET_REGISTRY_PAYLOAD").unwrap();
        let s2c_finish = encode_frame(0x03, &[]).unwrap();
        upstream.write_all(&secret_registry_frame).await.unwrap();
        upstream.write_all(&s2c_finish).await.unwrap();

        let mut cfg_recv = vec![0u8; secret_registry_frame.len() + s2c_finish.len()];
        client.read_exact(&mut cfg_recv).await.unwrap();

        // C2S Acknowledge Finish Configuration (0x03) -> transitions C2S to Play
        let c2s_finish = encode_frame(0x03, &[]).unwrap();
        client.write_all(&c2s_finish).await.unwrap();
        let mut c2s_finish_recv = vec![0u8; c2s_finish.len()];
        upstream.read_exact(&mut c2s_finish_recv).await.unwrap();

        // Play traffic in both directions MUST still be forwarded, but NOT recorded!
        let play_s2c = encode_frame(0x2b, &[9, 8, 7, 6]).unwrap();
        let play_c2s = encode_frame(0x1a, &[1, 2, 3]).unwrap();
        upstream.write_all(&play_s2c).await.unwrap();
        client.write_all(&play_c2s).await.unwrap();

        let mut play_s2c_recv = vec![0u8; play_s2c.len()];
        client.read_exact(&mut play_s2c_recv).await.unwrap();
        assert_eq!(play_s2c_recv, play_s2c);

        let mut play_c2s_recv = vec![0u8; play_c2s.len()];
        upstream.read_exact(&mut play_c2s_recv).await.unwrap();
        assert_eq!(play_c2s_recv, play_c2s);

        drop(client);
        drop(upstream);
        proxy_task.await.unwrap().unwrap();

        let mut rec_bytes = Vec::new();
        rec_read.read_to_end(&mut rec_bytes).await.unwrap();
        let entries = parse_recording(&rec_bytes).unwrap();
        assert_eq!(entries.len(), 7, "Play frames must not be recorded");
        assert_eq!(entries[0].state, ConnectionState::Handshaking);
        assert_eq!(entries[1].state, ConnectionState::Login);
        assert_eq!(entries[2].state, ConnectionState::Login);
        assert_eq!(entries[3].state, ConnectionState::Login);
        assert_eq!(entries[4].state, ConnectionState::Configuration);
        assert_eq!(entries[5].state, ConnectionState::Configuration);
        assert_eq!(entries[6].state, ConnectionState::Configuration);

        let report = format_structural_report(&entries);
        assert!(report.contains("uuid_version=4"));
        assert!(!report.contains("SECRET_REGISTRY_PAYLOAD"));
        assert!(!report.contains("SecretUser"));
    }

    #[tokio::test]
    async fn parser_error_stops_recording_without_dropping_tcp_stream() {
        let (mut client, proxy_client) = tokio::io::duplex(4096);
        let (proxy_upstream, mut upstream) = tokio::io::duplex(4096);
        let (rec_write, _rec_read) = tokio::io::duplex(4096);

        let proxy_task =
            tokio::spawn(
                async move { proxy_session(proxy_client, proxy_upstream, rec_write).await },
            );

        // Send a malformed 6-byte VarInt followed by arbitrary payload bytes.
        let malformed_stream = b"\x80\x80\x80\x80\x80\x80hello_raw_passthrough";
        client.write_all(malformed_stream).await.unwrap();

        let mut received = vec![0u8; malformed_stream.len()];
        upstream.read_exact(&mut received).await.unwrap();
        assert_eq!(received.as_slice(), malformed_stream);

        drop(client);
        drop(upstream);
        proxy_task.await.unwrap().unwrap();
    }
}
