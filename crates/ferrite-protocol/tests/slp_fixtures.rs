//! Compatibility tests against real wire frames captured from an official 26.3 client.

use ferrite_protocol::codec::{decode_frame, read_varint};
use ferrite_protocol::{
    decode_exact, HandshakePacket, Intent, Packet, PingRequestPacket, StatusRequestPacket,
    PROTOCOL_VERSION,
};

const C2S_HANDSHAKE_STATUS: &[u8] = include_bytes!("fixtures/v26_3/c2s_handshake_status.bin");
const C2S_HANDSHAKE_LOGIN: &[u8] = include_bytes!("fixtures/v26_3/c2s_handshake_login.bin");
const C2S_STATUS_REQUEST: &[u8] = include_bytes!("fixtures/v26_3/c2s_status_request.bin");
const C2S_PING_REQUEST: &[u8] = include_bytes!("fixtures/v26_3/c2s_ping_request.bin");

fn parse_wire_frame<P: Packet>(mut raw: &[u8]) -> P {
    let body_len = read_varint(&mut raw).unwrap();
    assert!(body_len >= 0, "frame length must be non-negative");
    assert_eq!(
        raw.len(),
        body_len as usize,
        "frame length prefix must match remaining wire bytes"
    );

    let (packet_id, payload) = decode_frame(raw).unwrap();
    assert_eq!(packet_id, P::ID, "packet ID mismatch");

    decode_exact(payload).unwrap()
}

#[test]
fn real_client_26_3_handshake_status_fixture() {
    let packet: HandshakePacket = parse_wire_frame(C2S_HANDSHAKE_STATUS);
    assert_eq!(
        packet,
        HandshakePacket {
            protocol_version: PROTOCOL_VERSION,
            server_address: "127.0.0.1".to_owned(),
            server_port: 25565,
            next_state: Intent::Status,
        }
    );
    assert_eq!(packet.to_frame().unwrap(), C2S_HANDSHAKE_STATUS);
}

#[test]
fn real_client_26_3_handshake_login_fixture() {
    let packet: HandshakePacket = parse_wire_frame(C2S_HANDSHAKE_LOGIN);
    assert_eq!(
        packet,
        HandshakePacket {
            protocol_version: PROTOCOL_VERSION,
            server_address: "127.0.0.1".to_owned(),
            server_port: 25565,
            next_state: Intent::Login,
        }
    );
    assert_eq!(packet.to_frame().unwrap(), C2S_HANDSHAKE_LOGIN);
}

#[test]
fn real_client_26_3_status_request_fixture() {
    let packet: StatusRequestPacket = parse_wire_frame(C2S_STATUS_REQUEST);
    assert_eq!(packet, StatusRequestPacket);
    assert_eq!(packet.to_frame().unwrap(), C2S_STATUS_REQUEST);
}

#[test]
fn real_client_26_3_ping_request_fixture() {
    let packet: PingRequestPacket = parse_wire_frame(C2S_PING_REQUEST);
    assert_eq!(packet, PingRequestPacket { timestamp: 806_178 });
    assert_eq!(packet.to_frame().unwrap(), C2S_PING_REQUEST);
}
