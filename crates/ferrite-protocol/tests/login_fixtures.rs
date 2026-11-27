//! Compatibility tests against real Login wire frames captured from an official 26.3 client.

use ferrite_protocol::codec::{decode_frame, read_varint};
use ferrite_protocol::{decode_exact, LoginAcknowledgedPacket, LoginStartPacket, Packet, Uuid};

const C2S_LOGIN_START: &[u8] = include_bytes!("fixtures/v26_3/c2s_login_start.bin");
const C2S_LOGIN_ACKNOWLEDGED: &[u8] = include_bytes!("fixtures/v26_3/c2s_login_acknowledged.bin");

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
fn real_client_26_3_login_start_fixture() {
    let packet: LoginStartPacket = parse_wire_frame(C2S_LOGIN_START);
    let expected_uuid = Uuid::parse_str("00010203-0405-0607-0809-0a0b0c0d0e0f").unwrap();
    assert_eq!(
        packet,
        LoginStartPacket {
            username: "TestPlayer_".to_owned(),
            player_uuid: expected_uuid,
        }
    );
    assert_eq!(packet.to_frame().unwrap(), C2S_LOGIN_START);
}

#[test]
fn real_client_26_3_login_acknowledged_fixture() {
    let packet: LoginAcknowledgedPacket = parse_wire_frame(C2S_LOGIN_ACKNOWLEDGED);
    assert_eq!(packet, LoginAcknowledgedPacket);
    assert_eq!(packet.to_frame().unwrap(), C2S_LOGIN_ACKNOWLEDGED);
}
