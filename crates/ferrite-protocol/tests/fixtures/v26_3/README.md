# Official Client Wire Fixtures — 26.3 (Protocol 777)

## Provenance
Captured directly from an unmodified official Java Edition **26.3** client connecting to `ferrite-server` over loopback (`127.0.0.1:25565`) with `FERRITE_CAPTURE_DIR` enabled on `2026-11-27`.

Each `.bin` file stores the exact uncompressed TCP wire frame sent by the client:
`VarInt(FrameBodyLength) | VarInt(PacketID) | Payload`.

No personal account data (usernames, UUIDs, tokens, or external IP addresses) is present in any of these packets.

## Files
- `c2s_handshake_status.bin` (17 bytes): `Handshake` (`0x00`), `protocol_version = 777`, `server_address = "127.0.0.1"`, `server_port = 25565`, `next_state = 1` (`Status`).
- `c2s_status_request.bin` (2 bytes): `Status Request` (`0x00`), empty payload.
- `c2s_ping_request.bin` (10 bytes): `Ping Request` (`0x01`), `timestamp = 806178` (`0x00000000000c4d22`, client monotonic milliseconds).
- `c2s_handshake_login.bin` (17 bytes): `Handshake` (`0x00`), `protocol_version = 777`, `server_address = "127.0.0.1"`, `server_port = 25565`, `next_state = 2` (`Login`).
