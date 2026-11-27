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
- `c2s_login_start.bin` (30 bytes, captured on Login): `Login Start` (`0x00`). All client-encoded VarInt prefixes (`FrameBodyLength`, `PacketID`, `UsernameByteLength`) are preserved verbatim from the client wire stream; before writing to disk, `ferrite-net` scrubs the 11-byte username payload in-place with `"TestPlayer_"` (`"TestPlayer______"[..name_len]`) and replaces the 16-byte account UUID in-place with `00010203-0405-0607-0809-0a0b0c0d0e0f` (`SANITIZED_FIXTURE_UUID`) so real account identifiers never touch disk.
- `c2s_login_acknowledged.bin` (2 bytes, captured on Login): `Login Acknowledged` (`0x03`), empty payload.
