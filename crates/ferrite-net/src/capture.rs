//! Opt-in raw wire fixture capture and in-place PII sanitization.

use std::path::Path;

use ferrite_protocol::codec::decode_varint_prefix;
use ferrite_protocol::{ProtocolError, Uuid};
use tokio::io::AsyncWriteExt;

use crate::framing::WireFrame;

/// Maximum raw wire frame size (in bytes) written when `capture_dir` is enabled.
pub const MAX_CAPTURE_FRAME_BYTES: usize = 65_536;

/// Deterministic placeholder UUID written into captured `Login Start` fixtures
/// (`00010203-0405-0607-0809-0a0b0c0d0e0f`) so account UUIDs never touch disk.
pub const SANITIZED_FIXTURE_UUID: Uuid = Uuid::from_bytes([
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
]);

pub(crate) async fn save_fixture_once(
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
pub(crate) fn sanitize_login_start_wire_frame(frame: &WireFrame) -> Result<Vec<u8>, ProtocolError> {
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
