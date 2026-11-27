//! Low-level wire format primitives and packet framing.

use crate::{ProtocolError, MAX_PACKET_LEN};

/// Maximum number of bytes a 32-bit VarInt may occupy on the wire.
pub const MAX_VARINT_BYTES: usize = 5;

/// Decodes a VarInt from the start of `buf` without mutating it.
///
/// Returns `Ok(None)` if `buf` does not yet contain a complete VarInt.
pub fn decode_varint_prefix(buf: &[u8]) -> Result<Option<(i32, usize)>, ProtocolError> {
    let mut result: u32 = 0;

    for (index, &byte) in buf.iter().enumerate() {
        if index >= MAX_VARINT_BYTES {
            return Err(ProtocolError::VarIntTooLong);
        }

        let value = u32::from(byte & 0x7F);
        result |= value << (index * 7);

        if (byte & 0x80) == 0 {
            return Ok(Some((result as i32, index + 1)));
        }

        if index == MAX_VARINT_BYTES - 1 {
            return Err(ProtocolError::VarIntTooLong);
        }
    }

    Ok(None)
}

/// Reads a VarInt from `input`, advancing the slice.
pub fn read_varint(input: &mut &[u8]) -> Result<i32, ProtocolError> {
    match decode_varint_prefix(input)? {
        Some((value, consumed)) => {
            *input = &input[consumed..];
            Ok(value)
        }
        None => Err(ProtocolError::UnexpectedEof),
    }
}

/// Appends a VarInt-encoded 32-bit integer to `out`.
pub fn write_varint(value: i32, out: &mut Vec<u8>) {
    let mut v = value as u32;
    loop {
        if (v & !0x7F) == 0 {
            out.push(v as u8);
            return;
        }
        out.push(((v & 0x7F) as u8) | 0x80);
        v >>= 7;
    }
}

/// Returns the encoded byte length of a VarInt.
#[must_use]
pub const fn varint_len(value: i32) -> usize {
    let v = value as u32;
    if v < (1 << 7) {
        1
    } else if v < (1 << 14) {
        2
    } else if v < (1 << 21) {
        3
    } else if v < (1 << 28) {
        4
    } else {
        5
    }
}

/// Reads a length-prefixed UTF-8 string, enforcing a maximum UTF-16 code unit count.
pub fn read_string(input: &mut &[u8], max_utf16_units: usize) -> Result<String, ProtocolError> {
    let raw_len = read_varint(input)?;
    if raw_len < 0 {
        return Err(ProtocolError::NegativeLength(raw_len));
    }
    let byte_len = raw_len as usize;
    let max_bytes = max_utf16_units.saturating_mul(3);
    if byte_len > max_bytes {
        return Err(ProtocolError::StringTooLong {
            len: byte_len,
            max: max_bytes,
        });
    }
    if input.len() < byte_len {
        return Err(ProtocolError::UnexpectedEof);
    }

    let (bytes, rest) = input.split_at(byte_len);
    *input = rest;

    let text = std::str::from_utf8(bytes)?;
    let utf16_len = text.encode_utf16().count();
    if utf16_len > max_utf16_units {
        return Err(ProtocolError::StringTooLong {
            len: utf16_len,
            max: max_utf16_units,
        });
    }

    Ok(text.to_owned())
}

/// Writes a length-prefixed UTF-8 string, enforcing a maximum UTF-16 code unit count.
pub fn write_string(
    value: &str,
    max_utf16_units: usize,
    out: &mut Vec<u8>,
) -> Result<(), ProtocolError> {
    let utf16_len = value.encode_utf16().count();
    if utf16_len > max_utf16_units {
        return Err(ProtocolError::StringTooLong {
            len: utf16_len,
            max: max_utf16_units,
        });
    }

    let byte_len = i32::try_from(value.len()).map_err(|_| ProtocolError::StringTooLong {
        len: value.len(),
        max: max_utf16_units.saturating_mul(3),
    })?;

    write_varint(byte_len, out);
    out.extend_from_slice(value.as_bytes());
    Ok(())
}

/// Reads a big-endian `u16` from `input`.
pub fn read_u16(input: &mut &[u8]) -> Result<u16, ProtocolError> {
    if input.len() < 2 {
        return Err(ProtocolError::UnexpectedEof);
    }
    let (bytes, rest) = input.split_at(2);
    *input = rest;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

/// Writes a big-endian `u16` to `out`.
pub fn write_u16(value: u16, out: &mut Vec<u8>) {
    out.extend_from_slice(&value.to_be_bytes());
}

/// Reads a big-endian `i64` from `input`.
pub fn read_i64(input: &mut &[u8]) -> Result<i64, ProtocolError> {
    if input.len() < 8 {
        return Err(ProtocolError::UnexpectedEof);
    }
    let (bytes, rest) = input.split_at(8);
    *input = rest;
    Ok(i64::from_be_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

/// Writes a big-endian `i64` to `out`.
pub fn write_i64(value: i64, out: &mut Vec<u8>) {
    out.extend_from_slice(&value.to_be_bytes());
}

/// Encodes an uncompressed length-prefixed packet frame (`Length | PacketID | Payload`).
pub fn encode_frame(packet_id: i32, payload: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    let body_len = varint_len(packet_id) + payload.len();
    if body_len > MAX_PACKET_LEN {
        return Err(ProtocolError::PacketTooLarge {
            len: body_len,
            max: MAX_PACKET_LEN,
        });
    }

    let body_len_i32 = i32::try_from(body_len).map_err(|_| ProtocolError::PacketTooLarge {
        len: body_len,
        max: MAX_PACKET_LEN,
    })?;

    let mut frame = Vec::with_capacity(varint_len(body_len_i32) + body_len);
    write_varint(body_len_i32, &mut frame);
    write_varint(packet_id, &mut frame);
    frame.extend_from_slice(payload);
    Ok(frame)
}

/// Splits an uncompressed packet frame body into `(packet_id, payload)`.
pub fn decode_frame(mut frame_body: &[u8]) -> Result<(i32, &[u8]), ProtocolError> {
    let packet_id = read_varint(&mut frame_body)?;
    Ok((packet_id, frame_body))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_roundtrip_known_vectors() {
        let cases: &[(i32, &[u8])] = &[
            (0, &[0x00]),
            (1, &[0x01]),
            (2, &[0x02]),
            (127, &[0x7F]),
            (128, &[0x80, 0x01]),
            (255, &[0xFF, 0x01]),
            (777, &[0x89, 0x06]),
            (25_565, &[0xDD, 0xC7, 0x01]),
            (2_097_151, &[0xFF, 0xFF, 0x7F]),
            (i32::MAX, &[0xFF, 0xFF, 0xFF, 0xFF, 0x07]),
            (-1, &[0xFF, 0xFF, 0xFF, 0xFF, 0x0F]),
            (i32::MIN, &[0x80, 0x80, 0x80, 0x80, 0x08]),
        ];

        for &(value, expected) in cases {
            let mut buf = Vec::new();
            write_varint(value, &mut buf);
            assert_eq!(buf.as_slice(), expected, "encoding {value}");
            assert_eq!(varint_len(value), expected.len(), "length for {value}");

            let mut slice = buf.as_slice();
            let decoded = read_varint(&mut slice).unwrap();
            assert_eq!(decoded, value, "decoding {value}");
            assert!(slice.is_empty());
        }
    }

    #[test]
    fn varint_rejects_too_long_and_truncated() {
        let too_long = [0x80, 0x80, 0x80, 0x80, 0x80, 0x01];
        let mut slice = too_long.as_slice();
        assert!(matches!(
            read_varint(&mut slice),
            Err(ProtocolError::VarIntTooLong)
        ));

        let truncated = [0x80, 0x80];
        assert_eq!(decode_varint_prefix(&truncated).unwrap(), None);
        let mut slice = truncated.as_slice();
        assert!(matches!(
            read_varint(&mut slice),
            Err(ProtocolError::UnexpectedEof)
        ));
    }

    #[test]
    fn string_roundtrip_and_limit() {
        let mut buf = Vec::new();
        write_string("ferrite.example", 255, &mut buf).unwrap();
        let mut slice = buf.as_slice();
        assert_eq!(read_string(&mut slice, 255).unwrap(), "ferrite.example");
        assert!(slice.is_empty());

        let mut buf = Vec::new();
        assert!(matches!(
            write_string("abcdef", 5, &mut buf),
            Err(ProtocolError::StringTooLong { .. })
        ));
    }

    #[test]
    fn frame_roundtrip() {
        let frame = encode_frame(0x01, &[1, 2, 3, 4]).unwrap();
        let mut slice = frame.as_slice();
        let len = read_varint(&mut slice).unwrap() as usize;
        assert_eq!(len, slice.len());
        let (id, payload) = decode_frame(slice).unwrap();
        assert_eq!(id, 0x01);
        assert_eq!(payload, &[1, 2, 3, 4]);
    }
}
