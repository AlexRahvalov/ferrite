//! 128-bit UUID representation and offline-mode Version 3 UUID generation.
//!
//! Sources:
//! - RFC 4122 §4.3 (Algorithm for Creating a Name-Based UUID with MD5, version 3)
//! - RFC 1321 (The MD5 Message-Digest Algorithm)
//! - Community Java Edition protocol documentation: offline servers derive player
//!   UUIDs via `UUID.nameUUIDFromBytes(("OfflinePlayer:" + username).getBytes(UTF_8))`.

use std::fmt;

use crate::ProtocolError;

/// Big-endian 128-bit UUID as transmitted on the wire (two 64-bit big-endian integers / 16 bytes).
///
/// Source: community protocol documentation (`Java Edition protocol/Data types#UUID`)
/// and `PrismarineJS/minecraft-data` (`UUID` native type, 16 bytes big-endian, MIT).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Uuid([u8; 16]);

impl Uuid {
    /// Constructs a [`Uuid`] from raw big-endian bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Returns the raw big-endian 16-byte representation.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Constructs a [`Uuid`] from a 128-bit integer.
    #[must_use]
    pub const fn from_u128(value: u128) -> Self {
        Self(value.to_be_bytes())
    }

    /// Converts this [`Uuid`] to a 128-bit integer.
    #[must_use]
    pub const fn as_u128(&self) -> u128 {
        u128::from_be_bytes(self.0)
    }

    /// Parses a canonical hyphenated (`8-4-4-4-12`) or 32-hex-digit UUID string.
    pub fn parse_str(input: &str) -> Result<Self, ProtocolError> {
        let hex_only: String = match input.len() {
            36 => {
                for &idx in &[8usize, 13, 18, 23] {
                    if input.as_bytes().get(idx) != Some(&b'-') {
                        return Err(ProtocolError::InvalidUuidString);
                    }
                }
                input.chars().filter(|&c| c != '-').collect()
            }
            32 => input.to_owned(),
            _ => return Err(ProtocolError::InvalidUuidString),
        };

        if hex_only.len() != 32 || !hex_only.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(ProtocolError::InvalidUuidString);
        }

        let mut bytes = [0u8; 16];
        for (i, slot) in bytes.iter_mut().enumerate() {
            let chunk = hex_only
                .get(i * 2..i * 2 + 2)
                .ok_or(ProtocolError::InvalidUuidString)?;
            *slot = u8::from_str_radix(chunk, 16).map_err(|_| ProtocolError::InvalidUuidString)?;
        }
        Ok(Self(bytes))
    }
}

impl fmt::Display for Uuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = &self.0;
        write!(
            f,
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            b[0], b[1], b[2], b[3],
            b[4], b[5],
            b[6], b[7],
            b[8], b[9],
            b[10], b[11], b[12], b[13], b[14], b[15]
        )
    }
}

impl fmt::Debug for Uuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Uuid({self})")
    }
}

/// Computes the deterministic offline-mode Version 3 UUID for `username`.
///
/// Algorithm (community Java Edition protocol specification & RFC 4122 §4.3):
/// 1. Concatenate ASCII `"OfflinePlayer:"` with UTF-8 bytes of `username`.
/// 2. Compute the 128-bit MD5 digest (RFC 1321).
/// 3. Set version bits in `digest[6]` to `0b0011` (Version 3) and variant bits in
///    `digest[8]` to `0b10` (RFC 4122 IETF variant).
#[must_use]
pub fn offline_uuid(username: &str) -> Uuid {
    let mut input = Vec::with_capacity("OfflinePlayer:".len() + username.len());
    input.extend_from_slice(b"OfflinePlayer:");
    input.extend_from_slice(username.as_bytes());

    let mut digest = md5(&input);
    digest[6] = (digest[6] & 0x0F) | 0x30;
    digest[8] = (digest[8] & 0x3F) | 0x80;
    Uuid::from_bytes(digest)
}

/// Pure safe Rust implementation of RFC 1321 MD5 message digest.
#[must_use]
fn md5(data: &[u8]) -> [u8; 16] {
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];

    const K: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613,
        0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193,
        0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d,
        0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122,
        0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
        0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244,
        0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb,
        0xeb86d391,
    ];

    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut padded = Vec::with_capacity((data.len() + 72) & !63);
    padded.extend_from_slice(data);
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0x00);
    }
    padded.extend_from_slice(&bit_len.to_le_bytes());

    let mut a0: u32 = 0x6745_2301;
    let mut b0: u32 = 0xefcd_ab89;
    let mut c0: u32 = 0x98ba_dcfe;
    let mut d0: u32 = 0x1032_5476;

    for chunk in padded.as_chunks::<64>().0 {
        let mut m = [0u32; 16];
        for (i, word) in m.iter_mut().enumerate() {
            let base = i * 4;
            *word = u32::from_le_bytes([
                chunk[base],
                chunk[base + 1],
                chunk[base + 2],
                chunk[base + 3],
            ]);
        }

        let mut a = a0;
        let mut b = b0;
        let mut c = c0;
        let mut d = d0;

        for i in 0..64 {
            let (f, g) = match i {
                0..=15 => ((b & c) | (!b & d), i),
                16..=31 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                32..=47 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            let temp = d;
            d = c;
            c = b;
            let sum = a.wrapping_add(f).wrapping_add(K[i]).wrapping_add(m[g]);
            b = b.wrapping_add(sum.rotate_left(S[i]));
            a = temp;
        }

        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }

    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&a0.to_le_bytes());
    out[4..8].copy_from_slice(&b0.to_le_bytes());
    out[8..12].copy_from_slice(&c0.to_le_bytes());
    out[12..16].copy_from_slice(&d0.to_le_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn md5_rfc1321_test_vectors() {
        // Official test suite from RFC 1321 §A.5.
        assert_eq!(hex(&md5(b"")), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(hex(&md5(b"a")), "0cc175b9c0f1b6a831c399e269772661");
        assert_eq!(hex(&md5(b"abc")), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(
            hex(&md5(b"message digest")),
            "f96b697d7cb7938d525a2f31aaf161d0"
        );
        assert_eq!(
            hex(&md5(b"abcdefghijklmnopqrstuvwxyz")),
            "c3fcd3d76192e4007dfb496cca67e13b"
        );
    }

    #[test]
    fn offline_uuid_matches_known_community_vector() {
        let uuid = offline_uuid("Notch");
        assert_eq!(uuid.to_string(), "b50ad385-829d-3141-a216-7e7d7539ba7f");
        assert_eq!(Uuid::parse_str(&uuid.to_string()).unwrap(), uuid);
        assert_eq!(uuid.as_bytes()[6] >> 4, 3, "must be UUID version 3");
        assert_eq!(uuid.as_bytes()[8] >> 6, 0b10, "must be RFC 4122 variant");
    }

    #[test]
    fn parse_str_rejects_non_hex_and_plus_prefixed_nibbles() {
        for invalid in [
            "+0+1+2+3-+4+5-+6+7-+8+9-+a+b+c+d+e+f",
            "+0+1+2+3+4+5+6+7+8+9+a+b+c+d+e+f",
            "g0010203-0405-0607-0809-0a0b0c0d0e0f",
            " 0010203-0405-0607-0809-0a0b0c0d0e0f",
        ] {
            let parsed = Uuid::parse_str(invalid);
            assert!(
                matches!(parsed, Err(ProtocolError::InvalidUuidString)),
                "expected InvalidUuidString for {invalid:?}, got {parsed:?}"
            );
        }
    }

    #[test]
    fn parse_str_multibyte_utf8_exact_uuid_byte_lengths_do_not_panic() {
        // 16 Cyrillic chars = exactly 32 UTF-8 bytes (same byte length as hex-only UUID).
        let cyrillic_32 = "ИльяТестАБВГДЕЖЗ";
        assert_eq!(cyrillic_32.len(), 32);
        assert!(matches!(
            Uuid::parse_str(cyrillic_32),
            Err(ProtocolError::InvalidUuidString)
        ));

        // 36 UTF-8 bytes with '-' at exact hyphen byte offsets [8, 13, 18, 23].
        let cyrillic_36_with_hyphens = "Илья-Те-ст-АБ-ВГДЕЖЗ";
        assert_eq!(cyrillic_36_with_hyphens.len(), 36);
        assert!(matches!(
            Uuid::parse_str(cyrillic_36_with_hyphens),
            Err(ProtocolError::InvalidUuidString)
        ));

        // 36 UTF-8 bytes where byte index 8 lands inside a 3-byte UTF-8 sequence ('─' = 3B).
        let mid_char_boundary_36 = "────────────";
        assert_eq!(mid_char_boundary_36.len(), 36);
        assert!(matches!(
            Uuid::parse_str(mid_char_boundary_36),
            Err(ProtocolError::InvalidUuidString)
        ));
    }
}
