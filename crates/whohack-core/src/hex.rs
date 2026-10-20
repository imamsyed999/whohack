//! Lowercase hex encoding for SHA-256 digests.
//!
//! Used as a serde adapter (`#[serde(with = "crate::hex::sha256")]`) so
//! digests serialize as a 64-character string instead of a 32-number array.

use std::fmt;

/// Encodes bytes as lowercase hex.
pub fn encode(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(DIGITS[usize::from(b >> 4)] as char);
        out.push(DIGITS[usize::from(b & 0x0f)] as char);
    }
    out
}

/// Error returned when a string is not a valid 32-byte hex digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HexError {
    Length(usize),
    InvalidChar(char),
}

impl fmt::Display for HexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HexError::Length(n) => write!(f, "expected 64 hex characters, got {n}"),
            HexError::InvalidChar(c) => write!(f, "invalid hex character {c:?}"),
        }
    }
}

impl std::error::Error for HexError {}

/// Decodes a 64-character hex string (either case) into a 32-byte digest.
pub fn decode32(s: &str) -> Result<[u8; 32], HexError> {
    if s.len() != 64 {
        return Err(HexError::Length(s.len()));
    }
    let mut out = [0u8; 32];
    let bytes = s.as_bytes();
    for (i, slot) in out.iter_mut().enumerate() {
        let hi = nibble(bytes[2 * i])?;
        let lo = nibble(bytes[2 * i + 1])?;
        *slot = (hi << 4) | lo;
    }
    Ok(out)
}

fn nibble(c: u8) -> Result<u8, HexError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(HexError::InvalidChar(char::from(c))),
    }
}

/// serde adapter for `[u8; 32]` digests.
pub mod sha256 {
    use serde::{Deserialize, Deserializer, Serializer, de::Error as _};

    pub fn serialize<S: Serializer>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&super::encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = <std::borrow::Cow<'de, str>>::deserialize(d)?;
        super::decode32(&s).map_err(D::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let mut d = [0u8; 32];
        for (i, b) in d.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(37);
        }
        let s = encode(&d);
        assert_eq!(s.len(), 64);
        assert_eq!(s, s.to_lowercase());
        assert_eq!(decode32(&s).unwrap(), d);
        assert_eq!(decode32(&s.to_uppercase()).unwrap(), d);
    }

    #[test]
    fn rejects_bad_input() {
        assert_eq!(decode32("abcd"), Err(HexError::Length(4)));
        let bad = format!("{}zz", "0".repeat(62));
        assert_eq!(decode32(&bad), Err(HexError::InvalidChar('z')));
    }
}
