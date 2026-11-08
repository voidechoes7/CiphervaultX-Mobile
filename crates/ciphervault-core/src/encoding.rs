//! Base64 (standard, URL-safe, URL-safe unpadded), Base32 (RFC 4648), Hex, and UUID v4.

use crate::crypto::keys::random_bytes;
use crate::error::{Result, VaultError};

const B64_STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const B64_URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const B32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

pub fn b64_encode_std(data: &[u8]) -> String {
    b64_encode(data, B64_STD, true)
}

pub fn b64_encode_url(data: &[u8]) -> String {
    b64_encode(data, B64_URL, true)
}

pub fn b64_encode_url_nopad(data: &[u8]) -> String {
    b64_encode(data, B64_URL, false)
}

fn b64_encode(data: &[u8], alpha: &[u8; 64], pad: bool) -> String {
    let mut out = Vec::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(alpha[((n >> 18) & 0x3F) as usize]);
        out.push(alpha[((n >> 12) & 0x3F) as usize]);
        if chunk.len() > 1 {
            out.push(alpha[((n >> 6) & 0x3F) as usize]);
        } else if pad {
            out.push(b'=');
        }
        if chunk.len() > 2 {
            out.push(alpha[(n & 0x3F) as usize]);
        } else if pad {
            out.push(b'=');
        }
    }
    String::from_utf8(out).expect("ascii")
}

pub fn b64_decode_std(s: &str) -> Result<Vec<u8>> {
    b64_decode(s, false)
}

pub fn b64_decode_url(s: &str) -> Result<Vec<u8>> {
    b64_decode(s, true)
}

fn b64_decode(s: &str, url: bool) -> Result<Vec<u8>> {
    let s = s.trim();
    let unpadded = s.trim_end_matches('=');
    if unpadded.len() % 4 == 1 {
        return Err(VaultError::Malformed("invalid base64 length".into()));
    }
    let mut out = Vec::with_capacity(unpadded.len() * 3 / 4);
    let bytes = unpadded.as_bytes();
    for chunk in bytes.chunks(4) {
        let mut vals = [0u32; 4];
        for (i, &b) in chunk.iter().enumerate() {
            vals[i] = match b {
                b'A'..=b'Z' => (b - b'A') as u32,
                b'a'..=b'z' => (b - b'a' + 26) as u32,
                b'0'..=b'9' => (b - b'0' + 52) as u32,
                b'+' if !url => 62,
                b'/' if !url => 63,
                b'-' if url => 62,
                b'_' if url => 63,
                _ => return Err(VaultError::Malformed("invalid base64 character".into())),
            };
        }
        let n = (vals[0] << 18) | (vals[1] << 12) | (vals[2] << 6) | vals[3];
        out.push(((n >> 16) & 0xFF) as u8);
        if chunk.len() > 2 {
            out.push(((n >> 8) & 0xFF) as u8);
        }
        if chunk.len() > 3 {
            out.push((n & 0xFF) as u8);
        }
    }
    Ok(out)
}

/// RFC 4648 Base32 uppercase encoding without padding (or with padding; 20 bytes = 160 bits -> exact 32 chars).
pub fn base32_encode(data: &[u8]) -> String {
    let mut out = Vec::with_capacity((data.len() * 8 + 4) / 5);
    let mut buffer: u64 = 0;
    let mut bits_left: usize = 0;
    for &b in data {
        buffer = (buffer << 8) | (b as u64);
        bits_left += 8;
        while bits_left >= 5 {
            bits_left -= 5;
            out.push(B32_ALPHABET[((buffer >> bits_left) & 0x1F) as usize]);
        }
    }
    if bits_left > 0 {
        out.push(B32_ALPHABET[((buffer << (5 - bits_left)) & 0x1F) as usize]);
    }
    String::from_utf8(out).expect("ascii")
}

/// Hex lowercase encoding.
pub fn hex_encode(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 2);
    for &b in data {
        use std::fmt::Write;
        let _ = write!(&mut s, "{b:02x}");
    }
    s
}

/// RFC 4122 UUID v4 from the OS CSPRNG.
pub fn uuid_v4() -> String {
    let mut b: [u8; 16] = random_bytes();
    b[6] = (b[6] & 0x0F) | 0x40;
    b[8] = (b[8] & 0x3F) | 0x80;
    format!(
        "{}-{}-{}-{}-{}",
        hex_encode(&b[0..4]),
        hex_encode(&b[4..6]),
        hex_encode(&b[6..8]),
        hex_encode(&b[8..10]),
        hex_encode(&b[10..16]),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b64_roundtrips() {
        for len in 0..32 {
            let v: Vec<u8> = (0..len).map(|i| (i * 19 + 7) as u8).collect();
            let s = b64_encode_std(&v);
            assert_eq!(b64_decode_std(&s).unwrap(), v);
            let u = b64_encode_url(&v);
            assert_eq!(b64_decode_url(&u).unwrap(), v);
            let unp = b64_encode_url_nopad(&v);
            assert_eq!(b64_decode_url(&unp).unwrap(), v);
        }
    }

    #[test]
    fn base32_20_bytes_is_32_chars() {
        let b = [0xABu8; 20];
        let s = base32_encode(&b);
        assert_eq!(s.len(), 32);
    }

    #[test]
    fn uuid_v4_shape() {
        let u = uuid_v4();
        assert_eq!(u.len(), 36);
        assert_eq!(u.as_bytes()[14], b'4');
    }
}
