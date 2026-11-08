//! Minimal, strict JSON object parser and formatter for Cryptomator vault structures.
//!
//! Only flat JSON objects with string and unsigned integer fields are needed by
//! `masterkey.cryptomator` and `vault.cryptomator` JWT headers/claims.

use std::collections::BTreeMap;

use crate::error::{Result, VaultError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JsonVal {
    Str(String),
    Num(u64),
}

impl JsonVal {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            JsonVal::Str(s) => Some(s),
            _ => None,
        }
    }
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            JsonVal::Num(n) => Some(*n),
            _ => None,
        }
    }
}

pub fn escape_json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                use std::fmt::Write;
                let _ = write!(&mut out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Parse a flat JSON object (`{"key": "val", "num": 123}`) into a map.
pub fn parse_flat_object(bytes: &[u8]) -> Result<BTreeMap<String, JsonVal>> {
    let s = std::str::from_utf8(bytes).map_err(|_| VaultError::Malformed("json not utf-8".into()))?;
    let mut chars = s.chars().peekable();
    skip_ws(&mut chars);
    if chars.next() != Some('{') {
        return Err(VaultError::Malformed("json: expected '{'".into()));
    }
    let mut map = BTreeMap::new();
    loop {
        skip_ws(&mut chars);
        match chars.peek().copied() {
            Some('}') => {
                chars.next();
                break;
            }
            Some('"') => {}
            _ => return Err(VaultError::Malformed("json: expected key or '}'".into())),
        }
        let key = parse_string(&mut chars)?;
        skip_ws(&mut chars);
        if chars.next() != Some(':') {
            return Err(VaultError::Malformed("json: expected ':'".into()));
        }
        skip_ws(&mut chars);
        let val = match chars.peek().copied() {
            Some('"') => JsonVal::Str(parse_string(&mut chars)?),
            Some(c) if c.is_ascii_digit() => JsonVal::Num(parse_u64(&mut chars)?),
            _ => return Err(VaultError::Malformed("json: expected string or unsigned integer".into())),
        };
        map.insert(key, val);
        skip_ws(&mut chars);
        match chars.peek().copied() {
            Some(',') => {
                chars.next();
            }
            Some('}') => {
                chars.next();
                break;
            }
            _ => return Err(VaultError::Malformed("json: expected ',' or '}'".into())),
        }
    }
    skip_ws(&mut chars);
    if chars.next().is_some() {
        return Err(VaultError::Malformed("json: trailing characters".into()));
    }
    Ok(map)
}

fn skip_ws(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) {
    while let Some(&c) = chars.peek() {
        if c.is_ascii_whitespace() {
            chars.next();
        } else {
            break;
        }
    }
}

fn parse_string(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) -> Result<String> {
    if chars.next() != Some('"') {
        return Err(VaultError::Malformed("json: expected '\"'".into()));
    }
    let mut out = String::new();
    while let Some(c) = chars.next() {
        match c {
            '"' => return Ok(out),
            '\\' => match chars.next() {
                Some('"') => out.push('"'),
                Some('\\') => out.push('\\'),
                Some('/') => out.push('/'),
                Some('n') => out.push('\n'),
                Some('r') => out.push('\r'),
                Some('t') => out.push('\t'),
                Some('u') => {
                    let mut hex = String::with_capacity(4);
                    for _ in 0..4 {
                        hex.push(chars.next().ok_or_else(|| VaultError::Malformed("json: incomplete \\u".into()))?);
                    }
                    let code = u32::from_str_radix(&hex, 16)
                        .map_err(|_| VaultError::Malformed("json: invalid \\u hex".into()))?;
                    out.push(char::from_u32(code).ok_or_else(|| VaultError::Malformed("json: invalid char".into()))?);
                }
                _ => return Err(VaultError::Malformed("json: invalid escape".into())),
            },
            c => out.push(c),
        }
    }
    Err(VaultError::Malformed("json: unterminated string".into()))
}

fn parse_u64(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) -> Result<u64> {
    let mut s = String::new();
    while let Some(&c) = chars.peek() {
        if c.is_ascii_digit() {
            s.push(c);
            chars.next();
        } else {
            break;
        }
    }
    s.parse::<u64>().map_err(|_| VaultError::Malformed("json: integer overflow".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_roundtrip() {
        let j = br#"{ "version": 999, "scryptSalt": "abc=", "cost": 32768 }"#;
        let m = parse_flat_object(j).unwrap();
        assert_eq!(m.get("version").unwrap().as_u64(), Some(999));
        assert_eq!(m.get("scryptSalt").unwrap().as_str(), Some("abc="));
        assert_eq!(m.get("cost").unwrap().as_u64(), Some(32768));
    }
}
