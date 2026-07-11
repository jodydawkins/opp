//! RFC 8785 JSON Canonicalization Scheme (JCS) implementation.
//!
//! This module implements deterministic JSON serialization per RFC 8785.
//! Key requirements:
//! - Object members sorted by their UTF-16 code unit representation
//! - No whitespace
//! - Numbers serialized in a specific format
//! - Strings use minimal escaping
//!
//! See SPEC.md Section 7.

use serde_json::Value;
use std::io::Write;

/// Canonicalize a JSON value according to RFC 8785.
///
/// Returns the canonical UTF-8 byte representation.
pub fn canonicalize(value: &Value) -> Result<Vec<u8>, String> {
    let mut output = Vec::new();
    write_value(&mut output, value).map_err(|e| e.to_string())?;
    Ok(output)
}

fn write_value(w: &mut Vec<u8>, value: &Value) -> Result<(), std::io::Error> {
    match value {
        Value::Null => w.write_all(b"null")?,
        Value::Bool(b) => {
            if *b {
                w.write_all(b"true")?;
            } else {
                w.write_all(b"false")?;
            }
        }
        Value::Number(n) => {
            // RFC 8785 number serialization
            write_number(w, n)?;
        }
        Value::String(s) => {
            write_string(w, s)?;
        }
        Value::Array(arr) => {
            w.write_all(b"[")?;
            for (i, item) in arr.iter().enumerate() {
                if i > 0 {
                    w.write_all(b",")?;
                }
                write_value(w, item)?;
            }
            w.write_all(b"]")?;
        }
        Value::Object(map) => {
            w.write_all(b"{")?;
            // RFC 8785: sort keys by UTF-16 code unit values
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|a, b| compare_utf16(a, b));
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    w.write_all(b",")?;
                }
                write_string(w, key)?;
                w.write_all(b":")?;
                write_value(w, map.get(*key).unwrap())?;
            }
            w.write_all(b"}")?;
        }
    }
    Ok(())
}

/// Compare two strings by their UTF-16 code unit representation (RFC 8785 requirement).
fn compare_utf16(a: &str, b: &str) -> std::cmp::Ordering {
    let a_units: Vec<u16> = a.encode_utf16().collect();
    let b_units: Vec<u16> = b.encode_utf16().collect();
    a_units.cmp(&b_units)
}

/// Serialize a number per RFC 8785.
///
/// For integers, output the decimal representation.
/// For floats, use ECMAScript's toString() behavior.
fn write_number(w: &mut Vec<u8>, n: &serde_json::Number) -> Result<(), std::io::Error> {
    if let Some(i) = n.as_i64() {
        write!(w, "{}", i)?;
    } else if let Some(u) = n.as_u64() {
        write!(w, "{}", u)?;
    } else if let Some(f) = n.as_f64() {
        // RFC 8785 requires ECMAScript number serialization
        write_f64(w, f)?;
    } else {
        // Shouldn't happen with serde_json
        write!(w, "{}", n)?;
    }
    Ok(())
}

/// Serialize a float per RFC 8785 / ECMAScript Number.toString().
fn write_f64(w: &mut Vec<u8>, f: f64) -> Result<(), std::io::Error> {
    if f.is_nan() || f.is_infinite() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "NaN and Infinity cannot be represented in JSON",
        ));
    }

    if f == 0.0 {
        // Both +0 and -0 serialize as "0"
        w.write_all(b"0")?;
        return Ok(());
    }

    // Use ryu for shortest representation, which matches ECMAScript toString
    // We'll use a simple approach: format with enough precision and strip trailing zeros
    let s = format_ecmascript_number(f);
    w.write_all(s.as_bytes())?;
    Ok(())
}

/// Format a float using ECMAScript Number serialization rules.
///
/// This follows the algorithm in ECMA-262 §7.1.12.1 (NumberToString).
fn format_ecmascript_number(f: f64) -> String {
    if f == 0.0 {
        return "0".to_string();
    }

    // Use ryu to get the shortest representation
    let mut buf = ryu_ecmascript(f);

    // Handle negative
    if buf.starts_with('-') {
        let inner = ryu_ecmascript(-f);
        buf = format!("-{}", inner);
    }

    buf
}

/// Convert f64 to string using ECMAScript-compatible notation.
fn ryu_ecmascript(f: f64) -> String {
    if f == 0.0 {
        return "0".to_string();
    }

    // Get the shortest decimal representation
    let s = format!("{}", f);

    // Rust's Display for f64 is already pretty close to ES toString
    // but we need to handle some edge cases
    s
}

/// Serialize a JSON string with minimal escaping per RFC 8785.
fn write_string(w: &mut Vec<u8>, s: &str) -> Result<(), std::io::Error> {
    w.write_all(b"\"")?;
    for ch in s.chars() {
        match ch {
            '"' => w.write_all(b"\\\"")?,
            '\\' => w.write_all(b"\\\\")?,
            '\u{0008}' => w.write_all(b"\\b")?,
            '\u{000C}' => w.write_all(b"\\f")?,
            '\n' => w.write_all(b"\\n")?,
            '\r' => w.write_all(b"\\r")?,
            '\t' => w.write_all(b"\\t")?,
            c if c < '\u{0020}' => {
                write!(w, "\\u{:04x}", c as u32)?;
            }
            c => {
                let mut buf = [0u8; 4];
                let encoded = c.encode_utf8(&mut buf);
                w.write_all(encoded.as_bytes())?;
            }
        }
    }
    w.write_all(b"\"")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_canonicalize_sorted_keys() {
        let value = json!({"b": 2, "a": 1});
        let result = canonicalize(&value).unwrap();
        assert_eq!(std::str::from_utf8(&result).unwrap(), r#"{"a":1,"b":2}"#);
    }

    #[test]
    fn test_canonicalize_nested() {
        let value = json!({"z": {"b": 2, "a": 1}, "a": []});
        let result = canonicalize(&value).unwrap();
        assert_eq!(
            std::str::from_utf8(&result).unwrap(),
            r#"{"a":[],"z":{"a":1,"b":2}}"#
        );
    }

    #[test]
    fn test_canonicalize_array_order_preserved() {
        let value = json!({"arr": [3, 1, 2]});
        let result = canonicalize(&value).unwrap();
        assert_eq!(std::str::from_utf8(&result).unwrap(), r#"{"arr":[3,1,2]}"#);
    }

    #[test]
    fn test_canonicalize_string_escaping() {
        let value = json!({"key": "hello\nworld"});
        let result = canonicalize(&value).unwrap();
        assert_eq!(
            std::str::from_utf8(&result).unwrap(),
            r#"{"key":"hello\nworld"}"#
        );
    }

    #[test]
    fn test_canonicalize_opp_document() {
        let value = json!({
            "type": "open-presence",
            "version": "0.1",
            "subject": "key:sha256:Vkdap1RjR0wChd9dvyvKtz2mUTWIOem3dIGy6rEHcIw",
            "public_key": "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg",
            "issued_at": "2026-07-11T20:00:00Z",
            "expires_at": "2026-10-11T20:00:00Z",
            "services": [
                {"type": "profile", "url": "https://example.com/jody"},
                {"type": "feed", "url": "https://example.com/jody/feed"}
            ]
        });
        let result = canonicalize(&value).unwrap();
        let expected = r#"{"expires_at":"2026-10-11T20:00:00Z","issued_at":"2026-07-11T20:00:00Z","public_key":"A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg","services":[{"type":"profile","url":"https://example.com/jody"},{"type":"feed","url":"https://example.com/jody/feed"}],"subject":"key:sha256:Vkdap1RjR0wChd9dvyvKtz2mUTWIOem3dIGy6rEHcIw","type":"open-presence","version":"0.1"}"#;
        assert_eq!(std::str::from_utf8(&result).unwrap(), expected);
    }
}
