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
/// Non-integer (floating-point) numbers are rejected because the current
/// implementation does not provide fully compliant ECMAScript Number.toString()
/// serialization. Since OPP's defined fields do not use numeric values,
/// this only affects unknown extension fields. A future version will add
/// a proven ECMAScript-compatible number formatter.
fn write_number(w: &mut Vec<u8>, n: &serde_json::Number) -> Result<(), std::io::Error> {
    if let Some(i) = n.as_i64() {
        write!(w, "{}", i)?;
    } else if let Some(u) = n.as_u64() {
        write!(w, "{}", u)?;
    } else {
        // Reject non-integer numbers until a fully compliant ECMAScript
        // Number.toString() implementation is available.
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "non-integer numeric values are not yet supported for canonicalization \
             (RFC 8785 requires ECMAScript Number.toString() serialization)",
        ));
    }
    Ok(())
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

    #[test]
    fn test_canonicalize_integers_accepted() {
        let value = json!({"count": 42, "negative": -1, "zero": 0});
        let result = canonicalize(&value).unwrap();
        assert_eq!(
            std::str::from_utf8(&result).unwrap(),
            r#"{"count":42,"negative":-1,"zero":0}"#
        );
    }

    #[test]
    fn test_canonicalize_rejects_float() {
        let value: Value = serde_json::from_str(r#"{"pi": 3.14}"#).unwrap();
        let result = canonicalize(&value);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("non-integer numeric values"));
    }

    #[test]
    fn test_canonicalize_null_bool_primitives() {
        let value = json!({"a": null, "b": true, "c": false});
        let result = canonicalize(&value).unwrap();
        assert_eq!(
            std::str::from_utf8(&result).unwrap(),
            r#"{"a":null,"b":true,"c":false}"#
        );
    }
}
