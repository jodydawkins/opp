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

/// Serialize a JSON number with ECMAScript `Number.toString()` semantics.
fn write_number(w: &mut Vec<u8>, n: &serde_json::Number) -> Result<(), std::io::Error> {
    let value = n.as_f64().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "numeric value cannot be represented as an IEEE-754 double",
        )
    })?;

    if !value.is_finite() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "non-finite numeric values are not permitted by RFC 8785",
        ));
    }

    let mut buffer = ryu_js::Buffer::new();
    w.write_all(buffer.format(value).as_bytes())
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

    #[derive(serde::Deserialize)]
    struct NumberVectors {
        cases: Vec<NumberVector>,
    }

    #[derive(serde::Deserialize)]
    struct NumberVector {
        ieee754: String,
        expected: Option<String>,
        #[serde(default)]
        comment: String,
    }

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
    fn test_rfc8785_appendix_b_number_serialization() {
        let vectors: NumberVectors = serde_json::from_str(include_str!(
            "../../../vectors/rfc8785-number-serialization.json"
        ))
        .unwrap();

        for case in vectors.cases {
            let bits = u64::from_str_radix(&case.ieee754, 16).unwrap();
            let number = serde_json::Number::from_f64(f64::from_bits(bits));

            match case.expected {
                Some(expected) => {
                    let value = Value::Number(number.unwrap());
                    let actual = String::from_utf8(canonicalize(&value).unwrap()).unwrap();
                    assert_eq!(actual, expected, "{} ({})", case.ieee754, case.comment);
                }
                None => assert!(
                    number.is_none(),
                    "{} ({}) must not be representable as JSON",
                    case.ieee754,
                    case.comment
                ),
            }
        }
    }

    #[test]
    fn test_canonicalize_all_numeric_forms() {
        let value: Value = serde_json::from_str(
            r#"[-0,1,-1,1.5,-1.5,0.1,0.01,0.001,1e30,1e-30,9007199254740991,-9007199254740991]"#,
        )
        .unwrap();

        let result = String::from_utf8(canonicalize(&value).unwrap()).unwrap();

        assert_eq!(
            result,
            "[0,1,-1,1.5,-1.5,0.1,0.01,0.001,1e+30,1e-30,9007199254740991,-9007199254740991]"
        );
    }

    #[test]
    fn test_canonicalize_large_integer_tokens_with_ieee754_semantics() {
        for (input, expected) in [
            ("9007199254740992", "9007199254740992"),
            ("9007199254740993", "9007199254740992"),
            ("-9007199254740992", "-9007199254740992"),
            ("295147905179352830000", "295147905179352830000"),
            ("9.999999999999997e+22", "9.999999999999997e+22"),
            ("1e+23", "1e+23"),
            ("1.0000000000000001e+23", "1.0000000000000001e+23"),
            ("999999999999999700000", "999999999999999700000"),
            ("999999999999999900000", "999999999999999900000"),
            ("1e+21", "1e+21"),
        ] {
            let value: Value = serde_json::from_str(input).unwrap();
            let actual = String::from_utf8(canonicalize(&value).unwrap()).unwrap();
            assert_eq!(actual, expected, "input: {input}");
        }
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
