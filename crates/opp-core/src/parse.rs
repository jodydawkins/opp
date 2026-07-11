//! JSON parsing with duplicate member detection.
//!
//! Standard JSON parsers silently discard duplicate object keys.
//! OPP requires that duplicate members are rejected before deserialization
//! can lose information. See SPEC.md Section 9.

use crate::error::ParseError;
use serde_json::Value;

/// An unverified OPP document parsed from raw JSON bytes.
///
/// This type represents untrusted input that has been successfully parsed
/// as valid JSON without duplicate members. It has NOT been validated or
/// verified cryptographically.
#[derive(Debug, Clone)]
pub struct UnverifiedDocument {
    pub(crate) value: Value,
}

impl UnverifiedDocument {
    /// Returns a reference to the underlying JSON value.
    pub fn value(&self) -> &Value {
        &self.value
    }
}

/// Parse raw bytes into an unverified OPP document.
///
/// This function:
/// 1. Validates that the input is valid UTF-8 and valid JSON.
/// 2. Checks for duplicate member names at every object level.
/// 3. Ensures the top-level value is a JSON object.
///
/// No field validation or cryptographic verification is performed.
pub fn parse(input: &[u8]) -> Result<UnverifiedDocument, ParseError> {
    let input_str =
        std::str::from_utf8(input).map_err(|e| ParseError::InvalidJson(e.to_string()))?;

    // Check for duplicate members before standard parsing
    check_duplicates(input_str)?;

    let value: Value =
        serde_json::from_str(input_str).map_err(|e| ParseError::InvalidJson(e.to_string()))?;

    if !value.is_object() {
        return Err(ParseError::NotAnObject);
    }

    Ok(UnverifiedDocument { value })
}

/// Check for duplicate keys in a JSON string by manually tracking seen keys.
///
/// We use serde_json's streaming deserializer to walk through the token stream
/// and detect duplicate keys at each nesting level.
fn check_duplicates(input: &str) -> Result<(), ParseError> {
    // We'll do a simple recursive descent check by parsing into a custom structure
    // that rejects duplicates.
    let mut chars = input.as_bytes();
    check_value(&mut chars, "")?;
    Ok(())
}

/// Custom duplicate-detecting JSON parser.
/// This is a minimal recursive-descent parser that only checks for duplicate keys.
fn check_value(input: &mut &[u8], path: &str) -> Result<(), ParseError> {
    skip_whitespace(input);
    match input.first() {
        Some(b'{') => check_object(input, path),
        Some(b'[') => check_array(input, path),
        Some(b'"') => {
            skip_string(input)?;
            Ok(())
        }
        Some(b't') => skip_literal(input, b"true"),
        Some(b'f') => skip_literal(input, b"false"),
        Some(b'n') => skip_literal(input, b"null"),
        Some(c) if *c == b'-' || c.is_ascii_digit() => {
            skip_number(input);
            Ok(())
        }
        _ => Err(ParseError::InvalidJson("unexpected character".to_string())),
    }
}

fn check_object(input: &mut &[u8], path: &str) -> Result<(), ParseError> {
    use std::collections::HashSet;

    *input = &input[1..]; // skip '{'
    skip_whitespace(input);

    if input.first() == Some(&b'}') {
        *input = &input[1..];
        return Ok(());
    }

    let mut seen = HashSet::new();

    loop {
        skip_whitespace(input);
        let key = parse_string_value(input)?;

        if !seen.insert(key.clone()) {
            return Err(ParseError::DuplicateMember {
                path: if path.is_empty() {
                    "$".to_string()
                } else {
                    path.to_string()
                },
                member: key,
            });
        }

        skip_whitespace(input);
        if input.first() != Some(&b':') {
            return Err(ParseError::InvalidJson("expected ':'".to_string()));
        }
        *input = &input[1..];

        let child_path = if path.is_empty() {
            format!("$.{}", key)
        } else {
            format!("{}.{}", path, key)
        };
        check_value(input, &child_path)?;

        skip_whitespace(input);
        match input.first() {
            Some(b',') => {
                *input = &input[1..];
            }
            Some(b'}') => {
                *input = &input[1..];
                return Ok(());
            }
            _ => return Err(ParseError::InvalidJson("expected ',' or '}'".to_string())),
        }
    }
}

fn check_array(input: &mut &[u8], path: &str) -> Result<(), ParseError> {
    *input = &input[1..]; // skip '['
    skip_whitespace(input);

    if input.first() == Some(&b']') {
        *input = &input[1..];
        return Ok(());
    }

    let mut idx = 0;
    loop {
        let child_path = format!("{}[{}]", path, idx);
        check_value(input, &child_path)?;
        idx += 1;

        skip_whitespace(input);
        match input.first() {
            Some(b',') => {
                *input = &input[1..];
            }
            Some(b']') => {
                *input = &input[1..];
                return Ok(());
            }
            _ => return Err(ParseError::InvalidJson("expected ',' or ']'".to_string())),
        }
    }
}

fn parse_string_value(input: &mut &[u8]) -> Result<String, ParseError> {
    skip_whitespace(input);
    if input.first() != Some(&b'"') {
        return Err(ParseError::InvalidJson("expected string".to_string()));
    }
    *input = &input[1..]; // skip opening quote

    let mut result = String::new();
    loop {
        match input.first() {
            None => return Err(ParseError::InvalidJson("unterminated string".to_string())),
            Some(b'"') => {
                *input = &input[1..];
                return Ok(result);
            }
            Some(b'\\') => {
                *input = &input[1..];
                match input.first() {
                    Some(b'"') => result.push('"'),
                    Some(b'\\') => result.push('\\'),
                    Some(b'/') => result.push('/'),
                    Some(b'b') => result.push('\u{0008}'),
                    Some(b'f') => result.push('\u{000C}'),
                    Some(b'n') => result.push('\n'),
                    Some(b'r') => result.push('\r'),
                    Some(b't') => result.push('\t'),
                    Some(b'u') => {
                        *input = &input[1..];
                        let hex = std::str::from_utf8(&input[..4])
                            .map_err(|_| ParseError::InvalidJson("invalid escape".to_string()))?;
                        let code = u16::from_str_radix(hex, 16)
                            .map_err(|_| ParseError::InvalidJson("invalid escape".to_string()))?;
                        *input = &input[4..];
                        // Handle surrogate pairs
                        if (0xD800..=0xDBFF).contains(&code) {
                            if input.starts_with(b"\\u") {
                                *input = &input[2..];
                                let hex2 = std::str::from_utf8(&input[..4]).map_err(|_| {
                                    ParseError::InvalidJson("invalid escape".to_string())
                                })?;
                                let code2 = u16::from_str_radix(hex2, 16).map_err(|_| {
                                    ParseError::InvalidJson("invalid escape".to_string())
                                })?;
                                *input = &input[4..];
                                let codepoint = 0x10000
                                    + ((code as u32 - 0xD800) << 10)
                                    + (code2 as u32 - 0xDC00);
                                result.push(char::from_u32(codepoint).ok_or_else(|| {
                                    ParseError::InvalidJson("invalid codepoint".to_string())
                                })?);
                            }
                        } else {
                            result.push(char::from_u32(code as u32).ok_or_else(|| {
                                ParseError::InvalidJson("invalid codepoint".to_string())
                            })?);
                        }
                        continue; // already advanced past the escape
                    }
                    _ => {
                        return Err(ParseError::InvalidJson("invalid escape".to_string()));
                    }
                }
                *input = &input[1..];
            }
            Some(_) => {
                // Read UTF-8 character
                let s = std::str::from_utf8(input)
                    .map_err(|e| ParseError::InvalidJson(e.to_string()))?;
                let ch = s.chars().next().unwrap();
                result.push(ch);
                *input = &input[ch.len_utf8()..];
            }
        }
    }
}

fn skip_string(input: &mut &[u8]) -> Result<(), ParseError> {
    parse_string_value(input)?;
    Ok(())
}

fn skip_whitespace(input: &mut &[u8]) {
    while let Some(c) = input.first() {
        if *c == b' ' || *c == b'\t' || *c == b'\n' || *c == b'\r' {
            *input = &input[1..];
        } else {
            break;
        }
    }
}

fn skip_literal(input: &mut &[u8], expected: &[u8]) -> Result<(), ParseError> {
    if input.starts_with(expected) {
        *input = &input[expected.len()..];
        Ok(())
    } else {
        Err(ParseError::InvalidJson("invalid literal".to_string()))
    }
}

fn skip_number(input: &mut &[u8]) {
    while let Some(c) = input.first() {
        if c.is_ascii_digit() || *c == b'.' || *c == b'-' || *c == b'+' || *c == b'e' || *c == b'E'
        {
            *input = &input[1..];
        } else {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_object() {
        let input = br#"{"type": "open-presence", "version": "0.1"}"#;
        let doc = parse(input).unwrap();
        assert!(doc.value().is_object());
    }

    #[test]
    fn test_reject_duplicate_top_level() {
        let input = br#"{"type": "open-presence", "type": "something-else"}"#;
        let err = parse(input).unwrap_err();
        assert!(matches!(err, ParseError::DuplicateMember { .. }));
    }

    #[test]
    fn test_reject_duplicate_nested() {
        let input = br#"{"services": [{"type": "profile", "url": "https://a.com", "url": "https://b.com"}]}"#;
        let err = parse(input).unwrap_err();
        assert!(matches!(err, ParseError::DuplicateMember { .. }));
    }

    #[test]
    fn test_reject_non_object() {
        let input = br#"[1, 2, 3]"#;
        let err = parse(input).unwrap_err();
        assert!(matches!(err, ParseError::NotAnObject));
    }

    #[test]
    fn test_reject_malformed_json() {
        let input = br#"{invalid"#;
        let err = parse(input).unwrap_err();
        assert!(matches!(err, ParseError::InvalidJson(_)));
    }
}
