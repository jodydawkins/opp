//! Validation logic for OPP document fields.
//!
//! This module validates individual fields of an OPP document:
//! - Type and version checks
//! - Timestamp validation (RFC 3339 UTC with Z suffix)
//! - Service object validation (HTTPS URLs, no credentials)
//! - Public key encoding validation
//!
//! See SPEC.md Sections 4, 5, and 9.

use crate::error::VerificationError;
use url::Url;

/// Validate that a timestamp string is RFC 3339 UTC with the Z suffix.
pub fn validate_timestamp(value: &str, field_name: &str) -> Result<(), VerificationError> {
    // Must end with 'Z' for UTC
    if !value.ends_with('Z') {
        return Err(if field_name == "issued_at" {
            VerificationError::InvalidIssuedAt(format!("must be UTC with Z suffix, got: {}", value))
        } else {
            VerificationError::InvalidExpiresAt(format!(
                "must be UTC with Z suffix, got: {}",
                value
            ))
        });
    }

    // Must be a full date-time, not just a date
    if !value.contains('T') {
        return Err(if field_name == "issued_at" {
            VerificationError::InvalidIssuedAt(format!("must be a full date-time, got: {}", value))
        } else {
            VerificationError::InvalidExpiresAt(format!("must be a full date-time, got: {}", value))
        });
    }

    // Try to parse with the time crate
    use time::format_description::well_known::Rfc3339;
    use time::OffsetDateTime;

    OffsetDateTime::parse(value, &Rfc3339).map_err(|e| {
        if field_name == "issued_at" {
            VerificationError::InvalidIssuedAt(e.to_string())
        } else {
            VerificationError::InvalidExpiresAt(e.to_string())
        }
    })?;

    // Reject non-UTC offsets (anything that has +/- offset instead of Z)
    // We already checked for Z suffix, but also reject things like +00:00
    if value.contains('+') || value[..value.len() - 1].contains('-') {
        // Allow hyphens in the date part only
        let time_part = value.split('T').nth(1).unwrap_or("");
        if time_part.contains('+') || time_part[..time_part.len().saturating_sub(1)].contains('-') {
            return Err(if field_name == "issued_at" {
                VerificationError::InvalidIssuedAt(format!("must use Z suffix, got: {}", value))
            } else {
                VerificationError::InvalidExpiresAt(format!("must use Z suffix, got: {}", value))
            });
        }
    }

    Ok(())
}

/// Validate a service URL.
///
/// Requirements:
/// - Must be a valid URL
/// - Must use the HTTPS scheme
/// - Must not contain username or password (credentials)
/// - Must be an absolute URL
pub fn validate_service_url(url_str: &str) -> Result<(), VerificationError> {
    let parsed = Url::parse(url_str)
        .map_err(|e| VerificationError::InvalidServiceUrl(format!("{}: {}", url_str, e)))?;

    // Must be HTTPS
    if parsed.scheme() != "https" {
        if parsed.scheme() == "http" {
            return Err(VerificationError::NonHttpsServiceUrl);
        }
        return Err(VerificationError::NonHttpsServiceUrl);
    }

    // Must not contain credentials
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(VerificationError::ServiceUrlContainsCredentials);
    }

    Ok(())
}

/// Validate unpadded Base64url encoding of a public key.
///
/// Requirements:
/// - Must be valid Base64url (no '+', '/', or '=')
/// - Must decode to exactly 32 bytes
pub fn validate_public_key_encoding(value: &str) -> Result<[u8; 32], VerificationError> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    // Reject standard Base64 characters
    if value.contains('+') || value.contains('/') {
        return Err(VerificationError::InvalidPublicKeyEncoding);
    }

    // Reject padding
    if value.contains('=') {
        return Err(VerificationError::InvalidPublicKeyEncoding);
    }

    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| VerificationError::InvalidPublicKeyEncoding)?;

    if bytes.len() != 32 {
        return Err(VerificationError::InvalidPublicKeyLength(bytes.len()));
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_timestamp() {
        assert!(validate_timestamp("2026-07-11T20:00:00Z", "issued_at").is_ok());
    }

    #[test]
    fn test_reject_non_utc_offset() {
        let err = validate_timestamp("2026-07-11T13:00:00-07:00", "issued_at").unwrap_err();
        assert!(matches!(err, VerificationError::InvalidIssuedAt(_)));
    }

    #[test]
    fn test_reject_no_z_suffix() {
        let err = validate_timestamp("2026-07-11T20:00:00", "issued_at").unwrap_err();
        assert!(matches!(err, VerificationError::InvalidIssuedAt(_)));
    }

    #[test]
    fn test_reject_date_only() {
        let err = validate_timestamp("2026-07-11Z", "issued_at").unwrap_err();
        assert!(matches!(err, VerificationError::InvalidIssuedAt(_)));
    }

    #[test]
    fn test_valid_https_url() {
        assert!(validate_service_url("https://example.com").is_ok());
        assert!(validate_service_url("https://example.com/path?q=1#frag").is_ok());
        assert!(validate_service_url("https://example.com:8080/path").is_ok());
    }

    #[test]
    fn test_reject_http_url() {
        let err = validate_service_url("http://example.com").unwrap_err();
        assert!(matches!(err, VerificationError::NonHttpsServiceUrl));
    }

    #[test]
    fn test_reject_credentials() {
        let url = format!("https://user:pass{}example.com/profile", "word@");
        let err = validate_service_url(&url).unwrap_err();
        assert!(matches!(
            err,
            VerificationError::ServiceUrlContainsCredentials
        ));
    }

    #[test]
    fn test_reject_username_only() {
        let err = validate_service_url("https://user@example.com/profile").unwrap_err();
        assert!(matches!(
            err,
            VerificationError::ServiceUrlContainsCredentials
        ));
    }

    #[test]
    fn test_reject_ftp_url() {
        let err = validate_service_url("ftp://example.com").unwrap_err();
        assert!(matches!(err, VerificationError::NonHttpsServiceUrl));
    }

    #[test]
    fn test_reject_relative_url() {
        let err = validate_service_url("/profile").unwrap_err();
        assert!(matches!(err, VerificationError::InvalidServiceUrl(_)));
    }

    #[test]
    fn test_valid_public_key() {
        let result = validate_public_key_encoding("A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg");
        assert!(result.is_ok());
    }

    #[test]
    fn test_reject_standard_base64() {
        let err = validate_public_key_encoding("A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg")
            .unwrap_err();
        assert!(matches!(err, VerificationError::InvalidPublicKeyEncoding));
    }

    #[test]
    fn test_reject_padded_base64url() {
        let err = validate_public_key_encoding("A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=")
            .unwrap_err();
        assert!(matches!(err, VerificationError::InvalidPublicKeyEncoding));
    }
}
