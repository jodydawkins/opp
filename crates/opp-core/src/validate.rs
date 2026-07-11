//! Validation logic for OPP document fields.
//!
//! This module validates individual fields of an OPP document:
//! - Type and version checks
//! - Timestamp validation (RFC 3339 UTC with Z suffix)
//! - Service object validation (HTTPS URLs, no credentials)
//! - Public key encoding validation
//! - Full document field validation (shared between signing and verification)
//!
//! See SPEC.md Sections 4, 5, and 9.

use crate::error::VerificationError;
use crate::subject::derive_subject;
use url::Url;

/// Validate all document fields except the signature.
///
/// This validation is shared between signing (which validates before producing
/// a signature) and verification (which validates before checking the signature).
///
/// Checks:
/// - Required fields are present (type, version, subject, public_key, issued_at, services)
/// - Field types are correct
/// - Type is "open-presence"
/// - Version is "0.1"
/// - Public key is valid Base64url-encoded 32 bytes
/// - Subject matches the public key
/// - Timestamps are valid RFC 3339 UTC with Z suffix
/// - If expires_at is present, it is after issued_at
/// - Service objects have valid types and HTTPS URLs
pub fn validate_document_fields(
    obj: &serde_json::Map<String, serde_json::Value>,
) -> Result<(), VerificationError> {
    // Check required fields (signature is not required here — signing adds it)
    let required_fields = ["type", "version", "subject", "public_key", "issued_at", "services"];
    for field in &required_fields {
        if !obj.contains_key(*field) {
            return Err(VerificationError::MissingField {
                field: field.to_string(),
            });
        }
    }

    // Validate type
    let type_val = obj
        .get("type")
        .unwrap()
        .as_str()
        .ok_or(VerificationError::InvalidFieldType {
            field: "type".to_string(),
            expected: "string".to_string(),
        })?;

    if type_val != "open-presence" {
        return Err(VerificationError::InvalidType(type_val.to_string()));
    }

    // Validate version
    let version_val = obj
        .get("version")
        .unwrap()
        .as_str()
        .ok_or(VerificationError::InvalidFieldType {
            field: "version".to_string(),
            expected: "string".to_string(),
        })?;

    if version_val != "0.1" {
        return Err(VerificationError::UnsupportedVersion(
            version_val.to_string(),
        ));
    }

    // Validate public key
    let public_key_str = obj
        .get("public_key")
        .unwrap()
        .as_str()
        .ok_or(VerificationError::InvalidFieldType {
            field: "public_key".to_string(),
            expected: "string".to_string(),
        })?;

    let public_key_bytes = validate_public_key_encoding(public_key_str)?;

    // Validate subject matches public key
    let subject_str = obj
        .get("subject")
        .unwrap()
        .as_str()
        .ok_or(VerificationError::InvalidFieldType {
            field: "subject".to_string(),
            expected: "string".to_string(),
        })?;

    let expected_subject = derive_subject(&public_key_bytes);
    if subject_str != expected_subject {
        return Err(VerificationError::SubjectMismatch);
    }

    // Validate issued_at
    let issued_at_str = obj
        .get("issued_at")
        .unwrap()
        .as_str()
        .ok_or(VerificationError::InvalidFieldType {
            field: "issued_at".to_string(),
            expected: "string".to_string(),
        })?;

    validate_timestamp(issued_at_str, "issued_at")?;

    // Validate expires_at if present
    if let Some(expires_val) = obj.get("expires_at") {
        let expires_str = expires_val
            .as_str()
            .ok_or(VerificationError::InvalidFieldType {
                field: "expires_at".to_string(),
                expected: "string".to_string(),
            })?;
        validate_timestamp(expires_str, "expires_at")?;

        // Check ordering
        use time::format_description::well_known::Rfc3339;
        use time::OffsetDateTime;

        let issued = OffsetDateTime::parse(issued_at_str, &Rfc3339)
            .map_err(|e| VerificationError::InvalidIssuedAt(e.to_string()))?;
        let expires = OffsetDateTime::parse(expires_str, &Rfc3339)
            .map_err(|e| VerificationError::InvalidExpiresAt(e.to_string()))?;

        if expires <= issued {
            return Err(VerificationError::ExpirationBeforeIssueTime);
        }
    }

    // Validate services
    let services_val = obj.get("services").unwrap();
    let services_arr = services_val
        .as_array()
        .ok_or(VerificationError::InvalidServices)?;

    for service in services_arr {
        let service_obj = service
            .as_object()
            .ok_or(VerificationError::InvalidServices)?;

        service_obj
            .get("type")
            .ok_or(VerificationError::InvalidServiceType)?
            .as_str()
            .ok_or(VerificationError::InvalidServiceType)?;

        let svc_url = service_obj
            .get("url")
            .ok_or(VerificationError::InvalidServiceUrl(
                "missing url field".to_string(),
            ))?
            .as_str()
            .ok_or(VerificationError::InvalidServiceUrl(
                "url must be a string".to_string(),
            ))?;

        validate_service_url(svc_url)?;
    }

    Ok(())
}

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
