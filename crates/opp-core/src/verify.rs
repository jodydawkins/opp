//! Document verification.
//!
//! Verifies an OPP presence document by checking:
//! - JSON structure and duplicate members
//! - Required fields and their types
//! - Type and version values
//! - Public key encoding and length
//! - Subject derivation match
//! - Timestamp validity
//! - Expiration
//! - Service URL validity
//! - Signature algorithm and value
//! - Cryptographic signature verification
//!
//! See SPEC.md Section 9.

use crate::canonicalize::canonicalize;
use crate::error::VerificationError;
use crate::parse::parse;
use crate::validate::{validate_document_fields, validate_public_key_encoding};
use crate::{PresenceDocument, ServiceObject};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// Context for document verification, including the verification time.
///
/// The verification time is used to check document expiration without
/// depending on the system clock.
#[derive(Debug, Clone)]
pub struct VerificationContext {
    pub verification_time: OffsetDateTime,
}

/// A verified OPP presence document.
///
/// This type can only be constructed through successful verification,
/// ensuring that a `VerifiedDocument` always represents a fully validated
/// and cryptographically verified document.
#[derive(Debug, Clone)]
pub struct VerifiedDocument {
    document: PresenceDocument,
}

impl VerifiedDocument {
    /// Returns a reference to the verified presence document.
    pub fn document(&self) -> &PresenceDocument {
        &self.document
    }
}

/// Verify a signed OPP presence document.
///
/// This function performs complete verification as defined in SPEC.md Section 9:
/// 1. Parses JSON and checks for duplicate members
/// 2. Validates required fields and their types
/// 3. Checks type and version
/// 4. Validates public key encoding
/// 5. Verifies subject matches public key
/// 6. Validates timestamps
/// 7. Checks expiration
/// 8. Validates service URLs
/// 9. Verifies the cryptographic signature
///
/// # Errors
///
/// Returns a specific `VerificationError` variant identifying exactly why
/// verification failed.
pub fn verify(
    input: &[u8],
    context: &VerificationContext,
) -> Result<VerifiedDocument, VerificationError> {
    // Step 1: Parse and check for duplicates
    let parsed = parse(input).map_err(|e| match e {
        crate::error::ParseError::InvalidJson(msg) => VerificationError::InvalidJson(msg),
        crate::error::ParseError::DuplicateMember { path, member } => {
            VerificationError::DuplicateMember { path, member }
        }
        crate::error::ParseError::NotAnObject => VerificationError::NotAnObject,
    })?;

    let obj = parsed.value.as_object().unwrap();

    // Step 2: Check that the signature field is present (required for verification)
    if !obj.contains_key("signature") {
        return Err(VerificationError::MissingField {
            field: "signature".to_string(),
        });
    }

    // Step 3: Validate all document fields (type, version, public key, subject,
    // timestamps, services) using the shared validation logic
    validate_document_fields(obj)?;

    // Step 4: Check expiration against verification time
    let issued_at_str = obj.get("issued_at").unwrap().as_str().unwrap();
    let expires_at_str = obj
        .get("expires_at")
        .map(|v| v.as_str().unwrap().to_string());

    if let Some(ref expires_at) = expires_at_str {
        let expires = OffsetDateTime::parse(expires_at, &Rfc3339)
            .map_err(|e| VerificationError::InvalidExpiresAt(e.to_string()))?;

        if context.verification_time >= expires {
            return Err(VerificationError::DocumentExpired);
        }
    }

    // Step 5: Validate and verify signature
    let sig_val = obj.get("signature").unwrap();
    let sig_obj = sig_val
        .as_object()
        .ok_or(VerificationError::InvalidFieldType {
            field: "signature".to_string(),
            expected: "object".to_string(),
        })?;

    let algorithm = sig_obj
        .get("algorithm")
        .ok_or(VerificationError::MissingField {
            field: "signature.algorithm".to_string(),
        })?
        .as_str()
        .ok_or(VerificationError::InvalidFieldType {
            field: "signature.algorithm".to_string(),
            expected: "string".to_string(),
        })?;

    if algorithm != "ed25519" {
        return Err(VerificationError::UnsupportedSignatureAlgorithm(
            algorithm.to_string(),
        ));
    }

    let sig_value_str = sig_obj
        .get("value")
        .ok_or(VerificationError::MissingField {
            field: "signature.value".to_string(),
        })?
        .as_str()
        .ok_or(VerificationError::InvalidFieldType {
            field: "signature.value".to_string(),
            expected: "string".to_string(),
        })?;

    // Reject padding in signature
    if sig_value_str.contains('=') {
        return Err(VerificationError::InvalidSignatureEncoding);
    }
    if sig_value_str.contains('+') || sig_value_str.contains('/') {
        return Err(VerificationError::InvalidSignatureEncoding);
    }

    let sig_bytes = URL_SAFE_NO_PAD
        .decode(sig_value_str)
        .map_err(|_| VerificationError::InvalidSignatureEncoding)?;

    if sig_bytes.len() != 64 {
        return Err(VerificationError::InvalidSignatureLength(sig_bytes.len()));
    }

    // Canonicalize the document without the signature
    let mut canon_value = parsed.value.clone();
    canon_value.as_object_mut().unwrap().remove("signature");
    let canonical_bytes =
        canonicalize(&canon_value).map_err(VerificationError::CanonicalizationFailed)?;

    // Verify the signature
    let public_key_str = obj.get("public_key").unwrap().as_str().unwrap();
    let public_key_bytes = validate_public_key_encoding(public_key_str)?;
    let verifying_key = VerifyingKey::from_bytes(&public_key_bytes)
        .map_err(|_| VerificationError::InvalidPublicKeyEncoding)?;

    let sig_array: [u8; 64] = sig_bytes.try_into().unwrap();
    let signature = Signature::from_bytes(&sig_array);

    verifying_key
        .verify(&canonical_bytes, &signature)
        .map_err(|_| VerificationError::SignatureVerificationFailed)?;

    // Build the verified document from already-validated fields
    let subject_str = obj.get("subject").unwrap().as_str().unwrap();
    let services_arr = obj.get("services").unwrap().as_array().unwrap();
    let mut services = Vec::new();
    for service in services_arr {
        let service_obj = service.as_object().unwrap();
        services.push(ServiceObject {
            service_type: service_obj
                .get("type")
                .unwrap()
                .as_str()
                .unwrap()
                .to_string(),
            url: service_obj
                .get("url")
                .unwrap()
                .as_str()
                .unwrap()
                .to_string(),
        });
    }

    Ok(VerifiedDocument {
        document: PresenceDocument {
            subject: subject_str.to_string(),
            public_key: public_key_str.to_string(),
            issued_at: issued_at_str.to_string(),
            expires_at: expires_at_str,
            services,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verification_context() -> VerificationContext {
        VerificationContext {
            verification_time: OffsetDateTime::parse("2026-07-12T00:00:00Z", &Rfc3339).unwrap(),
        }
    }

    fn valid_signed_document() -> &'static str {
        r#"{
  "type": "open-presence",
  "version": "0.1",
  "subject": "key:sha256:Vkdap1RjR0wChd9dvyvKtz2mUTWIOem3dIGy6rEHcIw",
  "public_key": "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg",
  "issued_at": "2026-07-11T20:00:00Z",
  "expires_at": "2026-10-11T20:00:00Z",
  "services": [
    {
      "type": "profile",
      "url": "https://example.com/jody"
    },
    {
      "type": "feed",
      "url": "https://example.com/jody/feed"
    }
  ],
  "signature": {
    "algorithm": "ed25519",
    "value": "-ojCCq5ngoVSQsUB68EGtvuTAQBLajwoHP4irGZUlvfkuyFOy_1uTOp-0lmAWX6wnUs_upzl6mwfMoizUNZbAw"
  }
}"#
    }

    #[test]
    fn test_verify_valid_document() {
        let ctx = verification_context();
        let result = verify(valid_signed_document().as_bytes(), &ctx);
        assert!(result.is_ok());
    }

    #[test]
    fn test_reject_expired_document() {
        let ctx = VerificationContext {
            verification_time: OffsetDateTime::parse("2027-01-01T00:00:00Z", &Rfc3339).unwrap(),
        };
        let result = verify(valid_signed_document().as_bytes(), &ctx);
        assert!(matches!(
            result.unwrap_err(),
            VerificationError::DocumentExpired
        ));
    }

    #[test]
    fn test_reject_missing_type() {
        let doc = r#"{
  "version": "0.1",
  "subject": "key:sha256:test",
  "public_key": "test",
  "issued_at": "2026-07-11T20:00:00Z",
  "services": [],
  "signature": {"algorithm": "ed25519", "value": "test"}
}"#;
        let ctx = verification_context();
        let result = verify(doc.as_bytes(), &ctx);
        assert!(matches!(
            result.unwrap_err(),
            VerificationError::MissingField { .. }
        ));
    }

    #[test]
    fn test_accept_unknown_fields() {
        // Add an unknown field to the valid document
        let doc = r#"{
  "type": "open-presence",
  "version": "0.1",
  "subject": "key:sha256:Vkdap1RjR0wChd9dvyvKtz2mUTWIOem3dIGy6rEHcIw",
  "public_key": "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg",
  "issued_at": "2026-07-11T20:00:00Z",
  "expires_at": "2026-10-11T20:00:00Z",
  "unknown_field": "should be ignored",
  "services": [
    {
      "type": "profile",
      "url": "https://example.com/jody",
      "unknown_service_field": true
    },
    {
      "type": "feed",
      "url": "https://example.com/jody/feed"
    }
  ],
  "signature": {
    "algorithm": "ed25519",
    "value": "-ojCCq5ngoVSQsUB68EGtvuTAQBLajwoHP4irGZUlvfkuyFOy_1uTOp-0lmAWX6wnUs_upzl6mwfMoizUNZbAw"
  }
}"#;
        let ctx = verification_context();
        // This will fail signature verification because the canonical form includes the unknown fields
        // That's expected - unknown fields are tolerated in parsing but affect the canonical form
        let result = verify(doc.as_bytes(), &ctx);
        // The unknown fields change the canonical bytes, so signature won't match
        assert!(matches!(
            result.unwrap_err(),
            VerificationError::SignatureVerificationFailed
        ));
    }
}
