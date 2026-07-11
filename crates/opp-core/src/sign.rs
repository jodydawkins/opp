//! Document signing.
//!
//! Signs an OPP document using Ed25519 after validating the document
//! and producing the RFC 8785 canonical form.
//!
//! See SPEC.md Section 7.

use crate::canonicalize::canonicalize;
use crate::error::{SigningError, VerificationError};
use crate::validate;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::Value;

/// An unsigned OPP document ready for signing.
///
/// This type ensures the document has been validated before signing.
#[derive(Debug, Clone)]
pub struct UnsignedDocument {
    pub(crate) value: Value,
}

impl UnsignedDocument {
    /// Create an unsigned document from a JSON value.
    ///
    /// The value must be a JSON object without a `signature` member.
    pub fn new(value: Value) -> Result<Self, SigningError> {
        if !value.is_object() {
            return Err(SigningError::ValidationFailed(
                VerificationError::NotAnObject,
            ));
        }
        if value.get("signature").is_some() {
            return Err(SigningError::AlreadySigned);
        }
        Ok(UnsignedDocument { value })
    }

    /// Returns a reference to the underlying JSON value.
    pub fn value(&self) -> &Value {
        &self.value
    }
}

/// Sign an OPP document using Ed25519.
///
/// This function:
/// 1. Validates that the document does not already have a signature.
/// 2. Performs full document validation (type, version, fields, timestamps,
///    services, public key, subject) — the same rules as verification minus
///    signature checks and expiration checks.
/// 3. Verifies the public key in the document matches the supplied private key.
/// 4. Canonicalizes the document per RFC 8785.
/// 5. Signs the canonical bytes with Ed25519.
/// 6. Returns the complete signed document with the signature member.
///
/// # Errors
///
/// Returns `SigningError` if:
/// - The document already contains a signature
/// - Any document field is invalid
/// - The public key in the document doesn't match the private key
/// - Canonicalization fails
pub fn sign(document: UnsignedDocument, private_key: &[u8; 32]) -> Result<Value, SigningError> {
    let obj = document
        .value
        .as_object()
        .ok_or(SigningError::ValidationFailed(
            VerificationError::NotAnObject,
        ))?;

    // Full document validation (same rules as verification, minus signature/expiration checks)
    validate::validate_document_fields(obj).map_err(SigningError::ValidationFailed)?;

    // Verify the public key in the document matches the private key
    let signing_key = SigningKey::from_bytes(private_key);
    let verifying_key = signing_key.verifying_key();
    let expected_public_key = verifying_key.to_bytes();

    let pk_str = obj.get("public_key").unwrap().as_str().unwrap();
    let doc_pk =
        validate::validate_public_key_encoding(pk_str).map_err(SigningError::ValidationFailed)?;

    if doc_pk != expected_public_key {
        return Err(SigningError::PublicKeyMismatch);
    }

    // Canonicalize the document (without signature)
    let canonical = canonicalize(&document.value).map_err(SigningError::CanonicalizationFailed)?;

    // Sign
    let signature = signing_key.sign(&canonical);
    let sig_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());

    // Build the signed document
    let mut signed = document.value;
    let sig_obj = serde_json::json!({
        "algorithm": "ed25519",
        "value": sig_b64
    });
    signed
        .as_object_mut()
        .unwrap()
        .insert("signature".to_string(), sig_obj);

    Ok(signed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn test_private_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        for (i, byte) in key.iter_mut().enumerate() {
            *byte = i as u8;
        }
        key
    }

    #[test]
    fn test_sign_deterministic_vector() {
        let doc = json!({
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

        let unsigned = UnsignedDocument::new(doc).unwrap();
        let signed = sign(unsigned, &test_private_key()).unwrap();

        let sig = signed["signature"]["value"].as_str().unwrap();
        assert_eq!(
            sig,
            "-ojCCq5ngoVSQsUB68EGtvuTAQBLajwoHP4irGZUlvfkuyFOy_1uTOp-0lmAWX6wnUs_upzl6mwfMoizUNZbAw"
        );
    }

    #[test]
    fn test_reject_already_signed() {
        let doc = json!({
            "type": "open-presence",
            "signature": {"algorithm": "ed25519", "value": "xxx"}
        });
        let err = UnsignedDocument::new(doc).unwrap_err();
        assert!(matches!(err, SigningError::AlreadySigned));
    }

    #[test]
    fn test_reject_public_key_mismatch() {
        // Use a valid-looking document but with a different key pair
        let other_key = [0xFFu8; 32];
        let other_signing = ed25519_dalek::SigningKey::from_bytes(&other_key);
        let other_public = other_signing.verifying_key().to_bytes();
        let other_pk_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(other_public);
        let other_subject = crate::subject::derive_subject(&other_public);

        let doc = json!({
            "type": "open-presence",
            "version": "0.1",
            "subject": other_subject,
            "public_key": other_pk_b64,
            "issued_at": "2026-07-11T20:00:00Z",
            "services": []
        });

        let unsigned = UnsignedDocument::new(doc).unwrap();
        let err = sign(unsigned, &test_private_key()).unwrap_err();
        assert!(matches!(err, SigningError::PublicKeyMismatch));
    }

    #[test]
    fn test_sign_rejects_missing_required_fields() {
        // Missing "type", "version", "subject", etc.
        let doc = json!({
            "public_key": "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg"
        });
        let unsigned = UnsignedDocument::new(doc).unwrap();
        let err = sign(unsigned, &test_private_key()).unwrap_err();
        assert!(matches!(err, SigningError::ValidationFailed(_)));
    }

    #[test]
    fn test_sign_rejects_invalid_version() {
        let doc = json!({
            "type": "open-presence",
            "version": "9.9",
            "subject": "key:sha256:Vkdap1RjR0wChd9dvyvKtz2mUTWIOem3dIGy6rEHcIw",
            "public_key": "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg",
            "issued_at": "2026-07-11T20:00:00Z",
            "services": []
        });
        let unsigned = UnsignedDocument::new(doc).unwrap();
        let err = sign(unsigned, &test_private_key()).unwrap_err();
        assert!(matches!(err, SigningError::ValidationFailed(_)));
    }

    #[test]
    fn test_sign_rejects_invalid_timestamp() {
        let doc = json!({
            "type": "open-presence",
            "version": "0.1",
            "subject": "key:sha256:Vkdap1RjR0wChd9dvyvKtz2mUTWIOem3dIGy6rEHcIw",
            "public_key": "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg",
            "issued_at": "not-a-timestamp",
            "services": []
        });
        let unsigned = UnsignedDocument::new(doc).unwrap();
        let err = sign(unsigned, &test_private_key()).unwrap_err();
        assert!(matches!(err, SigningError::ValidationFailed(_)));
    }

    #[test]
    fn test_sign_rejects_http_service_url() {
        let doc = json!({
            "type": "open-presence",
            "version": "0.1",
            "subject": "key:sha256:Vkdap1RjR0wChd9dvyvKtz2mUTWIOem3dIGy6rEHcIw",
            "public_key": "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg",
            "issued_at": "2026-07-11T20:00:00Z",
            "services": [{"type": "profile", "url": "http://example.com"}]
        });
        let unsigned = UnsignedDocument::new(doc).unwrap();
        let err = sign(unsigned, &test_private_key()).unwrap_err();
        assert!(matches!(err, SigningError::ValidationFailed(_)));
    }
}
