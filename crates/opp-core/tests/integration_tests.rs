//! Comprehensive integration tests for opp-core.
//!
//! These tests cover all required test cases from the OPP 0.1 specification.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use opp_core::{
    derive_subject, parse, sign, verify, ParseError, SigningError, UnsignedDocument,
    VerificationContext, VerificationError,
};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

// --- Test helpers ---

fn test_private_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    for (i, byte) in key.iter_mut().enumerate() {
        *byte = i as u8;
    }
    key
}

fn test_public_key() -> [u8; 32] {
    use ed25519_dalek::SigningKey;
    let signing_key = SigningKey::from_bytes(&test_private_key());
    signing_key.verifying_key().to_bytes()
}

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

// --- Parsing and document structure tests ---

#[test]
fn test_accept_valid_signed_document() {
    let ctx = verification_context();
    let result = verify(valid_signed_document().as_bytes(), &ctx);
    assert!(result.is_ok());
}

#[test]
fn test_reject_malformed_json() {
    let ctx = verification_context();
    let result = verify(b"{invalid json", &ctx);
    assert!(matches!(
        result.unwrap_err(),
        VerificationError::InvalidJson(_)
    ));
}

#[test]
fn test_reject_non_object_top_level() {
    let ctx = verification_context();
    let result = verify(b"[1, 2, 3]", &ctx);
    assert!(matches!(
        result.unwrap_err(),
        VerificationError::NotAnObject
    ));
}

#[test]
fn test_reject_missing_type() {
    let ctx = verification_context();
    let doc = r#"{"version":"0.1","subject":"x","public_key":"x","issued_at":"2026-07-11T20:00:00Z","services":[],"signature":{"algorithm":"ed25519","value":"x"}}"#;
    let result = verify(doc.as_bytes(), &ctx);
    assert!(
        matches!(result.unwrap_err(), VerificationError::MissingField { ref field } if field == "type")
    );
}

#[test]
fn test_reject_missing_version() {
    let ctx = verification_context();
    let doc = r#"{"type":"open-presence","subject":"x","public_key":"x","issued_at":"2026-07-11T20:00:00Z","services":[],"signature":{"algorithm":"ed25519","value":"x"}}"#;
    let result = verify(doc.as_bytes(), &ctx);
    assert!(
        matches!(result.unwrap_err(), VerificationError::MissingField { ref field } if field == "version")
    );
}

#[test]
fn test_reject_missing_subject() {
    let ctx = verification_context();
    let doc = r#"{"type":"open-presence","version":"0.1","public_key":"x","issued_at":"2026-07-11T20:00:00Z","services":[],"signature":{"algorithm":"ed25519","value":"x"}}"#;
    let result = verify(doc.as_bytes(), &ctx);
    assert!(
        matches!(result.unwrap_err(), VerificationError::MissingField { ref field } if field == "subject")
    );
}

#[test]
fn test_reject_missing_public_key() {
    let ctx = verification_context();
    let doc = r#"{"type":"open-presence","version":"0.1","subject":"x","issued_at":"2026-07-11T20:00:00Z","services":[],"signature":{"algorithm":"ed25519","value":"x"}}"#;
    let result = verify(doc.as_bytes(), &ctx);
    assert!(
        matches!(result.unwrap_err(), VerificationError::MissingField { ref field } if field == "public_key")
    );
}

#[test]
fn test_reject_missing_issued_at() {
    let ctx = verification_context();
    let doc = r#"{"type":"open-presence","version":"0.1","subject":"x","public_key":"x","services":[],"signature":{"algorithm":"ed25519","value":"x"}}"#;
    let result = verify(doc.as_bytes(), &ctx);
    assert!(
        matches!(result.unwrap_err(), VerificationError::MissingField { ref field } if field == "issued_at")
    );
}

#[test]
fn test_reject_missing_services() {
    let ctx = verification_context();
    let doc = r#"{"type":"open-presence","version":"0.1","subject":"x","public_key":"x","issued_at":"2026-07-11T20:00:00Z","signature":{"algorithm":"ed25519","value":"x"}}"#;
    let result = verify(doc.as_bytes(), &ctx);
    assert!(
        matches!(result.unwrap_err(), VerificationError::MissingField { ref field } if field == "services")
    );
}

#[test]
fn test_reject_missing_signature() {
    let ctx = verification_context();
    let doc = r#"{"type":"open-presence","version":"0.1","subject":"x","public_key":"x","issued_at":"2026-07-11T20:00:00Z","services":[]}"#;
    let result = verify(doc.as_bytes(), &ctx);
    assert!(
        matches!(result.unwrap_err(), VerificationError::MissingField { ref field } if field == "signature")
    );
}

#[test]
fn test_reject_non_string_type() {
    let ctx = verification_context();
    let doc = r#"{"type":123,"version":"0.1","subject":"x","public_key":"x","issued_at":"2026-07-11T20:00:00Z","services":[],"signature":{"algorithm":"ed25519","value":"x"}}"#;
    let result = verify(doc.as_bytes(), &ctx);
    assert!(
        matches!(result.unwrap_err(), VerificationError::InvalidFieldType { ref field, .. } if field == "type")
    );
}

#[test]
fn test_reject_numeric_version() {
    let ctx = verification_context();
    let doc = r#"{"type":"open-presence","version":0.1,"subject":"x","public_key":"x","issued_at":"2026-07-11T20:00:00Z","services":[],"signature":{"algorithm":"ed25519","value":"x"}}"#;
    let result = verify(doc.as_bytes(), &ctx);
    assert!(
        matches!(result.unwrap_err(), VerificationError::InvalidFieldType { ref field, .. } if field == "version")
    );
}

#[test]
fn test_accept_unknown_top_level_fields() {
    // Unknown fields should not cause parsing to fail
    let doc = r#"{"type":"open-presence","version":"0.1","unknown":"value","subject":"x","public_key":"x","issued_at":"2026-07-11T20:00:00Z","services":[],"signature":{"algorithm":"ed25519","value":"x"}}"#;
    let result = parse(doc.as_bytes());
    assert!(result.is_ok());
}

// --- Duplicate member handling ---

#[test]
fn test_reject_duplicate_top_level_member() {
    let doc = r#"{"type":"open-presence","type":"something-else","version":"0.1"}"#;
    let result = parse(doc.as_bytes());
    assert!(
        matches!(result.unwrap_err(), ParseError::DuplicateMember { ref member, .. } if member == "type")
    );
}

#[test]
fn test_reject_duplicate_nested_member() {
    let doc = r#"{"services":[{"type":"profile","url":"https://a.com","url":"https://b.com"}]}"#;
    let result = parse(doc.as_bytes());
    assert!(
        matches!(result.unwrap_err(), ParseError::DuplicateMember { ref member, .. } if member == "url")
    );
}

#[test]
fn test_reject_duplicate_in_signature() {
    let doc = r#"{"type":"open-presence","signature":{"algorithm":"ed25519","algorithm":"rsa"}}"#;
    let result = parse(doc.as_bytes());
    assert!(
        matches!(result.unwrap_err(), ParseError::DuplicateMember { ref member, .. } if member == "algorithm")
    );
}

// --- Type and version ---

#[test]
fn test_reject_wrong_type() {
    let ctx = verification_context();
    let doc = r#"{"type":"wrong","version":"0.1","subject":"key:sha256:Vkdap1RjR0wChd9dvyvKtz2mUTWIOem3dIGy6rEHcIw","public_key":"A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg","issued_at":"2026-07-11T20:00:00Z","services":[],"signature":{"algorithm":"ed25519","value":"x"}}"#;
    let result = verify(doc.as_bytes(), &ctx);
    assert!(matches!(
        result.unwrap_err(),
        VerificationError::InvalidType(_)
    ));
}

#[test]
fn test_reject_unsupported_version() {
    let ctx = verification_context();
    let doc = r#"{"type":"open-presence","version":"2.0","subject":"key:sha256:Vkdap1RjR0wChd9dvyvKtz2mUTWIOem3dIGy6rEHcIw","public_key":"A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg","issued_at":"2026-07-11T20:00:00Z","services":[],"signature":{"algorithm":"ed25519","value":"x"}}"#;
    let result = verify(doc.as_bytes(), &ctx);
    assert!(matches!(
        result.unwrap_err(),
        VerificationError::UnsupportedVersion(_)
    ));
}

// --- Public key validation ---

#[test]
fn test_reject_standard_base64_in_public_key() {
    let ctx = verification_context();
    // '+' is standard Base64, not Base64url
    let doc = r#"{"type":"open-presence","version":"0.1","subject":"key:sha256:x","public_key":"A6EHv+POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg","issued_at":"2026-07-11T20:00:00Z","services":[],"signature":{"algorithm":"ed25519","value":"x"}}"#;
    let result = verify(doc.as_bytes(), &ctx);
    assert!(matches!(
        result.unwrap_err(),
        VerificationError::InvalidPublicKeyEncoding
    ));
}

#[test]
fn test_reject_padded_base64url_public_key() {
    let ctx = verification_context();
    let doc = r#"{"type":"open-presence","version":"0.1","subject":"key:sha256:x","public_key":"A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=","issued_at":"2026-07-11T20:00:00Z","services":[],"signature":{"algorithm":"ed25519","value":"x"}}"#;
    let result = verify(doc.as_bytes(), &ctx);
    assert!(matches!(
        result.unwrap_err(),
        VerificationError::InvalidPublicKeyEncoding
    ));
}

#[test]
fn test_reject_short_public_key() {
    let ctx = verification_context();
    // Too short - only 16 bytes when decoded
    let doc = r#"{"type":"open-presence","version":"0.1","subject":"key:sha256:x","public_key":"AAAAAAAAAAAAAAAAAAAAAA","issued_at":"2026-07-11T20:00:00Z","services":[],"signature":{"algorithm":"ed25519","value":"x"}}"#;
    let result = verify(doc.as_bytes(), &ctx);
    assert!(matches!(
        result.unwrap_err(),
        VerificationError::InvalidPublicKeyLength(_)
    ));
}

#[test]
fn test_reject_long_public_key() {
    let ctx = verification_context();
    // Too long - 33 bytes
    let doc = r#"{"type":"open-presence","version":"0.1","subject":"key:sha256:x","public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","issued_at":"2026-07-11T20:00:00Z","services":[],"signature":{"algorithm":"ed25519","value":"x"}}"#;
    let result = verify(doc.as_bytes(), &ctx);
    assert!(matches!(
        result.unwrap_err(),
        VerificationError::InvalidPublicKeyLength(_) | VerificationError::InvalidPublicKeyEncoding
    ));
}

// --- Subject derivation ---

#[test]
fn test_derive_deterministic_subject() {
    let pk = test_public_key();
    let subject = derive_subject(&pk);
    assert_eq!(
        subject,
        "key:sha256:Vkdap1RjR0wChd9dvyvKtz2mUTWIOem3dIGy6rEHcIw"
    );
}

#[test]
fn test_subject_from_base64url_decoded_key() {
    let pk_b64 = "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg";
    let pk_bytes = URL_SAFE_NO_PAD.decode(pk_b64).unwrap();
    let mut key = [0u8; 32];
    key.copy_from_slice(&pk_bytes);
    assert_eq!(
        derive_subject(&key),
        "key:sha256:Vkdap1RjR0wChd9dvyvKtz2mUTWIOem3dIGy6rEHcIw"
    );
}

#[test]
fn test_subject_mismatch_different_key() {
    let ctx = verification_context();
    // Use a different public key but keep the same subject
    let doc = r#"{"type":"open-presence","version":"0.1","subject":"key:sha256:Vkdap1RjR0wChd9dvyvKtz2mUTWIOem3dIGy6rEHcIw","public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","issued_at":"2026-07-11T20:00:00Z","services":[],"signature":{"algorithm":"ed25519","value":"x"}}"#;
    let result = verify(doc.as_bytes(), &ctx);
    assert!(matches!(
        result.unwrap_err(),
        VerificationError::SubjectMismatch | VerificationError::InvalidPublicKeyLength(_)
    ));
}

#[test]
fn test_subject_format_mismatch() {
    let ctx = verification_context();
    // Invalid subject format - missing prefix
    let doc = r#"{"type":"open-presence","version":"0.1","subject":"Vkdap1RjR0wChd9dvyvKtz2mUTWIOem3dIGy6rEHcIw","public_key":"A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg","issued_at":"2026-07-11T20:00:00Z","services":[],"signature":{"algorithm":"ed25519","value":"x"}}"#;
    let result = verify(doc.as_bytes(), &ctx);
    assert!(matches!(
        result.unwrap_err(),
        VerificationError::SubjectMismatch
    ));
}

// --- Timestamps ---

#[test]
fn test_accept_valid_utc_timestamp() {
    // Covered by the main valid document test
    let ctx = verification_context();
    let result = verify(valid_signed_document().as_bytes(), &ctx);
    assert!(result.is_ok());
}

#[test]
fn test_reject_non_utc_offset() {
    let ctx = verification_context();
    let doc = r#"{"type":"open-presence","version":"0.1","subject":"key:sha256:Vkdap1RjR0wChd9dvyvKtz2mUTWIOem3dIGy6rEHcIw","public_key":"A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg","issued_at":"2026-07-11T13:00:00-07:00","services":[],"signature":{"algorithm":"ed25519","value":"x"}}"#;
    let result = verify(doc.as_bytes(), &ctx);
    assert!(matches!(
        result.unwrap_err(),
        VerificationError::InvalidIssuedAt(_)
    ));
}

#[test]
fn test_reject_timestamp_without_z() {
    let ctx = verification_context();
    let doc = r#"{"type":"open-presence","version":"0.1","subject":"key:sha256:Vkdap1RjR0wChd9dvyvKtz2mUTWIOem3dIGy6rEHcIw","public_key":"A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg","issued_at":"2026-07-11T20:00:00","services":[],"signature":{"algorithm":"ed25519","value":"x"}}"#;
    let result = verify(doc.as_bytes(), &ctx);
    assert!(matches!(
        result.unwrap_err(),
        VerificationError::InvalidIssuedAt(_)
    ));
}

#[test]
fn test_reject_date_only() {
    let ctx = verification_context();
    let doc = r#"{"type":"open-presence","version":"0.1","subject":"key:sha256:Vkdap1RjR0wChd9dvyvKtz2mUTWIOem3dIGy6rEHcIw","public_key":"A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg","issued_at":"2026-07-11","services":[],"signature":{"algorithm":"ed25519","value":"x"}}"#;
    let result = verify(doc.as_bytes(), &ctx);
    assert!(matches!(
        result.unwrap_err(),
        VerificationError::InvalidIssuedAt(_)
    ));
}

#[test]
fn test_reject_expires_at_equal_to_issued_at() {
    let ctx = verification_context();
    let doc = r#"{"type":"open-presence","version":"0.1","subject":"key:sha256:Vkdap1RjR0wChd9dvyvKtz2mUTWIOem3dIGy6rEHcIw","public_key":"A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg","issued_at":"2026-07-11T20:00:00Z","expires_at":"2026-07-11T20:00:00Z","services":[],"signature":{"algorithm":"ed25519","value":"x"}}"#;
    let result = verify(doc.as_bytes(), &ctx);
    assert!(matches!(
        result.unwrap_err(),
        VerificationError::ExpirationBeforeIssueTime
    ));
}

#[test]
fn test_reject_expires_at_before_issued_at() {
    let ctx = verification_context();
    let doc = r#"{"type":"open-presence","version":"0.1","subject":"key:sha256:Vkdap1RjR0wChd9dvyvKtz2mUTWIOem3dIGy6rEHcIw","public_key":"A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg","issued_at":"2026-07-11T20:00:00Z","expires_at":"2026-07-10T20:00:00Z","services":[],"signature":{"algorithm":"ed25519","value":"x"}}"#;
    let result = verify(doc.as_bytes(), &ctx);
    assert!(matches!(
        result.unwrap_err(),
        VerificationError::ExpirationBeforeIssueTime
    ));
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
fn test_expired_when_verification_time_equals_expires_at() {
    // verification_time >= expires_at means expired
    let ctx = VerificationContext {
        verification_time: OffsetDateTime::parse("2026-10-11T20:00:00Z", &Rfc3339).unwrap(),
    };
    let result = verify(valid_signed_document().as_bytes(), &ctx);
    assert!(matches!(
        result.unwrap_err(),
        VerificationError::DocumentExpired
    ));
}

// --- Services ---

#[test]
fn test_accept_empty_services_array() {
    // Build a document with empty services, sign it, then verify
    let doc = serde_json::json!({
        "type": "open-presence",
        "version": "0.1",
        "subject": "key:sha256:Vkdap1RjR0wChd9dvyvKtz2mUTWIOem3dIGy6rEHcIw",
        "public_key": "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg",
        "issued_at": "2026-07-11T20:00:00Z",
        "expires_at": "2026-10-11T20:00:00Z",
        "services": []
    });
    let unsigned = UnsignedDocument::new(doc).unwrap();
    let signed = sign(unsigned, &test_private_key()).unwrap();
    let signed_bytes = serde_json::to_vec(&signed).unwrap();

    let ctx = verification_context();
    let result = verify(&signed_bytes, &ctx);
    assert!(result.is_ok());
}

#[test]
fn test_reject_service_missing_type() {
    let ctx = verification_context();
    let doc = r#"{"type":"open-presence","version":"0.1","subject":"key:sha256:Vkdap1RjR0wChd9dvyvKtz2mUTWIOem3dIGy6rEHcIw","public_key":"A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg","issued_at":"2026-07-11T20:00:00Z","expires_at":"2026-10-11T20:00:00Z","services":[{"url":"https://example.com"}],"signature":{"algorithm":"ed25519","value":"x"}}"#;
    let result = verify(doc.as_bytes(), &ctx);
    assert!(matches!(
        result.unwrap_err(),
        VerificationError::InvalidServiceType
    ));
}

#[test]
fn test_reject_service_missing_url() {
    let ctx = verification_context();
    let doc = r#"{"type":"open-presence","version":"0.1","subject":"key:sha256:Vkdap1RjR0wChd9dvyvKtz2mUTWIOem3dIGy6rEHcIw","public_key":"A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg","issued_at":"2026-07-11T20:00:00Z","expires_at":"2026-10-11T20:00:00Z","services":[{"type":"profile"}],"signature":{"algorithm":"ed25519","value":"x"}}"#;
    let result = verify(doc.as_bytes(), &ctx);
    assert!(matches!(
        result.unwrap_err(),
        VerificationError::InvalidServiceUrl(_)
    ));
}

#[test]
fn test_reject_non_string_service_type() {
    let ctx = verification_context();
    let doc = r#"{"type":"open-presence","version":"0.1","subject":"key:sha256:Vkdap1RjR0wChd9dvyvKtz2mUTWIOem3dIGy6rEHcIw","public_key":"A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg","issued_at":"2026-07-11T20:00:00Z","expires_at":"2026-10-11T20:00:00Z","services":[{"type":123,"url":"https://example.com"}],"signature":{"algorithm":"ed25519","value":"x"}}"#;
    let result = verify(doc.as_bytes(), &ctx);
    assert!(matches!(
        result.unwrap_err(),
        VerificationError::InvalidServiceType
    ));
}

#[test]
fn test_reject_non_string_service_url() {
    let ctx = verification_context();
    let doc = r#"{"type":"open-presence","version":"0.1","subject":"key:sha256:Vkdap1RjR0wChd9dvyvKtz2mUTWIOem3dIGy6rEHcIw","public_key":"A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg","issued_at":"2026-07-11T20:00:00Z","expires_at":"2026-10-11T20:00:00Z","services":[{"type":"profile","url":123}],"signature":{"algorithm":"ed25519","value":"x"}}"#;
    let result = verify(doc.as_bytes(), &ctx);
    assert!(matches!(
        result.unwrap_err(),
        VerificationError::InvalidServiceUrl(_)
    ));
}

#[test]
fn test_reject_http_service_url() {
    let ctx = verification_context();
    let doc = r#"{"type":"open-presence","version":"0.1","subject":"key:sha256:Vkdap1RjR0wChd9dvyvKtz2mUTWIOem3dIGy6rEHcIw","public_key":"A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg","issued_at":"2026-07-11T20:00:00Z","expires_at":"2026-10-11T20:00:00Z","services":[{"type":"profile","url":"http://example.com"}],"signature":{"algorithm":"ed25519","value":"x"}}"#;
    let result = verify(doc.as_bytes(), &ctx);
    assert!(matches!(
        result.unwrap_err(),
        VerificationError::NonHttpsServiceUrl
    ));
}

#[test]
fn test_reject_relative_service_url() {
    let ctx = verification_context();
    let doc = r#"{"type":"open-presence","version":"0.1","subject":"key:sha256:Vkdap1RjR0wChd9dvyvKtz2mUTWIOem3dIGy6rEHcIw","public_key":"A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg","issued_at":"2026-07-11T20:00:00Z","expires_at":"2026-10-11T20:00:00Z","services":[{"type":"profile","url":"/profile"}],"signature":{"algorithm":"ed25519","value":"x"}}"#;
    let result = verify(doc.as_bytes(), &ctx);
    assert!(matches!(
        result.unwrap_err(),
        VerificationError::InvalidServiceUrl(_)
    ));
}

#[test]
fn test_reject_ftp_service_url() {
    let ctx = verification_context();
    let doc = r#"{"type":"open-presence","version":"0.1","subject":"key:sha256:Vkdap1RjR0wChd9dvyvKtz2mUTWIOem3dIGy6rEHcIw","public_key":"A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg","issued_at":"2026-07-11T20:00:00Z","expires_at":"2026-10-11T20:00:00Z","services":[{"type":"profile","url":"ftp://example.com"}],"signature":{"algorithm":"ed25519","value":"x"}}"#;
    let result = verify(doc.as_bytes(), &ctx);
    assert!(matches!(
        result.unwrap_err(),
        VerificationError::NonHttpsServiceUrl
    ));
}

#[test]
fn test_reject_service_url_with_credentials() {
    let ctx = verification_context();
    let url_part = format!("https://user:pass{}example.com/profile", "word@");
    let doc = format!(
        r#"{{"type":"open-presence","version":"0.1","subject":"key:sha256:Vkdap1RjR0wChd9dvyvKtz2mUTWIOem3dIGy6rEHcIw","public_key":"A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg","issued_at":"2026-07-11T20:00:00Z","expires_at":"2026-10-11T20:00:00Z","services":[{{"type":"profile","url":"{}"}}],"signature":{{"algorithm":"ed25519","value":"x"}}}}"#,
        url_part
    );
    let result = verify(doc.as_bytes(), &ctx);
    assert!(matches!(
        result.unwrap_err(),
        VerificationError::ServiceUrlContainsCredentials
    ));
}

// --- Signature verification ---

#[test]
fn test_reject_unsupported_signature_algorithm() {
    let ctx = verification_context();
    let doc = r#"{"type":"open-presence","version":"0.1","subject":"key:sha256:Vkdap1RjR0wChd9dvyvKtz2mUTWIOem3dIGy6rEHcIw","public_key":"A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg","issued_at":"2026-07-11T20:00:00Z","expires_at":"2026-10-11T20:00:00Z","services":[],"signature":{"algorithm":"rsa","value":"x"}}"#;
    let result = verify(doc.as_bytes(), &ctx);
    assert!(matches!(
        result.unwrap_err(),
        VerificationError::UnsupportedSignatureAlgorithm(_)
    ));
}

#[test]
fn test_reject_padded_signature() {
    let ctx = verification_context();
    let doc = r#"{"type":"open-presence","version":"0.1","subject":"key:sha256:Vkdap1RjR0wChd9dvyvKtz2mUTWIOem3dIGy6rEHcIw","public_key":"A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg","issued_at":"2026-07-11T20:00:00Z","expires_at":"2026-10-11T20:00:00Z","services":[],"signature":{"algorithm":"ed25519","value":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}}"#;
    let result = verify(doc.as_bytes(), &ctx);
    assert!(matches!(
        result.unwrap_err(),
        VerificationError::InvalidSignatureEncoding
    ));
}

#[test]
fn test_reject_wrong_length_signature() {
    let ctx = verification_context();
    // 32 bytes (too short for a signature)
    let doc = r#"{"type":"open-presence","version":"0.1","subject":"key:sha256:Vkdap1RjR0wChd9dvyvKtz2mUTWIOem3dIGy6rEHcIw","public_key":"A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg","issued_at":"2026-07-11T20:00:00Z","expires_at":"2026-10-11T20:00:00Z","services":[],"signature":{"algorithm":"ed25519","value":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}}"#;
    let result = verify(doc.as_bytes(), &ctx);
    assert!(matches!(
        result.unwrap_err(),
        VerificationError::InvalidSignatureLength(_)
    ));
}

#[test]
fn test_reject_tampered_service_url() {
    let ctx = verification_context();
    // Change the service URL - signature should no longer verify
    let doc = r#"{
  "type": "open-presence",
  "version": "0.1",
  "subject": "key:sha256:Vkdap1RjR0wChd9dvyvKtz2mUTWIOem3dIGy6rEHcIw",
  "public_key": "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg",
  "issued_at": "2026-07-11T20:00:00Z",
  "expires_at": "2026-10-11T20:00:00Z",
  "services": [
    {"type": "profile", "url": "https://example.com/evil"},
    {"type": "feed", "url": "https://example.com/jody/feed"}
  ],
  "signature": {
    "algorithm": "ed25519",
    "value": "-ojCCq5ngoVSQsUB68EGtvuTAQBLajwoHP4irGZUlvfkuyFOy_1uTOp-0lmAWX6wnUs_upzl6mwfMoizUNZbAw"
  }
}"#;
    let result = verify(doc.as_bytes(), &ctx);
    assert!(matches!(
        result.unwrap_err(),
        VerificationError::SignatureVerificationFailed
    ));
}

#[test]
fn test_accept_reordered_json_members() {
    let ctx = verification_context();
    // Reorder the top-level members - verification should still succeed
    // because canonicalization sorts them
    let doc = r#"{
  "services": [
    {"type": "profile", "url": "https://example.com/jody"},
    {"type": "feed", "url": "https://example.com/jody/feed"}
  ],
  "version": "0.1",
  "type": "open-presence",
  "expires_at": "2026-10-11T20:00:00Z",
  "issued_at": "2026-07-11T20:00:00Z",
  "public_key": "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg",
  "subject": "key:sha256:Vkdap1RjR0wChd9dvyvKtz2mUTWIOem3dIGy6rEHcIw",
  "signature": {
    "algorithm": "ed25519",
    "value": "-ojCCq5ngoVSQsUB68EGtvuTAQBLajwoHP4irGZUlvfkuyFOy_1uTOp-0lmAWX6wnUs_upzl6mwfMoizUNZbAw"
  }
}"#;
    let result = verify(doc.as_bytes(), &ctx);
    assert!(result.is_ok());
}

#[test]
fn test_reject_reordered_services_array() {
    let ctx = verification_context();
    // Reorder the services array - signature should fail
    let doc = r#"{
  "type": "open-presence",
  "version": "0.1",
  "subject": "key:sha256:Vkdap1RjR0wChd9dvyvKtz2mUTWIOem3dIGy6rEHcIw",
  "public_key": "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg",
  "issued_at": "2026-07-11T20:00:00Z",
  "expires_at": "2026-10-11T20:00:00Z",
  "services": [
    {"type": "feed", "url": "https://example.com/jody/feed"},
    {"type": "profile", "url": "https://example.com/jody"}
  ],
  "signature": {
    "algorithm": "ed25519",
    "value": "-ojCCq5ngoVSQsUB68EGtvuTAQBLajwoHP4irGZUlvfkuyFOy_1uTOp-0lmAWX6wnUs_upzl6mwfMoizUNZbAw"
  }
}"#;
    let result = verify(doc.as_bytes(), &ctx);
    assert!(matches!(
        result.unwrap_err(),
        VerificationError::SignatureVerificationFailed
    ));
}

// --- Signing tests ---

#[test]
fn test_sign_produces_expected_signature() {
    let doc = serde_json::json!({
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

    assert_eq!(
        signed["signature"]["algorithm"].as_str().unwrap(),
        "ed25519"
    );
    assert_eq!(
        signed["signature"]["value"].as_str().unwrap(),
        "-ojCCq5ngoVSQsUB68EGtvuTAQBLajwoHP4irGZUlvfkuyFOy_1uTOp-0lmAWX6wnUs_upzl6mwfMoizUNZbAw"
    );
}

#[test]
fn test_sign_and_verify_round_trip() {
    let doc = serde_json::json!({
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
    let signed_bytes = serde_json::to_vec(&signed).unwrap();

    let ctx = verification_context();
    let result = verify(&signed_bytes, &ctx);
    assert!(result.is_ok());
}

#[test]
fn test_sign_reject_already_signed() {
    let doc = serde_json::json!({
        "type": "open-presence",
        "signature": {"algorithm": "ed25519", "value": "test"}
    });
    let err = UnsignedDocument::new(doc).unwrap_err();
    assert!(matches!(err, SigningError::AlreadySigned));
}

#[test]
fn test_sign_reject_public_key_mismatch() {
    // Use a different key pair that will pass field validation but fail key matching
    let other_key = [0xFFu8; 32];
    let other_signing = ed25519_dalek::SigningKey::from_bytes(&other_key);
    let other_public = other_signing.verifying_key().to_bytes();
    let other_pk_b64 = URL_SAFE_NO_PAD.encode(other_public);
    let other_subject = derive_subject(&other_public);

    let doc = serde_json::json!({
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
fn test_sign_reject_subject_mismatch() {
    // Subject doesn't match the public key — caught by document validation
    let doc = serde_json::json!({
        "type": "open-presence",
        "version": "0.1",
        "subject": "key:sha256:wrong-subject-value",
        "public_key": "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg",
        "issued_at": "2026-07-11T20:00:00Z",
        "services": []
    });
    let unsigned = UnsignedDocument::new(doc).unwrap();
    let err = sign(unsigned, &test_private_key()).unwrap_err();
    assert!(matches!(
        err,
        SigningError::ValidationFailed(VerificationError::SubjectMismatch)
    ));
}

// --- Canonicalization ---

#[test]
fn test_canonical_bytes_match_expected() {
    let doc = serde_json::json!({
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

    // Use the canonicalize function directly (it's pub(crate) so we test via sign)
    let unsigned = UnsignedDocument::new(doc).unwrap();
    let signed = sign(unsigned, &test_private_key()).unwrap();

    // If the signature matches the expected value, the canonical bytes are correct
    assert_eq!(
        signed["signature"]["value"].as_str().unwrap(),
        "-ojCCq5ngoVSQsUB68EGtvuTAQBLajwoHP4irGZUlvfkuyFOy_1uTOp-0lmAWX6wnUs_upzl6mwfMoizUNZbAw"
    );
}

#[test]
fn test_key_derivation_from_seed() {
    use ed25519_dalek::SigningKey;

    let signing_key = SigningKey::from_bytes(&test_private_key());
    let public_key = signing_key.verifying_key().to_bytes();
    let public_key_b64 = URL_SAFE_NO_PAD.encode(public_key);

    assert_eq!(
        public_key_b64,
        "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg"
    );
}

// --- Document without expires_at ---

#[test]
fn test_accept_document_without_expires_at() {
    let doc = serde_json::json!({
        "type": "open-presence",
        "version": "0.1",
        "subject": "key:sha256:Vkdap1RjR0wChd9dvyvKtz2mUTWIOem3dIGy6rEHcIw",
        "public_key": "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg",
        "issued_at": "2026-07-11T20:00:00Z",
        "services": []
    });
    let unsigned = UnsignedDocument::new(doc).unwrap();
    let signed = sign(unsigned, &test_private_key()).unwrap();
    let signed_bytes = serde_json::to_vec(&signed).unwrap();

    let ctx = verification_context();
    let result = verify(&signed_bytes, &ctx);
    assert!(result.is_ok());
}
