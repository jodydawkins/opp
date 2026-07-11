//! Error types for the OPP protocol operations.

use thiserror::Error;

/// Errors that can occur when parsing an OPP document from raw bytes.
#[derive(Debug, Error)]
pub enum ParseError {
    #[error("invalid JSON: {0}")]
    InvalidJson(String),

    #[error("duplicate member \"{member}\" at path \"{path}\"")]
    DuplicateMember { path: String, member: String },

    #[error("document must be a JSON object")]
    NotAnObject,
}

/// Errors that can occur when signing an OPP document.
#[derive(Debug, Error)]
pub enum SigningError {
    #[error("document already contains a signature")]
    AlreadySigned,

    #[error("public key does not match the private key")]
    PublicKeyMismatch,

    #[error("canonicalization failed: {0}")]
    CanonicalizationFailed(String),

    #[error("validation failed: {0}")]
    ValidationFailed(#[from] VerificationError),
}

/// Errors that can occur when verifying an OPP document.
///
/// Each variant identifies a specific validation or verification failure,
/// allowing callers and tests to distinguish failure types.
#[derive(Debug, Error)]
pub enum VerificationError {
    #[error("invalid JSON: {0}")]
    InvalidJson(String),

    #[error("duplicate member \"{member}\" at path \"{path}\"")]
    DuplicateMember { path: String, member: String },

    #[error("unsupported version: {0}")]
    UnsupportedVersion(String),

    #[error("invalid type: expected \"open-presence\", got \"{0}\"")]
    InvalidType(String),

    #[error("missing required field: {field}")]
    MissingField { field: String },

    #[error("invalid field type for \"{field}\": expected {expected}")]
    InvalidFieldType { field: String, expected: String },

    #[error("invalid public key encoding")]
    InvalidPublicKeyEncoding,

    #[error("invalid public key length: expected 32 bytes, got {0}")]
    InvalidPublicKeyLength(usize),

    #[error("subject does not match public key")]
    SubjectMismatch,

    #[error("missing signature")]
    MissingSignature,

    #[error("unsupported signature algorithm: {0}")]
    UnsupportedSignatureAlgorithm(String),

    #[error("invalid signature encoding")]
    InvalidSignatureEncoding,

    #[error("invalid signature length: expected 64 bytes, got {0}")]
    InvalidSignatureLength(usize),

    #[error("signature verification failed")]
    SignatureVerificationFailed,

    #[error("invalid issued_at timestamp: {0}")]
    InvalidIssuedAt(String),

    #[error("invalid expires_at timestamp: {0}")]
    InvalidExpiresAt(String),

    #[error("expires_at must be later than issued_at")]
    ExpirationBeforeIssueTime,

    #[error("document has expired")]
    DocumentExpired,

    #[error("services must be an array")]
    InvalidServices,

    #[error("invalid service type")]
    InvalidServiceType,

    #[error("invalid service URL: {0}")]
    InvalidServiceUrl(String),

    #[error("service URL must use HTTPS")]
    NonHttpsServiceUrl,

    #[error("service URL contains credentials")]
    ServiceUrlContainsCredentials,

    #[error("canonicalization failed: {0}")]
    CanonicalizationFailed(String),

    #[error("document must be a JSON object")]
    NotAnObject,
}
