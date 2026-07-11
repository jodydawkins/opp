//! # OPP Core
//!
//! Reference implementation of Open Presence Protocol (OPP) version 0.1.
//!
//! This crate provides:
//! - Document parsing with duplicate JSON member detection
//! - Field validation (type, version, timestamps, services, public key)
//! - Subject derivation from Ed25519 public keys
//! - RFC 8785 JSON Canonicalization Scheme (JCS) serialization
//! - Ed25519 signing and signature verification
//!
//! See [SPEC.md](../../SPEC.md) for the full protocol specification.

mod canonicalize;
mod error;
mod parse;
mod sign;
mod subject;
mod validate;
mod verify;

pub use error::{ParseError, SigningError, VerificationError};
pub use parse::{parse, UnverifiedDocument};
pub use sign::{sign, UnsignedDocument};
pub use subject::derive_subject;
pub use verify::{verify, VerificationContext, VerifiedDocument};

/// Represents a verified OPP presence document.
///
/// The fields of this struct are only accessible after successful verification.
#[derive(Debug, Clone)]
pub struct PresenceDocument {
    pub subject: String,
    pub public_key: String,
    pub issued_at: String,
    pub expires_at: Option<String>,
    pub services: Vec<ServiceObject>,
}

/// Represents a service endpoint in an OPP document.
#[derive(Debug, Clone)]
pub struct ServiceObject {
    pub service_type: String,
    pub url: String,
}
