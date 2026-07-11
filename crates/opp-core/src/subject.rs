//! Subject derivation from Ed25519 public keys.
//!
//! The subject uniquely identifies the public key controlling the presence document.
//! Format: `key:sha256:<digest>` where `<digest>` is the SHA-256 hash of the decoded
//! Ed25519 public key encoded with unpadded Base64url.
//!
//! See SPEC.md Section 8.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use sha2::{Digest, Sha256};

/// Derive an OPP subject identifier from a 32-byte Ed25519 public key.
///
/// The subject format is `key:sha256:<base64url-unpadded-sha256-digest>`.
///
/// # Example
///
/// ```
/// use opp_core::derive_subject;
///
/// let public_key: [u8; 32] = [
///     0x03, 0xa1, 0x07, 0xbf, 0xf3, 0xce, 0x10, 0xbe,
///     0x1d, 0x70, 0xdd, 0x18, 0xe7, 0x4b, 0xc0, 0x99,
///     0x67, 0xe4, 0xd6, 0x30, 0x9b, 0xa5, 0x0d, 0x5f,
///     0x1d, 0xdc, 0x86, 0x64, 0x12, 0x55, 0x31, 0xb8,
/// ];
/// let subject = derive_subject(&public_key);
/// assert_eq!(subject, "key:sha256:Vkdap1RjR0wChd9dvyvKtz2mUTWIOem3dIGy6rEHcIw");
/// ```
pub fn derive_subject(public_key: &[u8; 32]) -> String {
    let digest = Sha256::digest(public_key);
    let encoded = URL_SAFE_NO_PAD.encode(digest);
    format!("key:sha256:{}", encoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deterministic_subject() {
        let public_key: [u8; 32] = [
            0x03, 0xa1, 0x07, 0xbf, 0xf3, 0xce, 0x10, 0xbe, 0x1d, 0x70, 0xdd, 0x18, 0xe7, 0x4b,
            0xc0, 0x99, 0x67, 0xe4, 0xd6, 0x30, 0x9b, 0xa5, 0x0d, 0x5f, 0x1d, 0xdc, 0x86, 0x64,
            0x12, 0x55, 0x31, 0xb8,
        ];
        assert_eq!(
            derive_subject(&public_key),
            "key:sha256:Vkdap1RjR0wChd9dvyvKtz2mUTWIOem3dIGy6rEHcIw"
        );
    }

    #[test]
    fn test_different_key_different_subject() {
        let key1 = [0u8; 32];
        let key2 = [1u8; 32];
        assert_ne!(derive_subject(&key1), derive_subject(&key2));
    }
}
