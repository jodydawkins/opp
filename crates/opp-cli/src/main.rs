//! OPP CLI - Command-line interface for Open Presence Protocol operations.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use opp_core::{derive_subject, sign, verify, UnsignedDocument, VerificationContext};
use std::fs;
use std::io::Read;
use std::process;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// OPP - Open Presence Protocol CLI
///
/// A reference implementation of Open Presence Protocol 0.1.
/// Generate keys, derive subjects, sign documents, and verify documents.
#[derive(Parser)]
#[command(name = "opp", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Key management operations
    Key {
        #[command(subcommand)]
        action: KeyAction,
    },
    /// Derive a subject from a public key
    Subject {
        #[command(subcommand)]
        action: SubjectAction,
    },
    /// Sign an OPP presence document
    Sign {
        /// Path to the unsigned document
        document: String,
        /// Path to the private key file (Base64url-encoded)
        #[arg(long)]
        private_key: String,
        /// Output file path (default: stdout)
        #[arg(long)]
        output: Option<String>,
    },
    /// Verify a signed OPP presence document
    Verify {
        /// Path to the signed document
        document: String,
        /// Output format
        #[arg(long, default_value = "text")]
        format: String,
        /// Verification time (RFC 3339, defaults to now)
        #[arg(long)]
        at: Option<String>,
    },
}

#[derive(Subcommand)]
enum KeyAction {
    /// Generate a new Ed25519 key pair
    Generate {
        /// Output file for the private key
        #[arg(long)]
        private_key: Option<String>,
        /// Output file for the public key
        #[arg(long)]
        public_key: Option<String>,
    },
}

#[derive(Subcommand)]
enum SubjectAction {
    /// Derive a subject from a public key
    Derive {
        /// Public key in unpadded Base64url encoding
        #[arg(long)]
        public_key: String,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Key { action } => match action {
            KeyAction::Generate {
                private_key: private_key_path,
                public_key: public_key_path,
            } => cmd_key_generate(private_key_path, public_key_path),
        },
        Commands::Subject { action } => match action {
            SubjectAction::Derive { public_key } => cmd_subject_derive(&public_key),
        },
        Commands::Sign {
            document,
            private_key,
            output,
        } => cmd_sign(&document, &private_key, output.as_deref()),
        Commands::Verify {
            document,
            format,
            at,
        } => cmd_verify(&document, &format, at.as_deref()),
    }
}

fn cmd_key_generate(private_key_path: Option<String>, public_key_path: Option<String>) {
    let mut csprng = rand::rngs::OsRng;
    let signing_key = SigningKey::generate(&mut csprng);

    let private_b64 = URL_SAFE_NO_PAD.encode(signing_key.to_bytes());
    let public_b64 = URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes());
    let subject = derive_subject(&signing_key.verifying_key().to_bytes());

    if let Some(path) = &private_key_path {
        fs::write(path, &private_b64).unwrap_or_else(|e| {
            eprintln!("Error writing private key: {}", e);
            process::exit(1);
        });
    }

    if let Some(path) = &public_key_path {
        fs::write(path, &public_b64).unwrap_or_else(|e| {
            eprintln!("Error writing public key: {}", e);
            process::exit(1);
        });
    }

    if private_key_path.is_none() {
        println!("private_key: {}", private_b64);
    }
    if public_key_path.is_none() {
        println!("public_key: {}", public_b64);
    }
    println!("subject: {}", subject);

    eprintln!();
    eprintln!("WARNING: The private key MUST be kept secret.");
    eprintln!("Do not share it or commit it to source control.");

    if private_key_path.is_some() {
        eprintln!("Private key written to file. Protect this file.");
    }
}

fn cmd_subject_derive(public_key_b64: &str) {
    // Reject standard Base64 characters
    if public_key_b64.contains('+') || public_key_b64.contains('/') || public_key_b64.contains('=')
    {
        eprintln!("Error: invalid Base64url encoding");
        process::exit(1);
    }

    let bytes = URL_SAFE_NO_PAD.decode(public_key_b64).unwrap_or_else(|e| {
        eprintln!("Error: invalid Base64url encoding: {}", e);
        process::exit(1);
    });

    if bytes.len() != 32 {
        eprintln!("Error: public key must be 32 bytes, got {}", bytes.len());
        process::exit(1);
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    println!("{}", derive_subject(&key));
}

fn cmd_sign(document_path: &str, private_key_path: &str, output_path: Option<&str>) {
    // Read the private key
    let pk_content = fs::read_to_string(private_key_path).unwrap_or_else(|e| {
        eprintln!("Error reading private key: {}", e);
        process::exit(1);
    });
    let pk_content = pk_content.trim();

    let pk_bytes = URL_SAFE_NO_PAD.decode(pk_content).unwrap_or_else(|e| {
        eprintln!("Error: invalid private key encoding: {}", e);
        process::exit(1);
    });

    if pk_bytes.len() != 32 {
        eprintln!("Error: private key must be 32 bytes");
        process::exit(1);
    }

    let mut private_key = [0u8; 32];
    private_key.copy_from_slice(&pk_bytes);

    // Read the document (with size limit)
    let doc_content = read_limited_file(document_path);

    // Parse as JSON and check for signature
    let value: serde_json::Value = serde_json::from_slice(&doc_content).unwrap_or_else(|e| {
        eprintln!("Error: invalid JSON: {}", e);
        process::exit(1);
    });

    let unsigned = UnsignedDocument::new(value).unwrap_or_else(|e| {
        eprintln!("Error: {}", e);
        process::exit(1);
    });

    let signed = sign(unsigned, &private_key).unwrap_or_else(|e| {
        eprintln!("Error: {}", e);
        process::exit(1);
    });

    let output_json = serde_json::to_string_pretty(&signed).unwrap();

    match output_path {
        Some(path) => {
            fs::write(path, &output_json).unwrap_or_else(|e| {
                eprintln!("Error writing output: {}", e);
                process::exit(1);
            });
        }
        None => {
            println!("{}", output_json);
        }
    }
}

fn cmd_verify(document_path: &str, format: &str, at: Option<&str>) {
    let doc_content = read_limited_file(document_path);

    let verification_time = match at {
        Some(time_str) => OffsetDateTime::parse(time_str, &Rfc3339).unwrap_or_else(|e| {
            eprintln!("Error: invalid verification time: {}", e);
            process::exit(1);
        }),
        None => OffsetDateTime::now_utc(),
    };

    let context = VerificationContext { verification_time };

    match verify(&doc_content, &context) {
        Ok(_) => {
            if format == "json" {
                println!(r#"{{"valid":true}}"#);
            } else {
                println!("valid");
            }
            process::exit(0);
        }
        Err(e) => {
            if format == "json" {
                let error_code = error_code(&e);
                let message = e.to_string();
                println!(
                    "{}",
                    serde_json::json!({
                        "valid": false,
                        "error": error_code,
                        "message": message
                    })
                );
            } else {
                eprintln!("invalid: {}", e);
            }
            process::exit(1);
        }
    }
}

fn error_code(e: &opp_core::VerificationError) -> &'static str {
    use opp_core::VerificationError::*;
    match e {
        InvalidJson(_) => "invalid_json",
        DuplicateMember { .. } => "duplicate_member",
        UnsupportedVersion(_) => "unsupported_version",
        InvalidType(_) => "invalid_type",
        MissingField { .. } => "missing_field",
        InvalidFieldType { .. } => "invalid_field_type",
        InvalidPublicKeyEncoding => "invalid_public_key_encoding",
        InvalidPublicKeyLength(_) => "invalid_public_key_length",
        SubjectMismatch => "subject_mismatch",
        MissingSignature => "missing_signature",
        UnsupportedSignatureAlgorithm(_) => "unsupported_signature_algorithm",
        InvalidSignatureEncoding => "invalid_signature_encoding",
        InvalidSignatureLength(_) => "invalid_signature_length",
        SignatureVerificationFailed => "signature_verification_failed",
        InvalidIssuedAt(_) => "invalid_issued_at",
        InvalidExpiresAt(_) => "invalid_expires_at",
        ExpirationBeforeIssueTime => "expiration_before_issue_time",
        DocumentExpired => "document_expired",
        InvalidServices => "invalid_services",
        InvalidServiceType => "invalid_service_type",
        InvalidServiceUrl(_) => "invalid_service_url",
        NonHttpsServiceUrl => "non_https_service_url",
        ServiceUrlContainsCredentials => "service_url_contains_credentials",
        CanonicalizationFailed(_) => "canonicalization_failed",
        NotAnObject => "not_an_object",
    }
}

/// Read a file with a reasonable size limit (10 MB).
fn read_limited_file(path: &str) -> Vec<u8> {
    const MAX_SIZE: u64 = 10 * 1024 * 1024; // 10 MB

    let metadata = fs::metadata(path).unwrap_or_else(|e| {
        eprintln!("Error reading file: {}", e);
        process::exit(1);
    });

    if metadata.len() > MAX_SIZE {
        eprintln!("Error: file exceeds maximum size of {} bytes", MAX_SIZE);
        process::exit(1);
    }

    let mut file = fs::File::open(path).unwrap_or_else(|e| {
        eprintln!("Error opening file: {}", e);
        process::exit(1);
    });

    let mut content = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut content).unwrap_or_else(|e| {
        eprintln!("Error reading file: {}", e);
        process::exit(1);
    });

    content
}
