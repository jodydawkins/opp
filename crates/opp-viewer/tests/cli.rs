//! CLI integration tests for opp-viewer.
//!
//! Exercises the compiled binary via `std::process::Command`.

use std::io::Write;
use std::process::{Command, Stdio};

use base64::Engine;

const PROJECT_ROOT: &str = env!("CARGO_MANIFEST_DIR");
const VECTORS_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../vectors/valid/");

/// Read a test vector by name.
fn vector(name: &str) -> String {
    std::fs::read_to_string(format!("{VECTORS_DIR}{name}"))
        .unwrap_or_else(|e| panic!("cannot read vector '{name}': {e}"))
}

/// Spawn the viewer via cargo run with content on stdin, no file arg.
fn run_stdin(stdin_input: &[u8]) -> (String, i32) {
    let mut child = Command::new("cargo")
        .args(["run", "-p", "opp-viewer"])
        .current_dir(PROJECT_ROOT)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn opp-viewer");

    if let Some(ref mut stdin) = child.stdin {
        stdin.write_all(stdin_input).unwrap();
    }

    let output = child.wait_with_output().expect("failed to wait on viewer");
    (
        String::from_utf8_lossy(&output.stdout).into_owned(),
        output.status.code().unwrap_or(-1),
    )
}

/// Spawn the viewer via cargo run with a file arg and empty stdin.
fn run_file(file: &str) -> (String, i32) {
    let mut child = Command::new("cargo")
        .args(["run", "-p", "opp-viewer"])
        .current_dir(PROJECT_ROOT)
        .arg(file)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn opp-viewer");

    if let Some(ref mut stdin) = child.stdin {
        stdin.write_all(b"").unwrap();
    }

    let output = child.wait_with_output().expect("failed to wait on viewer");
    (
        String::from_utf8_lossy(&output.stdout).into_owned(),
        output.status.code().unwrap_or(-1),
    )
}

/// Spawn the viewer with extra args via cargo run and empty stdin.
fn run_file_with_args(file: &str, extra_args: &[&str]) -> i32 {
    let mut args = vec!["run", "-p", "opp-viewer", file];
    args.extend_from_slice(extra_args);

    let mut child = Command::new("cargo")
        .args(&args)
        .current_dir(PROJECT_ROOT)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn opp-viewer");

    if let Some(ref mut stdin) = child.stdin {
        stdin.write_all(b"").unwrap();
    }

    child
        .wait_with_output()
        .expect("failed to wait on viewer")
        .status
        .code()
        .unwrap_or(-1)
}

// --- Valid input exits successfully ---

#[test]
fn test_valid_stdin_exits_success() {
    let content = vector("signed-document.json");
    let (_, code) = run_stdin(content.as_bytes());
    assert_eq!(code, 0);
}

#[test]
fn test_valid_file_input_exits_success() {
    let path = format!("{VECTORS_DIR}signed-document.json");
    let (_, code) = run_file(&path);
    assert_eq!(code, 0);
}

// --- Invalid/tampered input exits with non-zero ---

#[test]
fn test_invalid_json_exits_nonzero() {
    let (stdout, code) = run_stdin(b"{not valid json");
    assert_ne!(code, 0);
    assert!(!stdout.contains("VERIFIED"));
}

// --- Stdin input works (content verification) ---

#[test]
fn test_stdin_output_contains_verified() {
    let content = vector("signed-document.json");
    let (stdout, code) = run_stdin(content.as_bytes());
    assert_eq!(code, 0);
    assert!(stdout.contains("VERIFIED"));
}

// --- File input works (content verification) ---

#[test]
fn test_file_output_contains_verified() {
    let path = format!("{VECTORS_DIR}signed-document.json");
    let (stdout, code) = run_file(&path);
    assert_eq!(code, 0);
    assert!(stdout.contains("VERIFIED"));
}

// --- All declared services are rendered ---

#[test]
fn test_services_rendered() {
    let content = vector("signed-document.json");
    let (stdout, _) = run_stdin(content.as_bytes());
    assert!(stdout.contains("profile"));
    assert!(stdout.contains("feed"));
}

// --- Document without expires_at renders correctly (no "Valid Until" line) ---

#[test]
fn test_no_expires_at_no_valid_until_line() {
    // Build a signed document without expires_at using a fresh key pair.
    let seed: [u8; 32] = [1u8; 32];
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();

    let doc = serde_json::json!({
        "type": "open-presence",
        "version": "0.1",
        "subject": opp_core::derive_subject(&verifying_key.to_bytes()),
        "public_key": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(verifying_key.to_bytes()),
        "issued_at": "2026-07-11T20:00:00Z",
        "services": []
    });
    let unsigned = opp_core::UnsignedDocument::new(doc).unwrap();
    let signed = opp_core::sign(unsigned, &seed).unwrap();
    let signed_bytes = serde_json::to_string(&signed).unwrap();

    let (stdout, code) = run_stdin(signed_bytes.as_bytes());
    assert_eq!(code, 0);
    assert!(stdout.contains("VERIFIED"));
    assert!(stdout.contains("Subject"));
    // "Valid Until" should NOT appear because expires_at is absent
    assert!(!stdout.contains("Valid Until"));
}

// --- Verified presence information not printed when verification fails ---

#[test]
fn test_no_output_on_failure() {
    let (stdout, code) = run_stdin(b"{}");
    assert_ne!(code, 0);
    // No verified document fields should leak to stdout
    assert!(!stdout.contains("VERIFIED"));
    assert!(!stdout.contains("Subject"));
}

// --- Extra arguments rejected ---

#[test]
fn test_extra_args_rejected() {
    let path = format!("{VECTORS_DIR}signed-document.json");
    let code = run_file_with_args(&path, &["extra.json"]);
    assert_ne!(code, 0);
}

// --- Non-existent file rejected ---

#[test]
fn test_missing_file_rejected() {
    let (_, code) = run_file("/no/such/file.json");
    assert_ne!(code, 0);
}
