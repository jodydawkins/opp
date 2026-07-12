//! OPP Viewer — human-readable viewer for signed OPP presence documents.
//!
//! Reads a document from stdin or a file path, verifies it via `opp-core`,
//! and renders the contents in a clear text format.

use opp_core::{verify, VerificationContext};
use std::io;
use std::io::Read;
use std::process;
use time::OffsetDateTime;

/// Human-readable presentation of a verified OPP presence document.
fn render(
    subject: &str,
    public_key: &str,
    issued_at: &str,
    expires_at: Option<&str>,
    services: &[opp_core::ServiceObject],
) {
    println!("Open Presence Protocol\n");
    println!("Status: VERIFIED\n");

    println!("Subject");
    println!("{subject}\n");

    println!("Public Key");
    println!("{public_key}\n");

    println!("Valid From");
    println!("{issued_at}\n");

    if let Some(expires) = expires_at {
        println!("Valid Until");
        println!("{expires}\n");
    }

    if !services.is_empty() {
        println!("Services");
        for svc in services {
            println!("\n{}", svc.service_type);
            println!("{}", svc.url);
        }
        println!();
    }
}

/// Read input from a file or stdin.
fn read_input(path: Option<&str>) -> Vec<u8> {
    match path {
        Some(p) => std::fs::read(p).unwrap_or_else(|e| {
            eprintln!("Error: cannot read '{p}': {e}");
            process::exit(1);
        }),
        None => {
            let mut buf = Vec::new();
            io::stdin()
                .lock()
                .read_to_end(&mut buf)
                .unwrap_or_else(|e| {
                    eprintln!("Error: failed to read stdin: {e}");
                    process::exit(1);
                });
            buf
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 2 {
        eprintln!("Error: unexpected extra arguments (expected at most one file path)");
        process::exit(2);
    }
    let doc_path = args.get(1).map(|s| s.as_str());

    let doc_bytes = read_input(doc_path);

    let context = VerificationContext {
        verification_time: OffsetDateTime::now_utc(),
    };

    match verify(&doc_bytes, &context) {
        Ok(verified) => {
            let doc = verified.document();
            render(
                &doc.subject,
                &doc.public_key,
                &doc.issued_at,
                doc.expires_at.as_deref(),
                &doc.services,
            );
            process::exit(0);
        }
        Err(e) => {
            eprintln!("Verification failed: {e}");
            process::exit(1);
        }
    }
}
