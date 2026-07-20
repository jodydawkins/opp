# Open Presence Protocol (OPP)

**It's like DNS for people**

Open Presence Protocol (OPP) is an open, decentralized protocol for publishing and discovering the online presence of an identity.

An OPP document contains cryptographically verifiable claims about the public endpoints associated with an identity, enabling applications and services to locate and interact with that identity without relying on a central authority.

OPP intentionally does not define identity, content, messaging, or social networking. Those concerns are left to other protocols and applications.

Read the specification in [SPEC.md](SPEC.md).

New to OPP? Follow [Publish Your First OPP Presence](docs/PUBLISH-YOUR-FIRST-PRESENCE.md) to create, sign, host, and verify your first presence document.

## Reference Implementation

This repository contains the OPP 0.1 reference implementation in Rust.

### What it does

- Parses OPP presence documents with duplicate JSON member detection
- Validates required fields, types, timestamps, and service URLs
- Derives subject identifiers from Ed25519 public keys
- Serializes documents using RFC 8785 JSON Canonicalization Scheme
- Signs documents using Ed25519
- Verifies signed documents
- Provides a command-line interface for all operations

### What it deliberately does not do

- Discovery, federation, or replication
- Search or identity recovery
- Key rotation or content distribution
- Messaging or private presence documents
- Access control or persistent storage
- User accounts or web interface

### Numeric canonicalization

JSON numbers are canonicalized according to RFC 8785 using ECMAScript-compatible IEEE-754 double serialization. Integer tokens outside JavaScript's exact safe-integer range are rounded to the nearest representable double according to ECMAScript semantics.

## Building

### Prerequisites

Install Rust: https://rustup.rs/

### Build

```shell
cargo build --workspace --release
```

### Test

```shell
cargo test --workspace
```

### Lint

```shell
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
```

## Usage

The CLI executable is named `opp`.

### Generate a key pair

```shell
opp key generate
```

Write keys to files:

```shell
opp key generate --private-key private.key --public-key public.key
```

**WARNING:** The private key must be kept secret. Do not share it or commit it to source control.

### Derive a subject

```shell
opp subject derive --public-key A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg
```

Output:

```text
key:sha256:Vkdap1RjR0wChd9dvyvKtz2mUTWIOem3dIGy6rEHcIw
```

### Sign a document

```shell
opp sign presence.json --private-key private.key
```

Write to a file:

```shell
opp sign presence.json --private-key private.key --output signed-presence.json
```

### Verify a document

```shell
opp verify signed-presence.json
```

Successful output:

```text
valid
```

JSON output mode:

```shell
opp verify signed-presence.json --format json
```

Verify at a specific time:

```shell
opp verify signed-presence.json --at 2026-07-12T00:00:00Z
```

### Viewer

Build and run the terminal-based reference viewer:

```shell
cargo build -p opp-viewer
cat vectors/valid/signed-document.json | cargo run -p opp-viewer
```

The viewer reads a signed OPP presence document from standard input or a file path, verifies it using `opp-core`, and renders it in a human-readable format.

```shell
cargo run -p opp-viewer -- vectors/valid/signed-document.json
```

## Deterministic Test Vector

The following private-key seed is used for automated testing only. **It must never be used for a real identity.**

- **Private key seed (hex):** `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f`
- **Private key seed (Base64url):** `AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8`
- **Public key (Base64url):** `A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg`
- **Subject:** `key:sha256:Vkdap1RjR0wChd9dvyvKtz2mUTWIOem3dIGy6rEHcIw`

### Reproducing the test vector

```shell
# Write the deterministic private key
echo -n "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8" > test.key

# Derive the subject
opp subject derive --public-key A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg

# Sign the unsigned document
opp sign vectors/valid/unsigned-document.json --private-key test.key --output signed.json

# Verify (use --at to supply a verification time within the document's validity window)
opp verify signed.json --at 2026-07-12T00:00:00Z
```

## Test Vectors

The `vectors/` directory contains language-neutral test inputs:

- `vectors/valid/` — Documents that must be accepted
- `vectors/invalid/` — Documents that must be rejected

Other language implementations can reuse these files. See [vectors/README.md](vectors/README.md).

## Repository Structure

```text
opp/
├── Cargo.toml              # Workspace definition
├── crates/
│   ├── opp-core/           # Protocol implementation library
│   │   ├── Cargo.toml
│   │   ├── src/
│   │   └── tests/
│   └── opp-cli/            # CLI application
│       ├── Cargo.toml
│       └── src/
├── docs/                   # Publishing and usage guides
├── vectors/                # Language-neutral test vectors
│   ├── valid/
│   ├── invalid/
│   └── README.md
├── .github/workflows/      # CI configuration
├── SPEC.md                 # Protocol specification
└── README.md               # This file
```

## License

See [LICENSE](LICENSE).
