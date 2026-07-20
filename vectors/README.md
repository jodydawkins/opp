# Test Vectors

This directory contains language-neutral test inputs and expected results for Open Presence Protocol (OPP) 0.1 implementations.

## Directory Structure

- `valid/` — Documents and inputs that must be accepted by a conforming implementation.
- `invalid/` — Documents and inputs that must be rejected, with expected error categories.

## Deterministic Test Vector

The deterministic test vector uses the following private-key seed (for testing only):

**Hex:** `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f`

**Unpadded Base64url:** `AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8`

**Expected public key (Base64url):** `A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg`

**Expected subject:** `key:sha256:Vkdap1RjR0wChd9dvyvKtz2mUTWIOem3dIGy6rEHcIw`

**Verification time for valid tests:** `2026-07-12T00:00:00Z`

## WARNING

The private key in this directory is for automated testing only. It MUST NOT be used for a real identity.

## Using These Vectors

`rfc8785-number-serialization.json` contains the RFC 8785 Appendix B IEEE-754 number serialization cases. An `expected` value of `null` identifies a non-finite value that JSON and RFC 8785 require implementations to reject.

Each file in `invalid/` is named to suggest the expected failure category. Implementations in other languages should:

1. Attempt to verify each file in `valid/` and confirm success.
2. Attempt to verify each file in `invalid/` and confirm the expected error category.
3. Reproduce the deterministic signing test vector exactly.
