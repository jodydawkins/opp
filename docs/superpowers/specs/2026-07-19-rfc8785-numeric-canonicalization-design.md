# RFC 8785 Numeric Canonicalization Design

## Goal

Implement issue #3 by making the Rust reference implementation serialize every JSON number according to RFC 8785 and ECMAScript `Number.toString()` semantics.

## Decision

Keep the existing OPP canonicalizer and make the smallest targeted change to its numeric branch. Add `ryu-js` to `opp-core` and route every accepted JSON number through its ECMAScript-compatible `f64` formatter. Do not replace the canonicalizer or implement a custom floating-point formatter.

## Numeric Input Rules

- Convert finite fractional and exponential JSON numbers to `f64` and serialize them with `ryu-js`.
- Enable `serde_json`'s `float_roundtrip` feature so decimal input is converted to the nearest IEEE-754 value before canonicalization.
- Convert integer-valued JSON numbers to `f64` and serialize them through the same `ryu-js` path.
- Accept integer tokens only in the inclusive safe-integer range `-9007199254740991..=9007199254740991` so the conversion cannot silently change their value.
- Reject integer tokens outside that range with a canonicalization error.
- Reject non-finite values if they reach the canonicalizer, although ordinary `serde_json` parsing already excludes NaN and infinities.
- Preserve ECMAScript behavior for negative zero, producing `0`.

## Existing Behavior Preserved

The change will not alter object member sorting, string escaping, array order, literal serialization, whitespace removal, signing, or verification. Numeric formatting remains an internal responsibility of `crates/opp-core/src/canonicalize.rs`.

## Conformance Vectors

Add a language-neutral JSON vector file under `vectors/` containing the RFC 8785 Appendix B finite IEEE-754 bit patterns and expected JSON representations. Rust tests will reconstruct each `f64` from its hexadecimal bit pattern, create a `serde_json::Number`, canonicalize it, and compare the exact output with the vector.

NaN and infinity rows from Appendix B will be represented as rejection cases because RFC 8785 does not permit them in JSON. Separate tests will cover safe-integer acceptance and rejection immediately outside the safe range.

These vectors encode expected results published by RFC 8785, which are independently defined by ECMAScript and suitable for reuse by Ruby and future implementations.

## Documentation

Remove the README limitation that says fractional values are rejected. Replace it with a statement that numeric canonicalization follows RFC 8785 using ECMAScript-compatible IEEE-754 serialization, with integer inputs restricted to the exact JavaScript safe-integer range.

## Verification

Use test-driven development:

1. Add conformance and unsafe-integer tests and confirm they fail against the current implementation.
2. Add `ryu-js` and implement the minimal numeric-path change.
3. Confirm the focused canonicalization tests pass.
4. Run the complete workspace tests, formatting check, and Clippy with warnings denied.
