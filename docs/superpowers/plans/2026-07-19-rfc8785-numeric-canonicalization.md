# RFC 8785 Numeric Canonicalization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Serialize every accepted JSON number with RFC 8785 ECMAScript semantics while rejecting integer tokens outside the exact JavaScript safe-integer range.

**Architecture:** Preserve the existing recursive canonicalizer and replace only `write_number`. Classify integer-backed `serde_json::Number` values for range validation, convert every accepted value to finite `f64`, and format it through `ryu_js::Buffer`. Drive conformance from a reusable JSON file containing the RFC 8785 Appendix B IEEE-754 bit patterns and expected output.

**Tech Stack:** Rust 2021, `serde_json`, `ryu-js` 1.0, Cargo workspace tests.

## Global Constraints

- Keep the existing OPP canonicalizer in place.
- Preserve object ordering, string escaping, array handling, literal serialization, and whitespace behavior.
- Route every accepted JSON number, including integers, through `ryu-js`.
- Reject integer tokens outside `-9007199254740991..=9007199254740991`.
- Reject NaN and positive or negative infinity.
- Include every RFC 8785 Appendix B row as a language-neutral test vector.
- Do not add a custom floating-point formatter or replace the complete canonicalizer.

---

### Task 1: RFC 8785 Number Serialization

**Files:**
- Create: `vectors/rfc8785-number-serialization.json`
- Modify: `crates/opp-core/src/canonicalize.rs`
- Modify: `crates/opp-core/Cargo.toml`
- Modify: `README.md`
- Modify: `vectors/README.md`

**Interfaces:**
- Consumes: `serde_json::Number::{as_i64, as_u64, as_f64}` and `ryu_js::Buffer::format(f64)`.
- Produces: unchanged `canonicalize(value: &serde_json::Value) -> Result<Vec<u8>, String>` behavior with RFC 8785-compliant numeric output and explicit unsafe-integer rejection.

- [ ] **Step 1: Add the language-neutral RFC vectors**

Create `vectors/rfc8785-number-serialization.json`:

```json
{
  "source": "RFC 8785 Appendix B",
  "cases": [
    { "ieee754": "0000000000000000", "expected": "0", "comment": "Zero" },
    { "ieee754": "8000000000000000", "expected": "0", "comment": "Minus zero" },
    { "ieee754": "0000000000000001", "expected": "5e-324", "comment": "Min positive number" },
    { "ieee754": "8000000000000001", "expected": "-5e-324", "comment": "Min negative number" },
    { "ieee754": "7fefffffffffffff", "expected": "1.7976931348623157e+308", "comment": "Max positive number" },
    { "ieee754": "ffefffffffffffff", "expected": "-1.7976931348623157e+308", "comment": "Max negative number" },
    { "ieee754": "4340000000000000", "expected": "9007199254740992", "comment": "Max positive integer sample" },
    { "ieee754": "c340000000000000", "expected": "-9007199254740992", "comment": "Max negative integer sample" },
    { "ieee754": "4430000000000000", "expected": "295147905179352830000", "comment": "Approximately 2^68" },
    { "ieee754": "7fffffffffffffff", "expected": null, "comment": "NaN" },
    { "ieee754": "7ff0000000000000", "expected": null, "comment": "Infinity" },
    { "ieee754": "fff0000000000000", "expected": null, "comment": "Negative infinity" },
    { "ieee754": "44b52d02c7e14af5", "expected": "9.999999999999997e+22" },
    { "ieee754": "44b52d02c7e14af6", "expected": "1e+23" },
    { "ieee754": "44b52d02c7e14af7", "expected": "1.0000000000000001e+23" },
    { "ieee754": "444b1ae4d6e2ef4e", "expected": "999999999999999700000" },
    { "ieee754": "444b1ae4d6e2ef4f", "expected": "999999999999999900000" },
    { "ieee754": "444b1ae4d6e2ef50", "expected": "1e+21" },
    { "ieee754": "3eb0c6f7a0b5ed8c", "expected": "9.999999999999997e-7" },
    { "ieee754": "3eb0c6f7a0b5ed8d", "expected": "0.000001" },
    { "ieee754": "41b3de4355555553", "expected": "333333333.3333332" },
    { "ieee754": "41b3de4355555554", "expected": "333333333.33333325" },
    { "ieee754": "41b3de4355555555", "expected": "333333333.3333333" },
    { "ieee754": "41b3de4355555556", "expected": "333333333.3333334" },
    { "ieee754": "41b3de4355555557", "expected": "333333333.33333343" },
    { "ieee754": "becbf647612f3696", "expected": "-0.0000033333333333333333" },
    { "ieee754": "43143ff3c1cb0959", "expected": "1424953923781206.2", "comment": "Round to even" }
  ]
}
```

- [ ] **Step 2: Replace the obsolete float-rejection test with failing conformance tests**

In `crates/opp-core/src/canonicalize.rs`, add test-only vector types and replace `test_canonicalize_rejects_float`:

```rust
    #[derive(serde::Deserialize)]
    struct NumberVectors {
        cases: Vec<NumberVector>,
    }

    #[derive(serde::Deserialize)]
    struct NumberVector {
        ieee754: String,
        expected: Option<String>,
        #[serde(default)]
        comment: String,
    }

    #[test]
    fn test_rfc8785_appendix_b_number_serialization() {
        let vectors: NumberVectors = serde_json::from_str(include_str!(
            "../../../vectors/rfc8785-number-serialization.json"
        ))
        .unwrap();

        for case in vectors.cases {
            let bits = u64::from_str_radix(&case.ieee754, 16).unwrap();
            let number = serde_json::Number::from_f64(f64::from_bits(bits));

            match case.expected {
                Some(expected) => {
                    let value = Value::Number(number.unwrap());
                    let actual = String::from_utf8(canonicalize(&value).unwrap()).unwrap();
                    assert_eq!(actual, expected, "{} ({})", case.ieee754, case.comment);
                }
                None => assert!(
                    number.is_none(),
                    "{} ({}) must not be representable as JSON",
                    case.ieee754,
                    case.comment
                ),
            }
        }
    }

    #[test]
    fn test_canonicalize_all_numeric_forms() {
        let value: Value = serde_json::from_str(
            r#"[-0,1,-1,1.5,-1.5,0.1,0.01,0.001,1e30,1e-30,9007199254740991,-9007199254740991]"#,
        )
        .unwrap();

        let result = String::from_utf8(canonicalize(&value).unwrap()).unwrap();

        assert_eq!(
            result,
            "[0,1,-1,1.5,-1.5,0.1,0.01,0.001,1e+30,1e-30,9007199254740991,-9007199254740991]"
        );
    }

    #[test]
    fn test_canonicalize_rejects_integers_outside_safe_range() {
        for input in ["9007199254740992", "-9007199254740992"] {
            let value: Value = serde_json::from_str(input).unwrap();
            let error = canonicalize(&value).unwrap_err();
            assert!(error.contains("safe integer range"), "{input}: {error}");
        }
    }
```

- [ ] **Step 3: Run the focused tests and verify RED**

Run:

```bash
cargo test -p opp-core canonicalize::tests -- --nocapture
```

Expected: `test_rfc8785_appendix_b_number_serialization` and `test_canonicalize_all_numeric_forms` fail because the current implementation rejects fractional values; `test_canonicalize_rejects_integers_outside_safe_range` fails because the current code accepts those integers.

- [ ] **Step 4: Add the formatter dependency**

Add to `[dependencies]` in `crates/opp-core/Cargo.toml`:

```toml
ryu-js = "1.0"
```

Then run:

```bash
cargo check -p opp-core
```

Expected: PASS and `Cargo.lock` records the resolved `ryu-js` release.

- [ ] **Step 5: Implement the minimal numeric serialization change**

Replace `write_number` and its obsolete documentation in `crates/opp-core/src/canonicalize.rs` with:

```rust
/// Serialize a JSON number with ECMAScript `Number.toString()` semantics.
fn write_number(w: &mut Vec<u8>, n: &serde_json::Number) -> Result<(), std::io::Error> {
    const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

    if n.as_i64().is_some_and(|value| value.unsigned_abs() > MAX_SAFE_INTEGER)
        || n.as_u64().is_some_and(|value| value > MAX_SAFE_INTEGER)
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "integer numeric value is outside the IEEE-754 safe integer range",
        ));
    }

    let value = n.as_f64().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "numeric value cannot be represented as an IEEE-754 double",
        )
    })?;

    if !value.is_finite() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "non-finite numeric values are not permitted by RFC 8785",
        ));
    }

    let mut buffer = ryu_js::Buffer::new();
    w.write_all(buffer.format(value).as_bytes())
}
```

- [ ] **Step 6: Run focused tests and verify GREEN**

Run:

```bash
cargo test -p opp-core canonicalize::tests -- --nocapture
```

Expected: all canonicalizer unit tests PASS, including all Appendix B finite serialization rows, non-finite rejection vectors, numeric forms, and unsafe-integer rejection.

- [ ] **Step 7: Update user-facing documentation**

Replace the README `### Limitations` section with:

```markdown
### Numeric canonicalization

JSON numbers are canonicalized according to RFC 8785 using ECMAScript-compatible IEEE-754 double serialization. Integer tokens must be within JavaScript's exact safe-integer range (`-9007199254740991` through `9007199254740991`); larger integer values should be represented as JSON strings.
```

Add to `vectors/README.md` under `## Using These Vectors`:

```markdown
`rfc8785-number-serialization.json` contains the RFC 8785 Appendix B IEEE-754 number serialization cases. An `expected` value of `null` identifies a non-finite value that JSON and RFC 8785 require implementations to reject.
```

- [ ] **Step 8: Run complete verification**

Run:

```bash
cargo test --workspace
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
git diff --check
```

Expected: every command exits successfully with no warnings or formatting errors.

- [ ] **Step 9: Commit the implementation**

```bash
git add Cargo.lock crates/opp-core/Cargo.toml crates/opp-core/src/canonicalize.rs README.md vectors/README.md vectors/rfc8785-number-serialization.json
git commit -m "feat: implement RFC 8785 number serialization"
```
