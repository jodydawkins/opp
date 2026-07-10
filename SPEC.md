# Open Presence Protocol (OPP)

**Version:** 0.1 (Draft)

# Status of This Document

This specification is a draft and is subject to change. It is intended to encourage experimentation and discussion. Implementers should expect incompatible changes before version 1.0.

---

# 1. Introduction

Open Presence Protocol (OPP) is an open, decentralized protocol for publishing cryptographically verifiable presence declarations.

An OPP document contains signed claims about the public service endpoints associated with an identity, allowing applications to verify where an identity may be found without relying on a central authority.

OPP intentionally does not define identity, messaging, content distribution, or social networking. Those concerns belong to higher-level protocols.

---

# 2. Scope

OPP version 0.1 specifies:

- The structure of a presence document.
- How a presence document is signed.
- How a presence document is verified.

An OPP document answers one question:

> **Where can this identity be found?**

Version 0.1 intentionally does not define:

- Identity recovery
- Key rotation
- Federation
- Replication
- Discovery
- Search
- Private presence documents
- Access control
- Messaging
- Content distribution

---

# 3. Design Principles

- Solve one problem well.
- Be decentralized.
- Be cryptographically verifiable.
- Remain platform-neutral.
- Remain transport-agnostic.
- Compose with other protocols.
- Prefer simplicity over completeness.

---

# 4. Presence Document

An OPP presence document is a JSON object.

Required fields:

| Field | Description |
|---|---|
| type | Must equal `"open-presence"` |
| version | Protocol version |
| subject | Stable identifier derived from the public key |
| public_key | Ed25519 public key encoded using unpadded Base64url |
| issued_at | ISO-8601 UTC timestamp |
| services | Array of service objects |
| signature | Signature object |

Optional fields:

| Field | Description |
|---|---|
| expires_at | Expiration timestamp |

---

# 5. Service Objects

Each service object represents one publicly accessible endpoint.

Minimum example:

```json
{
  "type": "profile",
  "url": "https://example.com/profile"
}
```

Required fields:

| Field | Description |
|---|---|
| type | Generic service type |
| url | Absolute HTTPS URL |

Suggested initial service types:

- profile
- feed
- inbox
- media
- verification
- presence

Applications may define additional service types.

---

# 6. Example Presence Document

```json
{
  "type":"open-presence",
  "version":"0.1",
  "subject":"key:sha256:abc123...",
  "public_key":"base64url-public-key",
  "issued_at":"2026-07-09T04:00:00Z",
  "expires_at":"2026-10-09T04:00:00Z",
  "services":[
    {
      "type":"profile",
      "url":"https://example.com/jody"
    }
  ],
  "signature":{
    "algorithm":"ed25519",
    "value":"base64url-signature"
  }
}
```

---

# 7. Signing and Serialization

The signature authenticates the entire presence document.

To produce a signature:

1. Remove the `signature` field.
2. Serialize the remaining document using RFC 8785 JSON Canonicalization Scheme (JCS).
3. Encode as UTF-8.
4. Sign using Ed25519.
5. Encode the signature using unpadded Base64url.
6. Store the signature in `signature.value`.

The signature object has the following form:

```json
{
  "algorithm":"ed25519",
  "value":"base64url-signature"
}
```

OPP v0.1 supports only Ed25519.

---

# 8. Subject Identifiers

The `subject` uniquely identifies the public key controlling the presence document.

Format:

```
key:sha256:<digest>
```

`<digest>` is the SHA-256 hash of the decoded Ed25519 public key encoded with unpadded Base64url.

Consumers MUST verify that the subject matches the supplied public key.

---

# 9. Verification

Consumers MUST verify:

- Valid JSON.
- Supported version.
- `type == "open-presence"`.
- Required fields are present.
- Public key encoding is valid.
- Subject matches the public key.
- Signature is valid.
- Signature verifies the canonicalized document.
- `issued_at` and `expires_at` are valid timestamps.
- Document has not expired.
- Every service URL is an absolute HTTPS URL.

Consumers MAY ignore unknown service types and unknown fields.

Consumers MUST NOT trust any document that fails verification.

---

# 10. Identity

OPP does not define identity.

It defines only how a cryptographic identity publishes a verifiable declaration of its public presence.

Alternative identity systems (such as DIDs) may be supported by future versions provided they remain compatible with this protocol.

---

# 11. Content Boundary

Presence documents MUST NOT contain:

- Posts
- Messages
- Images
- Videos
- Articles
- Comments
- Reactions
- Social graph information

Presence documents contain only routing information.

---

# 12. Key Recovery

Version 0.1 does not define key recovery or key rotation.

If a private key is lost, the associated identity can no longer publish updated presence documents.

Future specifications may define recovery mechanisms.

---

# 13. Extensibility

Future versions may define:

- Additional service types
- Additional signature algorithms
- Alternative identity systems
- Discovery mechanisms
- Federation
- Replication
- Key rotation
- Recovery

Extensions should preserve backward compatibility whenever practical.

---

# 14. Philosophy

The Open Presence Protocol exists to provide a simple, verifiable, decentralized foundation for publishing online presence.

It intentionally solves only one problem and is designed to be composed with higher-level protocols rather than replace them.
