# Open Presence Protocol (OPP)

**Version:** 0.1.0 (Draft)

# Status of This Document

This specification is a draft and is subject to change. It is intended to encourage experimentation and discussion. Implementers should expect incompatible changes before version 1.0.

---

# 1. Introduction

Open Presence Protocol (OPP) is an open, decentralized protocol for publishing and discovering the online presence of an identity.

An OPP document contains cryptographically verifiable claims about the public endpoints associated with an identity, enabling applications and services to locate and interact with that identity without relying on a central authority.

OPP intentionally does not define identity, content, messaging, or social networking. Those concerns are left to other protocols and applications.

By remaining small, focused, and composable, OPP serves as a common foundation upon which interoperable services can be built.

---

# 2. Scope

The Open Presence Protocol defines a standard format for publishing signed presence declarations.

An OPP document answers one question:

> **Where can this identity be found?**

An OPP document does **not** answer:

- Who is this identity?
- What content has this identity published?
- How should messages be delivered?
- How should applications present or consume content?

---

# 3. Design Principles

OPP is designed around the following principles:

- Solve one problem well.
- Be decentralized.
- Be cryptographically verifiable.
- Remain platform-neutral.
- Remain transport-agnostic.
- Compose with other protocols.
- Prefer simplicity over completeness.

Features that do not directly contribute to expressing or verifying online presence should be implemented by other protocols.

---

# 4. Presence Document

An OPP presence document is a JSON object.

## Required Fields

| Field | Description |
|--------|-------------|
| `type` | Must be `"open-presence"` |
| `version` | OPP specification version |
| `subject` | Stable identifier for the identity |
| `public_key` | Public key corresponding to the signing key |
| `issued_at` | ISO-8601 timestamp indicating creation time |
| `services` | Array of public service endpoints |
| `signature` | Cryptographic signature over the document |

## Optional Fields

| Field | Description |
|--------|-------------|
| `expires_at` | Time after which consumers should no longer trust the document |

---

# 5. Service Objects

Each service entry represents one publicly accessible endpoint associated with the identity.

Minimum structure:

```json
{
  "type": "profile",
  "url": "https://example.com/profile"
}
```

## Required Fields

| Field | Description |
|--------|-------------|
| `type` | Generic service type |
| `url` | Public endpoint |

## Suggested Initial Types

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
  "type": "open-presence",
  "version": "0.1",
  "subject": "key:sha256:9b7e3e8b...",
  "public_key": "MCowBQYDK2VwAyEA...",
  "issued_at": "2026-07-09T04:00:00Z",
  "expires_at": "2026-10-09T04:00:00Z",
  "services": [
    {
      "type": "profile",
      "url": "https://example.com/jody"
    },
    {
      "type": "feed",
      "url": "https://example.com/jody/feed.json"
    },
    {
      "type": "inbox",
      "url": "https://example.com/inbox"
    }
  ],
  "signature": {
    "algorithm": "ed25519",
    "value": "base64-signature"
  }
}
```

---

# 7. Verification

Consumers SHOULD verify:

- The document is valid JSON.
- `type` equals `"open-presence"`.
- The signature is valid.
- The signature matches the supplied public key.
- The public key corresponds to the subject.
- The document has not expired.
- Service URLs are syntactically valid.

Consumers MAY ignore services they do not recognize.

---

# 8. Identity

OPP does not define identity.

The `subject` field represents a stable identifier controlled by the signing key.

Future versions of OPP may support additional identity systems such as Decentralized Identifiers (DIDs), provided they remain compatible with the protocol's design goals.

---

# 9. Content Boundary

Presence documents MUST NOT contain:

- Posts
- Articles
- Images
- Videos
- Comments
- Reactions
- Social graph information
- Messaging content

Such information belongs to higher-level protocols and applications.

---

# 10. Key Recovery

OPP version 0.1 does not define identity recovery.

If a private key is lost, the corresponding identity can no longer issue valid presence documents.

Future protocols or identity systems may define mechanisms for key rotation or identity recovery.

---

# 11. Extensibility

Future versions of OPP may define:

- Additional service types
- Alternative identity schemes
- Key rotation
- Recovery mechanisms
- Service discovery
- Additional signature algorithms

These extensions should preserve backward compatibility whenever practical.

---

# 12. Philosophy

The Open Presence Protocol exists to let any identity publish its online presence in a simple, verifiable, decentralized way.

It intentionally does not define identity, content, messaging, or social networking.

By remaining small, focused, and composable, OPP provides a common foundation upon which an open ecosystem of interoperable services can be built.