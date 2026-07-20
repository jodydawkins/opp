# Publish Your First OPP Presence

This guide walks you through creating, signing, publishing, and verifying an Open Presence Protocol presence document.

When you are finished, you will have a cryptographically signed presence declaration hosted at a public URL under your control.

OPP does not require an account, a particular hosting provider, or the reference OPP directory. Your independently hosted document is the source of your presence declaration.

## What You Will Need

You will need:

- Git
- Rust and Cargo
- A place where you can publish a static JSON file over HTTPS

Your website, GitHub Pages, Cloudflare Pages, an object-storage service, or a conventional web server can host the document.

## Build the OPP Command-Line Tool

Clone the reference implementation:

```shell
git clone https://github.com/jodydawkins/opp.git
cd opp
```

Build the release version:

```shell
cargo build --workspace --release
```

The executable will be located at:

```text
target/release/opp
```

The examples below use `./target/release/opp`. You may instead install or copy the executable somewhere on your `PATH` and invoke it as `opp`.

## Create a Working Directory

Create a separate directory for your keys and presence document:

```shell
mkdir my-opp-presence
cd my-opp-presence
```

For the remaining examples, adjust the path to the `opp` executable as needed.

## Generate an OPP Key Pair

Generate an Ed25519 private key and public key:

```shell
../target/release/opp key generate \
  --private-key private.key \
  --public-key public.key
```

The command writes the two keys to files and prints the derived subject:

```text
subject: key:sha256:...
```

Save that subject. You will place it in your presence document.

Your public key is stored in `public.key`. Display it with:

```shell
cat public.key
```

The value is an unpadded Base64url-encoded Ed25519 public key. You will also place this value in your presence document.

Your private key controls your OPP identity.

Do not share `private.key`, upload it to a website, or commit it to source control. OPP 0.1 does not define key recovery or rotation. If you lose the private key, you will no longer be able to sign updated documents for this subject.

## Create an Unsigned Presence Document

Create a file named `presence-unsigned.json`:

```json
{
  "type": "open-presence",
  "version": "0.1",
  "subject": "key:sha256:REPLACE_WITH_YOUR_SUBJECT",
  "public_key": "REPLACE_WITH_YOUR_PUBLIC_KEY",
  "issued_at": "REPLACE_WITH_CURRENT_UTC_TIMESTAMP",
  "services": [
    {
      "type": "profile",
      "url": "https://example.com/about"
    },
    {
      "type": "feed",
      "url": "https://example.com/feed.xml"
    }
  ]
}
```

Replace the example values with:

- The subject printed when you generated the key pair
- The public key stored in `public.key`
- The current UTC date and time
- The public service endpoints you want to declare

The `issued_at` value must be an RFC 3339 timestamp expressed in UTC with the `Z` suffix, such as `2026-07-20T05:30:00Z`.

Every service must contain a string-valued `type` and an absolute HTTPS `url`.

OPP 0.1 suggests these general service types:

- `profile`
- `feed`
- `inbox`
- `media`
- `verification`
- `presence`

Applications may define additional service types. Prefer general descriptions of what an endpoint provides rather than names tied to a particular platform.

Do not add a `signature` member to the unsigned document. The OPP command-line tool adds it when signing.

### Optional Expiration

You may add an `expires_at` field:

```json
"expires_at": "2027-07-20T05:30:00Z"
```

It must be later than `issued_at` and must also be an RFC 3339 UTC timestamp using the `Z` suffix.

Expiration is optional. Once an expiring document reaches that time, OPP verification will reject it until you publish a newly signed document.

## Sign the Presence Document

Sign the unsigned document with your private key:

```shell
../target/release/opp sign presence-unsigned.json \
  --private-key private.key \
  --output presence.json
```

The command validates the unsigned document, canonicalizes it using the JSON Canonicalization Scheme, signs it with Ed25519, and writes the completed document to `presence.json`.

The signed document will contain a signature object resembling:

```json
"signature": {
  "algorithm": "ed25519",
  "value": "..."
}
```

Do not edit the signed document manually. Changing any signed field will invalidate the signature.

When you need to make a change, edit the unsigned source document and sign it again.

## Verify the Document Locally

Verify the completed document before publishing it:

```shell
../target/release/opp verify presence.json
```

A successful verification prints:

```text
valid
```

Verification checks the document structure, version, subject, public key, timestamps, service URLs, and cryptographic signature.

A document that fails verification must not be trusted.

## Publish the Document

Upload `presence.json` to a publicly accessible HTTPS URL under your control.

A conventional location on a personal domain is:

```text
https://example.com/.opp/presence.json
```

This location is a useful convention, not a requirement of the OPP 0.1 core specification. OPP documents are transport-agnostic, and the protocol does not mandate a particular URL path or hosting provider.

Publish only the signed `presence.json` file.

Never publish `private.key`.

You may keep `presence-unsigned.json` and `public.key` privately or in source control if that fits your workflow. The private key must remain secret.

## Retrieve and Verify the Published Document

Download the document from its public location:

```shell
curl https://example.com/.opp/presence.json \
  --output downloaded-presence.json
```

Verify the downloaded copy:

```shell
../target/release/opp verify downloaded-presence.json
```

The result should be:

```text
valid
```

This final check proves that the file being served publicly is the same valid signed declaration you intended to publish.

## What Verification Establishes

Successful verification establishes that:

- The document conforms to the supported OPP format
- The subject was correctly derived from the included public key
- The document was signed by the corresponding private key
- The signed fields have not been changed
- The document is currently within its declared validity period
- Its declared service locations are absolute HTTPS URLs

Verification does not establish that every claim made by a service endpoint is true. It establishes which cryptographic identity signed the presence declaration.

## Publication and Discovery Are Different

Publishing makes your presence document retrievable from a public location.

Discovery helps an application find that location from a subject or another supported identifier.

The OPP 0.1 core specification defines presence documents, signing, and verification. It does not define discovery. A directory can provide discovery by mapping a subject or supported identifier to the independently hosted document, but the directory does not own the presence declaration and directory resolution does not replace document verification.

You may share the document URL directly, register it with a compatible directory, or expose it through an application that understands OPP.

## You Have Published an OPP Presence

You now have:

- A cryptographic OPP subject
- A signed presence document
- An independently hosted declaration of your public service endpoints
- A document that any compatible implementation can retrieve and verify

Your presence remains under your control.

Follow people, not platforms.
