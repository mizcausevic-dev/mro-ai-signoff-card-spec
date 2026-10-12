# MRO AI Sign-off Card v0.1 specification

**Status:** draft. **Wire version:** `0.1`. **License:** MIT.

The key words **MUST**, **MUST NOT**, **SHOULD**, and **MAY** describe this draft format. They do not restate aviation regulatory requirements.

## 1. Scope

One card travels with one AI-assisted maintenance finding and its exact source artifact. It records what the model reported, which artifact was inspected, what a human decided about that *finding*, and a signature over the record. A card is **not** a return-to-service authorization, airworthiness determination, maintenance release, certification artifact, or substitute for regulated records. The reviewer's identity and privileges must be established outside the card.

## 2. Required data

| Field | Meaning |
|---|---|
| `mro_signoff_card_version` | The literal string `"0.1"`. |
| `finding.{id,kind,summary,model_id,model_version,confidence}` | Publisher's finding and model provenance. `confidence` is a number from 0 through 1 and is not calibrated probability by this format. |
| `artifact.{id,sha256}` | Stable artifact identifier and lowercase hex SHA-256 of the original, exact artifact bytes. |
| `evidence_refs[]` | One or more HTTPS pointers to supporting material. Pointers are not verified evidence. |
| `human_review.{staff_id,decision,reviewed_at,authority_ref}` | Pseudonymous reviewer identifier, finding disposition, timestamp, and external authority-record pointer. |
| `signature.{profile,key_id,signed_at,signature_b64url}` | Signing profile, external key identifier, timestamp, and Ed25519 signature. |

If `finding.kind="other"`, `kind_other_text` **MUST** be present. If `human_review.decision="override"`, `override_reason` **MUST** be present. `override_reason` **MUST NOT** be supplied for another decision. `signature.signed_at` **MUST NOT** precede `human_review.reviewed_at`. The schema checks shape and the local validator checks the last two semantic rules.

## 3. Artifact and signature binding

The artifact digest is computed over the original byte stream, without newline conversion or other normalization. `byte_length`, when provided, is the length of that stream in bytes. A verifier **MUST** independently fetch or receive those bytes through an authorized channel and recompute the digest; the schema cannot establish that the artifact exists or is authentic.

`signature.profile` **MUST** equal `JCS-SHA256-Ed25519-v1` in this version. For signing, remove **only** `signature.signature_b64url`, then serialize the complete remaining JSON value using [RFC 8785 JSON Canonicalization Scheme](https://www.rfc-editor.org/rfc/rfc8785) and UTF-8. Compute SHA-256 of the canonical bytes. Use Ed25519 to sign those 32 digest bytes; encode the resulting 64-byte signature as unpadded base64url in `signature.signature_b64url`. The signed payload includes the signature profile, key ID, and signing timestamp. Consumers **MUST** reject duplicate JSON member names and values outside I-JSON before canonicalization.

A verifier **MUST** obtain the public key through an independently trusted key registry, bind it to the expected `key_id`, and check validity and revocation at the relevant time. An embedded or self-declared public key is not accepted as a trust anchor. `scripts/signature-profile.mjs` exposes `verifyCardSignatureRaw(raw, trustedKeyRecord)` for untrusted wire bytes; it rejects invalid UTF-8, duplicate keys, unsafe integer *literals*, non-finite numbers, and nonzero numbers that underflow to zero before canonicalization. Finite exponent notation such as RFC 8785's `1E30` remains valid. Its parsed-object helper is only safe after equivalent raw checks. The local test key record demonstrates key-ID binding but is not an operational registry. Cryptographic verification, reviewer identity, reviewer authorization, finding disposition, and maintenance-release authorization are separate outcomes. A passing signature **MUST NOT** be presented as proof of any of the latter three.

## 4. Security and privacy

All referenced URIs are untrusted input. Shape validation **MUST NOT** fetch them; tools that fetch records need independent SSRF controls, request size limits, timeouts, and permission checks. Public examples **MUST NOT** expose aircraft identifiers, actual staff personal data, export-controlled technical data, or unreleased findings. Real card distribution and retention must follow the operator's record-control and privacy policies.

## 5. Interoperability and versioning

`finding.model_id` and `finding.model_version` may match an Aviation ML Assurance Card's `system.id` and `system.version`; the relationship is a publisher assertion until checked against trusted records. A buyer may reference the card from a Procurement Decision Card. A breaking wire change requires a new `mro_signoff_card_version` and signature profile review.
