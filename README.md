# MRO AI Sign-off Card

**Draft v0.1, MIT.** A per-finding record for human review of an AI-assisted maintenance observation. It extends the [Kinetic Gain Protocol Suite](https://github.com/mizcausevic-dev/kinetic-gain-protocol-suite) alongside the [Aviation ML Assurance Card](https://github.com/mizcausevic-dev/aviation-ml-assurance-card-spec).

The card binds a model finding to the SHA-256 digest of the exact source artifact, evidence references, a reviewer decision, and a cryptographic signature. A valid signature proves that a holder of a trusted key signed the card's bytes. It does **not** prove the reviewer's identity, current authorization, the accuracy of the observation, or authority to return an aircraft to service.

## Quickstart

1. Author a JSON card against [mro-ai-signoff-card.schema.json](mro-ai-signoff-card.schema.json). The [signed fictional example](examples/synthetic-borescope-finding.json) is only a format and test fixture.
2. Run `npm ci` and `npm test`. The test checks schema semantics, strict raw JSON parsing, exact fixture-byte hashing, a known-positive Ed25519 signature, tamper rejection, and known-invalid controls.
3. For a real record, hash the original artifact bytes without text normalization. Sign the JCS-canonicalized card excluding only `signature.signature_b64url` with the `JCS-SHA256-Ed25519-v1` profile. Obtain the reviewer public key and authority status from separately trusted systems.

`scripts/create-synthetic-signed-fixture.mjs` can regenerate the fictional example and public key for local development. It creates a fresh ephemeral private key in memory and writes **no private key**. Regeneration changes the committed example and is not a production signing procedure.

## Files

- [SPEC.md](SPEC.md): wire contract, signing profile, trust boundaries, and privacy rules.
- [mro-ai-signoff-card.schema.json](mro-ai-signoff-card.schema.json): strict JSON Schema 2020-12 shape.
- [examples/](examples/): fictional signed and intentionally invalid records.
- [fixtures/](fixtures/): fictional artifact bytes, public verification key, and a test-only key-ID binding record. No private key is stored.
- [docs/ORIGIN.md](docs/ORIGIN.md): design rationale and limitations.

## Relationship to the Suite

This is a per-artifact human review record. A vendor's overall ML posture belongs in an Aviation ML Assurance Card; a buyer's procurement decision belongs in a Procurement Decision Card. An AI Incident Card may link a finding URI. None of these cards executes a safety function or substitutes for the operator's maintenance records and legally required release process.

The corresponding `mcp-kinetic-gain` tools and public Suite pages should be described as available only after their own reviewed release and live verification. This repository does not change the published MCP package.

## Status and license

This is a draft format, not an EASA, FAA, SAE, EUROCAE, or NIST standard. The text, schema, examples, and local validation code are [MIT-licensed](LICENSE). All example people, keys, models, findings, and artifacts are fictional. No real aircraft or patient data belongs in this repository.
