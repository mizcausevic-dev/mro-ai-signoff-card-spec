import { strict as assert } from "node:assert";
import { createHash, createPublicKey, generateKeyPairSync } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { canonicalize, verifyCardSignatureRaw } from "./signature-profile.mjs";
import { parseJcsJsonStrict } from "./strict-json.mjs";

const root = new URL("../", import.meta.url);
const schema = JSON.parse(readFileSync(new URL("mro-ai-signoff-card.schema.json", root), "utf8"));
const ajv = new Ajv2020({ allErrors: true, strict: true, strictRequired: false });
addFormats(ajv);
const validate = ajv.compile(schema);
const keyRecord = JSON.parse(readFileSync(new URL("fixtures/synthetic-trusted-key-record.json", root), "utf8"));
if (keyRecord.test_only !== true || keyRecord.public_key_file !== "synthetic-public-key.pub") {
  throw new Error("Synthetic trust fixture has unexpected contents");
}
const trustedKey = {
  keyId: keyRecord.key_id,
  publicKey: createPublicKey(readFileSync(new URL("fixtures/synthetic-public-key.pub", root), "utf8"))
};
const artifact = readFileSync(new URL("fixtures/synthetic-observation.json", root));

// RFC 8785 uses ECMAScript number serialization and UTF-16 key ordering.
assert.equal(canonicalize([333333333.33333329, 1e30, 4.50, 2e-3, 1e-27]), "[333333333.3333333,1e+30,4.5,0.002,1e-27]");
assert.equal(canonicalize({ "€": 1, "\r": 2, "😀": 3, "1": 4 }), '{"\\r":2,"1":4,"€":1,"😀":3}');
assert.throws(() => canonicalize("\ud800"), /Lone surrogate/);
process.stdout.write("VERIFIED JCS number serialization, UTF-16 key order, and lone-surrogate rejection\n");

const files = readdirSync(new URL("examples/", root)).filter((name) => name.endsWith(".json")).sort();
if (files.length === 0) throw new Error("No valid MRO examples found");
for (const file of files) {
  const raw = readFileSync(new URL(`examples/${file}`, root));
  const card = parseJcsJsonStrict(raw);
  if (!validate(card)) throw new Error(`${file}: ${ajv.errorsText(validate.errors)}`);
  if (card.human_review.decision !== "override" && card.human_review.override_reason !== undefined) {
    throw new Error(`${file}: override_reason supplied without an override decision`);
  }
  if (Date.parse(card.signature.signed_at) < Date.parse(card.human_review.reviewed_at)) {
    throw new Error(`${file}: signature predates human review`);
  }
  if (card.artifact.byte_length !== artifact.length) throw new Error(`${file}: fixture byte length mismatch`);
  if (card.artifact.sha256 !== createHash("sha256").update(artifact).digest("hex")) {
    throw new Error(`${file}: artifact digest mismatch`);
  }
  if (!verifyCardSignatureRaw(raw, trustedKey)) throw new Error(`${file}: signature verification failed`);
  process.stdout.write(`VALID and VERIFIED synthetic fixture examples/${file}\n`);
}

const invalid = JSON.parse(readFileSync(new URL("examples/invalid/unsigned.json", root), "utf8"));
if (validate(invalid)) throw new Error("Known-invalid unsigned fixture was accepted");
process.stdout.write("REJECTED known-invalid unsigned fixture\n");

const base = JSON.parse(readFileSync(new URL(`examples/${files[0]}`, root), "utf8"));
for (const [label, change] of [
  ["artifact digest tampering", (card) => { card.artifact.sha256 = "0".repeat(64); }],
  ["human decision tampering", (card) => { card.human_review.decision = "reject"; }],
  ["signature timestamp tampering", (card) => { card.signature.signed_at = "2026-10-12T14:02:00Z"; }]
]) {
  const altered = structuredClone(base);
  change(altered);
  if (!validate(altered)) throw new Error(`${label}: control unexpectedly schema-invalid`);
  if (verifyCardSignatureRaw(JSON.stringify(altered), trustedKey)) throw new Error(`${label}: tampered card verified`);
  process.stdout.write(`REJECTED ${label}\n`);
}

const override = structuredClone(base);
override.human_review.decision = "override";
delete override.human_review.override_reason;
if (validate(override)) throw new Error("Override without reason was accepted");
process.stdout.write("REJECTED override without reason\n");

if (verifyCardSignatureRaw(JSON.stringify(base), null)) throw new Error("Signature verified without a trusted key");
process.stdout.write("REJECTED signature without external trust anchor\n");

const unrelatedKey = { keyId: trustedKey.keyId, publicKey: generateKeyPairSync("ed25519").publicKey };
if (verifyCardSignatureRaw(JSON.stringify(base), unrelatedKey)) throw new Error("Signature verified with an unrelated key");
process.stdout.write("REJECTED signature with unrelated key\n");

const wrongKeyId = { keyId: "unrelated-reviewer-key", publicKey: trustedKey.publicKey };
if (verifyCardSignatureRaw(JSON.stringify(base), wrongKeyId)) throw new Error("Signature verified with an unbound key identifier");
process.stdout.write("REJECTED signature with mismatched trusted key ID\n");

const duplicateDecision = readFileSync(new URL(`examples/${files[0]}`, root), "utf8")
  .replace('"decision": "accept"', '"decision": "accept", "decision": "reject"');
assert.throws(() => verifyCardSignatureRaw(duplicateDecision, trustedKey), /Duplicate JSON object key/);
assert.throws(() => parseJcsJsonStrict('{"decision":1,"deci\\u0073ion":2}'), /Duplicate JSON object key/);
assert.throws(() => parseJcsJsonStrict('{"n":9007199254740993}'), /unsafe I-JSON number/);
assert.throws(() => parseJcsJsonStrict('{"n":1e400}'), /Non-finite or unsafe I-JSON number/);
assert.throws(() => parseJcsJsonStrict(Buffer.from([0xff])), /encoded|encoding/i);
assert.throws(() => parseJcsJsonStrict(Buffer.from([0xef, 0xbb, 0xbf, 0x7b, 0x7d])), /BOM/);
process.stdout.write("REJECTED duplicate keys, unsafe integers, and non-finite numeric literals before signature verification\n");

const backwardsTime = structuredClone(base);
backwardsTime.signature.signed_at = "2026-10-12T13:59:00Z";
if (!validate(backwardsTime)) throw new Error("Backwards-time control unexpectedly schema-invalid");
if (Date.parse(backwardsTime.signature.signed_at) >= Date.parse(backwardsTime.human_review.reviewed_at)) {
  throw new Error("Backwards-time control was accepted");
}
process.stdout.write("REJECTED signature timestamp before review\n");
