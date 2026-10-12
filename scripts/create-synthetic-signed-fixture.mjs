import { generateKeyPairSync, sign } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { signatureDigest } from "./signature-profile.mjs";

// Regenerates only fictional test data. The private key remains in memory and
// is discarded when the process exits. Do not use this key for a real card.
const cardPath = new URL("../examples/synthetic-borescope-finding.json", import.meta.url);
const publicPath = new URL("../fixtures/synthetic-public-key.pub", import.meta.url);
const card = JSON.parse(readFileSync(cardPath, "utf8"));
const { privateKey, publicKey } = generateKeyPairSync("ed25519");
card.signature.signature_b64url = sign(null, signatureDigest(card), privateKey).toString("base64url");
writeFileSync(cardPath, `${JSON.stringify(card, null, 2)}\n`);
writeFileSync(publicPath, publicKey.export({ type: "spki", format: "pem" }));
process.stdout.write("Regenerated fictional signed fixture and public key; no private key written.\n");
