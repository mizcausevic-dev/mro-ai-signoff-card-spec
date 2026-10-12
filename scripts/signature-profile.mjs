import { createHash, verify } from "node:crypto";
import { parseJcsJsonStrict } from "./strict-json.mjs";

// RFC 8785 JCS uses ECMAScript primitive serialization and UTF-16 key ordering.
// Cards must be parsed from unique-key I-JSON before this function is called.
export function canonicalize(value) {
  if (value === null || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("Non-finite JSON number");
    return JSON.stringify(value);
  }
  if (typeof value === "string") {
    if (/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(value)) {
      throw new TypeError("Lone surrogate is not I-JSON");
    }
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  if (typeof value === "object" && value !== undefined && Object.getPrototypeOf(value) === Object.prototype) {
    return `{${Object.keys(value).sort().map((key) => `${canonicalize(key)}:${canonicalize(value[key])}`).join(",")}}`;
  }
  throw new TypeError("Value is not I-JSON");
}

export function signedPayload(card) {
  const payload = structuredClone(card);
  if (!payload.signature || typeof payload.signature !== "object") throw new TypeError("Missing signature envelope");
  delete payload.signature.signature_b64url;
  return Buffer.from(canonicalize(payload), "utf8");
}

export function signatureDigest(card) {
  return createHash("sha256").update(signedPayload(card)).digest();
}

// Only use this parsed-object helper after strict raw parsing. JSON.parse alone
// loses duplicate keys and may round unsafe integer literals before hashing.
export function verifyCardSignature(card, trustedKeyRecord) {
  if (card.signature?.profile !== "JCS-SHA256-Ed25519-v1") return false;
  if (!trustedKeyRecord?.publicKey || !trustedKeyRecord.keyId) return false;
  if (card.signature.key_id !== trustedKeyRecord.keyId) return false;
  const signature = Buffer.from(card.signature.signature_b64url, "base64url");
  if (signature.length !== 64) return false;
  return verify(null, signatureDigest(card), trustedKeyRecord.publicKey, signature);
}

export function verifyCardSignatureRaw(rawCard, trustedKeyRecord) {
  return verifyCardSignature(parseJcsJsonStrict(rawCard), trustedKeyRecord);
}
