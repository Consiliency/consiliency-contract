// Authority-event contract: canonical signed-core bytes + Ed25519 verification.
//
// This is the ROOT OF TRUST reference implementation for the JS side. It is
// dependency-free (Node >=18 `node:crypto` only) so the governed-pipeline (gp)
// gate can verify an authority event without ICU/Unicode-16 canon or any npm
// dependency.
//
// CANON OWNERSHIP: the signed-core bytes ARE spec canon-core v2
// `canonical_bytes(core)` (NOT a new/4th canon). `canonicalizeCore` here is a
// metadata-safe-ASCII / integer-only PORT of that one normative algorithm — the
// AUTHORITY PROFILE, where non-ASCII / floats / null are fail-closed rejected by
// design (design amendment #3), which is exactly the subset on which canon v2's
// full rules and this port emit identical bytes. Parity is pinned per vector
// (`input.canon_core_v2_bytes`, produced from spec's canon.py) and the source is
// digest-pinned in `core/authority-canon/provenance.json`. See
// `docs/design/authority-event-canonical-bytes.md` for the normative spec.

import { Buffer } from "node:buffer";
import { createPublicKey, verify as cryptoVerify } from "node:crypto";

// A signed-core object key: ASCII snake_case identifier. Keeps the sort order
// (code-unit == code-point for ASCII) identical between JS and Python.
const KEY_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;

// Metadata-safe ASCII for every signed-core STRING field: printable ASCII
// 0x21..0x7E EXCLUDING the double-quote (0x22) and backslash (0x5C). Because no
// character in this set requires JSON escaping and none is non-ASCII, JS
// `JSON.stringify` and Python `json.dumps(ensure_ascii=False)` cannot diverge.
const VALUE_RE = /^[\x21\x23-\x5B\x5D-\x7E]+$/;

// RFC3339 UTC, fixed width, "Z" only. Fixed-width zero-padded UTC timestamps
// sort lexicographically == chronologically, so validity-window checks need no
// date parsing (another cross-language divergence removed).
const TIMESTAMP_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;

const SUPPORTED_SCHEME = "ed25519";

// SPKI DER prefix for a 32-byte Ed25519 public key. Node's `createPublicKey`
// does not accept a raw Ed25519 key, so we wrap the registry's raw hex bytes.
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

export class AuthorityCanonicalError extends Error {}

// Fail-closed canonical serializer for the signed core. Rejects anything that
// could serialize ambiguously across languages: non-ASCII, floats, unsafe
// integers, null/undefined, illegal keys, unsafe string bytes.
export function canonicalizeCore(value) {
  if (value === true) return "true";
  if (value === false) return "false";
  if (typeof value === "string") {
    if (!VALUE_RE.test(value)) {
      throw new AuthorityCanonicalError(`non-metadata-safe string: ${JSON.stringify(value)}`);
    }
    return `"${value}"`;
  }
  if (typeof value === "number") {
    if (!Number.isInteger(value) || !Number.isSafeInteger(value)) {
      throw new AuthorityCanonicalError(`non-integer or unsafe number: ${value}`);
    }
    return String(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalizeCore).join(",")}]`;
  }
  if (value && typeof value === "object") {
    const keys = Object.keys(value);
    for (const key of keys) {
      if (!KEY_RE.test(key)) throw new AuthorityCanonicalError(`illegal object key: ${JSON.stringify(key)}`);
    }
    keys.sort();
    return `{${keys.map((key) => `"${key}":${canonicalizeCore(value[key])}`).join(",")}}`;
  }
  throw new AuthorityCanonicalError(`unsupported value in signed core: ${String(value)}`);
}

// The exact bytes Portal signs and gp/spec verify.
export function canonicalCoreBytes(core) {
  return Buffer.from(canonicalizeCore(core), "utf8");
}

function isTimestamp(value) {
  return typeof value === "string" && TIMESTAMP_RE.test(value);
}

// not_before <= now < not_after, on fixed-width UTC strings (lexicographic).
function withinWindow(now, validity) {
  if (!validity || !isTimestamp(validity.not_before) || !isTimestamp(validity.not_after) || !isTimestamp(now)) {
    return false;
  }
  return validity.not_before <= now && now < validity.not_after;
}

function findKey(registry, keyId) {
  const keys = (registry && registry.keys) || [];
  return keys.find((entry) => entry.key_id === keyId) || null;
}

function ed25519Verify(publicKeyHex, signatureHex, message) {
  let keyObject;
  try {
    const raw = Buffer.from(publicKeyHex, "hex");
    if (raw.length !== 32) return false;
    const der = Buffer.concat([ED25519_SPKI_PREFIX, raw]);
    keyObject = createPublicKey({ key: der, format: "der", type: "spki" });
  } catch {
    return false;
  }
  let signature;
  try {
    signature = Buffer.from(signatureHex, "hex");
    if (signature.length !== 64) return false;
  } catch {
    return false;
  }
  try {
    return cryptoVerify(null, message, keyObject, signature);
  } catch {
    return false;
  }
}

// Verify an authority event against the pinned key registry.
//
// AUTHORITATIVE SOURCES: the scheme and public key come from the REGISTRY entry
// selected by the SIGNED core's `key_id` — never from the event's self-declared
// `signature.scheme`/`signature.key_id`. `expectedCertDigest` and `now` are
// supplied by the caller (the cert being ratified, the evaluation time) so the
// binding and window checks are deterministic.
//
// Returns { ok: boolean, reason: string }.
export function verifyAuthorityEvent(event, registry, { now, expectedCertDigest } = {}) {
  if (!event || typeof event !== "object" || !event.core || typeof event.core !== "object") {
    return { ok: false, reason: "malformed_event" };
  }
  const { core } = event;
  const signature = event.signature;
  if (!signature || typeof signature !== "object" || typeof signature.signature !== "string") {
    return { ok: false, reason: "missing_signature" };
  }

  // The signed bytes must be canonicalizable; a core that fails the fail-closed
  // canonicalizer is malformed, not merely unsigned.
  let message;
  try {
    message = canonicalCoreBytes(core);
  } catch {
    return { ok: false, reason: "malformed_event" };
  }

  const key = findKey(registry, core.key_id);
  if (!key) return { ok: false, reason: "unknown_key_id" };

  // Registry is authoritative for scheme; a mismatched self-declared scheme is
  // an algorithm-confusion attempt.
  if (key.scheme !== SUPPORTED_SCHEME || signature.scheme !== key.scheme) {
    return { ok: false, reason: "algorithm_confusion" };
  }
  if (key.revoked === true) return { ok: false, reason: "key_revoked" };
  if (!withinWindow(now, key.validity)) return { ok: false, reason: "key_expired" };

  // signer<->approver binding: the signing key must be registered to the
  // approver named in the signed core (amendment #4).
  if (core.approver !== key.approver) return { ok: false, reason: "signer_approver_mismatch" };

  // cert binding: the event authorizes exactly the cert the human saw (N4).
  if (typeof expectedCertDigest !== "string" || core.cert_digest !== expectedCertDigest) {
    return { ok: false, reason: "cert_digest_mismatch" };
  }
  if (!withinWindow(now, core.validity)) return { ok: false, reason: "core_validity_expired" };

  if (!ed25519Verify(key.public_key, signature.signature, message)) {
    return { ok: false, reason: "bad_signature" };
  }
  return { ok: true, reason: "verified" };
}
