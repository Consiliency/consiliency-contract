# Authority-event canonical bytes — the interop contract

This is the **normative** definition of the bytes an authority event's signature
covers. It is the interop contract between the Portal signer (Python), the spec
ledger (Python), and the governed-pipeline (gp) verifier (dependency-free JS on
Node 20). The two reference implementations —
[`consiliency_contract/authority.py`](../../consiliency_contract/authority.py)
and [`src/authority.js`](../../src/authority.js) — MUST produce byte-identical
output for every input, and the conformance suite proves it empirically
(`authority canonical core bytes match the Python reference byte-for-byte`).

Related contract artifacts:

- Schema: [`core/schemas/authority-event-protocol.schema.json`](../../core/schemas/authority-event-protocol.schema.json)
  (`consiliency.authority_event_protocol.v1`).
- Root of trust: [`core/registries/authority-key-registry.json`](../../core/registries/authority-key-registry.json)
  (`consiliency.authority_key_registry.v1`).
- Conformance vectors: `conformance/vectors/authority-*.json`.

## Why a bespoke canonicalization (and not spec's ICU canon)

The gp verifier runs on Node 20 with **no npm dependencies** and cannot use
spec's Unicode-16 / ICU canonicalization. So the signed bytes are defined by a
tightly-constrained JSON Canonicalization (a strict subset of RFC 8785 JCS) that
Node's `JSON`-level primitives and Python's `json` produce identically. The
trick is to remove — by construction — every place the two languages are allowed
to disagree: non-ASCII escaping, float formatting, and key collation.

## The signing split (core vs chain)

An authority event has three parts. **Only `core` is signed.**

- `core` — the Portal-signed, ledger-slot-INDEPENDENT payload. The Ed25519
  signature covers exactly `canonical_core_bytes(core)` and nothing else.
- `chain` — ledger-appended metadata (`entry_digest`, `previous_entry_digest`,
  `inclusion_proof`, `root_digest`). OUTSIDE the signature, so spec can append it
  without re-signing and therefore never becomes an authority minter. Appending
  or mutating `chain` does not invalidate the core signature (a conformance
  vector: `authority-chain-appended-still-verifies`).
- `signature` — `{ scheme, key_id, signature }`. The `scheme`/`key_id` here are
  transport echoes; **verification ignores them** in favour of the SIGNED
  `core.key_id` resolved against the pinned registry.

## `canonical_core_bytes(core)` — the algorithm

`canonical_core_bytes(core) = canonicalize(core).encode("utf-8")`, where
`canonicalize` is a **fail-closed** recursive serializer:

1. **Objects** — every key MUST match `^[A-Za-z_][A-Za-z0-9_]*$` (ASCII
   snake_case). Keys are sorted ascending by code point (identical to a UTF-16
   code-unit sort for ASCII). Emitted as
   `{"k1":v1,"k2":v2,...}` with no whitespace.
2. **Arrays** — order preserved. Emitted as `[v1,v2,...]` with no whitespace.
3. **Strings** — MUST match the metadata-safe set: printable ASCII `0x21`–`0x7E`
   EXCLUDING double-quote (`0x22`) and backslash (`0x5C`), i.e.
   `^[!#-[]-~]+$`. Because nothing in this set needs
   JSON escaping and nothing is non-ASCII, the value is emitted verbatim between
   double quotes.
4. **Booleans** — `true` / `false`.
5. **Integers** — base-10, safe range `[-(2^53-1), 2^53-1]`. (The v1 core uses
   no numbers; integers are supported for forward-compatibility only.)
6. **Rejected, fail-closed** — floats / any non-integer number, `null` /
   `undefined` / `None`, non-ASCII, out-of-range integers, illegal keys, and any
   other type. A core that cannot be canonicalized is `malformed_event`, never
   silently signed.

Because the constrained subset has no ambiguous cases, `canonicalize(core)` is
byte-identical to
`json.dumps(core, sort_keys=True, separators=(",", ":"), ensure_ascii=False)`
(Python) and to a recursively key-sorted, whitespace-free `JSON.stringify`
(JS). The suite asserts this equivalence in both languages
(`authority canonicalizer equals the constrained JCS form`), so the algorithm
stays legible ("it's just JCS") while the fail-closed guards keep it safe.

### Timestamps

`validity.not_before` / `validity.not_after` (and the caller's `now`) are RFC3339
UTC, fixed width, `Z`-only: `^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$`. Fixed-width
zero-padded UTC strings sort lexicographically == chronologically, so window
checks are pure string comparisons — no date parsing, no timezone math, no
cross-language divergence. `not_before <= t < not_after`.

## Verification (authoritative sources)

`verify_authority_event(event, registry, now, expected_cert_digest)` returns
`{ ok, reason }`. Checks run in this fail-closed order; the registry is
authoritative for scheme and public key, never the event's self-declared fields:

| # | check | reject reason |
|---|-------|---------------|
| 1 | event has a `core` object | `malformed_event` |
| 2 | `signature.signature` present | `missing_signature` |
| 3 | `core` canonicalizes | `malformed_event` |
| 4 | `core.key_id` resolves in the registry | `unknown_key_id` |
| 5 | registry scheme is ed25519 AND `signature.scheme` matches it | `algorithm_confusion` |
| 6 | key not revoked | `key_revoked` |
| 7 | `now` within the key's validity window | `key_expired` |
| 8 | `core.approver` == the key's registered approver | `signer_approver_mismatch` |
| 9 | `core.cert_digest` == caller's `expected_cert_digest` | `cert_digest_mismatch` |
| 10 | `now` within `core.validity` | `core_validity_expired` |
| 11 | Ed25519 verify over `canonical_core_bytes(core)` | `bad_signature` |
| — | all pass | `ok: true`, `verified` |

`expected_cert_digest` (the digest of the cert being ratified) and `now` are
supplied by the caller so binding and window checks are deterministic — the same
precedent as the lease vectors' pinned `now`.

## Root of trust, rotation, revocation

`authority-key-registry.json` vendored IN this contract repo — gated by the
repo's merge gate — IS the physical root of trust. There is deliberately **no**
live-fetch / Portal-served registry (panel amendment #2: no substitution surface
on the gate path). Each entry pins `key_id → { scheme, public_key (raw 32-byte
Ed25519, lowercase hex), approver, validity, revoked }`. Only PUBLIC keys live
here; the Portal holds the private key. Rotate by adding a new `key_id` with an
overlapping validity window; revoke by setting `revoked: true` or letting
validity lapse — either fails verification regardless of an otherwise-valid
signature.

## Regenerating the fixtures

The registry public keys and all signed vectors are generated deterministically
by [`scripts/gen_authority_vectors.py`](../../scripts/gen_authority_vectors.py)
from stable seed labels (SHA-256 of a documented string → the Ed25519 private
seed). That script is the ONLY place a private key exists and is NOT part of the
published package (npm `files` / the wheel force-includes cover `core/`,
`conformance/`, `src/` only). Ed25519 signatures are deterministic (RFC 8032), so
`python3 scripts/gen_authority_vectors.py --check` proves the committed bytes
match a fresh run (enforced by `test_authority_regenerates_deterministically`).
