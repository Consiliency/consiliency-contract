# CS-1.4 — the certified label rescope

XG-1 Slice 5 (`DESIGN-xg1-completion.md` §4/§6, consiliency-portal
`plans/unification/xg1-completion/`). Governed by COORDINATION-PLAN per the
audit's §4 decision (REFACTOR-STATE-RECONCILED.md §4, Inconsistency #1):
**COORDINATION-PLAN wins the word "certified."**

## The problem this closes

Before this rescope, `core/registries/maturity-labels.json` defined a single
evidence label:

> `certified` — "Reserved for post-XG-1 evidence attested by the certificate
> path."

That description was ambiguous about *what* it attested — a byte-reproducible
parity certificate, or a human-ratified authority event, or both. In practice
every artifact that has ever carried `certified` (the CS Phase 1 proj-S
projections, spec #74 / portal #165) has had **parity only** — a fail-closed
digest re-verify against certified truth. None has ever had a **verified
authority event** behind it, because the XG-1 authority path (contract Slices
1-4: the signable core, real Portal signing, gp verification, the live
human-ratify loop) has not shipped end-to-end yet. Calling that `certified`
without qualification overstates what is actually proven — exactly the kind
of false-green this program exists to close.

## The two tiers

| id | proves | does NOT prove | status |
|---|---|---|---|
| `parity-certified` | The artifact's rendered bytes fail-closed re-verify against a digest bind to the certified desired-state graph S (C1-C5 cert bind passed). Byte parity with certified truth. | That a human or authority signed off on it. No authority event is required or checked for this tier. | **Real today** — this is exactly what CS proj-S certification (spec #74, portal #165) ships. |
| `authority-certified` | Everything `parity-certified` proves, **plus** a valid, signature-verified authority event (`authority_event_protocol.v1` core/chain split, Ed25519) bound to the same `cert_digest`, ratified by a human through the XG-1 authority path. | — (this is the top tier) | **Reserved.** No artifact earns this label until the XG-1 authority loop (contract Slices 1-4, `DESIGN-xg1-completion.md` §4) lands end-to-end and delivers a verified `authority-event.json` alongside the cert. |

Ordering (evidence ladder): `presence-only -> hash-checked ->
realized-edge-observed -> parity-certified -> authority-certified`.

## The bare `certified` id: deprecated alias, not deleted

The design doc's original phrasing was "rename the current certified label"
to `parity-certified`. This slice instead keeps `certified` in both
`core/registries/maturity-labels.json` and
`core/schemas/projections-index-v1.schema.json`'s `maturity_label` enums,
marked `"deprecated": true` with `"deprecated_alias_of": "parity-certified"`.
Reasoning: a hard rename is a breaking change for every existing producer/
consumer that emits or reads the literal string `"certified"` — spec's
`spec-render/build_projections_index.py` (field-copies `maturity_label`
verbatim from the manifest, does not validate the string against an enum) and
portal's certified-projection display/transport module (task
"Portal: certified-projection transport + display module with digest
re-verify"). Neither is touched by this PR (contract-only scope); breaking
them here would be premature — the coordinated relabeling of spec's real
proj-S manifests happens in spec's own PR, tracked separately.

**The alias direction is load-bearing and one-way**: `certified` aliases
`parity-certified`, **never** `authority-certified`. Every artifact that has
ever carried the bare `certified` id has parity evidence only; aliasing it
upward to `authority-certified` would manufacture the exact false-green this
whole program exists to kill. New artifacts should emit `parity-certified` or
`authority-certified` directly; `certified` is not to be used in new
manifests.

## What changed, mechanically

- `core/registries/maturity-labels.json` — `parity-certified` and
  `authority-certified` added as first-class evidence labels; `certified`
  kept, marked deprecated + aliased; `phase0_disallowed` now lists all three
  ids (Phase 0 vectors must not claim any certified-tier maturity, old or
  new).
- `core/schemas/projections-index-v1.schema.json` — `maturity_label` enum
  (top-level and the `proj-S-certified` per-kind cap) extended to
  `[realized-edge-observed, certified, parity-certified, authority-certified]`;
  the `proj-code` per-kind cap is **unchanged**
  (`[presence-only, hash-checked]`) — the two-sided cap still excludes proj-code
  from every certified tier, old or new.
- `conformance/vectors/projections-index-pure-merge-deterministic.json` — the
  existing graphbase entry is re-labeled `parity-certified` (it has a parity
  cert, no authority event — the honest label); a second `proj-S-certified`
  entry on the same repo (`predicate: certified-projection-authority-pilot`)
  demonstrates `authority-certified` is a distinct, independently valid tier
  in the same deterministic merge. Verified byte-identical + schema-valid
  against the **real** `spec-render/build_projections_index.py` (origin/main)
  via the interchangeability harness
  (`scripts/interchangeability/run_driver_equivalence.py`) — not just this
  package's own reference merger.
- `conformance/vectors/manifest-invalid-certified-maturity.json` — description
  updated: `manifest.schema.json`'s `document.maturity` enum has never
  included any certified-tier value (it is capped at
  `realized-edge-observed`), so Phase 0 rejection of `parity-certified` /
  `authority-certified` is structurally guaranteed the same way the bare
  `certified` id already was; no new vector is needed to prove a schema
  impossibility.
- `tests/test_contract.py` + `tests/contract.test.mjs` — both readers assert
  the per-kind cap enums, the `certified` deprecation + alias metadata, and
  that no accepted vector carries a certified-tier claim outside
  `proj-S-certified`.
- Version bump `0.5.1 -> 0.6.0` (new registry surface, backward compatible —
  matches the `0.5.0` precedent for the authority-event core).

## Explicitly out of scope (do not conflate with this slice)

This PR does **not** touch `core/schemas/authority-event-protocol.schema.json`,
the Ed25519 canonicalization/verification code, or the authority-key
registry — those landed in `0.5.0`/`0.5.1` and are untouched here. This slice
is the label taxonomy only. In particular, `projections-index-v1.schema.json`
does **not** encode an authority-event object or a discriminator field for
"has a verified authority event" — that binding is enforced upstream by the
delivery/gate layer (spec's ingress, gp's `spec-certificate-gate.mjs`,
contract Slices 2-4), not by this JSON Schema. A `maturity_label` of
`authority-certified` on a `proj-S-certified` entry is, like `certified`
before it, a **producer-asserted claim** the schema permits structurally for
the right kind; the display/consumption layer is responsible for re-deriving
and trusting it (exactly as `parity-certified`'s digest re-verify already
works today).

## Blast radius (spec + portal) — not changed by this PR

- `spec-render/build_projections_index.py` (origin/main): field-copies
  `maturity_label` verbatim (`raw["maturity_label"]`, both `build_proj_code_entry`
  and `build_certified_entry`); does not hardcode-validate the string. Existing
  manifests emitting `"certified"` keep validating against this PR's schema
  (the alias). Verified live: pointing the interchangeability harness at
  `~/code/spec` (`origin/main`) reproduces the updated vector byte-for-byte
  and validates against the new schema (4/4 entries).
- Portal's certified-projection display/transport module (re-verifies the
  digest bind before rendering) reads `maturity_label` off the delivered
  index entry; it is unaffected by this PR (still sees `"certified"` from
  spec's real manifests until spec's own PR re-labels them to
  `parity-certified`).
- Neither spec nor portal is edited by this PR. The coordinated re-label of
  spec's real proj-S manifests, and portal's "honest label" display update
  (`DESIGN-xg1-completion.md` §6 Slice 5 acceptance: "portal projection
  display shows the honest label"), are tracked as separate follow-up PRs in
  their own repos.
