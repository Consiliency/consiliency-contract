# CS-0.12 + CS-0.10b Contract Content Design

Status: rev2 — incorporates the 3-leg advisory panel (codex + gemini + Fable, unanimous PARTIALLY AGREE). Rev2 makes the guardrail a *computed* proof (not an asserted fixture), adds handoff/done/announce-intent + boundary + adopted:false vectors, bounds the TTL, pins the exact expiry semantics, relaxes the version pin to `^0.2.\d+$`, and widens the ignore-set. Version stays `0.2.0`.

## Scope

`0.2.0` is an additive minor that lands two contract surfaces on top of the
`0.1.0` Phase-0 L0 payload, with no removals and no new required fields on any
existing schema:

- **CS-0.12 — adoption + governance-scoping.** How a repo declares that it
  consents to be governed, which of its documents are governed, and which
  namespaces are never touched.
- **CS-0.10b — lease + inbox coordination.** How multiple agents coordinate
  edits without a hard lock, via TTL leases held in a store that is the sole
  source of truth, with an advisory inbox that is never authoritative.

The package stays neutral: it defines shared JSON data + conformance vectors.
JavaScript and Python readers remain thin loaders over identical bytes and are
unchanged — new schemas/registries are registered in `core/contract.json` and
new vectors dropped into the flat `conformance/vectors/` directory; both
generic readers discover them automatically. This preserves the reader thinness
and the byte-parity guarantee.

## CS-0.12 — Adoption + Governance-Scoping

### Adoption profile (extends the manifest)

`manifest.schema.json` gains an optional `adoption` object:

```json
{"adopted": true, "contract_version": "0.2.0", "archetype": "service",
 "adopted_scope": ["layout", "gates"]}
```

- Adoption is a **profile, not a boolean.** `adopted_scope` is a subset of
  `[layout, gates, projections, cert]`, so partial adoption is first-class. When
  `adopted` is `true`, `adopted_scope` must be non-empty (enforced with
  `if/then`).
- **Presence of a valid profile = consent to be governed.** A repo with no
  adoption profile is ungoverned regardless of any other declaration
  (`adoption-absent-ungoverned`).
- **`adopted: false` is explicit non-adoption.** It is a recorded, auditable
  declaration that the repo is ungoverned for every facet — the explicit form of
  "no profile at all." A declared-false profile governs nothing even when a
  `governed_set` selector matches (`adoption-declared-false-ungoverned`). Only
  `adopted: true` requires a non-empty `adopted_scope`.

### Governed-set — allowlist by declaration

`manifest.schema.json` gains an optional `governed_set`: a list of selectors
`{by: path|glob|class, value}`. **Anything not matched by a selector is
ungoverned.** This is the core safety property: an undeclared doc is `foreign`
(governed:false), never silently ingested (`governed-set-undeclared-ungoverned`,
`doc-label-foreign-governed-false`).

### Default ignore-set (registry)

`core/registries/default-ignore-set.json` ships the tool/scratch namespaces
ingestion must never touch. The defaults cover every harness the fleet runs:
`.git/`, `.phase-loop/`, `.pipeline/`, `.claude/`, `.codex/`, `.opencode/`,
`.gemini/`, `.pi/`, `.agents/`, `.cursor/`, `node_modules/`, `.venv/`,
`scratch/`, `**/*.wip.md`, and transcript dirs; extensible per-repo. A `matching`
rule is pinned as data: a bare-directory entry (ends in `/`, no metacharacter)
matches at ANY depth (so `tools/.claude/notes.md` is ignored), while an entry
with a glob metacharacter is a glob over the repo-relative path. Precedence is
explicit and testable: `ignore-set-overrides-governed-set` — a scratch/nested
path is ungoverned even when a `governed_set` glob would match it
(`ignore-set-scratch-never-governed`, `ignore-set-nested-path-any-depth`).

### Governance labels (two-axis extension of maturity-labels)

`maturity-labels.json` now tags every label with a `kind`:

- `kind: "evidence"` — the existing evidence-strength axis
  (`presence-only` → `hash-checked` → `realized-edge-observed` → `certified`).
- `kind: "governance"` — a distinct governance-status axis:
  `present-nonconforming` (governed but malformed), `foreign` (governed:false,
  undeclared), and `unmanaged` (a cross-repo edge whose far end has not adopted).

Governance labels surface through a new **optional** `labels` array on the
conformance decision; they do **not** widen the `maturity` enum. `unmanaged` is
an **edge** label, so it also appears as an optional `governed` /
`governance_label` on `interface-declaration.schema.json` edges and is exercised
by an interface-shaped vector (`edge-label-unmanaged-cross-repo`).

## CS-0.10b — Lease + Inbox

### Lease (not a lock)

`lease.schema.json`: `{lease_id, holder, acquired_at, ttl_seconds, heartbeat_at,
mode: soft|hard, scope, phase}`. It is a lease, not a lock: TTL + heartbeat +
auto-expiry. `scope.granularity` is `repo | path-set | symbol` — **path-set is
the default, symbol is opt-in, line-level is out of scope** (pinned in the store
protocol). `ttl_seconds` is bounded `1..7200` (a 2-hour ceiling): an unbounded
TTL would regress the lease into a permanent lock and defeat auto-expiry, so the
ceiling keeps a leaked lease self-healing within two hours. All timestamps are a
fixed ISO-8601 UTC format (`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$`, enforced by
pattern) and all durations are integer seconds, so the JS and Python canonical
dumps stay byte-identical (floats would not).

### Event stream projected to a current-lease view

`lease-event.schema.json` is the append-only event (`acquire | renew | release |
expire`). The **current-lease view is a projection of the event stream** at a
given clock. Crucially, both test suites now *compute* that projection with a
small reference folder — folding `input.events` **only** (coordination messages
are structurally excluded from the fold), applying heartbeat-anchored,
exclusive-boundary TTL expiry — and assert it equals the fixture's
`expected.current_lease` + `effective_mode` for every coordination vector. This
turns the guardrail into a computed proof and validates each fixture's expiry
math for free (acquire/renew/expire/release/boundary lifecycle).

### LeaseStore protocol

`lease-store-protocol.schema.json` specs `acquire / renew / release / query`,
and pins the invariants as schema constants:

- `source_of_truth: "lease-store"` — the store is the sole truth for lock state.
- `atomicity.hard_requires_atomic_acquire: true`, and
  `degrade_without_atomic_backend: "soft"` — **hard mode degrades to soft when
  the backend has no atomic acquire** (`lease-hard-mode-atomic`,
  `lease-hard-degrades-to-soft`).
- `expiry` = TTL authoritative, heartbeat renews, auto-expiry, plus the exact
  semantics pinned as constants: `expires_at_formula = "heartbeat_at +
  ttl_seconds"` and `boundary = "exclusive"` (held over `[acquired_at,
  expires_at)`; expired iff `now >= heartbeat_at + ttl_seconds`). A dedicated
  `lease-expiry-boundary` vector fixes the contention instant at `now ==
  expires_at` so two vendoring consumers cannot disagree.
- `operation_semantics` specs each op's request/response, idempotency, and
  holder-only rule: `acquire` (non-idempotent, rejects on `conflict`), `renew`
  and `release` (idempotent, **holder-only** — a non-holder renew/release is
  rejected), `query` (idempotent, side-effect-free). `failure_modes` =
  `conflict | not-holder | not-found | expired`.
- `backends` pluggable: `local-file` → `portal` (off-device) → `coordinator`.

### CoordinationChannel (inbox) — the guardrail

`coordination-channel-protocol.schema.json` specs `send / subscribe` and the
message types `request-yield | announce-intent | handoff | done`. The
**sole-truth guardrail is encoded as schema constants, as computed vectors, and
in explicit prose**:

- `authority.inbox_authoritative: false`
- `authority.message_may_mutate_lease: false`
- `authority.message_prompts_actor_to_call_store_op: true` — deliberately named
  to avoid the mis-reading that a subscriber may translate a message into a
  mutation. A message may PROMPT an actor to CALL a store op; it never becomes an
  op or a lease transition itself.
- `lease_state_projection.formula: "current_lease = project(lease-store events,
  now)"` with `inbox_included_in_projection: false` — the projection excludes the
  inbox by definition.

The normative proof spans all four message types, each leaving the projected
lease unchanged (`changed_by_message: false`): `request-yield`
(`coordination-message-does-not-mutate-lease`), `handoff`
(`coordination-handoff-does-not-transfer-holder` — a HandoffPacket does not
transfer the holder), `done` (`coordination-done-does-not-release-lease`), and
`announce-intent` (`coordination-announce-intent-does-not-lease`). Because the
test computes the current-lease view by folding events *only* and then compares
to the fixture, the exclusion of messages is proven, not asserted.
`omniagent_plus_mapping` records the mapping to omniagent-plus `WorktreeLease`
(`consiliency.lease.v1`) and `HandoffPacket` (`handoff`).

## Design Principles (carried from CS-0.2)

- Shared JSON is normative; readers are thin accessors over identical bytes.
- Additive-only: no schema removed, no new required field on an existing schema.
- Phase-0 stays L0/warn; no artifact claims `certified`.
- No host-absolute paths; scopes and selectors are repo-relative or globs.

## Judgment Calls (for panel scrutiny)

1. **Version window follows the repo's per-minor convention.** The existing
   version-skew protocol pins a single-minor window (`>=0.1.0 <0.2.0`) and its
   incompatible vector uses a cross-minor pair. To stay coherent with that
   normative artifact, `0.2.0` moves the window to `>=0.2.0 <0.3.0`. The manifest
   and adoption-profile `contract_version` pins are `^0\.2\.\d+$` (any 0.2.x
   patch), NOT exact `^0\.2\.0$` — a `0.2.1` patch must not invalidate every
   adopter manifest, and the whole 0.2 minor is one compatibility window.
   "Additive" holds at the *content* level, and Phase-0 skew only *warns*, so a
   `0.1.0` consumer is not hard-broken. Alternative considered: a spanning
   `>=0.1.0 <0.3.0` window — rejected because it would contradict the shipped
   per-minor windowing.
2. **One decision schema, reused for coordination verdicts.** Every vector's
   `decision` must be `consiliency.conformance_decision.v1` (a suite invariant),
   so lease/coordination verdicts reuse it and set the doc-oriented `maturity`
   field to the neutral floor `presence-only`. Alternative considered: a
   dedicated coordination-decision schema — rejected because it would break the
   uniform decision-schema invariant the whole conformance suite rests on.
3. **Governance is a separate axis from evidence maturity.** Rather than
   overloading the `maturity` enum, governance labels are tagged
   `kind: "governance"` in the registry and surfaced via an optional
   `labels` array. This preempts conflating evidence-strength with
   governance-status.
4. **Normative outcome lives in `expected`.** The projected current-lease view
   and the governed/ungoverned outcome are carried in a top-level `expected`
   field (the CS-0.2 design already named an `expected` vector field), keeping
   the shared `decision` schema minimal. `expected` is byte-parity-checked like
   the rest of the vector.
5. **`unmanaged` is an edge label, not a doc label.** It attaches to
   interface-declaration edges (cross-repo into unadopted repos), not to
   governed docs.
6. **One deliberate cross-file `$ref`.** Every 0.1.0 schema is self-contained
   (internal `#/$defs` only). `lease-event.schema.json` is the single exception:
   its optional `lease` field references `lease.schema.json` by canonical `$id`
   rather than duplicating the full lease shape (which would drift). This is the
   correct JSON-Schema idiom for a validator that has all schemas registered; it
   does not affect the thin readers (which do not resolve `$ref`). A
   `lease-event-carries-lease` vector exercises it, and the out-of-band
   validation resolves it via a registry (a broken nested lease is caught through
   the `$ref`). Alternative considered: inline the lease shape into the event —
   rejected to avoid a second copy that can drift from `lease.schema.json`.
8. **TTL is bounded at 7200s.** An unbounded TTL turns a lease back into a
   permanent lock; a 2-hour ceiling keeps a leaked lease self-healing. The
   ceiling is a design choice open to tuning; it is enforced by schema so
   fixtures and adopters cannot regress it silently.
9. **Expiry boundary is exclusive.** `expires_at = heartbeat_at + ttl_seconds`,
   valid over `[acquired_at, expires_at)`. Choosing exclusive (vs inclusive)
   makes `now == expires_at` deterministically *free*, which is the safe default
   at the contention instant (a waiter can take the lease exactly when it lapses).
7. **The adoption profile's `archetype` allows `baseline-only`.** `archetypes.json`
   notes that `baseline-only` "is not an archetype" (it is a legal *declaration*).
   A baseline-only repo can still adopt the contract, so the profile's single
   `archetype` field accepts the seven archetypes plus `baseline-only`, mirroring
   the manifest `declaration` vocabulary rather than the archetype registry alone.

## Conformance Vectors (the normative core)

CS-0.12: `adoption-adopted-governed`, `adoption-absent-ungoverned`,
`adoption-declared-false-ungoverned`, `adoption-partial-scope`,
`governed-set-undeclared-ungoverned`, `ignore-set-scratch-never-governed`,
`ignore-set-nested-path-any-depth`, `doc-label-present-nonconforming`,
`doc-label-foreign-governed-false`, `edge-label-unmanaged-cross-repo`.

CS-0.10b: `lease-acquire`, `lease-renew`, `lease-expire`, `lease-release`,
`lease-expiry-boundary`, `lease-hard-mode-atomic`, `lease-hard-degrades-to-soft`,
`lease-event-carries-lease`, `coordination-message-does-not-mutate-lease`,
`coordination-handoff-does-not-transfer-holder`,
`coordination-done-does-not-release-lease`,
`coordination-announce-intent-does-not-lease`.

Every vector runs through both readers with byte-identical canonical JSON, and
every coordination vector's expected view is checked against a computed
events-only projection.

## Non-Goals

- No private `spec`, `agent-harness`, or `governed-pipeline` changes.
- No lock-store implementation, backend, or scheduler in this package.
- No line-level lease granularity.
- No cert-derived or `certified` claims.
- No reader-side schema validation (unchanged from CS-0.2).
