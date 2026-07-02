# CS-0.12 + CS-0.10b Contract Content Design

Status: draft for advisory-panel review.

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

### Governed-set — allowlist by declaration

`manifest.schema.json` gains an optional `governed_set`: a list of selectors
`{by: path|glob|class, value}`. **Anything not matched by a selector is
ungoverned.** This is the core safety property: an undeclared doc is `foreign`
(governed:false), never silently ingested (`governed-set-undeclared-ungoverned`,
`doc-label-foreign-governed-false`).

### Default ignore-set (registry)

`core/registries/default-ignore-set.json` ships the tool/scratch namespaces
ingestion must never touch (`.phase-loop/`, `.pipeline/`, `.claude/`, `.codex/`,
`.opencode/`, `node_modules/`, `.venv/`, `scratch/`, `**/*.wip.md`, transcript
dirs), extensible per-repo. Precedence is explicit and testable:
`ignore-set-overrides-governed-set` — a scratch path is ungoverned even when a
`governed_set` glob would match it (`ignore-set-scratch-never-governed`).

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
protocol). All durations are integer seconds and all timestamps are fixed ISO
strings so the JS and Python canonical dumps stay byte-identical (floats would
not).

### Event stream projected to a current-lease view

`lease-event.schema.json` is the append-only event (`acquire | renew | release |
expire`). The **current-lease view is a projection of the event stream** at a
given clock; the coordination vectors carry that projected view in `expected`
and assert it (acquire/renew/expire/release lifecycle).

### LeaseStore protocol

`lease-store-protocol.schema.json` specs `acquire / renew / release / query`,
and pins the invariants as schema constants:

- `source_of_truth: "lease-store"` — the store is the sole truth for lock state.
- `atomicity.hard_requires_atomic_acquire: true`, and
  `degrade_without_atomic_backend: "soft"` — **hard mode degrades to soft when
  the backend has no atomic acquire** (`lease-hard-mode-atomic`,
  `lease-hard-degrades-to-soft`).
- `expiry` = TTL authoritative, heartbeat renews, auto-expiry.
- `backends` pluggable: `local-file` → `portal` (off-device) → `coordinator`.

### CoordinationChannel (inbox) — the guardrail

`coordination-channel-protocol.schema.json` specs `send / subscribe` and the
message types `request-yield | announce-intent | handoff | done`. The
**sole-truth guardrail is encoded as schema constants and as a vector**:

- `authority.inbox_authoritative: false`
- `authority.message_may_mutate_lease: false`
- `authority.message_leads_to_store_op: true`

The normative proof is `coordination-message-does-not-mutate-lease`: a
`request-yield` message leaves the projected lease **unchanged**
(`changed_by_message: false`). A test asserts this invariant across every
coordination vector carrying a message, and asserts the protocol constants
directly. `omniagent_plus_mapping` records the mapping to omniagent-plus
`WorktreeLease` (`consiliency.lease.v1`) and `HandoffPacket` (`handoff`).

## Design Principles (carried from CS-0.2)

- Shared JSON is normative; readers are thin accessors over identical bytes.
- Additive-only: no schema removed, no new required field on an existing schema.
- Phase-0 stays L0/warn; no artifact claims `certified`.
- No host-absolute paths; scopes and selectors are repo-relative or globs.

## Judgment Calls (for panel scrutiny)

1. **Version window follows the repo's per-minor convention.** The existing
   version-skew protocol pins a single-minor window (`>=0.1.0 <0.2.0`) and its
   incompatible vector uses a cross-minor pair. To stay coherent with that
   normative artifact, `0.2.0` moves the window to `>=0.2.0 <0.3.0` and the
   manifest `contract_version` pin to exact `^0\.2\.0$`. "Additive" holds at the
   *content* level, and Phase-0 skew only *warns*, so a `0.1.0` consumer is not
   hard-broken. Alternative considered: a spanning `>=0.1.0 <0.3.0` window — 
   rejected because it would contradict the shipped per-minor windowing.
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
   does not affect the thin readers (which do not resolve `$ref`) and is not
   exercised by any conformance vector. Alternative considered: inline the lease
   shape into the event — rejected to avoid a second copy that can drift from
   `lease.schema.json`.
7. **The adoption profile's `archetype` allows `baseline-only`.** `archetypes.json`
   notes that `baseline-only` "is not an archetype" (it is a legal *declaration*).
   A baseline-only repo can still adopt the contract, so the profile's single
   `archetype` field accepts the seven archetypes plus `baseline-only`, mirroring
   the manifest `declaration` vocabulary rather than the archetype registry alone.

## Conformance Vectors (the normative core)

CS-0.12: `adoption-adopted-governed`, `adoption-absent-ungoverned`,
`adoption-partial-scope`, `governed-set-undeclared-ungoverned`,
`ignore-set-scratch-never-governed`, `doc-label-present-nonconforming`,
`doc-label-foreign-governed-false`, `edge-label-unmanaged-cross-repo`.

CS-0.10b: `lease-acquire`, `lease-renew`, `lease-expire`, `lease-release`,
`lease-hard-mode-atomic`, `lease-hard-degrades-to-soft`,
`coordination-message-does-not-mutate-lease`.

Every vector runs through both readers with byte-identical canonical JSON.

## Non-Goals

- No private `spec`, `agent-harness`, or `governed-pipeline` changes.
- No lock-store implementation, backend, or scheduler in this package.
- No line-level lease granularity.
- No cert-derived or `certified` claims.
- No reader-side schema validation (unchanged from CS-0.2).
