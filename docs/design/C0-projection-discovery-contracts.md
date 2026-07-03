# Slice C0 — Projection-discovery + git-discipline contracts (0.4.0)

Slice C0 lands the **neutral** contract foundation for the panel-approved
"pipeline-owned doc-projections: discovery, branch-scoped surfacing &
self-refresh" design. The full design (grounded in `spec`, `consiliency-portal`,
`agent-harness/phase-loop-runtime`, and `governed-pipeline`) motivates every
field here; this doc records only what ships in the contract package and why it
lives here rather than in a producer or consumer repo.

## Why these belong in `@consiliency/contract`

The projection index and the git-discipline contract have **four** independent
consumers: `spec` (producer of the index), the Portal (richest consumer),
`agent-harness/phase-loop-runtime` (a standalone driver), and
`governed-pipeline` (a headless driver). If the definition lived in any one of
them, the others would vendor a copy (drift) or depend in the wrong direction.
The neutral package is the only home all four can depend on without a cycle —
which is the structural expression of "Portal is a consumer, not the owner."

## What ships

### `core/schemas/projections-index-v1.schema.json` — `projections.index.v1`
A deterministic **pure-merge** index of the per-artifact projection manifests
(+ `portal_projection.v2` envelopes + refresh sidecars). Load-bearing choices:

- **No `generated_at` / `generated_at_commit`.** The index is a pure function of
  the manifests, so an in-memory `--check` rebuild is byte-identical across
  source commits that touch no manifest, and across all four drivers
  (interchangeability). Per-entry `pinned_commit` carries the meaningful
  provenance.
- **Claims, never authority.** `maturity_label` and `gate_state` are faithful
  copies of the manifest; the Portal re-derives the body digest and only honors
  the claim if the bind passes. The index can never elevate maturity.
- **Refresh state comes from a SIDECAR, never the manifest.** `refresh_status` /
  `refresh_failure_class` / `attempted_code_head_sha` are merged from the
  committed `<artifact>.refresh.json` sidecar. Manifests stay immutable,
  single-writer, `additionalProperties:false` gate records — so the merge (and
  `--check`) stays deterministic.
- **`branch` is optional.** A projection is a single pin per commit; branch
  currency is a *display-time* comparison (design §10.4), not a per-branch
  generation matrix. The optional `branch` field records pipeline-owned contract
  branch provenance without breaking single-pin determinism.

> Wire-const adaptation: the schema `const` is the non-namespaced
> `projections.index.v1` (the interchangeability wire value the not-yet-built
> `build_projections_index.py` producer emits), while the file name and loader
> key follow the package's hyphen/snake conventions
> (`projections-index-v1.schema.json` / `loadSchema('projections_index_v1')`).

### `core/schemas/git-discipline-protocol.schema.json` — `consiliency.git_discipline_protocol.v1`
The machine-readable form of the pipeline-owned git-discipline contract:
pipeline-owned ref patterns (+ the human default), lease metadata on pipeline
refs, the `.pipeline/**` + `.consiliency/**` write-footprint allowlist, and
merge policies (`auto` / `required` / `never`). The **NEVER-DELETE-HUMAN-REFS**
invariant is a schema-level rule: `invariants.never_delete_human_refs = true`,
`self_heal.scope = leased-pipeline-owned-refs-only`,
`self_heal.auto_fix = idempotent-safe-only`, `default_severity = warn`, and
`finding_human_required = false` (autonomy-first: soft default, opt-in to block,
`human_required` never set).

### `core/registries/pipeline-ref-classes.json` — `consiliency.pipeline_ref_classes.v1`
The falsifiable ref-class enumeration the protocol references: the harness
(`consiliency/pipeline/{roadmap_version}`, `phase-loop/sched/{target}/{phase}`)
and gp (`pipeline/{phase}-{node}`) pipeline-owned families, the human default
(`*`), and the self-heal deletion rule (`owner == pipeline AND
deletable_by_self_heal AND leased`). Both runtimes read it to agree on ownership.

## Conformance vectors

- `git-discipline-never-delete-human-refs.json` — a mixed ref set (leased/
  unleased pipeline refs across deletable and non-deletable classes, plus human
  default-branch and feature refs). The test classifies each ref against the
  registry and proves: no human ref is ever self-heal-deletable, every deletable
  ref is a leased pipeline ref, and deletable + protected partition all refs.
- `projections-index-pure-merge-deterministic.json` — a fixed manifest set
  supplied out of sort order, plus a stale refresh sidecar, mapped to the exact
  expected index bytes. The test implements the pure merge in both readers and
  asserts byte-identical reproduction + stability + absence of `generated_at`
  (the §12.3 interchangeability fixture, in miniature).

## Consumption

`loadSchema('projections_index_v1')`, `loadSchema('git_discipline_protocol')`,
`loadRegistry('pipeline_ref_classes')` — existing thin loaders, no new API. The
spec aggregator will validate its output against the index schema; the harness
`layout_validity` extension / `CloseoutValidator` and gp's footprint/merge gates
read the ref-class registry + git-discipline schema; the Portal validates the
index it renders and reads the contract working-branch. One definition, many
consumers.
