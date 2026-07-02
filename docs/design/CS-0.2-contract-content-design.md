# CS-0.2 Contract Content Design

Status: draft for advisory-panel review.

## Scope

CS-0.2 turns the 0.0.x provisioning placeholder into the first normative
contract payload for `0.1.0`. The package remains neutral: it defines shared data
and conformance vectors, while `agent-harness`, `governed-pipeline`, and
`consiliency-portal` consume it later.

This phase does not modify private `spec`, `agent-harness`, `governed-pipeline`,
or `consiliency-portal`. It relocates the contract vocabulary here by copying
the current `canonical_html.v1` contract surface into this public package and
leaving the old copies in place for Phase 0 drift checks.

## Design Principles

- Shared JSON is normative. JavaScript and Python readers are thin accessors over
  identical bytes.
- Conformance vectors describe decisions rather than implementation details.
- Phase 0 is L0-only: no artifact claims `certified`, and no code depends on the
  producer-to-certificate path.
- All gate defaults are soft/warn. Blocking is opt-in.
- Local paths in package data are examples or repo-relative contract paths, not
  host paths.
- Version skew is a first-class gate from day one.

## Package Shape

```text
core/
  contract.json
  schemas/
    decision.schema.json
    manifest.schema.json
    contract-version-status.schema.json
    interface-declaration.schema.json
    loop-gate-protocol.schema.json
    version-skew-protocol.schema.json
    canonical-html-v1.schema.json
  registries/
    document-classes.json
    archetypes.json
    required-documents.json
    maturity-labels.json
  canonical-html/
    contract-v1.json
    provenance.json
conformance/
  vectors/
    manifest-valid-product.json
    manifest-valid-baseline-only.json
    manifest-invalid-unknown-archetype.json
    required-docs-product-service-data-bearing.json
    interface-valid-realized-and-promised.json
    loop-gate-missing-doc-warns.json
    version-skew-compatible.json
    version-skew-incompatible-warns.json
    canonical-html-contract-loaded.json
src/
  index.js
  index.d.ts
consiliency_contract/
  __init__.py
```

The `core/contract.json` file is the package index. It names the contract id,
contract version, schema ids, registry paths, protocol paths, and conformance
vector manifest. Readers expose this object and deterministic helpers to load
schema/registry/vector JSON.

Root `core/` and `conformance/` are the canonical source layout. npm ships those
directories directly. PyPI maps those same root bytes into
`consiliency_contract/_data/` at wheel/sdist build time with Hatch
`force-include`; the Python reader uses root files in a source checkout and
package data after installation.

## Normative Data

### `.consiliency/` Layout and Manifest

The manifest schema defines:

- `schema`: `consiliency.manifest.v1`
- `contract_version`: semver string
- `repo`: stable repo id, display name, default branch, and optional homepage
- `declaration`: either `{ "mode": "baseline-only" }` or `{ "mode":
  "archetyped", "archetypes": [...], "modifiers": [...] }`
- `documents`: required and optional document declarations, each with `id`,
  `class`, `path` or `ref`, `maturity`, `target_level`, `required`, and
  optional `last_attested_at`
- `interfaces`: path to the interface declaration
- `legacy_layouts`: optional old-layout fallback declarations for Phase 0
  dual-read

Paths are repo-relative. External refs are declared as refs, not hashed local
files. Schema constraints are explicit: no absolute paths, no `..` segments,
exactly one of `path` or `ref`, unique document ids, known document classes,
known maturity labels, and `additionalProperties: false` except where a typed
extension map is deliberately named.

### Archetype Registry

The locked registry is:

- `product`
- `service`
- `library`
- `infra`
- `tooling-meta`
- `experiment`
- `document`

Legal modifiers are:

- `data-bearing`
- `public`
- `regulated`
- `user-facing`

`baseline-only` is legal and is not an archetype. It means only universal
baseline artifacts apply.

### Document Classes and Required Documents

The seven document classes are:

- `intent-ground`
- `intent-plan`
- `proj-S`
- `proj-code`
- `ops-fact`
- `static`
- `index`

The required-doc registry composes:

- universal baseline
- archetype additions
- modifier additions

Each row declares a document id, class, requirement level, maturity floor, and
whether a stub is acceptable at L0. The L0 glossary is represented as a
presence-stub with an authored zone; it is not a fake `proj-S` projection.

Composition order is deterministic: baseline first, archetypes in registry
order, then modifiers in registry order. Duplicate ids with byte-identical rows
are de-duplicated; conflicting duplicate ids are a conformance failure. Multiple
archetypes are legal only under that merge rule.

### Interface Declaration

The interface declaration schema supports both:

- `realized_edges`: observed/pinned facts such as git refs, copied-literal
  drift checks, declared package imports, and repo-relative source references
  inside the declared repo.
- `promised_edges`: authored future or intended interfaces that ground `S`
  later.

Each edge carries provider repo, consumer repo, interface id, typed ref,
maturity label, metadata-only evidence refs, and optional upstream pin. Allowed
ref kinds are `git-ref`, `package-coordinate`, `repo-relative-path`,
`copied-literal`, and `opaque-external-ref`. Host absolute paths, local sibling
checkout paths, private raw payloads, and `..` traversal are invalid package
data. Phase 0 explicitly rejects `certified` maturity in contract vectors.

### Loop Gate Protocol

The protocol defines gate families:

- `presence`
- `freshness`
- `local-integrity`
- `cross-repo-integrity`
- `version-skew`

All gate records carry `severity_default: "warn"`, effective severity, result,
consumer policy, metadata-only evidence refs, and a maturity label. Blocking is
an opt-in consumer policy; the normative default remains warn.

### `canonical_html.v1`

The current governed-pipeline `canonical_html.v1` contract vocabulary is copied
into `core/canonical-html/contract-v1.json` and indexed from
`core/contract.json`. `core/canonical-html/provenance.json` records source repo,
source commit, source path, source sha256, packaged sha256, publishability scan
posture, and the rule that old copies stay in place for Phase 0 drift checks.
This package becomes the public contract home. Existing private copies stay in
place for Phase 0; downstream drift-checks can compare the package bytes against
their vendored copy.

The package does not implement an HTML parser, sanitizer, renderer, or Portal
viewer in CS-0.2. It freezes the vocabulary and data used by those consumers.

### Contract Version/Status

The status artifact schema defines:

- `schema`: `consiliency.contract_version_status.v1`
- `package`: package name and version
- `repo_contract_version`: version declared by the repo
- `consumer`: optional reader name and version
- `compatibility`: `compatible`, `negotiated`, `incompatible`, or `unknown`
- `maturity`: mandatory maturity label
- `checked_at`: deterministic fixture timestamp or runtime timestamp
- `evidence`: metadata-only refs

### Version-Skew Protocol

The protocol defines:

- compatible semver ranges
- where compatibility ranges live
- package version vs contract version authority
- prerelease/build metadata posture
- negotiation result shape
- fail-safe behavior: emit warn by default in Phase 0 unless a consumer opts into
  blocking
- no automatic mutation of repo files by the reader package

## Reader API

JavaScript:

```js
import {
  CONTRACT,
  CONTRACT_VERSION,
  loadContract,
  loadRegistry,
  loadSchema,
  loadVector,
  listVectors,
} from "@consiliency/contract";
```

Python:

```python
from consiliency_contract import (
    CONTRACT,
    CONTRACT_VERSION,
    load_contract,
    load_registry,
    load_schema,
    load_vector,
    list_vectors,
)
```

Readers return parsed JSON dictionaries/objects loaded from package data. They
do not validate schemas yet; validation belongs to CS-0.5/CS-0.6 consumers or a
later package helper once dependency choices are settled.

## Conformance

Each vector contains:

- `id`
- `description`
- `input`
- `expected`
- `decision`

CS-0.2 tests run every vector through both readers and assert byte-identical
canonical JSON decisions. A vector's `decision` object validates against
`decision.schema.json`. The canonical JSON serializer recursively sorts object
keys, preserves array order, uses UTF-8, does not ASCII-escape Unicode, uses
compact separators, emits no trailing newline, and forbids non-integer numbers
in decision payloads.

## Acceptance Checks

- `npm pack` includes `core/`, `conformance/`, `src/`, README, and license.
- `python -m build` includes the same shared JSON data under
  `consiliency_contract/_data/` in wheel and sdist artifacts.
- JavaScript and Python tests load the same contract index, schemas,
  registries, and vectors.
- Cross-language vector decisions are byte-identical.
- `canonical_html.v1` package data is byte-equal to the copied governed-pipeline
  source contract at the recorded source commit and digest.
- No package data contains host absolute paths, secrets, tokens, provider
  payloads, raw Portal state, or certified maturity claims.
- Publish CI runs npm tests, Python tests, package-content tests, and build
  checks before any OIDC publish step.

## Non-Goals

- No private `spec` changes.
- No phase-loop self-dogfooding.
- No harness or governed-pipeline vendoring.
- No cert-derived projection claims.
- No Portal UI or Supabase work.
- No package-level dependency scan for fleet edges in this phase.
