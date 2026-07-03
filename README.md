# @consiliency/contract

The Consiliency cross-repo **contract package** — the single, neutral rulebook that
`agent-harness` and `governed-pipeline` vendor (owned by neither). It defines:

- the `.consiliency/` layout + manifest schema
- the **archetype registry** — `product` / `service` / `library` / `infra` / `tooling-meta` / `experiment` / `document`, plus modifiers (`data-bearing` / `public` / `regulated` / `user-facing`), with `baseline-only` as a legal declaration
- the required-document sets per archetype (the 7 document classes)
- the interface-declaration schema (realized + promised cross-repo edges)
- the loop-gate protocol (presence / freshness / integrity / version-skew)
- the `canonical_html.v1` display schema
- the version-skew protocol
- **adoption + governance-scoping (CS-0.12)** — the adoption profile (a partial-adoption profile, not a boolean; its presence = consent to be governed), the governed-set allowlist-by-declaration, the default ignore-set registry, and the `present-nonconforming` / `foreign` / `unmanaged` governance labels
- **lease + inbox coordination (CS-0.10b)** — the `lease` (TTL + heartbeat + auto-expiry, soft/hard, repo/path-set/symbol scope), the append-only `lease_event` stream, the `lease_store` protocol (sole source of truth) and the `coordination_channel` inbox protocol (never authoritative)
- **projection discovery + git-discipline (Slice C0)** — the `projections.index.v1` schema (a deterministic pure-merge index of per-artifact projection manifests, no `generated_at`, so every driver reproduces byte-identical entries), the `git_discipline_protocol` (pipeline-owned ref classes, lease + write-footprint, merge policy, and the **NEVER-DELETE-HUMAN-REFS** invariant as a schema-level rule), and the `pipeline_ref_classes` registry both runtimes read to agree on ref ownership
- **interchangeability conformance (Slice X)** — `scripts/interchangeability/run_driver_equivalence.py` proves the pure-merge claim above isn't just asserted by this package's own reference mergers: it feeds the `projections-index-pure-merge-deterministic` vector through the real `spec-render/build_projections_index.py` producer and asserts byte-identical output, honestly scoped (see `scripts/interchangeability/README.md`)
- **authority-event contract core (XG-1 Slice 1)** — the single, cryptographically-authenticated `authority_event_protocol.v1` schema with the **core/chain signing split** (Portal signs the slot-independent `core`; spec appends `chain` OUTSIDE the signature and never re-signs), one **canonical-bytes algorithm** implementable in dependency-free JS on Node 20 (see [`docs/design/authority-event-canonical-bytes.md`](docs/design/authority-event-canonical-bytes.md)), the vendored digest-pinned `authority_key_registry.v1` **Ed25519 root of trust** (public keys only), an Ed25519 verify reference in both readers, and 13 conformance vectors — a valid event VERIFIES in both readers and every forgery class (bad/missing signature, unknown/attacker key_id, algorithm-confusion, signer↔approver mismatch, revoked/expired key, cert_digest mismatch) REJECTS

Dual-published: **npm** [`@consiliency/contract`](https://www.npmjs.com/package/@consiliency/contract) + **PyPI** [`consiliency-contract`](https://pypi.org/project/consiliency-contract/), from shared JSON data + conformance vectors so the two language readers stay byte-identical.

> **Status — `0.5.0` adds the XG-1 Slice 1 authority-event contract core: the
> `authority_event_protocol.v1` schema (core/chain signing split), the
> `authority_key_registry.v1` Ed25519 root of trust, the canonical-bytes interop
> algorithm + Ed25519 verify reference in both readers, and 13 forgery
> conformance vectors. `0.4.2` makes the `projections.index.v1` per-kind maturity caps
> two-sided: proj-code is `[presence-only, hash-checked]` and `proj-S-certified`
> is `[realized-edge-observed, certified]` (floor-revert), replacing the
> one-sided `not:certified` guard. `0.4.1` made the entry per-kind (proj-code
> pins a code commit + facts; `proj-S-certified` requires `source_S_digest`,
> no facts/commit). `0.4.0` added the Slice C0 projection-discovery +
> git-discipline contracts (`projections.index.v1`, `git_discipline_protocol`,
> `pipeline_ref_classes`) on top of the `0.3.0` required-document rebalance,
> the `0.2.0` CS-0.12 adoption/governance-scoping + CS-0.10b lease/inbox
> coordination, and the `0.1.0` Phase-0 L0 content.**
> The shared JSON data lives under `core/` and `conformance/`; npm and PyPI
> readers are intentionally thin loaders over those same bytes.

## Reader API

JavaScript:

```js
import {
  CONTRACT,
  CONTRACT_VERSION,
  listVectors,
  loadContract,
  loadRegistry,
  loadSchema,
  loadVector,
  // authority-event core (XG-1 Slice 1)
  canonicalCoreBytes,
  verifyAuthorityEvent,
} from "@consiliency/contract";
```

Python:

```python
from consiliency_contract import (
    CONTRACT,
    CONTRACT_VERSION,
    list_vectors,
    load_contract,
    load_registry,
    load_schema,
    load_vector,
)
# authority-event core (XG-1 Slice 1); needs the optional `authority` extra
# (cryptography) only for signature verification.
from consiliency_contract.authority import (
    canonical_core_bytes,
    verify_authority_event,
)
```

## Verification

```sh
npm test
python -m unittest discover -s tests -p 'test_*.py'
python -m build
```
