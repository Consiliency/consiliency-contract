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

Dual-published: **npm** [`@consiliency/contract`](https://www.npmjs.com/package/@consiliency/contract) + **PyPI** [`consiliency-contract`](https://pypi.org/project/consiliency-contract/), from shared JSON data + conformance vectors so the two language readers stay byte-identical.

> **Status — `0.2.0` adds CS-0.12 adoption/governance-scoping and CS-0.10b lease/inbox coordination on top of the `0.1.0` Phase-0 L0 content.**
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
```

## Verification

```sh
npm test
python -m unittest discover -s tests -p 'test_*.py'
python -m build
```
