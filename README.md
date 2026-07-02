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

Dual-published: **npm** [`@consiliency/contract`](https://www.npmjs.com/package/@consiliency/contract) + **PyPI** [`consiliency-contract`](https://pypi.org/project/consiliency-contract/), from shared JSON data + conformance vectors so the two language readers stay byte-identical.

> **Status — `0.1.0` carries the first normative Phase-0 L0 contract content.**
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
