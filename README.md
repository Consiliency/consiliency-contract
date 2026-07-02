# @consiliency/contract

The Consiliency cross-repo **contract package** — the single, neutral rulebook that
`agent-harness` and `governed-pipeline` vendor (owned by neither). It defines:

- the `.consiliency/` layout + manifest schema
- the **archetype registry** — `product` / `service` / `library` / `infra` / `tooling-meta` / `experiment` / `document`, plus modifiers (`data-bearing` / `public` / `regulated` / `user-facing`), with `baseline-only` as a legal declaration
- the required-document sets per archetype (the 7 document classes)
- the interface-declaration schema (realized + promised cross-repo edges)
- the loop-gate protocol (presence / freshness / integrity)
- the `canonical_html.v1` display schema
- the version-skew protocol

Dual-published: **npm** [`@consiliency/contract`](https://www.npmjs.com/package/@consiliency/contract) + **PyPI** [`consiliency-contract`](https://pypi.org/project/consiliency-contract/), from shared JSON data + conformance vectors so the two language readers stay byte-identical.

> **Status — `v0.0.x` is a provisioning placeholder.** It establishes the publishing
> homes (npm + PyPI OIDC trusted publishing) so CI can publish tokenlessly. The
> normative contract content lands in **`0.1.0`**.
