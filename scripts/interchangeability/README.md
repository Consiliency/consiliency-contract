# Interchangeability conformance (Slice X, DESIGN §12.3)

`run_driver_equivalence.py` is the conformance harness for the projection-
discovery design's §12.3 "interchangeability test": *the `projections.index.v1`
merge is a pure function of the manifests, so any driver reproduces the same
bytes for the same manifests.*

## What this proves today

`conformance/vectors/projections-index-pure-merge-deterministic.json` fixes one
manifest set and one expected `projections.index.v1` payload. Three things
already reproduce it byte-for-byte, checked in this order of directness:

1. **The contract's own Python reference merger**
   (`tests/test_contract.py::ContractReaderTest._build_projections_index`).
2. **The contract's own JS reference merger**
   (`tests/contract.test.mjs::buildProjectionsIndex`).
3. **The real producer** — `spec`'s `spec-render/build_projections_index.py`,
   unmodified, run by this harness against a fixture directory built from the
   vector. This is the one that matters: (1) and (2) are re-implementations
   *inside this repo* for testing the schema; (3) is the actual code that ships
   in `spec`'s CI gate and writes the committed `projections.index.json`
   consumed downstream. If (3) drifts from (1)/(2), that is a genuine
   interchangeability regression — the reference mergers and the real producer
   have diverged — and the harness reports it as a **finding**, not a
   formatting nit.

The harness also validates the real producer's output against this repo's
*currently pinned* `projections_index_v1` schema (not spec's vendored copy),
so a schema change here that the real producer hasn't caught up to shows up as
a failure too.

## What this does NOT prove yet (honest scoping)

DESIGN §12.3 names three drivers: **Portal + pipeline**, **agent-harness
standalone**, and **headless pipeline (gp)**. None of the three has its own
index-building code today — all three either invoke, or are expected to
eventually invoke, the *same* `spec-render/build_projections_index.py` this
harness already exercises. So right now:

- "Portal + pipeline" and "headless pipeline" reduce to *this same driver*,
  invoked from a different orchestration context — proving them again would be
  re-running identical code, not testing a second implementation.
- "agent-harness standalone" (DESIGN §12.2) is scoped to drive "the same
  aggregator" too — i.e. it is also expected to call this same script, not
  reimplement the merge.

**Until one of those runtimes ships its own index-building logic, this harness
is the whole of the falsifiable claim: the one real producer that exists
reproduces the neutral contract's vector.** When a second, independently
implemented driver exists (e.g. a harness-native aggregator that doesn't shell
out to `build_projections_index.py`), extend this harness to run it the same
way and add it to the comparison — don't claim that coverage before it's true.

## Running it

```sh
CONFORMANCE_SPEC_REPO=/path/to/spec python3 scripts/interchangeability/run_driver_equivalence.py
```

- Without `CONFORMANCE_SPEC_REPO` set (and no sibling `../spec` checkout next
  to this repo), the harness — and the two test-suite assertions that wrap it
  (`tests/test_contract.py`, `tests/contract.test.mjs`) — **skip** with a clear
  reason. This is deliberate: contract-only CI has no reason to check out
  `spec`, and a skip must never be confused with a pass.
- The harness reads the driver by content via `git show <ref>:spec-render/build_projections_index.py`
  (default ref `origin/main`, override with `CONFORMANCE_SPEC_REF`) rather than
  trusting whatever branch happens to be checked out locally, since the file
  may not exist on every branch.
- Prints one JSON line: `{"status": "pass"|"fail"|"skip", ...}`. Exit code 0
  for pass/skip, 1 for fail.
