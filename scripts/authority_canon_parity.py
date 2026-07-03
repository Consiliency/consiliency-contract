#!/usr/bin/env python3
"""Live parity gate: the committed canon-core-v2 byte pins still match spec's canon.

The authority signed-core bytes ARE canon-core v2 `canonical_bytes(core)`; this
contract carries a metadata-safe/integer-only PORT of that one algorithm. The
committed per-vector `canon_core_v2_bytes` pin (produced from spec's canon.py at
generation time) makes parity an offline, committed fact — but this gate
additionally confirms the pin still matches the CURRENT spec canon-core v2.

Locates spec via `CONFORMANCE_SPEC_REPO` (a spec checkout root) or the sibling
`../spec` default; canon.py is `<root>/canon/py/canon.py`. SKIPS (status "skip",
exit 0) when no spec checkout is present — a contract-only CI run has no spec.
Exit 1 only on a real parity FAILURE (the port/pin and spec canon disagree).
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from consiliency_contract import list_vectors, load_vector  # noqa: E402


def _load_spec_canon():
    roots = []
    env = os.environ.get("CONFORMANCE_SPEC_REPO")
    if env:
        roots.append(Path(env).expanduser())
    roots.append(ROOT.parent / "spec")
    for root in roots:
        candidate = root / "canon" / "py" / "canon.py"
        if candidate.exists():
            spec = importlib.util.spec_from_file_location("spec_canon_v2", candidate)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            return module, str(candidate)
    return None, None


def main() -> int:
    module, path = _load_spec_canon()
    if module is None:
        print(json.dumps({"status": "skip", "reason": "no spec canon-core v2 (set CONFORMANCE_SPEC_REPO)"}))
        return 0

    mismatches = []
    checked = 0
    for name in list_vectors():
        if not name.startswith("authority-"):
            continue
        vector = load_vector(name)
        core = vector["input"]["event"]["core"]
        pinned = vector["input"]["canon_core_v2_bytes"]
        actual = module.canonical_bytes(core).hex()
        checked += 1
        if actual != pinned:
            mismatches.append({"vector": vector["id"], "pinned": pinned, "spec_canon": actual})

    if mismatches:
        print(json.dumps({"status": "fail", "canon_source": path, "mismatches": mismatches}))
        return 1
    print(json.dumps({"status": "pass", "canon_source": path, "checked": checked}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
