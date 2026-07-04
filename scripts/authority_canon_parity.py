#!/usr/bin/env python3
"""REQUIRED authority-canon parity gate — the committed canon-core-v2 byte pins hold. NEVER skips.

The authority signed-core bytes ARE canon-core v2 ``canonical_bytes(core)``; this contract carries a
metadata-safe / integer-only PORT of that one algorithm (``consiliency_contract.authority
.canonical_core_bytes`` — the function actually inside every signature preimage). Each authority
vector commits the ``input.canon_core_v2_bytes`` pin (produced from spec's canon.py at generation
time). Because the PORT and the PINS both live in this repo, parity is a SELF-CONTAINED, offline,
committed fact — a contract-only CI run needs NO spec checkout. So this gate no longer skips.

It asserts, ALWAYS (the required floor):
  1. ``AUTHORITY_SIGNING_PREFIX`` == ``spec-canon:v2:authority\n`` — the canon-core v2 per-profile
     domain format (domain prefix + profile + newline), so the signed preimage converges with the
     XG-4 ``digest(core, "authority")`` profile (zero re-signing later); and
  2. for every authority vector, the contract's OWN ``canonical_core_bytes(core).hex()`` reproduces
     the committed ``canon_core_v2_bytes`` pin, byte-for-byte.

When a spec checkout IS present (``CONFORMANCE_SPEC_REPO`` or the sibling ``../spec``), it ADDITIONALLY
runs a LIVE cross-check: spec's real ``canon/py/canon.py`` ``canonical_bytes(core).hex()`` reproduces
each pin, and spec's ``_DOMAIN_PREFIX`` matches the signing prefix. Its ABSENCE downgrades that extra
cross-check to "unavailable" — it does NOT skip the gate. Exit 1 only on a real parity FAILURE.
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
    from consiliency_contract.authority import (
        AUTHORITY_SIGNING_PREFIX,
        canonical_core_bytes,
    )

    # --- Required floor #1: the signing prefix IS the canon-core v2 authority-profile domain format,
    #     verified against the literal format (no spec checkout needed).
    expected_prefix = b"spec-canon:v2:authority\n"
    if AUTHORITY_SIGNING_PREFIX != expected_prefix:
        print(json.dumps({
            "status": "fail",
            "reason": "authority signing prefix diverges from canon-core v2 domain format",
            "ours": AUTHORITY_SIGNING_PREFIX.decode("ascii", "replace"),
            "expected": expected_prefix.decode("ascii"),
        }))
        return 1

    # --- Required floor #2: the contract's OWN port reproduces every committed pin (self-contained).
    port_mismatches = []
    checked = 0
    for name in list_vectors():
        if not name.startswith("authority-"):
            continue
        vector = load_vector(name)
        core = vector["input"]["event"]["core"]
        pinned = vector["input"]["canon_core_v2_bytes"]
        actual = canonical_core_bytes(core).hex()
        checked += 1
        if actual != pinned:
            port_mismatches.append({"vector": vector["id"], "pinned": pinned, "port": actual})

    if port_mismatches:
        print(json.dumps({"status": "fail", "layer": "offline-pin", "mismatches": port_mismatches}))
        return 1

    # --- Optional live cross-check: the CURRENT spec canon-core v2 still reproduces the same pins.
    module, path = _load_spec_canon()
    if module is None:
        spec_crosscheck = {"status": "unavailable", "reason": "no spec checkout (set CONFORMANCE_SPEC_REPO)"}
    else:
        spec_prefix = (module._DOMAIN_PREFIX + "authority\n").encode("ascii")
        spec_mismatches = []
        if spec_prefix != AUTHORITY_SIGNING_PREFIX:
            spec_mismatches.append({"prefix": spec_prefix.decode("ascii", "replace")})
        for name in list_vectors():
            if not name.startswith("authority-"):
                continue
            vector = load_vector(name)
            core = vector["input"]["event"]["core"]
            pinned = vector["input"]["canon_core_v2_bytes"]
            if module.canonical_bytes(core).hex() != pinned:
                spec_mismatches.append({"vector": vector["id"], "pinned": pinned,
                                        "spec_canon": module.canonical_bytes(core).hex()})
        if spec_mismatches:
            print(json.dumps({"status": "fail", "layer": "live-spec-crosscheck",
                              "canon_source": path, "mismatches": spec_mismatches}))
            return 1
        spec_crosscheck = {"status": "pass", "canon_source": path}

    print(json.dumps({
        "status": "pass",
        "checked": checked,
        "prefix": AUTHORITY_SIGNING_PREFIX.decode("ascii"),
        "offline_pin": "pass",
        "spec_live_crosscheck": spec_crosscheck,
    }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
