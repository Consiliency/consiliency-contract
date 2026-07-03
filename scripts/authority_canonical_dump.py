#!/usr/bin/env python3
"""Emit {vector_id: hex(canonical_core_bytes(core))} for every authority vector.

Consumed by the JS test suite (tests/contract.test.mjs) to prove — empirically,
byte-for-byte — that the Python and JS canonical-core-bytes algorithms agree.
This is the interop contract's acceptance check; if this ever diverges, a
Portal-signed core would produce a signature gp could not verify.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from consiliency_contract import list_vectors, load_vector  # noqa: E402
from consiliency_contract.authority import canonical_core_bytes  # noqa: E402

out = {}
for name in list_vectors():
    if not name.startswith("authority-"):
        continue
    vector = load_vector(name)
    core = vector["input"]["event"]["core"]
    out[vector["id"]] = canonical_core_bytes(core).hex()

print(json.dumps(out, sort_keys=True))
