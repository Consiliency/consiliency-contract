#!/usr/bin/env python3
"""Emit the Python verifier's verdict for every case of the test-registry matrix.

Consumed by the JS test suite (tests/contract.test.mjs), which builds the same
matrix and asserts that ``verifyAuthorityEvent`` returns the same
``{ok, reason}`` as ``verify_authority_event`` for every case: each authority
vector (plus two malformed events) against each registry variant, with each
form of the test-registry opt-in. The case names below are mirrored in the JS
suite; the JS test also asserts both sides produce the same set of case keys.
"""
from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from consiliency_contract import list_vectors, load_conformance_registry, load_registry, load_vector  # noqa: E402
from consiliency_contract.authority import verify_authority_event  # noqa: E402

_ABSENT = object()


def _with_marker(registry: dict, value: object) -> dict:
    out = copy.deepcopy(registry)
    if value is _ABSENT:
        out.pop("test_only", None)
    else:
        out["test_only"] = value
    return out


def registry_variants() -> dict[str, object]:
    test = load_conformance_registry("authority_key_registry_test")
    prod = load_registry("authority_key_registry")
    return {
        "test": test,
        "prod": prod,
        "prod_marked_test": _with_marker(prod, True),
        "test_marker_absent": _with_marker(test, _ABSENT),
        "test_marker_false": _with_marker(test, False),
        "test_marker_null": _with_marker(test, None),
        "test_marker_true_string": _with_marker(test, "true"),
        "test_marker_false_string": _with_marker(test, "false"),
        "test_marker_one": _with_marker(test, 1),
        "test_marker_zero": _with_marker(test, 0),
        # malformed shapes (JSON-expressible), each refused as malformed_registry
        "registry_null": None,
        "registry_list": [],
        "keys_null": dict(test, keys=None),
        "keys_object": dict(test, keys={}),
        "entry_not_record": dict(test, keys=[1]),
        # well-formed but odd entry values, judged by the ordinary checks
        "validity_not_record": dict(test, keys=[dict(k, validity="x") for k in test["keys"]]),
        "public_key_number": dict(test, keys=[dict(k, public_key=7) for k in test["keys"]]),
    }


# name -> kwargs for the opt-in (``omitted`` passes nothing).
OPT_IN_VARIANTS: dict[str, dict] = {
    "omitted": {},
    "false": {"allow_test_registry": False},
    "true": {"allow_test_registry": True},
    "one": {"allow_test_registry": 1},
    "true_string": {"allow_test_registry": "true"},
}


def event_cases() -> dict[str, tuple[object, str, str]]:
    """name -> (event, now, expected_cert_digest)."""
    cases: dict[str, tuple[object, str, str]] = {}
    for name in list_vectors():
        if not name.startswith("authority-"):
            continue
        inp = load_vector(name)["input"]
        cases[name] = (inp["event"], inp["now"], inp["expected_cert_digest"])
    valid = load_vector("authority-valid")["input"]
    cases["__malformed_empty__"] = ({}, valid["now"], valid["expected_cert_digest"])
    cases["__malformed_null__"] = (None, valid["now"], valid["expected_cert_digest"])
    return cases


def main() -> int:
    out = {}
    registries = registry_variants()
    for event_name, (event, now, digest) in event_cases().items():
        for reg_name, registry in registries.items():
            for opt_name, kwargs in OPT_IN_VARIANTS.items():
                res = verify_authority_event(event, registry, now=now, expected_cert_digest=digest, **kwargs)
                out[f"{event_name}|{reg_name}|{opt_name}"] = {"ok": res["ok"], "reason": res["reason"]}
    print(json.dumps(out, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
