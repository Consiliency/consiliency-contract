#!/usr/bin/env python3
"""Slice X — the §12.3 interchangeability test (DESIGN-projection-discovery.md).

Proves the `projections.index.v1` merge is a PURE FUNCTION of the manifests by
feeding the fixed manifest set from
`conformance/vectors/projections-index-pure-merge-deterministic.json` through
the ACTUAL index-building logic of the real `spec-render/build_projections_index.py`
driver (fetched by content from a sibling `spec` checkout — no vendoring, no
reimplementation) and asserting it reproduces `expected.index` byte-for-byte,
the same fixed point the contract's own JS and Python reference mergers already
reproduce (`tests/contract.test.mjs`, `tests/test_contract.py`).

This is NOT a reimplementation of the merge — it runs spec's own script,
unmodified, against a fixture directory laid out the way spec's aggregator
expects (`{projcode,certified}/<repo>/<name>.manifest.json` [+ `.refresh.json`
sidecars]), because `build_projections_index.py` globs relative to its own
file location and takes no `--render-dir` flag.

Locating the driver:
  - `CONFORMANCE_SPEC_REPO` (env) — path to a `spec` checkout. Defaults to
    trying sibling directories next to this contract checkout.
  - `CONFORMANCE_SPEC_REF` (env) — git ref to read the driver from. Defaults to
    trying `origin/main`, then `main`, then `HEAD`.
  - If no checkout/ref combination yields the file, this SKIPS (status
    "skip") rather than failing — a contract-only CI run has no reason to have
    `spec` checked out. See `README.md` in this directory for what "skip" does
    and does not prove.

Exit codes: 0 = pass or skip, 1 = fail (a real interchangeability finding —
the real producer and the vector/reference mergers disagree).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Optional

HERE = Path(__file__).resolve().parent            # conformance/interchangeability
ROOT = HERE.parent.parent                          # contract repo root
VECTORS_DIR = ROOT / "conformance" / "vectors"

DEFAULT_VECTOR = "projections-index-pure-merge-deterministic"
DRIVER_REL_PATH = "spec-render/build_projections_index.py"


def canon(value: Any) -> str:
    """Same canonical form the readers' own tests compare against."""
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _candidate_spec_repos() -> list[Path]:
    env = os.environ.get("CONFORMANCE_SPEC_REPO")
    if env:
        return [Path(env).expanduser()]
    # Honest default: only a sibling checkout next to this contract repo is
    # guessed at. No home-directory or absolute-path assumptions.
    return [ROOT.parent / "spec"]


def _git_show(repo: Path, ref: str, rel_path: str) -> Optional[bytes]:
    try:
        out = subprocess.run(
            ["git", "-C", str(repo), "show", f"{ref}:{rel_path}"],
            capture_output=True, check=True,
        )
        return out.stdout
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None


def locate_driver() -> tuple[Optional[bytes], Optional[Path], Optional[str]]:
    """Return (driver_bytes, spec_repo, ref_used) or (None, None, None)."""
    env_ref = os.environ.get("CONFORMANCE_SPEC_REF")
    refs = [env_ref] if env_ref else ["origin/main", "main", "HEAD"]
    for repo in _candidate_spec_repos():
        if not (repo / ".git").exists():
            continue
        for ref in refs:
            content = _git_show(repo, ref, DRIVER_REL_PATH)
            if content is not None:
                return content, repo, ref
    return None, None, None


def load_vector(name: str) -> dict[str, Any]:
    path = VECTORS_DIR / f"{name}.json"
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def build_fixture(tmp: Path, vector: dict[str, Any]) -> None:
    """Lay out the vector's manifests + sidecars the way the real aggregator
    globs them: `{projcode,certified}/<repo>/<name>.manifest.json` (+ a
    same-named `.refresh.json` sidecar per DESIGN §2.3/§5's naming convention).
    """
    manifests = vector["input"]["manifests"]
    sidecars = {s["manifest_path"]: s for s in vector["input"].get("refresh_sidecars", [])}

    for m in manifests:
        subdir = "certified" if m["kind"] == "proj-S-certified" else "projcode"
        target_dir = tmp / subdir / m["target"]
        target_dir.mkdir(parents=True, exist_ok=True)
        filename = os.path.basename(m["manifest_path"])
        (target_dir / filename).write_text(json.dumps(m), encoding="utf-8")

        sidecar = sidecars.get(m["manifest_path"])
        if sidecar is not None:
            assert filename.endswith(".manifest.json"), filename
            sidecar_name = filename[: -len(".manifest.json")] + ".refresh.json"
            (target_dir / sidecar_name).write_text(json.dumps(sidecar), encoding="utf-8")


def run_driver(tmp: Path, driver_bytes: bytes) -> dict[str, Any]:
    driver_path = tmp / "build_projections_index.py"
    driver_path.write_bytes(driver_bytes)

    gen = subprocess.run(
        [sys.executable, str(driver_path)], cwd=tmp, capture_output=True, text=True,
    )
    result: dict[str, Any] = {
        "generate_returncode": gen.returncode,
        "generate_stdout": gen.stdout.strip(),
        "generate_stderr": gen.stderr.strip(),
    }
    index_path = tmp / "projections.index.json"
    if gen.returncode != 0 or not index_path.exists():
        result["index"] = None
        return result
    result["index"] = json.loads(index_path.read_text(encoding="utf-8"))

    # Validate the real driver's output against the CURRENT contract schema
    # (not a possibly-stale vendored copy in spec) by pointing it at this repo.
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    val = subprocess.run(
        [sys.executable, str(driver_path), "--validate"],
        cwd=tmp, capture_output=True, text=True, env=env,
    )
    result["validate_returncode"] = val.returncode
    result["validate_stdout"] = val.stdout.strip()
    result["validate_stderr"] = val.stderr.strip()
    return result


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vector", default=DEFAULT_VECTOR)
    args = parser.parse_args(argv)

    driver_bytes, spec_repo, ref_used = locate_driver()
    if driver_bytes is None:
        print(json.dumps({
            "status": "skip",
            "reason": (
                f"no spec checkout with {DRIVER_REL_PATH} found "
                f"(set CONFORMANCE_SPEC_REPO to override the sibling-checkout default)"
            ),
        }))
        return 0

    vector = load_vector(args.vector)
    expected_canon = canon(vector["expected"]["index"])

    with tempfile.TemporaryDirectory(prefix="consiliency-interchangeability-") as tmp_str:
        tmp = Path(tmp_str)
        build_fixture(tmp, vector)
        driven = run_driver(tmp, driver_bytes)

    report: dict[str, Any] = {
        "vector": args.vector,
        "spec_repo": str(spec_repo),
        "spec_ref": ref_used,
        "driver_sha256": hashlib.sha256(driver_bytes).hexdigest(),
        "generate_returncode": driven["generate_returncode"],
    }

    if driven["index"] is None:
        report["status"] = "fail"
        report["reason"] = "real driver did not produce projections.index.json"
        report["generate_stderr"] = driven["generate_stderr"]
        print(json.dumps(report))
        return 1

    real_canon = canon(driven["index"])
    byte_identical = real_canon == expected_canon
    report["byte_identical_to_vector"] = byte_identical
    report["validate_returncode"] = driven.get("validate_returncode")
    report["validate_stdout"] = driven.get("validate_stdout")
    schema_valid = driven.get("validate_returncode") == 0

    if not byte_identical:
        report["status"] = "fail"
        report["reason"] = "real driver's index differs from expected.index — reference merger and real producer have drifted"
        report["real_index"] = driven["index"]
    elif not schema_valid:
        report["status"] = "fail"
        report["reason"] = "real driver's output failed schema validation against the current contract"
        report["validate_stderr"] = driven.get("validate_stderr")
    else:
        report["status"] = "pass"

    print(json.dumps(report))
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
