#!/usr/bin/env python3
"""Deterministically generate the authority-key registry + conformance vectors.

This script is the ONLY place a private Ed25519 key exists, and it is NOT part
of the published package (package.json `files` and the pyproject wheel/sdist
force-includes cover core/, conformance/, src/ — never scripts/). Private keys
are regenerated on demand from the documented SEED_LABELS below (SHA-256 of a
stable label), so nothing secret is committed: the repo carries only the PUBLIC
keys (in the registry) and the signed vectors.

Ed25519 signatures are deterministic (RFC 8032), so re-running this reproduces
byte-identical registry + vectors. Run from the repo root:

    python3 scripts/gen_authority_vectors.py            # write files
    python3 scripts/gen_authority_vectors.py --check    # verify committed == regenerated
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from consiliency_contract.authority import (  # noqa: E402
    AUTHORITY_SIGNING_PREFIX,
    authority_signing_preimage,
    canonical_core_bytes,
)

REGISTRY_PATH = ROOT / "core" / "registries" / "authority-key-registry.json"
VECTORS_DIR = ROOT / "conformance" / "vectors"
CANON_PROVENANCE_PATH = ROOT / "core" / "authority-canon" / "provenance.json"


import functools  # noqa: E402


@functools.lru_cache(maxsize=1)
def _load_spec_canon():
    """Import spec's canon-core v2 Python reference, or return None.

    The authority signed-core bytes ARE canon-core v2's `canonical_bytes`; this
    contract carries a metadata-safe/integer-only PORT of that one algorithm, not
    a new canon. At generation time we pin the canon-core-v2 bytes per vector by
    calling spec's real `canon.py` (an INDEPENDENT witness), so the committed
    parity test proves the port matches without a spec checkout at CI time.

    Locate spec via `CONFORMANCE_SPEC_REPO` (a spec checkout root) or the sibling
    `../spec` default; canon.py lives at `<root>/canon/py/canon.py`.
    """
    import importlib.util
    import os

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
            return module, candidate, root
    return None, None, None


def _canon_core_v2_hex(core: dict):
    """canon-core v2 `canonical_bytes(core)` hex from spec's canon.py, or None."""
    module, _, _ = _load_spec_canon()
    if module is None:
        return None
    return module.canonical_bytes(core).hex()

NOW = "2026-07-03T12:00:00Z"
CERT_DIGEST = hashlib.sha256(b"consiliency/xg1/graphbase.bundle.deterministic-export/cert").hexdigest()
OTHER_CERT_DIGEST = hashlib.sha256(b"consiliency/xg1/some-other-cert").hexdigest()
PORTAL_APPROVER = "consiliency:portal:governance"

# key_id -> stable seed label (SHA-256 of the label is the 32-byte private seed).
SEED_LABELS = {
    "portal-authority-ed25519-v1": "consiliency.authority_event.v1/portal-authority-ed25519-v1",
    "portal-authority-ed25519-rotated-out": "consiliency.authority_event.v1/portal-authority-ed25519-rotated-out",
    "portal-authority-ed25519-expired": "consiliency.authority_event.v1/portal-authority-ed25519-expired",
    # Attacker key — deliberately NOT registered.
    "attacker-key-001": "consiliency.authority_event.v1/ATTACKER-not-in-registry",
}

# EXTERNAL production key(s): a REAL public key provided out-of-band. Unlike the
# fixture keys above (whose private seed is sha256(label) and therefore publicly
# derivable — they exist ONLY to sign the conformance vectors), a production key's
# PRIVATE half is generated off-box and held in the Portal's GCP Secret Manager;
# it is NOT derivable from any label. The registry commits ONLY the public key, and
# this generator never has access to the private half.
EXTERNAL_PUBLIC_KEYS = {
    "portal-authority-ed25519-prod-v1": "27499adc83381305359e7950b6ea9f1f7fa93480c9fe647b9fc8d4a64d6a467a",
}


def _private_key(key_id: str) -> Ed25519PrivateKey:
    seed = hashlib.sha256(SEED_LABELS[key_id].encode("ascii")).digest()
    return Ed25519PrivateKey.from_private_bytes(seed)


def _public_hex(key_id: str) -> str:
    from cryptography.hazmat.primitives import serialization

    raw = _private_key(key_id).public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return raw.hex()


def _sign(key_id: str, core: dict) -> str:
    # Sign the canon-core v2 AUTHORITY-PROFILE digest preimage (domain-prefixed),
    # not the bare bytes (XG-4 domain-separation decision).
    return _private_key(key_id).sign(authority_signing_preimage(core)).hex()


def build_registry() -> dict:
    return {
        "schema": "consiliency.authority_key_registry.v1",
        "$comment": (
            "The vendored, digest-pinned root of trust. This registry living IN the "
            "contract repo — gated by the repo's merge gate — IS the physical root of "
            "trust; there is deliberately no live-fetch/Portal-served option (panel "
            "amendment #2). Verification selects a key by the SIGNED core's key_id and "
            "takes scheme + public_key + approver + validity + revoked FROM HERE, never "
            "from the event. Only PUBLIC keys live here; the Portal holds the private key."
        ),
        "rotation": {
            "policy": "Add a new key_id with its own validity window; overlap windows to roll signers. Never reuse a retired key_id.",
            "identity_binding": "A key_id is bound to exactly one approver identity; a signature verifies only if core.approver == the key's registered approver."
        },
        "revocation": {
            "policy": "Set revoked:true (or let validity lapse) to retire a key_id. A revoked or out-of-window key fails verification regardless of an otherwise-valid signature.",
            "irreversible": True
        },
        "keys": [
            {
                "key_id": "portal-authority-ed25519-v1",
                "scheme": "ed25519",
                "public_key": _public_hex("portal-authority-ed25519-v1"),
                "approver": PORTAL_APPROVER,
                "validity": {"not_before": "2026-01-01T00:00:00Z", "not_after": "2027-01-01T00:00:00Z"},
                "revoked": False
            },
            {
                "key_id": "portal-authority-ed25519-rotated-out",
                "scheme": "ed25519",
                "public_key": _public_hex("portal-authority-ed25519-rotated-out"),
                "approver": PORTAL_APPROVER,
                "validity": {"not_before": "2026-01-01T00:00:00Z", "not_after": "2027-01-01T00:00:00Z"},
                "revoked": True
            },
            {
                "key_id": "portal-authority-ed25519-expired",
                "scheme": "ed25519",
                "public_key": _public_hex("portal-authority-ed25519-expired"),
                "approver": PORTAL_APPROVER,
                "validity": {"not_before": "2025-01-01T00:00:00Z", "not_after": "2025-06-01T00:00:00Z"},
                "revoked": False
            },
            {
                # PRODUCTION key — real, externally generated; private half in the
                # Portal's GCP Secret Manager (secret AUTHORITY_SIGNER_ED25519_PROD_V1).
                # Public key committed here; not seed-derivable (see EXTERNAL_PUBLIC_KEYS).
                "key_id": "portal-authority-ed25519-prod-v1",
                "scheme": "ed25519",
                "public_key": EXTERNAL_PUBLIC_KEYS["portal-authority-ed25519-prod-v1"],
                "approver": PORTAL_APPROVER,
                "validity": {"not_before": "2026-07-04T00:00:00Z", "not_after": "2027-07-04T00:00:00Z"},
                "revoked": False
            }
        ]
    }


def base_core(**overrides) -> dict:
    core = {
        "authority_event_version": "1",
        "event_type": "ratify",
        "decision_id": "d1f0c0de-0000-4000-8000-000000000001",
        "audience": {
            "repo": "governed-pipeline",
            "env": "pilot",
            "lineage": "main",
            "policy_epoch": "2026Q3",
            "canon_version": "v2",
            "phase": "XG1",
            "subgraph": "graphbase.bundle.deterministic-export"
        },
        "cert_digest": CERT_DIGEST,
        "approver": PORTAL_APPROVER,
        "key_id": "portal-authority-ed25519-v1",
        "validity": {"not_before": "2026-01-01T00:00:00Z", "not_after": "2027-01-01T00:00:00Z"},
        "custody_binding": {"phase_loop_driver_allowed": False},
        "proposal_ref": "portal:proposal:0001",
        "ratify_ref": "portal:ratify:0001"
    }
    core.update(overrides)
    return core


def event(core: dict, sign_with: str, *, scheme: str = "ed25519", mutate_sig: bool = False) -> dict:
    sig_hex = _sign(sign_with, core)
    if mutate_sig:
        # Flip the last hex nibble — still 128 lowercase hex, but not the real signature.
        sig_hex = sig_hex[:-1] + ("0" if sig_hex[-1] != "0" else "1")
    return {
        "schema": "consiliency.authority_event_protocol.v1",
        "core": core,
        "signature": {"scheme": scheme, "key_id": core["key_id"], "signature": sig_hex}
    }


def chain_block(core: dict) -> dict:
    entry = hashlib.sha256(canonical_core_bytes(core)).hexdigest()
    root = hashlib.sha256(b"root:" + entry.encode("ascii")).hexdigest()
    prev = "0" * 64
    return {
        "entry_digest": entry,
        "previous_entry_digest": prev,
        "root_digest": root,
        "inclusion_proof": {"entry_digest": entry, "previous_entry_digest": prev, "root_digest": root}
    }


def _pin_canon_bytes(core: dict) -> str:
    """The committed canon-core-v2 byte pin for a core.

    Prefer spec's canon.py (independent witness); cross-assert it equals our port.
    Fall back to our port only when spec is absent (offline regen), so `--check`
    still runs; the durable committed test asserts port == pin regardless.
    """
    mine = canonical_core_bytes(core).hex()
    theirs = _canon_core_v2_hex(core)
    if theirs is not None and theirs != mine:
        raise SystemExit(
            f"CANON DIVERGENCE: contract port != canon-core v2\n  port : {mine}\n  canon: {theirs}"
        )
    return theirs if theirs is not None else mine


def scenario(event_obj: dict, *, expected_cert_digest: str = CERT_DIGEST) -> dict:
    return {
        "schema": "consiliency.authority_verification_scenario.v1",
        "registry": "authority_key_registry",
        "now": NOW,
        "expected_cert_digest": expected_cert_digest,
        # The exact bytes the Ed25519 signature covers = canon-core v2
        # `canonical_bytes(core)`. Pinned here (from spec's canon.py) so the
        # contract's byte parity with canon-core v2 is a committed, offline-checkable fact.
        "canon_core_v2_bytes": _pin_canon_bytes(event_obj["core"]),
        "event": event_obj
    }


def decision(status: str, code: str, severity: str, message: str) -> dict:
    return {
        "schema": "consiliency.conformance_decision.v1",
        "status": status,
        "maturity": "presence-only",
        "findings": [{"code": code, "severity": severity, "message": message}]
    }


def vector(vid, description, scen, dec, verifies, reason, schema_valid) -> dict:
    return {
        "id": vid,
        "description": description,
        "input": scen,
        "decision": dec,
        "expected": {"verifies": verifies, "reason": reason, "schema_valid": schema_valid}
    }


def build_vectors() -> list[dict]:
    vectors: list[dict] = []

    # 1. VALID — a real Ed25519-signed event verifies.
    valid_event = event(base_core(), "portal-authority-ed25519-v1")
    vectors.append(vector(
        "authority-valid",
        "A Portal-signed authority event with a valid Ed25519 signature over the canonical core, "
        "in-window, approver bound to the signing key, and cert_digest matching the cert -> VERIFIES.",
        scenario(valid_event),
        decision("accepted", "authority.verified", "info", "Valid Ed25519-signed authority event."),
        True, "verified", True
    ))

    # 2. CORE/CHAIN INDEPENDENCE — appending ledger chain data does NOT invalidate the core signature.
    chained = {**valid_event, "chain": chain_block(base_core())}
    vectors.append(vector(
        "authority-chain-appended-still-verifies",
        "The SAME valid event with spec's ledger `chain` block appended (entry/previous/root digests + "
        "inclusion proof). Because the signature covers only the core, the appended chain does NOT "
        "invalidate it -> still VERIFIES. Separation-of-powers: spec appends without re-signing.",
        scenario(chained),
        decision("accepted", "authority.verified", "info", "Chain-appended event still verifies over the core."),
        True, "verified", True
    ))

    # 3. BAD SIGNATURE — signature bytes mutated.
    vectors.append(vector(
        "authority-bad-signature",
        "A well-formed event whose signature bytes were altered -> REJECT (bad_signature).",
        scenario(event(base_core(), "portal-authority-ed25519-v1", mutate_sig=True)),
        decision("rejected", "authority.bad_signature", "block", "Signature does not verify over the canonical core."),
        False, "bad_signature", True
    ))

    # 4. MISSING SIGNATURE — no signature block at all.
    unsigned = {"schema": "consiliency.authority_event_protocol.v1", "core": base_core()}
    vectors.append(vector(
        "authority-missing-signature",
        "An event with no signature block -> REJECT (missing_signature). Schema-invalid (signature required).",
        scenario(unsigned),
        decision("rejected", "authority.missing_signature", "block", "No signature present."),
        False, "missing_signature", False
    ))

    # 5. FORGED / self-minted — attacker key_id (not in registry), attacker's own key + approver.
    forged_core = base_core(key_id="attacker-key-001", approver="attacker:self-approved",
                            decision_id="attacker-decision-9999")
    vectors.append(vector(
        "authority-forged-self-minted",
        "THE EXPLOIT: an attacker mints an event with their own key_id, own approver, own decision_id, and "
        "signs it with their own key (zero Portal). The keyless digest stack ACCEPTED this; the real "
        "signature stack REJECTs it because attacker-key-001 is not in the pinned registry (unknown_key_id).",
        scenario(event(forged_core, "attacker-key-001")),
        decision("rejected", "authority.unknown_key_id", "block", "Signing key_id is not in the pinned authority-key registry."),
        False, "unknown_key_id", True
    ))

    # 6. UNKNOWN key_id — a key_id simply absent from the registry (typo/rotation gap), any signer.
    vectors.append(vector(
        "authority-unknown-key-id",
        "core.key_id references a key that is not present in the registry -> REJECT (unknown_key_id).",
        scenario(event(base_core(key_id="portal-authority-ed25519-v9"), "attacker-key-001")),
        decision("rejected", "authority.unknown_key_id", "block", "Signing key_id is not in the pinned authority-key registry."),
        False, "unknown_key_id", True
    ))

    # 7. WRONG KEY behind a valid key_id — real registered key_id, but signed with the attacker key.
    vectors.append(vector(
        "authority-wrong-key-valid-id",
        "core.key_id names a real registered key, but the signature was produced by a DIFFERENT (attacker) "
        "private key -> REJECT (bad_signature): the registry pubkey does not verify the attacker signature.",
        scenario(event(base_core(), "attacker-key-001")),
        decision("rejected", "authority.bad_signature", "block", "Registry public key does not verify the signature."),
        False, "bad_signature", True
    ))

    # 8. ALGORITHM CONFUSION — self-declared scheme disagrees with the registry.
    vectors.append(vector(
        "authority-algorithm-confusion",
        "The event self-declares signature.scheme=hmac-sha256 while the registry key is ed25519 -> REJECT "
        "(algorithm_confusion). Verification trusts the REGISTRY scheme, never the event's. Schema-invalid "
        "(signature.scheme const is ed25519).",
        scenario(event(base_core(), "portal-authority-ed25519-v1", scheme="hmac-sha256")),
        decision("rejected", "authority.algorithm_confusion", "block", "Declared scheme disagrees with the registry key scheme."),
        False, "algorithm_confusion", False
    ))

    # 9. SIGNER<->APPROVER mismatch — validly signed by the real key, but core.approver != the key's approver.
    mismatch_core = base_core(approver="attacker:self-approved")
    vectors.append(vector(
        "authority-signer-approver-mismatch",
        "A cryptographically-valid signature by the real portal key, but core.approver does not match the "
        "approver the key is registered to -> REJECT (signer_approver_mismatch). Amendment #4: signer==approver "
        "is a key-binding-in-registry check.",
        scenario(event(mismatch_core, "portal-authority-ed25519-v1")),
        decision("rejected", "authority.signer_approver_mismatch", "block", "Signing key is not registered to the core's approver."),
        False, "signer_approver_mismatch", True
    ))

    # 10. REVOKED key — validly signed by a key the registry marks revoked.
    revoked_core = base_core(key_id="portal-authority-ed25519-rotated-out")
    vectors.append(vector(
        "authority-key-revoked",
        "A valid signature by a key the registry marks revoked:true -> REJECT (key_revoked) despite the "
        "signature verifying.",
        scenario(event(revoked_core, "portal-authority-ed25519-rotated-out")),
        decision("rejected", "authority.key_revoked", "block", "Signing key is revoked in the registry."),
        False, "key_revoked", True
    ))

    # 11. EXPIRED key — validly signed by a key whose registry validity window has lapsed.
    expired_core = base_core(key_id="portal-authority-ed25519-expired")
    vectors.append(vector(
        "authority-key-expired",
        "A valid signature by a key whose registry validity window ended before `now` -> REJECT (key_expired).",
        scenario(event(expired_core, "portal-authority-ed25519-expired")),
        decision("rejected", "authority.key_expired", "block", "Signing key is outside its registry validity window."),
        False, "key_expired", True
    ))

    # 12. CERT-DIGEST mismatch — valid event, but bound to a different cert than the one presented.
    vectors.append(vector(
        "authority-cert-digest-mismatch",
        "A valid event for one cert must NOT ratify a DIFFERENT cert (N4). core.cert_digest is validly signed, "
        "but the presented cert's digest differs -> REJECT (cert_digest_mismatch).",
        scenario(event(base_core(), "portal-authority-ed25519-v1"), expected_cert_digest=OTHER_CERT_DIGEST),
        decision("rejected", "authority.cert_digest_mismatch", "block", "Event cert_digest does not match the presented cert."),
        False, "cert_digest_mismatch", True
    ))

    # 13. CORE VALIDITY expired — the event's own validity window has lapsed (key still valid).
    stale_core = base_core(validity={"not_before": "2025-01-01T00:00:00Z", "not_after": "2025-06-01T00:00:00Z"})
    vectors.append(vector(
        "authority-core-validity-expired",
        "A valid signature by a current key, but the event's own validity window ended before `now` -> "
        "REJECT (core_validity_expired).",
        scenario(event(stale_core, "portal-authority-ed25519-v1")),
        decision("rejected", "authority.core_validity_expired", "block", "Authority event is outside its own validity window."),
        False, "core_validity_expired", True
    ))

    return vectors


def build_provenance():
    """Digest-pin the spec canon-core v2 source this port was verified against.

    Returns None when spec is unavailable (offline regen); the committed file is
    then left untouched. A change to spec's canon source flips these digests and
    trips re-verification of the byte parity.
    """
    import subprocess

    module, canon_py, spec_root = _load_spec_canon()
    if module is None:
        return None

    def _sha256(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    try:
        commit = subprocess.run(
            ["git", "-C", str(spec_root), "rev-parse", "HEAD"],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        commit = None

    # Convergence check: our authority signing prefix MUST equal what canon-core v2
    # will produce for a `digest(core, "authority")` — its domain prefix + profile
    # + newline — so there is zero re-signing when XG-4 registers the profile.
    expected_prefix = (module._DOMAIN_PREFIX + "authority\n").encode("ascii")
    if AUTHORITY_SIGNING_PREFIX != expected_prefix:
        raise SystemExit(
            "AUTHORITY PREFIX DIVERGENCE from canon-core v2 domain format:\n"
            f"  ours : {AUTHORITY_SIGNING_PREFIX!r}\n  canon: {expected_prefix!r}"
        )

    canon_ts = spec_root / "canon" / "ts" / "canon.ts"
    spec_md = spec_root / "canon" / "SPEC.md"
    return {
        "schema": "consiliency.authority_canon_provenance.v1",
        "$comment": (
            "The authority signed-core bytes ARE canon-core v2 `canonical_bytes(core)`. This contract "
            "carries a metadata-safe-ASCII / integer-only PORT of that one normative algorithm (the "
            "AUTHORITY PROFILE — non-ASCII/float/null are fail-closed rejected by design, amendment #3), "
            "NOT a fourth canon. These digests pin the exact spec canon-core v2 source the port was proven "
            "byte-identical against; a change here must re-verify parity."
        ),
        "canon_version": "spec-canon:v2",
        "normative_source": {
            "repo": "spec",
            "spec_commit": commit,
            "files": {
                "canon/py/canon.py": _sha256(canon_py) if canon_py.exists() else None,
                "canon/ts/canon.ts": _sha256(canon_ts) if canon_ts.exists() else None,
                "canon/SPEC.md": _sha256(spec_md) if spec_md.exists() else None,
            },
        },
        "authority_profile": {
            "profile_id": "authority",
            "domain_prefix": AUTHORITY_SIGNING_PREFIX.decode("ascii"),
            "signed_preimage": "\"spec-canon:v2:authority\\n\" || canon_core_v2.canonical_bytes(core)",
            "canonical_bytes": "canon_core_v2.canonical_bytes(core) (pinned per vector as input.canon_core_v2_bytes)",
            "field_constraints": "every signed-core string is metadata-safe ASCII (0x21-0x7E minus '\"' and '\\\\'); no floats/NaN/Inf; no null; ASCII snake_case keys",
            "signature": "ed25519 over the signed_preimage above",
            "domain_separation": (
                "SETTLED (XG-4 decision, 2026-07-03): the signature covers the DOMAIN-PREFIXED authority-profile "
                "digest preimage `spec-canon:v2:authority\\n || canonical_bytes(core)`, NOT bare bytes — preventing "
                "cross-context signature reuse and matching canon-core v2's per-profile prefixing. canon-core v2 "
                "does not yet register an `authority` profile (the four are semantic-content, run, artifact-byte, "
                "certificate); this prefix is byte-identical to what `canon.digest(core, \"authority\")` will hash "
                "once XG-4 adds it, so there is ZERO re-signing at XG-4 (the convergence obligation)."
            ),
        },
    }


def _dump(path: Path, data: dict) -> str:
    return json.dumps(data, indent=2, ensure_ascii=False) + "\n"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="verify committed files match regenerated output")
    args = parser.parse_args(argv)

    outputs = {REGISTRY_PATH: build_registry()}
    for vec in build_vectors():
        outputs[VECTORS_DIR / f"{vec['id']}.json"] = vec
    provenance = build_provenance()
    if provenance is not None:
        outputs[CANON_PROVENANCE_PATH] = provenance

    if args.check:
        mismatched = []
        for path, data in outputs.items():
            want = _dump(path, data)
            have = path.read_text(encoding="utf-8") if path.exists() else None
            if have != want:
                mismatched.append(str(path.relative_to(ROOT)))
        if mismatched:
            print("STALE (regenerate with scripts/gen_authority_vectors.py):", *mismatched, sep="\n  ")
            return 1
        note = "" if provenance is not None else " (spec canon absent: provenance not re-checked)"
        print(f"OK: registry + {len(outputs) - 1 if provenance is None else len(outputs) - 2} vectors match committed output{note}")
        return 0

    CANON_PROVENANCE_PATH.parent.mkdir(parents=True, exist_ok=True)
    for path, data in outputs.items():
        path.write_text(_dump(path, data), encoding="utf-8")
    extra = "" if provenance is None else " + canon provenance"
    print(f"wrote registry + {len([k for k in outputs if k != CANON_PROVENANCE_PATH and k != REGISTRY_PATH])} vectors{extra}")
    if provenance is None:
        print("WARN: spec canon-core v2 not found (set CONFORMANCE_SPEC_REPO); provenance + pins used the local port only")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
