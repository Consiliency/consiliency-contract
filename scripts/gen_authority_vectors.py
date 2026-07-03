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
from consiliency_contract.authority import canonical_core_bytes  # noqa: E402

REGISTRY_PATH = ROOT / "core" / "registries" / "authority-key-registry.json"
VECTORS_DIR = ROOT / "conformance" / "vectors"

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
    return _private_key(key_id).sign(canonical_core_bytes(core)).hex()


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


def scenario(event_obj: dict, *, expected_cert_digest: str = CERT_DIGEST) -> dict:
    return {
        "schema": "consiliency.authority_verification_scenario.v1",
        "registry": "authority_key_registry",
        "now": NOW,
        "expected_cert_digest": expected_cert_digest,
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


def _dump(path: Path, data: dict) -> str:
    return json.dumps(data, indent=2, ensure_ascii=False) + "\n"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="verify committed files match regenerated output")
    args = parser.parse_args(argv)

    outputs = {REGISTRY_PATH: build_registry()}
    for vec in build_vectors():
        outputs[VECTORS_DIR / f"{vec['id']}.json"] = vec

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
        print(f"OK: registry + {len(outputs) - 1} vectors match committed output")
        return 0

    for path, data in outputs.items():
        path.write_text(_dump(path, data), encoding="utf-8")
    print(f"wrote registry + {len(outputs) - 1} vectors")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
