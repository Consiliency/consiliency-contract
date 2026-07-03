"""Authority-event contract: canonical signed-core bytes + Ed25519 verify.

This is the ROOT OF TRUST reference implementation for the Python side (Portal
signer / spec ledger).

CANON OWNERSHIP: the signed-core bytes ARE spec canon-core v2
``canonical_bytes(core)`` (NOT a new/4th canon). ``canonicalize_core`` here is a
metadata-safe-ASCII / integer-only PORT of that one normative algorithm — the
AUTHORITY PROFILE, where non-ASCII / floats / null are fail-closed rejected by
design (amendment #3), which is exactly the subset on which canon v2's full
rules and this port emit identical bytes. Parity is pinned per vector
(``input.canon_core_v2_bytes``, from spec's canon.py) and the source is
digest-pinned in ``core/authority-canon/provenance.json``. See
``docs/design/authority-event-canonical-bytes.md`` for the normative spec.

``cryptography`` is imported lazily inside :func:`verify_authority_event` so the
base contract reader (``consiliency_contract``) stays dependency-free; only
consumers that actually verify signatures need the optional ``authority`` extra.
"""

from __future__ import annotations

import re
from typing import Any, Optional

# ASCII snake_case identifier — keeps JS/Python key sort order identical.
KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

# Metadata-safe ASCII for every signed-core STRING field: printable ASCII
# 0x21..0x7E EXCLUDING double-quote (0x22) and backslash (0x5C). Nothing in this
# set requires JSON escaping and nothing is non-ASCII, so the JS and Python
# serializers provably cannot diverge.
VALUE_RE = re.compile(r"^[\x21\x23-\x5b\x5d-\x7e]+$")

# RFC3339 UTC, fixed width, "Z" only — sorts lexicographically == chronologically.
TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

SUPPORTED_SCHEME = "ed25519"
_SAFE_INT_MAX = 2 ** 53 - 1


class AuthorityCanonicalError(ValueError):
    """Raised when a value cannot be canonicalized fail-closed."""


def canonicalize_core(value: Any) -> str:
    """Fail-closed canonical serializer for the signed core.

    Rejects anything that could serialize ambiguously across languages:
    non-ASCII, floats, unsafe integers, ``None``, illegal keys, unsafe strings.
    """
    # bool is a subclass of int — handle it first.
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        if not VALUE_RE.match(value):
            raise AuthorityCanonicalError(f"non-metadata-safe string: {value!r}")
        return '"' + value + '"'
    if isinstance(value, int):
        if abs(value) > _SAFE_INT_MAX:
            raise AuthorityCanonicalError(f"unsafe integer: {value}")
        return str(value)
    if isinstance(value, float):
        raise AuthorityCanonicalError(f"non-integer numeric forbidden in signed core: {value}")
    if isinstance(value, list):
        return "[" + ",".join(canonicalize_core(item) for item in value) + "]"
    if isinstance(value, dict):
        for key in value:
            if not isinstance(key, str) or not KEY_RE.match(key):
                raise AuthorityCanonicalError(f"illegal object key: {key!r}")
        keys = sorted(value)
        return "{" + ",".join('"' + key + '":' + canonicalize_core(value[key]) for key in keys) + "}"
    raise AuthorityCanonicalError(f"unsupported value in signed core: {value!r}")


def canonical_core_bytes(core: Any) -> bytes:
    """The exact bytes Portal signs and gp/spec verify."""
    # ``ascii`` encoding is a second fail-closed guard against non-ASCII.
    return canonicalize_core(core).encode("ascii")


def _is_timestamp(value: Any) -> bool:
    return isinstance(value, str) and bool(TIMESTAMP_RE.match(value))


def _within_window(now: Any, validity: Any) -> bool:
    if not isinstance(validity, dict):
        return False
    not_before = validity.get("not_before")
    not_after = validity.get("not_after")
    if not (_is_timestamp(now) and _is_timestamp(not_before) and _is_timestamp(not_after)):
        return False
    return not_before <= now < not_after


def _find_key(registry: Any, key_id: Any) -> Optional[dict]:
    for entry in (registry or {}).get("keys", []):
        if entry.get("key_id") == key_id:
            return entry
    return None


def _ed25519_verify(public_key_hex: str, signature_hex: str, message: bytes) -> bool:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        raw = bytes.fromhex(public_key_hex)
        signature = bytes.fromhex(signature_hex)
    except ValueError:
        return False
    if len(raw) != 32 or len(signature) != 64:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(raw).verify(signature, message)
        return True
    except InvalidSignature:
        return False


def verify_authority_event(
    event: Any,
    registry: Any,
    *,
    now: str,
    expected_cert_digest: str,
) -> dict[str, Any]:
    """Verify an authority event against the pinned key registry.

    AUTHORITATIVE SOURCES: scheme and public key come from the REGISTRY entry
    selected by the SIGNED core's ``key_id`` — never the event's self-declared
    ``signature.scheme``/``signature.key_id``. ``expected_cert_digest`` and
    ``now`` are supplied by the caller so binding/window checks are deterministic.

    Returns ``{"ok": bool, "reason": str}``.
    """
    if not isinstance(event, dict) or not isinstance(event.get("core"), dict):
        return {"ok": False, "reason": "malformed_event"}
    core = event["core"]
    signature = event.get("signature")
    if not isinstance(signature, dict) or not isinstance(signature.get("signature"), str):
        return {"ok": False, "reason": "missing_signature"}

    try:
        message = canonical_core_bytes(core)
    except AuthorityCanonicalError:
        return {"ok": False, "reason": "malformed_event"}

    key = _find_key(registry, core.get("key_id"))
    if key is None:
        return {"ok": False, "reason": "unknown_key_id"}

    if key.get("scheme") != SUPPORTED_SCHEME or signature.get("scheme") != key.get("scheme"):
        return {"ok": False, "reason": "algorithm_confusion"}
    if key.get("revoked") is True:
        return {"ok": False, "reason": "key_revoked"}
    if not _within_window(now, key.get("validity")):
        return {"ok": False, "reason": "key_expired"}

    if core.get("approver") != key.get("approver"):
        return {"ok": False, "reason": "signer_approver_mismatch"}

    if not isinstance(expected_cert_digest, str) or core.get("cert_digest") != expected_cert_digest:
        return {"ok": False, "reason": "cert_digest_mismatch"}
    if not _within_window(now, core.get("validity")):
        return {"ok": False, "reason": "core_validity_expired"}

    if not _ed25519_verify(key["public_key"], signature["signature"], message):
        return {"ok": False, "reason": "bad_signature"}
    return {"ok": True, "reason": "verified"}
