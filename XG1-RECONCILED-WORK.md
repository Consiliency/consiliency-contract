# XG-1 authority leg — reconciled state + THIS repo's remaining work

> Verified read-only across all four repos on 2026-07-16 by the consiliency-portal agent.
> The 2026-07-03 `DESIGN-xg1-completion.md` / original brief are **stale on how much is already done**.
> Ground new work here, not in the stale "build the signer / pick the scheme" framing.

## Already DONE + merged (do NOT re-decide or rebuild)
- **Signature scheme is SETTLED + SHIPPED.** Ed25519 (Option B) — panel-settled (DESIGN §9) and **merged + production-key-wired** in consiliency-portal (`authority_signer.py`, PR #175/#180/#181). It is NOT an open HMAC-vs-Ed25519 decision.
- **Portal producer half is BYTE-PARITY-COMPLETE.** A real Portal-signed `core` (`cert_digest` mandatory = N4; decision-id-vs-phaseId reconciled; `phase_loop_driver_allowed:false`) verifies **byte-for-byte** at contract **v0.6.5** (`{ok:true, verified}`) AND at spec's ingress (`receive_authority_event`: accepted, signature valid post chain-append). Contract 13-vector parity gate + spec ingress gate (12/12 + delivery 4/4) pass. No re-vendoring needed.
- contract core (`authority-event-protocol.schema.json` @ v0.6.5), spec ingress receiver (`spec-engine/authority/ingress.py`, N1), gp consumer gate (#102), and the Portal forward client (`handlers/authority_signer.py` → `SPEC_AUTHORITY_LEDGER_URL`) all exist.

## The real remaining work (Slice 4), by owner
| Repo | Remaining |
|---|---|
| consiliency-portal | wire live overlay ratify UI → `/api/control-plane/ratify` (Ed25519 path) + operational config → then activate flags + acceptance |
| spec | add a live HTTP **listener** binding around the verified receiver; confirm N5 delivery of `authority-event.json` |
| governed-pipeline | confirm `cert_digest` verification + `authority-forged` / cert-digest-mismatch negative tests REJECT |
| consiliency-contract | confirm the `authority-forged` conformance vector is published (negative vector) |

**Pilot node:** `XG1 ↔ graphbase.bundle.deterministic-export` (design default). **Gating cross-repo dep for the live loop: spec's HTTP listener** (the Portal forward client has nowhere to POST until it exists). Cross-vendor CR convergence before any merge.

## YOUR PART — consiliency-contract
The core is shipped (`core/schemas/authority-event-protocol.schema.json` @ v0.6.5; `core/registries/authority-key-registry.json`; canonical-bytes reference). Remaining is **confirmation**:
- Confirm the **`authority-forged`** conformance vector is published under `conformance/vectors/` and is a **negative** vector (must FAIL signature verification) — this is the vector today's stack historically had no test for.
- Confirm the full negative set is present (absent, tampered, expired, revoked, superseded, scope-mismatch, driver-originated, cert-digest-mismatch) and that the interchangeability harness validates them.
- The vendored `key_id→pubkey` registry in THIS repo is the pinned root of trust (panel amendment #2) — confirm rotation/revocation are modeled and the registry is digest-pinned (no live-fetch substitution surface).
