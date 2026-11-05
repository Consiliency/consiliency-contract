from __future__ import annotations

import hashlib
import itertools
import json
import re
import struct
import subprocess
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

from consiliency_contract import (
    CONTRACT,
    CONTRACT_VERSION,
    list_vectors,
    load_contract,
    load_registry,
    load_schema,
    load_vector,
)
from consiliency_contract.authority import (
    authority_signing_preimage,
    canonical_core_bytes,
    canonicalize_core,
    verify_authority_event,
)


def _stable_jcs(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


class ContractReaderTest(unittest.TestCase):
    def test_loads_contract_data(self) -> None:
        self.assertEqual(CONTRACT_VERSION, "0.7.0")
        self.assertEqual(load_contract()["contract_version"], "0.7.0")
        self.assertEqual(CONTRACT["contract_id"], "consiliency.contract.v1")
        self.assertEqual(len(load_registry("archetypes")["archetypes"]), 7)
        self.assertEqual(load_schema("manifest")["properties"]["schema"]["const"], "consiliency.manifest.v1")
        self.assertGreaterEqual(len(list_vectors()), 10)

    def test_vector_decisions_are_phase0_safe(self) -> None:
        certified_tiers = set(load_registry("maturity_labels")["phase0_disallowed"])
        self.assertEqual(certified_tiers, {"certified", "parity-certified", "authority-certified"})
        for name in list_vectors():
            vector = load_vector(name)
            self.assertEqual(vector["decision"]["schema"], "consiliency.conformance_decision.v1", name)
            self.assertNotIn(vector["decision"]["maturity"], certified_tiers, name)

    def test_certified_label_rescope_cs1_4(self) -> None:
        # CS-1.4: the bare 'certified' evidence label is split into two honest
        # tiers. 'certified' survives ONLY as a deprecated alias of
        # parity-certified (never authority-certified — aliasing an unratified
        # artifact upward would manufacture the false-green this rescope exists
        # to close).
        labels = {label["id"]: label for label in load_registry("maturity_labels")["labels"]}
        for label_id in ("parity-certified", "authority-certified"):
            self.assertIn(label_id, labels)
            self.assertEqual(labels[label_id]["kind"], "evidence")
            self.assertFalse(labels[label_id].get("deprecated", False))
        self.assertTrue(labels["certified"].get("deprecated"))
        self.assertEqual(labels["certified"].get("deprecated_alias_of"), "parity-certified")

    def test_dynamic_loaders_reject_unknown_names_and_traversal(self) -> None:
        with self.assertRaises(ValueError):
            load_vector("../../package")
        with self.assertRaises(ValueError):
            load_schema("../../package")
        with self.assertRaises(ValueError):
            load_registry("../../package")

    def test_canonical_html_provenance_digest(self) -> None:
        provenance = json.loads(Path("core/canonical-html/provenance.json").read_text(encoding="utf-8"))
        digest = hashlib.sha256(Path(provenance["packaged"]["path"]).read_bytes()).hexdigest()
        self.assertEqual(digest, provenance["packaged"]["sha256"])
        self.assertEqual(digest, provenance["source"]["sha256"])

    def test_governance_labels_are_registered(self) -> None:
        governance = {
            label["id"]
            for label in load_registry("maturity_labels")["labels"]
            if label.get("kind") == "governance"
        }
        self.assertGreaterEqual(len(governance), 3)
        for name in list_vectors():
            for label in load_vector(name)["decision"].get("labels", []):
                self.assertIn(label, governance, name)

    def test_inbox_messages_never_mutate_lease(self) -> None:
        saw_message_vector = False
        for name in list_vectors():
            vector = load_vector(name)
            if vector["input"].get("schema") != "consiliency.coordination_scenario.v1":
                continue
            self.assertIn("expected", vector, name)
            self.assertIsInstance(vector["expected"]["changed_by_message"], bool)
            if vector["input"].get("messages"):
                saw_message_vector = True
                self.assertFalse(vector["expected"]["changed_by_message"], name)
        self.assertTrue(saw_message_vector)

    def test_coordination_protocols_pin_guardrail(self) -> None:
        channel = load_schema("coordination_channel_protocol")["properties"]
        authority = channel["authority"]["properties"]
        self.assertFalse(authority["inbox_authoritative"]["const"])
        self.assertFalse(authority["message_may_mutate_lease"]["const"])
        self.assertTrue(authority["message_prompts_actor_to_call_store_op"]["const"])
        projection = channel["lease_state_projection"]["properties"]
        self.assertEqual(projection["formula"]["const"], "current_lease = project(lease-store events, now)")
        self.assertFalse(projection["inbox_included_in_projection"]["const"])
        store = load_schema("lease_store_protocol")["properties"]
        self.assertEqual(store["source_of_truth"]["const"], "lease-store")
        self.assertTrue(store["atomicity"]["properties"]["hard_requires_atomic_acquire"]["const"])
        self.assertEqual(store["atomicity"]["properties"]["degrade_without_atomic_backend"]["const"], "soft")
        self.assertEqual(store["granularity_ladder"]["properties"]["out_of_scope"]["const"], "line")
        self.assertEqual(store["expiry"]["properties"]["expires_at_formula"]["const"], "heartbeat_at + ttl_seconds")
        self.assertEqual(store["expiry"]["properties"]["boundary"]["const"], "exclusive")
        self.assertTrue(store["operation_semantics"]["properties"]["renew"]["properties"]["holder_only"]["const"])
        self.assertTrue(store["operation_semantics"]["properties"]["release"]["properties"]["holder_only"]["const"])

    @staticmethod
    def _project_lease_view(inp: dict) -> dict:
        # Fold the lease-EVENT stream ONLY (messages excluded), then apply
        # heartbeat-anchored, exclusive-boundary TTL expiry at `now`.
        mode = "hard" if inp.get("requested_mode") == "hard" and inp.get("atomic_backend") is True else "soft"

        def parse(iso: str) -> float:
            return datetime.strptime(iso, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()

        lease = None
        for e in inp.get("events", []):
            if e["event"] == "acquire":
                lease = {
                    "schema": "consiliency.lease.v1",
                    "lease_id": e["lease_id"],
                    "holder": e["holder"],
                    "acquired_at": e["at"],
                    "ttl_seconds": e["ttl_seconds"],
                    "heartbeat_at": e["at"],
                    "mode": mode,
                    "scope": e["scope"],
                    "phase": e["phase"],
                }
            elif e["event"] == "renew":
                if lease and lease["lease_id"] == e["lease_id"] and lease["holder"] == e["holder"]:
                    lease["heartbeat_at"] = e["at"]
            elif e["event"] in ("release", "expire"):
                if lease and lease["lease_id"] == e["lease_id"]:
                    lease = None
        if lease and parse(inp["now"]) >= parse(lease["heartbeat_at"]) + lease["ttl_seconds"]:
            lease = None  # exclusive boundary
        return {"current_lease": lease, "effective_mode": mode}

    def test_coordination_view_equals_events_only_projection(self) -> None:
        seen = 0
        for name in list_vectors():
            vector = load_vector(name)
            if vector["input"].get("schema") != "consiliency.coordination_scenario.v1":
                continue
            seen += 1
            projected = self._project_lease_view(vector["input"])
            self.assertEqual(projected["current_lease"], vector["expected"].get("current_lease"), name)
            self.assertEqual(projected["effective_mode"], vector["expected"]["effective_mode"], name)
        self.assertGreaterEqual(seen, 8)

    def test_required_is_subset_of_properties(self) -> None:
        def check(node: object, path: str) -> None:
            if isinstance(node, dict):
                if node.get("additionalProperties") is False and isinstance(node.get("required"), list):
                    props = set((node.get("properties") or {}).keys())
                    for key in node["required"]:
                        self.assertIn(key, props, f"{path}: required '{key}' absent from properties")
                for k, v in node.items():
                    check(v, f"{path}.{k}")
            elif isinstance(node, list):
                for i, v in enumerate(node):
                    check(v, f"{path}[{i}]")

        for name in CONTRACT["schemas"]:
            check(load_schema(name), name)

    # --- Slice C0: projection-discovery + git-discipline contracts ---

    @staticmethod
    def _ref_pattern_to_regex(pattern: str) -> "re.Pattern[str]":
        seg, star = "\x01", "\x02"
        tokenized = re.sub(r"\{[^}]+\}", seg, pattern).replace("*", star)
        escaped = re.escape(tokenized)
        body = escaped.replace(re.escape(seg), "[^/]+").replace(re.escape(star), ".*")
        return re.compile(f"^{body}$")

    @classmethod
    def _ref_owner(cls, name: str, registry: dict) -> str:
        for rc in registry["ref_classes"]:
            if rc["owner"] == "pipeline" and cls._ref_pattern_to_regex(rc["pattern"]).match(name):
                return "pipeline"
        return registry["default_owner"]

    def test_git_discipline_pins_never_delete_human_refs(self) -> None:
        p = load_schema("git_discipline_protocol")["properties"]
        self.assertEqual(p["schema"]["const"], "consiliency.git_discipline_protocol.v1")
        self.assertEqual(p["contract_version"]["const"], CONTRACT_VERSION)
        self.assertTrue(p["invariants"]["properties"]["never_delete_human_refs"]["const"])
        self.assertEqual(p["invariants"]["properties"]["self_heal_scope"]["const"], "leased-pipeline-owned-refs-only")
        self.assertEqual(p["self_heal"]["properties"]["scope"]["const"], "leased-pipeline-owned-refs-only")
        self.assertEqual(p["self_heal"]["properties"]["auto_fix"]["const"], "idempotent-safe-only")
        self.assertEqual(p["self_heal"]["properties"]["default_severity"]["const"], "warn")
        self.assertFalse(p["self_heal"]["properties"]["finding_human_required"]["const"])
        self.assertEqual(p["ref_class_registry"]["const"], "pipeline-ref-classes")
        reg = load_registry("pipeline_ref_classes")
        self.assertEqual(reg["default_owner"], "human")
        self.assertTrue(reg["invariants"]["never_delete_human_refs"])
        self.assertFalse(reg["human_default"]["deletable_by_self_heal"])

    def test_never_delete_human_refs_vector(self) -> None:
        reg = load_registry("pipeline_ref_classes")
        vector = load_vector("git-discipline-never-delete-human-refs")
        refs = vector["input"]["refs"]
        expected = vector["expected"]
        leased = {r["name"]: r["leased"] for r in refs}
        computed_human = sorted(r["name"] for r in refs if self._ref_owner(r["name"], reg) == "human")

        self.assertEqual(computed_human, sorted(expected["human_refs"]))
        self.assertEqual(computed_human, sorted(expected["never_deleted_human_refs"]))
        for name in computed_human:
            self.assertNotIn(name, expected["deletable_by_self_heal"], name)
            self.assertIn(name, expected["protected"], name)
        def matched_class(name: str) -> dict:
            for rc in reg["ref_classes"]:
                if self._ref_pattern_to_regex(rc["pattern"]).match(name):
                    return rc
            return reg["human_default"]

        for name in expected["deletable_by_self_heal"]:
            self.assertEqual(self._ref_owner(name, reg), "pipeline", name)
            self.assertTrue(leased[name], name)
            self.assertTrue(matched_class(name)["deletable_by_self_heal"], name)
        all_refs = sorted(r["name"] for r in refs)
        union = sorted(expected["deletable_by_self_heal"] + expected["protected"])
        self.assertEqual(union, all_refs)
        self.assertEqual(len(set(union)), len(union))

    @staticmethod
    def _build_projections_index(inp: dict) -> dict:
        sidecar = {s["manifest_path"]: s for s in inp.get("refresh_sidecars", [])}
        entries = []
        for m in inp["manifests"]:
            e = {
                "repo": m["target"],
                "kind": m["kind"],
                "predicate": m["predicate"],
                "body_path": m["output_path"],
                "body_content_type": m["body_content_type"],
                "manifest_path": m["manifest_path"],
                "body_digest": m["body_digest"],
                "body_digest_domain": m["body_digest_domain"],
                "maturity_label": m["maturity_label"],
                "gate_state": m["gate_verdict"]["state"],
            }
            if m["kind"] == "proj-S-certified":
                # v0.4.1: certified pins the desired-state graph S, not a code commit.
                e["source_S_digest"] = m["source_S_digest"]
                if m.get("display_route") is not None:
                    e["display_route"] = m["display_route"]
            else:
                e["facts_path"] = m["facts_path"]
                e["facts_digest"] = m["facts_digest"]
                e["pinned_commit"] = m["code_head_sha"]
            s = sidecar.get(m["manifest_path"])
            if s:
                for k in ("refresh_status", "refresh_failure_class", "attempted_code_head_sha"):
                    if k in s:
                        e[k] = s[k]
            entries.append(e)
        entries.sort(key=lambda e: (e["repo"], e["kind"], e["predicate"]))
        return {"schema": "projections.index.v1", "entries": entries}

    def test_projections_index_is_deterministic_pure_merge(self) -> None:
        vector = load_vector("projections-index-pure-merge-deterministic")
        built = self._build_projections_index(vector["input"])
        canon = lambda v: json.dumps(v, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
        self.assertEqual(canon(built), canon(vector["expected"]["index"]))
        self.assertEqual(canon(self._build_projections_index(vector["input"])), canon(built))
        self.assertNotIn("generated_at", canon(vector["expected"]["index"]))

    def test_projections_index_entry_has_per_kind_conditional_requireds(self) -> None:
        entry = load_schema("projections_index_v1")["$defs"]["entry"]
        for f in ("pinned_commit", "facts_path", "facts_digest", "source_S_digest"):
            self.assertNotIn(f, entry["required"], f)
        code_block = next(b for b in entry["allOf"] if "proj-code-sbom" in b["if"]["properties"]["kind"].get("enum", []))
        cert_block = next(b for b in entry["allOf"] if b["if"]["properties"]["kind"].get("const") == "proj-S-certified")
        # proj-code: two-sided cap at [presence-only, hash-checked] — CS-1.4
        # keeps this cap unchanged, so proj-code can reach neither certified
        # tier (parity-certified nor authority-certified).
        self.assertEqual(sorted(code_block["then"]["required"]), ["facts_digest", "facts_path", "pinned_commit"])
        code_maturity_enum = code_block["then"]["properties"]["maturity_label"]["enum"]
        self.assertEqual(code_maturity_enum, ["presence-only", "hash-checked"])
        self.assertNotIn("certified", code_maturity_enum)
        self.assertNotIn("parity-certified", code_maturity_enum)
        self.assertNotIn("authority-certified", code_maturity_enum)
        # proj-S-certified: [realized-edge-observed, certified, parity-certified,
        # authority-certified] — CS-1.4 splits the certified rung into two
        # honest tiers, keeping the deprecated bare id as an alias; any
        # certified-tier value is permitted ONLY for this kind.
        self.assertIn("source_S_digest", cert_block["then"]["required"])
        self.assertEqual(
            cert_block["then"]["properties"]["maturity_label"]["enum"],
            ["realized-edge-observed", "certified", "parity-certified", "authority-certified"],
        )

    # --- Slice X: the §12.3 interchangeability test ---

    def test_real_producer_reproduces_the_vector_byte_for_byte(self) -> None:
        # Runs conformance/interchangeability/run_driver_equivalence.py, which
        # feeds this vector's manifests through the REAL
        # spec-render/build_projections_index.py (fetched by content from a
        # sibling `spec` checkout — see that script's docstring), rather than
        # this file's own reference merger above. Honest scoping: skips (does
        # not pass vacuously, does not fail the suite) when no spec checkout is
        # available, since contract-only CI has no reason to have one.
        script = Path(__file__).resolve().parent.parent / "scripts" / "interchangeability" / "run_driver_equivalence.py"
        proc = subprocess.run([sys.executable, str(script)], capture_output=True, text=True)
        report = json.loads(proc.stdout.strip())
        if report["status"] == "skip":
            self.skipTest(report["reason"])
        self.assertEqual(report["status"], "pass", report)
        self.assertTrue(report["byte_identical_to_vector"], report)

    # --- Slice 1 (XG-1): the authority-event contract core (root of trust) ---

    @staticmethod
    def _authority_vector_names() -> list[str]:
        return [name for name in list_vectors() if name.startswith("authority-")]

    @classmethod
    def _validate_against(cls, schema: dict, value: object, root: dict) -> bool:
        # Compact validator for the constructs the authority schema uses
        # ($ref/$defs, const, enum, type, pattern, minLength, required,
        # additionalProperties:false, properties) — no jsonschema dependency.
        if "$ref" in schema:
            node: object = root
            for key in schema["$ref"].lstrip("#/").split("/"):
                node = node[key]  # type: ignore[index]
            return cls._validate_against(node, value, root)  # type: ignore[arg-type]
        if "const" in schema:
            return value == schema["const"]
        if "enum" in schema:
            return value in schema["enum"]
        if schema.get("type") == "string":
            if not isinstance(value, str):
                return False
            if "minLength" in schema and len(value) < schema["minLength"]:
                return False
            if "pattern" in schema and not re.match(schema["pattern"], value):
                return False
            return True
        if schema.get("type") == "object" or "properties" in schema:
            if not isinstance(value, dict):
                return False
            props = schema.get("properties", {})
            for req in schema.get("required", []):
                if req not in value:
                    return False
            if schema.get("additionalProperties") is False:
                for key in value:
                    if key not in props:
                        return False
            return all(key not in props or cls._validate_against(props[key], entry, root) for key, entry in value.items())
        return True

    def test_authority_vectors_match_schema_valid_flag(self) -> None:
        schema = load_schema("authority_event_protocol")
        saw_valid_conform = saw_invalid = False
        for name in self._authority_vector_names():
            vector = load_vector(name)
            conforms = self._validate_against(schema, vector["input"]["event"], schema)
            self.assertEqual(conforms, vector["expected"]["schema_valid"], f"{name}: schema conformance")
            if vector["id"] == "authority-valid":
                saw_valid_conform = conforms
            if not vector["expected"]["schema_valid"]:
                saw_invalid = True
        self.assertTrue(saw_valid_conform, "the valid vector must conform to the shipped schema")
        self.assertTrue(saw_invalid, "at least one malformed vector must be rejected by the shipped schema")

    def test_authority_schema_pins_core_chain_split(self) -> None:
        schema = load_schema("authority_event_protocol")
        self.assertEqual(schema["properties"]["schema"]["const"], "consiliency.authority_event_protocol.v1")
        core = schema["properties"]["core"]
        self.assertNotIn("chain", core["properties"])
        self.assertNotIn("signature", core["properties"])
        for field in ("decision_id", "cert_digest", "key_id", "approver", "validity", "audience", "custody_binding"):
            self.assertIn(field, core["required"], field)
        self.assertEqual(core["properties"]["authority_event_version"]["const"], "1")
        self.assertEqual(core["properties"]["custody_binding"]["properties"]["phase_loop_driver_allowed"]["const"], False)
        self.assertNotIn("phase", core["required"])
        for field in ("phase", "subgraph", "canon_version"):
            self.assertIn(field, core["properties"]["audience"]["required"], field)
        self.assertEqual(schema["properties"]["signature"]["properties"]["scheme"]["const"], "ed25519")
        self.assertEqual(sorted(schema["required"]), ["core", "schema", "signature"])

    def test_authority_key_registry_is_pinned_root_of_trust(self) -> None:
        reg = load_registry("authority_key_registry")
        self.assertEqual(reg["schema"], "consiliency.authority_key_registry.v1")
        self.assertGreaterEqual(len(reg["keys"]), 3)
        for key in reg["keys"]:
            self.assertEqual(key["scheme"], "ed25519")
            self.assertRegex(key["public_key"], r"^[0-9a-f]{64}$")
            self.assertIsInstance(key["approver"], str)
            self.assertTrue(key["validity"]["not_before"] and key["validity"]["not_after"])
            self.assertIsInstance(key["revoked"], bool)
        self.assertTrue(any(key["revoked"] for key in reg["keys"]))
        self.assertNotRegex(json.dumps(reg), r"(?i)private_key|secret|seed")

    def test_authority_vectors_verify_or_reject_as_expected(self) -> None:
        reg = load_registry("authority_key_registry")
        names = self._authority_vector_names()
        self.assertGreaterEqual(len(names), 12)
        saw_valid = saw_forged = False
        for name in names:
            inp = load_vector(name)["input"]
            expected = load_vector(name)["expected"]
            decision = load_vector(name)["decision"]
            res = verify_authority_event(
                inp["event"], reg, now=inp["now"], expected_cert_digest=inp["expected_cert_digest"]
            )
            self.assertEqual(res["ok"], expected["verifies"], f"{name}: ok")
            self.assertEqual(res["reason"], expected["reason"], f"{name}: reason")
            self.assertEqual(decision["status"], "accepted" if expected["verifies"] else "rejected", f"{name}: decision")
            saw_valid = saw_valid or expected["verifies"]
            saw_forged = saw_forged or "forged" in name
        self.assertTrue(saw_valid and saw_forged)

    def test_forged_self_minted_event_rejects(self) -> None:
        reg = load_registry("authority_key_registry")
        inp = load_vector("authority-forged-self-minted")["input"]
        res = verify_authority_event(
            inp["event"], reg, now=inp["now"], expected_cert_digest=inp["expected_cert_digest"]
        )
        self.assertFalse(res["ok"])
        self.assertEqual(res["reason"], "unknown_key_id")

    def test_chain_append_preserves_core_signature(self) -> None:
        reg = load_registry("authority_key_registry")
        inp = load_vector("authority-valid")["input"]
        kwargs = dict(now=inp["now"], expected_cert_digest=inp["expected_cert_digest"])
        self.assertTrue(verify_authority_event(inp["event"], reg, **kwargs)["ok"])
        digest = "a" * 64
        chained = dict(inp["event"])
        chained["chain"] = {
            "entry_digest": digest,
            "previous_entry_digest": "0" * 64,
            "root_digest": "b" * 64,
            "inclusion_proof": {"entry_digest": digest, "previous_entry_digest": "0" * 64, "root_digest": "b" * 64},
        }
        self.assertTrue(verify_authority_event(chained, reg, **kwargs)["ok"], "core signature must survive chain append")

    def test_authority_canonicalizer_equals_jcs(self) -> None:
        for name in self._authority_vector_names():
            core = load_vector(name)["input"]["event"]["core"]
            self.assertEqual(canonicalize_core(core), _stable_jcs(core), f"{name}: canonicalizer must equal sorted JSON")

    def test_authority_signature_covers_prefixed_preimage(self) -> None:
        # Domain separation (XG-4): the signature covers spec-canon:v2:authority\n
        # || canonical_bytes(core), NOT bare bytes. Proven: the valid signature
        # verifies over the preimage and FAILS over the bare bytes.
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        reg = load_registry("authority_key_registry")
        vector = load_vector("authority-valid")
        core = vector["input"]["event"]["core"]
        key = next(k for k in reg["keys"] if k["key_id"] == core["key_id"])
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(key["public_key"]))
        sig = bytes.fromhex(vector["input"]["event"]["signature"]["signature"])
        pub.verify(sig, authority_signing_preimage(core))  # verifies over the preimage
        with self.assertRaises(InvalidSignature):
            pub.verify(sig, canonical_core_bytes(core))  # must NOT verify over bare bytes
        self.assertEqual(
            authority_signing_preimage(core),
            b"spec-canon:v2:authority\n" + canonical_core_bytes(core),
        )

    def test_authority_bytes_pinned_to_canon_core_v2(self) -> None:
        # The signed bytes ARE canon-core v2 canonical_bytes(core); our canonicalizer
        # is a metadata-safe/integer-only PORT. The pin was produced from spec's
        # canon.py, so this proves parity offline (see core/authority-canon/provenance.json).
        for name in self._authority_vector_names():
            vector = load_vector(name)
            self.assertEqual(
                canonical_core_bytes(vector["input"]["event"]["core"]).hex(),
                vector["input"]["canon_core_v2_bytes"],
                f"{vector['id']}: signed-core bytes must equal the pinned canon-core v2 canonical_bytes",
            )

    def test_authority_canon_provenance_pins_spec_source(self) -> None:
        from pathlib import Path

        prov = json.loads(Path("core/authority-canon/provenance.json").read_text(encoding="utf-8"))
        self.assertEqual(prov["schema"], "consiliency.authority_canon_provenance.v1")
        self.assertEqual(prov["canon_version"], "spec-canon:v2")
        self.assertRegex(prov["normative_source"]["files"]["canon/py/canon.py"], r"^[0-9a-f]{64}$")
        self.assertEqual(prov["authority_profile"]["profile_id"], "authority")
        self.assertEqual(prov["authority_profile"]["domain_prefix"], "spec-canon:v2:authority\n")
        self.assertIn("spec-canon:v2:authority", prov["authority_profile"]["signed_preimage"])
        self.assertIn("SETTLED", prov["authority_profile"]["domain_separation"])

    def test_authority_canon_parity_gate(self) -> None:
        # REQUIRED, never-skip: the contract's OWN authority port must reproduce every committed
        # canon_core_v2_bytes pin (self-contained, no spec checkout). The live spec cross-check is
        # additional when a spec checkout is present, but its absence must NOT skip the gate.
        import subprocess
        import sys
        from pathlib import Path

        root = Path(__file__).resolve().parent.parent
        proc = subprocess.run(
            [sys.executable, "scripts/authority_canon_parity.py"],
            cwd=root, capture_output=True, text=True,
        )
        report = json.loads(proc.stdout.strip())
        self.assertNotEqual(report["status"], "skip", "authority-canon parity gate must never skip")
        self.assertEqual(report["status"], "pass", report)
        self.assertEqual(report["offline_pin"], "pass", report)
        self.assertGreaterEqual(report["checked"], 13, report)

    def test_authority_canonicalizer_is_fail_closed(self) -> None:
        from consiliency_contract.authority import AuthorityCanonicalError

        for bad in ({"n": 1.5}, {"s": "a b"}, {"s": "é"}, {"x": None}):
            with self.assertRaises(AuthorityCanonicalError):
                canonicalize_core(bad)

    def test_authority_regenerates_deterministically(self) -> None:
        try:
            import cryptography  # noqa: F401
        except ImportError:  # pragma: no cover
            self.skipTest("cryptography not installed")
        import subprocess
        import sys
        from pathlib import Path

        root = Path(__file__).resolve().parent.parent
        proc = subprocess.run(
            [sys.executable, "scripts/gen_authority_vectors.py", "--check"],
            cwd=root, capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)

    # --- parity certificate schema distribution (0.6.4) ---

    @classmethod
    def _validate_with_refs(cls, schema: dict, value: object, roots: dict, current_root: dict | None = None) -> bool:
        # Cross-file-aware validator: the distributed parity certificate keeps
        # its relative cross-file $ref into result-state; resolve that external
        # fragment against the loaded result_state schema (no jsonschema dep).
        # current_root is the document bare `#/` refs resolve against; it
        # switches to result_state when a cross-file ref is followed.
        if current_root is None:
            current_root = roots["self"]
        if "$ref" in schema:
            ref = schema["$ref"]
            root = current_root
            if ref.startswith("result-state.schema.json#/"):
                root = roots["result_state"]
                ref = ref[len("result-state.schema.json"):]
            node: object = root
            for key in ref.lstrip("#/").split("/"):
                node = node[key]  # type: ignore[index]
            return cls._validate_with_refs(node, value, roots, root)  # type: ignore[arg-type]
        if "const" in schema:
            return value == schema["const"]
        if "enum" in schema:
            return value in schema["enum"]
        if schema.get("type") == "string":
            if not isinstance(value, str):
                return False
            if "minLength" in schema and len(value) < schema["minLength"]:
                return False
            if "pattern" in schema and not re.match(schema["pattern"], value):
                return False
            return True
        if schema.get("type") == "integer":
            if not isinstance(value, int) or isinstance(value, bool):
                return False
            if "minimum" in schema and value < schema["minimum"]:
                return False
            return True
        if schema.get("type") == "boolean":
            return isinstance(value, bool)
        if schema.get("type") == "array":
            if not isinstance(value, list):
                return False
            if "minItems" in schema and len(value) < schema["minItems"]:
                return False
            if "maxItems" in schema and len(value) > schema["maxItems"]:
                return False
            items = schema.get("items")
            return all(items is None or cls._validate_with_refs(items, item, roots, current_root) for item in value)
        if schema.get("type") == "object" or "properties" in schema:
            if not isinstance(value, dict):
                return False
            props = schema.get("properties", {})
            for req in schema.get("required", []):
                if req not in value:
                    return False
            if schema.get("additionalProperties") is False:
                for key in value:
                    if key not in props:
                        return False
            return all(key not in props or cls._validate_with_refs(props[key], entry, roots, current_root) for key, entry in value.items())
        return True

    def test_parity_certificate_closure_is_registered(self) -> None:
        cert = load_schema("certificate")
        result_state = load_schema("result_state")
        self.assertEqual(cert["$id"], "https://spec.consiliency/spec-parity/certificate.schema.json")
        self.assertEqual(result_state["$id"], "https://spec.consiliency/spec-parity/result-state.schema.json")
        self.assertEqual(cert["properties"]["schema_version"]["const"], "1")
        # The certificate's only outward $refs form the whole transitive closure
        # (result-state) — nothing outside these two files is referenced.
        external: set[str] = set()

        def collect(node: object) -> None:
            if isinstance(node, list):
                for item in node:
                    collect(item)
            elif isinstance(node, dict):
                ref = node.get("$ref")
                if isinstance(ref, str) and not ref.startswith("#"):
                    external.add(ref.split("#")[0])
                for item in node.values():
                    collect(item)

        collect(cert)
        self.assertEqual(sorted(external), ["result-state.schema.json"])

    def test_distributed_parity_certificate_validates_a_real_cert(self) -> None:
        roots = {"self": load_schema("certificate"), "result_state": load_schema("result_state")}

        def dim(dimension: str) -> dict:
            return {"dimension": dimension, "result_state": "pass"}

        cert = {
            "schema_version": "1",
            "projection_algo_version": "1.0.0",
            "canon_version": "v2",
            "idmodel_version": "v1",
            "kind_alignment_version": "v1",
            "permitted_freedom_vocab_version": "v1",
            "ec_revision_id": "rev-1",
            "spec_revision_digest": "a" * 64,
            "desired_graph_digest": "b" * 64,
            "ec_digest": "c" * 64,
            "code_head_sha": "d" * 40,
            "overall_result_state": "pass",
            "dimension_results": [
                dim("completeness"),
                dim("soundness"),
                dim("closure"),
                dim("prohibition"),
                dim("revision_alignment"),
            ],
            "findings_ref": "e" * 64,
            "digest": "f" * 64,
        }
        self.assertTrue(self._validate_with_refs(roots["self"], cert, roots))
        bad = dict(cert)
        bad["dimension_results"] = [{"dimension": "not_a_dimension", "result_state": "pass"}, *cert["dimension_results"][1:]]
        self.assertFalse(self._validate_with_refs(roots["self"], bad, roots))
        self.assertFalse(self._validate_with_refs(roots["self"], {**cert, "bogus": 1}, roots))

    def test_parity_cert_provenance_matches_shipped_bytes(self) -> None:
        prov = json.loads(Path("core/spec-parity/provenance.json").read_text(encoding="utf-8"))
        self.assertEqual(prov["schema"], "consiliency.spec_parity_provenance.v1")
        self.assertRegex(prov["normative_source"]["spec_commit"], r"^[0-9a-f]{40}$")
        self.assertEqual(sorted(prov["ref_closure"]["members"]), ["certificate", "result_state"])
        for key, path in (
            ("certificate", "core/schemas/certificate.schema.json"),
            ("result_state", "core/schemas/result-state.schema.json"),
        ):
            digest = hashlib.sha256(Path(path).read_bytes()).hexdigest()
            self.assertEqual(digest, prov["distributed"][key]["sha256"], key)
            base = path.split("/")[-1]
            self.assertEqual(digest, prov["normative_source"]["files"][base], key)

    # --- protected_source_category vocabulary (0.6.5) ---

    def test_protected_source_category_registry_and_schema_are_registered(self) -> None:
        reg = load_registry("protected_source_categories")
        schema = load_schema("protected_source_category")
        self.assertEqual(reg["schema"], "consiliency.protected_source_categories.v1")
        self.assertEqual(
            schema["$id"],
            "https://consiliency.io/contracts/protected-source-category.schema.json",
        )
        # The coarse enum is the seven execution-flow buckets: the pre-existing
        # six plus the new governance_contracts bucket.
        coarse_ids = [c["id"] for c in reg["coarse_categories"]]
        self.assertEqual(
            coarse_ids,
            [
                "specs",
                "diagrams",
                "adapter_config",
                "definition_files",
                "portal_contracts",
                "phase_artifacts",
                "governance_contracts",
            ],
        )
        pre_existing = {c["id"] for c in reg["coarse_categories"] if c["pre_existing"]}
        self.assertEqual(
            pre_existing,
            {"specs", "diagrams", "adapter_config", "definition_files", "portal_contracts", "phase_artifacts"},
        )
        new = [c["id"] for c in reg["coarse_categories"] if not c["pre_existing"]]
        self.assertEqual(new, ["governance_contracts"])
        # The schema's coarse enum MUST equal the registry's coarse ids (no drift).
        self.assertEqual(schema["properties"]["category"]["enum"], coarse_ids)
        # subtype is optional + free-form (a plain string, no enum gate).
        self.assertEqual(schema["required"], ["category"])
        self.assertEqual(schema["properties"]["subtype"]["type"], "string")
        self.assertNotIn("enum", schema["properties"]["subtype"])

    def test_protected_source_category_fine_to_coarse_map_is_total_and_closed(self) -> None:
        reg = load_registry("protected_source_categories")
        coarse_ids = {c["id"] for c in reg["coarse_categories"]}
        fine_names = set(reg["fine_subtypes"])
        mapping = reg["fine_to_coarse"]
        # Exactly the ~14 governed-pipeline fine names, mapped.
        expected_fine = {
            "active_canonical_specs",
            "canonical_specs",
            "canonical_spec_archive_manifests",
            "canonical_spec_mirror_manifests",
            "adoption_contracts",
            "current_phase_artifacts",
            "definition_validation_code",
            "execution_profiles",
            "phase_loop_bridge_contract_files",
            "pipeline_definition_json",
            "portal_contracts",
            "runtime_adapter_config",
            "skill_manifests",
            "instruction_surfaces",
        }
        self.assertEqual(fine_names, expected_fine)
        self.assertEqual(set(mapping), expected_fine)
        # Every mapping target is a registered coarse id; subtype echoes the key.
        for fine, target in mapping.items():
            self.assertIn(target["coarse"], coarse_ids, fine)
            self.assertEqual(target["subtype"], fine, fine)
        # The four unmappable fine names land in the new governance bucket.
        self.assertEqual(
            {f for f, t in mapping.items() if t["coarse"] == "governance_contracts"},
            {"adoption_contracts", "phase_loop_bridge_contract_files", "skill_manifests", "instruction_surfaces"},
        )

    def test_protected_source_category_schema_accepts_and_rejects(self) -> None:
        schema = load_schema("protected_source_category")

        def valid(value: object) -> bool:
            if not isinstance(value, dict):
                return False
            for req in schema.get("required", []):
                if req not in value:
                    return False
            if schema.get("additionalProperties") is False:
                for key in value:
                    if key not in schema["properties"]:
                        return False
            for key, entry in value.items():
                spec = schema["properties"].get(key)
                if not spec:
                    continue
                if spec.get("type") == "string":
                    if not isinstance(entry, str):
                        return False
                    if spec.get("minLength") is not None and len(entry) < spec["minLength"]:
                        return False
                if spec.get("enum") is not None and entry not in spec["enum"]:
                    return False
            return True

        self.assertTrue(valid({"category": "governance_contracts"}))
        self.assertTrue(valid({"category": "specs", "subtype": "active_canonical_specs"}))
        self.assertTrue(valid({"category": "specs", "subtype": "any-free-form-string"}))
        self.assertFalse(valid({"category": "not_a_category"}))
        self.assertFalse(valid({"subtype": "active_canonical_specs"}))  # category required
        self.assertFalse(valid({"category": "specs", "bogus": 1}))  # additionalProperties:false


# --- supervised-run status + admitted-launch envelope (0.6.6) ---
#
# core/supervised-run/ is distributed verbatim and digest-pinned
# (core/supervised-run/provenance.json). This package has no reader for the
# contract, so it checks what it can without one: byte identity, schema
# well-formedness, that every expected diagnostic is a defined semantic rule,
# that every control and every patched negative is schema-valid (as the
# conformance README promises), the envelope_digest rule and the journal
# segment chain. The remaining semantic diagnostics need a conforming reader.

SUPERVISED_RUN_ROOT = Path("core/supervised-run")

# Every JSON Schema keyword the supervised-run schemas may use (draft 2020-12 core,
# applicator and validation vocabularies this package's validator implements,
# plus annotations). Anything else fails, so a new keyword is never silently
# ignored by the subset validator below.
_SR_KEYWORDS = {
    "$schema", "$id", "$ref", "$defs", "title", "description",
    "type", "const", "enum", "anyOf", "oneOf",
    "properties", "required", "additionalProperties",
    "items", "minItems", "uniqueItems", "minProperties",
    "minLength", "maxLength", "pattern", "minimum", "maximum",
}


def _sr_jcs(value: object) -> str:
    # RFC 8785 (JCS): UTF-16 member order, ECMAScript numbers, RFC 8785 escapes; see r2_jcs_text below.
    return r2_jcs_text(value)


def _sr_resolve(root: dict, ref: str) -> dict:
    if not ref.startswith("#/"):
        raise ValueError(f"non-local $ref: {ref}")
    node: object = root
    for part in ref[2:].split("/"):
        node = node[part.replace("~1", "/").replace("~0", "~")]  # type: ignore[index]
    return node  # type: ignore[return-value]


def _sr_type_ok(name: str, value: object) -> bool:
    if name == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    return {
        "object": isinstance(value, dict),
        "array": isinstance(value, list),
        "string": isinstance(value, str),
        "boolean": isinstance(value, bool),
        "null": value is None,
    }[name]


def _sr_same(a: object, b: object) -> bool:
    return type(a) is type(b) and a == b


def _sr_valid(schema: dict, value: object, root: dict) -> bool:
    if "$ref" in schema and not _sr_valid(_sr_resolve(root, schema["$ref"]), value, root):
        return False
    if "type" in schema:
        names = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
        if not any(_sr_type_ok(name, value) for name in names):
            return False
    if "const" in schema and not _sr_same(value, schema["const"]):
        return False
    if "enum" in schema and not any(_sr_same(value, entry) for entry in schema["enum"]):
        return False
    if "anyOf" in schema and not any(_sr_valid(sub, value, root) for sub in schema["anyOf"]):
        return False
    if "oneOf" in schema and sum(_sr_valid(sub, value, root) for sub in schema["oneOf"]) != 1:
        return False
    if isinstance(value, str):
        if len(value) < schema.get("minLength", 0):
            return False
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            return False
        if "pattern" in schema and not re.search(schema["pattern"], value):
            return False
    if isinstance(value, int) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            return False
        if "maximum" in schema and value > schema["maximum"]:
            return False
    if isinstance(value, list):
        if len(value) < schema.get("minItems", 0):
            return False
        if schema.get("uniqueItems") and len({_sr_jcs(item) for item in value}) != len(value):
            return False
        if "items" in schema and not all(_sr_valid(schema["items"], item, root) for item in value):
            return False
    if isinstance(value, dict):
        props = schema.get("properties", {})
        if any(key not in value for key in schema.get("required", [])):
            return False
        if len(value) < schema.get("minProperties", 0):
            return False
        if schema.get("additionalProperties") is False and any(key not in props for key in value):
            return False
        if not all(_sr_valid(props[key], entry, root) for key, entry in value.items() if key in props):
            return False
    return True


def _sr_apply_patch(document: object, patch: list) -> object:
    # RFC 6902 add / remove / replace with RFC 6901 pointers; strict.
    doc = json.loads(json.dumps(document))
    for op in patch:
        parts = [p.replace("~1", "/").replace("~0", "~") for p in op["path"][1:].split("/")]
        parent = doc
        for part in parts[:-1]:
            parent = parent[int(part)] if isinstance(parent, list) else parent[part]
        key = parts[-1]
        kind = op["op"]
        if isinstance(parent, list):
            if kind == "add":
                if key == "-":
                    parent.append(op["value"])
                else:
                    index = int(key)
                    if index > len(parent):
                        raise IndexError(op["path"])
                    parent.insert(index, op["value"])
            elif kind in ("remove", "replace"):
                index = int(key)
                if index >= len(parent):
                    raise IndexError(op["path"])
                if kind == "remove":
                    del parent[index]
                else:
                    parent[index] = op["value"]
            else:
                raise ValueError(f"unsupported op {kind}")
        else:
            if kind in ("remove", "replace") and key not in parent:
                raise KeyError(op["path"])
            if kind == "remove":
                del parent[key]
            elif kind in ("add", "replace"):
                parent[key] = op["value"]
            else:
                raise ValueError(f"unsupported op {kind}")
    return doc


def _sr_envelope_digest(envelope: dict) -> str:
    body = {key: value for key, value in envelope.items() if key != "envelope_digest"}
    return hashlib.sha256(_sr_jcs(body).encode("utf-8")).hexdigest()


def _sr_segment_bytes(segment: dict) -> bytes:
    lines = [line if isinstance(line, str) else _sr_jcs(line) for line in segment["lines"]]
    return ("\n".join(lines) + ("\n" if segment["final_newline"] else "")).encode("utf-8")


def _sr_chain_ok(journal: dict) -> bool:
    for attempt in journal["attempts"]:
        previous = None
        for index, segment in enumerate(attempt["segments"]):
            header = segment["lines"][0]["body"]
            expected = None if previous is None else hashlib.sha256(_sr_segment_bytes(previous)).hexdigest()
            if header["segment_index"] != index or header["previous_segment_sha256"] != expected:
                return False
            previous = segment
    return True


# The frozen v1 payload, pinned here independently of provenance.json so that
# no provenance edit can bless a changed v1 byte (0.7.0 adds v2 alongside).
SUPERVISED_RUN_V1_PINS = {
    "admitted-launch-envelope.schema.json": "0273f7a5d80eab95ee84660cd657445e881431bca3b8f91cec61015a5d39d41d",
    "run-status.schema.json": "5118c1ab8604e85990150d66bf6b8c1af979dcc404fc84ee5a3c4ba4fead9a30",
    "conformance/README.md": "2d5045245105af88f1f45f720aa8bc3f366efc95c25e25a9c50e402a175533ca",
    "conformance/envelope.vectors.json": "876d322c313b444e49d7a95ee8f7ca39eef13c45864c67a0b3877235e1db6d7f",
    "conformance/run-status.vectors.json": "5bf9dfbf65805f7340290586d546038fc88659785e60e2f55532df4ac6696730",
}
# sha256 of the v1 manifest, which is kept verbatim as the first five lines of SHA256SUMS.
SUPERVISED_RUN_V1_MANIFEST_SHA256 = "b9c2dad7ca32d32b9860e56c2e14141827955a50b52a54c8088760d9756e1285"


class SupervisedRunContractTest(unittest.TestCase):
    PAYLOAD = tuple(SUPERVISED_RUN_V1_PINS)
    V2_PAYLOAD = (
        "admitted-launch-envelope.v2.schema.json",
        "conformance/README.v2.md",
        "conformance/envelope.v2.vectors.json",
        "conformance/envelope.v2.canonical.vectors.json",
        "conformance/envelope.v2.apply.vectors.json",
    )

    @classmethod
    def setUpClass(cls) -> None:
        cls.prov = json.loads((SUPERVISED_RUN_ROOT / "provenance.json").read_text(encoding="utf-8"))
        cls.envelope_schema = load_schema("admitted_launch_envelope")
        cls.run_schema = load_schema("supervised_run_status")
        cls.vector_sets = {
            name: (json.loads(Path(path).read_text(encoding="utf-8")), schema)
            for name, path, schema in (
                ("admitted_launch_envelope", CONTRACT["supervised_run"]["vectors"]["admitted_launch_envelope"], cls.envelope_schema),
                ("supervised_run_status", CONTRACT["supervised_run"]["vectors"]["supervised_run_status"], cls.run_schema),
            )
        }

    def _case_inputs(self, vectors: dict) -> list[tuple[dict, dict]]:
        controls = {case["id"]: case for case in vectors["cases"] if case["role"] == "control"}
        out = []
        for case in vectors["cases"]:
            if case["role"] == "control":
                out.append((case, case["input"]))
                continue
            control = controls[case["control"]]
            patched = _sr_apply_patch(control["input"], case["patch"])
            if case.get("rehash"):
                patched["envelope"]["envelope_digest"] = _sr_envelope_digest(patched["envelope"])
            out.append((case, patched))
        return out

    def _schema_failures(self, kind: str, value: dict) -> list[str]:
        defs = self.run_schema["$defs"]
        bad = []
        if kind in ("admission", "echo") and not _sr_valid(self.envelope_schema, value["envelope"], self.envelope_schema):
            bad.append("envelope")
        for attempt in value.get("journal", {}).get("attempts", []):
            for segment in attempt["segments"]:
                for line in segment["lines"]:
                    if isinstance(line, dict) and not _sr_valid(defs["journal_line"], line, self.run_schema):
                        bad.append("journal_line")
        if kind == "projection" and not _sr_valid(defs["projection"], value["projection"], self.run_schema):
            bad.append("projection")
        if kind == "reader_view" and not _sr_valid(defs["reader_view"], value, self.run_schema):
            bad.append("reader_view")
        if kind == "page":
            if not _sr_valid(defs["page_request"], value["request"], self.run_schema):
                bad.append("page_request")
            if not _sr_valid(defs["page"], value["page"], self.run_schema):
                bad.append("page")
        return bad

    def test_registered_with_pinned_ids(self) -> None:
        self.assertEqual(self.prov["schema"], "consiliency.supervised_run_provenance.v1")
        self.assertEqual(self.prov["status"], "provisional")
        self.assertEqual(CONTRACT["supervised_run"]["provenance"], "core/supervised-run/provenance.json")
        for name, entry in self.prov["distributed"]["schemas"].items():
            self.assertEqual(CONTRACT["schemas"][name], entry["path"], name)
            self.assertEqual(load_schema(name)["$id"], entry["schema_id"], name)
        self.assertEqual(CONTRACT["supervised_run"]["vectors"], self.prov["distributed"]["vectors"])

    def test_payload_bytes_match_pinned_digests(self) -> None:
        # Any changed payload byte fails here. v1: verbatim copy, source sha == shipped sha ==
        # the independent pins above. v2: authored in this repository, pinned in provenance.
        self.assertRegex(self.prov["normative_source"]["spec_commit"], r"^[0-9a-f]{40}$")
        self.assertEqual(self.prov["normative_source"]["files"], SUPERVISED_RUN_V1_PINS)
        self.assertEqual(sorted(self.prov["authored_here"]["files"]), sorted(self.V2_PAYLOAD))
        self.assertEqual(self.prov["authored_here"]["contract_ids"], ["admitted_launch_envelope.v2"])
        self.assertEqual(
            self.prov["distributed"]["files"],
            {**self.prov["normative_source"]["files"], **self.prov["authored_here"]["files"]},
        )
        for rel in self.PAYLOAD + self.V2_PAYLOAD:
            digest = hashlib.sha256((SUPERVISED_RUN_ROOT / rel).read_bytes()).hexdigest()
            self.assertEqual(digest, self.prov["distributed"]["files"][rel], rel)
        for rel, pin in SUPERVISED_RUN_V1_PINS.items():
            self.assertEqual(hashlib.sha256((SUPERVISED_RUN_ROOT / rel).read_bytes()).hexdigest(), pin, f"v1 frozen: {rel}")
        manifest = self.prov["distributed"]["manifest"]
        self.assertEqual(manifest["path"], self.prov["normative_source"]["manifest"]["path"])
        self.assertEqual(self.prov["normative_source"]["manifest"]["sha256"], SUPERVISED_RUN_V1_MANIFEST_SHA256)
        self.assertEqual(manifest["v1_prefix"], {"lines": 5, "sha256": SUPERVISED_RUN_V1_MANIFEST_SHA256})
        self.assertEqual(f"{SUPERVISED_RUN_ROOT}/{manifest['path']}", CONTRACT["supervised_run"]["manifest"])
        data = (SUPERVISED_RUN_ROOT / manifest["path"]).read_bytes()
        self.assertEqual(hashlib.sha256(data).hexdigest(), manifest["sha256"])
        prefix = b"".join(data.splitlines(keepends=True)[:5])
        self.assertEqual(hashlib.sha256(prefix).hexdigest(), SUPERVISED_RUN_V1_MANIFEST_SHA256, "v1 manifest lines moved")

    def test_manifest_lists_exactly_the_payload_and_verifies(self) -> None:
        conformance = SUPERVISED_RUN_ROOT / "conformance"
        listed = {}
        for line in (conformance / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
            digest, rel = re.fullmatch(r"([0-9a-f]{64})  (\S+)", line).groups()  # type: ignore[union-attr]
            listed[rel] = digest
        self.assertEqual(len(listed), len(self.PAYLOAD) + len(self.V2_PAYLOAD))
        for rel, digest in listed.items():
            path = (conformance / rel).resolve()
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest, rel)
            shipped = path.relative_to(SUPERVISED_RUN_ROOT.resolve()).as_posix()
            self.assertEqual(self.prov["distributed"]["files"][shipped], digest, rel)

    def test_schemas_are_well_formed(self) -> None:
        for name, schema in (
            ("admitted_launch_envelope", self.envelope_schema),
            ("supervised_run_status", self.run_schema),
            ("admitted_launch_envelope_v2", load_schema("admitted_launch_envelope_v2")),
        ):
            self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema", name)
            self.assertTrue(schema["x-semantic-rules"], name)
            for code, text in schema["x-semantic-rules"].items():
                self.assertRegex(code, r"^[a-z][a-z0-9_]*$", name)
                self.assertTrue(isinstance(text, str) and text, f"{name}:{code}")

            def walk(node: object, path: str, in_map: bool = False) -> None:
                if isinstance(node, list):
                    for index, item in enumerate(node):
                        walk(item, f"{path}[{index}]")
                    return
                if not isinstance(node, dict):
                    return
                if in_map:  # keys of properties / $defs are names, values are schemas
                    for key, item in node.items():
                        walk(item, f"{path}.{key}")
                    return
                for key, item in node.items():
                    if key.startswith("x-"):
                        continue  # extension annotations, not schema
                    self.assertIn(key, _SR_KEYWORDS, f"{name}{path}: unknown keyword {key}")
                    if key == "$ref":
                        _sr_resolve(schema, item)  # every $ref is local and resolves
                    if key == "enum":
                        self.assertTrue(item, f"{name}{path}: empty enum")
                        self.assertEqual(len({_sr_jcs(e) for e in item}), len(item), f"{name}{path}: duplicate enum")
                    if key == "pattern":
                        re.compile(item)
                    if key == "required":
                        self.assertEqual(len(set(item)), len(item), f"{name}{path}: duplicate required")
                    walk(item, f"{path}.{key}", in_map=key in ("properties", "$defs"))

            walk(schema, "")

    def test_expected_diagnostics_are_defined_semantic_rules(self) -> None:
        for name, (vectors, schema) in self.vector_sets.items():
            self.assertEqual(vectors["contract"], schema["$id"].removeprefix("urn:contract:"), name)
            self.assertEqual(vectors["status"], "provisional", name)
            rules = set(schema["x-semantic-rules"])
            ids = [case["id"] for case in vectors["cases"]]
            self.assertEqual(len(set(ids)), len(ids), name)
            controls = {case["id"]: case for case in vectors["cases"] if case["role"] == "control"}
            for case in vectors["cases"]:
                self.assertIn(case["role"], ("control", "negative"), case["id"])
                self.assertTrue(set(case["expected"]) <= rules, f"{case['id']}: {case['expected']}")
                self.assertEqual(len(set(case["expected"])), len(case["expected"]), case["id"])
                if case["role"] == "control":
                    self.assertEqual(case["expected"], [], case["id"])
                else:
                    self.assertTrue(case["expected"], case["id"])
                    self.assertIn(case["control"], controls, case["id"])
                    self.assertEqual(controls[case["control"]]["kind"], case["kind"], case["id"])
        # The provisional rule addition this relocation attests consumer reconciliation for.
        recon = self.prov["consumer_reconciliation"]
        self.assertTrue(recon["consumers_reconciled"])
        self.assertEqual(recon["provisional_rule_additions"], ["attempt_evidence_copied"])
        self.assertIn("attempt_evidence_copied", self.run_schema["x-semantic-rules"])
        exercised = {code for case in self.vector_sets["supervised_run_status"][0]["cases"] for code in case["expected"]}
        self.assertIn("attempt_evidence_copied", exercised)

    def test_every_control_and_patched_negative_is_schema_valid(self) -> None:
        seen = 0
        for name, (vectors, _schema) in self.vector_sets.items():
            for case, value in self._case_inputs(vectors):
                self.assertEqual(self._schema_failures(case["kind"], value), [], f"{name}:{case['id']}")
                seen += 1
        self.assertEqual(seen, 51)

    def test_subset_validator_rejects_malformed_records(self) -> None:
        # Non-vacuity: the validator above must be able to say no.
        vectors = self.vector_sets["admitted_launch_envelope"][0]
        envelope = next(case for case in vectors["cases"] if case["id"] == "E-admitted")["input"]["envelope"]
        root = self.envelope_schema
        self.assertTrue(_sr_valid(root, envelope, root))
        self.assertFalse(_sr_valid(root, {**envelope, "bogus": 1}, root))
        self.assertFalse(_sr_valid(root, {k: v for k, v in envelope.items() if k != "caller_context"}, root))
        self.assertFalse(_sr_valid(root, {**envelope, "envelope_digest": "A" * 64}, root))
        bad_tier = json.loads(json.dumps(envelope))
        bad_tier["enforcement"]["tier"] = "sandboxed"
        self.assertFalse(_sr_valid(root, bad_tier, root))
        run_vectors = self.vector_sets["supervised_run_status"][0]
        journal = next(case for case in run_vectors["cases"] if case["id"] == "V-running")["input"]["journal"]
        line = journal["attempts"][0]["segments"][0]["lines"][0]
        line_schema = self.run_schema["$defs"]["journal_line"]
        self.assertTrue(_sr_valid(line_schema, line, self.run_schema))
        self.assertTrue(_sr_valid(self.run_schema, line, self.run_schema))  # root $ref is journal_line
        self.assertFalse(_sr_valid(line_schema, {**line, "line_kind": "note"}, self.run_schema))
        self.assertFalse(_sr_valid(line_schema, {**line, "seq": -1}, self.run_schema))
        self.assertFalse(_sr_valid(line_schema, {**line, "seq": True}, self.run_schema))
        self.assertFalse(_sr_valid(line_schema, {**line, "body": {"body_kind": "state"}}, self.run_schema))

    def test_envelope_digest_self_verifies_unless_mismatch_is_expected(self) -> None:
        cases = self._case_inputs(self.vector_sets["admitted_launch_envelope"][0])
        mismatches = []
        for case, value in cases:
            envelope = value["envelope"]
            ok = _sr_envelope_digest(envelope) == envelope["envelope_digest"]
            self.assertEqual(ok, "envelope_digest_mismatch" not in case["expected"], case["id"])
            if not ok:
                mismatches.append(case["id"])
        self.assertEqual(mismatches, ["S-digest-not-rehashed"])

    def test_control_journal_segment_chains_verify(self) -> None:
        cases = self._case_inputs(self.vector_sets["supervised_run_status"][0])
        chained = 0
        for case, value in cases:
            if case["role"] == "control" and "journal" in value:
                self.assertTrue(_sr_chain_ok(value["journal"]), case["id"])
                chained += 1
        self.assertGreaterEqual(chained, 5)
        # Non-vacuity: rewriting a sealed segment in place breaks the next header's link.
        replaced = next(value for case, value in cases if case["id"] == "N04a-replaced-in-place")
        self.assertFalse(_sr_chain_ok(replaced["journal"]))


# --- admitted_launch_envelope.v2 (0.7.0) ---
#
# v2 is authored in this repository, alongside the frozen v1. Its vectors are replayed through the
# reference reading below, which is copied verbatim from the generator's reader so the suite and the
# generator cannot drift; tests/contract.test.mjs carries an independently written JS reading.

# --- admitted_launch_envelope.v2 reference reading (test-local; not package API) -------------------
# This block is copied verbatim into tests/test_contract.py. It is a test-local reading of the v2
# schema's x-semantic-rules, used to prove the vectors are internally consistent. It is not a
# conforming harness: a harness captures the material itself.

import decimal as _r2_decimal
import hashlib as _r2_hashlib
import json as _r2_json
import math as _r2_math
import re as _r2_re


class R2Unbindable(ValueError):
    pass


R2_MAX_SAFE_INTEGER = 9007199254740991


def r2_es_number(x) -> str:
    """ECMAScript Number::toString of a finite binary64 value: the RFC 8785 serializer primitive.

    This primitive is not the v2 commitment domain; r2_domain_number adds the safe-integer bound.
    """
    if isinstance(x, bool):
        raise R2Unbindable("boolean is not a number")
    if isinstance(x, int):
        if float(x) != x:
            raise R2Unbindable("integer is not a binary64 value")
        x = float(x)
    if _r2_math.isnan(x) or _r2_math.isinf(x):
        raise R2Unbindable("non-finite number")
    if x == 0:
        return "0"
    if x < 0:
        return "-" + r2_es_number(-x)
    _sign, digits, exp = _r2_decimal.Decimal(repr(x)).as_tuple()
    text = "".join(map(str, digits))
    stripped = text.rstrip("0")
    exp += len(text) - len(stripped)
    k, n = len(stripped), len(stripped) + exp
    if k <= n <= 21:
        return stripped + "0" * (n - k)
    if 0 < n <= 21:
        return stripped[:n] + "." + stripped[n:]
    if -6 < n <= 0:
        return "0." + "0" * (-n) + stripped
    e = n - 1
    mantissa = stripped if k == 1 else stripped[0] + "." + stripped[1:]
    return f"{mantissa}e{'+' if e >= 0 else '-'}{abs(e)}"


def r2_domain_number(x) -> str:
    """The v2 commitment domain (x-canonicalization): finite binary64, integer-valued only within
    +-(2**53 - 1), checked on the value whatever its spelling; host integers are range-checked first."""
    if isinstance(x, bool):
        raise R2Unbindable("boolean is not a number")
    if isinstance(x, int):
        if abs(x) > R2_MAX_SAFE_INTEGER:
            raise R2Unbindable("integer outside the safe range")
        return r2_es_number(float(x))
    if _r2_math.isnan(x) or _r2_math.isinf(x):
        raise R2Unbindable("non-finite number")
    if x.is_integer() and abs(x) > R2_MAX_SAFE_INTEGER:
        raise R2Unbindable("integer-valued number outside the safe range")
    return r2_es_number(x)


_R2_SHORT = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t"}


def r2_es_string(value: str) -> str:
    out = ['"']
    for ch in value:
        code = ord(ch)
        if 0xD800 <= code <= 0xDFFF:
            raise R2Unbindable("lone surrogate")
        out.append(_R2_SHORT.get(ch) or (f"\\u{code:04x}" if code < 0x20 else ch))
    out.append('"')
    return "".join(out)


def r2_jcs_text(value) -> str:
    if value is None or isinstance(value, bool):
        return {None: "null", True: "true", False: "false"}[value]
    if isinstance(value, (int, float)):
        return r2_domain_number(value)
    if isinstance(value, str):
        return r2_es_string(value)
    if isinstance(value, list):
        return "[" + ",".join(r2_jcs_text(item) for item in value) + "]"
    if isinstance(value, dict):
        if not all(isinstance(key, str) for key in value):
            raise R2Unbindable("non-string member name")
        keys = sorted(value, key=lambda key: key.encode("utf-16-be", "surrogatepass"))
        return "{" + ",".join(r2_es_string(key) + ":" + r2_jcs_text(value[key]) for key in keys) + "}"
    raise R2Unbindable(f"not a JSON value: {type(value).__name__}")


def r2_jcs(value) -> bytes:
    return r2_jcs_text(value).encode("utf-8")


def r2_sha(data) -> str:
    return _r2_hashlib.sha256(data.encode("utf-8") if isinstance(data, str) else data).hexdigest()


def r2_jcs_sha(value) -> str:
    return r2_sha(r2_jcs(value))


def _r2_no_dups(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise R2Unbindable("duplicate member name")
        out[key] = value
    return out


def _r2_parse_int(text):
    value = int(text)
    r2_domain_number(value)  # range-checked before any conversion
    return value


def _r2_parse_float(text):
    value = float(text)  # round-to-nearest, ties-to-even
    r2_domain_number(value)
    return value


def _r2_reject_constant(name):
    raise R2Unbindable(f"non-JSON constant {name}")


def _r2_well_formed(node) -> bool:
    if isinstance(node, str):
        return not any(0xD800 <= ord(ch) <= 0xDFFF for ch in node)
    if isinstance(node, list):
        return all(_r2_well_formed(item) for item in node)
    if isinstance(node, dict):
        return all(_r2_well_formed(key) and _r2_well_formed(item) for key, item in node.items())
    return True


def r2_strict_parse(raw: bytes):
    """The RFC 8785 / I-JSON boundary on raw input: UTF-8, no duplicate names, finite exact numbers, no lone surrogates."""
    try:
        text = raw.decode("utf-8")
        value = _r2_json.loads(
            text, object_pairs_hook=_r2_no_dups, parse_int=_r2_parse_int,
            parse_float=_r2_parse_float, parse_constant=_r2_reject_constant,
        )
    except R2Unbindable:
        raise
    except ValueError as exc:
        raise R2Unbindable(str(exc)) from exc
    if not _r2_well_formed(value):
        raise R2Unbindable("lone surrogate")
    return value


_R2_IDENTIFIER = _r2_re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def r2_relpath_ok(value, *, allow_dot: bool = False) -> bool:
    if not isinstance(value, str):
        return False
    if allow_dot and value == ".":
        return True
    if value == "" or ":" in value or "\\" in value:
        return False
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value):
        return False
    return all(segment not in ("", ".", "..") for segment in value.split("/"))


def r2_valid_text(value) -> bool:
    return isinstance(value, str) and "\x00" not in value and _r2_well_formed(value)


def r2_capture_manifest(capture: list) -> list:
    """x-digest-forms.rfc8785_tree_manifest from a capture listing; raises R2Unbindable."""
    entries, seen, kinds = [], set(), {}
    for item in capture:
        path = item.get("path")
        if isinstance(path, str) and (path == ".git" or path.startswith(".git/")):
            continue
        if not isinstance(path, str) or not r2_valid_text(path) or not r2_relpath_ok(path):
            raise R2Unbindable("path not representable")
        if path in seen:
            raise R2Unbindable("duplicate path")
        seen.add(path)
        kinds[path] = item.get("type")
        kind = item.get("type")
        if kind == "dir":
            continue
        if kind == "file":
            mode = item.get("mode")
            if not isinstance(mode, int) or isinstance(mode, bool):
                raise R2Unbindable("mode unavailable")
            data = bytes.fromhex(item["content_hex"]) if "content_hex" in item else item["content"].encode("utf-8")
            entries.append([path, "executable_file" if mode & 0o111 else "file", r2_sha(data)])
        elif kind == "symlink":
            entries.append([path, "symlink", r2_sha(bytes.fromhex(item["target_hex"]))])
        else:
            raise R2Unbindable(f"unsupported entry type {kind}")
    # Ancestor consistency, whatever the listing order: a represented non-directory is never a proper
    # ancestor of another listed path (directories may be implicit).
    for path in kinds:
        segments = path.split("/")
        for depth in range(1, len(segments)):
            ancestor = "/".join(segments[:depth])
            if ancestor in kinds and kinds[ancestor] != "dir":
                raise R2Unbindable("non-directory ancestor")
    return sorted(entries, key=lambda entry: entry[0].encode("utf-8"))


def r2_tree_sha(manifest: list) -> str:
    return r2_jcs_sha(manifest)


def r2_route_key(record: dict) -> str:
    return r2_jcs_text([
        record["tier"], record["action"], record["transport_id"],
        [[e["locator_kind"], e["locator"], e["sha256"]] for e in record["executable_chain"]],
        record["template_sha256"], record["qualification_sha256"],
    ])


def r2_grant_value_digest(material_grant: dict) -> str:
    if material_grant["canonical_form"] == "raw_bytes":
        return r2_sha(material_grant["text"])
    return r2_jcs_sha(material_grant["value"])


def r2_redacted_environment(env: dict, classification: dict) -> dict:
    secret_names = sorted((n for n in env if isinstance(classification.get(n), dict)), key=lambda n: n.encode("utf-16-be"))
    return {"non_secret": {n: v for n, v in env.items() if classification.get(n) == "non_secret"}, "secret_names": secret_names}


def _r2_strings(node, out):
    if isinstance(node, str):
        out.append(node)
    elif isinstance(node, list):
        for item in node:
            _r2_strings(item, out)
    elif isinstance(node, dict):
        for key, item in node.items():
            out.append(key)
            _r2_strings(item, out)
    return out


def r2_evaluate(schema: dict, value: dict, *, staged: bool = True):
    """(diagnostics of the first reporting stage, admission effect) for an admission case."""
    env = value["envelope"]
    if r2_schema_errors(schema, env, schema, "/envelope"):
        return ["envelope_schema_invalid"], {"attempt": {"state": "refused", "worker_invocations": 0, "refusal": {"reason": "envelope_schema_invalid"}}}
    ctx, mat, launch = value["validator_context"], value["launch_material"], env["launch"]
    tier = env["enforcement"]["tier"]
    tiers = schema["x-enforcement-tiers"]
    box: dict = {"constraint": None, "record": None}
    sources = [launch["instructions"]["source"]] + [r["source"] for r in launch["references"]]
    sources = [s for s in sources if s is not None]
    process = mat["process"]
    try:
        policy_doc = r2_strict_parse(mat["environment"]["policy"].encode("utf-8"))
        classification = policy_doc["classification"]
    except (R2Unbindable, KeyError, TypeError):
        classification = None

    def digest():
        try:
            body = {key: item for key, item in env.items() if key != "envelope_digest"}
            return set() if r2_jcs_sha(body) == env["envelope_digest"] else {"envelope_digest_mismatch"}
        except R2Unbindable:
            return {"envelope_digest_mismatch"}

    def authority():
        if env["assignment_digest"] != ctx["expected_assignment_digest"] or env["units"]["crosswalk_ref"] != ctx["expected_crosswalk_ref"]:
            return {"authority_foreign"}
        return {"authority_baseline_stale"} if env["units"]["snapshot_ref"] != ctx["expected_snapshot_ref"] else set()

    def shape():
        out = set()
        state = launch["workspace_state"]
        paths = list(env["workspace"]["repo_relative_locators"])
        paths += [s["path"] for s in sources if s["namespace"] in ("workspace", "declared_root")]
        paths += [e["locator"] for e in launch["executable_chain"] if e["locator_kind"] == "repo_relative"]
        paths += [loc for pair in state["target_map"] for loc in (pair["workspace_locator"], pair["protected_locator"])]
        if not all(r2_relpath_ok(p) for p in paths) or not r2_relpath_ok(state["cwd"]["path"], allow_dot=True):
            out.add("locator_not_repo_relative")
        strings = _r2_strings({key: item for key, item in env.items() if key != "caller_context"}, [])
        if any(len(s) > 512 or any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in s) for s in strings):
            out.add("raw_output_in_record")
        deps = env["executable_dependencies"]
        if deps["declared"] and deps["admitted_dependency_digest"] is None:
            out.add("dependency_digest_required")
        if env["workspace"]["kind"] in ("separate_clone", "git_worktree_of_protected") and state["base_commit"] is None:
            out.add("workspace_source_inconsistent")
        chain = launch["executable_chain"]
        if (
            chain[-1]["role"] != "executable" or any(e["role"] != "wrapper" for e in chain[:-1])
            or any(e["locator_kind"] == "declared" and not _R2_IDENTIFIER.match(e["locator"]) for e in chain)
        ):
            out.add("executable_chain_invalid")
        if sum(r["role"] == "baseline" for r in launch["references"]) != 1:
            out.add("baseline_reference_required")
        scope = env["workspace"]["repo_relative_locators"]
        if any(not any(p["protected_locator"] == s or p["protected_locator"].startswith(s + "/") for s in scope) for p in state["target_map"]):
            out.add("target_map_outside_scope")
        return out

    def tier_stage():
        return {"tier_unqualified"} if tiers[tier]["status"] == "reserved" else set()

    def route():
        trusted = launch["trusted_policy"]
        if trusted["qualification_sha256"] is None:
            return {"route_not_qualified"}
        key = r2_route_key({
            "tier": tier, "action": launch["action"], "transport_id": launch["transport_id"],
            "executable_chain": launch["executable_chain"], "template_sha256": trusted["template_sha256"],
            "qualification_sha256": trusted["qualification_sha256"],
        })
        matches = [record for record in ctx["qualified_routes"] if r2_route_key(record) == key]
        if len(matches) != 1:
            return {"route_not_qualified"}
        box["record"] = matches[0]
        return set()

    def capability():
        out = set()
        info = tiers[tier]
        unsupported = [c for c in env["enforcement"]["required_constraints"] if info["constraints"][c] == "not_enforced"]
        if unsupported:
            out.add("constraint_unsupported")
            box["constraint"] = unsupported[0]
        if env["workspace"]["kind"] not in info["workspace_kinds"]:
            out.add("workspace_not_separate_copy")
        record = box["record"] or {"grants": {}, "credential_sources": []}
        grants = launch.get("grants", {})
        if any(kind not in info["grant_kinds"] or record["grants"].get(kind) != commitment for kind, commitment in grants.items()):
            out.add("grant_unqualified")
        if "dependency_projection_sha256" in grants and not env["executable_dependencies"]["declared"]:
            out.add("grant_unqualified")
        if any(s["namespace"] == "descriptor" for s in sources) and "descriptor_capabilities_sha256" not in grants:
            out.add("grant_unqualified")
        if launch["workspace_state"]["cwd"]["namespace"] == "view_root" and "filesystem_view_sha256" not in grants:
            out.add("grant_unqualified")
        if isinstance(classification, dict):
            for name in process["worker"]["env"]:
                entry = classification.get(name)
                if isinstance(entry, dict) and entry.get("secret") not in record.get("credential_sources", []):
                    out.add("grant_unqualified")
        if launch["action"] == "execution" and launch["stop"]["deadline_action"] == "not_armed":
            out.add("stop_policy_unbounded")
        if launch["stop"]["timeout_seconds"] > ctx["timeout_max_seconds"]:
            out.add("timeout_over_declared_max")
        return out

    def material():
        out = set()
        unbound = lambda: out.add("launch_input_unbound")  # noqa: E731
        spawn, worker = process["spawn"], process["worker"]
        policy = mat["policy"]
        grants_material = policy["grants"]

        # source tree capture (x-digest-forms.rfc8785_tree_manifest)
        try:
            manifest = r2_capture_manifest(mat["workspace"]["capture"])
            files = {e[0]: e for e in manifest}
        except R2Unbindable:
            manifest, files = None, None
            unbound()

        def tree_joins(path, sha):
            if files is None:
                return True
            entry = files.get(path)
            return entry is not None and entry[1] in ("file", "executable_file") and entry[2] == sha

        # structured grants, for descriptor and view-root resolution and the terminal exclusion
        def grant_value(kind):
            g = grants_material.get(kind)
            return g["value"] if isinstance(g, dict) and g.get("canonical_form") == "rfc8785" else None

        descriptors = (grant_value("descriptor_capabilities_sha256") or {}).get("descriptors", [])
        if any(isinstance(d, dict) and d.get("terminal") for d in descriptors):
            unbound()
        roots = set()
        for line in policy["config"].splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] == "root":
                roots.add(parts[1])

        def resolvable(source, captured):
            if captured.get("content") is None or not captured.get("within_root", False):
                return False
            if source["namespace"] == "declared_root":
                return source["root"] in roots
            if source["namespace"] == "descriptor":
                return any(isinstance(d, dict) and d.get("id") == source["descriptor"] for d in descriptors)
            return True

        # argv and environment representability
        argvs_ok = all(
            isinstance(vec, list) and all(r2_valid_text(arg) for arg in vec)
            for vec in (spawn["argv"], worker["argv"])
        )
        if not argvs_ok:
            unbound()

        def env_ok(env_map):
            return isinstance(env_map, dict) and all(
                r2_valid_text(n) and n != "" and "=" not in n and r2_valid_text(v) for n, v in env_map.items()
            )

        envs_ok = env_ok(spawn["env"]) and env_ok(worker["env"])
        if not envs_ok:
            unbound()
        classified = envs_ok and isinstance(classification, dict) and all(
            classification.get(n) == "non_secret" or (isinstance(classification.get(n), dict) and "secret" in classification[n])
            for n in worker["env"]
        )
        if envs_ok and not classified:
            unbound()

        # secret values never enter committed material
        if classified:
            secrets = [v for n, v in worker["env"].items() if isinstance(classification.get(n), dict) and v]
            committed = _r2_strings([
                env,
                spawn["argv"], worker["argv"], mat["instructions"].get("content"),
                [r.get("content") for r in mat["references"]], policy["config"], policy["template"],
                policy["qualification"], mat["environment"]["policy"],
                [g.get("text") if g.get("canonical_form") == "raw_bytes" else r2_jcs_text(g.get("value")) for g in grants_material.values()],
                [v for n, v in worker["env"].items() if classification.get(n) == "non_secret"],
                [c.get("content") for c in mat["workspace"]["capture"] if "content" in c],
            ], [])
            derived = [r2_sha(secret) for secret in secrets]
            if any(secret in text for secret in secrets + derived for text in committed):
                unbound()

        # standard input delivery (interactive terminal excluded)
        stdin = mat["stdin"]
        writes = stdin["writes"]
        if stdin["mode"] == "pty":
            unbound()
        elif launch["stdin"] == "devnull":
            if stdin["mode"] != "devnull" or writes:
                unbound()
        else:
            if stdin["mode"] != "pipe" or len(writes) != 1 or writes[0]["after"] != "start":
                unbound()
            elif writes[0]["text"] != mat["instructions"].get("content"):
                out.add("launch_instructions_mismatch")
        if mat["unbound_inputs"]:
            unbound()

        # instructions
        instr, captured = launch["instructions"], mat["instructions"]
        content = captured.get("content")
        if captured.get("source") != instr["source"]:
            out.add("launch_instructions_mismatch")
        if content is None:
            unbound()
        else:
            if r2_sha(content) != instr["sha256"] or len(content.encode("utf-8")) != instr["byte_length"]:
                out.add("launch_instructions_mismatch")
            if instr["source"] is None:
                inline = (launch["stdin"] == "input") or (argvs_ok and worker["argv"].count(content) == 1)
                if not inline:
                    out.add("launch_instructions_mismatch")
            elif not resolvable(instr["source"], captured):
                unbound()
            elif instr["source"]["namespace"] == "workspace" and not tree_joins(instr["source"]["path"], instr["sha256"]):
                out.add("launch_instructions_mismatch")

        # references
        bound_refs = [(r["role"], r2_jcs_text(r["source"]), r["sha256"], r["byte_length"]) for r in launch["references"]]
        used_refs = []
        for r in mat["references"]:
            c = r.get("content")
            used_refs.append((r["role"], r2_jcs_text(r["source"]), None if c is None else r2_sha(c), None if c is None else len(c.encode("utf-8"))))
            if not resolvable(r["source"], r):
                unbound()
        if bound_refs != used_refs:
            out.add("launch_reference_mismatch")
        for r in launch["references"]:
            if r["source"]["namespace"] == "workspace" and not tree_joins(r["source"]["path"], r["sha256"]):
                out.add("launch_reference_mismatch")

        # argv (outermost spawn)
        if argvs_ok:
            if r2_jcs_sha(spawn["argv"]) != launch["argv"]["sha256"] or len(spawn["argv"]) != launch["argv"]["element_count"]:
                out.add("launch_argv_mismatch")

        # executable chain
        fields = ("role", "locator_kind", "locator", "sha256")
        if [tuple(e[f] for f in fields) for e in launch["executable_chain"]] != [tuple(e.get(f) for f in fields) for e in mat["executable_chain"]]:
            out.add("launch_executable_mismatch")
        for e in launch["executable_chain"]:
            if e["locator_kind"] == "repo_relative" and not tree_joins(e["locator"], e["sha256"]):
                out.add("launch_executable_mismatch")

        # declared transformations (x-process-boundary)
        try:
            template = r2_strict_parse(policy["template"].encode("utf-8"))
            helpers = template.get("helpers", [])
            spawn_cwd = template["spawn_cwd"]
        except (R2Unbindable, KeyError, TypeError, AttributeError):
            template, helpers, spawn_cwd = None, [], None
            unbound()
        if template is not None:
            if spawn["cwd"] != spawn_cwd:
                unbound()
            if argvs_ok:
                shift = sum(h.get("argv_shift", 0) for h in helpers)
                if spawn["argv"][shift:] != worker["argv"]:
                    out.add("launch_argv_mismatch")
            if envs_ok:
                derived = dict(spawn["env"])
                consumed_ok = True
                for h in helpers:
                    for name, val in h.get("env_consumed", {}).items():
                        if derived.get(name) != val:
                            consumed_ok = False
                        derived.pop(name, None)
                    derived.update(h.get("env_set", {}))
                consumed = {n for h in helpers for n in h.get("env_consumed", {})}
                ambient = set(spawn["env"]) - consumed - set(worker["env"])
                if not consumed_ok or ambient:
                    unbound()
                elif derived != worker["env"]:
                    out.add("launch_environment_mismatch")
            derived_cwd = spawn["cwd"]
            for h in helpers:
                if h.get("cwd") is not None:
                    derived_cwd = h["cwd"]
            if derived_cwd != worker["cwd"]:
                out.add("launch_workspace_mismatch")

        # workspace state and working directory
        state, used = launch["workspace_state"], mat["workspace"]
        if used["base_commit"] != state["base_commit"] or used["target_map"] != state["target_map"]:
            out.add("launch_workspace_mismatch")
        if manifest is not None and r2_tree_sha(manifest) != state["content_sha256"]:
            out.add("launch_workspace_mismatch")
        if worker["cwd"] != state["cwd"]:
            out.add("launch_workspace_mismatch")
        resolution = process["cwd_resolution"]
        if not resolution["within_root"]:
            unbound()
        if state["cwd"]["namespace"] == "view_root":
            view_roots = [r.get("id") for r in (grant_value("filesystem_view_sha256") or {}).get("roots", []) if isinstance(r, dict)]
            if state["cwd"]["root"] not in view_roots:
                unbound()
        bound_sources = [r2_jcs_text(r["source"]) for r in launch["references"]]
        if any(r2_jcs_text(found) not in bound_sources for found in resolution["discovered"]):
            unbound()

        # environment commitment
        environment = launch["environment"]
        if classified:
            if r2_jcs_sha(r2_redacted_environment(worker["env"], classification)) != environment["map_sha256"]:
                out.add("launch_environment_mismatch")
        if mat["environment"]["policy_id"] != environment["policy"]["id"] or r2_sha(mat["environment"]["policy"]) != environment["policy"]["sha256"]:
            out.add("launch_environment_mismatch")

        # trusted policy and grants
        trusted = launch["trusted_policy"]
        qualification = None if policy["qualification"] is None else r2_sha(policy["qualification"])
        if r2_sha(policy["config"]) != trusted["config_sha256"] or r2_sha(policy["template"]) != trusted["template_sha256"] or qualification != trusted["qualification_sha256"]:
            out.add("launch_policy_mismatch")
        bound_grants = launch.get("grants", {})
        if set(bound_grants) != set(grants_material):
            out.add("launch_policy_mismatch")
        for kind, commitment in bound_grants.items():
            g = grants_material.get(kind)
            try:
                if g is None or g["canonical_form"] != commitment["canonical_form"] or r2_grant_value_digest(g) != commitment["sha256"]:
                    out.add("launch_policy_mismatch")
            except R2Unbindable:
                unbound()

        # deadline
        stop, deadline = launch["stop"], process["deadline"]
        armed = stop["timeout_seconds"] if stop["deadline_action"] == "terminate_process_group" else None
        if deadline["seconds"] != armed or (armed is not None and (deadline["origin"] != "first_chain_process" or deadline["restarted_at_helper"])):
            out.add("launch_timeout_mismatch")

        # qualification probes
        for probe in process["probes"]:
            if probe["phase"] != "before_admission" or probe["mutated_captured"] or (argvs_ok and probe["argv"] == worker["argv"]):
                unbound()
        return out

    reported: set = set()
    for stage in (digest, authority, shape, tier_stage, route, capability, material):
        reported |= stage()
        if reported and staged:
            break
    order = [code for group in schema["x-evaluation-order"]["stages"] for code in group]
    codes = sorted(reported, key=order.index)
    if not codes:
        return [], {"attempt": {"state": "queued", "worker_invocations": 0}}
    constraint = box["constraint"] if codes[0] == "constraint_unsupported" else None
    return codes, {"attempt": {"state": "refused", "worker_invocations": 0, "refusal": {"reason": codes[0], "constraint": constraint, "tier": tier}}}


def r2_schema_errors(schema, value, root, path=""):
    """JSON Schema errors as (instance_path, keyword); a type failure masks its node, anyOf reports itself."""
    errors = set()
    if "$ref" in schema:
        target = root
        for part in schema["$ref"][2:].split("/"):
            target = target[part]
        errors |= r2_schema_errors(target, value, root, path)

    def type_ok(name, v):
        if name == "integer":
            return isinstance(v, int) and not isinstance(v, bool)
        return {"object": isinstance(v, dict), "array": isinstance(v, list), "string": isinstance(v, str),
                "boolean": isinstance(v, bool), "null": v is None}[name]

    def same(a, b):
        return type(a) is type(b) and a == b

    if "type" in schema:
        names = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
        if not any(type_ok(name, value) for name in names):
            errors.add((path, "type"))
            return errors
    if "const" in schema and not same(value, schema["const"]):
        errors.add((path, "const"))
    if "enum" in schema and not any(same(value, entry) for entry in schema["enum"]):
        errors.add((path, "enum"))
    if "anyOf" in schema and not any(not r2_schema_errors(sub, value, root, path) for sub in schema["anyOf"]):
        errors.add((path, "anyOf"))
    if isinstance(value, str):
        if len(value) < schema.get("minLength", 0):
            errors.add((path, "minLength"))
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            errors.add((path, "maxLength"))
        if "pattern" in schema and not _r2_re.search(schema["pattern"], value):
            errors.add((path, "pattern"))
    if isinstance(value, int) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            errors.add((path, "minimum"))
        if "maximum" in schema and value > schema["maximum"]:
            errors.add((path, "maximum"))
    if isinstance(value, list):
        if len(value) < schema.get("minItems", 0):
            errors.add((path, "minItems"))
        if schema.get("uniqueItems") and len({r2_jcs_text(item) for item in value}) != len(value):
            errors.add((path, "uniqueItems"))
        if "items" in schema:
            for index, item in enumerate(value):
                errors |= r2_schema_errors(schema["items"], item, root, f"{path}/{index}")
    if isinstance(value, dict):
        props = schema.get("properties", {})
        if any(key not in value for key in schema.get("required", [])):
            errors.add((path, "required"))
        if len(value) < schema.get("minProperties", 0):
            errors.add((path, "minProperties"))
        if schema.get("additionalProperties") is False and any(key not in props for key in value):
            errors.add((path, "additionalProperties"))
        for key, item in value.items():
            if key in props:
                errors |= r2_schema_errors(props[key], item, root, f"{path}/{key}")
    return errors


# --- write_scope apply check (x-constraint-semantics.write_scope, x-apply-outcomes) ---------------

def r2_apply(fixture: dict):
    """(outcome, protected_after) for an application fixture."""
    env, before, proposal = fixture["envelope"], fixture["protected_before"], fixture["proposal"]
    mapping = {pair["workspace_locator"]: pair["protected_locator"] for pair in env["target_map"]}
    scope = env["repo_relative_locators"]
    ops = {"modify", "add", "delete", "rename", "copy"}

    def protected(path):
        target = mapping.get(path)
        if target is None or not any(target == s or target.startswith(s + "/") for s in scope):
            return None
        return target

    if r2_sha(proposal["text"]) != proposal["recorded_sha256"]:
        return "proposal_digest_mismatch", dict(before)
    entries = proposal["entries"]
    if any(e.get("op") not in ops or not isinstance(e.get("path"), str) or (e["op"] in ("rename", "copy") and not isinstance(e.get("from"), str)) for e in entries):
        return "proposal_unattributable", dict(before)
    if any(e.get("kind") != "file" or e.get("mode_change") for e in entries):
        return "proposal_entry_unsupported", dict(before)
    touched = [p for e in entries for p in ([e["path"]] + ([e["from"]] if e["op"] in ("rename", "copy") else []))]
    if any(protected(p) is None for p in touched):
        return "proposal_out_of_scope", dict(before)
    after = dict(before)
    for e in entries:
        target = protected(e["path"])
        if e["op"] in ("modify", "delete"):
            if before.get(target) != e["base_sha256"]:
                return "proposal_stale", dict(before)
        if e["op"] in ("add", "rename", "copy") and target in before:
            return "proposal_stale", dict(before)
        if e["op"] in ("rename", "copy"):
            source = protected(e["from"])
            if before.get(source) != e["base_sha256"]:
                return "proposal_stale", dict(before)
            if e["op"] == "rename":
                after.pop(source)
        if e["op"] == "delete":
            after.pop(target)
        else:
            after[target] = e["new_sha256"]
    return "proposal_applied", after


# --- supervised_run_status lifecycle subset (frozen run-status rules) ------------------------------

def r2_journal_codes(journal: dict, run_schema: dict) -> list:
    """refused_after_launch and lifecycle_invalid, read as the frozen run-status x-semantic-rules define them."""
    lifecycle = run_schema["x-journal-rules"]["lifecycle"]
    codes = set()
    for attempt in journal["attempts"]:
        states = []
        for segment in attempt["segments"]:
            for line in segment["lines"]:
                if isinstance(line, dict) and line.get("line_kind") in ("state", "terminal"):
                    states.append(line["body"])
        previous = None
        for body in states:
            state = body["state"]
            invalid_transition = previous is not None and state not in lifecycle[previous]
            after_launch = state == "refused" and (previous in ("running", "cancelling") or body["worker_invocations"] > 0)
            if after_launch:
                codes.add("refused_after_launch")
            elif invalid_transition:
                codes.add("lifecycle_invalid")
            if body.get("body_kind") == "terminal":
                if state == "finished" and body.get("termination") is None:
                    codes.add("lifecycle_invalid")
                if state == "refused" and body.get("refusal") is None:
                    codes.add("lifecycle_invalid")
            previous = state
    return sorted(codes)

class SupervisedRunEnvelopeV2Test(unittest.TestCase):
    """admitted_launch_envelope.v2 (0.7.0): every vector replayed through the reference reading above."""

    # Independent pins (not produced by this suite's own serializer).
    UTF16_KEYS_SHA256 = "10921118479ffb2077228b69799235faedcf1ce522092829370ceb5a2b0840d2"
    CODEPOINT_KEYS_SHA256 = "a67e33a8d5f207d14ebee49ac747d857fe0d8804a7ecf55c1ea2ba80f581a494"
    FAKE_SECRETS = ("fake-credential-0001-not-a-real-secret", "fake-credential-0002-rotated-not-real")
    FINDINGS = {
        "V2-BIND-01", "V2-QUAL-01", "V2-JCS-01", "V2-TREE-01", "V2-TIER-01", "V2-PRIV-01", "R1", "R2", "R3",
        "V2-GRANT-01", "S3", "V2-VEC-01", "V2-VEC-02", "V2-LOC-01", "S4",
        "R2-JCS-02", "R2-SECRET-01", "R2-TREE-01", "R2-BIND-01",
    }
    PROTO_OBJECT_SHA256 = "0fb20b06cf5847cf21cc37dd0d3602c176cc3f96ea4281167bbfe61cbe5813a3"

    @classmethod
    def setUpClass(cls) -> None:
        cls.schema = load_schema("admitted_launch_envelope_v2")
        cls.v1_schema = load_schema("admitted_launch_envelope")
        cls.run_schema = load_schema("supervised_run_status")
        vectors = CONTRACT["supervised_run"]["vectors"]
        cls.vectors = json.loads(Path(vectors["admitted_launch_envelope_v2"]).read_text(encoding="utf-8"))
        cls.canonical = json.loads(Path(vectors["admitted_launch_envelope_v2_canonical"]).read_text(encoding="utf-8"))
        cls.apply = json.loads(Path(vectors["admitted_launch_envelope_v2_apply"]).read_text(encoding="utf-8"))
        controls = {case["id"]: case for case in cls.vectors["cases"] if case["role"] == "control"}
        cls.cases = []
        for case in cls.vectors["cases"]:
            if case["role"] == "control":
                cls.cases.append((case, case["input"]))
                continue
            patched = _sr_apply_patch(controls[case["control"]]["input"], case["patch"])
            if case.get("rehash"):
                patched["envelope"]["envelope_digest"] = _sr_envelope_digest(patched["envelope"])
            cls.cases.append((case, patched))
        cls.by_id = {case["id"]: value for case, value in cls.cases}

    def outcome(self, case: dict, value: dict) -> list:
        if case["kind"] == "echo":
            same = r2_jcs_text(value["echoed_caller_context"]) == r2_jcs_text(value["envelope"]["caller_context"])
            return [] if same else ["caller_context_interpreted"]
        return r2_evaluate(self.schema, value)[0]

    # ---- structure

    def test_registered_alongside_frozen_v1(self) -> None:
        self.assertEqual(self.schema["$id"], "urn:contract:admitted_launch_envelope.v2")
        self.assertEqual(CONTRACT["schemas"]["admitted_launch_envelope_v2"], "core/supervised-run/admitted-launch-envelope.v2.schema.json")
        for name in ("vectors", "canonical", "apply"):
            self.assertEqual(getattr(self, name)["contract"], "admitted_launch_envelope.v2", name)
            self.assertEqual(getattr(self, name)["status"], "provisional", name)
        self.assertEqual(set(self.schema["required"]) - set(self.v1_schema["required"]), {"launch"})
        self.assertEqual(set(self.v1_schema["x-semantic-rules"]) - set(self.schema["x-semantic-rules"]), set())
        for key in ("assignment_digest", "units", "obligations", "executable_dependencies", "redaction_posture"):
            self.assertEqual(self.schema["properties"][key], self.v1_schema["properties"][key], key)
        self.assertIs(self.schema["properties"]["launch"]["additionalProperties"], False)

    def test_caller_context_is_opaque_and_never_a_launch_input(self) -> None:
        # S4: the normative sentence, kept verbatim, plus the refusal and echo controls.
        description = self.schema["properties"]["caller_context"]["description"]
        self.assertIn("never interpreted by the harness or the workbench reader, and never a source of any launch input", description)
        self.assertEqual(self.schema["x-launch-semantics"]["caller_context"], "No launch input is ever taken from caller_context.")
        self.assertIn("caller_context", self.schema["required"])
        self.assertNotIn("caller_context", json.dumps(self.schema["properties"]["launch"]))
        ids = {case["id"] for case, _ in self.cases}
        self.assertTrue({"S2-caller-context-launch-input", "E2-echo", "E2-jcs-echo", "S2-caller-context-interpreted", "S2-jcs-echo-number-changed"} <= ids)

    def test_semantic_rules_and_evaluation_order_agree(self) -> None:
        flat = [code for stage in self.schema["x-evaluation-order"]["stages"] for code in stage]
        self.assertEqual(len(flat), len(set(flat)))
        self.assertEqual(set(flat) | {"caller_context_interpreted", "refusal_zero_invocations"}, set(self.schema["x-semantic-rules"]))
        self.assertIn("zero launch-chain processes", self.schema["x-semantic-rules"]["refusal_zero_invocations"])
        self.assertNotIn("before any process starts", self.schema["x-semantic-rules"]["refusal_zero_invocations"])

    def test_tiers_describe_semantics_and_apply_check_is_unconditional(self) -> None:
        tiers = self.schema["x-enforcement-tiers"]
        constraints = self.schema["properties"]["enforcement"]["properties"]["required_constraints"]["items"]["enum"]
        for name, info in tiers.items():
            self.assertNotIn("qualified", info, name)
            self.assertEqual(sorted(info["constraints"]), sorted(constraints), name)
            self.assertEqual(info["constraints"]["write_prevention"], "not_enforced", name)
            expected = ("required", "defined") if info["status"] == "defined" else ("not_admissible", "reserved")
            self.assertEqual((info["qualification"], info["status"]), expected, name)
        write_scope = self.schema["x-constraint-semantics"]["write_scope"]
        self.assertIn("runs whether or not required_constraints lists write_scope", write_scope)
        self.assertIn("running -> finished", write_scope)
        self.assertIn("refused_after_launch", write_scope)
        self.assertEqual(
            sorted(k for k in self.schema["x-apply-outcomes"] if not k.startswith("$")),
            sorted(fixture["expected"]["outcome"] for fixture in self.apply["applications"]) and sorted({
                "proposal_digest_mismatch", "proposal_unattributable", "proposal_entry_unsupported",
                "proposal_out_of_scope", "proposal_stale", "proposal_applied"}),
        )

    def test_cases_are_well_formed(self) -> None:
        rules = set(self.schema["x-semantic-rules"])
        ids = [case["id"] for case, _ in self.cases]
        self.assertEqual(len(ids), len(set(ids)))
        controls = {case["id"]: case for case, _ in self.cases if case["role"] == "control"}
        for case, _ in self.cases:
            self.assertIn(case["role"], ("control", "negative", "schema_negative"), case["id"])
            self.assertTrue(set(case["expected"]) <= rules, case["id"])
            if case["role"] == "control":
                self.assertEqual(case["expected"], [], case["id"])
                continue
            self.assertEqual(controls[case["control"]]["kind"], case["kind"], case["id"])
            self.assertTrue(case["expected"], case["id"])
            if case["role"] == "schema_negative":
                self.assertEqual(case["expected"], ["envelope_schema_invalid"], case["id"])
                self.assertTrue(case["expected_schema_errors"], case["id"])
        roles = [case["role"] for case, _ in self.cases]
        self.assertEqual((roles.count("control"), roles.count("negative"), roles.count("schema_negative")), (20, 168, 62))

    # ---- envelope admission

    def test_schema_validity_and_exact_schema_errors(self) -> None:
        for case, value in self.cases:
            errors = r2_schema_errors(self.schema, value["envelope"], self.schema, "/envelope")
            self.assertEqual(_sr_valid(self.schema, value["envelope"], self.schema), not errors, case["id"])
            expected = {(e["instance_path"], e["keyword"]) for e in case.get("expected_schema_errors", [])}
            self.assertEqual(errors, expected, case["id"])

    def test_envelope_digest_self_verifies_unless_mismatch_is_expected(self) -> None:
        mismatches = []
        for case, value in self.cases:
            ok = _sr_envelope_digest(value["envelope"]) == value["envelope"]["envelope_digest"]
            self.assertEqual(ok, "envelope_digest_mismatch" not in case["expected"], case["id"])
            if not ok:
                mismatches.append(case["id"])
        self.assertEqual(sorted(mismatches), ["S2-digest-not-rehashed", "S2-jcs-ascii-escaped-envelope", "S2-jcs-codepoint-order-envelope"])

    def test_every_vector_matches_the_staged_rules(self) -> None:
        for case, value in self.cases:
            self.assertEqual(self.outcome(case, value), case["expected"], case["id"])
            if case["kind"] == "admission":
                _codes, effect = r2_evaluate(self.schema, value)
                self.assertTrue(_sr2_subset(case["expected_effect"], effect), f"{case['id']}: {effect}")
                self.assertEqual(effect["attempt"]["worker_invocations"], 0, case["id"])

    def test_staging_is_load_bearing(self) -> None:
        widened = {case["id"] for case, value in self.cases
                   if case["kind"] == "admission" and case["role"] == "negative" and r2_evaluate(self.schema, value, staged=False)[0] != case["expected"]}
        self.assertTrue({"S2-os-enforced", "S2-chain-executable-not-last", "S2-qual-duplicate-identical"} <= widened, widened)

    def test_qualification_needs_exactly_one_matching_record_in_any_order(self) -> None:
        # V2-QUAL-01: every permutation of the held records gives the same answer.
        for case, value in self.cases:
            if case["kind"] != "admission" or case["role"] == "schema_negative":
                continue
            routes = value["validator_context"]["qualified_routes"]
            if len(routes) > 4:
                continue
            for order in itertools.permutations(range(len(routes))):
                permuted = json.loads(json.dumps(value))
                permuted["validator_context"]["qualified_routes"] = [routes[i] for i in order]
                self.assertEqual(r2_evaluate(self.schema, permuted)[0], case["expected"], f"{case['id']} {order}")
        duplicate = self.by_id["S2-qual-duplicate-identical"]
        self.assertEqual(r2_evaluate(self.schema, duplicate)[0], ["route_not_qualified"])
        self.assertEqual(self.by_id["S2-qual-single-noncovering"]["validator_context"]["qualified_routes"].__len__(), 1)

    def test_every_new_field_finding_and_rule_has_a_positive_and_a_negative(self) -> None:
        def norm(path: str) -> str:
            path = re.sub(r"/\d+(?=/|$)", "/*", path)
            path = re.sub(r"/grants/[a-z_]+_sha256(?=/)", "/grants/<grant>", path)
            return re.sub(r"/(instructions/source|references/\*/source)(?=/|$)", "/<source>", path)

        leaves = {norm(p) for p in _r2_leaves(self.schema, self.schema["properties"]["launch"], "/envelope/launch")}
        controls = [value for case, value in self.cases if case["role"] == "control"]
        present = set()
        for value in controls:
            present |= {norm(p) for p in _r2_paths(value["envelope"]["launch"], "/envelope/launch")}
        touched = set()
        for case, _ in self.cases:
            for op in case.get("patch", []):
                touched.add(norm(op["path"]))
                if isinstance(op.get("value"), (dict, list)):
                    touched |= {norm(p) for p in _r2_paths(op["value"], op["path"])}
        for leaf in sorted(leaves):
            self.assertIn(leaf, present, f"no positive: {leaf}")
            self.assertTrue(any(t == leaf or t.startswith(leaf + "/") for t in touched), f"no negative: {leaf}")
        self.assertIn("/envelope/launch", touched)
        for kind in self.schema["properties"]["launch"]["properties"]["grants"]["properties"]:
            prefix = f"/envelope/launch/grants/{kind}"
            self.assertTrue(any(op["path"].startswith(prefix) for case, _ in self.cases for op in case.get("patch", [])), kind)
        negatives = {code for case, _ in self.cases for code in case["expected"]}
        self.assertEqual(negatives, set(self.schema["x-semantic-rules"]) - {"refusal_zero_invocations"})
        findings = {case.get("finding") for case, _ in self.cases}
        findings |= {f.get("finding") for f in self.apply["applications"] + self.apply["journals"]}
        self.assertTrue(self.FINDINGS <= findings, self.FINDINGS - findings)

    def test_drive_absolute_locators_are_refused_in_every_family(self) -> None:
        # V2-LOC-01: built here because package data may not carry drive-absolute strings.
        for spelling in ("C" + ":/src", "C" + ":\\src", "c" + ":/", "\\\\server\\share"):
            self.assertFalse(r2_relpath_ok(spelling), spelling)
        base = self.by_id["E2-execution"]
        drive = "C" + ":/src/module/target.ts"
        edits = {
            "workspace": lambda e: e["workspace"]["repo_relative_locators"].append("C" + ":/src"),
            "source": lambda e: e["launch"]["references"][1]["source"].update(path=drive),
            "target_map": lambda e: e["launch"]["workspace_state"]["target_map"][0].update(workspace_locator=drive),
            "cwd": lambda e: e["launch"]["workspace_state"]["cwd"].update(path="C" + ":/src"),
        }
        for family, edit in edits.items():
            value = json.loads(json.dumps(base))
            edit(value["envelope"])
            value["envelope"]["envelope_digest"] = _sr_envelope_digest(value["envelope"])
            self.assertEqual(r2_evaluate(self.schema, value)[0], ["locator_not_repo_relative"], family)

    def test_in_place_audit_admission_and_its_negatives(self) -> None:
        # V2-VEC-02
        self.assertIn("in_place", self.schema["x-enforcement-tiers"]["post_write_audit_only"]["workspace_kinds"])
        self.assertEqual(r2_evaluate(self.schema, self.by_id["E2-audit-in-place"])[0], [])
        self.assertEqual(self.by_id["E2-audit-in-place"]["envelope"]["workspace"]["kind"], "in_place")
        for cid, code in (("S2-inplace-no-qualification", "route_not_qualified"), ("S2-inplace-write-scope", "constraint_unsupported"),
                          ("S2-inplace-provider-tier", "workspace_not_separate_copy")):
            self.assertEqual(r2_evaluate(self.schema, self.by_id[cid])[0], [code], cid)

    def test_secret_values_never_enter_a_commitment(self) -> None:
        # V2-PRIV-01 + S1: rotating the fake secret does not move the envelope; no value or value digest appears anywhere.
        self.assertEqual(self.by_id["E2-secret-env"]["envelope"], self.by_id["E2-secret-env-rotated"]["envelope"])
        self.assertEqual(self.by_id["E2-secret-env-opaque"]["envelope"], self.by_id["E2-secret-env-opaque-rotated"]["envelope"])
        needles = [s for secret in self.FAKE_SECRETS for s in (secret, hashlib.sha256(secret.encode()).hexdigest())]
        carrying = set()
        for case, value in self.cases:
            text = json.dumps(value["envelope"], ensure_ascii=False)
            if any(needle in text for needle in needles):
                carrying.add(case["id"])
                # R2-SECRET-01: an envelope that carries a secret or its digest anywhere is refused, never admitted.
                self.assertEqual(case["expected"], ["launch_input_unbound"], case["id"])
                self.assertEqual(r2_evaluate(self.schema, value)[0], ["launch_input_unbound"], case["id"])
        self.assertEqual(carrying, {
            "S3-secret-in-caller-context", "S3-secret-digest-in-caller-context", "S3-secret-in-caller-context-array",
            "S3-secret-in-caller-context-member-name", "S3-secret-digest-in-caller-context-member-name",
            "S3-secret-in-caller-context-escaped", "S3-secret-in-caller-context-substring",
        })
        raw = Path(CONTRACT["supervised_run"]["vectors"]["admitted_launch_envelope_v2"]).read_text(encoding="utf-8")
        self.assertIn("".join(f"\\u{ord(ch):04x}" for ch in self.FAKE_SECRETS[0]), raw)  # the escaped spelling is really escaped
        commitment = self.schema["x-environment-commitment"]
        self.assertIn("No salt or key is added", commitment["confidentiality"])
        self.assertIn("not confidentiality protection", commitment["confidentiality"])

    def test_cwd_does_not_change_the_source_tree_digest(self) -> None:
        # R2
        view, root = self.by_id["E2-view-cwd"], self.by_id["E2-execution"]
        self.assertEqual(view["envelope"]["launch"]["workspace_state"]["cwd"]["namespace"], "view_root")
        self.assertEqual(view["launch_material"]["workspace"]["capture"], root["launch_material"]["workspace"]["capture"])
        self.assertEqual(view["envelope"]["launch"]["workspace_state"]["content_sha256"], root["envelope"]["launch"]["workspace_state"]["content_sha256"])

    def test_helper_deadline_origin_and_expiry(self) -> None:
        # S3: one deadline, from the first launch-chain process, never restarted.
        material = self.by_id["E2-helper-transform"]["launch_material"]["process"]
        self.assertEqual(material["deadline"], {"origin": "first_chain_process", "seconds": 1800, "restarted_at_helper": False})
        self.assertNotEqual(material["spawn"]["env"], material["worker"]["env"])
        self.assertNotEqual(material["spawn"]["cwd"], material["worker"]["cwd"])
        self.assertTrue(all(p["phase"] == "before_admission" for p in material["probes"]))

    def test_controls_bind_their_launch_material(self) -> None:
        control = self.by_id["E2-execution"]
        argv = control["launch_material"]["process"]["spawn"]["argv"]
        self.assertTrue(any(ord(ch) > 127 for arg in argv for ch in arg))
        self.assertEqual(control["envelope"]["launch"]["argv"]["sha256"], r2_sha(r2_jcs(argv)))
        self.assertNotEqual(r2_sha(json.dumps(argv, separators=(",", ":"))), r2_sha(r2_jcs(argv)))

    def test_v1_and_v2_envelopes_do_not_cross_validate(self) -> None:
        v1_vectors = json.loads(Path(CONTRACT["supervised_run"]["vectors"]["admitted_launch_envelope"]).read_text(encoding="utf-8"))
        v1_envelope = next(case for case in v1_vectors["cases"] if case["id"] == "E-admitted")["input"]["envelope"]
        v2_envelope = self.by_id["E2-execution"]["envelope"]
        self.assertTrue(_sr_valid(self.v1_schema, v1_envelope, self.v1_schema))
        self.assertEqual(r2_schema_errors(self.schema, v1_envelope, self.schema, "/envelope"), {("/envelope", "required"), ("/envelope/schema", "const")})
        self.assertFalse(_sr_valid(self.v1_schema, v2_envelope, self.v1_schema))

    # ---- canonicalization and capture (V2-JCS-01, V2-TREE-01)

    def test_rfc8785_numbers(self) -> None:
        rfc_rows = 0
        for row in self.canonical["numbers"]:
            value = struct.unpack(">d", bytes.fromhex(row["bits"]))[0]
            if row.get("reject"):
                with self.assertRaises(R2Unbindable, msg=row["id"]):
                    r2_es_number(value)
            else:
                self.assertEqual(r2_es_number(value), row["canonical"], row["id"])
                rfc_rows += row["pin"] == "RFC 8785 Appendix B"
        self.assertEqual(rfc_rows, 24)

    def test_commitment_domain_safe_integers(self) -> None:
        # R2-JCS-01: the same verdict through raw parsing and through in-memory commitment, whatever the spelling.
        tokens = {row["token"]: row for row in self.canonical["domain"]}
        for row in self.canonical["domain"]:
            for path in ("raw", "in_memory"):
                try:
                    value = r2_strict_parse(f"[{row['token']}]".encode()) [0] if path == "raw" else json.loads(row["token"])
                    got = r2_jcs_text([value])[1:-1]
                except (R2Unbindable, ValueError):
                    got = None
                self.assertEqual(got, row.get("canonical"), f"{row['id']} {path}")
        for token in ("9007199254740992", "-9007199254740992", "9007199254740992.0", "9.007199254740992e15", "1e21", "999999999999999900000"):
            self.assertFalse(tokens[token]["accept"], token)
        for token in ("9007199254740991", "-9007199254740991", "1.0", "-0"):
            self.assertTrue(tokens[token]["accept"], token)
        for value in (2 ** 53, -(2 ** 53), 2.0 ** 53, 1e21, 999999999999999900000):
            with self.assertRaises(R2Unbindable, msg=repr(value)):
                r2_jcs_text({"n": value})
        self.assertEqual(r2_jcs_text({"n": R2_MAX_SAFE_INTEGER}), '{"n":9007199254740991}')
        # The serializer primitive still formats large doubles (RFC 8785 Appendix B); acceptance is a separate rule.
        self.assertEqual(r2_es_number(1e21), "1e+21")

    def test_proto_member_is_ordinary_and_pinned(self) -> None:
        # R2-JCS-02: independently pinned bytes; Python's dicts preserve the member; the JS suite checks own properties.
        docs = {d["id"]: d for d in self.canonical["documents"]}
        self.assertEqual(docs["J-proto-object"]["canonical"], '{"__proto__":{"x":1}}')
        self.assertEqual(docs["J-proto-object"]["sha256"], self.PROTO_OBJECT_SHA256)
        self.assertEqual(r2_sha(r2_jcs_text(r2_strict_parse(b'{"__proto__":{"x":1}}'))), self.PROTO_OBJECT_SHA256)
        self.assertEqual(r2_evaluate(self.schema, self.by_id["E2-jcs-proto"])[0], [])
        self.assertIn("__proto__", self.by_id["E2-jcs-proto"]["envelope"]["caller_context"])

    def test_instruction_byte_length_is_utf8_bytes(self) -> None:
        # R2-BIND-01
        value = self.by_id["E2-multibyte-instructions"]
        content = value["launch_material"]["instructions"]["content"]
        self.assertNotEqual(len(content), len(content.encode("utf-8")))
        self.assertEqual(value["envelope"]["launch"]["instructions"]["byte_length"], len(content.encode("utf-8")))
        for cid in ("S3-instructions-length-char-count", "S3-instructions-length-plus-one"):
            case = self.by_id[cid]
            self.assertEqual(case["envelope"]["launch"]["instructions"]["sha256"], value["envelope"]["launch"]["instructions"]["sha256"])
            self.assertEqual(r2_evaluate(self.schema, case)[0], ["launch_instructions_mismatch"], cid)

    def test_rfc8785_documents_and_parse_boundary(self) -> None:
        docs = {d["id"]: d for d in self.canonical["documents"]}
        for doc in self.canonical["documents"]:
            raw = doc["raw"].encode("utf-8") if "raw" in doc else bytes.fromhex(doc["raw_hex"])
            if doc.get("reject"):
                with self.assertRaises(R2Unbindable, msg=doc["id"]):
                    r2_strict_parse(raw)
                continue
            canonical = r2_jcs_text(r2_strict_parse(raw))
            self.assertEqual(canonical, doc["canonical"], doc["id"])
            self.assertEqual(r2_sha(canonical), doc["sha256"], doc["id"])
        self.assertEqual(docs["J-utf16-keys"]["sha256"], self.UTF16_KEYS_SHA256)
        for alt in self.canonical["alternates"]:
            self.assertEqual(r2_sha(alt["preimage"]), alt["sha256"], alt["id"])
            self.assertNotEqual(alt["sha256"], docs[alt["of"]]["sha256"], alt["id"])
        self.assertEqual(next(a for a in self.canonical["alternates"] if a["id"] == "A-codepoint-order")["sha256"], self.CODEPOINT_KEYS_SHA256)
        with self.assertRaises(R2Unbindable):
            r2_jcs_text({"a": float("nan")})
        with self.assertRaises(R2Unbindable):
            r2_jcs_text({"a": "\ud800"})

    def test_source_tree_capture(self) -> None:
        trees = {t["id"]: t for t in self.canonical["tree_captures"]}
        for tree in self.canonical["tree_captures"]:
            if tree.get("unbindable"):
                with self.assertRaises(R2Unbindable, msg=tree["id"]):
                    r2_capture_manifest(tree["capture"])
                continue
            manifest = r2_capture_manifest(tree["capture"])
            self.assertEqual(manifest, tree["manifest"], tree["id"])
            self.assertEqual(r2_tree_sha(manifest), tree["sha256"], tree["id"])
        root = trees["T-root-git-directory"]["sha256"]
        self.assertEqual(trees["T-root-git-file"]["sha256"], root)
        self.assertEqual(trees["T-root-git-symlink"]["sha256"], root)
        self.assertNotEqual(trees["T-nested-git-removed"]["sha256"], root)
        self.assertNotEqual(trees["T-exec-bit-cleared"]["sha256"], root)
        # R2-TREE-01: implicit directories are fine; a represented non-directory ancestor is refused in either order.
        self.assertEqual(trees["T-implicit-directories"]["sha256"], root)
        self.assertEqual(trees["T-root-git-file-with-children"]["sha256"], root)
        for tid in ("T-symlink-ancestor", "T-symlink-ancestor-listed-after", "T-file-ancestor", "T-file-ancestor-listed-after", "T-nested-git-symlink-ancestor"):
            self.assertTrue(trees[tid].get("unbindable"), tid)
        for alt in self.canonical["tree_alternates"]:
            self.assertEqual(r2_tree_sha(alt["manifest"]), alt["sha256"], alt["id"])
            derived = r2_tree_sha(r2_capture_manifest(trees[alt["of"]]["capture"]))
            self.assertNotEqual(derived, alt["sha256"], alt["id"])
            self.assertEqual(alt["expected"], "launch_workspace_mismatch")

    # ---- apply check and runtime journal (V2-TIER-01, S3)

    def test_write_scope_apply_check(self) -> None:
        for fixture in self.apply["applications"]:
            outcome, after = r2_apply(fixture)
            self.assertEqual(outcome, fixture["expected"]["outcome"], fixture["id"])
            self.assertEqual(after, fixture["expected"]["protected_after"], fixture["id"])
            self.assertEqual(fixture["envelope"]["required_constraints"], [], fixture["id"])
            if outcome != "proposal_applied":
                self.assertEqual(after, fixture["protected_before"], fixture["id"])
        controls = [f for f in self.apply["applications"] if f["role"] == "control"]
        self.assertEqual([f["expected"]["applied"] for f in controls], [True])

    def test_runtime_journals_follow_frozen_rules(self) -> None:
        line_schema = self.run_schema["$defs"]["journal_line"]
        for entry in self.apply["journals"]:
            for attempt in entry["journal"]["attempts"]:
                for segment in attempt["segments"]:
                    for line in segment["lines"]:
                        self.assertTrue(_sr_valid(line_schema, line, self.run_schema), entry["id"])
            self.assertEqual(r2_journal_codes(entry["journal"], self.run_schema), entry["expected"], entry["id"])
        # The lifecycle subset reads the frozen v1 journal vectors exactly as they expect.
        v1 = json.loads(Path(CONTRACT["supervised_run"]["vectors"]["supervised_run_status"]).read_text(encoding="utf-8"))
        controls = {c["id"]: c for c in v1["cases"] if c["role"] == "control"}
        checked = 0
        for case in v1["cases"]:
            if case["kind"] != "journal" or not set(case["expected"]) <= {"refused_after_launch", "lifecycle_invalid"}:
                continue
            value = case["input"] if case["role"] == "control" else _sr_apply_patch(controls[case["control"]]["input"], case["patch"])
            self.assertEqual(r2_journal_codes(value["journal"], self.run_schema), case["expected"], case["id"])
            checked += 1
        self.assertGreaterEqual(checked, 6)

    def test_worked_grant_example_is_in_the_readme(self) -> None:
        # S2 + V2-GRANT-01: the README's worked example is this control, byte for byte.
        readme = (SUPERVISED_RUN_ROOT / "conformance" / "README.v2.md").read_text(encoding="utf-8")
        worked = self.by_id["E2-grants-worked"]
        for kind, commitment in worked["envelope"]["launch"]["grants"].items():
            self.assertIn(commitment["sha256"], readme, kind)
            material = worked["launch_material"]["policy"]["grants"][kind]
            preimage = material["text"] if material["canonical_form"] == "raw_bytes" else r2_jcs_text(material["value"])
            self.assertEqual(r2_sha(preimage), commitment["sha256"], kind)
        record = worked["validator_context"]["qualified_routes"][1]
        self.assertEqual(record["grants"], worked["envelope"]["launch"]["grants"])
        self.assertIn(r2_jcs_text(record["grants"]), readme)


def _sr2_subset(expected: object, actual: object) -> bool:
    if isinstance(expected, dict):
        return isinstance(actual, dict) and all(k in actual and _sr2_subset(v, actual[k]) for k, v in expected.items())
    return type(expected) is type(actual) and expected == actual


def _r2_leaves(schema: dict, node: dict, prefix: str) -> set:
    if "$ref" in node:
        target = schema
        for part in node["$ref"][2:].split("/"):
            target = target[part]
        node = target
    if "anyOf" in node:
        out = set()
        for branch in node["anyOf"]:
            if branch.get("type") != "null":
                out |= _r2_leaves(schema, branch, prefix)
        return out
    if "properties" in node:
        out = set()
        for key, sub in node["properties"].items():
            out |= _r2_leaves(schema, sub, f"{prefix}/{key}")
        return out
    if "items" in node:
        return _r2_leaves(schema, node["items"], f"{prefix}/*")
    return {prefix}


def _r2_paths(value: object, prefix: str) -> set:
    out = {prefix}
    if isinstance(value, dict):
        for key, item in value.items():
            out |= _r2_paths(item, f"{prefix}/{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            out |= _r2_paths(item, f"{prefix}/{index}")
    return out

if __name__ == "__main__":
    unittest.main()
