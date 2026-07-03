from __future__ import annotations

import hashlib
import json
import re
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
    canonical_core_bytes,
    canonicalize_core,
    verify_authority_event,
)


def _stable_jcs(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


class ContractReaderTest(unittest.TestCase):
    def test_loads_contract_data(self) -> None:
        self.assertEqual(CONTRACT_VERSION, "0.5.0")
        self.assertEqual(load_contract()["contract_version"], "0.5.0")
        self.assertEqual(CONTRACT["contract_id"], "consiliency.contract.v1")
        self.assertEqual(len(load_registry("archetypes")["archetypes"]), 7)
        self.assertEqual(load_schema("manifest")["properties"]["schema"]["const"], "consiliency.manifest.v1")
        self.assertGreaterEqual(len(list_vectors()), 10)

    def test_vector_decisions_are_phase0_safe(self) -> None:
        for name in list_vectors():
            vector = load_vector(name)
            self.assertEqual(vector["decision"]["schema"], "consiliency.conformance_decision.v1", name)
            self.assertNotEqual(vector["decision"]["maturity"], "certified", name)

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
        # proj-code: two-sided cap at [presence-only, hash-checked].
        self.assertEqual(sorted(code_block["then"]["required"]), ["facts_digest", "facts_path", "pinned_commit"])
        self.assertEqual(code_block["then"]["properties"]["maturity_label"]["enum"], ["presence-only", "hash-checked"])
        # certified: [realized-edge-observed, certified]; certified permitted ONLY here.
        self.assertIn("source_S_digest", cert_block["then"]["required"])
        self.assertEqual(cert_block["then"]["properties"]["maturity_label"]["enum"], ["realized-edge-observed", "certified"])

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
        self.assertEqual(prov["authority_profile"]["signed_bytes"], "canon_core_v2.canonical_bytes(core)")
        self.assertIn("XG-4", prov["authority_profile"]["domain_separation_status"])

    def test_authority_canon_parity_gate(self) -> None:
        # Confirms the committed pins still match the CURRENT spec canon; skips
        # (does not vacuously pass) when no spec checkout is present.
        import subprocess
        import sys
        from pathlib import Path

        root = Path(__file__).resolve().parent.parent
        proc = subprocess.run(
            [sys.executable, "scripts/authority_canon_parity.py"],
            cwd=root, capture_output=True, text=True,
        )
        report = json.loads(proc.stdout.strip())
        if report["status"] == "skip":
            self.skipTest(report["reason"])
        self.assertEqual(report["status"], "pass", report)

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


if __name__ == "__main__":
    unittest.main()
