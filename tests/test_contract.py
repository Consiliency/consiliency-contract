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
    # RFC 8785 for the vectors' value space (ASCII keys, integers only).
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


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
# v2 is authored in this repository, alongside the frozen v1. Its vectors add a
# third role, schema_negative: refused by JSON Schema (envelope_schema_invalid)
# with the exact failing (instance_path, keyword) pairs. The helpers below are a
# test-local reading of the v2 schema and its x-semantic-rules, used only to prove
# that every vector is internally consistent (each control is admitted, each
# negative is refused with exactly its expected diagnostics in the staged order).
# They are not part of the package API and not a conforming harness.

_SR2_TREE_KINDS = {"file", "executable_file", "symlink"}


def _sr2_sha(data: object) -> str:
    raw = data.encode("utf-8") if isinstance(data, str) else data
    return hashlib.sha256(raw).hexdigest()  # type: ignore[arg-type]


def _sr2_jcs_sha(value: object) -> str:
    return _sr2_sha(_sr_jcs(value))


def _sr2_errors(schema: dict, value: object, root: dict, path: str = "") -> set[tuple[str, str]]:
    # JSON Schema errors as (instance_path, keyword). A type failure masks the node's other keywords;
    # anyOf / oneOf report themselves, not their branches.
    errors: set[tuple[str, str]] = set()
    if "$ref" in schema:
        errors |= _sr2_errors(_sr_resolve(root, schema["$ref"]), value, root, path)
    if "type" in schema:
        names = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
        if not any(_sr_type_ok(name, value) for name in names):
            errors.add((path, "type"))
            return errors
    if "const" in schema and not _sr_same(value, schema["const"]):
        errors.add((path, "const"))
    if "enum" in schema and not any(_sr_same(value, entry) for entry in schema["enum"]):
        errors.add((path, "enum"))
    if "anyOf" in schema and not any(not _sr2_errors(sub, value, root, path) for sub in schema["anyOf"]):
        errors.add((path, "anyOf"))
    if "oneOf" in schema and sum(not _sr2_errors(sub, value, root, path) for sub in schema["oneOf"]) != 1:
        errors.add((path, "oneOf"))
    if isinstance(value, str):
        if len(value) < schema.get("minLength", 0):
            errors.add((path, "minLength"))
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            errors.add((path, "maxLength"))
        if "pattern" in schema and not re.search(schema["pattern"], value):
            errors.add((path, "pattern"))
    if isinstance(value, int) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            errors.add((path, "minimum"))
        if "maximum" in schema and value > schema["maximum"]:
            errors.add((path, "maximum"))
    if isinstance(value, list):
        if len(value) < schema.get("minItems", 0):
            errors.add((path, "minItems"))
        if schema.get("uniqueItems") and len({_sr_jcs(item) for item in value}) != len(value):
            errors.add((path, "uniqueItems"))
        if "items" in schema:
            for index, item in enumerate(value):
                errors |= _sr2_errors(schema["items"], item, root, f"{path}/{index}")
    if isinstance(value, dict):
        props = schema.get("properties", {})
        if any(key not in value for key in schema.get("required", [])):
            errors.add((path, "required"))
        if len(value) < schema.get("minProperties", 0):
            errors.add((path, "minProperties"))
        if schema.get("additionalProperties") is False and any(key not in props for key in value):
            errors.add((path, "additionalProperties"))
        for key, entry in value.items():
            if key in props:
                errors |= _sr2_errors(props[key], entry, root, f"{path}/{key}")
    return errors


def _sr2_tree_sha(entries: list) -> str:
    return _sr2_jcs_sha(sorted(entries, key=lambda entry: entry[0].encode("utf-8")))


def _sr2_bad_locator(locator: str) -> bool:
    return locator == "" or locator.startswith("/") or "\\" in locator or ".." in locator.split("/")


def _sr2_raw_strings(node: object) -> bool:
    if isinstance(node, str):
        return len(node) > 512 or any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in node)
    if isinstance(node, list):
        return any(_sr2_raw_strings(item) for item in node)
    if isinstance(node, dict):
        return any(_sr2_raw_strings(item) for item in node.values())
    return False


def _sr2_route_key(record: dict) -> tuple:
    chain = tuple((entry["locator_kind"], entry["locator"], entry["sha256"]) for entry in record["executable_chain"])
    return (record["tier"], record["action"], record["transport_id"], chain, record["template_sha256"], record["qualification_sha256"])


def _sr2_evaluate(schema: dict, value: dict, *, staged: bool = True) -> tuple[list[str], dict]:
    """Diagnostics of the first reporting stage of x-evaluation-order, and the admission effect."""
    env = value["envelope"]
    order = schema["x-evaluation-order"]["stages"]
    if _sr2_errors(schema, env, schema, "/envelope"):
        return ["envelope_schema_invalid"], {"attempt": {"state": "refused", "worker_invocations": 0, "refusal": {"reason": "envelope_schema_invalid"}}}
    ctx, mat, launch = value["validator_context"], value["launch_material"], env["launch"]
    tier = env["enforcement"]["tier"]
    tiers = schema["x-enforcement-tiers"]
    constraint: list[str] = []
    record_box: list[dict] = []

    def digest() -> set[str]:
        body = {key: item for key, item in env.items() if key != "envelope_digest"}
        return {"envelope_digest_mismatch"} if _sr2_jcs_sha(body) != env["envelope_digest"] else set()

    def authority() -> set[str]:
        if env["assignment_digest"] != ctx["expected_assignment_digest"] or env["units"]["crosswalk_ref"] != ctx["expected_crosswalk_ref"]:
            return {"authority_foreign"}
        return {"authority_baseline_stale"} if env["units"]["snapshot_ref"] != ctx["expected_snapshot_ref"] else set()

    def shape() -> set[str]:
        out = set()
        state = launch["workspace_state"]
        locators = list(env["workspace"]["repo_relative_locators"])
        locators += [launch["instructions"]["locator"]] if launch["instructions"]["locator"] is not None else []
        locators += [ref["locator"] for ref in launch["references"]]
        locators += [entry["locator"] for entry in launch["executable_chain"] if entry["locator_kind"] == "repo_relative"]
        locators += [loc for pair in state["target_map"] for loc in (pair["workspace_locator"], pair["protected_locator"])]
        locators += [state["cwd"]] if state["cwd"] != "." else []
        if any(_sr2_bad_locator(loc) for loc in locators):
            out.add("locator_not_repo_relative")
        if _sr2_raw_strings({key: item for key, item in env.items() if key != "caller_context"}):
            out.add("raw_output_in_record")
        deps = env["executable_dependencies"]
        if deps["declared"] and deps["admitted_dependency_digest"] is None:
            out.add("dependency_digest_required")
        if env["workspace"]["kind"] in ("separate_clone", "git_worktree_of_protected") and state["base_commit"] is None:
            out.add("workspace_source_inconsistent")
        chain = launch["executable_chain"]
        identifier = schema["$defs"]["identifier"]["pattern"]
        if (
            chain[-1]["role"] != "executable"
            or any(entry["role"] != "wrapper" for entry in chain[:-1])
            or any(entry["locator_kind"] == "declared" and not re.search(identifier, entry["locator"]) for entry in chain)
        ):
            out.add("executable_chain_invalid")
        if sum(ref["role"] == "baseline" for ref in launch["references"]) != 1:
            out.add("baseline_reference_required")
        scope = env["workspace"]["repo_relative_locators"]
        if any(not any(p["protected_locator"] == s or p["protected_locator"].startswith(s + "/") for s in scope) for p in state["target_map"]):
            out.add("target_map_outside_scope")
        return out

    def tier_stage() -> set[str]:
        return {"tier_unqualified"} if tiers[tier]["status"] == "reserved" else set()

    def route() -> set[str]:
        if launch["trusted_policy"]["qualification_sha256"] is None:
            return {"route_not_qualified"}
        key = _sr2_route_key({
            "tier": tier, "action": launch["action"], "transport_id": launch["transport_id"],
            "executable_chain": launch["executable_chain"],
            "template_sha256": launch["trusted_policy"]["template_sha256"],
            "qualification_sha256": launch["trusted_policy"]["qualification_sha256"],
        })
        matches = [record for record in ctx["qualified_routes"] if _sr2_route_key(record) == key]
        record_box[:] = matches[:1]
        return set() if matches else {"route_not_qualified"}

    def capability() -> set[str]:
        out = set()
        info = tiers[tier]
        unsupported = [c for c in env["enforcement"]["required_constraints"] if info["constraints"][c] == "not_enforced"]
        if unsupported:
            out.add("constraint_unsupported")
            constraint.append(unsupported[0])
        if env["workspace"]["kind"] not in info["workspace_kinds"]:
            out.add("workspace_not_separate_copy")
        covered = record_box[0]["grants"] if record_box else {}
        grants = launch.get("grants", {})
        if any(kind not in info["grant_kinds"] or covered.get(kind) != sha for kind, sha in grants.items()):
            out.add("grant_unqualified")
        if "dependency_projection_sha256" in grants and not env["executable_dependencies"]["declared"]:
            out.add("grant_unqualified")
        if launch["action"] == "execution" and launch["stop"]["deadline_action"] == "not_armed":
            out.add("stop_policy_unbounded")
        if launch["stop"]["timeout_seconds"] > ctx["timeout_max_seconds"]:
            out.add("timeout_over_declared_max")
        return out

    def material() -> set[str]:
        out = set()
        instr = launch["instructions"]
        if _sr2_sha(mat["instructions"]) != instr["sha256"] or len(mat["instructions"].encode("utf-8")) != instr["byte_length"]:
            out.add("launch_instructions_mismatch")
        if launch["stdin"] == "input" and mat["stdin"] != mat["instructions"]:
            out.add("launch_instructions_mismatch")
        bound_refs = [(r["locator"], r["sha256"], r["byte_length"]) for r in launch["references"]]
        used_refs = [(r["locator"], _sr2_sha(r["content"]), len(r["content"].encode("utf-8"))) for r in mat["references"]]
        if bound_refs != used_refs:
            out.add("launch_reference_mismatch")
        if _sr2_jcs_sha(mat["argv"]) != launch["argv"]["sha256"] or len(mat["argv"]) != launch["argv"]["element_count"]:
            out.add("launch_argv_mismatch")
        fields = ("role", "locator_kind", "locator", "sha256")
        if [tuple(e[f] for f in fields) for e in launch["executable_chain"]] != [tuple(e[f] for f in fields) for e in mat["executable_chain"]]:
            out.add("launch_executable_mismatch")
        state, used = launch["workspace_state"], mat["workspace"]
        if (
            used["base_commit"] != state["base_commit"] or used["cwd"] != state["cwd"]
            or used["target_map"] != state["target_map"] or _sr2_tree_sha(used["entries"]) != state["content_sha256"]
        ):
            out.add("launch_workspace_mismatch")
        environment = launch["environment"]
        if (
            _sr2_jcs_sha(mat["environment"]["map"]) != environment["map_sha256"]
            or mat["environment"]["policy_id"] != environment["policy"]["id"]
            or _sr2_sha(mat["environment"]["policy"]) != environment["policy"]["sha256"]
        ):
            out.add("launch_environment_mismatch")
        policy, trusted = mat["policy"], launch["trusted_policy"]
        qualification = None if policy["qualification"] is None else _sr2_sha(policy["qualification"])
        if (
            _sr2_sha(policy["config"]) != trusted["config_sha256"] or _sr2_sha(policy["template"]) != trusted["template_sha256"]
            or qualification != trusted["qualification_sha256"]
            or {kind: _sr2_sha(text) for kind, text in policy["grants"].items()} != launch.get("grants", {})
        ):
            out.add("launch_policy_mismatch")
        stop = launch["stop"]
        armed = stop["timeout_seconds"] if stop["deadline_action"] == "terminate_process_group" else None
        if mat["deadline_seconds"] != armed:
            out.add("launch_timeout_mismatch")
        if (
            (launch["stdin"] == "devnull" and mat["stdin"] is not None) or mat["unbound_inputs"]
            or any("\x00" in arg for arg in mat["argv"]) or any(entry[1] not in _SR2_TREE_KINDS for entry in used["entries"])
        ):
            out.add("launch_input_unbound")
        return out

    reported: set[str] = set()
    for stage in (digest, authority, shape, tier_stage, route, capability, material):
        reported |= stage()
        if reported and staged:
            break
    flat = [code for group in order for code in group]
    codes = sorted(reported, key=flat.index)
    if not codes:
        return [], {"attempt": {"state": "queued", "worker_invocations": 0}}
    refusal = {"reason": codes[0], "constraint": constraint[0] if codes[0] == "constraint_unsupported" else None, "tier": tier}
    return codes, {"attempt": {"state": "refused", "worker_invocations": 0, "refusal": refusal}}


def _sr2_subset(expected: object, actual: object) -> bool:
    if isinstance(expected, dict):
        return isinstance(actual, dict) and all(k in actual and _sr2_subset(v, actual[k]) for k, v in expected.items())
    return _sr_same(expected, actual)


def _sr2_leaves(schema: dict, node: dict, prefix: str) -> set[str]:
    if "$ref" in node:
        node = _sr_resolve(schema, node["$ref"])
    if "properties" in node:
        out = set()
        for key, sub in node["properties"].items():
            out |= _sr2_leaves(schema, sub, f"{prefix}/{key}")
        return out
    if "items" in node:
        return _sr2_leaves(schema, node["items"], f"{prefix}/*")
    return {prefix}


class SupervisedRunEnvelopeV2Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schema = load_schema("admitted_launch_envelope_v2")
        cls.v1_schema = load_schema("admitted_launch_envelope")
        cls.vectors = json.loads(Path(CONTRACT["supervised_run"]["vectors"]["admitted_launch_envelope_v2"]).read_text(encoding="utf-8"))
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

    def stages(self) -> list[str]:
        return [code for stage in self.schema["x-evaluation-order"]["stages"] for code in stage]

    def test_registered_alongside_frozen_v1(self) -> None:
        self.assertEqual(self.schema["$id"], "urn:contract:admitted_launch_envelope.v2")
        self.assertEqual(self.schema["properties"]["schema"]["const"], "admitted_launch_envelope.v2")
        self.assertEqual(CONTRACT["schemas"]["admitted_launch_envelope_v2"], "core/supervised-run/admitted-launch-envelope.v2.schema.json")
        self.assertEqual(self.vectors["contract"], "admitted_launch_envelope.v2")
        self.assertEqual(self.vectors["status"], "provisional")
        # v2 keeps every v1 field, closed, and every v1 rule; launch is the only new top-level field.
        self.assertEqual(set(self.schema["required"]) - set(self.v1_schema["required"]), {"launch"})
        self.assertEqual(set(self.v1_schema["x-semantic-rules"]) - set(self.schema["x-semantic-rules"]), set())
        for key in self.v1_schema["properties"]:
            if key not in ("schema", "enforcement", "envelope_digest", "caller_context", "workspace"):
                self.assertEqual(self.schema["properties"][key], self.v1_schema["properties"][key], key)
        self.assertEqual(self.schema["properties"]["enforcement"]["properties"]["tier"], self.v1_schema["properties"]["enforcement"]["properties"]["tier"])
        self.assertIs(self.schema["properties"]["launch"]["additionalProperties"], False)
        self.assertNotIn("caller_context", json.dumps(self.schema["properties"]["launch"]))

    def test_semantic_rules_and_evaluation_order_agree(self) -> None:
        flat = self.stages()
        self.assertEqual(len(flat), len(set(flat)))
        self.assertEqual(set(flat) | {"caller_context_interpreted", "refusal_zero_invocations"}, set(self.schema["x-semantic-rules"]))

    def test_tiers_describe_semantics_not_qualification(self) -> None:
        tiers = self.schema["x-enforcement-tiers"]
        self.assertEqual(sorted(tiers), sorted(self.schema["properties"]["enforcement"]["properties"]["tier"]["enum"]))
        constraints = self.schema["properties"]["enforcement"]["properties"]["required_constraints"]["items"]["enum"]
        grants = sorted(self.schema["properties"]["launch"]["properties"]["grants"]["properties"])
        kinds = self.schema["properties"]["workspace"]["properties"]["kind"]["enum"]
        for name, info in tiers.items():
            self.assertNotIn("qualified", info, name)
            self.assertEqual(sorted(info["constraints"]), sorted(constraints), name)
            self.assertTrue(set(info["constraints"].values()) <= {"checked_before_apply", "not_enforced"}, name)
            self.assertTrue(set(info["grant_kinds"]) <= set(grants), name)
            self.assertTrue(set(info["workspace_kinds"]) <= set(kinds), name)
            self.assertTrue(info["semantics"] and info["limits"], name)
            expected = ("required", "defined") if info["status"] == "defined" else ("not_admissible", "reserved")
            self.assertEqual((info["qualification"], info["status"]), expected, name)
            self.assertEqual(info["constraints"]["write_prevention"], "not_enforced", name)
        self.assertEqual(tiers["os_enforced"]["status"], "reserved")
        self.assertEqual(sorted(self.schema["x-constraint-semantics"]), sorted(constraints))
        self.assertIn("unqualified means refused", self.schema["x-route-qualification"]["rule"])

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
            else:
                self.assertNotIn("envelope_schema_invalid", case["expected"], case["id"])
                self.assertNotIn("expected_schema_errors", case, case["id"])
        roles = [case["role"] for case, _ in self.cases]
        self.assertEqual((roles.count("control"), roles.count("negative"), roles.count("schema_negative")), (4, 61, 51))

    def test_schema_validity_and_exact_schema_errors(self) -> None:
        for case, value in self.cases:
            errors = _sr2_errors(self.schema, value["envelope"], self.schema, "/envelope")
            valid = _sr_valid(self.schema, value["envelope"], self.schema)
            self.assertEqual(valid, not errors, case["id"])  # two independent readings agree
            if case["role"] == "schema_negative":
                expected = {(e["instance_path"], e["keyword"]) for e in case["expected_schema_errors"]}
                self.assertEqual(errors, expected, case["id"])
            else:
                self.assertEqual(errors, set(), case["id"])

    def test_envelope_digest_self_verifies_unless_mismatch_is_expected(self) -> None:
        mismatches = []
        for case, value in self.cases:
            ok = _sr_envelope_digest(value["envelope"]) == value["envelope"]["envelope_digest"]
            self.assertEqual(ok, "envelope_digest_mismatch" not in case["expected"], case["id"])
            if not ok:
                mismatches.append(case["id"])
        self.assertEqual(mismatches, ["S2-digest-not-rehashed"])

    def test_every_vector_matches_the_staged_rules(self) -> None:
        for case, value in self.cases:
            if case["kind"] == "echo":
                echoed = _sr_jcs(value["echoed_caller_context"]) == _sr_jcs(value["envelope"]["caller_context"])
                self.assertEqual([] if echoed else ["caller_context_interpreted"], case["expected"], case["id"])
                continue
            codes, effect = _sr2_evaluate(self.schema, value)
            self.assertEqual(codes, case["expected"], case["id"])
            self.assertTrue(_sr2_subset(case["expected_effect"], effect), f"{case['id']}: {effect}")

    def test_staging_is_load_bearing(self) -> None:
        # Without the first-reporting-stage stop, refusals collect diagnostics from later stages.
        widened = []
        for case, value in self.cases:
            if case["kind"] == "admission" and case["role"] == "negative":
                if _sr2_evaluate(self.schema, value, staged=False)[0] != case["expected"]:
                    widened.append(case["id"])
        self.assertIn("S2-os-enforced", widened)
        self.assertIn("S2-chain-executable-not-last", widened)

    def test_controls_bind_their_launch_material(self) -> None:
        # Non-vacuity: the digests are of RFC 8785 forms; the control argv is not ASCII, so an
        # ASCII-escaping or whitespace serializer gives a different digest.
        control = next(value for case, value in self.cases if case["id"] == "E2-execution")
        argv = control["launch_material"]["argv"]
        self.assertTrue(any(ord(ch) > 127 for arg in argv for ch in arg))
        self.assertEqual(control["envelope"]["launch"]["argv"]["sha256"], _sr2_sha(_sr_jcs(argv)))
        self.assertNotEqual(_sr2_sha(json.dumps(argv, separators=(",", ":"))), _sr2_sha(_sr_jcs(argv)))
        entries = control["launch_material"]["workspace"]["entries"]
        self.assertEqual(control["envelope"]["launch"]["workspace_state"]["content_sha256"], _sr2_tree_sha(entries))

    def test_every_new_field_and_rule_has_a_positive_and_a_negative(self) -> None:
        launch = self.schema["properties"]["launch"]
        leaves = _sr2_leaves(self.schema, launch, "/envelope/launch")
        controls = [value for case, value in self.cases if case["role"] == "control"]
        touched = set()
        for case, _ in self.cases:
            for op in case.get("patch", []):
                touched.add(re.sub(r"/\d+(?=/|$)", "/*", op["path"]))
                if isinstance(op.get("value"), dict) and op["path"].startswith("/envelope/launch"):
                    touched |= {re.sub(r"/\d+(?=/|$)", "/*", op["path"]) + "/" + key for key in op["value"]}

        def present(value: object, parts: list[str]) -> bool:
            if not parts:
                return True
            if parts[0] == "*":
                return isinstance(value, list) and any(present(item, parts[1:]) for item in value)
            return isinstance(value, dict) and parts[0] in value and present(value[parts[0]], parts[1:])

        for leaf in sorted(leaves):
            parts = leaf.split("/")[2:]
            self.assertTrue(any(present(value["envelope"], parts) for value in controls), f"no positive: {leaf}")
            self.assertTrue(any(path == leaf or path.startswith(leaf + "/") for path in touched), f"no negative: {leaf}")
        self.assertIn("/envelope/launch", touched)  # missing launch
        values = [op.get("value") for case, _ in self.cases for op in case.get("patch", [])]
        self.assertIn("write_prevention", values)
        negatives = {code for case, _ in self.cases for code in case["expected"]}
        self.assertEqual(negatives, set(self.schema["x-semantic-rules"]) - {"refusal_zero_invocations"})
        self.assertEqual(len(controls), 4)

    def test_v1_and_v2_envelopes_do_not_cross_validate(self) -> None:
        v1_vectors = json.loads(Path(CONTRACT["supervised_run"]["vectors"]["admitted_launch_envelope"]).read_text(encoding="utf-8"))
        v1_envelope = next(case for case in v1_vectors["cases"] if case["id"] == "E-admitted")["input"]["envelope"]
        v2_envelope = next(value for case, value in self.cases if case["id"] == "E2-execution")["envelope"]
        self.assertTrue(_sr_valid(self.v1_schema, v1_envelope, self.v1_schema))
        self.assertEqual(_sr2_errors(self.schema, v1_envelope, self.schema, "/envelope"), {("/envelope", "required"), ("/envelope/schema", "const")})
        self.assertFalse(_sr_valid(self.v1_schema, v2_envelope, self.v1_schema))


if __name__ == "__main__":
    unittest.main()
