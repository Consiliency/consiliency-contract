from __future__ import annotations

import hashlib
import json
import unittest
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


class ContractReaderTest(unittest.TestCase):
    def test_loads_contract_data(self) -> None:
        self.assertEqual(CONTRACT_VERSION, "0.1.0")
        self.assertEqual(load_contract()["contract_version"], "0.1.0")
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


if __name__ == "__main__":
    unittest.main()
