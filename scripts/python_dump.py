from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from consiliency_contract import (
    CONTRACT,
    CONTRACT_VERSION,
    list_vectors,
    load_registry,
    load_schema,
    load_vector,
)


def canonical(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


payload = {
    "contract_version": CONTRACT_VERSION,
    "contract": CONTRACT,
    "schemas": {name: load_schema(name) for name in sorted(CONTRACT["schemas"])},
    "registries": {name: load_registry(name) for name in sorted(CONTRACT["registries"])},
    "vectors": {name: load_vector(name) for name in list_vectors()},
    "decisions": {name: load_vector(name)["decision"] for name in list_vectors()},
}

print(canonical(payload))
