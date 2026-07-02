"""Thin Python reader for the Consiliency shared contract data."""

from __future__ import annotations

import json
from importlib import resources
from pathlib import Path
from typing import Any

CONTRACT_PACKAGE = "consiliency-contract"
CONTRACT_VERSION = "0.2.2"
__version__ = "0.2.2"


def _source_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _read_text(relative_path: str) -> str:
    source_path = _source_root() / relative_path
    if source_path.exists():
        return source_path.read_text(encoding="utf-8")
    data_path = resources.files(__package__).joinpath("_data", relative_path)
    return data_path.read_text(encoding="utf-8")


def _read_json(relative_path: str) -> dict[str, Any]:
    return json.loads(_read_text(relative_path))


def load_contract() -> dict[str, Any]:
    return _read_json("core/contract.json")


CONTRACT = load_contract()


def load_schema(name: str) -> dict[str, Any]:
    relative_path = CONTRACT["schemas"].get(name)
    if not relative_path:
        raise ValueError(f"Unknown schema: {name}")
    return _read_json(relative_path)


def load_registry(name: str) -> dict[str, Any]:
    relative_path = CONTRACT["registries"].get(name)
    if not relative_path:
        raise ValueError(f"Unknown registry: {name}")
    return _read_json(relative_path)


def list_vectors() -> list[str]:
    source_dir = _source_root() / CONTRACT["conformance"]["vector_root"]
    if source_dir.exists():
        return sorted(path.name for path in source_dir.glob("*.json"))
    data_dir = resources.files(__package__).joinpath("_data", CONTRACT["conformance"]["vector_root"])
    return sorted(path.name for path in data_dir.iterdir() if path.name.endswith(".json"))


def load_vector(name: str) -> dict[str, Any]:
    filename = name if name.endswith(".json") else f"{name}.json"
    if filename not in list_vectors():
        raise ValueError(f"Unknown vector: {name}")
    return _read_json(f"{CONTRACT['conformance']['vector_root']}/{filename}")
