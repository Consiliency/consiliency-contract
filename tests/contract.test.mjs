import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";

import {
  CONTRACT,
  CONTRACT_VERSION,
  listVectors,
  loadContract,
  loadRegistry,
  loadSchema,
  loadVector,
} from "../src/index.js";

function canonical(value) {
  if (Array.isArray(value)) {
    return `[${value.map(canonical).join(",")}]`;
  }
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function walk(value, visitor, path = []) {
  visitor(value, path);
  if (Array.isArray(value)) {
    value.forEach((entry, index) => walk(entry, visitor, [...path, String(index)]));
  } else if (value && typeof value === "object") {
    Object.entries(value).forEach(([key, entry]) => walk(entry, visitor, [...path, key]));
  }
}

function jsonFiles(root) {
  const results = [];
  for (const entry of readdirSync(root, { withFileTypes: true })) {
    const path = join(root, entry.name);
    if (entry.isDirectory()) {
      results.push(...jsonFiles(path));
    } else if (entry.isFile() && entry.name.endsWith(".json")) {
      results.push(path);
    }
  }
  return results;
}

test("loads contract, registries, schemas, and vectors", () => {
  assert.equal(CONTRACT_VERSION, "0.1.0");
  assert.equal(loadContract().contract_version, "0.1.0");
  assert.equal(CONTRACT.contract_id, "consiliency.contract.v1");
  assert.equal(loadRegistry("archetypes").archetypes.length, 7);
  assert.equal(loadSchema("manifest").properties.schema.const, "consiliency.manifest.v1");
  assert.ok(listVectors().length >= 10);
  assert.equal(loadVector("canonical-html-contract-loaded").decision.status, "accepted");
});

test("dynamic loaders reject unknown names and traversal", () => {
  assert.throws(() => loadVector("../../package"), /Unknown vector/);
  assert.throws(() => loadSchema("../../package"), /Unknown schema/);
  assert.throws(() => loadRegistry("../../package"), /Unknown registry/);
});

test("required-document registries have unique ids per composed segment", () => {
  const required = loadRegistry("required_documents");
  const segments = [
    ["baseline", required.baseline],
    ...Object.entries(required.archetypes).map(([name, rows]) => [`archetype:${name}`, rows]),
    ...Object.entries(required.modifiers).map(([name, rows]) => [`modifier:${name}`, rows]),
  ];
  for (const [segment, rows] of segments) {
    const ids = rows.map((row) => row.id);
    assert.equal(new Set(ids).size, ids.length, segment);
  }
});

test("canonical_html contract matches recorded provenance", () => {
  const provenance = JSON.parse(readFileSync("core/canonical-html/provenance.json", "utf8"));
  const bytes = readFileSync(provenance.packaged.path);
  const digest = createHash("sha256").update(bytes).digest("hex");
  assert.equal(digest, provenance.packaged.sha256);
  assert.equal(digest, provenance.source.sha256);
});

test("decisions are canonical and Phase-0 safe", () => {
  for (const vectorName of listVectors()) {
    const vector = loadVector(vectorName);
    assert.equal(vector.decision.schema, "consiliency.conformance_decision.v1", vectorName);
    assert.notEqual(vector.decision.maturity, "certified", vectorName);
    assert.equal(canonical(JSON.parse(canonical(vector.decision))), canonical(vector.decision), vectorName);
  }
});

test("package data avoids host absolute paths and accepted certified claims", () => {
  const files = ["core", "conformance"].flatMap(jsonFiles);
  for (const file of files) {
    const value = JSON.parse(readFileSync(file, "utf8"));
    walk(value, (entry, path) => {
      if (typeof entry !== "string") return;
      assert.doesNotMatch(entry, /^\/home\//, `${file}:${path.join(".")}`);
      assert.doesNotMatch(entry, /^[A-Za-z]:[\\/]/, `${file}:${path.join(".")}`);
    });
    if (file.includes("conformance/vectors/")) {
      if (value.decision?.status === "accepted") {
        assert.doesNotMatch(JSON.stringify(value.input), /"certified"/, file);
      }
    }
  }
});

test("Python reader produces byte-identical canonical payload", () => {
  const py = execFileSync("python3", ["scripts/python_dump.py"], { encoding: "utf8" }).trim();
  const jsPayload = {
    contract_version: CONTRACT_VERSION,
    contract: CONTRACT,
    schemas: Object.fromEntries(Object.keys(CONTRACT.schemas).sort().map((name) => [name, loadSchema(name)])),
    registries: Object.fromEntries(Object.keys(CONTRACT.registries).sort().map((name) => [name, loadRegistry(name)])),
    vectors: Object.fromEntries(listVectors().map((name) => [name, loadVector(name)])),
    decisions: Object.fromEntries(listVectors().map((name) => [name, loadVector(name).decision])),
  };
  assert.equal(py, canonical(jsPayload));
});
