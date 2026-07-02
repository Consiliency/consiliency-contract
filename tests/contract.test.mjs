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
  assert.equal(CONTRACT_VERSION, "0.2.0");
  assert.equal(loadContract().contract_version, "0.2.0");
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

test("governance labels used in decisions are registered governance labels", () => {
  const governance = new Set(
    loadRegistry("maturity_labels").labels
      .filter((label) => label.kind === "governance")
      .map((label) => label.id),
  );
  assert.ok(governance.size >= 3);
  for (const name of listVectors()) {
    const { decision } = loadVector(name);
    for (const label of decision.labels ?? []) {
      assert.ok(governance.has(label), `${name}: unknown governance label ${label}`);
    }
  }
});

test("coordination inbox messages never mutate lease state (sole-truth guardrail)", () => {
  let sawMessageVector = false;
  for (const name of listVectors()) {
    const vector = loadVector(name);
    if (vector.input.schema !== "consiliency.coordination_scenario.v1") continue;
    assert.ok(vector.expected, `${name}: coordination vector needs an expected view`);
    assert.equal(typeof vector.expected.changed_by_message, "boolean", name);
    if ((vector.input.messages ?? []).length > 0) {
      sawMessageVector = true;
      assert.equal(vector.expected.changed_by_message, false, `${name}: a message must not change lease state`);
    }
  }
  assert.ok(sawMessageVector, "expected at least one coordination vector carrying an inbox message");
});

test("coordination protocols pin the sole-truth guardrail", () => {
  const channel = loadSchema("coordination_channel_protocol").properties;
  assert.equal(channel.authority.properties.inbox_authoritative.const, false);
  assert.equal(channel.authority.properties.message_may_mutate_lease.const, false);
  assert.equal(channel.authority.properties.message_prompts_actor_to_call_store_op.const, true);
  assert.equal(channel.lease_state_projection.properties.formula.const, "current_lease = project(lease-store events, now)");
  assert.equal(channel.lease_state_projection.properties.inbox_included_in_projection.const, false);
  const store = loadSchema("lease_store_protocol").properties;
  assert.equal(store.source_of_truth.const, "lease-store");
  assert.equal(store.atomicity.properties.hard_requires_atomic_acquire.const, true);
  assert.equal(store.atomicity.properties.degrade_without_atomic_backend.const, "soft");
  assert.equal(store.granularity_ladder.properties.out_of_scope.const, "line");
  assert.equal(store.expiry.properties.expires_at_formula.const, "heartbeat_at + ttl_seconds");
  assert.equal(store.expiry.properties.boundary.const, "exclusive");
  assert.equal(store.operation_semantics.properties.renew.properties.holder_only.const, true);
  assert.equal(store.operation_semantics.properties.release.properties.holder_only.const, true);
});

// Reference projection: fold the lease-EVENT stream ONLY (coordination messages
// are structurally excluded), then apply heartbeat-anchored, exclusive-boundary
// TTL expiry at `now`. This makes the sole-truth guardrail a computed proof and
// validates each fixture's expiry math.
function projectLeaseView(input) {
  const mode = input.requested_mode === "hard" && input.atomic_backend === true ? "hard" : "soft";
  const parse = (iso) => Date.parse(iso) / 1000;
  let lease = null;
  for (const e of input.events ?? []) {
    if (e.event === "acquire") {
      lease = {
        schema: "consiliency.lease.v1",
        lease_id: e.lease_id,
        holder: e.holder,
        acquired_at: e.at,
        ttl_seconds: e.ttl_seconds,
        heartbeat_at: e.at,
        mode,
        scope: e.scope,
        phase: e.phase,
      };
    } else if (e.event === "renew") {
      if (lease && lease.lease_id === e.lease_id && lease.holder === e.holder) {
        lease = { ...lease, heartbeat_at: e.at };
      }
    } else if (e.event === "release" || e.event === "expire") {
      if (lease && lease.lease_id === e.lease_id) lease = null;
    }
  }
  if (lease && parse(input.now) >= parse(lease.heartbeat_at) + lease.ttl_seconds) {
    lease = null; // exclusive boundary: expired at now == expires_at
  }
  return { current_lease: lease, effective_mode: mode };
}

test("coordination current-lease view equals the events-only projection (messages excluded)", () => {
  let seen = 0;
  for (const name of listVectors()) {
    const vector = loadVector(name);
    if (vector.input.schema !== "consiliency.coordination_scenario.v1") continue;
    seen += 1;
    const projected = projectLeaseView(vector.input);
    assert.deepEqual(projected.current_lease, vector.expected.current_lease ?? null, `${name}: current_lease`);
    assert.equal(projected.effective_mode, vector.expected.effective_mode, `${name}: effective_mode`);
  }
  assert.ok(seen >= 8, "expected coordination vectors to project");
});

test("every additionalProperties:false object keeps required a subset of properties", () => {
  const check = (node, path) => {
    if (Array.isArray(node)) {
      node.forEach((entry, index) => check(entry, `${path}[${index}]`));
    } else if (node && typeof node === "object") {
      if (node.additionalProperties === false && Array.isArray(node.required)) {
        const props = new Set(Object.keys(node.properties ?? {}));
        for (const key of node.required) {
          assert.ok(props.has(key), `${path}: required '${key}' absent from properties`);
        }
      }
      for (const [key, value] of Object.entries(node)) check(value, `${path}.${key}`);
    }
  };
  for (const name of Object.keys(CONTRACT.schemas)) {
    check(loadSchema(name), name);
  }
});
