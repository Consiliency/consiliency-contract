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
  assert.equal(CONTRACT_VERSION, "0.4.2");
  assert.equal(loadContract().contract_version, "0.4.2");
  assert.equal(CONTRACT.contract_id, "consiliency.contract.v1");
  assert.equal(loadRegistry("archetypes").archetypes.length, 7);
  assert.equal(loadSchema("manifest").properties.schema.const, "consiliency.manifest.v1");
  assert.ok(listVectors().length >= 10);
  assert.equal(loadVector("canonical-html-contract-loaded").decision.status, "accepted");
});

test("package metadata, runtime, and TypeScript declarations agree on version", () => {
  const packageJson = JSON.parse(readFileSync("package.json", "utf8"));
  const declarations = readFileSync("src/index.d.ts", "utf8");
  assert.equal(packageJson.version, CONTRACT_VERSION);
  assert.equal(loadContract().contract_version, CONTRACT_VERSION);
  assert.ok(declarations.includes(`CONTRACT_VERSION: "${CONTRACT_VERSION}"`));
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
        // v0.4.1 exemption: the projections-index vector legitimately exercises a
        // proj-S-certified entry whose maturity_label comes from the CERTIFICATE path
        // (post-XG-1 slice 1 — certified evidence is real for proj-S). The guard
        // still bars every other accepted vector from smuggling certified claims.
        if (value.id !== "projections-index-pure-merge-deterministic") {
          assert.doesNotMatch(JSON.stringify(value.input), /"certified"/, file);
        } else {
          const certifiedCarriers = (value.input.manifests ?? []).filter((m) =>
            JSON.stringify(m).includes('"certified"'));
          for (const m of certifiedCarriers) {
            assert.equal(m.kind, "proj-S-certified", `${file}: certified claim outside the certified kind`);
          }
        }
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

// --- Slice C0: projection-discovery + git-discipline contracts ---

// Convert a pipeline-ref-classes pattern ({seg} -> one path segment, * -> rest)
// into an anchored regex, so ref classification is computed, not asserted.
function refPatternToRegex(pattern) {
  const SEG = "SEGPLACEHOLDERXX";
  const STAR = "STARPLACEHOLDERXX";
  const tokenized = pattern.replace(/\{[^}]+\}/g, SEG).replace(/\*/g, STAR);
  const escaped = tokenized.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const body = escaped.split(SEG).join("[^/]+").split(STAR).join(".*");
  return new RegExp(`^${body}$`);
}

function refOwner(name, registry) {
  for (const cls of registry.ref_classes) {
    if (cls.owner === "pipeline" && refPatternToRegex(cls.pattern).test(name)) return "pipeline";
  }
  return registry.default_owner;
}

test("git-discipline protocol pins the never-delete-human-refs invariant as a schema-level rule", () => {
  const p = loadSchema("git_discipline_protocol").properties;
  assert.equal(p.schema.const, "consiliency.git_discipline_protocol.v1");
  assert.equal(p.contract_version.const, CONTRACT_VERSION);
  assert.equal(p.invariants.properties.never_delete_human_refs.const, true);
  assert.equal(p.invariants.properties.self_heal_scope.const, "leased-pipeline-owned-refs-only");
  assert.equal(p.self_heal.properties.scope.const, "leased-pipeline-owned-refs-only");
  assert.equal(p.self_heal.properties.auto_fix.const, "idempotent-safe-only");
  assert.equal(p.self_heal.properties.default_severity.const, "warn");
  assert.equal(p.self_heal.properties.finding_human_required.const, false);
  assert.equal(p.ref_class_registry.const, "pipeline-ref-classes");
  const reg = loadRegistry("pipeline_ref_classes");
  assert.equal(reg.default_owner, "human");
  assert.equal(reg.invariants.never_delete_human_refs, true);
  assert.equal(reg.human_default.deletable_by_self_heal, false);
});

test("never-delete-human-refs vector: no human ref is self-heal-deletable; deletables are leased pipeline refs", () => {
  const reg = loadRegistry("pipeline_ref_classes");
  const { input, expected } = loadVector("git-discipline-never-delete-human-refs");
  const refs = input.refs;
  const leasedByName = new Map(refs.map((r) => [r.name, r.leased]));
  const computedHuman = refs.filter((r) => refOwner(r.name, reg) === "human").map((r) => r.name);

  // The invariant, computed from the registry — not read from the fixture's labels.
  assert.deepEqual(computedHuman.slice().sort(), expected.human_refs.slice().sort());
  assert.deepEqual(computedHuman.slice().sort(), expected.never_deleted_human_refs.slice().sort());
  for (const name of computedHuman) {
    assert.ok(!expected.deletable_by_self_heal.includes(name), `${name}: human ref must never be self-heal-deletable`);
    assert.ok(expected.protected.includes(name), `${name}: human ref must be protected`);
  }
  // Every self-heal-deletable ref is a LEASED, pipeline-owned ref whose matched
  // class is itself deletable (a non-deletable pipeline class — e.g. the working
  // branch — must never appear in the deletable set even when leased).
  const matchedClass = (name) =>
    reg.ref_classes.find((cls) => refPatternToRegex(cls.pattern).test(name)) ?? reg.human_default;
  for (const name of expected.deletable_by_self_heal) {
    assert.equal(refOwner(name, reg), "pipeline", `${name}: only pipeline refs are deletable`);
    assert.equal(leasedByName.get(name), true, `${name}: only leased refs are deletable`);
    assert.equal(matchedClass(name).deletable_by_self_heal, true, `${name}: matched class must be deletable`);
  }
  // deletable and protected partition every ref, disjointly.
  const all = refs.map((r) => r.name).sort();
  const union = [...expected.deletable_by_self_heal, ...expected.protected].sort();
  assert.deepEqual(union, all, "deletable + protected must cover every ref");
  assert.equal(new Set(union).size, union.length, "deletable and protected must be disjoint");
});

// Reference pure-merge: field-copy manifests (+ sidecar refresh fields),
// deterministically sorted by (repo, kind, predicate), with no generated_at.
function buildProjectionsIndex(input) {
  const sidecar = new Map((input.refresh_sidecars ?? []).map((s) => [s.manifest_path, s]));
  const entries = input.manifests.map((m) => {
    const e = {
      repo: m.target,
      kind: m.kind,
      predicate: m.predicate,
      body_path: m.output_path,
      body_content_type: m.body_content_type,
      manifest_path: m.manifest_path,
      body_digest: m.body_digest,
      body_digest_domain: m.body_digest_domain,
      maturity_label: m.maturity_label,
      gate_state: m.gate_verdict.state,
    };
    if (m.kind === "proj-S-certified") {
      // v0.4.1: certified pins the desired-state graph S, not a code commit.
      e.source_S_digest = m.source_S_digest;
      if (m.display_route != null) e.display_route = m.display_route;
    } else {
      e.facts_path = m.facts_path;
      e.facts_digest = m.facts_digest;
      e.pinned_commit = m.code_head_sha;
    }
    const s = sidecar.get(m.manifest_path);
    if (s) {
      for (const k of ["refresh_status", "refresh_failure_class", "attempted_code_head_sha"]) {
        if (k in s) e[k] = s[k];
      }
    }
    return e;
  });
  const key = (e) => `${e.repo} ${e.kind} ${e.predicate}`;
  entries.sort((a, b) => (key(a) < key(b) ? -1 : key(a) > key(b) ? 1 : 0));
  return { schema: "projections.index.v1", entries };
}

test("projections index is a deterministic pure merge of the manifests (§12.3 fixture)", () => {
  const { input, expected } = loadVector("projections-index-pure-merge-deterministic");
  const built = buildProjectionsIndex(input);
  assert.equal(canonical(built), canonical(expected.index), "merge must reproduce expected.index byte-for-byte");
  // Determinism: re-running the merge yields identical bytes.
  assert.equal(canonical(buildProjectionsIndex(input)), canonical(built));
  // No timestamp field anywhere — the property that makes --check stable.
  assert.doesNotMatch(canonical(expected.index), /generated_at/);
});

test("projections index entry has per-kind conditional requireds with two-sided maturity caps", () => {
  const entry = loadSchema("projections_index_v1").$defs.entry;
  // The code-shaped pins are NOT unconditional entry requirements (a certified
  // entry has none of them).
  for (const f of ["pinned_commit", "facts_path", "facts_digest", "source_S_digest"]) {
    assert.ok(!entry.required.includes(f), `${f} must not be an unconditional entry requirement`);
  }
  const codeBlock = entry.allOf.find((b) => (b.if.properties.kind.enum ?? []).includes("proj-code-sbom"));
  const certBlock = entry.allOf.find((b) => b.if.properties.kind.const === "proj-S-certified");
  assert.ok(codeBlock && certBlock, "both per-kind conditional blocks must exist");
  // proj-code: pins a commit + facts; maturity capped TWO-SIDED at
  // [presence-only, hash-checked] — never realized-edge-observed or certified.
  assert.deepEqual(codeBlock.then.required.slice().sort(), ["facts_digest", "facts_path", "pinned_commit"]);
  assert.deepEqual(codeBlock.then.properties.maturity_label.enum, ["presence-only", "hash-checked"]);
  // certified: pins a graph S; maturity is [realized-edge-observed, certified]
  // (floor-revert semantics), and certified is permitted ONLY here.
  assert.ok(certBlock.then.required.includes("source_S_digest"));
  assert.deepEqual(certBlock.then.properties.maturity_label.enum, ["realized-edge-observed", "certified"]);
});
