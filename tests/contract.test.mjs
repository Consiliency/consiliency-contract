import assert from "node:assert/strict";
import { createHash, createPublicKey, verify as cryptoVerify } from "node:crypto";
import { execFileSync, spawnSync } from "node:child_process";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";

import {
  CONTRACT,
  CONTRACT_VERSION,
  authoritySigningPreimage,
  canonicalCoreBytes,
  canonicalizeCore,
  listVectors,
  loadContract,
  loadRegistry,
  loadSchema,
  loadVector,
  verifyAuthorityEvent,
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
  assert.equal(CONTRACT_VERSION, "0.7.0");
  assert.equal(loadContract().contract_version, CONTRACT_VERSION);
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
  const certifiedTiers = new Set(loadRegistry("maturity_labels").phase0_disallowed);
  assert.deepEqual([...certifiedTiers].sort(), ["authority-certified", "certified", "parity-certified"]);
  for (const vectorName of listVectors()) {
    const vector = loadVector(vectorName);
    assert.equal(vector.decision.schema, "consiliency.conformance_decision.v1", vectorName);
    assert.ok(!certifiedTiers.has(vector.decision.maturity), vectorName);
    assert.equal(canonical(JSON.parse(canonical(vector.decision))), canonical(vector.decision), vectorName);
  }
});

test("package data avoids host absolute paths and accepted certified-tier claims outside proj-S-certified", () => {
  const files = ["core", "conformance"].flatMap(jsonFiles);
  // certified / parity-certified / authority-certified (CS-1.4) — real
  // evidence only for proj-S-certified (post-XG-1 slice 1 + the label
  // rescope). No accepted vector may smuggle a certified-tier claim onto
  // any other kind.
  const certifiedTierLabels = new Set(["certified", "parity-certified", "authority-certified"]);
  for (const file of files) {
    const value = JSON.parse(readFileSync(file, "utf8"));
    walk(value, (entry, path) => {
      if (typeof entry !== "string") return;
      assert.doesNotMatch(entry, /^\/home\//, `${file}:${path.join(".")}`);
      assert.doesNotMatch(entry, /^[A-Za-z]:[\\/]/, `${file}:${path.join(".")}`);
    });
    if (file.includes("conformance/vectors/") && value.decision?.status === "accepted") {
      const certifiedCarriers = (value.input.manifests ?? []).filter((m) =>
        certifiedTierLabels.has(m.maturity_label));
      for (const m of certifiedCarriers) {
        assert.equal(m.kind, "proj-S-certified", `${file}: certified-tier claim outside the certified kind`);
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
  // [presence-only, hash-checked] — never realized-edge-observed nor any
  // certified tier (certified, parity-certified, authority-certified; CS-1.4
  // keeps this cap unchanged).
  assert.deepEqual(codeBlock.then.required.slice().sort(), ["facts_digest", "facts_path", "pinned_commit"]);
  assert.deepEqual(codeBlock.then.properties.maturity_label.enum, ["presence-only", "hash-checked"]);
  // proj-S-certified: pins a graph S; maturity is [realized-edge-observed,
  // certified, parity-certified, authority-certified] (floor-revert
  // semantics). CS-1.4 splits the certified rung into two honest tiers
  // (parity-certified: byte parity only; authority-certified: + a verified
  // authority event), keeping the deprecated bare 'certified' id as an alias.
  // Any certified-tier value is permitted ONLY for this kind.
  assert.ok(certBlock.then.required.includes("source_S_digest"));
  assert.deepEqual(
    certBlock.then.properties.maturity_label.enum,
    ["realized-edge-observed", "certified", "parity-certified", "authority-certified"],
  );
});

test("certified label rescope (CS-1.4): parity-certified/authority-certified are new, certified is a deprecated alias of parity-certified only", () => {
  const labels = Object.fromEntries(loadRegistry("maturity_labels").labels.map((label) => [label.id, label]));
  for (const labelId of ["parity-certified", "authority-certified"]) {
    assert.ok(labels[labelId], `${labelId} must be registered`);
    assert.equal(labels[labelId].kind, "evidence");
    assert.ok(!labels[labelId].deprecated);
  }
  assert.ok(labels.certified.deprecated);
  assert.equal(labels.certified.deprecated_alias_of, "parity-certified");
});

// --- Slice X: the §12.3 interchangeability test ---

test("the real spec-render producer reproduces the vector byte-for-byte (skips without a sibling spec checkout)", (t) => {
  // conformance/interchangeability/run_driver_equivalence.py feeds this same
  // vector's manifests through the REAL build_projections_index.py (fetched
  // by content — see that script's docstring), not either reader's own
  // reference merger above. Honest scoping: skip, don't vacuously pass or
  // fail the suite, when no spec checkout is available.
  const script = join("scripts", "interchangeability", "run_driver_equivalence.py");
  const proc = spawnSync("python3", [script], { encoding: "utf8" });
  const report = JSON.parse(proc.stdout.trim());
  if (report.status === "skip") {
    t.skip(report.reason);
    return;
  }
  assert.equal(report.status, "pass", JSON.stringify(report));
  assert.ok(report.byte_identical_to_vector, JSON.stringify(report));
});

// --- Slice 1 (XG-1): the authority-event contract core (root of trust) ---

// Recursively key-sorted, whitespace-free JSON — the constrained JCS form the
// authority canonicalizer must equal on the metadata-safe ASCII / integer
// subset. If canonicalizeCore ever drifts from this, JS and Python signers
// stop agreeing.
function stableStringify(value) {
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((k) => `${JSON.stringify(k)}:${stableStringify(value[k])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function authorityVectorNames() {
  return listVectors().filter((name) => name.startsWith("authority-"));
}

// A compact JSON-Schema validator covering exactly the constructs the
// authority-event schema uses ($ref/$defs, const, enum, type, pattern,
// minLength, required, additionalProperties:false, properties). Enough to prove
// the shipped schema actually accepts the valid event and rejects the malformed
// forgeries — without adding an ajv dependency the repo doesn't carry.
function validateAgainst(schema, value, root) {
  if (schema.$ref) {
    const node = schema.$ref.replace(/^#\//, "").split("/").reduce((acc, key) => acc[key], root);
    return validateAgainst(node, value, root);
  }
  if ("const" in schema) return value === schema.const;
  if (schema.enum) return schema.enum.includes(value);
  if (schema.type === "string") {
    if (typeof value !== "string") return false;
    if (schema.minLength != null && value.length < schema.minLength) return false;
    if (schema.pattern && !new RegExp(schema.pattern, "u").test(value)) return false;
    return true;
  }
  if (schema.type === "object" || schema.properties) {
    if (!value || typeof value !== "object" || Array.isArray(value)) return false;
    const props = schema.properties || {};
    for (const req of schema.required || []) if (!(req in value)) return false;
    if (schema.additionalProperties === false) {
      for (const key of Object.keys(value)) if (!(key in props)) return false;
    }
    return Object.entries(value).every(([key, entry]) => !props[key] || validateAgainst(props[key], entry, root));
  }
  return true;
}

test("authority-event protocol schema pins the core/chain signing split", () => {
  const schema = loadSchema("authority_event_protocol");
  assert.equal(schema.properties.schema.const, "consiliency.authority_event_protocol.v1");
  // The signature covers exactly `core`; `chain` and `signature` sit OUTSIDE it.
  const core = schema.properties.core;
  assert.ok(!core.properties.chain, "chain must not live inside the signed core");
  assert.ok(!core.properties.signature, "signature must not live inside the signed core");
  for (const field of ["decision_id", "cert_digest", "key_id", "approver", "validity", "audience", "custody_binding"]) {
    assert.ok(core.required.includes(field), `signed core must require ${field}`);
  }
  assert.equal(core.properties.authority_event_version.const, "1");
  // phase_loop_driver_allowed is hard-pinned false (authority never minted by the driver).
  assert.equal(core.properties.custody_binding.properties.phase_loop_driver_allowed.const, false);
  // decision_id is the authority identity; phase/subgraph are SCOPED audience fields.
  assert.ok(!core.required.includes("phase"), "the phase is not the authority identity; decision_id is");
  for (const field of ["phase", "subgraph", "canon_version"]) {
    assert.ok(core.properties.audience.required.includes(field), `audience must scope ${field}`);
  }
  // ed25519-only signature; chain is optional (appended after signing).
  assert.equal(schema.properties.signature.properties.scheme.const, "ed25519");
  assert.deepEqual(schema.required.slice().sort(), ["core", "schema", "signature"]);
});

test("authority-key registry is the pinned Ed25519 root of trust", () => {
  const reg = loadRegistry("authority_key_registry");
  assert.equal(reg.schema, "consiliency.authority_key_registry.v1");
  assert.ok(reg.keys.length >= 3);
  for (const key of reg.keys) {
    assert.equal(key.scheme, "ed25519");
    assert.match(key.public_key, /^[0-9a-f]{64}$/); // 32-byte raw Ed25519 public key
    assert.equal(typeof key.approver, "string");
    assert.ok(key.validity.not_before && key.validity.not_after);
    assert.equal(typeof key.revoked, "boolean");
  }
  assert.ok(reg.keys.some((key) => key.revoked === true), "registry must model a revoked key");
  // No private/secret material may ever ship in the contract.
  assert.doesNotMatch(JSON.stringify(reg), /private_key|secret|seed/i);
});

test("authority vectors verify/reject exactly as the vector expects (JS reader)", () => {
  const reg = loadRegistry("authority_key_registry");
  const names = authorityVectorNames();
  assert.ok(names.length >= 12, "expected the full authority conformance vector set");
  let sawValid = false;
  let sawForged = false;
  for (const name of names) {
    const vector = loadVector(name);
    const { event, now, expected_cert_digest: expectedCertDigest } = vector.input;
    const res = verifyAuthorityEvent(event, reg, { now, expectedCertDigest });
    assert.equal(res.ok, vector.expected.verifies, `${name}: ok`);
    assert.equal(res.reason, vector.expected.reason, `${name}: reason`);
    // The conformance decision must agree with the crypto verdict.
    assert.equal(vector.decision.status, vector.expected.verifies ? "accepted" : "rejected", `${name}: decision`);
    if (vector.expected.verifies) sawValid = true;
    if (name.includes("forged")) sawForged = true;
  }
  assert.ok(sawValid, "at least one valid Ed25519-signed event must verify");
  assert.ok(sawForged, "the forged self-minted vector must be present");
});

test("the forged self-minted authority event REJECTS (the closed hole)", () => {
  const reg = loadRegistry("authority_key_registry");
  const vector = loadVector("authority-forged-self-minted");
  const { event, now, expected_cert_digest: expectedCertDigest } = vector.input;
  const res = verifyAuthorityEvent(event, reg, { now, expectedCertDigest });
  assert.equal(res.ok, false, "a self-minted event must never verify");
  assert.equal(res.reason, "unknown_key_id");
});

test("appending ledger chain data does NOT invalidate the core signature", () => {
  const reg = loadRegistry("authority_key_registry");
  const vector = loadVector("authority-valid");
  const opts = { now: vector.input.now, expectedCertDigest: vector.input.expected_cert_digest };
  assert.equal(verifyAuthorityEvent(vector.input.event, reg, opts).ok, true);
  const digest = "a".repeat(64);
  const chain = {
    entry_digest: digest,
    previous_entry_digest: "0".repeat(64),
    root_digest: "b".repeat(64),
    inclusion_proof: { entry_digest: digest, previous_entry_digest: "0".repeat(64), root_digest: "b".repeat(64) },
  };
  const withChain = { ...vector.input.event, chain };
  assert.equal(verifyAuthorityEvent(withChain, reg, opts).ok, true, "core signature must survive chain append");
});

test("authority canonicalizer equals the constrained JCS form (JS)", () => {
  for (const name of authorityVectorNames()) {
    const core = loadVector(name).input.event.core;
    assert.equal(canonicalizeCore(core), stableStringify(core), `${name}: canonicalizer must equal recursively-sorted JSON`);
  }
});

test("the authority signature covers the domain-prefixed preimage, not bare bytes", () => {
  // Domain separation (XG-4 decision): the signature covers
  // `spec-canon:v2:authority\n` ‖ canonical_bytes(core), NOT bare bytes. Proven
  // key-free: the valid vector's signature verifies over the preimage and FAILS
  // over the bare bytes.
  const reg = loadRegistry("authority_key_registry");
  const vector = loadVector("authority-valid");
  const core = vector.input.event.core;
  const key = reg.keys.find((k) => k.key_id === core.key_id);
  const der = Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(key.public_key, "hex")]);
  const pub = createPublicKey({ key: der, format: "der", type: "spki" });
  const sig = Buffer.from(vector.input.event.signature.signature, "hex");
  const preimage = authoritySigningPreimage(core);
  const bare = canonicalCoreBytes(core);
  assert.equal(cryptoVerify(null, preimage, pub, sig), true, "signature must verify over the prefixed preimage");
  assert.equal(cryptoVerify(null, bare, pub, sig), false, "signature must NOT verify over bare canonical bytes");
  // The preimage is exactly the authority-profile prefix ‖ canon-core v2 bytes.
  assert.equal(preimage.toString("latin1"), "spec-canon:v2:authority\n" + bare.toString("latin1"));
});

test("authority signed-core bytes are pinned byte-identical to canon-core v2", () => {
  // The signed bytes ARE canon-core v2 `canonical_bytes(core)`; our canonicalizer
  // is a metadata-safe/integer-only PORT of that one algorithm, not a 4th canon.
  // The pin is produced from spec's canon.py at generation time, so this is an
  // offline, committed proof of parity (see core/authority-canon/provenance.json).
  for (const name of authorityVectorNames()) {
    const vector = loadVector(name);
    assert.equal(
      canonicalCoreBytes(vector.input.event.core).toString("hex"),
      vector.input.canon_core_v2_bytes,
      `${vector.id}: signed-core bytes must equal the pinned canon-core v2 canonical_bytes`,
    );
  }
});

test("the canon-core v2 provenance pins the spec canon source", () => {
  const prov = JSON.parse(readFileSync("core/authority-canon/provenance.json", "utf8"));
  assert.equal(prov.schema, "consiliency.authority_canon_provenance.v1");
  assert.equal(prov.canon_version, "spec-canon:v2");
  assert.match(prov.normative_source.files["canon/py/canon.py"], /^[0-9a-f]{64}$/);
  assert.equal(prov.authority_profile.profile_id, "authority");
  assert.equal(prov.authority_profile.domain_prefix, "spec-canon:v2:authority\n");
  assert.match(prov.authority_profile.signed_preimage, /spec-canon:v2:authority/);
  assert.match(prov.authority_profile.domain_separation, /SETTLED/);
});

test("committed canon pins still match the CURRENT spec canon-core v2 (skips without spec)", (t) => {
  const proc = spawnSync("python3", ["scripts/authority_canon_parity.py"], { encoding: "utf8" });
  const report = JSON.parse(proc.stdout.trim());
  if (report.status === "skip") {
    t.skip(report.reason);
    return;
  }
  assert.equal(report.status, "pass", JSON.stringify(report));
});

test("authority canonical core bytes match the Python reference byte-for-byte", () => {
  const py = JSON.parse(execFileSync("python3", ["scripts/authority_canonical_dump.py"], { encoding: "utf8" }));
  for (const name of authorityVectorNames()) {
    const vector = loadVector(name);
    const jsHex = canonicalCoreBytes(vector.input.event.core).toString("hex");
    assert.equal(jsHex, py[vector.id], `${vector.id}: JS and Python canonical core bytes must be identical`);
  }
});

test("authority vectors conform (or not) to the shipped protocol schema as flagged", () => {
  const schema = loadSchema("authority_event_protocol");
  let sawValidConform = false;
  let sawInvalid = false;
  for (const name of authorityVectorNames()) {
    const vector = loadVector(name);
    const conforms = validateAgainst(schema, vector.input.event, schema);
    assert.equal(conforms, vector.expected.schema_valid, `${name}: schema conformance vs schema_valid flag`);
    if (vector.id === "authority-valid") sawValidConform = conforms;
    if (!vector.expected.schema_valid) sawInvalid = true;
  }
  assert.ok(sawValidConform, "the valid vector must conform to the shipped schema");
  assert.ok(sawInvalid, "at least one malformed vector must be rejected by the shipped schema");
});

test("the canonicalizer is fail-closed on ambiguous input", () => {
  assert.throws(() => canonicalizeCore({ n: 1.5 }), /non-integer/); // float forbidden
  assert.throws(() => canonicalizeCore({ s: "a b" }), /metadata-safe/); // space not metadata-safe
  assert.throws(() => canonicalizeCore({ s: "é" }), /metadata-safe/); // non-ASCII
  assert.throws(() => canonicalizeCore({ x: null }), /unsupported/); // null forbidden
});

// --- parity certificate schema distribution (0.6.4) ---

// A cross-file-aware validator: the parity certificate schema is distributed
// verbatim from spec, so it keeps its relative cross-file $ref into the
// result-state schema (`result-state.schema.json#/$defs/...`). Extend the
// authority-suite's #/-only resolver with one branch that resolves that
// external fragment against the loaded result_state schema — no ajv (which the
// repo deliberately omits), faithful to the shipped bytes.
// `currentRoot` is the schema DOCUMENT that bare `#/` refs resolve against; it
// starts as the certificate and switches to result_state when a cross-file ref
// is followed (so result-state's own internal `#/$defs` refs resolve correctly).
function validateWithRefs(schema, value, roots, currentRoot = roots.self) {
  if (schema.$ref) {
    let ref = schema.$ref;
    let root = currentRoot;
    if (ref.startsWith("result-state.schema.json#/")) {
      root = roots.result_state;
      ref = ref.slice("result-state.schema.json".length);
    }
    const node = ref.replace(/^#\//, "").split("/").reduce((acc, key) => acc[key], root);
    return validateWithRefs(node, value, roots, root);
  }
  if ("const" in schema) return value === schema.const;
  if (schema.enum) return schema.enum.includes(value);
  if (schema.type === "string") {
    if (typeof value !== "string") return false;
    if (schema.minLength != null && value.length < schema.minLength) return false;
    if (schema.pattern && !new RegExp(schema.pattern, "u").test(value)) return false;
    return true;
  }
  if (schema.type === "integer") {
    if (typeof value !== "number" || !Number.isInteger(value)) return false;
    if (schema.minimum != null && value < schema.minimum) return false;
    return true;
  }
  if (schema.type === "boolean") return typeof value === "boolean";
  if (schema.type === "array") {
    if (!Array.isArray(value)) return false;
    if (schema.minItems != null && value.length < schema.minItems) return false;
    if (schema.maxItems != null && value.length > schema.maxItems) return false;
    return value.every((item) => !schema.items || validateWithRefs(schema.items, item, roots, currentRoot));
  }
  if (schema.type === "object" || schema.properties) {
    if (!value || typeof value !== "object" || Array.isArray(value)) return false;
    const props = schema.properties || {};
    for (const req of schema.required || []) if (!(req in value)) return false;
    if (schema.additionalProperties === false) {
      for (const key of Object.keys(value)) if (!(key in props)) return false;
    }
    return Object.entries(value).every(([key, entry]) => !props[key] || validateWithRefs(props[key], entry, roots, currentRoot));
  }
  return true;
}

test("the parity certificate schema + its result-state closure are registered and self-contained", () => {
  // Both closure members are registered; loadSchema returns them verbatim.
  const cert = loadSchema("certificate");
  const resultState = loadSchema("result_state");
  assert.equal(cert.$id, "https://spec.consiliency/spec-parity/certificate.schema.json");
  assert.equal(resultState.$id, "https://spec.consiliency/spec-parity/result-state.schema.json");
  assert.equal(cert.properties.schema_version.const, "1");
  // The certificate's ONLY outward $refs point into result-state (the whole
  // transitive closure); nothing outside these two files is referenced.
  const externalRefs = new Set();
  const collect = (node) => {
    if (Array.isArray(node)) node.forEach(collect);
    else if (node && typeof node === "object") {
      if (typeof node.$ref === "string" && !node.$ref.startsWith("#")) externalRefs.add(node.$ref.split("#")[0]);
      Object.values(node).forEach(collect);
    }
  };
  collect(cert);
  assert.deepEqual([...externalRefs].sort(), ["result-state.schema.json"]);
});

test("the distributed parity certificate schema validates a real certificate (and rejects a malformed one)", () => {
  const roots = { self: loadSchema("certificate"), result_state: loadSchema("result_state") };
  const dim = (dimension) => ({ dimension, result_state: "pass" });
  const cert = {
    schema_version: "1",
    projection_algo_version: "1.0.0",
    canon_version: "v2",
    idmodel_version: "v1",
    kind_alignment_version: "v1",
    permitted_freedom_vocab_version: "v1",
    ec_revision_id: "rev-1",
    spec_revision_digest: "a".repeat(64),
    desired_graph_digest: "b".repeat(64),
    ec_digest: "c".repeat(64),
    code_head_sha: "d".repeat(40),
    overall_result_state: "pass",
    dimension_results: [
      dim("completeness"),
      dim("soundness"),
      dim("closure"),
      dim("prohibition"),
      dim("revision_alignment"),
    ],
    findings_ref: "e".repeat(64),
    digest: "f".repeat(64),
  };
  assert.ok(validateWithRefs(roots.self, cert, roots), "a real certificate must validate against the distributed schema");
  // The cross-file $ref is actually exercised (a bad dimension enum must reject).
  const bad = { ...cert, dimension_results: [{ dimension: "not_a_dimension", result_state: "pass" }, ...cert.dimension_results.slice(1)] };
  assert.ok(!validateWithRefs(roots.self, bad, roots), "an out-of-vocab dimension must reject via the result-state $ref");
  // additionalProperties:false is enforced.
  assert.ok(!validateWithRefs(roots.self, { ...cert, bogus: 1 }, roots), "unknown top-level fields must reject");
});

test("the parity-cert provenance pins the spec source and matches the shipped bytes", () => {
  const prov = JSON.parse(readFileSync("core/spec-parity/provenance.json", "utf8"));
  assert.equal(prov.schema, "consiliency.spec_parity_provenance.v1");
  assert.match(prov.normative_source.spec_commit, /^[0-9a-f]{40}$/);
  assert.deepEqual(prov.ref_closure.members.slice().sort(), ["certificate", "result_state"]);
  for (const [key, path] of [["certificate", "core/schemas/certificate.schema.json"], ["result_state", "core/schemas/result-state.schema.json"]]) {
    const digest = createHash("sha256").update(readFileSync(path)).digest("hex");
    assert.equal(digest, prov.distributed[key].sha256, `${key}: shipped bytes must match provenance sha256`);
    // Verbatim copy: source sha == shipped sha.
    const base = path.split("/").pop();
    assert.equal(digest, prov.normative_source.files[base], `${key}: shipped sha must equal pinned spec source sha`);
  }
});

// --- protected_source_category vocabulary (0.6.5) ---

test("protected_source_category registry + schema are registered with the seven-bucket coarse enum", () => {
  const reg = loadRegistry("protected_source_categories");
  const schema = loadSchema("protected_source_category");
  assert.equal(reg.schema, "consiliency.protected_source_categories.v1");
  assert.equal(schema.$id, "https://consiliency.io/contracts/protected-source-category.schema.json");
  const coarseIds = reg.coarse_categories.map((c) => c.id);
  assert.deepEqual(coarseIds, [
    "specs",
    "diagrams",
    "adapter_config",
    "definition_files",
    "portal_contracts",
    "phase_artifacts",
    "governance_contracts",
  ]);
  // The pre-existing six vs the one new coarse bucket.
  const preExisting = reg.coarse_categories.filter((c) => c.pre_existing).map((c) => c.id).sort();
  assert.deepEqual(preExisting, ["adapter_config", "definition_files", "diagrams", "phase_artifacts", "portal_contracts", "specs"]);
  assert.deepEqual(reg.coarse_categories.filter((c) => !c.pre_existing).map((c) => c.id), ["governance_contracts"]);
  // The schema's coarse enum MUST equal the registry ids (no drift between them).
  assert.deepEqual(schema.properties.category.enum, coarseIds);
  assert.deepEqual(schema.required, ["category"]);
  // subtype is optional + free-form (a plain string, never enum-gated).
  assert.equal(schema.properties.subtype.type, "string");
  assert.ok(!("enum" in schema.properties.subtype));
});

test("protected_source_category fine→coarse map covers exactly the 14 gp fine names and closes over the coarse enum", () => {
  const reg = loadRegistry("protected_source_categories");
  const coarseIds = new Set(reg.coarse_categories.map((c) => c.id));
  const expectedFine = [
    "active_canonical_specs",
    "adoption_contracts",
    "canonical_spec_archive_manifests",
    "canonical_spec_mirror_manifests",
    "canonical_specs",
    "current_phase_artifacts",
    "definition_validation_code",
    "execution_profiles",
    "instruction_surfaces",
    "phase_loop_bridge_contract_files",
    "pipeline_definition_json",
    "portal_contracts",
    "runtime_adapter_config",
    "skill_manifests",
  ];
  assert.deepEqual(reg.fine_subtypes.slice().sort(), expectedFine);
  assert.deepEqual(Object.keys(reg.fine_to_coarse).sort(), expectedFine);
  // Every mapping target is a registered coarse id; the subtype echoes the fine key.
  for (const [fine, target] of Object.entries(reg.fine_to_coarse)) {
    assert.ok(coarseIds.has(target.coarse), `${fine}: coarse target must be registered`);
    assert.equal(target.subtype, fine, `${fine}: subtype must echo the fine key`);
  }
  // The four unmappable fine names land in the new governance_contracts bucket.
  const governance = Object.entries(reg.fine_to_coarse)
    .filter(([, t]) => t.coarse === "governance_contracts")
    .map(([f]) => f)
    .sort();
  assert.deepEqual(governance, ["adoption_contracts", "instruction_surfaces", "phase_loop_bridge_contract_files", "skill_manifests"]);
});

test("the protected_source_category schema accepts a valid descriptor and rejects malformed ones", () => {
  const schema = loadSchema("protected_source_category");
  const valid = (value) => validateAgainst(schema, value, schema);
  assert.ok(valid({ category: "governance_contracts" }), "coarse-only descriptor must validate");
  assert.ok(valid({ category: "specs", subtype: "active_canonical_specs" }), "coarse + registered subtype must validate");
  assert.ok(valid({ category: "specs", subtype: "any-free-form-string" }), "subtype is free-form");
  assert.ok(!valid({ category: "not_a_category" }), "an out-of-enum category must reject");
  assert.ok(!valid({ subtype: "active_canonical_specs" }), "category is required");
  assert.ok(!valid({ category: "specs", bogus: 1 }), "additionalProperties:false must reject unknown fields");
});

// --- supervised-run status + admitted-launch envelope (0.6.6) ---
//
// core/supervised-run/ is distributed verbatim and digest-pinned
// (core/supervised-run/provenance.json). Without a reader for the contract this
// package checks byte identity, that every expected diagnostic is a defined
// semantic rule, that every control and patched negative is schema-valid, and
// the envelope_digest rule. Mirrors the Python suite.

const SR_ROOT = "core/supervised-run";
// The frozen v1 payload, pinned here independently of provenance.json (0.7.0 adds v2 alongside).
const SR_V1_PINS = {
  "admitted-launch-envelope.schema.json": "0273f7a5d80eab95ee84660cd657445e881431bca3b8f91cec61015a5d39d41d",
  "run-status.schema.json": "5118c1ab8604e85990150d66bf6b8c1af979dcc404fc84ee5a3c4ba4fead9a30",
  "conformance/README.md": "2d5045245105af88f1f45f720aa8bc3f366efc95c25e25a9c50e402a175533ca",
  "conformance/envelope.vectors.json": "876d322c313b444e49d7a95ee8f7ca39eef13c45864c67a0b3877235e1db6d7f",
  "conformance/run-status.vectors.json": "5bf9dfbf65805f7340290586d546038fc88659785e60e2f55532df4ac6696730",
};
const SR_V1_MANIFEST_SHA256 = "b9c2dad7ca32d32b9860e56c2e14141827955a50b52a54c8088760d9756e1285";
const SR_PAYLOAD = Object.keys(SR_V1_PINS);
const SR_V2_PAYLOAD = [
  "admitted-launch-envelope.v2.schema.json",
  "conformance/README.v2.md",
  "conformance/envelope.v2.vectors.json",
  "conformance/envelope.v2.canonical.vectors.json",
  "conformance/envelope.v2.apply.vectors.json",
];

function srResolve(root, ref) {
  assert.ok(ref.startsWith("#/"), `non-local $ref ${ref}`);
  return ref.slice(2).split("/").reduce((node, part) => node[part.replaceAll("~1", "/").replaceAll("~0", "~")], root);
}

function srTypeOk(name, value) {
  switch (name) {
    case "object": return value !== null && typeof value === "object" && !Array.isArray(value);
    case "array": return Array.isArray(value);
    case "string": return typeof value === "string";
    case "boolean": return typeof value === "boolean";
    case "null": return value === null;
    case "integer": return Number.isInteger(value);
    default: throw new Error(`unsupported type ${name}`);
  }
}

function srValid(schema, value, root) {
  if (schema.$ref !== undefined && !srValid(srResolve(root, schema.$ref), value, root)) return false;
  if (schema.type !== undefined) {
    const names = Array.isArray(schema.type) ? schema.type : [schema.type];
    if (!names.some((name) => srTypeOk(name, value))) return false;
  }
  if ("const" in schema && canonical(value) !== canonical(schema.const)) return false;
  if (schema.enum !== undefined && !schema.enum.some((entry) => canonical(entry) === canonical(value))) return false;
  if (schema.anyOf !== undefined && !schema.anyOf.some((sub) => srValid(sub, value, root))) return false;
  if (schema.oneOf !== undefined && schema.oneOf.filter((sub) => srValid(sub, value, root)).length !== 1) return false;
  if (typeof value === "string") {
    const length = [...value].length;
    if (schema.minLength !== undefined && length < schema.minLength) return false;
    if (schema.maxLength !== undefined && length > schema.maxLength) return false;
    if (schema.pattern !== undefined && !new RegExp(schema.pattern, "u").test(value)) return false;
  }
  if (Number.isInteger(value) && schema.minimum !== undefined && value < schema.minimum) return false;
  if (Number.isInteger(value) && schema.maximum !== undefined && value > schema.maximum) return false;
  if (Array.isArray(value)) {
    if (schema.minItems !== undefined && value.length < schema.minItems) return false;
    if (schema.uniqueItems && new Set(value.map(canonical)).size !== value.length) return false;
    if (schema.items !== undefined && !value.every((item) => srValid(schema.items, item, root))) return false;
  }
  if (srTypeOk("object", value)) {
    const props = schema.properties ?? {};
    if ((schema.required ?? []).some((key) => !(key in value))) return false;
    if (schema.minProperties !== undefined && Object.keys(value).length < schema.minProperties) return false;
    if (schema.additionalProperties === false && Object.keys(value).some((key) => !(key in props))) return false;
    if (!Object.entries(value).every(([key, entry]) => !(key in props) || srValid(props[key], entry, root))) return false;
  }
  return true;
}

function srApplyPatch(document, patch) {
  const doc = JSON.parse(JSON.stringify(document));
  for (const op of patch) {
    const parts = op.path.slice(1).split("/").map((p) => p.replaceAll("~1", "/").replaceAll("~0", "~"));
    const key = parts.pop();
    const parent = parts.reduce((node, part) => (Array.isArray(node) ? node[Number(part)] : node[part]), doc);
    if (Array.isArray(parent)) {
      if (op.op === "add") {
        if (key === "-") parent.push(op.value);
        else {
          assert.ok(Number(key) <= parent.length, op.path);
          parent.splice(Number(key), 0, op.value);
        }
      } else if (op.op === "remove" || op.op === "replace") {
        assert.ok(Number(key) < parent.length, op.path);
        if (op.op === "remove") parent.splice(Number(key), 1);
        else parent[Number(key)] = op.value;
      } else throw new Error(`unsupported op ${op.op}`);
    } else {
      if (op.op === "remove" || op.op === "replace") assert.ok(key in parent, op.path);
      if (op.op === "remove") delete parent[key];
      else if (op.op === "add" || op.op === "replace") parent[key] = op.value;
      else throw new Error(`unsupported op ${op.op}`);
    }
  }
  return doc;
}

function srEnvelopeDigest(envelope) {
  // RFC 8785 (r2Jcs below): UTF-16 member order, ECMAScript numbers, rejects lone surrogates and non-finite numbers.
  const { envelope_digest: _omit, ...body } = envelope;
  return createHash("sha256").update(r2Jcs(body), "utf8").digest("hex");
}

function srVectorSets() {
  return [
    ["admitted_launch_envelope", loadSchema("admitted_launch_envelope")],
    ["supervised_run_status", loadSchema("supervised_run_status")],
  ].map(([name, schema]) => [name, JSON.parse(readFileSync(CONTRACT.supervised_run.vectors[name], "utf8")), schema]);
}

function srCaseInputs(vectors) {
  const controls = Object.fromEntries(vectors.cases.filter((c) => c.role === "control").map((c) => [c.id, c]));
  return vectors.cases.map((c) => {
    if (c.role === "control") return [c, c.input];
    const patched = srApplyPatch(controls[c.control].input, c.patch);
    if (c.rehash) patched.envelope.envelope_digest = srEnvelopeDigest(patched.envelope);
    return [c, patched];
  });
}

test("supervised-run payload is registered and byte-identical to its pinned digests", () => {
  const prov = JSON.parse(readFileSync(`${SR_ROOT}/provenance.json`, "utf8"));
  assert.equal(prov.schema, "consiliency.supervised_run_provenance.v1");
  assert.match(prov.normative_source.spec_commit, /^[0-9a-f]{40}$/);
  assert.deepEqual(prov.normative_source.files, SR_V1_PINS);
  assert.deepEqual(Object.keys(prov.authored_here.files).sort(), [...SR_V2_PAYLOAD].sort());
  assert.deepEqual(prov.distributed.files, { ...prov.normative_source.files, ...prov.authored_here.files });
  for (const rel of [...SR_PAYLOAD, ...SR_V2_PAYLOAD]) {
    const digest = createHash("sha256").update(readFileSync(`${SR_ROOT}/${rel}`)).digest("hex");
    assert.equal(digest, prov.distributed.files[rel], `${rel}: shipped bytes must match the pinned sha256`);
  }
  for (const [rel, pin] of Object.entries(SR_V1_PINS)) {
    assert.equal(createHash("sha256").update(readFileSync(`${SR_ROOT}/${rel}`)).digest("hex"), pin, `v1 frozen: ${rel}`);
  }
  assert.equal(prov.distributed.manifest.path, prov.normative_source.manifest.path);
  assert.equal(prov.normative_source.manifest.sha256, SR_V1_MANIFEST_SHA256);
  assert.deepEqual(prov.distributed.manifest.v1_prefix, { lines: 5, sha256: SR_V1_MANIFEST_SHA256 });
  const manifestBytes = readFileSync(`${SR_ROOT}/${prov.distributed.manifest.path}`);
  assert.equal(createHash("sha256").update(manifestBytes).digest("hex"), prov.distributed.manifest.sha256);
  const prefix = manifestBytes.toString("utf8").split("\n").slice(0, 5).join("\n") + "\n";
  assert.equal(createHash("sha256").update(prefix, "utf8").digest("hex"), SR_V1_MANIFEST_SHA256, "v1 manifest lines moved");
  const lines = manifestBytes.toString("utf8").split("\n").filter(Boolean);
  assert.equal(lines.length, SR_PAYLOAD.length + SR_V2_PAYLOAD.length);
  for (const line of lines) {
    const [, digest, rel] = line.match(/^([0-9a-f]{64}) {2}(\S+)$/);
    const shipped = join("conformance", rel).replaceAll("\\", "/");
    assert.equal(prov.distributed.files[shipped], digest, `SHA256SUMS ${rel}`);
  }
  for (const [name, entry] of Object.entries(prov.distributed.schemas)) {
    assert.equal(CONTRACT.schemas[name], entry.path, name);
    assert.equal(loadSchema(name).$id, entry.schema_id, name);
  }
  assert.deepEqual(CONTRACT.supervised_run.vectors, prov.distributed.vectors);
  assert.deepEqual(prov.consumer_reconciliation.provisional_rule_additions, ["attempt_evidence_copied"]);
  assert.equal(prov.consumer_reconciliation.consumers_reconciled, true);
});

test("supervised-run vectors expect only defined semantic rules and pair negatives with same-kind controls", () => {
  for (const [name, vectors, schema] of srVectorSets()) {
    assert.equal(schema.$schema, "https://json-schema.org/draft/2020-12/schema", name);
    assert.equal(`urn:contract:${vectors.contract}`, schema.$id, name);
    const rules = new Set(Object.keys(schema["x-semantic-rules"]));
    const controls = new Map(vectors.cases.filter((c) => c.role === "control").map((c) => [c.id, c]));
    assert.equal(new Set(vectors.cases.map((c) => c.id)).size, vectors.cases.length, name);
    for (const c of vectors.cases) {
      for (const code of c.expected) assert.ok(rules.has(code), `${c.id}: ${code} is not in x-semantic-rules`);
      if (c.role === "control") assert.deepEqual(c.expected, [], c.id);
      else {
        assert.equal(c.role, "negative", c.id);
        assert.ok(c.expected.length > 0, c.id);
        assert.equal(controls.get(c.control)?.kind, c.kind, c.id);
      }
    }
  }
});

test("every supervised-run control and patched negative is schema-valid; envelope_digest self-verifies unless a mismatch is expected", () => {
  const sets = srVectorSets();
  const envelopeSchema = sets[0][2];
  const runSchema = sets[1][2];
  const defs = runSchema.$defs;
  let seen = 0;
  const mismatches = [];
  for (const [name, vectors] of sets) {
    for (const [c, value] of srCaseInputs(vectors)) {
      const label = `${name}:${c.id}`;
      if (value.envelope) {
        assert.ok(srValid(envelopeSchema, value.envelope, envelopeSchema), `${label} envelope`);
        const ok = srEnvelopeDigest(value.envelope) === value.envelope.envelope_digest;
        assert.equal(ok, !c.expected.includes("envelope_digest_mismatch"), label);
        if (!ok) mismatches.push(c.id);
      }
      for (const attempt of value.journal?.attempts ?? []) {
        for (const segment of attempt.segments) {
          for (const line of segment.lines) {
            if (typeof line !== "string") assert.ok(srValid(defs.journal_line, line, runSchema), `${label} journal line`);
          }
        }
      }
      if (c.kind === "projection") assert.ok(srValid(defs.projection, value.projection, runSchema), `${label} projection`);
      if (c.kind === "reader_view") assert.ok(srValid(defs.reader_view, value, runSchema), `${label} reader_view`);
      if (c.kind === "page") {
        assert.ok(srValid(defs.page_request, value.request, runSchema), `${label} page_request`);
        assert.ok(srValid(defs.page, value.page, runSchema), `${label} page`);
      }
      seen += 1;
    }
  }
  assert.equal(seen, 51);
  assert.deepEqual(mismatches, ["S-digest-not-rehashed"]);
  // Non-vacuity: the validator must be able to say no.
  const envelope = sets[0][1].cases.find((c) => c.id === "E-admitted").input.envelope;
  assert.ok(!srValid(envelopeSchema, { ...envelope, bogus: 1 }, envelopeSchema));
  assert.ok(!srValid(envelopeSchema, { ...envelope, envelope_digest: "A".repeat(64) }, envelopeSchema));
  const line = sets[1][1].cases.find((c) => c.id === "V-running").input.journal.attempts[0].segments[0].lines[0];
  assert.ok(srValid(runSchema, line, runSchema), "root $ref is journal_line");
  assert.ok(!srValid(defs.journal_line, { ...line, line_kind: "note" }, runSchema));
  assert.ok(!srValid(defs.journal_line, { ...line, seq: -1 }, runSchema));
});

// --- admitted_launch_envelope.v2 (0.7.0) ---
//
// An independently written JS reading of the v2 contract, mirroring the Python suite: the I-JSON
// parse boundary and RFC 8785 serializer, source-tree capture, the staged x-semantic-rules over
// captured launch material, the write_scope apply check and the frozen run-status lifecycle subset.
// Test-only; not part of the package API and not a conforming harness.

class R2Unbindable extends Error {}

function r2IsWellFormed(text) {
  for (let i = 0; i < text.length; i += 1) {
    const code = text.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = text.charCodeAt(i + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
      i += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return false;
    }
  }
  return true;
}

function r2EsNumber(value) {
  if (typeof value !== "number" || !Number.isFinite(value)) throw new R2Unbindable("non-finite number");
  return Object.is(value, -0) ? "0" : String(value);
}

function r2EsString(text) {
  if (!r2IsWellFormed(text)) throw new R2Unbindable("lone surrogate");
  const short = { '"': '\\"', "\\": "\\\\", "\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t" };
  let out = '"';
  for (const ch of text) {
    const code = ch.codePointAt(0);
    if (short[ch] !== undefined) out += short[ch];
    else if (code < 0x20) out += `\\u${code.toString(16).padStart(4, "0")}`;
    else out += ch;
  }
  return `${out}"`;
}

function r2Jcs(value) {
  if (value === null) return "null";
  if (value === true || value === false) return String(value);
  if (typeof value === "number") return r2EsNumber(value);
  if (typeof value === "string") return r2EsString(value);
  if (Array.isArray(value)) return `[${value.map(r2Jcs).join(",")}]`;
  if (typeof value === "object") {
    // Default sort compares UTF-16 code units, which is the RFC 8785 member order.
    return `{${Object.keys(value).sort().map((key) => `${r2EsString(key)}:${r2Jcs(value[key])}`).join(",")}}`;
  }
  throw new R2Unbindable(`not a JSON value: ${typeof value}`);
}

function r2Sha(data) {
  return createHash("sha256").update(data, typeof data === "string" ? "utf8" : undefined).digest("hex");
}

function r2JcsSha(value) {
  return r2Sha(r2Jcs(value));
}

// The RFC 8785 / I-JSON boundary on raw bytes: a small recursive-descent parser, because JSON.parse
// silently keeps the last duplicate member and cannot see a lossy integer literal.
function r2StrictParse(bytes) {
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new R2Unbindable("invalid UTF-8");
  }
  let i = 0;
  const ws = () => { while (" \t\n\r".includes(text[i] ?? "x")) i += 1; };
  const fail = (why) => { throw new R2Unbindable(`${why} at ${i}`); };
  const parseString = () => {
    if (text[i] !== '"') fail("expected string");
    i += 1;
    let out = "";
    for (;;) {
      const ch = text[i];
      if (ch === undefined) fail("unterminated string");
      if (ch === '"') { i += 1; break; }
      if (ch.charCodeAt(0) < 0x20) fail("control character in string");
      if (ch === "\\") {
        const esc = text[i + 1];
        const map = { '"': '"', "\\": "\\", "/": "/", b: "\b", f: "\f", n: "\n", r: "\r", t: "\t" };
        if (map[esc] !== undefined) { out += map[esc]; i += 2; continue; }
        if (esc === "u" && /^[0-9a-fA-F]{4}$/.test(text.slice(i + 2, i + 6))) {
          out += String.fromCharCode(parseInt(text.slice(i + 2, i + 6), 16));
          i += 6;
          continue;
        }
        fail("bad escape");
      }
      out += ch;
      i += 1;
    }
    if (!r2IsWellFormed(out)) fail("lone surrogate");
    return out;
  };
  const parseValue = () => {
    ws();
    const ch = text[i];
    if (ch === "{") {
      i += 1;
      const out = {};
      const seen = new Set();
      ws();
      if (text[i] === "}") { i += 1; return out; }
      for (;;) {
        ws();
        const key = parseString();
        if (seen.has(key)) fail("duplicate member");
        seen.add(key);
        ws();
        if (text[i] !== ":") fail("expected colon");
        i += 1;
        out[key] = parseValue();
        ws();
        if (text[i] === ",") { i += 1; continue; }
        if (text[i] === "}") { i += 1; return out; }
        fail("expected , or }");
      }
    }
    if (ch === "[") {
      i += 1;
      const out = [];
      ws();
      if (text[i] === "]") { i += 1; return out; }
      for (;;) {
        out.push(parseValue());
        ws();
        if (text[i] === ",") { i += 1; continue; }
        if (text[i] === "]") { i += 1; return out; }
        fail("expected , or ]");
      }
    }
    if (ch === '"') return parseString();
    for (const [word, value] of [["true", true], ["false", false], ["null", null]]) {
      if (text.startsWith(word, i)) { i += word.length; return value; }
    }
    const match = /^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?/.exec(text.slice(i));
    if (!match || match[0] === "-") fail("unexpected token");
    i += match[0].length;
    const value = Number(match[0]);
    if (!Number.isFinite(value)) fail("non-finite number");
    if (match[2] === undefined && match[3] === undefined) {
      const exact = BigInt(match[0]);
      const limit = 2n ** 53n;
      if ((exact > limit || exact < -limit) && r2EsNumber(value) !== exact.toString()) fail("integer not losslessly representable");
    }
    return value;
  };
  const value = parseValue();
  ws();
  if (i !== text.length) fail("trailing data");
  return value;
}

const R2_IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/u;

function r2RelpathOk(value, allowDot = false) {
  if (typeof value !== "string") return false;
  if (allowDot && value === ".") return true;
  if (value === "" || value.includes(":") || value.includes("\\")) return false;
  if (/[\u0000-\u001f\u007f]/u.test(value)) return false;
  return value.split("/").every((segment) => segment !== "" && segment !== "." && segment !== "..");
}

function r2ValidText(value) {
  return typeof value === "string" && !value.includes("\u0000") && r2IsWellFormed(value);
}

function r2CaptureManifest(capture) {
  const entries = [];
  const seen = new Set();
  for (const item of capture) {
    const path = item.path;
    if (typeof path === "string" && (path === ".git" || path.startsWith(".git/"))) continue;
    if (!r2ValidText(path) || !r2RelpathOk(path)) throw new R2Unbindable("path not representable");
    if (seen.has(path)) throw new R2Unbindable("duplicate path");
    seen.add(path);
    if (item.type === "dir") continue;
    if (item.type === "file") {
      if (!Number.isInteger(item.mode)) throw new R2Unbindable("mode unavailable");
      const data = item.content_hex !== undefined ? Buffer.from(item.content_hex, "hex") : Buffer.from(item.content, "utf8");
      entries.push([path, (item.mode & 0o111) !== 0 ? "executable_file" : "file", r2Sha(data)]);
    } else if (item.type === "symlink") {
      entries.push([path, "symlink", r2Sha(Buffer.from(item.target_hex, "hex"))]);
    } else {
      throw new R2Unbindable(`unsupported entry type ${item.type}`);
    }
  }
  return entries.sort((a, b) => Buffer.compare(Buffer.from(a[0], "utf8"), Buffer.from(b[0], "utf8")));
}

function r2RouteKey(record) {
  return r2Jcs([record.tier, record.action, record.transport_id,
    record.executable_chain.map((e) => [e.locator_kind, e.locator, e.sha256]), record.template_sha256, record.qualification_sha256]);
}

function r2GrantDigest(grant) {
  return grant.canonical_form === "raw_bytes" ? r2Sha(grant.text) : r2JcsSha(grant.value);
}

function r2Redacted(env, classification) {
  const nonSecret = {};
  const secretNames = [];
  for (const [name, value] of Object.entries(env)) {
    if (classification[name] === "non_secret") nonSecret[name] = value;
    else if (classification[name] && typeof classification[name] === "object") secretNames.push(name);
  }
  return { non_secret: nonSecret, secret_names: secretNames.sort() };
}

function r2Strings(node, out = []) {
  if (typeof node === "string") out.push(node);
  else if (Array.isArray(node)) node.forEach((item) => r2Strings(item, out));
  else if (node && typeof node === "object") for (const [key, item] of Object.entries(node)) { out.push(key); r2Strings(item, out); }
  return out;
}

function r2SameJson(a, b) {
  try {
    return r2Jcs(a) === r2Jcs(b);
  } catch {
    return false;
  }
}

function r2Evaluate(schema, value, staged = true) {
  const env = value.envelope;
  if (sr2Errors(schema, env, schema, "/envelope").size > 0) {
    return [["envelope_schema_invalid"], { attempt: { state: "refused", worker_invocations: 0, refusal: { reason: "envelope_schema_invalid" } } }];
  }
  const ctx = value.validator_context;
  const mat = value.launch_material;
  const launch = env.launch;
  const tier = env.enforcement.tier;
  const info = schema["x-enforcement-tiers"][tier];
  const proc = mat.process;
  const sources = [launch.instructions.source, ...launch.references.map((r) => r.source)].filter((s) => s !== null);
  let classification = null;
  try {
    classification = r2StrictParse(Buffer.from(mat.environment.policy, "utf8")).classification ?? null;
  } catch {
    classification = null;
  }
  let constraint = null;
  let record = null;
  const stages = [
    () => {
      const { envelope_digest: _omit, ...body } = env;
      try {
        return r2JcsSha(body) === env.envelope_digest ? [] : ["envelope_digest_mismatch"];
      } catch {
        return ["envelope_digest_mismatch"];
      }
    },
    () => {
      if (env.assignment_digest !== ctx.expected_assignment_digest || env.units.crosswalk_ref !== ctx.expected_crosswalk_ref) return ["authority_foreign"];
      return env.units.snapshot_ref !== ctx.expected_snapshot_ref ? ["authority_baseline_stale"] : [];
    },
    () => {
      const out = [];
      const state = launch.workspace_state;
      const paths = [
        ...env.workspace.repo_relative_locators,
        ...sources.filter((s) => s.namespace === "workspace" || s.namespace === "declared_root").map((s) => s.path),
        ...launch.executable_chain.filter((e) => e.locator_kind === "repo_relative").map((e) => e.locator),
        ...state.target_map.flatMap((p) => [p.workspace_locator, p.protected_locator]),
      ];
      if (!paths.every((p) => r2RelpathOk(p)) || !r2RelpathOk(state.cwd.path, true)) out.push("locator_not_repo_relative");
      const { caller_context: _cc, ...rest } = env;
      if (r2Strings(rest).some((s) => [...s].length > 512 || /[\u0000-\u001f\u007f]/u.test(s))) out.push("raw_output_in_record");
      if (env.executable_dependencies.declared && env.executable_dependencies.admitted_dependency_digest === null) out.push("dependency_digest_required");
      if (["separate_clone", "git_worktree_of_protected"].includes(env.workspace.kind) && state.base_commit === null) out.push("workspace_source_inconsistent");
      const chain = launch.executable_chain;
      if (chain.at(-1).role !== "executable" || chain.slice(0, -1).some((e) => e.role !== "wrapper") ||
          chain.some((e) => e.locator_kind === "declared" && !R2_IDENTIFIER.test(e.locator))) out.push("executable_chain_invalid");
      if (launch.references.filter((r) => r.role === "baseline").length !== 1) out.push("baseline_reference_required");
      const scope = env.workspace.repo_relative_locators;
      if (state.target_map.some((p) => !scope.some((s) => p.protected_locator === s || p.protected_locator.startsWith(`${s}/`)))) out.push("target_map_outside_scope");
      return out;
    },
    () => (info.status === "reserved" ? ["tier_unqualified"] : []),
    () => {
      const trusted = launch.trusted_policy;
      if (trusted.qualification_sha256 === null) return ["route_not_qualified"];
      const key = r2RouteKey({ tier, action: launch.action, transport_id: launch.transport_id, executable_chain: launch.executable_chain,
        template_sha256: trusted.template_sha256, qualification_sha256: trusted.qualification_sha256 });
      const matches = ctx.qualified_routes.filter((r) => r2RouteKey(r) === key);
      if (matches.length !== 1) return ["route_not_qualified"];
      [record] = matches;
      return [];
    },
    () => {
      const out = new Set();
      const unsupported = env.enforcement.required_constraints.filter((c) => info.constraints[c] === "not_enforced");
      if (unsupported.length) { out.add("constraint_unsupported"); [constraint] = unsupported; }
      if (!info.workspace_kinds.includes(env.workspace.kind)) out.add("workspace_not_separate_copy");
      const held = record ?? { grants: {}, credential_sources: [] };
      const grants = launch.grants ?? {};
      if (Object.entries(grants).some(([kind, c]) => !info.grant_kinds.includes(kind) || !r2SameJson(held.grants[kind], c))) out.add("grant_unqualified");
      if ("dependency_projection_sha256" in grants && !env.executable_dependencies.declared) out.add("grant_unqualified");
      if (sources.some((s) => s.namespace === "descriptor") && !("descriptor_capabilities_sha256" in grants)) out.add("grant_unqualified");
      if (launch.workspace_state.cwd.namespace === "view_root" && !("filesystem_view_sha256" in grants)) out.add("grant_unqualified");
      if (classification && typeof classification === "object") {
        for (const name of Object.keys(proc.worker.env)) {
          const entry = classification[name];
          if (entry && typeof entry === "object" && !(held.credential_sources ?? []).includes(entry.secret)) out.add("grant_unqualified");
        }
      }
      if (launch.action === "execution" && launch.stop.deadline_action === "not_armed") out.add("stop_policy_unbounded");
      if (launch.stop.timeout_seconds > ctx.timeout_max_seconds) out.add("timeout_over_declared_max");
      return [...out];
    },
    () => r2Material(launch, mat, proc, classification),
  ];
  const reported = new Set();
  for (const stage of stages) {
    for (const code of stage()) reported.add(code);
    if (reported.size && staged) break;
  }
  const order = schema["x-evaluation-order"].stages.flat();
  const codes = [...reported].sort((a, b) => order.indexOf(a) - order.indexOf(b));
  if (!codes.length) return [[], { attempt: { state: "queued", worker_invocations: 0 } }];
  const refusal = { reason: codes[0], constraint: codes[0] === "constraint_unsupported" ? constraint : null, tier };
  return [codes, { attempt: { state: "refused", worker_invocations: 0, refusal } }];
}

function r2Material(launch, mat, proc, classification) {
  const out = new Set();
  const unbound = () => out.add("launch_input_unbound");
  const { spawn, worker } = proc;
  const policy = mat.policy;
  const grantsMat = policy.grants;
  const bytes = (text) => Buffer.byteLength(text, "utf8");

  let files = null;
  let manifest = null;
  try {
    manifest = r2CaptureManifest(mat.workspace.capture);
    files = new Map(manifest.map((e) => [e[0], e]));
  } catch (error) {
    if (!(error instanceof R2Unbindable)) throw error;
    unbound();
  }
  const treeJoins = (path, sha) => {
    if (files === null) return true;
    const entry = files.get(path);
    return entry !== undefined && (entry[1] === "file" || entry[1] === "executable_file") && entry[2] === sha;
  };
  const grantValue = (kind) => (grantsMat[kind]?.canonical_form === "rfc8785" ? grantsMat[kind].value : null);
  const descriptors = grantValue("descriptor_capabilities_sha256")?.descriptors ?? [];
  if (descriptors.some((d) => d && d.terminal)) unbound();
  const roots = new Set(policy.config.split("\n").map((line) => line.split(/\s+/)).filter((p) => p.length >= 2 && p[0] === "root").map((p) => p[1]));
  const resolvable = (source, captured) => {
    if (captured.content === null || captured.content === undefined || !captured.within_root) return false;
    if (source.namespace === "declared_root") return roots.has(source.root);
    if (source.namespace === "descriptor") return descriptors.some((d) => d && d.id === source.descriptor);
    return true;
  };

  const argvsOk = [spawn.argv, worker.argv].every((vec) => Array.isArray(vec) && vec.every(r2ValidText));
  if (!argvsOk) unbound();
  const envOk = (map) => map !== null && typeof map === "object" &&
    Object.entries(map).every(([n, v]) => r2ValidText(n) && n !== "" && !n.includes("=") && r2ValidText(v));
  const envsOk = envOk(spawn.env) && envOk(worker.env);
  if (!envsOk) unbound();
  const classified = envsOk && classification !== null && typeof classification === "object" &&
    Object.keys(worker.env).every((n) => classification[n] === "non_secret" || (classification[n] && typeof classification[n] === "object" && "secret" in classification[n]));
  if (envsOk && !classified) unbound();

  if (classified) {
    const secrets = Object.entries(worker.env).filter(([n, v]) => classification[n] && typeof classification[n] === "object" && v).map(([, v]) => v);
    const needles = [...secrets, ...secrets.map(r2Sha)];
    const committed = r2Strings([
      spawn.argv, worker.argv, mat.instructions.content ?? null, mat.references.map((r) => r.content ?? null),
      policy.config, policy.template, policy.qualification, mat.environment.policy,
      Object.values(grantsMat).map((g) => (g.canonical_form === "raw_bytes" ? g.text : r2Jcs(g.value))),
      Object.entries(worker.env).filter(([n]) => classification[n] === "non_secret").map(([, v]) => v),
      mat.workspace.capture.filter((c) => typeof c.content === "string").map((c) => c.content),
    ]);
    if (needles.some((needle) => committed.some((text) => text.includes(needle)))) unbound();
  }

  const { stdin } = mat;
  if (stdin.mode === "pty") unbound();
  else if (launch.stdin === "devnull") {
    if (stdin.mode !== "devnull" || stdin.writes.length) unbound();
  } else if (stdin.mode !== "pipe" || stdin.writes.length !== 1 || stdin.writes[0].after !== "start") unbound();
  else if (stdin.writes[0].text !== mat.instructions.content) out.add("launch_instructions_mismatch");
  if (mat.unbound_inputs.length) unbound();

  const instr = launch.instructions;
  const captured = mat.instructions;
  if (!r2SameJson(captured.source ?? null, instr.source)) out.add("launch_instructions_mismatch");
  if (captured.content === null || captured.content === undefined) unbound();
  else {
    if (r2Sha(captured.content) !== instr.sha256 || bytes(captured.content) !== instr.byte_length) out.add("launch_instructions_mismatch");
    if (instr.source === null) {
      const inline = launch.stdin === "input" || (argvsOk && worker.argv.filter((a) => a === captured.content).length === 1);
      if (!inline) out.add("launch_instructions_mismatch");
    } else if (!resolvable(instr.source, captured)) unbound();
    else if (instr.source.namespace === "workspace" && !treeJoins(instr.source.path, instr.sha256)) out.add("launch_instructions_mismatch");
  }

  const bound = launch.references.map((r) => [r.role, r2Jcs(r.source), r.sha256, r.byte_length]);
  const used = mat.references.map((r) => {
    if (!resolvable(r.source, r)) unbound();
    const c = r.content ?? null;
    return [r.role, r2Jcs(r.source), c === null ? null : r2Sha(c), c === null ? null : bytes(c)];
  });
  if (JSON.stringify(bound) !== JSON.stringify(used)) out.add("launch_reference_mismatch");
  for (const r of launch.references) {
    if (r.source.namespace === "workspace" && !treeJoins(r.source.path, r.sha256)) out.add("launch_reference_mismatch");
  }

  if (argvsOk && (r2JcsSha(spawn.argv) !== launch.argv.sha256 || spawn.argv.length !== launch.argv.element_count)) out.add("launch_argv_mismatch");

  const chainKey = (chain) => JSON.stringify(chain.map((e) => [e.role, e.locator_kind, e.locator, e.sha256]));
  if (chainKey(launch.executable_chain) !== chainKey(mat.executable_chain)) out.add("launch_executable_mismatch");
  for (const e of launch.executable_chain) {
    if (e.locator_kind === "repo_relative" && !treeJoins(e.locator, e.sha256)) out.add("launch_executable_mismatch");
  }

  let template = null;
  try {
    template = r2StrictParse(Buffer.from(policy.template, "utf8"));
    if (!("spawn_cwd" in template)) template = null;
  } catch {
    template = null;
  }
  if (template === null) unbound();
  else {
    const helpers = template.helpers ?? [];
    if (!r2SameJson(spawn.cwd, template.spawn_cwd)) unbound();
    if (argvsOk) {
      const shift = helpers.reduce((sum, h) => sum + (h.argv_shift ?? 0), 0);
      if (JSON.stringify(spawn.argv.slice(shift)) !== JSON.stringify(worker.argv)) out.add("launch_argv_mismatch");
    }
    if (envsOk) {
      const derived = { ...spawn.env };
      let consumedOk = true;
      const consumed = new Set();
      for (const h of helpers) {
        for (const [name, val] of Object.entries(h.env_consumed ?? {})) {
          if (derived[name] !== val) consumedOk = false;
          delete derived[name];
          consumed.add(name);
        }
        Object.assign(derived, h.env_set ?? {});
      }
      const ambient = Object.keys(spawn.env).filter((n) => !consumed.has(n) && !(n in worker.env));
      if (!consumedOk || ambient.length) unbound();
      else if (!r2SameJson(derived, worker.env)) out.add("launch_environment_mismatch");
    }
    let derivedCwd = spawn.cwd;
    for (const h of helpers) if (h.cwd !== undefined && h.cwd !== null) derivedCwd = h.cwd;
    if (!r2SameJson(derivedCwd, worker.cwd)) out.add("launch_workspace_mismatch");
  }

  const state = launch.workspace_state;
  const ws = mat.workspace;
  if (ws.base_commit !== state.base_commit || !r2SameJson(ws.target_map, state.target_map)) out.add("launch_workspace_mismatch");
  if (manifest !== null && r2JcsSha(manifest) !== state.content_sha256) out.add("launch_workspace_mismatch");
  if (!r2SameJson(worker.cwd, state.cwd)) out.add("launch_workspace_mismatch");
  if (!proc.cwd_resolution.within_root) unbound();
  if (state.cwd.namespace === "view_root") {
    const viewRoots = (grantValue("filesystem_view_sha256")?.roots ?? []).map((r) => r && r.id);
    if (!viewRoots.includes(state.cwd.root)) unbound();
  }
  const boundSources = launch.references.map((r) => r2Jcs(r.source));
  if (proc.cwd_resolution.discovered.some((found) => !boundSources.includes(r2Jcs(found)))) unbound();

  const environment = launch.environment;
  if (classified && r2JcsSha(r2Redacted(worker.env, classification)) !== environment.map_sha256) out.add("launch_environment_mismatch");
  if (mat.environment.policy_id !== environment.policy.id || r2Sha(mat.environment.policy) !== environment.policy.sha256) out.add("launch_environment_mismatch");

  const trusted = launch.trusted_policy;
  const qualification = policy.qualification === null ? null : r2Sha(policy.qualification);
  if (r2Sha(policy.config) !== trusted.config_sha256 || r2Sha(policy.template) !== trusted.template_sha256 || qualification !== trusted.qualification_sha256) {
    out.add("launch_policy_mismatch");
  }
  const boundGrants = launch.grants ?? {};
  if (JSON.stringify(Object.keys(boundGrants).sort()) !== JSON.stringify(Object.keys(grantsMat).sort())) out.add("launch_policy_mismatch");
  for (const [kind, commitment] of Object.entries(boundGrants)) {
    const g = grantsMat[kind];
    try {
      if (!g || g.canonical_form !== commitment.canonical_form || r2GrantDigest(g) !== commitment.sha256) out.add("launch_policy_mismatch");
    } catch (error) {
      if (!(error instanceof R2Unbindable)) throw error;
      unbound();
    }
  }

  const { stop } = launch;
  const { deadline } = proc;
  const armed = stop.deadline_action === "terminate_process_group" ? stop.timeout_seconds : null;
  if (deadline.seconds !== armed || (armed !== null && (deadline.origin !== "first_chain_process" || deadline.restarted_at_helper))) out.add("launch_timeout_mismatch");

  for (const probe of proc.probes) {
    if (probe.phase !== "before_admission" || probe.mutated_captured || (argvsOk && JSON.stringify(probe.argv) === JSON.stringify(worker.argv))) unbound();
  }
  return [...out];
}

function r2Apply(fixture) {
  const { envelope: env, protected_before: before, proposal } = fixture;
  const mapping = new Map(env.target_map.map((p) => [p.workspace_locator, p.protected_locator]));
  const scope = env.repo_relative_locators;
  const protectedPath = (path) => {
    const target = mapping.get(path);
    return target !== undefined && scope.some((s) => target === s || target.startsWith(`${s}/`)) ? target : null;
  };
  const unchanged = () => ({ ...before });
  if (r2Sha(proposal.text) !== proposal.recorded_sha256) return ["proposal_digest_mismatch", unchanged()];
  const ops = ["modify", "add", "delete", "rename", "copy"];
  const twoSided = (e) => e.op === "rename" || e.op === "copy";
  if (proposal.entries.some((e) => !ops.includes(e.op) || typeof e.path !== "string" || (twoSided(e) && typeof e.from !== "string"))) {
    return ["proposal_unattributable", unchanged()];
  }
  if (proposal.entries.some((e) => e.kind !== "file" || e.mode_change)) return ["proposal_entry_unsupported", unchanged()];
  if (proposal.entries.flatMap((e) => (twoSided(e) ? [e.path, e.from] : [e.path])).some((p) => protectedPath(p) === null)) {
    return ["proposal_out_of_scope", unchanged()];
  }
  const after = { ...before };
  for (const e of proposal.entries) {
    const target = protectedPath(e.path);
    if ((e.op === "modify" || e.op === "delete") && before[target] !== e.base_sha256) return ["proposal_stale", unchanged()];
    if (["add", "rename", "copy"].includes(e.op) && target in before) return ["proposal_stale", unchanged()];
    if (twoSided(e)) {
      const source = protectedPath(e.from);
      if (before[source] !== e.base_sha256) return ["proposal_stale", unchanged()];
      if (e.op === "rename") delete after[source];
    }
    if (e.op === "delete") delete after[target];
    else after[target] = e.new_sha256;
  }
  return ["proposal_applied", after];
}

function r2JournalCodes(journal, runSchema) {
  const lifecycle = runSchema["x-journal-rules"].lifecycle;
  const codes = new Set();
  for (const attempt of journal.attempts) {
    const states = attempt.segments.flatMap((s) => s.lines).filter((l) => typeof l === "object" && (l.line_kind === "state" || l.line_kind === "terminal")).map((l) => l.body);
    let previous = null;
    for (const body of states) {
      const invalid = previous !== null && !lifecycle[previous].includes(body.state);
      const afterLaunch = body.state === "refused" && (previous === "running" || previous === "cancelling" || body.worker_invocations > 0);
      if (afterLaunch) codes.add("refused_after_launch");
      else if (invalid) codes.add("lifecycle_invalid");
      if (body.body_kind === "terminal") {
        if (body.state === "finished" && body.termination === null) codes.add("lifecycle_invalid");
        if (body.state === "refused" && body.refusal === null) codes.add("lifecycle_invalid");
      }
      previous = body.state;
    }
  }
  return [...codes].sort();
}

function sr2Errors(schema, value, root, path = "", out = new Set()) {
  if (schema.$ref !== undefined) sr2Errors(srResolve(root, schema.$ref), value, root, path, out);
  if (schema.type !== undefined) {
    const names = Array.isArray(schema.type) ? schema.type : [schema.type];
    if (!names.some((name) => srTypeOk(name, value))) {
      out.add(`${path} type`);
      return out;
    }
  }
  if ("const" in schema && !r2SameJson(value, schema.const)) out.add(`${path} const`);
  if (schema.enum !== undefined && !schema.enum.some((entry) => r2SameJson(entry, value))) out.add(`${path} enum`);
  if (schema.anyOf !== undefined && !schema.anyOf.some((sub) => sr2Errors(sub, value, root, path).size === 0)) out.add(`${path} anyOf`);
  if (typeof value === "string") {
    const length = [...value].length;
    if (schema.minLength !== undefined && length < schema.minLength) out.add(`${path} minLength`);
    if (schema.maxLength !== undefined && length > schema.maxLength) out.add(`${path} maxLength`);
    if (schema.pattern !== undefined && !new RegExp(schema.pattern, "u").test(value)) out.add(`${path} pattern`);
  }
  if (Number.isInteger(value)) {
    if (schema.minimum !== undefined && value < schema.minimum) out.add(`${path} minimum`);
    if (schema.maximum !== undefined && value > schema.maximum) out.add(`${path} maximum`);
  }
  if (Array.isArray(value)) {
    if (schema.minItems !== undefined && value.length < schema.minItems) out.add(`${path} minItems`);
    if (schema.items !== undefined) value.forEach((item, index) => sr2Errors(schema.items, item, root, `${path}/${index}`, out));
  }
  if (srTypeOk("object", value)) {
    const props = schema.properties ?? {};
    if ((schema.required ?? []).some((key) => !(key in value))) out.add(`${path} required`);
    if (schema.minProperties !== undefined && Object.keys(value).length < schema.minProperties) out.add(`${path} minProperties`);
    if (schema.additionalProperties === false && Object.keys(value).some((key) => !(key in props))) out.add(`${path} additionalProperties`);
    for (const [key, entry] of Object.entries(value)) if (key in props) sr2Errors(props[key], entry, root, `${path}/${key}`, out);
  }
  return out;
}

function sr2Subset(expected, actual) {
  if (expected && typeof expected === "object" && !Array.isArray(expected)) {
    return actual !== null && typeof actual === "object" && Object.entries(expected).every(([k, v]) => k in actual && sr2Subset(v, actual[k]));
  }
  return JSON.stringify(expected) === JSON.stringify(actual);
}

function sr2Load() {
  const schema = loadSchema("admitted_launch_envelope_v2");
  const read = (name) => JSON.parse(readFileSync(CONTRACT.supervised_run.vectors[name], "utf8"));
  const vectors = read("admitted_launch_envelope_v2");
  const controls = Object.fromEntries(vectors.cases.filter((c) => c.role === "control").map((c) => [c.id, c]));
  const cases = vectors.cases.map((c) => {
    if (c.role === "control") return [c, c.input];
    const patched = srApplyPatch(controls[c.control].input, c.patch);
    if (c.rehash) patched.envelope.envelope_digest = srEnvelopeDigest(patched.envelope);
    return [c, patched];
  });
  return {
    schema, vectors, cases, byId: Object.fromEntries(cases.map(([c, v]) => [c.id, v])),
    canonical: read("admitted_launch_envelope_v2_canonical"), apply: read("admitted_launch_envelope_v2_apply"),
  };
}

function sr2Outcome(schema, c, value) {
  if (c.kind === "echo") return r2SameJson(value.echoed_caller_context, value.envelope.caller_context) ? [] : ["caller_context_interpreted"];
  return r2Evaluate(schema, value)[0];
}

test("admitted_launch_envelope.v2: registration, rules, tiers and the caller_context sentence", () => {
  const { schema, vectors, canonical: canon, apply } = sr2Load();
  const v1 = loadSchema("admitted_launch_envelope");
  assert.equal(schema.$id, "urn:contract:admitted_launch_envelope.v2");
  for (const doc of [vectors, canon, apply]) assert.equal(doc.contract, "admitted_launch_envelope.v2");
  assert.deepEqual(schema.required.filter((k) => !v1.required.includes(k)), ["launch"]);
  for (const rule of Object.keys(v1["x-semantic-rules"])) assert.ok(rule in schema["x-semantic-rules"], rule);
  const flat = schema["x-evaluation-order"].stages.flat();
  assert.equal(new Set(flat).size, flat.length);
  assert.deepEqual([...flat, "caller_context_interpreted", "refusal_zero_invocations"].sort(), Object.keys(schema["x-semantic-rules"]).sort());
  for (const [name, info] of Object.entries(schema["x-enforcement-tiers"])) {
    assert.ok(!("qualified" in info), name);
    assert.equal(info.constraints.write_prevention, "not_enforced", name);
    assert.equal(info.qualification, info.status === "defined" ? "required" : "not_admissible", name);
  }
  assert.match(schema.properties.caller_context.description, /never interpreted by the harness or the workbench reader, and never a source of any launch input/);
  assert.match(schema["x-constraint-semantics"].write_scope, /runs whether or not required_constraints lists write_scope/);
  assert.match(schema["x-semantic-rules"].refusal_zero_invocations, /zero launch-chain processes/);
});

test("admitted_launch_envelope.v2: every vector gives exactly its schema errors, digest and staged diagnostics", () => {
  const { schema, cases } = sr2Load();
  const counts = { control: 0, negative: 0, schema_negative: 0 };
  const mismatches = [];
  const widened = new Set();
  for (const [c, value] of cases) {
    counts[c.role] += 1;
    const errors = sr2Errors(schema, value.envelope, schema, "/envelope");
    assert.equal(srValid(schema, value.envelope, schema), errors.size === 0, c.id);
    const expectedErrors = (c.expected_schema_errors ?? []).map((e) => `${e.instance_path} ${e.keyword}`).sort();
    assert.deepEqual([...errors].sort(), expectedErrors, c.id);
    if (srEnvelopeDigest(value.envelope) !== value.envelope.envelope_digest) mismatches.push(c.id);
    assert.deepEqual(sr2Outcome(schema, c, value), c.expected, c.id);
    if (c.kind === "admission") {
      const [, effect] = r2Evaluate(schema, value);
      assert.ok(sr2Subset(c.expected_effect, effect), `${c.id}: ${JSON.stringify(effect)}`);
      assert.equal(effect.attempt.worker_invocations, 0, c.id);
      if (c.role === "negative" && JSON.stringify(r2Evaluate(schema, value, false)[0]) !== JSON.stringify(c.expected)) widened.add(c.id);
    }
  }
  assert.deepEqual(counts, { control: 15, negative: 154, schema_negative: 62 });
  assert.deepEqual(mismatches.sort(), ["S2-digest-not-rehashed", "S2-jcs-ascii-escaped-envelope", "S2-jcs-codepoint-order-envelope"]);
  for (const id of ["S2-os-enforced", "S2-chain-executable-not-last", "S2-qual-duplicate-identical"]) assert.ok(widened.has(id), id);
});

test("admitted_launch_envelope.v2: exactly one qualification record, in any order", () => {
  const { schema, cases } = sr2Load();
  const permutations = (items) => (items.length <= 1 ? [items] : items.flatMap((x, i) => permutations([...items.slice(0, i), ...items.slice(i + 1)]).map((p) => [x, ...p])));
  for (const [c, value] of cases) {
    if (c.kind !== "admission" || c.role === "schema_negative") continue;
    const routes = value.validator_context.qualified_routes;
    if (routes.length > 4) continue;
    for (const order of permutations(routes)) {
      const permuted = JSON.parse(JSON.stringify(value));
      permuted.validator_context.qualified_routes = order;
      assert.deepEqual(r2Evaluate(schema, permuted)[0], c.expected, `${c.id} permuted`);
    }
  }
});

test("admitted_launch_envelope.v2: secrets stay out of commitments; cwd keeps the tree digest; findings are covered", () => {
  const { cases, byId, apply } = sr2Load();
  assert.deepEqual(byId["E2-secret-env"].envelope, byId["E2-secret-env-rotated"].envelope);
  const secrets = ["fake-credential-0001-not-a-real-secret", "fake-credential-0002-rotated-not-real"];
  const needles = [...secrets, ...secrets.map(r2Sha)];
  for (const [c, value] of cases) {
    const text = JSON.stringify(value.envelope);
    for (const needle of needles) assert.ok(!text.includes(needle), c.id);
  }
  assert.equal(byId["E2-view-cwd"].envelope.launch.workspace_state.content_sha256, byId["E2-execution"].envelope.launch.workspace_state.content_sha256);
  assert.deepEqual(byId["E2-helper-transform"].launch_material.process.deadline, { origin: "first_chain_process", seconds: 1800, restarted_at_helper: false });
  const findings = new Set([...cases.map(([c]) => c.finding), ...apply.applications.map((f) => f.finding), ...apply.journals.map((f) => f.finding)]);
  for (const f of ["V2-BIND-01", "V2-QUAL-01", "V2-JCS-01", "V2-TREE-01", "V2-TIER-01", "V2-PRIV-01", "R1", "R2", "R3", "V2-GRANT-01", "S3", "V2-VEC-01", "V2-VEC-02", "V2-LOC-01", "S4"]) {
    assert.ok(findings.has(f), f);
  }
});

test("admitted_launch_envelope.v2: RFC 8785 numbers, documents, parse boundary and wrong preimages", () => {
  const { canonical: canon } = sr2Load();
  let rfcRows = 0;
  for (const row of canon.numbers) {
    const value = Buffer.from(row.bits, "hex").readDoubleBE(0);
    if (row.reject) assert.throws(() => r2EsNumber(value), R2Unbindable, row.id);
    else {
      assert.equal(r2EsNumber(value), row.canonical, row.id);
      if (row.pin === "RFC 8785 Appendix B") rfcRows += 1;
    }
  }
  assert.equal(rfcRows, 24);
  const docs = Object.fromEntries(canon.documents.map((d) => [d.id, d]));
  for (const doc of canon.documents) {
    const raw = doc.raw !== undefined ? Buffer.from(doc.raw, "utf8") : Buffer.from(doc.raw_hex, "hex");
    if (doc.reject) {
      assert.throws(() => r2StrictParse(raw), R2Unbindable, doc.id);
      continue;
    }
    const text = r2Jcs(r2StrictParse(raw));
    assert.equal(text, doc.canonical, doc.id);
    assert.equal(r2Sha(text), doc.sha256, doc.id);
  }
  assert.equal(docs["J-utf16-keys"].sha256, "10921118479ffb2077228b69799235faedcf1ce522092829370ceb5a2b0840d2");
  for (const alt of canon.alternates) {
    assert.equal(r2Sha(alt.preimage), alt.sha256, alt.id);
    assert.notEqual(alt.sha256, docs[alt.of].sha256, alt.id);
  }
  assert.throws(() => r2Jcs({ a: Number.NaN }), R2Unbindable);
  assert.throws(() => r2Jcs({ a: "\ud800" }), R2Unbindable);
  assert.throws(() => r2Jcs({ a: undefined }), R2Unbindable);
});

test("admitted_launch_envelope.v2: source-tree capture", () => {
  const { canonical: canon } = sr2Load();
  const trees = Object.fromEntries(canon.tree_captures.map((t) => [t.id, t]));
  for (const tree of canon.tree_captures) {
    if (tree.unbindable) {
      assert.throws(() => r2CaptureManifest(tree.capture), R2Unbindable, tree.id);
      continue;
    }
    const manifest = r2CaptureManifest(tree.capture);
    assert.deepEqual(manifest, tree.manifest, tree.id);
    assert.equal(r2JcsSha(manifest), tree.sha256, tree.id);
  }
  const root = trees["T-root-git-directory"].sha256;
  assert.equal(trees["T-root-git-file"].sha256, root);
  assert.equal(trees["T-root-git-symlink"].sha256, root);
  assert.notEqual(trees["T-nested-git-removed"].sha256, root);
  assert.notEqual(trees["T-exec-bit-cleared"].sha256, root);
  for (const alt of canon.tree_alternates) {
    assert.equal(r2JcsSha(alt.manifest), alt.sha256, alt.id);
    assert.notEqual(r2JcsSha(r2CaptureManifest(trees[alt.of].capture)), alt.sha256, alt.id);
  }
});

test("admitted_launch_envelope.v2: write_scope apply check and runtime journals", () => {
  const { apply } = sr2Load();
  const runSchema = loadSchema("supervised_run_status");
  for (const fixture of apply.applications) {
    const [outcome, after] = r2Apply(fixture);
    assert.equal(outcome, fixture.expected.outcome, fixture.id);
    assert.deepEqual(after, fixture.expected.protected_after, fixture.id);
    assert.deepEqual(fixture.envelope.required_constraints, [], fixture.id);
    if (outcome !== "proposal_applied") assert.deepEqual(after, fixture.protected_before, fixture.id);
  }
  for (const entry of apply.journals) {
    for (const line of entry.journal.attempts.flatMap((a) => a.segments.flatMap((s) => s.lines))) {
      assert.ok(srValid(runSchema.$defs.journal_line, line, runSchema), entry.id);
    }
    assert.deepEqual(r2JournalCodes(entry.journal, runSchema), entry.expected, entry.id);
  }
  const v1 = JSON.parse(readFileSync(CONTRACT.supervised_run.vectors.supervised_run_status, "utf8"));
  const controls = Object.fromEntries(v1.cases.filter((c) => c.role === "control").map((c) => [c.id, c]));
  let checked = 0;
  for (const c of v1.cases) {
    if (c.kind !== "journal" || !c.expected.every((code) => code === "refused_after_launch" || code === "lifecycle_invalid")) continue;
    const value = c.role === "control" ? c.input : srApplyPatch(controls[c.control].input, c.patch);
    assert.deepEqual(r2JournalCodes(value.journal, runSchema), c.expected, c.id);
    checked += 1;
  }
  assert.ok(checked >= 6);
});

test("admitted_launch_envelope.v2: the README worked grant example is the control, byte for byte", () => {
  const { byId } = sr2Load();
  const readme = readFileSync(`${SR_ROOT}/conformance/README.v2.md`, "utf8");
  const worked = byId["E2-grants-worked"];
  for (const [kind, commitment] of Object.entries(worked.envelope.launch.grants)) {
    assert.ok(readme.includes(commitment.sha256), kind);
    assert.equal(r2GrantDigest(worked.launch_material.policy.grants[kind]), commitment.sha256, kind);
  }
  const record = worked.validator_context.qualified_routes[1];
  assert.deepEqual(record.grants, worked.envelope.launch.grants);
  assert.ok(readme.includes(r2Jcs(record.grants)));
});

test("admitted_launch_envelope.v2: drive-absolute locators are refused in every field family", () => {
  // V2-LOC-01: built here because package data may not carry drive-absolute strings.
  const { schema, byId } = sr2Load();
  for (const spelling of ["C" + ":/src", "C" + ":\\src", "c" + ":/", "\\\\server\\share"]) assert.ok(!r2RelpathOk(spelling), spelling);
  const drive = "C" + ":/src/module/target.ts";
  const edits = {
    workspace: (e) => e.workspace.repo_relative_locators.push("C" + ":/src"),
    source: (e) => { e.launch.references[1].source.path = drive; },
    target_map: (e) => { e.launch.workspace_state.target_map[0].workspace_locator = drive; },
    cwd: (e) => { e.launch.workspace_state.cwd.path = "C" + ":/src"; },
  };
  for (const [family, edit] of Object.entries(edits)) {
    const value = JSON.parse(JSON.stringify(byId["E2-execution"]));
    edit(value.envelope);
    value.envelope.envelope_digest = srEnvelopeDigest(value.envelope);
    assert.deepEqual(r2Evaluate(schema, value)[0], ["locator_not_repo_relative"], family);
  }
});
