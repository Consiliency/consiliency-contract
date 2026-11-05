# Conformance vectors: admitted_launch_envelope.v2

Status: **provisional**. `admitted_launch_envelope.v2` is a harness-neutral, language-neutral contract, published
alongside the frozen `admitted_launch_envelope.v1`. It names no deployment, repository, host or application, and is
meant to be vendored unchanged. `README.md` in this directory still describes v1 and `supervised_run_status.v1`; it is
part of the frozen v1 pin set, so it is not edited.

## Files

| File | Content |
|---|---|
| `../admitted-launch-envelope.v2.schema.json` | JSON Schema (draft 2020-12) for the v2 envelope, its enforcement tiers (`x-enforcement-tiers`), constraint semantics, route qualification, digest forms, launch semantics, evaluation order and semantic rules |
| `envelope.v2.vectors.json` | v2 admission and caller-context echo vectors |
| `README.v2.md` | this file |
| `SHA256SUMS` | its first five lines are the v1 manifest, byte for byte; the lines after them add the three v2 files |

v1 files and their digests do not change. A v1 envelope is not a v2 envelope (the `schema` const differs and `launch`
is required); a reader selects the contract by `schema`.

## What v2 adds

v2 keeps every v1 field with its v1 meaning and adds one required, closed `launch` block. It binds, by digest or
repository-relative locator only, every input that determines what process starts and what it is given:

| `launch` field | Binds |
|---|---|
| `action`, `transport_id`, `stdin` | execution or review; the route the harness selected; whether stdin carries the instruction bytes or nothing |
| `instructions` | SHA-256 and length of the exact instruction bytes |
| `references` | ordered SHA-256, length and locator of every other consumed byte sequence: exactly one `baseline`, plus `context` and `config` files |
| `argv` | SHA-256 of the UTF-8 RFC 8785 serialization of the final ordered argument vector, and its length |
| `executable_chain` | every wrapper, outermost first, then the executable: locator (repository-relative or a declared name) and raw-file SHA-256 |
| `workspace_state` | base commit (or null), tree-manifest digest of the materialized working tree including overlays, cwd, and the workspace-to-protected target map |
| `environment` | SHA-256 of the effective environment map, and the id and raw-byte digest of the policy that built it |
| `trusted_policy` | raw-byte SHA-256 of the trusted configuration, the argument template and the qualification evidence (null when there is none) |
| `stop` | `timeout_seconds` (integer, 1 to 3600) and `deadline_action` |
| `grants` (optional) | digests of the filesystem view, descriptor capabilities, dependency projection, supervisor identity and egress policy actually applied |

Tier and constraints, and the assignment, snapshot, project and dependency authority, stay where v1 has them.

## Tiers and qualification

`x-enforcement-tiers` describes each tier's semantics and limits; it does not qualify any installed tool. Admission under
a defined tier needs a qualification record that the validator holds itself, matching the route: the tier, action,
transport, executable chain, template digest and qualification digest. Without one the launch is refused with
`route_not_qualified`; a reserved tier is refused with `tier_unqualified`. Unqualified means refused: there is no
fallback tier and no warn-only admission. `write_scope: checked_before_apply` is an apply-time check of the returned
proposal bytes, spelled out in `x-constraint-semantics`. Prevention during the run is the separate constraint
`write_prevention`, which no defined tier provides.

## Reading a vector

Each case has `role`:

- `control`: a complete `input`, expected to be admitted (`expected: []`, effect `queued`).
- `negative`: a JSON Patch (RFC 6902 `add`, `remove` and `replace`, RFC 6901 pointers) applied to a copy of the named
  control's input. The patched envelope is schema-valid. It must be refused by the semantic rule named in `expected`, not
  by JSON Schema.
- `schema_negative`: a patch that makes the envelope schema-invalid. `expected` is `["envelope_schema_invalid"]` and
  `expected_schema_errors` is the exact set of `{instance_path, keyword}` pairs a validator reports. Paths are RFC 6901
  pointers into the case input. A `type` failure masks the other keywords at that node, and `anyOf` is reported
  at its own node, not per branch.

When `rehash` is `true`, recompute `envelope.envelope_digest` after patching, so the envelope self-verifies and is refused
on its merits.

`expected` is the exact set of diagnostics. Diagnostics are evaluated in the stages of `x-evaluation-order`; the first
stage that reports anything ends evaluation, so a negative expects only that stage's diagnostics. `expected_effect` is
matched as a subset: a refusal is `refused` with `worker_invocations: 0` and `refusal.reason` equal to the first
reported diagnostic in stage order (`refusal.constraint` names the constraint for `constraint_unsupported`).

An admission input has three parts:

- `envelope`: the record under test.
- `validator_context`: what the validator holds independently of the envelope. That is the expected authority values,
  `timeout_max_seconds` from its trusted configuration, and `qualified_routes`. Each route record has `tier`, `action`,
  `transport_id`, `executable_chain` (`locator_kind`, `locator`, `sha256`), `template_sha256`,
  `qualification_sha256` and `grants`, the grant digests its evidence covers.
- `launch_material`: what the harness is about to use, observed immediately before start. Text values stand for exact
  UTF-8 bytes.
  - `stdin` (null when nothing), `instructions`, `references` (`role`, `locator`, `content`), `argv`;
  - `executable_chain` (resolved-file digests);
  - `workspace`: `base_commit`, `cwd`, tree `entries` as `[path, kind, sha256]`, `target_map`;
  - `environment`: `map`, `policy_id`, `policy`;
  - `policy`: `config`, `template`, `qualification`, and `grants` as grant kind to text;
  - `deadline_seconds`: the deadline about to be armed, or null;
  - `unbound_inputs`: any input not covered by the launch block.

Every launch digest in an envelope is recomputed from this material. Each `launch_*_mismatch` negative changes only the
material, or only one envelope digest, so exactly one binding fails.

## Digests

- `envelope_digest`: SHA-256 of the UTF-8 RFC 8785 serialization of the envelope without `envelope_digest`.
- `argv.sha256` and `environment.map_sha256`: SHA-256 of the UTF-8 RFC 8785 serialization of the array or object.
  The vectors include a non-ASCII argument, so an ASCII-escaping or whitespace-adding serializer does not match.
- `workspace_state.content_sha256`: SHA-256 of the UTF-8 RFC 8785 serialization of the `[path, kind, sha256]` entries
  sorted by the UTF-8 bytes of `path` (`x-digest-forms.rfc8785_tree_manifest`).
- Every other digest is the SHA-256 of the exact raw bytes.

The vectors use ASCII object keys, strings and integers. The one non-integer number is `X2-timeout-fractional`, where
`1800.5` serializes the same way in RFC 8785 and the common serializers.
