import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { rmSync, readdirSync } from "node:fs";
import test from "node:test";

test("npm package includes shared JSON data", () => {
  const output = execFileSync("npm", ["pack", "--dry-run", "--json"], { encoding: "utf8" });
  const [pack] = JSON.parse(output);
  const files = new Set(pack.files.map((file) => file.path));
  assert.ok(files.has("core/contract.json"));
  assert.ok(files.has("core/canonical-html/contract-v1.json"));
  assert.ok(files.has("conformance/vectors/manifest-valid-product.json"));
  assert.ok(files.has("src/index.js"));
  for (const rel of ["provenance.json", "admitted-launch-envelope.schema.json", "run-status.schema.json", "conformance/README.md", "conformance/envelope.vectors.json", "conformance/run-status.vectors.json", "conformance/SHA256SUMS"]) {
    assert.ok(files.has(`core/supervised-run/${rel}`), rel);
  }
});

test("wheel and sdist include shared JSON data", () => {
  rmSync("dist", { recursive: true, force: true });
  execFileSync("python3", ["-m", "build"], { stdio: "pipe" });
  const wheel = readdirSync("dist").find((name) => name.endsWith(".whl"));
  const sdist = readdirSync("dist").find((name) => name.endsWith(".tar.gz"));
  assert.ok(wheel, "wheel artifact missing");
  assert.ok(sdist, "sdist artifact missing");

  const wheelFiles = execFileSync("python3", ["-c", "import sys, zipfile; z=zipfile.ZipFile(sys.argv[1]); print('\\n'.join(z.namelist()))", `dist/${wheel}`], { encoding: "utf8" });
  assert.match(wheelFiles, /consiliency_contract\/_data\/core\/contract\.json/);
  assert.match(wheelFiles, /consiliency_contract\/_data\/conformance\/vectors\/manifest-valid-product\.json/);
  assert.match(wheelFiles, /consiliency_contract\/_data\/core\/supervised-run\/conformance\/SHA256SUMS/);
  assert.match(wheelFiles, /consiliency_contract\/_data\/core\/supervised-run\/conformance\/README\.md/);
  assert.match(wheelFiles, /consiliency_contract\/_data\/core\/supervised-run\/run-status\.schema\.json/);

  const sdistFiles = execFileSync("tar", ["-tf", `dist/${sdist}`], { encoding: "utf8" });
  assert.match(sdistFiles, /\/core\/contract\.json/);
  assert.match(sdistFiles, /\/conformance\/vectors\/manifest-valid-product\.json/);
  assert.match(sdistFiles, /\/core\/supervised-run\/conformance\/SHA256SUMS/);
});
