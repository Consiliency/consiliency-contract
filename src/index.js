import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export const CONTRACT_PACKAGE = "@consiliency/contract";
export const CONTRACT_VERSION = "0.6.1";

export {
  AuthorityCanonicalError,
  authoritySigningPreimage,
  canonicalizeCore,
  canonicalCoreBytes,
  verifyAuthorityEvent,
} from "./authority.js";

const packageRoot = dirname(dirname(fileURLToPath(import.meta.url)));

function readJson(relativePath) {
  return JSON.parse(readFileSync(join(packageRoot, relativePath), "utf8"));
}

function assertKnown(mapping, name, type) {
  const relativePath = mapping[name];
  if (!relativePath) {
    throw new Error(`Unknown ${type}: ${name}`);
  }
  return relativePath;
}

export const CONTRACT = readJson("core/contract.json");

export function loadContract() {
  return readJson("core/contract.json");
}

export function loadSchema(name) {
  return readJson(assertKnown(CONTRACT.schemas, name, "schema"));
}

export function loadRegistry(name) {
  return readJson(assertKnown(CONTRACT.registries, name, "registry"));
}

export function listVectors() {
  return readdirSync(join(packageRoot, CONTRACT.conformance.vector_root))
    .filter((name) => name.endsWith(".json"))
    .sort();
}

export function loadVector(name) {
  const filename = name.endsWith(".json") ? name : `${name}.json`;
  if (!listVectors().includes(filename)) {
    throw new Error(`Unknown vector: ${name}`);
  }
  return readJson(join(CONTRACT.conformance.vector_root, filename));
}
