export declare const CONTRACT_PACKAGE: "@consiliency/contract";
export declare const CONTRACT_VERSION: "0.6.4";
export declare const CONTRACT: Record<string, unknown>;
export declare function loadContract(): Record<string, unknown>;
export declare function loadSchema(name: string): Record<string, unknown>;
export declare function loadRegistry(name: string): Record<string, unknown>;
export declare function listVectors(): string[];
export declare function loadVector(name: string): Record<string, unknown>;

export declare class AuthorityCanonicalError extends Error {}
export declare function canonicalizeCore(core: unknown): string;
export declare function canonicalCoreBytes(core: unknown): Buffer;
export declare function authoritySigningPreimage(core: unknown): Buffer;
export interface AuthorityVerifyResult {
  ok: boolean;
  reason: string;
}
export declare function verifyAuthorityEvent(
  event: unknown,
  registry: unknown,
  options: { now: string; expectedCertDigest: string },
): AuthorityVerifyResult;
