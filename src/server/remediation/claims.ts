/** Which executor owns an in-flight verification; stored in Remediation.approvedOperations. */
export type VerificationClaim = { lease: string; at?: string };

export function verificationClaimOf(ops: unknown): VerificationClaim | null {
  const claim = (ops as { verificationClaim?: VerificationClaim } | null)?.verificationClaim;
  return claim && typeof claim.lease === "string" ? claim : null;
}

/** Returns approvedOperations with the claim set (or removed when `lease` is null). */
export function withVerificationClaim(ops: unknown, lease: string | null): Record<string, unknown> {
  const base = { ...((ops as Record<string, unknown> | null) ?? {}) };
  if (lease) base.verificationClaim = { lease, at: new Date().toISOString() };
  else delete base.verificationClaim;
  return base;
}
