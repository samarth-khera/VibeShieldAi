import { getRemediationDeps } from "@/server/deps";
import { handleVerificationResult, handleVerificationSpec } from "@/server/remediation/api";

type Ctx = { params: Promise<{ id: string; remediationId: string }> };

/** Worker-only: signed fetch of the approved remediation to verify. */
export async function GET(req: Request, ctx: Ctx) {
  const { id, remediationId } = await ctx.params;
  return handleVerificationSpec(req, id, remediationId, getRemediationDeps());
}

/** Worker-only: signed verification result. */
export async function POST(req: Request, ctx: Ctx) {
  const { id, remediationId } = await ctx.params;
  return handleVerificationResult(req, id, remediationId, getRemediationDeps());
}
