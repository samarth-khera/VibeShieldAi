import { getRemediationDeps } from "@/server/deps";
import { handleDownloadPatch } from "@/server/remediation/api";

export async function GET(
  req: Request,
  ctx: { params: Promise<{ id: string; remediationId: string }> },
) {
  const { id, remediationId } = await ctx.params;
  return handleDownloadPatch(id, remediationId, getRemediationDeps());
}
