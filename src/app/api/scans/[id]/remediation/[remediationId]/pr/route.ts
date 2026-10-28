import { getRemediationDeps } from "@/server/deps";
import { handleCreatePullRequest } from "@/server/remediation/api";

export async function POST(
  _req: Request,
  ctx: { params: Promise<{ id: string; remediationId: string }> },
) {
  const { id, remediationId } = await ctx.params;
  return handleCreatePullRequest(id, remediationId, getRemediationDeps());
}
