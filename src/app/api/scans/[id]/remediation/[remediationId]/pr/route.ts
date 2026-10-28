import { requireJobOwner } from "@/server/auth/owner-gate";
import { getRemediationDeps } from "@/server/deps";
import { handleCreatePullRequest } from "@/server/remediation/api";

export async function POST(req: Request, ctx: { params: Promise<{ id: string; remediationId: string }> }) {
  const { id, remediationId } = await ctx.params;
  // Job owner first; the handler then requires the user's own live GitHub authorization.
  const owner = requireJobOwner(req, id);
  if (!owner.ok) return owner.response;
  return handleCreatePullRequest(req, id, remediationId, getRemediationDeps(), owner.subject);
}
