import { gateScanAccess } from "@/server/auth/gate";
import { requireJobOwner } from "@/server/auth/owner-gate";
import { getRemediationDeps } from "@/server/deps";
import { handleApproveRemediation } from "@/server/remediation/api";

export async function POST(req: Request, ctx: { params: Promise<{ id: string; remediationId: string }> }) {
  const { id, remediationId } = await ctx.params;
  const owner = requireJobOwner(req, id);
  if (!owner.ok) return owner.response;
  const denied = await gateScanAccess(req, id, { live: true });
  if (denied) return denied;
  return handleApproveRemediation(req, id, remediationId, getRemediationDeps(), owner.subject);
}
