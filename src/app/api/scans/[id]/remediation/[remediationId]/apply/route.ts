import { gateScanAccess } from "@/server/auth/gate";
import { getRemediationDeps } from "@/server/deps";
import { handleApplyRemediation } from "@/server/remediation/api";

export async function POST(
  req: Request,
  ctx: { params: Promise<{ id: string; remediationId: string }> },
) {
  const { id, remediationId } = await ctx.params;
  const denied = await gateScanAccess(req, id, { live: true });
  if (denied) return denied;
  return handleApplyRemediation(id, remediationId, getRemediationDeps());
}
