import { gateScanAccess } from "@/server/auth/gate";
import { getRemediationDeps } from "@/server/deps";
import { handleListRemediations } from "@/server/remediation/api";

export async function GET(req: Request, ctx: { params: Promise<{ id: string }> }) {
  const { id } = await ctx.params;
  const denied = await gateScanAccess(req, id);
  if (denied) return denied;
  return handleListRemediations(id, getRemediationDeps());
}
