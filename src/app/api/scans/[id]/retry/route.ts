import { gateScanAccess, refusePrivateExecution } from "@/server/auth/gate";
import { requireJobOwner } from "@/server/auth/owner-gate";
import { getScanDeps } from "@/server/deps";
import { retryScan } from "@/server/scans-service";

export async function POST(req: Request, ctx: { params: Promise<{ id: string }> }) {
  const { id } = await ctx.params;
  const owner = requireJobOwner(req, id);
  if (!owner.ok) return owner.response;
  const denied = (await gateScanAccess(req, id, { live: true })) ?? (await refusePrivateExecution(id));
  if (denied) return denied;
  return retryScan(id, getScanDeps());
}
