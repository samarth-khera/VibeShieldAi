import { gateScanAccess } from "@/server/auth/gate";
import { attachViewer } from "@/server/auth/owner-gate";
import { getScanDeps } from "@/server/deps";
import { getScan } from "@/server/scans-service";

export async function GET(req: Request, ctx: { params: Promise<{ id: string }> }) {
  const { id } = await ctx.params;
  const denied = await gateScanAccess(req, id);
  if (denied) return denied;
  return attachViewer(req, id, await getScan(id, getScanDeps()));
}
