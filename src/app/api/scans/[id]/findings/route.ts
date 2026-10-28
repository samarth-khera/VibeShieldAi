import { gateScanAccess } from "@/server/auth/gate";
import { getScanDeps } from "@/server/deps";
import { listScanFindings } from "@/server/scans-service";

export async function GET(req: Request, ctx: { params: Promise<{ id: string }> }) {
  const { id } = await ctx.params;
  const denied = await gateScanAccess(req, id);
  if (denied) return denied;
  return listScanFindings(id, req, getScanDeps());
}
