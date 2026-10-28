import { gateScanAccess } from "@/server/auth/gate";
import { getScanDeps } from "@/server/deps";
import { startScan } from "@/server/scans-service";

export async function POST(req: Request, ctx: { params: Promise<{ id: string }> }) {
  const { id } = await ctx.params;
  const denied = await gateScanAccess(req, id, { live: true });
  if (denied) return denied;
  return startScan(id, getScanDeps());
}
