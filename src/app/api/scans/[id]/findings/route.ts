import { getScanDeps } from "@/server/deps";
import { listScanFindings } from "@/server/scans-service";

export async function GET(req: Request, ctx: { params: Promise<{ id: string }> }) {
  const { id } = await ctx.params;
  return listScanFindings(id, req, getScanDeps());
}
