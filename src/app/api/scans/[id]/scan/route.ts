import { getScanDeps } from "@/server/deps";
import { startScan } from "@/server/scans-service";

export async function POST(_req: Request, ctx: { params: Promise<{ id: string }> }) {
  const { id } = await ctx.params;
  return startScan(id, getScanDeps());
}
