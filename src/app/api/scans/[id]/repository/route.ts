import { getScanDeps } from "@/server/deps";
import { getScanRepository } from "@/server/scans-service";

export async function GET(_req: Request, ctx: { params: Promise<{ id: string }> }) {
  const { id } = await ctx.params;
  return getScanRepository(id, getScanDeps());
}
