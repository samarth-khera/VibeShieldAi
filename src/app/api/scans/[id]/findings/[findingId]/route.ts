import { getScanDeps } from "@/server/deps";
import { getScanFinding } from "@/server/scans-service";

export async function GET(_req: Request, ctx: { params: Promise<{ id: string; findingId: string }> }) {
  const { id, findingId } = await ctx.params;
  return getScanFinding(id, findingId, getScanDeps());
}
