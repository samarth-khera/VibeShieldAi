import { gateScanAccess } from "@/server/auth/gate";
import { getScanDeps } from "@/server/deps";
import { getScanFinding } from "@/server/scans-service";

export async function GET(req: Request, ctx: { params: Promise<{ id: string; findingId: string }> }) {
  const { id, findingId } = await ctx.params;
  const denied = await gateScanAccess(req, id);
  if (denied) return denied;
  return getScanFinding(id, findingId, getScanDeps());
}
