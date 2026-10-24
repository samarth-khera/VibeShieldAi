import { getRemediationDeps } from "@/server/deps";
import { handleListRemediations } from "@/server/remediation/api";

export async function GET(req: Request, ctx: { params: Promise<{ id: string }> }) {
  const { id } = await ctx.params;
  return handleListRemediations(id, getRemediationDeps());
}
