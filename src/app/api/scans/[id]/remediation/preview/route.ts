import { getRemediationDeps } from "@/server/deps";
import { handleCreatePreview } from "@/server/remediation/api";

export async function POST(req: Request, ctx: { params: Promise<{ id: string }> }) {
  const { id } = await ctx.params;
  return handleCreatePreview(req, id, getRemediationDeps());
}
