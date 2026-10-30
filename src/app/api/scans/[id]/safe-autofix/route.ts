import { requireJobOwner } from "@/server/auth/owner-gate";
import { getRemediationDeps } from "@/server/deps";
import { handleSafeAutoFix } from "@/server/remediation/api";

export async function POST(req: Request, ctx: { params: Promise<{ id: string }> }) {
  const { id } = await ctx.params;
  // Only the browser that started the scan; the handler then requires that browser's own GitHub user.
  const owner = requireJobOwner(req, id);
  if (!owner.ok) return owner.response;
  return handleSafeAutoFix(req, id, getRemediationDeps());
}
