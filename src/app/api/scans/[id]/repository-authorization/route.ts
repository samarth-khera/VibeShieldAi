import { requireJobOwner } from "@/server/auth/owner-gate";
import { handleRepositoryAuthorization } from "@/server/auth/repository-authorization";
import { getAuthDeps, getScanDeps } from "@/server/deps";

export async function POST(req: Request, ctx: { params: Promise<{ id: string }> }) {
  const { id } = await ctx.params;
  // Only the browser that started the scan; the handler then requires that browser's own GitHub user.
  const owner = requireJobOwner(req, id);
  if (!owner.ok) return owner.response;
  return handleRepositoryAuthorization(req, id, { auth: getAuthDeps(), jobs: getScanDeps().store }, owner.subject);
}
