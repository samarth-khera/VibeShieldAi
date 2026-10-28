import { gateScanAccessWithToken } from "@/server/auth/gate";
import { requireJobOwner } from "@/server/auth/owner-gate";
import { getConfig } from "@/server/config";
import { getRemediationDeps } from "@/server/deps";
import { handleCreatePreview } from "@/server/remediation/api";

export async function POST(req: Request, ctx: { params: Promise<{ id: string }> }) {
  const { id } = await ctx.params;
  const owner = requireJobOwner(req, id);
  if (!owner.ok) return owner.response;
  const gate = await gateScanAccessWithToken(req, id);
  if (gate.denied) return gate.denied;
  const config = getConfig();
  // Private repositories: source files are read with the authorizing user's own token.
  const deps = getRemediationDeps(gate.privateToken ? { ...config, githubToken: gate.privateToken } : config);
  return handleCreatePreview(req, id, deps);
}
