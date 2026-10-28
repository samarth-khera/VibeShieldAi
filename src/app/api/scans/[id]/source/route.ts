import { getAuthDeps } from "@/server/deps";
import { handleScanSource } from "@/server/scan-callbacks";

/** Signed worker endpoint: source location for a private-repository scan. */
export async function POST(req: Request, ctx: { params: Promise<{ id: string }> }) {
  const { id } = await ctx.params;
  return handleScanSource(req, id, getAuthDeps());
}
