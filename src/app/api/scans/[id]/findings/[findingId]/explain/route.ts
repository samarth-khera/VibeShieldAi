import { gateScanAccess } from "@/server/auth/gate";
import { requireJobOwner } from "@/server/auth/owner-gate";
import { getScanDeps } from "@/server/deps";
import { explainScanFinding } from "@/server/scans-service";

/** Generating an explanation spends shared AI quota, so only the job owner may request one. */
export async function POST(req: Request, props: { params: Promise<{ id: string; findingId: string }> }) {
  const { id, findingId } = await props.params;
  const owner = requireJobOwner(req, id);
  if (!owner.ok) return owner.response;
  const denied = await gateScanAccess(req, id);
  if (denied) return denied;
  return explainScanFinding(id, findingId, req, getScanDeps());
}
