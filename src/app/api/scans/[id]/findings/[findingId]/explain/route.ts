import { gateScanAccess } from "@/server/auth/gate";
import { getScanDeps } from "@/server/deps";
import { explainScanFinding } from "@/server/scans-service";

export async function POST(
  req: Request,
  props: { params: Promise<{ id: string; findingId: string }> }
) {
  const { id, findingId } = await props.params;
  const denied = await gateScanAccess(req, id);
  if (denied) return denied;
  return explainScanFinding(id, findingId, req, getScanDeps());
}
