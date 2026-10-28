import { getScanDeps } from "@/server/deps";
import { handleScanCallback } from "@/server/scan-callbacks";
import { pumpQueue } from "@/server/scans-service";

export async function POST(req: Request, props: { params: Promise<{ id: string }> }): Promise<Response> {
  const { id } = await props.params;
  return handleScanCallback(req, id, () => pumpQueue(getScanDeps()));
}
