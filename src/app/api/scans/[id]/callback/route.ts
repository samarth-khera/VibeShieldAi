import { getRemediationDeps, getScanDeps, runAfterResponse } from "@/server/deps";
import { runSafeAutoFix } from "@/server/remediation/automation";
import { handleScanCallback } from "@/server/scan-callbacks";
import { pumpQueue } from "@/server/scans-service";

export async function POST(req: Request, props: { params: Promise<{ id: string }> }): Promise<Response> {
  const { id } = await props.params;
  const res = await handleScanCallback(req, id, () => pumpQueue(getScanDeps()));
  // The callback that completed the scan (exactly once) starts Safe Auto-Fix when the repository
  // opted in; runSafeAutoFix checks the opt-in, the scan status and the repository itself.
  const body = (await res.clone().json().catch(() => null)) as { data?: { success?: boolean; status?: string } } | null;
  if (body?.data?.success && body.data.status === "completed") {
    runAfterResponse(() => runSafeAutoFix(id, getRemediationDeps()));
  }
  return res;
}
