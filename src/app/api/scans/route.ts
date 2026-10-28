import { attachOwnerGrant } from "@/server/auth/owner-gate";
import { getScanDeps } from "@/server/deps";
import { submitScan } from "@/server/scans-service";

export async function POST(request: Request) {
  // The submitting browser becomes the job owner (HttpOnly grant cookie); the job ID alone is read-only.
  return attachOwnerGrant(request, await submitScan(request, getScanDeps()));
}
