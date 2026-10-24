import { getScanDeps } from "@/server/deps";
import { submitScan } from "@/server/scans-service";

export async function POST(request: Request) {
  return submitScan(request, getScanDeps());
}
