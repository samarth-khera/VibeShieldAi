import { getAuthDeps } from "@/server/deps";
import { disconnect } from "@/server/auth/service";

export async function POST(req: Request) {
  return disconnect(req, getAuthDeps());
}
