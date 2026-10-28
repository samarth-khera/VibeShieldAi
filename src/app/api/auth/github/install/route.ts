import { connection } from "next/server";
import { getAuthDeps } from "@/server/deps";
import { startInstall } from "@/server/auth/service";

export async function GET(req: Request) {
  // Always request-time: these handlers depend on cookies, state and live GitHub checks.
  await connection();
  return startInstall(req, getAuthDeps());
}
