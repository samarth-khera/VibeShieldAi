import { connection } from "next/server";
import { getAuthDeps, getScanDeps } from "@/server/deps";
import { handleGithubStatus } from "@/server/auth/handlers";

export async function GET(req: Request) {
  // Always request-time: these handlers depend on cookies, state and live GitHub checks.
  await connection();
  return handleGithubStatus(req, getAuthDeps(), getScanDeps().store);
}
