import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { executeScanJob, PRIVATE_REPOSITORY } from "@/server/worker/scan-executor";
import { verifyCallbackSignature } from "@/server/callback-auth";
import { getConfig } from "@/server/config";

afterEach(() => vi.unstubAllGlobals());

/** A real gzip tarball shaped like GitHub's archive (single top-level directory). */
function fixtureTarball(): Buffer {
  const dir = mkdtempSync(path.join(tmpdir(), "vs-private-fixture-"));
  mkdirSync(path.join(dir, "acme-secretrepo-abc1234"));
  writeFileSync(path.join(dir, "acme-secretrepo-abc1234", "README.md"), "# private\n");
  const out = path.join(dir, "a.tar.gz");
  execFileSync("tar", ["-czf", out, "-C", dir, "acme-secretrepo-abc1234"], { env: { ...process.env, COPYFILE_DISABLE: "1" } });
  return readFileSync(out);
}

describe("private-repository scan in the worker", () => {
  it("gets identity and a short-lived archive URL from the signed source endpoint, downloads without credentials, and never logs the name", async () => {
    const secret = "test-callback-secret";
    const sha = "a".repeat(40);
    const archiveUrl = `https://codeload.github.com/acme/secretrepo/legacy.tar.gz/${sha}?token=TMPARCHIVE`;
    const tarball = fixtureTarball();
    const calls: { url: string; auth: string | null; body?: string }[] = [];

    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string, init?: RequestInit) => {
        const body = init?.body ? String(init.body) : undefined;
        calls.push({ url, auth: new Headers(init?.headers).get("authorization"), body });
        if (url.endsWith("/api/scans/job1/source")) {
          expect(verifyCallbackSignature(body!, new Headers(init?.headers).get("x-vibeshield-signature"), secret).valid).toBe(true);
          return Response.json({ data: { owner: "acme", repo: "secretrepo", defaultBranch: "main", commitSha: sha, archiveUrl } });
        }
        if (url === archiveUrl) return new Response(new Uint8Array(tarball), { status: 200 });
        if (url.endsWith("/api/scans/job1/callback")) return Response.json({ data: { accepted: true } });
        return new Response("unexpected", { status: 500 });
      }),
    );

    const logs: string[] = [];
    await executeScanJob({
      jobId: "job1",
      repositoryUrl: PRIVATE_REPOSITORY,
      callbackUrl: "https://vs.example/api/scans/job1/callback",
      secret,
      config: getConfig(),
      log: (l) => logs.push(l),
    });

    // No GitHub API metadata calls: identity came from the app, authorized by the user.
    expect(calls.some((c) => c.url.startsWith("https://api.github.com"))).toBe(false);
    const download = calls.find((c) => c.url === archiveUrl)!;
    expect(download.auth).toBeNull();
    const final = calls.filter((c) => c.url.endsWith("/callback")).map((c) => JSON.parse(c.body!)).find((b) => !b.type);
    expect(final.commitSha).toBe(sha);
    expect(final.fileCount).toBe(1);
    expect(logs.join("\n")).not.toMatch(/secretrepo|TMPARCHIVE/);
  });

  it("fails the scan (without leaking anything) when the app refuses the source", async () => {
    const posted: Record<string, unknown>[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string, init?: RequestInit) => {
        if (url.endsWith("/source")) return Response.json({ error: { code: "access_lost" } }, { status: 403 });
        posted.push(JSON.parse(String(init?.body)));
        return Response.json({ data: {} });
      }),
    );
    const outcome = await executeScanJob({
      jobId: "job1",
      repositoryUrl: PRIVATE_REPOSITORY,
      callbackUrl: "https://vs.example/api/scans/job1/callback",
      secret: "s",
      config: getConfig(),
    });
    expect(outcome).toBe("failed");
    const failed = posted.find((p) => p.status === "failed")!;
    expect(failed.errorMessage).toBe("Private repository source unavailable (HTTP 403).");
  });
});
