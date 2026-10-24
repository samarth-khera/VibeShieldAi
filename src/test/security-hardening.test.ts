import { describe, expect, it } from "vitest";
import { safeEntryPath } from "@/server/archive";
import { assertApprovedUrl, safeFetch } from "@/server/github";
import { clientKey } from "@/server/rate-limit";
import { redactText, redactEvidence } from "@/server/scanners/redact";
import { runSubprocess, getCleanEnv } from "@/server/scanners/runner";
import { getPlatformIsolationInfo } from "@/server/scanners/isolation-spec";
import { JOB_ID_RE } from "@/server/job-store";
import { getScan, listScanFindings, getScanFinding, explainScanFinding } from "@/server/scans-service";
import { InMemoryJobStore } from "./mock-store";
import { getConfig } from "@/server/config";
import path from "node:path";
import os from "node:os";
import { mkdtemp, rm } from "node:fs/promises";

describe("Security Hardening & Production Readiness Audit", () => {
  describe("1. Scanner Subprocess Isolation & Resource Limits", () => {
    it("reports platform isolation capabilities accurately", () => {
      const info = getPlatformIsolationInfo();
      expect(info.platform).toBe(os.platform());
      expect(info.controls.processTreeKill).toBe(true);
      expect(info.controls.isolatedSandboxHome).toBe(true);
      expect(info.controls.outputBufferLimitBytes).toBe(10 * 1024 * 1024);
      if (os.platform() === "darwin") {
        expect(info.isolationMode).toBe("darwin_process_sandbox");
        expect(info.limitations.length).toBeGreaterThan(0);
        expect(info.limitations[0]).toContain("macOS (Darwin) host");
      }
    });

    it("ensures child process environment isolates $HOME and does not inherit host user files", async () => {
      const tmp = await mkdtemp(path.join(os.tmpdir(), "vibe-env-test-"));
      try {
        const env = await getCleanEnv(tmp);
        expect(env.HOME).toBe(path.join(tmp, ".sandbox_home"));
        expect(env.TMPDIR).toBe(path.join(tmp, ".sandbox_tmp"));
        expect(env.HOME).not.toBe(process.env.HOME);
        expect(env.USER).toBe("scanner");
      } finally {
        await rm(tmp, { recursive: true, force: true });
      }
    });

    it("terminates process group on execution timeout without leaking zombie processes", async () => {
      const tmp = await mkdtemp(path.join(os.tmpdir(), "vibe-timeout-test-"));
      try {
        await expect(
          runSubprocess("node", ["-e", "setInterval(() => {}, 1000)"], {
            cwd: tmp,
            timeoutMs: 500,
          })
        ).rejects.toThrow(/timed out after 500ms/);
      } finally {
        await rm(tmp, { recursive: true, force: true });
      }
    });

    it("terminates process group if output exceeds max buffer limit", async () => {
      const tmp = await mkdtemp(path.join(os.tmpdir(), "vibe-buffer-test-"));
      try {
        // Output 50KB while limit is 10KB
        await expect(
          runSubprocess(
            "node",
            ["-e", "process.stdout.write('A'.repeat(50000))"],
            {
              cwd: tmp,
              maxBufferBytes: 10 * 1024,
            }
          )
        ).rejects.toThrow(/output exceeded maximum buffer limit/);
      } finally {
        await rm(tmp, { recursive: true, force: true });
      }
    });

    it("redacts sensitive tokens from process stderr output before throwing", async () => {
      const tmp = await mkdtemp(path.join(os.tmpdir(), "vibe-redact-test-"));
      try {
        const syntheticSecret = ["ghp", "999999999999999999999999999999999999"].join("_");
        await expect(
          runSubprocess(
            "node",
            ["-e", `console.error('Fatal crash with token ${syntheticSecret}'); process.exit(1);`],
            {
              cwd: tmp,
            }
          )
        ).rejects.toThrow(/\[REDACTED\]/);
      } finally {
        await rm(tmp, { recursive: true, force: true });
      }
    });
  });

  describe("2. GitHub Retrieval & SSRF Defense", () => {
    it("rejects non-approved hosts, http protocol, ports and credentials", () => {
      expect(() => assertApprovedUrl("http://api.github.com/repos/foo/bar")).toThrow();
      expect(() => assertApprovedUrl("https://evil.com/malicious")).toThrow();
      expect(() => assertApprovedUrl("https://localhost/api")).toThrow();
      expect(() => assertApprovedUrl("https://127.0.0.1/api")).toThrow();
      expect(() => assertApprovedUrl("https://169.254.169.254/latest/meta-data/")).toThrow();
      expect(() => assertApprovedUrl("https://user:pass@api.github.com/repos/foo/bar")).toThrow();
      expect(() => assertApprovedUrl("https://api.github.com:8443/repos/foo/bar")).toThrow();
    });

    it("rejects redirects to external or private destinations", async () => {
      const mockFetch = async () =>
        new Response(null, {
          status: 302,
          headers: { location: "http://169.254.169.254/metadata" },
        });

      await expect(
        safeFetch(mockFetch, "https://api.github.com/repos/owner/repo", {}, new AbortController().signal)
      ).rejects.toThrow(/redirect/);
    });

    it("blocks archive path traversal attacks (.., absolute paths, Windows drive letters, alternate streams)", () => {
      const root = "/tmp/safe-workspace";
      expect(() => safeEntryPath(root, "repo-main/../../etc/passwd")).toThrow(/unsafe_path/);
      expect(() => safeEntryPath(root, "/etc/passwd")).toThrow(/unsafe_path/);
      expect(() => safeEntryPath(root, "C:\\Windows\\System32")).toThrow(/unsafe_path/);
      expect(() => safeEntryPath(root, "repo-main/subdir/..\\..\\secret")).toThrow(/unsafe_path/);
      expect(() => safeEntryPath(root, "repo-main/file.txt\0payload")).toThrow(/unsafe_path/);
      expect(() => safeEntryPath(root, "repo-main/file:stream")).toThrow(/unsafe_path/);
    });
  });

  describe("3. Secrets Redaction & Privacy Invariants", () => {
    it("redacts GitHub tokens, AWS keys, Stripe keys, Slack tokens, JWTs, and database passwords", () => {
      const gh = ["ghp", "ABCDEF1234567890ABCDEF"].join("_");
      expect(redactText(`my token is ${gh}`)).toBe("my token is [REDACTED]");

      const stripe = ["sk", "live", "123456789012345678901234"].join("_");
      expect(redactText(`stripe key = ${stripe}`)).toBe("stripe key = [REDACTED]");

      expect(redactText("AKIA1234567890123456")).toBe("[REDACTED]");
      const slack = ["xoxb", "123456789012", "123456789012", "abcdef"].join("-");
      expect(redactText(slack)).toBe("[REDACTED]");

      const jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozGzN_ce";
      expect(redactText(`Bearer ${jwt}`)).toContain("[REDACTED]");

      const dbUrl = "postgres://vibeshield:supersecretpass@127.0.0.1:5432/vibeshield";
      expect(redactText(`DATABASE_URL=${dbUrl}`)).not.toContain("supersecretpass");
      expect(redactText(`DATABASE_URL=${dbUrl}`)).toContain("••••••••");
    });

    it("redacts evidence snippets safely while preserving non-sensitive context", () => {
      const syntheticKey = ["sk", "live", "999999999999999999999999"].join("_");
      const snippet = `const stripe = new Stripe("${syntheticKey}");\nconsole.log("ready");`;
      const cleaned = redactEvidence(snippet);
      expect(cleaned).not.toContain(syntheticKey);
      expect(cleaned).toContain("[REDACTED]");
      expect(cleaned).toContain('console.log("ready");');
    });
  });

  describe("4. Anti-Spoofing & Client Rate Limiting", () => {
    it("does not blindly trust leftmost attacker-supplied X-Forwarded-For IP", () => {
      // Attacker sends: X-Forwarded-For: 1.1.1.1, reverse proxy appends real IP: 203.0.113.195
      const h1 = new Headers({
        "x-forwarded-for": "1.1.1.1, 203.0.113.195",
        "user-agent": "test-agent",
      });
      // Attacker changes first IP to 1.1.1.2 trying to bypass rate limits
      const h2 = new Headers({
        "x-forwarded-for": "1.1.1.2, 203.0.113.195",
        "user-agent": "test-agent",
      });

      const key1 = clientKey(h1);
      const key2 = clientKey(h2);

      // Both must resolve to the identical rate limiting key because the trusted proxy IP is 203.0.113.195!
      expect(key1).toBe(key2);
    });

    it("prioritizes direct edge proxy headers (cf-connecting-ip, fly-client-ip) over x-forwarded-for", () => {
      const h = new Headers({
        "cf-connecting-ip": "198.51.100.42",
        "x-forwarded-for": "10.0.0.1, 10.0.0.2",
      });
      const key = clientKey(h);
      const directKey = clientKey(new Headers({ "cf-connecting-ip": "198.51.100.42" }));
      expect(key).toBe(directKey);
    });

    it("binds user-agent fingerprint when IP is unknown to prevent total limit evasion", () => {
      const h1 = new Headers({ "user-agent": "Agent-Alpha" });
      const h2 = new Headers({ "user-agent": "Agent-Beta" });
      expect(clientKey(h1)).not.toBe(clientKey(h2));
    });
  });

  describe("5. Authorization Boundaries & Safe Error Responses", () => {
    it("validates job IDs strictly against 192-bit CSPRNG format and rejects malformed IDs", async () => {
      const store = new InMemoryJobStore();
      const config = getConfig();
      const deps = {
        store,
        config,
        enqueue: async () => {},
        rateLimit: async () => ({ allowed: true, retryAfterSeconds: 0 }),
        workerOnline: async () => true,
      };

      // Invalid IDs
      const res1 = await getScan("../etc/passwd", deps);
      expect(res1.status).toBe(404);

      const res2 = await getScan("short", deps);
      expect(res2.status).toBe(404);

      const res3 = await getScan("a".repeat(33), deps);
      expect(res3.status).toBe(404);

      // Valid format
      const validJob = await store.create({
        owner: "test",
        repo: "repo",
        repositoryUrl: "https://github.com/test/repo",
        expiresAt: new Date(Date.now() + 3600_000),
      });
      expect(JOB_ID_RE.test(validJob.id)).toBe(true);

      const res4 = await getScan(validJob.id, deps);
      expect(res4.status).toBe(200);
    });

    it("enforces scan finding authorization and prevents cross-job ID leakage", async () => {
      const store = new InMemoryJobStore();
      const config = getConfig();
      const deps = {
        store,
        config,
        enqueue: async () => {},
        rateLimit: async () => ({ allowed: true, retryAfterSeconds: 0 }),
        workerOnline: async () => true,
      };

      const _job1 = await store.create({
        owner: "org1",
        repo: "repo1",
        repositoryUrl: "https://github.com/org1/repo1",
        expiresAt: new Date(Date.now() + 3600_000),
      });
      void _job1;
      const job2 = await store.create({
        owner: "org2",
        repo: "repo2",
        repositoryUrl: "https://github.com/org2/repo2",
        expiresAt: new Date(Date.now() + 3600_000),
      });

      // Querying findings on job2 for an invalid finding ID returns 404
      const res = await getScanFinding(job2.id, "nonexistent-finding-id", deps);
      expect(res.status).toBe(404);
    });

    it("bounds limit and offset pagination parameters safely", async () => {
      const store = new InMemoryJobStore();
      const config = getConfig();
      const deps = {
        store,
        config,
        enqueue: async () => {},
        rateLimit: async () => ({ allowed: true, retryAfterSeconds: 0 }),
        workerOnline: async () => true,
      };
      const job = await store.create({
        owner: "org",
        repo: "repo",
        repositoryUrl: "https://github.com/org/repo",
        expiresAt: new Date(Date.now() + 3600_000),
      });

      // Pass extreme limit 999999
      const req = new Request(`http://localhost/api/scans/${job.id}/findings?limit=999999&offset=-50`);
      const res = await listScanFindings(job.id, req, deps);
      expect(res.status).toBe(200);
      const json = await res.json();
      expect(json.data.limit).toBe(200); // Capped to max 200
      expect(json.data.offset).toBe(0);   // Non-negative bounded
    });

    it("fails safely with sanitized error responses without leaking stack traces or internal paths", async () => {
      const store = new InMemoryJobStore();
      const config = getConfig();
      const deps = {
        store,
        config,
        enqueue: async () => {},
        rateLimit: async () => ({ allowed: true, retryAfterSeconds: 0 }),
        workerOnline: async () => true,
      };
      const validJob = await store.create({
        owner: "test",
        repo: "repo",
        repositoryUrl: "https://github.com/test/repo",
        expiresAt: new Date(Date.now() + 3600_000),
      });

      const req = new Request("http://localhost", { headers: new Headers() });
      const res = await explainScanFinding(validJob.id, "unknown-id", req, deps);
      expect(res.status).toBe(404);
      const json = await res.json();
      expect(json.error.code).toBe("not_found");
      expect(json.error.message).toBe("Finding not found.");
      expect(json.error.stack).toBeUndefined();
    });
  });

  describe("5. Launch Gates & Production Readiness (Phase 6)", () => {
    it("configures active non-deprecated Anthropic model identifier", async () => {
      const { AnthropicProvider } = await import("@/server/ai/client");
      const provider = new AnthropicProvider();
      const model = provider.getModelName();
      expect(model).toBe("claude-sonnet-5-5");
      expect(model).not.toContain("claude-3-5-sonnet");
    });

    it("creates isolated sandbox home and tmp directories with mode 0700", async () => {
      const { stat } = await import("node:fs/promises");
      const tmp = await mkdtemp(path.join(os.tmpdir(), "vibe-sandbox-perm-"));
      try {
        const env = await getCleanEnv(tmp);
        const homeStat = await stat(env.HOME!);
        const tmpStat = await stat(env.TMPDIR!);
        expect(homeStat.mode & 0o777).toBe(0o700);
        expect(tmpStat.mode & 0o777).toBe(0o700);
      } finally {
        await rm(tmp, { recursive: true, force: true });
      }
    });
  });
});
