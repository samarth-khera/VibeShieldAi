// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { RemediationPanel } from "@/components/report/remediation-panel";
import { findingFixStatus } from "@/lib/remediation-eligibility";
import type { GithubStatus, PublicFinding, PublicRemediation, RemediationPullRequest } from "@/lib/scan-client";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

const proxyAddr = {
  id: "cmvu0vp9v000ti708v1nuwqxr",
  fingerprint: "fp-proxy",
  scanner: "osv-scanner",
  ruleId: "GHSA-jqcg-44mw-7w3h",
  category: "Dependencies",
  severity: "critical",
  title: "proxy-addr vulnerable to IP spoofing via IPv4-mapped IPv6 trust subnet",
  description: "",
  filePath: "backend/package-lock.json",
  startLine: null,
  endLine: null,
  redactedEvidence: null,
  vulnerabilityId: "CVE-2026-90711",
  remediation: "Upgrade proxy-addr to version 2.0.8 or higher.",
  packageInfo: { name: "proxy-addr", version: "2.0.7", ecosystem: "npm", fixedVersion: "2.0.8" },
} as unknown as PublicFinding;

const links = { connect: "/api/auth/github/start?x", install: "/api/auth/github/install?x", manageInstallations: "https://github.com/settings/installations" };
const authorized: GithubStatus = {
  configured: true,
  connected: true,
  user: { login: "samarth-khera", avatarUrl: null },
  repository: {
    fullName: "samarth-khera/Job-portal",
    defaultBranch: "main",
    canRead: true,
    canPush: true,
    installed: true,
    appCanWrite: true,
    readyToWrite: true,
    id: 1106558267,
    ownerType: "User",
    canAdmin: true,
    authorization: { state: "authorized", message: "ok", installationId: 176245393, installationAccount: "samarth-khera" },
  },
  links,
};

const COMMIT = "7f90143a47c6280f6bcf9d55bb7c4767a48c1542";
const DIFF = "--- a/backend/package-lock.json\n+++ b/backend/package-lock.json\n@@ -1,3 +1,3 @@\n a\n-b\n+c\n d\n";
const rem = (over: Partial<PublicRemediation> = {}): PublicRemediation => ({
  id: "e2823631-314d-45a4-97b6-5798488788e9",
  scanJobId: "A-NZKPwxBNay-TeEZnpfGGpWYqlikg9p",
  status: "preview",
  findingFingerprints: ["fp-proxy"],
  commitSha: COMMIT,
  patchSummary: "Update proxy-addr 2.0.7 → 2.0.8",
  unifiedDiff: DIFF,
  affectedFiles: ["backend/package-lock.json"],
  eligibility: "potentially_breaking",
  eligibilityReason: "proxy-addr is not in package.json; express@5.1.0 (\"^2.0.7\") installs it.",
  requiresRotation: false,
  warnings: [],
  approvedAt: null,
  rescanStatus: null,
  rescanSummary: null,
  branchName: null,
  pullRequestUrl: null,
  pullRequest: null,
  verification: null,
  createdAt: "2026-10-29T20:57:42.714Z",
  updatedAt: "2026-10-29T20:57:42.714Z",
  ...over,
});
const UNSUITABLE = rem({
  eligibility: "unsuitable",
  unifiedDiff: "",
  eligibilityReason: "proxy-addr is not a direct dependency of this project, so it is only upgraded through its parent package. Manual review is required.",
});

/** Serves GitHub status, then each remediation list in turn (the last one repeats). */
function stub(lists: PublicRemediation[][], extra: (url: string, init?: RequestInit) => Response | null = () => null) {
  const calls: { method: string; url: string }[] = [];
  let i = 0;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init?: RequestInit) => {
      calls.push({ method: init?.method ?? "GET", url });
      const special = extra(url, init);
      if (special) return special;
      if (url.startsWith("/api/auth/github/status")) return new Response(JSON.stringify({ data: authorized }), { status: 200 });
      const list = lists[Math.min(i++, lists.length - 1)];
      return new Response(JSON.stringify({ data: list }), { status: 200 });
    }),
  );
  return calls;
}
const status = () => screen.findByTestId("workflow-status");
const render_ = (finding: PublicFinding = proxyAddr) => render(<RemediationPanel jobId="A-NZKPwxBNay-TeEZnpfGGpWYqlikg9p" finding={finding} mode="autofix" />);

describe("Auto-Fix status is truthful", () => {
  it("authorized repository + ineligible finding: shows the server's reason, no PR or approval, and can check again", async () => {
    const calls = stub([[UNSUITABLE]], (url, init) =>
      url.endsWith("/remediation/preview") && init?.method === "POST" ? new Response(JSON.stringify({ data: rem() }), { status: 201 }) : null,
    );
    render_();
    expect((await screen.findByText(/^Repository authorized/)).textContent).toContain("samarth-khera/Job-portal");
    expect((await status()).textContent).toContain("Status: Manual review required");
    const box = screen.getByTestId("manual-review");
    expect(box.textContent).toContain("proxy-addr is not a direct dependency of this project");
    expect(box.textContent).toContain("proxy-addr@2.0.7 (fixed in 2.0.8)");
    expect(box.textContent).toContain("7f90143a47c6");
    expect(box.textContent).toContain("Nothing was changed in the repository.");
    expect(screen.queryByText(/Approve Patch/)).toBeNull();
    expect(screen.queryByText(/create pull request/i)).toBeNull();

    fireEvent.click(within(box).getByText("Check again"));
    expect((await screen.findByText(/Preview ready — waiting for your explicit approval/))).toBeTruthy();
    expect(calls.filter((c) => c.method === "POST" && c.url.endsWith("/remediation/preview"))).toHaveLength(1);
  });

  it("authorized repository + eligible finding: authorization alone claims no fix; the preview waits for explicit approval", async () => {
    stub([[]]);
    render_();
    expect(await screen.findByText(/^Repository authorized/)).toBeTruthy();
    const s = await status();
    expect(s.textContent).toContain("Status: No fix generated yet");
    expect(s.textContent).toContain("Nothing runs until you generate the preview; eligibility is decided then, by the server.");
    expect(screen.getByTestId("engine-note").textContent).toMatch(/^No AI request: VibeShield's deterministic npm engine/);
    expect(screen.queryByText(/Security verification complete|Fix Verified|Pull request #/)).toBeNull();
    expect(screen.queryByText(/Pull request #/)).toBeNull();
    cleanup();

    stub([[rem()]]);
    render_();
    expect((await status()).textContent).toContain("Status: Preview ready — waiting for your explicit approval");
    const approve = (await screen.findByText("Approve, verify and open pull request")).closest("button")!;
    expect(approve.disabled).toBe(true); // until the reviewer ticks the box
  });

  it("names a finding that is not eligible before any preview, without offering one", async () => {
    stub([[]]);
    render_({ ...proxyAddr, packageInfo: { name: "proxy-addr", version: "2.0.7", ecosystem: "npm", fixedVersion: null } } as unknown as PublicFinding);
    expect((await status()).textContent).toContain("Status: Finding not eligible for automatic remediation");
    expect(screen.getByTestId("not-eligible").textContent).toContain("No upstream patched version");
    expect(screen.queryByText("Preview Proposed Patch")).toBeNull();
  });

  it("shows queued vs. running verification from the server's claim, with elapsed time", async () => {
    vi.useFakeTimers({ toFake: ["Date"], now: new Date("2026-10-30T10:00:30Z") });
    stub([[rem({ status: "applied", approvedAt: "2026-10-30T10:00:00Z", updatedAt: "2026-10-30T10:00:10Z", verification: { claimedAt: null, runtime: null } })]]);
    render_();
    expect((await status()).textContent).toContain("Applying patch in isolated verification environment (queued)");
    expect(screen.getByTestId("verification-running").textContent).toMatch(/Queued for an isolated verification worker…Waiting 20s/);
    cleanup();

    stub([[rem({ status: "applied", approvedAt: "2026-10-30T10:00:00Z", verification: { claimedAt: "2026-10-30T10:00:25Z", runtime: "github-actions" } })]]);
    render_();
    expect((await status()).textContent).toContain("Verification worker started");
    expect(screen.getByTestId("verification-running").textContent).toContain("GitHub Actions scanner worker started 5s ago");
    expect(screen.getByTestId("verification-running").textContent).toContain("after 15 minutes without a result it is marked as timed out");
  });

  it("reports a verification timeout as such", async () => {
    stub([
      [
        rem({
          status: "failed",
          approvedAt: "2026-10-30T10:00:00Z",
          rescanStatus: "failed",
          rescanSummary: { targetResolved: false, originalFindingsCount: 0, postRescanFindingsCount: 0, newFindingsCount: 0, resolvedFingerprints: [], remainingFingerprints: [], regressions: [], reason: "verification_timeout", detail: "x" },
        }),
      ],
    ]);
    render_();
    expect((await status()).textContent).toContain("Status: Verification timed out — nothing was verified");
    expect(screen.getByText(/Verification Timed Out — Nothing Was Verified/)).toBeTruthy();
  });

  it("after a reload, shows the stored publish step and follows it to the confirmed pull request", async () => {
    const verified = { status: "verified" as const, rescanStatus: "verified" as const, approvedAt: "2026-10-30T10:00:00Z" };
    const running: RemediationPullRequest = {
      status: "in_progress",
      step: "pushing_branch",
      message: "Creating and pushing the remediation branch.",
      branch: "vibeshield/fix-a-e2823631",
      openedBy: { githubUserId: 1, login: "samarth-khera" },
      at: new Date().toISOString(),
    };
    const created: RemediationPullRequest = {
      status: "created",
      message: "Pull request created on GitHub.",
      branch: "vibeshield/fix-a-e2823631",
      baseBranch: "main",
      headSha: "abc1234def5678",
      number: 7,
      url: "https://github.com/samarth-khera/Job-portal/pull/7",
      state: "open",
      openedBy: { githubUserId: 1, login: "samarth-khera" },
      prAuthor: "samarth-khera",
      commit: { sha: "abc1234def5678", authorName: "samarth khera", authorLogin: "samarth-khera", verified: true },
      at: new Date().toISOString(),
    };
    stub([[rem({ ...verified, pullRequest: running })], [rem({ ...verified, pullRequest: running })], [rem({ ...verified, pullRequest: created, pullRequestUrl: created.url! })]]);
    render_();
    const steps = await screen.findByRole("list", { name: "Authorization and fix status" });
    expect(steps.textContent).toContain("Creating and pushing branch");
    expect((await status()).textContent).toContain("Publishing the verified fix");
    expect((screen.getByText("Publishing…").closest("button") as HTMLButtonElement).disabled).toBe(true);
    // Polling picks up the confirmed result; nothing is claimed before it.
    expect(await screen.findByText("View pull request on GitHub", {}, { timeout: 4000 })).toBeTruthy();
    expect((await status()).textContent).toContain("Pull request #7 created");
    expect(screen.getByText(/Pull request author on GitHub: @samarth-khera/)).toBeTruthy();
  });

  it("treats a publish that stopped updating as interrupted and offers a safe retry", async () => {
    stub([
      [
        rem({
          status: "verified",
          rescanStatus: "verified",
          approvedAt: "2026-10-30T10:00:00Z",
          pullRequest: { status: "in_progress", step: "creating_commit", message: "m", branch: "b", at: new Date(Date.now() - 5 * 60_000).toISOString() },
        }),
      ],
    ]);
    render_();
    expect(await screen.findByText("Publishing was interrupted")).toBeTruthy();
    expect(screen.getByText(/Retrying is safe: it reuses the same branch and pull request/)).toBeTruthy();
    expect(screen.getByText(/Retry pull request/)).toBeTruthy();
  });

  it("names rate limiting and revoked authorization in the status", async () => {
    for (const [code, text] of [
      ["rate_limited", "GitHub rate limit reached — nothing was created"],
      ["credential_invalid", "GitHub authorization expired or revoked — nothing was created"],
    ] as const) {
      stub([[rem({ status: "verified", rescanStatus: "verified", approvedAt: "x", pullRequest: { status: "failed", code, message: "m", branch: "b", at: "2026-10-30T10:00:00Z" } })]]);
      render_();
      expect((await status()).textContent).toContain(text);
      cleanup();
    }
  });
});

describe("complete Auto-Fix interaction", () => {
  const generating = (stage: string, stages: string[]) =>
    rem({
      unifiedDiff: "",
      eligibilityReason: "Generating…",
      generation: { state: "running", stage: stage as never, engine: "npm", stages: stages.map((s) => ({ stage: s as never, at: new Date().toISOString() })), startedAt: new Date().toISOString(), at: new Date().toISOString() },
      createdAt: new Date().toISOString(),
    });

  it("clicking Preview sends one preview request for this finding and shows the server's stored steps while it runs", async () => {
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const posts: { url: string; body: unknown }[] = [];
    stub([[], [generating("validating_dependency_changes", ["checking_repository", "checking_eligibility", "generating_remediation", "validating_dependency_changes"])]], (url, init) => {
      if (url.endsWith("/remediation/preview") && init?.method === "POST") {
        posts.push({ url, body: JSON.parse(String(init.body)) });
        return null;
      }
      return null;
    });
    // The preview POST resolves only when released, like a slow server.
    const original = globalThis.fetch;
    vi.stubGlobal("fetch", async (url: string, init?: RequestInit) => {
      if (url.endsWith("/remediation/preview") && init?.method === "POST") {
        posts.push({ url, body: JSON.parse(String(init.body)) });
        await gate;
        return new Response(JSON.stringify({ data: rem({ eligibility: "safe", generation: { state: "done", engine: "npm", stages: [], startedAt: "x", at: "x" } }) }), { status: 201 });
      }
      return original(url, init);
    });
    render_();
    fireEvent.click(await screen.findByText("Preview Proposed Patch"));
    expect(posts).toEqual([{ url: "/api/scans/A-NZKPwxBNay-TeEZnpfGGpWYqlikg9p/remediation/preview", body: { findingId: proxyAddr.id } }]);
    const steps = await screen.findByTestId("generation-steps", {}, { timeout: 3000 });
    expect(steps.textContent).toContain("Checking finding eligibility");
    expect(steps.textContent).toContain("Validating dependency changes");
    expect((await status()).textContent).toContain("Validating dependency changes…");
    release();
    expect(await screen.findByText(/Preview ready — waiting for your explicit approval/)).toBeTruthy();
  });

  it("after a reload, an interrupted generation is reported as interrupted, not as running", async () => {
    stub([[{ ...generating("generating_remediation", ["checking_eligibility"]), generation: { ...generating("x", []).generation!, state: "running", at: "2026-10-01T00:00:00Z" } }]]);
    render_();
    expect((await status()).textContent).toContain("Fix generation was interrupted");
  });

  it("one explicit approval authorizes publishing and starts the full verification", async () => {
    const calls: { url: string; body?: string }[] = [];
    stub([[rem()]], (url, init) => {
      if (url.endsWith("/approve")) {
        calls.push({ url, body: String(init?.body) });
        return new Response(JSON.stringify({ data: rem({ status: "approved", approvedAt: "2026-10-30T10:00:00Z", publishAfterVerification: { login: "samarth-khera" } }) }), { status: 200 });
      }
      if (url.endsWith("/apply")) {
        calls.push({ url });
        return new Response(JSON.stringify({ data: rem({ status: "applied", approvedAt: "2026-10-30T10:00:00Z", verification: { claimedAt: null, runtime: null, progress: null } }) }), { status: 202 });
      }
      return null;
    });
    render_();
    const label = await screen.findByText(/I approve exactly this diff/);
    expect(label.textContent).toContain("opens a pull request in samarth-khera/Job-portal with my GitHub account (@samarth-khera)");
    expect(label.textContent).toContain("Nothing is merged and the default branch is not touched.");
    fireEvent.click(screen.getByRole("checkbox", { name: /I approve exactly this diff/ }));
    fireEvent.click(screen.getByText("Approve, verify and open pull request"));
    expect(await screen.findByTestId("verification-running")).toBeTruthy();
    expect(calls.map((c) => c.url.split("/").pop())).toEqual(["approve", "apply"]);
    expect(JSON.parse(calls[0].body!)).toEqual({ publish: true });
  });

  it("shows each scanner's real progress, then automatic publishing after a passed verification", async () => {
    stub([
      [
        rem({
          status: "applied",
          approvedAt: "x",
          verification: {
            claimedAt: new Date().toISOString(),
            runtime: "github-actions",
            progress: { stage: "scanning", scanners: { gitleaks: "completed", semgrep: "running", osvScanner: "completed" }, at: "x" },
          },
        }),
      ],
    ]);
    render_();
    expect((await status()).textContent).toContain("Running Gitleaks, Semgrep and OSV-Scanner (2 of 3 finished)");
    const steps = screen.getByTestId("verification-steps").textContent!;
    expect(steps).toContain("Running Gitleaks — completed");
    expect(steps).toContain("Running OSV-Scanner — completed");
    expect(steps).toMatch(/Running Semgrep(?! —)/);
    cleanup();

    stub([[rem({ status: "verified", rescanStatus: "verified", approvedAt: "x", publishAfterVerification: { login: "samarth-khera" } })]]);
    render_();
    expect((await status()).textContent).toContain("Security verification complete — creating the pull request automatically");
    expect(screen.queryByText("Review & create pull request")).toBeNull();
  });

  it("Safe Auto-Fix is off by default and needs an explicit, repository-specific confirmation", async () => {
    const bodies: unknown[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string, init?: RequestInit) => {
        if (url.startsWith("/api/auth/github/status")) {
          return new Response(JSON.stringify({ data: { ...authorized, repository: { ...authorized.repository!, safeAutoFix: { enabled: false, enabledBy: null, enabledAt: null, available: true } } } }), { status: 200 });
        }
        if (url.endsWith("/safe-autofix")) {
          bodies.push(JSON.parse(String(init?.body)));
          return new Response(JSON.stringify({ data: { enabled: true, enabledBy: "samarth-khera", enabledAt: "x", started: true } }), { status: 200 });
        }
        return new Response(JSON.stringify({ data: [] }), { status: 200 });
      }),
    );
    render_();
    const box = await screen.findByTestId("safe-autofix");
    expect(box.textContent).toContain("Safe Auto-Fix for samarth-khera/Job-portal: Off");
    expect(screen.getByTestId("authorized-details").textContent).toContain("Authorized account@samarth-khera");
    fireEvent.click(within(box).getByText("Enable Safe Auto-Fix…"));
    const dialog = await screen.findByRole("dialog", { name: "Enable Safe Auto-Fix" });
    expect(dialog.textContent).toContain("Potentially breaking upgrades, manual-review findings, secrets and AI-generated code changes are never processed automatically.");
    const enable = within(dialog).getByText("Enable Safe Auto-Fix").closest("button")!;
    expect(enable.disabled).toBe(true);
    expect(bodies).toEqual([]);
    fireEvent.click(within(dialog).getByRole("checkbox"));
    fireEvent.click(enable);
    expect(await screen.findByText(/Safe Auto-Fix is processing this scan's dependency findings/)).toBeTruthy();
    expect(bodies).toEqual([{ action: "enable", confirm: true, repositoryId: 1106558267 }]);
  });
});

describe("report badges use the server's decision", () => {
  it("does not count lockfile findings as eligible until the server has decided, then follows its decision", () => {
    expect(findingFixStatus(proxyAddr)).toMatchObject({ kind: "decided_on_preview", eligible: false, label: "Checked on Preview" });
    expect(findingFixStatus(proxyAddr, UNSUITABLE)).toMatchObject({ kind: "manual_review", eligible: false, reason: expect.stringContaining("not a direct dependency") });
    expect(findingFixStatus(proxyAddr, rem())).toMatchObject({ kind: "fix_ready", eligible: true });
    const requirements = { ...proxyAddr, filePath: "backend/requirements.txt", packageInfo: { name: "flask", version: "2.0.0", fixedVersion: "2.3.0" } } as unknown as PublicFinding;
    expect(findingFixStatus(requirements)).toMatchObject({ kind: "potentially_breaking", eligible: true });
  });
});
