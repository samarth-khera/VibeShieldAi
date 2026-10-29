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
    expect((await screen.findByTestId("workflow-status")).textContent).toMatch(/Status: (Generating remediation|Patch preview ready)/);
    expect((await screen.findByText(/Patch preview ready — waiting for your explicit approval/))).toBeTruthy();
    expect(calls.filter((c) => c.method === "POST" && c.url.endsWith("/remediation/preview"))).toHaveLength(1);
  });

  it("authorized repository + eligible finding: authorization alone claims no fix; the preview waits for explicit approval", async () => {
    stub([[]]);
    render_();
    expect(await screen.findByText(/^Repository authorized/)).toBeTruthy();
    const s = await status();
    expect(s.textContent).toContain("Status: No fix generated yet");
    expect(s.textContent).toContain("Eligibility is decided when the preview is generated.");
    expect(screen.queryByText(/verified/i)).toBeNull();
    expect(screen.queryByText(/Pull request #/)).toBeNull();
    cleanup();

    stub([[rem()]]);
    render_();
    expect((await status()).textContent).toContain("Status: Patch preview ready — waiting for your explicit approval");
    const approve = (await screen.findByText("Approve Patch")).closest("button")!;
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
    expect((await status()).textContent).toContain("Running Gitleaks, Semgrep and OSV-Scanner on the patched repository");
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

describe("report badges use the server's decision", () => {
  it("does not count lockfile findings as eligible until the server has decided, then follows its decision", () => {
    expect(findingFixStatus(proxyAddr)).toMatchObject({ kind: "decided_on_preview", eligible: false, label: "Checked on Preview" });
    expect(findingFixStatus(proxyAddr, UNSUITABLE)).toMatchObject({ kind: "manual_review", eligible: false, reason: expect.stringContaining("not a direct dependency") });
    expect(findingFixStatus(proxyAddr, rem())).toMatchObject({ kind: "fix_ready", eligible: true });
    const requirements = { ...proxyAddr, filePath: "backend/requirements.txt", packageInfo: { name: "flask", version: "2.0.0", fixedVersion: "2.3.0" } } as unknown as PublicFinding;
    expect(findingFixStatus(requirements)).toMatchObject({ kind: "potentially_breaking", eligible: true });
  });
});
