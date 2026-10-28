// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { RemediationPanel } from "@/components/report/remediation-panel";
import type { GithubStatus, PublicFinding, PublicRemediation } from "@/lib/scan-client";
import { createHash } from "node:crypto";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const finding = {
  id: "f1",
  fingerprint: "fp-1",
  scanner: "osv-scanner",
  ruleId: "GHSA-6w46-j5rx-g56g",
  category: "Dependencies",
  severity: "medium",
  title: "pytest has vulnerable tmpdir handling",
  description: "",
  filePath: "backend/requirements.txt",
  startLine: null,
  endLine: null,
  redactedEvidence: null,
  vulnerabilityId: "CVE-2025-71176",
  remediation: "Upgrade pytest to version 9.0.3 or higher.",
  packageInfo: { name: "pytest", version: "8.0", ecosystem: "PyPI", fixedVersion: "9.0.3" },
} as unknown as PublicFinding;

const remediation = (over: Partial<PublicRemediation> = {}): PublicRemediation => ({
  id: "3daa6a28-d133-472e-9a2c-a9f2041fb879",
  scanJobId: "job1",
  status: "verified",
  findingFingerprints: ["fp-1"],
  commitSha: "69581cd57ffd089cda3aeb3b8325cd60dbfb212c",
  patchSummary: "Bump pytest",
  unifiedDiff: "--- a/backend/requirements.txt\n+++ b/backend/requirements.txt\n@@ -5,1 +5,1 @@\n-pytest>=8.0\n+pytest==9.0.3\n",
  affectedFiles: ["backend/requirements.txt"],
  eligibility: "potentially_breaking",
  eligibilityReason: "Major version bump",
  requiresRotation: false,
  warnings: [],
  approvedAt: "2026-10-28T11:54:01.000Z",
  rescanStatus: "verified",
  rescanSummary: {
    targetResolved: true,
    originalFindingsCount: 8,
    postRescanFindingsCount: 6,
    newFindingsCount: 0,
    resolvedFingerprints: ["fp-1"],
    remainingFingerprints: [],
    regressions: [],
    runtime: "warm-worker",
    scannerStatuses: { gitleaks: "completed", semgrep: "completed", osvScanner: "completed" },
  },
  branchName: null,
  pullRequestUrl: null,
  pullRequest: null,
  createdAt: "2026-10-28T11:54:00.000Z",
  updatedAt: "2026-10-28T11:54:08.000Z",
  ...over,
});

const links = {
  connect: "/api/auth/github/start?returnTo=%2Freport%2Fjob1%3Ffinding%3Df1%26mode%3Dautofix",
  install: "/api/auth/github/install?returnTo=%2Freport%2Fjob1%3Ffinding%3Df1%26mode%3Dautofix",
  manageInstallations: "https://github.com/settings/installations",
};
const ready: GithubStatus = {
  configured: true,
  connected: true,
  user: { login: "alice", avatarUrl: null },
  repository: {
    fullName: "samarth-khera/FraudAi",
    defaultBranch: "main",
    canRead: true,
    canPush: true,
    installed: true,
    appCanWrite: true,
    readyToWrite: true,
  },
  links,
};

function stubApi(list: PublicRemediation[], status: GithubStatus, pr?: { status: number; body: unknown }) {
  const calls: { method: string; url: string; body?: string }[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init?: RequestInit) => {
      calls.push({ method: init?.method ?? "GET", url, body: init?.body as string | undefined });
      if (url.startsWith("/api/auth/github/status")) return new Response(JSON.stringify({ data: status }), { status: 200 });
      if (url.endsWith("/pr")) return new Response(JSON.stringify(pr!.body), { status: pr!.status });
      return new Response(JSON.stringify({ data: list }), { status: 200 });
    }),
  );
  return calls;
}

const render_ = () => render(<RemediationPanel jobId="job1" finding={finding} mode="autofix" />);

describe("GitHub authorization and pull request UI", () => {
  it("says authorization is not configured and keeps the patch download", async () => {
    stubApi([remediation()], { configured: false, unavailableReason: "not_configured", connected: false, links });
    render_();
    expect(await screen.findByText("GitHub authorization is not configured yet")).toBeTruthy();
    expect(screen.queryByText(/Connect GitHub/)).toBeNull();
    expect(screen.queryByText(/create pull request/i)).toBeNull();
    expect(screen.getAllByText("Download .patch File").length).toBeGreaterThan(0);
  });

  it("offers the real GitHub connect flow when not connected, and no PR button", async () => {
    stubApi([remediation()], { configured: true, connected: false, links });
    render_();
    const connect = await screen.findByText("Connect GitHub");
    expect(connect.closest("a")!.getAttribute("href")).toBe(links.connect);
    expect(screen.getByText("GitHub not connected")).toBeTruthy();
    expect(screen.queryByText(/create pull request/i)).toBeNull();
  });

  it("asks to authorize the repository when the app is not installed, with the organization hint", async () => {
    stubApi([remediation()], {
      ...ready,
      repository: { ...ready.repository!, installed: false, appCanWrite: false, readyToWrite: false, reason: "not_installed", message: "Not installed." },
    });
    render_();
    const authorize = await screen.findByText("Authorize this repository");
    expect(authorize.closest("a")!.getAttribute("href")).toBe(links.install);
    expect(screen.getByText("Repository not authorized for VibeShield")).toBeTruthy();
    expect(screen.getByText(/organization owner may need to approve/)).toBeTruthy();
    expect(screen.queryByText(/create pull request/i)).toBeNull();
  });

  it("shows permission denied for a user without write access", async () => {
    stubApi([remediation()], {
      ...ready,
      repository: { ...ready.repository!, canPush: false, readyToWrite: false, reason: "no_push_permission", message: "No write access." },
    });
    render_();
    expect(await screen.findByText("Permission denied: no write access")).toBeTruthy();
    expect(screen.queryByText(/create pull request/i)).toBeNull();
  });

  it("requires confirming the exact diff, sends its SHA-256, and shows the PR only after GitHub confirms it", async () => {
    const created = remediation({
      branchName: "vibeshield/fix-x",
      pullRequestUrl: "https://github.com/samarth-khera/FraudAi/pull/10",
      pullRequest: {
        status: "created",
        message: "Pull request created on GitHub.",
        number: 10,
        url: "https://github.com/samarth-khera/FraudAi/pull/10",
        branch: "vibeshield/fix-x",
        baseBranch: "main",
        headSha: "cc992972ecb6",
        state: "open",
        openedBy: { githubUserId: 1001, login: "alice" },
        at: "2026-10-28T12:00:00Z",
      },
    });
    const calls = stubApi([remediation()], ready, { status: 201, body: { data: { remediation: created, pullRequest: created.pullRequest } } });
    render_();
    fireEvent.click(await screen.findByText("Review & create pull request"));
    const dialog = screen.getByRole("dialog", { name: "Create pull request" });
    expect(dialog.textContent).toContain("samarth-khera/FraudAi");
    expect(dialog.textContent).toContain("@alice via the VibeShield AI GitHub App");
    const create = screen.getByText("Create pull request", { selector: "button" }) as HTMLButtonElement;
    expect(create.closest("button")!.disabled).toBe(true);
    expect(screen.queryByText(/Pull request #10 created/)).toBeNull();
    fireEvent.click(screen.getByRole("checkbox", { name: /I approve publishing exactly this diff/ }));
    fireEvent.click(create);
    expect((await screen.findAllByText("Pull request #10 created")).length).toBeGreaterThan(0);
    const post = calls.find((c) => c.method === "POST")!;
    const expected = createHash("sha256").update(remediation().unifiedDiff).digest("hex");
    expect(JSON.parse(post.body!)).toEqual({ approvedDiffSha256: expected });
    expect(screen.getByText(/opened as @alice via the VibeShield AI GitHub App/)).toBeTruthy();
  });

  it("restores a verified fix and its PR after a reload instead of offering a new preview", async () => {
    stubApi(
      [
        remediation({
          pullRequestUrl: "https://github.com/samarth-khera/FraudAi/pull/10",
          pullRequest: {
            status: "exists",
            message: "exists",
            number: 10,
            url: "https://github.com/samarth-khera/FraudAi/pull/10",
            branch: "vibeshield/fix-x",
            baseBranch: "main",
            state: "open",
            at: "2026-10-28T12:00:00Z",
          },
        }),
      ],
      ready,
    );
    render_();
    expect((await screen.findAllByText("Pull request #10 already exists (open)")).length).toBeGreaterThan(0);
    expect(screen.queryByText("Preview Proposed Patch")).toBeNull();
    expect(screen.getByText("Persistent warm scanner worker")).toBeTruthy();
  });

  it("never shows 'created' when GitHub refused, and surfaces the real reason", async () => {
    stubApi([remediation()], ready, {
      status: 403,
      body: { error: { code: "access_denied", message: "GitHub refused the write with your authorization." } },
    });
    render_();
    fireEvent.click(await screen.findByText("Review & create pull request"));
    fireEvent.click(screen.getByRole("checkbox", { name: /I approve publishing exactly this diff/ }));
    fireEvent.click(screen.getByText("Create pull request", { selector: "button" }));
    expect(await screen.findByRole("alert")).toBeTruthy();
    expect(screen.getByRole("alert").textContent).toContain("Permission denied by GitHub");
    expect(screen.queryByText(/Pull request #/)).toBeNull();
  });

  it("offers no PR for a fix that did not pass verification", async () => {
    stubApi([remediation({ status: "needs_review", rescanStatus: "needs_review" })], ready);
    render_();
    expect(await screen.findByText(/Pull requests are only offered for verified fixes/)).toBeTruthy();
    expect(screen.queryByText(/create pull request/i)).toBeNull();
  });
});
