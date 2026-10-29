// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { RemediationPanel } from "@/components/report/remediation-panel";
import type { GithubStatus, PublicFinding, PublicRemediation, RepositoryAuthorizationState } from "@/lib/scan-client";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const finding = {
  id: "f1",
  fingerprint: "fp-1",
  scanner: "osv-scanner",
  ruleId: "GHSA-q7qp-rjg7-q26m",
  category: "Dependencies",
  severity: "high",
  title: "multer vulnerable to Denial of Service",
  description: "",
  filePath: "backend/package-lock.json",
  startLine: null,
  endLine: null,
  redactedEvidence: null,
  vulnerabilityId: "CVE-2026-113872",
  remediation: "Upgrade multer to version 2.5.0 or higher.",
  packageInfo: { name: "multer", version: "2.0.2", ecosystem: "npm", fixedVersion: "2.5.0" },
} as unknown as PublicFinding;

const links = { connect: "/api/auth/github/start?x", install: "/api/auth/github/install?returnTo=%2Freport%2Fjob1", manageInstallations: "https://github.com/settings/installations" };
const SETTINGS = "https://github.com/settings/installations/176245393";

const statusFor = (state: RepositoryAuthorizationState, over: Partial<NonNullable<GithubStatus["repository"]>> = {}): GithubStatus => ({
  configured: true,
  connected: true,
  user: { login: "alice", avatarUrl: null },
  repository: {
    fullName: "samarth-khera/Job-portal",
    defaultBranch: "main",
    canRead: true,
    canPush: true,
    installed: state === "authorized",
    appCanWrite: state === "authorized",
    readyToWrite: state === "authorized",
    ...(state === "authorized" ? {} : { reason: "not_installed" as const, message: "Not authorized yet." }),
    id: 1106558267,
    ownerType: "User",
    canAdmin: true,
    authorization: { state, message: `message for ${state}`, installationId: 176245393, installationAccount: "samarth-khera", installationSettingsUrl: SETTINGS },
    ...over,
  },
  links,
});

const PREPARED = {
  state: "authorization_required",
  message: "x",
  repository: { id: 1106558267, fullName: "samarth-khera/Job-portal", defaultBranch: "main", isPrivate: false, ownerType: "User", canPush: true, canAdmin: true },
  installation: { id: 176245393, account: "samarth-khera", repositorySelection: "selected" },
  scannedCommit: "7f90143a47c6280f6bcf9d55bb7c4767a48c1542",
  links: { install: links.install, installationSettings: SETTINGS },
  request: { intent: "I".repeat(43), expiresAt: "2026-10-30T12:10:00Z" },
};

type Reply = { status: number; body: unknown };
function stub(statuses: GithubStatus[], replies: { prepare?: Reply; confirm?: Reply } = {}, list: PublicRemediation[] = []) {
  const calls: { method: string; url: string; body?: Record<string, unknown> }[] = [];
  let n = 0;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init?: RequestInit) => {
      const body = init?.body ? JSON.parse(String(init.body)) : undefined;
      calls.push({ method: init?.method ?? "GET", url, body });
      if (url.startsWith("/api/auth/github/status")) {
        const s = statuses[Math.min(n++, statuses.length - 1)];
        return new Response(JSON.stringify({ data: s }), { status: 200 });
      }
      if (url.endsWith("/repository-authorization")) {
        const r = body.action === "prepare" ? replies.prepare : body.action === "confirm" ? replies.confirm : { status: 200, body: { data: { cancelled: true } } };
        return new Response(JSON.stringify(r!.body), { status: r!.status });
      }
      return new Response(JSON.stringify({ data: list }), { status: 200 });
    }),
  );
  return calls;
}
const authorizationCalls = (calls: ReturnType<typeof stub>) => calls.filter((c) => c.url.endsWith("/repository-authorization")).map((c) => c.body!.action);

const render_ = () => render(<RemediationPanel jobId="job1" finding={finding} mode="autofix" />);

describe("repository access in Auto-Fix", () => {
  it("authorizes exactly the shown repository after explicit confirmation, and shows success only once GitHub confirms", async () => {
    const calls = stub([statusFor("authorization_required"), statusFor("authorized")], {
      prepare: { status: 200, body: { data: PREPARED } },
      confirm: { status: 200, body: { data: { ...PREPARED, state: "authorized", added: true, request: undefined } } },
    });
    render_();
    expect(await screen.findByText(/Repository authorization required/)).toBeTruthy();
    expect(screen.getByText(/Public scan available/)).toBeTruthy();
    expect(screen.queryByText(/^Repository authorized/)).toBeNull();

    fireEvent.click(screen.getByText("Authorize repository", { selector: "button" }));
    const dialog = await screen.findByRole("dialog", { name: "Authorize repository" });
    expect(dialog.textContent).toContain("Allow VibeShield AI to access this repository?");
    for (const text of ["samarth-khera/Job-portal", "1106558267", "main", "7f90143a47c6", "#176245393", "Never merge automatically", "never selects \"All repositories\"", "administrator"]) {
      expect(dialog.textContent).toContain(text);
    }
    // Nothing is sent to GitHub before the user confirms.
    expect(authorizationCalls(calls)).toEqual(["prepare"]);
    const confirm = screen.getAllByText("Authorize repository", { selector: "button" }).at(-1)!.closest("button")!;
    expect(confirm.disabled).toBe(true);
    fireEvent.click(screen.getByRole("checkbox", { name: /I authorize VibeShield AI to access only samarth-khera\/Job-portal/ }));
    fireEvent.click(confirm);

    expect(await screen.findByText(/GitHub now lists samarth-khera\/Job-portal in the VibeShield AI installation/)).toBeTruthy();
    expect(screen.getByText(/^Repository authorized/)).toBeTruthy();
    const sent = calls.find((c) => c.body?.action === "confirm")!.body;
    expect(sent).toEqual({ action: "confirm", intent: PREPARED.request.intent, repositoryId: 1106558267, installationId: 176245393 });
  });

  it("shows GitHub's refusal and the GitHub-managed path, never success", async () => {
    stub([statusFor("authorization_required")], {
      prepare: { status: 200, body: { data: PREPARED } },
      confirm: {
        status: 403,
        body: {
          error: { code: "organization_approval_required", message: "GitHub requires approval from an organization owner." },
          data: { state: "authorization_required", links: { installationSettings: SETTINGS } },
        },
      },
    });
    render_();
    fireEvent.click(await screen.findByText("Authorize repository", { selector: "button" }));
    await screen.findByRole("dialog", { name: "Authorize repository" });
    fireEvent.click(screen.getByRole("checkbox", { name: /I authorize VibeShield AI/ }));
    fireEvent.click(screen.getAllByText("Authorize repository", { selector: "button" }).at(-1)!);
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toContain("approval from an organization owner");
    expect(alert.querySelector("a")!.getAttribute("href")).toBe(SETTINGS);
    expect(screen.queryByText(/^Repository authorized/)).toBeNull();
  });

  it("cancelling discards the pending request without authorizing", async () => {
    const calls = stub([statusFor("authorization_required")], { prepare: { status: 200, body: { data: PREPARED } } });
    render_();
    fireEvent.click(await screen.findByText("Authorize repository", { selector: "button" }));
    await screen.findByRole("dialog", { name: "Authorize repository" });
    fireEvent.click(screen.getByText("Cancel"));
    await waitFor(() => expect(authorizationCalls(calls)).toEqual(["prepare", "cancel"]));
    expect(screen.queryByRole("dialog", { name: "Authorize repository" })).toBeNull();
  });

  it("explains insufficient permissions without offering authorization", async () => {
    stub([statusFor("admin_required", { canAdmin: false })]);
    render_();
    expect(await screen.findByText(/Insufficient repository permissions/)).toBeTruthy();
    expect(screen.getByText("message for admin_required")).toBeTruthy();
    expect(screen.queryByText("Authorize repository", { selector: "button" })).toBeNull();
  });

  it("points to the one-time app setup on GitHub when the permission is missing", async () => {
    stub([statusFor("app_setup_required")]);
    render_();
    expect(await screen.findByText(/One-time GitHub App setup required/)).toBeTruthy();
    expect(screen.getByText("Open the installation on GitHub").closest("a")!.getAttribute("href")).toBe(SETTINGS);
    expect(screen.queryByText("Authorize repository", { selector: "button" })).toBeNull();
  });

  it("asks to reconnect when the authorization expired or was revoked", async () => {
    stub([{ configured: true, connected: false, authorizationProblem: "authorization_revoked", links }]);
    render_();
    expect(await screen.findByText("Authorization expired or revoked")).toBeTruthy();
    expect(screen.getByText("Reconnect GitHub").closest("a")!.getAttribute("href")).toBe(links.connect);
  });

  it("shows the real branch, commit, changed files and GitHub's attribution for a created PR", async () => {
    const pr = {
      status: "created" as const,
      message: "Pull request created on GitHub.",
      number: 3,
      url: "https://github.com/samarth-khera/Job-portal/pull/3",
      branch: "vibeshield/fix-abc-123",
      baseBranch: "main",
      headSha: "abcdef1234567",
      state: "open" as const,
      openedBy: { githubUserId: 1, login: "alice" },
      commit: { sha: "abcdef1234567", authorName: "alice", authorLogin: "alice", authorEmailIsNoreply: true, verified: true },
      prAuthor: "alice",
      at: "2026-10-30T12:00:00Z",
    };
    const rem = {
      id: "3daa6a28-d133-472e-9a2c-a9f2041fb879",
      scanJobId: "job1",
      status: "verified",
      findingFingerprints: ["fp-1"],
      commitSha: "7f90143a47c6280f6bcf9d55bb7c4767a48c1542",
      patchSummary: "Upgrade multer",
      unifiedDiff: "--- a/backend/package.json\n+++ b/backend/package.json\n@@ -1,1 +1,1 @@\n-a\n+b\n",
      affectedFiles: ["backend/package.json", "backend/package-lock.json"],
      eligibility: "potentially_breaking",
      eligibilityReason: "x",
      requiresRotation: false,
      warnings: [],
      approvedAt: "2026-10-30T11:00:00Z",
      rescanStatus: "verified",
      rescanSummary: null,
      branchName: pr.branch,
      pullRequestUrl: pr.url,
      pullRequest: pr,
      createdAt: "2026-10-30T11:00:00Z",
      updatedAt: "2026-10-30T11:00:00Z",
    } as unknown as PublicRemediation;
    stub([statusFor("authorized")], {}, [rem]);
    render_();
    expect((await screen.findAllByText("Pull request #3 created")).length).toBeGreaterThan(0);
    expect(screen.getByText(/vibeshield\/fix-abc-123 → main · commit abcdef1/)).toBeTruthy();
    expect(screen.getByText("Changed files: backend/package.json, backend/package-lock.json")).toBeTruthy();
    expect(
      screen.getByText(
        /prepared this verified change on behalf of @alice\. GitHub recorded the commit as authored by alice \(@alice\), GitHub noreply address, signature verified\. Pull request author on GitHub: @alice\./,
      ),
    ).toBeTruthy();
    expect(screen.getByText("Branch, commit and pull request were read back from GitHub and match.")).toBeTruthy();
    expect(screen.getByText("View pull request on GitHub").closest("a")!.getAttribute("href")).toBe(pr.url);
  });
});
