// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { RemediationPanel } from "@/components/report/remediation-panel";
import type { PublicFinding, PublicRemediation } from "@/lib/scan-client";

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
  pullRequest: { availability: "enabled" },
  createdAt: "2026-10-28T11:54:00.000Z",
  updatedAt: "2026-10-28T11:54:08.000Z",
  ...over,
});

function stubApi(list: PublicRemediation[], pr?: { status: number; body: unknown }) {
  const calls: string[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init?: RequestInit) => {
      calls.push(`${init?.method ?? "GET"} ${url}`);
      if (url.endsWith("/pr")) return new Response(JSON.stringify(pr!.body), { status: pr!.status });
      return new Response(JSON.stringify({ data: list }), { status: 200 });
    }),
  );
  return calls;
}

describe("Auto-Fix pull request UI", () => {
  it("restores a verified fix and its PR after a reload instead of offering a new preview", async () => {
    stubApi([
      remediation({
        branchName: "vibeshield/fix-x",
        pullRequestUrl: "https://github.com/samarth-khera/FraudAi/pull/10",
        pullRequest: { availability: "enabled", status: "created", number: 10, url: "https://github.com/samarth-khera/FraudAi/pull/10", branch: "vibeshield/fix-x", baseBranch: "main", state: "open" },
      }),
    ]);
    render(<RemediationPanel jobId="job1" finding={finding} mode="autofix" />);
    expect(await screen.findByText("Pull request #10 created")).toBeTruthy();
    expect(screen.queryByText("Preview Proposed Patch")).toBeNull();
    expect(screen.getByText("Persistent warm scanner worker")).toBeTruthy();
    expect(screen.getByText(/View pull request on GitHub/).closest("a")!.getAttribute("href")).toBe(
      "https://github.com/samarth-khera/FraudAi/pull/10",
    );
  });

  it("shows 'GitHub authorization required' with no PR button when the deployment has no write credential", async () => {
    stubApi([remediation({ pullRequest: { availability: "not_configured" } })]);
    render(<RemediationPanel jobId="job1" finding={finding} mode="autofix" />);
    expect(await screen.findByText("GitHub authorization required")).toBeTruthy();
    expect(screen.queryByText("Open GitHub Pull Request")).toBeNull();
    expect(screen.getByText("Download .patch File")).toBeTruthy();
  });

  it("offers no PR for a fix that did not pass verification", async () => {
    stubApi([remediation({ status: "needs_review", rescanStatus: "needs_review" })]);
    render(<RemediationPanel jobId="job1" finding={finding} mode="autofix" />);
    expect(await screen.findByText(/only offered for fixes that passed the security rescan/)).toBeTruthy();
    expect(screen.queryByText("Open GitHub Pull Request")).toBeNull();
  });

  it("never shows 'created' when GitHub refused, and offers a retry with the real reason", async () => {
    const calls = stubApi([remediation()], {
      status: 403,
      body: { error: { code: "access_denied", message: "The server's GitHub credential cannot write to this repository." } },
    });
    render(<RemediationPanel jobId="job1" finding={finding} mode="autofix" />);
    fireEvent.click(await screen.findByText("Open GitHub Pull Request"));
    expect(await screen.findByText(/Creation failed — Repository access denied/)).toBeTruthy();
    expect(screen.getByText(/cannot write to this repository/)).toBeTruthy();
    expect(screen.queryByText(/Pull request #/)).toBeNull();
    expect(screen.getByText("Retry Pull Request")).toBeTruthy();
    await waitFor(() => expect(calls.filter((c) => c.startsWith("POST")).length).toBe(1));
  });
});
