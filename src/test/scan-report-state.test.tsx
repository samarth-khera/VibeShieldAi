// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { RealReportView } from "@/components/report/real-report-view";
import { ScanStatusPanel } from "@/components/home/scan-status";
import { toPublicJob } from "@/server/api";
import { getConfig } from "@/server/config";
import { RetrievalError } from "@/server/errors";
import type { JobRecord } from "@/server/job-store";
import { executeScanJob } from "@/server/worker/scan-executor";
import type { PublicScanJob } from "@/lib/scan-client";

const JOB_ID = "r".repeat(32);
const NOW = new Date("2026-10-29T16:06:55.000Z");

function record(overrides: Partial<JobRecord>): JobRecord {
  return {
    id: JOB_ID,
    status: "queued",
    owner: "samarth-khera",
    repo: "FraudAi",
    repositoryUrl: "https://github.com/samarth-khera/FraudAi",
    defaultBranch: "main",
    commitSha: "8d76bcbc6c8c5ab89d8a0a21b71be38b6ced4e0d",
    description: null,
    repoSizeKb: null,
    stars: null,
    primaryLanguage: null,
    fileCount: null,
    unpackedBytes: null,
    archiveBytes: null,
    clientIpHash: null,
    attempts: 1,
    failureCategory: null,
    errorMessage: null,
    gitleaksStatus: null,
    gitleaksDurationMs: null,
    gitleaksError: null,
    semgrepStatus: null,
    semgrepDurationMs: null,
    semgrepError: null,
    osvStatus: null,
    osvDurationMs: null,
    osvError: null,
    scannerVersions: null,
    scanCoverage: null,
    criticalCount: null,
    highCount: null,
    mediumCount: null,
    lowCount: null,
    infoCount: null,
    workflowRunId: null,
    workflowRunUrl: null,
    createdAt: new Date(NOW.getTime() - 30_000),
    updatedAt: NOW,
    startedAt: new Date(NOW.getTime() - 29_000),
    completedAt: NOW,
    expiresAt: new Date(NOW.getTime() + 7 * 86400_000),
    ...overrides,
  } as JobRecord;
}

const allCompleted = {
  gitleaksStatus: "completed",
  semgrepStatus: "completed",
  osvStatus: "completed",
  criticalCount: 0,
  highCount: 0,
  mediumCount: 0,
  lowCount: 0,
  infoCount: 0,
} as const;

// The exact shape production stored for job RJ2D… (archive over the limit, reported before this fix).
const failedBeforeScanning = record({ status: "failed", failureCategory: "scan_failed", errorMessage: "rejected_by_limits:archive_too_large" });

describe("public job projection: what a report may claim", () => {
  it("a scan that failed before any scanner ran is `failed`, has no summary, and carries a safe reason", () => {
    const j = toPublicJob(failedBeforeScanning);
    expect(j.reportState).toBe("failed");
    expect(j.scanPerformed).toBe(false);
    expect(j.summary).toBeNull();
    expect(j.incompleteScanners).toEqual(["gitleaks", "semgrep", "osv-scanner"]);
    expect(j.failure).toEqual({ category: "archive_too_large", message: "The repository archive is larger than the scan size limit, so no scanner ran." });
  });

  it("passes structured failures through unchanged", () => {
    const j = toPublicJob(record({ status: "failed", failureCategory: "archive_too_large", errorMessage: "Repository archive exceeds the size limit." }));
    expect(j.failure).toEqual({ category: "archive_too_large", message: "Repository archive exceeds the size limit." });
  });

  it("an unknown legacy code gets a generic message instead of raw internals", () => {
    const j = toPublicJob(record({ status: "failed", failureCategory: "scan_failed", errorMessage: "download_failed:something_new" }));
    expect(j.failure).toEqual({ category: "something_new", message: "The scan failed before the scanners completed." });
  });

  it("completed_with_warnings is `partial` and names the scanners that did not finish", () => {
    const j = toPublicJob(record({ ...allCompleted, status: "completed_with_warnings", semgrepStatus: "failed" }));
    expect(j.reportState).toBe("partial");
    expect(j.incompleteScanners).toEqual(["semgrep"]);
  });

  it("a `completed` job whose scanner results are not all completed is still only `partial`", () => {
    const j = toPublicJob(record({ ...allCompleted, status: "completed", osvStatus: null }));
    expect(j.reportState).toBe("partial");
    expect(j.incompleteScanners).toEqual(["osv-scanner"]);
  });

  it("cancelled scans are `cancelled`; queued and scanning are `in_progress`", () => {
    expect(toPublicJob(record({ status: "cancelled" })).reportState).toBe("cancelled");
    expect(toPublicJob(record({ status: "queued", completedAt: null })).reportState).toBe("in_progress");
    expect(toPublicJob(record({ status: "scanning", completedAt: null })).reportState).toBe("in_progress");
  });

  it("only a scan where all three scanners completed is `complete`, and zero findings is then a real result", () => {
    const j = toPublicJob(record({ ...allCompleted, status: "completed" }));
    expect(j.reportState).toBe("complete");
    expect(j.incompleteScanners).toEqual([]);
    expect(j.summary).toEqual({ critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 });
  });
});

describe("worker reports limit failures with their real category", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("archive_too_large is posted as such with the safe public message, not as scan_failed", async () => {
    const posted: Record<string, unknown>[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string, init?: RequestInit) => {
        if (url === "https://api.github.com/repos/o/r") {
          return Response.json({ full_name: "o/r", private: false, visibility: "public", default_branch: "main", size: 10 });
        }
        if (url === "https://api.github.com/repos/o/r/commits/main") return new Response("b".repeat(40));
        posted.push(JSON.parse(String(init?.body)));
        return Response.json({ data: {} });
      }),
    );
    const outcome = await executeScanJob({
      jobId: "job1",
      repositoryUrl: "https://github.com/o/r",
      callbackUrl: "https://vs.example/api/scans/job1/callback",
      secret: "s",
      config: getConfig(),
      archives: async () => {
        throw new RetrievalError("rejected_by_limits", "archive_too_large", "Repository archive exceeds the size limit.");
      },
    });
    expect(outcome).toBe("failed");
    const failed = posted.find((p) => p.status === "failed")!;
    expect(failed.failureCategory).toBe("archive_too_large");
    expect(failed.errorMessage).toBe("Repository archive exceeds the size limit.");
  });

  it("unexpected errors are still reported as scan_failed", async () => {
    const posted: Record<string, unknown>[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string, init?: RequestInit) => {
        if (url === "https://api.github.com/repos/o/r") {
          return Response.json({ full_name: "o/r", private: false, visibility: "public", default_branch: "main", size: 10 });
        }
        if (url === "https://api.github.com/repos/o/r/commits/main") return new Response("b".repeat(40));
        posted.push(JSON.parse(String(init?.body)));
        return Response.json({ data: {} });
      }),
    );
    await executeScanJob({
      jobId: "job1",
      repositoryUrl: "https://github.com/o/r",
      callbackUrl: "https://vs.example/api/scans/job1/callback",
      secret: "s",
      config: getConfig(),
      archives: async () => {
        throw new Error("socket hang up");
      },
    });
    expect(posted.find((p) => p.status === "failed")!.failureCategory).toBe("scan_failed");
  });
});

/** Public JSON as the browser receives it. */
const asPublic = (r: JobRecord) => JSON.parse(JSON.stringify({ ...toPublicJob(r), viewer: { isOwner: true } }));

function serve(job: ReturnType<typeof asPublic>) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string) =>
      String(url).includes("/findings")
        ? Response.json({ data: { jobId: JOB_ID, status: job.status, total: 0, limit: 200, offset: 0, findings: [] } })
        : Response.json({ data: job }),
    ),
  );
}

describe("report page never presents an unscanned repository as clean", () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it("failed before scanning: failure state and reason, no verified badge, no zero tiles, scanners 'not run'", async () => {
    serve(asPublic(failedBeforeScanning));
    render(<RealReportView jobId={JOB_ID} />);
    expect(await screen.findByText(/SCAN FAILED — NOT SCANNED/)).toBeTruthy();
    expect(screen.queryByText(/VERIFIED SCAN REPORT/)).toBeNull();
    expect(screen.getByRole("alert").textContent).toMatch(/This repository was not scanned/);
    expect(screen.getByRole("alert").textContent).toMatch(/larger than the scan size limit/);
    expect(screen.getByRole("alert").textContent).toMatch(/archive_too_large/);
    expect(screen.getByRole("alert").textContent).toMatch(/This is not a clean result/);
    expect(screen.getByText("Not scanned")).toBeTruthy();
    expect(screen.queryByLabelText("Severity summary")).toBeNull();
    expect(screen.queryByText(/No Security Findings Detected/)).toBeNull();
    expect(screen.queryByText(/Verified Finding/)).toBeNull();
    expect(screen.getAllByText("not run")).toHaveLength(3);
    // A size-limit failure would fail the same way again, so no retry is offered.
    expect(screen.queryByText(/Retry Scan/)).toBeNull();
  });

  it("stays truthful after a reload (fresh mount, same API data)", async () => {
    serve(asPublic(failedBeforeScanning));
    const first = render(<RealReportView jobId={JOB_ID} />);
    await screen.findByText(/SCAN FAILED — NOT SCANNED/);
    first.unmount();
    render(<RealReportView jobId={JOB_ID} />);
    expect(await screen.findByText(/SCAN FAILED — NOT SCANNED/)).toBeTruthy();
    expect(screen.queryByText(/VERIFIED SCAN REPORT/)).toBeNull();
  });

  it("partially completed: partial badge, names the missing scanner, empty list is not called clean", async () => {
    serve(asPublic(record({ ...allCompleted, status: "completed_with_warnings", semgrepStatus: "failed" })));
    render(<RealReportView jobId={JOB_ID} />);
    expect(await screen.findByText(/PARTIAL SCAN — INCOMPLETE COVERAGE/)).toBeTruthy();
    expect(screen.queryByText(/VERIFIED SCAN REPORT/)).toBeNull();
    expect(screen.getByText(/Did not complete: semgrep/)).toBeTruthy();
    expect(screen.getByText(/No findings from the scanners that completed/)).toBeTruthy();
    expect(screen.queryByText(/No Security Findings Detected/)).toBeNull();
  });

  it("cancelled: cancelled state, nothing presented as scanned", async () => {
    serve(asPublic(record({ status: "cancelled" })));
    render(<RealReportView jobId={JOB_ID} />);
    expect(await screen.findByText(/SCAN CANCELLED — NOT SCANNED/)).toBeTruthy();
    expect(screen.getByRole("alert").textContent).toMatch(/cancelled before it finished/);
    expect(screen.queryByLabelText("Severity summary")).toBeNull();
  });

  it("a genuinely clean scan (all three scanners completed, zero findings) is still shown as verified and clean", async () => {
    serve(asPublic(record({ ...allCompleted, status: "completed", fileCount: 12 })));
    render(<RealReportView jobId={JOB_ID} />);
    expect(await screen.findByText(/VERIFIED SCAN REPORT/)).toBeTruthy();
    expect(screen.getByText(/No Security Findings Detected/)).toBeTruthy();
    expect(screen.getByLabelText("Severity summary")).toBeTruthy();
    expect(screen.queryByRole("alert")).toBeNull();
  });
});

describe("home status card", () => {
  afterEach(() => cleanup());
  const noop = () => undefined;
  const card = (job: PublicScanJob) =>
    render(<ScanStatusPanel job={job} stale={false} pollError={false} onRetry={noop} onRecheck={noop} onReset={noop} />);

  it("partial results with zero findings are not described as clean", () => {
    card(asPublic(record({ ...allCompleted, status: "completed_with_warnings", osvStatus: "failed" })));
    expect(screen.getByText(/Partial Scan — Incomplete Coverage/)).toBeTruthy();
    expect(screen.getByText(/Did not complete: osv-scanner/)).toBeTruthy();
    expect(screen.queryByText(/No Findings Detected/)).toBeNull();
    expect(screen.queryByText(/checked without hits/)).toBeNull();
  });

  it("a failed scan shows its safe reason", () => {
    card(asPublic(failedBeforeScanning));
    expect(screen.getByRole("alert").textContent).toMatch(/Scan failed: The repository archive is larger than the scan size limit/);
  });

  it("a complete clean scan is described as such", () => {
    card(asPublic(record({ ...allCompleted, status: "completed" })));
    expect(screen.getByText(/Scan Completed — No Findings Detected/)).toBeTruthy();
  });
});
