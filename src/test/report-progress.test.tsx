// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { RealReportView } from "@/components/report/real-report-view";

const JOB_ID = "j".repeat(32);

function job(overrides: Record<string, unknown>) {
  return {
    id: JOB_ID,
    status: "queued",
    repository: { owner: "octocat", name: "demo", url: "https://github.com/octocat/demo", defaultBranch: null, commitSha: null, description: null, sizeKb: null, stars: null, language: null },
    retrieval: null,
    scanners: {
      gitleaks: { status: null, durationMs: null, error: null },
      semgrep: { status: null, durationMs: null, error: null },
      osvScanner: { status: null, durationMs: null, error: null },
    },
    scannerVersions: null,
    scanCoverage: null,
    summary: null,
    failure: null,
    retryable: false,
    scanPerformed: false,
    workerOnline: true,
    createdAt: new Date(Date.now() - 9000).toISOString(),
    updatedAt: new Date().toISOString(),
    startedAt: null,
    completedAt: null,
    expiresAt: new Date(Date.now() + 86400_000).toISOString(),
    ...overrides,
  };
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("Report page while a scan is running", () => {
  it("renders worker progress heartbeats (scanCoverage with only `progress`) without crashing", async () => {
    const startedAt = new Date(Date.now() - 2000).toISOString();
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        Response.json({
          data: job({ scanCoverage: { progress: { phase: "worker_started", worker_startedAt: startedAt } } }),
        }),
      ),
    );
    render(<RealReportView jobId={JOB_ID} />);

    expect(await screen.findByText(/Runner started — preparing scanners/)).toBeTruthy();
    expect(screen.getByText(/Queue wait \d/)).toBeTruthy();
    expect(screen.getByText(/Worker active/)).toBeTruthy();
    expect(screen.queryByText(/Coverage:/)).toBeNull();
  });

  it("shows queue wait, setup and per-scanner timings separately once complete", async () => {
    const created = Date.now() - 60_000;
    const at = (ms: number) => new Date(created + ms).toISOString();
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) =>
        url.includes("/findings")
          ? Response.json({ data: { jobId: JOB_ID, status: "completed", total: 0, limit: 200, offset: 0, findings: [] } })
          : Response.json({
              data: job({
                status: "completed",
                scanPerformed: true,
                createdAt: at(0),
                completedAt: at(40_000),
                summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 },
                scanners: {
                  gitleaks: { status: "completed", durationMs: 120, error: null },
                  semgrep: { status: "completed", durationMs: 2800, error: null },
                  osvScanner: { status: "completed", durationMs: 700, error: null },
                },
                scanCoverage: {
                  scannersRun: ["gitleaks", "semgrep", "osv-scanner"],
                  lockfilesFound: [],
                  limitations: [],
                  stageDurations: { metadataMs: 300, downloadMs: 200, extractionMs: 100, scanningMs: 2900, callbackMs: 150 },
                  progress: { worker_startedAt: at(6_000), retrievingAt: at(30_000) },
                },
              }),
            }),
      ),
    );
    render(<RealReportView jobId={JOB_ID} />);
    expect(await screen.findByText(/Queue wait 6\.0s · Runner setup 24\.0s · Retrieval 500ms/)).toBeTruthy();
    expect(screen.getByText(/Semgrep 2\.8s/)).toBeTruthy();
  });
});
