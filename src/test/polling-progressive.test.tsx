// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from "vitest";
import { act, cleanup, render, renderHook, screen } from "@testing-library/react";
import { useAdaptivePoll } from "@/lib/use-adaptive-poll";
import { RealReportView } from "@/components/report/real-report-view";

function setVisibility(state: "visible" | "hidden") {
  Object.defineProperty(document, "visibilityState", { configurable: true, get: () => state });
  document.dispatchEvent(new Event("visibilitychange"));
}

afterEach(() => {
  cleanup();
  vi.useRealTimers();
  vi.unstubAllGlobals();
  setVisibility("visible");
});

describe("useAdaptivePoll", () => {
  it("never overlaps requests, even when a response is slower than the interval", async () => {
    vi.useFakeTimers();
    let inFlight = 0;
    let maxInFlight = 0;
    let calls = 0;
    const poll = vi.fn(async () => {
      calls++;
      inFlight++;
      maxInFlight = Math.max(maxInFlight, inFlight);
      await new Promise((r) => setTimeout(r, 5000)); // delayed response
      inFlight--;
      return calls < 4;
    });
    renderHook(() => useAdaptivePoll(poll, true, { initialMs: 100, maxMs: 200 }));
    await act(async () => {
      await vi.advanceTimersByTimeAsync(60_000);
    });
    expect(maxInFlight).toBe(1);
    expect(poll).toHaveBeenCalledTimes(4); // stopped at the terminal answer
  });

  it("slows down while hidden and polls immediately when the tab becomes visible again", async () => {
    vi.useFakeTimers();
    const poll = vi.fn(async () => true);
    renderHook(() => useAdaptivePoll(poll, true, { initialMs: 1000, maxMs: 1000, hiddenMs: 30_000 }));
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });
    expect(poll).toHaveBeenCalledTimes(1);

    setVisibility("hidden");
    await act(async () => {
      await vi.advanceTimersByTimeAsync(1000); // the poll scheduled while visible
    });
    const afterHidden = poll.mock.calls.length;
    await act(async () => {
      await vi.advanceTimersByTimeAsync(20_000); // hidden: no poll within 30 s
    });
    expect(poll.mock.calls.length).toBe(afterHidden);

    setVisibility("visible");
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });
    expect(poll.mock.calls.length).toBe(afterHidden + 1);
  });

  it("stops at a terminal state and ignores visibility changes afterwards", async () => {
    vi.useFakeTimers();
    const poll = vi.fn(async () => false);
    renderHook(() => useAdaptivePoll(poll, true, { initialMs: 100 }));
    await act(async () => {
      await vi.advanceTimersByTimeAsync(10_000);
    });
    setVisibility("hidden");
    setVisibility("visible");
    await act(async () => {
      await vi.advanceTimersByTimeAsync(10_000);
    });
    expect(poll).toHaveBeenCalledTimes(1);
  });

  it("clears timers and schedules nothing after unmount, even if a response arrives late", async () => {
    vi.useFakeTimers();
    let resolve!: (v: boolean) => void;
    const poll = vi.fn(() => new Promise<boolean>((r) => (resolve = r)));
    const { unmount } = renderHook(() => useAdaptivePoll(poll, true, { initialMs: 100 }));
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });
    unmount();
    resolve(true); // late response
    await act(async () => {
      await vi.advanceTimersByTimeAsync(60_000);
    });
    expect(poll).toHaveBeenCalledTimes(1);
    expect(vi.getTimerCount()).toBe(0);
  });
});

const JOB_ID = "p".repeat(32);
const scanner = (status: string | null, durationMs: number | null = null) => ({ status, durationMs, error: null });

function scanningJob(revision: number, gitleaks: string | null) {
  return {
    id: JOB_ID,
    status: "scanning",
    repository: { owner: "octocat", name: "demo", url: "https://github.com/octocat/demo", defaultBranch: "main", commitSha: "c".repeat(40), description: null, sizeKb: null, stars: null, language: null },
    retrieval: { fileCount: 10, unpackedBytes: 100, archiveBytes: 50 },
    scanners: { gitleaks: scanner(gitleaks, gitleaks ? 400 : null), semgrep: scanner("running"), osvScanner: scanner("running") },
    scannerVersions: null,
    scanCoverage: { progress: { phase: "scanning", worker_startedAt: new Date().toISOString(), scanningAt: new Date().toISOString(), revision } },
    summary: null,
    failure: null,
    retryable: false,
    scanPerformed: false,
    workerOnline: null,
    queue: null,
    executor: "warm-worker",
    createdAt: new Date(Date.now() - 5000).toISOString(),
    updatedAt: new Date().toISOString(),
    startedAt: new Date().toISOString(),
    completedAt: null,
    expiresAt: new Date(Date.now() + 86400_000).toISOString(),
  };
}

describe("Progressive report", () => {
  it("shows findings from a finished scanner while others run, labelled partial, and refetches only on new revisions", async () => {
    const findingsCalls: string[] = [];
    let jobState = scanningJob(1, "completed");
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) => {
        if (url.includes("/findings")) {
          findingsCalls.push(url);
          return Response.json({
            data: {
              jobId: JOB_ID,
              status: "scanning",
              total: 1,
              limit: 200,
              offset: 0,
              findings: [
                {
                  id: "f1", fingerprint: "fp", scanner: "gitleaks", ruleId: "github-pat", category: "Secrets", severity: "critical",
                  title: "Secret detected: GitHub token", description: "d", filePath: "config/settings.txt", startLine: 1, endLine: 1,
                  redactedEvidence: "REDACTED", vulnerabilityId: null, remediation: null, createdAt: new Date().toISOString(),
                },
              ],
            },
          });
        }
        return Response.json({ data: jobState });
      }),
    );
    render(<RealReportView jobId={JOB_ID} />);

    expect(await screen.findByText(/Secret detected: GitHub token/)).toBeTruthy();
    expect(screen.getByText(/PARTIAL — SCAN STILL RUNNING/)).toBeTruthy();
    expect(screen.getByText(/Findings so far/)).toBeTruthy();
    expect(screen.getByText(/Gitleaks completed/)).toBeTruthy();
    expect(screen.getAllByText(/Semgrep running/).length).toBeGreaterThan(0);
    expect(screen.queryByText(/No Security Findings Detected/)).toBeNull();
    expect(findingsCalls).toHaveLength(1);

    // Same revision on the next poll: no findings refetch.
    await act(async () => {
      await new Promise((r) => setTimeout(r, 1700));
    });
    expect(findingsCalls).toHaveLength(1);

    // A new scanner result bumps the revision: exactly one more fetch.
    jobState = scanningJob(2, "completed");
    await act(async () => {
      await new Promise((r) => setTimeout(r, 2500));
    });
    expect(findingsCalls).toHaveLength(2);
  });

  it("never shows the clean state while scanners are still running", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) =>
        url.includes("/findings")
          ? Response.json({ data: { jobId: JOB_ID, status: "scanning", total: 0, limit: 200, offset: 0, findings: [] } })
          : Response.json({ data: scanningJob(1, "completed") }),
      ),
    );
    render(<RealReportView jobId={JOB_ID} />);
    expect(await screen.findByText(/No findings yet — scan still running/)).toBeTruthy();
    expect(screen.queryByText(/No Security Findings Detected/)).toBeNull();
  });
});
