"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import {
  ApiRequestError,
  TERMINAL_STATUSES,
  fetchScan,
  retryScan as apiRetry,
  submitScan,
  type PublicScanJob,
} from "@/lib/scan-client";

export type ScanFlow =
  | { phase: "idle" }
  | { phase: "validating" }
  | { phase: "error"; message: string; code?: string }
  | { phase: "job"; job: PublicScanJob; stale: boolean; pollError: boolean };

const POLL_FAST_MS = 1500;
const POLL_SLOW_MS = 3500;
const FAST_POLLS = 10;
const STALE_AFTER_MS = 5 * 60_000;
const MAX_POLL_FAILURES = 3;

/** Owns submit → poll → terminal lifecycle. Polling stops on terminal state, unmount or reset. */
export function useScanJob() {
  const [flow, setFlow] = useState<ScanFlow>({ phase: "idle" });
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const runId = useRef(0);

  const stop = useCallback(() => {
    runId.current++;
    if (timer.current) clearTimeout(timer.current);
    timer.current = null;
  }, []);

  useEffect(() => stop, [stop]);

  const pollRef = useRef<(id: string, startedAt: number, count: number, failures: number, myRun: number) => void>(() => {});

  const poll = useCallback((id: string, startedAt: number, count: number, failures: number, myRun: number) => {
    timer.current = setTimeout(async () => {
      if (myRun !== runId.current) return;
      try {
        const job = await fetchScan(id);
        if (myRun !== runId.current) return;
        const stale = Date.now() - startedAt > STALE_AFTER_MS;
        setFlow({ phase: "job", job, stale, pollError: false });
        if (TERMINAL_STATUSES.has(job.status)) return;
        pollRef.current(id, startedAt, count + 1, 0, myRun);
      } catch (e) {
        if (myRun !== runId.current) return;
        if (e instanceof ApiRequestError && e.status === 404) {
          setFlow({ phase: "error", message: "This scan job no longer exists. Submit the repository again." });
          return;
        }
        const next = failures + 1;
        setFlow((f) => (f.phase === "job" ? { ...f, pollError: next >= MAX_POLL_FAILURES } : f));
        if (next < MAX_POLL_FAILURES) pollRef.current(id, startedAt, count + 1, next, myRun);
      }
    }, count < FAST_POLLS ? POLL_FAST_MS : POLL_SLOW_MS);
  }, []);

  useEffect(() => {
    pollRef.current = poll;
  }, [poll]);

  const submit = useCallback(
    async (url: string) => {
      stop();
      const myRun = runId.current;
      setFlow({ phase: "validating" });
      try {
        const job = await submitScan(url);
        if (myRun !== runId.current) return;
        setFlow({ phase: "job", job, stale: false, pollError: false });
        poll(job.id, Date.now(), 0, 0, myRun);
      } catch (e) {
        if (myRun !== runId.current) return;
        const err = e instanceof ApiRequestError ? e : null;
        setFlow({ phase: "error", message: err?.message ?? "Something went wrong. Please try again.", code: err?.code });
      }
    },
    [poll, stop],
  );

  const retry = useCallback(
    async (id: string) => {
      stop();
      const myRun = runId.current;
      try {
        const job = await apiRetry(id);
        if (myRun !== runId.current) return;
        setFlow({ phase: "job", job, stale: false, pollError: false });
        poll(id, Date.now(), 0, 0, myRun);
      } catch (e) {
        if (myRun !== runId.current) return;
        setFlow({ phase: "error", message: e instanceof ApiRequestError ? e.message : "Retry failed. Please try again." });
      }
    },
    [poll, stop],
  );

  /** Resume polling after the poller gave up (e.g. network blip). */
  const recheck = useCallback(
    (id: string) => {
      stop();
      const myRun = runId.current;
      setFlow((f) => (f.phase === "job" ? { ...f, pollError: false } : f));
      poll(id, Date.now(), 0, 0, myRun);
    },
    [poll, stop],
  );

  const reset = useCallback(() => {
    stop();
    setFlow({ phase: "idle" });
  }, [stop]);

  const setClientError = useCallback((message: string) => {
    stop();
    setFlow({ phase: "error", message });
  }, [stop]);

  return { flow, submit, retry, recheck, reset, setClientError };
}
