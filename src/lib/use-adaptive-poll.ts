"use client";

import { useEffect, useRef } from "react";

export type AdaptivePollOptions = {
  /** Delay before the second poll; early phases change quickly. */
  initialMs?: number;
  /** Ceiling for the backoff during long queue waits. */
  maxMs?: number;
  /** Multiplier applied after each poll. */
  factor?: number;
  /** Delay used while the tab is hidden. */
  hiddenMs?: number;
};

/**
 * Calls `poll` until it returns false: immediately, then with exponential backoff. Polls slowly
 * while the tab is hidden and immediately when it becomes visible again. Pending timers are
 * cleared and late results ignored after unmount or when `enabled` turns false.
 */
export function useAdaptivePoll(
  poll: () => Promise<boolean>,
  enabled: boolean,
  { initialMs = 1500, maxMs = 8000, factor = 1.5, hiddenMs = 30_000 }: AdaptivePollOptions = {},
): void {
  const pollRef = useRef(poll);
  useEffect(() => {
    pollRef.current = poll;
  }, [poll]);

  useEffect(() => {
    if (!enabled) return;
    let active = true;
    let running = false;
    let finished = false;
    let timer: ReturnType<typeof setTimeout> | null = null;
    let delay = initialMs;

    const schedule = (ms: number) => {
      if (timer) clearTimeout(timer);
      timer = setTimeout(tick, ms);
    };

    async function tick() {
      timer = null;
      if (!active || running) return;
      running = true;
      let keepGoing = false;
      try {
        keepGoing = await pollRef.current();
      } catch {
        keepGoing = true; // transient network error: keep trying with backoff
      } finally {
        running = false;
      }
      if (!keepGoing) finished = true;
      if (!active || finished) return;
      const hidden = typeof document !== "undefined" && document.visibilityState === "hidden";
      schedule(hidden ? hiddenMs : delay);
      delay = Math.min(maxMs, Math.round(delay * factor));
    }

    const onVisible = () => {
      if (document.visibilityState === "visible" && active && !running && !finished) schedule(0);
    };

    document.addEventListener("visibilitychange", onVisible);
    void tick();
    return () => {
      active = false;
      if (timer) clearTimeout(timer);
      document.removeEventListener("visibilitychange", onVisible);
    };
  }, [enabled, initialMs, maxMs, factor, hiddenMs]);
}
