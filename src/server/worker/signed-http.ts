import { signCallbackPayload } from "../callback-auth";

const USER_AGENT = "VibeShieldAI-Worker/0.3";

/** POSTs a JSON payload signed with `secret`, retrying transient failures. Re-signs every attempt. */
export async function postSigned(
  url: string,
  secret: string,
  payload: unknown,
  opts: { attempts?: number; timeoutMs?: number } = {},
): Promise<Response> {
  const json = JSON.stringify(payload);
  const attempts = opts.attempts ?? 3;
  let last: Response | null = null;
  for (let attempt = 1; attempt <= attempts; attempt++) {
    try {
      const res = await fetch(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-VibeShield-Signature": signCallbackPayload(json, secret),
          "User-Agent": USER_AGENT,
        },
        body: json,
        signal: AbortSignal.timeout(opts.timeoutMs ?? 30_000),
      });
      // 4xx is a definitive answer (bad signature, stale lease, validation); never retry it.
      if (res.ok || (res.status >= 400 && res.status < 500)) return res;
      last = res;
    } catch {
      // network error: retry
    }
    if (attempt < attempts) await new Promise((r) => setTimeout(r, 500 * attempt));
  }
  if (last) return last;
  throw new Error(`POST failed after ${attempts} attempts.`);
}

/** GET authenticated by signing a canonical string instead of a body. */
export async function getSigned(url: string, secret: string, canonical: string, timeoutMs = 30_000): Promise<Response> {
  return fetch(url, {
    headers: { "X-VibeShield-Signature": signCallbackPayload(canonical, secret), "User-Agent": USER_AGENT },
    signal: AbortSignal.timeout(timeoutMs),
  });
}
