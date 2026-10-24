export type ScanStatus =
  | "queued"
  | "retrieving"
  | "ready_for_scan"
  | "invalid_repository"
  | "download_failed"
  | "rejected_by_limits"
  | "failed";

export type PublicScanJob = {
  id: string;
  status: ScanStatus;
  repository: {
    owner: string;
    name: string;
    url: string;
    defaultBranch: string | null;
    commitSha: string | null;
    description: string | null;
    sizeKb: number | null;
    stars: number | null;
    language: string | null;
  };
  retrieval: { fileCount: number | null; unpackedBytes: number | null; archiveBytes: number | null } | null;
  failure: { category: string | null; message: string } | null;
  retryable: boolean;
  scanPerformed: false;
  workerOnline: boolean | null;
};

export const TERMINAL_STATUSES: ReadonlySet<ScanStatus> = new Set([
  "ready_for_scan",
  "invalid_repository",
  "download_failed",
  "rejected_by_limits",
  "failed",
]);

export class ApiRequestError extends Error {
  constructor(
    public readonly code: string,
    message: string,
    public readonly status: number,
  ) {
    super(message);
  }
}

async function request(path: string, init?: RequestInit): Promise<PublicScanJob> {
  let res: Response;
  try {
    res = await fetch(path, { ...init, cache: "no-store" });
  } catch {
    throw new ApiRequestError("network_error", "Could not reach the server. Check your connection and try again.", 0);
  }
  let json: { data?: PublicScanJob; error?: { code: string; message: string } } | null = null;
  try {
    json = await res.json();
  } catch {
    /* non-JSON error page */
  }
  if (!res.ok || !json?.data) {
    throw new ApiRequestError(
      json?.error?.code ?? "server_error",
      json?.error?.message ?? "The server returned an unexpected response.",
      res.status,
    );
  }
  return json.data;
}

export const submitScan = (repositoryUrl: string) =>
  request("/api/scans", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ repositoryUrl }),
  });

export const fetchScan = (id: string) => request(`/api/scans/${encodeURIComponent(id)}`);

export const retryScan = (id: string) => request(`/api/scans/${encodeURIComponent(id)}/retry`, { method: "POST" });
