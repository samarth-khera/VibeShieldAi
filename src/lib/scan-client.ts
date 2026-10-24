export type ScanStatus =
  | "queued"
  | "retrieving"
  | "ready_for_scan"
  | "scanning"
  | "completed"
  | "completed_with_warnings"
  | "cancelled"
  | "invalid_repository"
  | "download_failed"
  | "rejected_by_limits"
  | "failed";

export type PublicFinding = {
  id: string;
  fingerprint: string;
  scanner: "gitleaks" | "semgrep" | "osv-scanner";
  ruleId: string;
  category: "Secrets" | "Code Analysis" | "Dependencies";
  severity: "critical" | "high" | "medium" | "low" | "info";
  originalSeverity?: string | null;
  title: string;
  description: string;
  filePath: string;
  startLine: number | null;
  endLine: number | null;
  redactedEvidence: string | null;
  vulnerabilityId: string | null;
  remediation: string | null;
  packageInfo?: {
    name: string;
    version: string;
    ecosystem?: string;
  } | null;
  metadata?: Record<string, unknown> | null;
  createdAt: string;
};

export type ScannerStatusDetail = {
  status: "completed" | "failed" | "skipped" | "running" | null;
  durationMs: number | null;
  error: string | null;
};

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
  scanners?: {
    gitleaks: ScannerStatusDetail;
    semgrep: ScannerStatusDetail;
    osvScanner: ScannerStatusDetail;
  };
  scannerVersions?: {
    gitleaks: string | null;
    semgrep: string | null;
    osvScanner: string | null;
  } | null;
  scanCoverage?: {
    filesAnalyzed?: number;
    lockfilesFound: string[];
    scannersRun: string[];
    limitations: string[];
  } | null;
  summary?: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    total: number;
  } | null;
  failure: { category: string | null; message: string } | null;
  retryable: boolean;
  scanPerformed: boolean;
  workerOnline: boolean | null;
  createdAt: string;
  updatedAt: string;
  completedAt: string | null;
  expiresAt: string;
};

export const TERMINAL_STATUSES: ReadonlySet<ScanStatus> = new Set([
  "completed",
  "completed_with_warnings",
  "ready_for_scan",
  "cancelled",
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

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response;
  try {
    res = await fetch(path, { ...init, cache: "no-store" });
  } catch {
    throw new ApiRequestError("network_error", "Could not reach the server. Check your connection and try again.", 0);
  }
  let json: { data?: T; error?: { code: string; message: string } } | null = null;
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
  request<PublicScanJob>("/api/scans", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ repositoryUrl }),
  });

export const fetchScan = (id: string) => request<PublicScanJob>(`/api/scans/${encodeURIComponent(id)}`);

export const retryScan = (id: string) =>
  request<PublicScanJob>(`/api/scans/${encodeURIComponent(id)}/retry`, { method: "POST" });

export const startSecurityScan = (id: string) =>
  request<PublicScanJob>(`/api/scans/${encodeURIComponent(id)}/scan`, { method: "POST" });

export type FindingsResponse = {
  jobId: string;
  status: ScanStatus;
  total: number;
  limit: number;
  offset: number;
  findings: PublicFinding[];
};

export const fetchFindings = (
  id: string,
  params?: { severity?: string; category?: string; query?: string; limit?: number; offset?: number },
) => {
  const q = new URLSearchParams();
  if (params?.severity) q.set("severity", params.severity);
  if (params?.category) q.set("category", params.category);
  if (params?.query) q.set("query", params.query);
  if (params?.limit != null) q.set("limit", String(params.limit));
  if (params?.offset != null) q.set("offset", String(params.offset));

  const queryStr = q.toString() ? `?${q.toString()}` : "";
  return request<FindingsResponse>(`/api/scans/${encodeURIComponent(id)}/findings${queryStr}`);
};

export const fetchFindingDetail = (id: string, findingId: string) =>
  request<PublicFinding>(`/api/scans/${encodeURIComponent(id)}/findings/${encodeURIComponent(findingId)}`);
