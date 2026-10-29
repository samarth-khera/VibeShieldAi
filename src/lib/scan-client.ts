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
    fixedVersion?: string | null;
  } | null;
  metadata?: Record<string, unknown> | null;
  aiExplanation?: {
    cacheKey?: string;
    model?: string;
    explanation: AiFindingExplanation;
    generatedAt?: string;
  } | null;
  createdAt: string;
};

export type ScannerStatusDetail = {
  status: "completed" | "failed" | "skipped" | "running" | null;
  durationMs: number | null;
  error: string | null;
};

export type ReportState = "in_progress" | "complete" | "partial" | "failed" | "cancelled";

const ACTIVE_STATES: ReadonlySet<string> = new Set(["queued", "retrieving", "ready_for_scan", "scanning"]);

/** The server's reportState, or the same rule derived locally (never more favourable than the data). */
export function reportStateOf(job: Pick<PublicScanJob, "status" | "scanners" | "reportState">): ReportState {
  if (job.reportState) return job.reportState;
  if (ACTIVE_STATES.has(job.status)) return "in_progress";
  if (job.status === "cancelled") return "cancelled";
  if (job.status !== "completed" && job.status !== "completed_with_warnings") return "failed";
  const s = job.scanners;
  const allDone = !!s && [s.gitleaks, s.semgrep, s.osvScanner].every((x) => x?.status === "completed");
  return job.status === "completed" && allDone ? "complete" : "partial";
}

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
    // Absent while a scan is running: the worker only reports `progress` until it finishes.
    lockfilesFound?: string[];
    scannersRun?: string[];
    limitations?: string[];
    stageDurations?: {
      metadataMs?: number;
      downloadMs?: number;
      extractionMs?: number;
      scanningMs?: number;
      callbackMs?: number;
    };
    /** ISO timestamps reported by the worker as it moves through each phase. */
    progress?: ScanProgress;
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
  /** What the report may claim; only "complete" is a verified result (see server/api.ts). */
  reportState?: ReportState;
  /** Scanners that did not finish (terminal states only). */
  incompleteScanners?: string[];
  workerOnline: boolean | null;
  /** Present while the scan waits for a free worker slot. */
  queue?: { waitingForSlot: boolean; position: number | null } | null;
  executor?: "warm-worker" | "github-actions" | null;
  /** Whether this browser started the scan (display only; the server re-checks every change). */
  viewer?: { isOwner: boolean };
  createdAt: string;
  updatedAt: string;
  startedAt?: string | null;
  completedAt: string | null;
  expiresAt: string;
};

export type ScanProgress = {
  phase?: "worker_started" | "retrieving" | "extracting" | "scanning";
  /** Increments whenever a scanner publishes results; refetch findings only when it changes. */
  revision?: number;
  firstFindingAt?: string;
  finalAt?: string;
  worker_startedAt?: string;
  retrievingAt?: string;
  extractingAt?: string;
  scanningAt?: string;
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
    /** Structured details some errors carry (e.g. GitHub-managed next steps). */
    public readonly data?: unknown,
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
      res.ok ? undefined : json?.data,
    );
  }
  return json.data;
}

export const submitScan = (repositoryUrl: string, turnstileToken?: string) =>
  request<PublicScanJob>("/api/scans", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ repositoryUrl, turnstileToken }),
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

export type CodeExample = {
  language: string;
  code: string;
  title?: string;
  isDiff?: boolean;
};

export type AiFindingExplanation = {
  summary: string;
  whyItMatters: string;
  impact: string;
  exploitabilityConditions: string;
  remediationSteps: string[];
  codeExample?: CodeExample | null;
  verificationSteps: string[];
  uncertainties: string[];
  disclaimer: string;
};

export type AiExplainResult =
  | {
      available: true;
      cached: boolean;
      model: string;
      explanation: AiFindingExplanation;
      generatedAt: string;
    }
  | {
      available: false;
      code: string;
      message: string;
      /** Safe diagnostics: matches the server's structured log line for this request. */
      diagnostic?: { correlationId?: string; category?: string };
    };

export const explainFindingWithAi = (id: string, findingId: string) =>
  request<AiExplainResult>(
    `/api/scans/${encodeURIComponent(id)}/findings/${encodeURIComponent(findingId)}/explain`,
    { method: "POST" }
  );

export type PublicRemediation = {
  id: string;
  scanJobId: string;
  status: "preview" | "approved" | "applied" | "verified" | "needs_review" | "failed" | "rejected";
  findingFingerprints: string[];
  commitSha: string;
  patchSummary: string;
  unifiedDiff: string;
  affectedFiles: string[];
  eligibility: "safe" | "potentially_breaking" | "unsuitable";
  eligibilityReason: string;
  requiresRotation: boolean;
  warnings: string[];
  approvedAt: string | null;
  rescanStatus: "verified" | "needs_review" | "failed" | null;
  rescanSummary: {
    targetResolved: boolean;
    originalFindingsCount: number;
    postRescanFindingsCount: number;
    newFindingsCount: number;
    resolvedFingerprints: string[];
    remainingFingerprints: string[];
    regressions: string[];
    reason?: string;
    detail?: string;
    scannerStatuses?: { gitleaks: string; semgrep: string; osvScanner: string };
    timings?: Record<string, number | undefined>;
    runtime?: "github-actions" | "warm-worker" | "local";
    snapshot?: { commitSha: string; fileCount: number };
    workflowRunUrl?: string;
  } | null;
  branchName: string | null;
  pullRequestUrl: string | null;
  pullRequest: RemediationPullRequest | null;
  /** While verification runs: whether a worker has claimed it yet. */
  verification?: { claimedAt: string | null; runtime: "warm-worker" | "github-actions" | null } | null;
  createdAt: string;
  updatedAt: string;
};

export type PullRequestFailureCode =
  | "credential_invalid"
  | "access_denied"
  | "repository_not_found"
  | "repository_mismatch"
  | "rate_limited"
  | "commit_not_found"
  | "unsafe_target"
  | "patch_conflict"
  | "branch_conflict"
  | "github_error"
  | "network_error"
  | "not_confirmed";

/** Steps of publishing a verified fix (stored while they run). */
export type PullRequestStep = "checking_repository" | "creating_commit" | "pushing_branch" | "creating_pull_request" | "confirming";

/** Outcome of the last pull-request attempt, as GitHub reported it. */
export type RemediationPullRequest = {
  status: "in_progress" | "created" | "exists" | "failed";
  step?: PullRequestStep;
  code?: PullRequestFailureCode;
  message: string;
  branch: string;
  baseBranch?: string;
  headSha?: string;
  number?: number;
  url?: string;
  state?: "open" | "closed" | "merged";
  baseAdvanced?: boolean;
  openedBy?: { githubUserId: number; login: string };
  /** The fix commit as GitHub recorded it. */
  commit?: {
    sha: string;
    url?: string;
    authorName?: string;
    committerName?: string;
    authorEmailIsNoreply?: boolean;
    verified?: boolean;
    verificationReason?: string;
    authorLogin?: string;
    committerLogin?: string;
  };
  /** The pull request's author as GitHub reports it. */
  prAuthor?: string;
  at: string;
};

/** Per-repository authorization state, from GitHub's live answer for the user's own token. */
export type RepositoryAuthorizationState =
  | "authorized"
  | "authorization_required"
  | "app_setup_required"
  | "installation_required"
  | "admin_required"
  | "organization_approval_required"
  | "no_push_permission"
  | "app_lacks_permission";

export type GithubAuthFailureCode =
  | "not_configured"
  | "not_connected"
  | "authorization_expired"
  | "authorization_revoked"
  | "repository_not_found"
  | "repository_changed"
  | "not_installed"
  | "no_push_permission"
  | "app_lacks_permission"
  | "rate_limited"
  | "github_unavailable";

/** The current browser session's GitHub App authorization, checked live by the server. */
export type GithubStatus = {
  configured: boolean;
  unavailableReason?: "not_configured" | "setup_incomplete";
  connected: boolean;
  user?: { login: string; avatarUrl: string | null };
  repository?: {
    fullName: string;
    defaultBranch?: string;
    isPrivate?: boolean;
    canRead: boolean;
    canPush: boolean;
    installed: boolean;
    appCanWrite: boolean;
    readyToWrite: boolean;
    reason?: GithubAuthFailureCode;
    message?: string;
    id?: number;
    ownerType?: "User" | "Organization";
    canAdmin?: boolean;
    authorization?: {
      state: RepositoryAuthorizationState;
      message: string;
      installationId?: number;
      installationAccount?: string;
      installationSettingsUrl?: string;
    };
  };
  authorizationProblem?: GithubAuthFailureCode;
  links: { connect: string; install: string; manageInstallations: string };
};

export const fetchGithubStatus = (jobId: string, returnTo: string) =>
  request<GithubStatus>(
    `/api/auth/github/status?jobId=${encodeURIComponent(jobId)}&returnTo=${encodeURIComponent(returnTo)}`,
  );

/** What the server bound for one "authorize this repository" confirmation (shown in the dialog). */
export type RepositoryAuthorizationPrepared = {
  state: RepositoryAuthorizationState;
  message: string;
  repository: {
    id: number;
    fullName: string;
    defaultBranch: string | null;
    isPrivate: boolean;
    ownerType: "User" | "Organization" | null;
    canPush: boolean;
    canAdmin: boolean;
  };
  installation: { id: number; account: string; repositorySelection: "all" | "selected" } | null;
  scannedCommit: string;
  links: { install: string; installationSettings: string | null };
  request: { intent: string; expiresAt: string } | null;
};

export type RepositoryAuthorizationResult = Omit<RepositoryAuthorizationPrepared, "request" | "scannedCommit"> & { added: boolean };

const repositoryAuthorization = <T>(jobId: string, body: Record<string, unknown>) =>
  request<T>(`/api/scans/${encodeURIComponent(jobId)}/repository-authorization`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });

export const prepareRepositoryAuthorization = (jobId: string, remediationId?: string) =>
  repositoryAuthorization<RepositoryAuthorizationPrepared>(jobId, { action: "prepare", ...(remediationId ? { remediationId } : {}) });

export const confirmRepositoryAuthorization = (jobId: string, p: RepositoryAuthorizationPrepared) =>
  repositoryAuthorization<RepositoryAuthorizationResult>(jobId, {
    action: "confirm",
    intent: p.request!.intent,
    repositoryId: p.repository.id,
    installationId: p.installation!.id,
  });

export const cancelRepositoryAuthorization = (jobId: string, intent: string) =>
  repositoryAuthorization<{ cancelled: true }>(jobId, { action: "cancel", intent });

export const disconnectGithub = () =>
  request<{ connected: false; revokedAtGitHub?: boolean }>("/api/auth/github/disconnect", { method: "POST" });

/** SHA-256 (hex) of the exact diff text shown to the user, sent as their confirmation. */
export async function diffSha256(diff: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(diff));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export const createRemediationPreview = (jobId: string, findingId: string) =>
  request<PublicRemediation>(`/api/scans/${encodeURIComponent(jobId)}/remediation/preview`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ findingId }),
  });

export const listRemediations = (jobId: string) =>
  request<PublicRemediation[]>(`/api/scans/${encodeURIComponent(jobId)}/remediation`);

export const approveRemediation = (jobId: string, remediationId: string) =>
  request<PublicRemediation>(
    `/api/scans/${encodeURIComponent(jobId)}/remediation/${encodeURIComponent(remediationId)}/approve`,
    { method: "POST" },
  );

export const applyRemediation = (jobId: string, remediationId: string) =>
  request<PublicRemediation>(
    `/api/scans/${encodeURIComponent(jobId)}/remediation/${encodeURIComponent(remediationId)}/apply`,
    { method: "POST" },
  );

/**
 * Opens the PR with the user's own GitHub App authorization (held server-side in an HttpOnly
 * session; the browser never sees a token). `approvedDiffSha256` confirms the exact diff shown.
 */
export const createRemediationPr = (jobId: string, remediationId: string, approvedDiffSha256: string) =>
  request<{ remediation: PublicRemediation; pullRequest: RemediationPullRequest }>(
    `/api/scans/${encodeURIComponent(jobId)}/remediation/${encodeURIComponent(remediationId)}/pr`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ approvedDiffSha256 }),
    },
  );


