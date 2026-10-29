"use client";

import { useState } from "react";
import {
  AlertCircle,
  CheckCircle2,
  Circle,
  ExternalLink,
  GitBranch,
  GitPullRequest,
  KeyRound,
  Loader2,
  LogOut,
  XCircle,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  ApiRequestError,
  createRemediationPr,
  diffSha256,
  disconnectGithub,
  listRemediations,
  type PublicFinding,
  type PublicRemediation,
} from "@/lib/scan-client";
import { DiffViewer } from "./diff-viewer";
import { useGithubStatus, type GithubStatusHandle } from "./repository-authorization";

const FAILURE_TITLES: Record<string, string> = {
  not_configured: "GitHub authorization is not configured",
  not_connected: "GitHub not connected",
  authorization_expired: "Authorization expired",
  authorization_revoked: "Authorization revoked",
  repository_not_found: "Repository not visible to your account",
  repository_changed: "Repository changed since the scan",
  not_installed: "Repository not authorized for VibeShield",
  no_push_permission: "Permission denied: no write access",
  app_lacks_permission: "App permissions not approved",
  rate_limited: "GitHub rate limit reached",
  github_unavailable: "Could not reach GitHub",
  credential_invalid: "Authorization rejected by GitHub",
  access_denied: "Permission denied by GitHub",
  repository_mismatch: "Repository changed since the scan",
  commit_not_found: "Scanned commit no longer on GitHub",
  unsafe_target: "Patched path is not a regular file",
  patch_conflict: "Patch no longer applies",
  branch_conflict: "Remediation branch conflict",
  not_verified: "Fix not verified",
  diff_confirmation_mismatch: "Diff changed; review it again",
  forbidden_origin: "Request blocked",
  network_error: "Could not reach the server",
};

type Step = { label: string; state: "done" | "pending" | "running" | "blocked"; detail?: string };

function StepRow({ step }: { step: Step }) {
  const icon =
    step.state === "done" ? (
      <CheckCircle2 className="size-3.5 text-accent" />
    ) : step.state === "running" ? (
      <Loader2 className="size-3.5 animate-spin text-muted" />
    ) : step.state === "blocked" ? (
      <XCircle className="size-3.5 text-sev-high" />
    ) : (
      <Circle className="size-3.5 text-muted" />
    );
  return (
    <li className="flex items-start gap-2">
      <span className="mt-0.5">{icon}</span>
      <span>
        <span className={step.state === "done" ? "text-foreground" : "text-muted"}>{step.label}</span>
        {step.detail && <span className="block text-[11px] text-muted">{step.detail}</span>}
      </span>
    </li>
  );
}

/**
 * GitHub authorization and pull-request publishing for one remediation. Authorization comes only
 * from GitHub's own consent and installation pages; this component never asserts access the
 * server has not just confirmed with GitHub.
 */
export function GithubPullRequestPanel({
  jobId,
  finding,
  remediation,
  onRemediationUpdated,
  patchDownloadUrl,
  github,
}: {
  jobId: string;
  finding: PublicFinding;
  remediation: PublicRemediation;
  onRemediationUpdated: (r: PublicRemediation) => void;
  patchDownloadUrl?: string;
  /** Status shared with the repository access panel; loaded here when not provided. */
  github?: GithubStatusHandle;
}) {
  const [dialogOpen, setDialogOpen] = useState(false);
  const [confirmed, setConfirmed] = useState(false);
  const [creating, setCreating] = useState(false);
  const [prError, setPrError] = useState<{ code: string; message: string } | null>(null);
  const [disconnecting, setDisconnecting] = useState(false);
  const returnTo = `/report/${jobId}?finding=${finding.id}&mode=autofix`;

  // Re-checked with GitHub whenever the remediation changes state and after every action.
  const own = useGithubStatus(jobId, returnTo, remediation.status, !github);
  const { status, error: statusError, reload: loadStatus } = github ?? own;

  const verified = remediation.status === "verified" && remediation.rescanStatus === "verified";
  const pr = remediation.pullRequest;
  const prDone = pr?.status === "created" || pr?.status === "exists";
  const repo = status?.repository;
  const lastFailure = prError ?? (pr?.status === "failed" && pr.code ? { code: pr.code, message: pr.message } : null);
  // The repository can be authorized from VibeShield itself (see RepositoryAuthorizationPanel).
  const inProductAuthorization = repo?.authorization?.state === "authorization_required";

  const steps: Step[] = [];
  if (status?.configured) {
    steps.push(
      status.connected
        ? { label: `GitHub connected as @${status.user?.login}`, state: "done" }
        : {
            label: status.authorizationProblem ? FAILURE_TITLES[status.authorizationProblem] : "GitHub not connected",
            state: status.authorizationProblem ? "blocked" : "pending",
          },
    );
    if (status.connected && repo) {
      steps.push(
        repo.canRead
          ? { label: `Repository read access confirmed (${repo.fullName})`, state: "done" }
          : { label: FAILURE_TITLES[repo.reason ?? "repository_not_found"], state: "blocked", detail: repo.message },
      );
      steps.push(
        repo.readyToWrite
          ? { label: "Repository authorized", state: "done", detail: "In the VibeShield AI installation; you can push." }
          : inProductAuthorization
            ? { label: "Repository authorization required", state: "pending", detail: "Authorize this repository under Repository access." }
            : repo.canRead
              ? { label: FAILURE_TITLES[repo.reason ?? "not_installed"], state: "blocked", detail: repo.authorization?.message ?? repo.message }
              : { label: "Repository write access", state: "pending" },
      );
    }
  }
  steps.push(
    remediation.approvedAt
      ? { label: "Patch approved", state: "done" }
      : { label: "Approval required", state: "pending", detail: "Fix preview ready: review the exact diff and approve it." },
  );
  steps.push(
    remediation.status === "applied"
      ? { label: "Verifying full repository", state: "running", detail: "Patch applied to the scanned commit; all scanners are rerunning." }
      : verified
        ? { label: "Fix verified by security rescan", state: "done" }
        : remediation.status === "failed" || remediation.status === "needs_review"
          ? { label: "Fix not verified", state: "blocked", detail: "Pull requests are only offered for verified fixes." }
          : { label: "Security verification", state: "pending" },
  );
  steps.push(
    creating
      ? { label: "Creating branch and commit, opening pull request", state: "running" }
      : prDone
        ? { label: pr?.status === "created" ? `Pull request #${pr.number} created` : `Pull request #${pr?.number} exists (${pr?.state})`, state: "done" }
        : lastFailure
          ? { label: `Fix or PR creation failed — ${FAILURE_TITLES[lastFailure.code] ?? "GitHub error"}`, state: "blocked", detail: lastFailure.message }
          : { label: "Pull request", state: "pending" },
  );

  const onCreate = async () => {
    if (creating) return;
    setCreating(true);
    setPrError(null);
    try {
      const res = await createRemediationPr(jobId, remediation.id, await diffSha256(remediation.unifiedDiff));
      onRemediationUpdated(res.remediation);
      setDialogOpen(false);
    } catch (err) {
      setPrError({
        code: err instanceof ApiRequestError ? err.code : "network_error",
        message: err instanceof Error ? err.message : "Failed to create pull request.",
      });
      const fresh = await listRemediations(jobId)
        .then((list) => list.find((r) => r.id === remediation.id))
        .catch(() => undefined);
      if (fresh) onRemediationUpdated(fresh);
      loadStatus();
    } finally {
      setCreating(false);
      setConfirmed(false);
    }
  };

  const onDisconnect = async () => {
    setDisconnecting(true);
    try {
      await disconnectGithub();
    } finally {
      setDisconnecting(false);
      loadStatus();
    }
  };

  return (
    <div className="rounded-lg border border-line bg-surface p-3 space-y-3 text-xs" aria-label="GitHub authorization">
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2 font-semibold text-foreground">
          <GitBranch className="size-4 text-accent" /> GitHub Pull Request
        </div>
        {status?.connected && (
          <button
            type="button"
            onClick={onDisconnect}
            disabled={disconnecting}
            className="inline-flex items-center gap-1 text-[11px] text-muted hover:text-foreground"
          >
            <LogOut className="size-3" /> {disconnecting ? "Disconnecting…" : "Disconnect GitHub"}
          </button>
        )}
      </div>

      {statusError && (
        <p className="text-sev-high" role="alert">
          {statusError}
        </p>
      )}

      {status && !status.configured ? (
        <div className="rounded border border-line bg-surface-subtle p-2.5 text-muted" role="status">
          <p className="flex items-center gap-1.5 font-semibold text-foreground">
            <KeyRound className="size-3.5" /> GitHub authorization is not configured yet
          </p>
          <p className="mt-1">
            This deployment has not set up its GitHub App, so it cannot open pull requests. Scanning, review and verification
            are unaffected; download the verified .patch and apply it with git apply.
          </p>
        </div>
      ) : (
        <>
          <p className="text-muted">
            VibeShield opens a separate branch based on the scanned commit {remediation.commitSha.slice(0, 7)} and a pull
            request for your review. It never pushes to the default branch and never merges.
          </p>
          <ul className="space-y-1.5" aria-label="Authorization and fix status">
            {steps.map((s) => (
              <StepRow key={s.label} step={s} />
            ))}
          </ul>
        </>
      )}

      {prDone && pr?.url && (
        <div className="rounded border border-accent/30 bg-accent/10 p-2.5 text-accent" role="status">
          <p className="font-semibold">
            {pr.status === "created" ? `Pull request #${pr.number} created` : `Pull request #${pr.number} already exists (${pr.state})`}
          </p>
          <p className="mt-1 font-mono text-[11px] text-muted">
            {pr.branch} → {pr.baseBranch}
            {pr.headSha ? ` · commit ${pr.headSha.slice(0, 7)}` : ""}
            {pr.openedBy ? ` · opened as @${pr.openedBy.login} via the VibeShield AI GitHub App` : ""}
          </p>
          <p className="mt-1 text-[11px] text-muted">Changed files: {remediation.affectedFiles.join(", ")}</p>
          {pr.openedBy && (
            <p className="mt-1 text-[11px] text-muted">
              VibeShield prepared this verified change on behalf of @{pr.openedBy.login}.
              {pr.commit?.authorName
                ? ` GitHub recorded the commit as authored by ${pr.commit.authorName}${pr.commit.authorEmailIsNoreply ? " (GitHub noreply address)" : ""}${pr.commit.verified ? ", signature verified" : ""}.`
                : ""}
            </p>
          )}
          {pr.baseAdvanced && (
            <p className="mt-1 text-muted">
              {pr.baseBranch} has new commits since the scan. GitHub shows whether the pull request still merges cleanly.
            </p>
          )}
          <a href={pr.url} target="_blank" rel="noreferrer" className="mt-1 inline-flex items-center gap-1 underline">
            View pull request on GitHub <ExternalLink className="size-3" />
          </a>
        </div>
      )}

      <div className="flex flex-wrap items-center gap-2">
        {status?.configured && !status.connected && !github && (
          <a href={status.links.connect} className="inline-flex h-8 items-center gap-1.5 rounded-lg bg-accent px-3 font-medium text-background">
            <KeyRound className="size-3.5" /> {status.authorizationProblem ? "Reconnect GitHub" : "Connect GitHub"}
          </a>
        )}
        {status?.connected && repo && !repo.readyToWrite && !inProductAuthorization && (repo.reason === "not_installed" || repo.reason === "app_lacks_permission") && (
          <a href={status.links.install} className="inline-flex h-8 items-center gap-1.5 rounded-lg bg-accent px-3 font-medium text-background">
            <GitBranch className="size-3.5" /> Authorize this repository
          </a>
        )}
        {verified && !prDone && repo?.readyToWrite && (
          <Button onClick={() => setDialogOpen(true)} size="sm" disabled={creating}>
            <GitPullRequest className="size-3.5" /> {lastFailure ? "Retry pull request" : "Review & create pull request"}
          </Button>
        )}
        {patchDownloadUrl && (
          <a
            href={patchDownloadUrl}
            download
            className="inline-flex h-8 items-center gap-1.5 rounded-lg border border-line px-3 font-medium text-foreground hover:border-line-bright"
          >
            Download .patch File
          </a>
        )}
      </div>

      {status?.connected && repo?.reason === "not_installed" && !inProductAuthorization && (
        <p className="text-[11px] text-muted">
          If {repo.fullName.split("/")[0]} is an organization, an organization owner may need to approve the VibeShield app
          before it can be installed on this repository. You can review or remove access at any time in{" "}
          <a href={status.links.manageInstallations} target="_blank" rel="noreferrer" className="underline">
            GitHub settings
          </a>
          .
        </p>
      )}

      {dialogOpen && (
        <div
          role="dialog"
          aria-modal="true"
          aria-label="Create pull request"
          className="fixed inset-0 z-[60] flex items-center justify-center bg-black/60 p-4"
        >
          <div className="max-h-[90vh] w-full max-w-2xl overflow-y-auto rounded-xl border border-line bg-surface p-4 space-y-3 text-xs">
            <h3 className="flex items-center gap-2 text-sm font-semibold text-foreground">
              <GitPullRequest className="size-4 text-accent" /> Create pull request
            </h3>
            <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 font-mono text-[11px]">
              <dt className="text-muted">Repository</dt>
              <dd>{repo?.fullName}</dd>
              <dt className="text-muted">Base branch</dt>
              <dd>{repo?.defaultBranch}</dd>
              <dt className="text-muted">Based on</dt>
              <dd>verified scan commit {remediation.commitSha.slice(0, 12)}</dd>
              <dt className="text-muted">Finding</dt>
              <dd>
                {finding.title} ({finding.ruleId})
              </dd>
              <dt className="text-muted">Opened as</dt>
              <dd>@{status?.user?.login} via the VibeShield AI GitHub App</dd>
            </dl>
            <DiffViewer diff={remediation.unifiedDiff} summary={remediation.patchSummary} />
            <label className="flex items-start gap-2 text-foreground">
              <input type="checkbox" checked={confirmed} onChange={(e) => setConfirmed(e.target.checked)} className="mt-0.5" />
              <span>
                I approve publishing exactly this diff as a new branch and pull request in {repo?.fullName}. Nothing will be
                merged automatically.
              </span>
            </label>
            {prError && (
              <p className="flex items-center gap-1.5 text-sev-high" role="alert">
                <AlertCircle className="size-3.5" /> {FAILURE_TITLES[prError.code] ?? "Failed"} — {prError.message}
              </p>
            )}
            <div className="flex justify-end gap-2">
              <Button variant="secondary" size="sm" onClick={() => setDialogOpen(false)} disabled={creating}>
                Cancel
              </Button>
              <Button size="sm" onClick={onCreate} disabled={!confirmed || creating}>
                {creating ? <Loader2 className="size-3.5 animate-spin" /> : <GitPullRequest className="size-3.5" />}
                {creating ? "Creating…" : "Create pull request"}
              </Button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
