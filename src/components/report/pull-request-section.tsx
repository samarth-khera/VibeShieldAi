"use client";

import { AlertCircle, CheckCircle2, GitBranch, GitPullRequest, KeyRound, Loader2, Lock } from "lucide-react";
import { Button } from "@/components/ui/button";
import type { PublicRemediation } from "@/lib/scan-client";

const FAILURE_TITLES: Record<string, string> = {
  not_configured: "GitHub authorization required",
  repository_not_allowed: "Repository not authorized for pull requests",
  credential_invalid: "GitHub credential rejected",
  access_denied: "Repository access denied",
  repository_not_found: "Repository not found",
  repository_mismatch: "Repository changed since the scan",
  rate_limited: "GitHub rate limit reached",
  commit_not_found: "Scanned commit no longer on GitHub",
  unsafe_target: "Patched path is not a regular file",
  patch_conflict: "Patch no longer applies",
  branch_conflict: "Remediation branch conflict",
  not_verified: "Fix not verified",
  network_error: "Could not reach the server",
};

/**
 * PR creation is a separate step from verification: it is only offered for a verified fix, and
 * "created" is shown only after GitHub returned the pull request.
 */
export function PullRequestSection({
  remediation,
  isOpening,
  requestError,
  onOpen,
  patchDownloadUrl,
}: {
  remediation: PublicRemediation;
  isOpening: boolean;
  requestError: { code: string; message: string } | null;
  onOpen: () => void;
  patchDownloadUrl?: string;
}) {
  const pr = remediation.pullRequest;
  const verified = remediation.status === "verified" && remediation.rescanStatus === "verified";
  const availability = pr?.availability;
  const done = pr?.status === "created" || pr?.status === "exists";
  const blocked = availability === "not_configured" || availability === "repository_not_allowed";
  const failure = requestError ?? (pr?.status === "failed" && pr.code ? { code: pr.code, message: pr.message ?? "" } : null);

  return (
    <div className="rounded-lg border border-line bg-surface p-3 space-y-3" aria-label="Pull request">
      <div className="flex items-center gap-2 text-xs font-semibold text-foreground">
        <GitBranch className="size-4 text-accent" /> Branch &amp; Pull Request
      </div>

      {!verified ? (
        <p className="text-xs text-muted">
          Pull requests are only offered for fixes that passed the security rescan. You can still download the patch to
          review it locally.
        </p>
      ) : done ? (
        <div className="rounded border border-accent/30 bg-accent/10 p-2.5 text-xs text-accent" role="status">
          <p className="flex items-center gap-1.5 font-semibold">
            <CheckCircle2 className="size-3.5" />
            {pr?.status === "created"
              ? `Pull request #${pr.number} created`
              : `Pull request #${pr?.number} already exists (${pr?.state ?? "open"})`}
          </p>
          <p className="mt-1 font-mono text-[11px] text-muted">
            {pr?.branch} → {pr?.baseBranch}
            {pr?.headSha ? ` · commit ${pr.headSha.slice(0, 7)}` : ""}
          </p>
          {pr?.url && (
            <a href={pr.url} target="_blank" rel="noreferrer" className="mt-1 inline-flex underline font-mono text-[11px]">
              View pull request on GitHub →
            </a>
          )}
        </div>
      ) : blocked ? (
        <div className="rounded border border-line bg-surface-subtle p-2.5 text-xs text-muted" role="status">
          <p className="flex items-center gap-1.5 font-semibold text-foreground">
            {availability === "not_configured" ? <KeyRound className="size-3.5" /> : <Lock className="size-3.5" />}
            {FAILURE_TITLES[availability!]}
          </p>
          <p className="mt-1">
            {availability === "not_configured"
              ? "This deployment has no server-side GitHub write credential, so it cannot open pull requests. The verified fix was not affected; download the .patch and apply it with git apply."
              : "This deployment only opens pull requests in repositories its operator has authorized. Download the verified .patch and apply it with git apply."}
          </p>
        </div>
      ) : (
        <p className="text-xs text-muted">
          Commits exactly the verified patch to a new branch based on commit {remediation.commitSha.slice(0, 7)} and opens a
          pull request. The default branch is never modified and nothing is merged.
        </p>
      )}

      {verified && !done && failure && !blocked && (
        <div className="rounded border border-sev-high/40 bg-sev-high/10 p-2.5 text-xs" role="alert">
          <p className="flex items-center gap-1.5 font-semibold text-sev-high">
            <AlertCircle className="size-3.5" /> Creation failed — {FAILURE_TITLES[failure.code] ?? "GitHub error"}
          </p>
          <p className="mt-1 text-muted">{failure.message}</p>
        </div>
      )}

      {isOpening && (
        <p className="flex items-center gap-1.5 text-xs text-muted" role="status">
          <Loader2 className="size-3.5 animate-spin" /> Creating remediation branch, committing the verified patch and
          opening the pull request…
        </p>
      )}

      <div className="flex flex-wrap items-center gap-2">
        {verified && !done && !blocked && (
          <Button onClick={onOpen} disabled={isOpening} size="sm">
            {isOpening ? <Loader2 className="size-3.5 animate-spin" /> : <GitPullRequest className="size-3.5" />}
            {failure ? "Retry Pull Request" : "Open GitHub Pull Request"}
          </Button>
        )}
        {patchDownloadUrl && (
          <a
            href={patchDownloadUrl}
            download
            className="inline-flex items-center gap-1.5 h-8 px-3 rounded-lg border border-line hover:border-line-bright text-xs font-medium text-foreground transition-colors"
          >
            Download .patch File
          </a>
        )}
      </div>
    </div>
  );
}
