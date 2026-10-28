"use client";

import { useCallback, useEffect, useState } from "react";
import {
  AlertCircle,
  AlertTriangle,
  CheckCircle2,
  Loader2,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Terminal,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  ApiRequestError,
  applyRemediation,
  approveRemediation,
  createRemediationPreview,
  createRemediationPr,
  listRemediations,
  type PublicFinding,
  type PublicRemediation,
} from "@/lib/scan-client";
import { PullRequestSection } from "./pull-request-section";
import { DiffViewer } from "./diff-viewer";
import { classifyRemediationEligibility } from "@/lib/remediation-eligibility";
import { useAdaptivePoll } from "@/lib/use-adaptive-poll";

const FAILURE_REASONS: Record<string, string> = {
  source_snapshot_unavailable: "The repository snapshot for the scanned commit could not be rebuilt.",
  commit_unknown: "The scanned commit is unknown, so the patch could not be tied to a revision.",
  patch_target_missing: "A file in the patch does not exist at the scanned commit.",
  patch_tool_unavailable: "The patch tool was unavailable in the verification runtime.",
  patch_does_not_apply: "The patch does not apply cleanly to the scanned commit.",
  scanner_failed: "At least one required scanner did not complete, so nothing was verified.",
  target_not_resolved: "The targeted finding is still reported after the patch.",
  new_findings_introduced: "The patched repository has findings the original scan did not.",
  verification_timeout: "The verification worker did not report a result in time.",
  worker_failed: "The verification worker failed before finishing.",
};

function VerificationDetails({ summary }: { summary: NonNullable<PublicRemediation["rescanSummary"]> }) {
  const t = summary.timings ?? {};
  const fmt = (ms?: number) => (ms == null ? "—" : ms < 1000 ? `${ms}ms` : `${(ms / 1000).toFixed(1)}s`);
  return (
    <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 font-mono text-[11px] text-muted">
      {summary.runtime && (
        <>
          <dt>Runtime</dt>
          <dd>
            {summary.runtime === "github-actions"
              ? "GitHub Actions scanner worker"
              : summary.runtime === "warm-worker"
                ? "Persistent warm scanner worker"
                : "Local scanner runtime"}
          </dd>
        </>
      )}
      {summary.snapshot && (
        <>
          <dt>Snapshot</dt>
          <dd>
            commit {summary.snapshot.commitSha.slice(0, 7)} · {summary.snapshot.fileCount} files
          </dd>
        </>
      )}
      {summary.scannerStatuses && (
        <>
          <dt>Scanners</dt>
          <dd>
            Gitleaks {summary.scannerStatuses.gitleaks} · Semgrep {summary.scannerStatuses.semgrep} · OSV{" "}
            {summary.scannerStatuses.osvScanner}
          </dd>
        </>
      )}
      {summary.timings && (
        <>
          <dt>Timings</dt>
          <dd>
            queue {fmt(t.queueMs)} · download {fmt(t.downloadMs)} · extract {fmt(t.extractionMs)} · apply{" "}
            {fmt(t.applyMs)} · scan {fmt(t.scanMs)} · total {fmt(t.totalMs)}
          </dd>
        </>
      )}
      <dt>Findings</dt>
      <dd>
        {summary.originalFindingsCount} before · {summary.postRescanFindingsCount} after · {summary.newFindingsCount} new
      </dd>
      {summary.workflowRunUrl && (
        <>
          <dt>Run</dt>
          <dd>
            <a href={summary.workflowRunUrl} target="_blank" rel="noreferrer" className="underline">
              workflow log
            </a>
          </dd>
        </>
      )}
    </dl>
  );
}

export function RemediationPanel({
  jobId,
  finding,
  existingRemediation,
  onRemediationUpdated,
  mode = "review",
}: {
  jobId: string;
  finding: PublicFinding;
  existingRemediation?: PublicRemediation | null;
  onRemediationUpdated?: (rem: PublicRemediation) => void;
  mode?: "review" | "autofix";
}) {
  const [remediation, setRemediation] = useState<PublicRemediation | null>(existingRemediation ?? null);
  const [isGenerating, setIsGenerating] = useState(false);
  const [isApproving, setIsApproving] = useState(false);
  const [isApplying, setIsApplying] = useState(false);
  const [isOpeningPr, setIsOpeningPr] = useState(false);
  const [prError, setPrError] = useState<{ code: string; message: string } | null>(null);
  const [approvedChecked, setApprovedChecked] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Restore the latest remediation for this finding after a reload, so a verified fix and its
  // pull request state are shown instead of offering a fresh preview.
  useEffect(() => {
    if (existingRemediation) return;
    let cancelled = false;
    listRemediations(jobId)
      .then((list) => {
        const latest = list
          .filter((r) => r.findingFingerprints.includes(finding.fingerprint) && r.status !== "rejected")
          .sort((a, b) => b.createdAt.localeCompare(a.createdAt))[0];
        if (!cancelled && latest) setRemediation((current) => current ?? latest);
      })
      .catch(() => undefined);
    return () => {
      cancelled = true;
    };
  }, [jobId, finding.fingerprint, existingRemediation]);

  const initialEligibility = classifyRemediationEligibility(finding);
  const effectiveEligibility = remediation?.eligibility ?? initialEligibility.eligibility;
  const isSecret = initialEligibility.requiresRotation || finding.category === "Secrets" || finding.ruleId.includes("secret") || finding.ruleId.includes("token");

  const onGeneratePreview = async () => {
    setIsGenerating(true);
    setError(null);
    try {
      const res = await createRemediationPreview(jobId, finding.id);
      setRemediation(res);
      onRemediationUpdated?.(res);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to generate preview.");
    } finally {
      setIsGenerating(false);
    }
  };

  const onApprove = async () => {
    if (!remediation) return;
    setIsApproving(true);
    setError(null);
    try {
      const res = await approveRemediation(jobId, remediation.id);
      setRemediation(res);
      onRemediationUpdated?.(res);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Approval failed.");
    } finally {
      setIsApproving(false);
    }
  };

  // Verification runs on the scanner worker; poll until it reports a final result.
  const pollVerification = useCallback(async () => {
    if (!remediation) return false;
    const list = await listRemediations(jobId);
    const fresh = list.find((r) => r.id === remediation.id);
    if (!fresh) return false;
    if (fresh.status !== remediation.status || fresh.updatedAt !== remediation.updatedAt) {
      setRemediation(fresh);
      onRemediationUpdated?.(fresh);
    }
    return fresh.status === "applied";
  }, [jobId, remediation, onRemediationUpdated]);
  useAdaptivePoll(pollVerification, remediation?.status === "applied", { initialMs: 3000, maxMs: 5000 });

  const onApplyAndVerify = async () => {
    if (!remediation) return;
    setIsApplying(true);
    setError(null);
    try {
      const res = await applyRemediation(jobId, remediation.id);
      setRemediation(res);
      onRemediationUpdated?.(res);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Application and rescan failed.");
    } finally {
      setIsApplying(false);
    }
  };

  const onOpenPr = async () => {
    if (!remediation || isOpeningPr) return;
    setIsOpeningPr(true);
    setPrError(null);
    try {
      const res = await createRemediationPr(jobId, remediation.id);
      setRemediation(res.remediation);
      onRemediationUpdated?.(res.remediation);
    } catch (err) {
      setPrError({
        code: err instanceof ApiRequestError ? err.code : "network_error",
        message: err instanceof Error ? err.message : "Failed to create pull request.",
      });
      // The server records failed attempts; refresh so the panel shows the stored state.
      const fresh = await listRemediations(jobId)
        .then((list) => list.find((r) => r.id === remediation.id))
        .catch(() => undefined);
      if (fresh) setRemediation(fresh);
    } finally {
      setIsOpeningPr(false);
    }
  };

  const patchDownloadUrl = remediation ? `/api/scans/${jobId}/remediation/${remediation.id}/patch` : undefined;

  return (
    <div className="rounded-xl border border-line bg-surface/50 p-4 space-y-4">
      {/* Header & Eligibility indicator */}
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-line pb-3">
        <div className="flex items-center gap-2">
          <Sparkles className="size-4 text-accent" />
          <h4 className="text-sm font-semibold text-foreground">
            {mode === "review" ? "AI Proposed Patch (Review Only)" : "AI Auto-Fix & Verification"}
          </h4>
          <span className="rounded bg-surface-subtle border border-line px-2 py-0.5 font-mono text-[10px] text-muted uppercase">
            {mode === "review" ? "Mode A: Read-Only" : "Mode B: Auto-Fix"}
          </span>
        </div>

        {isSecret ? (
          <span className="inline-flex items-center gap-1 rounded-full bg-sev-critical/15 px-2.5 py-0.5 text-xs font-semibold text-sev-critical">
            <ShieldAlert className="size-3" /> Manual Credential Rotation Required
          </span>
        ) : effectiveEligibility === "safe" ? (
          <span className="inline-flex items-center gap-1 rounded-full bg-accent/15 px-2.5 py-0.5 text-xs font-semibold text-accent">
            <ShieldCheck className="size-3" /> Safe to Auto-Fix
          </span>
        ) : effectiveEligibility === "potentially_breaking" ? (
          <span className="inline-flex items-center gap-1 rounded-full bg-sev-medium/15 px-2.5 py-0.5 text-xs font-semibold text-sev-medium">
            <AlertTriangle className="size-3" /> Potentially Breaking Change
          </span>
        ) : (
          <span className="inline-flex items-center gap-1 rounded-full bg-surface-subtle px-2.5 py-0.5 text-xs font-semibold text-muted">
            Manual Review Required
          </span>
        )}
      </div>

      {/* Secret Rotation Warning */}
      {isSecret && (
        <div className="rounded-lg border border-sev-critical/30 bg-sev-critical/10 p-3 text-xs space-y-2">
          <div className="flex items-center gap-2 font-semibold text-sev-critical">
            <ShieldAlert className="size-4" /> Leaked Credentials Cannot Be Auto-Fixed
          </div>
          <p className="text-muted leading-relaxed">
            Removing this secret from source files does <strong>not</strong> revoke it with the service provider, and it
            remains exposed in your Git commit history.
          </p>
          <ul className="list-disc pl-4 space-y-1 text-muted">
            <li>Immediately rotate or invalidate this token in the provider&apos;s management console.</li>
            <li>Purge the compromised commit from your repository history using <code>git-filter-repo</code>.</li>
            <li>Store active secrets in environment variables or a secrets manager.</li>
          </ul>
        </div>
      )}

      {/* Errors */}
      {error && (
        <div className="rounded-lg border border-sev-critical/30 bg-sev-critical/10 p-3 text-xs text-sev-critical flex items-center gap-2">
          <AlertCircle className="size-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Action to generate preview if none yet */}
      {!remediation && !isSecret && (
        <div className="space-y-3">
          <p className="text-xs text-muted leading-relaxed">
            Generate an exact, reviewable unified diff to resolve <strong>{finding.ruleId}</strong>. No repository files
            will be modified without your explicit approval.
          </p>
          <Button onClick={onGeneratePreview} disabled={isGenerating} size="sm">
            {isGenerating ? (
              <>
                <Loader2 className="size-3.5 animate-spin" /> Generating Safe Patch…
              </>
            ) : (
              <>
                <Terminal className="size-3.5" /> Preview Proposed Patch
              </>
            )}
          </Button>
        </div>
      )}

      {/* Reviewable Diff & Approval Flow */}
      {remediation && remediation.unifiedDiff && (
        <div className="space-y-4">
          <DiffViewer
            diff={remediation.unifiedDiff}
            patchUrl={patchDownloadUrl}
            summary={remediation.patchSummary}
          />

          {/* Warnings if any */}
          {remediation.warnings && remediation.warnings.length > 0 && (
            <div className="rounded-lg border border-sev-medium/30 bg-sev-medium/10 p-3 text-xs space-y-1">
              <div className="font-semibold text-sev-medium flex items-center gap-1.5">
                <AlertTriangle className="size-3.5" /> Important Considerations
              </div>
              <ul className="list-disc pl-4 text-muted space-y-0.5">
                {remediation.warnings.map((w, idx) => (
                  <li key={idx}>{w}</li>
                ))}
              </ul>
            </div>
          )}

          {/* Status: Preview -> Requires Approval */}
          {remediation.status === "preview" && (
            <div className="rounded-lg border border-line bg-surface p-3 space-y-3">
              {mode === "review" ? (
                <div className="space-y-2">
                  <p className="text-xs text-muted leading-relaxed">
                    <strong className="text-foreground">Mode A — Review Only:</strong> Proposed diff is displayed above for inspection. No repository files will be modified. You may copy the diff or download the standalone patch file.
                  </p>
                  <p className="text-[11px] text-muted">
                    To apply this patch and rescan in an isolated sandbox, switch to <strong>Mode B (AI Auto-Fix)</strong> in the report view.
                  </p>
                  {patchDownloadUrl && (
                    <a
                      href={patchDownloadUrl}
                      download
                      className="inline-flex items-center gap-1.5 h-8 px-3 rounded-lg border border-line hover:border-line-bright text-xs font-medium text-foreground transition-colors"
                    >
                      Download .patch
                    </a>
                  )}
                </div>
              ) : (
                <>
                  <label className="flex items-start gap-2.5 text-xs text-foreground cursor-pointer select-none">
                    <input
                      type="checkbox"
                      checked={approvedChecked}
                      onChange={(e) => setApprovedChecked(e.target.checked)}
                      className="mt-0.5 rounded border-line text-accent focus:ring-accent"
                    />
                    <span>
                      I have reviewed the proposed diff and authorize applying it in an isolated sandbox for security verification.
                    </span>
                  </label>

                  <div className="flex items-center gap-2">
                    <Button onClick={onApprove} disabled={!approvedChecked || isApproving} size="sm">
                      {isApproving ? <Loader2 className="size-3.5 animate-spin" /> : <CheckCircle2 className="size-3.5" />}
                      Approve Patch
                    </Button>
                    {patchDownloadUrl && (
                      <a
                        href={patchDownloadUrl}
                        download
                        className="inline-flex items-center gap-1.5 h-8 px-3 rounded-lg border border-line hover:border-line-bright text-xs font-medium text-foreground transition-colors"
                      >
                        Download .patch
                      </a>
                    )}
                  </div>
                </>
              )}
            </div>
          )}

          {/* Status: Approved -> Apply & Rescan */}
          {remediation.status === "approved" && (
            <div className="rounded-lg border border-line bg-surface p-3 space-y-3">
              <div className="flex items-center gap-2 text-xs font-semibold text-foreground">
                <CheckCircle2 className="size-4 text-accent" /> Patch Approved by User
              </div>
              <p className="text-xs text-muted">
                Rebuild the scanned commit, apply this patch in an isolated workspace, and rescan the whole repository to
                verify whether <strong>{finding.ruleId}</strong> is resolved without introducing new findings.
              </p>
              <Button onClick={onApplyAndVerify} disabled={isApplying} size="sm">
                {isApplying ? (
                  <>
                    <Loader2 className="size-3.5 animate-spin" /> Starting verification…
                  </>
                ) : (
                  <>
                    <ShieldCheck className="size-3.5" /> Verify Fix on Full Repository
                  </>
                )}
              </Button>
            </div>
          )}

          {/* Verification running on the worker */}
          {remediation.status === "applied" && (
            <div className="rounded-lg border border-accent/40 bg-accent/5 p-3 space-y-1 text-xs" role="status" aria-live="polite">
              <div className="flex items-center gap-2 font-semibold text-foreground">
                <Loader2 className="size-4 animate-spin text-accent" /> Verifying on the scanner worker…
              </div>
              <p className="text-muted">
                The full repository at commit <code>{remediation.commitSha.slice(0, 7)}</code> is being rebuilt, patched,
                and rescanned with Gitleaks, Semgrep, and OSV-Scanner. This usually takes under a minute.
              </p>
            </div>
          )}

          {remediation.status === "failed" && (
            <div className="rounded-lg border border-sev-high/40 bg-sev-high/10 p-3 text-xs space-y-2">
              <div className="flex items-center gap-2 font-bold text-sev-high">
                <AlertCircle className="size-4" /> Verification Failed — Nothing Was Verified
              </div>
              <p className="text-muted">
                {FAILURE_REASONS[remediation.rescanSummary?.reason ?? ""] ??
                  remediation.rescanSummary?.detail ??
                  "Verification could not complete."}
              </p>
              {remediation.rescanSummary && <VerificationDetails summary={remediation.rescanSummary} />}
              <Button onClick={onApprove} disabled={isApproving} size="sm" variant="secondary">
                {isApproving ? <Loader2 className="size-3.5 animate-spin" /> : <ShieldCheck className="size-3.5" />}
                Approve Again to Retry
              </Button>
            </div>
          )}

          {/* Rescan Results */}
          {(remediation.status === "verified" || remediation.status === "needs_review") && (
            <div className="space-y-3">
              {remediation.rescanStatus === "verified" ? (
                <div className="rounded-lg border border-accent/40 bg-accent/10 p-3 text-xs space-y-1">
                  <div className="flex items-center gap-2 font-bold text-accent">
                    <ShieldCheck className="size-4" /> Fix Verified by Security Rescan
                  </div>
                  <p className="text-muted">
                    The patched repository was rescanned by all three scanners: the target finding is resolved and no new
                    findings were introduced.
                  </p>
                  {remediation.rescanSummary && <VerificationDetails summary={remediation.rescanSummary} />}
                </div>
              ) : (
                <div className="rounded-lg border border-sev-medium/40 bg-sev-medium/10 p-3 text-xs space-y-1">
                  <div className="flex items-center gap-2 font-bold text-sev-medium">
                    <AlertTriangle className="size-4" /> Verification Incomplete or Regressions Detected
                  </div>
                  <p className="text-muted">
                    {FAILURE_REASONS[remediation.rescanSummary?.reason ?? ""] ??
                      "Rescan found remaining issues or regressions. Please inspect the patch carefully."}
                  </p>
                  {remediation.rescanSummary && <VerificationDetails summary={remediation.rescanSummary} />}
                </div>
              )}

              <PullRequestSection
                remediation={remediation}
                isOpening={isOpeningPr}
                requestError={prError}
                onOpen={onOpenPr}
                patchDownloadUrl={patchDownloadUrl}
              />
            </div>
          )}
        </div>
      )}
    </div>
  );
}
