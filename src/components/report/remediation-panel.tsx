"use client";

import { useState } from "react";
import {
  AlertCircle,
  AlertTriangle,
  CheckCircle2,
  GitBranch,
  GitPullRequest,
  Loader2,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Terminal,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  applyRemediation,
  approveRemediation,
  createRemediationPreview,
  createRemediationPr,
  type PublicFinding,
  type PublicRemediation,
} from "@/lib/scan-client";
import { DiffViewer } from "./diff-viewer";
import { classifyRemediationEligibility } from "@/lib/remediation-eligibility";

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
  const [prResult, setPrResult] = useState<{ url?: string; message: string; hasWriteAccess: boolean } | null>(null);
  const [approvedChecked, setApprovedChecked] = useState(false);
  const [error, setError] = useState<string | null>(null);

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
    if (!remediation) return;
    setIsOpeningPr(true);
    setError(null);
    try {
      const res = await createRemediationPr(jobId, remediation.id);
      setRemediation(res.remediation);
      setPrResult({
        url: res.remediation.pullRequestUrl ?? undefined,
        message: res.message,
        hasWriteAccess: res.hasWriteAccess,
      });
      onRemediationUpdated?.(res.remediation);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create pull request.");
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
                Run security rescan in an isolated sandbox to verify whether <strong>{finding.ruleId}</strong> is resolved
                without introducing regressions.
              </p>
              <Button onClick={onApplyAndVerify} disabled={isApplying} size="sm">
                {isApplying ? (
                  <>
                    <Loader2 className="size-3.5 animate-spin" /> Testing &amp; Rescanning…
                  </>
                ) : (
                  <>
                    <ShieldCheck className="size-3.5" /> Verify Fix in Sandbox
                  </>
                )}
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
                    Target finding was successfully resolved in sandbox. Zero new security regressions detected.
                  </p>
                </div>
              ) : (
                <div className="rounded-lg border border-sev-medium/40 bg-sev-medium/10 p-3 text-xs space-y-1">
                  <div className="flex items-center gap-2 font-bold text-sev-medium">
                    <AlertTriangle className="size-4" /> Verification Incomplete or Regressions Detected
                  </div>
                  <p className="text-muted">
                    Rescan found remaining issues or regressions. Please inspect the patch carefully.
                  </p>
                </div>
              )}

              {/* GitHub PR or Download Patch Flow */}
              <div className="rounded-lg border border-line bg-surface p-3 space-y-3">
                <div className="flex items-center gap-2 text-xs font-semibold text-foreground">
                  <GitBranch className="size-4 text-accent" /> Branch &amp; Pull Request Flow
                </div>
                <p className="text-xs text-muted">
                  Create a dedicated branch (<code>vibeshield/fixes/{jobId.slice(0, 8)}</code>) and open a Pull Request.
                  Default branch is never touched.
                </p>

                {prResult && (
                  <div
                    className={`rounded p-2.5 text-xs ${
                      prResult.url ? "bg-accent/10 text-accent border border-accent/30" : "bg-surface-subtle text-muted"
                    }`}
                  >
                    <p className="font-semibold">{prResult.message}</p>
                    {prResult.url && (
                      <a
                        href={prResult.url}
                        target="_blank"
                        rel="noreferrer"
                        className="mt-1 inline-flex items-center gap-1 underline font-mono text-[11px]"
                      >
                        View Pull Request on GitHub &rarr;
                      </a>
                    )}
                  </div>
                )}

                <div className="flex flex-wrap items-center gap-2">
                  <Button onClick={onOpenPr} disabled={isOpeningPr} size="sm">
                    {isOpeningPr ? (
                      <Loader2 className="size-3.5 animate-spin" />
                    ) : (
                      <GitPullRequest className="size-3.5" />
                    )}
                    Open GitHub Pull Request
                  </Button>
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
            </div>
          )}
        </div>
      )}
    </div>
  );
}
