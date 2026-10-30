import { log } from "../errors";
import { checkRepositoryAccess } from "../auth/github-app";
import { isMissingTable, loadScanAccess } from "../auth/repository-access";
import { getUserToken, markRevoked } from "../auth/service";
import type { SafeAutoFixRecord } from "../auth/store";
import { compareVersions, isNpmLockfileFinding, parseVersion } from "./npm-lockfile";
import { remediationBranchName, type PrFailureCode, type PullRequestState } from "./github-pr";
import {
  applyAndVerify,
  approveRemediation,
  createPreview,
  pullRequestStateOf,
  RemediationError,
  requestPullRequest,
  type ApprovalBinding,
  type RemediationDeps,
} from "./service";

/**
 * What happens after a person (or the Safe Auto-Fix policy) has approved an exact diff:
 *  - publishing: once the patch passed the full security rescan, the branch, commit and pull
 *    request are created with the approving user's own GitHub authorization, re-checked live;
 *  - Safe Auto-Fix: for a repository whose owner explicitly opted in, fixes the server classifies
 *    as safe are generated, approved by policy and verified, then published the same way.
 * Nothing here runs without a stored approval that names the exact diff, commit, repository and user.
 */

/** A publish that stopped updating longer than this did not finish; another attempt is safe (idempotent). */
const PUBLISH_STALE_MS = 2 * 60_000;
/** Bounded work per Safe Auto-Fix run (registry and GitHub requests per package). */
export const SAFE_AUTOFIX_MAX_PACKAGES = 25;

export async function safeAutoFixSetting(deps: RemediationDeps, githubRepoId: number | null | undefined): Promise<SafeAutoFixRecord | null> {
  if (!deps.auth?.app || githubRepoId == null) return null;
  try {
    return await deps.auth.store.getSafeAutoFix(githubRepoId);
  } catch (err) {
    if (isMissingTable(err)) return null; // migration not applied yet: the feature is off
    throw err;
  }
}

async function recordPublishFailure(
  scanJobId: string,
  remediationId: string,
  deps: RemediationDeps,
  code: PrFailureCode,
  message: string,
  openedBy?: { githubUserId: number; login: string },
): Promise<PullRequestState> {
  const current = await deps.store.getRemediation(scanJobId, remediationId);
  const state: PullRequestState = {
    status: "failed",
    code,
    message,
    branch: remediationBranchName(scanJobId, remediationId),
    openedBy,
    at: new Date().toISOString(),
  };
  await deps.store.updateRemediation(scanJobId, remediationId, {
    approvedOperations: { ...((current?.approvedOperations as Record<string, unknown> | null) ?? {}), pullRequest: state },
  });
  return state;
}

/**
 * Publishes a verified remediation whose approval included consent to publish. Returns the stored
 * pull-request state, or null when there is nothing to publish (not verified, no consent).
 * Idempotent: a created PR is returned as is, a running attempt is left alone, retries converge on
 * the same branch and pull request.
 */
export async function publishVerifiedRemediation(scanJobId: string, remediationId: string, deps: RemediationDeps): Promise<PullRequestState | null> {
  const auth = deps.auth;
  if (!auth?.app) return null;
  const job = await deps.store.get(scanJobId);
  const rem = await deps.store.getRemediation(scanJobId, remediationId);
  if (!job || !rem || rem.status !== "verified" || rem.rescanStatus !== "verified") return null;
  const binding = rem.approvedOperations as Partial<ApprovalBinding> | null;
  const consent = binding?.publish;
  if (!consent || !binding?.diffSha256 || !binding.ownerSubject) return null;

  const last = pullRequestStateOf(rem.approvedOperations);
  if (last && (last.status === "created" || last.status === "exists")) return last;
  if (last?.status === "in_progress" && Date.now() - Date.parse(last.at) < PUBLISH_STALE_MS) return last;
  const fail = (code: PrFailureCode, message: string) => recordPublishFailure(scanJobId, remediationId, deps, code, message, consent);

  if (binding.approvedBy === "safe_autofix") {
    const setting = await safeAutoFixSetting(deps, binding.githubRepoId);
    if (!setting || setting.enabledByGithubUserId !== consent.githubUserId) {
      return fail("publish_cancelled", "Safe Auto-Fix was turned off for this repository before publishing. Nothing was created.");
    }
  }

  // The approving user's own authorization, re-checked live with GitHub right before any write.
  const account = await auth.store.getAccountByGithubUserId(consent.githubUserId);
  if (!account) {
    return fail("credential_invalid", "The approving GitHub account is no longer connected (disconnected or revoked). Nothing was created; reconnect GitHub and retry.");
  }
  const token = await getUserToken(account, auth);
  if ("error" in token) {
    return fail("credential_invalid", "The approving GitHub authorization expired or was revoked. Nothing was created; reconnect GitHub and retry.");
  }
  const scanAccess = await loadScanAccess(auth, job.id);
  const access = await checkRepositoryAccess(token.token, job.owner, job.repo, auth.fetchImpl);
  if (access.status === "unauthorized") {
    await markRevoked(account, auth, "token_rejected");
    return fail("credential_invalid", "GitHub rejected the approving authorization. Nothing was created; reconnect GitHub and retry.");
  }
  if (access.status === "rate_limited") return fail("rate_limited", "GitHub API rate limit reached. Nothing was created; it is retried when the report is open.");
  if (access.status !== "ok") return fail("repository_not_found", "The repository is not visible to the approving GitHub account. Nothing was created.");
  if (access.repoId !== binding.githubRepoId || (scanAccess && access.repoId !== scanAccess.githubRepoId)) {
    return fail("repository_mismatch", "The repository on GitHub is no longer the one that was scanned and approved. Nothing was created.");
  }
  if (!access.installed || !access.canPush || !access.appCanWrite) {
    return fail("access_denied", "The approving GitHub account can no longer write to this repository through VibeShield. Nothing was created.");
  }

  try {
    const { pullRequest } = await requestPullRequest(scanJobId, remediationId, deps, {
      githubUserId: account.githubUserId,
      login: account.login,
      token: token.token,
      repoId: access.repoId!,
      // The diff the person (or policy) approved; requestPullRequest re-checks it against the stored diff.
      confirmedDiffSha256: binding.diffSha256,
      ownerSubject: binding.ownerSubject,
    });
    await auth.store.audit({
      action: "pull_request",
      outcome: pullRequest.status === "failed" ? `failed:${pullRequest.code}` : pullRequest.status,
      githubUserId: account.githubUserId,
      githubLogin: account.login,
      scanJobId,
      remediationId,
      repository: `${job.owner}/${job.repo}`,
      detail: `${binding.approvedBy === "safe_autofix" ? "safe auto-fix" : "auto-publish after approval"}${pullRequest.number ? ` #${pullRequest.number}` : ""}`,
    });
    return pullRequest;
  } catch (err) {
    if (err instanceof RemediationError) return fail("approval_invalid", err.message);
    log("error", "remediation_publish_failed", { jobId: scanJobId, remediationId });
    return fail("github_error", "Publishing failed unexpectedly. Nothing is reported as created; it is retried when the report is open.");
  }
}

/**
 * Recovery: publishes verified remediations whose approval included consent and that have no
 * final pull-request state (e.g. the request that should have published was interrupted).
 * One per call, so a page poll stays cheap.
 */
export async function pumpPublications(scanJobId: string, deps: RemediationDeps): Promise<number> {
  if (!deps.auth?.app) return 0;
  const list = await deps.store.listRemediations(scanJobId);
  const due = list.find((r) => {
    if (r.status !== "verified" || r.rescanStatus !== "verified") return false;
    if (!(r.approvedOperations as Partial<ApprovalBinding> | null)?.publish) return false;
    const pr = pullRequestStateOf(r.approvedOperations);
    if (!pr) return true;
    if (pr.status === "in_progress") return Date.now() - Date.parse(pr.at) >= PUBLISH_STALE_MS;
    // Transient failures are retried; decisions (cancelled, revoked, mismatched) wait for the user.
    return pr.status === "failed" && (pr.code === "rate_limited" || pr.code === "network_error") && Date.now() - Date.parse(pr.at) >= PUBLISH_STALE_MS;
  });
  if (!due) return 0;
  await publishVerifiedRemediation(scanJobId, due.id, deps);
  return 1;
}

export type SafeAutoFixRun = { considered: number; safe: number; notSafe: number; skipped: number; started: string[] };

/**
 * Safe Auto-Fix for one scan of a repository that opted in: for each vulnerable npm package (at most
 * SAFE_AUTOFIX_MAX_PACKAGES per run) without an existing remediation, generate the fix; only a fix
 * the server classified as "safe" is approved by policy and verified (it is published after it
 * passes). Everything else is left as a preview for a person to review.
 */
export async function runSafeAutoFix(scanJobId: string, deps: RemediationDeps): Promise<SafeAutoFixRun> {
  const run: SafeAutoFixRun = { considered: 0, safe: 0, notSafe: 0, skipped: 0, started: [] };
  const auth = deps.auth;
  const job = await deps.store.get(scanJobId);
  if (!auth?.app || !job || job.status !== "completed") return run;
  const scanAccess = await loadScanAccess(auth, scanJobId);
  if (!scanAccess || scanAccess.isPrivate) return run; // private repositories are never auto-fixed
  const setting = await safeAutoFixSetting(deps, scanAccess.githubRepoId);
  if (!setting) return run;

  const { findings } = await deps.store.getFindings(scanJobId, { limit: 1000 });
  const existing = new Set(
    (await deps.store.listRemediations(scanJobId)).filter((r) => r.status !== "rejected").flatMap((r) => r.findingFingerprints),
  );
  const groups = new Map<string, typeof findings>();
  for (const f of findings) {
    const p = (f.packageInfo ?? {}) as { name?: string; version?: string; fixedVersion?: string | null };
    if (!isNpmLockfileFinding(f) || !p.name || !p.version || !p.fixedVersion) continue;
    if (!parseVersion(p.fixedVersion) || !parseVersion(p.version) || compareVersions(p.fixedVersion, p.version) <= 0) continue;
    const key = `${f.filePath}|${p.name}|${p.version}`;
    groups.set(key, [...(groups.get(key) ?? []), f]);
  }
  const audit = (outcome: string, detail: string, remediationId?: string) =>
    auth.store.audit({
      action: "safe_autofix",
      outcome,
      githubUserId: setting.enabledByGithubUserId,
      githubLogin: setting.enabledByLogin,
      scanJobId,
      remediationId: remediationId ?? null,
      repository: `${job.owner}/${job.repo}`,
      detail,
    });

  const ownerSubject = `safe-autofix:${setting.enabledByGithubUserId}`;
  for (const [key, group] of groups) {
    if (group.some((f) => existing.has(f.fingerprint))) {
      run.skipped++;
      continue;
    }
    if (run.considered >= SAFE_AUTOFIX_MAX_PACKAGES) break;
    run.considered++;
    // Start from the advisory with the lowest fixed release: it is the one npm can reach inside the
    // parents' ranges; the generator then includes every other advisory that release also fixes.
    const fixedOf = (f: (typeof group)[number]) => (f.packageInfo as { fixedVersion: string }).fixedVersion;
    const representative = [...group].sort((a, b) => compareVersions(fixedOf(a), fixedOf(b)))[0];
    const preview = await createPreview(scanJobId, representative.id, deps);
    for (const fp of preview.findingFingerprints) existing.add(fp);
    if (preview.eligibility !== "safe" || !preview.unifiedDiff) {
      run.notSafe++;
      await audit("left_for_review", `${key.split("|").slice(1).join("@")}: ${preview.eligibility}`, preview.id);
      continue;
    }
    run.safe++;
    try {
      await approveRemediation(scanJobId, preview.id, deps, {
        ownerSubject,
        approvedBy: "safe_autofix",
        githubUserId: setting.enabledByGithubUserId,
        githubRepoId: scanAccess.githubRepoId,
        publish: { githubUserId: setting.enabledByGithubUserId, login: setting.enabledByLogin },
      });
      const verifying = await applyAndVerify(scanJobId, preview.id, deps, { ownerSubject });
      run.started.push(preview.id);
      await audit("verification_started", key.split("|").slice(1).join("@"), preview.id);
      // In-process verification (local runtime) finishes here; the worker callback publishes otherwise.
      if (verifying.status === "verified") await publishVerifiedRemediation(scanJobId, preview.id, deps);
    } catch (err) {
      await audit("failed", err instanceof Error ? err.message.slice(0, 200) : "unknown", preview.id);
    }
  }
  log("info", "safe_autofix_run", { jobId: scanJobId, ...run, started: run.started.length });
  return run;
}
