import { z } from "zod";
import { fail, ok } from "../api";
import { log } from "../errors";
import { JOB_ID_RE, type JobRecord, type JobStore } from "../job-store";
import { decryptSecret, encryptSecret, randomToken, sha256Hex } from "./crypto";
import { addRepositoryToInstallation, checkRepositoryAccess, GithubAuthError, type RepoAccess } from "./github-app";
import { checkJobAccess, isMissingTable } from "./repository-access";
import { isSameOrigin, markRevoked, resolveAuthorizedUser, type AuthDeps } from "./service";
import type { AccountRecord, ScanAccessRecord } from "./store";

/**
 * Per-repository authorization from inside VibeShield.
 *
 * GitHub limits a user-to-server token to the repositories selected in the app installation. When
 * the scanned repository is not selected yet, a repository administrator can add exactly that
 * repository (by immutable ID) to the existing installation on the owner's account through
 * PUT /user/installations/{installation_id}/repositories/{repository_id}, which requires the app's
 * "GitHub App installation repository access: write" permission. Nothing is added until the user
 * confirms a single-use request that binds their session, GitHub user, scan, scanned commit,
 * repository ID and installation ID; success is reported only after GitHub lists the repository in
 * the installation. Repositories are never removed and "All repositories" is never selected.
 */

export type RepositoryAuthorizationState =
  /** In the installation, the user can push, and Contents/Pull requests write are granted. */
  | "authorized"
  /** Not in the installation yet; this user can add it here (in-product authorization). */
  | "authorization_required"
  /** The installation lacks "installation repository access: write" (one-time app change). */
  | "app_setup_required"
  /** No installation of the app on the repository owner's account: GitHub's install flow. */
  | "installation_required"
  /** The user is not a repository administrator, which GitHub requires to add it. */
  | "admin_required"
  /** GitHub refused the addition for an organization repository: an owner must approve it. */
  | "organization_approval_required"
  /** The user cannot push to the repository. */
  | "no_push_permission"
  /** In the installation, but Contents or Pull requests write is not granted. */
  | "app_lacks_permission";

export const STATE_MESSAGES: Record<RepositoryAuthorizationState, string> = {
  authorized: "VibeShield can open a pull request in this repository with your GitHub authorization.",
  authorization_required:
    "VibeShield is not authorized for this repository yet. You are an administrator, so you can authorize this one repository here.",
  app_setup_required:
    "The VibeShield GitHub App cannot add repositories for you yet: its \"GitHub App installation repository access\" permission is not granted on this installation. Until that one-time change is approved, add this repository on GitHub's installation page.",
  installation_required:
    "The VibeShield GitHub App is not installed on this account. Install it on GitHub and select this repository; for an organization, an owner may need to approve the request.",
  admin_required:
    "Only a repository administrator can authorize VibeShield for this repository. Ask an administrator to add it to the VibeShield installation; you can keep using the scan report and the .patch download.",
  organization_approval_required:
    "GitHub requires approval from an organization owner before VibeShield can access this repository. Request it through GitHub's installation page.",
  no_push_permission: "Your GitHub account cannot push to this repository, so VibeShield cannot open a pull request with it.",
  app_lacks_permission:
    "The installation lacks Contents or Pull requests write permission. The installation owner must approve the app's permissions on GitHub.",
};

/** What the user may do next, from GitHub's live answer for their own token. */
export function repositoryAuthorizationState(a: RepoAccess): RepositoryAuthorizationState {
  if (a.installed) {
    if (!a.appCanWrite) return "app_lacks_permission";
    return a.canPush ? "authorized" : "no_push_permission";
  }
  const inst = a.ownerInstallation;
  if (!inst || inst.repositorySelection === "all") return "installation_required";
  if (!a.canAdmin) return a.canPush ? "admin_required" : "no_push_permission";
  if (!inst.canAddRepositories) return "app_setup_required";
  return "authorization_required";
}

/** GitHub's own page for reviewing or changing one installation's repositories. */
export function installationSettingsUrl(a: RepoAccess): string | null {
  const inst = a.ownerInstallation;
  if (!inst) return null;
  return a.ownerType === "Organization"
    ? `https://github.com/organizations/${encodeURIComponent(inst.accountLogin)}/settings/installations/${inst.id}`
    : `https://github.com/settings/installations/${inst.id}`;
}

const INTENT_TTL_MS = 10 * 60_000;
/** GitHub may take a moment to list a newly added repository. */
const RECHECK_ATTEMPTS = 3;

type Binding = {
  v: 1;
  jobId: string;
  ownerSubject: string;
  githubUserId: number;
  repoId: number;
  fullName: string;
  installationId: number;
  commitSha: string;
  remediationId: string | null;
};

const RequestSchema = z.discriminatedUnion("action", [
  z.object({ action: z.literal("prepare"), remediationId: z.string().regex(/^[0-9a-f-]{36}$/).optional() }),
  z.object({
    action: z.literal("confirm"),
    intent: z.string().regex(/^[A-Za-z0-9_-]{20,100}$/),
    repositoryId: z.number().int().positive(),
    installationId: z.number().int().positive(),
  }),
  z.object({ action: z.literal("cancel"), intent: z.string().regex(/^[A-Za-z0-9_-]{20,100}$/) }),
]);

const COMMIT_SHA_RE = /^[0-9a-f]{40}$/;

export type RepositoryAuthorizationDeps = {
  auth: AuthDeps;
  jobs: Pick<JobStore, "get" | "getRemediation">;
  /** Delay between post-addition re-checks (tests use 0). */
  recheckDelayMs?: number;
};

const nowOf = (deps: AuthDeps) => (deps.now ?? (() => new Date()))();

function publicRepository(a: RepoAccess) {
  return {
    id: a.repoId!,
    fullName: a.fullName!,
    defaultBranch: a.defaultBranch ?? null,
    isPrivate: Boolean(a.isPrivate),
    ownerType: a.ownerType ?? null,
    canPush: Boolean(a.canPush),
    canAdmin: Boolean(a.canAdmin),
  };
}

function publicInstallation(a: RepoAccess) {
  const inst = a.ownerInstallation;
  return inst ? { id: inst.id, account: inst.accountLogin, repositorySelection: inst.repositorySelection } : null;
}

function links(job: Pick<JobRecord, "id">, a: RepoAccess | null) {
  const returnTo = encodeURIComponent(`/report/${job.id}`);
  return {
    install: `/api/auth/github/install?returnTo=${returnTo}`,
    installationSettings: a ? installationSettingsUrl(a) : null,
  };
}

type Live =
  | { ok: true; access: RepoAccess }
  | { ok: false; status: number; code: string; message: string };

/** Live repository check with the user's own token; the scan's stored repository ID must still match. */
async function liveAccess(
  deps: AuthDeps,
  account: AccountRecord,
  token: string,
  job: Pick<JobRecord, "owner" | "repo">,
  scanAccess: ScanAccessRecord | null,
): Promise<Live> {
  const access = await checkRepositoryAccess(token, job.owner, job.repo, deps.fetchImpl);
  if (access.status === "unauthorized") {
    await markRevoked(account, deps, "token_rejected");
    return { ok: false, status: 401, code: "authorization_revoked", message: "Your GitHub authorization was revoked. Connect GitHub again." };
  }
  if (access.status === "rate_limited") return { ok: false, status: 429, code: "rate_limited", message: "GitHub API rate limit reached. Try again later." };
  if (access.status === "error") {
    return { ok: false, status: 502, code: "github_unavailable", message: "Could not verify access with GitHub. Nothing was changed; retrying is safe." };
  }
  if (access.status === "not_found" || !access.canRead) {
    return { ok: false, status: 403, code: "repository_not_found", message: "Your GitHub account cannot see this repository." };
  }
  if (scanAccess && access.repoId !== scanAccess.githubRepoId) {
    return {
      ok: false,
      status: 409,
      code: "repository_changed",
      message: "The repository on GitHub is no longer the one that was scanned (renamed, transferred or recreated).",
    };
  }
  return { ok: true, access };
}

/**
 * POST /api/scans/:id/repository-authorization
 *   { action: "prepare", remediationId? }  → live state; for an addable repository, a single-use request to confirm
 *   { action: "confirm", intent, repositoryId, installationId } → adds exactly that repository, then re-reads GitHub
 *   { action: "cancel", intent } → discards the request
 * The route has already checked that this browser owns the job (`ownerSubject`).
 */
export async function handleRepositoryAuthorization(
  req: Request,
  jobId: string,
  deps: RepositoryAuthorizationDeps,
  ownerSubject: string,
): Promise<Response> {
  const auth = deps.auth;
  if (!JOB_ID_RE.test(jobId)) return fail(404, "not_found", "Scan job not found.");
  if (!auth.app) return fail(503, "not_configured", "GitHub authorization is not configured on this deployment yet.");
  if (!isSameOrigin(req, auth.app)) return fail(403, "forbidden_origin", "Cross-site request refused.");

  let body: z.infer<typeof RequestSchema>;
  try {
    body = RequestSchema.parse(await req.json());
  } catch {
    return fail(400, "invalid_request", "Invalid repository authorization request.");
  }

  try {
    const job = await deps.jobs.get(jobId);
    if (!job) return fail(404, "not_found", "Scan job not found.");
    const gate = await checkJobAccess(req, auth, job);
    if (gate.denied) return gate.denied;
    const repository = `${job.owner}/${job.repo}`;

    const user = await resolveAuthorizedUser(req, auth);
    if (!user.ok) {
      const message =
        user.code === "not_connected"
          ? "Connect your GitHub account first."
          : user.code === "not_configured"
            ? "GitHub authorization is not configured on this deployment yet."
            : "Your GitHub authorization expired or was revoked. Connect GitHub again.";
      return fail(user.code === "not_configured" ? 503 : 401, user.code, message);
    }
    const { account, token, sessionId } = user;
    const audit = (outcome: string, detail?: string | null) =>
      auth.store.audit({
        action: "repository_authorization",
        outcome,
        githubUserId: account.githubUserId,
        githubLogin: account.login,
        scanJobId: job.id,
        remediationId: body.action === "prepare" ? (body.remediationId ?? null) : null,
        repository,
        detail: detail ?? null,
      });

    if (body.action === "cancel") {
      const st = await auth.store.consumeState(sha256Hex(body.intent), sessionId, "repo_access", nowOf(auth));
      await audit("cancelled", st ? null : "request already used or expired");
      return ok({ cancelled: true });
    }

    if (body.action === "prepare") {
      if (!job.commitSha || !COMMIT_SHA_RE.test(job.commitSha)) {
        return fail(409, "commit_unknown", "The scanned commit is unknown, so this repository cannot be authorized for a fix.");
      }
      if (body.remediationId && !(await deps.jobs.getRemediation(job.id, body.remediationId))) {
        return fail(404, "remediation_not_found", "Remediation not found.");
      }
      const live = await liveAccess(auth, account, token, job, gate.scanAccess);
      if (!live.ok) return fail(live.status, live.code, live.message);
      const a = live.access;
      const state = repositoryAuthorizationState(a);
      const result = {
        state,
        message: STATE_MESSAGES[state],
        repository: publicRepository(a),
        installation: publicInstallation(a),
        scannedCommit: job.commitSha,
        links: links(job, a),
        request: null as null | { intent: string; expiresAt: string },
      };
      if (state !== "authorization_required") return ok(result);

      const intent = randomToken();
      const binding: Binding = {
        v: 1,
        jobId: job.id,
        ownerSubject,
        githubUserId: account.githubUserId,
        repoId: a.repoId!,
        fullName: a.fullName!,
        installationId: a.ownerInstallation!.id,
        commitSha: job.commitSha,
        remediationId: body.remediationId ?? null,
      };
      const expiresAt = new Date(nowOf(auth).getTime() + INTENT_TTL_MS);
      await auth.store.createState({
        id: sha256Hex(intent),
        sessionId,
        purpose: "repo_access",
        returnTo: `/report/${job.id}`,
        codeVerifierEnc: encryptSecret(JSON.stringify(binding), auth.app.encryptionKey),
        expiresAt,
      });
      await audit("requested", `repo ${binding.repoId} installation ${binding.installationId}`);
      return ok({ ...result, request: { intent, expiresAt: expiresAt.toISOString() } });
    }

    // confirm: single use, bound to this browser session.
    const st = await auth.store.consumeState(sha256Hex(body.intent), sessionId, "repo_access", nowOf(auth));
    if (!st?.codeVerifierEnc) {
      await audit("rejected", "request invalid, expired or already used");
      return fail(409, "authorization_request_invalid", "This authorization request expired or was already used. Review the repository again.");
    }
    let binding: Binding;
    try {
      binding = JSON.parse(decryptSecret(st.codeVerifierEnc, auth.app.encryptionKey)) as Binding;
    } catch {
      await audit("rejected", "request unreadable");
      return fail(409, "authorization_request_invalid", "This authorization request is no longer valid. Review the repository again.");
    }
    // Everything the user saw and confirmed must be exactly what was bound when the dialog opened.
    const mismatch =
      binding.v !== 1 ||
      binding.jobId !== job.id ||
      binding.ownerSubject !== ownerSubject ||
      binding.githubUserId !== account.githubUserId ||
      binding.repoId !== body.repositoryId ||
      binding.installationId !== body.installationId ||
      binding.commitSha !== job.commitSha;
    if (mismatch) {
      await audit("rejected", "binding mismatch");
      return fail(409, "authorization_mismatch", "The authorization request does not match this scan, repository, installation or GitHub account.");
    }

    const live = await liveAccess(auth, account, token, job, gate.scanAccess);
    if (!live.ok) {
      await audit("denied", live.code);
      return fail(live.status, live.code, live.message);
    }
    let a = live.access;
    if (a.repoId !== binding.repoId) {
      await audit("rejected", "repository changed");
      return fail(409, "repository_changed", "The repository on GitHub is no longer the one you reviewed.");
    }
    if (a.ownerInstallation?.id !== binding.installationId) {
      await audit("rejected", "installation changed");
      return fail(409, "installation_changed", "The VibeShield installation for this account changed. Review the repository again.");
    }

    let added = false;
    if (!a.installed) {
      const state = repositoryAuthorizationState(a);
      if (state !== "authorization_required") {
        await audit("denied", state);
        return Response.json(
          { error: { code: state, message: STATE_MESSAGES[state] }, data: { state, links: links(job, a) } },
          { status: 403, headers: { "Cache-Control": "no-store" } },
        );
      }
      let result;
      try {
        result = await addRepositoryToInstallation(token, binding.installationId, binding.repoId, auth.fetchImpl);
      } catch (err) {
        if (err instanceof GithubAuthError && err.code === "unauthorized") {
          await markRevoked(account, auth, "token_rejected");
          await audit("failed", "authorization_revoked");
          return fail(401, "authorization_revoked", "Your GitHub authorization was revoked. Connect GitHub again.");
        }
        const code = err instanceof GithubAuthError && err.code === "rate_limited" ? "rate_limited" : "github_unavailable";
        await audit("failed", code);
        return fail(code === "rate_limited" ? 429 : 502, code, "GitHub did not confirm the change. Nothing is assumed; check the status and retry.");
      }
      if (result !== "added") {
        // GitHub's answer decides; nothing is retried with broader access.
        const refusal =
          result === "forbidden" && a.ownerType === "Organization"
            ? { code: "organization_approval_required", message: STATE_MESSAGES.organization_approval_required }
            : result === "forbidden"
              ? {
                  code: "github_forbidden",
                  message:
                    "GitHub refused to add this repository to the installation. It requires administrator access to the repository and the app's \"installation repository access\" permission. Nothing was changed.",
                }
              : result === "not_found"
                ? { code: "app_setup_required", message: STATE_MESSAGES.app_setup_required }
                : { code: "github_rejected", message: "GitHub rejected adding this repository to the installation. Nothing was changed." };
        await audit("denied", `github ${result}`);
        return Response.json(
          { error: refusal, data: { state: repositoryAuthorizationState(a), links: links(job, a) } },
          { status: 403, headers: { "Cache-Control": "no-store" } },
        );
      }
      added = true;

      // Success is what GitHub lists afterwards, not what the PUT returned.
      for (let i = 0; i < RECHECK_ATTEMPTS; i++) {
        if (i > 0 && (deps.recheckDelayMs ?? 1000) > 0) await new Promise((r) => setTimeout(r, deps.recheckDelayMs ?? 1000));
        const again = await liveAccess(auth, account, token, job, gate.scanAccess);
        if (!again.ok) {
          await audit("failed", `recheck ${again.code}`);
          return fail(again.status, again.code, again.message);
        }
        a = again.access;
        if (a.installed && a.installationId === binding.installationId && a.repoId === binding.repoId) break;
      }
      if (!a.installed || a.installationId !== binding.installationId || a.repoId !== binding.repoId) {
        await audit("not_confirmed", `repo ${binding.repoId} installation ${binding.installationId}`);
        return fail(
          502,
          "authorization_not_confirmed",
          "GitHub accepted the request but does not list the repository in the installation yet. It is not treated as authorized; check again shortly.",
        );
      }
    } else if (a.installationId !== binding.installationId) {
      await audit("rejected", "installed under a different installation");
      return fail(409, "installation_changed", "The repository is listed under a different installation. Review it again.");
    }

    const state = repositoryAuthorizationState(a);
    await audit(added ? "added" : "already_present", `repo ${binding.repoId} installation ${binding.installationId} state ${state}`);
    log("info", "repository_authorization", { jobId: job.id, added, state });
    return ok({
      state,
      added,
      message: STATE_MESSAGES[state],
      repository: publicRepository(a),
      installation: publicInstallation(a),
      links: links(job, a),
    });
  } catch (err) {
    if (isMissingTable(err)) return fail(503, "setup_incomplete", "GitHub authorization storage is not set up on this deployment yet.");
    log("error", "repository_authorization_failed", { jobId });
    return fail(500, "internal_error", "Repository authorization failed. Nothing is assumed to have changed.");
  }
}
