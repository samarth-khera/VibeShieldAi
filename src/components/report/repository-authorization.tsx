"use client";

import { useCallback, useEffect, useState } from "react";
import { AlertCircle, CheckCircle2, ExternalLink, KeyRound, Loader2, ShieldAlert, ShieldCheck } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  ApiRequestError,
  cancelRepositoryAuthorization,
  confirmRepositoryAuthorization,
  fetchGithubStatus,
  prepareRepositoryAuthorization,
  type GithubStatus,
  type RepositoryAuthorizationPrepared,
  type RepositoryAuthorizationState,
} from "@/lib/scan-client";

export type GithubStatusHandle = { status: GithubStatus | null; error: string | null; reload: () => void };

/** The current session's GitHub authorization for one scan, re-checked live by the server on each load. */
export function useGithubStatus(jobId: string, returnTo: string, refreshKey: unknown, enabled = true): GithubStatusHandle {
  const [status, setStatus] = useState<GithubStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [version, setVersion] = useState(0);
  const reload = useCallback(() => setVersion((v) => v + 1), []);
  useEffect(() => {
    if (!enabled) return;
    let cancelled = false;
    fetchGithubStatus(jobId, returnTo)
      .then((s) => {
        if (cancelled) return;
        setStatus(s);
        setError(null);
      })
      .catch((err) => {
        if (!cancelled) setError(err instanceof Error ? err.message : "Could not load GitHub authorization status.");
      });
    return () => {
      cancelled = true;
    };
  }, [jobId, returnTo, refreshKey, version, enabled]);
  return { status, error, reload };
}

const STATE_TITLES: Record<RepositoryAuthorizationState, string> = {
  authorized: "Repository authorized",
  authorization_required: "Repository authorization required",
  app_setup_required: "One-time GitHub App setup required",
  installation_required: "VibeShield GitHub App not installed on this account",
  admin_required: "Insufficient repository permissions",
  organization_approval_required: "Organization approval required",
  no_push_permission: "Insufficient repository permissions",
  app_lacks_permission: "App permissions not approved",
};

const CAPABILITIES = [
  "Read repository contents for security analysis.",
  "Write a verified fix on a dedicated new branch.",
  "Create a pull request for your review.",
  "Never merge automatically and never push to the default branch.",
];

/**
 * "Repository access" for Auto-Fix: shows whether VibeShield may open pull requests in this exact
 * repository and, when the signed-in user administers it, lets them add only this repository to
 * the existing GitHub App installation after an explicit confirmation. Success is shown only when
 * the server reports that GitHub lists the repository in the installation.
 */
export function RepositoryAuthorizationPanel({
  jobId,
  remediationId,
  github,
}: {
  jobId: string;
  remediationId?: string;
  github: GithubStatusHandle;
}) {
  const { status } = github;
  const [prepared, setPrepared] = useState<RepositoryAuthorizationPrepared | null>(null);
  const [preparing, setPreparing] = useState(false);
  const [confirming, setConfirming] = useState(false);
  const [checked, setChecked] = useState(false);
  const [error, setError] = useState<{ message: string; link?: string | null } | null>(null);
  const [justAuthorized, setJustAuthorized] = useState<string | null>(null);

  if (!status || !status.configured) return null;
  const repo = status.repository;
  const authz = repo?.authorization;

  const open = async () => {
    setError(null);
    setPreparing(true);
    try {
      const p = await prepareRepositoryAuthorization(jobId, remediationId);
      if (p.request && p.installation) {
        setChecked(false);
        setPrepared(p);
      } else {
        // GitHub's current answer changed (e.g. already authorized): show it instead of a dialog.
        github.reload();
      }
    } catch (err) {
      setError({ message: err instanceof Error ? err.message : "Could not check this repository with GitHub." });
    } finally {
      setPreparing(false);
    }
  };

  const close = () => {
    if (prepared?.request) void cancelRepositoryAuthorization(jobId, prepared.request.intent).catch(() => undefined);
    setPrepared(null);
  };

  const confirm = async () => {
    if (!prepared || confirming) return;
    setConfirming(true);
    setError(null);
    try {
      const r = await confirmRepositoryAuthorization(jobId, prepared);
      setPrepared(null);
      if (r.state === "authorized") setJustAuthorized(r.repository.fullName);
    } catch (err) {
      const data = err instanceof ApiRequestError ? (err.data as { links?: { installationSettings?: string | null } } | undefined) : undefined;
      setError({
        message: err instanceof Error ? err.message : "GitHub did not confirm the authorization.",
        link: data?.links?.installationSettings ?? null,
      });
      setPrepared(null);
    } finally {
      setConfirming(false);
      github.reload();
    }
  };

  const state = authz?.state;
  const ok = state === "authorized";
  return (
    <section className="rounded-lg border border-line bg-surface p-3 space-y-2 text-xs" aria-label="Repository access">
      <div className="flex items-center gap-2 font-semibold text-foreground">
        <KeyRound className="size-4 text-accent" /> Repository access
      </div>
      <p className="text-muted">
        Public scan available: this report and the .patch download need no GitHub access. Opening a pull request needs
        your GitHub authorization for this one repository.
      </p>

      {!status.connected ? (
        <div className="flex flex-wrap items-center gap-2" role="status">
          <span className="font-medium text-foreground">
            {status.authorizationProblem ? "Authorization expired or revoked" : "GitHub connection required"}
          </span>
          <a href={status.links.connect} className="inline-flex h-8 items-center gap-1.5 rounded-lg bg-accent px-3 font-medium text-background">
            <KeyRound className="size-3.5" /> {status.authorizationProblem ? "Reconnect GitHub" : "Connect GitHub"}
          </a>
        </div>
      ) : repo && authz ? (
        <div className="space-y-2" role="status" aria-live="polite">
          <p className={`flex items-start gap-1.5 font-medium ${ok ? "text-accent" : "text-foreground"}`}>
            {ok ? <ShieldCheck className="mt-0.5 size-3.5 shrink-0" /> : <ShieldAlert className="mt-0.5 size-3.5 shrink-0 text-sev-medium" />}
            <span>
              {STATE_TITLES[authz.state]} — <span className="font-mono">{repo.fullName}</span>
              {ok && authz.installationAccount ? ` (installation on ${authz.installationAccount})` : ""}
            </span>
          </p>
          {justAuthorized && ok && (
            <p className="text-accent">GitHub now lists {justAuthorized} in the VibeShield AI installation.</p>
          )}
          {!ok && <p className="text-muted">{authz.message}</p>}
          <div className="flex flex-wrap items-center gap-2">
            {state === "authorization_required" && (
              <Button size="sm" onClick={open} disabled={preparing}>
                {preparing ? <Loader2 className="size-3.5 animate-spin" /> : <KeyRound className="size-3.5" />} Authorize repository
              </Button>
            )}
            {state === "installation_required" && (
              <a href={status.links.install} className="inline-flex h-8 items-center gap-1.5 rounded-lg bg-accent px-3 font-medium text-background">
                Install on GitHub <ExternalLink className="size-3" />
              </a>
            )}
            {(state === "app_setup_required" || state === "app_lacks_permission" || state === "organization_approval_required") &&
              authz.installationSettingsUrl && (
                <a
                  href={authz.installationSettingsUrl}
                  target="_blank"
                  rel="noreferrer"
                  className="inline-flex h-8 items-center gap-1.5 rounded-lg border border-line px-3 font-medium text-foreground hover:border-line-bright"
                >
                  Open the installation on GitHub <ExternalLink className="size-3" />
                </a>
              )}
          </div>
          {state === "installation_required" && repo.ownerType === "Organization" && (
            <p className="text-[11px] text-muted">
              For an organization, GitHub may ask an owner to approve the installation; VibeShield shows it as requested until then.
            </p>
          )}
        </div>
      ) : repo ? (
        <p className="text-muted" role="status">
          {repo.message ?? "Repository access could not be confirmed with GitHub."}
        </p>
      ) : null}

      {error && (
        <p className="flex items-start gap-1.5 text-sev-high" role="alert">
          <AlertCircle className="mt-0.5 size-3.5 shrink-0" />
          <span>
            {error.message}
            {error.link && (
              <>
                {" "}
                <a href={error.link} target="_blank" rel="noreferrer" className="underline">
                  Open the installation on GitHub
                </a>
              </>
            )}
          </span>
        </p>
      )}

      {prepared && prepared.installation && (
        <div role="dialog" aria-modal="true" aria-label="Authorize repository" className="fixed inset-0 z-[60] flex items-center justify-center bg-black/60 p-4">
          <div className="max-h-[90vh] w-full max-w-lg overflow-y-auto rounded-xl border border-line bg-surface p-4 space-y-3 text-xs">
            <h3 className="flex items-center gap-2 text-sm font-semibold text-foreground">
              <KeyRound className="size-4 text-accent" /> Allow VibeShield AI to access this repository?
            </h3>
            <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 font-mono text-[11px]">
              <dt className="text-muted">Repository</dt>
              <dd>{prepared.repository.fullName}</dd>
              <dt className="text-muted">Repository ID</dt>
              <dd>{prepared.repository.id}</dd>
              <dt className="text-muted">Owner</dt>
              <dd>
                {prepared.installation.account} ({prepared.repository.ownerType === "Organization" ? "organization" : "user account"})
              </dd>
              <dt className="text-muted">Pull requests target</dt>
              <dd>{prepared.repository.defaultBranch ?? "default branch"}</dd>
              <dt className="text-muted">Scanned commit</dt>
              <dd>{prepared.scannedCommit.slice(0, 12)}</dd>
              <dt className="text-muted">Installation</dt>
              <dd>
                VibeShield AI on {prepared.installation.account} (#{prepared.installation.id})
              </dd>
            </dl>
            <div>
              <p className="font-semibold text-foreground">Requested capabilities</p>
              <ul className="mt-1 list-disc pl-4 text-muted space-y-0.5">
                {CAPABILITIES.map((c) => (
                  <li key={c}>{c}</li>
                ))}
              </ul>
            </div>
            <p className="text-muted">
              VibeShield will add only {prepared.repository.fullName} to the existing VibeShield AI installation, using your
              own GitHub authorization. It never selects &quot;All repositories&quot; and never removes repositories. GitHub
              requires you to be an administrator of this repository; it, not VibeShield, decides whether the change is
              allowed. You can remove access at any time in GitHub&apos;s installation settings.
            </p>
            <label className="flex items-start gap-2 text-foreground">
              <input type="checkbox" checked={checked} onChange={(e) => setChecked(e.target.checked)} className="mt-0.5" />
              <span>I authorize VibeShield AI to access only {prepared.repository.fullName}.</span>
            </label>
            {confirming && (
              <p className="flex items-center gap-1.5 text-muted" role="status">
                <Loader2 className="size-3.5 animate-spin" /> Adding repository to installation…
              </p>
            )}
            <div className="flex justify-end gap-2">
              <Button variant="secondary" size="sm" onClick={close} disabled={confirming}>
                Cancel
              </Button>
              <Button size="sm" onClick={confirm} disabled={!checked || confirming}>
                {confirming ? <Loader2 className="size-3.5 animate-spin" /> : <CheckCircle2 className="size-3.5" />}
                {confirming ? "Authorizing…" : "Authorize repository"}
              </Button>
            </div>
          </div>
        </div>
      )}
    </section>
  );
}
