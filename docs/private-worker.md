# Private repository scanning: worker requirements

**Status: not available.** No private worker is deployed. `PRIVATE_SCANNING_AVAILABLE` in
`src/server/auth/private-source.ts` is `false`, so private repositories are refused before any job
is created.

## Why the existing executors are not acceptable

The production executor runs on GitHub-hosted runners of this **public** repository. Several things
about those runs are public:
- run names (`VibeShield scan <job_id>`)
- step environment (`JOB_ID`)
- timings and logs

Omitting the repository name and tokens from workflow inputs isn't enough to make a private scan
private.

## Fail-closed paths (enforced today)

| Path | Behaviour |
|---|---|
| `POST /api/scans` | Anything not confirmed public is rejected with `400 not_found_or_private` before a job, access record or dispatch exists. Public means GitHub metadata with `private: false` and, if present, `visibility: "public"`. Missing visibility is treated as non-public. `submitScan` also refuses a private gate result with `403 private_scanning_unavailable` (defence in depth). |
| Queue → GitHub Actions dispatch (`pumpQueue` → `enqueue`) | `repositoryUrlForWorker` throws for a private job, so the job fails and nothing is dispatched. |
| Warm-worker claim | A claimed private job is failed (`private_scanning_unavailable`) and not handed out. |
| Retry / rescan / apply (verification) routes | `refusePrivateExecution` answers `403 private_scanning_unavailable` before queueing or dispatch. |
| Verification spec / signed source endpoint | `resolvePrivateSource` returns `private_scanning_unavailable`, so no archive URL is ever issued. |

## Minimum secure configuration for a future private worker

1. **Dedicated, non-public execution.** Use a host (or private CI) whose logs, job names and
   artifacts are not publicly visible. The existing hardened warm-worker container
   (`deploy/warm-worker/`) is the starting point: read-only root, UID 10001, all capabilities
   dropped, `no-new-privileges`, pid/memory/CPU limits, `noexec` tmpfs workspace.
2. **Outbound-only, authenticated channel.** The worker polls the HMAC-signed claim/heartbeat API
   with a dedicated secret. It receives only a job ID and a lease. Every callback carries the lease
   and is re-validated server-side.
3. **Routing.** Private jobs must be claimable **only** by that worker. The GitHub Actions path must
   keep refusing them (it already does). Enabling private scans needs an executor-aware claim, so
   the public dispatcher never selects a private job, plus tests for every dispatch path.
4. **Source access.** The worker never receives user tokens. It gets a short-lived, single-archive
   download URL from the signed source endpoint, after the server re-checks the authorizing user's
   access and the repository's immutable ID.
5. **Isolation and hygiene.**
   - one workspace per job, deleted afterwards
   - private archives never cached on disk
   - bounded download, unpack size and file count with safe extraction
   - strict timeouts
   - scanners never execute repository code
   - egress restricted to GitHub and the app
6. **Logs.** No repository names, file paths, findings or source in worker logs. Keep only job ID
   and timing metrics in a private log sink.
7. **Truthful status.** `PRIVATE_SCANNING_AVAILABLE` may be set to `true` only after the worker is
   deployed and an end-to-end private scan has been verified. `/api/health` must report the worker
   from real heartbeats.

On ₹0 infrastructure the realistic option is a free-tier VM (for example Oracle Cloud Always Free)
running the warm-worker container. That needs an account and credentials, so it has not been done.
