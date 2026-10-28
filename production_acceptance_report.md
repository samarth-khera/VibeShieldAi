# VibeShield AI — Authorization Hardening Before GitHub App Launch

**Date:** 2026-10-28 · **Starting HEAD:** `e8274e4` (verified as local = remote, clean tree) · **Fix commit:** `cf5ff08` (deployed, §7) · **Production:** https://vibeshield-ai-phi.vercel.app

The previous report, on per-user GitHub App authorization, is in git history (`git show e8274e4:production_acceptance_report.md`). Everything below was measured or read in this session.

---

## 1. Root causes and code paths

### Issue 1: a report link could change someone else's job

- **Job IDs are not secret.** The public scanner workflow has `run-name: VibeShield <mode> <job_id>`, and `JOB_ID` is in its step environment, so every job ID is listed at `github.com/samarth-khera/VibeShieldAi/actions`.
- **Every state-changing route trusted that ID.** Each route called `gateScanAccess`, which returns immediately when the GitHub App is not configured (production) and passes public jobs even when it is. Affected routes:
  - `POST /api/scans/:id/remediation/preview`
  - `…/:rid/approve`
  - `…/:rid/apply` (starts a verification run and takes a heavy-worker slot)
  - `…/:rid/pr`
  - `POST /api/scans/:id/retry`
  - `POST /api/scans/:id/scan` (rescan)
  - `POST /api/scans/:id/findings/:fid/explain` (spends shared Gemini quota)
- **Approval wasn't bound to anything** except a diff digest; `approvedBy` was a free-text string.

So anyone could approve and verify any public scan's fix and spend shared quota. With the GitHub App configured, a stranger could have approved a fix that the owner later published.

### Issue 2: private jobs would run on the public workflow

- `repositoryUrlForWorker` replaced a private repository's URL with `private`, but still dispatched the job to GitHub-hosted runners of this public repository. Their run names and logs expose job IDs and timings.
- **No private job has ever existed in production.** The private path is only installed when `GITHUB_APP_*` is configured, which it never has been (`/api/health` → `githubApp: not_configured`). Before that, `fetchRepoMetadata` rejected non-public repositories.
- Visibility was "public unless `private === true`", so a response missing the field counted as public.

## 2. Authorization policy (now enforced server-side)

| Action | Who | Notes |
|---|---|---|
| Submit a public scan | Anyone (rate-limited) | No GitHub connection needed. The submitting browser becomes the job owner. |
| View a public-repo report: status, findings, finding detail, stored AI explanations, remediation list, verification details, `.patch` download | Anyone with the report link (read-only) | The data derives from public source code. The UI shows "Read-only report" and no actions to non-owners. |
| Generate a fix preview, request an AI explanation, approve, apply/verify, retry, rescan, open a PR | **Job owner only**, same-origin request | A job ID, report URL, or client-supplied identity is never enough |
| Open a PR | Job owner **and** that user's live GitHub App authorization with write access to the exact repository (immutable ID), plus confirmation of the exact diff digest | Unchanged from the previous round; now also requires the approving owner session |
| Private repository: anything | **Refused** while no private worker exists (§4) | Legacy or future private records stay visible only to their authorizing GitHub user |

## 3. How ownership and approval are bound

**Owner grant (`src/server/auth/ownership.ts`)**
- The response that creates a job sets `__Host-vibeshield_owner`: HttpOnly, Secure, SameSite=Lax, Path=/, host-only, Max-Age 7 days (job retention).
- Its value is a random 128-bit session ID plus up to 30 job IDs created by that browser, each timestamped. It is HMAC-SHA256 signed with a key derived from `SCAN_CALLBACK_SECRET` under a fixed label; `OWNER_SESSION_SECRET` overrides it.
- A grant entry is only ever added from the server's own 202 response, never from request input. It never appears in a URL or local storage.
- There is no database change, so no migration was needed.

**Every change is checked by `requireJobOwner`:**
- `Sec-Fetch-Site: same-origin`, or `Origin` equal to the app origin. This is CSRF protection on top of SameSite=Lax.
- A valid grant containing this job.

Failures return `403 forbidden_origin`, `403 not_job_owner`, or `503 ownership_unavailable` if no key is configured, which fails closed.

**Approval binding (`approvedOperations`, all derived server-side):**
- `ownerSubject` (SHA-256 of the grant's session ID)
- `scanJobId`, `remediationId`
- `commitSha` (must equal the job's scanned commit)
- `findingFingerprints`, `approvedFiles`
- `diffSha256`
- `approvedAt`, plus `githubUserId` when the session is GitHub-connected

On apply, every field is re-derived. On any mismatch the remediation is reset to `preview`, so it must be re-approved:

| Mismatch | Error code |
|---|---|
| Different session | `approval_session_mismatch` |
| Job, commit or finding changed | `approval_target_mismatch` |
| Diff changed | `approval_diff_changed` |
| Approval older than 24 h | `approval_expired` |

The PR step re-checks the same binding, except expiry.

**Session expiry and recovery:** a grant entry lasts as long as the job (7 days). If the cookie is cleared or the user switches browser, ownership is lost on purpose; the report becomes read-only and the user can start a new scan. There is no recovery link, because any link would be a shareable ownership token.

**Existing data:** jobs created before `cf5ff08` have no owner, so they are read-only for everyone. Their unbound approvals can no longer be applied. This is a deliberate, controlled expiry.

## 4. Private scanning: fail-closed

`PRIVATE_SCANNING_AVAILABLE = false` (`src/server/auth/private-source.ts`). Every path:

| Path | Behaviour | Proof |
|---|---|---|
| `POST /api/scans` | Anything not confirmed public → `400 not_found_or_private`, "Private repository scanning is currently unavailable", before quota reservation, job, access record or dispatch | Test with connected user who has push access; negative control; **visible Chrome against real GitHub** (§6) |
| `submitScan` itself | A private gate result → `403 private_scanning_unavailable` (defence in depth) | Test + negative control |
| Visibility | Requires an explicit `private: false` (and `visibility: "public"` if present); missing → non-public | Test + negative control |
| Queue → Actions dispatch | `repositoryUrlForWorker` throws, so the job fails and nothing is dispatched | Test (`pumpQueue` with a private record: nothing enqueued, job failed) + negative control |
| Warm-worker claim | The private job is failed (`private_scanning_unavailable`) and not handed out | Code |
| Retry / rescan / apply routes | `refusePrivateExecution` → `403` before queueing | Route-wiring tests |
| Verification spec, signed source endpoint | No archive URL is issued (`private_scanning_unavailable`) | Test |

**Existing exposure:** none. No private job could be created in any deployed version (see §1).

**Future private worker:** `docs/private-worker.md` covers the minimum secure design: a dedicated non-public host, a signed outbound-only channel, private-only routing, short-lived archive URLs, isolation, no repository data in logs, and truthful status. **Not deployed.**

## 5. Tests

| Suite | Result |
|---|---|
| `npx vitest run` | **29 files: 26 passed, 3 skipped. 376 tests: 358 passed, 18 skipped, 0 failed.** The skipped tests are the Postgres, real-scanner and live-Gemini suites; the first two were run separately below. Live Gemini was not run (no key locally). |
| `npm run test:postgres` (disposable Postgres 16) | 17/17 |
| `npm run test:scanners` (real Gitleaks, Semgrep, OSV) | 61/61 |
| New `ownership.test.ts` (29) | Requested cases 1–17:<br>• cross-user approve; link-only visitor; forged grant, re-signed grant, client-supplied identity<br>• CSRF (cross-site, same-site sibling, foreign Origin, header-less)<br>• patch changed after approval; commit or finding substituted; other session; expiry<br>• verification result signed for another job (400, state unchanged)<br>• idempotent approve and apply; public scan without the GitHub App, with the grant issued only from the 202 response<br>• unknown visibility; patch-download fallback; route wiring for all 7 mutating routes, private refusal on retry, rescan and apply, and only the submit route issuing grants |
| Updated `github-app-auth.test.ts` (32) | Private refusal before job, access record and dispatch, even for a user with push access; a private job reaching the queue is never dispatched; no source URL issued; PR refused for another owner session; disconnect mid-remediation; prior GitHub App cases |
| Negative controls (12) | Each guard was removed in the working tree with the original bytes held in memory; the targeted test failed; the file was restored and byte-compared. Guards covered:<br>• owner check · CSRF check · grant signature<br>• approval session · target · diff · expiry<br>• private refusal in the gate · in `submitScan` · at dispatch<br>• visibility default · approve-route gate<br>Each removal made 1–2 targeted tests fail; after restore, 61/61 passed. |
| `tsc` · `eslint` · `next build` | Clean · clean · success (all 27 API routes request-time) |
| Gitleaks (history) · Semgrep `p/default` · OSV (lockfile) | No leaks · 0 · 0 |

*Process note:* my first negative-control run used a shell loop whose backups silently failed, which left all nine mutations in the working tree. I caught this before committing, reversed each mutation exactly, re-ran the suites (118/118), and repeated the controls with the in-memory harness. The committed code was diff-reviewed after the restore.

## 6. Visible Chrome acceptance (non-headless)

**Production `cf5ff08`.** Two separate Chrome profiles: A = owner, B = unrelated visitor holding only the copied report URL.

| Step | Result |
|---|---|
| A submits FraudAi via the form, no GitHub | `202`, job `M0p3IuJtJVEKDtaxQkGgORRD8BuwKJN9`. Cookie `__Host-vibeshield_owner`: httpOnly ✓, secure ✓, sameSite Lax, host-only, path `/`. |
| Scan completes; A reloads | `completed`, 8 findings, `viewer.isOwner: true`, no read-only notice |
| A previews and approves via the UI | Approve `200`, remediation `0ba8c59b-…` |
| B opens the copied URL | "Read-only report" notice; panel note; explain note; **no** Preview, Approve, Verify or Explain buttons |
| B's direct API calls | approve, approve with a forged identity body, apply, preview, explain, retry, rescan, PR: **all `403 not_job_owner`** |
| B's reads | scan `200` (`isOwner: false`), findings `200`, remediations `200`, patch `200` (public read policy) |
| State after B's attempts | Remediation still `approved` with A's original `approvedAt` |
| A's real cookie replayed cross-site | `403 forbidden_origin` |
| A verifies | "Fix Verified by Security Rescan", Actions run `40696196753`; Gitleaks, Semgrep and OSV completed; 8 → 6 findings, 0 new; 38.4 s |
| GitHub card | "GitHub authorization is not configured yet", with the patch download (`200`) |
| Private-repo attempt in production | **Not exercised.** My IP had used its 10 daily scans, so the request got `429 daily_ip_limit` before the visibility check. No job was created, and no workflow run appeared (only the 2 runs for A's public job since the baseline). |
| Console / network | Only the deliberate 403s from B's direct calls; no other errors |

**Private refusal, visible Chrome, local server running the deployed build, real GitHub metadata.** The server's read token can see the repository (`private: true`, verified separately; name withheld):

| Attempt | Result |
|---|---|
| A real private repository I own | `400 not_found_or_private` with "Repository not found or not public. Private repository scanning is currently unavailable." No job (DB count 1 → 1), no owner cookie, no dispatch. |
| A nonexistent repository | Same response, so existence is not revealed |

Screenshots are kept locally and contain no credentials or private repository names.

## 7. Deployment

| Item | Value |
|---|---|
| Commit | `cf5ff08`, fast-forward from `e8274e4` (then this report) |
| Remote `main` | `cf5ff08` at verification time |
| Vercel | `dpl_2oALTy9aYNAi2iMU3h2WuuQm6AmP`, `githubCommitSha cf5ff08`, READY, aliased to production |
| Actions | Scan `40696078893` and verify `40696196753` on the deployed code: success |
| `/api/health` | `healthy`; database healthy; dispatcher ready; warm worker disabled; **`githubApp: not_configured`** |
| Schema | Unchanged this round. The GitHub App migration from the previous round is still **not applied** in production. |

## 8. One-time GitHub App setup (still pending, owner action)

Unchanged; see `docs/github-app-setup.md`.
1. Register the app with the callback and setup URLs, user-token expiry on, and Contents RW, Pull requests RW and Metadata R.
2. `npx prisma migrate deploy` on production.
3. Set `GITHUB_APP_CLIENT_ID`, `GITHUB_APP_CLIENT_SECRET`, `GITHUB_APP_SLUG` and `GITHUB_APP_TOKEN_ENCRYPTION_KEY` in Vercel.
4. Redeploy, then run the live checklist.

**Recommended:** also set a dedicated `OWNER_SESSION_SECRET` (32+ random characters). Without it the owner-grant key is derived from `SCAN_CALLBACK_SECRET`, which the GitHub Actions workers also hold.

## 9. Private worker

**Pending, not deployed.** Private scanning is refused on every path (§4). Enabling it requires a deployed and verified private worker, private-only routing, and an end-to-end test (`docs/private-worker.md`).

## 10. Residual limitations

1. **GitHub App not configured.** PR creation is unavailable in production by design. It has not been tested live.
2. **Read access by link:** public-repo reports, including findings and patches, remain readable by anyone with the job ID, and job IDs are public in the Actions logs. This is the chosen policy for public data. It can be tightened to owner-only reads if wanted.
3. **Ownership is per browser.** Clearing cookies or switching device loses the ability to act on a job; start a new scan.
4. **Shared key:** the owner-grant key is derived from a secret the Actions workers also hold. Set `OWNER_SESSION_SECRET` to separate them.
5. **Signed grants can't be revoked individually** before they expire (7 days). Rotating the key revokes all of them.
6. **Production private-scan refusal** was not exercised live because of the per-IP quota. It is proven by tests, negative controls, and the local run of the deployed build against real GitHub.
7. **Unchanged:** Turnstile not configured; Semgrep toolchain pins carry advisories; PR #10 on FraudAi from an earlier round is still open, and was not merged or touched.
