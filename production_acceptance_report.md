# VibeShield AI — Multi-User GitHub App Authorization Report

**Date:** 2026-10-28 · **Starting HEAD:** `7839536` · **Feature commits:** `c71b0aa` (authorization), `9d6905f` (report fix) · **Production:** https://vibeshield-ai-phi.vercel.app

The previous report, on the operator-token PR flow and multi-repository audit, is in git history (`git show 7839536:production_acceptance_report.md`). Everything below was measured, read from an API, or run in this session.

**Bottom line**
- Multi-user GitHub App authorization is implemented, tested and deployed.
- The **live GitHub App test is BLOCKED**: no GitHub App is registered for this deployment, and I cannot register one without the owner's GitHub session.
- Production truthfully reports "GitHub authorization is not configured yet" and keeps the verified-patch download.

---

## 1. What was replaced and why

**Before (audited at `7839536`):**
- PRs used a single operator credential, `GITHUB_WRITE_TOKEN`, gated by an owner-maintained allowlist, `GITHUB_PR_REPOSITORIES`.
- There were no users or sessions; a job ID was the only capability.
- Private repositories were rejected.
- `GITHUB_TOKEN` is the read token used for public archive downloads and API rate limits. It never had a write role and still doesn't.

**Now:**
- `GITHUB_WRITE_TOKEN` and `GITHUB_PR_REPOSITORIES` are **removed from the code**. No operator token can write.
- Each user authorizes the **VibeShield GitHub App** and chooses repositories on GitHub's own installation page.

## 2. Authorization architecture

| Concern | Implementation |
|---|---|
| Identity | GitHub App **user authorization** (OAuth web flow with PKCE S256). |
| Credential used for writes | The **requesting user's own** user-to-server token. GitHub limits it to repositories the user can push to **and** has selected in the installation, so the app can never exceed the user's access. No app private key or installation token is used. |
| Session | Random 256-bit cookie `__Host-vibeshield_session` (HttpOnly, Secure, SameSite=Lax, Path=/). Only its SHA-256 is stored, in `AuthSession`. Rotated on connect, so a pre-auth session can't be fixated. |
| State | Random, stored hashed, **single use** (atomic consume), 10-minute TTL, bound to the initiating session and to its purpose (`connect` / `install`). This blocks CSRF, replay and login/session swapping. `returnTo` is limited to `/` or `/report/<id>?…`, so it can't be used as an open redirect. |
| Tokens at rest | AES-256-GCM with a fixed 16-byte tag, key `GITHUB_APP_TOKEN_ENCRYPTION_KEY`. Access and refresh tokens and the PKCE verifier are encrypted. Never in local storage, URLs, logs or responses. |
| Expiry / refresh | 8-hour tokens refreshed 2 minutes early. A row-version guard handles concurrent refresh with GitHub's single-use refresh tokens. A rejected refresh, a token GitHub rejects (401), or a token encrypted under a rotated key all delete the stored authorization and show "authorization expired/revoked". |
| Installation | "Authorize this repository" goes to `github.com/apps/<slug>/installations/new?state=…`. On return, `installation_id` is accepted only if GitHub lists it in `GET /user/installations` for that user's token. `setup_action=request` shows that an organization owner must approve. |
| Per-request check | Before every write (and every private-scan read), GitHub is checked live for: repository visible to the user; user `push`; repository in an installation of this app granting **Contents: write** and **Pull requests: write**; and the repository's **immutable ID** equal to the ID recorded at scan time (`ScanAccess`). Nothing from an earlier page state is reused. |
| PR gates | The remediation is approved and **verified**; its commit equals the job's commit; the diff's SHA-256 equals the digest recorded at approval; and the publishing user confirms that exact digest in the dialog. Then a branch `vibeshield/fix-<job>-<remediation>` (full remediation ID) whose only parent is the verified commit, one commit with exactly the patch, and a PR against the default branch. "Base branch moved" is reported, not hidden. Never pushes to the default branch, never merges. Retries are idempotent. |
| Attribution | The PR and commit are created by the user "via" the VibeShield app. The dialog and result say "opened as @login via the VibeShield AI GitHub App". |
| Disconnect | `POST /api/auth/github/disconnect` (same origin only) revokes the app grant at GitHub (`DELETE /applications/{client_id}/grant`) and deletes the stored tokens. All sessions of that account become disconnected. |
| Private repositories | Submitted only when the session's user can read the repository through the installation. Visible **only** to that user, and only while access lasts: 12 scan routes are gated; preview, approve, apply, patch, retry and rescan re-check live with GitHub. The access record is written **before** the job exists. Workers get a short-lived, single-archive `codeload` URL from a **signed** endpoint (`POST /api/scans/:id/source`) or the signed verification spec, never a token. Public workflow inputs carry `private`, not the name. Private archives skip the warm-worker disk cache. |
| Audit | `AuditEvent`: connect, disconnect, installation verified or requested, authorization lost, private scan submitted, PR created / exists / denied / failed. Each event records user, repository and job. It never records tokens, codes or state values (asserted in tests). |
| Unconfigured | With no `GITHUB_APP_*`, nothing touches the new tables. The UI says "GitHub authorization is not configured yet", the PR API returns `503 not_configured`, "Connect" returns to `/?github=not_configured` without leaving the site, and the patch download works. |

**Minimum GitHub App permissions:**
- Repository: Contents read & write, Pull requests read & write, Metadata read.
- No account or organization permissions.
- Webhooks off; access is re-checked live instead.

## 3. Migration

`prisma/migrations/20261028120000_add_github_app_authorization` is **additive only**. It adds:
- `AuthSession`
- `GithubAccount` (with `githubUserId` as BIGINT unique)
- `OAuthState`
- `ScanAccess`
- `AuditEvent`

No existing table changes, so deployments without it keep working. It was applied with `prisma migrate deploy` to the disposable Postgres, and `prisma migrate diff` shows no drift against the schema. **Not applied to production** (operator step, §7). `/api/health` reports `services.githubApp`: `not_configured` / `setup_incomplete` / `configured`.

## 4. Tests

| Suite | Result |
|---|---|
| `npx vitest run` | **28 files: 25 passed, 3 skipped. 344 tests: 326 passed, 18 skipped, 0 failed.** The skipped tests are the Postgres, real-scanner and live-Gemini suites; the first two were run separately below. |
| `github-app-auth.test.ts` (29) | Against a modelled GitHub (OAuth with PKCE, single-use refresh tokens, grant revocation, per-user installations and permissions, private tarball redirects). Covers:<br>• initiation and redirect parameters; cookie flags; open-redirect refusal<br>• callback: encrypted storage, session rotation, audit<br>• missing, unknown, expired and replayed state<br>• CSRF/session swap; PKCE mismatch; declined consent; not configured<br>• installation flow, including a forged `installation_id`<br>• refresh, refresh failure, refresh race; revoked token; key rotation; disconnect (including cross-site refusal)<br>• not connected / no push / not installed / repository removed / installation removed / missing app permission / repository ID substitution<br>• PR with the user's own token only (every write's `Authorization` asserted)<br>• another user's session can't use it; unapproved / unverified / needs-review / wrong-diff / swapped-diff / commit-mismatch rejections; idempotent retry<br>• not-configured `503` with patch fallback; rejection after disconnect<br>• public scan without GitHub; private scan with and without access; access record before job; `private` placeholder for workers; private visibility; live re-check; archive URL instead of token |
| `github-pr.test.ts` (21) | Strict diff application; real commit content and parent; idempotency under concurrent clicks; closed-PR reuse; branch conflict; patch conflict; symlink refusal; renamed or recreated repository; GitHub 401 / 403 / 429 / network / 404 mapping; user token only; base-branch drift |
| `pull-request-ui.test.tsx` (8) | Not configured; Connect link is GitHub's real flow; "Authorize this repository" plus org hint; permission denied; exact-diff confirmation sends its SHA-256 and "created" appears only after the server confirms; restore after reload; refused PR shows the real reason; no PR for unverified fixes |
| `private-scan-executor.test.ts` (2) | Worker obtains identity and archive URL via the signed endpoint, downloads with **no** Authorization header, never logs the repository name or URL token; fails closed when access is lost |
| `polling-progressive.test.tsx` (+1) | A finished report never renders "0 findings" while findings load (see §6) |
| `npm run test:postgres` (real Postgres 16, migrated) | **17/17**, including 3 new: one consumed state among 20 concurrent callbacks; session and purpose binding; expiry; refresh row-version race (1 of 2 wins); disconnect unlinks sessions; 64-bit GitHub IDs; audit rows without secrets |
| `npm run test:scanners` (real Gitleaks 8.30.1, Semgrep 1.182.0, OSV 2.7.0) | 61/61 |
| Negative controls | Each one breaks the check and the targeted test fails; restoring it makes the test pass:<br>• state not bound to session → CSRF test fails<br>• repository-ID check removed → 2 substitution tests fail<br>• exact-diff confirmation removed → diff test fails<br>• report loading order reverted → zero-findings test fails |
| `tsc --noEmit` · `eslint .` · `next build` | Clean · clean · success. All 6 `/api/auth/github/*` routes are request-time (ƒ). |
| Gitleaks (history) · Semgrep `p/default` · OSV (`package-lock.json`) | No leaks · 0 (an initial GCM tag-length finding was fixed) · 0 |
| **Live GitHub App integration test** | **NOT RUN: BLOCKED.** No GitHub App credentials exist for this deployment. Not counted as passed. |

## 5. Visible-browser evidence (production, Chrome, non-headless)

All against `9d6905f` (Vercel `dpl_BYHKc271VkTcBFghBtLGrJyfU2Ke`, READY, aliased to `vibeshield-ai-phi.vercel.app`).

| Step | Result |
|---|---|
| Public scan without GitHub | FraudAi `69581cd` via the form, job `G7C8fcuo…`. Gitleaks, Semgrep and OSV all completed; 8 findings; queue 7.7 s, setup 17.2 s, scan 4.1 s. This also exercised the restructured worker on real Actions. |
| Report → Auto-Fix → finding → preview | Exact diff `-pytest>=8.0` / `+pytest==9.0.3` |
| Apply without approval | `403 approval_required` |
| PR before verification | `503 not_configured` (authorization is checked first) |
| Approve → verify | "Fix Verified by Security Rescan": Actions run `40692742412`, snapshot 182 files, 8 → 6, 0 new, 34.4 s click → result |
| Authorization card | "GitHub authorization is not configured yet"; the only action is "Download .patch File"; no PR button |
| `GET /api/auth/github/status` | `{configured: false, unavailableReason: "not_configured", connected: false}` |
| PR API | `503 not_configured` |
| "Connect" endpoint | Redirects to `/?github=not_configured`; never shows a simulated dialog |
| `.patch` download | 200 `text/x-diff`, byte-identical to the reviewed diff |
| 390 px width | Card and verification panel render without overflow |
| Console / network | Only the three deliberate negative requests failed (403, 503, 503); no other errors |

**Not performed (BLOCKED, needs the GitHub App):**
- real Connect, consent and installation
- a PR authored through the app
- retry and idempotency on GitHub
- disconnect and revoke on GitHub

These are covered only by the deterministic tests in §4, which are **not** live proof.

## 6. Other fix found during the browser run

A finished FraudAi report briefly showed **"VERIFIED SCAN REPORT · 0 findings"** (screenshot captured) while 8 findings were loading. The job was committed before its findings. `9d6905f` now loads findings first and commits both in one render; a regression test fails without the fix.

## 7. One-time operator setup (exact)

Full guide: `docs/github-app-setup.md`.

1. Register a GitHub App:
   - Callback URL: `https://vibeshield-ai-phi.vercel.app/api/auth/github/callback`
   - Setup URL: `https://vibeshield-ai-phi.vercel.app/api/auth/github/setup` (redirect on update on)
   - Expire user tokens: **on**
   - Request user authorization during installation: **off**
   - Webhook: **off**
   - Permissions: Contents RW, Pull requests RW, Metadata R
   - Installable on any account
2. Apply the migration to production: `npx prisma migrate deploy`.
3. In Vercel Production, set as Sensitive:
   - `GITHUB_APP_CLIENT_ID`
   - `GITHUB_APP_CLIENT_SECRET`
   - `GITHUB_APP_SLUG`
   - `GITHUB_APP_TOKEN_ENCRYPTION_KEY` (`openssl rand -base64 32`)

   App ID, private key and webhook secret are **not** required by this implementation. `APP_URL` is already set.
4. Redeploy. `/api/health` → `services.githubApp: "configured"`.
5. Run the live checklist in the guide against a repository you own.

No personal access token is used or needed.

## 8. Deployment

| Item | Value |
|---|---|
| Commits | `c71b0aa` (feature), `9d6905f` (report fix), then this report. Fast-forward pushes to `main`; no force. |
| Vercel | `dpl_DbGr8GBp…` (`c71b0aa`), then `dpl_BYHKc271…` (`9d6905f`), both READY |
| `/api/health` | `healthy`; database healthy; dispatcher ready; warm worker disabled; `githubApp: not_configured` |
| Actions | Scan and verify runs on the deployed code: success (`40692742412` verify) |
| Cost | No paid service added. Uses GitHub App OAuth (free), existing Neon and Vercel. |

## 9. Remaining blockers and limits

1. **BLOCKED: live GitHub App flow.** It needs the owner to register the app and set four variables (§7). Until then PR creation and private scanning are unavailable in production by design.
2. **Production migration not applied** (owner action, §7 step 2). It is harmless until then.
3. **Private-scan workers** run on this public repository's GitHub-hosted Actions runners. The repository name, tokens and archive URL are kept out of workflow inputs and logs (tested). The source is still processed on GitHub's ephemeral runner, and scan timings and job IDs appear in the public Actions log. Use the warm worker on a private host if that is not acceptable.
4. Approval itself is not tied to a GitHub identity. Anyone with a public job's link can approve, as before. Publishing requires the publishing user's own write access **and** that user's confirmation of the exact diff.
5. Pre-existing and unchanged: Turnstile is not configured; Semgrep's runner toolchain pins carry advisories (`.github/scanner-requirements.txt`); PR #10 from the previous round is still open on `samarth-khera/FraudAi` for review.
