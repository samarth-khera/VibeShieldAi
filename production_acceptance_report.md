# VibeShield AI — GitHub App Activation, Live Production Acceptance and Defect Fixes

> **Update 2026-10-30:** in-product per-repository authorization and npm lockfile Auto-Fix were
> implemented and deployed (`6d3a08f`). See **§12**. The live Job-portal test is **BLOCKED** on
> the owner's one-time GitHub App permission change and on the scan quota window (§12.6).
>
> **Update 2026-10-30 (later):** the Auto-Fix workflow on the existing Job-portal report was
> diagnosed from production logs, the database and visible Chrome. A production bug stopped every
> eligible npm fix at the preview (HTTP 500). It is fixed and deployed at `41fb7e9`, together with
> transitive npm fixes and a truthful status UI. See **§13**. The live PR step needs the owner's
> own browser session (§13.8).
>
> **Update 2026-10-30 (evening):** the complete Auto-Fix workflow was built out and deployed at
> `9180734`: real progress for every stage, one approval that verifies and then publishes, and an
> opt-in Safe Auto-Fix. It was tested locally against simulated GitHub, with no production scan or AI
> quota used. See **§14**, including the steps for your own final test.
>
> **Update 2026-10-30 (night):** a disposable acceptance-test repository,
> `samarth-khera/vibeshield-e2e-lab`, was created and validated, and an OSV fixed-version bug was
> fixed (`a4a6467`). The production part is **BLOCKED** before any scan: the GitHub App still lacks
> "GitHub App installation repository access: write" (§15).

**Dates:** 2026-10-28 (activation, first live session) and 2026-10-29 (final acceptance run, then three defect fixes)
**Production:** https://vibeshield-ai-phi.vercel.app
**Code under acceptance test (§2–§6):** `9e9d5d9`. Nothing was changed or deployed while those tests ran.
**Fixes (§7) deployed afterwards:** `dd7cdd5`, `27a3e75`, `9cccccf` → production `dpl_7wt3B6w6SBtsaz7duqZ3dmHiG2JP` at `9cccccf`

The previous report (job ownership and private-scan hardening) is in git history: `git show 9e9d5d9:production_acceptance_report.md`.

Everything below was observed during these sessions. Statuses are `PASS`, `FAIL`, `BLOCKED` or `NOT TESTED`.

---

## 1. Summary

| Area | Status |
|---|---|
| Production migration | **PASS**. Applied; no pending migrations; existing data unchanged. |
| GitHub App configuration | **PASS**. `/api/health` → `githubApp: "configured"`. Real consent, install and callback flows worked. |
| Deployment | **PASS**. Acceptance ran on `9e9d5d9`. The fixes are deployed at `9cccccf` (READY, production domain, health `healthy`, §8). |
| Authorization boundaries (ownership, CSRF, installation scope, write access, disconnect) | **PASS**, live |
| Token refresh after expiry | **PASS**, live |
| Fresh scan → approve → full rescan → real PR → duplicate check | **BLOCKED** (§9). The one allowed scan failed with `archive_too_large`. No suitable small repository is in the installation yet, and the quota window has not reset. |
| Failed scan shown as "VERIFIED SCAN REPORT" with 0 findings | Found as **FAIL**. **Fixed** in `dd7cdd5` and verified in production (§7.1). |
| `.patch` fallback with plain `git apply` | Found as **FAIL**. **Fixed** in `27a3e75`. Verified locally with real git and real scanners; production generation of a new patch is BLOCKED by quota (§7.2). |
| Diff viewer shows `>=`/`==` as ligatures | Found as **FAIL**. **Fixed** in `9cccccf` and verified in production (§7.3). |

---

## 2. Starting state and reuse of earlier work

- **Scheduled run.** The run scheduled for 2026-10-28 17:56 UTC **never ran**: the session ended first. No scan, remediation or PR was created, and there are no Actions runs between 2026-10-28 13:24 UTC and the final run.
- **Lost local material.** The browser profiles and logs of the 2026-10-28 session lived in a session-scoped temporary folder that was cleared. That included the GitHub-connected profile and the JSON database backup (§3). Results from that session are quoted from the logs as they were observed.
- **Persistent folder.** The final run kept its state, log and screenshots in `~/.vibeshield-e2e/` so they survive.
- **Profile lost on 2026-10-28.** The browser profile that owned the earlier FraudAi job lost its owner cookie. A plain-Chrome relaunch could not decrypt the cookies stored under the automation keychain, and Chrome deleted them. Ownership could not be recovered (and was not forged). This is the intended behaviour: losing the cookie loses the right to act.

---

## 3. Production database migration (2026-10-28)

| Item | Result |
|---|---|
| Linked project | Vercel `vibeshield-ai` (`prj_OTyt39WFCETQdYiLK9DHRuhsoNCF`). Production domain verified in deployment aliases. |
| Database | Neon (pooled and direct URLs agree). Confirmed different from the local `.env` database before running anything. |
| Pending before | **2:** `20261028050000_add_worker_heartbeat` and `20261028120000_add_github_app_authorization`. The heartbeat migration from an earlier round had also never been applied. |
| Safety review | Both are additive only: `CREATE TABLE`, indexes, and one foreign key between new tables. No `DROP` or `ALTER` of existing tables, and no data rewrite. |
| Backup | A full logical JSON export of every table, plus the schema, was taken before migrating. **That export was later lost** with the temporary folder (§2). The Neon restore point is the pre-migration timestamp **2026-10-28 15:54:00 UTC**. |
| Command | `npm run db:migrate` (`prisma migrate deploy`), with production env loaded only in the shell, never printed. No `db push` and no reset. |
| After | "Database schema is up to date!" `prisma migrate diff` (DB → `schema.prisma`) reports no drift. |
| Data unchanged | Row counts before and after are identical: ScanJob 16, Finding 157, Remediation 7, AiRequestLog 7, AiCircuitBreaker 0. New tables are empty. |

## 4. GitHub App configuration

| Item | Result |
|---|---|
| Production variables | `GITHUB_APP_CLIENT_ID`, `GITHUB_APP_CLIENT_SECRET`, `GITHUB_APP_SLUG` and `GITHUB_APP_TOKEN_ENCRYPTION_KEY` are present in Production and marked Sensitive (values not readable or printed). `DATABASE_URL` and `DATABASE_URL_UNPOOLED` are present. |
| `APP_URL` | Sensitive, so not readable through the CLI. Verified in behaviour: the generated `redirect_uri` is exactly `https://vibeshield-ai-phi.vercel.app/api/auth/github/callback`. |
| Callback URL | GitHub showed the **"Authorize VibeShield AI"** consent page with no redirect-URI error. After consent the user returned to the report, and the server recorded `github_connect / success`. |
| Setup URL | After installation GitHub redirected to `/api/auth/github/setup`, which returned to the same report and finding with `github=installed`. The server verified the installation against the user's own token (`github_install / verified`, installation `176245393`). |
| App slug | `vibeshield-ai` |
| Token expiry | Enabled: 8-hour access tokens and 6-month refresh tokens, observed in stored expiry metadata. |
| `/api/health` | `githubApp: "configured"` (it was `not_configured` before the redeploy). |
| PKCE and state | The authorize URL carries `code_challenge_method=S256` and a 43-character single-use state. |

## 5. Deployment and health

| Item | Value |
|---|---|
| Redeploy by me (2026-10-28 15:56 UTC) | `dpl_HDv3Crvd6h6Q75qEx8EcQLZENeTM`, source `9e9d5d9`, READY, production |
| Current production | `dpl_5ujXNKsLzAA4F29SkAEqaksuyor3`: a dashboard **redeploy of the same commit `9e9d5d9`** at 2026-10-28 16:17 UTC (not started by me). No environment variable changed afterwards. |
| Remote `main` | `9e9d5d9`. Local tree clean. |
| `/api/health` (2026-10-29) | `healthy`; database healthy; dispatcher ready; warm worker disabled (fallback github-actions); `githubApp: configured` |

---

## 6. Live test results

### 6.1 Scan budget (final run, 2026-10-29)

| Attempt | Time (UTC) | Outcome |
|---|---|---|
| 1 | 16:03:32 | **Never reached the server.** The script typed before React hydrated, so the URL field was empty and the browser blocked the submit. Confirmed: no `ScanJob` row and no Actions run. |
| 2 | 16:06:24 | **Accepted:** `202`, job `RJ2D5vXW08VrNUvDAdKGKzlJEssWR4QB`, owner cookie set, GitHub not connected. |

**New production scan jobs created: 1** (budget 1). The job details:
- FraudAi `main` at `8d76bcbc6c8c5ab89d8a0a21b71be38b6ced4e0d`
- Actions run `40908267334`
- failed after 30 s (16:06:25 → 16:06:55) with `rejected_by_limits:archive_too_large`
- Gitleaks, Semgrep and OSV-Scanner **did not run** (`scanPerformed: false`)
- FraudAi reports about 27 MB on GitHub after today's merges; the cap is `MAX_ARCHIVE_MB = 25`

No retry was made: it would fail the same way, and raising the cap would change production mid-test.

### 6.2 Results

| # | Test | Status | Evidence |
|---|---|---|---|
| 1 | Public scan submission without GitHub connected | **PASS** (submission and dispatch) | `202` and owner cookie with GitHub disconnected; job dispatched to Actions |
| 2 | Scan completion with all three scanners | **BLOCKED** | `archive_too_large` (above). The same deployed commit completed FraudAi scans on 2026-10-28, when the repo was under the cap. |
| 3 | Connect GitHub (real consent) and return to the same report and finding | **PASS** | 2026-10-28: returned to `/report/M0p3…?finding=cmvs5byem0004…&mode=autofix`, and the drawer showed PYSEC-2026-1845 in `ml/requirements.txt`. 2026-10-29: reconnected as `samarth-khera`. |
| 4 | Authorize this repository (installation flow) | **PASS** | 2026-10-28: `github=installed`; audit `github_install / verified` |
| 5 | FraudAi access after narrowing the installation | **PASS** | 2026-10-29: `canPush, installed, appCanWrite, readyToWrite: true` for both FraudAi jobs (`8d76bcb`, `69581cd`) |
| 6 | Repository not in the installation (VibeShieldAi) | **PASS** | `canPush: true` but `installed: false`, so `readyToWrite: false` with reason `not_installed`. This is the same live check the PR route runs before writing. Before narrowing, it correctly showed `installed: true`. |
| 7 | No write access (pallets/itsdangerous) | **PASS** | `canPush: false`, `readyToWrite: false` |
| 8 | Write gate on an owned job, live | **PASS** | Not connected → `401 not_connected` (audit `pull_request / denied / not_connected`). Connected → `404 remediation_not_found`, meaning the live write authorization for FraudAi passed and only then was the nonexistent remediation rejected. |
| 9 | Approval and mutation from a browser that didn't start the scan | **PASS** | 2026-10-28, from a GitHub-connected browser that wasn't the owner: preview, approve (with forged `ownerSubject`), apply, PR, retry, rescan and explain all returned `403 not_job_owner`; remediations unchanged; UI read-only. 2026-10-29: same 7 routes via same-origin requests → `403 not_job_owner`. |
| 10 | Forged owner cookie | **PASS** | Forged `__Host-vibeshield_owner` with a bad MAC → `403 not_job_owner` |
| 11 | CSRF and same-origin | **PASS** | From `https://example.com`, credentialed POSTs to disconnect, approve and preview → 403; session stayed connected. With curl, a foreign `Origin`, `Sec-Fetch-Site: cross-site`, `same-site`, or no browser headers → `403 forbidden_origin` on approve and disconnect. |
| 12 | Approve the exact displayed diff | **BLOCKED** | Needs a completed owned scan (test 2) |
| 13 | Full security rescan of the approved fix | **BLOCKED** | Same |
| 14 | Altered or hash-mismatched diff rejected at PR time | **BLOCKED** (live) | Needs an owned verified remediation. Covered by regression tests (`diff_confirmation_mismatch`, `approval_diff_changed`, `patch_mismatch`). |
| 15 | Create a real PR and inspect it on GitHub | **BLOCKED** | No owned verified remediation. **No PR was created.** PR #10 on FraudAi is still open and untouched. |
| 16 | Duplicate PR prevention | **BLOCKED** (live) | Same. Covered by regression tests (idempotent branch and PR lookup). |
| 17 | Token expiry → refresh | **PASS** | Stored access-token expiry set to the past (metadata only; no token read or changed). The next request refreshed with GitHub: access expiry `2026-10-29 16:10:31` → `2026-10-30 00:11:34`, refresh expiry renewed to `2027-04-29 16:11:34`, session stayed connected. |
| 18 | Disconnect → grant revoked → writes refused | **PASS** | Audit `github_disconnect / revoked` (grant revoked at GitHub); stored accounts `0` (tokens deleted); next PR write → `401 not_connected` (audit and re-check from the same browser) |
| 19 | `.patch` download integrity | **PASS** | `200 text/x-diff`, `attachment; filename="vibeshield-fix-<id>.patch"`, `Cache-Control: no-store`, byte-identical to the stored reviewed diff (2 remediations) |
| 20 | `.patch` applies with plain `git apply` at the scanned commit | **FAIL** on `9e9d5d9`; **fixed** in `27a3e75` | §7.2 |
| 21 | Private repository scans refused | **PASS** (not re-run live) | Fail-closed on every path. Evidence is from the previous round: regression tests, negative controls, and a local run of the deployed build against real GitHub. Not re-submitted to production, to protect the quota. |
| 22 | Displayed diff fidelity | **FAIL** on `9e9d5d9`; **fixed** in `9cccccf` and verified in production | §7.3 |
| 23 | Failed scan presented truthfully | **FAIL** on `9e9d5d9`; **fixed** in `dd7cdd5` and verified in production | §7.1 |

**Correction.** An earlier progress message (2026-10-28) listed `nosniff` on the patch download. That was wrong: the response carries **no** `X-Content-Type-Options` header. The risk is low (attachment with `text/x-diff`), but it is recorded here.

### 6.3 Local regression suites (code `9e9d5d9`)

| Suite | Result |
|---|---|
| `tsc --noEmit`, `eslint --max-warnings=0` | Pass (2026-10-29) |
| `vitest run` | 26 files passed, 3 skipped; **358 tests passed, 18 skipped, 0 failed** (2026-10-29). The skipped suites are the Postgres, real-scanner and live-Gemini suites, which need opt-in environments. |
| `test:postgres` (disposable Postgres container) | 17/17 passed (2026-10-28) |
| `test:scanners` (real Gitleaks, Semgrep, OSV) | 61/61 passed (2026-10-28) |
| `next build` | Pass; all `/api/auth/github/*` routes dynamic (2026-10-28) |

These suites are regression evidence, not production evidence.

---

## 7. Defects found and fixed (one commit each)

Each fix has focused regression tests. Each was checked with a negative control: the old behaviour was put back temporarily, the new tests were confirmed to fail, then the file was restored and checked byte for byte.

### 7.1 Failed scans presented as clean: `dd7cdd5` (highest priority)

**Root cause.**
- `real-report-view.tsx` showed "VERIFIED SCAN REPORT" for every status that was not actively scanning, including `failed`. Header count, zero tiles and scanner "pending" labels were drawn regardless.
- Separately, the scan worker flattened structured `RetrievalError`s (`rejected_by_limits` / `archive_too_large`, with a safe public message) into category `scan_failed` with the raw text `rejected_by_limits:archive_too_large`.

**Fix.**
- **API:** `toPublicJob` now returns `reportState`, one of `in_progress`, `complete`, `partial`, `failed` or `cancelled`, plus `incompleteScanners`.
  - `complete` requires status `completed` **and** all three scanners `completed`.
  - `summary` stays `null` unless scanners ran.
- **Legacy failures:** `<status>:<category>` failure text is mapped to the category and a safe, actionable message.
- **Worker:** reports a `RetrievalError` with its real category and public message.
- **Report page:**
  - Only `complete` gets the verified badge.
  - Failed or cancelled scans show "SCAN FAILED / CANCELLED — NOT SCANNED", an alert with the reason and reason code, and "This is not a clean result". The header shows "— Not scanned"; scanners read "not run"; there are no severity tiles and no findings workflow.
  - No retry is offered for size or safety-limit failures.
  - Partial scans name the scanners that did not finish and never call an empty list clean.
- **Home card:** zero findings are called clean only for `complete`.

**Tests.** `src/test/scan-report-state.test.tsx`, 17 tests:
- API projection for failed-before-scanning (the exact stored shape of job `RJ2D…`), structured and unknown legacy failures, partial (`completed_with_warnings`, and `completed` with a missing scanner), cancelled, in-progress and genuinely clean
- the worker posting `archive_too_large`, and unexpected errors staying `scan_failed`
- report page: failed, after reload, partial, cancelled, clean-with-zero-findings
- home card

Negative controls: verified badge for every finished state → 4 failed; raw legacy failure text → 4 failed; executor flattening → 1 failed.

**Live evidence.**
- **Local production build** (visible Chrome): the failed `RJ2D`-shaped job, before and after reload, shows the failed badge, the reason and `archive_too_large`, the "not a clean result" note, no tiles, and three "not run" scanners. The partial job shows the partial badge and is not called clean. The clean job shows the verified badge and "No Security Findings Detected".
- **Production (`9cccccf`)**, job `RJ2D5vXW08VrNUvDAdKGKzlJEssWR4QB`:
  - API: `reportState: failed`, `scanPerformed: false`, `summary: null`, `incompleteScanners` = all three, failure `archive_too_large` with "The repository archive is larger than the scan size limit, so no scanner ran."
  - Visible Chrome, load and reload: no verified badge, failure alert with reason and code, no zero tiles, 3× "not run", no clean claim.
  - Completed job `M0p3…` still shows "VERIFIED SCAN REPORT".

### 7.2 `.patch` downloads needed `--unidiff-zero`: `27a3e75`

**Root cause.** Generated hunks carried no context lines (`@@ -5,1 +5,1 @@`). Plain `git apply` anchors such a hunk to the end of the file, so any change that was not on a file's last line was rejected. Verification only passed because the worker used `git apply --unidiff-zero`.

**Fix.**
- **New `canonical-diff.ts`.** Strictly applies the generated diff to the real files at the scanned commit, then re-renders it with up to 3 context lines. It merges nearby hunks and handles "No newline at end of file" and CRLF. The result is accepted only if strictly applying the new diff reproduces exactly the same files.
- **Preview.** Every preview is canonicalized this way. A patch that does not match the real file, or whose source cannot be fetched, is marked unsuitable instead of offered. This is stricter than before: a malformed LLM hunk or an evidence-based patch pointing at the wrong line used to pass a header-only check.
- **Older zero-context remediations.** These are regenerated before approval or verification. If the diff hash changes, the approval is voided, the remediation returns to preview with the new diff, and the server answers `409 patch_regenerated`. The owner must approve the new exact diff, and the approval binding carries the new hash. The panel reloads the stored diff and clears the approval tick after any refused approval.
- **Verification worker (`sandbox.ts`).** Uses plain `git apply` with no `--unidiff-zero`. After applying, it checks that the files equal the strict-apply result byte for byte (`patch_integrity_mismatch` otherwise). The PR path already used the same strict applier, so preview, approval, verification and PR now share one patch semantics.
- **Verified remediations stay as they are.** Their approval and verification are bound to their exact stored diff, so it is not rewritten. Their downloads stay the old zero-context form.

**Tests.** `src/test/patch-git-apply.test.ts`, 12 tests, using real `git` in a clean checkout of the exact commit:
- production pipeline (`createPreview`): the FraudAi line-5-of-13 case (whose zero-context form plain git rejects), last line, first line, and `package.json`
- a two-file patch
- short and unusual files: 1 line, 2 lines, no trailing newline (end and middle), CRLF, two distant changes giving two hunks
- `git apply --check` and plain `git apply` succeed; `git status` shows only the intended files; contents equal the strict-apply result byte for byte
- a mismatching patch and a missing source are refused
- the worker rescans exactly the approved tree, and rejects a zero-context mid-file patch, wrong context, and file creation
- the legacy zero-context diff is regenerated (hash changes, approval void), then freshly approved with the new hash

Fixtures were updated to canonical diffs. A stale patch is now refused at approval (`patch_does_not_apply`) instead of at verification.

Negative controls: worker back on `--unidiff-zero` → 1 failed; preview not canonicalized → 5 failed; legacy upgrade disabled → 1 failed.

**Live evidence (local production build, visible Chrome, real GitHub source and real scanners).**
- **Preview.** For FraudAi `69581cd`, `backend/requirements.txt` line 5 of 13, the preview is `@@ -2,7 +2,7 @@` with 3 context lines each side. The download is byte-identical.
- **Plain git.** In a clean checkout of `69581cd`, `git apply --check` and `git apply` succeed. `git status` shows only `backend/requirements.txt` (1 insertion, 1 deletion), and line 5 becomes `pytest==9.0.3`.
- **Verification.** Approve, then in-process verification with plain `git apply` and the real Gitleaks, Semgrep and OSV, against the real 8-finding baseline: **"Fix Verified by Security Rescan"**, target resolved, no new findings, 28 s.
- **Legacy remediation** (`ml/requirements.txt`, `@@ -6,1 +6,1 @@`): Approve → `409 patch_regenerated` → the diff shown changes to `@@ -3,4 +3,4 @@` with context, approval cleared, tick cleared → approved again (200), and the diff is unchanged since regeneration.

**Production.** Generating a **new** patch in production needs a new owned scan, which is BLOCKED for this window (§9). Production downloads of the existing older remediations are unchanged, and they stay byte-identical to their stored diffs.

### 7.3 Diff viewer ligatures: `9cccccf`

**Root cause.** JetBrains Mono's ligatures and contextual alternates render `>=` as `≥` and merge `==`.

**Fix.** A `.code-literal` utility (`font-variant-ligatures: none; font-feature-settings: "liga" 0, "clig" 0, "calt" 0, "dlig" 0`) on `DiffViewer`. That one component renders both the Auto-Fix preview and the pull-request confirmation dialog. Stored patch text is unchanged.

**Tests.** `src/test/diff-viewer-literal.test.tsx`, 3 tests:
- `>=`, `==`, `!=`, `<=`, `===`, `=>` and `->` are rendered literally, with no `≥≤≠⇒→`
- the class and its CSS rule are present
- both panels use this viewer

Negative control: class removed → 1 failed.

**Live evidence.**
- **Local:** computed style `font-variant-ligatures: none`, features `"calt" 0, "clig" 0, "dlig" 0, "liga" 0`; the screenshot shows `pytest>=8.0` and `pytest==9.0.3` literally.
- **Production:** the deployed stylesheet contains `.code-literal`, and the diff line's computed style is the same. The screenshot shows literal `>=` and `==`. No console errors.
- **Not tested live:** the PR confirmation dialog in production, which needs an owned verified remediation and a connected GitHub user (§9). It renders the same component.

**Build-cache note.** The first local build after this change served stale CSS from `.next/cache/turbopack`; the rule was missing. A clean build fixed it. The production deployment was checked in the browser for the same problem, and its stylesheet does contain the rule.

### 7.4 Other observations

- **Repository size:** FraudAi exceeds the 25 MB archive cap. The cap is unchanged, pending a separate size-limit review.
- **Missing header:** the `.patch` download has no `X-Content-Type-Options: nosniff`. Not changed.

## 8. Fix verification and deployment

| Item | Result |
|---|---|
| Commits | `dd7cdd5` (Fix 1), `27a3e75` (Fix 2), `9cccccf` (Fix 3), pushed fast-forward from `9e9d5d9` |
| `tsc --noEmit`, `eslint --max-warnings=0` | Pass after each fix |
| `vitest run` (final) | 29 files passed, 3 skipped; **390 passed, 18 skipped, 0 failed**. Before the fixes: 358. |
| `test:scanners` (real Gitleaks, Semgrep, OSV) | 61/61 (after Fix 2) |
| `test:postgres` (disposable container) | 17/17 (after Fix 2; a first attempt failed only because Docker was not running) |
| `next build` | Pass. `prisma:error` lines during prerender come from the unreachable local dev database and are unrelated. |
| Vercel | `dpl_7wt3B6w6SBtsaz7duqZ3dmHiG2JP`, READY, target production, `githubCommitSha 9cccccf391abf4d373cf8967efdf2c5dcf2d39ba`, aliased to `vibeshield-ai-phi.vercel.app` |
| `/api/health` | `healthy`; database healthy; dispatcher ready; warm worker disabled; `githubApp: configured` |

## 9. Remaining blockers and owner actions

1. **Real PR acceptance (scan → approve → rescan → PR → duplicate → altered diff on a live PR): BLOCKED.**
   - **No suitable repository is in the installation.** It covers only FraudAi, which is over 25 MB.
   - **Existing small repos don't work.** Job-portal and Chat-app have real OSV advisories, but against `package-lock.json`; VibeShield auto-fixes only `requirements.txt` and `package.json` declarations, so they correctly yield "manual review". The portfolio has no advisories. No PR will be opened on these real projects.
   - **Needed from the owner:**
     - authorize a dedicated disposable test repository and add **only** that repository to the VibeShield AI installation (not "All repositories")
     - decide its contents; a real, currently vulnerable pinned dependency in `requirements.txt` gives an eligible fix
   - **Then:** after the quota window resets (24 h after the `RJ2D…` submission, i.e. after **2026-10-30 16:06 UTC**), run at most one scan and the full flow on that job, without merging anything.
2. **Private worker: pending, not deployed.** Private scans remain refused on every path.
3. **Turnstile:** not configured.
4. **`OWNER_SESSION_SECRET`:** not set.
5. **PR #10 on FraudAi:** open, not merged, not modified.

## 10. Test-profile cleanup

- **GitHub sign-out:** the temporary GitHub-connected profile was signed out with GitHub's own **Sign out** for that browser session only; `logged_in` went from `yes` to `no`, and `user_session` was removed.
- **Profiles deleted:** `~/.vibeshield-e2e/owner-profile`, plus the visitor, local and production-check profiles and the scratch clones. No session-cookie files remain.
- **Already revoked:** the VibeShield GitHub authorization for that profile was revoked at GitHub by the earlier disconnect test (§6.2 #18).
- **Kept:** evidence (logs with OAuth values redacted, and screenshots) in `~/.vibeshield-e2e/`.

## 11. Evidence locations

- `~/.vibeshield-e2e/state.json`: scan attempts and job ID
- `~/.vibeshield-e2e/final-e2e.log`: scan run
- `~/.vibeshield-e2e/connect-tests.log`: connect, scope and write-gate checks; OAuth `state` and `code_challenge` values redacted
- `~/.vibeshield-e2e/evidence/*.png`: unsubmitted form, failed-scan report before the fix, connected, after disconnect
- `~/.vibeshield-e2e/evidence/local-build/`: local visible-Chrome screenshots of the fixes and the downloaded `backend.patch`
- `~/.vibeshield-e2e/evidence/prod-fixes/`: production screenshots of the fixed failed-scan report and the diff viewer
- **Gap:** log lines after the refresh step were lost when the log file was replaced during redaction. The refresh and disconnect outcomes above come from the database, the audit log, and a re-check from the same browser.
- **Production audit log** (`AuditEvent`), 2026-10-29 16:08–16:12 UTC:
  - `pull_request / denied / not_connected`
  - `github_connect / success`
  - `github_disconnect / revoked`
  - `pull_request / denied / not_connected`

---

## 12. Per-repository authorization and npm lockfile Auto-Fix (2026-10-30)

**Code:** `07d3aac`, `06db3f9`, `466d99b`, `6d3a08f` (fast-forward from `260cb2f`). **Production:**
`dpl_6EEEqnQgSj5j7jbCcovucUdXKeUk`, READY, target production, `meta.githubCommitSha` =
`6d3a08f13e77216952de1579a811933126777c10`, aliased to `vibeshield-ai-phi.vercel.app`. `/api/health`
reported `healthy`, database `healthy`, `githubApp: "configured"`. No production scan was submitted
and no migration was needed (no schema change).

### 12.1 Why every repository had to be added on GitHub

`checkRepositoryAccess` only looked for an installation that already listed the repository. When
it was missing, the write check returned `not_installed`, and the UI's only action was a link to
GitHub's installation pages. No code called GitHub's add-repository API. That API needs a permission
the app registration does not have. Read-only check on 2026-10-30 (`GET /apps/vibeshield-ai`):
`{"contents":"write","metadata":"read","pull_requests":"write"}`.

### 12.2 GitHub's requirements (official sources)

- `PUT /user/installations/{installation_id}/repositories/{repository_id}`: "Add a single
  repository to an installation. The authenticated user must have admin access to the
  repository." Responses: 204, 304, 403, 404
  ([REST docs](https://docs.github.com/en/rest/apps/installations)).
- Required permission: repository permission **"GitHub App installation repository access"
  (write)**, usable with user access tokens
  ([permissions reference](https://docs.github.com/en/rest/authentication/permissions-required-for-github-apps)).
  It was introduced on 2026-10-13 as `installation_repositories:write`. "If the caller is a user,
  they must also be an organization owner or an administrator on the repository in question."
  ([changelog](https://github.blog/changelog/2026-10-13-github-app-improvements-for-least-privilege-and-management/)).
- GitHub's published OpenAPI description does not list this key in `app-permissions` yet.
  VibeShield therefore reads it from the installation's `permissions` (`installation_repositories`).
  If it is absent, the code treats in-product authorization as unavailable (`app_setup_required`)
  and makes no request.

### 12.3 What was built

- **Flow.** The user clicks *Authorize repository* in the Auto-Fix "Repository access" card. The
  server reads GitHub live with the user's own token:
  - canonical repository ID
  - owner account ID and type
  - the user's admin and push role
  - this app's installation on the owner account, matched by immutable account ID
  - whether the repository is already selected
  - whether the installation holds the permission

  It returns one of: `authorized`, `authorization_required`, `app_setup_required`,
  `installation_required`, `admin_required`, `organization_approval_required`,
  `no_push_permission` or `app_lacks_permission`.
- **Confirmation.** For an addable repository the dialog shows exactly what was bound: repository,
  repository ID, owner, PR base branch, scanned commit, installation and capabilities. That binding
  is a single-use request with these properties:
  - It is stored as a SHA-256-hashed `OAuthState` id with purpose `repo_access`, and its binding is
    AES-256-GCM encrypted.
  - It is bound to the browser session, the GitHub user, the job-owner grant, the scan, the
    scanned commit, the repository ID and the installation ID.
  - It expires after 10 minutes.
- **Addition.** Confirming consumes the request and rejects any substitution. The server re-checks
  GitHub and sends one `PUT` for that repository ID. It reports success only after GitHub lists
  the repository in that installation (up to 3 re-reads).
  - It never selects "All repositories" and never removes anything.
  - Refusals are reported honestly, with GitHub-managed links: a 403 on an organization repository
    means owner approval is required; a non-admin user cannot add a repository; a missing
    permission means one-time setup.
- **Audit.** `repository_authorization` events record: requested, added, already_present, denied,
  rejected, not_confirmed and cancelled. They contain no tokens, cookies or request secrets.
- **Writes.** These are unchanged: before every PR the user's own token is live-checked for push
  access, installation scope, repository ID, approved diff hash, scanned commit and verification
  status. PRs now record GitHub's own commit attribution: author and committer names, a noreply
  flag (the email is not stored) and signature verification.
  - The PR body says the change was prepared on the user's behalf.
  - The PR request schema is strict, so a client-supplied author is rejected with 400.
- **npm lockfile Auto-Fix.** OSV findings reported against `package-lock.json` were previously
  refused. They now produce the change `npm install <pkg>@<v> --package-lock-only --ignore-scripts`
  would make, without running npm or repository code:
  - the target is the lowest stable release that fixes every advisory reported for that version
  - only the declared range in `package.json` changes
  - the lock entry comes from registry metadata, with the tarball host and sha512 checked
  - orphaned packages are pruned and npm's flags recomputed
  - the output is serialized with npm's key order

  Anything else is refused as needing manual review.
- **Private repositories** stay blocked from the public GitHub Actions workers, as before. That code
  was not changed.

### 12.4 Job-portal fixture (Phase 7 preconditions)

- Repository `samarth-khera/Job-portal`: public, ID `1106558267`, default branch `main`, HEAD
  `7f90143a47c6280f6bcf9d55bb7c4767a48c1542`. `backend/package.json` declares `"multer": "^2.0.2"`;
  the lockfile has `multer@2.0.2` (lockfileVersion 3).
- OSV (queried 2026-10-30) lists nine advisories for multer 2.0.2, fixed in 2.1.0 to 2.5.0:
  GHSA-3p4h-7m6x-2hcm, GHSA-535w-7cp7-47q4, GHSA-5528-5vmv-3xc2, GHSA-72gw-mp4g-v24j,
  GHSA-q7qp-rjg7-q26m, GHSA-qvfw-j98x-7q72, GHSA-v52c-386h-88mc, GHSA-wc9g-mqfw-jrwm,
  GHSA-xf7r-hgr6-v32p. npm `latest` is 2.5.0, which drops `concat-stream`, `mkdirp`,
  `object-assign` and `xtend` as dependencies.
- **Eligibility confirmed (local).** VibeShield's generated `package.json` and `package-lock.json`
  are byte-identical to npm 10.9.3's output. The npm run used an empty directory with no `.npmrc`,
  scripts disabled and only the lockfile written. Nine packages are pruned
  (`buffer-from`, `concat-stream`, `minimist`, `mkdirp`, `readable-stream`, `string_decoder`,
  `typedarray`, `util-deprecate`, `xtend`).
  - The two-file diff applies with plain `git apply`.
  - A real Gitleaks/Semgrep/OSV-Scanner rescan resolves all nine multer findings with no
    regressions.

### 12.5 Test evidence

| Suite | Result |
|---|---|
| `vitest` (all unit/integration) | **467 passed**, 19 skipped (was 390) |
| Real scanners (`npm run test:scanners`) | **62/62**, incl. the Job-portal multer fix verified by a full rescan |
| PostgreSQL (`npm run test:postgres`) | **18/18**, incl. a `repo_access` request consumed once under 20 concurrent confirmations |
| Typecheck, lint, production build | clean |
| Gitleaks on the 4 commits / `npm audit --omit=dev` | no leaks / 0 vulnerabilities |
| Semgrep (p/typescript, p/secrets, p/nodejsscan) on the new server/UI files | 2 ReDoS warnings in `npm-lockfile.ts`, reviewed as false positives (no nested quantifiers; inputs validated and escaped) |

New tests cover the following:
- already authorized; added after explicit confirmation; exact repository ID only
- already present / added meanwhile; replayed and concurrent confirmations
- admin vs. push-only user; organization 403; missing permission; no installation
- expired token refreshed; revoked token
- repository, installation, job, owner-session and GitHub-user substitution
- another account's installation; repository changed; cancellation
- CSRF; not connected; not configured
- the status never shows "authorized" before GitHub confirms
- commit attribution and spoofed author refused; real PR URL
- the UI dialog and states; npm byte equality and 19 fail-closed cases

Existing suites still cover approval binding, altered diffs, regression detection, ownership, public
scans without GitHub and private-scan fail-closed.

**Production, read-only (visible Chrome, no sign-in, no scan):** the `M0p3…` report still shows
"VERIFIED SCAN REPORT". A non-owner sees the read-only note, no "Repository access" card and no
Authorize button, and the console shows no errors. The new endpoint returns 403 `forbidden_origin`
for a cross-site POST and 403 `not_job_owner` without an owner grant. Screenshot:
`~/.vibeshield-e2e/evidence/prod-repo-auth/`.

An unscoped `prisma migrate deploy` was run once by mistake while preparing the Postgres suite.
Prisma's CLI reads only `.env`, whose `DATABASE_URL` points to localhost, and this change has no
migrations, so nothing was applied anywhere. Production was not touched.

### 12.6 Live Job-portal workflow: **BLOCKED**

The live test needs three things, none of which can be done on the owner's behalf:

1. **One-time app change (owner).** In GitHub App settings → Permissions, set
   **GitHub App installation repository access: Read and write** and save. Then accept the updated
   permissions on installation `176245393` (`https://github.com/settings/installations/176245393`),
   keeping "Only select repositories". Details: `docs/github-app-setup.md` §1a. Until then, production
   correctly reports `app_setup_required` and makes no add request.
2. **Scan quota window.** The last production scan was at 2026-10-29 16:06:25 UTC, so the window
   resets after **2026-10-30 16:06 UTC**.
3. **GitHub sign-in** by the owner in a visible test Chrome profile, as in the earlier runs.

Planned single run, with at most one scan and no retries:
- scan Job-portal
- open a multer finding, then Repository access → Authorize repository → confirm, and check on
  GitHub that the installation lists only FraudAi and Job-portal
- preview the multer 2.5.0 diff, approve it and run the full rescan
- create the PR, then repeat the request to check duplicates are prevented
- inspect the branch, the commit attribution and that the default branch is untouched
- do not merge

| Requirement | Status |
|---|---|
| Already-authorized / add / exact repository ID / idempotency / substitution / denial and cancellation | **PASS** (deterministic tests), **NOT TESTED** live |
| Push-only user, organization approval, missing permission | **PASS** (tests). Production shows the missing-permission state until the owner's change. |
| Expired, revoked and refreshed tokens | **PASS** (tests; live refresh passed on 2026-10-28, §6) |
| npm fix eligibility for Job-portal | **PASS** (npm byte equality, plain `git apply`, real-scanner rescan) |
| Live in-product authorization of Job-portal | **BLOCKED** (item 1) |
| Live scan → approve → rescan → real PR → duplicate check | **BLOCKED** (items 1–3) |

---

## 13. Auto-Fix-to-commit workflow on the existing Job-portal report (2026-10-29/30)

**Code:** `bedc5b4`, `85f8df3`, `9b177a9`, `41fb7e9` (fast-forward from `d58bb1b`).
**Production:** `dpl_5UjFFDWHF2axQrNpiKUjyQYwiCqZ`, READY, target production,
`meta.githubCommitSha` = `41fb7e9b649d424e076e40e710ae32bdceac2480`, aliased to
`vibeshield-ai-phi.vercel.app`. `/api/health` reported `healthy`, database `healthy`,
`githubApp: "configured"`, dispatcher `ready`. **No production scan was submitted.** The existing
job was reused, and the Job-portal repository was not modified.

### 13.1 Starting state (observed)

- **Deployed commit:** `d58bb1b` (`dpl_5yupkqGBysaMi8RDnerLGELpAnbH`), healthy.
- **GitHub App registration:** `contents: write`, `metadata: read`, `pull_requests: write`. The
  installation-repository-access permission is still not granted. There are no
  `repository_authorization` audit events, so Job-portal was added to installation `176245393` on
  GitHub's own page, and "Repository authorized" was GitHub's live answer for that.
- **Existing job:** `A-NZKPwxBNay-TeEZnpfGGpWYqlikg9p` (`samarth-khera/Job-portal`, public, repository
  ID `1106558267`, commit `7f90143a47c6280f6bcf9d55bb7c4767a48c1542`). Created 20:54:52 UTC and
  completed 20:55:27 UTC, with Gitleaks, Semgrep and OSV-Scanner all `completed` and 180 findings.
  GitHub was connected at 20:56:08 UTC (`samarth-khera`).

### 13.2 What actually happened (Vercel request logs and database records)

| UTC | Request | HTTP | Result |
|---|---|---|---|
| 20:57:42 | `POST …/remediation/preview` (finding `cmvu0vp9v000ti708v1nuwqxr`, proxy-addr) | 201 | Remediation `e2823631-…` saved: `unsuitable`, empty diff, reason "proxy-addr is not a direct dependency of this project…" |
| 20:58:05 | `POST …/findings/cmvu0vp9v000ti708v1nuwqxr/explain` | 200 | AI explanation |
| 20:58:50 | `POST …/remediation/preview` (brace-expansion) | 201 | Remediation `39c0b4c7-…` saved: `unsuitable`, empty diff |
| 20:59:49 | `POST …/remediation/preview` (a directly declared package such as multer) | **500** | `prisma.remediation.create()`: **P2000 "The provided value for the column is too long for the column's type"**. Nothing saved. The UI showed "Failed to generate remediation preview." |

No approval, verification, branch, commit or pull request was requested. No GitHub write took
place. The journey stopped at the preview.

### 13.3 Root causes

1. **Production bug, which blocked every eligible npm fix.** The npm lockfile fix from `06db3f9`
   generated a 594-character explanation for the `VARCHAR(500)` column `Remediation.eligibilityReason`,
   so the insert failed with P2000. I introduced this in the previous round. It was missed because
   the in-memory test store accepted any length. Fixed in `bedc5b4`:
   - text is fitted to its column in the service and in the Prisma store;
   - the test store now enforces PostgreSQL's limits;
   - the explanations are short by design (`85f8df3`).
2. **Engine gap.** Every package not declared in `package.json` was refused. The selected finding is
   `GHSA-jqcg-44mw-7w3h` (CVE-2026-90711, critical, osv-scanner, `proxy-addr` 2.0.7, fixed in 2.0.8,
   `backend/package-lock.json`). It is fixable as npm fixes it: `express@5.1.0` declares `"^2.0.7"`,
   and `npm update proxy-addr` changes only that lockfile entry. Fixed in `85f8df3`.
3. **The UI hid the server's decision.** For a remediation with an empty diff, the panel rendered
   only the "Manual Review Required" badge. The reason and warnings lived inside the diff section,
   and there was no next step. Fixed in `41fb7e9`.
4. **The badges and selection summary used an optimistic client-side guess.** Any dependency with a
   fixed version counted as "eligible for automated fix", so they disagreed with the server
   ("1 eligible" versus "Manual Review Required"). Fixed in `41fb7e9`.

**Answers to the Phase 1 questions:**
1. **The finding:** ID `cmvu0vp9v000ti708v1nuwqxr`, osv-scanner, `GHSA-jqcg-44mw-7w3h`, `proxy-addr@2.0.7`
   (fixed in 2.0.8), `backend/package-lock.json`, commit `7f90143…`.
2. **The server's decision:** `unsuitable`, reason "not a direct dependency" (the engine gap).
3. **Why the panel said "Manual Review Required":** the stored remediation had
   `eligibility: unsuitable`, and the reason was never rendered.
4. **Why the summary disagreed:** it used the client-side guess.
5. **Did clicking send a request:** yes, three preview POSTs (above).
6. **The requests:** see §13.2.
7. **What was created:** two remediation records (no diff), and nothing else.
8. **What was wrong in the UI:** the error was hidden (the reason was not shown), there was no
   action, and the eligible preview failed with a generic message.

### 13.4 Eligibility of every finding in the existing scan (real engine, files at the scanned commit, live registry)

| Lockfile | Package (installed) | Findings | Decision |
|---|---|---|---|
| backend | multer 2.0.2 (direct) | 9 | **Eligible** → 2.5.0, `package.json` and lockfile; fixes all 9 |
| backend | proxy-addr 2.0.7 (via express `^2.0.7`) | 1 | **Eligible** → 2.0.8, lockfile only |
| backend | jws 3.2.2 | 1 | **Eligible** → 3.2.3, lockfile only |
| backend | path-to-regexp 8.3.0 | 2 | **Eligible** → 8.4.2, lockfile only |
| backend | brace-expansion 1.1.12 (via minimatch `^1.1.7`) | 7 | 1 eligible → 1.1.21. 6 manual: fixed only in 5.x, outside minimatch's range |
| backend | body-parser 2.2.1 / qs 6.14.0 | 2 / 5 | Manual: the fixed release needs other packages upgraded too |
| backend | minimatch 3.1.2 / picomatch 2.3.1 | 3 / 2 | Manual: the fix is outside the parent's range (nodemon / anymatch, readdirp) |
| backend | mongoose 9.0.0 | 2 | Manual: OSV's recorded fix (6.13.x) is for another release line |
| root | moment 2.30.1 (direct) | 1 | **Eligible** → 2.31.0 |
| root | follow-redirects 1.15.11 | 1 | **Eligible** → 1.16.2, lockfile only |
| root | axios 1.13.2 / react-router 7.9.5 / form-data 4.0.4 | 35 / 13 / 1 | Manual: needs form-data upgraded / outside react-router-dom's exact `7.9.5` / another release line |
| frontend | all 30 packages | 105 | Manual: today's npm rewrites 72 unrelated lines of this lockfile (written by another npm version), so no minimal change exists |
| backend/.env | generic-api-key (Gitleaks) | 1 | Rotate credential; never auto-fixed |

**Proof for every eligible fix:**
- Each generated file is byte-identical to npm 10.9.3's own output for the same change. npm ran in
  an empty directory with no `.npmrc`, with `--package-lock-only --ignore-scripts`; the command was
  `npm install <pkg>@<v>` for direct dependencies and `npm update <pkg>` for transitive ones.
- Each result installs with `npm ci --ignore-scripts` and passes `npm ls --all`.
- Real Gitleaks/Semgrep/OSV-Scanner rescans verify `multer` (9/9 resolved) and `proxy-addr`
  (1/1), with no regressions.

One planner gap found by this oracle was fixed before the release: `peerDependenciesMeta`, published
by follow-redirects 1.16.2, had been dropped. Unknown fields are now refused, never dropped.

### 13.5 Changes

- **`bedc5b4`:** previews can no longer fail on long text, enforced at the service and the store.
- **`85f8df3`:** transitive npm fixes with npm-update semantics, accurate refusal reasons,
  release-line checks, and complete lockfile metadata.
- **`9b177a9`:** approvals bind the canonical repository ID, and the PR is refused for another
  repository ID or GitHub account. PR steps are stored while they run. The branch ref, commit
  (tree and single parent) and PR (head, base, author) are read back from GitHub before anything is
  reported as created; otherwise the result is `not_confirmed`. Verification exposes whether a
  worker has claimed it.
- **`41fb7e9`:** the status line covers every stage:
  - not eligible, manual review with the actual reason, generating
  - preview ready / waiting for approval, approved
  - queued, then running Gitleaks, Semgrep and OSV-Scanner, with elapsed time
  - verified, failed or timed out
  - publishing steps, PR created, rate-limited, authorization revoked

  It also adds "Check again", server-based badges and selection counts, persisted PR progress and
  interruption handling, and shows the commit and PR authors as GitHub reports them.

**Unchanged:** failed-scan reporting, the plain `git apply` context fix, the ligature fix, the
authorization guards and the patch-integrity rules. Their suites pass.

### 13.6 Evidence

- **Production before the fix (visible Chrome, read-only).**
  - The proxy-addr row was badged "Potentially Breaking"; selecting it showed
    "1 findings selected (1 eligible for automated fix)".
  - The panel text was only "AI Auto-Fix & Verification | MODE B: AUTO-FIX | Manual Review
    Required". The reason was in the API response but not rendered; no console errors.
  - Evidence: `~/.vibeshield-e2e/evidence/autofix-diagnosis/prod-before/`.
- **Owner view on the deployed code (`d58bb1b`).** Local production build, local PostgreSQL holding a
  copy of the job's 180 findings and 2 remediations, local owner grant, visible Chrome.
  - proxy-addr: badge only, no reason.
  - multer: Preview → `POST /remediation/preview` **500** `{"code":"internal_error","message":"Failed
    to generate remediation preview."}`; the server log shows P2000.
  - Evidence: `…/local-before-d58bb1b/`.
- **Owner view on the fixed build (same data).**
  - proxy-addr shows its reason and package facts. "Check again" returns 201 with the lockfile-only
    2.0.8 diff; the status becomes "Patch preview ready — waiting for your explicit approval".
  - multer preview returns 201 with the two-file diff. After the explicit approval, verification
    ran with the real scanners:
    - Gitleaks, Semgrep and OSV-Scanner all `completed`
    - 9/9 targets resolved, 0 new findings, findings 180 → 171
    - approved diff SHA-256 = stored diff
  - After a reload the status is "Fix verified — ready to open a pull request".
  - The report badges show the server's "Fix Ready". Selecting proxy-addr, jws and mongoose shows
    "1 eligible for automated fix · 2 checked when previewed". No console errors.
  - Evidence: `…/local-after-fixed/`.
- **Production after the deploy (visible Chrome, read-only).** proxy-addr shows "Status: Manual review
  required" with the stored reason and facts; the summary shows "0 eligible"; no console errors.
  Evidence: `…/prod-after/`.

| Suite | Result |
|---|---|
| `vitest` (unit and integration) | **490 passed**, 20 skipped (Postgres, real scanners and live-GitHub suites run separately) |
| Real scanners | **63/63**, including multer and proxy-addr fixes verified by full rescans |
| PostgreSQL | **19/19**, including an over-length explanation stored without P2000 |
| Negative controls | Without the column fitting, real Postgres raises the exact production P2000 and the service test fails |
| Typecheck, lint, production build | Clean |
| Gitleaks (commits `d58bb1b..41fb7e9`, `src`) / `npm audit --omit=dev` | No leaks / 0 vulnerabilities |
| Semgrep on the changed server and UI files | 5 notices, all reviewed: linear regexes with validated inputs (ReDoS false positives) and the existing retry jitter |

**Phase 6 test matrix:**

| Requirement | Tests |
|---|---|
| Authorized repository, ineligible finding | `autofix-status-ui` "authorized repository + ineligible finding…"; `autofix-workflow` "an authorized repository does not make an ineligible finding fixable" |
| Authorized repository, eligible finding | `autofix-workflow` "keeps one remediation ID, one commit and one diff…"; `autofix-status-ui` "authorized repository + eligible finding…" |
| Authorization does not imply remediation success | `autofix-status-ui` (status "No fix generated yet", no verified/PR claims) |
| Missing or insufficient permissions | `repository-authorization` (push-only user, missing app permission); `github-app-auth` (no write access); `pull-request-ui` |
| Missing, stale or revoked authorization | `repository-authorization` (expired → refresh, revoked); `github-app-auth` token lifecycle; `repository-authorization-ui` (reconnect) |
| Approval missing or for another diff; patch changed after approval | `github-app-auth` "enforces approval, verification and the exact approved diff"; `patch-git-apply` (a regenerated diff needs a fresh approval); `remediation` |
| Wrong repository ID or commit SHA | `autofix-workflow` (approval for another repository ID or GitHub account); `github-pr` (recreated or renamed repository); `github-app-auth` (`commit_mismatch`) |
| Verification failure or incomplete scanners | `remediation` (failing engine, regression); `real-scanners` (still-vulnerable bump); `autofix-status-ui` (timeout) |
| Committing an unverified patch | `github-app-auth` (`not_verified`) |
| Branch or commit creation failure; result not confirmed | `github-pr` (denied writes, branch conflict); `autofix-workflow` (`not_confirmed` read-back) |
| PR API failure; duplicate retry | `github-pr` (double click, existing closed PR); `pull-request-ui` (refused); `autofix-workflow` (retry returns the same PR) |
| Commit and PR attribution | `repository-authorization` (spoofed author refused); `autofix-workflow` (PR author and commit login from GitHub); `autofix-status-ui` |
| Cross-user access, CSRF | `github-app-auth`; `repository-authorization` (substitution, origin); `ownership` |
| Status UI in progress and failed | `autofix-status-ui` (queued/running, timeout, interrupted, rate-limited, revoked) |
| Reload persistence | `autofix-status-ui` (stored publish step followed to the confirmed PR); `pull-request-ui` (verified fix and PR restored) |

### 13.7 Stages that truly executed

| Stage | Production (live) | Local (fixed build, real scanners) |
|---|---|---|
| Repository authorized (GitHub's live answer) | Yes, in the owner's session (added on GitHub's page; no in-product addition) | n/a (GitHub App not configured locally) |
| Eligibility decided | Yes: 2 refusals stored, 1 eligible preview failed with 500 | Yes |
| Patch generated and displayed | **No** (the 500, fixed in `bedc5b4`) | Yes |
| Explicit approval | Not reached | Yes |
| All three scanners completed, fix verified | Not reached | Yes (multer, 9/9, 0 new) |
| Branch, commit, push, PR | None created | n/a locally; covered by tests against the stateful GitHub fake |
| PR URL | None | None |

### 13.8 One controlled live test: **NOT RUN — needs the owner's browser session**

The job's owner grant is an HttpOnly cookie in the browser that started the scan. It cannot be
transferred, and recreating it would mean bypassing ownership or submitting a new scan, and both are
excluded. The live step therefore needs the owner to click in their own browser while the server
side, the database and GitHub are checked. Recommended: the proxy-addr fix (one lockfile entry):

1. Open the report → AI Auto-Fix → the proxy-addr finding → **Check again**.
2. Review the diff, tick the box and click **Approve Patch**, then **Verify Fix on Full Repository**.
3. When the status says **Fix verified**, use **Review & create pull request**, confirm the exact
   diff and create the pull request.

At most one PR, never merged.

The installation's current repository selection can only be read with the owner's token or on
GitHub's settings page (`https://github.com/settings/installations/176245393`). The app-level
permissions are as in §13.1.

### 13.9 Remaining limitations

- **Still manual review:** frontend findings (lockfile written by another npm version); fixes that
  need several packages (body-parser, qs, root axios); fixes outside a parent's range (minimatch,
  picomatch, brace-expansion 5.x, react-router); fixes recorded for another release line (mongoose,
  form-data, rollup); prerelease-only fixes (@babel/core).
- **Old record:** the stored `unsuitable` proxy-addr record from 20:57 stays until **Check again** is
  used, so badges show its old decision until then.
- **Repository authorization:** in-product repository addition still needs the one-time app
  permission (§12.6); adding repositories on GitHub's page keeps working.
- **Live run:** the live PR flow on production is not yet observed (§13.8). The PR steps, read-back
  and binding are covered by tests and the local run only.

### 13.10 Live run attempt, 2026-10-30 17:03 UTC: **STOPPED — this automation does not hold the owning browser session**

- **Ownership.** The only browser I can control is a fresh visible-Chrome profile. For it,
  `GET /api/scans/A-NZKPwxBNay-TeEZnpfGGpWYqlikg9p` returns `viewer: {"isOwner": false}`. No Chrome
  on this machine exposes a debugging port, so the user's running Chrome cannot be driven, and Chrome
  does not allow remote debugging of a default profile. Copying that profile or its cookies would mean
  moving session credentials, so it was not done.
- **Who owns the job.** The report is owned by the browser that submitted the scan on 2026-10-29 at
  20:54:52 UTC and connected GitHub at 20:56:08 UTC (HttpOnly `__Host-vibeshield_owner` cookie). The
  job and the grant remain valid until 2026-11-05 20:54 UTC.
- **State at the stop (read-only checks).**
  - The only proxy-addr record is still the 20:57:42 `unsuitable` remediation `e2823631…`. "Check
    again" has not been used, so no diff has been generated.
  - On GitHub, `samarth-khera/Job-portal` has only `main`, at the scanned commit `7f90143a47c6`,
    and no pull requests.
- **Nothing was created.** No scan, preview, approval, verification, branch, commit or PR was
  created by this attempt.

---

## 14. Complete Auto-Fix workflow: diagnosis, both modes, local verification (2026-10-30)

**Code:** `797e0fc` (server), `81cda0a` (UI), `9180734` (local test harness), fast-forward from
`7ec78ec`. **Production:** `dpl_5pLRPDj9eQRFKStW65X6w8WbP5Bf`, READY, target production,
`meta.githubCommitSha` = `9180734d0dead784ad07f6ae5762c9219c187c3d`, aliased to
`vibeshield-ai-phi.vercel.app`. `/api/health` reported `healthy`, database `healthy`,
`githubApp: "configured"`, dispatcher `ready`.

**Quota:** no production scan, no production preview or remediation, and no AI (Gemini) request
were made during this task. Production was only read:
- read-only database queries;
- Vercel request logs;
- GET-only page loads, with zero POSTs observed in the browser check.

### 14.1 Why the new report showed "No fix generated yet"

Your 17:07 UTC scan created a new job, `tgXZMOF1onmDJsS3mATJRptGoVGUHgDe` (same commit `7f90143`;
`proxy-addr` finding `cmvv87qcr000tl50858hrlz1p`). GitHub was connected at 17:09.
- **What the records show:** the request logs have no `POST …/remediation/preview` for that job and
  the database has no remediation for it, so **no fix was ever requested**. The status was accurate;
  nothing had failed.
- **The previous failure was different.** On the earlier job, eligible previews returned HTTP 500
  (P2000, fixed in `bedc5b4`), and `proxy-addr` was wrongly refused (fixed in `85f8df3`), §13.
- **What was missing as a product:**
  - nothing said that a preview had to be requested, or whether it uses AI quota;
  - generation was one opaque request;
  - approval, verification and the PR were three separate manual steps;
  - verification showed nothing until the end;
  - a "Potentially Breaking" badge came from a client-side guess before the server had decided.

### 14.2 How a fix is generated (evidence for `proxy-addr`)

For `proxy-addr` 2.0.7, installed through `express@5.1.0` (`"^2.0.7"`), the fix is → **2.0.8**:
- **Change:** lockfile only, identical to `npm update proxy-addr --package-lock-only` (byte-equal
  fixture).
- **Classification:** **safe** — transitive, patch-level, inside the parent's range, and no other
  lockfile entry changes.
- **Engine:** the deterministic npm engine, which makes **no AI request**.

Stored generation steps, as observed in the local run (HTTP 201):
1. `checking_repository`, recording that the account can publish to `samarth-khera/Job-portal`
2. `checking_eligibility`
3. `generating_remediation`
4. `validating_dependency_changes`
5. `generating_patch`

The verification worker applies the result with plain `git apply` and a byte check (§7.2).

| Package (existing scan) | Server decision |
|---|---|
| proxy-addr 2.0.7, jws 3.2.2, brace-expansion 1.1.12 (one advisory → 1.1.21) | **Safe**: lockfile-only patch updates |
| multer 2.0.2 → 2.5.0 (direct), path-to-regexp → 8.4.2, moment, follow-redirects | Eligible, **potentially breaking**: a person must approve |
| mongoose, body-parser, qs, minimatch, picomatch, react-router, frontend lockfile, … | Manual review, with the reason shown (§13.4) |

### 14.3 The two modes and their permission boundaries

**Review and Approve (default).**
1. **Fix with AI:** the user clicks Preview Proposed Patch. The status says beforehand that nothing
   runs until then, and the engine note says whether AI is used.
2. **Live steps:** the stored steps are shown while generation runs, and the exact diff appears at
   the end.
3. **One explicit approval.** When the repository is authorized, the approval also states and
   authorizes publishing: a new branch, a commit of exactly this diff, and a PR with the user's
   account; never merged, default branch untouched. Consent counts only if GitHub confirms, live,
   that the connected account can write to the repository.
4. **Verification:** it starts immediately. The worker posts signed progress: snapshot rebuilt,
   patch applied, then Gitleaks, Semgrep and OSV-Scanner each running and finished.
5. **Publishing after it passes,** with the approving user's own stored authorization, re-checked
   live: account still connected, token valid, same repository ID, push and installation write. The
   steps are recorded (re-check, commit, branch push, PR, read-back), and the branch ref, commit tree
   and parent, and PR head, base and author are read back before success is shown.
6. **Retries are safe.** A recovery pump finishes interrupted publications, and retries reuse the
   same branch and PR.

**Safe Auto-Fix (explicit per-repository opt-in, off by default).**
- **Enabling requires:**
  - the job owner's browser;
  - a same-origin request;
  - a connected GitHub user whose write access GitHub confirms live;
  - a confirmation dialog;
  - the exact repository ID.
- **What it processes:** for a completed scan (and on "Run on this scan now"), it generates fixes for
  up to 25 vulnerable npm packages. Only server-classified **safe** fixes are approved by the policy
  (recorded as `approvedBy: safe_autofix`), verified and published.
- **What it never processes:** potentially breaking upgrades, manual-review findings, secrets,
  AI-generated code changes and private repositories. Those stay as previews for a person.
- **Turning it off** cancels pending publications (`publish_cancelled`).
- **Audit:** every step is recorded (`safe_autofix` and `pull_request` events).

**Never, in either mode:** direct pushes to the default branch, merges, client-supplied authors (the
approve request reads only `publish`; the PR request schema is strict), or success shown before
GitHub's read-back.

### 14.4 Tests

| Suite | Result |
|---|---|
| `vitest` (unit, integration, UI) | **507 passed**, 21 skipped (Postgres, real-scanner and live suites run separately) |
| Real scanners (`npm run test:scanners`) | **63/63** |
| PostgreSQL (`npm run test:postgres`, incl. the new `SafeAutoFixSetting` table) | **20/20** |
| Typecheck, lint, production build | Clean |
| Gitleaks on commits `7ec78ec..9180734` / `npm audit --omit=dev` | No leaks / 0 vulnerabilities |
| Semgrep on the changed files | 5 notices, reviewed: linear regexes with validated inputs (ReDoS false positives) |

New tests (`autofix-automation`, `autofix-status-ui`, `postgres-auth`) cover:
- authorization does not imply a fix;
- Preview sends exactly one request and shows the stored steps;
- a reload while generating, and an interrupted generation;
- safe versus potentially-breaking classification;
- the stored diff hash;
- publish consent needing live write access;
- failed verification preventing any commit;
- signed progress callbacks, with an unsigned one refused;
- automatic publishing with read-back, and no duplicate commit or PR from late callbacks or polls;
- a disconnected account blocking later writes;
- Safe Auto-Fix: off by default, explicit confirmation, write access required, only safe fixes,
  cancellation on turning it off, policy refusal of non-safe fixes, and the lowest-fix
  representative;
- the opt-in store against real Postgres.

Existing suites still cover cross-user access, CSRF, forged identities, altered patches and
attribution.

**Bugs found and fixed during testing:**
- **Scan callback failure:** Next's `after()` throws outside a request scope, which made the
  scan-completion callback fail in an integration test. Deferred work now runs detached when
  `after()` is unavailable, and can never fail the request that scheduled it.
- **Safe Auto-Fix missed in-range fixes:** it started from the first advisory of a package; it now
  starts from the lowest fixed release, which is the one npm can reach inside the parents' ranges.

### 14.5 Visible-browser tests and what was simulated

**Local (`http://localhost:3100`).**
- **Setup:** a production build; local PostgreSQL with a copy of the existing report `tgXZ…` (180
  findings); **real** Gitleaks, Semgrep and OSV-Scanner; the live npm registry.
- **Simulated GitHub:** in-process (`src/test/e2e/local-github-preload.mts`, seeded with the real
  Job-portal tree at `7f90143`). Every other outbound host, including AI, was blocked, and PR links
  point to `simulated-github.local`. **These are simulated results, not real pull requests.**

Observed in visible Chrome, with no console or network errors:
1. **Before any preview:** the card shows `samarth-khera/Job-portal` (ID 1106558267), authorized
   account @samarth-khera, write access, base branch `main`, and that a branch, commit and PR are
   possible after a verified approval. Safe Auto-Fix is Off. Status "No fix generated yet"; engine
   note "No AI request".
2. **Preview:** HTTP 201 with the five stored steps, eligibility `safe`, and the exact diff (2.0.8).
3. **Refusal:** mongoose shows its release-line reason.
4. **One approval with publish consent:** real verification, then simulated branch, commit and
   **PR #1** read back (about 9 seconds). Status "Pull request #1 created"; it persisted after a
   reload.
5. **Duplicate check:** two more PR requests both returned PR #1. Simulated GitHub still had 1
   commit and 1 PR, and the commit request carried only `message`, `parents` and `tree`.
6. **Safe Auto-Fix:**
   - Enabled through the dialog.
   - `jws` was processed automatically: policy approval, real rescan, simulated **PR #2**.
   - `multer` and `path-to-regexp` were left as potentially-breaking previews.
   - Every refusal kept its reason.

**Production (read-only, non-owner):** on the new report, the `proxy-addr` panel shows "Checked on
preview", "Status: No fix generated yet", that nothing runs until the preview, and "No AI request:
VibeShield's deterministic npm engine…". The page sent **zero POST requests** and logged no console
errors.

### 14.6 Not verified live (quota preservation and permissions)

- **Not run in production:** preview, approval, the Actions worker's progress callbacks, publishing
  and Safe Auto-Fix. These were verified only locally, against simulated GitHub, and by tests.
- **Safe Auto-Fix needs one database migration in production.** The additive migration
  `20261030180000_add_safe_autofix_setting` (a single `CREATE TABLE "SafeAutoFixSetting"`) is the
  only pending one; `prisma migrate status` confirmed this read-only. Applying it was refused by this
  session's permission policy. Until it is applied, the card shows no Safe Auto-Fix control and
  enabling returns "setup incomplete". Review and Approve does not need it.
- **Real GitHub writes** (branch, commit, PR) were not performed in this task.

### 14.7 Your production test, step by step

1. **Optional, for Safe Auto-Fix.** Apply the migration once, from the repository:
   - `npx vercel env pull .env.production.local --environment=production`
   - `set -a; . ./.env.production.local; set +a; npx prisma migrate status` (expect only
     `20261030180000_add_safe_autofix_setting`)
   - `npx prisma migrate deploy`
   - `rm .env.production.local`
2. **Open your report.** Use the browser that started the scan:
   `https://vibeshield-ai-phi.vercel.app/report/tgXZMOF1onmDJsS3mATJRptGoVGUHgDe`. Choose
   **AI Auto-Fix**, then the `proxy-addr` finding. The card should say "Repository authorized" with
   your account, write access, `main` and `7f90143`.
3. **Preview.** Click **Preview Proposed Patch** (no AI request). Watch the five steps; expect
   "Preview ready — waiting for your explicit approval", a **Safe to Auto-Fix** badge, and a one-file
   diff to `proxy-addr` 2.0.8.
4. **Approve.** Tick the approval, which names the repository and your account, then click **Approve,
   verify and open pull request**.
5. **Watch verification.** Expect: rebuilding the repository, applying the approved patch, then
   Gitleaks, Semgrep and OSV-Scanner each finishing (on the GitHub Actions worker), then "Security
   verification complete — creating the pull request automatically".
6. **Watch publishing.** Expect: commit, branch push, pull request, then "Branch, commit and pull
   request were read back from GitHub and match". Open the PR link and confirm it on GitHub: base
   `main`, a single commit whose parent is `7f90143`, and only `backend/package-lock.json` changed.
   **Do not merge it.**
7. **Optional, after step 1.** Enable Safe Auto-Fix in the card; expect `jws` (and one
   `brace-expansion` advisory) to be processed into separate PRs automatically, with everything else
   left for review. Turn it off afterwards if you don't want it.

---

## 15. Production acceptance on a disposable repository: preparation and blocker (2026-10-30)

**Status:** Phases 1, 2 and 5 are done. Phases 3, 4 and 6–11 are **BLOCKED** before the production scan,
as instructed: the one-time GitHub App permission is missing.
- **Production scans submitted:** **0**.
- **Live Gemini calls:** **0**.
- **Existing repositories:** none were modified.

### 15.1 Phase 1: production checks

| Check | Result |
|---|---|
| Remote `main` / working tree | `dd96ab9` at the start of this task (`a4a6467` after the fix below); clean |
| Deployed commit and health | `dpl_8C2WuqQLDPmDHoT9TSVgddqGhP4T` READY at `a4a6467`; `/api/health` `healthy`, database `healthy`, `githubApp: configured` |
| Dynamic repository authorization deployed | Yes (since `07d3aac`) |
| **"GitHub App installation repository access: write"** | **Missing.** `GET /apps/vibeshield-ai` → `{"contents":"write","metadata":"read","pull_requests":"write"}`, registration last updated 2026-10-28 |
| Installation restricted to selected repositories; connected user | Not verifiable without the owner's GitHub session. Last observed: selected repositories, user `samarth-khera` |
| Safe Auto-Fix table in production | Migration `20261030180000_add_safe_autofix_setting` still pending (§14.6) |
| Scan quota | Not checked yet. It is keyed by a secret-derived client hash, so it will be checked immediately before the single scan |

### 15.2 Phase 2: disposable repository

- **Repository:** https://github.com/samarth-khera/vibeshield-e2e-lab
  - **Visibility:** public
  - **Immutable ID:** `1440088658`
  - **Default branch:** `main`
  - **Size:** 7 files, about 35 KB
- **Commits:**
  - `8821a3e97f46c1706aa0fc23551495730b06c012`: the initial fixture.
  - `904bc7ea48639bede3e038b7100f79c13260f659` (tip; the commit the scan will use): removes two
    scanner cache files that the local scanner run had written into the fixture before the first
    commit. They held only an empty log and a random Semgrep install ID. The fix is a normal commit;
    no history rewrite, no force-push.
- **Manifests:**
  - `express ~5.2.1` → 5.2.1, which declares `proxy-addr ^2.0.7` → **proxy-addr 2.0.7**.
  - `minimatch ^3.1.5` → 3.1.5, which declares `brace-expansion ^1.1.7` → **brace-expansion 1.1.17**.
  - The lockfile was generated by npm 10.9.3 (lockfileVersion 3, 72 packages, no `overrides`) and
    `npm ci --ignore-scripts` plus `npm ls --all` are clean. The two in-range versions were selected
    with npm's own `overrides`, which were then removed; npm keeps the recorded versions.
- **Advisories (OSV, 2026-10-30):**
  - `proxy-addr@2.0.7`: **GHSA-jqcg-44mw-7w3h** (CVE-2026-90711), fixed in 2.0.8.
  - `brace-expansion@1.1.17`: **GHSA-rgw5-rvv9-x895** (fixed 1.1.18), **GHSA-6j4f-fj2g-mc7p**
    (1.1.19), **GHSA-qhr7-859c-m2p7** (1.1.20) and **GHSA-q2hr-2g5m-vwhr** (1.1.21).
  - The parents have no advisories (`express@5.2.1`, `minimatch@3.1.5`: none).
- **Planted scanner fixtures:**
  - `fixtures/insecure/eval-example.js`: never imported or executed.
  - `fixtures/secrets/fake-canary.env`: a random synthetic value, not a credential.
  - The README documents every planted finding.
- **Local real-scanner check** (the production engine, 2.4 s): Gitleaks, Semgrep and OSV-Scanner all
  `completed`, with 7 findings:
  - Gitleaks: `generic-api-key` on the canary.
  - Semgrep: `js-code-execution-eval` on the eval fixture.
  - OSV-Scanner: the five advisories above.
- **Engine eligibility, proved locally** (live registry, real scanners):

| Fix | Classification | npm equality | Verification (plain `git apply` + full rescan) |
|---|---|---|---|
| proxy-addr 2.0.7 → 2.0.8 (lockfile only) | **safe** | identical to `npm update proxy-addr` | verified: 3/3 scanners completed, 1/1 resolved, 0 regressions, findings 7 → 6 |
| brace-expansion 1.1.17 → 1.1.21 (lockfile only) | **safe**, targets all 4 advisories | identical to `npm update brace-expansion` | verified: 3/3 completed, 4/4 resolved, 0 regressions, 7 → 3 |

These are two independent safe fixes: proxy-addr is planned for Review and Approve (Phase 6) and
brace-expansion for Safe Auto-Fix (Phase 9).

### 15.3 Defect fixed while preparing: OSV fixed versions (`a4a6467`)

- **The bug:** the OSV parser recorded the advisory's first `fixed` event. For multi-line advisories,
  that is often another release line. For example, brace-expansion@1.1.17 was reported as fixed in
  5.0.10/5.0.11/5.0.12, which made Auto-Fix under-target or refuse fixes.
- **The fix:** it now records the fix of the range containing the installed version, with the old
  behaviour only as a fallback.
- **Tests:** `osv-fixed-version` (real OSV range shapes). Full suite 510 passed / 21 skipped; real
  scanners 63/63.
- **Deployed:** `dpl_8C2WuqQLDPmDHoT9TSVgddqGhP4T`, healthy.

### 15.4 Phase 5: AI explanations, mocked provider only (live Gemini NOT tested)

`ai-analyst`, `ai-latency` and `gemini-migration`: **56 passed, 1 skipped**, run with a guard that
blocks every outbound network connection. They cover:
- the request lifecycle and structured-schema validation;
- markdown-fenced, malformed and truncated JSON;
- provider timeout, offline service and API errors;
- quota exhaustion (never retried) and the circuit breaker;
- evidence redaction and prompt-injection-as-data;
- caching and cache invalidation on evidence or model change;
- per-IP and global caps.

Live Gemini behaviour was not tested, to preserve the free-tier quota.

### 15.5 What unblocks the remaining phases (owner actions)

1. **GitHub App permission (required for Phase 3).**
   - GitHub → Settings → Developer settings → GitHub Apps → **VibeShield AI** → Permissions & events
     → Repository permissions → **GitHub App installation repository access → Read and write**.
     Change nothing else, and save.
   - Accept the updated permissions on installation `176245393`
     (https://github.com/settings/installations/176245393), keeping **Only select repositories**.
2. **Safe Auto-Fix table (required for Phase 9).** Apply the pending additive migration (§14.7, step 1).
3. **A visible browser session for the production UI.** Signing in to GitHub must be done by you, in
   a Chrome window I open (as in §6), because only that browser can own the scan and approve fixes.
   Then: authorize `vibeshield-e2e-lab` in the Repository Access card; submit the single scan;
   Review and Approve for proxy-addr (real PR, read back, duplicate check, never merged); Safe
   Auto-Fix for brace-expansion; then turn Safe Auto-Fix off.

