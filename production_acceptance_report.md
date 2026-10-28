# VibeShield AI — GitHub PR Integration, Multi-Repository E2E Audit & Limits Report

**Date:** 2026-10-28 · **Starting HEAD:** `03d62fb` · **Feature commit:** `197cd59` (deployed and confirmed, §F) · **Report commit:** the one that adds this file
**Production:** https://vibeshield-ai-phi.vercel.app

Earlier reports are in git history (`git show 03d62fb:production_acceptance_report.md`). Every number here comes from a production API response, an Actions run, a GitHub API read, or a command I ran in this session. **Local** means the app ran on my machine against a disposable Postgres container and real GitHub. **Production** means the deployed site.

---

## A. GitHub PR integration

### Root cause of "GitHub write authorization is not configured"

1. **No credential in production.** The Vercel production variable names (read with `vercel env ls`, values never read) include neither `GITHUB_WRITE_TOKEN` nor `GITHUB_TOKEN`. `createRemediationPullRequest` returned that message whenever both were empty.
2. **The PR flow could never have worked, even with a token.** It created `vibeshield/fixes/<scan>` pointing at the scanned commit, but **never committed the patch**. The PR would therefore have had zero commits: GitHub returns 422, and the code reported a generic failure.
3. **Unsafe credential handling.** The route accepted a GitHub token from the client's `Authorization` header. It also fell back to `GITHUB_TOKEN`, the read token used for archive downloads.
4. **Weak gates.** The code only checked `approvedAt`, so a patch that failed or needed review could be opened as a PR. All remediations of one scan shared a single branch.
5. **UI.** The panel offered the button for every rescanned fix and showed the server message as plain text. After a reload it forgot the remediation completely (the drawer never passed it in) and offered a fresh preview.

### Fix (`197cd59`)

**Authorization model.** This is an owner-operated deployment with anonymous users, so a single global credential must not be able to write wherever its owner can. The new model has two parts:
- **Credential:** server-only `GITHUB_WRITE_TOKEN`, the name the code already used. There is no fallback to `GITHUB_TOKEN` or `GITHUB_DISPATCH_TOKEN`, and the client cannot supply a token.
- **Allowlist:** new `GITHUB_PR_REPOSITORIES` (`owner/repo,owner/repo`). PR creation is disabled for any repository not listed, and entirely when the list is empty.

The client sends only the scan and remediation IDs. Repository, commit, branch and diff all come from the stored scan.

A per-user GitHub App would be the right model if users should open PRs in their own repositories. That is a larger change and was not introduced.

**Minimum permissions** for a fine-grained PAT (or GitHub App), limited to the allowlisted repositories:
- Metadata: read
- Contents: read and write
- Pull requests: read and write

**Gates checked before any GitHub call:**
- status and rescan status are both `verified`
- `approvedAt` is set
- the remediation commit equals the job's 40-hex commit
- the SHA-256 of the diff equals the digest recorded at approval (new)

**Flow (`remediation/github-pr.ts`):**
1. `GET /repos/{o}/{r}`: the full name must equal the scanned repository (catches rename or transfer), and the repository must not be archived or `push:false`.
2. Read the scanned commit and walk its trees to each affected file. Only regular blobs (100644/100755) of valid UTF-8 are accepted; symlinks and submodules are refused.
3. Apply the diff strictly in memory (`strict-apply.ts`): every context or removed line must match at its stated position, as `git apply` requires during verification. Any mismatch is reported as `patch_conflict`.
4. `POST /git/trees` (with base tree), `/git/commits` (parent = scanned commit) and `/git/refs` for `vibeshield/fix-<job>-<remediation>`.
5. Look for an existing PR on that branch in any state. If there is none, open one against the repository's default branch. The PR body covers the finding, files, reason, all three scanner statuses, before/after counts, the verification run link, and the limitation that the repository's own tests were not run.

**Idempotency.** Trees are content-addressed, so a retry finds its own branch, confirms it has the same tree and parent, and reuses it. A different tree is reported as `branch_conflict` and the branch is left untouched. A concurrent double click is resolved by the 422 race on the ref or PR. Repeats within 15 s return the stored outcome without calling GitHub, so the credential's rate limit can't be burned. Nothing is force-pushed, the default branch is never written, and nothing is merged.

**Errors** map to distinct codes, never to success:

| Code | HTTP |
|---|---|
| `not_configured` | 503 |
| `repository_not_allowed` | 403 |
| `credential_invalid` (GitHub 401) | 502 |
| `access_denied` | 403 |
| `repository_not_found` | 404 |
| `rate_limited` | 429 |
| `commit_not_found`, `patch_conflict`, `branch_conflict`, `repository_mismatch` | 409 |
| `unsafe_target` | 422 |
| `network_error`, `github_error` | 502 |

Each outcome is stored in `approvedOperations.pullRequest`. `branchName` and `pullRequestUrl` are set only on success.

**UI (`pull-request-section.tsx`)** has separate states:
- GitHub authorization required
- repository not authorized
- not verified (no PR offered)
- creating (branch, then commit, then PR)
- created #N (with link)
- already exists #N (open, closed or merged)
- failed with the real reason, plus Retry

The panel restores the latest remediation for its finding after a reload. The `.patch` download is always available.

### Are production credentials configured? **No: BLOCKED.**

Production correctly reports `503 not_configured`. This is from the browser run, remediation `a94d503d`:
- The PR section shows "GitHub authorization required".
- There is no PR button and `pullRequestUrl: null`.
- The patch download works.

I did **not** copy my local `gh` session token into Vercel. It is a classic token with broad `repo` scope, and creating or installing production credentials is the owner's decision.

**To enable PRs in production:**
1. Create a fine-grained PAT, limited to the chosen repositories (for example `samarth-khera/FraudAi`), with the permissions above.
2. In Vercel → Project `vibeshield-ai` → Settings → Environment Variables (Production), add:
   - `GITHUB_WRITE_TOKEN` (sensitive)
   - `GITHUB_PR_REPOSITORIES=samarth-khera/FraudAi`
3. Redeploy.

### Real PR evidence (local app, real GitHub, owner's repository)

The local app ran from `197cd59` with a server-side credential from the existing `gh` session (never printed) and the allowlist `samarth-khera/fraudai`. Clicks were made in visible Chrome.

| Check | Result |
|---|---|
| PR | **https://github.com/samarth-khera/FraudAi/pull/10**: open, not merged, not a draft, 1 commit, 1 changed file |
| Branch / head | `vibeshield/fix-0tlmfilavi-3daa6a28d1` → `main`, head `cc992972ecb6`, **only parent `69581cd`** (the scanned commit) |
| Content | GitHub's commit API shows exactly `-pytest>=8.0` / `+pytest==9.0.3` in `backend/requirements.txt`. This is the diff verified by the rescan (Gitleaks, Semgrep and OSV all completed; 8 → 6 findings; 0 new). |
| Default branch | `main` still at `69581cd` afterwards |
| Click → created | HTTP 201 in 7.05 s; UI "Pull request #10 created", with branch, commit and link |
| Duplicate protection | Immediate repeat returned the stored result. After the 15 s window, a re-check returned `200 exists #10 (open)`. GitHub shows exactly **one** PR for the branch. |
| After reload | "Pull request #10 already exists (open)" with link; 0 console errors |
| Credential failure (controlled) | Server restarted with a deliberately invalid token. A second verified fix (`ml/requirements.txt`) got a **real GitHub 401**: HTTP 502 `credential_invalid`, UI "Creation failed — GitHub credential rejected" with Retry, persisted after reload. No branch was created (GitHub returns 404 for `vibeshield/fix-0tlmfilavi-2f6d30bea8`). |
| Approval gate | Both apply and PR before approval returned `403 approval_required` |
| `.patch` download | 200 `text/x-diff`, byte-identical to the reviewed diff |

PR #10 is left **open and unmerged** so it can be inspected. It is a genuine verified fix; close it or merge it as you see fit. FraudAi's pre-existing branches (`main`, `v2-rebuild`) and PRs #5–#9 were not touched.

---

## B. Multi-repository testing

| Repository | Where | Commit | Job | Scanners (status, ms) | Findings | Submit → complete | Features exercised |
|---|---|---|---|---|---|---|---|
| samarth-khera/FraudAi (Python/ML) | Production, GitHub Actions | `69581cd` | `3w3loa7G…` | Gitleaks 738 · Semgrep 2740 · OSV 1039, all `completed` | 8 (OSV: pytest, scikit-learn) | 51.0 s | form submit, queue, progressive partial results, finding drawer, AI explain (uncached + cached), Auto-Fix preview → reject unapproved → approve → verify, PR state, patch download, mobile width |
| samarth-khera/VibeShieldAi (TS/Next.js) | Production, GitHub Actions | `197cd59` | `CpTsMRQc…` | 386 · 1532 · 1106, all `completed` | 0 | 37.1 s | concurrent scan, clean-report path |
| pallets/itsdangerous (third-party, **read-only**) | Production, GitHub Actions | `672971d` | `ecvVKL6D…` | 420 · 1451 · 2513, all `completed` | 85 | 70.7 s (42.8 s of it queued) | queue position "#1 in line" while both slots were busy |
| samarth-khera/FraudAi | Local, warm worker | `69581cd` | 5 runs | all `completed` every run | 8 | p50 6.4 s | real PR, duplicate and credential-failure cases |
| samarth-khera/VibeShieldAi | Local, warm worker | `03d62fb` | 3 runs | all `completed` | 0 | p50 6.2 s | |
| samarth-khera/Tic-Tac-Toe | Local, warm worker | `5875fb5` | 5 runs | all `completed` | 0 | p50 4.6 s | benign repository with no findings |

Nothing was written to `pallets/itsdangerous`.

---

## C. Feature acceptance matrix

| Feature | Status | Evidence |
|---|---|---|
| URL validation, SSRF, traversal | **PASS** | Production: 12 bad inputs all rejected with no job created. Malformed → 400 `invalid_url`; gitlab and `github.com.evil.com` → `unsupported_host`; `http://169.254.169.254` → `unsupported_protocol`; `../` paths and credentials in URL → `invalid_url`; owner-only URL and SSH form rejected; nonexistent repo → `not_found_or_private`; `text/plain` → 415. *Fixed after the run:* the nonexistent-repo message was a raw code string; it now returns the public sentence (report commit). |
| Private repositories | **PASS (by design)** | Rejected as `not_found_or_private`; only public repositories are supported |
| Scanner execution, all three | **PASS** | 3 production and 13 local scans, every scanner `completed`. Fail-closed wrappers covered by `npm run test:scanners` (61/61 with real binaries). |
| Progressive results, partial labelling | **PASS** | Production FraudAi: 8 findings shown under "PARTIAL — SCAN STILL RUNNING" with chips "Gitleaks completed 738ms · Semgrep running · OSV completed" before the final report |
| Queue, concurrency cap 2, queue position | **PASS** | Third concurrent production scan showed "All worker slots are busy — your scan is accepted and #1 in line", waited 42.8 s, then completed. Postgres race tests 14/14. |
| Queue full, quotas, abuse | **PASS (tests)** | `queue_full`, hourly, daily and global limits asserted at the new defaults. Not triggered in production, to avoid burning the shared daily cap. |
| Stale-job reaping, leases, heartbeats | **PASS (Postgres tests)** | `postgres-worker.test.ts` (lease expiry re-queue, stale lease 409, replay rejection) |
| Archive cache | **PASS (local)** | Warm worker: miss on each repository's first scan, hit afterwards, keyed by the immutable commit |
| Finding details and advisory links | **PASS** | Drawer shows scanner, rule, dependency and CVE link (screenshots) |
| Search / filter UI | **NOT TESTED** this round in the browser (covered by `findings-api.test.ts`) | |
| AI explanation | **PASS** | Production `gemini-2.5-flash`: uncached 3.18 s click → response (+31 ms render), cached 0.39 s, renders from stored cache after reload. Malformed, truncated and schema-invalid output not cached (`ai-latency.test.ts`). |
| Auto-Fix eligibility categories | **PASS (tests)**, **partial live** | Live: dependency bumps classified `potentially_breaking`. Secret rotation, unsuitable and safe categories covered by `remediation.test.ts`. |
| Patch preview = download | **PASS** | Byte-identical in production and locally |
| Unapproved apply rejected | **PASS** | 403 `approval_required` (production and local) |
| Real full-snapshot verification | **PASS** | Production run `40685693063`: 182-file snapshot of `69581cd`, all scanners completed, 8 → 6, 0 new, `verified`, 32.1 s click → result |
| Failed and unavailable verification fails closed | **PASS (tests)** | `autofix-production.test.ts`, `remediation.test.ts` |
| **GitHub PR creation** | **PASS locally against real GitHub; BLOCKED in production** | PR #10 above. Production has no `GITHUB_WRITE_TOKEN` and correctly returns 503 `not_configured`. |
| PR duplicate protection and retry | **PASS** | Live: one PR after repeat and re-check. Tests: concurrent double click → one branch, commit and PR; closed PR not duplicated. |
| PR permission and credential errors | **PASS** | Live GitHub 401 → `credential_invalid`. Tests: 403 write → `access_denied`, rate limit, network, 404, renamed repo, symlink, patch conflict, branch conflict. |
| Turnstile | **NOT CONFIGURED (pre-existing)** | No `TURNSTILE_*` variables in Vercel and no widget script on the page. Unchanged. |
| Mobile width | **PASS** | 390 px screenshot of the PR section, no layout break |
| Console / network errors | **PASS** | Final production pass: 0 console errors, 0 failed requests. The only 4xx/5xx in the other runs were the deliberate negative tests. |

---

## D. Performance

| Measurement | Before | After | Sample / state |
|---|---|---|---|
| Production scan submit → complete (FraudAi `69581cd`) | 25.9 s warm cache, 65.2 s cold (previous round) | 51.0 s, of which 36.5 s was runner setup | n=1 each, GitHub Actions. Setup varies with Actions cache restore, and this run was slower than the previous best. **No production speed-up is claimed.** |
| Production scanners (FraudAi) | Gitleaks 395, Semgrep 1711, OSV 708 ms | 738, 2740, 1039 ms | n=1, run-to-run noise |
| Local warm worker submit → complete, 13 scans | — | **p50 5.7 s, p95 7.1 s** (accept p50 0.68 s; pickup p50 2.6 s, up to 3.9 s because idle polling is 5 s) | Docker linux/arm64 on a Mac, local DB. **Not deployed:** no free Linux host was available to me. |
| AI explain (production) | 3.38 s uncached, 0.32 s cached | 3.18 s uncached, 0.39 s cached | n=1 each, same model, no code change this round |
| Auto-Fix verification (production) | 30.7 s | 32.1 s click → verified (worker: queue 22.5 s, scan 3.0 s, total 3.8 s) | n=1 |
| Auto-Fix verification (local warm worker) | — | 8.0 s click → verified (worker total 1.7 s, archive cache hit) | n=2 |
| PR creation (local, real GitHub) | never succeeded | 7.05 s click → created | n=1 |
| UI update lag | — | 0.5–1 s in the focused window. A background window updated up to 64 s late, because hidden tabs poll every 30 s by design. | Observed during the 3-window concurrent run |

---

## E. Limits

| Limit | Old | New | Reason / capacity check |
|---|---|---|---|
| Scans per IP per hour (`MAX_SCANS_PER_IP_HOURLY`) | 3 | **6** | Execution stays capped at 2. Public-repo Actions runners are free. |
| Scans per IP per day | 5 | **10** | Same |
| Global scans per day | 20 | **40** | About 40 × (1 workflow + ~60 polls/callbacks) ≈ 2.4k Vercel invocations/day, small against the Hobby allowance. Neon free compute impact is small, but it is an **assumption**: I could not see Neon usage. |
| Waiting queue (`MAX_QUEUED_SCANS`) | 10 | **20** | A waiting job is one row with no runner; the 30-min queue timeout still applies |
| AI per IP per hour / day | 5 / 15 | **8 / 25** | Cache hits never count |
| Heavy-job concurrency | 2 | **2 (kept)** | Shared by scans and verifications; no measured headroom for more on the Actions path |
| Global AI per day | 50 | **50 (kept)** | Guards the Gemini free-tier quota, which I could not inspect |
| Archive 25 MB, unpacked 200 MB, 10k files, 15-min job timeout, diff 50 KB / 5 files | — | **kept** | These bound worker disk, time and patch review size |

Each value is changed in one place (`config.ts`), plus the matching defaults in `ai/circuit-breaker.ts` and `docs/gemini-setup.md`; no hidden smaller cap remains. A regression test asserts the new defaults and the rejection just past each one. Enforcement is still the atomic Postgres advisory lock.

---

## F. Quality and deployment

| Check | Result |
|---|---|
| `npx vitest run` | **25 files: 23 passed, 2 skipped. 309 tests: 294 passed, 15 skipped, 0 failed.** The skipped tests are the Postgres, real-scanner and live-Gemini suites, run separately below. Live Gemini was **not** run locally (no key); production AI was exercised through the app. |
| `npm run test:postgres` (disposable Postgres 16) | 14/14 passed |
| `npm run test:scanners` (real Gitleaks 8.30.1, Semgrep 1.182.0, OSV 2.7.0) | 61/61 passed |
| New tests | `github-pr.test.ts` (22, against a modelled Git Data/Pulls API), `pull-request-ui.test.tsx` (4), default-limits test |
| `tsc --noEmit`, `eslint .`, `next build` | clean, clean, success |
| Gitleaks `git` | no leaks |
| Gitleaks `dir` | 16 hits, all in untracked, ignored files (`.next` build output, `.env`, `.env.local`); 0 in tracked files |
| Semgrep `p/default` | 0 (the 5 mutable action-tag findings were fixed by pinning workflow actions to commit SHAs) |
| OSV-Scanner | `package-lock.json`: 0. `.github/scanner-requirements.txt` (Semgrep's pinned Python toolchain on the Actions runner): 6 packages with advisories (anyio, certifi, idna, mcp, opentelemetry-api, python-multipart). These are pre-existing transitive pins of Semgrep 1.182.0, not app runtime. **Not changed**, because re-pinning needs a Semgrep upgrade and re-verified checksums. Follow-up item. |
| Pushed | `03d62fb..197cd59` fast-forward to `main`; remote `main` = `197cd59` |
| Vercel | Deployment `dpl_3tdhNUKKBV29Vriar5E2KKttZZXk`, `githubCommitSha 197cd595e56b`, READY, aliased to `vibeshield-ai-phi.vercel.app` |
| Actions | Scan runs `40685016193`, `40685016122`, `40685097070` and verify run `40685693063`: all success on the deployed code |
| `/api/health` | `healthy`, database healthy, dispatcher ready, `warmWorker: disabled` (fallback github-actions) |
| Paid services | None added. The warm worker is optional and off. |

---

## G. Remaining blockers and follow-ups

1. **BLOCKED: production PR creation.** No `GITHUB_WRITE_TOKEN` or `GITHUB_PR_REPOSITORIES` in Vercel. Setup is in §A. Until then production truthfully shows "GitHub authorization required" and offers the verified `.patch`.
2. **Warm worker not deployed.** No free-tier Linux host or cloud credentials were available. To enable it:
   - apply migration `20261028050000_add_worker_heartbeat`
   - set `WARM_WORKER_ENABLED` and `WARM_WORKER_SECRET`
   - run the hardened container per `deploy/warm-worker/README.md`

   Until then GitHub Actions remains the executor, and its runner setup (≈22–37 s) dominates scan time.
3. **Turnstile is not configured** (pre-existing). Recommended before wider exposure, especially with the raised quotas.
4. **Semgrep toolchain advisories** in `.github/scanner-requirements.txt` (see §F).
5. The scikit-learn bump to `==1.5.0` replaces a `>=1.4` floor with a pin. It is flagged "potentially breaking" and needs human review. Verification runs the security scanners, not the project's own tests; the PR body says so.

**Verified facts vs assumptions:** everything in §A–§F is measured or read directly. The only assumptions are the Vercel and Neon free-tier headroom estimates in §E, which I could not observe because I had no dashboard access.
