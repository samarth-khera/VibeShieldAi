# VibeShield AI — Production Performance, Auto-Fix Reliability & Queue Report

**Date:** 2026-10-28 · **Starting HEAD:** `878c1f6` · **Deployed code:** `a0744ef` → `72e3b3d` (plus this report and a polling tweak, see §9)
**Production:** https://vibeshield-ai-phi.vercel.app · **Scope:** Phases 0–8 of the performance/Auto-Fix/queue roadmap.

The previous round's report is in git history (`git show 878c1f6:production_acceptance_report.md`).

Every number below comes from a production API response, a GitHub Actions job log, or a local command run during this session. Nothing was estimated.

---

## 1. Root causes reproduced

| # | Problem | How it was reproduced | Impact |
|---|---|---|---|
| 1 | **Every scan since `878c1f6` failed before the worker ran.** `setup-python` with `cache: pip` errored: *"No file … matched to [\*\*/requirements.txt or \*\*/pyproject.toml]"*. | Actions run `40555155653` log. | No callback was sent, so the job stayed `queued`. With a cap of 1 it also blocked every other user for the 15-minute stale window. This is the main "very slow / stuck" report. |
| 2 | **Gitleaks never scanned anything in production.** The pinned v8.18.2 has no `dir` subcommand (*"unknown command "dir""*, exit 1). The wrapper allowed exit 1 and treated empty output as "no leaks". | Ran the real 8.18.2 binary; production job showed Gitleaks `completed` in **6 ms**. | Secret scanning was silently off. Local tests passed only because Homebrew has 8.30.1. |
| 3 | **Production Auto-Fix "verification" was fake.** `getRemediationDeps()` provided no source snapshot, so the sandbox wrote `// source file placeholder`, applied the diff to it with a context-blind fallback, and ran scanners that do not exist on Vercel. | Production preview → approve → apply on the FraudAi scan: returned in **0.50 s** with `rescanStatus: failed` but `targetResolved: true` and a "resolved" fingerprint. | Users were shown a resolution that never ran. |
| 4 | **Queue replacement and cap bypass.** One global workflow concurrency group keeps only one pending run and cancels older pending runs. `retry` and `scan` (rescan) dispatched without any quota check. "Active" was measured by `createdAt`, so a retried old job didn't count. | Code inspection, then proven with the live-Postgres tests in §6. | Pending jobs could be stranded; the cap could be exceeded. |
| 5 | **Scanner caches did nothing useful.** Binaries were cached under root-owned `/usr/local/bin`. The OSV "pre-cache" step failed on every run (*"databases can only be downloaded when running in offline mode"*), and the scan used online mode anyway. | Run `40320526931` log. | ~37 s of setup on every run (Semgrep pip ≈10 s, `npm ci` 19 s). Actual scanning was ≈5 s. |
| 6 | **AI latency.** Gemini 2.5 Flash thinks by default, and thinking tokens share `maxOutputTokens`. The provider's `Promise.race` timer was never cleared, the SDK request was never aborted, a second SDK-level timeout also applied, and retries got a fresh full timeout. The prompt repeated the JSON schema already sent as `responseJsonSchema`. The finding was read from the DB twice. | Code inspection plus production timings in §2. | 5–6.4 s per uncached explanation. |
| 7 | **Report page crash (found during this round's browser run).** Worker heartbeats store only `progress` in `scanCoverage` mid-scan, and the coverage block dereferenced `lockfilesFound.length`. | Visible-Chrome production run showed *"This page couldn't load"*. A jsdom test reproduces the same `TypeError`. | Fixed in `72e3b3d` before any user exposure beyond this test. |
| 8 | **Misleading "resolved" after a version bump (found by real-scanner test).** OSV fingerprints include the package version and Semgrep/Gitleaks include the line. Any bump therefore made the old fingerprint disappear and counted as "resolved". | Real OSV-Scanner: bumping pytest 7.1.0 → 7.1.1 (still vulnerable) reported `targetResolved: true`. | Fixed with identity-based comparison (§3). |

---

## 2. Baseline vs final timings (real measurements)

### Scan: same repository (`samarth-khera/FraudAi`) and commit (`69581cd`)

| Stage | Baseline (run `40320526931`, job `bFYrWsEe…`) | Final, cache miss (run `40629764092`) | Final, cache hit (run `40630758400`) |
|---|---|---|---|
| Submit → runner start (queue) | ≈4 s (job created 12:10:41 → started 12:10:43; submit 12:10:38.2) | 7.0 s | 7.2 s |
| Runner setup (start → worker retrieving) | ≈37 s (install 13 s + `npm ci` 19 s + Node 2 s + Prisma 1 s + misc) | 52.6 s (cold: Semgrep venv 22.8 s, `npm ci` 19 s) | 14.2 s |
| Metadata + download | not logged separately | 396 + 363 ms | 374 + 389 ms |
| Extraction | not logged separately | 243 ms | 237 ms |
| Scanning (parallel) | Gitleaks 6 ms (**not scanning**), Semgrep 2779 ms, OSV 699 ms | Gitleaks 659 ms, Semgrep 2590 ms, OSV 678 ms (4041 ms total) | Gitleaks 395 ms, Semgrep 1711 ms, OSV 708 ms (2691 ms total) |
| Callback | not logged | 205 ms | 147 ms |
| **Submit → completed** | **49.3 s** | 65.2 s (one-time cold cache) | **25.9 s** |
| Actions job duration | 46 s | 73 s | 23 s |

Gitleaks timings are not comparable: 6 ms was an error exit, not a scan.

### AI explanation (production, `gemini-2.5-flash`, uncached, same scan data)

| Sample | Before | After |
|---|---|---|
| FraudAi pytest advisory, backend | 6.40 s (`PYSEC-2026-1845`, curl) | 3.38 s (`GHSA-6w46-j5rx-g56g`, visible Chrome click → API response; render +27 ms) |
| scikit-learn `PYSEC-2024-110`, backend | 5.09 s (curl) | 3.42 s (curl) |
| Output size | 1972 / 2082 chars | 1743 / 1879 chars (all schema fields present) |
| Repeat request (cache) | 0.51 s, `cached: true` | 0.32 s, `cached: true`; after reload it renders from the stored explanation with no button and no model call |

Model output-token counts are now logged per request (`ai_inference` event: prompt, output, and thinking tokens, finish reason). I did not have access to Vercel logs, so token counts are **not reported** here.

### Auto-Fix (production)

| Step | Before | After |
|---|---|---|
| Preview (source fetch + eligibility + diff) | 1.09 s | 0.93 s (repeat previews of the same file/commit now hit an immutable per-commit cache; covered by test, not measured in prod) |
| Apply | 0.50 s, **nothing verified** | 1.41 s to dispatch (`202 applied`); **30.7 s** click → `verified` recorded server-side |
| Worker breakdown (run `40630570111`, cache hit) | — | spec fetch 337 ms · download 487 ms · extract 444 ms · apply 7 ms · scan 3538 ms (Gitleaks 682, Semgrep 2365, OSV 762) · total 4.8 s; dispatch → worker 25.5 s (runner queue + setup) |
| UI shows result | — | 80.9 s after click in the automated window. The result existed at 30.7 s, so the UI noticed ~50 s late. The likely cause is Chrome treating the automated window as hidden (30 s polling), but this is **unconfirmed**: the automated browser became unreliable before I could check. Verification polling is now capped at 5 s for a visible tab. |

---

## 3. What changed

**Auto-Fix verification (P0)**
- `remediation/verify.ts` (new): rebuilds the full repository at the immutable `job.commitSha` using the existing bounded `openArchive` + `extractArchiveSafely`. Branch names are refused (`commit_unknown`), and nothing is downloaded in that case.
- `remediation/sandbox.ts`: no placeholders and no context-blind fallback. The flow is `git apply --unidiff-zero --check`, then apply. The patch lives outside the scanned tree. The result is `failed` with an explicit `reason` for each of these: `source_snapshot_unavailable`, `patch_target_missing`, `patch_does_not_apply`, `patch_tool_unavailable`, `scanner_failed`. A result is `verified` only when every scanner reports `completed`, every targeted identity is gone, and no identity occurs more often than before. Identity is (scanner, rule, file, and package name for OSV), which fixes root cause 8.
- `remediation/service.ts` and `deps.ts`: with the GitHub Actions backend, `applyAndVerify` reserves a worker slot, moves `approved → applied`, and dispatches a `verify` workflow run. Only identifiers travel as workflow inputs. On dispatch failure the slot is released and the API returns 503. Without that backend, verification runs locally against a rebuilt snapshot, never against injected files. Approval is limited to `preview|failed → approved`.
- New worker endpoints, `GET|POST /api/scans/:id/remediation/:rid/verification`. The worker fetches the approved diff with an HMAC over a canonical string, so a signature can't be reused for another remediation. It posts a signed result. The server re-checks scanner statuses, snapshot commit, target, and regressions before accepting `verified`, accepts one result only, and ignores replays.
- Preview requires a 40-hex scan commit (the `"main"` fallback is gone). Source comes from `remediation/source-cache.ts`: keyed by owner/repo/commit/path, 10-minute TTL, 64 entries / 4 MB, in-flight requests deduplicated.
- Human approval is still mandatory. Nothing pushes to, branches, or opens PRs on the scanned repository: FraudAi HEAD was `69581cd` before and after, and its branches were unchanged.

**Queue and concurrency (P0/P1)**
- `quota.ts` (new, no DB import) holds the shared `evaluateQuota` and `countActiveHeavyWork` (scans + in-flight verifications, measured by `updatedAt`).
- `db.ts` `withHeavySlotLock` takes `pg_advisory_xact_lock`, reaps stale work (sanitized `worker_timeout` / `verification_timeout`), and counts slots. New scans (`createWithQuota`), retries and rescans (`requeueWithQuota`), and verifications (`beginRemediationVerification`) all use it. Hourly, daily, global daily, and AI quotas are unchanged.
- Workflow concurrency is per job and remediation (`vibeshield-<mode>-<job>-<remediation>`), so pending runs can no longer replace each other. I didn't use `queue: max`, because it was not needed and would not add throughput.
- `MAX_CONCURRENT_HEAVY_SCANS` default raised 1 → **2**. Basis: free standard runners for a public repo, a 20-concurrent-job account limit, and the race-safety proof in §6. Rejections are explicit 429s (*"All 2 free-tier scan worker slots are busy, so this request was not queued"*) with `Retry-After: 60`. Nothing is accepted and then dropped.
- `startScan` refuses jobs that are already queued or running, so the same job can't be dispatched twice. `getScan` and the remediation list fail stale work explicitly instead of showing "queued" forever.
- Worker heartbeats (`worker_started`, `retrieving`, `extracting`, `scanning`) are signed and forward-only, and are kept in the final `scanCoverage.progress`. A dependency-free `scripts/ci/post-worker-status.mjs` reports "started" before `npm ci`, and an `if: failure() || cancelled()` step reports failures. Root cause 1 can no longer strand a job.

**Scanner workflow and caches (P1)**
- Tools live in `~/.vibeshield/{bin,semgrep-venv}` and are added to `PATH`. The cache key covers OS, arch, exact Python build, tool versions, and installer hash. `scripts/ci/install-scanners.sh` checks pinned SHA-256s (tarball and binary) on every run, both fresh and restored, and reinstalls on mismatch. It prints `CACHE_STATUS` and `TIMING` lines.
- Gitleaks is now **8.30.1**, pinned to the official checksums. All three wrappers fail closed on empty or invalid output, and Gitleaks on any non-zero exit.
- Semgrep is pinned to 1.182.0 in `.github/scanner-requirements.txt`, used for both `cache-dependency-path` and the venv.
- `node_modules` is cached under a key of lockfile hash + Node 22 + OS/arch. On a miss it runs `npm ci --ignore-scripts`: no third-party install scripts, and no Prisma (the worker never imports it, verified by loading the worker graph without a generated client). The separate Prisma step is removed.
- OSV: the broken pre-cache and the unused DB cache are removed, and scans stay on the live OSV API (always-current advisories). Locally, offline mode on a PyPI fixture was 1.14 s warm vs 1.95–2.21 s online, but 5.79 s cold. OSV runs in parallel with the slower Semgrep, so it is off the critical path and has no measurable end-to-end gain. No offline-DB speedup is claimed.
- The callback secret is set only on the three steps that need it, never at workflow level or during dependency install. `persist-credentials: false`.

**AI (P1)**: one `AbortController` deadline across attempts, an abort promise even if the SDK ignores the signal, and the timer is always cleared. `thinkingBudget: 0` for `gemini-2.5-flash*` (override with `AI_THINKING_BUDGET`). The system prompt is cut to rules only (no schema). Structured output still uses `responseJsonSchema` plus Zod. No retry on 429, at most one retry on 500/503 inside the same deadline. The explain route passes the finding it already loaded. Correlation ID and category are shown in the UI error and logged. The prompt version was bumped to `2026.10.3`, so old cached explanations regenerate once. No new model or paid fallback.

**UI (P2)**: `useAdaptivePoll` starts at 1.5 s, backs off ×1.5 to 8 s, polls every 30 s while hidden and immediately on refocus, stops at a final state, and clears timers on unmount. Findings load once at a final state. The progress banner shows Queued → Runner started → Retrieving → Extracting → Scanning, with queue wait separate from worker-active time. The completed view lists queue, setup, retrieval, extraction, per-scanner, and callback timings. The Auto-Fix panel polls while `applied` and shows `failed` with a readable reason plus runtime, snapshot, scanner, and timing details and a workflow link.

---

## 4. Queue / concurrency behavior (production)

- **Configured cap:** 2 (default, confirmed live: two simultaneous API submissions both returned 202).
- **Parallel execution:** jobs `vbWddBWx…` (FraudAi) and `FmXhpxEf…` (VibeShieldAi) had runners start at 04:09:57.7 and 04:09:59.6, and completed at 25.9 s and 35.2 s after submit.
- **A third concurrent request was not sent live.** It would have hit the per-IP hourly limit (3/h), not the cap. Cap rejection is proven by the tests in §6 instead.

---

## 5. Real full-repository sandbox verification

Production run `40630570111` (verify mode), remediation `33fe5796…`, finding `GHSA-6w46-j5rx-g56g` (pytest) in `backend/requirements.txt`:

- Diff: `-pytest>=8.0` → `+pytest==9.0.3` at commit `69581cd`.
- Snapshot: 182 files rebuilt from the archive of that commit.
- Scanners: Gitleaks, Semgrep, and OSV all `completed`.
- Findings 8 → 6. Target resolved, 0 new findings, status `verified`.

Unapproved apply was rejected with `403 approval_required`.

---

## 6. Test results (local, this session)

| Command | Result |
|---|---|
| `npx vitest run` (full suite) | **21 files: 20 passed, 1 skipped · 261 tests: 255 passed, 6 skipped, 0 failed.** The 6 skipped are the 5 Postgres tests (no `VIBESHIELD_PG_TEST_URL`) and the live-Gemini test (no `GEMINI_API_KEY`). Both now report as *skipped*; before, they logged `[BLOCKED]` and counted as passed. |
| `REQUIRE_REAL_SCANNERS=1` real-scanner suite (`npm run test:scanners` runs it with the scanner-backed remediation tests) | 3/3 passed with real Gitleaks 8.30.1, Semgrep 1.182.0, and OSV-Scanner 2.7.0 (live OSV API): planted runtime-generated token detected, real dependency fix verified on a full snapshot, still-vulnerable bump not verified. Fails, not skips, if a binary is missing. |
| `VIBESHIELD_PG_TEST_URL=… npm run test:postgres` (disposable `postgres:16-alpine`, real migrations) | 5/5 passed: 12 simultaneous submissions → exactly 2 accepted; 5 verifications + 5 scans racing for the last slot → exactly 1; 4 contended retries with cap 1 → exactly 1; stale job reaped and slot freed; heartbeats forward-only and unsigned rejected. **Negative control:** with the advisory lock removed, the same tests accepted 12/12, 10/10, and 4/4. |
| New mock-boundary tests | `autofix-production.test.ts` (17): production composition dispatches with identifiers only, source fetched at the commit SHA, no injected files or engine, signed-protocol tamper/replay/downgrade cases, timeout reaping, cap shared with verifications. `queue-workflow.test.ts` (16). `ai-latency.test.ts` (7). `report-progress.test.tsx` (2, reproduces the §1 #7 crash without the fix). |
| `npx tsc --noEmit` | clean |
| `npx eslint .` | clean (0 errors, 0 warnings) |
| `npm run build` (Next 16.4.3) | succeeded; the new `/verification` route is dynamic |
| Gitleaks 8.30.1 `git` (history) | no leaks |
| Gitleaks `dir` (working tree) | findings only in untracked, git-ignored `.env`/`.env.local` and in `node_modules`/`.next` |
| Semgrep (`rules/semgrep-rules.yaml`, `src` + `scripts`) | 0 results, 0 errors, 93 files. The previous partial-parse warning in `job-store.ts` was fixed. |
| OSV-Scanner (`package-lock.json`) | 0 vulnerabilities |

Mocked provider and scanner tests are **not** counted as live proof. Live proof is in §2, §4, and §5.

---

## 7. Visible browser evidence

All runs used non-headless Google Chrome via `puppeteer-core` against production, with screenshots kept locally.

1. Scan submitted through the real form, showing *"Queued — waiting for a GitHub Actions runner… · Queue wait 6.8s"*. This run exposed the §1 #7 crash, which was fixed and redeployed.
2. Explain with AI: 3.38 s to response, rendered 27 ms later. Repeat served from cache; after reload it renders from the stored explanation.
3. Mode B preview with the exact manifest diff.
4. Unapproved apply returned 403.
5. Checkbox approval, then "Verify Fix on Full Repository", then *"Verifying on the scanner worker…"*, then *"Fix Verified by Security Rescan"* with runtime, snapshot `69581cd · 182 files`, all scanners completed, and *"8 before · 6 after · 0 new"*.

**Limitation:** progress phases after "Queued" were not captured on screen during the cache-miss scan, because the page crashed (since fixed). The fixed rendering is covered by a jsdom test, and the phases are confirmed in production data (`scanCoverage.progress` timestamps). A later attempt to recheck tab visibility in the automated browser failed (navigation/evaluate timeouts), so the UI polling-lag explanation in §2 remains unconfirmed.

---

## 8. Free-tier posture

There are no paid services, larger runners, or external queues. Standard `ubuntu-latest` runners are free for this public repository, and the cap is 2. Gemini stays `gemini-2.5-flash` on the free tier with zero retries on 429. The DB is still Neon via Prisma, with one advisory-lock transaction per reservation.

---

## 9. Deployment and remaining items

- Pushed to `main` fast-forward only: `a0744ef` (main change), `72e3b3d` (report crash fix), then a final commit with this report and the 5 s verification-poll cap. Vercel deployed each push; the deploy was confirmed live by the new route returning 401 unsigned, and `/api/health` returns `healthy`.
- **Not verified:** Vercel function logs (no Vercel access), so per-request inference and token logs and DB-vs-inference splits were not read in production. A live Gemini call from the local test suite was not run (no key locally; production calls were made through the app instead).
- **Turnstile:** production accepted API scan submissions without a token, so `TURNSTILE_SECRET_KEY` appears to be unset. This is pre-existing and unchanged. Worth configuring.
- **Remaining latency:** on a cache hit, about 7 s is queue (dispatch → runner) and about 14 s is setup (checkout, Python, cache restores, checksum verification). These are GitHub Actions overheads, not app code. Scanning is 2.7–4 s.
- **Data quirk observed (not changed):** OSV reports a git commit as the "fixed version" for scikit-learn `PYSEC-2024-110`. The eligibility logic should not offer that as a version bump; worth a follow-up check.
- If `pytest>=8.0` is meant as a floor, the generated `pytest==9.0.3` pin is stricter than the original specifier. It is still flagged "potentially breaking" for human review.
