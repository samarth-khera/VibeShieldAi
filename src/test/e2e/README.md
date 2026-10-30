# Local UI end-to-end harness (simulated GitHub)

`local-github-preload.mts` lets a **local** production build (`next start`) run the complete Auto-Fix
workflow without touching GitHub or any AI provider: GitHub's API is served in-process by
`FakeGitHubApp`, seeded with a real repository snapshot at its real commit. The npm registry and OSV
are reached for real (public, read-only); every other outbound host is refused. Pull requests it
creates are simulated and link to `simulated-github.local`.

It is never imported by application code. To use it:

1. Bundle it (Next's module loading does not mix with the `tsx` loader):
   `npx esbuild src/test/e2e/local-github-preload.mts --bundle --platform=node --format=esm --outfile=<dir>/preload.mjs --banner:js="import { createRequire as __cr } from 'node:module'; const require = __cr(import.meta.url);"`
2. Seed a local database (`prisma migrate deploy`) with a scan job, its findings and `ScanAccess`,
   plus a `GithubAccount` whose access token is encrypted with the local
   `GITHUB_APP_TOKEN_ENCRYPTION_KEY` and an `AuthSession` linked to it.
3. Start the server with `NODE_OPTIONS="--import <dir>/preload.mjs"`, the GitHub App variables set to
   the fake's values (`GITHUB_APP_CLIENT_ID=Iv1.testclient`, `GITHUB_APP_CLIENT_SECRET=test-client-secret`),
   `GITHUB_TOKEN=` and `GEMINI_API_KEY=` empty, `AI_GEMINI_ENABLED=false`, `SCAN_DISPATCH_BACKEND=bullmq`
   with an empty `REDIS_URL` (verification runs in-process with the real scanners), and the
   `E2E_*` variables read at the top of the preload (`E2E_SIMULATED_GITHUB=1` is required).
4. In the browser, set the session cookie and an owner grant signed with the local
   `SCAN_CALLBACK_SECRET`.
