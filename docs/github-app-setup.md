# GitHub App setup (one-time, operator)

VibeShield opens Auto-Fix pull requests and scans private repositories **only with each user's own
GitHub authorization**. Users connect GitHub themselves and choose which repositories the app may
use. There is no operator token and no list of allowed repositories.

Until the steps below are done, the feature is off. Public scanning, review, AI explanations and
verification all work as before, and the Auto-Fix panel says "GitHub authorization is not
configured yet" and offers the verified `.patch` download.

## How it works

- **Identity.** "Connect GitHub" runs GitHub's user authorization flow for the app. It uses a
  single-use, session-bound `state` and PKCE. The resulting user-to-server token is stored
  AES-256-GCM encrypted. The browser only holds an HttpOnly, `SameSite=Lax`, `__Host-` session cookie.
- **Repository access (in product).** When a user clicks **Authorize repository** in Auto-Fix,
  VibeShield shows the exact repository, its immutable ID, the installation and the requested
  capabilities. Only after the user confirms does it call GitHub's
  `PUT /user/installations/{installation_id}/repositories/{repository_id}` with that user's own
  token. That call adds exactly one repository to the existing installation on the repository
  owner's account; the installation is matched by the owner's immutable account ID. The confirmation is
  single use and bound to the browser session, GitHub user, scan, scanned commit, repository ID
  and installation ID. "Authorized" is shown only after GitHub lists the repository in the
  installation. VibeShield never selects "All repositories" and never removes repositories.
  GitHub requires the user to be an administrator of the repository and the app to hold the
  permission in step 1a. Without them, the user is sent to GitHub's own installation pages, which
  are also used for the first installation on an account and for organization approval requests.
- **Writes.** Branch, commit and PR are created with the requesting user's token. GitHub limits that
  token to repositories that are *both* writable by the user *and* selected in the installation, so
  the app can never grant more than the user personally has. Before every write the server re-checks
  live with GitHub that:
  - the user can push to the repository
  - the repository is in an installation of this app that grants Contents and Pull requests write
  - the repository's immutable ID matches the scanned repository

  Every PR is opened by the user "via" the VibeShield app. It goes on a new branch whose only parent
  is the verified scan commit, and is never merged.
- **Private scans.** These are visible only to the GitHub user who authorized them, and only while
  that user still has access. Workers never receive a user token. They get a short-lived,
  single-archive download URL from a signed endpoint. Workflow inputs carry `private` instead of the
  repository name.

The app private key and installation tokens are **not** used, so they are not needed.

## 1. Register the app

On GitHub, go to **Settings → Developer settings → GitHub Apps → New GitHub App**. For an
organization-owned app, use the organization's settings instead.

| Field | Value |
|---|---|
| GitHub App name | e.g. `VibeShield AI` (its URL slug is used below) |
| Homepage URL | `https://vibeshield-ai-phi.vercel.app` |
| Callback URL | `https://vibeshield-ai-phi.vercel.app/api/auth/github/callback` |
| Expire user authorization tokens | **On** (8-hour tokens plus refresh tokens) |
| Request user authorization (OAuth) during installation | **Off**. The app's own Connect step carries the session-bound state. |
| Enable Device Flow | Off |
| Setup URL | `https://vibeshield-ai-phi.vercel.app/api/auth/github/setup` |
| Redirect on update | On |
| Webhook → Active | **Off**. Access is re-checked live on every request instead. |
| Repository permissions | **Contents: Read and write**, **Pull requests: Read and write**, **GitHub App installation repository access: Read and write** (see 1a), Metadata: Read-only (mandatory). Nothing else. |
| Organization / account permissions | None |
| Where can this GitHub App be installed? | Any account |

The host in both URLs must equal the deployment's `APP_URL`.

After creating the app:
1. Copy the **Client ID** and the **slug** (the last part of `https://github.com/apps/<slug>`).
2. Click **Generate a new client secret** and copy it.

## 1a. Enable in-product repository authorization (one-time)

Without this permission, users must add each new repository on GitHub's installation settings page.
VibeShield reports the state as "One-time GitHub App setup required" and links to that page.

1. In the app's settings (**Settings → Developer settings → GitHub Apps → VibeShield AI →
   Permissions & events**), under **Repository permissions**, set **GitHub App installation
   repository access** to **Read and write**. Change nothing else, and save. GitHub added this
   permission on 2026-10-13; the REST API reports it as `installation_repositories: write`.
2. Each existing installation must accept the new permission. For example, its owner opens
   `https://github.com/settings/installations/<installation id>` (for an organization,
   `https://github.com/organizations/<org>/settings/installations/<installation id>`) and accepts the
   updated permissions request GitHub shows there. Until then, GitHub does not list the permission
   for that installation and VibeShield keeps using the GitHub-managed path.
3. Keep the installation on **Only select repositories**. VibeShield adds repositories one at a time
   and treats an "All repositories" installation as already covering every repository.

Check it took effect (read-only): `GET https://api.github.com/apps/<slug>` returns the app's
`permissions`, which should then include `installation_repositories: write`. In the report, the Auto-Fix "Repository
access" card shows **Repository authorization required** with an **Authorize repository** button for
a repository you administer that is not yet in the installation.

The permission lets the app's user tokens add or remove repositories in its installations, but only
repositories the signed-in user administers (GitHub enforces this). VibeShield's code only ever adds
the single scanned repository after the user confirms, and never removes anything.

## 2. Apply the database migration

This migration is additive. Nothing reads its tables until step 3:

```sh
DATABASE_URL=<production pooled URL> DATABASE_URL_UNPOOLED=<production direct URL> npx prisma migrate deploy
```

It creates `AuthSession`, `GithubAccount`, `OAuthState`, `ScanAccess` and `AuditEvent`
(`prisma/migrations/20261028120000_add_github_app_authorization`).

## 3. Configure Vercel (Production, mark as Sensitive)

| Variable | Value |
|---|---|
| `GITHUB_APP_CLIENT_ID` | Client ID from step 1 |
| `GITHUB_APP_CLIENT_SECRET` | Client secret from step 1 |
| `GITHUB_APP_SLUG` | App slug |
| `GITHUB_APP_TOKEN_ENCRYPTION_KEY` | Output of `openssl rand -base64 32` (32 bytes; generate it yourself, never reuse another secret) |

`APP_URL` is already set and must remain `https://vibeshield-ai-phi.vercel.app`.

Redeploy, then check `GET /api/health`: `services.githubApp` must be `"configured"`.
`"setup_incomplete"` means the migration in step 2 has not been applied.

## 4. Live acceptance test

1. In Chrome, scan a public repository you own without connecting GitHub.
2. Open the report, switch to **AI Auto-Fix**, open an eligible finding and preview the fix.
3. Click **Connect GitHub** and complete GitHub's consent screen. You return to the same finding.
4. Click **Authorize this repository** and select only that repository on GitHub.
5. Approve the diff, then **Verify Fix on Full Repository**.
6. Click **Review & create pull request**, confirm the exact diff, and create the PR.
7. Open the PR on GitHub and confirm that:
   - the branch is `vibeshield/fix-…`
   - its parent is the scanned commit
   - only the verified lines changed
   - nothing was merged
8. Click the button again; the same PR is reported.
9. Click **Disconnect GitHub**; another PR attempt is refused.

## Rotation and revocation

- **Users:** "Disconnect GitHub" revokes the app's grant at GitHub and deletes the stored tokens.
  Removing a repository from the installation, or revoking the app in GitHub settings, takes effect
  on the next request.
- **Client secret:** rotate it in the app settings and update `GITHUB_APP_CLIENT_SECRET`. Existing
  tokens keep working until they expire and then refresh with the new secret.
- **Encryption key:** changing `GITHUB_APP_TOKEN_ENCRYPTION_KEY` makes stored tokens unreadable, and
  users are asked to connect again.
