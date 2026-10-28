# Persistent warm scanner worker

Optional executor that keeps Gitleaks, Semgrep and OSV-Scanner installed on one Linux host, so scans
skip the per-run GitHub Actions setup. GitHub Actions stays the fallback: if no warm worker polls
within `WARM_WORKER_HEALTHY_MS`, or a waiting job is not claimed within `WARM_WORKER_GRACE_MS`, the
app dispatches it to Actions as before.

## How it connects

- Outbound HTTPS only: the worker polls `POST /api/internal/worker/claim` and renews leases with
  `POST /api/internal/worker/heartbeat`. No inbound port and no database credentials on the host.
- Every request is HMAC-signed with `WARM_WORKER_SECRET` and carries a strictly increasing per-worker
  timestamp; replays are rejected. The endpoints return 404 unless `WARM_WORKER_ENABLED=true`.
- Claims use the same PostgreSQL advisory lock as submissions, retries and Auto-Fix verifications,
  so `MAX_CONCURRENT_HEAVY_SCANS` holds across both executors.
- A claim returns a lease. Callbacks without the current lease get `409 stale_lease`. A lease not
  renewed within `WARM_LEASE_MS` is re-queued (at most 3 attempts) and its partial findings dropped.

## Enable (application side)

1. Apply the additive migration `prisma/migrations/20261028050000_add_worker_heartbeat`
   (`npx prisma migrate deploy` against the production database).
2. Set `WARM_WORKER_ENABLED=true` and a new random `WARM_WORKER_SECRET` in Vercel, then redeploy.
   Leave it unset (the default) to keep GitHub Actions as the only executor.

## Host

```sh
docker build -f deploy/warm-worker/Dockerfile -t vibeshield-warm-worker:current .
install -m 600 -o root /dev/null /etc/vibeshield/worker.env   # then add:
#   WORKER_ID=oci-a1-1
#   VIBESHIELD_API_URL=https://vibeshield-ai-phi.vercel.app
#   WARM_WORKER_SECRET=...            (same value as in Vercel)
#   GITHUB_TOKEN=...                  (optional, read-only, raises the GitHub API rate limit)
#   WORKER_CAPACITY=1                 (2 only if measured memory allows)
cp deploy/warm-worker/vibeshield-warm-worker.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now vibeshield-warm-worker
curl -s http://127.0.0.1:8787/healthz   # loopback-only readiness
```

The unit runs the container read-only, as UID 10001, with all capabilities dropped,
`no-new-privileges`, a pid limit, memory/CPU limits and a `noexec` tmpfs for workspaces. The worker
refuses to start if any scanner binary is missing. Egress is not restricted by these files; restrict
it with the host firewall if required.

## Rollback

`systemctl disable --now vibeshield-warm-worker`, or set `WARM_WORKER_ENABLED=false` in Vercel.
In-flight leases expire and the jobs are re-queued for GitHub Actions; nothing else changes.
