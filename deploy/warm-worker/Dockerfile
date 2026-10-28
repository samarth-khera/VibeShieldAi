# Persistent warm scanner worker (linux/amd64 or linux/arm64, e.g. an Always Free Ampere A1 VM).
# Scanner binaries are installed once at build time with pinned SHA-256 checks, never per scan.
# Build from the repository root:  docker build -f deploy/warm-worker/Dockerfile -t vibeshield-warm-worker .
FROM node:22-bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl git python3 python3-venv \
 && rm -rf /var/lib/apt/lists/*

# Dedicated unprivileged account; the worker and every scanner subprocess run as this user.
RUN useradd --system --uid 10001 --create-home --home-dir /home/scanner --shell /usr/sbin/nologin scanner

WORKDIR /app
COPY package.json package-lock.json ./
# No dependency install scripts run (the worker never uses Prisma or native build steps).
RUN npm ci --ignore-scripts --no-audit --no-fund && npm cache clean --force
COPY tsconfig.json ./
COPY src ./src
COPY worker ./worker
COPY rules ./rules
COPY scripts/ci/install-scanners.sh .github/scanner-requirements.txt ./deploy-tools/
RUN chown -R root:root /app && chmod -R a-w /app

USER 10001:10001
ENV VIBESHIELD_TOOLS_DIR=/home/scanner/.vibeshield \
    VIBESHIELD_SCANNER_REQUIREMENTS=/app/deploy-tools/scanner-requirements.txt \
    GITLEAKS_VERSION=8.30.1 \
    OSV_SCANNER_VERSION=2.7.0 \
    SEMGREP_VERSION=1.182.0 \
    NODE_ENV=production
RUN bash /app/deploy-tools/install-scanners.sh
# Writable archive cache owned by the worker user (a named volume mounted here inherits it).
USER root
RUN mkdir -p /home/scanner/archive-cache && chown 10001:10001 /home/scanner/archive-cache && chmod 700 /home/scanner/archive-cache
USER 10001:10001
ENV PATH=/home/scanner/.vibeshield/bin:$PATH \
    WORKER_ARCHIVE_CACHE_DIR=/home/scanner/archive-cache

CMD ["node", "--import", "tsx", "worker/warm-worker.ts"]
