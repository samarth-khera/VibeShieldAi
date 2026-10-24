# Multi-stage hardened production Dockerfile for VibeShield AI
# Provides targets for both the web frontend/API and the isolated scanning worker.

FROM node:20-bookworm-slim AS base
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    git \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Stage 1: Dependencies
FROM base AS deps
WORKDIR /app
COPY package.json package-lock.json ./
COPY prisma ./prisma/
RUN npm ci

# Stage 2: Application Build
FROM base AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
RUN npx prisma generate
RUN npm run build

# Stage 3: Web Service Target (Unprivileged non-root nextjs user)
FROM node:20-bookworm-slim AS web
WORKDIR /app
ENV NODE_ENV=production
ENV PORT=3100
ENV HOSTNAME="0.0.0.0"
ENV NEXT_TELEMETRY_DISABLED=1

RUN groupadd --system --gid 1001 nodejs && \
    useradd --system --uid 1001 nextjs

COPY --from=builder --chown=nextjs:nodejs /app/package.json ./package.json
COPY --from=builder --chown=nextjs:nodejs /app/node_modules ./node_modules
COPY --from=builder --chown=nextjs:nodejs /app/public ./public
COPY --from=builder --chown=nextjs:nodejs /app/.next ./.next
COPY --from=builder --chown=nextjs:nodejs /app/prisma ./prisma

USER nextjs:nodejs
EXPOSE 3100
CMD ["npm", "start"]

# Stage 4: Hardened Scanner Worker Target
# Runs unprivileged as scanner (UID 10001) with bounded temp directories.
FROM base AS worker
WORKDIR /app
ENV NODE_ENV=production

RUN pip3 install --no-cache-dir --break-system-packages semgrep || true

RUN groupadd --system --gid 10001 scanner && \
    useradd --system --uid 10001 scanner -g scanner -d /home/scanner -m

COPY --from=builder --chown=scanner:scanner /app/package.json ./package.json
COPY --from=builder --chown=scanner:scanner /app/node_modules ./node_modules
COPY --from=builder --chown=scanner:scanner /app/worker ./worker
COPY --from=builder --chown=scanner:scanner /app/src ./src
COPY --from=builder --chown=scanner:scanner /app/prisma ./prisma
COPY --from=builder --chown=scanner:scanner /app/tsconfig.json ./tsconfig.json

RUN mkdir -p /home/scanner/.cache/osv-scanner /tmp && \
    chown -R scanner:scanner /home/scanner /tmp && \
    chmod 0700 /home/scanner

USER 10001:10001
CMD ["npm", "run", "worker"]
