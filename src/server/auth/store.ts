import type { PrismaClient } from "@prisma/client";

export type AccountRecord = {
  id: string;
  githubUserId: number;
  login: string;
  avatarUrl: string | null;
  accessTokenEnc: string;
  accessTokenExpiresAt: Date | null;
  refreshTokenEnc: string | null;
  refreshTokenExpiresAt: Date | null;
  updatedAt: Date;
};

export type SessionRecord = { id: string; expiresAt: Date; account: AccountRecord | null };

export type StateRecord = {
  id: string;
  sessionId: string;
  /** "repo_access": a pending per-repository authorization; codeVerifierEnc then holds its encrypted binding. */
  purpose: "connect" | "install" | "repo_access";
  returnTo: string;
  codeVerifierEnc: string | null;
  expiresAt: Date;
};

export type SafeAutoFixRecord = { githubRepoId: number; enabledByGithubUserId: number; enabledByLogin: string; scope: string; enabledAt: Date };

export type ScanAccessRecord = { scanJobId: string; githubRepoId: number; isPrivate: boolean; githubUserId: number | null };

export type AuditInput = {
  action: string;
  outcome: string;
  githubUserId?: number | null;
  githubLogin?: string | null;
  scanJobId?: string | null;
  remediationId?: string | null;
  repository?: string | null;
  detail?: string | null;
};

export type NewTokens = {
  accessTokenEnc: string;
  accessTokenExpiresAt: Date | null;
  refreshTokenEnc: string | null;
  refreshTokenExpiresAt: Date | null;
};

export interface AuthStore {
  createSession(id: string, expiresAt: Date): Promise<void>;
  /** Active (not expired, not revoked) session with its linked account. */
  getSession(id: string, now: Date): Promise<SessionRecord | null>;
  linkSession(id: string, accountId: string | null): Promise<void>;
  revokeSession(id: string, now: Date): Promise<void>;
  createState(state: StateRecord): Promise<void>;
  /**
   * Atomically marks the state consumed and returns it, only if it exists, is unexpired, unused,
   * has the expected purpose and belongs to `sessionId`. Any other attempt returns null.
   */
  consumeState(id: string, sessionId: string, purpose: StateRecord["purpose"], now: Date): Promise<StateRecord | null>;
  upsertAccount(data: Omit<AccountRecord, "id" | "updatedAt">): Promise<AccountRecord>;
  getAccount(id: string): Promise<AccountRecord | null>;
  getAccountByGithubUserId(githubUserId: number): Promise<AccountRecord | null>;
  /** Replaces tokens only if the row was not changed since `seenUpdatedAt` (refresh race guard). */
  updateTokens(id: string, tokens: NewTokens, seenUpdatedAt: Date): Promise<boolean>;
  /** Deletes the account; every session linked to it becomes disconnected. */
  deleteAccount(id: string): Promise<void>;
  getScanAccess(scanJobId: string): Promise<ScanAccessRecord | null>;
  setScanAccess(rec: ScanAccessRecord): Promise<void>;
  audit(event: AuditInput): Promise<void>;
  getSafeAutoFix(githubRepoId: number): Promise<SafeAutoFixRecord | null>;
  setSafeAutoFix(rec: { githubRepoId: number; enabledByGithubUserId: number; enabledByLogin: string }): Promise<SafeAutoFixRecord>;
  deleteSafeAutoFix(githubRepoId: number): Promise<void>;
}

const toAccount = (a: {
  id: string;
  githubUserId: bigint;
  login: string;
  avatarUrl: string | null;
  accessTokenEnc: string;
  accessTokenExpiresAt: Date | null;
  refreshTokenEnc: string | null;
  refreshTokenExpiresAt: Date | null;
  updatedAt: Date;
}): AccountRecord => ({ ...a, githubUserId: Number(a.githubUserId) });

export function createPrismaAuthStore(prisma: PrismaClient): AuthStore {
  return {
    async createSession(id, expiresAt) {
      await prisma.authSession.create({ data: { id, expiresAt } });
    },
    async getSession(id, now) {
      const s = await prisma.authSession.findUnique({ where: { id }, include: { githubAccount: true } });
      if (!s || s.revokedAt || s.expiresAt <= now) return null;
      return { id: s.id, expiresAt: s.expiresAt, account: s.githubAccount ? toAccount(s.githubAccount) : null };
    },
    async linkSession(id, accountId) {
      await prisma.authSession.update({ where: { id }, data: { githubAccountId: accountId, lastSeenAt: new Date() } });
    },
    async revokeSession(id, now) {
      await prisma.authSession.updateMany({ where: { id }, data: { revokedAt: now, githubAccountId: null } });
    },
    async createState(state) {
      await prisma.oAuthState.create({ data: state });
    },
    async consumeState(id, sessionId, purpose, now) {
      const res = await prisma.oAuthState.updateMany({
        where: { id, sessionId, purpose, consumedAt: null, expiresAt: { gt: now } },
        data: { consumedAt: now },
      });
      if (res.count !== 1) return null;
      const s = await prisma.oAuthState.findUnique({ where: { id } });
      return s ? { ...s, purpose: s.purpose as StateRecord["purpose"] } : null;
    },
    async upsertAccount(data) {
      const { githubUserId, ...rest } = data;
      const a = await prisma.githubAccount.upsert({
        where: { githubUserId: BigInt(githubUserId) },
        create: { githubUserId: BigInt(githubUserId), ...rest },
        update: rest,
      });
      return toAccount(a);
    },
    async getAccount(id) {
      const a = await prisma.githubAccount.findUnique({ where: { id } });
      return a ? toAccount(a) : null;
    },
    async getAccountByGithubUserId(githubUserId) {
      const a = await prisma.githubAccount.findUnique({ where: { githubUserId: BigInt(githubUserId) } });
      return a ? toAccount(a) : null;
    },
    async updateTokens(id, tokens, seenUpdatedAt) {
      const res = await prisma.githubAccount.updateMany({ where: { id, updatedAt: seenUpdatedAt }, data: tokens });
      return res.count === 1;
    },
    async deleteAccount(id) {
      await prisma.githubAccount.deleteMany({ where: { id } });
    },
    async getScanAccess(scanJobId) {
      const r = await prisma.scanAccess.findUnique({ where: { scanJobId } });
      return r
        ? {
            scanJobId: r.scanJobId,
            githubRepoId: Number(r.githubRepoId),
            isPrivate: r.isPrivate,
            githubUserId: r.githubUserId === null ? null : Number(r.githubUserId),
          }
        : null;
    },
    async setScanAccess(rec) {
      const data = {
        githubRepoId: BigInt(rec.githubRepoId),
        isPrivate: rec.isPrivate,
        githubUserId: rec.githubUserId === null ? null : BigInt(rec.githubUserId),
      };
      await prisma.scanAccess.upsert({ where: { scanJobId: rec.scanJobId }, create: { scanJobId: rec.scanJobId, ...data }, update: data });
    },
    async getSafeAutoFix(githubRepoId) {
      const r = await prisma.safeAutoFixSetting.findUnique({ where: { githubRepoId: BigInt(githubRepoId) } });
      return r ? { ...r, githubRepoId: Number(r.githubRepoId), enabledByGithubUserId: Number(r.enabledByGithubUserId) } : null;
    },
    async setSafeAutoFix(rec) {
      const data = { enabledByGithubUserId: BigInt(rec.enabledByGithubUserId), enabledByLogin: rec.enabledByLogin, enabledAt: new Date() };
      const r = await prisma.safeAutoFixSetting.upsert({
        where: { githubRepoId: BigInt(rec.githubRepoId) },
        create: { githubRepoId: BigInt(rec.githubRepoId), ...data },
        update: data,
      });
      return { ...r, githubRepoId: Number(r.githubRepoId), enabledByGithubUserId: Number(r.enabledByGithubUserId) };
    },
    async deleteSafeAutoFix(githubRepoId) {
      await prisma.safeAutoFixSetting.deleteMany({ where: { githubRepoId: BigInt(githubRepoId) } });
    },
    async audit(e) {
      await prisma.auditEvent.create({
        data: {
          action: e.action.slice(0, 40),
          outcome: e.outcome.slice(0, 30),
          githubUserId: e.githubUserId == null ? null : BigInt(e.githubUserId),
          githubLogin: e.githubLogin ?? null,
          scanJobId: e.scanJobId ?? null,
          remediationId: e.remediationId ?? null,
          repository: e.repository?.slice(0, 140) ?? null,
          detail: e.detail?.slice(0, 300) ?? null,
        },
      });
    },
  };
}

/** Non-persistent implementation for tests and fixtures. */
export class InMemoryAuthStore implements AuthStore {
  sessions = new Map<string, { id: string; expiresAt: Date; revokedAt: Date | null; accountId: string | null }>();
  states = new Map<string, StateRecord & { consumedAt: Date | null }>();
  accounts = new Map<string, AccountRecord>();
  access = new Map<string, ScanAccessRecord>();
  events: AuditInput[] = [];
  private seq = 0;

  async createSession(id: string, expiresAt: Date) {
    this.sessions.set(id, { id, expiresAt, revokedAt: null, accountId: null });
  }
  async getSession(id: string, now: Date) {
    const s = this.sessions.get(id);
    if (!s || s.revokedAt || s.expiresAt <= now) return null;
    return { id, expiresAt: s.expiresAt, account: s.accountId ? (this.accounts.get(s.accountId) ?? null) : null };
  }
  async linkSession(id: string, accountId: string | null) {
    const s = this.sessions.get(id);
    if (s) s.accountId = accountId;
  }
  async revokeSession(id: string, now: Date) {
    const s = this.sessions.get(id);
    if (s) Object.assign(s, { revokedAt: now, accountId: null });
  }
  async createState(state: StateRecord) {
    this.states.set(state.id, { ...state, consumedAt: null });
  }
  async consumeState(id: string, sessionId: string, purpose: StateRecord["purpose"], now: Date) {
    const s = this.states.get(id);
    if (!s || s.consumedAt || s.sessionId !== sessionId || s.purpose !== purpose || s.expiresAt <= now) return null;
    s.consumedAt = now;
    return { ...s };
  }
  async upsertAccount(data: Omit<AccountRecord, "id" | "updatedAt">) {
    const existing = [...this.accounts.values()].find((a) => a.githubUserId === data.githubUserId);
    const rec: AccountRecord = { ...data, id: existing?.id ?? `acct-${++this.seq}`, updatedAt: new Date(Date.now() + this.seq) };
    this.accounts.set(rec.id, rec);
    return rec;
  }
  async getAccount(id: string) {
    return this.accounts.get(id) ?? null;
  }
  async getAccountByGithubUserId(githubUserId: number) {
    return [...this.accounts.values()].find((a) => a.githubUserId === githubUserId) ?? null;
  }
  async updateTokens(id: string, tokens: NewTokens, seenUpdatedAt: Date) {
    const a = this.accounts.get(id);
    if (!a || a.updatedAt.getTime() !== seenUpdatedAt.getTime()) return false;
    this.accounts.set(id, { ...a, ...tokens, updatedAt: new Date(a.updatedAt.getTime() + 1) });
    return true;
  }
  async deleteAccount(id: string) {
    this.accounts.delete(id);
    for (const s of this.sessions.values()) if (s.accountId === id) s.accountId = null;
  }
  async getScanAccess(scanJobId: string) {
    return this.access.get(scanJobId) ?? null;
  }
  async setScanAccess(rec: ScanAccessRecord) {
    this.access.set(rec.scanJobId, rec);
  }
  safeAutoFix = new Map<number, SafeAutoFixRecord>();
  async getSafeAutoFix(githubRepoId: number) {
    return this.safeAutoFix.get(githubRepoId) ?? null;
  }
  async setSafeAutoFix(rec: { githubRepoId: number; enabledByGithubUserId: number; enabledByLogin: string }) {
    const r: SafeAutoFixRecord = { ...rec, scope: "safe_dependency_patch", enabledAt: new Date() };
    this.safeAutoFix.set(rec.githubRepoId, r);
    return r;
  }
  async deleteSafeAutoFix(githubRepoId: number) {
    this.safeAutoFix.delete(githubRepoId);
  }
  async audit(event: AuditInput) {
    this.events.push(event);
  }
}
