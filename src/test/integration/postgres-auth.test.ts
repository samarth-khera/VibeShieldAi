/**
 * GitHub App authorization storage against a real PostgreSQL server (the migration's actual
 * tables): single-use OAuth state under concurrency, session binding, refresh-race guard,
 * disconnect cascading to sessions, BigInt GitHub IDs, and audit rows free of secrets.
 * Skipped unless VIBESHIELD_PG_TEST_URL points at a disposable, migrated database (tables are truncated).
 */
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import type { PrismaClient } from "@prisma/client";
import type { AuthStore } from "@/server/auth/store";

const PG_URL = process.env.VIBESHIELD_PG_TEST_URL?.trim();
if (process.env.REQUIRE_POSTGRES === "1" && !PG_URL) {
  throw new Error("REQUIRE_POSTGRES=1 but VIBESHIELD_PG_TEST_URL is not set");
}

describe.skipIf(!PG_URL)("PostgreSQL GitHub App authorization store (live database)", () => {
  let prisma: PrismaClient;
  let store: AuthStore;
  const now = new Date("2026-10-28T12:00:00Z");
  const later = new Date(now.getTime() + 3600_000);

  beforeAll(async () => {
    process.env.DATABASE_URL = PG_URL;
    process.env.DATABASE_URL_UNPOOLED = PG_URL;
    prisma = (await import("@/server/db")).prisma;
    store = (await import("@/server/auth/store")).createPrismaAuthStore(prisma);
  });
  beforeEach(async () => {
    await prisma.$executeRawUnsafe('TRUNCATE "AuthSession", "GithubAccount", "OAuthState", "ScanAccess", "AuditEvent", "SafeAutoFixSetting" CASCADE');
  });
  afterAll(async () => {
    await prisma?.$disconnect();
  });

  it("consumes a state exactly once under 20 concurrent callbacks, and only for its own session and purpose", async () => {
    await store.createSession("s1", later);
    await store.createSession("s2", later);
    await store.createState({ id: "st1", sessionId: "s1", purpose: "connect", returnTo: "/", codeVerifierEnc: "v1.x.y.z", expiresAt: later });
    expect(await store.consumeState("st1", "s2", "connect", now)).toBeNull(); // other browser
    expect(await store.consumeState("st1", "s1", "install", now)).toBeNull(); // other purpose
    const results = await Promise.all(Array.from({ length: 20 }, () => store.consumeState("st1", "s1", "connect", now)));
    expect(results.filter(Boolean)).toHaveLength(1);
    await store.createState({ id: "st2", sessionId: "s1", purpose: "connect", returnTo: "/", codeVerifierEnc: null, expiresAt: now });
    expect(await store.consumeState("st2", "s1", "connect", now)).toBeNull(); // expired
  });

  it("keeps a repository authorization request single use under concurrent confirmations", async () => {
    const now = new Date();
    const later = new Date(now.getTime() + 600_000);
    await store.createState({ id: "ra1", sessionId: "s1", purpose: "repo_access", returnTo: "/report/job1", codeVerifierEnc: "v1.a.b.c", expiresAt: later });
    expect(await store.consumeState("ra1", "s1", "connect", now)).toBeNull(); // not usable as an OAuth state
    expect(await store.consumeState("ra1", "s2", "repo_access", now)).toBeNull(); // other browser
    const results = await Promise.all(Array.from({ length: 20 }, () => store.consumeState("ra1", "s1", "repo_access", now)));
    expect(results.filter(Boolean)).toHaveLength(1);
    expect(results.find(Boolean)).toMatchObject({ purpose: "repo_access", codeVerifierEnc: "v1.a.b.c" });
  });

  it("stores the Safe Auto-Fix opt-in per repository (off when absent) with 64-bit IDs", async () => {
    expect(await store.getSafeAutoFix(1106558267)).toBeNull();
    const big = 2 ** 40 + 7;
    const on = await store.setSafeAutoFix({ githubRepoId: big, enabledByGithubUserId: 188962529, enabledByLogin: "samarth-khera" });
    expect(on).toMatchObject({ githubRepoId: big, enabledByGithubUserId: 188962529, enabledByLogin: "samarth-khera", scope: "safe_dependency_patch" });
    // Re-enabling by another user replaces the owner of the opt-in; it never creates a second row.
    await store.setSafeAutoFix({ githubRepoId: big, enabledByGithubUserId: 42, enabledByLogin: "other" });
    expect(await prisma.safeAutoFixSetting.count()).toBe(1);
    expect((await store.getSafeAutoFix(big))?.enabledByLogin).toBe("other");
    await store.deleteSafeAutoFix(big);
    await store.deleteSafeAutoFix(big); // idempotent
    expect(await store.getSafeAutoFix(big)).toBeNull();
  });

  it("guards token refresh with the row version, cascades disconnect to sessions, and keeps 64-bit GitHub IDs", async () => {
    const big = 2 ** 40 + 7;
    const acct = await store.upsertAccount({
      githubUserId: big,
      login: "alice",
      avatarUrl: null,
      accessTokenEnc: "v1.a.b.c",
      accessTokenExpiresAt: later,
      refreshTokenEnc: "v1.d.e.f",
      refreshTokenExpiresAt: later,
    });
    expect((await store.getAccountByGithubUserId(big))?.id).toBe(acct.id);
    const tokens = { accessTokenEnc: "v1.n.e.w", accessTokenExpiresAt: later, refreshTokenEnc: null, refreshTokenExpiresAt: null };
    const [a, b] = await Promise.all([store.updateTokens(acct.id, tokens, acct.updatedAt), store.updateTokens(acct.id, tokens, acct.updatedAt)]);
    expect([a, b].filter(Boolean)).toHaveLength(1);

    await store.createSession("s3", later);
    await store.linkSession("s3", acct.id);
    expect((await store.getSession("s3", now))?.account?.login).toBe("alice");
    await store.deleteAccount(acct.id);
    const s = await store.getSession("s3", now);
    expect(s).not.toBeNull();
    expect(s!.account).toBeNull();
    await store.revokeSession("s3", now);
    expect(await store.getSession("s3", now)).toBeNull();
  });

  it("stores scan access and audit events without secrets", async () => {
    await store.setScanAccess({ scanJobId: "job1", githubRepoId: 4242, isPrivate: true, githubUserId: 1001 });
    expect(await store.getScanAccess("job1")).toEqual({ scanJobId: "job1", githubRepoId: 4242, isPrivate: true, githubUserId: 1001 });
    await store.audit({ action: "pull_request", outcome: "created", githubUserId: 1001, githubLogin: "alice", scanJobId: "job1", detail: "#10" });
    const rows = await prisma.auditEvent.findMany();
    expect(rows).toHaveLength(1);
    expect(JSON.stringify(rows, (_k, v) => (typeof v === "bigint" ? Number(v) : v))).not.toMatch(/ghu_|ghr_|v1\./);
  });
});
