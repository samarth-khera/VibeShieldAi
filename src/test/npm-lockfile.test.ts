import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import {
  generateNpmLockfilePatch,
  planNpmUpgrade,
  satisfies,
  stringifyNpmLock,
  type NpmVersionManifest,
} from "@/server/remediation/npm-lockfile";
import { approveRemediation, createPreview, diffDigest, type RemediationDeps } from "@/server/remediation/service";
import { InMemoryJobStore } from "@/test/mock-store";

const FIX = path.join(process.cwd(), "src/test/fixtures/npm-job-portal");
const read = (f: string) => readFileSync(path.join(FIX, f), "utf8");
const MANIFEST = read("original.package.json");
const LOCK = read("original.package-lock.json");
const REGISTRY = JSON.parse(read("registry-multer-2.5.0.json")) as NpmVersionManifest;
const PROXY_ADDR = JSON.parse(read("registry-proxy-addr-2.0.8.json")) as NpmVersionManifest;
const SHA = "7f90143a47c6280f6bcf9d55bb7c4767a48c1542";

const plan = (over: Partial<Parameters<typeof planNpmUpgrade>[0]> = {}) =>
  planNpmUpgrade({ manifestText: MANIFEST, lockText: LOCK, name: "multer", fromVersion: "2.0.2", toVersion: "2.5.0", registryManifest: REGISTRY, ...over });

/** Edits the fixture lockfile as data and re-serializes it exactly as npm would. */
type LockJson = {
  lockfileVersion: number;
  packages: Record<string, { version?: string; resolved?: string; dev?: boolean; dependencies?: Record<string, string> }>;
};
const lockWith = (edit: (lock: LockJson) => void) => {
  const lock = JSON.parse(LOCK);
  edit(lock);
  return stringifyNpmLock(lock, "  ");
};

// The advisories OSV reports for multer 2.0.2 (fixed versions as VibeShield's OSV parser records them).
const ADVISORIES: [string, string][] = [
  ["GHSA-3p4h-7m6x-2hcm", "2.2.0"],
  ["GHSA-535w-7cp7-47q4", "2.3.0"],
  ["GHSA-5528-5vmv-3xc2", "2.1.1"],
  ["GHSA-72gw-mp4g-v24j", "2.2.0"],
  ["GHSA-q7qp-rjg7-q26m", "2.5.0"],
  ["GHSA-qvfw-j98x-7q72", "2.3.0"],
  ["GHSA-v52c-386h-88mc", "2.1.0"],
  ["GHSA-wc9g-mqfw-jrwm", "2.3.0"],
  ["GHSA-xf7r-hgr6-v32p", "2.1.0"],
];
const finding = (id: string, fixed: string | null, over: Record<string, unknown> = {}) => ({
  fingerprint: `fp-${id}`,
  scanner: "osv-scanner",
  ruleId: id,
  category: "Dependencies",
  severity: "high",
  title: `multer advisory ${id}`,
  description: "",
  filePath: "backend/package-lock.json",
  startLine: null,
  endLine: null,
  redactedEvidence: null,
  vulnerabilityId: id,
  remediation: null,
  packageInfo: { name: "multer", version: "2.0.2", ecosystem: "npm", fixedVersion: fixed },
  metadata: { fixedVersion: fixed },
  ...over,
});

const RECORDED: Record<string, string> = {
  "https://registry.npmjs.org/multer/2.5.0": read("registry-multer-2.5.0.json"),
  "https://registry.npmjs.org/proxy-addr/2.0.8": read("registry-proxy-addr-2.0.8.json"),
  "https://registry.npmjs.org/proxy-addr": read("registry-proxy-addr.versions.json"),
  "https://registry.npmjs.org/brace-expansion": read("registry-brace-expansion.versions.json"),
};
function registryFetch(calls: { url: string; headers: Headers }[]) {
  return async (url: string, init?: RequestInit) => {
    calls.push({ url, headers: new Headers(init?.headers) });
    return RECORDED[url] ? new Response(RECORDED[url], { status: 200 }) : new Response("{}", { status: 404 });
  };
}

describe("npm lockfile upgrade reproduces npm exactly", () => {
  it("serializes the committed lockfile byte for byte like npm, keeping its indentation", () => {
    expect(stringifyNpmLock(JSON.parse(LOCK), "  ")).toBe(LOCK);
    const four = JSON.stringify(JSON.parse(LOCK), null, 4) + "\n";
    expect(planNpmUpgrade({ manifestText: MANIFEST, lockText: four, name: "multer", fromVersion: "2.0.2", toVersion: "2.5.0", registryManifest: REGISTRY }).lockText).toBe(
      JSON.stringify(JSON.parse(read("npm-expected.package-lock.json")), null, 4) + "\n",
    );
  });

  it("produces exactly what `npm install multer@2.5.0 --package-lock-only` wrote for Job-portal", () => {
    const r = plan();
    expect(r.manifestText).toBe(read("npm-expected.package.json"));
    expect(r.lockText).toBe(read("npm-expected.package-lock.json"));
    expect([r.oldSpec, r.newSpec]).toEqual(["^2.0.2", "^2.5.0"]);
    expect(r.removed).toEqual([
      "node_modules/buffer-from",
      "node_modules/concat-stream",
      "node_modules/minimist",
      "node_modules/mkdirp",
      "node_modules/readable-stream",
      "node_modules/string_decoder",
      "node_modules/typedarray",
      "node_modules/util-deprecate",
      "node_modules/xtend",
    ]);
    const lock = JSON.parse(r.lockText);
    expect(lock.packages["node_modules/multer"]).toMatchObject({
      version: "2.5.0",
      resolved: "https://registry.npmjs.org/multer/-/multer-2.5.0.tgz",
      integrity: REGISTRY.dist.integrity,
    });
  });
});

describe("transitive dependencies (npm update semantics)", () => {
  const proxyAddr = (fixed: string, over: Record<string, unknown> = {}) =>
    finding("GHSA-jqcg-44mw-7w3h", fixed, { packageInfo: { name: "proxy-addr", version: "2.0.7", ecosystem: "npm", fixedVersion: fixed }, ...over });

  it("updates proxy-addr within express's range exactly as `npm update proxy-addr` does, leaving package.json alone", async () => {
    const calls: { url: string; headers: Headers }[] = [];
    const p = await generateNpmLockfilePatch({
      finding: proxyAddr("2.0.8"),
      scanFindings: [proxyAddr("2.0.8")],
      lockText: LOCK,
      readFile: async () => MANIFEST,
      fetchImpl: registryFetch(calls),
    });
    expect(p.files.map((f) => f.path)).toEqual(["backend/package-lock.json"]);
    expect(p.files[0].after).toBe(read("npm-update-proxy-addr.package-lock.json"));
    expect(p.patchSummary).toBe("Update proxy-addr 2.0.7 → 2.0.8 in backend/package-lock.json (transitive; fixes 1 advisory; package.json unchanged)");
    expect(p.reason).toMatch(/express@5\.1\.0 \("\^2\.0\.7"\) installs it\. 2\.0\.8 is the newest release that range allows/);
    expect(p.reason).toMatch(/Same result as `npm update proxy-addr --package-lock-only`/);
    expect(p.reason.length).toBeLessThanOrEqual(500);
    // The release list and the chosen version's metadata come from the public registry, without credentials.
    expect(calls.map((c) => c.url)).toEqual(["https://registry.npmjs.org/proxy-addr", "https://registry.npmjs.org/proxy-addr/2.0.8"]);
    expect(calls.every((c) => c.headers.get("authorization") === null)).toBe(true);
  });

  it("explains why a fix outside the parent's range needs the parent upgraded instead of forcing it", async () => {
    const brace = (id: string, fixed: string) =>
      finding(id, fixed, { packageInfo: { name: "brace-expansion", version: "1.1.12", ecosystem: "npm", fixedVersion: fixed } });
    await expect(
      generateNpmLockfilePatch({
        finding: brace("GHSA-qhr7-859c-m2p7", "5.0.11"),
        scanFindings: [brace("GHSA-qhr7-859c-m2p7", "5.0.11"), brace("GHSA-rgw5-rvv9-x895", "1.1.18")],
        lockText: LOCK,
        readFile: async () => MANIFEST,
        fetchImpl: registryFetch([]),
      }),
    ).rejects.toThrow(/brace-expansion is not in package\.json; it is installed because minimatch@3\.1\.2 requires "\^1\.1\.7"\. The fix \(5\.0\.11\) is outside that range \(newest allowed: 1\.1\.\d+\), so minimatch must be upgraded first/);
  });

  it("does not trust an advisory fix recorded for another release line", async () => {
    await expect(
      generateNpmLockfilePatch({
        finding: finding("GHSA-old-line", "1.4.4"),
        scanFindings: [],
        lockText: LOCK,
        readFile: async () => MANIFEST,
        fetchImpl: registryFetch([]),
      }),
    ).rejects.toThrow(/recorded fix \(1\.4\.4\) is not newer than the installed multer 2\.0\.2: it belongs to another release line/);
  });
});

describe("npm lockfile remediation", () => {
  it("upgrades to the lowest release fixing every reported advisory and targets all of them", async () => {
    const calls: { url: string; headers: Headers }[] = [];
    const all = ADVISORIES.map(([id, fixed]) => finding(id, fixed));
    const clicked = all[6]; // fixed in 2.1.0 alone, but 2.5.0 is needed for the rest
    const p = await generateNpmLockfilePatch({
      finding: clicked,
      scanFindings: [...all, finding("GHSA-other", "9.9.9", { packageInfo: { name: "express", version: "5.1.0", ecosystem: "npm", fixedVersion: "9.9.9" } })],
      lockText: LOCK,
      readFile: async (p) => (p === "backend/package.json" ? MANIFEST : undefined),
      fetchImpl: registryFetch(calls),
    });
    expect(p.findingFingerprints[0]).toBe(clicked.fingerprint);
    expect(new Set(p.findingFingerprints)).toEqual(new Set(all.map((f) => f.fingerprint)));
    expect(p.files.map((f) => f.path)).toEqual(["backend/package.json", "backend/package-lock.json"]);
    expect(p.files[1].after).toBe(read("npm-expected.package-lock.json"));
    expect(p.patchSummary).toBe("Upgrade multer 2.0.2 → 2.5.0 in backend/package.json and backend/package-lock.json (fixes 9 advisories)");
    expect(p.reason).toMatch(/lowest multer release that fixes all 9 advisories/);
    // Only the public registry, for exactly this version, and never with credentials.
    expect(calls.map((c) => c.url)).toEqual(["https://registry.npmjs.org/multer/2.5.0"]);
    expect(calls[0].headers.get("authorization")).toBeNull();
  });

  it("does not target advisories whose only fix is a prerelease", async () => {
    const p = await generateNpmLockfilePatch({
      finding: finding("GHSA-v52c-386h-88mc", "2.1.0"),
      scanFindings: [finding("GHSA-v52c-386h-88mc", "2.1.0"), finding("GHSA-q7qp-rjg7-q26m", "2.5.0"), finding("GHSA-pre", "3.0.0-alpha.2")],
      lockText: LOCK,
      readFile: async () => MANIFEST,
      fetchImpl: registryFetch([]),
    });
    expect(p.findingFingerprints).toEqual(["fp-GHSA-v52c-386h-88mc", "fp-GHSA-q7qp-rjg7-q26m"]);
  });

  it("creates a preview whose diff applies with plain git apply and yields npm's files", async () => {
    const store = new InMemoryJobStore();
    const job = await store.create({
      owner: "samarth-khera",
      repo: "Job-portal",
      repositoryUrl: "https://github.com/samarth-khera/Job-portal",
      expiresAt: new Date(Date.now() + 3_600_000),
    });
    await store.update(job.id, { status: "completed", commitSha: SHA });
    const findings = ADVISORIES.map(([id, fixed]) => finding(id, fixed));
    await store.saveFindings(job.id, findings as never);
    const target = (await store.getFindings(job.id)).findings.find((f) => f.ruleId === "GHSA-qvfw-j98x-7q72")!;
    const deps: RemediationDeps = {
      store,
      sourceFiles: { "backend/package.json": MANIFEST, "backend/package-lock.json": LOCK },
      registryFetch: registryFetch([]),
    };
    const rem = await createPreview(job.id, target.id, deps);
    expect(rem).toMatchObject({ eligibility: "potentially_breaking", affectedFiles: ["backend/package.json", "backend/package-lock.json"] });
    expect(rem.findingFingerprints).toHaveLength(9);
    expect(rem.eligibilityReason).toMatch(/Same result as `npm install multer@2\.5\.0 --package-lock-only`/);
    expect(rem.eligibilityReason.length).toBeLessThanOrEqual(500);
    expect(rem.unifiedDiff).toMatch(/^--- a\/backend\/package\.json\n\+\+\+ b\/backend\/package\.json\n@@ /);
    expect(rem.unifiedDiff).toContain('-    "multer": "^2.0.2"\n+    "multer": "^2.5.0"');

    // The exact two-file diff is approvable as generated (no regeneration), bound to both files.
    const approved = await approveRemediation(job.id, rem.id, deps, { ownerSubject: "owner-1" });
    expect(approved.status).toBe("approved");
    expect(approved.unifiedDiff).toBe(rem.unifiedDiff);
    expect(approved.approvedOperations).toMatchObject({
      approvedFiles: ["backend/package.json", "backend/package-lock.json"],
      findingFingerprints: rem.findingFingerprints,
      diffSha256: diffDigest(rem.unifiedDiff),
    });

    // Real git: a clean checkout of the two committed files, plain `git apply` (no --unidiff-zero).
    const dir = mkdtempSync(path.join(tmpdir(), "vs-npm-apply-"));
    try {
      const git = (...args: string[]) => execFileSync("git", args, { cwd: dir, encoding: "utf8" });
      git("init", "-q");
      mkdirSync(path.join(dir, "backend"));
      writeFileSync(path.join(dir, "backend/package.json"), MANIFEST);
      writeFileSync(path.join(dir, "backend/package-lock.json"), LOCK);
      git("-c", "user.name=t", "-c", "user.email=t@example.com", "add", ".");
      git("-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-qm", "base");
      writeFileSync(path.join(dir, "fix.patch"), rem.unifiedDiff);
      git("apply", "--check", "fix.patch");
      git("apply", "fix.patch");
      expect(readFileSync(path.join(dir, "backend/package.json"), "utf8")).toBe(read("npm-expected.package.json"));
      expect(readFileSync(path.join(dir, "backend/package-lock.json"), "utf8")).toBe(read("npm-expected.package-lock.json"));
      expect(git("status", "--porcelain").split("\n").filter(Boolean).sort()).toEqual([" M backend/package-lock.json", " M backend/package.json", "?? fix.patch"]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("marks the finding for manual review instead of inventing a fix when the registry cannot confirm the release", async () => {
    const store = new InMemoryJobStore();
    const job = await store.create({ owner: "o", repo: "r", repositoryUrl: "https://github.com/o/r", expiresAt: new Date(Date.now() + 3_600_000) });
    await store.update(job.id, { status: "completed", commitSha: SHA });
    await store.saveFindings(job.id, [finding("GHSA-q7qp-rjg7-q26m", "2.5.0")] as never);
    const f = (await store.getFindings(job.id)).findings[0];
    const rem = await createPreview(job.id, f.id, {
      store,
      sourceFiles: { "backend/package.json": MANIFEST, "backend/package-lock.json": LOCK },
      registryFetch: async () => new Response("down", { status: 503 }),
    });
    expect(rem).toMatchObject({ eligibility: "unsuitable", unifiedDiff: "" });
    expect(rem.eligibilityReason).toMatch(/registry did not return multer@2\.5\.0/);
  });
});

describe("npm lockfile entry metadata", () => {
  it("copies every field npm copies (e.g. peerDependenciesMeta) instead of dropping it", () => {
    const r = plan({ registryManifest: { ...REGISTRY, peerDependenciesMeta: { debug: { optional: true } } } });
    expect(JSON.parse(r.lockText).packages["node_modules/multer"].peerDependenciesMeta).toEqual({ debug: { optional: true } });
  });
});

describe("npm lockfile upgrade fails closed", () => {
  const cases: [string, Partial<Parameters<typeof planNpmUpgrade>[0]>, RegExp][] = [
    ["a version that is not newer", { toVersion: "2.0.2" }, /not newer/],
    ["prerelease targets", { toVersion: "3.0.0-alpha.2" }, /release versions/],
    ["a different installed version", { fromVersion: "2.0.1" }, /not installed at the top level/],
    ["mismatched registry metadata", { registryManifest: { ...REGISTRY, version: "2.4.0" } }, /does not match/],
    ["a tarball outside the public registry", { registryManifest: { ...REGISTRY, dist: { ...REGISTRY.dist, tarball: "https://evil.example/multer-2.5.0.tgz" } } }, /tarball or integrity/],
    ["install scripts", { registryManifest: { ...REGISTRY, hasInstallScript: true } }, /hasInstallScript/],
    ["deprecated releases", { registryManifest: { ...REGISTRY, deprecated: "do not use" } }, /deprecated/],
    ["platform restrictions", { registryManifest: { ...REGISTRY, os: ["linux"] } }, /declares "os"/],
    ["optional peer-only metadata with real peers", { registryManifest: { ...REGISTRY, peerDependencies: { debug: "*" } } }, /declares "peerDependencies"/],
    ["new packages npm would have to add", { registryManifest: { ...REGISTRY, dependencies: { ...(REGISTRY.dependencies as object), "left-pad": "^1.3.0" } } }, /left-pad, which is not installed yet, so npm would add packages/],
    ["locked versions outside the new range", { registryManifest: { ...REGISTRY, dependencies: { ...(REGISTRY.dependencies as object), busboy: "^2.0.0" } } }, /needs busboy@\^2\.0\.0, but busboy 1\.6\.0 is installed, so npm would upgrade busboy too/],
    ["CRLF lockfiles", { lockText: LOCK.replace(/\n/g, "\r\n") }, /CRLF/],
    [
      "lockfiles not in npm's exact format",
      {
        lockText: (() => {
          const l = JSON.parse(LOCK);
          const e = l.packages["node_modules/busboy"];
          l.packages["node_modules/busboy"] = Object.fromEntries(Object.entries(e).reverse());
          return JSON.stringify(l, null, 2) + "\n";
        })(),
      },
      /exact format npm writes/,
    ],
    ["lockfileVersion 2", { lockText: lockWith((l) => (l.lockfileVersion = 2)) }, /lockfileVersion 3/],
    ["inconsistent dependency flags", { lockText: lockWith((l) => (l.packages["node_modules/busboy"].dev = true)) }, /does not match what the current npm writes \(first difference: node_modules\/busboy\)/],
    ["extraneous packages", { lockText: lockWith((l) => (l.packages["node_modules/orphan"] = { version: "1.0.0" })) }, /first difference: node_modules\/orphan\)/],
    ["a custom registry", { lockText: lockWith((l) => (l.packages["node_modules/multer"].resolved = "https://npm.internal.example/multer-2.0.2.tgz")) }, /public npm registry/],
    ["a nested copy of the package", { lockText: lockWith((l) => (l.packages["node_modules/express/node_modules/multer"] = { version: "1.4.5" })) }, /also installed as a nested dependency/],
    [
      "a transitive version outside its dependents' ranges",
      {
        name: "proxy-addr",
        fromVersion: "2.0.7",
        toVersion: "3.0.0",
        registryManifest: { ...PROXY_ADDR, version: "3.0.0", dist: { ...PROXY_ADDR.dist, tarball: "https://registry.npmjs.org/proxy-addr/-/proxy-addr-3.0.0.tgz" } },
      },
      /proxy-addr@3\.0\.0 is outside the range "\^2\.0\.7" that express@5\.1\.0 declares; express itself must be upgraded/,
    ],
    ["ranges other than ^/~/exact", { lockText: lockWith((l) => (l.packages[""].dependencies!.multer = ">=2.0.0")), manifestText: MANIFEST.replace('"^2.0.2"', '">=2.0.0"') }, /not a plain version/],
    ["package.json disagreeing with the lockfile", { manifestText: MANIFEST.replace('"^2.0.2"', '"^2.0.1"') }, /disagree/],
  ];
  it.each(cases)("refuses %s", (_name, over, message) => {
    expect(() => plan(over)).toThrow(message);
  });
});

describe("semver subset", () => {
  it.each([
    ["1.6.0", "^1.6.0", true],
    ["2.0.0", "^1.6.0", false],
    ["0.2.5", "^0.2.3", true],
    ["0.3.0", "^0.2.3", false],
    ["0.0.4", "^0.0.3", false],
    ["1.2.9", "~1.2.3", true],
    ["1.3.0", "~1.2.3", false],
    ["1.5.0", ">=1.2.0 <2.0.0", true],
    ["2.0.0", ">=1.2.0 <2.0.0", false],
    ["3.1.0", "^1.0.0 || ^3.0.0", true],
    ["1.9.9", "1.x", true],
    ["2.0.0", "1.x", false],
    ["4.0.0", "*", true],
    ["1.2.3", "1.2.3", true],
    ["1.2.4", "1.2.3", false],
    ["1.2.3", "<=1.2", true],
    ["1.3.0", "<=1.2", false],
  ])("%s satisfies %s → %s", (v, range, expected) => {
    expect(satisfies(v, range)).toBe(expected);
  });
  it("refuses ranges it does not understand", () => {
    expect(() => satisfies("1.0.0", "1.0.0 - 2.0.0")).toThrow();
    expect(() => satisfies("1.0.0", "npm:other@1")).toThrow();
    expect(() => satisfies("1.0.0", "latest")).toThrow();
  });
});
