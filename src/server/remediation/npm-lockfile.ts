import type { FetchLike } from "../github";

/**
 * Deterministic npm dependency upgrade for a vulnerability reported against package-lock.json.
 *
 * Reproduces what `npm install <name>@<version> --package-lock-only --ignore-scripts` writes for a
 * directly declared registry dependency: the manifest spec, the lockfile root spec, the package's
 * lock entry (from the registry's published metadata for that exact version), pruning of packages
 * nothing depends on any more, and npm's dev/optional/peer flags. No npm process or repository code
 * runs. Anything outside that well-understood case (new transitive packages, install scripts,
 * custom registries, workspaces, links, a lockfile npm would not write byte for byte) is refused,
 * so a patch is either exactly what npm would produce or not offered at all.
 */

export class NpmUpgradeError extends Error {}

const refuse = (msg: string): never => {
  throw new NpmUpgradeError(`${msg} Manual review is required.`);
};

// ---------------------------------------------------------------------------------------------
// npm's lockfile serialization (json-stringify-nice with npm's preferred key order)
// ---------------------------------------------------------------------------------------------

const LOCK_KEY_ORDER = ["name", "version", "lockfileVersion", "resolved", "integrity", "requires", "packages", "dependencies"];
const isObj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);

function compareKeys(a: string, b: string): number {
  const ia = LOCK_KEY_ORDER.indexOf(a);
  const ib = LOCK_KEY_ORDER.indexOf(b);
  if (ia >= 0 && ib < 0) return -1;
  if (ib >= 0 && ia < 0) return 1;
  if (ia >= 0 && ib >= 0) return ia - ib;
  return a.localeCompare(b, "en");
}

/** Exactly npm's output: scalar keys before object keys, preferred keys first, then locale order. */
export function stringifyNpmLock(data: unknown, indent: string): string {
  const seen = new Map<object, unknown>();
  const sorted = (_key: string, val: unknown) => {
    if (!isObj(val)) return val;
    if (seen.has(val)) return seen.get(val);
    const ret = Object.fromEntries(
      Object.entries(val).sort(([ak, av], [bk, bv]) => (isObj(av) === isObj(bv) ? compareKeys(ak, bk) : isObj(av) ? 1 : -1)),
    );
    seen.set(val, ret);
    return ret;
  };
  return JSON.stringify(data, sorted, indent) + "\n";
}

// ---------------------------------------------------------------------------------------------
// The subset of semver ranges npm manifests use in practice; anything else is refused.
// ---------------------------------------------------------------------------------------------

type V = [number, number, number];
const cmp = (a: V, b: V) => a[0] - b[0] || a[1] - b[1] || a[2] - b[2];

/** A plain release version (no prerelease/build), or null. */
export function parseVersion(v: string): V | null {
  const m = /^v?(\d{1,9})\.(\d{1,9})\.(\d{1,9})$/.exec(v.trim());
  return m ? [Number(m[1]), Number(m[2]), Number(m[3])] : null;
}

export function compareVersions(a: string, b: string): number {
  const x = parseVersion(a);
  const y = parseVersion(b);
  if (!x || !y) throw new NpmUpgradeError(`Cannot compare versions ${a} and ${b}.`);
  return cmp(x, y);
}

type Bound = { min: V; max: V | null; maxInclusive?: boolean };

function partial(s: string): { parts: number[] } | null {
  const t = s.replace(/^[v=]+/, "");
  if (t === "" || t === "*" || t === "x" || t === "X") return { parts: [] };
  const m = /^(\d{1,9})(?:\.(\d{1,9}|[xX*]))?(?:\.(\d{1,9}|[xX*]))?$/.exec(t);
  if (!m) return null;
  const parts: number[] = [];
  for (const p of [m[1], m[2], m[3]]) {
    if (p === undefined || /^[xX*]$/.test(p)) break;
    parts.push(Number(p));
  }
  return { parts };
}

function comparatorBounds(c: string): Bound {
  const m = /^(\^|~|>=|<=|>|<|=)?(.*)$/.exec(c)!;
  const op = m[1] ?? "";
  const p = partial(m[2]);
  if (!p) return refuse(`Unsupported version range "${c}".`);
  const [a = 0, b = 0, d = 0] = p.parts;
  const n = p.parts.length;
  const exactNext = (): V => (n === 0 ? [Infinity, 0, 0] : n === 1 ? [a + 1, 0, 0] : n === 2 ? [a, b + 1, 0] : [a, b, d + 1]);
  switch (op) {
    case "":
    case "=":
      return n === 3 ? { min: [a, b, d], max: [a, b, d], maxInclusive: true } : { min: [a, b, d], max: n === 0 ? null : exactNext() };
    case "^": {
      if (n === 0) return { min: [0, 0, 0], max: null };
      const max: V = a > 0 || n === 1 ? [a + 1, 0, 0] : b > 0 || n === 2 ? [0, b + 1, 0] : [0, 0, d + 1];
      return { min: [a, b, d], max };
    }
    case "~":
      return { min: [a, b, d], max: n === 0 ? null : n === 1 ? [a + 1, 0, 0] : [a, b + 1, 0] };
    case ">=":
      return { min: [a, b, d], max: null };
    case ">":
      return { min: n === 3 ? [a, b, d + 1] : exactNext(), max: null };
    case "<":
      return { min: [0, 0, 0], max: [a, b, d] };
    case "<=":
      return n === 3 ? { min: [0, 0, 0], max: [a, b, d], maxInclusive: true } : { min: [0, 0, 0], max: exactNext() };
  }
  return refuse(`Unsupported version range "${c}".`);
}

/** semver.satisfies for release versions and the common range grammar; throws on anything else. */
export function satisfies(version: string, range: string): boolean {
  const v = parseVersion(version);
  if (!v) return refuse(`Unsupported version "${version}".`);
  return range.split("||").some((alt) => {
    const comparators = alt
      .trim()
      .replace(/(\^|~|>=|<=|>|<|=)\s+/g, "$1")
      .split(/\s+/)
      .filter(Boolean);
    if (comparators.some((c) => c === "-")) refuse(`Unsupported version range "${range}".`);
    return (comparators.length ? comparators : ["*"]).every((c) => {
      const { min, max, maxInclusive } = comparatorBounds(c);
      if (cmp(v, min) < 0) return false;
      if (!max) return true;
      const r = cmp(v, max);
      return maxInclusive ? r <= 0 : r < 0;
    });
  });
}

// ---------------------------------------------------------------------------------------------
// Lockfile dependency graph and npm's flags
// ---------------------------------------------------------------------------------------------

type LockEntry = Record<string, unknown> & {
  version?: string;
  resolved?: string;
  integrity?: string;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  peerDependenciesMeta?: Record<string, { optional?: boolean }>;
};
type Packages = Record<string, LockEntry>;
type EdgeType = "prod" | "dev" | "optional" | "peer" | "peerOptional";
const FLAGS = ["dev", "optional", "devOptional", "peer"] as const;

/** "node_modules/a/node_modules/@s/b" → "node_modules/a"; top-level → "" (the root). */
function parentLocation(loc: string): string {
  const i = loc.lastIndexOf("/node_modules/");
  return i < 0 ? "" : loc.slice(0, i);
}

/** Node's module resolution over the lockfile's install locations. */
function resolveFrom(packages: Packages, from: string, name: string): string | null {
  for (let loc = from; ; loc = parentLocation(loc)) {
    const candidate = loc ? `${loc}/node_modules/${name}` : `node_modules/${name}`;
    if (packages[candidate]) return candidate;
    if (!loc) return null;
  }
}

function edgesOf(packages: Packages, loc: string): { to: string; type: EdgeType }[] {
  const e = packages[loc];
  const types = new Map<string, EdgeType>();
  for (const name of Object.keys(e.dependencies ?? {})) types.set(name, "prod");
  if (loc === "") for (const name of Object.keys(e.devDependencies ?? {})) types.set(name, "dev");
  for (const name of Object.keys(e.optionalDependencies ?? {})) types.set(name, "optional");
  for (const name of Object.keys(e.peerDependencies ?? {})) {
    types.set(name, e.peerDependenciesMeta?.[name]?.optional ? "peerOptional" : "peer");
  }
  const out: { to: string; type: EdgeType }[] = [];
  for (const [name, type] of types) {
    // Peer dependencies are provided by the dependent's parent, so resolve from there.
    const to = resolveFrom(packages, type === "peer" || type === "peerOptional" ? parentLocation(loc) : loc, name);
    if (to) out.push({ to, type });
  }
  return out;
}

function reach(packages: Packages, allow: (type: EdgeType, fromRoot: boolean) => boolean): Set<string> {
  const seen = new Set<string>([""]);
  const queue = [""];
  while (queue.length) {
    const loc = queue.shift()!;
    for (const { to, type } of edgesOf(packages, loc)) {
      if (seen.has(to) || !allow(type, loc === "")) continue;
      seen.add(to);
      queue.push(to);
    }
  }
  return seen;
}

/** npm's flags: dev/optional/peer when every path from the root goes through such an edge. */
function computeFlags(packages: Packages): { reachable: Set<string>; flags: Map<string, Set<(typeof FLAGS)[number]>> } {
  const optionalEdge = (t: EdgeType) => t === "optional" || t === "peerOptional";
  const peerEdge = (t: EdgeType) => t === "peer" || t === "peerOptional";
  const reachable = reach(packages, () => true);
  const nonDev = reach(packages, (t, root) => !(root && t === "dev"));
  const nonOpt = reach(packages, (t) => !optionalEdge(t));
  const nonDevOpt = reach(packages, (t, root) => !(root && t === "dev") && !optionalEdge(t));
  const nonPeer = reach(packages, (t) => !peerEdge(t));
  const flags = new Map<string, Set<(typeof FLAGS)[number]>>();
  for (const loc of reachable) {
    if (loc === "") continue;
    const f = new Set<(typeof FLAGS)[number]>();
    const dev = !nonDev.has(loc);
    const optional = !nonOpt.has(loc);
    if (dev) f.add("dev");
    if (optional) f.add("optional");
    if (!nonDevOpt.has(loc) && !dev && !optional) f.add("devOptional");
    if (!nonPeer.has(loc)) f.add("peer");
    flags.set(loc, f);
  }
  return { reachable, flags };
}

const recordedFlags = (e: LockEntry) => new Set(FLAGS.filter((f) => e[f] === true));
const sameSet = <T>(a: Set<T>, b: Set<T>) => a.size === b.size && [...a].every((x) => b.has(x));

// ---------------------------------------------------------------------------------------------
// Registry metadata
// ---------------------------------------------------------------------------------------------

const NAME_RE = /^(?:@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/;
const REGISTRY = "https://registry.npmjs.org/";

export type NpmVersionManifest = Record<string, unknown> & {
  name: string;
  version: string;
  dist: { tarball: string; integrity: string };
};

/** The registry's published metadata for exactly one version (https://registry.npmjs.org/<name>/<version>). */
export async function fetchNpmVersionManifest(name: string, version: string, fetchImpl: FetchLike): Promise<NpmVersionManifest> {
  if (!NAME_RE.test(name) || !parseVersion(version)) refuse(`Invalid package ${name}@${version}.`);
  const path = name.startsWith("@") ? `@${encodeURIComponent(name.slice(1))}` : encodeURIComponent(name);
  let res: Response;
  try {
    res = await fetchImpl(`${REGISTRY}${path}/${encodeURIComponent(version)}`, {
      headers: { Accept: "application/json", "User-Agent": "VibeShield-AI-Remediation" },
      signal: AbortSignal.timeout(15_000),
    });
  } catch {
    return refuse(`The npm registry could not be reached to confirm ${name}@${version}.`);
  }
  const text = res.ok ? await res.text() : "";
  if (!res.ok || text.length > 2_000_000) refuse(`The npm registry did not return ${name}@${version}.`);
  const m = JSON.parse(text) as NpmVersionManifest;
  if (m?.name !== name || m.version !== version || typeof m.dist?.tarball !== "string" || typeof m.dist?.integrity !== "string") {
    refuse(`The npm registry returned unexpected metadata for ${name}@${version}.`);
  }
  return m;
}

// ---------------------------------------------------------------------------------------------
// The upgrade
// ---------------------------------------------------------------------------------------------

export type NpmUpgradeInput = {
  /** package.json and package-lock.json of one npm project, as committed at the scanned commit. */
  manifestText: string;
  lockText: string;
  name: string;
  /** Version the scan found installed (the finding's version). */
  fromVersion: string;
  toVersion: string;
  registryManifest: NpmVersionManifest;
};

export type NpmUpgradeResult = {
  manifestText: string;
  lockText: string;
  oldSpec: string;
  newSpec: string;
  /** Lockfile locations npm prunes because nothing depends on them any more. */
  removed: string[];
};

/** Lock entry fields npm copies from the package manifest (arborist's pkgMetaKeys we support). */
function lockEntryFor(m: NpmVersionManifest, previous: LockEntry): LockEntry {
  const nonEmpty = (v: unknown) => (isObj(v) ? Object.keys(v).length > 0 : Array.isArray(v) ? v.length > 0 : Boolean(v));
  for (const key of [
    "hasInstallScript",
    "deprecated",
    "bundleDependencies",
    "bundledDependencies",
    "_hasShrinkwrap",
    "os",
    "cpu",
    "peerDependencies",
    "optionalDependencies",
    "acceptDependencies",
    "workspaces",
  ]) {
    if (nonEmpty(m[key])) refuse(`${m.name}@${m.version} declares "${key}", which VibeShield does not update automatically.`);
  }
  if (nonEmpty(m.bin) && JSON.stringify(m.bin) !== JSON.stringify(previous.bin)) {
    refuse(`${m.name}@${m.version} changes its executables ("bin").`);
  }
  const entry: LockEntry = {
    version: m.version,
    resolved: m.dist.tarball,
    integrity: m.dist.integrity,
  };
  const license = isObj(m.license) && typeof m.license.type === "string" ? m.license.type : m.license;
  if (license !== undefined && license !== null && license !== "") {
    if (typeof license !== "string") refuse(`${m.name}@${m.version} has an unrecognized license field.`);
    entry.license = license;
  }
  if (nonEmpty(m.dependencies)) entry.dependencies = m.dependencies as Record<string, string>;
  if (nonEmpty(m.engines)) entry.engines = m.engines;
  if (nonEmpty(m.funding)) {
    const ok = (f: unknown) => isObj(f) && typeof f.url === "string";
    if (!(ok(m.funding) || (Array.isArray(m.funding) && m.funding.every(ok)))) refuse(`${m.name}@${m.version} has an unrecognized funding field.`);
    entry.funding = m.funding;
  }
  if (nonEmpty(m.bin)) entry.bin = m.bin;
  return entry;
}

function tarballUrl(name: string, version: string): string {
  const base = name.startsWith("@") ? name.split("/")[1] : name;
  return `${REGISTRY}${name}/-/${base}-${version}.tgz`;
}

export function planNpmUpgrade(input: NpmUpgradeInput): NpmUpgradeResult {
  const { name, fromVersion, toVersion, registryManifest: m } = input;
  if (!NAME_RE.test(name)) refuse(`Invalid package name "${name}".`);
  if (!parseVersion(fromVersion) || !parseVersion(toVersion)) refuse(`Only release versions can be upgraded automatically.`);
  if (compareVersions(toVersion, fromVersion) <= 0) refuse(`${toVersion} is not newer than the installed ${fromVersion}.`);
  if (m.name !== name || m.version !== toVersion) refuse(`Registry metadata does not match ${name}@${toVersion}.`);
  if (m.dist.tarball !== tarballUrl(name, toVersion) || !/^sha512-[A-Za-z0-9+/]{86}==$/.test(m.dist.integrity)) {
    refuse(`The registry tarball or integrity for ${name}@${toVersion} is not in the expected form.`);
  }

  // The lockfile must be exactly what npm writes, so the rewrite changes only what npm would change.
  if (input.lockText.includes("\r")) refuse("package-lock.json uses CRLF line endings.");
  let lock: { lockfileVersion?: number; packages?: Packages; dependencies?: unknown } & Record<string, unknown>;
  try {
    lock = JSON.parse(input.lockText);
  } catch {
    return refuse("package-lock.json is not valid JSON.");
  }
  if (lock.lockfileVersion !== 3 || !isObj(lock.packages) || lock.dependencies !== undefined) {
    refuse("Only npm lockfileVersion 3 is updated automatically.");
  }
  const indent = /^\{\n([ \t]+)"/.exec(input.lockText)?.[1] ?? "  ";
  if (stringifyNpmLock(lock, indent) !== input.lockText) refuse("package-lock.json is not in the exact format npm writes.");
  const packages = lock.packages!;
  const root = packages[""];
  if (!root) refuse("package-lock.json has no root package entry.");
  for (const [loc, e] of Object.entries(packages)) {
    if (e.link || e.inBundle || (loc === "" && (e.workspaces || e.peerDependencies))) {
      refuse("Lockfiles with links, workspaces, bundled or root peer dependencies are not updated automatically.");
    }
  }

  // A directly declared registry dependency, installed once, at the version the scan found.
  const loc = `node_modules/${name}`;
  const current = packages[loc];
  if (!current || current.version !== fromVersion) refuse(`${name}@${fromVersion} is not installed at the top level of this lockfile.`);
  if (!current.resolved?.startsWith(REGISTRY)) refuse(`${name} is not installed from the public npm registry.`);
  const elsewhere = Object.keys(packages).filter((k) => k !== loc && (k.endsWith(`/node_modules/${name}`)));
  if (elsewhere.length) refuse(`${name} is also installed as a nested dependency (${elsewhere[0]}).`);
  const section = (["dependencies", "devDependencies", "optionalDependencies"] as const).find((s) => typeof root[s]?.[name] === "string");
  if (!section) refuse(`${name} is not a direct dependency of this project, so it is only upgraded through its parent package.`);
  const oldSpec = root[section!]![name];
  const specMatch = /^(\^|~)?(\d+\.\d+\.\d+)$/.exec(oldSpec);
  if (!specMatch) refuse(`The declared range "${oldSpec}" for ${name} is not a plain version or ^/~ range.`);
  const newSpec = `${specMatch![1] ?? ""}${toVersion}`;

  let manifest: Record<string, Record<string, string> | unknown>;
  try {
    manifest = JSON.parse(input.manifestText);
  } catch {
    return refuse("package.json is not valid JSON.");
  }
  if ((manifest[section!] as Record<string, string> | undefined)?.[name] !== oldSpec) {
    refuse(`package.json and package-lock.json disagree about ${name}.`);
  }

  // npm's flags must be reproducible on the lockfile as committed before we trust them on the result.
  const before = computeFlags(packages);
  for (const [l, e] of Object.entries(packages)) {
    if (l === "") continue;
    if (!before.reachable.has(l)) refuse(`package-lock.json contains packages nothing depends on (${l}); run npm install first.`);
    if (!sameSet(before.flags.get(l)!, recordedFlags(e))) refuse(`package-lock.json dependency flags for ${l} differ from npm's; run npm install first.`);
  }

  // Apply: root spec, the upgraded entry, then prune and re-flag.
  const next: Packages = structuredClone(packages);
  next[""][section!] = { ...next[""][section!], [name]: newSpec };
  next[loc] = lockEntryFor(m, current);
  for (const [dep, range] of Object.entries(next[loc].dependencies ?? {})) {
    const at = resolveFrom(next, loc, dep);
    if (!at) refuse(`${name}@${toVersion} needs ${dep}, which is not in the lockfile; npm would install a new package.`);
    if (!satisfies(String(next[at!].version), range)) {
      refuse(`${name}@${toVersion} needs ${dep}@${range}, but ${next[at!].version} is locked; npm would change other packages.`);
    }
  }
  const after = computeFlags(next);
  const removed = Object.keys(next).filter((l) => l !== "" && !after.reachable.has(l));
  for (const l of removed) delete next[l];
  for (const [l, e] of Object.entries(next)) {
    if (l === "") continue;
    for (const f of FLAGS) delete e[f];
    for (const f of after.flags.get(l)!) e[f] = true;
  }

  // package.json: change only the one value, in place, keeping the file's formatting.
  const lines = input.manifestText.split("\n");
  const keyRe = new RegExp(`^(\\s*"${name.replace(/[.*+?^${}()|[\]\\/]/g, "\\$&")}"\\s*:\\s*)"${oldSpec.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}"(,?\\s*)$`);
  const hits = lines.flatMap((l, i) => (keyRe.test(l) ? [i] : []));
  if (hits.length !== 1) refuse(`Could not locate the single "${name}" declaration in package.json.`);
  lines[hits[0]] = lines[hits[0]].replace(keyRe, `$1"${newSpec}"$2`);
  const manifestText = lines.join("\n");
  const expected = structuredClone(manifest) as Record<string, Record<string, string>>;
  expected[section!][name] = newSpec;
  if (JSON.stringify(JSON.parse(manifestText)) !== JSON.stringify(expected)) refuse("package.json could not be updated in place.");

  return { manifestText, lockText: stringifyNpmLock({ ...lock, packages: next }, indent), oldSpec, newSpec, removed };
}

// ---------------------------------------------------------------------------------------------
// Remediation for an OSV finding reported against package-lock.json
// ---------------------------------------------------------------------------------------------

type DependencyFinding = {
  fingerprint: string;
  scanner: string;
  filePath: string;
  ruleId: string;
  packageInfo?: unknown;
};

const pkgOf = (f: DependencyFinding) =>
  (isObj(f.packageInfo) ? f.packageInfo : {}) as { name?: string; version?: string; ecosystem?: string; fixedVersion?: string | null };

export const isNpmLockfileFinding = (f: DependencyFinding) =>
  f.scanner === "osv-scanner" && /(^|\/)package-lock\.json$/.test(f.filePath) && pkgOf(f).ecosystem?.toLowerCase() === "npm";

export type NpmLockfilePatch = {
  files: { path: string; before: string; after: string }[];
  patchSummary: string;
  reason: string;
  /** The finding itself first, then every other advisory this upgrade resolves for the same package. */
  findingFingerprints: string[];
};

/**
 * Upgrades the vulnerable package to the lowest release that fixes every advisory the scan reported
 * for that installed version, updating package.json and package-lock.json together.
 */
export async function generateNpmLockfilePatch(params: {
  finding: DependencyFinding;
  /** All findings of the same scan (siblings for the same package are fixed together). */
  scanFindings: DependencyFinding[];
  lockText: string;
  readFile: (path: string) => Promise<string | undefined>;
  fetchImpl: FetchLike;
}): Promise<NpmLockfilePatch> {
  const { finding } = params;
  const pkg = pkgOf(finding);
  if (!pkg.name || !pkg.version) return refuse("The finding does not name the installed package and version.");
  if (!pkg.fixedVersion || !parseVersion(pkg.fixedVersion)) {
    return refuse(`No stable fixed release of ${pkg.name} is published for ${finding.ruleId}.`);
  }
  const related = params.scanFindings.filter((f) => {
    const p = pkgOf(f);
    return f.filePath === finding.filePath && isNpmLockfileFinding(f) && p.name === pkg.name && p.version === pkg.version && p.fixedVersion && parseVersion(p.fixedVersion);
  });
  const targets = [finding, ...related.filter((f) => f.fingerprint !== finding.fingerprint)];
  const toVersion = targets.map((f) => pkgOf(f).fixedVersion!).reduce((a, b) => (compareVersions(a, b) >= 0 ? a : b));

  const dir = finding.filePath.includes("/") ? finding.filePath.slice(0, finding.filePath.lastIndexOf("/") + 1) : "";
  const manifestPath = `${dir}package.json`;
  const manifestText = await params.readFile(manifestPath);
  if (manifestText === undefined) return refuse(`${manifestPath} could not be read at the scanned commit.`);
  const registryManifest = await fetchNpmVersionManifest(pkg.name, toVersion, params.fetchImpl);
  const plan = planNpmUpgrade({ manifestText, lockText: params.lockText, name: pkg.name, fromVersion: pkg.version, toVersion, registryManifest });

  const ids = targets.map((f) => f.ruleId);
  const pruned = plan.removed.length ? ` npm no longer needs ${plan.removed.length} package(s), which are removed from the lockfile as npm would.` : "";
  return {
    files: [
      { path: manifestPath, before: manifestText, after: plan.manifestText },
      { path: finding.filePath, before: params.lockText, after: plan.lockText },
    ],
    patchSummary: `Upgrade ${pkg.name} ${pkg.version} → ${toVersion} in ${manifestPath} and ${finding.filePath} (fixes ${ids.length} advisor${ids.length === 1 ? "y" : "ies"})`,
    reason:
      `${toVersion} is the lowest ${pkg.name} release that fixes all ${ids.length} advisor${ids.length === 1 ? "y" : "ies"} reported for ${pkg.version} in this scan (${ids.join(", ")}). ` +
      `The declared range changes from "${plan.oldSpec}" to "${plan.newSpec}", and the lockfile entry uses the npm registry's published tarball and integrity for ${toVersion}.${pruned} ` +
      `The result is identical to running npm install ${pkg.name}@${toVersion} --package-lock-only.`,
    findingFingerprints: targets.map((f) => f.fingerprint),
  };
}
