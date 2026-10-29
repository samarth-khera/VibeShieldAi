import type { FetchLike } from "../github";
import { validateUnifiedDiff } from "./patch";
import { applyDiffStrict, DiffApplyError } from "./strict-apply";

export type PrFailureCode =
  | "credential_invalid"
  | "access_denied"
  | "repository_not_found"
  | "repository_mismatch"
  | "rate_limited"
  | "commit_not_found"
  | "unsafe_target"
  | "patch_conflict"
  | "branch_conflict"
  | "github_error"
  | "network_error"
  | "not_confirmed";

/** Steps of publishing a verified fix, persisted while they run so the UI can show real progress. */
export type PrStep = "checking_repository" | "creating_commit" | "pushing_branch" | "creating_pull_request" | "confirming";

/** Persisted in Remediation.approvedOperations.pullRequest and returned to the UI. */
export type PullRequestState = {
  /** "in_progress" is stored while the steps run; the final state replaces it. */
  status: "in_progress" | "created" | "exists" | "failed";
  step?: PrStep;
  code?: PrFailureCode;
  message: string;
  branch: string;
  baseBranch?: string;
  headSha?: string;
  number?: number;
  url?: string;
  state?: "open" | "closed" | "merged";
  /** The default branch has commits after the scanned commit; the PR still targets it. */
  baseAdvanced?: boolean;
  /** GitHub user whose authorization opened (or tried to open) the PR, via the VibeShield app. */
  openedBy?: { githubUserId: number; login: string };
  /** The fix commit exactly as GitHub recorded it (never client-supplied). */
  commit?: CommitAttribution;
  /** The pull request's author as GitHub reports it. */
  prAuthor?: string;
  at: string;
};

/**
 * Author/committer as GitHub's commit metadata reports them. VibeShield never sends an author or
 * committer, so GitHub fills both from the user whose token created the commit. Email addresses
 * are not stored; only whether GitHub used the user's private noreply address.
 */
export type CommitAttribution = {
  sha: string;
  url?: string;
  authorName?: string;
  committerName?: string;
  authorEmailIsNoreply?: boolean;
  /** GitHub's signature verification of the commit. */
  verified?: boolean;
  verificationReason?: string;
  /** GitHub accounts GitHub associates with the commit's author and committer. */
  authorLogin?: string;
  committerLogin?: string;
};

function attributionOf(sha: string, json: Record<string, unknown>): CommitAttribution {
  const person = (v: unknown) => (v && typeof v === "object" ? (v as { name?: unknown; email?: unknown }) : {});
  const author = person(json.author);
  const committer = person(json.committer);
  const verification = (json.verification ?? {}) as { verified?: unknown; reason?: unknown };
  const str = (v: unknown) => (typeof v === "string" ? v.slice(0, 120) : undefined);
  return {
    sha,
    url: str(json.html_url),
    authorName: str(author.name),
    committerName: str(committer.name),
    authorEmailIsNoreply: typeof author.email === "string" ? /@users\.noreply\.github\.com$/i.test(author.email) : undefined,
    verified: typeof verification.verified === "boolean" ? verification.verified : undefined,
    verificationReason: str(verification.reason),
  };
}

/** One branch per remediation, so retries and double clicks converge on the same branch and PR. */
export function remediationBranchName(scanJobId: string, remediationId: string): string {
  const slug = (s: string, n: number) => s.replace(/[^a-zA-Z0-9]/g, "").slice(0, n).toLowerCase();
  // The full remediation ID: two remediations never share a branch.
  return `vibeshield/fix-${slug(scanJobId, 10)}-${slug(remediationId, 32)}`;
}

export type CreatePrParams = {
  owner: string;
  repo: string;
  /** Immutable scanned commit; the fix commit's only parent. */
  commitSha: string;
  scanJobId: string;
  remediationId: string;
  unifiedDiff: string;
  title: string;
  body: string;
  /** The requesting user's own GitHub App user-to-server token. */
  token: string;
  /** GitHub repository ID recorded for the scan; the live repository must have the same ID. */
  expectedRepoId?: number;
  fetchImpl?: FetchLike;
  timeoutMs?: number;
  /** Called before each step; the caller persists it so progress is visible and survives reloads. */
  onProgress?: (step: PrStep) => Promise<void> | void;
};

const MESSAGES: Record<PrFailureCode, string> = {
  credential_invalid: "GitHub rejected your authorization (expired or revoked). No branch or pull request was created.",
  access_denied: "GitHub refused the write with your authorization. No branch or pull request was created.",
  repository_not_found: "The repository was not found or is not visible to your GitHub authorization.",
  repository_mismatch: "The repository on GitHub no longer matches the scanned repository (renamed or transferred).",
  rate_limited: "GitHub API rate limit reached. Try again later.",
  commit_not_found: "The scanned commit no longer exists on GitHub, so the verified patch cannot be committed.",
  unsafe_target: "A patched path is not a regular text file at the scanned commit, so it was not committed.",
  patch_conflict: "The verified patch no longer applies to the scanned commit's files. Nothing was committed.",
  branch_conflict:
    "The remediation branch already exists with different content. It was left untouched; no pull request was opened.",
  github_error: "GitHub rejected the request.",
  network_error: "Could not reach the GitHub API. Nothing was confirmed; retrying is safe.",
  not_confirmed:
    "GitHub accepted the request, but reading the branch, commit or pull request back did not match. It is not reported as created; retrying is safe.",
};

class PrError extends Error {
  constructor(
    readonly code: PrFailureCode,
    detail?: string,
  ) {
    super(detail ? `${MESSAGES[code]} (${detail})` : MESSAGES[code]);
  }
}

type GhResponse = { status: number; json: Record<string, unknown> & { message?: string }; headers: Headers };

/**
 * Commits an already-verified patch onto a new branch based on the scanned commit and opens a pull
 * request against the repository's default branch. Never writes to an existing branch it did not
 * create with identical content, never touches the default branch and never merges.
 */
export async function createRemediationPullRequest(params: CreatePrParams): Promise<PullRequestState> {
  const branch = remediationBranchName(params.scanJobId, params.remediationId);
  const at = () => new Date().toISOString();
  const failed = (err: PrError): PullRequestState => ({
    status: "failed",
    code: err.code,
    message: err.message,
    branch,
    at: at(),
  });

  const token = params.token?.trim();
  if (!token) return failed(new PrError("credential_invalid"));
  const fullName = `${params.owner}/${params.repo}`;

  const fetchFn = params.fetchImpl ?? fetch;
  const base = `https://api.github.com/repos/${encodeURIComponent(params.owner)}/${encodeURIComponent(params.repo)}`;
  const gh = async (method: string, path: string, body?: unknown): Promise<GhResponse> => {
    let res: Response;
    try {
      res = await fetchFn(`${base}${path}`, {
        method,
        headers: {
          Authorization: `Bearer ${token}`,
          Accept: "application/vnd.github+json",
          "User-Agent": "VibeShield-AI-Remediation",
          "X-GitHub-Api-Version": "2022-11-28",
          ...(body ? { "Content-Type": "application/json" } : {}),
        },
        body: body ? JSON.stringify(body) : undefined,
        signal: AbortSignal.timeout(params.timeoutMs ?? 15_000),
      });
    } catch {
      throw new PrError("network_error");
    }
    const json = ((await res.json().catch(() => ({}))) ?? {}) as GhResponse["json"];
    if (res.status === 401) throw new PrError("credential_invalid");
    if (res.status === 429 || (res.status === 403 && res.headers.get("x-ratelimit-remaining") === "0")) {
      throw new PrError("rate_limited");
    }
    if (res.status === 403 && /rate limit/i.test(String(json.message ?? ""))) throw new PrError("rate_limited");
    if (res.status >= 500) throw new PrError("github_error", `HTTP ${res.status}`);
    return { status: res.status, json, headers: res.headers };
  };
  const ghMessage = (r: GhResponse) => String(r.json.message ?? `HTTP ${r.status}`).slice(0, 200);
  const progress = async (step: PrStep) => {
    await params.onProgress?.(step);
  };

  try {
    const validation = validateUnifiedDiff(params.unifiedDiff);
    if (!validation.valid) throw new PrError("patch_conflict", validation.error);

    // 1. The credential can see and push to exactly the scanned repository.
    await progress("checking_repository");
    const repoRes = await gh("GET", "");
    if (repoRes.status === 404 || repoRes.status === 403) throw new PrError("repository_not_found");
    if (repoRes.status !== 200) throw new PrError("github_error", ghMessage(repoRes));
    const repoInfo = repoRes.json as {
      id?: number;
      full_name?: string;
      default_branch?: string;
      archived?: boolean;
      permissions?: { push?: boolean };
    };
    if (repoInfo.full_name?.toLowerCase() !== fullName.toLowerCase()) throw new PrError("repository_mismatch");
    if (params.expectedRepoId !== undefined && repoInfo.id !== params.expectedRepoId) throw new PrError("repository_mismatch");
    if (repoInfo.archived) throw new PrError("access_denied", "repository is archived");
    if (repoInfo.permissions && repoInfo.permissions.push === false) throw new PrError("access_denied");
    const baseBranch = repoInfo.default_branch;
    if (!baseBranch) throw new PrError("github_error", "repository has no default branch");

    // 2. Rebuild the patched files from the scanned commit itself.
    const commitRes = await gh("GET", `/git/commits/${params.commitSha}`);
    if (commitRes.status !== 200) throw new PrError("commit_not_found");
    const baseTree = (commitRes.json.tree as { sha: string }).sha;

    const originals = new Map<string, string>();
    const modes = new Map<string, string>();
    const treeCache = new Map<string, { path: string; type: string; mode: string; sha: string }[]>();
    const listTree = async (sha: string) => {
      const cached = treeCache.get(sha);
      if (cached) return cached;
      const r = await gh("GET", `/git/trees/${sha}`);
      if (r.status !== 200) throw new PrError("github_error", ghMessage(r));
      const entries = (r.json.tree ?? []) as { path: string; type: string; mode: string; sha: string }[];
      treeCache.set(sha, entries);
      return entries;
    };
    for (const file of validation.affectedFiles) {
      let treeSha = baseTree;
      const parts = file.split("/");
      let entry: { type: string; mode: string; sha: string } | undefined;
      for (let i = 0; i < parts.length; i++) {
        entry = (await listTree(treeSha)).find((e) => e.path === parts[i]);
        if (!entry) throw new PrError("patch_conflict", `${file} is not present at the scanned commit`);
        if (i < parts.length - 1) {
          if (entry.type !== "tree") throw new PrError("unsafe_target", file);
          treeSha = entry.sha;
        }
      }
      // Regular files only: symlinks (120000) and submodules (160000) are refused.
      if (!entry || entry.type !== "blob" || (entry.mode !== "100644" && entry.mode !== "100755")) {
        throw new PrError("unsafe_target", file);
      }
      const blob = await gh("GET", `/git/blobs/${entry.sha}`);
      if (blob.status !== 200 || blob.json.encoding !== "base64") throw new PrError("github_error", `blob for ${file}`);
      const bytes = Buffer.from(String(blob.json.content), "base64");
      const text = bytes.toString("utf8");
      if (!Buffer.from(text, "utf8").equals(bytes)) throw new PrError("unsafe_target", `${file} is not UTF-8 text`);
      originals.set(file, text);
      modes.set(file, entry.mode);
    }

    let patched: Map<string, string>;
    try {
      patched = applyDiffStrict(originals, params.unifiedDiff);
    } catch (err) {
      throw new PrError("patch_conflict", err instanceof DiffApplyError ? err.message : undefined);
    }

    // 3. Trees are content-addressed, so the same verified patch always yields the same tree SHA.
    await progress("creating_commit");
    const treeRes = await gh("POST", "/git/trees", {
      base_tree: baseTree,
      tree: [...patched].map(([path, content]) => ({ path, mode: modes.get(path), type: "blob", content })),
    });
    if (treeRes.status === 404 || treeRes.status === 403) throw new PrError("access_denied");
    if (treeRes.status !== 201) throw new PrError("github_error", ghMessage(treeRes));
    const newTree = String(treeRes.json.sha);

    // 4. Reuse our own branch if a previous attempt created it with this exact content.
    let commitInfo: CommitAttribution | undefined;
    const existingHead = async (): Promise<string | null> => {
      const ref = await gh("GET", `/git/ref/heads/${branch}`);
      if (ref.status === 404) return null;
      if (ref.status !== 200) throw new PrError("github_error", ghMessage(ref));
      const sha = String((ref.json.object as { sha: string }).sha);
      const head = await gh("GET", `/git/commits/${sha}`);
      const parents = (head.json.parents ?? []) as { sha: string }[];
      const sameContent =
        head.status === 200 &&
        (head.json.tree as { sha: string }).sha === newTree &&
        parents.length === 1 &&
        parents[0].sha === params.commitSha;
      if (!sameContent) throw new PrError("branch_conflict");
      commitInfo = attributionOf(sha, head.json);
      return sha;
    };

    let headSha = await existingHead();
    if (!headSha) {
      const commit = await gh("POST", "/git/commits", {
        message: `${params.title}\n\nVerified by VibeShield AI security rescan (scan ${params.scanJobId}, remediation ${params.remediationId}).`,
        tree: newTree,
        parents: [params.commitSha],
      });
      if (commit.status === 404 || commit.status === 403) throw new PrError("access_denied");
      if (commit.status !== 201) throw new PrError("github_error", ghMessage(commit));
      const commitSha = String(commit.json.sha);
      await progress("pushing_branch");
      const ref = await gh("POST", "/git/refs", { ref: `refs/heads/${branch}`, sha: commitSha });
      if (ref.status === 201) {
        headSha = commitSha;
        commitInfo = attributionOf(commitSha, commit.json);
      }
      else if (ref.status === 422) headSha = await existingHead(); // a concurrent attempt won the race
      else if (ref.status === 404 || ref.status === 403) throw new PrError("access_denied");
      else throw new PrError("github_error", ghMessage(ref));
      if (!headSha) throw new PrError("github_error", "branch was not created");
    }

    // The PR always targets the default branch; report (not hide) that it moved after the scan.
    const baseRef = await gh("GET", `/git/ref/heads/${baseBranch}`);
    const baseAdvanced = baseRef.status === 200 && String((baseRef.json.object as { sha?: string })?.sha) !== params.commitSha;

    // 5. One pull request per remediation branch, whatever its state.
    await progress("creating_pull_request");
    const findExisting = async (): Promise<PullRequestState | null> => {
      const list = await gh("GET", `/pulls?head=${encodeURIComponent(`${params.owner}:${branch}`)}&state=all&per_page=5`);
      if (list.status !== 200) return null;
      const prs = list.json as unknown as { number: number; html_url: string; state: string; merged_at: string | null; base: { ref: string } }[];
      const pr = Array.isArray(prs) ? prs[0] : undefined;
      if (!pr) return null;
      const state = pr.merged_at ? "merged" : pr.state === "open" ? "open" : "closed";
      return {
        status: "exists",
        message: `A pull request for this remediation already exists (${state}).`,
        branch,
        baseBranch: pr.base.ref,
        headSha: headSha!,
        number: pr.number,
        url: pr.html_url,
        state,
        baseAdvanced,
        commit: commitInfo,
        at: at(),
      };
    };
    // 6. Report only what GitHub shows when read back: branch → commit, commit content and parent,
    //    and the pull request's head, base and author.
    const confirm = async (state: PullRequestState): Promise<PullRequestState> => {
      await progress("confirming");
      const ref = await gh("GET", `/git/ref/heads/${branch}`);
      if (ref.status !== 200 || String((ref.json.object as { sha?: string } | undefined)?.sha) !== headSha) {
        throw new PrError("not_confirmed", "branch");
      }
      const gitCommit = await gh("GET", `/git/commits/${headSha}`);
      const parents = (gitCommit.json.parents ?? []) as { sha: string }[];
      if (gitCommit.status !== 200 || (gitCommit.json.tree as { sha?: string } | undefined)?.sha !== newTree || parents.length !== 1 || parents[0].sha !== params.commitSha) {
        throw new PrError("not_confirmed", "commit");
      }
      const prRes = await gh("GET", `/pulls/${state.number}`);
      const pr = prRes.json as { head?: { ref?: string; sha?: string }; base?: { ref?: string }; user?: { login?: string }; html_url?: string; state?: string; merged_at?: string | null };
      if (prRes.status !== 200 || pr.head?.ref !== branch || pr.head?.sha !== headSha || pr.base?.ref !== baseBranch) {
        throw new PrError("not_confirmed", "pull request");
      }
      const restCommit = await gh("GET", `/commits/${headSha}`);
      const login = (v: unknown) => (v && typeof v === "object" && typeof (v as { login?: unknown }).login === "string" ? String((v as { login: string }).login).slice(0, 39) : undefined);
      return {
        ...state,
        url: typeof pr.html_url === "string" ? pr.html_url : state.url,
        state: pr.merged_at ? "merged" : pr.state === "open" ? "open" : "closed",
        prAuthor: login(pr.user),
        commit: {
          ...attributionOf(headSha!, gitCommit.json),
          ...(commitInfo ?? {}),
          ...(restCommit.status === 200 ? { authorLogin: login(restCommit.json.author), committerLogin: login(restCommit.json.committer) } : {}),
        },
      };
    };

    const existing = await findExisting();
    if (existing) return await confirm(existing);

    const pr = await gh("POST", "/pulls", {
      title: params.title,
      head: branch,
      base: baseBranch,
      body: params.body,
      draft: false,
    });
    if (pr.status === 201) {
      return await confirm({
        status: "created",
        message: "Pull request created on GitHub.",
        branch,
        baseBranch,
        headSha,
        number: Number(pr.json.number),
        url: String(pr.json.html_url),
        state: "open",
        baseAdvanced,
        commit: commitInfo,
        at: at(),
      });
    }
    if (pr.status === 422) {
      const raced = await findExisting();
      if (raced) return await confirm(raced);
    }
    if (pr.status === 404 || pr.status === 403) throw new PrError("access_denied");
    throw new PrError("github_error", ghMessage(pr));
  } catch (err) {
    if (err instanceof PrError) return failed(err);
    return failed(new PrError("github_error"));
  }
}
