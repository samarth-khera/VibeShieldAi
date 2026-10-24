import { describe, it, expect } from "vitest";
import { parseGithubRepoUrl } from "@/lib/github-url";

describe("parseGithubRepoUrl", () => {
  it("accepts valid standard GitHub repository URLs", () => {
    const res = parseGithubRepoUrl("https://github.com/facebook/react");
    expect(res.ok).toBe(true);
    if (res.ok) {
      expect(res.owner).toBe("facebook");
      expect(res.repo).toBe("react");
      expect(res.url).toBe("https://github.com/facebook/react");
    }
  });

  it("normalizes trailing slash and .git extension", () => {
    const res1 = parseGithubRepoUrl("https://github.com/vercel/next.js/");
    expect(res1.ok).toBe(true);
    if (res1.ok) {
      expect(res1.owner).toBe("vercel");
      expect(res1.repo).toBe("next.js");
      expect(res1.url).toBe("https://github.com/vercel/next.js");
    }

    const res2 = parseGithubRepoUrl("https://github.com/tailwindlabs/tailwindcss.git");
    expect(res2.ok).toBe(true);
    if (res2.ok) {
      expect(res2.owner).toBe("tailwindlabs");
      expect(res2.repo).toBe("tailwindcss");
      expect(res2.url).toBe("https://github.com/tailwindlabs/tailwindcss");
    }
  });

  it("accepts www.github.com", () => {
    const res = parseGithubRepoUrl("https://www.github.com/torvalds/linux");
    expect(res.ok).toBe(true);
    if (res.ok) {
      expect(res.owner).toBe("torvalds");
      expect(res.repo).toBe("linux");
      expect(res.url).toBe("https://github.com/torvalds/linux");
    }
  });

  it("rejects non-https protocols", () => {
    expect(parseGithubRepoUrl("http://github.com/owner/repo").ok).toBe(false);
    expect(parseGithubRepoUrl("git@github.com:owner/repo.git").ok).toBe(false);
    expect(parseGithubRepoUrl("ssh://git@github.com/owner/repo").ok).toBe(false);
    expect(parseGithubRepoUrl("ftp://github.com/owner/repo").ok).toBe(false);
  });

  it("rejects host spoofing and SSRF attempts", () => {
    expect(parseGithubRepoUrl("https://evil-github.com/owner/repo").ok).toBe(false);
    expect(parseGithubRepoUrl("https://github.com.evil.com/owner/repo").ok).toBe(false);
    expect(parseGithubRepoUrl("https://localhost/owner/repo").ok).toBe(false);
    expect(parseGithubRepoUrl("https://127.0.0.1/owner/repo").ok).toBe(false);
    expect(parseGithubRepoUrl("https://169.254.169.254/latest/meta-data").ok).toBe(false);
    expect(parseGithubRepoUrl("https://gitlab.com/owner/repo").ok).toBe(false);
  });

  it("rejects URLs with credentials, ports, queries or fragments", () => {
    expect(parseGithubRepoUrl("https://user:pass@github.com/owner/repo").ok).toBe(false);
    expect(parseGithubRepoUrl("https://github.com:8443/owner/repo").ok).toBe(false);
    expect(parseGithubRepoUrl("https://github.com/owner/repo?branch=main").ok).toBe(false);
    expect(parseGithubRepoUrl("https://github.com/owner/repo#readme").ok).toBe(false);
  });

  it("rejects path traversal, control chars and extra segments", () => {
    expect(parseGithubRepoUrl("https://github.com/owner/repo/tree/main").ok).toBe(false);
    expect(parseGithubRepoUrl("https://github.com/owner/../admin/secret").ok).toBe(false);
    expect(parseGithubRepoUrl("https://github.com/owner/repo\u0000").ok).toBe(false);
    expect(parseGithubRepoUrl("https://github.com/owner/repo%2Fextra").ok).toBe(false);
    expect(parseGithubRepoUrl("https://github.com/").ok).toBe(false);
    expect(parseGithubRepoUrl("https://github.com/onlyowner").ok).toBe(false);
    expect(parseGithubRepoUrl("").ok).toBe(false);
  });
});
