import { describe, it, expect } from "vitest";
import { assertApprovedUrl, safeFetch } from "@/server/github";
import { RetrievalError } from "@/server/errors";

describe("assertApprovedUrl", () => {
  it("allows api.github.com and codeload.github.com", () => {
    expect(assertApprovedUrl("https://api.github.com/repos/owner/repo").hostname).toBe("api.github.com");
    expect(assertApprovedUrl("https://codeload.github.com/owner/repo/legacy.tar.gz/main").hostname).toBe("codeload.github.com");
  });

  it("rejects non-approved hosts and protocols", () => {
    expect(() => assertApprovedUrl("http://api.github.com/repos/owner/repo")).toThrow(RetrievalError);
    expect(() => assertApprovedUrl("https://github.com/repos/owner/repo")).toThrow(RetrievalError);
    expect(() => assertApprovedUrl("https://evil.com/")).toThrow(RetrievalError);
    expect(() => assertApprovedUrl("https://127.0.0.1:8000/")).toThrow(RetrievalError);
    expect(() => assertApprovedUrl("https://api.github.com:8443/repos/owner/repo")).toThrow(RetrievalError);
    expect(() => assertApprovedUrl("https://user:pass@api.github.com/")).toThrow(RetrievalError);
  });
});

describe("safeFetch redirect enforcement", () => {
  it("rejects redirect to an external/unapproved host", async () => {
    const mockFetch = async (url: string) => {
      if (url.startsWith("https://api.github.com/repos/owner/repo/tarball")) {
        return new Response(null, {
          status: 302,
          headers: { location: "https://attacker.evil.com/payload.tar.gz" },
        });
      }
      return new Response("ok", { status: 200 });
    };

    const controller = new AbortController();
    await expect(
      safeFetch(mockFetch as never, "https://api.github.com/repos/owner/repo/tarball", {}, controller.signal),
    ).rejects.toThrow(RetrievalError);
  });

  it("allows redirect to approved codeload.github.com", async () => {
    const mockFetch = async (url: string) => {
      if (url.startsWith("https://api.github.com/repos/owner/repo/tarball")) {
        return new Response(null, {
          status: 302,
          headers: { location: "https://codeload.github.com/owner/repo/legacy.tar.gz/ref" },
        });
      }
      return new Response("tarball-bytes", { status: 200 });
    };

    const controller = new AbortController();
    const res = await safeFetch(
      mockFetch as never,
      "https://api.github.com/repos/owner/repo/tarball",
      {},
      controller.signal,
    );
    expect(res.status).toBe(200);
    expect(await res.text()).toBe("tarball-bytes");
  });

  it("rejects too many redirects", async () => {
    const mockFetch = async () => {
      return new Response(null, {
        status: 302,
        headers: { location: "https://api.github.com/redirect-loop" },
      });
    };

    const controller = new AbortController();
    await expect(
      safeFetch(mockFetch as never, "https://api.github.com/start", {}, controller.signal),
    ).rejects.toThrow("too_many_redirects");
  });
});
