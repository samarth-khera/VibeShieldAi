import { describe, expect, it } from "vitest";
import { findFixedVersionForPackage } from "@/server/scanners/osv";

// Real range shapes from OSV (2026-10-30): one range per release line, not in version order.
const rgw5 = {
  id: "GHSA-rgw5-rvv9-x895",
  affected: [
    { package: { name: "brace-expansion", ecosystem: "npm" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "1.1.18" }] }] },
    { package: { name: "brace-expansion", ecosystem: "npm" }, ranges: [{ type: "SEMVER", events: [{ introduced: "2.0.0" }, { fixed: "2.1.4" }] }] },
    { package: { name: "brace-expansion", ecosystem: "npm" }, ranges: [{ type: "SEMVER", events: [{ introduced: "3.0.0" }, { fixed: "3.0.6" }] }] },
    { package: { name: "brace-expansion", ecosystem: "npm" }, ranges: [{ type: "SEMVER", events: [{ introduced: "4.0.0" }, { fixed: "5.0.9" }] }] },
  ],
};
const q2hr = {
  id: "GHSA-q2hr-2g5m-vwhr",
  affected: [
    { package: { name: "brace-expansion", ecosystem: "npm" }, ranges: [{ type: "SEMVER", events: [{ introduced: "4.0.0" }, { fixed: "5.0.12" }] }] },
    { package: { name: "brace-expansion", ecosystem: "npm" }, ranges: [{ type: "SEMVER", events: [{ introduced: "3.0.0" }, { fixed: "3.0.9" }] }] },
    { package: { name: "brace-expansion", ecosystem: "npm" }, ranges: [{ type: "SEMVER", events: [{ introduced: "2.0.0" }, { fixed: "2.1.7" }] }] },
    { package: { name: "brace-expansion", ecosystem: "npm" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "1.1.21" }] }] },
  ],
};

describe("OSV fixed version for the installed release line", () => {
  it("returns the fix of the range that contains the installed version", () => {
    expect(findFixedVersionForPackage(q2hr as never, "brace-expansion", "npm", "1.1.17")).toBe("1.1.21");
    expect(findFixedVersionForPackage(q2hr as never, "brace-expansion", "npm", "2.0.5")).toBe("2.1.7");
    expect(findFixedVersionForPackage(q2hr as never, "brace-expansion", "npm", "5.0.3")).toBe("5.0.12");
    expect(findFixedVersionForPackage(rgw5 as never, "brace-expansion", "npm", "1.1.17")).toBe("1.1.18");
    expect(findFixedVersionForPackage(rgw5 as never, "brace-expansion", "npm", "3.0.5")).toBe("3.0.6");
  });

  it("handles several ranges in one entry and prerelease bounds", () => {
    const multi = {
      id: "X",
      affected: [
        {
          package: { name: "pkg", ecosystem: "npm" },
          ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "2.2.0" }, { introduced: "3.0.0-alpha.1" }, { fixed: "3.0.0-alpha.2" }] }],
        },
      ],
    };
    expect(findFixedVersionForPackage(multi as never, "pkg", "npm", "2.0.2")).toBe("2.2.0");
    expect(findFixedVersionForPackage(multi as never, "pkg", "npm", "3.0.0-alpha.1")).toBe("3.0.0-alpha.2");
  });

  it("falls back to the first fixed release when the version is unknown or outside every range", () => {
    expect(findFixedVersionForPackage(q2hr as never, "brace-expansion", "npm")).toBe("5.0.12");
    expect(findFixedVersionForPackage(rgw5 as never, "brace-expansion", "npm", "9.9.9")).toBe("1.1.18");
    expect(findFixedVersionForPackage(rgw5 as never, "other-package", "npm", "1.0.0")).toBeNull();
  });
});
