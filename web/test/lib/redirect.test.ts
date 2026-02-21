import { describe, it, expect } from "vitest";
import { getSafeRedirect } from "@/lib/redirect";

describe("getSafeRedirect", () => {
  describe("valid redirects", () => {
    it("returns the path for valid relative URLs", () => {
      expect(getSafeRedirect("/dashboard")).toBe("/dashboard");
    });

    it("returns the path for nested paths", () => {
      expect(getSafeRedirect("/users/123/profile")).toBe("/users/123/profile");
    });

    it("returns the path for paths with query strings", () => {
      expect(getSafeRedirect("/dashboard?tab=settings")).toBe("/dashboard?tab=settings");
    });

    it("returns the path for paths with hash fragments", () => {
      expect(getSafeRedirect("/dashboard#section")).toBe("/dashboard#section");
    });

    it("handles URL-encoded paths", () => {
      expect(getSafeRedirect("%2Fdashboard")).toBe("/dashboard");
    });

    it("handles double-encoded paths", () => {
      // Double-encoded: %252F -> %2F after first decode -> still doesn't start with /
      expect(getSafeRedirect("%252Fdashboard")).toBe("/");
    });

    it("returns root for root path", () => {
      expect(getSafeRedirect("/")).toBe("/");
    });
  });

  describe("invalid redirects - returns fallback", () => {
    it("returns fallback for null input", () => {
      expect(getSafeRedirect(null)).toBe("/");
    });

    it("returns fallback for empty string", () => {
      expect(getSafeRedirect("")).toBe("/");
    });

    it("blocks absolute URLs with http", () => {
      expect(getSafeRedirect("http://evil.com/phish")).toBe("/");
    });

    it("blocks absolute URLs with https", () => {
      expect(getSafeRedirect("https://evil.com/phish")).toBe("/");
    });

    it("blocks protocol-relative URLs", () => {
      expect(getSafeRedirect("//evil.com/phish")).toBe("/");
    });

    it("blocks URLs with embedded protocol (encoded)", () => {
      expect(getSafeRedirect("/path/http://evil.com")).toBe("/");
    });

    it("blocks URLs with credentials", () => {
      expect(getSafeRedirect("/path/@evil.com")).toBe("/");
    });

    it("blocks URLs with encoded credentials", () => {
      expect(getSafeRedirect("%2Fpath%40evil.com")).toBe("/");
    });

    it("blocks javascript: URLs", () => {
      expect(getSafeRedirect("javascript:alert(1)")).toBe("/");
    });

    it("blocks data: URLs", () => {
      expect(getSafeRedirect("data:text/html,<script>alert(1)</script>")).toBe("/");
    });

    it("blocks relative URLs without leading slash", () => {
      expect(getSafeRedirect("dashboard")).toBe("/");
    });

    it("blocks backslash-based paths", () => {
      expect(getSafeRedirect("\\\\evil.com")).toBe("/");
    });

    it("blocks encoded protocol in path", () => {
      expect(getSafeRedirect("/path%3A%2F%2Fevil.com")).toBe("/");
    });
  });

  describe("edge cases", () => {
    it("handles paths with special characters", () => {
      expect(getSafeRedirect("/path/with-dash_and_underscore")).toBe(
        "/path/with-dash_and_underscore",
      );
    });

    it("handles paths with unicode", () => {
      expect(getSafeRedirect("/路径")).toBe("/路径");
    });

    it("handles paths with dots", () => {
      expect(getSafeRedirect("/path/../other")).toBe("/path/../other");
    });

    it("handles malformed URI encoding", () => {
      expect(getSafeRedirect("/path%ZZ")).toBe("/");
    });
  });
});
