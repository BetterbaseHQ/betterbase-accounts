import { describe, it, expect } from "vitest";
import { cn, formatError } from "@/lib/utils";

describe("cn (className merger)", () => {
  it("merges class names", () => {
    expect(cn("foo", "bar")).toBe("foo bar");
  });

  it("handles conditional classes", () => {
    const shouldAppendBar = () => false;

    expect(cn("foo", shouldAppendBar() && "bar", "baz")).toBe("foo baz");
  });

  it("handles undefined values", () => {
    expect(cn("foo", undefined, "bar")).toBe("foo bar");
  });

  it("handles null values", () => {
    expect(cn("foo", null, "bar")).toBe("foo bar");
  });

  it("handles empty strings", () => {
    expect(cn("foo", "", "bar")).toBe("foo bar");
  });

  it("handles object syntax", () => {
    expect(cn({ foo: true, bar: false })).toBe("foo");
  });

  it("handles array syntax", () => {
    expect(cn(["foo", "bar"])).toBe("foo bar");
  });

  it("merges tailwind classes correctly", () => {
    // twMerge should handle conflicting classes
    expect(cn("p-4", "p-2")).toBe("p-2");
  });

  it("handles complex tailwind merging", () => {
    expect(cn("text-red-500", "text-blue-500")).toBe("text-blue-500");
  });

  it("preserves non-conflicting classes", () => {
    expect(cn("px-4", "py-2")).toBe("px-4 py-2");
  });
});

describe("formatError", () => {
  it("capitalizes first letter of error message", () => {
    expect(formatError(new Error("something went wrong"))).toBe("Something went wrong");
  });

  it("handles already capitalized messages", () => {
    expect(formatError(new Error("Already capitalized"))).toBe("Already capitalized");
  });

  it("uses fallback for non-Error values", () => {
    expect(formatError("string error")).toBe("An error occurred");
  });

  it("uses fallback for null", () => {
    expect(formatError(null)).toBe("An error occurred");
  });

  it("uses fallback for undefined", () => {
    expect(formatError(undefined)).toBe("An error occurred");
  });

  it("uses fallback for numbers", () => {
    expect(formatError(404)).toBe("An error occurred");
  });

  it("uses custom fallback when provided", () => {
    expect(formatError(null, "Custom fallback")).toBe("Custom fallback");
  });

  it("capitalizes custom fallback from error", () => {
    const err = new Error("custom error");
    expect(formatError(err, "Fallback")).toBe("Custom error");
  });

  it("handles single character error message", () => {
    expect(formatError(new Error("x"))).toBe("X");
  });

  it("handles empty error message", () => {
    expect(formatError(new Error(""))).toBe("");
  });

  it("handles error message with leading whitespace", () => {
    expect(formatError(new Error("  whitespace"))).toBe("  whitespace");
  });
});
