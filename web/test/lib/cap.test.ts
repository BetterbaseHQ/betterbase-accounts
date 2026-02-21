import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

interface CAPWidgetMock {
  solve(): Promise<{ token: string }>;
}

interface CapConstructorMock {
  new (_options: { apiEndpoint: string }): CAPWidgetMock;
}

interface WindowWithCap extends Window {
  Cap?: CapConstructorMock;
}

describe("CAP module", () => {
  const originalWindow = global.window;

  beforeEach(() => {
    vi.resetModules();
    // Reset window
    if (typeof global.window !== "undefined") {
      delete (global.window as WindowWithCap).Cap;
    }
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllEnvs();
    global.window = originalWindow;
  });

  describe("solveCAPChallenge", () => {
    it("returns empty string when CAP_KEY_ID is not configured", async () => {
      // Mock environment without CAP_KEY_ID
      vi.stubEnv("VITE_CAP_KEY_ID", "");

      const { solveCAPChallenge } = await import("@/lib/cap");
      const result = await solveCAPChallenge();

      expect(result).toBe("");
    });

    it("solves challenge when CAP is configured and available", async () => {
      vi.stubEnv("VITE_CAP_KEY_ID", "test-key-id");

      // Mock window.Cap using a class so `new` works correctly
      const mockSolve = vi.fn().mockResolvedValue({ token: "test-cap-token" });
      const mockCap = vi.fn().mockImplementation(function (this: CAPWidgetMock) {
        this.solve = mockSolve;
      }) as unknown as CapConstructorMock;

      global.window = {
        ...global.window,
        Cap: mockCap,
      } as Window & typeof globalThis;

      const { solveCAPChallenge } = await import("@/lib/cap");
      const result = await solveCAPChallenge();

      expect(result).toBe("test-cap-token");
      expect(mockCap).toHaveBeenCalledWith({ apiEndpoint: "/cap/test-key-id/" });
    });

    it("throws error when CAP script fails to solve", async () => {
      vi.stubEnv("VITE_CAP_KEY_ID", "test-key-id");

      const mockSolve = vi.fn().mockRejectedValue(new Error("Challenge failed"));
      const mockCap = vi.fn().mockImplementation(function (this: CAPWidgetMock) {
        this.solve = mockSolve;
      }) as unknown as CapConstructorMock;

      global.window = {
        ...global.window,
        Cap: mockCap,
      } as Window & typeof globalThis;

      const { solveCAPChallenge } = await import("@/lib/cap");

      await expect(solveCAPChallenge()).rejects.toThrow(
        "Verification challenge failed. Please try again.",
      );
    });

    it("throws error when Cap global is not available after script load", async () => {
      vi.stubEnv("VITE_CAP_KEY_ID", "test-key-id");

      global.window = {} as Window & typeof globalThis;

      const { solveCAPChallenge } = await import("@/lib/cap");

      // This will fail because we can't actually load the script in tests
      await expect(solveCAPChallenge()).rejects.toThrow(
        "Verification challenge failed. Please try again.",
      );
    });
  });
});
