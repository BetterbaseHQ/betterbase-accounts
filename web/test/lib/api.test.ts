import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// Mock fetch and localStorage
const mockFetch = vi.fn();
const mockLocalStorage = {
  getItem: vi.fn(),
  setItem: vi.fn(),
  removeItem: vi.fn(),
};

vi.stubGlobal("fetch", mockFetch);
vi.stubGlobal("localStorage", mockLocalStorage);

// Import after mocking
const { api } = await import("@/lib/api");

describe("API client", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockLocalStorage.getItem.mockReturnValue(null);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe("sendVerificationCode", () => {
    it("sends verification code request", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        text: async () => "",
      });

      await api.sendVerificationCode("test@example.com", "registration", "cap-token");

      expect(mockFetch).toHaveBeenCalledWith("/v1/accounts/verify/send", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email: "test@example.com",
          purpose: "registration",
          cap_token: "cap-token",
        }),
      });
    });

    it("throws on error response", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 400,
        text: async () => JSON.stringify({ error: "Invalid email" }),
      });

      await expect(api.sendVerificationCode("invalid", "registration")).rejects.toThrow(
        "Invalid email",
      );
    });
  });

  describe("confirmVerificationCode", () => {
    it("confirms verification code", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        text: async () => JSON.stringify({ verification_token: "vt-123" }),
      });

      const result = await api.confirmVerificationCode(
        "test@example.com",
        "123456",
        "registration",
      );

      expect(result).toEqual({ verification_token: "vt-123" });
    });
  });

  describe("registerInit", () => {
    it("sends registration init request", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        text: async () =>
          JSON.stringify({ opaque_response: "resp", state_token: "st-123", user_id: "u-123" }),
      });

      const result = await api.registerInit(
        "user",
        "test@example.com",
        "opaque-req",
        "vt-123",
        "cap",
      );

      expect(result).toEqual({ opaque_response: "resp", state_token: "st-123", user_id: "u-123" });
    });
  });

  describe("registerFinalize", () => {
    it("sends registration finalize request with wrapped root key", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        text: async () => JSON.stringify({ auth_token: "at-123", user_id: "u-123" }),
      });

      const result = await api.registerFinalize("st-123", "opaque-record", "wmk");

      expect(result).toEqual({ auth_token: "at-123", user_id: "u-123" });
      const call = mockFetch.mock.calls[0];
      const body = JSON.parse(call[1].body);
      expect(body.wrapped_root_key).toBe("wmk");
    });
  });

  describe("loginInit", () => {
    it("sends login init request", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        text: async () => JSON.stringify({ opaque_ke2: "ke2", login_token: "lt-123" }),
      });

      const result = await api.loginInit("user", "ke1", "cap");

      expect(result).toEqual({ opaque_ke2: "ke2", login_token: "lt-123" });
    });
  });

  describe("loginFinalize", () => {
    it("sends login finalize request", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        text: async () => JSON.stringify({ auth_token: "at-123", user_id: "u-123" }),
      });

      const result = await api.loginFinalize("lt-123", "ke3");

      expect(result).toEqual({ auth_token: "at-123", user_id: "u-123" });
    });
  });

  describe("Authenticated endpoints", () => {
    beforeEach(() => {
      mockLocalStorage.getItem.mockReturnValue("auth-token-123");
    });

    describe("oauthConsent", () => {
      it("sends OAuth consent with auth token", async () => {
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: async () => ({ redirect_uri: "http://localhost/callback" }),
        });

        const result = await api.oauthConsent("state-123", true, "keys-jwe", "thumbprint");

        expect(result).toEqual({ redirect_uri: "http://localhost/callback" });
        expect(mockFetch).toHaveBeenCalledWith(
          "/oauth/consent",
          expect.objectContaining({
            headers: expect.objectContaining({
              Authorization: "Bearer auth-token-123",
            }),
          }),
        );
      });

      it("sends OAuth consent denial", async () => {
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: async () => ({ redirect_uri: "http://localhost/callback" }),
        });

        await api.oauthConsent("state-123", false);

        const call = mockFetch.mock.calls[0];
        const body = JSON.parse(call[1].body);
        expect(body.approved).toBe(false);
      });
    });

    describe("getRootKey", () => {
      it("gets wrapped root key", async () => {
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: async () => ({ wrapped_root_key: "wmk-base64" }),
        });

        const result = await api.getRootKey();

        expect(result).toEqual({ wrapped_root_key: "wmk-base64" });
      });
    });

    describe("setRootKey", () => {
      it("sets wrapped root key", async () => {
        mockFetch.mockResolvedValueOnce({
          ok: true,
          status: 204,
          json: async () => undefined,
        });

        await api.setRootKey("wmk-base64");

        const call = mockFetch.mock.calls[0];
        expect(call[1].method).toBe("PUT");
        expect(JSON.parse(call[1].body)).toEqual({ wrapped_root_key: "wmk-base64" });
      });
    });

    describe("getGrantWrappedKeys", () => {
      it("gets grant wrapped keys", async () => {
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: async () => ({
            grants: [{ grant_id: "g-1", client_id: "c-1", wrapped_scoped_key: "wsk" }],
          }),
        });

        const result = await api.getGrantWrappedKeys();

        expect(result.grants).toHaveLength(1);
      });
    });

    describe("updateGrantWrappedKeys", () => {
      it("updates grant wrapped keys", async () => {
        mockFetch.mockResolvedValueOnce({
          ok: true,
          status: 204,
          json: async () => undefined,
        });

        await api.updateGrantWrappedKeys([{ grant_id: "g-1", wrapped_scoped_key: "wsk" }]);

        const call = mockFetch.mock.calls[0];
        expect(call[1].method).toBe("PUT");
      });
    });

    describe("rotateRootKey", () => {
      it("rotates root key with grants", async () => {
        mockFetch.mockResolvedValueOnce({
          ok: true,
          status: 204,
          json: async () => undefined,
        });

        await api.rotateRootKey(
          "new-wmk",
          [{ grant_id: "g-1", wrapped_scoped_key: "wsk" }],
          "recovery-blob",
        );

        const call = mockFetch.mock.calls[0];
        const body = JSON.parse(call[1].body);
        expect(body.wrapped_root_key).toBe("new-wmk");
        expect(body.recovery_blob).toBe("recovery-blob");
      });
    });

    describe("storeRecoveryBlob", () => {
      it("stores recovery blob", async () => {
        mockFetch.mockResolvedValueOnce({
          ok: true,
          status: 204,
          json: async () => undefined,
        });

        await api.storeRecoveryBlob('{"version":2}');

        const call = mockFetch.mock.calls[0];
        expect(JSON.parse(call[1].body)).toEqual({ blob: '{"version":2}' });
      });
    });

    describe("getRecoveryBlob", () => {
      it("gets recovery blob with verification token", async () => {
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: async () => ({ blob: '{"version":2}' }),
        });

        const result = await api.getRecoveryBlob("test@example.com", "vt-123");

        expect(result).toEqual({ blob: '{"version":2}' });
        const call = mockFetch.mock.calls[0];
        expect(call[0]).toBe("/v1/accounts/recovery-blob/fetch");
        expect(call[1].method).toBe("POST");
        expect(call[1].headers).toMatchObject({
          Authorization: "Bearer vt-123",
          "Content-Type": "application/json",
        });
        expect(JSON.parse(call[1].body)).toEqual({
          email: "test@example.com",
        });
      });
    });

    describe("passwordChangeInit", () => {
      it("starts password change", async () => {
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: async () => ({ opaque_ke2: "ke2", login_token: "lt-123" }),
        });

        const result = await api.passwordChangeInit("user", "ke1");

        expect(result).toEqual({ opaque_ke2: "ke2", login_token: "lt-123" });
      });
    });

    describe("passwordChangeVerify", () => {
      it("verifies password change", async () => {
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: async () => ({ opaque_response: "resp", state_token: "st-123" }),
        });

        const result = await api.passwordChangeVerify("lt-123", "ke3", "opaque-req");

        expect(result).toEqual({ opaque_response: "resp", state_token: "st-123" });
      });
    });

    describe("passwordChangeComplete", () => {
      it("completes password change", async () => {
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: async () => ({ auth_token: "at-123", user_id: "u-123" }),
        });

        const result = await api.passwordChangeComplete("st-123", "record", "wmk");

        expect(result).toEqual({ auth_token: "at-123", user_id: "u-123" });
      });
    });
  });

  describe("Error handling", () => {
    it("throws when response body is empty and a body is required", async () => {
      mockLocalStorage.getItem.mockReturnValue("auth-token-123");

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        text: async () => "",
      });

      await expect(api.getGrantWrappedKeys()).rejects.toThrow("Empty response body");
    });

    it("extracts error message from JSON response", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 400,
        text: async () => JSON.stringify({ error: "Bad request" }),
      });

      await expect(api.sendVerificationCode("test@example.com", "registration")).rejects.toThrow(
        "Bad request",
      );
    });

    it("uses status code when no error message", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 500,
        text: async () => "",
      });

      await expect(api.sendVerificationCode("test@example.com", "registration")).rejects.toThrow(
        "Request failed (500)",
      );
    });

    it("uses response text when not JSON", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 500,
        text: async () => "Internal Server Error",
      });

      await expect(api.sendVerificationCode("test@example.com", "registration")).rejects.toThrow(
        "Internal Server Error",
      );
    });

    it("extracts error from OAuth errors", async () => {
      mockLocalStorage.getItem.mockReturnValue("token");

      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 400,
        text: async () =>
          JSON.stringify({ error: "invalid_request", error_description: "Missing parameter" }),
      });

      // The error field is extracted first
      await expect(api.oauthConsent("state", true)).rejects.toThrow("invalid_request");
    });

    it("extracts error_description when error is not present", async () => {
      mockLocalStorage.getItem.mockReturnValue("token");

      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 400,
        text: async () => JSON.stringify({ error_description: "Missing parameter" }),
      });

      await expect(api.oauthConsent("state", true)).rejects.toThrow("Missing parameter");
    });
  });

  describe("Recovery endpoints", () => {
    it("calls recoverInit", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        text: async () =>
          JSON.stringify({ opaque_response: "resp", state_token: "st-123", user_id: "u-123" }),
      });

      const result = await api.recoverInit("test@example.com", "opaque-req", "vt-123", "cap");

      expect(result).toEqual({ opaque_response: "resp", state_token: "st-123", user_id: "u-123" });
    });

    it("calls recoverFinalize with wrapped root key", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        text: async () => JSON.stringify({ auth_token: "at-123", user_id: "u-123" }),
      });

      const result = await api.recoverFinalize("st-123", "record", "wmk", "new-blob");

      expect(result).toEqual({ auth_token: "at-123", user_id: "u-123" });
      const call = mockFetch.mock.calls[0];
      const body = JSON.parse(call[1].body);
      expect(body.wrapped_root_key).toBe("wmk");
      expect(body.new_blob).toBe("new-blob");
    });
  });

  describe("getGrantKeypairBlob", () => {
    it("gets grant keypair blob", async () => {
      mockLocalStorage.getItem.mockReturnValue("token");
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ app_keypair_blob: "blob", wrapped_scoped_key: "wsk" }),
      });

      const result = await api.getGrantKeypairBlob("client-123");

      expect(result).toEqual({ app_keypair_blob: "blob", wrapped_scoped_key: "wsk" });
      expect(mockFetch).toHaveBeenCalledWith(
        "/oauth/grant-keypair?client_id=client-123",
        expect.objectContaining({ method: "GET" }),
      );
    });
  });
});
