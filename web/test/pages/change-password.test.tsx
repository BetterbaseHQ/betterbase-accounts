// @vitest-environment happy-dom
import { act } from "react";
import { createRoot } from "react-dom/client";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { beforeEach, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  completed: false,
  setAuth: vi.fn(),
  getRootKey: vi.fn(),
  unwrapRootKey: vi.fn(),
}));

vi.mock("@/contexts/auth-context", () => ({
  useAuth: () => ({
    authToken: "old-token",
    userId: "user",
    email: "user@example.test",
    setAuth: mocks.setAuth,
  }),
}));
vi.mock("@/lib/opaque", () => ({
  startLogin: async () => ({ clientLoginState: "login", ke1: "ke1" }),
  finishLogin: async () => ({ ke3: "ke3", exportKey: "old-export" }),
  startRegistration: async () => ({
    clientRegistrationState: "registration",
    registrationRequest: "request",
  }),
  finishRegistration: async () => ({ registrationRecord: "record", exportKey: "new-export" }),
}));
vi.mock("@/lib/crypto", () => ({
  base64UrlDecode: () => new Uint8Array(32),
  deriveRootKeyWrappingKey: async () => ({}),
  unwrapRootKey: mocks.unwrapRootKey,
  wrapRootKey: async () => new Uint8Array(41),
}));
vi.mock("@/lib/validation", () => ({
  validatePassword: () => ({ valid: true, score: 4, suggestions: [] }),
  getPasswordStrengthColor: () => "",
  getPasswordStrengthLabel: () => "Strong",
}));
vi.mock("@/lib/api", () => ({
  api: {
    passwordChangeInit: async () => ({ opaque_ke2: "ke2", login_token: "login-token" }),
    passwordChangeVerify: async () => ({ opaque_response: "response", state_token: "state-token" }),
    passwordChangeComplete: async () => {
      mocks.completed = true;
      return { auth_token: "new-token", user_id: "user" };
    },
    getRootKey: mocks.getRootKey,
  },
}));

const { ChangePasswordPage } = await import("@/pages/change-password");

beforeEach(() => {
  mocks.completed = false;
  vi.clearAllMocks();
  mocks.unwrapRootKey.mockReset();
});

function LoginDestination() {
  const { search } = useLocation();
  return <div data-testid="login">{new URLSearchParams(search).get("redirect")}</div>;
}

it.each(["none", "fetch", "unwrap"])(
  "preserves the replacement session after password change with failure: %s",
  async (failure) => {
    mocks.unwrapRootKey.mockResolvedValueOnce(new Uint8Array(32));
    if (failure === "unwrap") {
      mocks.unwrapRootKey.mockRejectedValueOnce(new Error("Unable to unwrap root"));
    } else {
      mocks.unwrapRootKey.mockResolvedValueOnce(new Uint8Array(32).fill(8));
    }
    mocks.getRootKey.mockImplementation(async (token?: string) => {
      if (mocks.completed && token !== "new-token")
        throw new Error("credentials changed, re-authenticate");
      if (mocks.completed) {
        expect(mocks.setAuth).toHaveBeenCalledWith(
          "new-token",
          "user",
          "user@example.test",
          null,
          null,
          null,
        );
        if (failure === "fetch") throw new Error("Network unavailable");
      }
      return {
        wrapped_root_key: btoa(mocks.completed ? "current-root" : "wrapped"),
        root_key_version: mocks.completed ? 8 : 0,
      };
    });
    const container = document.createElement("div");
    document.body.appendChild(container);
    const root = createRoot(container);
    try {
      await act(async () =>
        root.render(
          <MemoryRouter initialEntries={["/change-password"]}>
            <Routes>
              <Route path="/change-password" element={<ChangePasswordPage />} />
              <Route path="/recovery-setup" element={<div data-testid="recovery" />} />
              <Route path="/login" element={<LoginDestination />} />
            </Routes>
          </MemoryRouter>,
        ),
      );
      for (const [id, value] of [
        ["current-password", "old-password"],
        ["new-password", "new-password"],
        ["confirm-password", "new-password"],
      ]) {
        const input = container.querySelector<HTMLInputElement>(`#${id}`)!;
        await act(async () => {
          Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!.call(
            input,
            value,
          );
          input.dispatchEvent(new Event("input", { bubbles: true }));
        });
      }
      await act(async () => {
        container
          .querySelector("form")!
          .dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
      });
      expect(mocks.getRootKey).toHaveBeenLastCalledWith("new-token");
      if (failure !== "none") {
        expect(mocks.setAuth).toHaveBeenCalledTimes(1);
        expect(container.textContent).toContain("Your password was changed successfully");
        expect(container.textContent).not.toContain("Failed to change password");
        expect(container.querySelector("form")).toBeNull();
        await act(async () => container.querySelector("button")!.click());
        expect(container.querySelector('[data-testid="login"]')?.textContent).toBe(
          "/recovery-setup?reset=true",
        );
        return;
      }
      expect(mocks.setAuth).toHaveBeenCalledWith(
        "new-token",
        "user",
        "user@example.test",
        expect.any(Uint8Array),
        new Uint8Array(32).fill(8),
        8,
      );
      expect(mocks.unwrapRootKey).toHaveBeenLastCalledWith(
        new TextEncoder().encode("current-root"),
        expect.anything(),
      );
      expect(container.querySelector('[data-testid="recovery"]')).not.toBeNull();
    } finally {
      act(() => root.unmount());
      container.remove();
    }
  },
);
