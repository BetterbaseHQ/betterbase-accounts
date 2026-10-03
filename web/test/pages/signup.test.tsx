// @vitest-environment happy-dom
import { act } from "react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { render, fill, submit, pasteCode } from "../dom";

const mocks = vi.hoisted(() => ({
  navigate: vi.fn(),
  setAuth: vi.fn(),
  sendVerificationCode: vi.fn(),
  confirmVerificationCode: vi.fn(),
  registerInit: vi.fn(),
  registerFinalize: vi.fn(),
  getRootKey: vi.fn(),
}));
vi.mock("react-router-dom", async (original) => ({
  ...(await original<typeof import("react-router-dom")>()),
  useNavigate: () => mocks.navigate,
}));
vi.mock("@/contexts/auth-context", () => ({ useAuth: () => ({ setAuth: mocks.setAuth }) }));
vi.mock("@/lib/cap", () => ({ solveCAPChallenge: async () => "cap" }));
vi.mock("@/lib/api", () => ({ api: mocks }));
vi.mock("@/lib/opaque", () => ({
  startRegistration: async () => ({
    clientRegistrationState: "state",
    registrationRequest: "request",
  }),
  finishRegistration: async () => ({ registrationRecord: "record", exportKey: "export" }),
}));
vi.mock("@/lib/crypto", () => ({
  base64UrlDecode: () => new Uint8Array([1, 2, 3]),
  generateRandomKey: () => new Uint8Array([4, 5, 6]),
  deriveRootKeyWrappingKey: async () => ({}),
  wrapRootKey: async () => new Uint8Array(41).fill(1),
}));
const { SignupPage } = await import("@/pages/signup");

beforeEach(() => {
  vi.resetAllMocks();
  vi.useFakeTimers();
  mocks.sendVerificationCode.mockResolvedValue(undefined);
  mocks.confirmVerificationCode.mockResolvedValue({ verification_token: "verified" });
  mocks.registerInit.mockResolvedValue({
    opaque_response: "response",
    state_token: "state-token",
    user_id: "user",
  });
  mocks.registerFinalize.mockResolvedValue({ auth_token: "token", user_id: "user" });
  mocks.getRootKey.mockResolvedValue({ root_key_version: 0 });
});
afterEach(() => {
  vi.useRealTimers();
});

it.each(["none", "registerInit", "registerFinalize", "getRootKey"] as const)(
  "requires verification and completes signup only after success: %s",
  async (failure) => {
    if (failure !== "none") mocks[failure].mockRejectedValue(new Error("server unavailable"));
    const view = render(
      <MemoryRouter initialEntries={["/signup?oauth=signed%2Bstate&client_name=untrusted"]}>
        <SignupPage />
      </MemoryRouter>,
    );
    try {
      await fill(view.container, "#username", "ALICE");
      await fill(view.container, "#email", "alice@example.test");
      await submit(view.container);
      expect(mocks.sendVerificationCode).toHaveBeenCalledWith(
        "alice@example.test",
        "registration",
        "cap",
        "alice",
      );
      expect(mocks.registerInit).not.toHaveBeenCalled();
      await pasteCode(view.container, "012345");
      await act(async () => {
        await vi.advanceTimersByTimeAsync(1750);
      });
      expect(mocks.confirmVerificationCode).toHaveBeenCalledWith(
        "alice@example.test",
        "012345",
        "registration",
      );
      const password = "tangle-jupiter-cobalt-whisper-726!";
      await fill(view.container, "#password", password);
      await fill(view.container, "#confirmPassword", password);
      await submit(view.container);
      expect(mocks.registerInit).toHaveBeenCalledWith(
        "alice",
        "alice@example.test",
        "request",
        "verified",
        "cap",
      );
      if (failure !== "none") {
        expect(mocks.setAuth).not.toHaveBeenCalled();
        expect(mocks.navigate).not.toHaveBeenCalled();
        expect(view.container.querySelector('[role="alert"]')!.textContent).toContain(
          "Server unavailable",
        );
      } else {
        expect(mocks.registerFinalize).toHaveBeenCalledWith(
          "state-token",
          "record",
          btoa(String.fromCharCode(...new Uint8Array(41).fill(1))),
        );
        expect(mocks.getRootKey).toHaveBeenCalledWith("token");
        expect(mocks.setAuth).toHaveBeenCalledWith(
          "token",
          "user",
          "alice",
          new Uint8Array([1, 2, 3]),
          new Uint8Array([4, 5, 6]),
          0,
        );
        expect(mocks.navigate).toHaveBeenCalledExactlyOnceWith(
          "/recovery-setup?oauth=signed%2Bstate",
        );
      }
    } finally {
      view.cleanup();
    }
  },
);

it("validates identity fields and allows retry after a failed verification send", async () => {
  const view = render(
    <MemoryRouter>
      <SignupPage />
    </MemoryRouter>,
  );
  try {
    await submit(view.container);
    expect(mocks.sendVerificationCode).not.toHaveBeenCalled();
    expect(view.container.querySelector("#username-error")).not.toBeNull();
    expect(view.container.querySelector("#email-error")).not.toBeNull();
    await fill(view.container, "#username", "alice");
    await fill(view.container, "#email", "alice@example.test");
    mocks.sendVerificationCode.mockRejectedValueOnce(new Error("too many requests"));
    await submit(view.container);
    expect(view.container.querySelector('[role="alert"]')!.textContent).toContain(
      "Too many requests",
    );
    expect(view.container.querySelector<HTMLButtonElement>('button[type="submit"]')!.disabled).toBe(
      false,
    );
    await submit(view.container);
    expect(mocks.sendVerificationCode).toHaveBeenCalledTimes(2);
    expect(view.container.querySelector('[aria-label="Digit 1 of 6"]')).not.toBeNull();
  } finally {
    view.cleanup();
  }
});
