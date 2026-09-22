// @vitest-environment happy-dom
import { act } from "react";
import { createRoot } from "react-dom/client";
import { MemoryRouter } from "react-router-dom";
import { expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  verificationForm: vi.fn((_props: { onVerified: (token: string) => void }) => null),
  recoveryForm: vi.fn(
    (_props: { onSubmit: (email: string, phrase: string) => Promise<void> }) => null,
  ),
  authForm: vi.fn(
    (_props: { onSubmit: (username: string, email: string, password: string) => Promise<void> }) =>
      null,
  ),
  setAuth: vi.fn(),
  unwrapRootKey: vi.fn(async () => new Uint8Array(32).fill(8)),
  recoverInit: vi.fn(),
  getRecoveryBlob: vi.fn(),
}));

vi.mock("@/components/verification-form", () => ({ VerificationForm: mocks.verificationForm }));
vi.mock("@/components/recovery/recovery-form", () => ({ RecoveryForm: mocks.recoveryForm }));
vi.mock("@/components/auth-form", () => ({ AuthForm: mocks.authForm }));
vi.mock("@/contexts/auth-context", () => ({ useAuth: () => ({ setAuth: mocks.setAuth }) }));
vi.mock("@/lib/cap", () => ({ solveCAPChallenge: async () => "cap-token" }));
vi.mock("@/lib/recovery", () => ({
  deriveRecoveryKey: async () => ({}),
  decryptRootKey: async () => new Uint8Array(32),
}));
vi.mock("@/lib/opaque", () => ({
  startRegistration: async () => ({
    clientRegistrationState: "registration",
    registrationRequest: "request",
  }),
  finishRegistration: async () => ({ registrationRecord: "record", exportKey: "export" }),
}));
vi.mock("@/lib/crypto", () => ({
  base64UrlDecode: () => new Uint8Array(32),
  deriveRootKeyWrappingKey: async () => ({}),
  wrapRootKey: async () => new Uint8Array(41),
  unwrapRootKey: mocks.unwrapRootKey,
}));
vi.mock("@/lib/api", () => ({
  api: {
    sendVerificationCode: async () => {},
    getRecoveryBlob: mocks.getRecoveryBlob,
    recoverInit: mocks.recoverInit,
    recoverFinalize: async () => ({ auth_token: "new-token", user_id: "user" }),
    getRootKey: async () => ({ wrapped_root_key: btoa("current-root"), root_key_version: 8 }),
  },
}));

const { RecoverPage } = await import("@/pages/recover");

it("binds recovery to the root version fetched with the decrypted blob", async () => {
  const blobResponse = { blob: "{}", root_key_version: 7 };
  mocks.getRecoveryBlob.mockResolvedValue(blobResponse);
  mocks.recoverInit.mockResolvedValue({
    opaque_response: "response",
    state_token: "state",
    user_id: "user",
  });
  const container = document.createElement("div");
  document.body.appendChild(container);
  const root = createRoot(container);
  try {
    await act(async () =>
      root.render(
        <MemoryRouter>
          <RecoverPage />
        </MemoryRouter>,
      ),
    );
    const input = container.querySelector<HTMLInputElement>("#email")!;
    await act(async () => {
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!.call(
        input,
        "user@example.com",
      );
      input.dispatchEvent(new Event("input", { bubbles: true }));
    });
    await act(async () => {
      container
        .querySelector("form")!
        .dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    });
    const verificationProps = mocks.verificationForm.mock.lastCall![0];
    await act(async () => verificationProps.onVerified("verification-token"));
    const recoveryProps = mocks.recoveryForm.mock.lastCall![0];
    await act(async () => recoveryProps.onSubmit("user@example.com", "recovery phrase"));

    // A later version must not replace the snapshot associated with this root key.
    blobResponse.root_key_version = 8;
    const passwordProps = mocks.authForm.mock.lastCall![0];
    await act(async () => passwordProps.onSubmit("", "user@example.com", "new-password"));
    expect(mocks.getRecoveryBlob).toHaveBeenCalledOnce();
    expect(mocks.recoverInit).toHaveBeenCalledWith(
      "user@example.com",
      "request",
      "verification-token",
      "cap-token",
      7,
    );
    expect(mocks.unwrapRootKey).toHaveBeenCalledWith(
      new TextEncoder().encode("current-root"),
      expect.anything(),
    );
    expect(mocks.setAuth).toHaveBeenCalledWith(
      "new-token",
      "user",
      "user@example.com",
      expect.any(Uint8Array),
      new Uint8Array(32).fill(8),
      8,
    );
  } finally {
    act(() => root.unmount());
    container.remove();
  }
});
