// @vitest-environment happy-dom
import { act } from "react";
import { createRoot } from "react-dom/client";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  navigate: vi.fn(),
  setAuth: vi.fn(),
  cap: vi.fn(),
  startLogin: vi.fn(),
  finishLogin: vi.fn(),
  loginInit: vi.fn(),
  loginFinalize: vi.fn(),
  getRootKey: vi.fn(),
  unwrapRootKey: vi.fn(),
}));
let submit: (username: string, email: string, password: string) => Promise<void>;
vi.mock("@/components/auth-form", () => ({
  AuthForm: (props: { onSubmit: typeof submit }) => {
    submit = props.onSubmit;
    return null;
  },
}));
vi.mock("react-router-dom", async (original) => ({
  ...(await original<typeof import("react-router-dom")>()),
  useNavigate: () => mocks.navigate,
}));
vi.mock("@/contexts/auth-context", () => ({ useAuth: () => ({ setAuth: mocks.setAuth }) }));
vi.mock("@/lib/cap", () => ({ solveCAPChallenge: mocks.cap }));
vi.mock("@/lib/opaque", () => ({ startLogin: mocks.startLogin, finishLogin: mocks.finishLogin }));
vi.mock("@/lib/api", () => ({ api: mocks }));
vi.mock("@/lib/crypto", () => ({
  base64UrlDecode: () => new Uint8Array([1, 2, 3]),
  deriveRootKeyWrappingKey: async () => ({}),
  unwrapRootKey: mocks.unwrapRootKey,
}));
const { LoginPage } = await import("@/pages/login");

beforeEach(() => {
  vi.resetAllMocks();
  mocks.cap.mockResolvedValue("cap");
  mocks.startLogin.mockResolvedValue({ clientLoginState: "state", ke1: "ke1" });
  mocks.loginInit.mockResolvedValue({ opaque_ke2: "ke2", login_token: "login-token" });
  mocks.finishLogin.mockResolvedValue({ ke3: "ke3", exportKey: "export" });
  mocks.loginFinalize.mockResolvedValue({ auth_token: "token", user_id: "user" });
  mocks.getRootKey.mockResolvedValue({ wrapped_root_key: btoa("wrapped"), root_key_version: 4 });
  mocks.unwrapRootKey.mockResolvedValue(new Uint8Array([4, 5, 6]));
});

async function withPage(uri: string, check: () => Promise<void>) {
  const root = createRoot(document.createElement("div"));
  try {
    await act(async () =>
      root.render(
        <MemoryRouter initialEntries={[uri]}>
          <LoginPage />
        </MemoryRouter>,
      ),
    );
    await act(check);
  } finally {
    act(() => root.unmount());
  }
}

it.each([
  ["/login?redirect=%2Fsettings", "/settings"],
  ["/login?redirect=https%3A%2F%2Fevil.test", "/"],
  [
    "/login?oauth=signed%2Bstate&redirect=%2Fsettings&client_name=untrusted",
    "/consent?oauth=signed%2Bstate",
  ],
])("authenticates before navigating safely from %s", async (uri, destination) => {
  await withPage(uri, async () => {
    await submit("alice", "", "password");
  });
  expect(mocks.loginInit).toHaveBeenCalledWith("alice", "ke1", "cap");
  expect(mocks.loginFinalize).toHaveBeenCalledWith("login-token", "ke3");
  expect(mocks.getRootKey).toHaveBeenCalledWith("token");
  expect(mocks.setAuth).toHaveBeenCalledWith(
    "token",
    "user",
    "alice",
    new Uint8Array([1, 2, 3]),
    new Uint8Array([4, 5, 6]),
    4,
  );
  expect(mocks.navigate).toHaveBeenCalledExactlyOnceWith(destination);
});

it.each(["cap", "loginInit", "loginFinalize", "getRootKey", "unwrapRootKey"] as const)(
  "does not publish authentication or navigate when %s fails",
  async (step) => {
    mocks[step].mockRejectedValue(new Error("failure"));
    await withPage("/login", async () => {
      await expect(submit("alice", "", "password")).rejects.toThrow("failure");
    });
    expect(mocks.setAuth).not.toHaveBeenCalled();
    expect(mocks.navigate).not.toHaveBeenCalled();
    if (step === "cap") expect(mocks.startLogin).not.toHaveBeenCalled();
  },
);

it("rejects the wrong password without finalizing a session", async () => {
  mocks.finishLogin.mockResolvedValue(null);
  await withPage("/login", async () => {
    await expect(submit("alice", "", "wrong")).rejects.toThrow("Invalid username or password");
  });
  expect(mocks.loginFinalize).not.toHaveBeenCalled();
  expect(mocks.setAuth).not.toHaveBeenCalled();
  expect(mocks.navigate).not.toHaveBeenCalled();
});
