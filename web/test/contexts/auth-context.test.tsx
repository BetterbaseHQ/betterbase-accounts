// @vitest-environment happy-dom
import { act } from "react";
import { createRoot } from "react-dom/client";
import { expect, it } from "vitest";
import { AuthProvider, useAuth } from "@/contexts/auth-context";

it("publishes a new root-key version without clearing reused key material", () => {
  let auth: ReturnType<typeof useAuth>;
  function Consumer() {
    auth = useAuth();
    return <span>{auth.rootKeyVersion}</span>;
  }
  localStorage.clear();
  const container = document.createElement("div");
  const root = createRoot(container);
  const exportKey = new Uint8Array([1, 2, 3]);
  const rootKey = new Uint8Array([4, 5, 6]);
  try {
    act(() =>
      root.render(
        <AuthProvider>
          <Consumer />
        </AuthProvider>,
      ),
    );
    act(() => auth.setAuth("token", "user", "email", exportKey, rootKey, 1));
    act(() => auth.setAuth("token", "user", "email", exportKey, rootKey, 2));
    expect(container.textContent).toBe("2");
    expect([...exportKey]).toEqual([1, 2, 3]);
    expect([...rootKey]).toEqual([4, 5, 6]);
    act(() => auth.clearAuth());
    expect([...exportKey]).toEqual([0, 0, 0]);
    expect([...rootKey]).toEqual([0, 0, 0]);
    expect(localStorage.getItem("auth_token")).toBeNull();
  } finally {
    act(() => root.unmount());
    localStorage.clear();
  }
});
