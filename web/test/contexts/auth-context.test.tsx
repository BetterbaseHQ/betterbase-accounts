// @vitest-environment happy-dom
import { act } from "react";
import { createRoot } from "react-dom/client";
import { renderToString } from "react-dom/server";
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

function mountAuth() {
  let current!: ReturnType<typeof useAuth>;
  function Consumer() {
    current = useAuth();
    return null;
  }
  const root = createRoot(document.createElement("div"));
  act(() =>
    root.render(
      <AuthProvider>
        <Consumer />
      </AuthProvider>,
    ),
  );
  return {
    get auth() {
      return current;
    },
    unmount: () => act(() => root.unmount()),
  };
}

it("zeroes replaced keys while preserving their replacements", () => {
  localStorage.clear();
  const view = mountAuth();
  const oldExport = new Uint8Array([1, 2, 3]);
  const oldRoot = new Uint8Array([4, 5, 6]);
  const newExport = new Uint8Array([7, 8, 9]);
  const newRoot = new Uint8Array([10, 11, 12]);
  try {
    act(() => view.auth.setAuth("old-token", "old-user", "old-email", oldExport, oldRoot, 1));
    act(() => view.auth.setAuth("new-token", "new-user", "new-email", newExport, newRoot, 2));
    expect([...oldExport]).toEqual([0, 0, 0]);
    expect([...oldRoot]).toEqual([0, 0, 0]);
    expect([...newExport]).toEqual([7, 8, 9]);
    expect([...newRoot]).toEqual([10, 11, 12]);
    expect(view.auth).toMatchObject({
      authToken: "new-token",
      userId: "new-user",
      email: "new-email",
      exportKey: newExport,
      rootKey: newRoot,
      rootKeyVersion: 2,
      hasExportKey: true,
      hasRootKey: true,
    });
    expect(localStorage.getItem("auth_token")).toBe("new-token");
    expect(localStorage.getItem("user_id")).toBe("new-user");
    expect(localStorage.getItem("user_email")).toBe("new-email");
  } finally {
    view.unmount();
    localStorage.clear();
  }
});

it.each(["clearExportKey", "clearAuth"] as const)(
  "%s clears keys and is safe to repeat",
  (method) => {
    localStorage.clear();
    const view = mountAuth();
    const exportKey = new Uint8Array([1, 2, 3]);
    const rootKey = new Uint8Array([4, 5, 6]);
    try {
      act(() => view.auth.setAuth("token", "user", "email", exportKey, rootKey, 5));
      act(() => view.auth[method]());
      act(() => view.auth[method]());
      expect([...exportKey]).toEqual([0, 0, 0]);
      expect([...rootKey]).toEqual([0, 0, 0]);
      expect(view.auth).toMatchObject({
        exportKey: null,
        rootKey: null,
        rootKeyVersion: null,
        hasExportKey: false,
        hasRootKey: false,
      });
      const retain = method === "clearExportKey";
      expect(view.auth.authToken).toBe(retain ? "token" : null);
      expect(view.auth.userId).toBe(retain ? "user" : null);
      expect(view.auth.email).toBe(retain ? "email" : null);
      expect(localStorage.getItem("auth_token")).toBe(retain ? "token" : null);
      expect(localStorage.getItem("user_id")).toBe(retain ? "user" : null);
      expect(localStorage.getItem("user_email")).toBe(retain ? "email" : null);
    } finally {
      view.unmount();
      localStorage.clear();
    }
  },
);

it("restores only session metadata after remounting and never persists keys", () => {
  localStorage.clear();
  let view = mountAuth();
  try {
    act(() =>
      view.auth.setAuth(
        "token",
        "user",
        "email",
        new Uint8Array([1, 2, 3]),
        new Uint8Array([4, 5, 6]),
        5,
      ),
    );
    expect(Object.keys(localStorage).sort()).toEqual(["auth_token", "user_email", "user_id"]);
    view.unmount();
    view = mountAuth();
    expect(view.auth).toMatchObject({
      authToken: "token",
      userId: "user",
      email: "email",
      exportKey: null,
      rootKey: null,
      rootKeyVersion: null,
      hasExportKey: false,
      hasRootKey: false,
    });
    act(() => view.auth.clearAuth());
    view.unmount();
    view = mountAuth();
    expect(view.auth).toMatchObject({ authToken: null, userId: null, email: null });
  } finally {
    view.unmount();
    localStorage.clear();
  }
});

it("discards in-memory keys when replacing authentication with a metadata-only session", () => {
  localStorage.clear();
  const view = mountAuth();
  const exportKey = new Uint8Array([1, 2, 3]);
  const rootKey = new Uint8Array([4, 5, 6]);
  try {
    act(() => view.auth.setAuth("old", "user", "email", exportKey, rootKey, 1));
    act(() => view.auth.setAuth("replacement", "user", "email", null, null, null));
    expect([...exportKey]).toEqual([0, 0, 0]);
    expect([...rootKey]).toEqual([0, 0, 0]);
    expect(view.auth).toMatchObject({
      authToken: "replacement",
      exportKey: null,
      rootKey: null,
      rootKeyVersion: null,
      hasExportKey: false,
      hasRootKey: false,
    });
  } finally {
    view.unmount();
    localStorage.clear();
  }
});

it("requires an AuthProvider", () => {
  function OutsideProvider() {
    useAuth();
    return null;
  }
  expect(() => renderToString(<OutsideProvider />)).toThrow(
    "useAuth must be used within an AuthProvider",
  );
});
