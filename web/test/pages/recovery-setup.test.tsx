// @vitest-environment happy-dom
/**
 * AUD-016 regressions: the recovery blob must be stored only after the
 * user confirms saving the phrase — never on mount — and navigation must
 * wait for a successful store.
 */
import { act } from "react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const storeRecoveryBlob = vi.fn(async () => {
  /* ok */
});

vi.mock("@/lib/api", () => ({
  api: { storeRecoveryBlob: (...args: unknown[]) => storeRecoveryBlob(...args) },
}));

vi.mock("@/lib/recovery", () => ({
  generateRecoveryPhrase: () =>
    "alpha bravo charlie delta echo foxtrot golf hotel india juliet kilo lima",
  deriveRecoveryKey: async () => new Uint8Array(32),
  encryptRootKey: async () => ({ ciphertext: "staged-blob" }),
}));

vi.mock("@/contexts/auth-context", () => ({
  useAuth: () => ({ authToken: "token", rootKey: new Uint8Array(32) }),
}));

const { RecoverySetupPage } = await import("@/pages/recovery-setup");

function renderAt(path: string): { root: Root; container: HTMLElement } {
  const container = document.createElement("div");
  document.body.appendChild(container);
  const root = createRoot(container);
  act(() => {
    root.render(
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route path="/recovery-setup" element={<RecoverySetupPage />} />
          <Route path="/" element={<div data-testid="home" />} />
          <Route path="/consent" element={<div data-testid="consent" />} />
        </Routes>
      </MemoryRouter>,
    );
  });
  return { root, container };
}

const continueButton = (container: HTMLElement) =>
  [...container.querySelectorAll("button")].find((b) =>
    b.textContent?.includes("Continue"),
  ) as HTMLButtonElement;

const acknowledge = (container: HTMLElement) => {
  const checkbox = container.querySelector<HTMLInputElement>("input[type=checkbox]")!;
  act(() => {
    checkbox.click();
  });
};

describe("RecoverySetupPage AUD-016: staged recovery secret", () => {
  let roots: Root[];

  beforeEach(() => {
    storeRecoveryBlob.mockClear();
    roots = [];
  });

  afterEach(() => {
    for (const root of roots) {
      act(() => root.unmount());
    }
    document.body.innerHTML = "";
  });

  it("does not store the recovery blob on mount", async () => {
    const rendered = renderAt("/recovery-setup");
    roots.push(rendered.root);
    const { container } = rendered;

    // The phrase is displayed, but the server-side secret replacement
    // has not happened: closing the tab now leaves the previous recovery
    // path intact.
    expect(container.textContent).toContain("alpha bravo");
    await act(async () => {});
    expect(storeRecoveryBlob).not.toHaveBeenCalled();
  });

  it("stores and navigates only after the user acknowledges the phrase", async () => {
    const rendered = renderAt("/recovery-setup");
    roots.push(rendered.root);
    const { container } = rendered;

    acknowledge(container);
    await act(async () => {
      continueButton(container).click();
    });

    expect(storeRecoveryBlob).toHaveBeenCalledTimes(1);
    expect(container.querySelector('[data-testid="home"]')).not.toBeNull();
  });

  it("a failed store shows the error and stays on the page", async () => {
    storeRecoveryBlob.mockRejectedValueOnce(new Error("network down"));
    const rendered = renderAt("/recovery-setup");
    roots.push(rendered.root);
    const { container } = rendered;

    acknowledge(container);
    await act(async () => {
      continueButton(container).click();
    });

    expect(storeRecoveryBlob).toHaveBeenCalledTimes(1);
    expect(container.querySelector('[data-testid="home"]')).toBeNull();
    expect(container.textContent).toMatch(/Failed to set up recovery|Network down/i);

    // Retry after failure succeeds and navigates (the checkbox is still
    // acknowledged — no need to re-check it).
    await act(async () => {
      continueButton(container).click();
    });
    expect(storeRecoveryBlob).toHaveBeenCalledTimes(2);
    expect(container.querySelector('[data-testid="home"]')).not.toBeNull();
  });
});
