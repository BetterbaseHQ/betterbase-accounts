// @vitest-environment happy-dom
/**
 * AUD-008 review: pin the consent page's submit contract — the app
 * keypair is always paired with the wrapped scoped key it was encrypted
 * under, and transient grant-read failures surface as user-visible
 * errors instead of generating replacement key material.
 */
import { act } from "react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const getGrantKeypairBlob = vi.fn();
const oauthConsent = vi.fn();
const getConsentContext = vi.fn();

vi.mock("@/lib/api", () => ({
  api: {
    getGrantKeypairBlob: (...a: unknown[]) => getGrantKeypairBlob(...a),
    oauthConsent: (...a: unknown[]) => oauthConsent(...a),
    getConsentContext: (...a: unknown[]) => getConsentContext(...a),
  },
}));

// Crypto stubs sufficient for consent-keys to run for real; its outputs
// are what the page must pair.
vi.mock("@/lib/crypto", () => ({
  encryptAsJWE: vi.fn(async () => "jwe"),
  computeJwkThumbprint: vi.fn(async () => "thumb"),
  buildScopedKeyJWK: vi.fn(() => ({ kty: "oct" })),
  isValidP256PublicKey: vi.fn(() => true),
  unwrapWithRootKey: vi.fn(async () => new Uint8Array([9, 9, 9])),
  wrapWithRootKey: vi.fn(async () => new Uint8Array([5, 5, 5])),
  generateRandomKey: () => new Uint8Array([7, 7, 7]),
  computeScopedKeyKid: vi.fn(async () => "kid"),
  deriveAppKeypairKey: vi.fn(async () => ({}) as CryptoKey),
  generateAppKeypair: () => ({
    publicKeyJwk: { kty: "EC", crv: "P-256", x: "gen", y: "gen" },
    privateKeyJwk: { kty: "EC", crv: "P-256", x: "gen", y: "gen", d: "gen" },
  }),
  encryptAppKeypairBlob: vi.fn(async () => "keypair-blob"),
  decryptAppKeypairBlob: vi.fn(async () => ({
    kty: "EC",
    crv: "P-256",
    x: "k",
    y: "k",
    d: "k",
  })),
}));

const { ConsentPage } = await import("@/pages/consent");

vi.mock("@/contexts/auth-context", () => ({
  useAuth: () => ({
    authToken: "token",
    userId: "user-1",
    email: "user@example.test",
    rootKey: new Uint8Array(32),
    hasRootKey: true,
  }),
}));

function renderAt(path: string): { root: Root; container: HTMLElement } {
  const container = document.createElement("div");
  document.body.appendChild(container);
  const root = createRoot(container);
  act(() => {
    root.render(
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route path="/consent" element={<ConsentPage />} />
        </Routes>
      </MemoryRouter>,
    );
  });
  return { root, container };
}

const approveButton = (container: HTMLElement) =>
  [...container.querySelectorAll("button")].find(
    (b) => b.textContent?.trim() === "Allow",
  ) as HTMLButtonElement;

const jwk = {
  kty: "EC",
  crv: "P-256",
  x: "AACAVQ",
  y: "AAAE4k",
};

describe("ConsentPage submit contract (AUD-008)", () => {
  let roots: Root[];

  beforeEach(() => {
    roots = [];
    getGrantKeypairBlob.mockReset();
    oauthConsent.mockReset();
    getConsentContext.mockReset();
    getConsentContext.mockResolvedValue({
      client_id: "client-1",
      client_name: "Test App",
      scope: "openid sync",
      redirect_uri: "http://app/cb",
      keys_jwk: jwk,
    });
  });

  afterEach(() => {
    for (const root of roots) {
      act(() => root.unmount());
    }
    document.body.innerHTML = "";
  });

  it("pairs the app keypair with the wrapped scoped key it was encrypted under", async () => {
    // Existing grant: a wrapped scoped key is present; keypair absent.
    getGrantKeypairBlob.mockResolvedValue({
      app_keypair_blob: "",
      wrapped_scoped_key: "d3JhcHBlZA==",
    });
    oauthConsent.mockResolvedValue({ redirect_uri: "http://app/cb?code=x" });

    const rendered = renderAt("/consent?oauth=state-token");
    roots.push(rendered.root);
    const { container } = rendered;

    // Wait for the server-validated context to load before approving.
    for (let i = 0; i < 20 && !approveButton(container); i++) {
      await act(async () => {});
    }
    const button = approveButton(container);
    if (!button) throw new Error("PAGE: " + container.textContent?.slice(0, 300));
    await act(async () => {
      button.click();
    });

    expect(oauthConsent).toHaveBeenCalledTimes(1);
    const [, , , , appKeypairBlob, , wrappedScopedKeyB64] = oauthConsent.mock.calls[0] as unknown[];
    expect(appKeypairBlob).toBeTruthy();
    // Reuse path: the byte-identical stored wrapper is resubmitted.
    expect(wrappedScopedKeyB64).toBe("d3JhcHBlZA==");
    expect(getGrantKeypairBlob).toHaveBeenCalledTimes(1);
  });

  it("a grant-read failure shows an error and never calls consent", async () => {
    getGrantKeypairBlob.mockRejectedValue(new Error("network down"));

    const rendered = renderAt("/consent?oauth=state-token");
    roots.push(rendered.root);
    const { container } = rendered;

    for (let i = 0; i < 20 && !approveButton(container); i++) {
      await act(async () => {});
    }
    const button = approveButton(container);
    expect(button).toBeTruthy();
    await act(async () => {
      button.click();
    });

    expect(oauthConsent).not.toHaveBeenCalled();
    expect(container.textContent).toMatch(/network down|retry/i);
  });
});
