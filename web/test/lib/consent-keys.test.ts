/**
 * AUD-008 regressions: consent key resolution fails closed. Transient
 * read failures and undecryptable existing material must throw — never
 * silently generate replacement key material over an existing grant.
 * Only an explicit absence may generate.
 */
import { describe, expect, it, vi } from "vitest";

const { fetchGrantKeyInfo, resolveScopedKey, resolveAppKeypair } =
  await import("@/lib/consent-keys");

// The crypto layer is exercised elsewhere; here it is stubbed to keep the
// matrix deterministic (node env has no btoa/atob-independent guarantee).
vi.mock("@/lib/crypto", () => ({
  unwrapWithRootKey: vi.fn(async (wrapped: Uint8Array) => {
    if (wrapped[0] === 0xff) throw new Error("unwrap failed");
    return new Uint8Array([9, 9, 9]);
  }),
  wrapWithRootKey: vi.fn(async () => new Uint8Array([5, 5, 5])),
  generateRandomKey: () => new Uint8Array([7, 7, 7]),
  computeScopedKeyKid: vi.fn(async () => "kid"),
  deriveAppKeypairKey: vi.fn(async () => ({}) as CryptoKey),
  generateAppKeypair: () => ({
    publicKeyJwk: { kty: "EC", crv: "P-256", x: "gen", y: "gen" },
    privateKeyJwk: { kty: "EC", crv: "P-256", x: "gen", y: "gen", d: "gen" },
  }),
  encryptAppKeypairBlob: vi.fn(async () => "blob"),
  decryptAppKeypairBlob: vi.fn(async (blob: string) => {
    if (blob === "bad") throw new Error("decrypt failed");
    if (blob === "wrong-shape") return { kty: "oct" } as JsonWebKey;
    return {
      kty: "EC",
      crv: "P-256",
      x: "stored",
      y: "stored",
      d: "stored",
    } as JsonWebKey;
  }),
}));

const rootKey = new Uint8Array(32);

describe("resolveScopedKey (AUD-008)", () => {
  it("reuses the existing wrapped key and submits it byte-identically", async () => {
    const api = {
      getGrantKeypairBlob: vi.fn(async () => ({
        app_keypair_blob: "",
        wrapped_scoped_key: "QUFB", // btoa("AAA")
      })),
    };
    const result = await resolveScopedKey(await fetchGrantKeyInfo(api, "client"), rootKey);
    expect(result.wrappedScopedKeyB64).toBe("QUFB");
  });

  it("fails closed when the grant read fails", async () => {
    const api = {
      getGrantKeypairBlob: vi.fn(async () => {
        throw new Error("network down");
      }),
    };
    // The shared fetch propagates the read failure; the consent page
    // fails closed before either resolver can generate anything.
    await expect(fetchGrantKeyInfo(api, "client")).rejects.toThrow(/network down/);
  });

  it("fails closed when the stored wrapper cannot be unwrapped", async () => {
    // 0xff first byte makes the stubbed unwrap fail (e.g. root rotated).
    const api = {
      getGrantKeypairBlob: vi.fn(async () => ({
        app_keypair_blob: "",
        wrapped_scoped_key: btoa(String.fromCharCode(0xff, 0x01)),
      })),
    };
    await expect(resolveScopedKey(await fetchGrantKeyInfo(api, "client"), rootKey)).rejects.toThrow(
      /strand/i,
    );
  });

  it("generates only on explicit absence", async () => {
    const result = await resolveScopedKey({ app_keypair_blob: "" }, rootKey);
    expect(result.wrappedScopedKeyB64).toBe(btoa(String.fromCharCode(5, 5, 5)));
  });
});

describe("resolveAppKeypair (AUD-008)", () => {
  it("recovers the stored keypair", async () => {
    const kp = await resolveAppKeypair({ app_keypair_blob: "good" }, {} as CryptoKey);
    expect(kp.publicKeyJwk.x).toBe("stored");
  });

  it("fails closed when the stored blob cannot be decrypted", async () => {
    await expect(resolveAppKeypair({ app_keypair_blob: "bad" }, {} as CryptoKey)).rejects.toThrow(
      /signing identity/i,
    );
  });

  it("fails closed when the stored keypair is malformed", async () => {
    await expect(
      resolveAppKeypair({ app_keypair_blob: "wrong-shape" }, {} as CryptoKey),
    ).rejects.toThrow(/malformed/i);
  });

  it("generates only on explicit absence", async () => {
    const api = {
      getGrantKeypairBlob: vi.fn(async () => ({
        app_keypair_blob: "",
      })),
    };
    const kp = await resolveAppKeypair(api, "client", {} as CryptoKey);
    expect(kp.publicKeyJwk.x).toBe("gen");
  });
});
