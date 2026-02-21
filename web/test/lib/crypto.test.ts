import { describe, it, expect } from "vitest";
import * as jose from "jose";
import {
  generateRandomKey,
  deriveRootKeyWrappingKey,
  wrapRootKey,
  unwrapRootKey,
  wrapWithRootKey,
  unwrapWithRootKey,
  computeJwkThumbprint,
  encryptAsJWE,
  parseJwkFromBase64Url,
  isValidP256PublicKey,
  buildScopedKeyJWK,
  computeScopedKeyKid,
  base64UrlEncode,
  base64UrlDecode,
  generateAppKeypair,
  deriveAppKeypairKey,
  encryptAppKeypairBlob,
  decryptAppKeypairBlob,
} from "@/lib/crypto";

const TEST_UUID = "550e8400-e29b-41d4-a716-446655440000";

describe("crypto", () => {
  describe("generateRandomKey", () => {
    it("generates 32 random bytes", () => {
      const key = generateRandomKey();
      expect(key.length).toBe(32);
    });

    it("generates different keys each time", () => {
      const key1 = generateRandomKey();
      const key2 = generateRandomKey();
      expect(key1).not.toEqual(key2);
    });
  });

  describe("deriveRootKeyWrappingKey", () => {
    it("produces deterministic output for same inputs", async () => {
      const exportKey = new Uint8Array(32).fill(42);
      const key1 = await deriveRootKeyWrappingKey(exportKey, TEST_UUID);
      const key2 = await deriveRootKeyWrappingKey(exportKey, TEST_UUID);

      // Verify determinism by wrapping with key1 and unwrapping with key2
      const testKey = generateRandomKey();
      const wrapped = await wrapRootKey(testKey, key1);
      const unwrapped = await unwrapRootKey(wrapped, key2);
      expect(unwrapped).toEqual(testKey);
    });

    it("rejects non-UUID userId", async () => {
      const exportKey = new Uint8Array(32).fill(42);
      await expect(deriveRootKeyWrappingKey(exportKey, "not-a-uuid")).rejects.toThrow(
        "Invalid user ID format",
      );
    });
  });

  describe("wrapRootKey / unwrapRootKey", () => {
    it("round-trips a 32-byte key", async () => {
      const exportKey = new Uint8Array(32).fill(42);
      const wrappingKey = await deriveRootKeyWrappingKey(exportKey, TEST_UUID);

      const rootKey = generateRandomKey();
      const wrapped = await wrapRootKey(rootKey, wrappingKey);
      const unwrapped = await unwrapRootKey(wrapped, wrappingKey);

      expect(unwrapped).toEqual(rootKey);
    });

    it("produces 41-byte output (1B version + 40B AES-KW)", async () => {
      const exportKey = new Uint8Array(32).fill(42);
      const wrappingKey = await deriveRootKeyWrappingKey(exportKey, TEST_UUID);

      const rootKey = generateRandomKey();
      const wrapped = await wrapRootKey(rootKey, wrappingKey);

      expect(wrapped.length).toBe(41);
      expect(wrapped[0]).toBe(0x01); // version byte
    });

    it("fails to unwrap with wrong key", async () => {
      const exportKey1 = new Uint8Array(32).fill(1);
      const exportKey2 = new Uint8Array(32).fill(2);
      const wrappingKey1 = await deriveRootKeyWrappingKey(exportKey1, TEST_UUID);
      const wrappingKey2 = await deriveRootKeyWrappingKey(exportKey2, TEST_UUID);

      const rootKey = generateRandomKey();
      const wrapped = await wrapRootKey(rootKey, wrappingKey1);

      await expect(unwrapRootKey(wrapped, wrappingKey2)).rejects.toThrow();
    });

    it("rejects invalid wrapped key length", async () => {
      const exportKey = new Uint8Array(32).fill(42);
      const wrappingKey = await deriveRootKeyWrappingKey(exportKey, TEST_UUID);

      await expect(unwrapRootKey(new Uint8Array(40), wrappingKey)).rejects.toThrow(
        "Invalid wrapped key length",
      );
    });

    it("rejects invalid version byte", async () => {
      const exportKey = new Uint8Array(32).fill(42);
      const wrappingKey = await deriveRootKeyWrappingKey(exportKey, TEST_UUID);

      const badWrapped = new Uint8Array(41).fill(0);
      badWrapped[0] = 0x99; // bad version
      await expect(unwrapRootKey(badWrapped, wrappingKey)).rejects.toThrow(
        "Unsupported wrapped key version",
      );
    });
  });

  describe("wrapWithRootKey / unwrapWithRootKey", () => {
    it("round-trips a scoped key", async () => {
      const rootKey = generateRandomKey();
      const scopedKey = generateRandomKey();

      const wrapped = await wrapWithRootKey(scopedKey, rootKey);
      const unwrapped = await unwrapWithRootKey(wrapped, rootKey);

      expect(unwrapped).toEqual(scopedKey);
    });

    it("produces 41-byte output", async () => {
      const rootKey = generateRandomKey();
      const scopedKey = generateRandomKey();
      const wrapped = await wrapWithRootKey(scopedKey, rootKey);
      expect(wrapped.length).toBe(41);
    });

    it("fails with wrong root key", async () => {
      const rootKey1 = generateRandomKey();
      const rootKey2 = generateRandomKey();
      const scopedKey = generateRandomKey();

      const wrapped = await wrapWithRootKey(scopedKey, rootKey1);
      await expect(unwrapWithRootKey(wrapped, rootKey2)).rejects.toThrow();
    });
  });

  describe("computeScopedKeyKid", () => {
    it("produces kid with timestamp and fingerprint", async () => {
      const key = generateRandomKey();
      const kid = await computeScopedKeyKid(key);

      const parts = kid.split("-");
      expect(parts.length).toBe(2);

      const timestamp = parseInt(parts[0], 10);
      expect(timestamp).toBeGreaterThan(1700000000);
      expect(timestamp).toBeLessThan(2000000000);

      expect(parts[1]).toMatch(/^[0-9a-f]{16}$/);
    });
  });

  describe("computeJwkThumbprint", () => {
    it("computes correct thumbprint for P-256 EC key", async () => {
      const jwk: JsonWebKey = {
        kty: "EC",
        crv: "P-256",
        x: "WbbAOkFz5ZYnfvqWKy-06K9UNgbKLhDGGtdGK3MxA3o",
        y: "JVkJ0Tne7RtqPJAoFRWDL67v6QBGX3-VxreFN6VjrOE",
      };

      const thumbprint = await computeJwkThumbprint(jwk);
      expect(thumbprint).toMatch(/^[A-Za-z0-9_-]+$/);

      const thumbprint2 = await computeJwkThumbprint(jwk);
      expect(thumbprint).toBe(thumbprint2);
    });

    it("produces different thumbprints for different keys", async () => {
      const jwk1: JsonWebKey = {
        kty: "EC",
        crv: "P-256",
        x: "WbbAOkFz5ZYnfvqWKy-06K9UNgbKLhDGGtdGK3MxA3o",
        y: "JVkJ0Tne7RtqPJAoFRWDL67v6QBGX3-VxreFN6VjrOE",
      };
      const jwk2: JsonWebKey = {
        kty: "EC",
        crv: "P-256",
        x: "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
        y: "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
      };

      const thumbprint1 = await computeJwkThumbprint(jwk1);
      const thumbprint2 = await computeJwkThumbprint(jwk2);
      expect(thumbprint1).not.toBe(thumbprint2);
    });

    it("matches jose library calculation for EC keys", async () => {
      const { publicKey } = await jose.generateKeyPair("ES256");
      const jwk = await jose.exportJWK(publicKey);

      const ourThumbprint = await computeJwkThumbprint(jwk);
      const joseThumbprint = await jose.calculateJwkThumbprint(jwk, "sha256");
      expect(ourThumbprint).toBe(joseThumbprint);
    });
  });

  describe("encryptAsJWE and decryption round-trip", () => {
    it("encrypts and decrypts payload correctly", async () => {
      const { publicKey, privateKey } = await jose.generateKeyPair("ECDH-ES+A256KW", {
        crv: "P-256",
      });
      const publicJwk = await jose.exportJWK(publicKey);

      const payload = {
        "test-bucket": {
          kty: "oct" as const,
          k: base64UrlEncode(new Uint8Array(32).fill(99)),
          kid: "1234567890-abcdef0123456789",
          alg: "A256GCM" as const,
        },
      };

      const jwe = await encryptAsJWE(payload, publicJwk);
      expect(jwe.split(".").length).toBe(5);

      const { plaintext } = await jose.compactDecrypt(jwe, privateKey);
      const decrypted = JSON.parse(new TextDecoder().decode(plaintext));
      expect(decrypted).toEqual(payload);
    });
  });

  describe("parseJwkFromBase64Url", () => {
    it("parses base64url-encoded JWK", () => {
      const jwk: JsonWebKey = { kty: "EC", crv: "P-256", x: "test-x", y: "test-y" };
      const encoded = base64UrlEncode(new TextEncoder().encode(JSON.stringify(jwk)));
      const parsed = parseJwkFromBase64Url(encoded);

      expect(parsed.kty).toBe("EC");
      expect(parsed.crv).toBe("P-256");
    });
  });

  describe("isValidP256PublicKey", () => {
    it("returns true for valid P-256 public key", () => {
      expect(
        isValidP256PublicKey({
          kty: "EC",
          crv: "P-256",
          x: "WbbAOkFz5ZYnfvqWKy-06K9UNgbKLhDGGtdGK3MxA3o",
          y: "JVkJ0Tne7RtqPJAoFRWDL67v6QBGX3-VxreFN6VjrOE",
        }),
      ).toBe(true);
    });

    it("returns false for key with private component", () => {
      expect(
        isValidP256PublicKey({
          kty: "EC",
          crv: "P-256",
          x: "WbbAOkFz5ZYnfvqWKy-06K9UNgbKLhDGGtdGK3MxA3o",
          y: "JVkJ0Tne7RtqPJAoFRWDL67v6QBGX3-VxreFN6VjrOE",
          d: "private",
        }),
      ).toBe(false);
    });
  });

  describe("buildScopedKeyJWK", () => {
    it("builds correct JWK structure", () => {
      const key = new Uint8Array(32).fill(123);
      const kid = "1234567890-abcdef";

      const jwk = buildScopedKeyJWK(key, kid);

      expect(jwk.kty).toBe("oct");
      expect(jwk.alg).toBe("A256GCM");
      expect(jwk.kid).toBe(kid);
      expect(jwk.k).toBe(base64UrlEncode(key));
    });
  });

  describe("generateAppKeypair", () => {
    it("generates a valid P-256 ECDSA keypair", async () => {
      const keypair = await generateAppKeypair();

      expect(keypair.publicKeyJwk.kty).toBe("EC");
      expect(keypair.publicKeyJwk.crv).toBe("P-256");
      expect(keypair.publicKeyJwk.d).toBeUndefined();
      expect(keypair.privateKeyJwk.d).toBeDefined();
    });

    it("generates different keypairs each time", async () => {
      const kp1 = await generateAppKeypair();
      const kp2 = await generateAppKeypair();
      expect(kp1.publicKeyJwk.x).not.toBe(kp2.publicKeyJwk.x);
    });
  });

  describe("deriveAppKeypairKey", () => {
    const testPlaintext = new TextEncoder().encode("test data");

    it("produces deterministic output for same inputs", async () => {
      const scopedKey = new Uint8Array(32).fill(42);
      const key1 = await deriveAppKeypairKey(scopedKey, TEST_UUID, "client-1");
      const key2 = await deriveAppKeypairKey(scopedKey, TEST_UUID, "client-1");

      const iv = crypto.getRandomValues(new Uint8Array(12));
      const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key1, testPlaintext);
      const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key2, ciphertext);
      expect(new Uint8Array(decrypted)).toEqual(testPlaintext);
    });

    it("produces different keys for different client IDs", async () => {
      const scopedKey = new Uint8Array(32).fill(42);
      const key1 = await deriveAppKeypairKey(scopedKey, TEST_UUID, "client-a");
      const key2 = await deriveAppKeypairKey(scopedKey, TEST_UUID, "client-b");

      const iv = crypto.getRandomValues(new Uint8Array(12));
      const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key1, testPlaintext);
      await expect(
        crypto.subtle.decrypt({ name: "AES-GCM", iv }, key2, ciphertext),
      ).rejects.toThrow();
    });

    it("rejects non-UUID userId", async () => {
      const scopedKey = new Uint8Array(32).fill(42);
      await expect(deriveAppKeypairKey(scopedKey, "not-uuid", "client-1")).rejects.toThrow(
        "Invalid user ID format",
      );
    });

    it("rejects invalid client ID", async () => {
      const scopedKey = new Uint8Array(32).fill(42);
      await expect(deriveAppKeypairKey(scopedKey, TEST_UUID, "bad:client")).rejects.toThrow(
        "Invalid client ID format",
      );
    });
  });

  describe("encryptAppKeypairBlob and decryptAppKeypairBlob", () => {
    it("round-trips a keypair correctly", async () => {
      const { privateKeyJwk } = await generateAppKeypair();
      const scopedKey = new Uint8Array(32).fill(42);
      const wrappingKey = await deriveAppKeypairKey(scopedKey, TEST_UUID, "client-1");

      const blob = await encryptAppKeypairBlob(privateKeyJwk, wrappingKey);
      const decrypted = await decryptAppKeypairBlob(blob, wrappingKey);

      expect(decrypted.kty).toBe(privateKeyJwk.kty);
      expect(decrypted.crv).toBe(privateKeyJwk.crv);
      expect(decrypted.d).toBe(privateKeyJwk.d);
    });

    it("decryption fails with wrong wrapping key", async () => {
      const { privateKeyJwk } = await generateAppKeypair();
      const scopedKey1 = new Uint8Array(32).fill(1);
      const scopedKey2 = new Uint8Array(32).fill(2);
      const key1 = await deriveAppKeypairKey(scopedKey1, TEST_UUID, "client-1");
      const key2 = await deriveAppKeypairKey(scopedKey2, TEST_UUID, "client-1");

      const blob = await encryptAppKeypairBlob(privateKeyJwk, key1);
      await expect(decryptAppKeypairBlob(blob, key2)).rejects.toThrow();
    });
  });

  describe("base64UrlEncode and base64UrlDecode", () => {
    it("round-trips binary data correctly", () => {
      const original = new Uint8Array([0, 1, 2, 255, 254, 253, 128, 127]);
      const encoded = base64UrlEncode(original);
      const decoded = base64UrlDecode(encoded);
      expect(decoded).toEqual(original);
    });

    it("produces URL-safe output", () => {
      const data = new Uint8Array([251, 255, 254]);
      const encoded = base64UrlEncode(data);
      expect(encoded).not.toContain("+");
      expect(encoded).not.toContain("/");
      expect(encoded).not.toContain("=");
    });

    it("handles empty input", () => {
      const empty = new Uint8Array(0);
      const encoded = base64UrlEncode(empty);
      const decoded = base64UrlDecode(encoded);
      expect(decoded).toEqual(empty);
    });
  });
});
