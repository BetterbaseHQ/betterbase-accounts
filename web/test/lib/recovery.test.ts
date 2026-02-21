import { describe, it, expect } from "vitest";
import {
  generateRecoveryPhrase,
  validateRecoveryPhrase,
  deriveRecoveryKey,
  encryptRootKey,
  decryptRootKey,
} from "@/lib/recovery";

describe("recovery", () => {
  describe("generateRecoveryPhrase", () => {
    it("generates 12 words", () => {
      const phrase = generateRecoveryPhrase();
      const words = phrase.split(" ");
      expect(words.length).toBe(12);
    });

    it("generates valid BIP39 mnemonic", () => {
      const phrase = generateRecoveryPhrase();
      expect(validateRecoveryPhrase(phrase)).toBe(true);
    });

    it("generates different phrases each time", () => {
      const phrase1 = generateRecoveryPhrase();
      const phrase2 = generateRecoveryPhrase();
      expect(phrase1).not.toBe(phrase2);
    });
  });

  describe("validateRecoveryPhrase", () => {
    it("returns true for valid mnemonic", () => {
      // Known valid BIP39 mnemonic
      const valid =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
      expect(validateRecoveryPhrase(valid)).toBe(true);
    });

    it("returns false for invalid mnemonic", () => {
      // Invalid checksum
      const invalid =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
      expect(validateRecoveryPhrase(invalid)).toBe(false);
    });

    it("returns false for non-wordlist words", () => {
      const invalid = "hello world test invalid words that are not in the bip39 wordlist test";
      expect(validateRecoveryPhrase(invalid)).toBe(false);
    });

    it("handles case insensitivity", () => {
      const valid =
        "ABANDON ABANDON ABANDON ABANDON ABANDON ABANDON ABANDON ABANDON ABANDON ABANDON ABANDON ABOUT";
      expect(validateRecoveryPhrase(valid)).toBe(true);
    });

    it("handles extra whitespace", () => {
      const valid =
        "  abandon  abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about  ";
      expect(validateRecoveryPhrase(valid)).toBe(true);
    });
  });

  describe("deriveRecoveryKey", () => {
    it("derives deterministic key from mnemonic (verified via encryption)", async () => {
      const mnemonic =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

      const key1 = await deriveRecoveryKey(mnemonic);
      const key2 = await deriveRecoveryKey(mnemonic);

      // Test determinism by encrypting with key1 and decrypting with key2
      const testData = new Uint8Array(32).fill(99);
      const blob = await encryptRootKey(testData, key1);
      const decrypted = await decryptRootKey(blob, key2);

      expect(decrypted).toEqual(testData);
    });

    it("derives different keys for different mnemonics (verified via encryption)", async () => {
      const mnemonic1 =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
      const mnemonic2 = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong";

      const key1 = await deriveRecoveryKey(mnemonic1);
      const key2 = await deriveRecoveryKey(mnemonic2);

      // Encrypt with key1, try to decrypt with key2 - should fail
      const testData = new Uint8Array(32).fill(42);
      const blob = await encryptRootKey(testData, key1);

      await expect(decryptRootKey(blob, key2)).rejects.toThrow();
    });

    it("produces key usable for AES-GCM encryption", async () => {
      const mnemonic = generateRecoveryPhrase();
      const key = await deriveRecoveryKey(mnemonic);

      // Key should be usable for encryption/decryption
      const testData = new Uint8Array(32).fill(123);
      const blob = await encryptRootKey(testData, key);
      const decrypted = await decryptRootKey(blob, key);

      expect(decrypted).toEqual(testData);
    });

    it("normalizes extra whitespace between words", async () => {
      const canonical =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
      const withExtraSpaces =
        "abandon  abandon   abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

      const key1 = await deriveRecoveryKey(canonical);
      const key2 = await deriveRecoveryKey(withExtraSpaces);

      // Both should derive the same key - verify by encrypting with one and decrypting with other
      const testData = new Uint8Array(32).fill(77);
      const blob = await encryptRootKey(testData, key1);
      const decrypted = await decryptRootKey(blob, key2);

      expect(decrypted).toEqual(testData);
    });

    it("normalizes leading and trailing whitespace", async () => {
      const canonical =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
      const withPadding =
        "  abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about  ";

      const key1 = await deriveRecoveryKey(canonical);
      const key2 = await deriveRecoveryKey(withPadding);

      const testData = new Uint8Array(32).fill(88);
      const blob = await encryptRootKey(testData, key1);
      const decrypted = await decryptRootKey(blob, key2);

      expect(decrypted).toEqual(testData);
    });

    it("normalizes uppercase to lowercase", async () => {
      const canonical =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
      const uppercase =
        "ABANDON ABANDON ABANDON ABANDON ABANDON ABANDON ABANDON ABANDON ABANDON ABANDON ABANDON ABOUT";

      const key1 = await deriveRecoveryKey(canonical);
      const key2 = await deriveRecoveryKey(uppercase);

      const testData = new Uint8Array(32).fill(55);
      const blob = await encryptRootKey(testData, key1);
      const decrypted = await decryptRootKey(blob, key2);

      expect(decrypted).toEqual(testData);
    });
  });

  describe("encryptRootKey and decryptRootKey", () => {
    it("round-trips root key correctly", async () => {
      const mnemonic = generateRecoveryPhrase();
      const recoveryKey = await deriveRecoveryKey(mnemonic);

      const rootKey = new Uint8Array(32);
      crypto.getRandomValues(rootKey);

      const blob = await encryptRootKey(rootKey, recoveryKey);
      const decrypted = await decryptRootKey(blob, recoveryKey);

      expect(decrypted).toEqual(rootKey);
    });

    it("produces blob with correct structure", async () => {
      const mnemonic = generateRecoveryPhrase();
      const recoveryKey = await deriveRecoveryKey(mnemonic);
      const rootKey = new Uint8Array(32).fill(42);

      const blob = await encryptRootKey(rootKey, recoveryKey);

      expect(blob.version).toBe(2);
      expect(blob.alg).toBe("A256GCM");
      expect(typeof blob.iv).toBe("string");
      expect(typeof blob.ciphertext).toBe("string");
    });

    it("produces different ciphertext each time (random IV)", async () => {
      const mnemonic = generateRecoveryPhrase();
      const recoveryKey = await deriveRecoveryKey(mnemonic);
      const rootKey = new Uint8Array(32).fill(42);

      const blob1 = await encryptRootKey(rootKey, recoveryKey);
      const blob2 = await encryptRootKey(rootKey, recoveryKey);

      expect(blob1.iv).not.toBe(blob2.iv);
      expect(blob1.ciphertext).not.toBe(blob2.ciphertext);
    });

    it("decryption fails with wrong key", async () => {
      const mnemonic1 = generateRecoveryPhrase();
      const mnemonic2 = generateRecoveryPhrase();

      const recoveryKey1 = await deriveRecoveryKey(mnemonic1);
      const recoveryKey2 = await deriveRecoveryKey(mnemonic2);

      const rootKey = new Uint8Array(32).fill(42);
      const blob = await encryptRootKey(rootKey, recoveryKey1);

      await expect(decryptRootKey(blob, recoveryKey2)).rejects.toThrow();
    });

    it("rejects blob with wrong version", async () => {
      const mnemonic = generateRecoveryPhrase();
      const recoveryKey = await deriveRecoveryKey(mnemonic);

      const invalidBlob = {
        version: 1 as const,
        alg: "A256GCM" as const,
        iv: "AAAAAAAAAAAAAAAA",
        ciphertext: "test",
      };

      // Type assertion needed to bypass TypeScript check
      await expect(decryptRootKey(invalidBlob as never, recoveryKey)).rejects.toThrow(
        "Unsupported recovery blob format",
      );
    });
  });
});
