import { generateMnemonic, validateMnemonic, mnemonicToSeed } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english.js";
import { base64UrlDecode, base64UrlEncode } from "./base64url";

/**
 * Recovery blob format stored on the server.
 * v2: encrypts root_key (not export_key).
 */
export interface RecoveryBlob {
  version: 2;
  alg: "A256GCM";
  iv: string; // base64url-encoded IV (12 bytes)
  ciphertext: string; // base64url-encoded ciphertext (includes auth tag)
}

/**
 * Generate a new 12-word BIP39 mnemonic phrase.
 * Uses 128 bits of entropy, giving ~3.4×10³⁸ possible phrases.
 *
 * @returns Space-separated 12-word mnemonic
 */
export function generateRecoveryPhrase(): string {
  // 128 bits of entropy = 12 words
  return generateMnemonic(wordlist, 128);
}

/**
 * Validate that a recovery phrase is a valid BIP39 mnemonic.
 *
 * @param phrase - Space-separated mnemonic words
 * @returns true if the phrase is a valid BIP39 mnemonic
 */
export function validateRecoveryPhrase(phrase: string): boolean {
  // Normalize whitespace: trim and collapse multiple spaces to single space
  const normalized = phrase.trim().toLowerCase().replace(/\s+/g, " ");
  return validateMnemonic(normalized, wordlist);
}

/**
 * Derive a recovery key from a BIP39 mnemonic using HKDF.
 * The key is suitable for AES-256-GCM encryption.
 *
 * @param mnemonic - The 12-word BIP39 mnemonic
 * @returns A CryptoKey for AES-256-GCM encryption/decryption
 */
export async function deriveRecoveryKey(mnemonic: string): Promise<CryptoKey> {
  // Normalize: trim, lowercase, collapse whitespace
  const normalized = mnemonic.trim().toLowerCase().replace(/\s+/g, " ");
  // Convert mnemonic to seed (64 bytes using PBKDF2)
  const seed = await mnemonicToSeed(normalized);

  // Import the seed as HKDF key material
  const hkdfKey = await crypto.subtle.importKey("raw", new Uint8Array(seed), "HKDF", false, [
    "deriveBits",
  ]);

  // Derive 32 bytes using HKDF-SHA256 with domain separation
  const info = new TextEncoder().encode("less:recovery_key:v1");
  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new Uint8Array(0), // Empty salt - seed already has high entropy
      info,
    },
    hkdfKey,
    256, // 256 bits = 32 bytes
  );

  // Import as AES-GCM key
  return crypto.subtle.importKey("raw", derivedBits, { name: "AES-GCM", length: 256 }, false, [
    "encrypt",
    "decrypt",
  ]);
}

/**
 * Encrypt the root_key with the recovery key.
 * Uses AES-256-GCM with a random IV.
 *
 * @param rootKey - The root key (32 bytes)
 * @param recoveryKey - The CryptoKey derived from the mnemonic
 * @returns The encrypted blob ready for server storage
 */
export async function encryptRootKey(
  rootKey: Uint8Array,
  recoveryKey: CryptoKey,
): Promise<RecoveryBlob> {
  // Generate random 12-byte IV for AES-GCM
  const iv = crypto.getRandomValues(new Uint8Array(12));

  // Encrypt the root key
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    recoveryKey,
    new Uint8Array(rootKey),
  );

  return {
    version: 2,
    alg: "A256GCM",
    iv: base64UrlEncode(iv),
    ciphertext: base64UrlEncode(new Uint8Array(ciphertext)),
  };
}

/**
 * Decrypt the root_key from a recovery blob using the recovery key.
 *
 * @param blob - The encrypted recovery blob from the server
 * @param recoveryKey - The CryptoKey derived from the mnemonic
 * @returns The decrypted root key (32 bytes)
 */
export async function decryptRootKey(
  blob: RecoveryBlob,
  recoveryKey: CryptoKey,
): Promise<Uint8Array> {
  if (blob.version !== 2 || blob.alg !== "A256GCM") {
    throw new Error("Unsupported recovery blob format");
  }

  const iv = base64UrlDecode(blob.iv);
  const ciphertext = base64UrlDecode(blob.ciphertext);

  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: new Uint8Array(iv) },
    recoveryKey,
    new Uint8Array(ciphertext),
  );

  return new Uint8Array(plaintext);
}
