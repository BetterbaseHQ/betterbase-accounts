import * as jose from "jose";
import { base64UrlDecode, base64UrlEncode } from "./base64url";

/**
 * Type for scoped key JWK (what we encrypt in the JWE payload)
 */
export interface ScopedKeyJWK {
  kty: "oct";
  k: string; // base64url-encoded key material
  kid: string;
  alg: "A256GCM";
}

// Client ID must be alphanumeric with hyphens/underscores only.
// This prevents injection attacks via the HKDF info string.
const VALID_CLIENT_ID_PATTERN = /^[a-zA-Z0-9_-]+$/;

// UUID format validation for userId in HKDF info strings.
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Validate that a client ID is safe to use in HKDF info string.
 * Client IDs must be alphanumeric with hyphens and underscores only.
 */
export function isValidClientId(clientId: string): boolean {
  return VALID_CLIENT_ID_PATTERN.test(clientId) && clientId.length > 0 && clientId.length <= 128;
}

/**
 * Validate that a userId is a valid UUID format.
 * Prevents colon injection in HKDF info strings.
 */
function validateUserId(userId: string): void {
  if (!UUID_PATTERN.test(userId)) {
    throw new Error("Invalid user ID format: must be UUID");
  }
}

// Version byte for wrapped key blobs
const WRAPPED_KEY_VERSION = 0x01;

/**
 * Generate a random 32-byte key.
 */
export function generateRandomKey(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32));
}

/**
 * Derive a wrapping key for the root key using HKDF-SHA256.
 * Info string: "betterbase:root_key_wrap:v1:{userId}"
 */
export async function deriveRootKeyWrappingKey(
  exportKey: Uint8Array,
  userId: string,
): Promise<CryptoKey> {
  validateUserId(userId);

  const info = new TextEncoder().encode(`betterbase:root_key_wrap:v1:${userId}`);

  const baseKey = await crypto.subtle.importKey("raw", new Uint8Array(exportKey), "HKDF", false, [
    "deriveKey",
  ]);

  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new Uint8Array(0),
      info,
    },
    baseKey,
    { name: "AES-KW", length: 256 },
    false,
    ["wrapKey", "unwrapKey"],
  );
}

/**
 * Wrap a key using AES-KW.
 * Returns [version:1B][AES-KW output:40B] = 41 bytes.
 */
async function aesKwWrap(keyToWrap: Uint8Array, wrappingKey: CryptoKey): Promise<Uint8Array> {
  // Import the raw key as a CryptoKey for wrapping
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    new Uint8Array(keyToWrap),
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt"],
  );

  const wrapped = await crypto.subtle.wrapKey("raw", cryptoKey, wrappingKey, "AES-KW");

  // Prepend version byte
  const result = new Uint8Array(1 + wrapped.byteLength);
  result[0] = WRAPPED_KEY_VERSION;
  result.set(new Uint8Array(wrapped), 1);
  return result;
}

/**
 * Unwrap a key using AES-KW.
 * Expects [version:1B][AES-KW output:40B] = 41 bytes.
 */
async function aesKwUnwrap(wrappedBlob: Uint8Array, unwrappingKey: CryptoKey): Promise<Uint8Array> {
  if (wrappedBlob.length !== 41) {
    throw new Error(`Invalid wrapped key length: expected 41, got ${wrappedBlob.length}`);
  }
  if (wrappedBlob[0] !== WRAPPED_KEY_VERSION) {
    throw new Error(`Unsupported wrapped key version: ${wrappedBlob[0]}`);
  }

  const wrapped = wrappedBlob.slice(1);

  const unwrapped = await crypto.subtle.unwrapKey(
    "raw",
    wrapped,
    unwrappingKey,
    "AES-KW",
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt"],
  );

  const exported = await crypto.subtle.exportKey("raw", unwrapped);
  return new Uint8Array(exported);
}

/**
 * Wrap the root key with the export-key-derived wrapping key.
 * Returns 41 bytes: [version:1B][AES-KW output:40B]
 */
export async function wrapRootKey(
  rootKey: Uint8Array,
  wrappingKey: CryptoKey,
): Promise<Uint8Array> {
  return aesKwWrap(rootKey, wrappingKey);
}

/**
 * Unwrap the root key.
 */
export async function unwrapRootKey(
  wrapped: Uint8Array,
  wrappingKey: CryptoKey,
): Promise<Uint8Array> {
  return aesKwUnwrap(wrapped, wrappingKey);
}

/**
 * Wrap a scoped key with the root key.
 * First imports the root key as an AES-KW CryptoKey.
 */
export async function wrapWithRootKey(key: Uint8Array, rootKey: Uint8Array): Promise<Uint8Array> {
  const wrappingKey = await crypto.subtle.importKey(
    "raw",
    new Uint8Array(rootKey),
    { name: "AES-KW", length: 256 },
    false,
    ["wrapKey"],
  );
  return aesKwWrap(key, wrappingKey);
}

/**
 * Unwrap a scoped key with the root key.
 */
export async function unwrapWithRootKey(
  wrapped: Uint8Array,
  rootKey: Uint8Array,
): Promise<Uint8Array> {
  const unwrappingKey = await crypto.subtle.importKey(
    "raw",
    new Uint8Array(rootKey),
    { name: "AES-KW", length: 256 },
    false,
    ["unwrapKey"],
  );
  return aesKwUnwrap(wrapped, unwrappingKey);
}

/**
 * Compute JWK thumbprint per RFC 7638.
 * For EC P-256 keys: SHA-256({"crv":"P-256","kty":"EC","x":"...","y":"..."})
 *
 * @param jwk - The JWK to compute thumbprint for
 * @returns Base64url-encoded SHA-256 thumbprint
 */
export async function computeJwkThumbprint(jwk: JsonWebKey): Promise<string> {
  // For EC keys, the thumbprint input is {"crv","kty","x","y"} in that order
  if (jwk.kty === "EC") {
    const thumbprintInput = JSON.stringify({
      crv: jwk.crv,
      kty: jwk.kty,
      x: jwk.x,
      y: jwk.y,
    });
    const hash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(thumbprintInput));
    return base64UrlEncode(new Uint8Array(hash));
  }

  // For other key types, delegate to jose's implementation
  return jose.calculateJwkThumbprint(jwk as jose.JWK, "sha256");
}

/**
 * Encrypt a scoped keys payload as JWE using ECDH-ES + A256GCM.
 *
 * @param payload - Map of client IDs to scoped key JWKs
 * @param recipientPublicKey - The app's ephemeral P-256 public key as JWK
 * @returns The compact JWE string
 */
export async function encryptAsJWE(
  payload: Record<string, ScopedKeyJWK | JsonWebKey>,
  recipientPublicKey: JsonWebKey,
): Promise<string> {
  // Import the recipient's public key
  const publicKey = await jose.importJWK(recipientPublicKey as jose.JWK, "ECDH-ES+A256KW");

  // Create the JWE
  const jwe = await new jose.CompactEncrypt(new TextEncoder().encode(JSON.stringify(payload)))
    .setProtectedHeader({
      alg: "ECDH-ES+A256KW",
      enc: "A256GCM",
      // Include the recipient's key thumbprint for key identification
      kid: await computeJwkThumbprint(recipientPublicKey),
    })
    .encrypt(publicKey);

  return jwe;
}

/**
 * Parse a base64url-encoded JWK string.
 *
 * @param encoded - Base64url-encoded JWK JSON
 * @returns The parsed JWK
 */
export function parseJwkFromBase64Url(encoded: string): JsonWebKey {
  const json = new TextDecoder().decode(base64UrlDecode(encoded));
  return JSON.parse(json);
}

/**
 * Validate that a JWK is a P-256 EC public key suitable for ECDH.
 *
 * @param jwk - The JWK to validate
 * @returns true if valid P-256 public key
 */
export function isValidP256PublicKey(jwk: JsonWebKey): boolean {
  return (
    jwk.kty === "EC" &&
    jwk.crv === "P-256" &&
    typeof jwk.x === "string" &&
    typeof jwk.y === "string" &&
    jwk.d === undefined // Must not contain private key
  );
}

/**
 * Build a ScopedKeyJWK from raw key material.
 */
export function buildScopedKeyJWK(key: Uint8Array, kid: string): ScopedKeyJWK {
  return {
    kty: "oct",
    k: base64UrlEncode(key),
    kid,
    alg: "A256GCM",
  };
}

/**
 * Compute a key ID (kid) for a scoped key.
 */
export async function computeScopedKeyKid(key: Uint8Array): Promise<string> {
  const keyHash = await crypto.subtle.digest("SHA-256", new Uint8Array(key));
  const fingerprint = Array.from(new Uint8Array(keyHash).slice(0, 8))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  const timestamp = Math.floor(Date.now() / 1000);
  return `${timestamp}-${fingerprint}`;
}

/**
 * Generate a P-256 ECDSA keypair for app-level identity.
 * Returns the public and private key as JWKs.
 */
export async function generateAppKeypair(): Promise<{
  publicKeyJwk: JsonWebKey;
  privateKeyJwk: JsonWebKey;
}> {
  const { publicKey, privateKey } = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );

  const publicKeyJwk = await crypto.subtle.exportKey("jwk", publicKey);
  const privateKeyJwk = await crypto.subtle.exportKey("jwk", privateKey);

  return { publicKeyJwk, privateKeyJwk };
}

/**
 * Derive a wrapping key for the app keypair blob using HKDF.
 * Sourced from scopedKey (NOT exportKey) — survives both password change and root key rotation.
 * Info string: "betterbase:app_keypair:v1:{userId}:{clientId}"
 */
export async function deriveAppKeypairKey(
  scopedKey: Uint8Array,
  userId: string,
  clientId: string,
): Promise<CryptoKey> {
  validateUserId(userId);
  if (!isValidClientId(clientId)) {
    throw new Error("Invalid client ID format");
  }

  const info = new TextEncoder().encode(`betterbase:app_keypair:v1:${userId}:${clientId}`);

  const baseKey = await crypto.subtle.importKey("raw", new Uint8Array(scopedKey), "HKDF", false, [
    "deriveKey",
  ]);

  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new Uint8Array(0),
      info,
    },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

/**
 * Encrypt a private key JWK into a blob using AES-256-GCM.
 * Returns a base64-encoded string containing IV + ciphertext.
 */
export async function encryptAppKeypairBlob(
  privateKeyJwk: JsonWebKey,
  wrappingKey: CryptoKey,
): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = new TextEncoder().encode(JSON.stringify(privateKeyJwk));

  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, wrappingKey, plaintext);

  // Concatenate IV + ciphertext
  const combined = new Uint8Array(iv.length + ciphertext.byteLength);
  combined.set(iv);
  combined.set(new Uint8Array(ciphertext), iv.length);

  const chars = Array.from(combined, (byte) => String.fromCharCode(byte));
  return btoa(chars.join(""));
}

/**
 * Decrypt an app keypair blob back to a private key JWK.
 */
export async function decryptAppKeypairBlob(
  blob: string,
  wrappingKey: CryptoKey,
): Promise<JsonWebKey> {
  const binaryString = atob(blob);
  const combined = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    combined[i] = binaryString.charCodeAt(i);
  }

  const iv = combined.slice(0, 12);
  const ciphertext = combined.slice(12);

  const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, wrappingKey, ciphertext);

  return JSON.parse(new TextDecoder().decode(plaintext));
}

// Re-export for use in demo app
export { base64UrlEncode, base64UrlDecode };
