/**
 * AUD-008: consent key-material resolution that fails closed.
 *
 * Every path here distinguishes "the grant genuinely has no key material"
 * from "we could not read what is there". Transient failures (network,
 * server errors, undecryptable blobs) throw instead of silently generating
 * replacement keys: a replacement scoped key or signing keypair installed
 * over an existing one strands previously encrypted data and destroys the
 * signing identity. Only an explicit absence may generate fresh material.
 */

import {
  unwrapWithRootKey,
  wrapWithRootKey,
  generateRandomKey,
  computeScopedKeyKid,
  deriveAppKeypairKey,
  generateAppKeypair,
  encryptAppKeypairBlob,
  decryptAppKeypairBlob,
} from "@/lib/crypto";

/** Minimal API surface these helpers need (satisfied by `api`). */
export interface GrantKeyApi {
  getGrantKeypairBlob: (clientId: string) => Promise<GrantKeyInfo>;
}

export interface GrantKeyInfo {
  app_keypair_blob: string;
  wrapped_scoped_key?: string;
}

/**
 * Fetch the grant's stored key info once per consent submit; both the
 * scoped-key and app-keypair resolutions consume this snapshot so they
 * cannot observe different grant states (review of AUD-008).
 */
export async function fetchGrantKeyInfo(api: GrantKeyApi, clientId: string): Promise<GrantKeyInfo> {
  return api.getGrantKeypairBlob(clientId);
}

export interface ResolvedScopedKey {
  /** The scoped key the grant will use. */
  scopedKey: Uint8Array;
  /**
   * Base64 wrapped form to submit with consent — byte-identical to the
   * stored wrapper when reusing, fresh when generating. The server
   * installs the keypair bundle only when this matches its stored state
   * (or the grant is empty), closing the stale-read race atomically.
   */
  wrappedScopedKeyB64: string;
}

export function base64Encode(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

export function base64DecodeToBytes(b64: string): Uint8Array {
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}

/**
 * Resolve the grant's scoped key. Throws when the stored wrapper cannot
 * be unwrapped under the current root key (the shared snapshot fetch
 * already failed closed on read errors).
 */
export async function resolveScopedKey(
  info: GrantKeyInfo,
  rootKey: Uint8Array,
): Promise<ResolvedScopedKey> {
  if (info.wrapped_scoped_key) {
    let scopedKey: Uint8Array;
    try {
      scopedKey = await unwrapWithRootKey(base64DecodeToBytes(info.wrapped_scoped_key), rootKey);
    } catch (err) {
      throw new Error(
        `The existing scoped key could not be unwrapped with this device's root key (${err instanceof Error ? err.message : String(err)}). ` +
          "Refusing to generate a replacement — that would strand data already encrypted under the existing key.",
      );
    }
    return { scopedKey, wrappedScopedKeyB64: info.wrapped_scoped_key };
  }

  // Explicit absence: first consent for this grant — safe to generate.
  const scopedKey = generateRandomKey();
  const wrapped = await wrapWithRootKey(scopedKey, rootKey);
  return { scopedKey, wrappedScopedKeyB64: base64Encode(wrapped) };
}

export interface ResolvedAppKeypair {
  privateKeyJwk: JsonWebKey;
  publicKeyJwk: JsonWebKey;
}

/**
 * Recover the grant's app signing keypair, or generate one on explicit
 * absence only. Undecryptable or malformed existing material throws —
 * silently replacing the signing identity revokes shared-space access
 * and edit-chain continuity.
 */
export async function resolveAppKeypair(
  info: GrantKeyInfo,
  wrappingKey: CryptoKey,
): Promise<ResolvedAppKeypair> {
  if (info.app_keypair_blob) {
    let decrypted: JsonWebKey;
    try {
      decrypted = await decryptAppKeypairBlob(info.app_keypair_blob, wrappingKey);
    } catch (err) {
      throw new Error(
        `The existing app signing key could not be decrypted (${err instanceof Error ? err.message : String(err)}). ` +
          "Refusing to generate a replacement — that would destroy this app's signing identity.",
      );
    }
    if (
      decrypted.kty !== "EC" ||
      decrypted.crv !== "P-256" ||
      !decrypted.x ||
      !decrypted.y ||
      !decrypted.d
    ) {
      throw new Error("The stored app signing key is malformed: expected a P-256 EC private key.");
    }
    return {
      privateKeyJwk: decrypted,
      publicKeyJwk: {
        kty: decrypted.kty,
        crv: decrypted.crv,
        x: decrypted.x,
        y: decrypted.y,
      },
    };
  }

  return generateAppKeypair();
}

/** Convenience: derive the app keypair wrapping key from the scoped key. */
export function appWrappingKey(
  scopedKey: Uint8Array,
  userId: string,
  clientId: string,
): Promise<CryptoKey> {
  return deriveAppKeypairKey(scopedKey, userId, clientId);
}

export { computeScopedKeyKid, encryptAppKeypairBlob };
