import { useState, useEffect } from "react";
import { useSearchParams, useNavigate } from "react-router-dom";
import { Shield, Check, X, AlertTriangle, Loader2, AlertCircle } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { useAuth } from "@/contexts/auth-context";
import { api } from "@/lib/api";
import { formatError } from "@/lib/utils";
import {
  generateRandomKey,
  wrapWithRootKey,
  unwrapWithRootKey,
  encryptAsJWE,
  computeJwkThumbprint,
  parseJwkFromBase64Url,
  buildScopedKeyJWK,
  computeScopedKeyKid,
  isValidP256PublicKey,
  generateAppKeypair,
  deriveAppKeypairKey,
  encryptAppKeypairBlob,
  decryptAppKeypairBlob,
} from "@/lib/crypto";
import type { ScopedKeyJWK } from "@/lib/crypto";

/**
 * Recover an existing app keypair from the server, or generate a fresh one.
 * Falls back to generation on any error (network, decryption, validation).
 */
async function getOrCreateAppKeypair(
  clientId: string,
  wrappingKey: CryptoKey,
): Promise<{ publicKeyJwk: JsonWebKey; privateKeyJwk: JsonWebKey }> {
  try {
    const existing = await api.getGrantKeypairBlob(clientId);
    if (existing.app_keypair_blob) {
      const decrypted = await decryptAppKeypairBlob(existing.app_keypair_blob, wrappingKey);
      if (
        decrypted.kty !== "EC" ||
        decrypted.crv !== "P-256" ||
        !decrypted.x ||
        !decrypted.y ||
        !decrypted.d
      ) {
        throw new Error("Decrypted keypair is invalid: expected P-256 EC private key");
      }
      return {
        privateKeyJwk: decrypted,
        publicKeyJwk: { kty: decrypted.kty, crv: decrypted.crv, x: decrypted.x, y: decrypted.y },
      };
    }
  } catch (err) {
    console.warn(
      "Failed to recover existing keypair, generating new:",
      err instanceof Error ? err.message : String(err),
    );
  }
  return generateAppKeypair();
}

export function ConsentPage() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const { authToken, userId, email: loginIdentifier, rootKey, hasRootKey } = useAuth();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // OAuth state token from server (contains all validated OAuth params)
  const oauthState = searchParams.get("oauth");
  const clientId = searchParams.get("client_id") || "";
  const clientName = searchParams.get("client_name") || "Unknown Application";
  const scopeString = searchParams.get("scope") || "profile";
  const scopes = scopeString.split(" ");

  // Server-validated keys_jwk passed as URL parameter (not parsed from JWT)
  const keysJwkParam = searchParams.get("keys_jwk");

  // Check if sync scope is requested with keys_jwk (require key derivation)
  const hasSyncScope = scopes.includes("sync");
  const needsKeyDerivation = hasSyncScope && !!keysJwkParam;

  // Build login URL with all OAuth params preserved (including keys_jwk)
  const buildLoginUrl = (reauth: boolean = false) => {
    const params = new URLSearchParams({
      oauth: oauthState || "",
      client_id: clientId,
      client_name: clientName,
      scope: scopeString,
    });
    if (keysJwkParam) {
      params.set("keys_jwk", keysJwkParam);
    }
    if (reauth && loginIdentifier) {
      params.set("reauth", "true");
      params.set("username", loginIdentifier);
    }
    return `/login?${params.toString()}`;
  };

  useEffect(() => {
    // If not logged in, redirect to login with OAuth params
    if (!authToken && oauthState) {
      navigate(buildLoginUrl());
    }
  }, [authToken, oauthState, clientName, scopeString, keysJwkParam, navigate]);

  // If sync scope with keys_jwk is requested but we don't have the root key (page refresh),
  // redirect to login to re-authenticate with reauth mode for better UX
  useEffect(() => {
    if (authToken && needsKeyDerivation && !hasRootKey && oauthState) {
      navigate(buildLoginUrl(true));
    }
  }, [
    authToken,
    needsKeyDerivation,
    hasRootKey,
    oauthState,
    clientId,
    clientName,
    scopeString,
    keysJwkParam,
    loginIdentifier,
    navigate,
  ]);

  const scopeDescriptions: Record<string, string> = {
    openid: "Verify your identity",
    profile: "Access your basic profile information",
    email: "Read your email address",
    sync: "Sync app data across devices",
    files: "Upload and download large files",
  };

  const getScopeDescription = (scope: string): string => {
    return scopeDescriptions[scope] || scope;
  };

  const handleConsent = async (approved: boolean) => {
    if (!oauthState || !userId) return;

    // If sync scope with keys_jwk is requested but we don't have root key, redirect to reauth
    if (approved && needsKeyDerivation && !rootKey) {
      navigate(buildLoginUrl(true));
      return;
    }

    setLoading(true);
    setError(null);

    try {
      let keysJWE: string | undefined;
      let keysJWKThumbprint: string | undefined;
      let appKeypairBlob: string | undefined;
      let appPublicKeyJwk: string | undefined;
      let wrappedScopedKeyB64: string | undefined;

      // If sync scope is requested with keys_jwk and approved, derive and encrypt key
      if (approved && needsKeyDerivation && rootKey && clientId) {
        if (!keysJwkParam) {
          throw new Error(
            "Missing keys_jwk - app must provide ephemeral public key for encryption",
          );
        }

        const recipientPublicKey = parseJwkFromBase64Url(keysJwkParam);

        if (!isValidP256PublicKey(recipientPublicKey)) {
          throw new Error("Invalid recipient public key");
        }

        // Check if we already have a wrapped scoped key for this grant
        let scopedKey: Uint8Array;
        let existingWrappedScopedKey: string | undefined;

        try {
          const grantInfo = await api.getGrantKeypairBlob(clientId);
          if (grantInfo.wrapped_scoped_key) {
            existingWrappedScopedKey = grantInfo.wrapped_scoped_key;
          }
        } catch {
          // No existing grant, will generate new scoped key
        }

        if (existingWrappedScopedKey) {
          // Unwrap existing scoped key with root key
          const wrappedBytes = Uint8Array.from(atob(existingWrappedScopedKey), (c) =>
            c.charCodeAt(0),
          );
          scopedKey = await unwrapWithRootKey(wrappedBytes, rootKey);
        } else {
          // Generate new random scoped key and wrap it
          scopedKey = generateRandomKey();
          const wrappedScopedKey = await wrapWithRootKey(scopedKey, rootKey);
          wrappedScopedKeyB64 = btoa(String.fromCharCode(...wrappedScopedKey));
        }

        const kid = await computeScopedKeyKid(scopedKey);

        // Derive app keypair wrapping key from scopedKey (not rootKey/exportKey)
        const appWrappingKey = await deriveAppKeypairKey(scopedKey, userId, clientId);
        const { publicKeyJwk, privateKeyJwk } = await getOrCreateAppKeypair(
          clientId,
          appWrappingKey,
        );

        // Encrypt the private key as a blob for server storage
        appKeypairBlob = await encryptAppKeypairBlob(privateKeyJwk, appWrappingKey);
        appPublicKeyJwk = JSON.stringify({
          kty: publicKeyJwk.kty,
          crv: publicKeyJwk.crv,
          x: publicKeyJwk.x,
          y: publicKeyJwk.y,
        });

        // Build scoped keys payload including both the symmetric key and the app keypair
        const scopedKeys: Record<string, ScopedKeyJWK | JsonWebKey> = {
          [clientId]: buildScopedKeyJWK(scopedKey, kid),
          "app-keypair": {
            kty: privateKeyJwk.kty!,
            crv: privateKeyJwk.crv!,
            x: privateKeyJwk.x!,
            y: privateKeyJwk.y!,
            d: privateKeyJwk.d!,
            alg: "ES256",
          },
        };

        // Encrypt to the app's ephemeral public key
        keysJWE = await encryptAsJWE(scopedKeys, recipientPublicKey);

        // Compute the thumbprint for PKCE binding
        keysJWKThumbprint = await computeJwkThumbprint(recipientPublicKey);
      }

      const response = await api.oauthConsent(
        oauthState,
        approved,
        keysJWE,
        keysJWKThumbprint,
        appKeypairBlob,
        appPublicKeyJwk,
        wrappedScopedKeyB64,
      );
      // Redirect to the client's redirect_uri with code or error
      window.location.href = response.redirect_uri;
    } catch (err) {
      setError(formatError(err, "Failed to process consent"));
      setLoading(false);
    }
  };

  // Missing OAuth state - invalid request
  if (!oauthState) {
    return (
      <div className="flex min-h-screen items-center justify-center p-4">
        <Card className="w-full max-w-md">
          <CardHeader className="text-center">
            <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-full bg-destructive/10">
              <AlertTriangle className="h-6 w-6 text-destructive" />
            </div>
            <CardTitle className="text-xl">Invalid Request</CardTitle>
            <CardDescription>
              This authorization request is invalid or has been tampered with.
            </CardDescription>
          </CardHeader>
        </Card>
      </div>
    );
  }

  // Not logged in - show loading while redirecting
  if (!authToken) {
    return (
      <div className="flex min-h-screen items-center justify-center p-4">
        <Card className="w-full max-w-md">
          <CardHeader className="text-center">
            <Loader2 className="mx-auto h-8 w-8 animate-spin text-primary" />
            <CardDescription className="mt-4">Redirecting to login...</CardDescription>
          </CardHeader>
        </Card>
      </div>
    );
  }

  return (
    <div className="flex min-h-screen items-center justify-center p-4">
      <Card className="w-full max-w-md">
        <CardHeader className="text-center">
          <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-full bg-primary/10">
            <Shield className="h-6 w-6 text-primary" />
          </div>
          <CardTitle className="text-xl">Authorize {clientName}</CardTitle>
          <CardDescription>This application wants to access your account</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-3">
            <p className="text-sm font-medium text-muted-foreground">
              This will allow {clientName} to:
            </p>
            <ul className="space-y-2">
              {scopes.map((scope) => (
                <li key={scope} className="flex items-center gap-2 rounded-md bg-muted p-2 text-sm">
                  <Check className="h-4 w-4 text-primary" />
                  <span>{getScopeDescription(scope)}</span>
                </li>
              ))}
            </ul>
            {error && (
              <div
                role="alert"
                className="flex items-center gap-2 rounded-md bg-destructive/10 p-3 text-sm text-destructive"
              >
                <AlertCircle className="h-4 w-4 flex-shrink-0" />
                <span>{error}</span>
              </div>
            )}
          </div>
        </CardContent>
        <CardFooter className="flex gap-3">
          <Button
            variant="outline"
            className="flex-1"
            onClick={() => handleConsent(false)}
            disabled={loading}
          >
            {loading ? (
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
            ) : (
              <X className="mr-2 h-4 w-4" />
            )}
            Deny
          </Button>
          <Button className="flex-1" onClick={() => handleConsent(true)} disabled={loading}>
            {loading ? (
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
            ) : (
              <Check className="mr-2 h-4 w-4" />
            )}
            Allow
          </Button>
        </CardFooter>
      </Card>
    </div>
  );
}
