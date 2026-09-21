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
  encryptAsJWE,
  computeJwkThumbprint,
  buildScopedKeyJWK,
  isValidP256PublicKey,
} from "@/lib/crypto";
import type { ScopedKeyJWK } from "@/lib/crypto";
import {
  fetchGrantKeyInfo,
  resolveScopedKey,
  resolveAppKeypair,
  appWrappingKey,
  computeScopedKeyKid,
  encryptAppKeypairBlob,
} from "@/lib/consent-keys";

/** Server-validated authorization context from /oauth/consent-context. */
interface ConsentContext {
  clientId: string;
  clientName: string;
  scopes: string[];
  keysJwk?: { kty: string; crv: string; x: string; y: string };
}

export function ConsentPage() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const {
    authToken,
    userId,
    email: loginIdentifier,
    rootKey,
    rootKeyVersion,
    hasRootKey,
  } = useAuth();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [context, setContext] = useState<ConsentContext | null>(null);

  // Only the signed state token is read from the URL. Everything the page
  // displays or uses for key wrapping comes from the server-validated
  // authorization context (/oauth/consent-context), never from unsigned URL
  // parameters.
  const oauthState = searchParams.get("oauth");

  const scopes = context?.scopes ?? [];

  // Check if sync scope is requested with keys_jwk (require key derivation)
  const hasSyncScope = scopes.includes("sync");
  const needsKeyDerivation = hasSyncScope && !!context?.keysJwk;

  // Build login URL with the signed state preserved
  const buildLoginUrl = (reauth: boolean = false) => {
    const params = new URLSearchParams({
      oauth: oauthState || "",
    });
    if (reauth && loginIdentifier) {
      params.set("reauth", "true");
      params.set("username", loginIdentifier);
    }
    return `/login?${params.toString()}`;
  };

  // Load the server-validated authorization context once authenticated
  useEffect(() => {
    if (!authToken || !oauthState || context) return;
    let cancelled = false;
    (async () => {
      try {
        const ctx = await api.getConsentContext(oauthState);
        if (cancelled) return;
        setContext({
          clientId: ctx.client_id,
          clientName: ctx.client_name,
          scopes: ctx.scope.split(" ").filter(Boolean),
          keysJwk: ctx.keys_jwk,
        });
      } catch (err) {
        if (cancelled) return;
        setError(formatError(err, "Failed to load authorization request"));
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [authToken, oauthState, context]);

  useEffect(() => {
    // If not logged in, redirect to login with the signed OAuth state
    if (!authToken && oauthState) {
      navigate(buildLoginUrl());
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [authToken, oauthState, navigate]);

  // If sync scope with keys_jwk is requested but we don't have the root key
  // (page refresh), redirect to login to re-authenticate with reauth mode
  // for better UX
  useEffect(() => {
    if (authToken && needsKeyDerivation && !hasRootKey && oauthState) {
      navigate(buildLoginUrl(true));
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [authToken, needsKeyDerivation, hasRootKey, oauthState, loginIdentifier, navigate]);

  const scopeDescriptions: Record<string, string> = {
    openid: "Verify your identity",
    profile: "Access your basic profile information",
    email: "Read your email address",
    sync: "Sync app data across devices",
    files: "Upload and download large files",
  };

  const getScopeDescription = (scope: string) => {
    return scopeDescriptions[scope] || scope;
  };

  const handleConsent = async (approved: boolean) => {
    if (!oauthState || !userId || !context) return;

    // If sync scope with keys_jwk is requested but we don't have root key,
    // redirect to reauth
    if (approved && needsKeyDerivation && !rootKey) {
      navigate(buildLoginUrl(true));
      return;
    }

    const { clientId, keysJwk } = context;

    setLoading(true);
    setError(null);

    try {
      let keysJWE: string | undefined;
      let keysJWKThumbprint: string | undefined;
      let appKeypairBlob: string | undefined;
      let appPublicKeyJwk: string | undefined;
      let wrappedScopedKeyB64: string | undefined;

      // If sync scope is requested with keys_jwk and approved, derive and
      // encrypt key. The recipient is the server-validated keys_jwk from the
      // signed authorization context.
      if (approved && needsKeyDerivation && rootKey && clientId) {
        if (!keysJwk) {
          throw new Error(
            "Missing keys_jwk - app must provide ephemeral public key for encryption",
          );
        }

        // The recipient JWK arrives as an object from the server-validated
        // context (already parsed from the signed state).
        const recipientPublicKey = keysJwk as unknown as JsonWebKey;

        if (!isValidP256PublicKey(recipientPublicKey)) {
          throw new Error("Invalid recipient public key");
        }

        // AUD-008: resolve the scoped key and app keypair through
        // fail-closed helpers over a SINGLE grant snapshot. A transient
        // read failure or an undecryptable existing blob throws — it must
        // never silently generate replacement key material over an
        // existing grant.
        const grantInfo = await fetchGrantKeyInfo(api, clientId);
        const resolved = await resolveScopedKey(grantInfo, rootKey);
        // Always submit the wrapped form alongside the keypair: the server
        // installs the bundle only when it matches the stored wrapper (or
        // the grant is empty), atomically rejecting stale-read races.
        wrappedScopedKeyB64 = resolved.wrappedScopedKeyB64;

        const kid = await computeScopedKeyKid(resolved.scopedKey);

        const wrappingKey = await appWrappingKey(resolved.scopedKey, userId, clientId);
        const { publicKeyJwk, privateKeyJwk } = await resolveAppKeypair(grantInfo, wrappingKey);

        // Encrypt the private key as a blob for server storage
        appKeypairBlob = await encryptAppKeypairBlob(privateKeyJwk, wrappingKey);
        appPublicKeyJwk = JSON.stringify({
          kty: publicKeyJwk.kty,
          crv: publicKeyJwk.crv,
          x: publicKeyJwk.x,
          y: publicKeyJwk.y,
        });

        // Build scoped keys payload including both the symmetric key and the
        // app keypair
        const scopedKeys: Record<string, ScopedKeyJWK | JsonWebKey> = {
          [clientId]: buildScopedKeyJWK(resolved.scopedKey, kid),
          "app-keypair": {
            kty: privateKeyJwk.kty!,
            crv: privateKeyJwk.crv!,
            x: privateKeyJwk.x!,
            y: privateKeyJwk.y!,
            d: privateKeyJwk.d!,
            alg: "ES256",
          },
        };

        // Encrypt to the app's ephemeral public key from the signed context
        keysJWE = await encryptAsJWE(scopedKeys, recipientPublicKey);

        // Compute the thumbprint of the signed recipient for PKCE binding
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
        rootKeyVersion ?? undefined,
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

  // Authenticated but the server-validated context has not loaded yet
  if (!context) {
    return (
      <div className="flex min-h-screen items-center justify-center p-4">
        <Card className="w-full max-w-md">
          <CardHeader className="text-center">
            {error ? (
              <>
                <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-full bg-destructive/10">
                  <AlertTriangle className="h-6 w-6 text-destructive" />
                </div>
                <CardTitle className="text-xl">Invalid Request</CardTitle>
                <CardDescription>{error}</CardDescription>
              </>
            ) : (
              <>
                <Loader2 className="mx-auto h-8 w-8 animate-spin text-primary" />
                <CardDescription className="mt-4">Loading authorization request...</CardDescription>
              </>
            )}
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
          <CardTitle className="text-xl">Authorize {context.clientName}</CardTitle>
          <CardDescription>This application wants to access your account</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-3">
            <p className="text-sm font-medium text-muted-foreground">
              This will allow {context.clientName} to:
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
