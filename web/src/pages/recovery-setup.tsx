import { useEffect, useMemo, useState, useRef } from "react";
import { useNavigate, useSearchParams, Navigate } from "react-router-dom";
import { MnemonicDisplay } from "@/components/recovery/mnemonic-display";
import { useAuth } from "@/contexts/auth-context";
import { api } from "@/lib/api";
import { generateRecoveryPhrase, deriveRecoveryKey, encryptRootKey } from "@/lib/recovery";
import { formatError } from "@/lib/utils";

export function RecoverySetupPage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { authToken, rootKey } = useAuth();
  const [blobStored, setBlobStored] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const storingRef = useRef(false);

  // Check if coming from password reset
  const isReset = searchParams.get("reset") === "true";

  // OAuth parameter (passed through from signup; only the signed state)
  const oauthState = searchParams.get("oauth");

  // Generate mnemonic once on mount
  const mnemonic = useMemo(() => generateRecoveryPhrase(), []);

  // Store the encrypted blob immediately when we have the root key
  useEffect(() => {
    if (!rootKey || storingRef.current || blobStored) return;
    storingRef.current = true;

    (async () => {
      try {
        const recoveryKey = await deriveRecoveryKey(mnemonic);
        const blob = await encryptRootKey(rootKey, recoveryKey);
        await api.storeRecoveryBlob(JSON.stringify(blob));
        setBlobStored(true);
      } catch (err) {
        setError(formatError(err, "Failed to set up recovery"));
        storingRef.current = false;
      }
    })();
  }, [rootKey, mnemonic, blobStored]);

  // If root key is missing (page refresh), redirect to login with return URL
  useEffect(() => {
    if (authToken && !rootKey) {
      const params = new URLSearchParams();
      params.set("redirect", "/recovery-setup");
      if (oauthState) {
        params.set("oauth", oauthState);
      }
      navigate(`/login?${params.toString()}`, { replace: true });
    }
  }, [authToken, rootKey, navigate, oauthState]);

  // If not authenticated at all, redirect to login
  if (!authToken) {
    const params = new URLSearchParams(searchParams);
    params.set("redirect", "/recovery-setup");
    return <Navigate to={`/login?${params.toString()}`} replace />;
  }

  // If no root key, show loading while redirect happens
  if (!rootKey) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <p className="text-muted-foreground">Redirecting to login...</p>
      </div>
    );
  }

  // Show error if blob storage failed
  if (error) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <p className="text-destructive">{error}</p>
      </div>
    );
  }

  const handleContinue = () => {
    // Build redirect destination — only the signed state token is preserved;
    // the consent page loads its context from the server.
    if (oauthState) {
      navigate(`/consent?oauth=${encodeURIComponent(oauthState)}`);
    } else {
      navigate("/");
    }
  };

  return (
    <div className="flex min-h-screen flex-col items-center justify-center p-4">
      <MnemonicDisplay
        mnemonic={mnemonic}
        onContinue={handleContinue}
        {...(isReset && {
          title: "New Recovery Phrase",
          description:
            "Your password has been reset. Save this new recovery phrase in place of your old one.",
          checkboxLabel: "I have replaced my old recovery phrase with this new one",
        })}
      />
    </div>
  );
}
