import { useEffect, useMemo, useState } from "react";
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
  const [storing, setStoring] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Check if coming from password reset
  const isReset = searchParams.get("reset") === "true";

  // OAuth parameter (passed through from signup; only the signed state)
  const oauthState = searchParams.get("oauth");

  // Generate mnemonic once on mount. The encrypted blob is only stored
  // after the user confirms saving the phrase (AUD-016): storing on mount
  // replaced the previously recorded recovery secret before the user had
  // the new phrase anywhere — closing the tab or refreshing at that moment
  // invalidated the old recovery path with the new one lost.
  const mnemonic = useMemo(() => generateRecoveryPhrase(), []);

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

  const handleContinue = async () => {
    // AUD-016: activate the new recovery secret only after the user has
    // confirmed saving the phrase. Until this write lands, the previous
    // recovery path (old phrase / password / device) stays intact. The
    // user cannot leave the flow with the write unacknowledged: navigation
    // happens only after the store succeeds.
    if (storing) return;
    setStoring(true);
    try {
      const recoveryKey = await deriveRecoveryKey(mnemonic);
      const blob = await encryptRootKey(rootKey!, recoveryKey);
      await api.storeRecoveryBlob(JSON.stringify(blob));
    } catch (err) {
      setError(formatError(err, "Failed to set up recovery"));
      setStoring(false);
      return;
    }

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
      {error && <p className="mb-4 text-destructive">{error}</p>}
      <MnemonicDisplay
        mnemonic={mnemonic}
        onContinue={handleContinue}
        disabled={storing}
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
