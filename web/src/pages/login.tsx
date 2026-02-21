import { useNavigate, useSearchParams } from "react-router-dom";
import { AuthForm } from "@/components/auth-form";
import { useAuth } from "@/contexts/auth-context";
import { api } from "@/lib/api";
import { startLogin, finishLogin } from "@/lib/opaque";
import { getSafeRedirect } from "@/lib/redirect";
import { base64UrlDecode, deriveRootKeyWrappingKey, unwrapRootKey } from "@/lib/crypto";
import { solveCAPChallenge } from "@/lib/cap";

export function LoginPage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { setAuth } = useAuth();

  // Check for OAuth flow - if oauth param exists, redirect to consent after login
  const oauthState = searchParams.get("oauth");
  const oauthClientId = searchParams.get("client_id");
  const oauthClientName = searchParams.get("client_name");
  const oauthScope = searchParams.get("scope");
  const oauthKeysJwk = searchParams.get("keys_jwk");

  // Reauth mode - user is already logged in but needs to re-enter password
  // (e.g., to derive export key for scoped encryption)
  const isReauth = searchParams.get("reauth") === "true";
  const reauthUsername = searchParams.get("username");

  // Normal redirect or consent page redirect for OAuth
  const getRedirectTo = () => {
    if (oauthState) {
      const params = new URLSearchParams({
        oauth: oauthState,
        client_id: oauthClientId || "",
        client_name: oauthClientName || "",
        scope: oauthScope || "",
      });
      if (oauthKeysJwk) {
        params.set("keys_jwk", oauthKeysJwk);
      }
      return `/consent?${params.toString()}`;
    }
    return getSafeRedirect(searchParams.get("redirect"));
  };

  const handleLogin = async (username: string, _email: string, password: string) => {
    // Step 0: Solve CAP proof-of-work challenge
    const capToken = await solveCAPChallenge();

    // Step 1: Start OPAQUE login
    const { clientLoginState, ke1 } = await startLogin(password);

    // Step 2: Send KE1 to server, get KE2
    const initResponse = await api.loginInit(username, ke1, capToken);

    // Step 3: Finish OPAQUE login
    const loginResult = await finishLogin(clientLoginState, initResponse.opaque_ke2, password);

    if (!loginResult) {
      throw new Error("Invalid username or password");
    }

    // Step 4: Send KE3 to server to complete authentication
    const finalResponse = await api.loginFinalize(initResponse.login_token, loginResult.ke3);

    const exportKeyBytes = base64UrlDecode(loginResult.exportKey);

    // Step 5: Fetch and unwrap root key (pass token directly — not yet in localStorage)
    const rootKeyResponse = await api.getRootKey(finalResponse.auth_token);
    const wrappedRootKey = Uint8Array.from(atob(rootKeyResponse.wrapped_root_key), (c) =>
      c.charCodeAt(0),
    );
    const wrappingKey = await deriveRootKeyWrappingKey(exportKeyBytes, finalResponse.user_id);
    const rootKey = await unwrapRootKey(wrappedRootKey, wrappingKey);

    // Store auth token, export key, and root key in context
    setAuth(finalResponse.auth_token, finalResponse.user_id, username, exportKeyBytes, rootKey);

    // Redirect
    navigate(getRedirectTo());
  };

  return (
    <div className="flex min-h-screen items-center justify-center p-4">
      <div className="w-full max-w-md">
        <AuthForm
          mode="login"
          onSubmit={handleLogin}
          defaultUsername={reauthUsername || ""}
          usernameReadOnly={isReauth && !!reauthUsername}
          showEmail={false}
          title={isReauth ? "Verify your password" : undefined}
          description={isReauth ? "Please re-enter your password to continue" : undefined}
          submitLabel={isReauth ? "Continue" : undefined}
          hideAccountLink={isReauth}
          showForgotPassword={!isReauth}
        />
      </div>
    </div>
  );
}
