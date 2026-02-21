import { useState } from "react";
import { useNavigate, useSearchParams, Link } from "react-router-dom";
import { Loader2, Mail, AtSign } from "lucide-react";
import { AuthForm } from "@/components/auth-form";
import { VerificationForm } from "@/components/verification-form";
import { useAuth } from "@/contexts/auth-context";
import { api } from "@/lib/api";
import { startRegistration, finishRegistration } from "@/lib/opaque";
import {
  base64UrlDecode,
  generateRandomKey,
  deriveRootKeyWrappingKey,
  wrapRootKey,
} from "@/lib/crypto";
import { solveCAPChallenge } from "@/lib/cap";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { cn, formatError } from "@/lib/utils";
import { AlertCircle } from "lucide-react";
import { validateEmail, validateUsername } from "@/lib/validation";

type Step = "email" | "verify" | "password";

export function SignupPage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { setAuth } = useAuth();

  const [step, setStep] = useState<Step>("email");
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [verificationToken, setVerificationToken] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});

  // Check for OAuth flow - if oauth param exists, redirect to consent after signup
  const oauthState = searchParams.get("oauth");
  const oauthClientId = searchParams.get("client_id");
  const oauthClientName = searchParams.get("client_name");
  const oauthScope = searchParams.get("scope");
  const oauthKeysJwk = searchParams.get("keys_jwk");

  // Always redirect to recovery-setup after signup, preserving OAuth params
  const getRedirectTo = () => {
    const params = new URLSearchParams();
    if (oauthState) {
      params.set("oauth", oauthState);
      params.set("client_id", oauthClientId || "");
      params.set("client_name", oauthClientName || "");
      params.set("scope", oauthScope || "");
      if (oauthKeysJwk) {
        params.set("keys_jwk", oauthKeysJwk);
      }
    }
    const query = params.toString();
    return `/recovery-setup${query ? "?" + query : ""}`;
  };

  const queryString = searchParams.toString();
  const linkSuffix = queryString ? `?${queryString}` : "";

  const clearFieldError = (field: string) => {
    setFieldErrors((prev) => {
      const next = { ...prev };
      delete next[field];
      return next;
    });
  };

  const handleUsernameBlur = () => {
    if (!username) return;
    const result = validateUsername(username);
    if (!result.valid && result.error) {
      setFieldErrors((prev) => ({ ...prev, username: result.error! }));
    } else {
      clearFieldError("username");
    }
  };

  const handleEmailBlur = () => {
    if (!email) return;
    const result = validateEmail(email);
    if (!result.valid && result.error) {
      setFieldErrors((prev) => ({ ...prev, email: result.error! }));
    } else if (result.suggestion) {
      setFieldErrors((prev) => ({ ...prev, email: `Did you mean ${result.suggestion}?` }));
    } else {
      clearFieldError("email");
    }
  };

  const handleEmailSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setFieldErrors({});

    // Validate all fields
    const errors: Record<string, string> = {};
    let hasErrors = false;

    const usernameResult = validateUsername(username);
    if (!usernameResult.valid && usernameResult.error) {
      errors.username = usernameResult.error;
      hasErrors = true;
    }

    const emailResult = validateEmail(email);
    if (!emailResult.valid && emailResult.error) {
      errors.email = emailResult.error;
      hasErrors = true;
    }

    if (hasErrors) {
      setFieldErrors(errors);
      return;
    }

    setLoading(true);
    try {
      const capToken = await solveCAPChallenge();
      await api.sendVerificationCode(email, "registration", capToken, username);
      setStep("verify");
    } catch (err) {
      const message = formatError(err, "Failed to send verification code");
      // Check for conflict errors (409)
      if (message.toLowerCase().includes("username already taken")) {
        setFieldErrors({ username: "This username is already taken" });
      } else if (message.toLowerCase().includes("email already registered")) {
        setFieldErrors({ email: "This email is already registered" });
      } else {
        setError(message);
      }
    } finally {
      setLoading(false);
    }
  };

  const handleVerified = (token: string) => {
    setVerificationToken(token);
    setStep("password");
  };

  const handleResendCode = async () => {
    const capToken = await solveCAPChallenge();
    await api.sendVerificationCode(email, "registration", capToken, username);
  };

  const handleSignup = async (_username: string, _email: string, password: string) => {
    // Step 0: Solve CAP proof-of-work challenge
    const capToken = await solveCAPChallenge();

    // Step 1: Start OPAQUE registration
    const { clientRegistrationState, registrationRequest } = await startRegistration(password);

    // Step 2: Send registration request to server with verification token
    // Server creates account and returns user_id for key wrapping
    const initResponse = await api.registerInit(
      username,
      email,
      registrationRequest,
      verificationToken,
      capToken,
    );

    // Step 3: Finish OPAQUE registration
    const { registrationRecord, exportKey } = await finishRegistration(
      clientRegistrationState,
      initResponse.opaque_response,
      password,
    );

    const exportKeyBytes = base64UrlDecode(exportKey);

    // Step 4: Generate and wrap root key (use userId from init response)
    const rootKey = generateRandomKey();
    const wrappingKey = await deriveRootKeyWrappingKey(exportKeyBytes, initResponse.user_id);
    const wrappedRootKey = await wrapRootKey(rootKey, wrappingKey);
    const wrappedB64 = btoa(String.fromCharCode(...wrappedRootKey));

    // Step 5: Send registration record and wrapped root key to server
    const finalResponse = await api.registerFinalize(
      initResponse.state_token,
      registrationRecord,
      wrappedB64,
    );

    // Store auth token, export key, and root key in context
    setAuth(finalResponse.auth_token, finalResponse.user_id, username, exportKeyBytes, rootKey);

    // Redirect
    navigate(getRedirectTo());
  };

  return (
    <div className="flex min-h-screen items-center justify-center p-4">
      <div className="w-full max-w-md">
        {step === "email" && (
          <Card className="w-full">
            <CardHeader className="space-y-1 text-center">
              <CardTitle className="text-2xl font-bold tracking-tight">Create an account</CardTitle>
              <CardDescription>Choose a username and enter your email</CardDescription>
            </CardHeader>
            <form onSubmit={handleEmailSubmit}>
              <CardContent className="space-y-4">
                {error && (
                  <div
                    role="alert"
                    className="flex items-center gap-2 rounded-md bg-destructive/10 p-3 text-sm text-destructive"
                  >
                    <AlertCircle className="h-4 w-4 flex-shrink-0" />
                    <span>{error}</span>
                  </div>
                )}
                <div className="space-y-2">
                  <Label htmlFor="username">Username</Label>
                  <div className="relative">
                    <AtSign className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                    <Input
                      id="username"
                      type="text"
                      placeholder="username"
                      value={username}
                      onChange={(e) => {
                        setUsername(e.target.value.toLowerCase().trim());
                        clearFieldError("username");
                      }}
                      onBlur={handleUsernameBlur}
                      error={!!fieldErrors.username}
                      errorId="username-error"
                      className="pl-10"
                      autoComplete="username"
                      disabled={loading}
                    />
                  </div>
                  {fieldErrors.username && (
                    <p id="username-error" className="text-sm text-destructive">
                      {fieldErrors.username}
                    </p>
                  )}
                </div>
                <div className="space-y-2">
                  <Label htmlFor="email">Email</Label>
                  <div className="relative">
                    <Mail className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                    <Input
                      id="email"
                      type="email"
                      placeholder="name@example.com"
                      value={email}
                      onChange={(e) => {
                        setEmail(e.target.value);
                        clearFieldError("email");
                      }}
                      onBlur={handleEmailBlur}
                      error={!!fieldErrors.email && !fieldErrors.email.startsWith("Did you mean")}
                      errorId="email-error"
                      className="pl-10"
                      autoComplete="email"
                      disabled={loading}
                    />
                  </div>
                  {fieldErrors.email && (
                    <p
                      id="email-error"
                      className={cn(
                        "text-sm",
                        fieldErrors.email.startsWith("Did you mean")
                          ? "text-muted-foreground"
                          : "text-destructive",
                      )}
                    >
                      {fieldErrors.email.startsWith("Did you mean") ? (
                        <>
                          Did you mean{" "}
                          <button
                            type="button"
                            onClick={() => {
                              const match = fieldErrors.email?.match(/Did you mean (.+)\?/);
                              if (match?.[1]) {
                                setEmail(match[1]);
                                clearFieldError("email");
                              }
                            }}
                            className="underline hover:text-foreground"
                          >
                            {fieldErrors.email.match(/Did you mean (.+)\?/)?.[1]}
                          </button>
                          ?
                        </>
                      ) : (
                        fieldErrors.email
                      )}
                    </p>
                  )}
                </div>
              </CardContent>
              <CardFooter className="flex flex-col space-y-4">
                <Button type="submit" className="w-full" disabled={loading}>
                  {loading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                  Continue
                </Button>
                <p className="text-center text-sm text-muted-foreground">
                  Already have an account?{" "}
                  <Link
                    to={`/login${linkSuffix}`}
                    className={cn(
                      "font-medium text-primary underline-offset-4 hover:underline",
                      loading && "pointer-events-none",
                    )}
                  >
                    Sign in
                  </Link>
                </p>
              </CardFooter>
            </form>
          </Card>
        )}

        {step === "verify" && (
          <VerificationForm
            email={email}
            purpose="registration"
            onVerified={handleVerified}
            onResend={handleResendCode}
            onChangeEmail={() => {
              setStep("email");
              setError(null);
            }}
          />
        )}

        {step === "password" && (
          <AuthForm
            mode="signup"
            onSubmit={handleSignup}
            defaultUsername={username}
            usernameReadOnly
            defaultEmail={email}
            emailReadOnly
            title="Set your password"
            description="Choose a secure password for your account"
            hideAccountLink
          />
        )}
      </div>
    </div>
  );
}
