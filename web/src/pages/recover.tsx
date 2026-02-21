import { useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import { Loader2, Mail } from "lucide-react";
import { RecoveryForm } from "@/components/recovery/recovery-form";
import { VerificationForm } from "@/components/verification-form";
import { AuthForm } from "@/components/auth-form";
import { useAuth } from "@/contexts/auth-context";
import { api } from "@/lib/api";
import { deriveRecoveryKey, decryptRootKey, RecoveryBlob } from "@/lib/recovery";
import { base64UrlDecode, deriveRootKeyWrappingKey, wrapRootKey } from "@/lib/crypto";
import { startRegistration, finishRegistration } from "@/lib/opaque";
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
import { validateEmail } from "@/lib/validation";

type Step = "email" | "verify" | "phrase" | "password";

interface RecoveryState {
  email: string;
  verificationToken: string;
  rootKey: Uint8Array; // Decrypted root key from recovery blob
}

export function RecoverPage() {
  const navigate = useNavigate();
  const { setAuth } = useAuth();
  const [step, setStep] = useState<Step>("email");
  const [email, setEmail] = useState("");
  const [verificationToken, setVerificationToken] = useState("");
  const [recoveryState, setRecoveryState] = useState<RecoveryState | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});

  const clearFieldError = (field: string) => {
    setFieldErrors((prev) => {
      const next = { ...prev };
      delete next[field];
      return next;
    });
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

    const emailResult = validateEmail(email);
    if (!emailResult.valid && emailResult.error) {
      setFieldErrors({ email: emailResult.error });
      return;
    }

    setLoading(true);
    try {
      const capToken = await solveCAPChallenge();
      await api.sendVerificationCode(email, "recovery", capToken);
      setStep("verify");
    } catch (err) {
      setError(formatError(err, "Failed to send verification code"));
    } finally {
      setLoading(false);
    }
  };

  const handleVerified = (token: string) => {
    setVerificationToken(token);
    setStep("phrase");
  };

  const handleResendCode = async () => {
    const capToken = await solveCAPChallenge();
    await api.sendVerificationCode(email, "recovery", capToken);
  };

  const handlePhraseSubmit = async (_phraseEmail: string, phrase: string) => {
    if (!verificationToken) {
      throw new Error("Recovery state lost. Please start over.");
    }

    setError(null);

    // Fetch recovery blob from server (requires verification token)
    let blobResponse;
    try {
      blobResponse = await api.getRecoveryBlob(email, verificationToken);
    } catch {
      throw new Error("Unable to recover this account. Please check your email address.");
    }

    // Parse and decrypt the blob to validate the phrase is correct
    const blob: RecoveryBlob = JSON.parse(blobResponse.blob);
    const recoveryKey = await deriveRecoveryKey(phrase);

    let rootKey: Uint8Array;
    try {
      rootKey = await decryptRootKey(blob, recoveryKey);
    } catch {
      throw new Error("Invalid recovery phrase. Please check your words and try again.");
    }

    // Store the decrypted root key for use in the password step
    setRecoveryState({ email, verificationToken, rootKey });
    setStep("password");
  };

  const handlePasswordSubmit = async (_username: string, _email: string, password: string) => {
    if (!recoveryState) {
      throw new Error("Recovery state lost. Please start over.");
    }

    setError(null);

    // Step 0: Solve CAP proof-of-work challenge
    const capToken = await solveCAPChallenge();

    // Step 1: Start OPAQUE registration with new password
    const { clientRegistrationState, registrationRequest } = await startRegistration(password);

    // Step 2: Send recovery init request to server (requires verification token)
    // Server returns user_id for key wrapping
    const initResponse = await api.recoverInit(
      recoveryState.email,
      registrationRequest,
      recoveryState.verificationToken,
      capToken,
    );

    // Step 3: Finish OPAQUE registration
    const { registrationRecord, exportKey: newExportKey } = await finishRegistration(
      clientRegistrationState,
      initResponse.opaque_response,
      password,
    );

    // Step 4: Re-wrap root key with new export key (use userId from init response)
    const newExportKeyBytes = base64UrlDecode(newExportKey);
    const wrappingKey = await deriveRootKeyWrappingKey(newExportKeyBytes, initResponse.user_id);
    const wrappedRootKey = await wrapRootKey(recoveryState.rootKey, wrappingKey);
    const wrappedB64 = btoa(String.fromCharCode(...wrappedRootKey));

    // Step 5: Send registration record and wrapped root key to server
    const finalResponse = await api.recoverFinalize(
      initResponse.state_token,
      registrationRecord,
      wrappedB64,
    );

    // Step 6: Store auth in context with new export key and recovered root key
    setAuth(
      finalResponse.auth_token,
      finalResponse.user_id,
      recoveryState.email,
      newExportKeyBytes,
      recoveryState.rootKey,
    );

    // Step 7: Redirect to recovery setup to save new recovery phrase
    navigate("/recovery-setup?reset=true");
  };

  return (
    <div className="flex min-h-screen flex-col items-center justify-center p-4">
      {step === "email" && (
        <Card className="w-full max-w-md">
          <CardHeader className="space-y-1 text-center">
            <CardTitle className="text-2xl font-bold tracking-tight">
              Recover your account
            </CardTitle>
            <CardDescription>Enter your email to start the recovery process</CardDescription>
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
                Remember your password?{" "}
                <Link
                  to="/login"
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
          purpose="recovery"
          onVerified={handleVerified}
          onResend={handleResendCode}
          onChangeEmail={() => {
            setStep("email");
            setError(null);
          }}
        />
      )}

      {step === "phrase" && (
        <RecoveryForm onSubmit={handlePhraseSubmit} defaultEmail={email} emailReadOnly />
      )}

      {step === "password" && recoveryState && (
        <AuthForm
          mode="signup"
          onSubmit={handlePasswordSubmit}
          showUsername={false}
          defaultEmail={recoveryState.email}
          emailReadOnly
          title="Set New Password"
          description="Choose a new password for your account"
          submitLabel="Reset Password"
          hideAccountLink
        />
      )}
    </div>
  );
}
