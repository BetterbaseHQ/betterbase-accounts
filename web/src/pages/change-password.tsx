import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Loader2, Lock, Eye, EyeOff, AlertCircle } from "lucide-react";
import { useAuth } from "@/contexts/auth-context";
import { api } from "@/lib/api";
import { startLogin, finishLogin } from "@/lib/opaque";
import { startRegistration, finishRegistration } from "@/lib/opaque";
import {
  base64UrlDecode,
  deriveRootKeyWrappingKey,
  unwrapRootKey,
  wrapRootKey,
} from "@/lib/crypto";
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
import {
  validatePassword,
  getPasswordStrengthColor,
  getPasswordStrengthLabel,
} from "@/lib/validation";

export function ChangePasswordPage() {
  const navigate = useNavigate();
  const { authToken, userId, email, setAuth } = useAuth();

  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showCurrentPassword, setShowCurrentPassword] = useState(false);
  const [showNewPassword, setShowNewPassword] = useState(false);
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const [passwordScore, setPasswordScore] = useState<number>(-1);
  const [passwordSuggestions, setPasswordSuggestions] = useState<string[]>([]);
  const [passwordWarning, setPasswordWarning] = useState<string | undefined>();

  if (!authToken || !userId) {
    navigate("/login");
    return null;
  }

  // Check if form is valid enough to submit
  const canSubmit = (() => {
    if (!currentPassword || !newPassword || !confirmPassword) return false;
    if (passwordScore < 2) return false;
    if (newPassword !== confirmPassword) return false;
    if (newPassword === currentPassword) return false;
    return true;
  })();

  const clearFieldError = (field: string) => {
    setFieldErrors((prev) => {
      const next = { ...prev };
      delete next[field];
      return next;
    });
  };

  const handleNewPasswordBlur = () => {
    // Password feedback is shown through the strength indicator, not field errors
  };

  const handleConfirmPasswordBlur = () => {
    if (!confirmPassword) return;
    if (newPassword !== confirmPassword) {
      setFieldErrors((prev) => ({ ...prev, confirmPassword: "Passwords do not match" }));
    } else {
      clearFieldError("confirmPassword");
    }
  };

  const handleNewPasswordChange = (value: string) => {
    setNewPassword(value);
    if (value) {
      const result = validatePassword(value);
      setPasswordScore(result.score);
      setPasswordSuggestions(result.suggestions);
      setPasswordWarning(result.warning);
    } else {
      setPasswordScore(-1);
      setPasswordSuggestions([]);
      setPasswordWarning(undefined);
    }
    clearFieldError("newPassword");
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setFieldErrors({});

    // Validate all fields
    const errors: Record<string, string> = {};
    let hasErrors = false;

    if (!currentPassword) {
      errors.currentPassword = "Current password is required";
      hasErrors = true;
    }

    if (newPassword && currentPassword && newPassword === currentPassword) {
      errors.newPassword = "New password must be different from current password";
      hasErrors = true;
    }

    const passwordResult = validatePassword(newPassword);
    if (!passwordResult.valid) {
      // Don't show field error - strength indicator handles feedback
      hasErrors = true;
    }

    if (newPassword !== confirmPassword) {
      errors.confirmPassword = "Passwords do not match";
      hasErrors = true;
    }

    if (hasErrors) {
      setFieldErrors(errors);
      return;
    }

    setLoading(true);

    try {
      // Step 1: OPAQUE login with current password to verify it
      const { clientLoginState, ke1 } = await startLogin(currentPassword);
      const initResponse = await api.passwordChangeInit(email || "", ke1);

      // Step 2: Finish OPAQUE login to get old exportKey
      const loginResult = await finishLogin(
        clientLoginState,
        initResponse.opaque_ke2,
        currentPassword,
      );
      if (!loginResult) {
        throw new Error("Current password is incorrect");
      }

      // Step 3: Start OPAQUE registration with new password
      const { clientRegistrationState, registrationRequest } = await startRegistration(newPassword);

      // Step 4: Verify current password and get registration response for new password
      const verifyResponse = await api.passwordChangeVerify(
        initResponse.login_token,
        loginResult.ke3,
        registrationRequest,
      );

      // Step 5: Finish OPAQUE registration with new password
      const { registrationRecord, exportKey: newExportKey } = await finishRegistration(
        clientRegistrationState,
        verifyResponse.opaque_response,
        newPassword,
      );

      // Step 6: Unwrap root key with old export key, re-wrap with new export key
      const oldExportKeyBytes = base64UrlDecode(loginResult.exportKey);
      const oldWrappingKey = await deriveRootKeyWrappingKey(oldExportKeyBytes, userId);

      // Fetch the current wrapped root key
      const rootKeyResponse = await api.getRootKey();
      const wrappedRootKeyBytes = Uint8Array.from(atob(rootKeyResponse.wrapped_root_key), (c) =>
        c.charCodeAt(0),
      );
      const rootKey = await unwrapRootKey(wrappedRootKeyBytes, oldWrappingKey);

      // Re-wrap with new export key
      const newExportKeyBytes = base64UrlDecode(newExportKey);
      const newWrappingKey = await deriveRootKeyWrappingKey(newExportKeyBytes, userId);
      const newWrappedRootKey = await wrapRootKey(rootKey, newWrappingKey);
      const newWrappedB64 = btoa(String.fromCharCode(...newWrappedRootKey));

      // Step 7: Complete password change
      const completeResponse = await api.passwordChangeComplete(
        verifyResponse.state_token,
        registrationRecord,
        newWrappedB64,
      );

      // Step 8: Update auth context with new credentials
      setAuth(
        completeResponse.auth_token,
        completeResponse.user_id,
        email || "",
        newExportKeyBytes,
        rootKey,
      );

      // Step 9: Redirect to recovery setup (new mnemonic needed for new blob)
      navigate("/recovery-setup?reset=true");
    } catch (err) {
      setError(formatError(err, "Failed to change password"));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center p-4">
      <div className="w-full max-w-md">
        <Card className="w-full">
          <CardHeader className="space-y-1 text-center">
            <div className="mx-auto mb-2 flex h-12 w-12 items-center justify-center rounded-full bg-primary/10">
              <Lock className="h-6 w-6 text-primary" />
            </div>
            <CardTitle className="text-2xl font-bold tracking-tight">Change Password</CardTitle>
            <CardDescription>Enter your current password and choose a new one</CardDescription>
          </CardHeader>
          <form onSubmit={handleSubmit}>
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
                <Label htmlFor="current-password">Current Password</Label>
                <div className="relative">
                  <Input
                    id="current-password"
                    type={showCurrentPassword ? "text" : "password"}
                    value={currentPassword}
                    onChange={(e) => {
                      setCurrentPassword(e.target.value);
                      clearFieldError("currentPassword");
                    }}
                    error={!!fieldErrors.currentPassword}
                    errorId="current-password-error"
                    autoComplete="current-password"
                    disabled={loading}
                  />
                  <button
                    type="button"
                    onClick={() => setShowCurrentPassword(!showCurrentPassword)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                    tabIndex={-1}
                    aria-label={showCurrentPassword ? "Hide password" : "Show password"}
                  >
                    {showCurrentPassword ? (
                      <EyeOff className="h-4 w-4" />
                    ) : (
                      <Eye className="h-4 w-4" />
                    )}
                  </button>
                </div>
                {fieldErrors.currentPassword && (
                  <p id="current-password-error" className="text-sm text-destructive">
                    {fieldErrors.currentPassword}
                  </p>
                )}
              </div>
              <div className="space-y-2">
                <Label htmlFor="new-password">New Password</Label>
                <div className="relative">
                  <Input
                    id="new-password"
                    type={showNewPassword ? "text" : "password"}
                    value={newPassword}
                    onChange={(e) => handleNewPasswordChange(e.target.value)}
                    onBlur={handleNewPasswordBlur}
                    error={!!fieldErrors.newPassword}
                    errorId="new-password-error"
                    autoComplete="new-password"
                    disabled={loading}
                  />
                  <button
                    type="button"
                    onClick={() => setShowNewPassword(!showNewPassword)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                    tabIndex={-1}
                    aria-label={showNewPassword ? "Hide password" : "Show password"}
                  >
                    {showNewPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                  </button>
                </div>
                {fieldErrors.newPassword && (
                  <p id="new-password-error" className="text-sm text-destructive">
                    {fieldErrors.newPassword}
                  </p>
                )}
                {passwordScore >= 0 && (
                  <div className="space-y-1">
                    <div className="flex items-center justify-between text-xs">
                      <span className="text-muted-foreground">Password strength</span>
                      <span
                        className={cn(
                          passwordScore <= 1 && "text-destructive",
                          passwordScore === 2 && "text-orange-500",
                          passwordScore === 3 && "text-yellow-600",
                          passwordScore === 4 && "text-green-500",
                        )}
                      >
                        {getPasswordStrengthLabel(passwordScore)}
                      </span>
                    </div>
                    <div className="h-1 rounded-full bg-muted overflow-hidden">
                      <div
                        className={cn(
                          "h-full transition-all",
                          getPasswordStrengthColor(passwordScore),
                        )}
                        style={{ width: `${(passwordScore + 1) * 20}%` }}
                      />
                    </div>
                    {passwordWarning && passwordScore < 4 && (
                      <p className="text-xs text-muted-foreground">{passwordWarning}</p>
                    )}
                    {passwordSuggestions.length > 0 && passwordScore < 4 && (
                      <ul className="text-xs text-muted-foreground space-y-0.5">
                        {passwordSuggestions.map((s, i) => (
                          <li key={i}>{s}</li>
                        ))}
                      </ul>
                    )}
                  </div>
                )}
              </div>
              <div className="space-y-2">
                <Label htmlFor="confirm-password">Confirm New Password</Label>
                <Input
                  id="confirm-password"
                  type="password"
                  value={confirmPassword}
                  onChange={(e) => {
                    setConfirmPassword(e.target.value);
                    clearFieldError("confirmPassword");
                  }}
                  onBlur={handleConfirmPasswordBlur}
                  error={!!fieldErrors.confirmPassword}
                  errorId="confirm-password-error"
                  autoComplete="new-password"
                  disabled={loading}
                />
                {fieldErrors.confirmPassword && (
                  <p id="confirm-password-error" className="text-sm text-destructive">
                    {fieldErrors.confirmPassword}
                  </p>
                )}
              </div>
            </CardContent>
            <CardFooter className="flex flex-col space-y-4">
              <Button type="submit" className="w-full" disabled={!canSubmit || loading}>
                {loading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                Change Password
              </Button>
              <Button
                type="button"
                variant="ghost"
                className="w-full"
                onClick={() => navigate("/")}
                disabled={loading}
              >
                Cancel
              </Button>
            </CardFooter>
          </form>
        </Card>
      </div>
    </div>
  );
}
