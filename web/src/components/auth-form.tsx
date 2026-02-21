import { useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { Eye, EyeOff, Loader2, Mail, Lock, AlertCircle, AtSign } from "lucide-react";
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
  validateEmail,
  validateUsername,
  validatePassword,
  getPasswordStrengthColor,
  getPasswordStrengthLabel,
} from "@/lib/validation";

interface AuthFormProps {
  mode: "login" | "signup";
  onSubmit: (username: string, email: string, password: string) => Promise<void>;
  defaultUsername?: string;
  usernameReadOnly?: boolean;
  showUsername?: boolean;
  /** Prefill and optionally lock the email field */
  defaultEmail?: string;
  /** Make email field read-only (for reauth) */
  emailReadOnly?: boolean;
  showEmail?: boolean;
  /** Custom title (overrides default) */
  title?: string;
  /** Custom description (overrides default) */
  description?: string;
  /** Custom submit button label */
  submitLabel?: string;
  /** Hide the "sign up / sign in" toggle link */
  hideAccountLink?: boolean;
  /** Show "Forgot password?" link (login mode only) */
  showForgotPassword?: boolean;
}

export function AuthForm({
  mode,
  onSubmit,
  defaultUsername = "",
  usernameReadOnly = false,
  showUsername = true,
  defaultEmail = "",
  emailReadOnly = false,
  showEmail = mode === "signup",
  title,
  description,
  submitLabel,
  hideAccountLink = false,
  showForgotPassword = false,
}: AuthFormProps) {
  const [searchParams] = useSearchParams();
  const [username, setUsername] = useState(defaultUsername);
  const [email, setEmail] = useState(defaultEmail);
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const [passwordScore, setPasswordScore] = useState<number>(-1);
  const [passwordSuggestions, setPasswordSuggestions] = useState<string[]>([]);
  const [passwordWarning, setPasswordWarning] = useState<string | undefined>();

  const isSignup = mode === "signup";
  const queryString = searchParams.toString();
  const linkSuffix = queryString ? `?${queryString}` : "";

  // Determine display text (allow override via props)
  const displayTitle = title ?? (isSignup ? "Create an account" : "Welcome back");
  const displayDescription =
    description ??
    (isSignup
      ? "Choose a username and verify your email to create your account"
      : "Enter your username to sign in to your account");
  const displaySubmitLabel = submitLabel ?? (isSignup ? "Create account" : "Sign in");

  // Check if form is valid enough to submit
  const canSubmit = (() => {
    // Required fields must be filled
    if ((showUsername && !username) || !password) return false;
    if (showEmail && !email) return false;

    // For signup, password must be strong enough and match confirmation
    if (isSignup) {
      if (passwordScore < 2) return false;
      if (password !== confirmPassword) return false;
    }

    return true;
  })();

  const clearFieldError = (field: string) => {
    setFieldErrors((prev) => {
      const next = { ...prev };
      delete next[field];
      return next;
    });
  };

  const handleUsernameBlur = () => {
    if (!username || usernameReadOnly) return;
    const result = validateUsername(username);
    if (!result.valid && result.error) {
      setFieldErrors((prev) => ({ ...prev, username: result.error! }));
    } else {
      clearFieldError("username");
    }
  };

  const handleEmailBlur = () => {
    if (!email || emailReadOnly) return;
    const result = validateEmail(email);
    if (!result.valid && result.error) {
      setFieldErrors((prev) => ({ ...prev, email: result.error! }));
    } else if (result.suggestion) {
      setFieldErrors((prev) => ({ ...prev, email: `Did you mean ${result.suggestion}?` }));
    } else {
      clearFieldError("email");
    }
  };

  const handlePasswordBlur = () => {
    // Password feedback is shown through the strength indicator, not field errors
  };

  const handleConfirmPasswordBlur = () => {
    if (!confirmPassword) return;
    if (password !== confirmPassword) {
      setFieldErrors((prev) => ({ ...prev, confirmPassword: "Passwords do not match" }));
    } else {
      clearFieldError("confirmPassword");
    }
  };

  const handlePasswordChange = (value: string) => {
    setPassword(value);
    if (isSignup && value) {
      const result = validatePassword(value);
      setPasswordScore(result.score);
      setPasswordSuggestions(result.suggestions);
      setPasswordWarning(result.warning);
    } else {
      setPasswordScore(-1);
      setPasswordSuggestions([]);
      setPasswordWarning(undefined);
    }
    clearFieldError("password");
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setFieldErrors({});

    // Validate all visible fields
    const errors: Record<string, string> = {};
    let hasErrors = false;

    if (showUsername && !usernameReadOnly) {
      const result = validateUsername(username);
      if (!result.valid && result.error) {
        errors.username = result.error;
        hasErrors = true;
      }
    }

    if (showEmail && !emailReadOnly) {
      const result = validateEmail(email);
      if (!result.valid && result.error) {
        errors.email = result.error;
        hasErrors = true;
      }
    }

    const passwordResult = validatePassword(password);
    if (!passwordResult.valid) {
      // Button should be disabled, but validate anyway for safety
      hasErrors = true;
    }

    if (isSignup && password !== confirmPassword) {
      errors.confirmPassword = "Passwords do not match";
      hasErrors = true;
    }

    if (hasErrors) {
      setFieldErrors(errors);
      return;
    }

    setLoading(true);
    try {
      await onSubmit(username, email, password);
    } catch (err) {
      setError(formatError(err));
    } finally {
      setLoading(false);
    }
  };

  return (
    <Card className="w-full max-w-md">
      <CardHeader className="space-y-1 text-center">
        <CardTitle className="text-2xl font-bold tracking-tight">{displayTitle}</CardTitle>
        <CardDescription>{displayDescription}</CardDescription>
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
          {showUsername && (
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
                  className={cn("pl-10", usernameReadOnly && "bg-muted")}
                  autoComplete="username"
                  disabled={loading}
                  readOnly={usernameReadOnly}
                />
              </div>
              {fieldErrors.username && (
                <p id="username-error" className="text-sm text-destructive">
                  {fieldErrors.username}
                </p>
              )}
            </div>
          )}
          {showEmail && (
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
                  className={cn("pl-10", emailReadOnly && "bg-muted")}
                  autoComplete="email"
                  disabled={loading}
                  readOnly={emailReadOnly}
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
          )}
          <div className="space-y-2">
            <Label htmlFor="password">Password</Label>
            <div className="relative">
              <Lock className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
              <Input
                id="password"
                type={showPassword ? "text" : "password"}
                placeholder="Enter your password"
                value={password}
                onChange={(e) => handlePasswordChange(e.target.value)}
                onBlur={handlePasswordBlur}
                className="pl-10 pr-10"
                autoComplete={isSignup ? "new-password" : "current-password"}
                disabled={loading}
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                tabIndex={-1}
                aria-label={showPassword ? "Hide password" : "Show password"}
              >
                {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
              </button>
            </div>
            {isSignup && passwordScore >= 0 && (
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
                    className={cn("h-full transition-all", getPasswordStrengthColor(passwordScore))}
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
            {showForgotPassword && !isSignup && (
              <div className="text-right">
                <Link
                  to="/recover"
                  className={cn(
                    "text-sm text-muted-foreground underline-offset-4 hover:underline",
                    loading && "pointer-events-none",
                  )}
                >
                  Forgot password?
                </Link>
              </div>
            )}
          </div>
          {isSignup && (
            <div className="space-y-2">
              <Label htmlFor="confirmPassword">Confirm Password</Label>
              <div className="relative">
                <Lock className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                <Input
                  id="confirmPassword"
                  type={showPassword ? "text" : "password"}
                  placeholder="Confirm your password"
                  value={confirmPassword}
                  onChange={(e) => {
                    setConfirmPassword(e.target.value);
                    clearFieldError("confirmPassword");
                  }}
                  onBlur={handleConfirmPasswordBlur}
                  error={!!fieldErrors.confirmPassword}
                  errorId="confirm-password-error"
                  className="pl-10"
                  autoComplete="new-password"
                  disabled={loading}
                />
              </div>
              {fieldErrors.confirmPassword && (
                <p id="confirm-password-error" className="text-sm text-destructive">
                  {fieldErrors.confirmPassword}
                </p>
              )}
            </div>
          )}
        </CardContent>
        <CardFooter className="flex flex-col space-y-4">
          <Button type="submit" className="w-full" disabled={!canSubmit || loading}>
            {loading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
            {displaySubmitLabel}
          </Button>
          {!hideAccountLink && (
            <p className="text-center text-sm text-muted-foreground">
              {isSignup ? (
                <>
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
                </>
              ) : (
                <>
                  Don't have an account?{" "}
                  <Link
                    to={`/signup${linkSuffix}`}
                    className={cn(
                      "font-medium text-primary underline-offset-4 hover:underline",
                      loading && "pointer-events-none",
                    )}
                  >
                    Sign up
                  </Link>
                </>
              )}
            </p>
          )}
        </CardFooter>
      </form>
    </Card>
  );
}
