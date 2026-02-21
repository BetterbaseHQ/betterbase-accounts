import { useState, useRef, useEffect, useCallback } from "react";
import { Loader2, Mail, Check, AlertCircle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { cn, formatError } from "@/lib/utils";
import { api } from "@/lib/api";

const TIMING = {
  MIN_VERIFY_DURATION: 500,
  SUCCESS_DISPLAY: 1100,
  TRANSITION_DELAY: 150,
} as const;

type Phase = "idle" | "verifying" | "success";

interface VerificationFormProps {
  email: string;
  purpose: "registration" | "recovery";
  onVerified: (verificationToken: string) => void;
  onResend: () => Promise<void>;
  onChangeEmail?: () => void;
}

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

export function VerificationForm({
  email,
  purpose,
  onVerified,
  onResend,
  onChangeEmail,
}: VerificationFormProps) {
  const [code, setCode] = useState(["", "", "", "", "", ""]);
  const [phase, setPhase] = useState<Phase>("idle");
  const [resending, setResending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [resendCooldown, setResendCooldown] = useState(0);

  const inputRefs = useRef<(HTMLInputElement | null)[]>([]);
  const submittingRef = useRef(false);

  useEffect(() => {
    inputRefs.current[0]?.focus();
  }, []);

  useEffect(() => {
    if (resendCooldown <= 0) return;
    const timer = setTimeout(() => setResendCooldown((c) => c - 1), 1000);
    return () => clearTimeout(timer);
  }, [resendCooldown]);

  const handleSubmit = useCallback(
    async (codeString?: string) => {
      const fullCode = codeString || code.join("");
      if (fullCode.length !== 6) {
        setError("Please enter all 6 digits");
        return;
      }

      if (submittingRef.current) return;
      submittingRef.current = true;

      setPhase("verifying");
      setError(null);

      const verifyStart = Date.now();

      try {
        const response = await api.confirmVerificationCode(email, fullCode, purpose);

        // Ensure minimum display time for verification state
        const elapsed = Date.now() - verifyStart;
        if (elapsed < TIMING.MIN_VERIFY_DURATION) {
          await sleep(TIMING.MIN_VERIFY_DURATION - elapsed);
        }

        setPhase("success");

        await sleep(TIMING.SUCCESS_DISPLAY);
        await sleep(TIMING.TRANSITION_DELAY);

        onVerified(response.verification_token);
      } catch (err) {
        // Ensure minimum display time even for errors
        const elapsed = Date.now() - verifyStart;
        if (elapsed < TIMING.MIN_VERIFY_DURATION) {
          await sleep(TIMING.MIN_VERIFY_DURATION - elapsed);
        }

        setError(formatError(err, "Invalid code"));
        setCode(["", "", "", "", "", ""]);
        setPhase("idle");
        inputRefs.current[0]?.focus();
      } finally {
        submittingRef.current = false;
      }
    },
    [code, email, purpose, onVerified],
  );

  const handleChange = (index: number, value: string) => {
    if (value && !/^\d$/.test(value)) return;

    const newCode = [...code];
    newCode[index] = value;
    setCode(newCode);
    setError(null);

    if (value && index < 5) {
      inputRefs.current[index + 1]?.focus();
    }

    if (value && index === 5 && newCode.every((d) => d !== "")) {
      handleSubmit(newCode.join(""));
    }
  };

  const handleKeyDown = (index: number, e: React.KeyboardEvent) => {
    if (e.key === "Backspace" && !code[index] && index > 0) {
      inputRefs.current[index - 1]?.focus();
    }
    if (e.key === "Enter" && code.every((d) => d !== "")) {
      handleSubmit();
    }
  };

  const handlePaste = (e: React.ClipboardEvent) => {
    e.preventDefault();
    const pasted = e.clipboardData.getData("text").replace(/\D/g, "").slice(0, 6);
    if (pasted.length === 6) {
      setCode(pasted.split(""));
      handleSubmit(pasted);
    }
  };

  const handleResend = async () => {
    setResending(true);
    setError(null);
    try {
      await onResend();
      setResendCooldown(60);
    } catch (err) {
      setError(formatError(err, "Failed to resend code"));
    } finally {
      setResending(false);
    }
  };

  const title = purpose === "registration" ? "Verify your email" : "Verify your identity";
  const description =
    purpose === "registration"
      ? "Enter the 6-digit code sent to your email"
      : "Enter the 6-digit code sent to your email to continue";

  const isIdle = phase === "idle";
  const isComplete = code.every((d) => d !== "");

  return (
    <Card className="w-full max-w-md">
      <CardHeader className="space-y-1 text-center">
        <CardTitle className="text-2xl font-bold tracking-tight">{title}</CardTitle>
        <CardDescription>{description}</CardDescription>
        <div className="flex items-center justify-center gap-2 pt-2 text-sm text-muted-foreground">
          <Mail className="h-4 w-4" />
          <span>{email}</span>
        </div>
      </CardHeader>

      <CardContent className="space-y-4">
        {/* Screen reader announcements */}
        <div aria-live="polite" aria-atomic="true" className="sr-only">
          {phase === "verifying" && "Verifying your code"}
          {phase === "success" && "Code verified successfully"}
        </div>

        {error && (
          <div
            role="alert"
            className="flex items-center gap-2 rounded-md bg-destructive/10 p-3 text-sm text-destructive"
          >
            <AlertCircle className="h-4 w-4 flex-shrink-0" />
            <span>{error}</span>
          </div>
        )}

        <fieldset>
          <legend className="text-sm font-medium">Verification code</legend>
          <div
            className="mt-3 flex justify-center gap-2"
            role="group"
            aria-label="6-digit verification code"
          >
            {code.map((digit, index) => (
              <Input
                key={index}
                ref={(el) => {
                  inputRefs.current[index] = el;
                }}
                type="text"
                inputMode="numeric"
                maxLength={1}
                value={digit}
                onChange={(e) => handleChange(index, e.target.value)}
                onKeyDown={(e) => handleKeyDown(index, e)}
                onPaste={index === 0 ? handlePaste : undefined}
                aria-label={`Digit ${index + 1} of 6`}
                className={cn(
                  "h-12 w-12 text-center text-lg font-semibold transition-colors duration-200",
                  phase === "success" && "border-green-500 bg-green-50 dark:bg-green-950/30",
                )}
                disabled={!isIdle}
                autoComplete={index === 0 ? "one-time-code" : "off"}
              />
            ))}
          </div>
        </fieldset>
      </CardContent>

      <CardFooter className="flex flex-col space-y-4">
        <Button
          type="button"
          className={cn(
            "w-full transition-colors duration-200",
            phase === "success" && "bg-green-600 hover:bg-green-600",
          )}
          onClick={() => handleSubmit()}
          disabled={!isIdle || !isComplete}
        >
          {phase === "verifying" && (
            <>
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              Verifying...
            </>
          )}
          {phase === "success" && (
            <>
              <Check className="mr-2 h-4 w-4" />
              Verified
            </>
          )}
          {isIdle && "Verify"}
        </Button>

        <div className="flex flex-col items-center gap-2 text-sm">
          <button
            type="button"
            onClick={handleResend}
            disabled={resending || resendCooldown > 0 || !isIdle}
            className={cn(
              "text-muted-foreground underline-offset-4 hover:underline",
              (resending || resendCooldown > 0 || !isIdle) && "pointer-events-none opacity-50",
            )}
          >
            {resending
              ? "Sending..."
              : resendCooldown > 0
                ? `Resend code in ${resendCooldown}s`
                : "Resend code"}
          </button>

          {onChangeEmail && (
            <button
              type="button"
              onClick={onChangeEmail}
              disabled={!isIdle}
              className={cn(
                "text-muted-foreground underline-offset-4 hover:underline",
                !isIdle && "pointer-events-none opacity-50",
              )}
            >
              Change email address
            </button>
          )}
        </div>
      </CardFooter>
    </Card>
  );
}
