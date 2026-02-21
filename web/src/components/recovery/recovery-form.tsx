import { useState } from "react";
import { Link } from "react-router-dom";
import { Loader2, Mail, AlertCircle } from "lucide-react";
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
import { validateRecoveryPhrase } from "@/lib/recovery";
import { formatError } from "@/lib/utils";

interface RecoveryFormProps {
  onSubmit: (email: string, phrase: string) => Promise<void>;
  defaultEmail?: string;
  emailReadOnly?: boolean;
}

export function RecoveryForm({
  onSubmit,
  defaultEmail = "",
  emailReadOnly = false,
}: RecoveryFormProps) {
  const [email, setEmail] = useState(defaultEmail);
  const [phrase, setPhrase] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    if (!email) {
      setError("Please enter your email address");
      return;
    }

    const normalizedPhrase = phrase.trim().toLowerCase().replace(/\s+/g, " ");
    if (!validateRecoveryPhrase(normalizedPhrase)) {
      setError("Invalid recovery phrase. Please check your words and try again.");
      return;
    }

    setLoading(true);
    try {
      await onSubmit(email, normalizedPhrase);
    } catch (err) {
      setError(formatError(err));
    } finally {
      setLoading(false);
    }
  };

  return (
    <Card className="w-full max-w-lg">
      <CardHeader className="space-y-1 text-center">
        <CardTitle className="text-2xl font-bold tracking-tight">
          {emailReadOnly ? "Enter Recovery Phrase" : "Recover Your Account"}
        </CardTitle>
        <CardDescription>
          {emailReadOnly
            ? "Enter your 12-word recovery phrase to continue"
            : "Enter your email and 12-word recovery phrase"}
        </CardDescription>
      </CardHeader>
      <form onSubmit={handleSubmit}>
        <CardContent className="space-y-6">
          {error && (
            <div
              role="alert"
              className="flex items-center gap-2 rounded-md bg-destructive/10 p-3 text-sm text-destructive"
            >
              <AlertCircle className="h-4 w-4 flex-shrink-0" />
              <span>{error}</span>
            </div>
          )}

          {/* Email input */}
          {!emailReadOnly && (
            <div className="space-y-2">
              <Label htmlFor="email">Email</Label>
              <div className="relative">
                <Mail className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                <Input
                  id="email"
                  type="email"
                  placeholder="name@example.com"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="pl-10"
                  autoComplete="email"
                  disabled={loading}
                />
              </div>
            </div>
          )}

          {/* Recovery phrase input */}
          <div className="space-y-2">
            <Label htmlFor="phrase">Recovery Phrase</Label>
            <textarea
              id="phrase"
              value={phrase}
              onChange={(e) => {
                setPhrase(e.target.value);
                setError(null);
              }}
              placeholder="Enter your 12-word recovery phrase"
              className="flex min-h-24 w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50"
              autoComplete="off"
              spellCheck={false}
              disabled={loading}
            />
          </div>
        </CardContent>
        <CardFooter className="flex flex-col space-y-4">
          <Button type="submit" disabled={!email || !phrase.trim() || loading} className="w-full">
            {loading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
            Continue
          </Button>
          <p className="text-center text-sm text-muted-foreground">
            Remember your password?{" "}
            <Link
              to="/login"
              className="font-medium text-primary underline-offset-4 hover:underline"
            >
              Sign in
            </Link>
          </p>
        </CardFooter>
      </form>
    </Card>
  );
}
