import { useState } from "react";
import { Check, Copy } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

interface MnemonicDisplayProps {
  mnemonic: string;
  onContinue: () => void;
  title?: string;
  description?: string;
  checkboxLabel?: string;
}

export function MnemonicDisplay({
  mnemonic,
  onContinue,
  title = "Recovery Phrase",
  description = "Your account uses advanced encryption. Your 12-word recovery phrase is the only way to recover your account if you forget your password.",
  checkboxLabel = "I have saved my recovery phrase somewhere safe",
}: MnemonicDisplayProps) {
  const [acknowledged, setAcknowledged] = useState(false);
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    await navigator.clipboard.writeText(mnemonic);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <Card className="w-full max-w-lg">
      <CardHeader className="space-y-1 text-center">
        <CardTitle className="text-2xl font-bold tracking-tight">{title}</CardTitle>
        <CardDescription>{description}</CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        {/* Phrase display */}
        <div className="relative rounded-xl border-2 border-dashed border-primary/20 bg-gradient-to-br from-primary/5 to-transparent p-6">
          <p className="text-center font-mono text-base leading-relaxed text-foreground/90">
            {mnemonic}
          </p>
          <button
            onClick={handleCopy}
            className="absolute right-2 top-2 rounded-md p-2 text-muted-foreground transition-colors hover:bg-primary/10 hover:text-foreground"
            title="Copy to clipboard"
          >
            {copied ? <Check className="h-4 w-4 text-green-600" /> : <Copy className="h-4 w-4" />}
          </button>
        </div>

        {/* Acknowledgment checkbox */}
        <label className="flex cursor-pointer items-center justify-center gap-3">
          <input
            type="checkbox"
            checked={acknowledged}
            onChange={(e) => setAcknowledged(e.target.checked)}
            className="h-4 w-4 rounded border-gray-300"
          />
          <span className="text-sm text-muted-foreground">{checkboxLabel}</span>
        </label>
      </CardContent>
      <CardFooter>
        <Button onClick={onContinue} disabled={!acknowledged} className="w-full">
          Continue
        </Button>
      </CardFooter>
    </Card>
  );
}
