import * as React from "react";
import { Check, Copy, KeyRound, RefreshCw, ShieldCheck } from "lucide-react";
import {
  generatePassphrase,
  generateRandomPassword,
  type GeneratedResult,
  type PassphraseOptions,
  type RandomPasswordOptions,
} from "@/lib/generator";
import { Badge } from "./ui/badge";
import { Button } from "./ui/button";
import { Input } from "./ui/input";
import { Label } from "./ui/label";
import { Progress } from "./ui/progress";
import { Select } from "./ui/select";
import { Separator } from "./ui/separator";
import { Switch } from "./ui/switch";

type GeneratorMode = "password" | "passphrase";

export const PasswordGeneratorView: React.FC = () => {
  const [mode, setMode] = React.useState<GeneratorMode>("password");
  const [pwOpts, setPwOpts] = React.useState<RandomPasswordOptions>({
    length: 24,
    lowercase: true,
    uppercase: true,
    digits: true,
    symbols: true,
    excludeAmbiguous: false,
  });
  const [phraseOpts, setPhraseOpts] = React.useState<PassphraseOptions>({
    wordCount: 10,
    separator: "-",
    capitalize: true,
    appendNumber: true,
  });
  const [result, setResult] = React.useState<GeneratedResult>(() =>
    generateRandomPassword({
      length: 24,
      lowercase: true,
      uppercase: true,
      digits: true,
      symbols: true,
      excludeAmbiguous: false,
    })
  );
  const [copied, setCopied] = React.useState(false);

  const regenerate = React.useCallback(
    (nextMode = mode, nextPw = pwOpts, nextPhrase = phraseOpts) => {
      const generated =
        nextMode === "password"
          ? generateRandomPassword(nextPw)
          : generatePassphrase(nextPhrase);
      setResult(generated);
      setCopied(false);
    },
    [mode, pwOpts, phraseOpts]
  );

  React.useEffect(() => {
    regenerate(mode, pwOpts, phraseOpts);
  }, [mode, pwOpts, phraseOpts, regenerate]);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(result.value);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 2000);
    } catch {
      // Clipboard unavailable
    }
  };

  const progressPct = Math.min(100, Math.round((result.entropyBits / 160) * 100));

  return (
    <div className="mx-auto max-w-3xl space-y-8 p-8">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div className="space-y-1">
          <h1 className="text-2xl font-semibold tracking-tight">Password Generator</h1>
          <p className="text-sm text-muted-foreground">
            CSPRNG offline generator (<code>crypto.getRandomValues</code>) with entropy and
            crack-time analysis.
          </p>
        </div>
        <div className="flex gap-2">
          <Button
            size="sm"
            variant={mode === "password" ? "secondary" : "ghost"}
            onClick={() => setMode("password")}
          >
            Random Password
          </Button>
          <Button
            size="sm"
            variant={mode === "passphrase" ? "secondary" : "ghost"}
            onClick={() => setMode("passphrase")}
          >
            Passphrase
          </Button>
        </div>
      </div>

      <section className="space-y-4 rounded-lg border border-border bg-card p-5">
        <div className="flex items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <KeyRound className="h-4 w-4 text-primary" />
            <span className="text-sm font-medium">{result.entropyBits} bits of entropy</span>
          </div>
          <Badge variant={result.entropyBits >= 128 ? "default" : "secondary"}>
            {result.rating}
          </Badge>
        </div>

        <div className="rounded-md border border-border bg-background p-4 font-mono text-base leading-relaxed break-all select-all">
          {result.value}
        </div>

        <Progress value={progressPct} />

        <div className="flex flex-wrap gap-2">
          <Button size="sm" onClick={() => regenerate()}>
            <RefreshCw className="h-4 w-4" />
            Regenerate
          </Button>
          <Button variant="outline" size="sm" onClick={handleCopy}>
            {copied ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
            {copied ? "Copied" : "Copy"}
          </Button>
        </div>
      </section>

      <section className="space-y-4 rounded-lg border border-border bg-card p-5">
        <h2 className="text-base font-medium">Parameters</h2>
        {mode === "password" ? (
          <div className="space-y-4">
            <div className="space-y-1.5">
              <div className="flex items-center justify-between">
                <Label htmlFor="gen-len">Length ({pwOpts.length} characters)</Label>
                <Input
                  id="gen-len"
                  type="number"
                  min={12}
                  max={128}
                  className="w-24"
                  value={pwOpts.length}
                  onChange={(e) =>
                    setPwOpts((o) => ({
                      ...o,
                      length: Math.max(12, Math.min(128, Number(e.target.value) || 12)),
                    }))
                  }
                />
              </div>
              <input
                type="range"
                min={12}
                max={64}
                value={Math.min(64, pwOpts.length)}
                onChange={(e) => setPwOpts((o) => ({ ...o, length: Number(e.target.value) }))}
                className="w-full accent-primary"
                aria-label="Password length slider"
              />
            </div>

            <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
              <label className="flex items-center justify-between rounded-md border border-border p-3 text-sm">
                <span>Lowercase (a-z)</span>
                <Switch
                  checked={pwOpts.lowercase}
                  onCheckedChange={(v) => setPwOpts((o) => ({ ...o, lowercase: v }))}
                />
              </label>
              <label className="flex items-center justify-between rounded-md border border-border p-3 text-sm">
                <span>Uppercase (A-Z)</span>
                <Switch
                  checked={pwOpts.uppercase}
                  onCheckedChange={(v) => setPwOpts((o) => ({ ...o, uppercase: v }))}
                />
              </label>
              <label className="flex items-center justify-between rounded-md border border-border p-3 text-sm">
                <span>Digits (0-9)</span>
                <Switch
                  checked={pwOpts.digits}
                  onCheckedChange={(v) => setPwOpts((o) => ({ ...o, digits: v }))}
                />
              </label>
              <label className="flex items-center justify-between rounded-md border border-border p-3 text-sm">
                <span>Symbols (!@#)</span>
                <Switch
                  checked={pwOpts.symbols}
                  onCheckedChange={(v) => setPwOpts((o) => ({ ...o, symbols: v }))}
                />
              </label>
              <label className="flex items-center justify-between rounded-md border border-border p-3 text-sm sm:col-span-2">
                <span>Exclude ambiguous (O, 0, I, l, 1)</span>
                <Switch
                  checked={pwOpts.excludeAmbiguous}
                  onCheckedChange={(v) => setPwOpts((o) => ({ ...o, excludeAmbiguous: v }))}
                />
              </label>
            </div>
          </div>
        ) : (
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div className="space-y-1.5">
              <Label htmlFor="phrase-words">Words ({phraseOpts.wordCount})</Label>
              <Input
                id="phrase-words"
                type="number"
                min={4}
                max={16}
                value={phraseOpts.wordCount}
                onChange={(e) =>
                  setPhraseOpts((o) => ({
                    ...o,
                    wordCount: Math.max(4, Math.min(16, Number(e.target.value) || 4)),
                  }))
                }
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="phrase-sep">Separator</Label>
              <Select
                id="phrase-sep"
                value={phraseOpts.separator}
                onChange={(e) =>
                  setPhraseOpts((o) => ({
                    ...o,
                    separator: e.target.value as PassphraseOptions["separator"],
                  }))
                }
              >
                <option value="-">Hyphen (-)</option>
                <option value=".">Dot (.)</option>
                <option value="_">Underscore (_)</option>
                <option value=" ">Space</option>
              </Select>
            </div>
            <label className="flex items-center justify-between rounded-md border border-border p-3 text-sm">
              <span>Capitalize Words</span>
              <Switch
                checked={phraseOpts.capitalize}
                onCheckedChange={(v) => setPhraseOpts((o) => ({ ...o, capitalize: v }))}
              />
            </label>
            <label className="flex items-center justify-between rounded-md border border-border p-3 text-sm">
              <span>Append 4-digit Number</span>
              <Switch
                checked={phraseOpts.appendNumber}
                onCheckedChange={(v) => setPhraseOpts((o) => ({ ...o, appendNumber: v }))}
              />
            </label>
          </div>
        )}
      </section>

      <section className="space-y-3">
        <h2 className="text-base font-medium">Estimated Crack Times (Average 50% Keyspace)</h2>
        <div className="overflow-hidden rounded-lg border border-border bg-card">
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="border-b border-border text-xs uppercase tracking-wider text-muted-foreground">
                <th className="px-4 py-2.5 font-medium">Attack Scenario</th>
                <th className="px-4 py-2.5 font-medium">Assumed Rate</th>
                <th className="px-4 py-2.5 text-right font-medium">Estimated Time</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {result.estimates.map((est) => (
                <tr key={est.scenario}>
                  <td className="px-4 py-2.5 font-medium">{est.scenario}</td>
                  <td className="px-4 py-2.5 text-xs text-muted-foreground">{est.rateLabel}</td>
                  <td className="px-4 py-2.5 text-right font-mono text-xs text-primary">
                    {est.duration}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <Separator />

      <section className="space-y-2.5 rounded-lg border border-border bg-card p-5">
        <div className="flex items-center gap-2 text-sm font-medium">
          <ShieldCheck className="h-4 w-4 text-primary" />
          <span>Security Recommendations</span>
        </div>
        <ul className="list-disc space-y-1.5 pl-5 text-xs leading-relaxed text-muted-foreground">
          {result.recommendations.map((rec, idx) => (
            <li key={idx}>{rec}</li>
          ))}
        </ul>
      </section>
    </div>
  );
};
