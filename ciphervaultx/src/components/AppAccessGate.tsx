import * as React from "react";
import { Eye, EyeOff, KeyRound, Lock, ShieldCheck } from "lucide-react";
import { backend, type AppGateStatus } from "@/lib/api";
import { Button } from "./ui/button";
import { Input } from "./ui/input";
import { Label } from "./ui/label";

interface AppAccessGateProps {
  status: AppGateStatus;
  onUnlocked: (next: AppGateStatus) => void;
}

export const AppAccessGate: React.FC<AppAccessGateProps> = ({ status, onUnlocked }) => {
  const [passphrase, setPassphrase] = React.useState("");
  const [showPassphrase, setShowPassphrase] = React.useState(false);
  const [unlocking, setUnlocking] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!passphrase.trim() || unlocking) return;
    setUnlocking(true);
    setError(null);
    try {
      const next = await backend.unlockAppGate(passphrase);
      setPassphrase("");
      onUnlocked(next);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setUnlocking(false);
    }
  };

  return (
    <div className="flex min-h-screen w-screen items-center justify-center bg-background p-6 text-foreground">
      <div className="w-full max-w-md space-y-6 rounded-2xl border border-border bg-card p-8 shadow-2xl">
        <div className="flex flex-col items-center text-center space-y-3">
          <div className="flex h-16 w-16 items-center justify-center rounded-2xl border border-primary/40 bg-primary/10">
            <Lock className="h-8 w-8 text-primary" />
          </div>
          <div>
            <h1 className="text-xl font-semibold tracking-tight">CipherVaultX Private Access</h1>
            <p className="mt-1 text-xs text-muted-foreground">
              This private build is protected by an offline Argon2id Access Gate (
              {status.authorized_keys} authorized {status.authorized_keys === 1 ? "key" : "keys"}).
            </p>
          </div>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-1.5">
            <Label htmlFor="app-gate-passphrase">Personal Access Passphrase</Label>
            <div className="relative">
              <Input
                id="app-gate-passphrase"
                type={showPassphrase ? "text" : "password"}
                value={passphrase}
                onChange={(e) => setPassphrase(e.target.value)}
                placeholder="Enter your authorized access passphrase"
                autoFocus
                disabled={unlocking}
                className="pr-10"
              />
              <button
                type="button"
                onClick={() => setShowPassphrase((v) => !v)}
                className="absolute right-2.5 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                aria-label={showPassphrase ? "Hide passphrase" : "Show passphrase"}
              >
                {showPassphrase ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
              </button>
            </div>
          </div>

          {error && (
            <div className="rounded-lg border border-destructive/40 bg-destructive/10 px-3 py-2 text-xs text-destructive">
              {error}
            </div>
          )}

          <Button type="submit" className="w-full" disabled={unlocking || !passphrase.trim()}>
            <KeyRound className="mr-2 h-4 w-4" />
            {unlocking ? "Verifying Argon2id…" : "Unlock Application"}
          </Button>
        </form>

        <div className="flex items-start gap-2 rounded-lg border border-border/70 bg-muted/30 p-3 text-[11px] leading-relaxed text-muted-foreground">
          <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0 text-primary" />
          <span>
            100% offline verification. Your passphrase never leaves this device and is verified
            locally against the compiled Argon2id hash.
          </span>
        </div>
      </div>
    </div>
  );
};
