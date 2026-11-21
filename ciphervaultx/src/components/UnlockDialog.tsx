import * as React from "react";
import { backend, type VaultInfo } from "@/lib/api";
import { MIN_PASSWORD_CHARS } from "@/lib/password";
import { Button } from "./ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "./ui/dialog";
import { Input } from "./ui/input";
import { Label } from "./ui/label";

interface UnlockDialogProps {
  vault: VaultInfo | null;
  onClose: () => void;
  onUnlocked: (vault: VaultInfo) => void;
}

type Mode = "password" | "recovery" | "reset";

export const UnlockDialog: React.FC<UnlockDialogProps> = ({
  vault,
  onClose,
  onUnlocked,
}) => {
  const [mode, setMode] = React.useState<Mode>("password");
  const [password, setPassword] = React.useState("");
  const [recoveryKey, setRecoveryKey] = React.useState("");
  const [newPassword, setNewPassword] = React.useState("");
  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);

  React.useEffect(() => {
    setMode("password");
    setPassword("");
    setRecoveryKey("");
    setNewPassword("");
    setError(null);
    setBusy(false);
  }, [vault?.id]);

  if (!vault) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      let unlocked: VaultInfo;
      if (mode === "password") {
        unlocked = await backend.unlockVault(vault.id, password);
      } else if (mode === "recovery") {
        unlocked = await backend.unlockVaultWithRecovery(vault.id, recoveryKey);
      } else {
        if ([...newPassword].length < MIN_PASSWORD_CHARS) {
          throw new Error(`New password must be at least ${MIN_PASSWORD_CHARS} characters.`);
        }
        unlocked = await backend.resetPasswordWithRecovery({
          vaultId: vault.id,
          recoveryKey,
          newPassword,
          kdfProfile: "desktop",
        });
      }
      setPassword("");
      setRecoveryKey("");
      setNewPassword("");
      onUnlocked(unlocked);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog open={Boolean(vault)} onOpenChange={(open) => !open && onClose()}>
      <DialogContent>
        <form onSubmit={handleSubmit}>
          <DialogHeader>
            <DialogTitle>Unlock {vault.name}</DialogTitle>
            <DialogDescription className="truncate font-mono text-xs">
              {vault.path}
            </DialogDescription>
          </DialogHeader>

          <div className="mb-4 flex gap-2">
            <Button
              type="button"
              size="sm"
              variant={mode === "password" ? "secondary" : "ghost"}
              onClick={() => setMode("password")}
            >
              Password
            </Button>
            <Button
              type="button"
              size="sm"
              variant={mode === "recovery" ? "secondary" : "ghost"}
              onClick={() => setMode("recovery")}
            >
              Recovery Key
            </Button>
            <Button
              type="button"
              size="sm"
              variant={mode === "reset" ? "secondary" : "ghost"}
              onClick={() => setMode("reset")}
            >
              Reset Password
            </Button>
          </div>

          <div className="space-y-4">
            {mode === "password" ? (
              <div className="space-y-1.5">
                <Label htmlFor="unlock-pw">Master Password</Label>
                <Input
                  id="unlock-pw"
                  type="password"
                  autoFocus
                  autoComplete="current-password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                />
              </div>
            ) : (
              <>
                <div className="space-y-1.5">
                  <Label htmlFor="unlock-rec">Recovery Key</Label>
                  <Input
                    id="unlock-rec"
                    autoFocus
                    placeholder="XXXX-XXXX-XXXX-..."
                    className="font-mono"
                    value={recoveryKey}
                    onChange={(e) => setRecoveryKey(e.target.value)}
                  />
                </div>
                {mode === "reset" && (
                  <div className="space-y-1.5">
                    <Label htmlFor="reset-pw">
                      New Master Password (min {MIN_PASSWORD_CHARS} chars)
                    </Label>
                    <Input
                      id="reset-pw"
                      type="password"
                      autoComplete="new-password"
                      value={newPassword}
                      onChange={(e) => setNewPassword(e.target.value)}
                    />
                  </div>
                )}
              </>
            )}

            {error && <p className="text-sm text-destructive">{error}</p>}
          </div>

          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" disabled={busy}>
              {busy ? "Verifying…" : mode === "reset" ? "Reset & Unlock" : "Unlock"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
};
