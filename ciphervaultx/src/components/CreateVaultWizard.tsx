import * as React from "react";
import { Check, Copy, FolderOpen } from "lucide-react";
import { backend, type CipherSuite, type KdfProfile, type VaultInfo } from "@/lib/api";
import { MIN_PASSWORD_CHARS, passwordStrength } from "@/lib/password";
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
import { Progress } from "./ui/progress";
import { Select } from "./ui/select";

interface CreateVaultWizardProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onCreated: (vault: VaultInfo) => void;
}

export const CreateVaultWizard: React.FC<CreateVaultWizardProps> = ({
  open,
  onOpenChange,
  onCreated,
}) => {
  const [name, setName] = React.useState("");
  const [path, setPath] = React.useState("");
  const [suite, setSuite] = React.useState<CipherSuite>("xchacha20-poly1305");
  const [kdfProfile, setKdfProfile] = React.useState<KdfProfile>("desktop");
  const [password, setPassword] = React.useState("");
  const [confirm, setConfirm] = React.useState("");
  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);
  const [recoveryKey, setRecoveryKey] = React.useState<string | null>(null);
  const [createdVault, setCreatedVault] = React.useState<VaultInfo | null>(null);
  const [copied, setCopied] = React.useState(false);
  const [acknowledged, setAcknowledged] = React.useState(false);

  const strength = passwordStrength(password);

  const reset = () => {
    setName("");
    setPath("");
    setSuite("xchacha20-poly1305");
    setKdfProfile("desktop");
    setPassword("");
    setConfirm("");
    setBusy(false);
    setError(null);
    setRecoveryKey(null);
    setCreatedVault(null);
    setCopied(false);
    setAcknowledged(false);
  };

  const handleClose = (nextOpen: boolean) => {
    if (!nextOpen) {
      if (recoveryKey && !acknowledged) return;
      reset();
    }
    onOpenChange(nextOpen);
  };

  const handlePickFolder = async () => {
    const picked = await backend.pickFolder("Select empty folder for new vault");
    if (picked) setPath(picked);
  };

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    if (!path.trim()) {
      setError("Select a destination folder.");
      return;
    }
    if (!strength.meetsPolicy) {
      setError(`Password must be at least ${MIN_PASSWORD_CHARS} characters.`);
      return;
    }
    if (password !== confirm) {
      setError("Passwords do not match.");
      return;
    }
    setBusy(true);
    try {
      const res = await backend.createVault({
        name: name.trim() || "Vault",
        path: path.trim(),
        suite,
        kdfProfile,
        password,
      });
      setPassword("");
      setConfirm("");
      setCreatedVault(res.vault);
      setRecoveryKey(res.recovery_key);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  const handleCopyRecovery = async () => {
    if (!recoveryKey) return;
    try {
      await navigator.clipboard.writeText(recoveryKey);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 2000);
    } catch {
      // Clipboard unavailable
    }
  };

  const handleFinish = () => {
    if (!createdVault) return;
    const v = createdVault;
    reset();
    onOpenChange(false);
    onCreated(v);
  };

  return (
    <Dialog open={open} onOpenChange={handleClose}>
      <DialogContent className="max-w-xl">
        {recoveryKey ? (
          <>
            <DialogHeader>
              <DialogTitle>Save One-Time Recovery Key</DialogTitle>
              <DialogDescription>
                This recovery key is displayed once and cannot be retrieved later. Store it offline
                in a secure location.
              </DialogDescription>
            </DialogHeader>

            <div className="space-y-4">
              <div className="rounded-md border border-border bg-background p-4 font-mono text-sm leading-relaxed break-all select-all">
                {recoveryKey}
              </div>

              <div className="flex items-center justify-between gap-2">
                <Button variant="outline" size="sm" onClick={handleCopyRecovery}>
                  {copied ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
                  {copied ? "Copied" : "Copy Recovery Key"}
                </Button>
                <label className="flex cursor-pointer items-center gap-2 text-sm">
                  <input
                    type="checkbox"
                    checked={acknowledged}
                    onChange={(e) => setAcknowledged(e.target.checked)}
                  />
                  I have stored this recovery key safely
                </label>
              </div>
            </div>

            <DialogFooter>
              <Button disabled={!acknowledged} onClick={handleFinish}>
                Open Vault
              </Button>
            </DialogFooter>
          </>
        ) : (
          <form onSubmit={handleCreate}>
            <DialogHeader>
              <DialogTitle>Create Encrypted Vault</DialogTitle>
              <DialogDescription>
                Files and filenames are encrypted locally in CVZ v1 format before touching disk.
              </DialogDescription>
            </DialogHeader>

            <div className="space-y-4">
              <div className="space-y-1.5">
                <Label htmlFor="vault-name">Vault Name</Label>
                <Input
                  id="vault-name"
                  placeholder="Personal Archive"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                />
              </div>

              <div className="space-y-1.5">
                <Label htmlFor="vault-folder">Empty Folder</Label>
                <div className="flex gap-2">
                  <Input
                    id="vault-folder"
                    placeholder="/path/to/empty-folder"
                    value={path}
                    onChange={(e) => setPath(e.target.value)}
                  />
                  <Button type="button" variant="outline" onClick={handlePickFolder}>
                    <FolderOpen className="h-4 w-4" />
                    Browse
                  </Button>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1.5">
                  <Label htmlFor="vault-suite">Cipher Suite</Label>
                  <Select
                    id="vault-suite"
                    value={suite}
                    onChange={(e) => setSuite(e.target.value as CipherSuite)}
                  >
                    <option value="xchacha20-poly1305">XChaCha20-Poly1305</option>
                    <option value="aes256-gcm">AES-256-GCM</option>
                  </Select>
                </div>

                <div className="space-y-1.5">
                  <Label htmlFor="vault-kdf">Argon2id Profile</Label>
                  <Select
                    id="vault-kdf"
                    value={kdfProfile}
                    onChange={(e) => setKdfProfile(e.target.value as KdfProfile)}
                  >
                    <option value="desktop">Desktop (256 MiB, t=3, p=1)</option>
                    <option value="mobile">Mobile (64 MiB, t=3, p=1)</option>
                  </Select>
                </div>
              </div>

              <div className="space-y-1.5">
                <Label htmlFor="vault-password">
                  Master Password (min {MIN_PASSWORD_CHARS} characters)
                </Label>
                <Input
                  id="vault-password"
                  type="password"
                  autoComplete="new-password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                />
                <div className="flex items-center justify-between text-xs text-muted-foreground">
                  <span>{strength.label}</span>
                  <span>~{strength.bits} bits</span>
                </div>
                <Progress value={(strength.score / 4) * 100} />
              </div>

              <div className="space-y-1.5">
                <Label htmlFor="vault-confirm">Confirm Password</Label>
                <Input
                  id="vault-confirm"
                  type="password"
                  autoComplete="new-password"
                  value={confirm}
                  onChange={(e) => setConfirm(e.target.value)}
                />
              </div>

              {error && <p className="text-sm text-destructive">{error}</p>}
            </div>

            <DialogFooter>
              <Button type="button" variant="outline" onClick={() => handleClose(false)}>
                Cancel
              </Button>
              <Button type="submit" disabled={busy || !strength.meetsPolicy}>
                {busy ? "Deriving keys…" : "Create Vault"}
              </Button>
            </DialogFooter>
          </form>
        )}
      </DialogContent>
    </Dialog>
  );
};
