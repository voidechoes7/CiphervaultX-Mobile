import * as React from "react";
import { Check, FolderOpen, FolderPlus, RefreshCw } from "lucide-react";
import { backend, type DiscoveredVault } from "@/lib/api";
import { Badge } from "./ui/badge";
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

interface AddExistingVaultDialogProps {
  open: boolean;
  isMobile: boolean;
  initialError?: string | null;
  onOpenChange: (open: boolean) => void;
  onAdded: () => void | Promise<void>;
}

export const AddExistingVaultDialog: React.FC<AddExistingVaultDialogProps> = ({
  open,
  isMobile,
  initialError = null,
  onOpenChange,
  onAdded,
}) => {
  const [path, setPath] = React.useState("");
  const [name, setName] = React.useState("");
  const [vaultsRoot, setVaultsRoot] = React.useState("");
  const [discovered, setDiscovered] = React.useState<DiscoveredVault[]>([]);
  const [scanning, setScanning] = React.useState(false);
  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);

  const loadLocalVaults = React.useCallback(async () => {
    setScanning(true);
    try {
      const [root, found] = await Promise.all([
        backend.defaultVaultsDir().catch(() => ""),
        backend.listDiscoveredVaults().catch(() => [] as DiscoveredVault[]),
      ]);
      setVaultsRoot(root);
      setDiscovered(found);
    } finally {
      setScanning(false);
    }
  }, []);

  React.useEffect(() => {
    if (open) {
      setError(initialError);
      void loadLocalVaults();
    } else {
      setPath("");
      setName("");
      setError(null);
      setBusy(false);
    }
  }, [open, initialError, loadLocalVaults]);

  const handleBrowse = async () => {
    setError(null);
    const picked = await backend.pickFolder("Select existing CVZ v1 vault folder");
    if (picked) {
      setPath(picked);
    }
  };

  const handleRegister = async (targetPath: string, targetName?: string) => {
    setError(null);
    const trimmed = targetPath.trim();
    if (!trimmed) {
      setError("Enter the folder path of an existing CVZ v1 vault.");
      return;
    }
    setBusy(true);
    try {
      await backend.registerExistingVault(trimmed, targetName?.trim() || undefined);
      await onAdded();
      onOpenChange(false);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    await handleRegister(path, name);
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <FolderPlus className="h-5 w-5 text-primary" />
            Add Existing Vault
          </DialogTitle>
          <DialogDescription>
            {isMobile
              ? "Select a vault found in app storage or enter the full path to a folder containing cvz.vault.json."
              : "Choose an existing CVZ v1 vault folder containing cvz.vault.json."}
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <Label className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
                Vaults in App Storage
              </Label>
              <Button
                type="button"
                variant="ghost"
                size="sm"
                className="h-7 px-2 text-xs"
                onClick={() => void loadLocalVaults()}
                disabled={scanning || busy}
              >
                <RefreshCw className={`h-3.5 w-3.5 ${scanning ? "animate-spin" : ""}`} />
                Refresh
              </Button>
            </div>

            {discovered.length === 0 ? (
              <div className="rounded-lg border border-dashed border-border bg-muted/30 p-3 text-xs text-muted-foreground">
                {scanning
                  ? "Scanning app storage…"
                  : "No unregistered vaults found in app storage yet."}
                {vaultsRoot && (
                  <div className="mt-1 truncate font-mono text-[11px] opacity-80">{vaultsRoot}</div>
                )}
              </div>
            ) : (
              <div className="max-h-44 space-y-2 overflow-y-auto pr-1">
                {discovered.map((v) => (
                  <div
                    key={v.path}
                    className="flex items-center justify-between gap-2 rounded-lg border border-border bg-card/80 px-3 py-2"
                  >
                    <div className="min-w-0 flex-1">
                      <div className="truncate text-sm font-medium">{v.name}</div>
                      <div className="truncate font-mono text-[11px] text-muted-foreground">
                        {v.path}
                      </div>
                    </div>
                    {v.already_registered ? (
                      <Badge variant="secondary" className="shrink-0 gap-1">
                        <Check className="h-3 w-3" />
                        Added
                      </Badge>
                    ) : (
                      <Button
                        type="button"
                        size="sm"
                        variant="outline"
                        className="shrink-0"
                        disabled={busy}
                        onClick={() => void handleRegister(v.path, v.name)}
                      >
                        Add
                      </Button>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>

          <form onSubmit={(e) => void handleSubmit(e)} className="space-y-3">
            <div className="space-y-1.5">
              <Label htmlFor="existing-vault-path">Vault Folder Path</Label>
              <div className="flex gap-2">
                <Input
                  id="existing-vault-path"
                  value={path}
                  onChange={(e) => setPath(e.target.value)}
                  placeholder={vaultsRoot ? `${vaultsRoot}/MyVault` : "/path/to/vault"}
                  className="font-mono text-xs"
                  disabled={busy}
                />
                {!isMobile && (
                  <Button
                    type="button"
                    variant="outline"
                    onClick={() => void handleBrowse()}
                    disabled={busy}
                  >
                    <FolderOpen className="h-4 w-4" />
                    Browse
                  </Button>
                )}
              </div>
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="existing-vault-name">Display Name (optional)</Label>
              <Input
                id="existing-vault-name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="Defaults to folder name"
                disabled={busy}
              />
            </div>

            {error && (
              <div className="rounded-lg border border-destructive/40 bg-destructive/10 px-3 py-2 text-xs text-destructive">
                {error}
              </div>
            )}

            <DialogFooter>
              <Button
                type="button"
                variant="ghost"
                onClick={() => onOpenChange(false)}
                disabled={busy}
              >
                Cancel
              </Button>
              <Button type="submit" disabled={busy || !path.trim()}>
                {busy ? "Adding…" : "Add Vault"}
              </Button>
            </DialogFooter>
          </form>
        </div>
      </DialogContent>
    </Dialog>
  );
};
