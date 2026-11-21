import * as React from "react";
import { FolderOpen, FolderPlus, Lock, Plus, Trash2, Unlock } from "lucide-react";
import type { VaultInfo } from "@/lib/api";
import { Badge } from "./ui/badge";
import { Button } from "./ui/button";

interface VaultDashboardProps {
  vaults: VaultInfo[];
  onCreateVault: () => void;
  onAddExisting: () => void;
  onRequestUnlock: (vault: VaultInfo) => void;
  onOpenVault: (vaultId: string) => void;
  onLockVault: (vaultId: string) => void;
  onRemoveVault: (vaultId: string) => void;
}

export const VaultDashboard: React.FC<VaultDashboardProps> = ({
  vaults,
  onCreateVault,
  onAddExisting,
  onRequestUnlock,
  onOpenVault,
  onLockVault,
  onRemoveVault,
}) => {
  return (
    <div className="mx-auto max-w-4xl space-y-8 p-8">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div className="space-y-1">
          <h1 className="text-2xl font-semibold tracking-tight">Encrypted Vaults</h1>
          <p className="text-sm text-muted-foreground">
            Client-side file and filename encryption using the CVZ v1 format.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" onClick={onAddExisting}>
            <FolderPlus className="h-4 w-4" />
            Add Existing
          </Button>
          <Button onClick={onCreateVault}>
            <Plus className="h-4 w-4" />
            New Vault
          </Button>
        </div>
      </div>

      {vaults.length === 0 ? (
        <div className="rounded-lg border border-dashed border-border bg-card p-12 text-center">
          <p className="text-sm font-medium">No vaults configured</p>
          <p className="mt-1 text-sm text-muted-foreground">
            Create a new encrypted vault in an empty folder, or register an existing CVZ v1 vault.
          </p>
          <div className="mt-6 flex justify-center gap-3">
            <Button onClick={onCreateVault}>Create Vault</Button>
            <Button variant="outline" onClick={onAddExisting}>
              Open Existing Folder
            </Button>
          </div>
        </div>
      ) : (
        <div className="grid gap-4">
          {vaults.map((v) => (
            <div
              key={v.id}
              className="flex flex-wrap items-center justify-between gap-4 rounded-lg border border-border bg-card p-5"
            >
              <div className="min-w-0 flex-1 space-y-1">
                <div className="flex items-center gap-2.5">
                  <span className="truncate text-base font-medium">{v.name}</span>
                  <Badge variant={v.unlocked ? "default" : "secondary"}>
                    {v.unlocked ? "Unlocked" : "Locked"}
                  </Badge>
                  {v.summary && (
                    <Badge variant="outline">{v.summary.suite}</Badge>
                  )}
                </div>
                <p className="truncate font-mono text-xs text-muted-foreground">{v.path}</p>
              </div>

              <div className="flex items-center gap-2">
                {v.unlocked ? (
                  <>
                    <Button size="sm" onClick={() => onOpenVault(v.id)}>
                      <FolderOpen className="h-4 w-4" />
                      Browse
                    </Button>
                    <Button variant="outline" size="sm" onClick={() => onLockVault(v.id)}>
                      <Lock className="h-4 w-4" />
                      Lock
                    </Button>
                  </>
                ) : (
                  <Button size="sm" onClick={() => onRequestUnlock(v)}>
                    <Unlock className="h-4 w-4" />
                    Unlock
                  </Button>
                )}
                <Button
                  variant="ghost"
                  size="icon"
                  aria-label={`Remove ${v.name} from list`}
                  onClick={() => onRemoveVault(v.id)}
                >
                  <Trash2 className="h-4 w-4 text-muted-foreground" />
                </Button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
