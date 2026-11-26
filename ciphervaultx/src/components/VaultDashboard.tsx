import * as React from "react";
import {
  FolderOpen,
  FolderPlus,
  Lock,
  Plus,
  ShieldCheck,
  Sparkles,
  Trash2,
  Unlock,
} from "lucide-react";
import type { VaultInfo } from "@/lib/api";
import { cn } from "@/lib/utils";
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
  const unlockedCount = vaults.filter((v) => v.unlocked).length;

  return (
    <div className="hero-glow min-h-full">
      <div className="mx-auto max-w-4xl space-y-6 p-4 md:space-y-8 md:p-8">
        <div className="flex flex-wrap items-end justify-between gap-4">
          <div className="space-y-1">
            <div className="inline-flex items-center gap-1.5 rounded-full border border-primary/30 bg-primary/10 px-2.5 py-0.5 text-[11px] font-medium text-primary">
              <Sparkles className="h-3 w-3" />
              Fortress · CVZ v1 · v0.2.1
            </div>
            <h1 className="text-2xl font-semibold tracking-tight md:text-3xl">Encrypted Vaults</h1>
            <p className="text-sm text-muted-foreground">
              Zero-knowledge local encryption for files, folders, and filenames.
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <Button variant="outline" onClick={onAddExisting}>
              <FolderPlus className="h-4 w-4" />
              Add Existing
            </Button>
            <Button onClick={onCreateVault} className="shadow-sm">
              <Plus className="h-4 w-4" />
              New Vault
            </Button>
          </div>
        </div>

        <div className="grid grid-cols-3 gap-2.5 md:gap-4">
          <div className="rounded-xl border border-border bg-card/85 p-3.5 shadow-sm md:p-4">
            <div className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
              Vaults
            </div>
            <div className="mt-1 text-xl font-semibold tracking-tight md:text-2xl">
              {vaults.length}
            </div>
          </div>
          <div className="rounded-xl border border-border bg-card/85 p-3.5 shadow-sm md:p-4">
            <div className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
              Unlocked
            </div>
            <div className="mt-1 flex items-center gap-2 text-xl font-semibold tracking-tight md:text-2xl">
              <span
                className={cn(
                  "h-2.5 w-2.5 rounded-full",
                  unlockedCount > 0 ? "bg-primary shadow-[0_0_8px_hsl(var(--primary))]" : "bg-muted-foreground/40"
                )}
              />
              {unlockedCount}
            </div>
          </div>
          <div className="rounded-xl border border-border bg-card/85 p-3.5 shadow-sm md:p-4">
            <div className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
              KDF &amp; AEAD
            </div>
            <div className="mt-1.5 flex items-center gap-1.5 text-xs font-medium text-foreground md:text-sm">
              <ShieldCheck className="h-4 w-4 shrink-0 text-primary" />
              <span className="truncate">Argon2id</span>
            </div>
          </div>
        </div>

        {vaults.length === 0 ? (
          <div className="rounded-2xl border border-dashed border-border bg-card/80 p-8 text-center shadow-sm md:p-12">
            <img
              src="/logo.png"
              alt="Fortress CipherVaultX"
              className="mx-auto mb-4 h-16 w-16 rounded-2xl border border-primary/30 object-cover shadow-md"
            />
            <p className="text-base font-semibold">Create your first encrypted vault</p>
            <p className="mx-auto mt-1.5 max-w-md text-sm text-muted-foreground">
              Every file, directory marker, and filename is authenticated locally with Argon2id +
              XChaCha20-Poly1305 or AES-256-GCM before touching disk.
            </p>
            <div className="mt-6 flex flex-wrap justify-center gap-3">
              <Button onClick={onCreateVault}>
                <Plus className="h-4 w-4" />
                Create Vault
              </Button>
              <Button variant="outline" onClick={onAddExisting}>
                <FolderPlus className="h-4 w-4" />
                Open Existing Folder
              </Button>
            </div>
          </div>
        ) : (
          <div className="grid gap-3.5">
            {vaults.map((v) => (
              <div
                key={v.id}
                className={cn(
                  "flex flex-wrap items-center justify-between gap-4 rounded-xl border bg-card/90 p-4 shadow-sm transition-all md:p-5",
                  v.unlocked
                    ? "border-primary/40 hover:border-primary/70"
                    : "border-border hover:border-primary/30"
                )}
              >
                <div className="min-w-0 flex-1 space-y-1.5">
                  <div className="flex flex-wrap items-center gap-2">
                    <span
                      className={cn(
                        "h-2 w-2 shrink-0 rounded-full",
                        v.unlocked
                          ? "bg-primary shadow-[0_0_8px_hsl(var(--primary))]"
                          : "bg-muted-foreground/40"
                      )}
                    />
                    <span className="truncate text-base font-semibold">{v.name}</span>
                    <Badge variant={v.unlocked ? "default" : "secondary"}>
                      {v.unlocked ? "Unlocked" : "Locked"}
                    </Badge>
                    {v.summary && <Badge variant="outline">{v.summary.suite}</Badge>}
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
    </div>
  );
};
