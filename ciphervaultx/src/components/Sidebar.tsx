import * as React from "react";
import { KeyRound, Lock, Plus, Settings, Shield, Unlock } from "lucide-react";
import type { VaultInfo } from "@/lib/api";
import { cn } from "@/lib/utils";
import { Button } from "./ui/button";
import { Separator } from "./ui/separator";

export type ActiveView =
  | { kind: "dashboard" }
  | { kind: "explorer"; vaultId: string }
  | { kind: "generator" }
  | { kind: "settings" };

interface SidebarProps {
  vaults: VaultInfo[];
  view: ActiveView;
  onSelectView: (view: ActiveView) => void;
  onCreateVault: () => void;
  onLockAll: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({
  vaults,
  view,
  onSelectView,
  onCreateVault,
  onLockAll,
}) => {
  const anyUnlocked = vaults.some((v) => v.unlocked);

  return (
    <aside className="surface-glass flex h-full w-64 shrink-0 flex-col border-r border-border">
      <div className="flex items-center gap-2.5 px-5 py-5">
        <div className="flex h-8 w-8 items-center justify-center rounded-md border border-border bg-card">
          <Shield className="h-4 w-4 text-primary" />
        </div>
        <div>
          <div className="text-sm font-semibold tracking-tight">Fortress</div>
          <div className="text-[11px] text-muted-foreground">CipherVaultX · CVZ v1</div>
        </div>
      </div>

      <Separator />

      <div className="flex-1 overflow-y-auto px-3 py-4">
        <div className="mb-2 flex items-center justify-between px-2">
          <span className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
            Vaults
          </span>
          <Button
            variant="ghost"
            size="icon"
            className="h-6 w-6"
            onClick={onCreateVault}
            aria-label="Create new vault"
          >
            <Plus className="h-3.5 w-3.5" />
          </Button>
        </div>

        <nav className="space-y-1" aria-label="Vault navigation">
          <button
            type="button"
            onClick={() => onSelectView({ kind: "dashboard" })}
            className={cn(
              "flex w-full items-center justify-between rounded-md px-2.5 py-2 text-left text-sm transition-colors",
              view.kind === "dashboard"
                ? "bg-accent font-medium text-accent-foreground"
                : "text-muted-foreground hover:bg-accent/50 hover:text-foreground"
            )}
          >
            <span>All Vaults</span>
            <span className="text-xs opacity-70">{vaults.length}</span>
          </button>

          {vaults.map((v) => {
            const active = view.kind === "explorer" && view.vaultId === v.id;
            return (
              <button
                key={v.id}
                type="button"
                onClick={() =>
                  v.unlocked
                    ? onSelectView({ kind: "explorer", vaultId: v.id })
                    : onSelectView({ kind: "dashboard" })
                }
                className={cn(
                  "flex w-full items-center gap-2 rounded-md px-2.5 py-2 text-left text-sm transition-colors",
                  active
                    ? "bg-accent font-medium text-accent-foreground"
                    : "text-muted-foreground hover:bg-accent/50 hover:text-foreground"
                )}
              >
                {v.unlocked ? (
                  <Unlock className="h-3.5 w-3.5 shrink-0 text-primary" />
                ) : (
                  <Lock className="h-3.5 w-3.5 shrink-0 opacity-60" />
                )}
                <span className="truncate">{v.name}</span>
              </button>
            );
          })}
        </nav>
      </div>

      <Separator />

      <div className="space-y-2 p-3">
        {anyUnlocked && (
          <Button variant="outline" size="sm" className="w-full" onClick={onLockAll}>
            <Lock className="h-3.5 w-3.5" />
            Lock All Vaults
          </Button>
        )}
        <Button
          variant={view.kind === "generator" ? "secondary" : "ghost"}
          size="sm"
          className="w-full justify-start"
          onClick={() => onSelectView({ kind: "generator" })}
        >
          <KeyRound className="h-4 w-4" />
          Password Generator
        </Button>
        <Button
          variant={view.kind === "settings" ? "secondary" : "ghost"}
          size="sm"
          className="w-full justify-start"
          onClick={() => onSelectView({ kind: "settings" })}
        >
          <Settings className="h-4 w-4" />
          Settings &amp; Verification
        </Button>
        <p className="px-2 pt-1 text-[11px] leading-snug text-muted-foreground">
          Pre-audit software. Not independently audited.
        </p>
      </div>
    </aside>
  );
};
