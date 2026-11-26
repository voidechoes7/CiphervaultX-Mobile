import * as React from "react";
import { listen } from "@tauri-apps/api/event";
import { FileArchive, KeyRound, Lock, Menu, Moon, Settings, Shield, Sun, X } from "lucide-react";
import { backend, isTauriRuntime, type AppGateStatus, type VaultInfo } from "@/lib/api";
import {
  applyTheme,
  isValidTheme,
  loadTheme,
  nextQuickTheme,
  resolveMode,
  type ThemeId,
} from "@/lib/themes";
import { cn } from "@/lib/utils";
import { AddExistingVaultDialog } from "./components/AddExistingVaultDialog";
import { AppAccessGate } from "./components/AppAccessGate";
import { CreateVaultWizard } from "./components/CreateVaultWizard";
import { FileExplorer } from "./components/FileExplorer";
import { PasswordGeneratorView } from "./components/PasswordGeneratorView";
import { SettingsView } from "./components/SettingsView";
import { Sidebar, type ActiveView } from "./components/Sidebar";
import { ToolsView } from "./components/ToolsView";
import { UnlockDialog } from "./components/UnlockDialog";
import { VaultDashboard } from "./components/VaultDashboard";

interface TransferEvent {
  vault_id: string;
  operation: string;
  done: number;
  total: number;
}

export const App: React.FC = () => {
  const [gateStatus, setGateStatus] = React.useState<AppGateStatus | null>(null);
  const [vaults, setVaults] = React.useState<VaultInfo[]>([]);
  const [view, setView] = React.useState<ActiveView>({ kind: "dashboard" });
  const [theme, setTheme] = React.useState<ThemeId>(() => loadTheme());
  const [autoLockMinutes, setAutoLockMinutes] = React.useState<number>(10);
  const [wizardOpen, setWizardOpen] = React.useState(false);
  const [addExistingOpen, setAddExistingOpen] = React.useState(false);
  const [addExistingError, setAddExistingError] = React.useState<string | null>(null);
  const [isMobilePlatform, setIsMobilePlatform] = React.useState(false);
  const [unlockTarget, setUnlockTarget] = React.useState<VaultInfo | null>(null);
  const [transfer, setTransfer] = React.useState<TransferEvent | null>(null);
  const [mobileMenuOpen, setMobileMenuOpen] = React.useState(false);

  const refreshVaults = React.useCallback(async () => {
    const list = await backend.listVaults();
    setVaults(list);
  }, []);

  React.useEffect(() => {
    applyTheme(theme);
  }, [theme]);

  React.useEffect(() => {
    void backend.getAppGateStatus().then((status) => {
      setGateStatus(status);
      if (!status.enabled || status.unlocked) {
        void refreshVaults();
      }
    });
    void backend.getSettings().then((s) => {
      if (isValidTheme(s.theme)) {
        setTheme(s.theme);
        applyTheme(s.theme);
      }
      setAutoLockMinutes(s.auto_lock_minutes);
    });
    void backend
      .isMobile()
      .then((mobile) => setIsMobilePlatform(mobile))
      .catch(() => undefined);
  }, [refreshVaults]);

  React.useEffect(() => {
    if (!isTauriRuntime()) return;
    let unlistenProgress: (() => void) | undefined;
    let unlistenAutoLock: (() => void) | undefined;
    let unlistenGateLock: (() => void) | undefined;

    void listen<TransferEvent>("transfer-progress", (event) => {
      const p = event.payload;
      if (p.total > 0 && p.done >= p.total) {
        setTransfer(null);
      } else {
        setTransfer(p);
      }
    }).then((fn) => {
      unlistenProgress = fn;
    });

    void listen<string[]>("vault-auto-locked", () => {
      void refreshVaults();
      setView({ kind: "dashboard" });
    }).then((fn) => {
      unlistenAutoLock = fn;
    });

    void listen("app-gate-locked", () => {
      void backend.getAppGateStatus().then(setGateStatus);
      setVaults([]);
      setView({ kind: "dashboard" });
    }).then((fn) => {
      unlistenGateLock = fn;
    });

    return () => {
      unlistenProgress?.();
      unlistenAutoLock?.();
      unlistenGateLock?.();
    };
  }, [refreshVaults]);

  const handleLockAppGate = async () => {
    const next = await backend.lockAppGate();
    setGateStatus(next);
    setVaults([]);
    setView({ kind: "dashboard" });
  };

  if (gateStatus === null) {
    return (
      <div className="flex h-screen w-screen items-center justify-center bg-background text-sm text-muted-foreground">
        Initializing CipherVaultX…
      </div>
    );
  }

  if (gateStatus.enabled && !gateStatus.unlocked) {
    return (
      <AppAccessGate
        status={gateStatus}
        onUnlocked={(next) => {
          setGateStatus(next);
          void refreshVaults();
        }}
      />
    );
  }

  const handleAddExisting = async () => {
    setAddExistingError(null);
    if (isMobilePlatform) {
      setAddExistingOpen(true);
      return;
    }
    const path = await backend.pickFolder("Select existing CVZ v1 vault folder");
    if (!path) return;
    try {
      await backend.registerExistingVault(path);
      await refreshVaults();
    } catch (err) {
      setAddExistingError(err instanceof Error ? err.message : String(err));
      setAddExistingOpen(true);
    }
  };

  const handleLockVault = async (vaultId: string) => {
    await backend.lockVault(vaultId);
    await refreshVaults();
    if (view.kind === "explorer" && view.vaultId === vaultId) {
      setView({ kind: "dashboard" });
    }
  };

  const handleLockAll = async () => {
    await backend.lockAllVaults();
    await refreshVaults();
    if (view.kind === "explorer") {
      setView({ kind: "dashboard" });
    }
  };

  const handleRemoveVault = async (vaultId: string) => {
    await backend.removeVaultEntry(vaultId);
    await refreshVaults();
    if (view.kind === "explorer" && view.vaultId === vaultId) {
      setView({ kind: "dashboard" });
    }
  };

  const handleThemeChange = async (next: ThemeId) => {
    setTheme(next);
    applyTheme(next);
    await backend.updateSettings({ theme: next, auto_lock_minutes: autoLockMinutes });
  };

  const handleQuickToggleTheme = () => {
    void handleThemeChange(nextQuickTheme(theme));
  };

  const handleAutoLockChange = async (minutes: number) => {
    setAutoLockMinutes(minutes);
    await backend.updateSettings({ theme, auto_lock_minutes: minutes });
  };

  const selectView = (next: ActiveView) => {
    setView(next);
    setMobileMenuOpen(false);
  };

  const activeVault =
    view.kind === "explorer" ? vaults.find((v) => v.id === view.vaultId) : undefined;
  const anyUnlocked = vaults.some((v) => v.unlocked);
  const isDark = resolveMode(theme) === "dark";

  return (
    <div
      className="flex h-[100dvh] w-screen flex-col overflow-hidden bg-background text-foreground md:flex-row"
      onPointerDown={() => void backend.touchActivity()}
    >
      {/* Mobile top bar (< 768px) with safe-area padding for iPhone notch / Android status bar */}
      <header
        className="surface-glass flex shrink-0 items-center justify-between border-b border-border px-4 py-3 md:hidden"
        style={{ paddingTop: "max(0.75rem, env(safe-area-inset-top))" }}
      >
        <div className="flex items-center gap-2.5">
          <button
            type="button"
            onClick={() => setMobileMenuOpen(true)}
            className="rounded-md p-1.5 text-muted-foreground hover:bg-accent hover:text-foreground"
            aria-label="Open navigation menu"
          >
            <Menu className="h-5 w-5" />
          </button>
          <img
            src="/logo.png"
            alt="Fortress CipherVaultX"
            className="h-7 w-7 rounded-md border border-primary/30 object-cover"
          />
          <div>
            <div className="text-sm font-semibold leading-tight tracking-tight">CipherVaultX</div>
            <div className="text-[10px] text-muted-foreground">Fortress · v0.2.0</div>
          </div>
        </div>
        <div className="flex items-center gap-1.5">
          <button
            type="button"
            onClick={handleQuickToggleTheme}
            className="rounded-md border border-border bg-card p-1.5 text-primary hover:bg-accent"
            aria-label="Toggle light or dark theme"
          >
            {isDark ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
          </button>
          {anyUnlocked && (
            <button
              type="button"
              onClick={() => void handleLockAll()}
              className="inline-flex items-center gap-1 rounded-md border border-border bg-card px-2.5 py-1.5 text-xs font-medium text-foreground"
            >
              <Lock className="h-3.5 w-3.5 text-primary" />
              Lock
            </button>
          )}
        </div>
      </header>

      {/* Desktop persistent sidebar (>= 768px) */}
      <div className="hidden h-full md:flex">
        <Sidebar
          vaults={vaults}
          view={view}
          theme={theme}
          onQuickToggleTheme={handleQuickToggleTheme}
          onSelectView={selectView}
          onCreateVault={() => setWizardOpen(true)}
          onLockAll={handleLockAll}
        />
      </div>

      {/* Mobile slide-over drawer (< 768px) */}
      {mobileMenuOpen && (
        <div className="fixed inset-0 z-50 flex md:hidden">
          <div
            className="fixed inset-0 bg-background/75 backdrop-blur-sm"
            onClick={() => setMobileMenuOpen(false)}
          />
          <div className="relative z-10 flex h-full w-72 max-w-[85vw] flex-col shadow-2xl">
            <button
              type="button"
              onClick={() => setMobileMenuOpen(false)}
              className="absolute right-3 top-4 z-20 rounded-md p-1.5 text-muted-foreground hover:bg-accent hover:text-foreground"
              aria-label="Close navigation menu"
            >
              <X className="h-4 w-4" />
            </button>
            <Sidebar
              vaults={vaults}
              view={view}
              theme={theme}
              onQuickToggleTheme={handleQuickToggleTheme}
              onSelectView={selectView}
              onCreateVault={() => {
                setMobileMenuOpen(false);
                setWizardOpen(true);
              }}
              onLockAll={() => {
                setMobileMenuOpen(false);
                void handleLockAll();
              }}
            />
          </div>
        </div>
      )}

      <main className="flex-1 overflow-y-auto">
        {view.kind === "dashboard" && (
          <VaultDashboard
            vaults={vaults}
            onCreateVault={() => setWizardOpen(true)}
            onAddExisting={handleAddExisting}
            onRequestUnlock={(v) => setUnlockTarget(v)}
            onOpenVault={(id) => selectView({ kind: "explorer", vaultId: id })}
            onLockVault={handleLockVault}
            onRemoveVault={handleRemoveVault}
          />
        )}

        {view.kind === "explorer" && activeVault && activeVault.unlocked && (
          <FileExplorer
            vault={activeVault}
            transfer={
              transfer && transfer.vault_id === activeVault.id
                ? {
                    operation: transfer.operation,
                    done: transfer.done,
                    total: transfer.total,
                  }
                : null
            }
            onLock={handleLockVault}
          />
        )}

        {view.kind === "generator" && <PasswordGeneratorView />}

        {view.kind === "tools" && <ToolsView />}

        {view.kind === "settings" && (
          <SettingsView
            theme={theme}
            autoLockMinutes={autoLockMinutes}
            vaults={vaults}
            gateStatus={gateStatus}
            onThemeChange={handleThemeChange}
            onAutoLockChange={handleAutoLockChange}
            onLockAppGate={() => void handleLockAppGate()}
          />
        )}
      </main>

      {/* Mobile bottom tab bar (< 768px) */}
      <nav
        aria-label="Mobile bottom navigation"
        className="surface-glass grid shrink-0 grid-cols-4 border-t border-border md:hidden"
        style={{ paddingBottom: "max(0.35rem, env(safe-area-inset-bottom))" }}
      >
        {(
          [
            {
              key: "dashboard",
              label: "Vaults",
              icon: Shield,
              active: view.kind === "dashboard" || view.kind === "explorer",
              target: { kind: "dashboard" } as ActiveView,
            },
            {
              key: "tools",
              label: "Tools",
              icon: FileArchive,
              active: view.kind === "tools",
              target: { kind: "tools" } as ActiveView,
            },
            {
              key: "generator",
              label: "PassGen",
              icon: KeyRound,
              active: view.kind === "generator",
              target: { kind: "generator" } as ActiveView,
            },
            {
              key: "settings",
              label: "Settings",
              icon: Settings,
              active: view.kind === "settings",
              target: { kind: "settings" } as ActiveView,
            },
          ] as const
        ).map((item) => {
          const Icon = item.icon;
          return (
            <button
              key={item.key}
              type="button"
              onClick={() => selectView(item.target)}
              className={cn(
                "flex flex-col items-center justify-center gap-0.5 py-2 text-[11px] font-medium transition-colors",
                item.active ? "text-primary" : "text-muted-foreground hover:text-foreground"
              )}
            >
              <Icon className="h-4 w-4" />
              <span>{item.label}</span>
            </button>
          );
        })}
      </nav>

      <CreateVaultWizard
        open={wizardOpen}
        onOpenChange={setWizardOpen}
        onCreated={async (created) => {
          await refreshVaults();
          selectView({ kind: "explorer", vaultId: created.id });
        }}
      />

      <AddExistingVaultDialog
        open={addExistingOpen}
        isMobile={isMobilePlatform}
        initialError={addExistingError}
        onOpenChange={(open) => {
          setAddExistingOpen(open);
          if (!open) setAddExistingError(null);
        }}
        onAdded={async () => {
          await refreshVaults();
        }}
      />

      <UnlockDialog
        vault={unlockTarget}
        onClose={() => setUnlockTarget(null)}
        onUnlocked={async (unlocked) => {
          setUnlockTarget(null);
          await refreshVaults();
          selectView({ kind: "explorer", vaultId: unlocked.id });
        }}
      />
    </div>
  );
};

export default App;
