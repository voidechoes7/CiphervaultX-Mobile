import * as React from "react";
import { listen } from "@tauri-apps/api/event";
import { backend, isTauriRuntime, type VaultInfo } from "@/lib/api";
import { applyTheme, isValidTheme, loadTheme, type ThemeId } from "@/lib/themes";
import { CreateVaultWizard } from "./components/CreateVaultWizard";
import { FileExplorer } from "./components/FileExplorer";
import { SettingsView } from "./components/SettingsView";
import { Sidebar, type ActiveView } from "./components/Sidebar";
import { UnlockDialog } from "./components/UnlockDialog";
import { VaultDashboard } from "./components/VaultDashboard";

interface TransferEvent {
  vault_id: string;
  operation: string;
  done: number;
  total: number;
}

export const App: React.FC = () => {
  const [vaults, setVaults] = React.useState<VaultInfo[]>([]);
  const [view, setView] = React.useState<ActiveView>({ kind: "dashboard" });
  const [theme, setTheme] = React.useState<ThemeId>(() => loadTheme());
  const [autoLockMinutes, setAutoLockMinutes] = React.useState<number>(10);
  const [wizardOpen, setWizardOpen] = React.useState(false);
  const [unlockTarget, setUnlockTarget] = React.useState<VaultInfo | null>(null);
  const [transfer, setTransfer] = React.useState<TransferEvent | null>(null);

  const refreshVaults = React.useCallback(async () => {
    const list = await backend.listVaults();
    setVaults(list);
  }, []);

  React.useEffect(() => {
    void refreshVaults();
    void backend.getSettings().then((s) => {
      if (isValidTheme(s.theme)) {
        setTheme(s.theme);
        applyTheme(s.theme);
      }
      setAutoLockMinutes(s.auto_lock_minutes);
    });
  }, [refreshVaults]);

  React.useEffect(() => {
    if (!isTauriRuntime()) return;
    let unlistenProgress: (() => void) | undefined;
    let unlistenAutoLock: (() => void) | undefined;

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

    return () => {
      unlistenProgress?.();
      unlistenAutoLock?.();
    };
  }, [refreshVaults]);

  const handleAddExisting = async () => {
    const path = await backend.pickFolder("Select existing CVZ v1 vault folder");
    if (!path) return;
    await backend.registerExistingVault(path);
    await refreshVaults();
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

  const handleAutoLockChange = async (minutes: number) => {
    setAutoLockMinutes(minutes);
    await backend.updateSettings({ theme, auto_lock_minutes: minutes });
  };

  const activeVault =
    view.kind === "explorer" ? vaults.find((v) => v.id === view.vaultId) : undefined;

  return (
    <div
      className="flex h-screen w-screen overflow-hidden bg-background text-foreground"
      onPointerDown={() => void backend.touchActivity()}
    >
      <Sidebar
        vaults={vaults}
        view={view}
        onSelectView={setView}
        onCreateVault={() => setWizardOpen(true)}
        onLockAll={handleLockAll}
      />

      <main className="flex-1 overflow-y-auto">
        {view.kind === "dashboard" && (
          <VaultDashboard
            vaults={vaults}
            onCreateVault={() => setWizardOpen(true)}
            onAddExisting={handleAddExisting}
            onRequestUnlock={(v) => setUnlockTarget(v)}
            onOpenVault={(id) => setView({ kind: "explorer", vaultId: id })}
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

        {view.kind === "settings" && (
          <SettingsView
            theme={theme}
            autoLockMinutes={autoLockMinutes}
            vaults={vaults}
            onThemeChange={handleThemeChange}
            onAutoLockChange={handleAutoLockChange}
          />
        )}
      </main>

      <CreateVaultWizard
        open={wizardOpen}
        onOpenChange={setWizardOpen}
        onCreated={async (created) => {
          await refreshVaults();
          setView({ kind: "explorer", vaultId: created.id });
        }}
      />

      <UnlockDialog
        vault={unlockTarget}
        onClose={() => setUnlockTarget(null)}
        onUnlocked={async (unlocked) => {
          setUnlockTarget(null);
          await refreshVaults();
          setView({ kind: "explorer", vaultId: unlocked.id });
        }}
      />
    </div>
  );
};

export default App;
