import * as React from "react";
import { CheckCircle2, ShieldAlert } from "lucide-react";
import { backend, type IntegrityReport, type VaultInfo } from "@/lib/api";
import { applyTheme, THEMES, type ThemeId } from "@/lib/themes";
import { cn } from "@/lib/utils";
import { Button } from "./ui/button";
import { Label } from "./ui/label";
import { Select } from "./ui/select";
import { Separator } from "./ui/separator";

interface SettingsViewProps {
  theme: ThemeId;
  autoLockMinutes: number;
  vaults: VaultInfo[];
  onThemeChange: (theme: ThemeId) => void;
  onAutoLockChange: (minutes: number) => void;
}

export const SettingsView: React.FC<SettingsViewProps> = ({
  theme,
  autoLockMinutes,
  vaults,
  onThemeChange,
  onAutoLockChange,
}) => {
  const unlockedVaults = vaults.filter((v) => v.unlocked);
  const [selectedVaultId, setSelectedVaultId] = React.useState<string>(
    unlockedVaults[0]?.id ?? ""
  );
  const [verifying, setVerifying] = React.useState(false);
  const [report, setReport] = React.useState<IntegrityReport | null>(null);
  const [verifyError, setVerifyError] = React.useState<string | null>(null);

  React.useEffect(() => {
    if (!unlockedVaults.some((v) => v.id === selectedVaultId)) {
      setSelectedVaultId(unlockedVaults[0]?.id ?? "");
    }
  }, [unlockedVaults, selectedVaultId]);

  const handleSelectTheme = (id: ThemeId) => {
    applyTheme(id);
    onThemeChange(id);
  };

  const handleVerify = async () => {
    if (!selectedVaultId) return;
    setVerifying(true);
    setReport(null);
    setVerifyError(null);
    try {
      const res = await backend.verifyVault(selectedVaultId);
      setReport(res);
    } catch (err) {
      setVerifyError(err instanceof Error ? err.message : String(err));
    } finally {
      setVerifying(false);
    }
  };

  return (
    <div className="mx-auto max-w-3xl space-y-8 p-8">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Settings &amp; Verification</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Appearance, session auto-lock, and authenticated vault integrity checks.
        </p>
      </div>

      <section className="space-y-4">
        <h2 className="text-base font-medium">Theme</h2>
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
          {THEMES.map((t) => (
            <button
              key={t.id}
              type="button"
              onClick={() => handleSelectTheme(t.id)}
              className={cn(
                "rounded-lg border p-3.5 text-left transition-colors",
                theme === t.id
                  ? "border-primary bg-accent"
                  : "border-border bg-card hover:bg-accent/40"
              )}
            >
              <div className="text-sm font-medium">{t.label}</div>
              <div className="mt-1 text-xs text-muted-foreground">{t.description}</div>
            </button>
          ))}
        </div>
      </section>

      <Separator />

      <section className="space-y-3">
        <h2 className="text-base font-medium">Auto-Lock Inactivity Timeout</h2>
        <div className="max-w-xs space-y-1.5">
          <Label htmlFor="autolock-select">Lock all vaults after inactivity</Label>
          <Select
            id="autolock-select"
            value={String(autoLockMinutes)}
            onChange={(e) => onAutoLockChange(Number(e.target.value))}
          >
            <option value="0">Disabled</option>
            <option value="5">5 minutes</option>
            <option value="10">10 minutes</option>
            <option value="15">15 minutes</option>
            <option value="30">30 minutes</option>
            <option value="60">60 minutes</option>
          </Select>
        </div>
      </section>

      <Separator />

      <section className="space-y-4">
        <div>
          <h2 className="text-base font-medium">Full Authenticated Integrity Verification</h2>
          <p className="mt-1 text-sm text-muted-foreground">
            Scans every filename (AES-SIV), directory marker, file header, and STREAM chunk in an
            unlocked vault.
          </p>
        </div>

        {unlockedVaults.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            Unlock a vault first to run integrity verification.
          </p>
        ) : (
          <div className="flex flex-wrap items-end gap-3">
            <div className="min-w-[220px] flex-1 space-y-1.5">
              <Label htmlFor="verify-vault">Unlocked Vault</Label>
              <Select
                id="verify-vault"
                value={selectedVaultId}
                onChange={(e) => setSelectedVaultId(e.target.value)}
              >
                {unlockedVaults.map((v) => (
                  <option key={v.id} value={v.id}>
                    {v.name}
                  </option>
                ))}
              </Select>
            </div>
            <Button onClick={handleVerify} disabled={verifying || !selectedVaultId}>
              {verifying ? "Scanning…" : "Run Integrity Scan"}
            </Button>
          </div>
        )}

        {verifyError && <p className="text-sm text-destructive">{verifyError}</p>}

        {report && (
          <div className="rounded-lg border border-border bg-card p-4 space-y-3">
            <div className="flex items-center gap-2">
              {report.issues.length === 0 ? (
                <CheckCircle2 className="h-5 w-5 text-primary" />
              ) : (
                <ShieldAlert className="h-5 w-5 text-destructive" />
              )}
              <span className="text-sm font-medium">
                {report.issues.length === 0
                  ? `Verified clean: ${report.files_checked} files, ${report.dirs_checked} directories.`
                  : `${report.issues.length} integrity failure(s) detected (${report.files_checked} files, ${report.dirs_checked} directories scanned).`}
              </span>
            </div>
            {report.issues.length > 0 && (
              <ul className="space-y-1.5 font-mono text-xs text-destructive">
                {report.issues.map((issue, idx) => (
                  <li key={`${issue.path}-${idx}`}>
                    {issue.path}: {issue.reason}
                  </li>
                ))}
              </ul>
            )}
          </div>
        )}
      </section>

      <Separator />

      <section className="rounded-lg border border-border bg-card p-4 text-xs leading-relaxed text-muted-foreground">
        <strong className="text-foreground">Security Posture:</strong> Fortress / CipherVaultX is
        pre-audit software and has not undergone an independent security audit. It must not be
        treated as production-ready or claimed to be more secure than audited tools such as
        Cryptomator.
      </section>
    </div>
  );
};
