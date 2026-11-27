import * as React from "react";
import { Check, CheckCircle2, Copy, KeyRound, Lock, ShieldAlert, ShieldCheck } from "lucide-react";
import { backend, type AppGateStatus, type IntegrityReport, type VaultInfo } from "@/lib/api";
import {
  applyTheme,
  applyUiStyle,
  THEMES,
  UI_STYLES,
  type ThemeId,
  type UiStyleId,
} from "@/lib/themes";
import { cn } from "@/lib/utils";
import { Button } from "./ui/button";
import { Input } from "./ui/input";
import { Label } from "./ui/label";
import { Select } from "./ui/select";
import { Separator } from "./ui/separator";

interface SettingsViewProps {
  theme: ThemeId;
  uiStyle: UiStyleId;
  autoLockMinutes: number;
  vaults: VaultInfo[];
  gateStatus: AppGateStatus;
  onThemeChange: (theme: ThemeId) => void;
  onUiStyleChange: (style: UiStyleId) => void;
  onAutoLockChange: (minutes: number) => void;
  onLockAppGate: () => void;
}

export const SettingsView: React.FC<SettingsViewProps> = ({
  theme,
  uiStyle,
  autoLockMinutes,
  vaults,
  gateStatus,
  onThemeChange,
  onUiStyleChange,
  onAutoLockChange,
  onLockAppGate,
}) => {
  const unlockedVaults = vaults.filter((v) => v.unlocked);
  const [selectedVaultId, setSelectedVaultId] = React.useState<string>(
    unlockedVaults[0]?.id ?? ""
  );
  const [verifying, setVerifying] = React.useState(false);
  const [report, setReport] = React.useState<IntegrityReport | null>(null);
  const [verifyError, setVerifyError] = React.useState<string | null>(null);

  const [gatePhrase, setGatePhrase] = React.useState("");
  const [generatedHash, setGeneratedHash] = React.useState<string | null>(null);
  const [generatingHash, setGeneratingHash] = React.useState(false);
  const [hashError, setHashError] = React.useState<string | null>(null);
  const [copiedHash, setCopiedHash] = React.useState(false);

  React.useEffect(() => {
    if (!unlockedVaults.some((v) => v.id === selectedVaultId)) {
      setSelectedVaultId(unlockedVaults[0]?.id ?? "");
    }
  }, [unlockedVaults, selectedVaultId]);

  const handleSelectTheme = (id: ThemeId) => {
    applyTheme(id);
    onThemeChange(id);
  };

  const handleSelectUiStyle = (id: UiStyleId) => {
    applyUiStyle(id);
    onUiStyleChange(id);
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

  const handleGenerateGateHash = async () => {
    if (gatePhrase.length < 8) {
      setHashError("Access passphrase must be at least 8 characters (12+ recommended).");
      return;
    }
    setGeneratingHash(true);
    setHashError(null);
    setGeneratedHash(null);
    setCopiedHash(false);
    try {
      const hash = await backend.generateAccessGateHash(gatePhrase);
      setGeneratedHash(hash);
      setGatePhrase("");
    } catch (err) {
      setHashError(err instanceof Error ? err.message : String(err));
    } finally {
      setGeneratingHash(false);
    }
  };

  const handleCopyHash = async () => {
    if (!generatedHash) return;
    await navigator.clipboard.writeText(generatedHash);
    setCopiedHash(true);
    setTimeout(() => setCopiedHash(false), 2000);
  };

  return (
    <div className="mx-auto max-w-3xl space-y-8 p-4 md:p-8">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Settings &amp; Verification</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Appearance, session auto-lock, Private Access Gate, and authenticated vault integrity
          checks.
        </p>
      </div>

      <section className="space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="text-base font-medium">Private Access Gate (Personal Build Lock)</h2>
            <p className="mt-1 text-sm text-muted-foreground">
              Lock compiled builds to authorized users via the{" "}
              <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs">
                CVZ_PRIVATE_ACCESS_HASH
              </code>{" "}
              GitHub Actions Secret. Separate multiple hashes with commas to authorize family or
              trusted friends.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <span
              className={cn(
                "inline-flex items-center gap-1.5 rounded-full border px-3 py-1 text-xs font-medium",
                gateStatus.enabled
                  ? "border-primary/40 bg-primary/10 text-primary"
                  : "border-border bg-muted text-muted-foreground"
              )}
            >
              <ShieldCheck className="h-3.5 w-3.5" />
              {gateStatus.enabled
                ? `Active (${gateStatus.authorized_keys} ${
                    gateStatus.authorized_keys === 1 ? "key" : "keys"
                  })`
                : "Inactive (Open Build)"}
            </span>
            {gateStatus.enabled && (
              <Button variant="outline" size="sm" onClick={onLockAppGate}>
                <Lock className="mr-1.5 h-3.5 w-3.5" />
                Lock App Now
              </Button>
            )}
          </div>
        </div>

        <div className="rounded-xl border border-border bg-card p-4 space-y-3 shadow-sm">
          <div className="text-xs font-medium text-foreground">
            Offline Argon2id Access Hash Generator
          </div>
          <div className="flex flex-wrap items-end gap-3">
            <div className="min-w-[220px] flex-1 space-y-1.5">
              <Label htmlFor="gate-phrase-gen">Access Passphrase (never leaves your device)</Label>
              <Input
                id="gate-phrase-gen"
                type="password"
                value={gatePhrase}
                onChange={(e) => setGatePhrase(e.target.value)}
                placeholder="Enter a strong access passphrase (12+ chars)"
                disabled={generatingHash}
              />
            </div>
            <Button
              onClick={handleGenerateGateHash}
              disabled={generatingHash || gatePhrase.length < 8}
            >
              <KeyRound className="mr-2 h-4 w-4" />
              {generatingHash ? "Hashing…" : "Generate Argon2id Hash"}
            </Button>
          </div>

          {hashError && <p className="text-xs text-destructive">{hashError}</p>}

          {generatedHash && (
            <div className="space-y-2 rounded-md border border-primary/30 bg-background p-3">
              <div className="flex items-center justify-between gap-2">
                <span className="text-xs font-medium text-primary">
                  Ready for GitHub Secret (CVZ_PRIVATE_ACCESS_HASH)
                </span>
                <Button variant="outline" size="sm" onClick={handleCopyHash}>
                  {copiedHash ? (
                    <>
                      <Check className="mr-1.5 h-3.5 w-3.5" />
                      Copied
                    </>
                  ) : (
                    <>
                      <Copy className="mr-1.5 h-3.5 w-3.5" />
                      Copy Hash
                    </>
                  )}
                </Button>
              </div>
              <code className="block break-all font-mono text-[11px] text-muted-foreground">
                {generatedHash}
              </code>
            </div>
          )}
        </div>
      </section>

      <Separator />

      <section className="space-y-4">
        <div>
          <h2 className="text-base font-medium">Interface Style (Light &amp; Dark)</h2>
          <p className="mt-0.5 text-xs text-muted-foreground">
            Switch the visual language independently from your color theme — works seamlessly in
            both Light and Dark modes.
          </p>
        </div>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          {UI_STYLES.map((s) => (
            <button
              key={s.id}
              type="button"
              onClick={() => handleSelectUiStyle(s.id)}
              className={cn(
                "rounded-xl border p-3.5 text-left transition-all",
                uiStyle === s.id
                  ? "border-primary bg-accent shadow-sm ring-1 ring-primary/40"
                  : "border-border bg-card hover:border-primary/40 hover:bg-accent/40"
              )}
            >
              <div className="flex items-center justify-between gap-2">
                <span className="text-sm font-semibold">{s.label}</span>
                <span className="inline-block rounded bg-muted px-2 py-0.5 text-[10px] font-medium uppercase tracking-wider text-muted-foreground">
                  {s.badge}
                </span>
              </div>
              <p className="mt-1.5 text-xs text-muted-foreground">{s.description}</p>
            </button>
          ))}
        </div>
      </section>

      <Separator />

      <section className="space-y-4">
        <div>
          <h2 className="text-base font-medium">Themes (Dark &amp; Light)</h2>
          <p className="mt-0.5 text-xs text-muted-foreground">
            Choose from 10 curated dark, OLED, cyber, and daylight themes across Windows, Android,
            and iOS.
          </p>
        </div>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {THEMES.map((t) => (
            <button
              key={t.id}
              type="button"
              onClick={() => handleSelectTheme(t.id)}
              className={cn(
                "rounded-xl border p-3.5 text-left transition-all",
                theme === t.id
                  ? "border-primary bg-accent shadow-sm ring-1 ring-primary/40"
                  : "border-border bg-card hover:border-primary/40 hover:bg-accent/40"
              )}
            >
              <div className="flex items-center justify-between gap-2">
                <span className="text-sm font-semibold">{t.label}</span>
                <div className="flex items-center gap-1">
                  {t.swatches.map((hex, i) => (
                    <span
                      key={`${t.id}-${i}`}
                      className="h-3 w-3 rounded-full border border-border/80"
                      style={{ backgroundColor: hex }}
                    />
                  ))}
                </div>
              </div>
              <div className="mt-1.5 flex items-center justify-between gap-2">
                <span className="text-xs text-muted-foreground">{t.description}</span>
              </div>
              <div className="mt-2">
                <span className="inline-block rounded bg-muted px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wider text-muted-foreground">
                  {t.mode === "system" ? "Auto" : t.mode}
                </span>
              </div>
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
