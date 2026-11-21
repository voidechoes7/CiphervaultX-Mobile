import * as React from "react";
import { Check, CheckCircle2, Copy, KeyRound, Lock, ShieldAlert, ShieldCheck } from "lucide-react";
import { backend, type AppGateStatus, type IntegrityReport, type VaultInfo } from "@/lib/api";
import { applyTheme, THEMES, type ThemeId } from "@/lib/themes";
import { cn } from "@/lib/utils";
import { Button } from "./ui/button";
import { Input } from "./ui/input";
import { Label } from "./ui/label";
import { Select } from "./ui/select";
import { Separator } from "./ui/separator";

interface SettingsViewProps {
  theme: ThemeId;
  autoLockMinutes: number;
  vaults: VaultInfo[];
  gateStatus: AppGateStatus;
  onThemeChange: (theme: ThemeId) => void;
  onAutoLockChange: (minutes: number) => void;
  onLockAppGate: () => void;
}

export const SettingsView: React.FC<SettingsViewProps> = ({
  theme,
  autoLockMinutes,
  vaults,
  gateStatus,
  onThemeChange,
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
    <div className="mx-auto max-w-3xl space-y-8 p-8">
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

        <div className="rounded-lg border border-border bg-card p-4 space-y-3">
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
