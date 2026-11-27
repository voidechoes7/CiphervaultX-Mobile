import * as React from "react";
import {
  ArrowUp,
  Download,
  FileArchive,
  FileText,
  Folder,
  FolderArchive,
  FolderOpen,
  Lock,
  PackageOpen,
  Unlock,
} from "lucide-react";
import {
  backend,
  type CipherSuite,
  type CryptomatorVaultInfo,
  type CustomArgon2Params,
  type KdfProfile,
  type VaultEntry,
} from "@/lib/api";
import { formatBytes, parentPath } from "@/lib/format";
import { MIN_PASSWORD_CHARS } from "@/lib/password";
import { Badge } from "./ui/badge";
import { Button } from "./ui/button";
import { Input } from "./ui/input";
import { Label } from "./ui/label";
import { Select } from "./ui/select";
import { Separator } from "./ui/separator";

type KdfChoice = "mobile" | "desktop" | "high" | "custom";

export const ToolsView: React.FC = () => {
  const initialIsMobile =
    typeof navigator !== "undefined" && /Android|iPhone|iPad|iPod/i.test(navigator.userAgent);

  // Standalone file encryptor (.zip, .7z, etc. -> .cvxenc)
  const [standaloneMode, setStandaloneMode] = React.useState<"encrypt" | "decrypt">("encrypt");
  const [srcFile, setSrcFile] = React.useState("");
  const [dstFile, setDstFile] = React.useState("");
  const [suite, setSuite] = React.useState<CipherSuite>("xchacha20-poly1305");
  const [kdfChoice, setKdfChoice] = React.useState<KdfChoice>(
    initialIsMobile ? "mobile" : "desktop"
  );
  const kdfTouchedRef = React.useRef(false);
  const [memoryMiB, setMemoryMiB] = React.useState(256);
  const [iterations, setIterations] = React.useState(3);
  const [parallelism, setParallelism] = React.useState(1);
  const [filePassword, setFilePassword] = React.useState("");
  const [fileBusy, setFileBusy] = React.useState(false);
  const [fileStatus, setFileStatus] = React.useState<string | null>(null);
  const [fileError, setFileError] = React.useState<string | null>(null);

  // ZIP / 7z archive utilities
  const [archiveBusy, setArchiveBusy] = React.useState(false);
  const [archiveStatus, setArchiveStatus] = React.useState<string | null>(null);
  const [archiveError, setArchiveError] = React.useState<string | null>(null);
  const [lastCompressedZip, setLastCompressedZip] = React.useState<string | null>(null);

  // Cryptomator Format 8 interop reader
  const [cmPath, setCmPath] = React.useState("");
  const [cmPassword, setCmPassword] = React.useState("");
  const [cmInfo, setCmInfo] = React.useState<CryptomatorVaultInfo | null>(null);
  const [cmCwd, setCmCwd] = React.useState("/");
  const [cmEntries, setCmEntries] = React.useState<VaultEntry[]>([]);
  const [cmBusy, setCmBusy] = React.useState(false);
  const [cmError, setCmError] = React.useState<string | null>(null);
  const [cmNotice, setCmNotice] = React.useState<string | null>(null);

  React.useEffect(() => {
    void backend
      .isMobile()
      .then((mobile) => {
        if (mobile && !kdfTouchedRef.current) {
          setKdfChoice("mobile");
        }
      })
      .catch(() => undefined);
  }, []);

  const handlePickSrcFile = async () => {
    setFileError(null);
    const picked = await backend.pickFileToImport();
    if (!picked) return;
    setSrcFile(picked);
    if (standaloneMode === "encrypt") {
      if (!picked.startsWith("content://") && !picked.startsWith("file://")) {
        setDstFile(`${picked}.cvxenc`);
      } else {
        setDstFile("");
      }
    } else if (picked.endsWith(".cvxenc") && !picked.startsWith("content://") && !picked.startsWith("file://")) {
      setDstFile(picked.slice(0, -".cvxenc".length));
    } else {
      setDstFile("");
    }
  };

  const handlePickDstFile = async () => {
    const srcName = srcFile.split(/[\\/]/).pop() || "";
    const defaultName =
      standaloneMode === "encrypt"
        ? srcName
          ? `${srcName}.cvxenc`
          : "archive.zip.cvxenc"
        : srcName.endsWith(".cvxenc")
        ? srcName.slice(0, -".cvxenc".length)
        : "restored_archive.zip";
    const picked = await backend.pickExportDestination(defaultName);
    if (picked) setDstFile(picked);
  };

  const handleRunStandalone = async (e: React.FormEvent) => {
    e.preventDefault();
    setFileError(null);
    setFileStatus(null);
    if (!srcFile.trim()) {
      setFileError("Select a source file first.");
      return;
    }
    if (standaloneMode === "encrypt" && [...filePassword].length < MIN_PASSWORD_CHARS) {
      setFileError(`Password must be at least ${MIN_PASSWORD_CHARS} characters.`);
      return;
    }

    let kdfProfile: KdfProfile = "desktop";
    let customKdf: CustomArgon2Params | null = null;

    if (standaloneMode === "encrypt") {
      if (kdfChoice === "mobile") {
        kdfProfile = "mobile";
      } else if (kdfChoice === "high") {
        kdfProfile = "desktop";
        customKdf = { m_cost: 512 * 1024, t_cost: 4, p_cost: 2 };
      } else if (kdfChoice === "custom") {
        if (memoryMiB < 64 || memoryMiB > 2048) {
          setFileError("Argon2id memory must be between 64 MiB and 2048 MiB.");
          return;
        }
        if (iterations < 2 || iterations > 500) {
          setFileError("Argon2id rounds (t) must be between 2 and 500.");
          return;
        }
        if (parallelism < 1 || parallelism > 16) {
          setFileError("Argon2id parallelism (p) must be between 1 and 16.");
          return;
        }
        customKdf = {
          m_cost: Math.round(memoryMiB) * 1024,
          t_cost: Math.round(iterations),
          p_cost: Math.round(parallelism),
        };
      }
    }

    setFileBusy(true);
    try {
      if (standaloneMode === "encrypt") {
        const res = await backend.encryptStandaloneFile({
          srcPath: srcFile.trim(),
          dstPath: dstFile.trim() || null,
          password: filePassword,
          suite,
          kdfProfile,
          customKdf,
        });
        setDstFile(res.path);
        setFileStatus(`Encrypted ${formatBytes(res.bytes)} successfully to ${res.path}`);
      } else {
        const res = await backend.decryptStandaloneFile({
          srcPath: srcFile.trim(),
          dstPath: dstFile.trim() || null,
          password: filePassword,
        });
        setDstFile(res.path);
        setFileStatus(`Decrypted ${formatBytes(res.bytes)} successfully to ${res.path}`);
      }
      setFilePassword("");
    } catch (err) {
      setFileError(err instanceof Error ? err.message : String(err));
    } finally {
      setFileBusy(false);
    }
  };

  const handleCompressFolder = async () => {
    setArchiveError(null);
    setArchiveStatus(null);
    setLastCompressedZip(null);
    const folder = await backend.pickFolder("Select folder to compress to .zip");
    if (!folder) return;
    const baseName = folder.replace(/[\\/]+$/, "").split(/[\\/]/).pop() || "folder";
    const dstZip = await backend.pickExportDestination(`${baseName}.zip`);
    if (!dstZip) return;

    setArchiveBusy(true);
    try {
      const res = await backend.compressToZip([folder], dstZip);
      setLastCompressedZip(res.path);
      setArchiveStatus(
        `Compressed ${res.entries} entries (${formatBytes(res.bytes)}) to ${res.path}`
      );
    } catch (err) {
      setArchiveError(err instanceof Error ? err.message : String(err));
    } finally {
      setArchiveBusy(false);
    }
  };

  const handleCompressFiles = async () => {
    setArchiveError(null);
    setArchiveStatus(null);
    setLastCompressedZip(null);
    const files = await backend.pickFilesToImport();
    if (files.length === 0) return;
    const dstZip = await backend.pickExportDestination("bundle.zip");
    if (!dstZip) return;

    setArchiveBusy(true);
    try {
      const res = await backend.compressToZip(files, dstZip);
      setLastCompressedZip(res.path);
      setArchiveStatus(
        `Compressed ${res.entries} entries (${formatBytes(res.bytes)}) to ${res.path}`
      );
    } catch (err) {
      setArchiveError(err instanceof Error ? err.message : String(err));
    } finally {
      setArchiveBusy(false);
    }
  };

  const handleExtractArchive = async () => {
    setArchiveError(null);
    setArchiveStatus(null);
    const archivePath = await backend.pickFileToImport();
    if (!archivePath) return;
    const dstDir = await backend.pickFolder("Select destination folder for extracted files");
    if (!dstDir) return;

    setArchiveBusy(true);
    try {
      const res = await backend.extractArchive(archivePath, dstDir);
      setArchiveStatus(
        `Extracted ${res.entries} entries (${formatBytes(res.bytes)}) into ${res.path}`
      );
    } catch (err) {
      setArchiveError(err instanceof Error ? err.message : String(err));
    } finally {
      setArchiveBusy(false);
    }
  };

  const loadCmDir = React.useCallback(async (dir: string) => {
    setCmError(null);
    try {
      const list = await backend.listCryptomatorDir(dir);
      setCmEntries(list);
      setCmCwd(dir);
    } catch (err) {
      setCmError(err instanceof Error ? err.message : String(err));
    }
  }, []);

  const handleOpenCryptomator = async (e: React.FormEvent) => {
    e.preventDefault();
    setCmError(null);
    setCmNotice(null);
    if (!cmPath.trim()) {
      setCmError("Select a Cryptomator vault folder (containing vault.cryptomator).");
      return;
    }
    setCmBusy(true);
    try {
      const info = await backend.openCryptomatorVault(cmPath.trim(), cmPassword);
      setCmPassword("");
      setCmInfo(info);
      await loadCmDir("/");
    } catch (err) {
      setCmError(err instanceof Error ? err.message : String(err));
    } finally {
      setCmBusy(false);
    }
  };

  const handleCloseCryptomator = async () => {
    await backend.closeCryptomatorVault();
    setCmInfo(null);
    setCmEntries([]);
    setCmCwd("/");
  };

  const handleExportCmFile = async (entry: VaultEntry) => {
    setCmError(null);
    setCmNotice(null);
    const dst = await backend.pickExportDestination(entry.name);
    if (!dst) return;
    try {
      const bytes = await backend.exportCryptomatorFile(entry.path, dst);
      setCmNotice(`Exported "${entry.name}" (${formatBytes(bytes)}) to ${dst}`);
    } catch (err) {
      setCmError(err instanceof Error ? err.message : String(err));
    }
  };

  return (
    <div className="mx-auto max-w-4xl space-y-6 p-4 md:space-y-8 md:p-8">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">
          File Locker, ZIP/7z &amp; Cryptomator
        </h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Compress folders to <code>.zip</code>, extract <code>.zip</code>/<code>.7z</code>,
          encrypt standalone files (<code>.cvxenc</code>) with custom Argon2id, or open Cryptomator
          Format 8 vaults.
        </p>
      </div>

      {/* Standalone File Encryptor */}
      <section className="space-y-4 rounded-xl border border-border bg-card p-4 shadow-sm md:p-6">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <FileArchive className="h-5 w-5 text-primary" />
            <h2 className="text-base font-medium">
              Standalone File Encryptor (.zip, .7z, any file)
            </h2>
          </div>
          <div className="flex gap-1.5">
            <Button
              size="sm"
              variant={standaloneMode === "encrypt" ? "secondary" : "ghost"}
              onClick={() => {
                setStandaloneMode("encrypt");
                setFileError(null);
                setFileStatus(null);
              }}
            >
              <Lock className="h-3.5 w-3.5" />
              Encrypt
            </Button>
            <Button
              size="sm"
              variant={standaloneMode === "decrypt" ? "secondary" : "ghost"}
              onClick={() => {
                setStandaloneMode("decrypt");
                setFileError(null);
                setFileStatus(null);
              }}
            >
              <Unlock className="h-3.5 w-3.5" />
              Decrypt (.cvxenc)
            </Button>
          </div>
        </div>

        <form onSubmit={(e) => void handleRunStandalone(e)} className="space-y-4" noValidate>
          <div className="space-y-1.5">
            <Label htmlFor="st-src">
              {standaloneMode === "encrypt"
                ? "Source File (.zip, .7z, etc.)"
                : "Encrypted File (.cvxenc)"}
            </Label>
            <div className="flex gap-2">
              <Input
                id="st-src"
                value={srcFile}
                onChange={(e) => setSrcFile(e.target.value)}
                placeholder="/path/to/archive.zip"
                className="min-w-0 flex-1 font-mono text-xs"
              />
              <Button type="button" variant="outline" onClick={() => void handlePickSrcFile()}>
                <FolderOpen className="h-4 w-4" />
                Browse
              </Button>
            </div>
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="st-dst">Output File (optional on mobile — defaults to App Exports)</Label>
            <div className="flex gap-2">
              <Input
                id="st-dst"
                value={dstFile}
                onChange={(e) => setDstFile(e.target.value)}
                placeholder="Auto-saved in App Exports or tap Save As"
                className="min-w-0 flex-1 font-mono text-xs"
              />
              <Button type="button" variant="outline" onClick={() => void handlePickDstFile()}>
                Save As
              </Button>
            </div>
          </div>

          {standaloneMode === "encrypt" && (
            <>
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                <div className="space-y-1.5">
                  <Label htmlFor="st-suite">Cipher Suite</Label>
                  <Select
                    id="st-suite"
                    value={suite}
                    onChange={(e) => setSuite(e.target.value as CipherSuite)}
                  >
                    <option value="xchacha20-poly1305">XChaCha20-Poly1305 (256-bit)</option>
                    <option value="aes256-gcm">AES-256-GCM (256-bit)</option>
                  </Select>
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor="st-kdf">Argon2id Profile</Label>
                  <Select
                    id="st-kdf"
                    value={kdfChoice}
                    onChange={(e) => {
                      kdfTouchedRef.current = true;
                      setKdfChoice(e.target.value as KdfChoice);
                    }}
                  >
                    <option value="mobile">Mobile (64 MiB, t=3, p=1)</option>
                    <option value="desktop">Desktop (256 MiB, t=3, p=1)</option>
                    <option value="high">High Desktop (512 MiB, t=4, p=2)</option>
                    <option value="custom">Custom Argon2id (Advanced)</option>
                  </Select>
                </div>
              </div>

              {kdfChoice === "custom" && (
                <div className="grid grid-cols-1 gap-3 rounded-lg border border-border bg-muted/30 p-3 sm:grid-cols-3">
                  <div className="space-y-1">
                    <Label htmlFor="st-argon-mem">Memory (MiB, ≥ 64)</Label>
                    <Input
                      id="st-argon-mem"
                      type="number"
                      min={64}
                      max={2048}
                      step={64}
                      value={memoryMiB}
                      onChange={(e) => setMemoryMiB(Number(e.target.value))}
                    />
                  </div>
                  <div className="space-y-1">
                    <Label htmlFor="st-argon-iter">Rounds (t ≥ 2)</Label>
                    <Input
                      id="st-argon-iter"
                      type="number"
                      min={2}
                      max={500}
                      value={iterations}
                      onChange={(e) => setIterations(Number(e.target.value))}
                    />
                  </div>
                  <div className="space-y-1">
                    <Label htmlFor="st-argon-par">Parallelism (p 1–16)</Label>
                    <Input
                      id="st-argon-par"
                      type="number"
                      min={1}
                      max={16}
                      value={parallelism}
                      onChange={(e) => setParallelism(Number(e.target.value))}
                    />
                  </div>
                </div>
              )}
            </>
          )}

          <div className="space-y-1.5">
            <Label htmlFor="st-pw">
              Password {standaloneMode === "encrypt" ? `(min ${MIN_PASSWORD_CHARS} chars)` : ""}
            </Label>
            <Input
              id="st-pw"
              type="password"
              value={filePassword}
              onChange={(e) => setFilePassword(e.target.value)}
            />
          </div>

          {fileError && (
            <div className="rounded-lg border border-destructive/40 bg-destructive/10 px-3 py-2 text-xs text-destructive">
              {fileError}
            </div>
          )}
          {fileStatus && (
            <div className="break-all rounded-lg border border-primary/30 bg-primary/10 px-3 py-2 text-xs text-primary">
              {fileStatus}
            </div>
          )}

          <Button type="submit" disabled={fileBusy}>
            {fileBusy
              ? "Processing…"
              : standaloneMode === "encrypt"
              ? "Encrypt File"
              : "Decrypt File"}
          </Button>
        </form>
      </section>

      <Separator />

      {/* Archive Utilities (.zip / .7z) */}
      <section className="space-y-4 rounded-xl border border-border bg-card p-4 shadow-sm md:p-6">
        <div className="flex items-center gap-2">
          <FolderArchive className="h-5 w-5 text-primary" />
          <div>
            <h2 className="text-base font-medium">Archive Utilities (ZIP &amp; 7z)</h2>
            <p className="text-xs text-muted-foreground">
              Atomic compression and Zip-Slip-hardened extraction for local folders and archives.
            </p>
          </div>
        </div>

        <div className="flex flex-wrap gap-2">
          <Button
            type="button"
            variant="outline"
            disabled={archiveBusy}
            onClick={() => void handleCompressFolder()}
          >
            <FolderArchive className="h-4 w-4" />
            Compress Folder → .zip
          </Button>
          <Button
            type="button"
            variant="outline"
            disabled={archiveBusy}
            onClick={() => void handleCompressFiles()}
          >
            <FileArchive className="h-4 w-4" />
            Compress Files → .zip
          </Button>
          <Button
            type="button"
            variant="outline"
            disabled={archiveBusy}
            onClick={() => void handleExtractArchive()}
          >
            <PackageOpen className="h-4 w-4" />
            Extract .zip / .7z
          </Button>
        </div>

        {archiveError && (
          <div className="rounded-lg border border-destructive/40 bg-destructive/10 px-3 py-2 text-xs text-destructive">
            {archiveError}
          </div>
        )}
        {archiveStatus && (
          <div className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-primary/30 bg-primary/10 px-3 py-2 text-xs text-primary">
            <span className="break-all">{archiveStatus}</span>
            {lastCompressedZip && (
              <Button
                type="button"
                size="sm"
                variant="outline"
                className="h-7 shrink-0 text-xs"
                onClick={() => {
                  setStandaloneMode("encrypt");
                  setSrcFile(lastCompressedZip);
                  setDstFile(`${lastCompressedZip}.cvxenc`);
                }}
              >
                <Lock className="h-3.5 w-3.5" />
                Load into Encryptor
              </Button>
            )}
          </div>
        )}
      </section>

      <Separator />

      {/* Cryptomator Vault Format 8 Reader */}
      <section className="space-y-4 rounded-xl border border-border bg-card p-4 shadow-sm md:p-6">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="text-base font-medium">
              Cryptomator Vault Reader (Format 8 · SIV_GCM)
            </h2>
            <p className="text-xs text-muted-foreground">
              Open existing Cryptomator vaults in read/export mode to inspect or migrate files.
            </p>
          </div>
          {cmInfo && (
            <div className="flex items-center gap-2">
              <Badge variant="outline">
                Format {cmInfo.format} · {cmInfo.cipher_combo}
              </Badge>
              <Button variant="secondary" size="sm" onClick={() => void handleCloseCryptomator()}>
                <Lock className="h-3.5 w-3.5" />
                Close Vault
              </Button>
            </div>
          )}
        </div>

        {!cmInfo ? (
          <form onSubmit={(e) => void handleOpenCryptomator(e)} className="space-y-4" noValidate>
            <div className="space-y-1.5">
              <Label htmlFor="cm-folder">Cryptomator Vault Folder</Label>
              <div className="flex gap-2">
                <Input
                  id="cm-folder"
                  value={cmPath}
                  onChange={(e) => setCmPath(e.target.value)}
                  placeholder="/path/to/cryptomator-vault"
                  className="min-w-0 flex-1 font-mono text-xs"
                />
                <Button
                  type="button"
                  variant="outline"
                  onClick={async () => {
                    const p = await backend.pickFolder("Select Cryptomator vault folder", {
                      highlightVaults: "cryptomator",
                    });
                    if (p) setCmPath(p);
                  }}
                >
                  <FolderOpen className="h-4 w-4" />
                  Browse
                </Button>
              </div>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="cm-pw">Cryptomator Password</Label>
              <Input
                id="cm-pw"
                type="password"
                value={cmPassword}
                onChange={(e) => setCmPassword(e.target.value)}
              />
            </div>
            {cmError && <p className="text-sm text-destructive">{cmError}</p>}
            <Button type="submit" disabled={cmBusy}>
              <Unlock className="h-4 w-4" />
              {cmBusy ? "Unlocking Cryptomator…" : "Open Cryptomator Vault"}
            </Button>
          </form>
        ) : (
          <div className="space-y-3">
            <div className="flex items-center justify-between text-xs text-muted-foreground">
              <span className="truncate font-mono">{cmCwd}</span>
              {cmCwd !== "/" && (
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => void loadCmDir(parentPath(cmCwd))}
                >
                  <ArrowUp className="h-3.5 w-3.5" />
                  Up
                </Button>
              )}
            </div>
            {cmError && <p className="text-sm text-destructive">{cmError}</p>}
            {cmNotice && <p className="break-all text-sm text-primary">{cmNotice}</p>}
            {cmEntries.length === 0 ? (
              <p className="py-6 text-center text-sm text-muted-foreground">
                This Cryptomator folder is empty.
              </p>
            ) : (
              <div className="divide-y divide-border rounded-md border border-border">
                {cmEntries.map((entry) => (
                  <div
                    key={entry.path}
                    className="flex flex-wrap items-center justify-between gap-2 px-3 py-2 text-sm"
                  >
                    {entry.kind === "directory" ? (
                      <button
                        type="button"
                        className="flex min-w-0 flex-1 items-center gap-2 font-medium hover:underline"
                        onClick={() => void loadCmDir(entry.path)}
                      >
                        <Folder className="h-4 w-4 shrink-0 text-primary" />
                        <span className="truncate">{entry.name}</span>
                      </button>
                    ) : (
                      <div className="flex min-w-0 flex-1 items-center gap-2">
                        <FileText className="h-4 w-4 shrink-0 text-muted-foreground" />
                        <span className="truncate">{entry.name}</span>
                        <span className="shrink-0 text-xs text-muted-foreground">
                          ({formatBytes(entry.size)})
                        </span>
                      </div>
                    )}
                    {entry.kind === "file" && (
                      <Button
                        variant="outline"
                        size="sm"
                        className="shrink-0"
                        onClick={() => void handleExportCmFile(entry)}
                      >
                        <Download className="h-3.5 w-3.5" />
                        Export
                      </Button>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </section>
    </div>
  );
};
