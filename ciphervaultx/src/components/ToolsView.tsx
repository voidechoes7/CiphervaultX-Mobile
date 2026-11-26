import * as React from "react";
import {
  ArrowUp,
  Download,
  FileArchive,
  FileText,
  Folder,
  FolderOpen,
  Lock,
  Unlock,
} from "lucide-react";
import {
  backend,
  type CipherSuite,
  type CryptomatorVaultInfo,
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

export const ToolsView: React.FC = () => {
  // Standalone file encryptor (.zip, .7z, etc. -> .cvxenc)
  const [standaloneMode, setStandaloneMode] = React.useState<"encrypt" | "decrypt">("encrypt");
  const [srcFile, setSrcFile] = React.useState("");
  const [dstFile, setDstFile] = React.useState("");
  const [suite, setSuite] = React.useState<CipherSuite>("xchacha20-poly1305");
  const [kdfProfile, setKdfProfile] = React.useState<KdfProfile>("desktop");
  const [filePassword, setFilePassword] = React.useState("");
  const [fileBusy, setFileBusy] = React.useState(false);
  const [fileStatus, setFileStatus] = React.useState<string | null>(null);
  const [fileError, setFileError] = React.useState<string | null>(null);

  // Cryptomator Format 8 interop reader
  const [cmPath, setCmPath] = React.useState("");
  const [cmPassword, setCmPassword] = React.useState("");
  const [cmInfo, setCmInfo] = React.useState<CryptomatorVaultInfo | null>(null);
  const [cmCwd, setCmCwd] = React.useState("/");
  const [cmEntries, setCmEntries] = React.useState<VaultEntry[]>([]);
  const [cmBusy, setCmBusy] = React.useState(false);
  const [cmError, setCmError] = React.useState<string | null>(null);
  const [cmNotice, setCmNotice] = React.useState<string | null>(null);

  const handlePickSrcFile = async () => {
    const picked = await backend.pickFileToImport();
    if (!picked) return;
    setSrcFile(picked);
    if (standaloneMode === "encrypt") {
      setDstFile(`${picked}.cvxenc`);
    } else if (picked.endsWith(".cvxenc")) {
      setDstFile(picked.slice(0, -".cvxenc".length));
    }
  };

  const handlePickDstFile = async () => {
    const defaultName =
      standaloneMode === "encrypt" ? "archive.zip.cvxenc" : "restored_archive.zip";
    const picked = await backend.pickExportDestination(defaultName);
    if (picked) setDstFile(picked);
  };

  const handleRunStandalone = async (e: React.FormEvent) => {
    e.preventDefault();
    setFileError(null);
    setFileStatus(null);
    if (!srcFile.trim() || !dstFile.trim()) {
      setFileError("Select both source and destination file paths.");
      return;
    }
    if (standaloneMode === "encrypt" && [...filePassword].length < MIN_PASSWORD_CHARS) {
      setFileError(`Password must be at least ${MIN_PASSWORD_CHARS} characters.`);
      return;
    }
    setFileBusy(true);
    try {
      if (standaloneMode === "encrypt") {
        const bytes = await backend.encryptStandaloneFile({
          srcPath: srcFile.trim(),
          dstPath: dstFile.trim(),
          password: filePassword,
          suite,
          kdfProfile,
        });
        setFileStatus(`Encrypted ${formatBytes(bytes)} successfully to ${dstFile.trim()}`);
      } else {
        const bytes = await backend.decryptStandaloneFile({
          srcPath: srcFile.trim(),
          dstPath: dstFile.trim(),
          password: filePassword,
        });
        setFileStatus(`Decrypted ${formatBytes(bytes)} successfully to ${dstFile.trim()}`);
      }
      setFilePassword("");
    } catch (err) {
      setFileError(err instanceof Error ? err.message : String(err));
    } finally {
      setFileBusy(false);
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
    <div className="mx-auto max-w-4xl space-y-8 p-8">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">
          File Locker &amp; Cryptomator Interop
        </h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Encrypt/decrypt standalone archives (<code>.zip</code>, <code>.7z</code>, etc.) or open
          existing Cryptomator Format 8 vaults.
        </p>
      </div>

      {/* Standalone File Encryptor */}
      <section className="space-y-4 rounded-lg border border-border bg-card p-6">
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

        <form onSubmit={handleRunStandalone} className="space-y-4">
          <div className="space-y-1.5">
            <Label htmlFor="st-src">
              {standaloneMode === "encrypt" ? "Source File (.zip, .7z, etc.)" : "Encrypted File (.cvxenc)"}
            </Label>
            <div className="flex gap-2">
              <Input
                id="st-src"
                value={srcFile}
                onChange={(e) => setSrcFile(e.target.value)}
                placeholder="/path/to/archive.zip"
              />
              <Button type="button" variant="outline" onClick={handlePickSrcFile}>
                <FolderOpen className="h-4 w-4" />
                Browse
              </Button>
            </div>
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="st-dst">Output File</Label>
            <div className="flex gap-2">
              <Input
                id="st-dst"
                value={dstFile}
                onChange={(e) => setDstFile(e.target.value)}
                placeholder="/path/to/archive.zip.cvxenc"
              />
              <Button type="button" variant="outline" onClick={handlePickDstFile}>
                Save As
              </Button>
            </div>
          </div>

          {standaloneMode === "encrypt" && (
            <div className="grid grid-cols-2 gap-3">
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
                  value={kdfProfile}
                  onChange={(e) => setKdfProfile(e.target.value as KdfProfile)}
                >
                  <option value="desktop">Desktop (256 MiB, t=3)</option>
                  <option value="mobile">Mobile (64 MiB, t=3)</option>
                </Select>
              </div>
            </div>
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

          {fileError && <p className="text-sm text-destructive">{fileError}</p>}
          {fileStatus && <p className="text-sm text-primary">{fileStatus}</p>}

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

      {/* Cryptomator Vault Format 8 Reader */}
      <section className="space-y-4 rounded-lg border border-border bg-card p-6">
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
              <Button variant="secondary" size="sm" onClick={handleCloseCryptomator}>
                <Lock className="h-3.5 w-3.5" />
                Close Vault
              </Button>
            </div>
          )}
        </div>

        {!cmInfo ? (
          <form onSubmit={handleOpenCryptomator} className="space-y-4">
            <div className="space-y-1.5">
              <Label htmlFor="cm-folder">Cryptomator Vault Folder</Label>
              <div className="flex gap-2">
                <Input
                  id="cm-folder"
                  value={cmPath}
                  onChange={(e) => setCmPath(e.target.value)}
                  placeholder="/path/to/cryptomator-vault"
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
              <span className="font-mono">{cmCwd}</span>
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
            {cmNotice && <p className="text-sm text-primary">{cmNotice}</p>}
            {cmEntries.length === 0 ? (
              <p className="py-6 text-center text-sm text-muted-foreground">
                Empty directory.
              </p>
            ) : (
              <table className="w-full text-left text-sm">
                <thead>
                  <tr className="border-b border-border text-xs uppercase tracking-wider text-muted-foreground">
                    <th className="py-2 font-medium">Name</th>
                    <th className="py-2 font-medium">Size</th>
                    <th className="py-2 text-right font-medium">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {cmEntries.map((entry) => (
                    <tr key={entry.path}>
                      <td className="py-2">
                        {entry.kind === "directory" ? (
                          <button
                            type="button"
                            className="flex items-center gap-2 font-medium hover:underline"
                            onClick={() => void loadCmDir(entry.path)}
                          >
                            <Folder className="h-4 w-4 text-primary" />
                            <span>{entry.name}</span>
                          </button>
                        ) : (
                          <div className="flex items-center gap-2">
                            <FileText className="h-4 w-4 text-muted-foreground" />
                            <span>{entry.name}</span>
                          </div>
                        )}
                      </td>
                      <td className="py-2 text-xs text-muted-foreground">
                        {entry.kind === "file" ? formatBytes(entry.size) : "—"}
                      </td>
                      <td className="py-2 text-right">
                        {entry.kind === "file" && (
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => handleExportCmFile(entry)}
                          >
                            <Download className="h-3.5 w-3.5" />
                            Export
                          </Button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        )}
      </section>
    </div>
  );
};
