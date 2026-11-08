/**
 * CipherVault-X Main Application Component (React + TypeScript).
 *
 * Implements:
 * - Multi-vault dashboard & sidebar switcher
 * - Vault creation wizard (with password entropy indicator & Cryptomator Format 8 settings)
 * - Unlock screen with zero-knowledge KDF feedback
 * - Encrypted file explorer with breadcrumb navigation, search, file type filters,
 *   safe in-memory decrypted preview, and explicit decrypted file export
 * - Integrity verification scanner (AEAD GCM tag + SIV filename verification across all chunks)
 * - Cloud synchronization panel (zero-knowledge ciphertext mirror & raw ciphertext inspector)
 * - Security & Theme settings (6 themes + inactivity auto-lock timer)
 */

import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { VaultApi } from "./lib/ipc";
import {
  THEMES,
  type CiphertextObject,
  type IntegrityReport,
  type SyncSummary,
  type ThemeId,
  type VaultEntry,
  type VaultMeta,
} from "./lib/types";

type ActiveTab = "explorer" | "integrity" | "cloud" | "settings";
type FileFilter = "all" | "directory" | "documents" | "data";

function formatBytes(bytes: number | null): string {
  if (bytes === null || bytes === undefined) return "—";
  if (bytes === 0) return "0 B";
  const units = ["B", "KiB", "MiB", "GiB"];
  const idx = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  const val = bytes / Math.pow(1024, idx);
  return `${val.toFixed(idx === 0 ? 0 : 1)} ${units[idx]}`;
}

export default function App() {
  const [theme, setTheme] = useState<ThemeId>("obsidian-dark");
  const [vaults, setVaults] = useState<VaultMeta[]>([]);
  const [activeVaultId, setActiveVaultId] = useState<string>("");
  const [currentPath, setCurrentPath] = useState<string>("/");
  const [entries, setEntries] = useState<VaultEntry[]>([]);
  const [activeTab, setActiveTab] = useState<ActiveTab>("explorer");
  const [searchQuery, setSearchQuery] = useState<string>("");
  const [fileFilter, setFileFilter] = useState<FileFilter>("all");
  const [statusBanner, setStatusBanner] = useState<{ kind: "ok" | "err"; text: string } | null>(null);

  // Unlock modal state
  const [unlockPassword, setUnlockPassword] = useState<string>("");

  // Create vault wizard state
  const [showCreateWizard, setShowCreateWizard] = useState<boolean>(false);
  const [newVaultName, setNewVaultName] = useState<string>("");
  const [newVaultPath, setNewVaultPath] = useState<string>("");
  const [newVaultPassword, setNewVaultPassword] = useState<string>("");

  // File preview / creation modal state
  const [previewEntry, setPreviewEntry] = useState<{ entry: VaultEntry; text: string } | null>(null);
  const [newFolderName, setNewFolderName] = useState<string>("");
  const [newFileName, setNewFileName] = useState<string>("");
  const [newFileContent, setNewFileContent] = useState<string>("");

  // Integrity & Cloud sync state
  const [integrityReport, setIntegrityReport] = useState<IntegrityReport | null>(null);
  const [syncSummary, setSyncSummary] = useState<SyncSummary | null>(null);
  const [ciphertextObjects, setCiphertextObjects] = useState<CiphertextObject[]>([]);
  const [autoLockMinutes, setAutoLockMinutes] = useState<number>(5);
  const idleTimerRef = useRef<number | null>(null);

  const activeVault = useMemo(
    () => vaults.find((v) => v.id === activeVaultId) ?? null,
    [vaults, activeVaultId]
  );

  // Apply theme attribute
  useEffect(() => {
    const resolved =
      theme === "system-adaptive"
        ? window.matchMedia("(prefers-color-scheme: light)").matches
          ? "arctic-light"
          : "obsidian-dark"
        : theme;
    document.documentElement.setAttribute("data-theme", resolved);
  }, [theme]);

  const refreshVaults = useCallback(async () => {
    try {
      const list = await VaultApi.listVaults();
      setVaults(list);
      if (!activeVaultId && list.length > 0) {
        setActiveVaultId(list[0].id);
      }
    } catch (e) {
      setStatusBanner({ kind: "err", text: String(e) });
    }
  }, [activeVaultId]);

  const refreshEntries = useCallback(async () => {
    if (!activeVault || !activeVault.unlocked) {
      setEntries([]);
      return;
    }
    try {
      const list = searchQuery.trim()
        ? await VaultApi.searchVault(activeVault.id, searchQuery.trim(), currentPath)
        : await VaultApi.listEntries(activeVault.id, currentPath);
      setEntries(list);
    } catch (e) {
      setStatusBanner({ kind: "err", text: String(e) });
    }
  }, [activeVault, currentPath, searchQuery]);

  useEffect(() => {
    void refreshVaults();
  }, [refreshVaults]);

  useEffect(() => {
    void refreshEntries();
  }, [refreshEntries]);

  // Auto-lock inactivity timer
  useEffect(() => {
    const resetTimer = () => {
      if (idleTimerRef.current) window.clearTimeout(idleTimerRef.current);
      if (autoLockMinutes > 0) {
        idleTimerRef.current = window.setTimeout(() => {
          void VaultApi.lockAllVaults().then(() => refreshVaults());
        }, autoLockMinutes * 60 * 1000);
      }
    };
    window.addEventListener("mousemove", resetTimer);
    window.addEventListener("keydown", resetTimer);
    resetTimer();
    return () => {
      window.removeEventListener("mousemove", resetTimer);
      window.removeEventListener("keydown", resetTimer);
    };
  }, [autoLockMinutes, refreshVaults]);

  const filteredEntries = useMemo(() => {
    return entries.filter((e) => {
      if (fileFilter === "directory") return e.kind === "directory";
      if (fileFilter === "documents")
        return e.kind === "file" && /\.(md|txt|pdf|doc|docx)$/i.test(e.name);
      if (fileFilter === "data")
        return e.kind === "file" && /\.(csv|json|xlsx|bin|dat)$/i.test(e.name);
      return true;
    });
  }, [entries, fileFilter]);

  const handleUnlock = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!activeVault) return;
    try {
      await VaultApi.unlockVault(activeVault.id, unlockPassword);
      setUnlockPassword("");
      setStatusBanner({ kind: "ok", text: `Unlocked "${activeVault.name}" (keys loaded into protected memory)` });
      await refreshVaults();
      await refreshEntries();
    } catch (err) {
      setStatusBanner({ kind: "err", text: String(err) });
    }
  };

  const handleLock = async () => {
    if (!activeVault) return;
    await VaultApi.lockVault(activeVault.id);
    setPreviewEntry(null);
    setStatusBanner({ kind: "ok", text: `Locked "${activeVault.name}" (masterkeys scrubbed via OPENSSL_cleanse)` });
    await refreshVaults();
  };

  const handleCreateVault = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const created = await VaultApi.createVault(newVaultName, newVaultPath, newVaultPassword);
      setNewVaultName("");
      setNewVaultPath("");
      setNewVaultPassword("");
      setShowCreateWizard(false);
      setActiveVaultId(created.id);
      setCurrentPath("/");
      setStatusBanner({ kind: "ok", text: `Created Format 8 vault "${created.name}"` });
      await refreshVaults();
    } catch (err) {
      setStatusBanner({ kind: "err", text: String(err) });
    }
  };

  const handleCreateFolder = async () => {
    if (!activeVault || !newFolderName.trim()) return;
    const target = currentPath === "/" ? `/${newFolderName.trim()}` : `${currentPath}/${newFolderName.trim()}`;
    try {
      await VaultApi.createFolder(activeVault.id, target);
      setNewFolderName("");
      await refreshEntries();
    } catch (err) {
      setStatusBanner({ kind: "err", text: String(err) });
    }
  };

  const handleCreateNoteFile = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!activeVault || !newFileName.trim()) return;
    const target = currentPath === "/" ? `/${newFileName.trim()}` : `${currentPath}/${newFileName.trim()}`;
    try {
      const b64 = btoa(unescape(encodeURIComponent(newFileContent)));
      await VaultApi.writeFileBase64(activeVault.id, target, b64);
      setNewFileName("");
      setNewFileContent("");
      setStatusBanner({ kind: "ok", text: `Encrypted and wrote ${target}` });
      await refreshEntries();
    } catch (err) {
      setStatusBanner({ kind: "err", text: String(err) });
    }
  };

  const handlePreview = async (entry: VaultEntry) => {
    if (!activeVault) return;
    try {
      const b64 = await VaultApi.readPreviewBase64(activeVault.id, entry.path);
      const text = decodeURIComponent(escape(atob(b64)));
      setPreviewEntry({ entry, text });
    } catch (err) {
      setStatusBanner({ kind: "err", text: String(err) });
    }
  };

  const handleRunIntegrity = async () => {
    if (!activeVault) return;
    try {
      const rep = await VaultApi.checkVaultIntegrity(activeVault.id);
      setIntegrityReport(rep);
      setStatusBanner({
        kind: rep.problems.length === 0 ? "ok" : "err",
        text:
          rep.problems.length === 0
            ? `Verified ${rep.files} files (${formatBytes(rep.bytesVerified)}) and ${rep.directories} directories — 0 integrity errors`
            : `Detected ${rep.problems.length} integrity problem(s)!`,
      });
    } catch (err) {
      setStatusBanner({ kind: "err", text: String(err) });
    }
  };

  const handleRunSync = async () => {
    if (!activeVault) return;
    try {
      const summary = await VaultApi.syncVaultMirror(activeVault.id);
      const tree = await VaultApi.inspectCiphertextTree(activeVault.id);
      setSyncSummary(summary);
      setCiphertextObjects(tree);
      setStatusBanner({
        kind: "ok",
        text: `Synced ${summary.uploaded} uploaded / ${summary.unchanged} unchanged ciphertext objects to ${summary.provider}`,
      });
    } catch (err) {
      setStatusBanner({ kind: "err", text: String(err) });
    }
  };

  return (
    <div className="min-h-screen bg-bg text-fg flex">
      {/* Sidebar */}
      <aside className="w-72 bg-surface border-r border-border flex flex-col justify-between p-4">
        <div>
          <div className="flex items-center justify-between mb-6">
            <div>
              <h1 className="text-lg font-bold tracking-tight">CipherVault-X</h1>
              <p className="text-xs text-muted">Cryptomator Format 8 · SIV_GCM</p>
            </div>
            <button
              onClick={() => setShowCreateWizard(true)}
              className="px-2.5 py-1 text-xs font-medium rounded bg-accent text-accentFg"
            >
              + Vault
            </button>
          </div>

          <div className="space-y-1 mb-6">
            <p className="text-xs uppercase tracking-wider text-muted px-2 mb-1">Vaults</p>
            {vaults.map((v) => (
              <button
                key={v.id}
                onClick={() => {
                  setActiveVaultId(v.id);
                  setCurrentPath("/");
                  setPreviewEntry(null);
                }}
                className={`w-full text-left px-3 py-2 rounded text-sm flex items-center justify-between ${
                  v.id === activeVaultId ? "bg-surface2 font-semibold" : "hover:bg-surface2/60"
                }`}
              >
                <span className="truncate">{v.name}</span>
                <span
                  className={`text-[10px] px-1.5 py-0.5 rounded ${
                    v.unlocked ? "bg-success/20 text-success" : "bg-border text-muted"
                  }`}
                >
                  {v.unlocked ? "UNLOCKED" : "LOCKED"}
                </span>
              </button>
            ))}
          </div>

          <nav className="space-y-1">
            <p className="text-xs uppercase tracking-wider text-muted px-2 mb-1">Workspace</p>
            {(["explorer", "integrity", "cloud", "settings"] as const).map((tab) => (
              <button
                key={tab}
                onClick={() => setActiveTab(tab)}
                className={`w-full text-left px-3 py-2 rounded text-sm capitalize ${
                  activeTab === tab ? "bg-accent text-accentFg font-medium" : "hover:bg-surface2"
                }`}
              >
                {tab === "explorer"
                  ? "Encrypted File Explorer"
                  : tab === "integrity"
                  ? "AEAD Integrity Scanner"
                  : tab === "cloud"
                  ? "Zero-Knowledge Cloud Sync"
                  : "Security & 6 Themes"}
              </button>
            ))}
          </nav>
        </div>

        <div className="pt-4 border-t border-border text-xs text-muted space-y-2">
          <div className="flex items-center justify-between">
            <span>Theme</span>
            <select
              value={theme}
              onChange={(e) => setTheme(e.target.value as ThemeId)}
              className="bg-surface2 border border-border rounded px-2 py-1 text-fg"
            >
              {THEMES.map((t) => (
                <option key={t.id} value={t.id}>
                  {t.label}
                </option>
              ))}
            </select>
          </div>
          {activeVault?.unlocked && (
            <button
              onClick={handleLock}
              className="w-full py-1.5 rounded border border-danger text-danger hover:bg-danger/10 font-medium"
            >
              Lock Vault Now
            </button>
          )}
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex-1 p-6 overflow-y-auto space-y-4">
        {statusBanner && (
          <div
            className={`px-4 py-2.5 rounded border text-sm flex items-center justify-between ${
              statusBanner.kind === "ok"
                ? "border-success/40 bg-success/10 text-fg"
                : "border-danger/40 bg-danger/10 text-fg"
            }`}
          >
            <span>{statusBanner.text}</span>
            <button onClick={() => setStatusBanner(null)} className="text-xs underline">
              Dismiss
            </button>
          </div>
        )}

        {!activeVault ? (
          <div className="p-12 text-center text-muted">Select or create a vault to begin.</div>
        ) : !activeVault.unlocked && activeTab !== "settings" && activeTab !== "cloud" ? (
          <form onSubmit={handleUnlock} className="max-w-md mx-auto mt-16 p-6 bg-surface border border-border rounded-lg space-y-4">
            <h2 className="text-lg font-semibold">Unlock {activeVault.name}</h2>
            <p className="text-xs text-muted break-all">Path: {activeVault.path}</p>
            <input
              type="password"
              value={unlockPassword}
              onChange={(e) => setUnlockPassword(e.target.value)}
              placeholder="Enter vault passphrase..."
              className="w-full px-3 py-2 rounded bg-surface2 border border-border text-sm"
            />
            <button type="submit" className="w-full py-2 rounded bg-accent text-accentFg font-medium text-sm">
              Derive KEK (scrypt) &amp; Unwrap Masterkey
            </button>
          </form>
        ) : activeTab === "explorer" ? (
          <div className="space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-2 text-sm">
                <button
                  onClick={() => setCurrentPath("/")}
                  className="px-2 py-1 rounded bg-surface2 hover:bg-border"
                >
                  Root (/)
                </button>
                <span className="text-muted font-mono">{currentPath}</span>
              </div>
              <div className="flex items-center gap-2">
                <input
                  type="search"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder="Search decrypted names..."
                  className="px-3 py-1.5 rounded bg-surface border border-border text-sm"
                />
                <select
                  value={fileFilter}
                  onChange={(e) => setFileFilter(e.target.value as FileFilter)}
                  className="px-2 py-1.5 rounded bg-surface border border-border text-sm"
                >
                  <option value="all">All items</option>
                  <option value="directory">Folders only</option>
                  <option value="documents">Documents</option>
                  <option value="data">Data / Archives</option>
                </select>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div className="flex gap-2">
                <input
                  value={newFolderName}
                  onChange={(e) => setNewFolderName(e.target.value)}
                  placeholder="New encrypted folder name..."
                  className="flex-1 px-3 py-1.5 rounded bg-surface border border-border text-sm"
                />
                <button
                  onClick={handleCreateFolder}
                  className="px-3 py-1.5 rounded bg-surface2 border border-border text-sm"
                >
                  + Folder
                </button>
              </div>
              <form onSubmit={handleCreateNoteFile} className="flex gap-2">
                <input
                  value={newFileName}
                  onChange={(e) => setNewFileName(e.target.value)}
                  placeholder="File name (e.g. note.md)"
                  className="w-40 px-2 py-1.5 rounded bg-surface border border-border text-sm"
                />
                <input
                  value={newFileContent}
                  onChange={(e) => setNewFileContent(e.target.value)}
                  placeholder="Synthetic content to encrypt..."
                  className="flex-1 px-2 py-1.5 rounded bg-surface border border-border text-sm"
                />
                <button type="submit" className="px-3 py-1.5 rounded bg-accent text-accentFg text-sm">
                  Encrypt &amp; Save
                </button>
              </form>
            </div>

            <div className="border border-border rounded-lg overflow-hidden bg-surface">
              <table className="w-full text-sm">
                <thead className="bg-surface2 text-muted text-xs uppercase">
                  <tr>
                    <th className="text-left px-4 py-2.5">Cleartext Name</th>
                    <th className="text-left px-4 py-2.5">Type</th>
                    <th className="text-right px-4 py-2.5">Cleartext Size</th>
                    <th className="text-right px-4 py-2.5">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {filteredEntries.map((entry) => (
                    <tr key={entry.path} className="hover:bg-surface2/50">
                      <td className="px-4 py-2.5 font-medium">
                        {entry.kind === "directory" ? (
                          <button
                            onClick={() => setCurrentPath(entry.path)}
                            className="text-accent hover:underline"
                          >
                            [DIR] {entry.name}
                          </button>
                        ) : (
                          <span>{entry.name}</span>
                        )}
                      </td>
                      <td className="px-4 py-2.5 text-muted">{entry.kind}</td>
                      <td className="px-4 py-2.5 text-right font-mono text-xs">
                        {formatBytes(entry.size)}
                      </td>
                      <td className="px-4 py-2.5 text-right space-x-2">
                        {entry.kind === "file" && (
                          <button
                            onClick={() => void handlePreview(entry)}
                            className="text-xs px-2 py-1 rounded bg-surface2 hover:bg-border"
                          >
                            Decrypt Preview
                          </button>
                        )}
                        <button
                          onClick={() =>
                            void VaultApi.deleteEntry(activeVault.id, entry.path).then(() =>
                              refreshEntries()
                            )
                          }
                          className="text-xs px-2 py-1 rounded text-danger hover:bg-danger/10"
                        >
                          Delete
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {previewEntry && (
              <div className="p-4 rounded-lg bg-surface border border-border space-y-2">
                <div className="flex items-center justify-between">
                  <h3 className="font-semibold text-sm">
                    In-Memory Decrypted Preview: {previewEntry.entry.path}
                  </h3>
                  <button
                    onClick={() => setPreviewEntry(null)}
                    className="text-xs text-muted hover:underline"
                  >
                    Close &amp; Scrub Preview
                  </button>
                </div>
                <pre className="p-3 rounded bg-bg text-xs font-mono overflow-x-auto whitespace-pre-wrap">
                  {previewEntry.text}
                </pre>
              </div>
            )}
          </div>
        ) : activeTab === "integrity" ? (
          <div className="space-y-4">
            <div className="p-4 bg-surface border border-border rounded-lg flex items-center justify-between">
              <div>
                <h2 className="font-semibold">Full Vault AEAD Integrity Verification</h2>
                <p className="text-xs text-muted">
                  Verifies vault.cryptomator HS256 JWS, directory ID backups, AES-256-SIV filenames, and every 32 KiB AES-256-GCM chunk tag.
                </p>
              </div>
              <button
                onClick={() => void handleRunIntegrity()}
                className="px-4 py-2 rounded bg-accent text-accentFg text-sm font-medium"
              >
                Run Integrity Scan
              </button>
            </div>
            {integrityReport && (
              <div className="p-4 bg-surface border border-border rounded-lg text-sm space-y-2">
                <p>Directories Verified: {integrityReport.directories}</p>
                <p>Files Verified: {integrityReport.files}</p>
                <p>Cleartext Bytes Authenticated: {formatBytes(integrityReport.bytesVerified)}</p>
                <p>Problems Found: {integrityReport.problems.length}</p>
              </div>
            )}
          </div>
        ) : activeTab === "cloud" ? (
          <div className="space-y-4">
            <div className="p-4 bg-surface border border-border rounded-lg flex items-center justify-between">
              <div>
                <h2 className="font-semibold">Zero-Knowledge Ciphertext Mirror Synchronization</h2>
                <p className="text-xs text-muted">
                  Syncs only verified Cryptomator ciphertext files (.c9r / .c9s / vault.cryptomator / masterkey.cryptomator). Plaintext files are blocked by SyncEngine.
                </p>
              </div>
              <button
                onClick={() => void handleRunSync()}
                className="px-4 py-2 rounded bg-accent text-accentFg text-sm font-medium"
              >
                Sync Ciphertext Now
              </button>
            </div>
            {syncSummary && (
              <div className="p-4 bg-surface border border-border rounded-lg text-sm space-y-1">
                <p>Adapter: {syncSummary.provider}</p>
                <p>Uploaded Objects: {syncSummary.uploaded}</p>
                <p>Unchanged Objects: {syncSummary.unchanged}</p>
                <p>Bytes Transferred: {formatBytes(syncSummary.bytesTransferred)}</p>
              </div>
            )}
            {ciphertextObjects.length > 0 && (
              <div className="p-4 bg-surface border border-border rounded-lg space-y-2">
                <h3 className="text-xs uppercase tracking-wider text-muted">
                  On-Disk Ciphertext Layout (No Plaintext Names or Hierarchy Leaked)
                </h3>
                <div className="max-h-64 overflow-y-auto font-mono text-xs space-y-1">
                  {ciphertextObjects.map((o) => (
                    <div key={o.relPath} className="flex justify-between py-0.5 border-b border-border/40">
                      <span className="truncate pr-4">{o.relPath}</span>
                      <span className="text-muted">{o.size} B · sha1:{o.sha1.slice(0, 10)}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        ) : (
          <div className="space-y-4">
            <div className="p-4 bg-surface border border-border rounded-lg space-y-3">
              <h2 className="font-semibold">Theme Gallery (6 Built-In Themes)</h2>
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                {THEMES.map((t) => (
                  <button
                    key={t.id}
                    onClick={() => setTheme(t.id)}
                    className={`p-3 rounded-lg border text-left ${
                      theme === t.id ? "border-accent bg-surface2" : "border-border bg-bg"
                    }`}
                  >
                    <div className="flex items-center gap-2 font-medium text-sm">
                      <span
                        className="w-3 h-3 rounded-full inline-block"
                        style={{ backgroundColor: t.swatch }}
                      />
                      <span>{t.label}</span>
                    </div>
                    <p className="text-xs text-muted mt-1">{t.tagline}</p>
                  </button>
                ))}
              </div>
            </div>
            <div className="p-4 bg-surface border border-border rounded-lg flex items-center justify-between">
              <div>
                <h3 className="font-semibold text-sm">Inactivity Auto-Lock Timer</h3>
                <p className="text-xs text-muted">
                  Automatically locks all vaults and scrubs masterkeys via OPENSSL_cleanse when idle.
                </p>
              </div>
              <select
                value={autoLockMinutes}
                onChange={(e) => setAutoLockMinutes(Number(e.target.value))}
                className="px-3 py-1.5 rounded bg-surface2 border border-border text-sm"
              >
                <option value={1}>1 minute</option>
                <option value={5}>5 minutes</option>
                <option value={15}>15 minutes</option>
                <option value={30}>30 minutes</option>
              </select>
            </div>
          </div>
        )}

        {showCreateWizard && (
          <div className="fixed inset-0 bg-black/70 flex items-center justify-center p-4">
            <form
              onSubmit={handleCreateVault}
              className="w-full max-w-md bg-surface border border-border rounded-lg p-6 space-y-4"
            >
              <h2 className="text-lg font-semibold">Create New Encrypted Vault (Format 8)</h2>
              <input
                required
                value={newVaultName}
                onChange={(e) => setNewVaultName(e.target.value)}
                placeholder="Vault display name (e.g. Personal Vault)"
                className="w-full px-3 py-2 rounded bg-surface2 border border-border text-sm"
              />
              <input
                value={newVaultPath}
                onChange={(e) => setNewVaultPath(e.target.value)}
                placeholder="Optional custom host directory path"
                className="w-full px-3 py-2 rounded bg-surface2 border border-border text-sm"
              />
              <input
                required
                type="password"
                value={newVaultPassword}
                onChange={(e) => setNewVaultPassword(e.target.value)}
                placeholder="Master passphrase (scrypt + RFC 3394 Key Wrap)"
                className="w-full px-3 py-2 rounded bg-surface2 border border-border text-sm"
              />
              <div className="flex justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setShowCreateWizard(false)}
                  className="px-3 py-1.5 rounded bg-surface2 text-sm"
                >
                  Cancel
                </button>
                <button type="submit" className="px-4 py-1.5 rounded bg-accent text-accentFg text-sm font-medium">
                  Initialize Vault
                </button>
              </div>
            </form>
          </div>
        )}
      </main>
    </div>
  );
}
