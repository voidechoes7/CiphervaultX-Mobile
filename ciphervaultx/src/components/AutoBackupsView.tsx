import * as React from "react";
import {
  CloudUpload,
  FolderOpen,
  Lock,
  Pencil,
  Play,
  Plus,
  RefreshCw,
  ShieldCheck,
  Trash2,
} from "lucide-react";
import {
  backend,
  type BackupJob,
  type BackupJobInput,
  type BackupMode,
  type BackupSchedule,
  type CipherSuite,
  type CustomArgon2Params,
  type VaultInfo,
} from "@/lib/api";
import { formatBytes } from "@/lib/format";
import { MIN_PASSWORD_CHARS } from "@/lib/password";
import { Badge } from "./ui/badge";
import { Button } from "./ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "./ui/dialog";
import { Input } from "./ui/input";
import { Label } from "./ui/label";
import { Select } from "./ui/select";

interface AutoBackupsViewProps {
  vaults: VaultInfo[];
}

type KdfChoice = "mobile" | "desktop" | "high" | "custom";

function scheduleLabel(s: BackupSchedule): string {
  switch (s) {
    case "hours12":
      return "Every 12h";
    case "hours24":
      return "Every 24h";
    case "days7":
      return "Every 7 days";
    default:
      return "Manual";
  }
}

function formatUnix(secs: number | null): string {
  if (!secs) return "Never run";
  try {
    return new Date(secs * 1000).toLocaleString();
  } catch {
    return String(secs);
  }
}

export const AutoBackupsView: React.FC<AutoBackupsViewProps> = ({ vaults }) => {
  const initialIsMobile =
    typeof navigator !== "undefined" && /Android|iPhone|iPad|iPod/i.test(navigator.userAgent);

  const [jobs, setJobs] = React.useState<BackupJob[]>([]);
  const [loading, setLoading] = React.useState(false);
  const [syncingAll, setSyncingAll] = React.useState(false);
  const [runningJobId, setRunningJobId] = React.useState<string | null>(null);
  const [error, setError] = React.useState<string | null>(null);
  const [notice, setNotice] = React.useState<string | null>(null);

  // Create / Edit modal state
  const [editorOpen, setEditorOpen] = React.useState(false);
  const [editingId, setEditingId] = React.useState<string | null>(null);
  const [name, setName] = React.useState("");
  const [mode, setMode] = React.useState<BackupMode>("vault_mirror");
  const [sourceDir, setSourceDir] = React.useState("");
  const [targetVaultId, setTargetVaultId] = React.useState(vaults[0]?.id ?? "");
  const [targetVaultDir, setTargetVaultDir] = React.useState("/Backups");
  const [targetOutputDir, setTargetOutputDir] = React.useState("");
  const [suite, setSuite] = React.useState<CipherSuite>("xchacha20-poly1305");
  const [kdfChoice, setKdfChoice] = React.useState<KdfChoice>(
    initialIsMobile ? "mobile" : "desktop"
  );
  const [memoryMiB, setMemoryMiB] = React.useState(64);
  const [iterations, setIterations] = React.useState(3);
  const [parallelism, setParallelism] = React.useState(1);
  const [schedule, setSchedule] = React.useState<BackupSchedule>("hours24");
  const [autoRunOnUnlock, setAutoRunOnUnlock] = React.useState(true);
  const [enabled, setEnabled] = React.useState(true);
  const [saving, setSaving] = React.useState(false);
  const [editorError, setEditorError] = React.useState<string | null>(null);

  // Snapshot password modal (password is never persisted to disk)
  const [snapshotPromptJob, setSnapshotPromptJob] = React.useState<BackupJob | null>(null);
  const [snapshotPassword, setSnapshotPassword] = React.useState("");
  const [snapshotError, setSnapshotError] = React.useState<string | null>(null);

  // Delete confirmation modal
  const [deleteTarget, setDeleteTarget] = React.useState<BackupJob | null>(null);

  const loadJobs = React.useCallback(async () => {
    setLoading(true);
    try {
      const list = await backend.listBackupJobs();
      setJobs(list);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, []);

  React.useEffect(() => {
    void loadJobs();
  }, [loadJobs]);

  const openCreateModal = () => {
    setEditingId(null);
    setName("");
    setMode("vault_mirror");
    setSourceDir("");
    setTargetVaultId(vaults[0]?.id ?? "");
    setTargetVaultDir("/Backups");
    setTargetOutputDir("");
    setSuite("xchacha20-poly1305");
    setKdfChoice(initialIsMobile ? "mobile" : "desktop");
    setMemoryMiB(64);
    setIterations(3);
    setParallelism(1);
    setSchedule("hours24");
    setAutoRunOnUnlock(true);
    setEnabled(true);
    setEditorError(null);
    setEditorOpen(true);
  };

  const openEditModal = (job: BackupJob) => {
    setEditingId(job.id);
    setName(job.name);
    setMode(job.mode);
    setSourceDir(job.source_dir);
    setTargetVaultId(job.target_vault_id ?? vaults[0]?.id ?? "");
    setTargetVaultDir(job.target_vault_dir ?? "/Backups");
    setTargetOutputDir(job.target_output_dir ?? "");
    setSuite(job.suite ?? "xchacha20-poly1305");
    if (job.kdf_params) {
      const mib = Math.round(job.kdf_params.m_cost / 1024);
      if (mib === 64 && job.kdf_params.t_cost === 3 && job.kdf_params.p_cost === 1) {
        setKdfChoice("mobile");
      } else if (mib === 256 && job.kdf_params.t_cost === 3 && job.kdf_params.p_cost === 1) {
        setKdfChoice("desktop");
      } else if (mib === 512 && job.kdf_params.t_cost === 4 && job.kdf_params.p_cost === 2) {
        setKdfChoice("high");
      } else {
        setKdfChoice("custom");
        setMemoryMiB(mib);
        setIterations(job.kdf_params.t_cost);
        setParallelism(job.kdf_params.p_cost);
      }
    } else {
      setKdfChoice(initialIsMobile ? "mobile" : "desktop");
    }
    setSchedule(job.schedule);
    setAutoRunOnUnlock(job.auto_run_on_unlock);
    setEnabled(job.enabled);
    setEditorError(null);
    setEditorOpen(true);
  };

  const handleSaveJob = async (e: React.FormEvent) => {
    e.preventDefault();
    setEditorError(null);
    if (!name.trim()) {
      setEditorError("Enter a name for this backup job.");
      return;
    }
    if (!sourceDir.trim()) {
      setEditorError("Select a local source folder.");
      return;
    }
    if (mode === "vault_mirror" && !targetVaultId) {
      setEditorError("Select a target vault.");
      return;
    }
    if (mode === "encrypted_snapshot" && !targetOutputDir.trim()) {
      setEditorError("Select a destination folder for encrypted snapshots.");
      return;
    }

    let kdfParams: CustomArgon2Params | null = null;
    if (mode === "encrypted_snapshot") {
      if (kdfChoice === "mobile") {
        kdfParams = { m_cost: 64 * 1024, t_cost: 3, p_cost: 1 };
      } else if (kdfChoice === "desktop") {
        kdfParams = { m_cost: 256 * 1024, t_cost: 3, p_cost: 1 };
      } else if (kdfChoice === "high") {
        kdfParams = { m_cost: 512 * 1024, t_cost: 4, p_cost: 2 };
      } else {
        if (memoryMiB < 64 || memoryMiB > 2048 || iterations < 2 || iterations > 500 || parallelism < 1 || parallelism > 16) {
          setEditorError("Custom Argon2id requires Memory 64–2048 MiB, Rounds 2–500, Parallelism 1–16.");
          return;
        }
        kdfParams = {
          m_cost: Math.round(memoryMiB) * 1024,
          t_cost: Math.round(iterations),
          p_cost: Math.round(parallelism),
        };
      }
    }

    const payload: BackupJobInput = {
      id: editingId,
      name: name.trim(),
      mode,
      source_dir: sourceDir.trim(),
      target_vault_id: mode === "vault_mirror" ? targetVaultId : null,
      target_vault_dir: mode === "vault_mirror" ? targetVaultDir.trim() || "/Backups" : null,
      target_output_dir: mode === "encrypted_snapshot" ? targetOutputDir.trim() : null,
      suite: mode === "encrypted_snapshot" ? suite : null,
      kdf_params: kdfParams,
      schedule,
      auto_run_on_unlock: mode === "vault_mirror" ? autoRunOnUnlock : false,
      enabled,
    };

    setSaving(true);
    try {
      await backend.saveBackupJob(payload);
      setEditorOpen(false);
      await loadJobs();
    } catch (err) {
      setEditorError(err instanceof Error ? err.message : String(err));
    } finally {
      setSaving(false);
    }
  };

  const handleRunJob = async (job: BackupJob) => {
    setError(null);
    setNotice(null);
    if (job.mode === "encrypted_snapshot") {
      setSnapshotPromptJob(job);
      setSnapshotPassword("");
      setSnapshotError(null);
      return;
    }
    setRunningJobId(job.id);
    try {
      const rep = await backend.runBackupJob(job.id, null);
      setNotice(
        `"${job.name}": synced ${rep.files_synced} file(s), skipped ${rep.files_skipped} unchanged (${formatBytes(rep.bytes_processed)}).`
      );
      await loadJobs();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setRunningJobId(null);
    }
  };

  const submitSnapshotRun = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!snapshotPromptJob) return;
    if ([...snapshotPassword].length < MIN_PASSWORD_CHARS) {
      setSnapshotError(`Password must be at least ${MIN_PASSWORD_CHARS} characters.`);
      return;
    }
    const job = snapshotPromptJob;
    setRunningJobId(job.id);
    setSnapshotError(null);
    try {
      const rep = await backend.runBackupJob(job.id, snapshotPassword);
      setSnapshotPassword("");
      setSnapshotPromptJob(null);
      setNotice(
        `Snapshot "${job.name}" saved (${rep.files_synced} entries, ${formatBytes(rep.bytes_processed)}) → ${rep.output_path ?? ""}`
      );
      await loadJobs();
    } catch (err) {
      setSnapshotError(err instanceof Error ? err.message : String(err));
    } finally {
      setRunningJobId(null);
    }
  };

  const handleSyncAll = async () => {
    setError(null);
    setNotice(null);
    setSyncingAll(true);
    try {
      const reports = await backend.runAllMirrorBackups(null);
      if (reports.length === 0) {
        setNotice("No enabled Vault Mirror jobs had an unlocked target vault.");
      } else {
        const synced = reports.reduce((acc, r) => acc + r.files_synced, 0);
        const skipped = reports.reduce((acc, r) => acc + r.files_skipped, 0);
        const bytes = reports.reduce((acc, r) => acc + r.bytes_processed, 0);
        setNotice(
          `Synced ${reports.length} backup job(s): ${synced} file(s) updated (${formatBytes(bytes)}), ${skipped} unchanged.`
        );
      }
      await loadJobs();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setSyncingAll(false);
    }
  };

  const confirmDeleteJob = async () => {
    if (!deleteTarget) return;
    setError(null);
    try {
      await backend.deleteBackupJob(deleteTarget.id);
      setDeleteTarget(null);
      await loadJobs();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  };

  const mirrorUnlockedCount = jobs.filter(
    (j) =>
      j.enabled &&
      j.mode === "vault_mirror" &&
      vaults.some((v) => v.id === j.target_vault_id && v.unlocked)
  ).length;

  return (
    <div className="mx-auto max-w-4xl space-y-6 p-4 md:space-y-8 md:p-8">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div className="space-y-1">
          <h1 className="text-2xl font-semibold tracking-tight">Automated Encrypted Backups</h1>
          <p className="text-sm text-muted-foreground">
            Incremental Zero-Knowledge vault mirroring and atomic cloud-ready{" "}
            <code>.zip.cvxenc</code> snapshots.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Button
            variant="outline"
            disabled={syncingAll || mirrorUnlockedCount === 0}
            onClick={() => void handleSyncAll()}
          >
            <RefreshCw className={`h-4 w-4 ${syncingAll ? "animate-spin" : ""}`} />
            {syncingAll ? "Syncing…" : `1-Tap Sync All (${mirrorUnlockedCount})`}
          </Button>
          <Button onClick={openCreateModal}>
            <Plus className="h-4 w-4" />
            New Backup Job
          </Button>
        </div>
      </div>

      <div className="flex items-start gap-2.5 rounded-xl border border-primary/30 bg-primary/5 p-3.5 text-xs text-muted-foreground">
        <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0 text-primary" />
        <span>
          <strong className="text-foreground">Zero-Knowledge Manifest:</strong> Incremental sync
          manifests store only SHA-256 hashes of relative paths — zero plaintext filenames are ever
          saved to JSON, symlinks are strictly ignored, and snapshots compress inside an RAII
          TempDir before atomic encryption.
        </span>
      </div>

      {error && (
        <div className="rounded-lg border border-destructive/40 bg-destructive/10 px-3 py-2 text-xs text-destructive">
          {error}
        </div>
      )}
      {notice && (
        <div className="break-all rounded-lg border border-primary/30 bg-primary/10 px-3 py-2 text-xs text-primary">
          {notice}
        </div>
      )}

      {loading ? (
        <p className="py-10 text-center text-sm text-muted-foreground">Loading backup jobs…</p>
      ) : jobs.length === 0 ? (
        <div className="rounded-2xl border border-dashed border-border bg-card/80 p-8 text-center md:p-12">
          <CloudUpload className="mx-auto mb-3 h-8 w-8 text-primary" />
          <p className="text-base font-semibold">No automated backup jobs configured</p>
          <p className="mx-auto mt-1 max-w-md text-xs text-muted-foreground">
            Create a <strong>Vault Mirror</strong> to incrementally sync a local folder into any
            unlocked vault, or an <strong>Encrypted Snapshot</strong> to generate atomic{" "}
            <code>.zip.cvxenc</code> archives for iCloud, Nextcloud, or USB.
          </p>
          <Button className="mt-5" onClick={openCreateModal}>
            <Plus className="h-4 w-4" />
            Create First Backup Job
          </Button>
        </div>
      ) : (
        <div className="grid gap-3.5">
          {jobs.map((job) => {
            const targetVault = vaults.find((v) => v.id === job.target_vault_id);
            const isMirrorLocked = job.mode === "vault_mirror" && !targetVault?.unlocked;
            const isRunning = runningJobId === job.id;
            return (
              <div
                key={job.id}
                className="flex flex-col gap-3 rounded-xl border border-border bg-card/90 p-4 shadow-sm sm:flex-row sm:items-center sm:justify-between"
              >
                <div className="min-w-0 flex-1 space-y-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="truncate text-base font-semibold">{job.name}</span>
                    <Badge variant={job.mode === "vault_mirror" ? "default" : "secondary"}>
                      {job.mode === "vault_mirror" ? "Vault Mirror" : "Encrypted Snapshot"}
                    </Badge>
                    <Badge variant="outline">{scheduleLabel(job.schedule)}</Badge>
                    {job.auto_run_on_unlock && job.mode === "vault_mirror" && (
                      <Badge variant="outline">Auto on Unlock</Badge>
                    )}
                    {!job.enabled && <Badge variant="destructive">Paused</Badge>}
                  </div>
                  <p className="truncate font-mono text-xs text-muted-foreground">
                    From: {job.source_dir}
                  </p>
                  <p className="truncate font-mono text-xs text-muted-foreground">
                    {job.mode === "vault_mirror"
                      ? `To Vault: ${targetVault?.name ?? "Unknown"} → ${job.target_vault_dir ?? "/Backups"}`
                      : `To Folder: ${job.target_output_dir ?? "App Exports"}`}
                  </p>
                  <div className="text-[11px] text-muted-foreground">
                    Last run: {formatUnix(job.last_run_unix)}
                    {job.last_status ? ` · ${job.last_status}` : ""}
                  </div>
                </div>

                <div className="flex flex-wrap items-center justify-end gap-1.5 sm:shrink-0">
                  <Button
                    size="sm"
                    disabled={isRunning || isMirrorLocked}
                    onClick={() => void handleRunJob(job)}
                    title={isMirrorLocked ? "Unlock the target vault first" : "Run backup now"}
                  >
                    {isMirrorLocked ? (
                      <>
                        <Lock className="h-3.5 w-3.5" />
                        Vault Locked
                      </>
                    ) : (
                      <>
                        <Play className="h-3.5 w-3.5" />
                        {isRunning
                          ? "Running…"
                          : job.mode === "vault_mirror"
                          ? "Sync Now"
                          : "Create Snapshot"}
                      </>
                    )}
                  </Button>
                  <Button
                    variant="ghost"
                    size="icon"
                    className="h-8 w-8"
                    aria-label={`Edit ${job.name}`}
                    onClick={() => openEditModal(job)}
                  >
                    <Pencil className="h-3.5 w-3.5" />
                  </Button>
                  <Button
                    variant="ghost"
                    size="icon"
                    className="h-8 w-8"
                    aria-label={`Delete ${job.name}`}
                    onClick={() => setDeleteTarget(job)}
                  >
                    <Trash2 className="h-3.5 w-3.5 text-muted-foreground" />
                  </Button>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Create / Edit Backup Job Modal */}
      <Dialog open={editorOpen} onOpenChange={(o) => !saving && setEditorOpen(o)}>
        <DialogContent className="max-w-xl">
          <form onSubmit={(e) => void handleSaveJob(e)} className="space-y-4" noValidate>
            <DialogHeader>
              <DialogTitle>{editingId ? "Edit Backup Job" : "New Encrypted Backup Job"}</DialogTitle>
              <DialogDescription>
                Configure a Zero-Knowledge incremental mirror or an atomic encrypted snapshot.
              </DialogDescription>
            </DialogHeader>

            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <div className="space-y-1.5">
                <Label htmlFor="bk-name">Job Name</Label>
                <Input
                  id="bk-name"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="Documents Backup"
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="bk-mode">Backup Mode</Label>
                <Select
                  id="bk-mode"
                  value={mode}
                  onChange={(e) => setMode(e.target.value as BackupMode)}
                >
                  <option value="vault_mirror">Vault Mirror (Incremental 1-Tap)</option>
                  <option value="encrypted_snapshot">Encrypted Snapshot (.zip.cvxenc)</option>
                </Select>
              </div>
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="bk-src">Local Source Folder</Label>
              <div className="flex gap-2">
                <Input
                  id="bk-src"
                  value={sourceDir}
                  onChange={(e) => setSourceDir(e.target.value)}
                  placeholder="/path/to/local-folder"
                  className="min-w-0 flex-1 font-mono text-xs"
                />
                <Button
                  type="button"
                  variant="outline"
                  onClick={async () => {
                    const p = await backend.pickFolder("Select local folder to back up");
                    if (p) setSourceDir(p);
                  }}
                >
                  <FolderOpen className="h-4 w-4" />
                  Browse
                </Button>
              </div>
            </div>

            {mode === "vault_mirror" ? (
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                <div className="space-y-1.5">
                  <Label htmlFor="bk-vault">Target Vault</Label>
                  <Select
                    id="bk-vault"
                    value={targetVaultId}
                    onChange={(e) => setTargetVaultId(e.target.value)}
                  >
                    {vaults.length === 0 ? (
                      <option value="">Create a vault first</option>
                    ) : (
                      vaults.map((v) => (
                        <option key={v.id} value={v.id}>
                          {v.name} {v.unlocked ? "(Unlocked)" : "(Locked)"}
                        </option>
                      ))
                    )}
                  </Select>
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor="bk-vdir">Target Folder Inside Vault</Label>
                  <Input
                    id="bk-vdir"
                    value={targetVaultDir}
                    onChange={(e) => setTargetVaultDir(e.target.value)}
                    placeholder="/Backups/Documents"
                    className="font-mono text-xs"
                  />
                </div>
              </div>
            ) : (
              <>
                <div className="space-y-1.5">
                  <Label htmlFor="bk-out">Snapshot Destination Folder (iCloud / Nextcloud / USB)</Label>
                  <div className="flex gap-2">
                    <Input
                      id="bk-out"
                      value={targetOutputDir}
                      onChange={(e) => setTargetOutputDir(e.target.value)}
                      placeholder="/path/to/cloud-sync-folder"
                      className="min-w-0 flex-1 font-mono text-xs"
                    />
                    <Button
                      type="button"
                      variant="outline"
                      onClick={async () => {
                        const p = await backend.pickFolder("Select snapshot output folder");
                        if (p) setTargetOutputDir(p);
                      }}
                    >
                      <FolderOpen className="h-4 w-4" />
                      Browse
                    </Button>
                  </div>
                </div>
                <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                  <div className="space-y-1.5">
                    <Label htmlFor="bk-suite">Cipher Suite</Label>
                    <Select
                      id="bk-suite"
                      value={suite}
                      onChange={(e) => setSuite(e.target.value as CipherSuite)}
                    >
                      <option value="xchacha20-poly1305">XChaCha20-Poly1305 (256-bit)</option>
                      <option value="aes256-gcm">AES-256-GCM (256-bit)</option>
                    </Select>
                  </div>
                  <div className="space-y-1.5">
                    <Label htmlFor="bk-kdf">Argon2id Profile</Label>
                    <Select
                      id="bk-kdf"
                      value={kdfChoice}
                      onChange={(e) => setKdfChoice(e.target.value as KdfChoice)}
                    >
                      <option value="mobile">Mobile (64 MiB, t=3, p=1)</option>
                      <option value="desktop">Desktop (256 MiB, t=3, p=1)</option>
                      <option value="high">High Desktop (512 MiB, t=4, p=2)</option>
                      <option value="custom">Custom Argon2id</option>
                    </Select>
                  </div>
                </div>
                {kdfChoice === "custom" && (
                  <div className="grid grid-cols-3 gap-2 rounded-lg border border-border bg-muted/30 p-3">
                    <div className="space-y-1">
                      <Label htmlFor="bk-mem">MiB (≥64)</Label>
                      <Input
                        id="bk-mem"
                        type="number"
                        min={64}
                        max={2048}
                        step={64}
                        value={memoryMiB}
                        onChange={(e) => setMemoryMiB(Number(e.target.value))}
                      />
                    </div>
                    <div className="space-y-1">
                      <Label htmlFor="bk-iter">Rounds (t)</Label>
                      <Input
                        id="bk-iter"
                        type="number"
                        min={2}
                        max={500}
                        value={iterations}
                        onChange={(e) => setIterations(Number(e.target.value))}
                      />
                    </div>
                    <div className="space-y-1">
                      <Label htmlFor="bk-par">Threads (p)</Label>
                      <Input
                        id="bk-par"
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

            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <div className="space-y-1.5">
                <Label htmlFor="bk-sched">Schedule</Label>
                <Select
                  id="bk-sched"
                  value={schedule}
                  onChange={(e) => setSchedule(e.target.value as BackupSchedule)}
                >
                  <option value="manual">Manual only</option>
                  <option value="hours12">Every 12 hours</option>
                  <option value="hours24">Every 24 hours</option>
                  <option value="days7">Every 7 days</option>
                </Select>
              </div>
              <div className="flex flex-col justify-end gap-2 pb-1 text-xs">
                {mode === "vault_mirror" && (
                  <label className="flex cursor-pointer items-center gap-2">
                    <input
                      type="checkbox"
                      checked={autoRunOnUnlock}
                      onChange={(e) => setAutoRunOnUnlock(e.target.checked)}
                    />
                    Auto-run when vault unlocks
                  </label>
                )}
                <label className="flex cursor-pointer items-center gap-2">
                  <input
                    type="checkbox"
                    checked={enabled}
                    onChange={(e) => setEnabled(e.target.checked)}
                  />
                  Job enabled
                </label>
              </div>
            </div>

            {editorError && (
              <div className="rounded-lg border border-destructive/40 bg-destructive/10 px-3 py-2 text-xs text-destructive">
                {editorError}
              </div>
            )}

            <DialogFooter>
              <Button
                type="button"
                variant="outline"
                onClick={() => setEditorOpen(false)}
                disabled={saving}
              >
                Cancel
              </Button>
              <Button type="submit" disabled={saving}>
                {saving ? "Saving…" : "Save Backup Job"}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      {/* Snapshot Passphrase Modal */}
      <Dialog
        open={Boolean(snapshotPromptJob)}
        onOpenChange={(o) => !o && !runningJobId && setSnapshotPromptJob(null)}
      >
        <DialogContent className="max-w-md">
          <form onSubmit={(e) => void submitSnapshotRun(e)} className="space-y-4" noValidate>
            <DialogHeader>
              <DialogTitle>Encrypt Snapshot: {snapshotPromptJob?.name}</DialogTitle>
              <DialogDescription>
                Enter an encryption passphrase (min {MIN_PASSWORD_CHARS} chars). Passphrases are
                never saved to disk.
              </DialogDescription>
            </DialogHeader>
            <div className="space-y-1.5">
              <Label htmlFor="snap-pw">Snapshot Password</Label>
              <Input
                id="snap-pw"
                type="password"
                value={snapshotPassword}
                onChange={(e) => setSnapshotPassword(e.target.value)}
                autoFocus
                disabled={Boolean(runningJobId)}
              />
            </div>
            {snapshotError && (
              <div className="rounded-lg border border-destructive/40 bg-destructive/10 px-3 py-2 text-xs text-destructive">
                {snapshotError}
              </div>
            )}
            <DialogFooter>
              <Button
                type="button"
                variant="outline"
                onClick={() => setSnapshotPromptJob(null)}
                disabled={Boolean(runningJobId)}
              >
                Cancel
              </Button>
              <Button type="submit" disabled={Boolean(runningJobId)}>
                {runningJobId ? "Compressing & Encrypting…" : "Create Snapshot"}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      {/* Delete Backup Job Confirmation Modal */}
      <Dialog open={Boolean(deleteTarget)} onOpenChange={(o) => !o && setDeleteTarget(null)}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>Delete Backup Job?</DialogTitle>
            <DialogDescription>
              Remove backup job <strong>{deleteTarget?.name}</strong> and its SHA-256 sync manifest?
              Files already encrypted in your vault or snapshots will not be deleted.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => setDeleteTarget(null)}>
              Cancel
            </Button>
            <Button type="button" variant="destructive" onClick={() => void confirmDeleteJob()}>
              Delete Job
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
};
