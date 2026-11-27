import { invoke } from "@tauri-apps/api/core";
import { open, save } from "@tauri-apps/plugin-dialog";

export type CipherSuite = "xchacha20-poly1305" | "aes256-gcm";
export type KdfProfile = "desktop" | "mobile";
export type EntryKind = "file" | "directory" | "unreadable";

export interface VaultSummary {
  vault_id: string;
  suite: CipherSuite;
  chunk_size: number;
  format: number;
}

export interface VaultInfo {
  id: string;
  name: string;
  path: string;
  unlocked: boolean;
  summary: VaultSummary | null;
}

export interface CreateVaultResult {
  vault: VaultInfo;
  recovery_key: string;
}

export interface VaultEntry {
  name: string;
  path: string;
  kind: EntryKind;
  size: number;
  modified_ms: number;
}

export interface IntegrityIssue {
  path: string;
  reason: string;
}

export interface IntegrityReport {
  files_checked: number;
  dirs_checked: number;
  issues: IntegrityIssue[];
}

export interface PreviewPayload {
  mime: string;
  base64: string;
  size: number;
}

export interface AppSettings {
  theme: string;
  ui_style: string;
  auto_lock_minutes: number;
}

export interface StandaloneOpResult {
  path: string;
  bytes: number;
}

export interface ArchiveOpResult {
  path: string;
  bytes: number;
  entries: number;
}

export type BackupMode = "vault_mirror" | "encrypted_snapshot";
export type BackupSchedule = "manual" | "hours12" | "hours24" | "days7";

export interface BackupJob {
  id: string;
  name: string;
  mode: BackupMode;
  source_dir: string;
  target_vault_id: string | null;
  target_vault_dir: string | null;
  target_output_dir: string | null;
  suite: CipherSuite | null;
  kdf_params: CustomArgon2Params | null;
  schedule: BackupSchedule;
  auto_run_on_unlock: boolean;
  enabled: boolean;
  last_run_unix: number | null;
  last_status: string | null;
}

export interface BackupJobInput {
  id?: string | null;
  name: string;
  mode: BackupMode;
  source_dir: string;
  target_vault_id?: string | null;
  target_vault_dir?: string | null;
  target_output_dir?: string | null;
  suite?: CipherSuite | null;
  kdf_params?: CustomArgon2Params | null;
  schedule: BackupSchedule;
  auto_run_on_unlock: boolean;
  enabled: boolean;
}

export interface BackupRunReport {
  job_id: string;
  mode: BackupMode;
  files_synced: number;
  files_skipped: number;
  bytes_processed: number;
  output_path: string | null;
  completed_unix: number;
}

export interface MountInfo {
  vault_id: string;
  url: string;
  mount_point: string;
  drive_letter: string | null;
}

export interface CustomArgon2Params {
  m_cost: number;
  t_cost: number;
  p_cost: number;
}

export interface CryptomatorVaultInfo {
  path: string;
  format: number;
  cipher_combo: string;
}

export interface AppGateStatus {
  enabled: boolean;
  unlocked: boolean;
  authorized_keys: number;
}

export interface DiscoveredVault {
  name: string;
  path: string;
  already_registered: boolean;
}

export interface StorageRoot {
  label: string;
  path: string;
  readable: boolean;
  kind: string;
}

export interface HostDirEntry {
  name: string;
  path: string;
  is_dir: boolean;
  size: number;
  is_cvz_vault: boolean;
  is_cryptomator_vault: boolean;
}

export interface HostDirListing {
  path: string;
  parent: string | null;
  is_empty: boolean;
  is_cvz_vault: boolean;
  is_cryptomator_vault: boolean;
  entries: HostDirEntry[];
}

export interface PickFolderOptions {
  requireEmptyFolder?: boolean;
  suggestedSubfolder?: string;
  highlightVaults?: "cvz" | "cryptomator";
  initialPath?: string;
}

export interface DevicePickerRequest {
  mode: "folder" | "file" | "files" | "save";
  title: string;
  defaultFileName?: string;
  requireEmptyFolder?: boolean;
  suggestedSubfolder?: string;
  highlightVaults?: "cvz" | "cryptomator";
  initialPath?: string;
}

export type DevicePickerHandler = (request: DevicePickerRequest) => Promise<string[] | null>;

interface AndroidStorageBridge {
  hasAllFilesAccess?: () => boolean;
  requestAllFilesAccess?: () => boolean;
  getExternalStorageRoot?: () => string;
}

declare global {
  interface Window {
    AndroidStorageBridge?: AndroidStorageBridge;
  }
}

export function hasAndroidStorageBridge(): boolean {
  return typeof window !== "undefined" && Boolean(window.AndroidStorageBridge);
}

export function hasAndroidAllFilesAccess(): boolean {
  try {
    return Boolean(window.AndroidStorageBridge?.hasAllFilesAccess?.());
  } catch {
    return false;
  }
}

export function requestAndroidAllFilesAccess(): boolean {
  try {
    return Boolean(window.AndroidStorageBridge?.requestAllFilesAccess?.());
  } catch {
    return false;
  }
}

let mobilePickerHandler: DevicePickerHandler | null = null;
let cachedIsMobile: boolean | null = null;

export function registerMobilePickerHandler(handler: DevicePickerHandler | null): void {
  mobilePickerHandler = handler;
}

export interface Backend {
  getAppGateStatus(): Promise<AppGateStatus>;
  unlockAppGate(passphrase: string): Promise<AppGateStatus>;
  lockAppGate(): Promise<AppGateStatus>;
  generateAccessGateHash(passphrase: string): Promise<string>;
  listVaults(): Promise<VaultInfo[]>;
  createVault(args: {
    name: string;
    path: string;
    suite: CipherSuite;
    kdfProfile: KdfProfile;
    password: string;
    customKdf?: CustomArgon2Params;
  }): Promise<CreateVaultResult>;
  registerExistingVault(path: string, name?: string): Promise<void>;
  removeVaultEntry(vaultId: string): Promise<boolean>;
  unlockVault(vaultId: string, password: string): Promise<VaultInfo>;
  unlockVaultWithRecovery(vaultId: string, recoveryKey: string): Promise<VaultInfo>;
  resetPasswordWithRecovery(args: {
    vaultId: string;
    recoveryKey: string;
    newPassword: string;
    kdfProfile: KdfProfile;
  }): Promise<VaultInfo>;
  changeVaultPassword(args: {
    vaultId: string;
    currentPassword: string;
    newPassword: string;
    kdfProfile: KdfProfile;
  }): Promise<void>;
  lockVault(vaultId: string): Promise<boolean>;
  lockAllVaults(): Promise<string[]>;
  mountVault(vaultId: string): Promise<MountInfo>;
  unmountVault(vaultId: string): Promise<boolean>;
  getMountInfo(vaultId: string): Promise<MountInfo | null>;
  revealMount(vaultId: string): Promise<void>;
  listDir(vaultId: string, path: string): Promise<VaultEntry[]>;
  createDir(vaultId: string, path: string): Promise<void>;
  importFile(vaultId: string, srcPath: string, dstVaultPath: string): Promise<number>;
  importPaths(vaultId: string, paths: string[], dstDir: string): Promise<number>;
  exportFile(vaultId: string, srcVaultPath: string, dstPath: string): Promise<number>;
  exportDir(vaultId: string, srcVaultDir: string, dstParentDir: string): Promise<number>;
  exportDirAsZip(
    vaultId: string,
    srcVaultDir: string,
    dstZipPath?: string | null
  ): Promise<ArchiveOpResult>;
  previewFile(vaultId: string, path: string): Promise<PreviewPayload>;
  renameEntry(vaultId: string, path: string, newName: string): Promise<void>;
  moveEntry(vaultId: string, srcPath: string, dstDir: string): Promise<void>;
  deleteEntry(vaultId: string, path: string): Promise<void>;
  searchVault(vaultId: string, query: string): Promise<VaultEntry[]>;
  verifyVault(vaultId: string): Promise<IntegrityReport>;
  getSettings(): Promise<AppSettings>;
  updateSettings(settings: AppSettings): Promise<void>;
  touchActivity(): Promise<void>;
  encryptStandaloneFile(args: {
    srcPath: string;
    dstPath?: string | null;
    password: string;
    suite: CipherSuite;
    kdfProfile: KdfProfile;
    customKdf?: CustomArgon2Params | null;
  }): Promise<StandaloneOpResult>;
  decryptStandaloneFile(args: {
    srcPath: string;
    dstPath?: string | null;
    password: string;
  }): Promise<StandaloneOpResult>;
  compressToZip(srcPaths: string[], dstZipPath?: string | null): Promise<ArchiveOpResult>;
  extractArchive(srcArchivePath: string, dstDir?: string | null): Promise<ArchiveOpResult>;
  listBackupJobs(): Promise<BackupJob[]>;
  saveBackupJob(job: BackupJobInput): Promise<BackupJob>;
  deleteBackupJob(jobId: string): Promise<boolean>;
  runBackupJob(jobId: string, password?: string | null): Promise<BackupRunReport>;
  runAllMirrorBackups(vaultId?: string | null): Promise<BackupRunReport[]>;
  runDueUnlockBackups(vaultId: string): Promise<BackupRunReport[]>;
  openCryptomatorVault(path: string, password: string): Promise<CryptomatorVaultInfo>;
  closeCryptomatorVault(): Promise<boolean>;
  listCryptomatorDir(path: string): Promise<VaultEntry[]>;
  exportCryptomatorFile(srcVaultPath: string, dstPath: string): Promise<number>;
  isMobile(): Promise<boolean>;
  defaultVaultPath(name?: string): Promise<string>;
  defaultVaultsDir(): Promise<string>;
  listDiscoveredVaults(): Promise<DiscoveredVault[]>;
  listStorageRoots(): Promise<StorageRoot[]>;
  listHostDir(path: string): Promise<HostDirListing>;
  createHostDir(parent: string, name: string): Promise<string>;
  defaultExportDir(): Promise<string>;
  pickFolder(title: string, options?: PickFolderOptions): Promise<string | null>;
  pickFileToImport(): Promise<string | null>;
  pickFilesToImport(): Promise<string[]>;
  pickExportDestination(defaultName: string): Promise<string | null>;
}

export function isTauriRuntime(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

const tauriBackend: Backend = {
  getAppGateStatus: () => invoke<AppGateStatus>("get_app_gate_status"),
  unlockAppGate: (passphrase) => invoke<AppGateStatus>("unlock_app_gate", { passphrase }),
  lockAppGate: () => invoke<AppGateStatus>("lock_app_gate"),
  generateAccessGateHash: (passphrase) =>
    invoke<string>("generate_access_gate_hash", { passphrase }),
  listVaults: () => invoke<VaultInfo[]>("list_vaults"),
  createVault: ({ name, path, suite, kdfProfile, password, customKdf }) =>
    invoke<CreateVaultResult>("create_vault", {
      name,
      path,
      suite,
      kdfProfile,
      password,
      customKdf: customKdf ?? null,
    }),
  registerExistingVault: async (path, name) => {
    await invoke("register_existing_vault", { path, name: name ?? null });
  },
  removeVaultEntry: (vaultId) => invoke<boolean>("remove_vault_entry", { vaultId }),
  unlockVault: (vaultId, password) =>
    invoke<VaultInfo>("unlock_vault", { vaultId, password }),
  unlockVaultWithRecovery: (vaultId, recoveryKey) =>
    invoke<VaultInfo>("unlock_vault_with_recovery", { vaultId, recoveryKey }),
  resetPasswordWithRecovery: ({ vaultId, recoveryKey, newPassword, kdfProfile }) =>
    invoke<VaultInfo>("reset_password_with_recovery", {
      vaultId,
      recoveryKey,
      newPassword,
      kdfProfile,
    }),
  changeVaultPassword: ({ vaultId, currentPassword, newPassword, kdfProfile }) =>
    invoke<void>("change_vault_password", {
      vaultId,
      currentPassword,
      newPassword,
      kdfProfile,
    }),
  lockVault: (vaultId) => invoke<boolean>("lock_vault", { vaultId }),
  lockAllVaults: () => invoke<string[]>("lock_all_vaults"),
  mountVault: (vaultId) => invoke<MountInfo>("mount_vault", { vaultId }),
  unmountVault: (vaultId) => invoke<boolean>("unmount_vault", { vaultId }),
  getMountInfo: (vaultId) => invoke<MountInfo | null>("get_mount_info", { vaultId }),
  revealMount: (vaultId) => invoke<void>("reveal_mount", { vaultId }),
  listDir: (vaultId, path) => invoke<VaultEntry[]>("list_dir", { vaultId, path }),
  createDir: (vaultId, path) => invoke<void>("create_dir", { vaultId, path }),
  importFile: (vaultId, srcPath, dstVaultPath) =>
    invoke<number>("import_file", { vaultId, srcPath, dstVaultPath }),
  importPaths: (vaultId, paths, dstDir) =>
    invoke<number>("import_paths", { vaultId, paths, dstDir }),
  exportFile: (vaultId, srcVaultPath, dstPath) =>
    invoke<number>("export_file", { vaultId, srcVaultPath, dstPath }),
  exportDir: (vaultId, srcVaultDir, dstParentDir) =>
    invoke<number>("export_dir", { vaultId, srcVaultDir, dstParentDir }),
  exportDirAsZip: (vaultId, srcVaultDir, dstZipPath) =>
    invoke<ArchiveOpResult>("export_dir_as_zip", {
      vaultId,
      srcVaultDir,
      dstZipPath: dstZipPath ?? null,
    }),
  previewFile: (vaultId, path) => invoke<PreviewPayload>("preview_file", { vaultId, path }),
  renameEntry: (vaultId, path, newName) =>
    invoke<void>("rename_entry", { vaultId, path, newName }),
  moveEntry: (vaultId, srcPath, dstDir) =>
    invoke<void>("move_entry", { vaultId, srcPath, dstDir }),
  deleteEntry: (vaultId, path) => invoke<void>("delete_entry", { vaultId, path }),
  searchVault: (vaultId, query) => invoke<VaultEntry[]>("search_vault", { vaultId, query }),
  verifyVault: (vaultId) => invoke<IntegrityReport>("verify_vault", { vaultId }),
  getSettings: () => invoke<AppSettings>("get_settings"),
  updateSettings: (settings) => invoke<void>("update_settings", { settings }),
  touchActivity: () => invoke<void>("touch_activity"),
  encryptStandaloneFile: ({ srcPath, dstPath, password, suite, kdfProfile, customKdf }) =>
    invoke<StandaloneOpResult>("encrypt_standalone_file", {
      srcPath,
      dstPath: dstPath ?? null,
      password,
      suite,
      kdfProfile,
      customKdf: customKdf ?? null,
    }),
  decryptStandaloneFile: ({ srcPath, dstPath, password }) =>
    invoke<StandaloneOpResult>("decrypt_standalone_file", {
      srcPath,
      dstPath: dstPath ?? null,
      password,
    }),
  compressToZip: (srcPaths, dstZipPath) =>
    invoke<ArchiveOpResult>("compress_to_zip", {
      srcPaths,
      dstZipPath: dstZipPath ?? null,
    }),
  extractArchive: (srcArchivePath, dstDir) =>
    invoke<ArchiveOpResult>("extract_archive", {
      srcArchivePath,
      dstDir: dstDir ?? null,
    }),
  listBackupJobs: () => invoke<BackupJob[]>("list_backup_jobs"),
  saveBackupJob: (job) => invoke<BackupJob>("save_backup_job", { job }),
  deleteBackupJob: (jobId) => invoke<boolean>("delete_backup_job", { jobId }),
  runBackupJob: (jobId, password) =>
    invoke<BackupRunReport>("run_backup_job", { jobId, password: password ?? null }),
  runAllMirrorBackups: (vaultId) =>
    invoke<BackupRunReport[]>("run_all_mirror_backups", { vaultId: vaultId ?? null }),
  runDueUnlockBackups: (vaultId) => invoke<BackupRunReport[]>("run_due_unlock_backups", { vaultId }),
  openCryptomatorVault: (path, password) =>
    invoke<CryptomatorVaultInfo>("open_cryptomator_vault", { path, password }),
  closeCryptomatorVault: () => invoke<boolean>("close_cryptomator_vault"),
  listCryptomatorDir: (path) => invoke<VaultEntry[]>("list_cryptomator_dir", { path }),
  exportCryptomatorFile: (srcVaultPath, dstPath) =>
    invoke<number>("export_cryptomator_file", { srcVaultPath, dstPath }),
  isMobile: async () => {
    if (cachedIsMobile !== null) return cachedIsMobile;
    try {
      cachedIsMobile = await invoke<boolean>("is_mobile");
    } catch {
      cachedIsMobile =
        typeof navigator !== "undefined" && /Android|iPhone|iPad|iPod/i.test(navigator.userAgent);
    }
    return cachedIsMobile;
  },
  defaultVaultPath: (name) => invoke<string>("default_vault_path", { name: name ?? null }),
  defaultVaultsDir: () => invoke<string>("default_vaults_dir"),
  listDiscoveredVaults: () => invoke<DiscoveredVault[]>("list_discovered_vaults"),
  listStorageRoots: () => invoke<StorageRoot[]>("list_storage_roots"),
  listHostDir: (path) => invoke<HostDirListing>("list_host_dir", { path }),
  createHostDir: (parent, name) => invoke<string>("create_host_dir", { parent, name }),
  defaultExportDir: () => invoke<string>("default_export_dir"),
  pickFolder: async (title, options) => {
    if ((await tauriBackend.isMobile()) && mobilePickerHandler) {
      const picked = await mobilePickerHandler({
        mode: "folder",
        title,
        ...options,
      });
      return picked?.[0] ?? null;
    }
    try {
      const res = await open({ directory: true, multiple: false, title });
      return typeof res === "string" ? res : null;
    } catch {
      if (mobilePickerHandler) {
        const picked = await mobilePickerHandler({
          mode: "folder",
          title,
          ...options,
        });
        return picked?.[0] ?? null;
      }
      return null;
    }
  },
  pickFileToImport: async () => {
    const isIos =
      typeof navigator !== "undefined" && /iPhone|iPad|iPod/i.test(navigator.userAgent);
    // On iOS, native UIDocumentPickerViewController (asCopy: true) lets users pick
    // files directly from iCloud Drive / Files app without 0-byte File Provider failures.
    if (isIos) {
      try {
        const res = await open({
          directory: false,
          multiple: false,
          title: "Select file",
        });
        if (typeof res === "string") return res;
      } catch {
        // Fall through to in-app browser
      }
    }
    if ((await tauriBackend.isMobile()) && mobilePickerHandler) {
      const picked = await mobilePickerHandler({
        mode: "file",
        title: "Select file",
      });
      return picked?.[0] ?? null;
    }
    try {
      const res = await open({
        directory: false,
        multiple: false,
        title: "Select file to encrypt",
      });
      return typeof res === "string" ? res : null;
    } catch {
      return null;
    }
  },
  pickFilesToImport: async () => {
    const isIos =
      typeof navigator !== "undefined" && /iPhone|iPad|iPod/i.test(navigator.userAgent);
    if (isIos) {
      try {
        const res = await open({
          directory: false,
          multiple: true,
          title: "Select files",
        });
        if (Array.isArray(res) && res.length > 0) return res;
        if (typeof res === "string") return [res];
      } catch {
        // Fall through to in-app browser
      }
    }
    if ((await tauriBackend.isMobile()) && mobilePickerHandler) {
      const picked = await mobilePickerHandler({
        mode: "files",
        title: "Select files to encrypt",
      });
      return picked ?? [];
    }
    try {
      const res = await open({
        directory: false,
        multiple: true,
        title: "Select files to encrypt",
      });
      if (Array.isArray(res)) return res;
      return typeof res === "string" ? [res] : [];
    } catch {
      return [];
    }
  },
  pickExportDestination: async (defaultName) => {
    if ((await tauriBackend.isMobile()) && mobilePickerHandler) {
      const picked = await mobilePickerHandler({
        mode: "save",
        title: "Export destination",
        defaultFileName: defaultName,
      });
      return picked?.[0] ?? null;
    }
    try {
      const res = await save({ defaultPath: defaultName, title: "Export decrypted copy" });
      if (typeof res === "string") return res;
    } catch {
      // Mobile platforms do not support desktop save-file dialogs; fall back to app exports dir.
      try {
        const dir = await invoke<string>("default_export_dir");
        return `${dir}/${defaultName}`;
      } catch {
        return null;
      }
    }
    return null;
  },
};

function createBrowserMockBackend(): Backend {
  let settings: AppSettings = {
    theme: "obsidian-dark",
    ui_style: "modern-vault",
    auto_lock_minutes: 10,
  };
  const vaults: VaultInfo[] = [
    {
      id: "mock-1",
      name: "Demo Vault (Browser Preview)",
      path: "/synthetic/demo-vault",
      unlocked: false,
      summary: null,
    },
  ];
  const entries = new Map<string, VaultEntry[]>([
    [
      "/",
      [
        {
          name: "Documents",
          path: "/Documents",
          kind: "directory",
          size: 0,
          modified_ms: Date.now(),
        },
        {
          name: "notes.txt",
          path: "/notes.txt",
          kind: "file",
          size: 128,
          modified_ms: Date.now(),
        },
      ],
    ],
    ["/Documents", []],
  ]);

  return {
    getAppGateStatus: async () => ({ enabled: false, unlocked: true, authorized_keys: 0 }),
    unlockAppGate: async () => ({ enabled: false, unlocked: true, authorized_keys: 0 }),
    lockAppGate: async () => ({ enabled: false, unlocked: true, authorized_keys: 0 }),
    generateAccessGateHash: async () =>
      "$argon2id$v=19$m=65536,t=3,p=1$MOCKSALTBASE64NOPAD$MOCKHASHBASE64NOPAD",
    listVaults: async () => vaults.map((v) => ({ ...v })),
    createVault: async ({ name, path, suite }) => {
      const vault: VaultInfo = {
        id: `mock-${Date.now()}`,
        name: name || "New Vault",
        path,
        unlocked: true,
        summary: { vault_id: "MOCKVAULTID", suite, chunk_size: 65536, format: 1 },
      };
      vaults.push(vault);
      return {
        vault,
        recovery_key: "AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-GGGG-HHHH-IIII-JJJJ-KKKK-LLLL-MMMM",
      };
    },
    registerExistingVault: async (path, name) => {
      vaults.push({
        id: `mock-${Date.now()}`,
        name: name || "Existing Vault",
        path,
        unlocked: false,
        summary: null,
      });
    },
    removeVaultEntry: async (vaultId) => {
      const idx = vaults.findIndex((v) => v.id === vaultId);
      if (idx >= 0) {
        vaults.splice(idx, 1);
        return true;
      }
      return false;
    },
    unlockVault: async (vaultId) => {
      const v = vaults.find((x) => x.id === vaultId);
      if (!v) throw new Error("vault not found");
      v.unlocked = true;
      v.summary = {
        vault_id: "MOCKVAULTID",
        suite: "xchacha20-poly1305",
        chunk_size: 65536,
        format: 1,
      };
      return { ...v };
    },
    unlockVaultWithRecovery: async (vaultId) => {
      const v = vaults.find((x) => x.id === vaultId);
      if (!v) throw new Error("vault not found");
      v.unlocked = true;
      return { ...v };
    },
    resetPasswordWithRecovery: async ({ vaultId }) => {
      const v = vaults.find((x) => x.id === vaultId);
      if (!v) throw new Error("vault not found");
      v.unlocked = true;
      return { ...v };
    },
    changeVaultPassword: async () => undefined,
    lockVault: async (vaultId) => {
      const v = vaults.find((x) => x.id === vaultId);
      if (!v) return false;
      v.unlocked = false;
      return true;
    },
    lockAllVaults: async () => {
      const locked: string[] = [];
      for (const v of vaults) {
        if (v.unlocked) {
          v.unlocked = false;
          locked.push(v.id);
        }
      }
      return locked;
    },
    mountVault: async (vaultId) => ({
      vault_id: vaultId,
      url: "http://127.0.0.1:49152/mock-token/",
      mount_point: "Z:\\",
      drive_letter: "Z:",
    }),
    unmountVault: async () => true,
    getMountInfo: async () => null,
    revealMount: async () => undefined,
    listDir: async (_vaultId, path) => [...(entries.get(path) ?? [])],
    createDir: async (_vaultId, path) => {
      const name = path.split("/").filter(Boolean).pop() ?? "Folder";
      const list = entries.get("/") ?? [];
      list.push({ name, path, kind: "directory", size: 0, modified_ms: Date.now() });
      entries.set("/", list);
      entries.set(path, []);
    },
    importFile: async () => 1024,
    importPaths: async () => 1024,
    exportFile: async () => 1024,
    exportDir: async () => 4096,
    exportDirAsZip: async (_vaultId, _srcVaultDir, dstZipPath) => ({
      path: dstZipPath || "/synthetic/app-exports/folder.zip",
      bytes: 4096,
      entries: 3,
    }),
    previewFile: async () => ({
      mime: "text/plain",
      base64: btoa("Synthetic preview content (browser mock mode)."),
      size: 46,
    }),
    renameEntry: async () => undefined,
    moveEntry: async () => undefined,
    deleteEntry: async () => undefined,
    searchVault: async (_vaultId, query) => {
      const q = query.toLowerCase();
      return [...entries.values()].flat().filter((e) => e.name.toLowerCase().includes(q));
    },
    verifyVault: async () => ({ files_checked: 1, dirs_checked: 2, issues: [] }),
    getSettings: async () => ({ ...settings }),
    updateSettings: async (next) => {
      settings = { ...next };
    },
    touchActivity: async () => undefined,
    encryptStandaloneFile: async ({ srcPath, dstPath }) => ({
      path: dstPath || `${srcPath}.cvxenc`,
      bytes: 2048,
    }),
    decryptStandaloneFile: async ({ srcPath, dstPath }) => ({
      path: dstPath || srcPath.replace(/\.cvxenc$/, ""),
      bytes: 2048,
    }),
    compressToZip: async (_srcPaths, dstZipPath) => ({
      path: dstZipPath || "/synthetic/app-exports/archive.zip",
      bytes: 4096,
      entries: 2,
    }),
    extractArchive: async (_srcArchivePath, dstDir) => ({
      path: dstDir || "/synthetic/app-exports/extracted",
      bytes: 4096,
      entries: 2,
    }),
    listBackupJobs: async () => [],
    saveBackupJob: async (job) => ({
      id: job.id || "mock-job-1",
      name: job.name,
      mode: job.mode,
      source_dir: job.source_dir,
      target_vault_id: job.target_vault_id ?? null,
      target_vault_dir: job.target_vault_dir ?? null,
      target_output_dir: job.target_output_dir ?? null,
      suite: job.suite ?? null,
      kdf_params: job.kdf_params ?? null,
      schedule: job.schedule,
      auto_run_on_unlock: job.auto_run_on_unlock,
      enabled: job.enabled,
      last_run_unix: null,
      last_status: null,
    }),
    deleteBackupJob: async () => true,
    runBackupJob: async (jobId) => ({
      job_id: jobId,
      mode: "vault_mirror",
      files_synced: 2,
      files_skipped: 0,
      bytes_processed: 4096,
      output_path: "/Backups",
      completed_unix: Math.floor(Date.now() / 1000),
    }),
    runAllMirrorBackups: async () => [],
    runDueUnlockBackups: async () => [],
    openCryptomatorVault: async (path) => ({
      path,
      format: 8,
      cipher_combo: "SIV_GCM",
      shortening_threshold: 220,
    }),
    closeCryptomatorVault: async () => true,
    listCryptomatorDir: async () => [],
    exportCryptomatorFile: async () => 1024,
    isMobile: async () =>
      typeof navigator !== "undefined" && /Android|iPhone|iPad|iPod/i.test(navigator.userAgent),
    defaultVaultPath: async (name) => `/synthetic/app-vaults/${name || "vault"}`,
    defaultVaultsDir: async () => "/synthetic/app-vaults",
    listDiscoveredVaults: async () =>
      vaults.map((v) => ({ name: v.name, path: v.path, already_registered: true })),
    listStorageRoots: async () => [
      { label: "App Vaults", path: "/synthetic/app-vaults", readable: true, kind: "app-vaults" },
      { label: "App Exports", path: "/synthetic/app-exports", readable: true, kind: "app-exports" },
      { label: "Internal Storage", path: "/storage/emulated/0", readable: true, kind: "internal" },
    ],
    listHostDir: async (path) => ({
      path,
      parent: path === "/" ? null : path.split("/").slice(0, -1).join("/") || "/",
      is_empty: false,
      is_cvz_vault: path.includes("demo-vault"),
      is_cryptomator_vault: false,
      entries: [
        {
          name: "DemoVault",
          path: `${path.replace(/\/$/, "")}/DemoVault`,
          is_dir: true,
          size: 0,
          is_cvz_vault: true,
          is_cryptomator_vault: false,
        },
        {
          name: "sample.txt",
          path: `${path.replace(/\/$/, "")}/sample.txt`,
          is_dir: false,
          size: 1024,
          is_cvz_vault: false,
          is_cryptomator_vault: false,
        },
      ],
    }),
    createHostDir: async (parent, name) => `${parent.replace(/\/$/, "")}/${name}`,
    defaultExportDir: async () => "/synthetic/app-exports",
    pickFolder: async (title, options) => {
      if (mobilePickerHandler) {
        const picked = await mobilePickerHandler({ mode: "folder", title, ...options });
        return picked?.[0] ?? null;
      }
      return "/synthetic/new-vault";
    },
    pickFileToImport: async () => "/synthetic/sample.txt",
    pickFilesToImport: async () => ["/synthetic/sample.txt"],
    pickExportDestination: async (name) => `/synthetic/export/${name}`,
  };
}

export const backend: Backend = isTauriRuntime() ? tauriBackend : createBrowserMockBackend();
