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
  auto_lock_minutes: number;
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

export interface Backend {
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
    dstPath: string;
    password: string;
    suite: CipherSuite;
    kdfProfile: KdfProfile;
  }): Promise<number>;
  decryptStandaloneFile(args: {
    srcPath: string;
    dstPath: string;
    password: string;
  }): Promise<number>;
  openCryptomatorVault(path: string, password: string): Promise<CryptomatorVaultInfo>;
  closeCryptomatorVault(): Promise<boolean>;
  listCryptomatorDir(path: string): Promise<VaultEntry[]>;
  exportCryptomatorFile(srcVaultPath: string, dstPath: string): Promise<number>;
  pickFolder(title: string): Promise<string | null>;
  pickFileToImport(): Promise<string | null>;
  pickFilesToImport(): Promise<string[]>;
  pickExportDestination(defaultName: string): Promise<string | null>;
}

export function isTauriRuntime(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

const tauriBackend: Backend = {
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
  encryptStandaloneFile: ({ srcPath, dstPath, password, suite, kdfProfile }) =>
    invoke<number>("encrypt_standalone_file", {
      srcPath,
      dstPath,
      password,
      suite,
      kdfProfile,
    }),
  decryptStandaloneFile: ({ srcPath, dstPath, password }) =>
    invoke<number>("decrypt_standalone_file", { srcPath, dstPath, password }),
  openCryptomatorVault: (path, password) =>
    invoke<CryptomatorVaultInfo>("open_cryptomator_vault", { path, password }),
  closeCryptomatorVault: () => invoke<boolean>("close_cryptomator_vault"),
  listCryptomatorDir: (path) => invoke<VaultEntry[]>("list_cryptomator_dir", { path }),
  exportCryptomatorFile: (srcVaultPath, dstPath) =>
    invoke<number>("export_cryptomator_file", { srcVaultPath, dstPath }),
  pickFolder: async (title) => {
    const res = await open({ directory: true, multiple: false, title });
    return typeof res === "string" ? res : null;
  },
  pickFileToImport: async () => {
    const res = await open({ directory: false, multiple: false, title: "Select file to encrypt" });
    return typeof res === "string" ? res : null;
  },
  pickFilesToImport: async () => {
    const res = await open({ directory: false, multiple: true, title: "Select files to encrypt" });
    if (Array.isArray(res)) return res;
    return typeof res === "string" ? [res] : [];
  },
  pickExportDestination: async (defaultName) => {
    const res = await save({ defaultPath: defaultName, title: "Export decrypted copy" });
    return typeof res === "string" ? res : null;
  },
};

function createBrowserMockBackend(): Backend {
  let settings: AppSettings = { theme: "obsidian-dark", auto_lock_minutes: 10 };
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
    encryptStandaloneFile: async () => 2048,
    decryptStandaloneFile: async () => 2048,
    openCryptomatorVault: async (path) => ({
      path,
      format: 8,
      cipher_combo: "SIV_GCM",
      shortening_threshold: 220,
    }),
    closeCryptomatorVault: async () => true,
    listCryptomatorDir: async () => [],
    exportCryptomatorFile: async () => 1024,
    pickFolder: async () => "/synthetic/new-vault",
    pickFileToImport: async () => "/synthetic/sample.txt",
    pickFilesToImport: async () => ["/synthetic/sample.txt"],
    pickExportDestination: async (name) => `/synthetic/export/${name}`,
  };
}

export const backend: Backend = isTauriRuntime() ? tauriBackend : createBrowserMockBackend();
