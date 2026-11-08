/**
 * Unified IPC client for CipherVault-X.
 *
 * Uses Tauri 2 `@tauri-apps/api/core` `invoke` when running inside the Tauri WebView,
 * and seamlessly falls back to the local `ciphervaultd` JSON-RPC endpoint (`/api/rpc`)
 * when running in browser preview / headless integration tests.
 */

import type {
  CiphertextObject,
  IntegrityReport,
  SyncSummary,
  VaultEntry,
  VaultMeta,
} from "./types";

declare global {
  interface Window {
    __TAURI_INTERNALS__?: {
      invoke: <T>(cmd: string, args?: Record<string, unknown>) => Promise<T>;
    };
  }
}

async function callBackend<T>(
  cmd: string,
  args: Record<string, string | number | boolean> = {}
): Promise<T> {
  if (typeof window !== "undefined" && window.__TAURI_INTERNALS__?.invoke) {
    return window.__TAURI_INTERNALS__.invoke<T>(cmd, args);
  }
  const resp = await fetch("/api/rpc", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ cmd, ...args }),
  });
  const payload = (await resp.json()) as {
    ok: boolean;
    data?: T;
    error?: string;
  };
  if (!payload.ok) {
    throw new Error(payload.error || `RPC command ${cmd} failed`);
  }
  return payload.data as T;
}

export const VaultApi = {
  listVaults: () => callBackend<VaultMeta[]>("list_vaults"),

  createVault: (name: string, path: string, password: string) =>
    callBackend<VaultMeta>("create_vault", { name, path, password }),

  unlockVault: (id: string, password: string) =>
    callBackend<VaultMeta>("unlock_vault", { id, password }),

  lockVault: (id: string) => callBackend<null>("lock_vault", { id }),

  lockAllVaults: () => callBackend<null>("lock_all_vaults"),

  listEntries: (id: string, vpath: string) =>
    callBackend<VaultEntry[]>("list_entries", { id, vpath }),

  createFolder: (id: string, vpath: string) =>
    callBackend<VaultEntry>("create_folder", { id, vpath }),

  writeFileBase64: (id: string, vpath: string, dataB64: string) =>
    callBackend<VaultEntry>("write_file_base64", { id, vpath, dataB64 }),

  readPreviewBase64: (id: string, vpath: string) =>
    callBackend<string>("read_preview_base64", { id, vpath }),

  renameEntry: (id: string, fromVpath: string, toVpath: string) =>
    callBackend<VaultEntry>("rename_entry", { id, fromVpath, toVpath }),

  deleteEntry: (id: string, vpath: string) =>
    callBackend<null>("delete_entry", { id, vpath }),

  searchVault: (id: string, query: string, under = "/") =>
    callBackend<VaultEntry[]>("search_vault", { id, query, under }),

  checkVaultIntegrity: (id: string) =>
    callBackend<IntegrityReport>("check_vault_integrity", { id }),

  syncVaultMirror: (id: string, mirrorPath = "") =>
    callBackend<SyncSummary>("sync_vault_mirror", { id, mirrorPath }),

  changePassword: (id: string, oldPassword: string, newPassword: string) =>
    callBackend<null>("change_password", { id, oldPassword, newPassword }),

  inspectCiphertextTree: (id: string) =>
    callBackend<CiphertextObject[]>("inspect_ciphertext_tree", { id }),
};
