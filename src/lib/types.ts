/**
 * Strict TypeScript domain models and theme definitions for CipherVault-X.
 */

export type ThemeId =
  | "obsidian-dark"
  | "arctic-light"
  | "midnight-blue"
  | "oled-black"
  | "emerald"
  | "system-adaptive";

export interface ThemeSpec {
  id: ThemeId;
  label: string;
  tagline: string;
  swatch: string;
}

export const THEMES: readonly ThemeSpec[] = [
  {
    id: "obsidian-dark",
    label: "Obsidian Dark",
    tagline: "Deep slate surfaces with indigo cryptographic accents",
    swatch: "#6366f1",
  },
  {
    id: "arctic-light",
    label: "Arctic Light",
    tagline: "Crisp high-contrast daylight paper with cobalt focus",
    swatch: "#2563eb",
  },
  {
    id: "midnight-blue",
    label: "Midnight Blue",
    tagline: "Naval command palette with cyan telemetry highlights",
    swatch: "#38bdf8",
  },
  {
    id: "oled-black",
    label: "OLED Black",
    tagline: "True #000000 zero-emission background with violet edge",
    swatch: "#a855f7",
  },
  {
    id: "emerald",
    label: "Emerald",
    tagline: "High-assurance hardware-HSM green on carbon",
    swatch: "#10b981",
  },
  {
    id: "system-adaptive",
    label: "System Adaptive",
    tagline: "Automatically tracks OS prefers-color-scheme",
    swatch: "#64748b",
  },
] as const;

export interface VaultMeta {
  id: string;
  name: string;
  path: string;
  unlocked: boolean;
  createdAt: number;
  mirrorPath: string | null;
}

export type EntryKind = "file" | "directory";

export interface VaultEntry {
  name: string;
  path: string;
  kind: EntryKind;
  size: number | null;
  modified: number | null;
}

export interface IntegrityProblem {
  location: string;
  error: string;
}

export interface IntegrityReport {
  directories: number;
  files: number;
  bytesVerified: number;
  problems: IntegrityProblem[];
}

export interface SyncSummary {
  provider: string;
  uploaded: number;
  downloaded: number;
  unchanged: number;
  bytesTransferred: number;
  mirrorPath?: string;
}

export interface CiphertextObject {
  relPath: string;
  size: number;
  sha1: string;
}
