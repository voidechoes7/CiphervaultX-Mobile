export type ThemeId =
  | "neon-cyber"
  | "obsidian-dark"
  | "midnight-blue"
  | "oled-black"
  | "emerald"
  | "crimson-sentinel"
  | "arctic-light"
  | "nordic-paper"
  | "solar-sand"
  | "system";

export type ColorMode = "dark" | "light";

export interface ThemeMeta {
  id: ThemeId;
  label: string;
  description: string;
  mode: ColorMode | "system";
  swatches: readonly [string, string, string];
}

export const THEME_STORAGE_KEY = "cvx-theme";

export const THEMES: readonly ThemeMeta[] = [
  {
    id: "neon-cyber",
    label: "Neon Cyber X",
    description: "Deep cyber void with electric cyan glow",
    mode: "dark",
    swatches: ["#070b18", "#101830", "#00e5ff"],
  },
  {
    id: "obsidian-dark",
    label: "Obsidian Dark",
    description: "Neutral dark slate for focused daily use",
    mode: "dark",
    swatches: ["#0f141e", "#171f2e", "#dce6f2"],
  },
  {
    id: "midnight-blue",
    label: "Midnight Blue",
    description: "Deep navy tones with sapphire accents",
    mode: "dark",
    swatches: ["#0c1324", "#121d36", "#58a6ff"],
  },
  {
    id: "oled-black",
    label: "OLED Black",
    description: "True pitch black for OLED displays & battery",
    mode: "dark",
    swatches: ["#000000", "#0d0d0d", "#f5f5f5"],
  },
  {
    id: "emerald",
    label: "Emerald Matrix",
    description: "Dark forest carbon with crisp emerald focus",
    mode: "dark",
    swatches: ["#0c1714", "#13221d", "#29c78b"],
  },
  {
    id: "crimson-sentinel",
    label: "Crimson Sentinel",
    description: "Tactical charcoal with sharp crimson accents",
    mode: "dark",
    swatches: ["#140c10", "#1f1318", "#f43f5e"],
  },
  {
    id: "arctic-light",
    label: "Arctic Light",
    description: "Crisp high-contrast porcelain daylight UI",
    mode: "light",
    swatches: ["#f7f9fc", "#ffffff", "#2563eb"],
  },
  {
    id: "nordic-paper",
    label: "Nordic Paper",
    description: "Warm Scandinavian stone with deep indigo",
    mode: "light",
    swatches: ["#f5f3ef", "#ffffff", "#4338ca"],
  },
  {
    id: "solar-sand",
    label: "Solar Sand",
    description: "Soft warm cream & teal, gentle on the eyes",
    mode: "light",
    swatches: ["#faf5ea", "#fffdf8", "#0d9488"],
  },
  {
    id: "system",
    label: "System Adaptive",
    description: "Follows operating system light or dark mode",
    mode: "system",
    swatches: ["#0f141e", "#f7f9fc", "#3b82f6"],
  },
] as const;

const LIGHT_THEMES: ReadonlySet<ThemeId> = new Set([
  "arctic-light",
  "nordic-paper",
  "solar-sand",
]);

export function isValidTheme(value: string): value is ThemeId {
  return THEMES.some((t) => t.id === value);
}

export function resolveMode(theme: ThemeId, prefersDark?: boolean): ColorMode {
  if (LIGHT_THEMES.has(theme)) return "light";
  if (theme === "system") {
    const dark =
      typeof prefersDark === "boolean"
        ? prefersDark
        : typeof window !== "undefined" &&
          typeof window.matchMedia === "function" &&
          window.matchMedia("(prefers-color-scheme: dark)").matches;
    return dark ? "dark" : "light";
  }
  return "dark";
}

export function applyTheme(theme: ThemeId, prefersDark?: boolean): ColorMode {
  const mode = resolveMode(theme, prefersDark);
  const effectiveTheme =
    theme === "system" ? (mode === "dark" ? "neon-cyber" : "arctic-light") : theme;

  if (typeof document !== "undefined") {
    const root = document.documentElement;
    root.setAttribute("data-theme", effectiveTheme);
    root.setAttribute("data-mode", mode);
  }
  if (typeof localStorage !== "undefined") {
    try {
      localStorage.setItem(THEME_STORAGE_KEY, theme);
    } catch {
      // Ignore storage restrictions
    }
  }
  return mode;
}

export function loadTheme(): ThemeId {
  if (typeof localStorage !== "undefined") {
    try {
      const saved = localStorage.getItem(THEME_STORAGE_KEY);
      if (saved && isValidTheme(saved)) {
        return saved;
      }
    } catch {
      // Ignore storage restrictions
    }
  }
  return "neon-cyber";
}

export function nextQuickTheme(current: ThemeId): ThemeId {
  const mode = resolveMode(current);
  return mode === "dark" ? "arctic-light" : "neon-cyber";
}
