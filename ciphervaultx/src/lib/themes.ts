export type ThemeId =
  | "obsidian-dark"
  | "arctic-light"
  | "midnight-blue"
  | "oled-black"
  | "emerald"
  | "system";

export type ColorMode = "dark" | "light";

export interface ThemeMeta {
  id: ThemeId;
  label: string;
  description: string;
  mode: ColorMode | "system";
}

export const THEME_STORAGE_KEY = "cvx-theme";

export const THEMES: readonly ThemeMeta[] = [
  {
    id: "obsidian-dark",
    label: "Obsidian Dark",
    description: "Neutral dark slate for focused daily use",
    mode: "dark",
  },
  {
    id: "arctic-light",
    label: "Arctic Light",
    description: "Crisp high-contrast daylight workspace",
    mode: "light",
  },
  {
    id: "midnight-blue",
    label: "Midnight Blue",
    description: "Deep navy tones with restrained blue accents",
    mode: "dark",
  },
  {
    id: "oled-black",
    label: "OLED Black",
    description: "True black background for high-contrast displays",
    mode: "dark",
  },
  {
    id: "emerald",
    label: "Emerald",
    description: "Dark forest surface with subtle emerald focus",
    mode: "dark",
  },
  {
    id: "system",
    label: "System Adaptive",
    description: "Follows operating system light or dark appearance",
    mode: "system",
  },
] as const;

export function isValidTheme(value: string): value is ThemeId {
  return THEMES.some((t) => t.id === value);
}

export function resolveMode(theme: ThemeId, prefersDark?: boolean): ColorMode {
  if (theme === "arctic-light") return "light";
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
    theme === "system" ? (mode === "dark" ? "obsidian-dark" : "arctic-light") : theme;

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
  return "obsidian-dark";
}
