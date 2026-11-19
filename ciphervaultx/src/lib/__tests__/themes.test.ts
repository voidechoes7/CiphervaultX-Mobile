import { describe, expect, it, beforeEach } from "vitest";
import {
  applyTheme,
  loadTheme,
  resolveMode,
  THEMES,
  THEME_STORAGE_KEY,
} from "../themes";

describe("themes", () => {
  beforeEach(() => {
    localStorage.clear();
    document.documentElement.removeAttribute("data-theme");
    document.documentElement.removeAttribute("data-mode");
  });

  it("defines all six required themes", () => {
    const ids = THEMES.map((t) => t.id);
    expect(ids).toEqual([
      "obsidian-dark",
      "arctic-light",
      "midnight-blue",
      "oled-black",
      "emerald",
      "system",
    ]);
  });

  it("resolves mode correctly for explicit and system themes", () => {
    expect(resolveMode("obsidian-dark")).toBe("dark");
    expect(resolveMode("arctic-light")).toBe("light");
    expect(resolveMode("oled-black")).toBe("dark");
    expect(resolveMode("system", true)).toBe("dark");
    expect(resolveMode("system", false)).toBe("light");
  });

  it("applies and persists theme selection", () => {
    applyTheme("emerald");
    expect(document.documentElement.getAttribute("data-theme")).toBe("emerald");
    expect(document.documentElement.getAttribute("data-mode")).toBe("dark");
    expect(localStorage.getItem(THEME_STORAGE_KEY)).toBe("emerald");
    expect(loadTheme()).toBe("emerald");

    applyTheme("system", false);
    expect(document.documentElement.getAttribute("data-theme")).toBe("arctic-light");
    expect(document.documentElement.getAttribute("data-mode")).toBe("light");
    expect(loadTheme()).toBe("system");
  });
});
