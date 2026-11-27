import { describe, expect, it, beforeEach } from "vitest";
import {
  applyTheme,
  applyUiStyle,
  isValidUiStyle,
  loadTheme,
  loadUiStyle,
  nextQuickTheme,
  resolveMode,
  THEMES,
  THEME_STORAGE_KEY,
  UI_STYLES,
  UI_STYLE_STORAGE_KEY,
} from "../themes";

describe("themes", () => {
  beforeEach(() => {
    localStorage.clear();
    document.documentElement.removeAttribute("data-theme");
    document.documentElement.removeAttribute("data-mode");
    document.documentElement.removeAttribute("data-ui-style");
  });

  it("defines all ten light, dark, and adaptive themes", () => {
    const ids = THEMES.map((t) => t.id);
    expect(ids).toEqual([
      "neon-cyber",
      "obsidian-dark",
      "midnight-blue",
      "oled-black",
      "emerald",
      "crimson-sentinel",
      "arctic-light",
      "nordic-paper",
      "solar-sand",
      "system",
    ]);
  });

  it("resolves mode correctly for explicit light, dark, and system themes", () => {
    expect(resolveMode("neon-cyber")).toBe("dark");
    expect(resolveMode("obsidian-dark")).toBe("dark");
    expect(resolveMode("crimson-sentinel")).toBe("dark");
    expect(resolveMode("arctic-light")).toBe("light");
    expect(resolveMode("nordic-paper")).toBe("light");
    expect(resolveMode("solar-sand")).toBe("light");
    expect(resolveMode("system", true)).toBe("dark");
    expect(resolveMode("system", false)).toBe("light");
  });

  it("applies, persists, and quick-toggles theme selection", () => {
    applyTheme("emerald");
    expect(document.documentElement.getAttribute("data-theme")).toBe("emerald");
    expect(document.documentElement.getAttribute("data-mode")).toBe("dark");
    expect(localStorage.getItem(THEME_STORAGE_KEY)).toBe("emerald");
    expect(loadTheme()).toBe("emerald");
    expect(nextQuickTheme("emerald")).toBe("arctic-light");

    applyTheme("system", false);
    expect(document.documentElement.getAttribute("data-theme")).toBe("arctic-light");
    expect(document.documentElement.getAttribute("data-mode")).toBe("light");
    expect(loadTheme()).toBe("system");
    expect(nextQuickTheme("arctic-light")).toBe("neon-cyber");
  });

  it("defines and persists all four interface styles for light and dark modes", () => {
    expect(UI_STYLES.map((s) => s.id)).toEqual([
      "liquid-glass",
      "modern-vault",
      "swiss-minimal",
      "cyber-neon",
    ]);
    expect(isValidUiStyle("liquid-glass")).toBe(true);
    expect(isValidUiStyle("unknown-style")).toBe(false);
    expect(loadUiStyle()).toBe("modern-vault");

    applyUiStyle("swiss-minimal");
    expect(document.documentElement.getAttribute("data-ui-style")).toBe("swiss-minimal");
    expect(localStorage.getItem(UI_STYLE_STORAGE_KEY)).toBe("swiss-minimal");
    expect(loadUiStyle()).toBe("swiss-minimal");
  });
});
