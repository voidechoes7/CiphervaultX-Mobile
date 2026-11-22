import { describe, expect, it, beforeEach } from "vitest";
import {
  applyTheme,
  loadTheme,
  nextQuickTheme,
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
});
