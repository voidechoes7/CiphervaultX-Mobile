import { describe, expect, it } from "vitest";
import {
  formatCrackDuration,
  generatePassphrase,
  generateRandomPassword,
} from "../generator";

describe("password generator", () => {
  it("generates high-entropy random passwords meeting requested length", () => {
    const res = generateRandomPassword({
      length: 24,
      lowercase: true,
      uppercase: true,
      digits: true,
      symbols: true,
      excludeAmbiguous: false,
    });
    expect(res.value.length).toBe(24);
    expect(res.entropyBits).toBeGreaterThanOrEqual(128);
    expect(res.rating).toBe("Post-Quantum Ready");
    expect(res.estimates.length).toBe(4);
  });

  it("excludes ambiguous characters when requested", () => {
    const res = generateRandomPassword({
      length: 40,
      lowercase: true,
      uppercase: true,
      digits: true,
      symbols: false,
      excludeAmbiguous: true,
    });
    expect(res.value).not.toMatch(/[O0Il1]/);
  });

  it("generates passphrases with expected word count and entropy", () => {
    const res = generatePassphrase({
      wordCount: 10,
      separator: "-",
      capitalize: true,
      appendNumber: true,
    });
    expect(res.value.split("-").length).toBe(11);
    expect(res.entropyBits).toBeGreaterThanOrEqual(90);
  });

  it("formats crack durations cleanly across scales", () => {
    expect(formatCrackDuration(0.2)).toBe("< 1 second");
    expect(formatCrackDuration(3600 * 5)).toBe("5 hours");
    expect(formatCrackDuration(1e30)).toContain("10^");
  });
});
