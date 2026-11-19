import { describe, expect, it } from "vitest";
import { estimatedBits, MIN_PASSWORD_CHARS, passwordStrength } from "../password";

describe("password strength", () => {
  it("enforces minimum 12-character policy", () => {
    expect(MIN_PASSWORD_CHARS).toBe(12);
    const short = passwordStrength("Abc123!@#");
    expect(short.meetsPolicy).toBe(false);
    expect(short.score).toBe(0);
    expect(short.label).toBe("Too short");
  });

  it("penalizes low-diversity repeated characters", () => {
    const repeated = estimatedBits("aaaaaaaaaaaa");
    const diverse = estimatedBits("aB3$kL9!pQ2#");
    expect(diverse).toBeGreaterThan(repeated);
  });

  it("rates long high-entropy passphrases as strong or very strong", () => {
    const res = passwordStrength("Tr0ub4dor&3-Correct-Horse-99!");
    expect(res.meetsPolicy).toBe(true);
    expect(res.score).toBeGreaterThanOrEqual(3);
  });
});
