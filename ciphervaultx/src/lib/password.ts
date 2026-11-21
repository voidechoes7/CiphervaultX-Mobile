export const MIN_PASSWORD_CHARS = 12;

export type StrengthLabel = "Too short" | "Weak" | "Fair" | "Strong" | "Very strong";

export interface PasswordAssessment {
  bits: number;
  score: 0 | 1 | 2 | 3 | 4;
  label: StrengthLabel;
  meetsPolicy: boolean;
}

export function estimatedBits(password: string): number {
  const len = [...password].length;
  if (len === 0) return 0;

  let charset = 0;
  if (/[a-z]/.test(password)) charset += 26;
  if (/[A-Z]/.test(password)) charset += 26;
  if (/[0-9]/.test(password)) charset += 10;
  if (/[^a-zA-Z0-9]/.test(password)) charset += 32;
  if (charset === 0) charset = 26;

  // Discount trivial repetition so "aaaaaaaaaaaa" never looks strong.
  const unique = new Set([...password]).size;
  const diversityFactor = Math.min(1, unique / Math.max(1, Math.min(len, 12)));
  return Math.round(len * Math.log2(charset) * (0.4 + 0.6 * diversityFactor));
}

export function passwordStrength(password: string): PasswordAssessment {
  const len = [...password].length;
  const bits = estimatedBits(password);
  const meetsPolicy = len >= MIN_PASSWORD_CHARS;

  if (!meetsPolicy) {
    return { bits, score: 0, label: "Too short", meetsPolicy: false };
  }
  if (bits < 55) {
    return { bits, score: 1, label: "Weak", meetsPolicy: true };
  }
  if (bits < 75) {
    return { bits, score: 2, label: "Fair", meetsPolicy: true };
  }
  if (bits < 100) {
    return { bits, score: 3, label: "Strong", meetsPolicy: true };
  }
  return { bits, score: 4, label: "Very strong", meetsPolicy: true };
}
