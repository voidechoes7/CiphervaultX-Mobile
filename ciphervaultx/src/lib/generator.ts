export interface RandomPasswordOptions {
  length: number;
  lowercase: boolean;
  uppercase: boolean;
  digits: boolean;
  symbols: boolean;
  excludeAmbiguous: boolean;
}

export interface PassphraseOptions {
  wordCount: number;
  separator: "-" | "." | "_" | " ";
  capitalize: boolean;
  appendNumber: boolean;
}

export interface CrackEstimate {
  scenario: string;
  rateLabel: string;
  duration: string;
}

export interface GeneratedResult {
  value: string;
  entropyBits: number;
  rating: "Weak" | "Fair" | "Strong" | "Very Strong" | "Post-Quantum Ready";
  estimates: CrackEstimate[];
  recommendations: string[];
}

const LOWER = "abcdefghijklmnopqrstuvwxyz";
const UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS = "0123456789";
const SYMBOLS = "!@#$%^&*()-_=+[]{}:;,.?/";
const AMBIGUOUS = new Set(["O", "0", "I", "l", "1"]);

// Curated 256-word unambiguous list (8 bits per word) for offline passphrase generation.
const WORDLIST: readonly string[] = [
  "anchor", "apex", "arbor", "arctic", "argon", "armor", "arrow", "aspen",
  "atlas", "atom", "aurora", "axiom", "badge", "basalt", "beacon", "beryl",
  "binary", "bison", "blade", "blaze", "bolt", "boulder", "breeze", "bridge",
  "bronze", "canyon", "carbon", "castle", "cedar", "cipher", "citadel", "cliff",
  "cobalt", "comet", "compass", "condor", "copper", "coral", "corona", "crater",
  "crest", "crimson", "crown", "crystal", "cyber", "cyclone", "dagger", "delta",
  "desert", "diamond", "draco", "drift", "dune", "dynamo", "eagle", "echo",
  "eclipse", "ember", "emerald", "enigma", "epoch", "equinox", "falcon", "ferret",
  "fjord", "flame", "flint", "forest", "forge", "fortress", "fossil", "frost",
  "fusion", "galaxy", "garnet", "geyser", "glacier", "granite", "griffin", "harbor",
  "hawk", "helium", "helix", "horizon", "hydra", "iceberg", "ignite", "indigo",
  "ion", "iron", "island", "ivory", "jackal", "jade", "jaguar", "jasper",
  "javelin", "jet", "juniper", "karma", "kernel", "kestrel", "keystone", "kinetic",
  "knight", "krypton", "lagoon", "lancer", "lantern", "laser", "lattice", "laurel",
  "legend", "leopard", "lightning", "lithium", "lotus", "lunar", "lynx", "magma",
  "magnet", "mantis", "marble", "matrix", "meadow", "mercury", "meteor", "mirage",
  "monarch", "monolith", "monsoon", "mosaic", "nebula", "nectar", "neon", "nexus",
  "nickel", "nimbus", "nitrate", "nomad", "nova", "obsidian", "ocean", "octave",
  "omega", "onyx", "opal", "orbit", "orchid", "orion", "osprey", "oxide",
  "paladin", "panther", "paradox", "pegasus", "pendulum", "phantom", "phoenix", "photon",
  "pioneer", "planet", "plasma", "platinum", "polar", "portal", "prism", "proton",
  "pulsar", "puma", "pyramid", "python", "quantum", "quartz", "quasar", "quest",
  "quiver", "radar", "radium", "raptor", "raven", "reactor", "reef", "relic",
  "ridge", "river", "rocket", "ruby", "rune", "saber", "saffron", "sapphire",
  "saturn", "scarab", "scepter", "sector", "sentinel", "sequoia", "shadow", "shield",
  "sierra", "signal", "silicon", "silver", "sirius", "solstice", "sonar", "spark",
  "specter", "sphere", "sphinx", "spiral", "spruce", "starlight", "stealth", "stellar",
  "stone", "storm", "stratos", "summit", "sunburst", "surge", "sylvan", "synapse",
  "talon", "tempest", "terra", "thistle", "thunder", "tiger", "timber", "titan",
  "topaz", "torch", "torrent", "trident", "tundra", "turbine", "twilight", "typhoon",
  "ultra", "umbra", "valkyrie", "valley", "vanguard", "vector", "velvet", "vortex",
  "voyager", "vulcan", "warden", "whisper", "wildfire", "willow", "zenith", "zephyr",
];

/** Cryptographically secure unbiased integer in [0, max). */
export function secureRandomInt(max: number): number {
  if (max <= 1) return 0;
  const limit = Math.floor(0x100000000 / max) * max;
  const buf = new Uint32Array(1);
  while (true) {
    crypto.getRandomValues(buf);
    const val = buf[0] ?? 0;
    if (val < limit) {
      return val % max;
    }
  }
}

export function formatCrackDuration(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds <= 0) return "Instant";
  if (seconds < 1) return "< 1 second";
  if (seconds < 60) return `${Math.round(seconds)} seconds`;
  const minutes = seconds / 60;
  if (minutes < 60) return `${Math.round(minutes)} minutes`;
  const hours = minutes / 60;
  if (hours < 24) return `${Math.round(hours)} hours`;
  const days = hours / 24;
  if (days < 365.25) return `${Math.round(days)} days`;
  const years = days / 365.25;
  if (years < 1_000) return `${Math.round(years)} years`;
  if (years < 1_000_000) return `${(years / 1_000).toFixed(1)} thousand years`;
  if (years < 1_000_000_000) return `${(years / 1_000_000).toFixed(1)} million years`;
  if (years < 1e12) return `${(years / 1e9).toFixed(1)} billion years`;
  if (years < 1e15) return `${(years / 1e12).toFixed(1)} trillion years`;
  const log10Years = Math.floor(Math.log10(years));
  return `> 10^${log10Years} years (longer than age of universe)`;
}

export function buildCrackEstimates(entropyBits: number): CrackEstimate[] {
  // Average search space is 2^(bits - 1).
  const avgGuesses = Math.pow(2, Math.max(0, entropyBits - 1));
  // Quantum Grover search complexity ~ 2^(bits / 2) sequential oracle steps (10^9 ops/s hypothetical).
  const groverSteps = Math.pow(2, entropyBits / 2);

  return [
    {
      scenario: "Online throttled attack",
      rateLabel: "1,000 guesses/sec",
      duration: formatCrackDuration(avgGuesses / 1e3),
    },
    {
      scenario: "Offline GPU cluster vs Argon2id",
      rateLabel: "10,000 guesses/sec",
      duration: formatCrackDuration(avgGuesses / 1e4),
    },
    {
      scenario: "Massive offline rig (fast hash, no KDF)",
      rateLabel: "100 billion guesses/sec",
      duration: formatCrackDuration(avgGuesses / 1e11),
    },
    {
      scenario: "Theoretical quantum computer (Grover)",
      rateLabel: "10^9 quantum ops/sec",
      duration: formatCrackDuration(groverSteps / 1e9),
    },
  ];
}

export function rateEntropy(bits: number): GeneratedResult["rating"] {
  if (bits < 55) return "Weak";
  if (bits < 75) return "Fair";
  if (bits < 100) return "Strong";
  if (bits < 128) return "Very Strong";
  return "Post-Quantum Ready";
}

export function buildRecommendations(bits: number, isPassphrase: boolean): string[] {
  const recs: string[] = [];
  if (bits < 80) {
    recs.push("Increase length to reach at least 80–100 bits for offline vault protection.");
  } else if (bits < 128) {
    recs.push(
      "Strong against classical GPU clusters. Aim for ≥ 128 bits for maximum long-term & post-quantum margin."
    );
  } else {
    recs.push(
      "Exceeds 128 bits of entropy: mathematically intractable for both classical GPU farms and Grover quantum search."
    );
  }
  if (isPassphrase) {
    recs.push("Passphrases are easier to memorize and type on mobile keyboards than dense symbols.");
  } else {
    recs.push("Store high-entropy random passwords in an offline password manager (e.g. KeePassXC) — never in plaintext.");
  }
  recs.push("Never reuse your master vault password anywhere else, and always back up your one-time Recovery Key offline.");
  return recs;
}

export function generateRandomPassword(opts: RandomPasswordOptions): GeneratedResult {
  let pool = "";
  const requiredSets: string[] = [];

  const filter = (s: string) =>
    opts.excludeAmbiguous ? [...s].filter((c) => !AMBIGUOUS.has(c)).join("") : s;

  if (opts.lowercase) {
    const s = filter(LOWER);
    pool += s;
    requiredSets.push(s);
  }
  if (opts.uppercase) {
    const s = filter(UPPER);
    pool += s;
    requiredSets.push(s);
  }
  if (opts.digits) {
    const s = filter(DIGITS);
    pool += s;
    requiredSets.push(s);
  }
  if (opts.symbols) {
    const s = filter(SYMBOLS);
    pool += s;
    requiredSets.push(s);
  }
  if (!pool) {
    const fallback = filter(LOWER);
    pool = fallback;
    requiredSets.push(fallback);
  }

  const len = Math.max(12, Math.min(128, Math.round(opts.length)));
  const chars: string[] = [];
  for (const set of requiredSets) {
    if (chars.length < len && set.length > 0) {
      chars.push(set[secureRandomInt(set.length)] ?? "a");
    }
  }
  while (chars.length < len) {
    chars.push(pool[secureRandomInt(pool.length)] ?? "a");
  }
  // Fisher-Yates shuffle using CSPRNG.
  for (let i = chars.length - 1; i > 0; i--) {
    const j = secureRandomInt(i + 1);
    const tmp = chars[i] ?? "";
    chars[i] = chars[j] ?? "";
    chars[j] = tmp;
  }

  const value = chars.join("");
  const entropyBits = Math.round(len * Math.log2(pool.length));
  return {
    value,
    entropyBits,
    rating: rateEntropy(entropyBits),
    estimates: buildCrackEstimates(entropyBits),
    recommendations: buildRecommendations(entropyBits, false),
  };
}

export function generatePassphrase(opts: PassphraseOptions): GeneratedResult {
  const count = Math.max(4, Math.min(16, Math.round(opts.wordCount)));
  const words: string[] = [];
  for (let i = 0; i < count; i++) {
    let w = WORDLIST[secureRandomInt(WORDLIST.length)] ?? "vault";
    if (opts.capitalize) {
      w = w.charAt(0).toUpperCase() + w.slice(1);
    }
    words.push(w);
  }
  let extraBits = 0;
  if (opts.appendNumber) {
    const num = secureRandomInt(10_000);
    words.push(String(num).padStart(4, "0"));
    extraBits = Math.log2(10_000);
  }
  const value = words.join(opts.separator);
  const entropyBits = Math.round(count * Math.log2(WORDLIST.length) + extraBits);
  return {
    value,
    entropyBits,
    rating: rateEntropy(entropyBits),
    estimates: buildCrackEstimates(entropyBits),
    recommendations: buildRecommendations(entropyBits, true),
  };
}
