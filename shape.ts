/**
 * How a redacted value is described to the model when it asks for its SHAPE.
 *
 * The problem this solves: leakguard redacts a value, and the model then cannot
 * tell a false positive from a real leak, because it cannot see anything about
 * the matched text. It cannot decide whether to work around the block or stop.
 * In a real session that meant several files could never be inspected at all.
 *
 * A description answers the questions the model actually needs and reveals none
 * of the secret:
 *
 *   - which rule matched (already known)
 *   - how long the value is
 *   - which character classes it uses (digits, upper, lower, symbols)
 *   - whether it looks like a placeholder or prose
 *   - a short invariant prefix/suffix ONLY when that prefix is not itself secret
 *
 * A prefix is only echoed when it is a known, published vendor prefix (ghp_,
 * sk-, AKIA...). For an unknown format nothing is echoed — a 4-char prefix of a
 * random 40-char secret still leaks 4 characters, and that is 10 bits.
 */

/** Characters that are never part of a real credential: prose, ids, paths. */
const PLACEHOLDER_WORDS = /(?:your|xxxx|test|example|redacted|placeholder|dummy|fake|actual|sample|insert|changeme)/i;

/** Published vendor prefixes. Safe to echo because they identify the FORMAT,
 * not the secret — they appear in every public example of that credential. */
const KNOWN_PREFIXES = [
  "ghp_", "gho_", "ghs_", "ghu_", "ghr_", "github_pat_",
  "sk-ant-", "sk-proj-", "sk-",
  "xoxb-", "xoxp-", "xoxa-", "xoxr-", "xoxs-",
  "AKIA", "AIza", "hvs.", "glpat-", "npm_", "SG.",
];

export interface SecretShape {
  /** Number of characters in the matched value. */
  length: number;
  /** Character classes present. */
  hasDigit: boolean;
  hasUpper: boolean;
  hasLower: boolean;
  hasSymbol: boolean;
  /** True when the value contains an obvious placeholder word. */
  looksPlaceholder: boolean;
  /** True when the value is mostly hyphens/underscores — prose, not a key. */
  looksProse: boolean;
  /** Published vendor prefix, if the value starts with one. */
  knownPrefix?: string;
  /** Entropy bucket, not an exact number: an exact value leaks information. */
  entropyPerChar: "low" | "medium" | "high";
}

/** Shannon entropy per character, bucketed so the exact number is not exposed. */
function bucketEntropy(value: string): "low" | "medium" | "high" {
  const freq = new Map<string, number>();
  for (const ch of value) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / value.length;
    entropy -= p * Math.log2(p);
  }
  const bits = entropy;
  if (bits < 3) return "low";
  if (bits < 4.2) return "medium";
  return "high";
}

/**
 * Heuristic: a credential is never made of dictionary-ish words joined by
 * hyphens/underscores. "sk-intent-need" is 3 words; "sk-without-ide" is 2.
 */
function looksLikeProse(value: string, hasDigit: boolean, separators: number): boolean {
  if (hasDigit) return false;
  if (separators < 1) return false;
  // every separator-delimited segment is short and alphabetic -> words
  const segments = value.split(/[-_.]/).filter(Boolean);
  if (segments.length < 2) return false;
  const allWordy = segments.every((seg) => /^[A-Za-z]{2,}$/.test(seg));
  return allWordy;
}

export function describeSecretValue(value: string): SecretShape {
  const hasDigit = /[0-9]/.test(value);
  const hasUpper = /[A-Z]/.test(value);
  const hasLower = /[a-z]/.test(value);
  const hasSymbol = /[^A-Za-z0-9]/.test(value);
  const separators = (value.match(/[-_.]/g) ?? []).length;
  const knownPrefix = KNOWN_PREFIXES.find((p) => value.startsWith(p));

  return {
    length: value.length,
    hasDigit,
    hasUpper,
    hasLower,
    hasSymbol,
    looksPlaceholder: PLACEHOLDER_WORDS.test(value),
    // prose has many separators relative to length and few digits
    looksProse: looksLikeProse(value, hasDigit, separators),
    knownPrefix,
    entropyPerChar: bucketEntropy(value),
  };
}

/**
 * One-line human/model readable description. Deliberately never includes the
 * value, and never includes an unknown prefix.
 */
export function describeSecretShape(value: string): string {
  const s = describeSecretValue(value);
  const classes: string[] = [];
  if (s.hasLower) classes.push("lower");
  if (s.hasUpper) classes.push("upper");
  if (s.hasDigit) classes.push("digit");
  if (s.hasSymbol) classes.push("symbol");

  const parts = [
    `${s.length} chars`,
    classes.join("+") || "letters",
    `entropy ${s.entropyPerChar}`,
  ];
  if (s.knownPrefix) parts.push(`prefix "${s.knownPrefix}"`);
  if (s.looksPlaceholder) parts.push("contains a placeholder word");
  if (s.looksProse) parts.push("looks like prose or an identifier, not a key");

  return parts.join(", ");
}

/**
 * The model-facing note for describe mode: the shape plus what it implies.
 * This is the answer to "is this a false positive?" without revealing anything.
 */
export function describeNote(count: number, shapes: string[], rules: string[]): string {
  const ruleList = [...new Set(rules)].join(", ") || "unknown rule";
  const lines = [
    `[leakguard describe mode: ${count} redacted value(s) — ${ruleList}.`,
    ...shapes.map((s) => `  ${s}`),
    "]",
  ];
  const anyProse = shapes.some((s) => s.includes("placeholder") || s.includes("prose or an identifier"));
  if (anyProse) {
    lines.push(
      "A value that looks like prose, an identifier, or a placeholder is probably a FALSE POSITIVE.",
      "If so, work around it (do not retry the same call) and mention it to the human."
    );
  } else {
    lines.push(
      "The shape above is all you get. To act on the real value, ask the human for /leakguard allow-once."
    );
  }
  return lines.join("\n") + "\n";
}
