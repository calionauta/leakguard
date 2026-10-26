/**
 * llm-hints.ts - Everything leakguard says to the model when it blocks something.
 *
 * The design rule here is one sentence: every block must answer three
 * questions in the message itself —
 *
 *   1. WHAT matched   (pattern name, not "secret-looking material")
 *   2. WHERE it is    (tool, argument role, line number, masked excerpt)
 *   3. WHAT TO DO     (a concrete alternative, or "stop, ask the human")
 *
 * Why this file exists: a real session spent 8 blocked tool calls and three
 * full rewrites of the same file because the block text named neither the
 * pattern nor the location. The model could only guess, retry, and guess
 * again. Those retries cost tokens and never converged. See
 * docs/leakguard-token-burn.md for the transcript-level evidence.
 *
 * Kept free of pi/ExtensionAPI imports so it is trivially unit-testable.
 */

import { REDACTION_PLACEHOLDER } from "./security.js";

/** How many times the same intent may be blocked before the message changes tack. */
export const REPEAT_BLOCK_THRESHOLD = 2;

export interface BlockContext {
  /** Pattern name, e.g. "GitHub PAT". Omitted when unknown. */
  pattern?: string;
  /** Where the match was found, e.g. "line 12", "argument 2", "path check". */
  location?: string;
  /** The offending text with the secret already masked. */
  masked?: string;
  /** Tool that was blocked. */
  tool?: string;
  /** How many times this same tool+intent has already been blocked. */
  attempts?: number;
}

/**
 * The header line. Always names the pattern when known — a bare
 * "secret-looking material" is what caused blind retries.
 */
export function blockHeadline(ctx: BlockContext): string {
  const what = ctx.pattern ? `"${ctx.pattern}"` : "secret-looking material";
  const where = ctx.location ? ` at ${ctx.location}` : "";
  return `leakguard blocked this ${ctx.tool ?? "call"}: found ${what}${where}.`;
}

/**
 * What the model should do instead. Chosen by pattern family so the advice is
 * actually applicable — telling someone to "build the string at runtime" is
 * useless advice for a private key block, and telling them to "rotate it" is
 * useless for a test fixture.
 */
export function remedyFor(pattern?: string): string {
  const p = (pattern ?? "").toLowerCase();

  // Path guards fire on FILES, not values. Sending the model to "rotate the
  // credential" here is wrong advice that also reads as "this is your fault":
  // nothing was read, and the usual reason is a shell rc / env file that the
  // command merely named.
  if (p.includes("sensitive file") || p.includes("sensitive path")) {
    return "Nothing was read, so no credential was exposed. Name the file without opening it (paths in a listing, a count, a yes/no check), or ask the human for the specific non-secret values you need.";
  }
  if (p.includes("private key") || p.includes("pem")) {
    return "Do not print, copy, or transcribe key material. Reference the file by path and let the human use it where it belongs.";
  }
  if (p.includes("password") || p.includes("credential") || p.includes("db url") || p.includes("url")) {
    return "Do not read the value. Read the KEY NAMES only (e.g. `grep -o '^[A-Z_]*=' file`), or ask the human to confirm the shape.";
  }
  if (p.includes("assignment")) {
    return "This looks like KEY=value where the value is secret. If you are writing a config or test fixture, use an obvious placeholder (`your-key-here`) or build the value at runtime.";
  }
  return "If this is a test fixture or a rule definition, build the string at runtime (string concatenation or character codes) instead of committing or echoing a literal. If it is a real credential, stop and ask the human to rotate it.";
}

/**
 * The remedies a model can actually take. Listed in the order a model should
 * try them, because models otherwise jump straight to the most destructive
 * option (rewriting the whole file) or to the loop that never converges
 * (re-sending the same call with cosmetic changes).
 */
export function escapeHatches(): string {
  return [
    "Options, cheapest first:",
    "  1. Do not need the value — proceed without it (most tasks do).",
    "  2. Need to know it exists/shape only — ask for names, counts, or a yes/no check.",
    "  3. Need the actual value — ask the human to run `/leakguard allow-once`.",
    `Note: retrying with different quoting, variable indirection, or \`${REDACTION_PLACEHOLDER}\` will not help. The check is on the VALUE, not the syntax.`,
  ].join("\n");
}

/**
 * The line that actually stops the retry loop. Explicitly tells the model that
 * the next attempt will fail the same way, which is the piece of information
 * it cannot derive from a single failure.
 */
export function repeatWarning(attempts: number, ctx: BlockContext): string {
  return [
    `This is attempt ${attempts} at the same operation.`,
    "Changing the command's syntax will NOT change the outcome — the check is about the value, not the spelling.",
    "Stop retrying. Either solve it without the value, or ask the human.",
  ].join(" ");
}

/**
 * Full block message for a tool call. `attempts` comes from per-turn state so
 * the third identical block reads differently from the first.
 */
export function blockMessage(ctx: BlockContext): string {
  const parts = [blockHeadline(ctx)];
  if (ctx.masked) {
    parts.push(`  ${ctx.masked}`);
  }
  if ((ctx.attempts ?? 0) >= REPEAT_BLOCK_THRESHOLD) {
    parts.push("", repeatWarning(ctx.attempts ?? 0, ctx));
  }
  parts.push("", remedyFor(ctx.pattern), "", escapeHatches());
  return parts.join("\n");
}

/**
 * Note prepended to redacted tool output. The old note was correct but told the
 * model to "ask the human" even on the first redaction, which reads as a
 * dead end; it also only counted secrets, never saying which rules fired.
 */
export function redactionNote(count: number, ruleNames: string[], repeat = false): string {
  const rules = ruleNames.length > 0 ? ` (${[...new Set(ruleNames)].join(", ")})` : "";
  const lines = [
    `[leakguard: ${count} secret(s) redacted${rules} — this is security, not an error.`,
  ];
  if (repeat) {
    lines.push(
      "This value was redacted before and will be redacted again. Re-running the same command will not reveal it."
    );
  }
  lines.push(
    "The task usually does not need the value. If it truly does, the human can run `/leakguard allow-once`.]"
  );
  return lines.join("\n") + "\n";
}

/**
 * Detects the specific false-positive shape that cost the most in practice:
 * a sensitive-looking string used as a SEARCH PATTERN rather than as a path or
 * a value. `grep -n 'DOTENV|\.env' file.ts` was blocked as a path access, and
 * the model then read a 583-line file instead — 5x the tokens the grep would
 * have cost.
 *
 * Returns the pattern text to suggest splitting, or undefined if the command
 * does not look like this shape.
 */
export function searchPatternFalsePositive(command: string, sensitiveHit: string): string | undefined {
  // only meaningful when the hit sits inside a quoted search pattern
  const quoted = command.match(/(?:'([^']*)'|"([^"]*)")/g);
  if (!quoted) return undefined;
  for (const q of quoted) {
    if (!q.includes(sensitiveHit)) continue;
    const inner = q.slice(1, -1);
    // a quoted argument with alternation / regex metacharacters is a pattern,
    // not a path: no sane path contains these
    if (/[|]|\\\.|\\\/|\*|\?\[|\(\?:|\[\^/.test(inner)) {
      return inner;
    }
  }
  return undefined;
}

/**
 * Advice shown when the sensitive string was only a search pattern.
 */
export function searchPatternHint(split: string): string {
  const first = split.split("|")[0] ?? split;
  // Suggest the split-in-two spelling ("DOT" + "ENV") so the retry does not
  // re-trigger the same path check.
  const softened = first.replace(/\.env/gi, "DOT" + "ENV");
  return [
    `This looks like a SEARCH PATTERN, not a file access: "${split}".`,
    "If so, this block is a false positive. Retry with the token split in two:",
    `  grep -nE '${softened}[|]...' <file>`,
    "  or search for a substring that does not contain the sensitive token.",
  ].join("\n");
}
