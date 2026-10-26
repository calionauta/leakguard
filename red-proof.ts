/**
 * red-proof.ts — run the OLD and NEW block messages side by side on the same
 * input, and show what the describe mode reveals about the file that could not
 * be inspected at all before.
 *
 * This is the missing test from the previous turn: the guidance code compiled
 * and its unit tests passed, but nobody had run it against the failures that
 * motivated it.
 */
import { blockMessage, remedyFor, escapeHatches } from "./llm-hints.js";
import { describeSecretShape } from "./shape.js";
import { SECRET_PATTERNS } from "./security.js";

const c = (...codes: number[]) => String.fromCharCode(...codes);
const GHP = c(103, 104, 112, 95);
const SK = c(115, 107, 45);
const BODY = "aB3xK9mQ2pL7vN4tR8yZ1cW6hJ5fD0sG2eU9";

const line = "=".repeat(74);
console.log(line);
console.log("1. OLD message (what the model actually received, worst case)");
console.log(line);
const OLD = "Blocked by pi-leakguard: write/edit payload contains secret-looking material";
console.log(OLD);
console.log("   -> no pattern, no line, no remedy. The only rational next step is a retry.");

console.log();
console.log(line);
console.log("2. NEW message, same input");
console.log(line);
const NEW = blockMessage({
  pattern: "GitHub PAT",
  masked: `line 12: TOKEN = "[GitHub PAT]"`,
  tool: "write",
  location: "write payload",
  attempts: 1,
});
console.log(NEW);

console.log();
console.log(line);
console.log("3. NEW message, SECOND attempt at the same intent");
console.log(line);
console.log(
  blockMessage({ pattern: "GitHub PAT", masked: "line 12: TOKEN = \"[GitHub PAT]\"", tool: "write", attempts: 2 })
);

console.log();
console.log(line);
console.log("4. The three failures that cost the most, with the NEW remedy");
console.log(line);
const cases: Array<[string, string]> = [
  ["write a test file containing a literal key prefix", "OpenAI API Key"],
  ["cat a .env to inspect it", "Password Assignment"],
  ["copy a private key into a doc", "Private Key Block"],
];
for (const [situation, pattern] of cases) {
  console.log(`  situation: ${situation}`);
  console.log(`  remedy   : ${remedyFor(pattern)}`);
  console.log();
}

console.log(line);
console.log("5. DESCRIBE MODE — the file that could not be inspected at all");
console.log(line);
console.log("   before: every read returned [LEAKGUARD_REDACTED], so the value's");
console.log("   nature was unknowable and the task was abandoned.");
console.log();
const samples: Array<[string, string]> = [
  ["a real-looking GitHub PAT", GHP + BODY],
  ["prose that looks like a prefix", SK + "intent-need"],
  ["a documented placeholder", SK + "proj-" + "your-actual-openai-key"],
  ["an unknown 40-char blob", "Zq7" + BODY],
];
for (const [label, val] of samples) {
  console.log(`   ${label.padEnd(34)} -> ${describeSecretShape(val)}`);
}

console.log();
console.log(line);
console.log("6. Escape hatches offered to the model (cheapest first)");
console.log(line);
console.log(escapeHatches());
