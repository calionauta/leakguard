/**
 * Apply describe mode to the actual picoclaw file that could not be inspected.
 *
 * Before: every read returned [LEAKGUARD_REDACTED], so whether the finding was a
 * real key or a documented placeholder was unknowable, and the borrow was
 * abandoned. Now the shape should answer it.
 */
import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { SECRET_PATTERNS } from "./security.js";
import { describeSecretShape } from "./shape.js";

const target = process.argv[2];
if (!target) {
  console.error("usage: tsx describe-file.ts <path>");
  process.exit(1);
}

const text = readFileSync(target, "utf8");
console.log(`file: ${target.replace(homedir(), "~")}  (${text.length} bytes)`);
console.log("=".repeat(74));

let found = 0;
for (const pat of SECRET_PATTERNS) {
  const rx = new RegExp(pat.pattern.source, pat.pattern.flags);
  for (const m of text.matchAll(rx)) {
    found++;
    const shape = describeSecretShape(m[0]);
    // show the rule and the SHAPE only — never the value
    const idx = m.index ?? 0;
    const line = text.slice(0, idx).split("\n").length;
    console.log(`  rule:  ${pat.name}`);
    console.log(`  line:  ${line}`);
    console.log(`  shape: ${shape}`);
    console.log();
  }
}
if (found === 0) console.log("  no pattern matched");
console.log("=".repeat(74));
console.log(`total: ${found} value(s) — described, never revealed`);
