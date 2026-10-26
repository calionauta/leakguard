/**
 * llm-hints.test.ts - the guidance layer.
 *
 * These assert the property that matters: a block message must let the model
 * act in ONE retry. That means it names the pattern, points at the location,
 * and says what to do instead — and, on a repeat, that it says "stop retrying"
 * explicitly.
 */
import assert from "node:assert/strict";
import test from "node:test";

import {
  blockHeadline,
  blockMessage,
  escapeHatches,
  redactionNote,
  remedyFor,
  repeatWarning,
  searchPatternFalsePositive,
  searchPatternHint,
  REPEAT_BLOCK_THRESHOLD,
} from "./llm-hints.js";

test("headline names the pattern and the location when known", () => {
  const h = blockHeadline({ pattern: "GitHub PAT", location: "line 12", tool: "write" });
  assert.match(h, /"GitHub PAT"/, "must name the pattern");
  assert.match(h, /line 12/, "must give the location");
});

test("headline degrades gracefully when the pattern is unknown", () => {
  const h = blockHeadline({ tool: "bash" });
  assert.match(h, /secret-looking material/);
  assert.doesNotMatch(h, /undefined|null/);
});

test("a block message always carries a remedy and an escape hatch", () => {
  const msg = blockMessage({ pattern: "OpenAI API Key", tool: "write", location: "line 3" });
  assert.match(msg, /"OpenAI API Key"/);
  assert.match(msg, /allow-once/, "must tell the model the human escape hatch");
  assert.match(msg, /will not help/, "must preempt cosmetic retries");
});

test("remedies are pattern-specific, not one generic sentence", () => {
  const key = remedyFor("Private Key Block");
  const pw = remedyFor("Password Assignment");
  const generic = remedyFor("GitHub PAT");
  assert.notEqual(key, pw);
  assert.notEqual(key, generic);
  assert.match(key, /by path/, "private keys should be referenced, not copied");
  assert.match(pw, /names/i, "passwords: read key names only");
});

test("a path-guard block does not tell the model to rotate a credential", () => {
  // Regression: the path guards used to reuse the credential wording, so naming
  // a shell rc file produced "stop and ask the human to rotate it". Nothing was
  // read, there is no credential, and the advice sends the model down a useless
  // path (it cannot rotate what was never exposed).
  const msg = blockMessage({
    tool: "bash",
    pattern: "sensitive file (shell rc)",
    location: "grep reads 'file'",
  });
  assert.match(msg, /Nothing was read/, "must state that no value was exposed");
  assert.doesNotMatch(msg, /rotate it/, "must not suggest rotating a credential that was never read");
  assert.match(msg, /Name the file without opening it/, "must offer the applicable alternative");
});

test("repeat vs first attempt differ, and the repeat explicitly forbids retrying", () => {
  const first = blockMessage({ pattern: "GitHub PAT", tool: "write", attempts: 1 });
  const second = blockMessage({ pattern: "GitHub PAT", tool: "write", attempts: REPEAT_BLOCK_THRESHOLD });
  assert.notEqual(first, second);
  assert.match(second, /attempt 2/i);
  assert.match(second, /Stop retrying/i);
  assert.doesNotMatch(first, /Stop retrying/i, "first attempt should not be scolding");
});

test("repeatWarning says the syntax is not the problem", () => {
  const w = repeatWarning(3, { tool: "bash" });
  assert.match(w, /attempt 3/);
  assert.match(w, /NOT change the outcome/);
});

test("escape hatches are ordered cheapest-first", () => {
  const h = escapeHatches();
  const iProceed = h.indexOf("proceed without it");
  const iHuman = h.indexOf("allow-once");
  assert.ok(iProceed >= 0 && iHuman >= 0);
  assert.ok(iProceed < iHuman, "cheapest option (skip the value) must come first");
});

test("redaction note names the rules that fired", () => {
  const note = redactionNote(2, ["GitHub PAT", "API Key Assignment"]);
  assert.match(note, /2 secret\(s\)/);
  assert.match(note, /GitHub PAT/);
  assert.match(note, /API Key Assignment/);
  assert.match(note, /not an error/, "must not read as a failure");
});

test("redaction note deduplicates rule names", () => {
  const note = redactionNote(3, ["GitHub PAT", "GitHub PAT"]);
  assert.equal(note.match(/GitHub PAT/g)?.length, 1);
});

test("repeat redaction note tells the model re-running will not help", () => {
  const note = redactionNote(1, ["Slack Token"], true);
  assert.match(note, /will be redacted again/);
  assert.match(note, /will not reveal it/);
});

// ---------------------------------------------------------------------------
// The false positive that cost the most tokens: a sensitive token used as a
// SEARCH PATTERN, blocked as if it were a file path.
// ---------------------------------------------------------------------------

test("detects a regex search pattern containing a sensitive token", () => {
  const cmd = `grep -n "PATTERN|DOTENV|\\.env" security.ts`;
  const found = searchPatternFalsePositive(cmd, ".env");
  assert.ok(found, "should recognise this as a pattern, not a path");
  assert.match(found!, /DOTENV/);
});

test("does NOT treat a real path as a search pattern", () => {
  assert.equal(searchPatternFalsePositive("cat .env", ".env"), undefined);
  assert.equal(searchPatternFalsePositive("cat /home/u/.secrets/x.env", ".env"), undefined);
  assert.equal(searchPatternFalsePositive('cp .env /tmp/', ".env"), undefined);
});

test("does NOT fire on a quoted filename without regex metacharacters", () => {
  assert.equal(searchPatternFalsePositive(`cat ".env"`, ".env"), undefined);
  assert.equal(searchPatternFalsePositive(`grep foo ".env"`, ".env"), undefined);
});

test("search pattern hint offers a concrete workaround", () => {
  const hint = searchPatternHint("DOTENV|\\.env");
  assert.match(hint, /SEARCH PATTERN/);
  assert.match(hint, /false positive/);
  assert.match(hint, /grep -nE/);
  assert.match(hint, /DOTENV/, "workaround must be copy-pasteable");
});
