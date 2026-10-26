/**
 * Red-proof tests for the betterleaks engine swap.
 *
 * These exist to make the deletion of 31 hand-written regexes falsifiable. Each
 * test asserts a behaviour the OLD implementation produced, so a regression
 * shows up as a failure rather than as silent coverage loss in a security tool.
 *
 * Every credential fixture is generated at runtime: this file holds no literal
 * secret-shaped text, so it can itself be scanned (which is also why the tests
 * are written with concatenation rather than convenient literals).
 */

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  applyRedaction,
  detectAll,
  detectWithEngine,
  engineStatus,
  REDACTION_PLACEHOLDER,
  ruleName,
} from "./engine.js";

const status = engineStatus();
const hasEngine = status.available;
const skipReason = hasEngine ? "" : `engine unavailable: ${status.reason}`;
const engineTest = hasEngine ? test : test.skip;

const ALPHA = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
/** Deterministic high-entropy string, never a literal in this file. */
const gen = (n: number, seed = 0): string =>
  Array.from({ length: n }, (_, i) => ALPHA[(i * 17 + seed) % ALPHA.length]).join("");
const H = gen(36, 3);
const cc = (...codes: number[]): string => String.fromCharCode(...codes);
const B32 = "QY7Z3MK9NP5RT2WX";

// Prefixes assembled from codes: writing them literally is what a scanner (and
// this extension) is supposed to flag.
const P_GHP = cc(103, 104, 112, 95);
const P_GHO = cc(103, 104, 111, 95);
const P_GHS = cc(103, 104, 115, 95);
const P_AKIA = cc(65, 75, 73, 65);
const P_ASIA = cc(65, 83, 73, 65);
const P_XOXB = cc(120, 111, 120) + "b-";
const P_JWT_SEG1 = cc(101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 73, 85, 122, 73, 49, 78, 105, 74, 57, 85, 50, 86, 120, 78, 103);
const P_JWT_SEG2 = cc(101, 121, 74, 122, 100, 87, 73, 105, 79, 105, 73, 120, 73, 110, 48, 73, 105, 74, 112, 81, 87, 108, 48, 73, 106, 70, 57);

// ---------------------------------------------------------------------------
// Engine availability is itself a contract: a missing scanner must be visible.
// ---------------------------------------------------------------------------

test("engine status is reported, never assumed", () => {
  assert.equal(typeof status.available, "boolean");
  if (!status.available) {
    assert.ok(status.reason, "an unavailable engine must carry a reason");
    console.log("ENGINE UNAVAILABLE: " + skipReason);
  } else {
    assert.match(String(status.version), /^\d+\.\d+\.\d+$/);
    console.log(`engine ${status.version} pinned=${status.pinnedVersion} drifted=${status.drifted}`);
  }
});

// ---------------------------------------------------------------------------
// Every shape the hand-written list used to catch must still be caught.
// ---------------------------------------------------------------------------

const SHAPES: Array<[string, string]> = [
  ["AWS", P_AKIA + B32],
  ["AWS", P_ASIA + B32],
  ["OpenAI", "sk-" + H],
  ["Anthropic", "sk-ant-" + H],
  ["GitHub", P_GHP + H],
  ["GitHub", "github" + "_pat_" + H],
  ["GitHub", P_GHO + H],
  ["GitHub", P_GHS + H],
  ["GitLab", "glpat-" + H],
  ["Slack", P_XOXB + "1234567890-" + gen(10, 7)],
  ["Stripe", "sk" + "_live_" + H],
  ["npm", "npm" + "_" + H],
  ["Vault", "hvs." + H],
  ["DB URL", "postgres://u:" + H + "@db:5432/x"],
  ["JWT", P_JWT_SEG1 + "." + P_JWT_SEG2 + "." + H],
];

for (const [label, secret] of SHAPES) {
  engineTest(`detects ${label} shape`, () => {
    const { findings, error } = detectAll(`value=${secret}\n`);
    assert.equal(error, undefined, `engine error: ${error}`);
    assert.ok(findings.length > 0, `${label} was NOT detected`);
    assert.ok(
      findings.some((f) => f.value === secret || f.name.toLowerCase().includes(label.toLowerCase())),
      `no finding matched ${label}; got: ${findings.map((f) => f.name).join("|")}`
    );
  });
}

// ---------------------------------------------------------------------------
// The two shapes betterleaks does not cover. If these ever pass unflagged, the
// residual list was dropped by mistake.
// ---------------------------------------------------------------------------

const AUTHZ = cc(65, 117, 116, 104, 111, 114, 105, 122, 97, 116, 105, 111, 110);
const BEARER = cc(66, 101, 97, 114, 101, 114);
const OPAQUE = gen(40, 11);

engineTest("detects a bare auth header value (residual gap 1)", () => {
  const { findings } = detectAll(`${AUTHZ}: ${BEARER} ${OPAQUE}\n`);
  assert.ok(findings.length > 0, "bare auth header must still be detected");
  assert.ok(findings.some((f) => f.name === "Bearer Token"), "should name it Bearer Token");
});

engineTest("detects a 1Password op:// reference (residual gap 2)", () => {
  const { findings } = detectAll("r='op://vault/item/field'\n");
  assert.ok(findings.some((f) => f.name === "1Password Secret Ref"), "op:// must be detected");
});

// ---------------------------------------------------------------------------
// Redaction: the observable behaviour the model depends on.
// ---------------------------------------------------------------------------

engineTest("redaction replaces the value and keeps a readable label", () => {
  // Use a shape the engine actually targets. A bare high-entropy string is
  // deliberately NOT flagged by betterleaks (its generic rules need assignment
  // context), which is what removed the old 176 false positives on git SHAs.
  const secret = P_GHP + H;
  const text = `token MARK_A${secret}MARK_B done`;
  const { findings } = detectAll(text);
  const out = applyRedaction(text, findings);
  assert.ok(out.count > 0, "nothing was redacted");
  assert.ok(!out.text.includes(secret), "secret value survived redaction");
  assert.ok(out.text.includes(REDACTION_PLACEHOLDER), "placeholder missing");
  assert.ok(/— [A-Za-z]/.test(out.text), "redaction lost its human-readable name");
  assert.ok(out.text.includes("MARK_A"), "surrounding text was destroyed");
  assert.ok(out.text.includes("MARK_B"), "surrounding text was destroyed");
});

engineTest("multiple distinct secrets are all redacted", () => {
  const a = P_GHP + H;
  const b = "sk-" + H;
  const text = `one=${a}\ntwo=${b}\n`;
  const { findings } = detectAll(text);
  const out = applyRedaction(text, findings);
  assert.ok(!out.text.includes(a), "first secret survived");
  assert.ok(!out.text.includes(b), "second secret survived");
  assert.ok(out.count >= 2, `expected >=2 redactions, got ${out.count}`);
});

engineTest("redaction is stable across a second pass", () => {
  const text = `k=${P_GHP + H}\n`;
  const r1 = applyRedaction(text, detectAll(text).findings);
  const r2 = applyRedaction(r1.text, detectAll(r1.text).findings);
  assert.equal(r2.text, r1.text, "a second pass altered already-redacted text");
});

// ---------------------------------------------------------------------------
// False positives the old pattern list had to work around.
// ---------------------------------------------------------------------------

engineTest("git SHAs and ask-HASH identifiers are not flagged", () => {
  const noise = [
    "commit " + gen(40, 23).toLowerCase(),
    "ask-" + gen(20, 29).toLowerCase(),
    "my-task-" + gen(20, 31).toLowerCase(),
    "sk-learn is a python library",
  ];
  for (const n of noise) {
    const { findings } = detectAll(n + "\n");
    assert.equal(findings.length, 0, `false positive on: ${n} -> ${findings.map((f) => f.name)}`);
  }
});

// ---------------------------------------------------------------------------
// Failure modes must never read as "clean".
// ---------------------------------------------------------------------------

test("a missing binary yields an error, not an empty clean result", () => {
  const { findings, error } = detectWithEngine("anything", { bin: "/nonexistent/betterleaks" });
  assert.equal(findings.length, 0);
  assert.ok(error, "missing engine must produce an error");
  assert.match(error!, /unavailable/);
});

test("rule names are stable for ids the model already knows", () => {
  assert.equal(ruleName("github-pat"), "GitHub PAT");
  assert.equal(ruleName("lg-github-token"), "GitHub PAT");
  assert.equal(ruleName("private-key"), "Private Key Block");
  assert.equal(ruleName("some-new-rule"), "some new rule");
});
