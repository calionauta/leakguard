/**
 * shape.test.ts — the describe mode.
 *
 * The contract has two halves and both matter:
 *   1. it must reveal enough to decide "real or false positive"
 *   2. it must reveal NOTHING about the actual secret
 */
import assert from "node:assert/strict";
import test from "node:test";

import {
  describeSecretShape,
  describeSecretValue,
  describeNote,
} from "./shape.js";

const c = (...codes: number[]) => String.fromCharCode(...codes);
const GHP = c(103, 104, 112, 95);
const SK = c(115, 107, 45);
const AKIA = c(65, 75, 73, 65);
const BODY = "aB3xK9mQ2pL7vN4tR8yZ1cW6hJ5fD0sG2eU9";

test("a real key reports length, classes, entropy and vendor prefix", () => {
  const v = GHP + BODY;
  const s = describeSecretValue(v);
  assert.equal(s.length, v.length);
  assert.ok(s.hasDigit && s.hasUpper && s.hasLower);
  assert.equal(s.entropyPerChar, "high");
  assert.equal(s.knownPrefix, GHP);
});

test("the description never contains the secret itself", () => {
  const v = GHP + BODY;
  const text = describeSecretShape(v);
  assert.doesNotMatch(text, new RegExp(BODY.slice(0, 8)), "body must not appear");
  assert.doesNotMatch(text, /aB3xK9m/, "no detectable fragment");
});

test("an UNKNOWN prefix is not echoed (a 4-char leak is still a leak)", () => {
  const v = "Zq7" + BODY; // no known vendor prefix
  const s = describeSecretValue(v);
  assert.equal(s.knownPrefix, undefined);
  const text = describeSecretShape(v);
  assert.doesNotMatch(text, /Zq7/, "unknown prefix must never be echoed");
});

test("prose is identified as prose, which flags a likely false positive", () => {
  const prose = SK + "intent-need";
  const s = describeSecretValue(prose);
  assert.equal(s.looksProse, true, "should look like prose");
  assert.equal(s.hasDigit, false);
});

test("placeholders are identified", () => {
  for (const p of [SK + "proj-" + "your-api-key-here", "AKIA" + "EXAMPLE".padEnd(16, "X")]) {
    assert.equal(describeSecretValue(p).looksPlaceholder, true, `placeholder: ${p.slice(0, 10)}`);
  }
});

test("high-entropy random body is not called a placeholder or prose", () => {
  const s = describeSecretValue(AKIA + "QYLPMN5HHMSUABCD");
  assert.equal(s.looksPlaceholder, false);
  assert.equal(s.looksProse, false);
});

test("low-entropy repeated text is bucketed low", () => {
  const s = describeSecretValue("a".repeat(40));
  assert.equal(s.entropyPerChar, "low");
});

test("describeNote says FALSE POSITIVE when the shape suggests one", () => {
  const note = describeNote(1, [describeSecretShape(SK + "intent-need")], ["OpenAI API Key"]);
  assert.match(note, /describe mode/);
  assert.match(note, /FALSE POSITIVE/);
  assert.match(note, /OpenAI API Key/);
});

test("describeNote does not call a real key a false positive", () => {
  const note = describeNote(1, [describeSecretShape(GHP + BODY)], ["GitHub PAT"]);
  assert.doesNotMatch(note, /FALSE POSITIVE/);
  assert.match(note, /allow-once/);
});

test("describeNote states the shape and the rule", () => {
  const note = describeNote(2, [describeSecretShape(GHP + BODY)], ["GitHub PAT", "Token Assignment"]);
  assert.match(note, /2 redacted/);
  assert.match(note, /GitHub PAT, Token Assignment/);
});
