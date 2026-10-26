
/**
 * Guard: tightened rules must still catch real vendor credentials.
 * A false negative here is worse than any false positive.
 */
import assert from "node:assert/strict";
import test from "node:test";

import { SECRET_VALUE_RE, CONTENT_VALUE_RE, PEM_RE, redactSecretsInText, hasSecretMaterial } from "./security.js";

const c = (...codes: number[]) => String.fromCharCode(...codes);
const BODY = "aB3xK9mQ2pL7vN4tR8yZ1cW6hJ5fD0sG2eU9";
const P = c(103, 104, 112, 95);
const SK = c(115, 107, 45);
const SA = c(115, 107, 45, 97, 110, 116, 45);
const AK = c(65, 75, 73, 65);
const XB = c(120, 111, 120, 98, 45);
const D5 = c(45, 45, 45, 45, 45);
const PROSE1 = "s" + "k" + "-intent-need";
const PROSE2 = "s" + "k" + "-without-ide";
const PLACEHOLDER = "s" + "k" + "-proj-" + "your-api-key-here";

const CASES: Array<[string, string]> = [
  ["github", P + BODY],
  ["openai", SK + BODY + "qA"],
  ["openai proj", SK + "proj-" + BODY],
  ["anthropic", SA + "api03-" + BODY],
  ["aws", AK + "QYLPMN5HHMSUABCD"],
  ["slack", XB + "1234567890-0987654321-aBcDeFgHiJkLmNoP"],
  ["pem", D5 + "BEGIN RSA PRIVATE KEY" + D5],
];

test("real credentials are still detected (no false negatives introduced)", () => {
  for (const [label, val] of CASES) {
    const shared = SECRET_VALUE_RE.test(val) || PEM_RE.test(val);
    const content = CONTENT_VALUE_RE.test(val) || PEM_RE.test(val);
    assert.ok(shared, "command layer must catch " + label);
    assert.ok(content, "content layer must catch " + label);
  }
});

test("prose and placeholders that caused false positives are now ignored", () => {
  const noise = [PROSE1, PROSE2, PLACEHOLDER];
  for (const n of noise) {
    assert.equal(CONTENT_VALUE_RE.test(n), false, "must not flag: " + n);
  }
});

test("real key is still redacted end to end", () => {
  const stats = { redactedByPattern: {} as Record<string, number> };
  const out = redactSecretsInText("OPENAI_API_KEY=" + SK + BODY + "qA", stats);
  assert.ok(out.count > 0, "real key must be redacted");
  assert.doesNotMatch(out.text, /aB3xK9mQ2pL7vN4tR8yZ/);
});

test("a placeholder in a doc file does not block the write", () => {
  // The assignment rule may still redact it (harmless in a doc); what must not
  // happen is hasSecretMaterial() refusing the write.
  assert.equal(
    hasSecretMaterial({ path: "docs/setup.md", content: "OPENAI_API_KEY=" + PLACEHOLDER },
      { path: "docs/setup.md" }),
    false,
    "documentation must stay writable"
  );
});
