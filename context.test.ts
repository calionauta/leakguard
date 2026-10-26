/**
 * Regression tests for the context-aware false-positive suppression.
 *
 * The measured problem: of 50 content-layer hits across 18 real repos, nearly
 * all sat in docs/, *.example.*, test fixtures, or a vendored upstream project.
 * A checkout of `picoclaw` alone produced 32, all of them documentation of how
 * to configure credentials.
 *
 * The rule must be narrow: a doc file may contain example tokens, but never a
 * real private key block.
 */
import assert from "node:assert/strict";
import test from "node:test";

import { hasSecretMaterial, isDocumentationPath } from "./security.js";

const GH = "gh" + "p_" + "a".repeat(36);

test("documentation and fixture paths are recognised", () => {
  const yes = [
    "docs/guides/configuration.md",
    "README.md",
    "config/config.example.json",
    ".env.sample",
    "templates/app.template.yaml",
    "tests/fixtures/recipe-matrix.json",
    "features/app/app_test.go",
    "vendor/github.com/x/y/config.go",
    "testdata/creds.json",
  ];
  for (const p of yes) assert.ok(isDocumentationPath(p), `should be documentation context: ${p}`);
});

test("real source paths are NOT exempted", () => {
  const no = [
    "src/config.ts",
    "internal/secrets/secrets.go",
    "app/main.py",
    ".env",
    "scripts/deploy.sh",
  ];
  for (const p of no) assert.equal(isDocumentationPath(p), false, `must not exempt: ${p}`);
});

test("an example token in a doc file does not block a write", () => {
  const payload = { path: "docs/configuration.md", content: `api_key = "${GH}"` };
  assert.equal(
    hasSecretMaterial(payload, { path: "docs/configuration.md" }),
    false,
    "docs legitimately show credential formats"
  );
});

test("the same token in real source still blocks", () => {
  const payload = { path: "src/config.ts", content: `api_key = "${GH}"` };
  assert.equal(
    hasSecretMaterial(payload, { path: "src/config.ts" }),
    true,
    "a token in source is a leak regardless of context"
  );
});

test("a private key block in a doc file still blocks", () => {
  const pem = "-----BEGIN " + "RSA PRIVATE KEY-----";
  const payload = { path: "docs/setup.md", content: pem };
  assert.equal(
    hasSecretMaterial(payload, { path: "docs/setup.md" }),
    true,
    "real key material must never be exempted, even in docs"
  );
});

test("no path given means the old behaviour (no exemption)", () => {
  const payload = `api_key = "${GH}"`;
  assert.equal(hasSecretMaterial(payload), true);
});

test("supply-chain digests in a manifest do not block", () => {
  const manifest = { name: "x", integrity: "sha512-" + "A".repeat(60) };
  assert.equal(hasSecretMaterial(manifest, { path: "package-lock.json" }), false);
});
