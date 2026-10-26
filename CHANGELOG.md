# Changelog

All notable changes to `pi-leakguard` are documented here.

## [0.9.1] - 2026-10-26

### Added

- **OpenCode plugin** (plugins/opencode.ts). Same engine, same config, same
  thin layer, different hook API: tool.execute.before for the path guard and the
  egress check, tool.execute.after for redaction. 14 assertions cover it,
  including the three that matter most: an SSH key read is blocked, an egress
  command carrying a credential is blocked, and a credential with no egress is
  NOT blocked (reading a token is not a leak).

### Fixed

- The git hook assumed betterleaks lives at ~/.bin/betterleaks. The Linux server
  keeps it at ~/bin/betterleaks, so the hook failed closed there and would have
  blocked every commit. It now probes both layouts, and the server gate passes
  5/5 with the same hook file as macOS.

### Notes

- The server pi-leakguard was pinned at 0.6.1, from before the engine swap. It is
  now on 0.9.0 with 140/140 tests passing and a clean typecheck on that machine.
  Engine and config were installed there too; the only gap had been the config,
  which meant the 46 lg-* rules never ran server-side.

## [0.9.0] - 2026-10-26

Detection is now delegated to [betterleaks](https://github.com/betterleaks/betterleaks).
The 31 hand-written regexes are gone; pi-leakguard keeps the judgement layers.

### Why

A secret scanner answers "is there a credential in this text?". It has no concept
of *"may the agent read this file"*. Those are different questions, and
pi-leakguard had been answering both at once with one hand-maintained pattern
list. That list was the weakest part: 31 expressions, no validators, and every
false-positive fix (git SHAs, ask-hash, prose like sk-intent-need, supply-chain
digests) needed another special case.

betterleaks ships 471 rules, 463 compiled into the binary, 218 able to prove a
finding valid/revoked/expired against the provider API. Those rules are someone
else's maintenance burden now, and they are written against real provider
response formats instead of guessed prefixes.

### Removed

- The 31 built-in regexes in SECRET_PATTERNS. Measured against 29 token shapes,
  betterleaks covered 27. Every shape the regexes caught and the engine did not
  was a shape they also over-matched. Keeping them as a fallback would have
  bought no coverage and introduced a second rule set to keep in sync.
- countCaptureGroups() and the offset-math redaction dance. The engine reports
  StartLine/StartColumn/EndColumn, so locateSecretMatch() masks the exact
  reported span instead of re-deriving it.

### Added

- engine.ts -- the adapter: detectWithEngine(), detectAll(), applyRedaction(),
  engineStatus(), plus a RULE_NAMES map so the model keeps seeing "GitHub PAT"
  and not github-pat. The two shapes betterleaks does not report stay here, each
  with the measurement that justifies it: a bare Authorization: Bearer <opaque> line (its rule needs
  a curl invocation to establish egress context) and op:// 1Password references
  (pointers to a credential, not the credential).
- Version drift reporting. The 463 default rules are compiled into the 22 MB
  binary, so a version change IS a rule change. Startup and the git hook now
  report drift rather than silently running a different rule set.
- engine.test.ts (24 assertions) making the deletion falsifiable.

### Changed

- redactSecretsInText, scanForSecrets, describeSecretMatch, locateSecretMatch,
  hasSecretMaterial, isTaintedEgress and commandHasSecret all ask the engine.
  User-supplied extraSecretPatterns still run on top: additive, not a substitute.
- describeSecretMatch() reports the rule that actually fired instead of guessing
  from regex order.

### Deliberately lost

- A bare 64-character hex digest is no longer flagged. That branch produced most
  of the false positives across 18 repositories: npm integrity fields, manifest
  hashes, sha256: image pins, provenance files. A digest is not a credential. The
  loss is asserted by a test rather than left implicit, and the exfil layers now
  test with a real credential instead of a digest. If it ever returns, it must
  return WITH CONTEXT (an egress or transform command), never as a bare pattern.

### Cost

~51 ms per tool result (process start dominates the scan), so ~5 s across a
100-tool-result session. A keyword prefilter would cut this to near zero, but it
would require embedding a copy of betterleaks' 462 keyword lists -- the same
drift problem this release removes. Rejected on those grounds.

### Fixed (found by the red-proof, all previously hidden by vacuous tests)

- The OpenAI fixture had no digit in its body, so it satisfied neither the old
  regex nor the engine -- the assertion had been passing on nothing.
- The GitHub fixture body was a sequential digit-then-alphabet string, which
  betterleaks correctly rejects via its stopwords filter. The old regex flagged
  it; the engine does not, and the engine is right.
- The PEM assertion expected the END marker to vanish, but the engine reports the
  header only, so the END marker legitimately survives.
- isTaintedEgress and hasSecretMaterial were still testing the deleted regex.

Suite: 105 -> 140 assertions, all passing; tsc --noEmit clean. End-to-end
validated against the git hook and the installed binary (13/13 checks).

## [0.8.0] - 2026-10-26

### Added
- **`llm-hints.ts` — every block now tells the model what matched, where, and what to do instead.** A block used to say only "secret-looking material", which named neither the pattern nor the location. In a real session that cost three full rewrites of one file: the model tried a literal, then a variable, then character codes, because each denial was indistinguishable and gave it nothing to act on. Blocks now carry the pattern name (`"GitHub PAT"`), the masked offending line (`line 12: token = "[GitHub PAT]"`), a remedy chosen per pattern family, and an explicit note that retrying with different syntax will not help. Remedies are pattern-specific: a private key is referenced by path, a password is read by key name, a test fixture is built at runtime.
- **Repeat-block detection.** `state.blockAttempts` counts blocks per tool+intent within a turn. From the second attempt the message changes: "Changing the command's syntax will NOT change the outcome — the check is about the value, not the spelling." The counter resets at `agent_end`, so a new turn is a new intent.
- **Search-pattern false positive recognition.** `grep -n 'DOTENV|\\.env' file.ts` was blocked as a path access, after which the model read a 583-line file instead of grepping it — 5x the tokens. A sensitive token inside a quoted argument containing regex metacharacters is now recognised as a search pattern, and the block says so with a copy-pasteable workaround.
- **Context-aware path allowlist.** `isDocumentationPath()` exempts `docs/`, `*.example.*`, `*.sample`, `*.template`, test fixtures, `testdata/`, and vendored upstream code. Those files exist to show what a credential looks like. Measured: of 50 content-layer hits across 18 real repos, nearly all were documentation. A real private key block is still caught even in docs.
- `describeSecretMatch()` / `locateSecretMatch()`, plus `context.test.ts`, `llm-hints.test.ts` and `coverage.test.ts` (30 new assertions).

### Added
- **`/leakguard describe` — report redacted values by SHAPE, never by value.** This closes the one gap that made leakguard unusable for auditing: once a value was redacted, its nature was unknowable, so a finding could not be classified as real or false-positive, and the file could never be inspected. Describe mode reports length, character classes, entropy bucket, and a *published* vendor prefix, plus whether the value looks like prose or a placeholder — enough to decide `real` vs `false positive` while revealing nothing. An unknown prefix is never echoed: a 4-char prefix of a random 40-char secret is still 10 bits of it.

  Verified against the file that previously could not be read at all (`picoclaw/pkg/config/example_security_usage.go`): 6 findings, and the shape immediately classified them — `sk-ant-` with a placeholder word and prose structure at line 43, `token-from-env`-style assignments at 51/72/74, and two high-entropy values at 545/552 whose surrounding lines read `# Channels` / `export ..._TOKEN=` — documentation, not a leak. The previous behaviour was to redact all six to `[LEAKGUARD_REDACTED]` and abandon the task.
- `red-proof.ts` — runs the old block message and the new one side by side on the same input, plus the describe output for four value classes. The previous turn shipped the guidance layer with unit tests but never exercised it against the failures that motivated it.

### Fixed
- **The pre-commit/push scan could not see `.env` files.** `index.ts` ran `git diff --cached -- . ':(exclude).env*'`, so `git add .env && git commit` produced no finding — the one thing a pre-commit scan most needs to catch. The exclusion is gone; staged env files are now detected by name and reported separately from secret-pattern hits.
- **The redaction note was attached to output block 0.** When a redaction landed in a later text block, the model saw redacted text with no explanation and re-ran the tool to get "the real output". The note now attaches to the block that changed, names the rules that fired, and on a repeat says the value will not be revealed by re-running.
- **Redaction double-counted overlapping rules.** A generic rule such as `API Key Assignment` matched the placeholder text emitted by a specific rule, inflating counts and nesting placeholders. Spans are now claimed by the first (most specific) pattern that matches.
- **False positives on supply-chain metadata.** `SECRET_VALUE_RE` included `[0-9a-f]{32,}`, which matches git SHAs that `stripGitSHAs()` does not reach (a 40-hex SHA inside a longer hex run), npm `integrity` digests, `sha256:` image pins, and CI fixtures asserting a digest is not flagged. Split into two patterns with opposite tolerance: `SECRET_VALUE_RE` (commands, egress — hex stays, because an HMAC key being shipped off-box matters) and `CONTENT_VALUE_RE` (file contents and tool output — hex dropped, because reading files is high-volume and low-stakes). Hex with context (`SOME_TOKEN=<hex>`) is still caught via `SECRET_ASSIGNMENT_RE`.
- **The `@SK` branch matched prose.** `sk-intent-need` (a task id) and `sk-without-ide` (a sentence) were flagged. Real keys are long base62 runs containing at least one digit; the branch now requires one, and placeholder words (`your`, `actual`, `example`, `xxxx`, `test`, `dummy`, `fake`, `placeholder`, `redacted`) are excluded.
- **PEM markers matched lowercase.** The `i` flag made the lowercase spelling match, which is the exact substring picoclaw's own secret detector searches for — the guard fired on code whose job is finding keys. `PEM_RE` is now case-sensitive and separate; real key blocks are always uppercase.

### Changed
- `hasSecretMaterial(value, { path })` accepts the write/edit target so documentation and fixtures are not flagged. Called without `path` the behaviour is unchanged.

### Measured
Over 18 real repositories on the author's server, blocking-layer false positives on tracked source fell **95 files → 21 → 2 → 0** across these fixes. Coverage is verified unchanged by `coverage.test.ts`, which asserts every real credential shape is still detected (`ghp_`, `sk-`, `sk-proj-`, `sk-ant-`, `AKIA`, `xoxb-`, PEM, plus the tightened `sk-` branch). Suite: 75 → 105 assertions, all passing; `tsc --noEmit` clean.

## [0.6.1] - 2026-10-17

### Fixed
- **GitHub OAuth (`gho_`) and GitHub App installation (`ghs_`) tokens are now redacted.** They had no dedicated pattern in `SECRET_PATTERNS`, so a bare token — e.g. pasted inside a `curl` command — passed through the redactor untouched. They were only caught when they carried an explicit key prefix (`export TOKEN=...`), which is the less common way a token leaks into a transcript. The same gap applied to `scanForSecrets`, the last line of defence before a push. Both patterns use `{36,}` because GitHub App installation tokens vary in length. This matters because `gho_`/`ghs_` are the highest-privilege GitHub credentials and the ones automation and CI actually carry.

### Changed
- `package-lock.json` was stuck at `0.5.0` while `package.json` said `0.6.0`. Lock now matches the manifest.

## [0.6.0] - 2026-07-15

### Changed
- Default protection mode is now `auto` instead of `max`. `auto` blocks sensitive paths and redacts secrets silently (no confirm prompts), which is the safe-by-default behavior most users expect. Restore confirm-prompt behavior with `/leakguard mode max`.

### Fixed
- Git object hashes (commit SHAs) are no longer falsely flagged as secret material. Commands such as `git show <sha>`, `git cat-file -p <sha>`, `git checkout <sha>`, and `git reset --hard <sha>` no longer trigger false-positive blocks. A new `stripGitSHAs()` helper strips 7–40 char hex runs before high-entropy secret matching while preserving longer-hex (sha256/sha512) detection. Added regression tests covering every `SECRET_VALUE_RE` consumer.

## [0.5.0] - 2026-07-10

### Changed
- **`"yolo"` renamed to `"auto"`** — "yolo" sounded like "allow everything", the opposite of what the mode does. `"auto"` clearly communicates "blocks automatically without confirm prompts". Use `/leakguard mode auto`.
- Internal: Mode type, `isBlockMode()`, `LeakguardConfig`, `checkBashWords()` all use `"auto"` now.
- Existing `leakguard.json` files with `"yolo"` silently fall back to `"max"` (default) on next load. Run `/leakguard mode auto` to re-save.

## [0.3.0] - 2026-07-09

### Changed
- **`yolo` is now a proper mode** (`/leakguard mode yolo`), not a session-only flag.
  YOLO mode provides the same protection as MAX (block sensitive paths + redact secrets)
  but blocks **silently** — no confirm prompts. Persisted to `leakguard.json` like
  any other mode.
- `/leakguard` without args now also accepts `stats` as an explicit alias.
- Removed standalone `/leakguard yolo` and `/leakguard yolo off` commands.
  Use `/leakguard mode yolo` instead.
- Status bar no longer shows a separate ` 🔥` suffix — YOLO has its own icon (🔥).

### Internal
- `Type Mode` now includes `"yolo"`.
- `ExtensionState.yolo` removed (replaced by mode).
- Added `isBlockMode()` helper (`mode === "max" || mode === "yolo"`).
- All guard checks use `isBlockMode()` instead of `mode === "max"`.
- `LeakguardConfig.mode` accepts `"yolo"`.
- `checkBashWords()` accepts `"yolo"` and treats it like `"max"` for path checks.

## [0.2.0] - 2026-07-08

### Added
- `/leakguard trust <pattern>` — session-level allow-list for redaction bypass.
  Literal string or `/regex/` syntax. Human-only via pi command.
- `trust list`, `trust clear`, `trust remove <n>` sub-commands.
- Informative placeholder: `[LEAKGUARD_REDACTED — JWT Token]` shows the pattern
  name that matched, giving the LLM context to ask for the right trust pattern.

### Security
- LLM never self-bypasses. Trust is human-only, same model as `allow-once`/`yolo`/`mode`.

### Tests
- 8 new tests: parseTrustedPattern (literal, regex, case-insensitive), trustedTest
  skip/isolation, informative placeholder (AWS key, JWT Token, safe text).

## [0.1.0] - 2026-07-02

### Added
- Initial project, inspired by [`@raquezha/noleaks`](https://pi.dev/packages/@raquezha/noleaks) (MIT, published on npm/pi.dev; independent continuation, MIT attribution retained).
- All security layers from the original, ported and tested:
  - Symlink guard (`realpathSync` before path checks).
  - Obfuscation detection (NFKC normalization variance + hidden/control chars).
  - Env-dump block (`env`/`printenv`/`set`/`export`).
  - Sensitive shell expansion (`$TOKEN`, `$SECRET`, ...).
  - Transform+smuggle (`base64`/`openssl`/`gpg` piping secret material).
  - Discovery/exfil combine (`nmap`/`curl`/`nc` + sensitive material).
  - Universal word scan (critical utilities as nested arguments: `sudo chmod`, `dd`, `shred`).
  - Write/edit payload scan (`hasSecretMaterial`).
  - `grep`/`find`/`ls` guards over sensitive paths (max mode).
  - Mode persistence via `~/.pi/agent/leakguard.json`.
- Richer redaction set: Vault (`hvs.`), Doppler (`dp.pt.`), 1Password (`op://`),
  Bearer tokens, DB URLs with credentials, plus the original's AWS/OpenAI/Anthropic/
  Google/GitHub/GitLab/Slack/Stripe/SendGrid/npm/JWT/private-key patterns.
- Interactive read confirmation (max mode) and detailed per-category/per-pattern
  session stats.
- Pure, unit-tested security helpers in `security.ts` (34 tests).
