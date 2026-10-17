# Changelog

All notable changes to `pi-leakguard` are documented here.

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
