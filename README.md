# pi-leakguard

**pi-leakguard** is a defense-in-depth "seatbelt" extension for [pi.dev](https://pi.dev).
It keeps the coding agent from reading/writing/exfiltrating credentials, and
redacts secrets from tool output before the model ever sees them.

> **Note:** this is an independent continuation of `@raquezha/noleaks`' ideas and security
> layers, not an official fork. It keeps the MIT license and attribution.

> **Security model:** this is a powerful defense-in-depth
> "seatbelt", **not** an airtight sandbox. It stops accidental leaks and common AI
> exfiltration tricks. For untrusted code or unattended automation, use a real sandbox
> (Docker, Micro-VM) — don't rely on this alone.

## Security model & limitations

When a layer fires, here's what happens:

- **BLOCK** — leakguard stops the tool call (unless you allow it via the confirm prompt or `/leakguard mode auto`).
- **REDACT** — leakguard replaces the secret text with `[LEAKGUARD_REDACTED]` before the model sees it; the agent still knows a secret *exists*, just not its value.
- **WARN** — leakguard shows a notification; it doesn't block anything.

| Layer | Action | What it catches | False-positive risk | False-negative risk |
| ----- | ------ | --------------- | ------------------ | ------------------ |
| Path protection (read/write/delete) | BLOCK (confirm) | Access to `.env`, `~/.ssh`, `/etc/shadow`, etc. | Low — patterns are specific file names | Medium — custom secret paths need manual config |
| Secret redaction (output) | REDACT | AWS/GitHub/Vault/1Password/DB-URL/etc. in tool output | Low — high-entropy + known prefixes | Medium — novel secret formats not in the pattern list |
| Symlink guard | BLOCK | Symlink bypass to a sensitive file | Very low | Low — `realpathSync` resolves before checking |
| Obfuscation (NFKC/control chars) | BLOCK | Homoglyph / zero-width bypass in commands | Low — normal whitespace is allowed | Low — only rejects clear variance |
| Shell exfil (env-dump, expansion, smuggle, discovery+secret) | BLOCK (confirm) | `env`, `$TOKEN`, `base64 \| curl`, `nmap`+secret | Low | Medium — arbitrarily obfuscated pipelines |
| Egress DLP | BLOCK (confirm) | `curl -u user:pass`, credentialed URLs, secret headers | Low — only fires on clear creds in egress | Medium — encoded/obfuscated payloads |
| Universal word scan | BLOCK (confirm) | `sudo chmod`, `dd`, `shred` as arguments | Low — only critical utils | Low | 
| Write/edit payload scan | BLOCK (confirm) | Secret material in write body | Low | Medium — novel formats |
| grep/find/ls guard | BLOCK (confirm) | These tools over sensitive paths | Low | Low |
| Taint tracking | BLOCK (confirm) | Egress of content read from a sensitive path | Low — only after a sensitive read | Medium — indirect leaks (e.g. summarizing then pasting) |
| Pre-commit/push scan | BLOCK (confirm) | Secret in `git diff` on commit/push | Low — scans diff, not whole tree | Medium — novel formats |
| Audit log | WARN (log only) | Every block/redact/allow event | None — observability | None |
| Extensible config | n/a | User allow/block paths + extra secret patterns | None — user-defined | None — user-defined |

### Why pi-leakguard does not detect prompt injection by pattern

Detecting prompt injection with regex/heuristics is **not a consolidated
industry strategy**. Attackers write injections in endless variations
(obfuscation, other languages, indirect phrasing like "the previous
instructions are deprecated"), so a fixed pattern list misses almost everything
and false-positives on normal prose ("ignore the previous section"). Maintaining
that list costs more than it's worth.

So instead of trying to *catch* the injection, it stops the **harm** it causes:

- If the model gets tricked into reading a secret, **redaction** strips it
  from what it can see and repeat.
- If it gets tricked into exfiltrating, **egress DLP** and **taint
  tracking** block the network call carrying credentials.

Think of leakguard as shrinking the blast radius, not as a detector.

### Measured false positives (18 real repositories)

The blocking layer was measured against every tracked file in 18 repositories,
then the same files again after each fix:

| stage | files flagged | what was firing |
|---|---|---|
| before | **95** | `[0-9a-f]{32,}` matching `UPSTREAM_SHA` provenance, npm `integrity` digests, `sha256:` image pins |
| hex split into command/content layers | 21 | documentation and example configs |
| context-aware path allowlist | 2 | a `SK proj` placeholder, lowercase PEM inside a detector |
| placeholder list + case-sensitive `PEM_RE` | **0** | — |

Guarded by `coverage.test.ts`: every real credential shape (`ghp_`, `sk-`,
`sk-proj-`, `sk-ant-`, `AKIA`, `xoxb-`, PEM) must still be detected. A false
negative is worse than a false positive, so that test gates any rule change.

### How pi-leakguard keeps false positives / false negatives in check

- **It confirms, it does not silently block.** Every BLOCK asks via `ctx.ui.confirm`
  (unless AUTO mode is active). This keeps the agent useful while still safe.
- **Conservative patterns.** leakguard's path and redaction patterns target specific
  file names and known secret prefixes; they avoid matching normal code.
- **AUTO mode** (🔥) provides the same protection as MAX but blocks silently
  without confirm prompts. Blocks are still recorded in stats and audit log.
  Redaction stays on. Persisted to `leakguard.json` like any other mode.
- **Redaction over blocking for output.** leakguard scrubs secrets from output
  instead of blocking it, which preserves agent utility (deploy still works via
  the environment) while preventing leakage — the preferred 2026 pattern of
  "don't give agents secrets".
- **Blocks that teach instead of just refusing.** Every block answers three
  questions in one line: **what matched** (the pattern name), **where** (tool,
  argument role, masked line number), and **what to do instead** (a remedy chosen
  for that pattern family). A block that says only "secret-looking material"
  leaves the model guessing, and guessing costs tokens on retries that cannot
  converge — see `llm-hints.ts`.
- **Repeat detection.** The second block of the same intent reads differently:
  "Changing the command's syntax will NOT change the outcome — the check is about
  the value, not the spelling. Stop retrying, or ask the human." The counter is
  per-turn, so a genuinely new task starts fresh.
- **Search-pattern recognition.** A sensitive token used as a *search pattern*
  (`grep -n 'DOTENV|\\.env' file.ts`) is not a file access. It is recognised as
  such and the block includes a copy-pasteable workaround instead of pushing the
  model toward reading whole files.
- **Documentation and fixtures are exempt.** `docs/`, `*.example.*`, `*.sample`,
  `*.template`, `testdata/`, test files, and vendored code may contain example
  credentials — that is what they are for. A real private key block is still
  caught anywhere.
- **`/leakguard describe` — shape, not value.** When a value is redacted, the
  model cannot tell a real leak from a false positive, so it either guesses or
  gives up on the file. Describe mode reports length, character classes, entropy
  bucket, a published vendor prefix, and whether the value looks like prose or a
  placeholder. Enough to classify the finding; nothing that helps an attacker.
  Unknown prefixes are never echoed.
- **Context note on redacted output.** Names the rules that fired, attaches to
  the block that actually changed, and on a repeat says plainly that re-running
  will not reveal the value.

## Features

- **Path protection**: leakguard blocks reads/writes/deletes of sensitive paths
  (`.env`, `~/.ssh/`, `~/.aws/`, `/etc/shadow`, Keychains, etc.)
- **Secret redaction**: leakguard scrubs API keys, tokens, passwords, private-key blocks,
  DB URLs, and secret assignments from `tool_result` content.
- **Informative placeholder**: redacted values show the pattern name that matched:
  `[LEAKGUARD_REDACTED — JWT Token]`. Helps the LLM understand what was redacted
  and ask for the right trust pattern.
- **Session trust**: mark a pattern as trusted for the current session. Leakguard
  skips redaction for output containing that pattern. LLM cannot self-bypass — only
  the human can run `/leakguard trust <pattern>`.
- **Symlink guard**: leakguard resolves paths to their *real* on-disk location before
  checking, so symlink bypasses are caught.
- **Obfuscation detection**: leakguard rejects NFKC normalization variance and hidden/control
  characters (homoglyph / zero-width attacks).
- **Shell exfiltration blocks**: leakguard blocks env dumps (`env`/`printenv`/`set`/`export`),
  sensitive variable expansion (`$TOKEN`), transform+smuggle (`base64`/`openssl`
  piping secrets), and discovery/exfil combine (`nmap`/`curl` + secrets).
- **Universal word scan**: leakguard blocks critical utilities even as nested arguments
  (`sudo chmod`, `dd`, `shred`, `mkfs`, ...).
- **Write/edit payload scan**: leakguard blocks writes whose body contains secret-looking
  material.
- **grep / find / ls guards**: leakguard blocks those tools over sensitive paths in
  `max` mode.
- **allow-once**: bypass redaction for one value without changing the mode.
  Human-only via confirm prompt — the LLM cannot trigger it.
- **Four modes** (persisted to `~/.pi/agent/leakguard.json`):
  - `max` — block sensitive paths AND redact secrets (with confirm prompts)
  - `auto` (default) — same as MAX, but blocks silently (no confirm prompts)
  - `basic` — allow reads but still redact secrets (Safe Debugging)
  - `off` — disable all protection (dangerous)

## What it blocks (in MAX mode)

| Category        | Examples                                                      |
| --------------- | ------------------------------------------------------------- |
| Environment     | `.env`, `.env.local`, `.env.production`                       |
| Private keys    | `id_rsa`, `id_ed25519`, `*.pem`, `*.key`, `*.p12`, `*.keystore` |
| Credentials     | `auth.json`, `.npmrc`, `.netrc`, `.pypirc`, `.git-credentials` |
| Cloud config    | `~/.aws/`, `~/.azure/`, `~/.config/gcloud/`, `~/.docker/`, `~/.kube/` |
| SSH / GPG       | `~/.ssh/`, `~/.gnupg/`                                        |
| Pi secrets      | `.pi-secrets/`                                                |
| Shell config    | `.bashrc`, `.zshrc`, `.profile`                               |
| System          | `/etc/shadow`, `/etc/sudoers`, `/etc/passwd`                  |
| macOS Keychain  | `~/Library/Keychains/`                                        |

## What it redacts

AWS, OpenAI, Anthropic, Google, GitHub (PAT + fine-grained), GitLab, Slack,
Stripe, SendGrid, npm, HashiCorp **Vault**, **Doppler**, **1Password** (`op://`),
JWTs, private-key blocks, DB URLs with credentials, generic
`key=`/`password=`/`token=` assignments, and `Bearer` tokens.

## Use with betterleaks (recommended, complementary)

pi-leakguard answers "may the *agent* read this?" — a question no off-the-shelf
scanner asks. The commit-time question ("did a credential just enter the diff?")
is better served by a maintained rule engine. Do both:

```sh
brew install betterleaks            # or: the release tarball in ~/.bin
betterleaks git --staged --config ~/.config/betterleaks/betterleaks.toml
```

Measured on this machine (18 repos, 2026-10):

| | shell hook | gitleaks | betterleaks |
|---|---|---|---|
| staged scan | ~10 ms | ~620 ms | ~80 ms |
| rules | 9 hand-written | 200+ | 471 (218 with API validation) |
| false positives on a normal commit | 0 | 0 | 0 / 28 repos |

**There is no fallback pattern list, on purpose.** An earlier version of the
git hook kept a hand-written copy of the patterns as a safety net. It was
removed on measurement: across 18 token shapes betterleaks covered **all** of
them and added extras the hand-written list never had (postgres URIs, JWTs, npm
tokens). A copy of rules the engine already owns buys no coverage — and a copy
that silently drifts is worse than none.

What survives is only what betterleaks is genuinely blind to:

| kept check | why betterleaks cannot do it |
|---|---|
| `.env` file refusal | a file with only `DEBUG=true` has no credential, so it exits 0 (measured) |
| fail-closed when the binary is missing | a secret gate that passes when its scanner is gone is not a gate |
| chain to repo-local hooks | a global `core.hooksPath` otherwise shadows `~/.git/hooks` |

Another measured win from the same swap: `ask-<hash>` and git SHA fragments no
longer false-positive. The hand-written list needed a two-step left-boundary
workaround because a bare `sk-`/`[0-9a-f]{32,}` matched them; betterleaks has
proper word boundaries and needs no workaround.

**Do not use `--baseline-path` as the gate.** It is safe for *new* and
*rotated* secrets (verified), but it turns the gate into "fail only on changes
since this file was generated", which ages badly.

**Never report to `/dev/stdout`.** `-r /dev/stdout` intermittently fails with
`permission denied` and the tool then exits 0 with zero findings. Use a real
file path. This cost several wrong conclusions during evaluation.

## Commands

| Command                     | Description                                              |
| --------------------------- | -------------------------------------------------------- |
| `/leakguard`                | Show session statistics (blocked, redacted)              |
| `/leakguard stats`          | Same as above (alias)                                    |
| `/leakguard mode max`       | Block sensitive paths AND redact secrets (with confirms) |
| `/leakguard mode auto`      | Same as MAX, but blocks silently (no confirm prompts)    |
| `/leakguard mode basic`     | Allow reads but still redact secrets                     |
| `/leakguard mode off`       | Disable all protection (dangerous)                       |
| `/leakguard allow-once`     | Allow one redacted value through without changing mode — single use, human-only via confirm |
| `/leakguard trust <pattern>`| Trust a pattern (literal or `/regex/`) for this session — skips redaction. Human-only. |
| `/leakguard trust list`     | List active trusted patterns                             |
| `/leakguard trust clear`    | Clear all trusted patterns                               |
| `/leakguard trust remove n` | Remove a trusted pattern by index                        |

## Installation

```bash
pi install git:github.com/calionauta/pi-leakguard
```

Or pin a version:

```bash
pi install git:github.com/calionauta/pi-leakguard
```

Once installed, pi auto-loads leakguard on the next session.

## Development

```bash
npm install
npm test          # runs security.test.ts via tsx
npm run typecheck # tsc --noEmit
```

## Status Icon

- 🔒 `max` - block paths + redact, with confirms
- 🔥 `auto` (default) - block paths + redact, no confirms (silent blocks)
- 🟡 `basic` - redact only
- ⚪ `off` - no protection (deactivated, wide open)
- ⚡ appended when `/leakguard allow-once` is active — next redacted output will pass through (single use, resets automatically).

## License

MIT.
