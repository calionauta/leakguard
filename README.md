# leakguard

**One detection engine, two hosts.** Secret-exposure seatbelt for AI coding
agents: it stops the agent reading credentials, redacts them from tool output, and
blocks a credential from leaving the machine.

Detection is delegated to [**betterleaks**](https://github.com/betterleaks/betterleaks),
a single static binary with 471 rules. This project is the layer a scanner cannot
be: *may the agent read this file*, *is this command exporting it*, *what should
the model be told when the gate refuses*.

| host | package | install |
|---|---|---|
| [pi.dev](https://pi.dev) | `pi-leakguard` (repo root) | `pi install git:github.com/calionauta/leakguard` |
| [OpenCode](https://opencode.ai) | `oc-leakguard` (`packages/oc-leakguard/`) | `opencode plugin add github:calionauta/leakguard` |

**Neither needs an npm publish.** Both resolve a GitHub repo directly: `pi`
installs from the repository root, OpenCode accepts a Git package specifier.

Shared in `core/`: the engine client, the blocked-path rules, and the egress
judgement. Per host, only the hook API and the wording of a refusal. That split is
deliberate -- when these were two copies, the same egress blind spot existed in
both at once and had to be fixed twice.

> **Note:** an independent continuation of `@raquezha/noleaks`' ideas, not an
> official fork. MIT licence, attribution kept.

> **Security model:** a powerful defense-in-depth "seatbelt", **not** an airtight
> sandbox. It stops accidental leaks and common exfiltration patterns. For
> untrusted code or unattended automation, use a real sandbox (Docker, Micro-VM).

## Install

### 1. The engine (required)

```sh
~/.bin/betterleaks-update          # installs betterleaks, checksum-verified
```

Nothing works without it except the path guards. `pi-leakguard` asks once at
install time; the OpenCode plugin and the git hook report DEGRADED and name the
command. Updates are **reported, never applied** -- the rules are compiled into
the binary, so a version bump is a rule change and must be reviewed.

### 2. pi.dev

```sh
pi install git:github.com/calionauta/leakguard
```

### 3. OpenCode

```sh
opencode plugin add github:calionauta/leakguard
# or, from a checkout:
cp -r packages/oc-leakguard ~/.config/opencode/plugins/leakguard
```

### 4. The commit gate (optional, recommended)

```sh
cp hooks/pre-commit ~/.git-hooks/pre-commit && chmod +x ~/.git-hooks/pre-commit
git config --global core.hooksPath ~/.git-hooks
```

### Verify, rather than assume

```sh
python3 scripts/verify-engine.py
```

## Security model & limitations

When a layer fires, here's what happens:

- **BLOCK** — leakguard stops the tool call (unless you allow it via the confirm prompt or `/leakguard mode auto`).
- **REDACT** — leakguard replaces the secret text with `[LEAKGUARD_REDACTED]` before the model sees it; the agent still knows a secret *exists*, just not its value.
- **WARN** — leakguard shows a notification; it doesn't block anything.

| Layer | Action | What it catches | False-positive risk | False-negative risk |
| ----- | ------ | --------------- | ------------------ | ------------------ |
| Path protection (read/write/delete) | BLOCK (confirm) | Access to `.env`, `~/.ssh`, `/etc/shadow`, etc. | Low — patterns are specific file names | Medium — custom secret paths need manual config |
| Secret redaction (output) | REDACT | anything the betterleaks engine reports (471 rules) plus two residual shapes | Low -- engine rules carry context, entropy and stopword filters | Medium -- a credential shape with no upstream rule |
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

Whatever the engine reports: AWS (key id, secret, session), OpenAI, Anthropic,
Google, GitHub (classic, fine-grained, OAuth, app, refresh), GitLab, Slack tokens
and webhooks, Stripe, SendGrid, npm, HashiCorp Vault, Doppler, 1Password (secret
key and service-account token), PEM private-key blocks, JWTs, database and
credential URLs, and key=/password= assignments -- 471 rules in total, plus the
two residual shapes listed below (Bearer headers without egress context, and
op:// references).

Because the engine ships 218 validators, a finding can also be reported as
valid, revoked, or expired rather than merely "looks like a key".

## Detection engine: betterleaks

Detection is **delegated** to [betterleaks](https://github.com/betterleaks/betterleaks),
a single static Go binary. pi-leakguard no longer carries a hand-written pattern
list; it asks the engine, then decides what to do with the answer.

```
betterleaks    471 rules, 463 compiled into the binary, 218 able to prove a
               finding valid/revoked/expired via the provider's API
pi-leakguard   the judgement layers: may the agent read this path, is this
               command exfiltrating, is this the agent's own retry, what do
               we tell the model
```

That split is not cosmetic. A scanner answers "is there a credential in this
text?". It has no concept of *"may the agent read this file"*. Five layers below
are not detection at all, and nothing off-the-shelf replaces them.

### Install

```sh
~/.bin/betterleaks-update --check     # installed vs latest, changes nothing
~/.bin/betterleaks-update             # install/update, checksum-verified
~/.bin/betterleaks-update --version 1.9.0   # pin or roll back explicitly
```

It lands in `~/.bin/betterleaks` with config at `~/.config/betterleaks/`. The
git hook and this extension read the **same** binary and the **same** config, so
there is one rule set to reason about, not two.

### Why the 31 patterns were deleted rather than kept as a fallback

Measured against 29 token shapes, betterleaks covered **27**. Every shape the
hand-written regexes caught and the engine did not was a shape they *also*
over-matched. A copy of rules the engine already owns buys no coverage, and a
copy that silently drifts is worse than no copy.

The two shapes the engine genuinely misses are kept, each with its measurement
recorded in `engine.ts`:

| residual | why betterleaks does not report it |
|---|---|
| a bare `Authorization: Bearer <opaque>` line | its rule needs a `curl` invocation to establish egress context |
| `op://` 1Password references | a pointer to a credential, not a credential |

### One deliberate coverage loss

A bare 64-character hex digest is **no longer flagged**. That single branch
produced most of the false positives across 18 repositories: npm `integrity`
fields, manifest hashes, `sha256:` image pins, provenance files. A digest is not
a credential. The removal is asserted by a test, not left implicit, and the
exfil layers now test with a real credential instead of a digest as a stand-in.

If it ever needs to return, it must return **with context** (an egress or
transform command), never as a bare pattern.

### Cost, measured

| | per tool result |
|---|---|
| detection (process start dominates) | ~51 ms |
| a 100-tool-result session | ~5 s total |

A keyword prefilter could cut this to near zero, but it would require embedding
a copy of betterleaks' 462 keyword lists — the same drift problem this change
removes. Rejected deliberately.

### Version pinning

Not vendored: the 463 default rules are compiled **into** the 22 MB binary, so
vendoring means an opaque blob per platform and a binary diff for every rule
change. Not auto-updating either: the rule set *is* the thing being trusted, and
a scanner that silently swaps its own detection logic is unreviewable.

In practice: `VERSION` records what is installed, and drift is **reported** at
extension startup and on commit. It is never corrected on your behalf.

## Verifying the stack

The measurements in this README are easy to re-derive **wrongly**: a fixture with
a sequential alphabet fails betterleaks' own entropy filter and then looks like
"the engine misses this shape"; `git` mode scans history while `dir` scans the
working tree; `config show` omits `targetRules` so its absence proves nothing.

`scripts/verify-engine.py` encodes those traps and checks the stack that can be
checked without planting a credential:

```sh
python3 scripts/verify-engine.py        # exit 1 on any failure, 2 if engine missing
```

It verifies the engine runs, the pinned version matches (drift reported, never
fixed), the config parses, **`useDefault` is true and 471 rules resolve**, every
path allowlist is scoped with `targetRules`, and no local rule reuses an engine
id. Five assertions, and it is itself tested against four injected regressions so
it fails when it should.

## Git hook and CI


The `pre-commit` gate uses the same binary, the same config, and the same rules.
Only three checks live in shell because betterleaks cannot do them:

| kept check | why |
|---|---|
| `.env` file refusal | a file holding only `DEBUG=true` contains no credential, so the engine exits 0 (measured) |
| fail-closed when the binary is missing | a gate that passes when its scanner is gone is not a gate |
| chain to repo-local hooks | a global `core.hooksPath` otherwise shadows `~/.git/hooks` |

Do **not** replay the engine's patterns by hand to "add coverage": that is the
copy that drifts. Add a rule to `betterleaks.toml` instead.

**Do not use `--baseline-path` as the gate.** It is safe for new and rotated
secrets (verified), but it degrades into "fail only on changes since this file
was generated", which ages badly.

**Never write a report to `/dev/stdout`.** `-r /dev/stdout` intermittently fails
with `permission denied` and the tool then exits 0 with zero findings —
indistinguishable from clean. Use a real file path. This cost several wrong
conclusions while evaluating.

## Other harnesses

The engine and the judgement layer are portable; only the hook API is not.

| harness | status |
|---|---|
| pi | full extension: hooks, confirm prompts, `/leakguard` commands, audit log |
| OpenCode | `plugins/opencode.ts` — path guard, egress check, redaction via `tool.execute.before`/`.after` |

Both read the **same** `~/.bin/betterleaks` and the **same** `betterleaks.toml`,
so the detection rules are identical and there is one thing to update. Install
the OpenCode plugin with:

```sh
cp plugins/opencode.ts ~/.config/opencode/plugins/leakguard.ts
```

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
