# pi-leakguard

Secret-exposure seatbelt for the [pi.dev](https://pi.dev) coding agent.

Blocks the agent from reading credential files, blocks a credential from leaving
the machine, redacts credentials from tool output **before the model sees them**,
and gates git commits.

Detection is delegated to [**betterleaks**](https://github.com/betterleaks/betterleaks)
(471 rules, one static binary). This package is the layer a scanner cannot be: it
decides whether the *agent* may read a path, whether a *command* is exporting
something, and what to tell the model when it refuses.

## Install

```sh
# 1. the engine (required)
~/.bin/betterleaks-update

# 2. the extension
pi install git:github.com/calionauta/leakguard
```

Installed from the **repository root** — `pi` has no subdirectory support for git
packages, and it identifies git packages by repository URL.

## What it does

| layer | action | catches |
|---|---|---|
| path guard | BLOCK | `~/.ssh/`, `.env`, `.aws/`, `.gnupg/`, `.kube/`, `.secrets/`, keychains, `/etc/shadow` |
| symlink guard | BLOCK | a symlink resolving into a protected path |
| obfuscation | BLOCK | homoglyph / zero-width / NFKC tricks in commands |
| shell exfil | BLOCK | a real network invocation carrying a credential |
| egress DLP | BLOCK | a secret-bearing header with a value, credentialed URLs |
| taint tracking | BLOCK | egress of content previously read from a sensitive path |
| output redaction | REDACT | any credential betterleaks reports |
| git scan | BLOCK | a credential in the staged diff on commit |
| engine state | INJECT | one line into the agent's context when the engine is missing or drifted |

## Commands

`/leakguard status`, `mode`, `allow-once`, `trust <pattern>`, `untrust`, `audit`.

## What it deliberately does not do

- **No pattern list.** The 31 hand-written regexes were deleted: measured across
  29 token shapes, betterleaks covered 27, and every shape the regexes caught and
  the engine missed was a shape they *also* over-matched.
- **No auto-update.** The rules are compiled into the binary, so a version bump is
  a rule change. Install asks once; drift is reported and left to you.
- **Not a sandbox.** It stops accidents and common exfiltration patterns. For
  untrusted code or unattended automation, use a real sandbox.

## Formats that are documented, not blocked

Once a value is redacted its nature is unknowable, so the extension can *describe*
a finding's shape without exposing it (`describe-file.ts`). This is what makes the
gate usable on a repo that legitimately contains credential-shaped test fixtures
and documentation.

## Licence

MIT. Shared core with the OpenCode host: <https://github.com/calionauta/leakguard>.
