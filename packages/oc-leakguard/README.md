# oc-leakguard

Secret-exposure guard for [OpenCode](https://opencode.ai).

Blocks the agent from reading credential files, blocks a credential from leaving
the machine in a shell command, and redacts credentials from tool output **before
the model sees them**.

Detection is delegated to [**betterleaks**](https://github.com/betterleaks/betterleaks)
(471 rules, one static binary). This package is the part a scanner cannot be: it
knows that `~/.ssh/id_rsa` is off-limits and that `curl -d "k=..."` is an exfil,
and it decides what to tell the model when it refuses.

## Install

```sh
# 1. the engine (required)
~/.bin/betterleaks-update

# 2. the plugin
opencode plugin add github:calionauta/leakguard

# or from a checkout
cp -r packages/oc-leakguard ~/.config/opencode/plugins/leakguard
```

No npm publish needed — OpenCode accepts a Git package specifier.

## What it does

| layer | action | catches |
|---|---|---|
| path guard | throws | `~/.ssh/`, `.env`, `.aws/`, `.gnupg/`, `.kube/`, `.secrets/`, keychains |
| egress | throws | a real network invocation carrying a credential |
| redaction | rewrites | any credential betterleaks reports in tool output |
| engine state | injects | one line into the system prompt when the engine is missing or drifted |

Documentation and fixture paths are allowed on purpose: refusing to read
`docs/setup.md` would make the guard useless for writing docs about secrets.

## What it deliberately does not do

- **No pattern list.** Every credential shape comes from the engine. A second copy
  of rules is a copy that drifts — that is why the pi host's 31 hand-written
  regexes were deleted.
- **No confirm prompt.** OpenCode's hook API can throw but not ask. To allow a
  one-off, resolve it in `betterleaks.toml` or remove the rule from the path set.
- **Not a sandbox.** It stops accidents and common exfiltration patterns, not a
  determined attacker with shell access.

## The engine, and why updates are manual

Betterleaks' 463 default rules are compiled **into** the binary, so a version
change *is* a rule change. Auto-updating a secret scanner means it swaps its own
detection logic unreviewed — and every false positive in this project's history
came from a rule change.

So: installing a missing engine is offered once, with consent; updating is
reported and left to you. `~/.config/betterleaks/VERSION` records the pin;
drift is surfaced at `session.created` and in the system prompt.

## Two layouts

macOS keeps the engine at `~/.bin/betterleaks`, the Linux server at
`~/bin/betterleaks`. Both are probed. Assuming one made a gate fail closed on the
server once, which would have blocked every commit there.

## Licence

MIT. Shared core with the pi host: <https://github.com/calionauta/leakguard>.
