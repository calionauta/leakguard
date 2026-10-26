# betterleaks engine — installation and update policy

`pi-leakguard`, its git hook, and the OpenCode plugin all delegate detection to
the **same** betterleaks binary. Without it, only path guards and the judgement
layers work; credential detection is off.

So the engine must always be present, and the install must say so before it
happens rather than blocking a commit later.

## The one rule

**Consent to install, notification to update.**

| situation | behaviour |
|---|---|
| engine missing | ask once, explicitly, then install on yes |
| engine present, a newer release exists | report it; never install |
| engine present, at the pinned version | say nothing |

The asymmetry is deliberate and it is not laziness. Installing a missing
dependency is a *new capability* — you say yes once, you know what you agreed
to. Silently upgrading a **secret scanner** is a change to the thing doing the
judging: its rules are compiled into the binary, so a version bump *is* a rules
change, and a scanner that swaps its own detection logic is unreviewable.

## Why not auto-update, when everyone else does

Endpoint antivirus auto-updates signatures because a signature is a *fact about
malware*, and being a day late is strictly worse. A scanner's rules are also
facts — but its **false positives** are not. Every false positive in this
project's history came from a rule change, not from a rule that was too old:

- a bare hex digest matched npm `integrity` fields and provenance files
- `Authorization:` matched the header *name* in documentation
- `ssh` and `export` matched ordinary prose in a heredoc

An auto-updating scanner delivers those to you unreviewed, mid-session, with no
record of what changed. Pinning and reporting inverts that: you find out, you
decide, and a regression is attributable to a version you chose.

The industry consensus points the same way — TruffleHog made its version check
opt-in after users objected to opt-out telemetry; CI guidance for security
scanners is to pin exact versions and explain rescans, because silent rule
updates make two runs of the same commit disagree.

## How the human and the model find out

Nothing depends on the model remembering to check.

| surface | when | what |
|---|---|---|
| pi extension | `session_start` | warning if absent or drifted |
| pi extension | `before_agent_start` | one-line context injected into the run |
| git hook | every commit | drift reported, commit allowed |
| OpenCode plugin | `session.created` | warning if absent or drifted |

The `before_agent_start` injection is what makes this work for an agent rather
than only for a person: the model sees the state at the start of the run, so it
does not have to discover a degraded gate halfway through a task.

## Concretely

```sh
~/.bin/betterleaks-update --check   # installed vs latest; changes nothing
~/.bin/betterleaks-update           # install or update, checksum-verified
~/.bin/betterleaks-update --version 1.9.0   # pin or roll back
```

The installed version is recorded in `~/.config/betterleaks/VERSION`. Drift is
computed from that file, so it survives a shell restart and is visible to every
consumer independently.

Checksums come from the release's `checksums.txt`; a mismatch refuses the
install. The new binary is smoke-tested (`--version`) *before* replacing the
working one, so a broken download cannot take the git hook down with it.

## Where the install is offered

- **`pi install git:github.com/calionauta/leakguard`** — a `prepare` script
  checks for the engine and, in an interactive terminal, asks whether to install
  it. In CI (`CI` set, or no TTY) it never prompts and never downloads; it prints
  the command and exits 0, so an install in a pipeline cannot hang.
- **The extension itself** — if the engine is still missing at `session_start`,
  it reports DEGRADED and names the exact command. It does not install on its
  own initiative mid-session.
- **The OpenCode plugin** — same report at `session.created`, no install.
