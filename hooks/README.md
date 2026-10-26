# hooks/ — the commit gate

`pre-commit` here is a **copy** of the global gate that lives at
`~/.git-hooks/pre-commit` and runs through `core.hooksPath`. It is versioned
here because it is the layer that actually stops a credential reaching a commit,
and until now it existed on exactly two machines with no history and no review.

## Install

```sh
git config --global core.hooksPath ~/.git-hooks
cp hooks/pre-commit ~/.git-hooks/pre-commit
chmod +x ~/.git-hooks/pre-commit
```

Nothing else. It is plain POSIX `sh` with no dependency beyond the engine.

## What it checks, and why only this much

| check | why it is not in the engine |
|---|---|
| `.env` file refusal | a file holding only `DEBUG=true` contains no credential, so the engine exits 0 (measured) |
| fail closed when the engine is missing | a gate that passes when its scanner is gone is not a gate |
| chain to repo-local hooks | a global `core.hooksPath` otherwise SHADOWS `~/.git/hooks`, silently disabling every repo's own hook |

Everything else is delegated to betterleaks, with the same binary and the same
config the pi extension and the OpenCode plugin use. **Do not re-implement an
engine rule here.** That is the copy that drifts, and it is why the 31 regexes
were deleted from the extension.

## Traps this file already accounts for

- **Two engine layouts.** macOS keeps it at `~/.bin/betterleaks`, the Linux
  server at `~/bin/betterleaks`. The hook probes both. Assuming one made it fail
  closed on the server and would have blocked every commit there.
- **Never report to `/dev/stdout`.** `-r /dev/stdout` intermittently fails with
  `permission denied` and the tool then exits 0 with zero findings —
  indistinguishable from clean.
- **Scan the staged diff, not the tree.** The hook scans what is being committed.
  A working-tree scan also surfaces untracked `.env` files the commit does not
  contain, which trains people to bypass the gate.

## Verifying it actually blocks

A gate that is installed but inert is the failure mode worth worrying about.
`scripts/verify-engine.py` checks the extension side; for the gate, commit a
file containing a credential in a throwaway repo and confirm it is refused:

```sh
d=$(mktemp -d); cd "$d"
git init -q . && git config user.email t@t.t && git config user.name t
git config core.hooksPath ~/.git-hooks
printf 'k=%s\n' "$(head -c 40 /dev/urandom | base64 | tr -d '=+/')" > f.txt
git add f.txt && git commit -m x     # must be refused
```

An engine-shaped token is needed for a *positive* test; a random string may be
correctly ignored for lacking a recognisable provider prefix. The
`scripts/verify-engine.py` control check covers that distinction.

## Where this is mirrored

`server-blueprint` versions the agent-side configuration (see its
`stack/pi/README.md`), but not this hook. If it is going to be reproducible on a
fresh machine, this directory is the source of truth to add there.
