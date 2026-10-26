#!/usr/bin/env python3
"""verify-engine.py - check the engine STACK, not just that a file exists.

Every measurement in this project that went wrong, went wrong the same way: a
conclusion drawn from a fixture or a scope that did not match the thing being
claimed. This script encodes the traps that can be checked WITHOUT planting a
credential, so it is safe to run at any time and on any machine.

What it verifies (all static or engine-introspective):

  1. the engine is present, in either known layout, and runs
  2. the pinned version vs the running version (drift is REPORTED, never fixed)
  3. the config parses
  4. useDefault is true AND the resolved rule count proves the engine's own
     rules are still active -- i.e. nothing was overwritten
  5. every path allowlist is scoped with targetRules, so it cannot silence the
     engine's rules
  6. no local rule reuses an engine rule id (an override in disguise)

What it deliberately does NOT do, and where that lives instead:

  - behavioural proof that allowlists do not hide a credential, and that the
    add-on rules still cover legacy variants. Those need a planted credential,
    which a secret gate blocks on purpose. They were measured once, by hand,
    with the numbers recorded in docs/engine-install-policy.md and in the
    config header. Re-run them by hand after changing a rule or an allowlist.

Traps this script exists to prevent:
  - "betterleaks config show" does NOT emit targetRules, so their absence there
    proves nothing -> scoping is checked in the config text, and the docs say to
    confirm by behaviour.
  - A path allowlist applies to every rule unless scoped -> check 5.
  - useDefault silently lost -> check 4, with a rule-count floor.
  - Drift unnoticed -> check 2.

Usage:  verify-engine.py [--quiet]
Exit:   0 all pass, 1 a check failed, 2 the engine is missing.
"""

import os
import re
import subprocess
import sys

QUIET = "--quiet" in sys.argv
FAILED = 0


def say(m):
    if not QUIET:
        print(m)


def ok(m):
    if not QUIET:
        print("  PASS  " + m)


def warn(m):
    print("  WARN  " + m, file=sys.stderr)


def bad(m):
    global FAILED
    FAILED += 1
    print("  FAIL  " + m, file=sys.stderr)


HOME = os.path.expanduser("~")
CFG = os.path.join(HOME, ".config", "betterleaks", "betterleaks.toml")
PIN = os.path.join(HOME, ".config", "betterleaks", "VERSION")

# Two layouts exist in practice: ~/.bin on macOS, ~/bin on the Linux server.
ENGINE = None
for cand in (os.path.join(HOME, ".bin", "betterleaks"), os.path.join(HOME, "bin", "betterleaks")):
    if os.access(cand, os.X_OK):
        ENGINE = cand
        break

if not ENGINE:
    print("  FAIL  engine missing - install with ~/.bin/betterleaks-update", file=sys.stderr)
    print("        pi-leakguard runs DEGRADED: path guards only, no secret scanning", file=sys.stderr)
    sys.exit(2)

say("engine: " + ENGINE)

# --- 1. runs ---------------------------------------------------------------
try:
    out = subprocess.run([ENGINE, "--version"], capture_output=True, text=True, timeout=30).stdout
except Exception as exc:
    out = ""
    bad("engine does not run: %s" % exc)

ver = ""
for tok in out.split():
    if tok[:1].isdigit() and tok.count(".") >= 1:
        ver = tok.strip("v")
        break
if ver:
    ok("engine runs (%s)" % ver)

# --- 2. drift is reported, never corrected --------------------------------
pinned = ""
if os.path.exists(PIN):
    pinned = open(PIN, encoding="utf-8").read().strip()
if pinned and ver and pinned != ver:
    warn("drift: pinned %s, running %s - rules are compiled into the binary" % (pinned, ver))
    warn("        review, then run ~/.bin/betterleaks-update (never automatic)")

# --- 3. config parses -----------------------------------------------------
if not os.path.exists(CFG):
    bad("no config at %s" % CFG)
    print()
    print("1 check(s) failed" if FAILED else "", file=sys.stderr)
    sys.exit(1)

chk = subprocess.run([ENGINE, "config", "check", "--config", CFG],
                     capture_output=True, text=True, timeout=120)
if chk.returncode == 0:
    first = (chk.stdout.strip().split(chr(10)) or [""])[0]
    ok("config parses (%s)" % first[:70])
else:
    bad("config does not parse: %s" % chk.stderr.strip()[:140])

cfg = open(CFG, encoding="utf-8").read()

# --- 4. engine defaults still active --------------------------------------
show = subprocess.run([ENGINE, "config", "show", "--config", CFG],
                      capture_output=True, text=True, timeout=180).stdout
resolved = show.count("[[rules]]")

m = re.search(r"useDefault\s*=\s*(\w+)", cfg)
if m and m.group(1) == "true":
    if resolved > 400:
        ok("engine defaults active (%d rules resolved)" % resolved)
    else:
        bad("useDefault is true but only %d rules resolved - defaults may be lost" % resolved)
else:
    bad("useDefault is not true: the engine's own rules are NOT active")

# --- 5. every path allowlist is scoped -----------------------------------
# A path allowlist applies to EVERY rule unless targetRules narrows it. Before
# scoping, a real credential in docs/, testdata/, vendor/ and *.test.ts files was
# invisible in six of eight locations. Assert the scoping exists.
#
# Parsed per [[allowlists]] block rather than by a fixed character window: a
# window-based check silently passes when the block is long, which is exactly the
# kind of false confidence this script exists to prevent.
blocks = re.split(r"\[\[allowlists\]\]", cfg)[1:]
unscoped = []
scoped = 0
for blk in blocks:
    if not re.search(r"^\s*paths\s*=\s*\[", blk, re.M):
        continue                      # not a path allowlist; not in scope here
    if re.search(r"^\s*targetRules\s*=\s*\[", blk, re.M):
        scoped += 1
    else:
        # identify the block for the error message
        hdr = re.search(r'description\s*=\s*"([^"]{0,60})', blk)
        unscoped.append(hdr.group(1) if hdr else "(no description)")

if scoped and not unscoped:
    ok("all %d path allowlists are scoped with targetRules" % scoped)
elif unscoped:
    bad("%d path allowlist(s) UNSCOPED - they also silence the engine's rules: %s"
        % (len(unscoped), "; ".join(unscoped[:3])))
else:
    warn("no path allowlists found - nothing to scope")

# --- 6. no local rule reuses an engine rule id ---------------------------
engine_ids = set(re.findall(r"^\s*id\s*=\s*['\"]([^'\"]+)['\"]", show, re.M))
local_ids = re.findall(r"^id\s*=\s*['\"]([^'\"]+)['\"]", cfg, re.M)
clashes = [i for i in local_ids if i in engine_ids and not i.startswith("lg-")]
if local_ids and not clashes:
    ok("no local rule overrides an engine id (%d local rules, add-only)" % len(local_ids))
elif clashes:
    bad("local rules reuse engine ids (an override in disguise): %s" % ", ".join(clashes[:5]))

print()
if FAILED == 0:
    say("all engine-stack checks passed")
    sys.exit(0)
print("%d check(s) failed" % FAILED, file=sys.stderr)
sys.exit(1)
