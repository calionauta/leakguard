#!/bin/sh
# One-time detection-engine install, with explicit consent.
#
# WHAT THIS IS AND IS NOT
#
# This is NOT the runtime gate. Both hosts check the engine themselves and report
# a degraded state to the human AND to the model:
#
#   pi        index.ts startup notify + before_agent_start, so an agent never
#             spends a turn believing a credential gate is armed when it is not
#   opencode  offerInstall() at load
#
# So this script exists for the narrow case those do not cover: offering the
# install ONCE, at install time, when a terminal is present and the user is
# already waiting. It is wired as the npm `ensure-engine` script and is run by
# hand or by a packaging step -- not by `prepare`, because a git install is
# headless and a prompt there breaks the install (see CHANGELOG 0.13.0).
#
# TWO KINDS OF "DRIFT", which are not interchangeable:
#
#   engineStatus() (runtime)  compares the pinned VERSION file against the
#                             binary that is actually running. Answers "have the
#                             rules changed since this was reviewed?" -- the
#                             question that matters for trust, because rules are
#                             compiled into the binary.
#   this script               asks the vendored updater whether a NEWER RELEASE
#                             exists. Answers "should I update?".
#
# A host can be drifted-but-current or pinned-but-behind. Neither check subsumes
# the other, which is the only reason both exist.
#
# Invariants, because this may run in a pipeline:
#   - never prompts without a terminal (CI, piped output, npm install -g)
#   - never downloads without a yes
#   - always exits 0, so a missing engine warns instead of failing the install
#
# Rationale for asking rather than installing: see docs/engine-install-policy.md.
# Short version: installing a missing capability once, with consent, is different
# from silently replacing a secret scanner's rules behind the user's back.

set -u

warn() { printf '\033[33m%s\033[0m\n' "$*" >&2; }
note() { printf '%s\n' "$*" >&2; }

# Where the engine can live. Two layouts exist in practice: ~/.bin on macOS and
# ~/bin on the Linux server. Probe both rather than assuming one.
found=""
for candidate in "${HOME}/.bin/betterleaks" "${HOME}/bin/betterleaks"; do
  if [ -x "$candidate" ]; then
    found="$candidate"
    break
  fi
done

# The installer has the same two-layout problem as the engine itself: macOS keeps
# it at ~/.bin, the Linux server at ~/bin. Resolving only ~/.bin reported "install
# not present" on a host that had it, and skipped the drift notice entirely.
installer=""
for candidate in "${HOME}/.bin/betterleaks-update" "${HOME}/bin/betterleaks-update"; do
  if [ -x "$candidate" ]; then
    installer="$candidate"
    break
  fi
done

if [ -n "$found" ]; then
  # Present. Report drift (a newer release exists) but never install it: the
  # rule set is the thing being trusted. This is a notification, not an offer.
  # The vendored updater hardcodes BIN_DIR=$HOME/.bin and reads the installed
  # version ONLY from $HOME/.config/betterleaks/VERSION. On the Linux layout
  # (~/bin, no VERSION file) it therefore reports "update available (none -> X)"
  # for an engine that is present and current, and this script used to print that
  # as fact: "installed but not the latest (none -> 1.9.0)". Telling someone their
  # current scanner is stale is how a rules change gets waved through.
  #
  # So: trust the updater's notion of LATEST, but take INSTALLED from the binary we
  # actually found.
  if [ -n "$installer" ]; then
    latest="$("$installer" --check 2>/dev/null | sed -n 's/^latest *: *//p')"
    running="$("$found" --version 2>/dev/null | grep -o '[0-9][0-9.]*' | head -1)"
    if [ -n "$latest" ] && [ -n "$running" ] && [ "$latest" != "$running" ]; then
      note "leakguard: betterleaks $running is installed; $latest is available."
      note "  Rules are compiled into the binary, so this IS a rules change."
      note "  Review and apply with: $installer"
    elif [ -z "$latest" ]; then
      note "leakguard: could not check for a newer betterleaks (updater said nothing)."
    fi
  fi
  exit 0
fi

warn "leakguard: the betterleaks detection engine is not installed."
note "  Without it, credential detection is DEGRADED: path guards and the"
note "  judgement layers still apply, but secret scanning does not run."
note ""

# Never prompt in a non-interactive context. A pipeline must not hang on a
# question nobody can see, and an unattended install must not run network code.
if [ -n "${CI:-}" ] || [ "${CI:-}" = "true" ] || [ ! -t 0 ] || [ ! -t 2 ]; then
  note "  Not asking (non-interactive). Install it with:"
  if [ -n "$installer" ]; then
    note "    $installer"
  else
    note "    curl the latest release from gitHub.com/betterleaks/betterleaks"
  fi
  exit 0
fi

if [ -z "$installer" ]; then
  warn "  No installer found in ~/.bin or ~/bin; install betterleaks manually."
  note "  Fetch the binary from https://github.com/betterleaks/betterleaks/releases"
  exit 0
fi

printf 'Install the betterleaks engine now? [y/N] ' >&2
answer=""
read -r answer || answer=""
case "$answer" in
  y|Y|yes|YES)
    note "installing..."
    if "$installer"; then
      note "done. Verify with: ~/.bin/betterleaks --version"
    else
      warn "install failed; the extension will run DEGRADED until it succeeds"
    fi
    ;;
  *)
    note "skipped. Install later with: $installer"
    ;;
esac

# Always succeed: a warning about a missing engine must not fail a pip/npm/pi
# install, which would look like the package is broken.
exit 0
