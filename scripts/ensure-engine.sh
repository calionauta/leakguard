#!/bin/sh
# Offer to install the detection engine, with explicit consent.
#
# Runs as an npm `prepare` script, which fires both when a contributor clones the
# repo and when `pi install` fetches it. Therefore:
#   - it never prompts without a terminal (CI, piped output, npm install -g)
#   - it never downloads without a yes
#   - it always exits 0, so a missing engine warns instead of failing the install
#
# Rationale for asking rather than just installing: see
# docs/engine-install-policy.md. Short version: installing a missing capability
# once, with consent, is different from silently replacing a secret scanner's
# rules behind the user's back.

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
  if [ -n "$installer" ]; then
    status="$("$installer" --check 2>/dev/null | sed -n 's/^status *: *//p')"
    case "$status" in
      *"update available"*)
        note "leakguard: betterleaks is installed but not the latest ($status)."
        note "  Rules are compiled into the binary, so this IS a rules change."
        note "  Review and apply with: $installer"
        ;;
    esac
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
