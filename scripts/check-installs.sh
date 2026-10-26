#!/bin/sh
# check-installs.sh — verify every surface where leakguard has to be live.
#
# WHY THIS EXISTS
#
# leakguard runs in four independent places, and each one failed silently at
# least once:
#
#   pi extension      does NOT pull its git checkout. It reconciles the package
#                     list at startup and leaves the code wherever it was, so the
#                     Mac sat 3 commits behind the repo with nothing reporting it.
#   opencode plugin   a manual copy with no update path. Drifted 135 lines behind
#                     and kept running: a stale plugin that loads is
#                     indistinguishable from a current one.
#   opencode runtime  caches the loaded module. Correcting the files is not
#                     enough — the running `opencode serve` keeps serving the old
#                     module and reports "Plugin failed" until it restarts. Found
#                     twice, on two machines, three days apart.
#   git hook          a copy, installed separately from the repo.
#
# Each surface can therefore be "correct on disk" and still be broken in
# practice. This script checks the file state AND, where it can, whether the
# running process actually loaded the current code.
#
# Usage:
#   scripts/check-installs.sh            check this machine
#   scripts/check-installs.sh --remote   also check server.calionauta.com over ssh
#
# Exit: 0 all good, 1 something needs fixing (each fix is printed).

set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REMOTE_HOST="${LEAKGUARD_REMOTE:-deploy@server.calionauta.com}"
REMOTE_DIR="${LEAKGUARD_REMOTE_DIR:-~/.pi/agent/git/github.com/calionauta/leakguard}"

problems=0
warn() { printf '  \033[33m%s\033[0m\n' "$*"; problems=$((problems + 1)); }
bad()  { printf '  \033[31m%s\033[0m\n' "$*"; problems=$((problems + 1)); }
good() { printf '  \033[32m%s\033[0m\n' "$*"; }
head_() { printf '\n\033[1m%s\033[0m\n' "$*"; }

# ---------------------------------------------------------------------------
# 1. pi extension: is the checkout on the same commit as this working copy?
# ---------------------------------------------------------------------------
check_pi() {
  head_ "pi extension"
  home="${1:-$HOME}"
  checkout="$home/.pi/agent/git/github.com/calionauta/leakguard"

  if [ ! -d "$checkout" ]; then
    bad "no checkout at $checkout (install: pi install git:github.com/calionauta/leakguard)"
    return
  fi

  installed="$(git -C "$checkout" rev-parse HEAD 2>/dev/null || echo unknown)"
  expected="$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"

  if [ "$installed" = "$expected" ]; then
    good "checkout at $(git -C "$checkout" log --oneline -1 | cut -c1-60)"
  else
    bad "checkout is STALE: at ${installed%"${installed#???????}"}, repo is at ${expected%"${expected#???????}"}"
    warn "fix: cd $checkout && git fetch -q origin main && git reset -q --hard origin/main"
  fi

  # The runtime reads index.ts; a missing dependency there is a load failure.
  if [ -f "$checkout/index.ts" ] && [ -f "$checkout/core/engine-client.ts" ]; then
    good "entry point and core/ present"
  else
    bad "missing index.ts or core/ in the checkout"
  fi
}

# ---------------------------------------------------------------------------
# 2. opencode plugin files: delegated, install-oc.sh already owns this check
# ---------------------------------------------------------------------------
check_oc_files() {
  head_ "opencode plugin (files)"
  if sh "$ROOT/scripts/install-oc.sh" --check >/dev/null 2>&1; then
    good "installed plugin matches the repo"
  else
    sh "$ROOT/scripts/install-oc.sh" --check 2>&1 | sed 's/^/  /' || true
    warn "fix: sh scripts/install-oc.sh"
  fi
}

# ---------------------------------------------------------------------------
# 3. opencode runtime: did the LOADED process get the current code?
#
# The module cache is per-process, so a correct file on disk proves nothing. The
# only honest signal is the most recent load in the harness log: compare when the
# file was last written against when the plugin last loaded cleanly.
# ---------------------------------------------------------------------------
check_oc_runtime() {
  head_ "opencode runtime (module cache)"
  home="${1:-$HOME}"
  log="$home/.local/share/opencode/log/opencode.log"
  plugin="$home/.config/opencode/plugins/leakguard/core/path-guard.ts"

  if [ ! -f "$log" ]; then
    good "no opencode log yet (nothing has loaded it)"
    return
  fi
  if [ ! -f "$plugin" ]; then
    bad "no installed plugin to check"
    return
  fi

  # Newest "failed to load" for leakguard, and newest successful load.
  last_fail="$(grep -a 'leakguard' "$log" 2>/dev/null | grep -a 'failed to load' | tail -1 || true)"
  last_ok="$(grep -a 'leakguard' "$log" 2>/dev/null | grep -a 'msg="loading plugin"' | tail -1 || true)"

  fail_ts="$(printf '%s' "$last_fail" | sed -n 's/^timestamp=\([^ ]*\).*/\1/p')"
  ok_ts="$(printf '%s' "$last_ok" | sed -n 's/^timestamp=\([^ ]*\).*/\1/p')"

  if [ -n "$last_fail" ] && { [ -z "$ok_ts" ] || [ "$fail_ts" \> "$ok_ts" ]; }; then
    cause="$(printf '%s' "$last_fail" | sed -n 's/.*cause="\(.*\)".*/\1/p' | cut -c1-90)"
    bad "the running process FAILED to load the plugin (latest event $fail_ts)"
    warn "  $cause"
    warn "  The files are probably fine; the process has a stale module cached."
    warn "  fix: restart the opencode service (this kills attached TUI sessions):"
    warn "    pkill -f 'opencode serve --service'; then reopen opencode"
    return
  fi

  if [ -z "$ok_ts" ]; then
    good "plugin has not been loaded yet (no load events)"
    return
  fi

  # Did the file change AFTER the last successful load? Then the process is
  # serving older code even though nothing errored.
  ok_epoch="$(date -j -f '%Y-%m-%dT%H:%M:%S' "${ok_ts%%.*}" +%s 2>/dev/null || date -d "${ok_ts%%.*}" +%s 2>/dev/null || echo 0)"
  file_epoch="$(stat -f %m "$plugin" 2>/dev/null || stat -c %Y "$plugin" 2>/dev/null || echo 0)"

  if [ "$ok_epoch" -gt 0 ] && [ "$file_epoch" -gt "$ok_epoch" ]; then
    warn "files are NEWER than the last successful load ($ok_ts)"
    warn "  the running process is serving older code; restart it to pick up changes"
    return
  fi

  good "loaded cleanly at $ok_ts, after the last file change"
}

# ---------------------------------------------------------------------------
# 4. git hook
# ---------------------------------------------------------------------------
check_hook() {
  head_ "git commit hook"
  home="${1:-$HOME}"
  hooks_path="$(git config --global core.hooksPath 2>/dev/null || true)"

  if [ -z "$hooks_path" ]; then
    warn "core.hooksPath is not set; no commit gate is active"
    warn "  fix: git config --global core.hooksPath ~/.git-hooks"
    return
  fi
  case "$hooks_path" in
    "~/"*) hooks_path="$home/${hooks_path#\~/}" ;;
  esac

  if [ ! -x "$hooks_path/pre-commit" ]; then
    bad "core.hooksPath=$hooks_path but pre-commit is missing or not executable"
    warn "  fix: cp hooks/pre-commit $hooks_path/pre-commit && chmod +x $hooks_path/pre-commit"
    return
  fi
  if cmp -s "$ROOT/hooks/pre-commit" "$hooks_path/pre-commit"; then
    good "installed hook matches the repo"
  else
    bad "installed hook DIFFERS from the repo"
    warn "  fix: cp $ROOT/hooks/pre-commit $hooks_path/pre-commit"
  fi
}

# ---------------------------------------------------------------------------
# 5. detection engine
# ---------------------------------------------------------------------------
check_engine() {
  head_ "detection engine (betterleaks)"
  home="${1:-$HOME}"
  found=""
  for c in "$home/.bin/betterleaks" "$home/bin/betterleaks"; do
    [ -x "$c" ] && found="$c" && break
  done
  if [ -z "$found" ]; then
    bad "not found in ~/.bin or ~/bin — every value-level guard is DEGRADED"
    warn "  fix: ~/.bin/betterleaks-update (or ~/bin on Linux)"
    return
  fi
  good "found at $found ($("$found" --version 2>/dev/null | head -1 || echo 'version unknown'))"
}

if [ "${1:-}" = "--remote" ]; then
  shift
fi

check_pi
check_oc_files
check_oc_runtime
check_hook
check_engine

if [ "${1:-}" = "--remote" ] || [ "${LEAKGUARD_CHECK_REMOTE:-}" = "1" ]; then
  printf '\n\033[1m=== %s ===\033[0m\n' "$REMOTE_HOST"
  if ssh -o ConnectTimeout=20 -o BatchMode=yes "$REMOTE_HOST" \
      "cd $REMOTE_DIR && sh scripts/check-installs.sh 2>&1" 2>/dev/null; then
    :
  else
    bad "remote check failed or host unreachable"
  fi
fi

printf '\n'
if [ "$problems" -eq 0 ]; then
  printf '\033[32mAll surfaces OK.\033[0m\n'
  exit 0
fi
printf '\033[31m%d problem(s) — fix lines above.\033[0m\n' "$problems"
exit 1
