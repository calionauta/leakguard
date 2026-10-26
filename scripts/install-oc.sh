#!/bin/sh
# install-oc.sh — install / update the OpenCode host from this checkout.
#
# WHY THIS EXISTS
#
# `opencode plugin add github:calionauta/leakguard` works now (see the note at the
# bottom), but it installs a PINNED snapshot and only refreshes when you re-run
# it. The pi host pulls from its git checkout on every start; the OpenCode host
# has no equivalent. That asymmetry is how the installed plugin drifted a full
# refactor behind the repo: 240-line core/ against the repo's 375, so OpenCode
# silently ran without line/column positions, without the curated rule names, and
# without the shared residual table. Nothing reported it, because a stale plugin
# that loads is indistinguishable from a current one.
#
# So: one command that copies, then VERIFIES the copy matches. The verification is
# the point — a copy step alone fails the same way it did before, silently.
#
# Usage:
#   scripts/install-oc.sh              install or update, then verify
#   scripts/install-oc.sh --check      verify only; exit 1 if stale (use in CI/hooks)
#   scripts/install-oc.sh --uninstall  remove the installed plugin
#
# Targets:
#   default                                  ~/.config/opencode/plugins/leakguard/
#   OPENCODE_PLUGINS_DIR=/path/to/plugins    explicit directory
#
# Safe to re-run. Removes the legacy single-file plugin (plugins/leakguard.ts) if
# present, because OpenCode would otherwise load it as a SECOND plugin alongside
# the directory.

set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PKG="$ROOT/packages/oc-leakguard"
MODE="${1:-}"

PLUGINS_DIR="${OPENCODE_PLUGINS_DIR:-${HOME}/.config/opencode/plugins}"
DEST="$PLUGINS_DIR/leakguard"
LEGACY="$PLUGINS_DIR/leakguard.ts"

die() { printf '\033[31m%s\033[0m\n' "$*" >&2; exit 1; }
note() { printf '%s\n' "$*" >&2; }
ok() { printf '\033[32m%s\033[0m\n' "$*" >&2; }

[ -d "$PKG" ] || die "missing $PKG (run from a full checkout)"

# The shipped copy must match the repo's single source. If it does not, the
# install would publish a stale core/ — exactly the drift this script exists to
# catch, so refuse rather than copy the wrong thing.
if ! sh "$ROOT/scripts/sync-core.sh" --check >/dev/null 2>&1; then
  die "packages/oc-leakguard/core is stale. Run: sh scripts/sync-core.sh"
fi

if [ "$MODE" = "--uninstall" ]; then
  rm -rf "$DEST" "$LEGACY"
  ok "removed $DEST"
  [ -e "$LEGACY" ] || ok "no legacy single-file plugin present"
  exit 0
fi

if [ "$MODE" = "--check" ]; then
  stale=0
  if [ ! -d "$DEST" ]; then
    note "  MISSING  $DEST"
    stale=$((stale + 1))
  else
    for f in index.ts package.json README.md; do
      if ! cmp -s "$PKG/$f" "$DEST/$f" 2>/dev/null; then
        note "  STALE    $f"
        stale=$((stale + 1))
      fi
    done
    for f in "$PKG"/core/*.ts; do
      base="$(basename "$f")"
      if ! cmp -s "$f" "$DEST/core/$base" 2>/dev/null; then
        note "  STALE    core/$base"
        stale=$((stale + 1))
      fi
    done
  fi
  if [ -e "$LEGACY" ]; then
    note "  LEFTOVER $LEGACY (loads as a second plugin; run without --check to remove)"
    stale=$((stale + 1))
  fi
  if [ "$stale" -eq 0 ]; then
    ok "installed OpenCode plugin matches the repo"
    exit 0
  fi
  die "installed OpenCode plugin is out of date ($stale difference(s))"
fi

[ -d "$PLUGINS_DIR" ] || die "no plugins directory at $PLUGINS_DIR — is OpenCode installed for this user?"

rm -rf "$DEST"
mkdir -p "$DEST/core"
cp "$PKG/index.ts" "$PKG/package.json" "$PKG/README.md" "$DEST"/
cp "$PKG"/core/*.ts "$DEST/core"/

if [ -e "$LEGACY" ]; then
  rm -f "$LEGACY"
  note "  removed $LEGACY (was loading as a second plugin)"
fi

# Verify by re-running the check, so a partial copy cannot report success.
if ! sh "$ROOT/scripts/install-oc.sh" --check >/dev/null 2>&1; then
  die "copy completed but verification failed — inspect $DEST"
fi

ok "installed to $DEST"
note ""
note "OpenCode loads this directory at startup. Restart OpenCode to pick it up,"
note "then confirm in its log that the plugin loaded:"
note "  grep -i leakguard ~/.local/share/opencode/log/opencode.log | tail -3"
note ""
note "A load failure is only a WARN and does not surface in the UI. If the last"
note "line for leakguard is not a successful load, the guard is NOT running."

# NOTE on `opencode plugin add github:calionauta/leakguard`
#
# That path works as of the commit that dropped the root `workspaces` field
# (anomalyco/opencode#49704: any build/prepare/preinstall/install/postinstall/
# prepack script OR a `workspaces` field makes the embedded npm fail the git
# dependency prepare step). It installs a pinned snapshot into the config's
# `plugins` array and re-resolves only when re-run.
#
# This script remains the recommended path because it (a) tracks the checkout,
# (b) verifies what it wrote, and (c) cleans up the legacy single-file plugin.
