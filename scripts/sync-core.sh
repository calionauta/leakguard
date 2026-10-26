#!/bin/sh
# sync-core.sh — copy core/ into the packages that ship it.
#
# Why this exists: pi resolves a git package from the REPOSITORY ROOT (it reads
# the root package.json and identifies git packages by repo URL, with no
# subdirectory support), while OpenCode installs an npm-shaped package that must
# be self-contained. So the repo keeps ONE source of truth in core/, and each
# package gets a copy at publish/install time.
#
# The copy is a build artifact, not a fork: this script overwrites it every time,
# so an edit made directly to packages/oc-leakguard/core/ is lost. That is
# intentional — two editable copies is exactly the drift this refactor removed.
#
# Usage: scripts/sync-core.sh          copy
#        scripts/sync-core.sh --check  fail if a copy is stale (use in CI)

set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/core"
MODE="${1:-}"

[ -d "$SRC" ] || { echo "missing $SRC" >&2; exit 1; }

stale=0
for pkg in oc-leakguard; do
  DST="$ROOT/packages/$pkg/core"
  if [ "$MODE" = "--check" ]; then
    if ! diff -r "$SRC" "$DST" >/dev/null 2>&1; then
      echo "  STALE  packages/$pkg/core differs from core/ — run scripts/sync-core.sh" >&2
      stale=$((stale + 1))
    fi
  else
    rm -rf "$DST"
    mkdir -p "$DST"
    cp "$SRC"/*.ts "$DST"/
    echo "synced core/ -> packages/$pkg/core/"
  fi
done

if [ "$MODE" = "--check" ]; then
  if [ "$stale" -eq 0 ]; then
    echo "core/ copies are in sync"
    exit 0
  fi
  exit 1
fi
