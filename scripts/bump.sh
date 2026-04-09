#!/bin/bash
set -e

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

PART=${1:-patch}  # major, minor, or patch (default: patch)

CURRENT=$(cat "$ROOT/VERSION" | tr -d '[:space:]')
IFS='.' read -r MAJOR MINOR PATCH <<< "$CURRENT"

case "$PART" in
  major) MAJOR=$((MAJOR + 1)); MINOR=0; PATCH=0 ;;
  minor) MINOR=$((MINOR + 1)); PATCH=0 ;;
  patch) PATCH=$((PATCH + 1)) ;;
  *) echo "Usage: $0 [major|minor|patch]"; exit 1 ;;
esac

NEW="$MAJOR.$MINOR.$PATCH"
echo "$NEW" > "$ROOT/VERSION"
echo "Bumped $CURRENT -> $NEW"

# Sync all packages
"$ROOT/scripts/sync-versions.sh"
