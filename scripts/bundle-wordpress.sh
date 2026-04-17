#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$SCRIPT_DIR/.."
PLUGIN_SRC="$ROOT/packages/server-wordpress"
OUTPUT="${1:-$ROOT/open-passkey.zip}"

if [ ! -d "$PLUGIN_SRC/vendor" ]; then
    echo "Running composer install..."
    cd "$PLUGIN_SRC" && composer install --no-dev --optimize-autoloader
fi

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

cp -RL "$PLUGIN_SRC" "$TMPDIR/open-passkey"

rm -f "$TMPDIR/open-passkey/PLAN.md" \
      "$TMPDIR/open-passkey/composer.lock"
find "$TMPDIR/open-passkey" -name .DS_Store -delete
find "$TMPDIR/open-passkey" -name ".phpunit.cache" -exec rm -rf {} + 2>/dev/null || true
find "$TMPDIR/open-passkey" -name "phpunit.xml" -delete
find "$TMPDIR/open-passkey" -path "*/tests" -type d -exec rm -rf {} + 2>/dev/null || true

cd "$TMPDIR"
zip -rq "$OUTPUT" open-passkey/

echo "Bundled: $OUTPUT ($(du -h "$OUTPUT" | cut -f1))"
