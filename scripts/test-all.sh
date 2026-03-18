#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FAIL=0

run() {
  echo "=== $1 ==="
  if (cd "$ROOT/$2" && eval "$3"); then
    echo "--- PASS: $1"
  else
    echo "--- FAIL: $1"
    FAIL=1
  fi
  echo
}

run "core-go"    "packages/core-go"    "go test ./... -v"
run "server-go"  "packages/server-go"  "go test ./... -v"
run "core-ts"          "packages/core-ts"          "npm test"
run "authenticator-ts"  "packages/authenticator-ts"  "npm test"
run "angular"          "packages/angular"          "npm test"

if [ $FAIL -ne 0 ]; then
  echo "SOME TESTS FAILED"
  exit 1
fi

echo "ALL TESTS PASSED"
