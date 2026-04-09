#!/bin/bash
set -e

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION=$(cat "$ROOT/VERSION" | tr -d '[:space:]')

echo "Publishing open-passkey v$VERSION to all registries"
echo ""

# ─── npm (18 packages) ──────────────────────────────────────────────
publish_npm() {
  local pkg=$1
  echo "=== npm: $pkg ==="
  cd "$ROOT/packages/$pkg"
  npm run build
  npm publish --access public
}

publish_angular() {
  echo "=== npm: angular ==="
  cd "$ROOT/packages/angular"
  npm run build
  cd dist
  npm publish --access public
}

echo "── npm ──"
for pkg in core-ts sdk-js authenticator-ts; do publish_npm "$pkg"; done
publish_npm server-ts
for pkg in server-express server-fastify server-hono server-nestjs \
           server-nextjs server-nuxt server-sveltekit server-remix server-astro; do
  publish_npm "$pkg"
done
for pkg in react vue svelte solid; do publish_npm "$pkg"; done
publish_angular

# ─── PyPI (5 packages) ──────────────────────────────────────────────
publish_py() {
  local pkg=$1
  echo "=== pypi: $pkg ==="
  cd "$ROOT/packages/$pkg"
  rm -rf dist/
  python3 -m build
  twine upload dist/*
}

echo ""
echo "── PyPI ──"
publish_py core-py
publish_py server-py
for pkg in server-flask server-fastapi server-django; do publish_py "$pkg"; done

# ─── NuGet (2 packages) ─────────────────────────────────────────────
echo ""
echo "── NuGet ──"
echo "=== nuget: core-dotnet ==="
cd "$ROOT/packages/core-dotnet"
dotnet pack -c Release
dotnet nuget push bin/Release/*.nupkg --api-key "$NUGET_API_KEY" --source https://api.nuget.org/v3/index.json

echo "=== nuget: server-aspnet ==="
cd "$ROOT/packages/server-aspnet"
dotnet pack -c Release
dotnet nuget push bin/Release/*.nupkg --api-key "$NUGET_API_KEY" --source https://api.nuget.org/v3/index.json

# ─── crates.io (2 packages) ─────────────────────────────────────────
echo ""
echo "── crates.io ──"
echo "=== crates: core-rust ==="
cd "$ROOT/packages/core-rust"
cargo publish

echo "Waiting for crates.io index..."
sleep 30

echo "=== crates: server-axum ==="
cd "$ROOT/packages/server-axum"
cargo publish

# ─── Go module tags ──────────────────────────────────────────────────
echo ""
echo "── Go modules ──"
echo "Creating Go module tags..."
cd "$ROOT"
git tag "packages/core-go/v$VERSION"
git tag "packages/server-go/v$VERSION"
git push origin "packages/core-go/v$VERSION" "packages/server-go/v$VERSION"

# ─── Maven Central (2 packages) ─────────────────────────────────────
echo ""
echo "── Maven Central ──"
echo "=== maven: core-java ==="
cd "$ROOT/packages/core-java"
mvn deploy -P release --batch-mode

echo "=== maven: server-spring ==="
cd "$ROOT/packages/server-spring"
mvn deploy -P release --batch-mode

echo ""
echo "Done! All packages published as v$VERSION"
