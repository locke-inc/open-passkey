#!/bin/bash
set -e

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# Dependency-ordered layers
LAYER1=(core-ts sdk-js authenticator-ts)
LAYER2=(server-ts)
LAYER3=(server-express server-fastify server-hono server-nestjs server-nextjs server-nuxt server-sveltekit server-remix server-astro)
LAYER4=(react vue svelte solid)

ALL=("${LAYER1[@]}" "${LAYER2[@]}" "${LAYER3[@]}" "${LAYER4[@]}" angular)

# --- Patch versions ---
echo "=== Patching versions ==="
for pkg in "${ALL[@]}"; do
  echo "  $pkg: $(cd "$ROOT/packages/$pkg" && npm version patch --no-git-tag-version | tail -1)"
done

# --- Build & publish ---
publish_pkg() {
  local pkg=$1
  echo "=== $pkg: build ==="
  cd "$ROOT/packages/$pkg"
  npm run build
  echo "=== $pkg: publish ==="
  npm publish --access public
}

publish_angular() {
  echo "=== angular: build ==="
  cd "$ROOT/packages/angular"
  npm run build
  echo "=== angular: publish ==="
  cd dist
  npm publish --access public
}

echo ""
echo "=== Layer 1: core-ts, sdk-js, authenticator-ts ==="
for pkg in "${LAYER1[@]}"; do publish_pkg "$pkg"; done

echo ""
echo "=== Layer 2: server-ts ==="
for pkg in "${LAYER2[@]}"; do publish_pkg "$pkg"; done

echo ""
echo "=== Layer 3: server bindings ==="
for pkg in "${LAYER3[@]}"; do publish_pkg "$pkg"; done

echo ""
echo "=== Layer 4: frontend SDKs ==="
for pkg in "${LAYER4[@]}"; do publish_pkg "$pkg"; done

echo ""
echo "=== Layer 5: angular ==="
publish_angular

echo ""
echo "Done! All packages published."
