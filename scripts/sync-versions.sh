#!/bin/bash
set -e

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION=$(cat "$ROOT/VERSION" | tr -d '[:space:]')

if [ -z "$VERSION" ]; then
  echo "ERROR: VERSION file is empty"
  exit 1
fi

echo "Syncing all packages to version $VERSION"

# --- npm (package.json) ---
for pkg in core-ts sdk-js authenticator-ts server-ts \
           server-express server-fastify server-hono server-nestjs \
           server-nextjs server-nuxt server-sveltekit server-remix server-astro \
           react vue svelte solid angular; do
  FILE="$ROOT/packages/$pkg/package.json"
  if [ -f "$FILE" ]; then
    # Use node to update version in-place (preserves formatting better than sed)
    node -e "
      const fs = require('fs');
      const pkg = JSON.parse(fs.readFileSync('$FILE', 'utf8'));
      pkg.version = '$VERSION';
      fs.writeFileSync('$FILE', JSON.stringify(pkg, null, 2) + '\n');
    "
    echo "  npm: $pkg -> $VERSION"
  fi
done

# --- Python (pyproject.toml) ---
for pkg in core-py server-py server-flask server-fastapi server-django; do
  FILE="$ROOT/packages/$pkg/pyproject.toml"
  if [ -f "$FILE" ]; then
    sed -i '' "s/^version = \".*\"/version = \"$VERSION\"/" "$FILE"
    echo "  pypi: $pkg -> $VERSION"
  fi
done

# --- Java (pom.xml) ---
for pkg in core-java server-spring; do
  FILE="$ROOT/packages/$pkg/pom.xml"
  if [ -f "$FILE" ]; then
    # Update the first <version>X.Y.Z</version> occurrence (the project's own version).
    # Uses Python instead of sed because BSD sed (macOS) doesn't support 0,/RE/ addresses.
    python3 -c "
import re
with open('$FILE', 'r') as f:
    content = f.read()
content = re.sub(
    r'(<version>)\d+\.\d+\.\d+(</version>)',
    r'\g<1>$VERSION\2',
    content,
    count=1
)
with open('$FILE', 'w') as f:
    f.write(content)
"
    echo "  maven: $pkg -> $VERSION"
  fi
done
# Also update server-spring's dependency on core-java
SPRING_POM="$ROOT/packages/server-spring/pom.xml"
if [ -f "$SPRING_POM" ]; then
  sed -i '' "s|<artifactId>core-java</artifactId>|<artifactId>core-java</artifactId>|" "$SPRING_POM"
  # Update the core-java dependency version
  python3 -c "
import re
with open('$SPRING_POM', 'r') as f:
    content = f.read()
content = re.sub(
    r'(<artifactId>core-java</artifactId>\s*<version>)[^<]*(</version>)',
    r'\g<1>$VERSION\2',
    content
)
with open('$SPRING_POM', 'w') as f:
    f.write(content)
"
fi

# --- .NET (.csproj) ---
for proj in "$ROOT/packages/core-dotnet/OpenPasskey.Core.csproj" \
            "$ROOT/packages/server-aspnet/OpenPasskey.AspNet.csproj"; do
  if [ -f "$proj" ]; then
    sed -i '' "s|<Version>.*</Version>|<Version>$VERSION</Version>|" "$proj"
    echo "  nuget: $(basename "$proj") -> $VERSION"
  fi
done

# --- Rust (Cargo.toml) ---
for pkg in core-rust server-axum; do
  FILE="$ROOT/packages/$pkg/Cargo.toml"
  if [ -f "$FILE" ]; then
    sed -i '' "s/^version = \".*\"/version = \"$VERSION\"/" "$FILE"
    echo "  crates: $pkg -> $VERSION"
  fi
done

# --- Go (no version in go.mod, uses git tags) ---
echo "  go: version is set via git tags (packages/core-go/v$VERSION, packages/server-go/v$VERSION)"

echo ""
echo "Done! All packages set to $VERSION"
echo ""
echo "Next steps:"
echo "  1. Commit the version bump"
echo "  2. Tag and push:  git tag v$VERSION && git push origin v$VERSION"
echo "  3. Go tags:       git tag packages/core-go/v$VERSION && git tag packages/server-go/v$VERSION"
echo "                    git push origin packages/core-go/v$VERSION packages/server-go/v$VERSION"
