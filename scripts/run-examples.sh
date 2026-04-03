#!/usr/bin/env bash
# Run all open-passkey examples concurrently for manual testing.
# Each example gets its own background process; Ctrl-C kills them all.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
EXAMPLES="$ROOT/examples"
PIDS=()

cleanup() {
  echo ""
  echo "Stopping all examples..."
  for pid in "${PIDS[@]}"; do
    kill "$pid" 2>/dev/null || true
  done
  wait 2>/dev/null
  echo "Done."
}
trap cleanup EXIT INT TERM

# Helper: run a command in background, log its output with a prefix
run() {
  local name="$1"; shift
  local port="$1"; shift
  local dir="$1"; shift
  echo "  $name -> http://localhost:$port"
  (cd "$dir" && "$@") > /dev/null 2>&1 &
  PIDS+=($!)
}

# Install venv+deps for a Python example if needed
ensure_venv() {
  local dir="$1"; shift
  local deps=("$@")
  if [ ! -d "$dir/.venv" ]; then
    python3 -m venv "$dir/.venv"
  fi
  (source "$dir/.venv/bin/activate" && pip install -q "${deps[@]}")
}

# Install node_modules if needed
ensure_npm() {
  local dir="$1"
  if [ ! -d "$dir/node_modules" ]; then
    (cd "$dir" && npm install --silent)
  fi
}

echo "Installing dependencies (this may take a moment on first run)..."

# --- Python examples ---
ensure_venv "$EXAMPLES/flask" flask -e "$ROOT/packages/core-py" -e "$ROOT/packages/server-py" -e "$ROOT/packages/server-flask"
ensure_venv "$EXAMPLES/fastapi" fastapi uvicorn -e "$ROOT/packages/core-py" -e "$ROOT/packages/server-py" -e "$ROOT/packages/server-fastapi"
ensure_venv "$EXAMPLES/django" django -e "$ROOT/packages/core-py" -e "$ROOT/packages/server-py" -e "$ROOT/packages/server-django"

# --- Node.js examples ---
for dir in express fastify hono nestjs angular solid; do
  ensure_npm "$EXAMPLES/$dir"
done

# --- Full-stack JS frameworks ---
for dir in nextjs nuxt sveltekit astro remix; do
  ensure_npm "$EXAMPLES/$dir"
done

echo ""
echo "Starting examples..."
echo ""

# Python
run "Flask"       5001 "$EXAMPLES/flask"    bash -c "source .venv/bin/activate && python app.py"
run "FastAPI"     5002 "$EXAMPLES/fastapi"  bash -c "source .venv/bin/activate && python app.py"
run "Django"      5003 "$EXAMPLES/django"   bash -c "source .venv/bin/activate && python manage.py runserver 5003 --noreload"

# Go
run "Gin"         4001 "$EXAMPLES/gin"      go run main.go
run "net/http"    4002 "$EXAMPLES/nethttp"  go run main.go
run "Echo"        4003 "$EXAMPLES/echo"     go run main.go
run "Fiber"       4004 "$EXAMPLES/fiber"    go run main.go
run "Chi"         4005 "$EXAMPLES/chi"      go run main.go

# Rust
run "Axum"        3000 "$EXAMPLES/axum"     cargo run --quiet

# Node.js servers
run "Express"     3001 "$EXAMPLES/express"  npm start
run "Fastify"     3002 "$EXAMPLES/fastify"  npm start
run "Hono"        3003 "$EXAMPLES/hono"     npm start

# Full-stack JS
run "Next.js"     3004 "$EXAMPLES/nextjs"   npm run dev
run "Nuxt"        3005 "$EXAMPLES/nuxt"     npm run dev
run "SvelteKit"   3006 "$EXAMPLES/sveltekit" npm run dev
run "Remix"       3007 "$EXAMPLES/remix"    npm run dev
run "Astro"       3008 "$EXAMPLES/astro"    npm run dev
run "NestJS"      3009 "$EXAMPLES/nestjs"   npm start

# Angular (client + API server via concurrently)
run "Angular"     4200 "$EXAMPLES/angular"  npm start

# Solid (client + API server via concurrently)
run "Solid"       3011 "$EXAMPLES/solid"    npm start

# .NET
run "ASP.NET"     5000 "$EXAMPLES/aspnet"   dotnet run

# Java
run "Spring Boot" 8080 "$EXAMPLES/spring"   mvn -q spring-boot:run

echo ""
echo "All examples launched. Press Ctrl-C to stop."
echo ""
wait
