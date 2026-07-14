#!/usr/bin/env bash
# Runs the full CI-equivalent verification sequence locally, in the same
# order as .github/workflows/ci.yml, and reports pass/fail per step.
#
# Usage: ./sh.sh [path-to-repo-root]
#   Defaults to current directory if no path given.
set -uo pipefail
REPO="${1:-.}"
cd "$REPO" || { echo "Cannot cd into $REPO"; exit 1; }
if [ ! -f go.mod ]; then
  echo "go.mod not found in $REPO — point this script at the rayyan-asm repo root."
  exit 1
fi
PASS=0
FAIL=0
FAILED_STEPS=()
step() {
  local job="$1" name="$2"
  shift 2
  echo ""
  echo "==> [$job] $name"
  echo "    \$ $*"
  if "$@" > /tmp/verify-step.log 2>&1; then
    echo "    PASS"
    PASS=$((PASS+1))
  else
    echo "    FAIL (exit $?)"
    echo "    --- output (last 40 lines) ---"
    tail -n 40 /tmp/verify-step.log | sed 's/^/    /'
    echo "    -------------------------------"
    FAIL=$((FAIL+1))
    FAILED_STEPS+=("[$job] $name")
  fi
}
echo "Rayyan ASM — local CI verification"
echo "Repo: $(pwd)"
date
# ---------------- Backend ----------------
export RAYYAN_AUTH_JWTSECRET="${RAYYAN_AUTH_JWTSECRET:-ci-test-secret-not-for-production-use-only-32chars}"
export RAYYAN_AUTH_CREDENTIALKEY="${RAYYAN_AUTH_CREDENTIALKEY:-MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=}"
step "Backend" "go mod download" go mod download
step "Backend" "go build ./..." go build ./...
step "Backend" "go vet ./..." go vet ./...
step "Backend" "go test" go test ./... -timeout 180s
# ---------------- Lint ----------------
if command -v golangci-lint >/dev/null 2>&1; then
  step "Lint" "golangci-lint" golangci-lint run --timeout=5m
else
  echo ""
  echo "==> [Lint] golangci-lint"
  echo "    SKIPPED — golangci-lint not installed."
  echo "    Install: go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.61.0"
  FAILED_STEPS+=("[Lint] golangci-lint (not installed — see message above)")
  FAIL=$((FAIL+1))
fi
# ---------------- Frontend ----------------
if [ -d frontend ]; then
  pushd frontend > /dev/null
  step "Frontend" "npm ci" npm ci
  step "Frontend" "tsc --noEmit" npx tsc --noEmit
  step "Frontend" "npm run lint" npm run lint
  step "Frontend" "npm run build" npm run build
  step "Frontend" "vitest run" npx vitest run
  popd > /dev/null
else
  echo "frontend/ not found — skipping frontend jobs"
fi
# ---------------- Docker smoke test ----------------
if command -v docker >/dev/null 2>&1; then
  step "Docker" "compose build" docker compose -f docker-compose.yml build
  step "Docker" "compose up -d" docker compose -f docker-compose.yml up -d
  echo ""
  echo "==> [Docker] waiting for /health"
  HEALTH_OK=0
  for i in $(seq 1 45); do
    if curl -sf http://localhost:8080/health > /tmp/verify-step.log 2>&1; then
      echo "    PASS (after $((i*2))s)"
      HEALTH_OK=1
      PASS=$((PASS+1))
      break
    fi
    sleep 2
  done
  if [ "$HEALTH_OK" -eq 0 ]; then
    echo "    FAIL — /health never returned 200 within 90s"
    docker compose -f docker-compose.yml ps
    docker compose -f docker-compose.yml logs --tail=80
    FAIL=$((FAIL+1))
    FAILED_STEPS+=("[Docker] /health check")
  fi
  echo ""
  echo "==> [Docker] tear down"
  docker compose -f docker-compose.yml down -v
else
  echo "docker not found — skipping docker smoke test"
fi
# ---------------- Summary ----------------
echo ""
echo "================ SUMMARY ================"
echo "Passed: $PASS"
echo "Failed: $FAIL"
if [ "$FAIL" -gt 0 ]; then
  echo ""
  echo "Failed steps:"
  for s in "${FAILED_STEPS[@]}"; do
    echo "  - $s"
  done
  echo ""
  echo "Paste the FAIL output blocks above back into the chat and I'll fix them."
  exit 1
else
  echo "All steps passed."
  exit 0
fi
