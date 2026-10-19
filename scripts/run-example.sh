#!/usr/bin/env bash
# Run an agentgateway recipe locally: upstream, ans-authz, agentgateway.
# Usage: scripts/run-example.sh [http|mcp|oauth]
# Requires: bin/ans-authz (make build), the pinned agentgateway binary
# (make agentgateway-bin) and a transparency log reachable at the baseURL in
# the selected ans-authz YAML (the local ANS reference stack by default).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RECIPE="${1:-http}"
AGW_BIN="${AGENTGATEWAY_BIN:-$ROOT/.cache/agentgateway-$(uname -s | tr '[:upper:]' '[:lower:]')-$(uname -m | sed -e 's/x86_64/amd64/' -e 's/aarch64/arm64/')}"
ANS_AUTHZ_BIN="${ANS_AUTHZ_BIN:-$ROOT/bin/ans-authz}"
UPSTREAM_DIR="$ROOT/.cache/bin"

case "$RECIPE" in
  http)  gateway_cfg="$ROOT/examples/agentgateway/config-http.yaml";  verifier_cfg="$ROOT/examples/agentgateway/ans-authz.yaml";       upstream="echo";  upstream_port=8081 ;;
  mcp)   gateway_cfg="$ROOT/examples/agentgateway/config-mcp.yaml";   verifier_cfg="$ROOT/examples/agentgateway/ans-authz.yaml";       upstream="mcpecho"; upstream_port=3001 ;;
  oauth) gateway_cfg="$ROOT/examples/agentgateway/config-oauth.yaml"; verifier_cfg="$ROOT/examples/agentgateway/ans-authz-oauth.yaml"; upstream="echo";  upstream_port=8081 ;;
  *) echo "unknown recipe '$RECIPE' (http, mcp, oauth)" >&2; exit 2 ;;
esac

for bin in "$AGW_BIN" "$ANS_AUTHZ_BIN"; do
  [ -x "$bin" ] || { echo "missing binary $bin (run: make build agentgateway-bin)" >&2; exit 2; }
done

pids=()
cleanup() {
  for pid in "${pids[@]:-}"; do
    [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
  done
  wait 2>/dev/null || true
}
trap cleanup EXIT INT TERM

wait_for() {
  local url="$1" name="$2"
  for _ in $(seq 1 120); do
    if curl -fsS -o /dev/null "$url"; then
      echo "$name ready at $url"
      return 0
    fi
    sleep 0.5
  done
  echo "$name did not become ready at $url" >&2
  return 1
}

cd "$ROOT"

# Build the upstream to a binary and run that directly, so the trap's kill
# reaches the server itself rather than a `go run` parent.
mkdir -p "$UPSTREAM_DIR"
go build -o "$UPSTREAM_DIR/$upstream" "./examples/$upstream"
"$UPSTREAM_DIR/$upstream" &
pids+=($!)

"$ANS_AUTHZ_BIN" --config "$verifier_cfg" &
pids+=($!)
wait_for http://127.0.0.1:9192/readyz ans-authz

"$AGW_BIN" --validate-only -f "$gateway_cfg"
"$AGW_BIN" -f "$gateway_cfg" &
pids+=($!)
wait_for http://127.0.0.1:15021/healthz/ready agentgateway

cat <<MSG

recipe '$RECIPE' is running
  gateway      http://127.0.0.1:8080 (mcp recipe: http://127.0.0.1:3000/mcp)
  upstream     $upstream on 127.0.0.1:$upstream_port
  verifier     http://127.0.0.1:9192/readyz  http://127.0.0.1:9192/metrics
  gateway ui   http://localhost:15000/ui
Press Ctrl-C to stop.
MSG

wait
