#!/usr/bin/env bash
set -euo pipefail

IMAGE="${1:-ghcr.io/optimiweb/oauthsonas:latest}"
NAME="oauthsonas-smoke-$$"

cleanup() {
  docker rm -f "$NAME" "$NAME-gate" 2>/dev/null || true
}
trap cleanup EXIT

echo "=== smoke: --version ==="
docker run --rm "$IMAGE" --version
echo ""

echo "=== smoke: default CMD (start server) ==="
docker run -d --rm --name "$NAME" -e OAUTHSONAS_ALLOW_NON_LOOPBACK=true -p 0:8181 "$IMAGE"
PORT=$(docker port "$NAME" 8181 | head -1 | cut -d: -f2)
BASE="http://127.0.0.1:${PORT}"

for i in $(seq 1 30); do
  if curl -sf "$BASE/healthz" > /dev/null 2>&1; then
    echo "  server ready after ${i}s"
    break
  fi
  if [ "$i" -eq 30 ]; then
    echo "  server did not start within 30s" >&2
    docker logs "$NAME"
    exit 1
  fi
  sleep 1
done

echo "=== smoke: /healthz ==="
HEALTH=$(curl -sf "$BASE/healthz")
echo "  $HEALTH"
echo "$HEALTH" | grep -q '"status":"ok"'
echo "$HEALTH" | grep -q '"issuer"'

echo "=== smoke: /readyz ==="
READY=$(curl -sf "$BASE/readyz")
echo "  $READY"
echo "$READY" | grep -q '"status":"ready"'

echo "=== smoke: /.well-known/openid-configuration ==="
DISC=$(curl -sf "$BASE/.well-known/openid-configuration")
echo "  issuer: $(echo "$DISC" | grep -o '"issuer":"[^"]*"')"
echo "$DISC" | grep -q '"authorization_endpoint"'
echo "$DISC" | grep -q '"token_endpoint"'
echo "$DISC" | grep -q '"jwks_uri"'

echo ""
echo "=== smoke: access code gate ==="
GATE_CODE="smoke-access-code-0123456789"
docker run -d --rm --name "$NAME-gate" \
  -e OAUTHSONAS_ALLOW_NON_LOOPBACK=true \
  -e OAUTHSONAS_ACCESS_CODE="$GATE_CODE" \
  -p 0:8181 "$IMAGE"
GATE_PORT=$(docker port "$NAME-gate" 8181 | head -1 | cut -d: -f2)
GATE_BASE="http://127.0.0.1:${GATE_PORT}"
for i in $(seq 1 30); do
  if curl -sf "$GATE_BASE/healthz" > /dev/null 2>&1; then
    echo "  gated server ready after ${i}s"
    break
  fi
  if [ "$i" -eq 30 ]; then
    echo "  gated server did not start within 30s" >&2
    docker logs "$NAME-gate"
    exit 1
  fi
  sleep 1
done
GATE_PAGE=$(curl -sf "$GATE_BASE/oauth2/auth")
echo "$GATE_PAGE" | grep -q 'access-code-input'
WRONG=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$GATE_BASE/oauth2/gate" \
  --data-urlencode 'return_to=/oauth2/auth' --data-urlencode 'code=definitely-wrong')
echo "  wrong code: $WRONG"
[ "$WRONG" = "401" ]
RIGHT=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$GATE_BASE/oauth2/gate" \
  --data-urlencode 'return_to=/oauth2/auth' --data-urlencode "code=${GATE_CODE}")
echo "  valid code: $RIGHT"
[ "$RIGHT" = "303" ]
docker rm -f "$NAME-gate"

echo ""
echo "=== smoke: PASS ==="
