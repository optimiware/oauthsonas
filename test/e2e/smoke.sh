#!/usr/bin/env bash
# Smoke-test a built oauthsonas image: start it, check the probes, and complete
# a real authorization-code + PKCE login. Set CONTAINER_CLI=podman to use Podman.
set -euo pipefail

IMAGE="${1:-ghcr.io/optimiweb/oauthsonas:latest}"
CLI="${CONTAINER_CLI:-docker}"
NAME="oauthsonas-smoke-$$"

cleanup() {
  "$CLI" rm -f "$NAME" "$NAME-gate" >/dev/null 2>&1 || true
}
trap cleanup EXIT

fail() {
  echo "  FAIL: $*" >&2
  exit 1
}

wait_ready() { # name base
  for i in $(seq 1 30); do
    if curl -sf "$2/healthz" >/dev/null 2>&1; then
      echo "  ready after ${i}s"
      return
    fi
    sleep 1
  done
  echo "  server did not start within 30s" >&2
  "$CLI" logs "$1" >&2
  exit 1
}

# json_field NAME: print the string value of a top-level JSON field from stdin.
json_field() {
  sed -n "s/.*\"$1\":\"\\([^\"]*\\)\".*/\\1/p"
}

echo "=== smoke: --version ==="
"$CLI" run --rm "$IMAGE" --version

echo "=== smoke: default CMD (start server) ==="
"$CLI" run -d --rm --name "$NAME" -e OAUTHSONAS_ALLOW_NON_LOOPBACK=true -p 127.0.0.1::8181 "$IMAGE" >/dev/null
PORT=$("$CLI" port "$NAME" 8181 | head -1 | awk -F: '{print $NF}')
BASE="http://127.0.0.1:${PORT}"
wait_ready "$NAME" "$BASE"

echo "=== smoke: --healthcheck inside the container ==="
"$CLI" exec "$NAME" /usr/local/bin/oauthsonas --healthcheck --listen 0.0.0.0:8181 \
  || fail "--healthcheck reported unhealthy"

echo "=== smoke: /healthz /readyz discovery ==="
curl -sf "$BASE/healthz" | grep -q '"status":"ok"' || fail "/healthz"
curl -sf "$BASE/readyz" | grep -q '"status":"ready"' || fail "/readyz"
DISC=$(curl -sf "$BASE/.well-known/openid-configuration")
for field in authorization_endpoint token_endpoint jwks_uri userinfo_endpoint; do
  echo "$DISC" | grep -q "\"$field\"" || fail "discovery is missing $field"
done

echo "=== smoke: full login (authorize -> token -> userinfo) ==="
REDIRECT_URI="http://127.0.0.1:5173/auth/callback"
VERIFIER=$(openssl rand -hex 32)
CHALLENGE=$(printf '%s' "$VERIFIER" | openssl dgst -sha256 -binary | openssl base64 -A | tr '+/' '-_' | tr -d '=')
HEADERS=$(curl -s -o /dev/null -D - -G "$BASE/oauth2/auth" \
  --data-urlencode "response_type=code" \
  --data-urlencode "client_id=dashboard" \
  --data-urlencode "redirect_uri=$REDIRECT_URI" \
  --data-urlencode "scope=openid profile email" \
  --data-urlencode "state=smoke-state" \
  --data-urlencode "nonce=smoke-nonce-0123456789" \
  --data-urlencode "code_challenge=$CHALLENGE" \
  --data-urlencode "code_challenge_method=S256" \
  --data-urlencode "login_hint=acme-admin" | tr -d '\r')
LOCATION=$(echo "$HEADERS" | sed -n 's/^[Ll]ocation: //p')
echo "$LOCATION" | grep -q "^$REDIRECT_URI" || fail "authorize did not redirect to the callback: $LOCATION"
echo "$LOCATION" | grep -q "state=smoke-state" || fail "state was not preserved: $LOCATION"
CODE=$(echo "$LOCATION" | sed -n 's/.*[?&]code=\([^&]*\).*/\1/p')
[ -n "$CODE" ] || fail "no authorization code in $LOCATION"

TOKENS=$(curl -sf -X POST "$BASE/oauth2/token" \
  -d "grant_type=authorization_code" -d "client_id=dashboard" -d "code=$CODE" \
  --data-urlencode "redirect_uri=$REDIRECT_URI" -d "code_verifier=$VERIFIER") || fail "token exchange failed"
ACCESS=$(echo "$TOKENS" | json_field access_token)
[ -n "$ACCESS" ] || fail "no access_token in $TOKENS"
echo "$TOKENS" | grep -q '"id_token"' || fail "no id_token in token response"

USERINFO=$(curl -sf -H "Authorization: Bearer $ACCESS" "$BASE/userinfo") || fail "userinfo rejected the access token"
echo "  userinfo: $USERINFO"
echo "$USERINFO" | grep -q '"sub":"oauthsonas|acme-admin"' || fail "unexpected userinfo subject"

REUSE=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/oauth2/token" \
  -d "grant_type=authorization_code" -d "client_id=dashboard" -d "code=$CODE" \
  --data-urlencode "redirect_uri=$REDIRECT_URI" -d "code_verifier=$VERIFIER")
[ "$REUSE" = "400" ] || fail "authorization code reuse returned $REUSE, want 400"

echo ""
echo "=== smoke: access code gate ==="
GATE_CODE="smoke-access-code-0123456789"
"$CLI" run -d --rm --name "$NAME-gate" \
  -e OAUTHSONAS_ALLOW_NON_LOOPBACK=true \
  -e OAUTHSONAS_ACCESS_CODE="$GATE_CODE" \
  -p 127.0.0.1::8181 "$IMAGE" >/dev/null
GATE_PORT=$("$CLI" port "$NAME-gate" 8181 | head -1 | awk -F: '{print $NF}')
GATE_BASE="http://127.0.0.1:${GATE_PORT}"
wait_ready "$NAME-gate" "$GATE_BASE"
curl -sf "$GATE_BASE/oauth2/auth" | grep -q 'access-code-input' || fail "gate page not served"
WRONG=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$GATE_BASE/oauth2/gate" \
  --data-urlencode 'return_to=/oauth2/auth' --data-urlencode 'code=definitely-wrong')
[ "$WRONG" = "401" ] || fail "wrong code returned $WRONG, want 401"
RIGHT=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$GATE_BASE/oauth2/gate" \
  --data-urlencode 'return_to=/oauth2/auth' --data-urlencode "code=${GATE_CODE}")
[ "$RIGHT" = "303" ] || fail "valid code returned $RIGHT, want 303"

echo ""
echo "=== smoke: PASS ==="
