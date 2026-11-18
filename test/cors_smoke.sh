#!/bin/bash
# CORS: the app page (demipass.com) calls api.dustforge.com, so the browser preflights every PUT/PATCH/DELETE and
# refuses a method the server does not list, before the server sees it ("Failed to fetch"). Every HTTP method the app
# page uses must be in Access-Control-Allow-Methods (Aaron 2026-11-18: the owner refill's PUT was not; "Failed to
# fetch" with nothing logged).
set -u
W=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
S=$(mktemp -d /tmp/dustforge-cors-smoke.XXXXXX)
PORT=${PORT:-3835}; API=http://127.0.0.1:$PORT
[ -d "$W/node_modules" ] || export NODE_PATH=${NODE_PATH:-/home/flimflam/project/dustforge/node_modules}
export IDENTITY_MASTER_KEY=$(python3 -c 'import secrets;print(secrets.token_hex(32))') DB_PATH=$S/dustforge.db PORT \
  STALWART_HOST=127.0.0.1 STALWART_PORT=1 SMTP_HOST=127.0.0.1 SMTP_PORT=9
cd "$W"
fails=0; ok(){ echo "ok   $*"; }; fail(){ echo "FAIL $*"; fails=$((fails+1)); }
node server.js >"$S/server.log" 2>&1 & SRV=$!; trap 'kill $SRV 2>/dev/null; rm -rf "$S"' EXIT
for i in $(seq 1 40); do curl -s -o /dev/null "$API/api/health" && break; sleep 0.5; done
# Every method the app page calls api() with, from the page itself: never a list kept by hand.
USED=$(grep -o -E "api\('(GET|POST|PUT|PATCH|DELETE)'" public/vault-mobile.html | sed -E "s/api\('//; s/'//" | sort -u)
[ -n "$USED" ] || fail "no api() calls found in the app page"
for m in $USED; do
  ALLOW=$(curl -s -i -X OPTIONS "$API/api/fleet/x/owner-refill" -H 'Origin: https://demipass.com' -H "Access-Control-Request-Method: $m" -H 'Access-Control-Request-Headers: authorization,content-type' | grep -i '^Access-Control-Allow-Methods:' | tr -d '\r')
  echo "$ALLOW" | grep -q -w "$m" && ok "preflight for $m: allowed" || fail "preflight for $m: not in '$ALLOW'"
done
echo "$fails failure(s)"; exit $(( fails > 0 ))
