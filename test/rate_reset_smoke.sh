#!/bin/bash
# The owner's rate-limit reset (Aaron 2026-11-15: "add a reset button that requires the app to get my pin / pattern /
# biometric to reset the rate limit").
#   - POST /api/identity/rate-limit/reset: a person's session only, a fresh PIN for intent rate-reset (single use),
#     clears the wallet's standard + fill counters, logs rate_limit_reset, capped by its own hourly limiter.
#   - The way back in has its own budgets: PIN verify, gate status and refresh still answer when the standard budget
#     is used up (before, a limited wallet could neither prove its PIN nor refresh its session).
#   - The app: a wallet 429 shows the reset banner; Settings has the button; the background polls are slower.
set -u
W=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
S=$(mktemp -d /tmp/dustforge-rate-reset.XXXXXX)
PORT=${PORT:-3874}; API=http://127.0.0.1:$PORT
[ -d "$W/node_modules" ] || export NODE_PATH=${NODE_PATH:-/home/flimflam/project/dustforge/node_modules}
export IDENTITY_MASTER_KEY=$(python3 -c 'import secrets;print(secrets.token_hex(32))') DB_PATH=$S/dustforge.db PORT \
  STALWART_HOST=127.0.0.1 STALWART_PORT=1 SMTP_RELAY_HOST= SMTP_HOST=127.0.0.1 SMTP_PORT=9 \
  RATE_STANDARD_MAX=20 RATE_RESET_MAX=4
cd "$W"
node server.js >>"$S/server.log" 2>&1 & SRV=$!
for i in $(seq 1 40); do curl -s -o /dev/null "$API/" && break; sleep 0.5; done
kill -0 $SRV 2>/dev/null || { echo "server died:"; tail -5 "$S/server.log"; exit 1; }
trap 'kill $SRV 2>/dev/null; [ -n "${KEEP:-}" ] || rm -rf "$S"' EXIT
H=$(printf '%s' hunter22 | sha256sum | cut -d' ' -f1)
SIL='silicon:rate-reset-smoke-token-0123456789'
node -e '
const identity = require("./identity"), crypto = require("crypto"); const Database = require("better-sqlite3"); const db = new Database(process.env.DB_PATH);
const id = identity.createIdentity(); const enc = id.encrypted_private_key || id.encryptedPrivateKey;
db.prepare("INSERT INTO identity_wallets (did, username, email, encrypted_private_key, balance_cents, password_hash) VALUES (?, ?, ?, ?, 100000, ?)").run(id.did, "rr-owner", "rr-owner@dustforge.com", enc, process.argv[1]);
db.prepare("INSERT INTO silicon_agents (agent_name, did, carbon_did, token_hash) VALUES (?, ?, ?, ?)").run("owner-bot", "did:silicon:rrown", id.did, crypto.createHash("sha256").update(process.argv[2]).digest("hex"));' "$H" "$SIL"

fails=0; ok(){ echo "ok   $*"; }; fail(){ echo "FAIL $*"; fails=$((fails+1)); }
J(){ python3 -c 'import json,sys; d=json.load(sys.stdin); v=d
for k in sys.argv[1].split("."):
    v = v[int(k)] if isinstance(v, list) else (v or {}).get(k)
print(v if not isinstance(v,(dict,list)) else json.dumps(v))' "$1"; }
Q(){ python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); r=c.execute(sys.argv[2]).fetchone(); print(r[0] if r else '')" "$DB_PATH" "$1"; }
call(){ local m=$1 p=$2 t=$3 b=${4:-}
  BODY=$(curl -s -o - -w '\n%{http_code}' -X "$m" "$API$p" -H 'Content-Type: application/json' ${t:+-H "Authorization: Bearer $t"} ${b:+-d "$b"})
  CODE=${BODY##*$'\n'}; BODY=${BODY%$'\n'*}; }

call POST /api/identity/auth-fingerprint "" '{"username":"rr-owner","password":"hunter22","scope":"transact","expires_in":"1h"}'
A=$(echo "$BODY" | J token); RT=$(echo "$BODY" | J refresh_token)
[ "$A" != None ] && ok "owner signed in" || { fail "login $CODE $BODY"; exit 1; }
call POST /api/identity/pin "$A" '{"pin":"4321","password":"hunter22"}'

# Use up the wallet's standard budget.
n=0; for i in $(seq 1 30); do call GET /api/blindkey/dashboard "$A"; [ "$CODE" = 429 ] && break; n=$((n+1)); done
[ "$CODE" = 429 ] && echo "$BODY" | grep -q 'this wallet' && [ "$(echo "$BODY" | J limiter)" = standard ] && ok "the standard budget runs out (429 'this wallet', limiter standard, after $n calls)" || fail "never limited: $CODE $BODY"
# Sign-in is counted by address and never on the caller's wallet: a Bearer token riding along can't move it onto a
# budget its owner can reset (review M1).
call POST /api/identity/auth-fingerprint "$A" '{"username":"rr-owner","password":"hunter22","scope":"transact","expires_in":"1h"}'
[ "$CODE" = 200 ] && ok "password sign-in is on its own (address) limiter, not the exhausted wallet budget" || fail "login while limited: $CODE $BODY"
# A biometric gate challenge rides on the gate budget (review L3).
call POST /api/identity/device/challenge "$A" '{"purpose":"gate","intent":"rate-reset:0"}'
[ "$CODE" != 429 ] && ok "a biometric gate challenge is not refused by the exhausted standard budget ($CODE)" || fail "device gate challenge: $CODE $BODY"

# The way back in still answers.
call GET /api/identity/gate/status "$A"; [ "$CODE" = 200 ] && ok "gate status still answers while limited" || fail "gate status: $CODE"
if [ "$RT" != None ] && [ -n "$RT" ]; then
  call POST /api/identity/refresh "" '{"refresh_token":"'$RT'"}'; [ "$CODE" = 200 ] && ok "refresh still answers while limited" || fail "refresh: $CODE $BODY"
  A2=$(echo "$BODY" | J token); [ "$A2" != None ] && A=$A2
else fail "no refresh token from sign-in"; fi

# No PIN, an agent token: refused.
call POST /api/identity/rate-limit/reset "$A" '{}'
[ "$CODE" = 403 ] && [ "$(echo "$BODY" | J intent)" = rate-reset:0 ] && ok "without a fresh PIN: 403 asking for it (intent rate-reset:0)" || fail "no pin: $CODE $BODY"
call POST /api/identity/rate-limit/reset "$SIL" '{}'
[ "$CODE" = 403 ] && echo "$BODY" | grep -q 'not by an agent token' && ok "an agent token is refused" || fail "silicon: $CODE $BODY"
call POST /api/identity/gate/verify "$SIL" '{"gate":"password","password":"guess"}'
[ "$CODE" = 403 ] && echo "$BODY" | grep -q "a person's" && ok "an agent token can't try the owner's password through the gate (no per-agent guessing budget)" || fail "agent password gate: $CODE $BODY"
for i in 1 2 3 4 5 6; do call POST /api/identity/rate-limit/reset "$SIL" '{}'; done
[ "$CODE" = 403 ] && ok "an agent's refused calls don't count against the owner's resets (still 403, never 429; review M2)" || fail "agent burns budget: $CODE"

# PIN verify works while limited, then the reset clears the budget.
call POST /api/identity/gate/verify "$A" '{"gate":"pin","pin":"4321","intent":"rate-reset:0"}'
[ "$CODE" = 200 ] && ok "the PIN is verified while the standard budget is used up" || fail "pin verify: $CODE $BODY"
call POST /api/identity/rate-limit/reset "$A" '{}'
[ "$CODE" = 200 ] && [ "$(echo "$BODY" | J reset)" = '["standard", "fill"]' ] && ok "reset with the PIN: standard and fill cleared" || fail "reset: $CODE $BODY"
call GET /api/blindkey/dashboard "$A"; [ "$CODE" = 200 ] && ok "the wallet's requests work again" || fail "after reset: $CODE"
call POST /api/identity/rate-limit/reset "$A" '{}'
[ "$CODE" = 403 ] && ok "the PIN proof is single use (a second reset asks again)" || fail "reuse: $CODE $BODY"
[ "$(Q "SELECT COUNT(*) FROM demipass_security_events WHERE event_type='rate_limit_reset'")" -ge 1 ] && ok "the reset is logged (rate_limit_reset)" || fail "no security event"

# The reset itself is capped (RATE_RESET_MAX=4 per hour here: the owner's three calls above count, the agent's don't).
call POST /api/identity/gate/verify "$A" '{"gate":"pin","pin":"4321","intent":"rate-reset:0"}'
call POST /api/identity/rate-limit/reset "$A" '{}'
[ "$CODE" = 200 ] && ok "a fourth owner call still resets (the agent's seven refused calls used none of it)" || fail "fourth: $CODE $BODY"
call POST /api/identity/gate/verify "$A" '{"gate":"pin","pin":"4321","intent":"rate-reset:0"}'
call POST /api/identity/rate-limit/reset "$A" '{}'
[ "$CODE" = 429 ] && ok "then resets are capped by their own hourly limit" || fail "reset cap: $CODE $BODY"

# The app.
V=public/vault-mobile.html
grep -q 'id="rate-banner"' $V && grep -q "d.limiter==='standard'||d.limiter==='fill'))showRateBanner();" $V && ok "app: a wallet 429 shows the reset banner" || fail "banner"
grep -q "apiGated('POST','/api/identity/rate-limit/reset'" $V && grep -q 'onclick="resetRateLimit()"' $V && ok "app: the reset goes through the PIN gate, from the banner and Settings" || fail "reset button"
grep -q "if(++pollN%15===0)" $V && grep -q "loadNetwork()},60000)" $V && ok "app: background polls every 60 s (was 16 s / 30 s)" || fail "polling"

echo; [ $fails = 0 ] && echo "ALL PASSED" || echo "$fails failure(s)"; exit $fails
