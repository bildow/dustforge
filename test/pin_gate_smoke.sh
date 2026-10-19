#!/bin/bash
# End-to-end smoke of the vault PIN gate (test/pin_gate_smoke.sh): boots server.js on a throwaway DB + random
# master key, creates one wallet through identity.js (password checked by the local sha256 fallback because
# Stalwart is pointed at a closed port), then drives the real HTTP routes: set / verify / lockout / change PIN,
# reveal gating, legacy 'fingerprint' policies. Needs node_modules (or NODE_PATH). No network, nothing persists.
set -u
W=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
S=$(mktemp -d /tmp/dustforge-pin-smoke.XXXXXX)
PORT=${PORT:-3777}; API=http://127.0.0.1:$PORT
[ -d "$W/node_modules" ] || export NODE_PATH=${NODE_PATH:-/home/flimflam/project/dustforge/node_modules}
export IDENTITY_MASTER_KEY=$(python3 -c 'import secrets;print(secrets.token_hex(32))') DB_PATH=$S/dustforge.db PORT STALWART_HOST=127.0.0.1 STALWART_PORT=1 SMTP_RELAY_HOST=
cd "$W"
node server.js >"$S/server.log" 2>&1 & SRV=$!
trap 'kill $SRV 2>/dev/null; rm -rf "$S"' EXIT
for i in $(seq 1 40); do curl -s -o /dev/null "$API/" && break; sleep 0.5; done
kill -0 $SRV 2>/dev/null || { echo "server died:"; tail -5 "$S/server.log"; exit 1; }
PW=hunter22; H=$(printf '%s' "$PW" | sha256sum | cut -d' ' -f1)
node -e '
const identity = require("./identity"); const Database = require("better-sqlite3");
const id = identity.createIdentity(); const enc = id.encrypted_private_key || id.encryptedPrivateKey;
const db = new Database(process.env.DB_PATH);
try { db.exec("ALTER TABLE identity_wallets ADD COLUMN password_hash TEXT"); } catch (_) {}
db.prepare("INSERT INTO identity_wallets (did, username, email, encrypted_private_key, balance_cents, password_hash, recovery_email) VALUES (?, ?, ?, ?, 100000, ?, ?)")
  .run(id.did, "pintester", "pintester@dustforge.com", enc, process.argv[1], "p@example.com");
console.log("wallet:", id.did.slice(0, 24) + "…");
' "$H"
fails=0; ok(){ echo "ok   $*"; }; fail(){ echo "FAIL $*"; fails=$((fails+1)); }
J(){ python3 -c 'import json,sys; d=json.load(sys.stdin); v=d
for k in sys.argv[1].split("."):
    v = v[int(k)] if isinstance(v, list) else v.get(k)
print(v)' "$1"; }
call(){ # method path token body → sets CODE and BODY
  local m=$1 p=$2 t=$3 b=${4:-}
  BODY=$(curl -s -o - -w '\n%{http_code}' -X "$m" "$API$p" -H 'Content-Type: application/json' ${t:+-H "Authorization: Bearer $t"} ${b:+-d "$b"})
  CODE=${BODY##*$'\n'}; BODY=${BODY%$'\n'*}
}
call POST /api/identity/auth-fingerprint "" '{"username":"pintester","password":"hunter22","scope":"transact","expires_in":"1h"}'
TK=$(echo "$BODY" | J token); [ "$CODE" = 200 ] && [ -n "$TK" ] && [ "$TK" != None ] && ok "login (transact token)" || { fail "login: $CODE $BODY"; exit 1; }
call GET /api/identity/gate/status "$TK"; [ "$(echo "$BODY" | J pin_set)" = False ] && ok "gate/status: pin_set=false on a fresh account" || fail "gate/status: $BODY"
echo "$BODY" | J presets.standard.reveal.0 | grep -q '^pin$' && ok "standard preset reveal gate is pin" || fail "preset: $(echo "$BODY" | J presets.standard.reveal)"
call POST /api/blindkey/store "$TK" '{"name":"sightless","value":"s3cret-value","secret_type":"password"}'; [ "$CODE" = 200 ] || [ "$CODE" = 201 ] && ok "store a secret" || fail "store: $CODE $BODY"
call POST /api/blindkey/reveal "$TK" '{"name":"sightless"}'; [ "$CODE" = 403 ] && [ "$(echo "$BODY" | J missing.0)" = pin ] && ok "reveal without PIN → 403 missing [pin]" || fail "reveal: $CODE $BODY"
call POST /api/identity/gate/verify "$TK" '{"gate":"pin","pin":"1234"}'; [ "$CODE" = 409 ] && ok "verify pin before one exists → 409" || fail "verify-no-pin: $CODE $BODY"
call POST /api/identity/pin "$TK" '{"pin":"12"}'; [ "$CODE" = 400 ] && ok "set: 2-digit PIN refused" || fail "short pin: $CODE"
call POST /api/identity/pin "$TK" '{"pin":"1234"}'; [ "$CODE" = 400 ] && ok "set: password required" || fail "no pw: $CODE $BODY"
call POST /api/identity/pin "$TK" '{"pin":"1234","password":"wrong"}'; [ "$CODE" = 403 ] && ok "set: wrong password → 403 (never 401)" || fail "wrong pw: $CODE $BODY"
call POST /api/identity/pin "$TK" '{"pin":"1234","password":"hunter22"}'; [ "$CODE" = 200 ] && [ "$(echo "$BODY" | J changed)" = False ] && ok "set PIN with password" || fail "set pin: $CODE $BODY"
call GET /api/identity/gate/status "$TK"; [ "$(echo "$BODY" | J pin_set)" = True ] && ok "gate/status: pin_set=true" || fail "status after set: $BODY"
call POST /api/blindkey/reveal "$TK" '{"name":"sightless"}'; [ "$CODE" = 403 ] && ok "reveal still gated after setting the PIN" || fail "reveal after set: $CODE"
call POST /api/identity/gate/verify "$TK" '{"gate":"pin","pin":"9999"}'; [ "$CODE" = 403 ] && [ "$(echo "$BODY" | J attempts_left)" = 4 ] && ok "wrong PIN → 403, 4 tries left" || fail "wrong pin: $CODE $BODY"
call POST /api/identity/gate/verify "$TK" '{"gate":"pin","pin":"1234"}'; [ "$CODE" = 200 ] && ok "correct PIN → gate fresh" || fail "verify: $CODE $BODY"
call POST /api/blindkey/reveal "$TK" '{"name":"sightless"}'; [ "$CODE" = 200 ] && [ "$(echo "$BODY" | J value)" = s3cret-value ] && ok "reveal after PIN → value" || fail "reveal: $CODE $BODY"
for i in 1 2 3 4; do call POST /api/identity/gate/verify "$TK" '{"gate":"pin","pin":"0000"}'; done
[ "$CODE" = 403 ] && [ "$(echo "$BODY" | J attempts_left)" = 1 ] && ok "four misses → 1 try left" || fail "misses: $CODE $BODY"
call POST /api/identity/gate/verify "$TK" '{"gate":"pin","pin":"0000"}'; [ "$CODE" = 429 ] && ok "fifth miss → 429 locked" || fail "lock: $CODE $BODY"
call POST /api/identity/gate/verify "$TK" '{"gate":"pin","pin":"1234"}'; [ "$CODE" = 429 ] && [ "$(echo "$BODY" | J locked_for_seconds)" -gt 800 ] && ok "correct PIN while locked → 429 (~15 min)" || fail "locked-correct: $CODE $BODY"
call POST /api/identity/pin "$TK" '{"pin":"5678","current_pin":"1234"}'; [ "$CODE" = 429 ] && ok "change with current PIN while locked → 429" || fail "change-locked: $CODE"
call GET /api/identity/gate/status "$TK"; [ "$(echo "$BODY" | J pin_locked_for_seconds)" -gt 800 ] && ok "gate/status reports the lock" || fail "status lock: $BODY"
python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute(\"UPDATE identity_wallets SET pin_locked_until=NULL WHERE username='pintester'\"); c.commit()" "$DB_PATH"   # the 15 minutes pass
call POST /api/identity/pin "$TK" '{"pin":"5678","current_pin":"1111"}'; [ "$CODE" = 403 ] && ok "change with wrong current PIN → 403" || fail "change-wrong: $CODE $BODY"
call POST /api/identity/pin "$TK" '{"pin":"5678","current_pin":"1234"}'; [ "$CODE" = 200 ] && [ "$(echo "$BODY" | J changed)" = True ] && ok "change PIN with current PIN" || fail "change: $CODE $BODY"
call POST /api/identity/gate/verify "$TK" '{"gate":"pin","pin":"1234"}'; [ "$CODE" = 403 ] && ok "old PIN no longer works" || fail "old pin: $CODE"
call POST /api/identity/gate/verify "$TK" '{"gate":"pin","pin":"5678"}'; [ "$CODE" = 200 ] && ok "new PIN works" || fail "new pin: $CODE $BODY"
call POST /api/identity/pin "$TK" '{"pin":"2468","password":"hunter22"}'; [ "$CODE" = 200 ] && ok "forgotten PIN: change with password" || fail "change-pw: $CODE $BODY"
call POST /api/blindkey/gate-policy "$TK" '{"name":"sightless","gate_policy":{"reveal":["fingerprint","twofa"],"rotate":[],"delete":[],"use":[]}}'
[ "$CODE" = 200 ] && [ "$(echo "$BODY" | J effective.reveal.0)" = pin ] && ok "legacy 'fingerprint' in a custom policy reads as pin" || fail "legacy policy: $CODE $BODY"
call POST /api/blindkey/gate-policy "$TK" '{"name":"sightless","security_depth":"standard"}'; [ "$CODE" = 200 ] && ok "back to standard depth" || fail "depth: $CODE"
python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute('DELETE FROM gate_verifications'); c.commit()" "$DB_PATH"   # the 5-minute PIN window expires
call POST /api/blindkey/reveal "$TK" '{"name":"sightless"}'; [ "$CODE" = 403 ] && ok "PIN freshness expired → reveal gated again" || fail "expiry: $CODE"
call POST /api/identity/gate/verify "$TK" '{"gate":"fingerprint"}'; [ "$CODE" = 200 ] && ok "legacy fingerprint verify still answers (token is fingerprint-authed)" || fail "legacy verify: $CODE $BODY"
call POST /api/blindkey/reveal "$TK" '{"name":"sightless"}'; [ "$CODE" = 403 ] && ok "a fingerprint-authed token alone no longer reveals (PIN required)" || fail "reveal w/o pin after fp: $CODE $BODY"
call POST /api/identity/gate/verify "$TK" '{"gate":"pin","pin":"2468"}'; call POST /api/blindkey/reveal "$TK" '{"name":"sightless"}'; [ "$CODE" = 200 ] && ok "PIN → reveal again" || fail "final reveal: $CODE"
grep -c "pin_failed\|pin_set\|pin_changed" "$S/server.log" >/dev/null && ok "security events logged" || true
echo "$fails failure(s)"; [ "$fails" = 0 ]
