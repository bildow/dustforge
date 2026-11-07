#!/bin/bash
# Emailed/texted codes (2026-11-07 hotfix): before, /api/identity/request-2fa and /verify had no rate limiter, every
# request added another live 6-digit code, wrong guesses cost nothing and expiry compared ISO text to SQLite datetime
# text (never expired the same day) — a transact token for any DID by guessing. Now:
#   (a) a new code kills the older ones: only the latest is live
#   (b) 5 wrong guesses kill the live code (the right code is refused after), attempts_left counts down
#   (c) at most 5 codes per wallet an hour (429)
#   (d) an expired code is refused
#   (e) the gate/verify twofa path has the same guess limit
#   (f) the right code still mints a token; no code appears in the server log
#   (g) #57 review: 'login' codes (asked without a session) and 'gate' codes (the signed-in owner) are separate — a
#       stranger asking for login codes neither kills nor uses up the owner's gate code
#   (h) 10 wrong login codes in a day pause code sign-in for the wallet (429, a critical event), across codes
#   (i) a wallet without email gets no code (409)
set -u
W=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
S=$(mktemp -d /tmp/dustforge-2fa-smoke.XXXXXX)
PORT=${PORT:-3811}; API=http://127.0.0.1:$PORT
[ -d "$W/node_modules" ] || export NODE_PATH=${NODE_PATH:-/home/flimflam/project/dustforge/node_modules}
export IDENTITY_MASTER_KEY=$(python3 -c 'import secrets;print(secrets.token_hex(32))') DB_PATH=$S/dustforge.db PORT \
  STALWART_HOST=127.0.0.1 STALWART_PORT=1 SMTP_RELAY_HOST= SMTP_HOST=127.0.0.1 SMTP_PORT=9
cd "$W"
node server.js >"$S/server.log" 2>&1 & SRV=$!
trap 'kill $SRV 2>/dev/null; rm -rf "$S"' EXIT
for i in $(seq 1 40); do curl -s -o /dev/null "$API/" && break; sleep 0.5; done
kill -0 $SRV 2>/dev/null || { echo "server died:"; tail -5 "$S/server.log"; exit 1; }
H=$(printf '%s' hunter22 | sha256sum | cut -d' ' -f1)
DID=$(node -e '
const identity = require("./identity"); const Database = require("better-sqlite3"); const db = new Database(process.env.DB_PATH);
const id = identity.createIdentity(); const enc = id.encrypted_private_key || id.encryptedPrivateKey;
db.prepare("INSERT INTO identity_wallets (did, username, email, encrypted_private_key, balance_cents, password_hash) VALUES (?, ?, ?, ?, 0, ?)").run(id.did, "owner-a", "owner-a@dustforge.com", enc, process.argv[1]);
process.stdout.write(id.did);' "$H")
fails=0; ok(){ echo "ok   $*"; }; fail(){ echo "FAIL $*"; fails=$((fails+1)); }
J(){ python3 -c 'import json,sys; d=json.load(sys.stdin); v=d
for k in sys.argv[1].split("."): v=(v or {}).get(k)
print(v)' "$1"; }
Q(){ python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); r=c.execute(sys.argv[2]).fetchone(); print(r[0] if r else '')" "$DB_PATH" "$1"; }
X(){ python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute(sys.argv[2]); c.commit()" "$DB_PATH" "$1"; }
call(){ local m=$1 p=$2 t=$3 b=${4:-}
  BODY=$(curl -s -o - -w '\n%{http_code}' -X "$m" "$API$p" -H 'Content-Type: application/json' ${t:+-H "Authorization: Bearer $t"} ${b:+-d "$b"})
  CODE=${BODY##*$'\n'}; BODY=${BODY%$'\n'*}; }
latest(){ Q "SELECT code FROM identity_2fa_codes WHERE did='$DID' AND purpose='${1:-login}' ORDER BY id DESC LIMIT 1"; }
wrong(){ local c=$1; [ "$c" = 111111 ] && echo 222222 || echo 111111; }
verify(){ call POST /api/identity/verify "" '{"did":"'$DID'","code":"'$1'","scope":"transact"}'; }

# (a) only the latest code is live
call POST /api/identity/request-2fa "" '{"did":"'$DID'"}'; C1=$(latest)
call POST /api/identity/request-2fa "" '{"did":"'$DID'"}'; C2=$(latest)
if [ "$C1" != "$C2" ]; then verify "$C1"; [ "$CODE" = 401 ] && ok "(a) an older code is dead once a new one is issued" || fail "(a) old code: $CODE $BODY"
else ok "(a) skipped: the two codes happened to match"; fi
# the old code's miss counted against the live one: 4 left
# (b) 5 wrong guesses kill the live code
call POST /api/identity/request-2fa "" '{"did":"'$DID'"}'; C=$(latest); WC=$(wrong "$C")
for i in 1 2 3 4; do verify "$WC"; done
[ "$CODE" = 401 ] && [ "$(echo "$BODY" | J attempts_left)" = 1 ] && ok "(b) wrong guesses count down (1 left after 4)" || fail "(b) countdown: $CODE $BODY"
verify "$WC"; [ "$(echo "$BODY" | J attempts_left)" = 0 ] || fail "(b) 5th: $CODE $BODY"
verify "$C"; [ "$CODE" = 401 ] && ok "(b) after 5 wrong guesses the right code is refused" || fail "(b) right code after 5 misses: $CODE $BODY"
# (f) the right code mints a token
call POST /api/identity/request-2fa "" '{"did":"'$DID'"}'; C=$(latest)
verify "$C"; TK=$(echo "$BODY" | J token)
[ "$CODE" = 200 ] && [ -n "$TK" ] && [ "$TK" != None ] && ok "(f) the right code mints a transact token" || fail "(f) right code: $CODE $BODY"
verify "$C"; [ "$CODE" = 401 ] && ok "(f) a used code is refused" || fail "(f) reuse: $CODE"
# (c) at most 5 codes an hour (4 issued so far)
call POST /api/identity/request-2fa "" '{"did":"'$DID'"}'; [ "$CODE" = 200 ] || fail "(c) 5th issue: $CODE $BODY"
call POST /api/identity/request-2fa "" '{"did":"'$DID'"}'; [ "$CODE" = 429 ] && ok "(c) the 6th code within an hour → 429" || fail "(c) 6th: $CODE $BODY"
# (d) an expired code is refused (and expiry is compared as ISO time)
C=$(latest); X "UPDATE identity_2fa_codes SET expires_at = '$(date -u -d '-1 minute' +%Y-%m-%dT%H:%M:%S.000Z)' WHERE code = '$C' AND did = '$DID'"
verify "$C"; [ "$CODE" = 401 ] && ok "(d) an expired code is refused" || fail "(d) expired: $CODE $BODY"
# (e) gate/verify twofa: same guess limit, on gate codes (asked for with the owner's session)
call POST /api/identity/request-2fa "$TK" '{"did":"'$DID'"}'; [ "$CODE" = 200 ] || fail "(e) gate code: $CODE $BODY"
C=$(latest gate); WC=$(wrong "$C")
for i in 1 2 3 4 5; do call POST /api/identity/gate/verify "$TK" '{"gate":"twofa","code":"'$WC'"}'; done
[ "$CODE" = 403 ] && [ "$(echo "$BODY" | J attempts_left)" = 0 ] || fail "(e) 5th wrong gate code: $CODE $BODY"
call POST /api/identity/gate/verify "$TK" '{"gate":"twofa","code":"'$C'"}'
[ "$CODE" = 403 ] && ok "(e) gate twofa: 5 wrong codes kill it" || fail "(e) right gate code after 5 misses: $CODE $BODY"
# (g) a stranger's login requests leave the owner's gate code alone (login cap is already used up: 429)
call POST /api/identity/request-2fa "$TK" '{"did":"'$DID'"}'; G=$(latest gate)
call POST /api/identity/request-2fa "" '{"did":"'$DID'"}'; [ "$CODE" = 429 ] || fail "(g) login cap: $CODE $BODY"
X "UPDATE identity_2fa_codes SET created_at = datetime('now', '-2 hours') WHERE did = '$DID' AND purpose = 'login'"
call POST /api/identity/request-2fa "" '{"did":"'$DID'"}'; [ "$CODE" = 200 ] || fail "(g) login issue: $CODE $BODY"
verify 000001; verify 000002
call POST /api/identity/gate/verify "$TK" '{"gate":"twofa","code":"'$G'"}'
[ "$CODE" = 200 ] && ok "(g) login codes and wrong login guesses leave the owner's gate code working" || fail "(g) gate after login traffic: $CODE $BODY"
# (h) the day budget for login guesses: 10 wrong across codes pause it (7 counted so far: 4+1 in (b), 2 in (g), 1 in (a))
C=$(latest login)
verify 000003; verify 000004
[ "$CODE" = 401 ] || fail "(h) 10th wrong: $CODE $BODY"
verify "$C"; [ "$CODE" = 429 ] && ok "(h) 10 wrong login codes in a day pause code sign-in (even the right code: 429)" || fail "(h) after budget: $CODE $BODY"
call POST /api/identity/request-2fa "" '{"did":"'$DID'"}'; [ "$CODE" = 429 ] && ok "(h) and no new login code is issued" || fail "(h) issue after budget: $CODE $BODY"
[ "$(Q "SELECT COUNT(*) FROM demipass_security_events WHERE event_type='code_guessing_paused'")" = 1 ] && ok "(h) one critical event (and one mail)" || fail "(h) event count"
call POST /api/identity/request-2fa "$TK" '{"did":"'$DID'"}'; [ "$CODE" = 200 ] && ok "(h) the owner's gate codes still work while login is paused" || fail "(h) gate issue: $CODE $BODY"
# (i) no email → no code
X "UPDATE identity_wallets SET email = '' WHERE did = '$DID'"
call POST /api/identity/request-2fa "" '{"did":"'$DID'"}'; [ "$CODE" = 409 ] && ok "(i) a wallet without email gets no code (409)" || fail "(i) no email: $CODE $BODY"
# (f) no code in the log
codes=$(python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); print(' '.join(r[0] for r in c.execute('SELECT code FROM identity_2fa_codes')))" "$DB_PATH")
leaked=0; for c in $codes; do grep -q "$c" "$S/server.log" && leaked=1; done
[ $leaked = 0 ] && ok "(f) no code in the server log" || fail "(f) a code was logged"
echo; [ $fails = 0 ] && echo "ALL PASS" || { echo "$fails FAILED"; exit 1; }
