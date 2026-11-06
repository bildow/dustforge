#!/bin/bash
# Mail send order (Aaron 2026-11-06): validate first, then the cap, then billing; X-Mail-Remaining on every mail call;
# 429 only after validation; a send the mail server refuses is refunded and gives its slot back; every send/refund row
# carries the token id that made it. server.js on a throwaway DB, a stand-in SMTP server (refuses *reject* recipients),
# the communal warmup cap set to 3/day.
set -u
W=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
S=$(mktemp -d /tmp/dustforge-mail-smoke.XXXXXX)
PORT=${PORT:-3803}; SMTPP=${SMTPP:-3804}; API=http://127.0.0.1:$PORT
[ -d "$W/node_modules" ] || export NODE_PATH=${NODE_PATH:-/home/flimflam/project/dustforge/node_modules}
export IDENTITY_MASTER_KEY=$(python3 -c 'import secrets;print(secrets.token_hex(32))') DB_PATH=$S/dustforge.db PORT \
  STALWART_HOST=127.0.0.1 STALWART_PORT=1 SMTP_RELAY_HOST= SMTP_HOST=127.0.0.1 SMTP_PORT=$SMTPP \
  MAIL_WARMUP_START_UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ) MAIL_WARMUP_INITIAL_DAILY_LIMIT=3 MAIL_WARMUP_MAX_DAILY_LIMIT=3
cd "$W"
node -e '
const fs = require("fs");
require("net").createServer(s => { s.write("220 fake\r\n"); let buf = "", data = false;
  s.on("data", d => { buf += d; let i; while ((i = buf.indexOf("\r\n")) >= 0) { const line = buf.slice(0, i); buf = buf.slice(i + 2);
    if (data) { if (line === ".") { data = false; fs.appendFileSync(process.argv[2], "DELIVERED\n"); s.write("250 queued\r\n"); } continue; }
    const v = line.slice(0, 4).toUpperCase();
    if (v === "EHLO" || v === "HELO") s.write("250 fake\r\n");
    else if (v === "RCPT") s.write(/reject/i.test(line) ? "550 no such user\r\n" : "250 ok\r\n");
    else if (v === "DATA") { data = true; s.write("354 go\r\n"); }
    else if (v === "QUIT") { s.write("221 bye\r\n"); s.end(); }
    else s.write("250 ok\r\n"); } });
  s.on("error", () => {}); }).listen(+process.argv[1], "127.0.0.1");' $SMTPP "$S/smtp.log" & SM=$!
node server.js >"$S/server.log" 2>&1 & SRV=$!
trap 'kill $SRV $SM 2>/dev/null; rm -rf "$S"' EXIT
for i in $(seq 1 40); do curl -s -o /dev/null "$API/" && break; sleep 0.5; done
kill -0 $SRV 2>/dev/null || { echo "server died:"; tail -5 "$S/server.log"; exit 1; }
H=$(printf '%s' hunter22 | sha256sum | cut -d' ' -f1)
node -e '
const identity = require("./identity"); const Database = require("better-sqlite3"); const db = new Database(process.env.DB_PATH);
for (const c of ["idempotency_key TEXT", "provenance TEXT DEFAULT '"'"'organic'"'"'"]) { try { db.exec("ALTER TABLE identity_transactions ADD COLUMN " + c); } catch (_) {} }
const id = identity.createIdentity(); const enc = id.encrypted_private_key || id.encryptedPrivateKey;
db.prepare("INSERT INTO identity_wallets (did, username, email, encrypted_private_key, balance_cents, password_hash) VALUES (?, ?, ?, ?, 100000, ?)").run(id.did, "mailer", "mailer@dustforge.com", enc, process.argv[1]);
db.prepare("INSERT INTO identity_transactions (did, amount_cents, type, description, balance_after) VALUES (?, 100000, ?, ?, 100000)").run(id.did, "topup", "smoke");' "$H"
fails=0; ok(){ echo "ok   $*"; }; fail(){ echo "FAIL $*"; fails=$((fails+1)); }
J(){ python3 -c 'import json,sys; d=json.load(sys.stdin); v=d
for k in sys.argv[1].split("."):
    v = v[int(k)] if isinstance(v, list) else (v or {}).get(k)
print(v)' "$1"; }
Q(){ python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); r=c.execute(sys.argv[2]).fetchone(); print(r[0] if r else '')" "$DB_PATH" "$1"; }
# call → CODE, BODY, REM (X-Mail-Remaining)
call(){ local m=$1 p=$2 t=$3 b=${4:-}
  local out; out=$(curl -s -D "$S/h" -o - -w '\n%{http_code}' -X "$m" "$API$p" -H 'Content-Type: application/json' ${t:+-H "Authorization: Bearer $t"} ${b:+-d "$b"})
  CODE=${out##*$'\n'}; BODY=${out%$'\n'*}; REM=$(grep -i '^x-mail-remaining:' "$S/h" | tr -d '\r' | awk '{print $2}'); }
call POST /api/identity/auth-fingerprint "" '{"username":"mailer","password":"hunter22","scope":"transact","expires_in":"1h"}'; T=$(echo "$BODY" | J token)
JTI=$(python3 -c 'import sys,json,base64; p=sys.argv[1].split(".")[1]; p+="="*(-len(p)%4); print(json.loads(base64.urlsafe_b64decode(p))["jti"])' "$T")
bal(){ Q "SELECT balance_cents FROM identity_wallets WHERE username='mailer'"; }
slots(){ python3 -c "import sqlite3,sys
c=sqlite3.connect(sys.argv[1])
try: r=c.execute(\"SELECT sent FROM email_warmup_daily WHERE day = date('now')\").fetchone(); print(r[0] if r else 0)
except sqlite3.OperationalError: print(0)   # no table yet: no slot was ever reserved" "$DB_PATH"; }
B0=$(bal)

call POST /api/email/send "$T" '{"subject":"s","body":"b"}'
[ "$CODE" = 400 ] && [ "$(bal)" = "$B0" ] && [ "$(slots)" = 0 ] && [ "$REM" = 3 ] && ok "missing 'to' → 400 before the cap and billing: nothing charged, no slot, X-Mail-Remaining 3" || fail "missing to: $CODE bal $(bal) slots $(slots) rem $REM"
call POST /api/email/send "$T" '{"to":"not an address","subject":"s","body":"b"}'
[ "$CODE" = 400 ] && [ "$(bal)" = "$B0" ] && [ "$(slots)" = 0 ] && ok "a malformed address → 400, nothing charged, no slot" || fail "bad addr: $CODE"
call POST /api/email/send "$T" '{"to":"a@example.com","subject":"line\nbreak","body":"b"}'
[ "$CODE" = 400 ] && [ "$(slots)" = 0 ] && ok "a subject with a line break → 400 (no header injection), no slot" || fail "subject: $CODE"
call POST /api/email/send "$T" '{"to":"a@example.com","subject":"hello","body":"b"}'
[ "$CODE" = 200 ] && [ "$REM" = 2 ] && [ "$(slots)" = 1 ] && [ "$(bal)" -lt "$B0" ] && ok "a valid send → 200, charged, one slot, X-Mail-Remaining 2" || fail "send: $CODE $BODY rem $REM slots $(slots)"
[ "$(Q "SELECT token_jti FROM identity_transactions WHERE type='email_send' ORDER BY id DESC LIMIT 1")" = "$JTI" ] && ok "the send's ledger row carries the token id that made it" || fail "token_jti: $(Q "SELECT token_jti FROM identity_transactions WHERE type='email_send' ORDER BY id DESC LIMIT 1")"
[ "$(grep -c DELIVERED "$S/smtp.log")" = 1 ] || fail "not delivered"
B1=$(bal)
call POST /api/email/send "$T" '{"to":"reject-me@example.com","subject":"hello","body":"b"}'
[ "$CODE" = 502 ] && [ "$(bal)" = "$B1" ] && [ "$(slots)" = 1 ] && [ "$REM" = 2 ] && [ "$(echo "$BODY" | J refunded)" -gt 0 ] && ok "refused by the mail server → 502, refunded, slot given back, header 2" || fail "refused: $CODE $BODY bal $B1→$(bal) slots $(slots) rem $REM"
[ "$(Q "SELECT token_jti FROM identity_transactions WHERE type='email_send_refund' ORDER BY id DESC LIMIT 1")" = "$JTI" ] && ok "…the refund row carries the same token id" || fail "refund jti"
call POST /api/email/send "$T" '{"to":"b@example.com","subject":"two","body":"b"}'; call POST /api/email/send "$T" '{"to":"c@example.com","subject":"three","body":"b"}'
[ "$CODE" = 200 ] && [ "$REM" = 0 ] || fail "fill cap: $CODE rem $REM"
B2=$(bal)
call POST /api/email/send "$T" '{"to":"d@example.com","subject":"four","body":"b"}'
[ "$CODE" = 429 ] && [ "$REM" = 0 ] && [ "$(bal)" = "$B2" ] && ok "cap reached: a valid send → 429, header 0, nothing charged" || fail "cap: $CODE rem $REM"
call POST /api/email/send "$T" '{"to":"","subject":"x","body":"b"}'
[ "$CODE" = 400 ] && ok "…while a malformed one still gets its 400, not 429 (validation first)" || fail "400 at cap: $CODE"
call POST /api/relay/forward "$T" '{"subject":"s","body":"b"}'
[ "$CODE" = 404 ] && [ "$(bal)" = "$B2" ] && ok "/relay/forward with no rules → 404 before any charge" || fail "relay: $CODE bal $(bal)"
echo; [ $fails = 0 ] && echo "ALL OK" || echo "$fails FAILED"; exit $fails
