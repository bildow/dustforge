#!/bin/bash
# Secret transfers wait (red team item 6): the owner's delay (default 1 hour, 5 min–7 days; lowering takes the PIN),
# either side cancels meanwhile, both are mailed at start and at the end (done / failed / cancelled), every check is
# made again when it is carried out, and the sweep carries it out on its own. server.js on a throwaway DB, a stand-in
# SMTP server that counts mails per recipient, the sweep every 500 ms.
set -u
W=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
S=$(mktemp -d /tmp/dustforge-transfer-delay.XXXXXX)
PORT=${PORT:-3833}; SMTPP=${SMTPP:-3834}; API=http://127.0.0.1:$PORT
[ -d "$W/node_modules" ] || export NODE_PATH=${NODE_PATH:-/home/flimflam/project/dustforge/node_modules}
export IDENTITY_MASTER_KEY=$(python3 -c 'import secrets;print(secrets.token_hex(32))') DB_PATH=$S/dustforge.db PORT \
  STALWART_HOST=127.0.0.1 STALWART_PORT=1 SMTP_RELAY_HOST= SMTP_HOST=127.0.0.1 SMTP_PORT=$SMTPP TRANSFER_SWEEP_MS=500
cd "$W"
node -e '
const fs = require("fs");
require("net").createServer(s => { s.write("220 fake\r\n"); let buf = "", data = false, rcpt = "";
  s.on("data", d => { buf += d; let i; while ((i = buf.indexOf("\r\n")) >= 0) { const line = buf.slice(0, i); buf = buf.slice(i + 2);
    if (data) { if (line === ".") { data = false; fs.appendFileSync(process.argv[2], rcpt + "\n"); s.write("250 queued\r\n"); } continue; }
    const v = line.slice(0, 4).toUpperCase();
    if (v === "RCPT") rcpt = (line.match(/<([^>]+)>/) || [])[1] || "";
    if (v === "EHLO" || v === "HELO") s.write("250 fake\r\n");
    else if (v === "DATA") { data = true; s.write("354 go\r\n"); }
    else if (v === "QUIT") { s.write("221 bye\r\n"); s.end(); }
    else s.write("250 ok\r\n"); } });
  s.on("error", () => {}); }).listen(+process.argv[1], "127.0.0.1");' $SMTPP "$S/mail.log" & SM=$!
node server.js >"$S/server.log" 2>&1 & SRV=$!
trap 'kill $SRV $SM 2>/dev/null; rm -rf "$S"' EXIT
for i in $(seq 1 40); do curl -s -o /dev/null "$API/" && break; sleep 0.5; done
kill -0 $SRV 2>/dev/null || { echo "server died:"; tail -5 "$S/server.log"; exit 1; }
H=$(printf '%s' hunter22 | sha256sum | cut -d' ' -f1)
node -e '
const identity = require("./identity"); const Database = require("better-sqlite3"); const db = new Database(process.env.DB_PATH);
for (const c of ["idempotency_key TEXT", "provenance TEXT DEFAULT '"'"'organic'"'"'"]) { try { db.exec("ALTER TABLE identity_transactions ADD COLUMN " + c); } catch (_) {} }
for (const u of ["ta", "tb"]) { const id = identity.createIdentity(); const enc = id.encrypted_private_key || id.encryptedPrivateKey;
  db.prepare("INSERT INTO identity_wallets (did, username, email, encrypted_private_key, balance_cents, password_hash) VALUES (?, ?, ?, ?, 100000, ?)").run(id.did, u, u + "@example.com", enc, process.argv[1]);
  db.prepare("INSERT INTO identity_transactions (did, amount_cents, type, description, balance_after) VALUES (?, 100000, ?, ?, 100000)").run(id.did, "topup", "smoke"); }' "$H"
fails=0; ok(){ echo "ok   $*"; }; fail(){ echo "FAIL $*"; fails=$((fails+1)); }
J(){ python3 -c 'import json,sys; d=json.load(sys.stdin); v=d
for k in sys.argv[1].split("."):
    v = v[int(k)] if isinstance(v, list) else (v or {}).get(k)
print(v)' "$1"; }
Q(){ python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); r=c.execute(sys.argv[2]).fetchone(); print(r[0] if r else '')" "$DB_PATH" "$1"; }
X(){ python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute(sys.argv[2]); c.commit()" "$DB_PATH" "$1"; }
call(){ local m=$1 p=$2 t=$3 b=${4:-}
  BODY=$(curl -s -o - -w '\n%{http_code}' -X "$m" "$API$p" -H 'Content-Type: application/json' ${t:+-H "Authorization: Bearer $t"} ${b:+-d "$b"})
  CODE=${BODY##*$'\n'}; BODY=${BODY%$'\n'*}; }
login(){ call POST /api/identity/auth-fingerprint "" '{"username":"'$1'","password":"hunter22","scope":"transact","expires_in":"1h"}'; echo "$BODY" | J token; }
pin(){ call POST /api/identity/gate/verify "$1" '{"gate":"pin","pin":"'$2'","intent":"'$3'"}'; [ "$CODE" = 200 ] || fail "pin $3: $CODE $BODY"; }
mails(){ sleep 0.6; grep -c "^$1@example.com$" "$S/mail.log" 2>/dev/null || echo 0; }
A=$(login ta); B=$(login tb)
call POST /api/identity/pin "$A" '{"pin":"1111","password":"hunter22"}'; call POST /api/identity/pin "$B" '{"pin":"2222","password":"hunter22"}'
DA=$(Q "SELECT did FROM identity_wallets WHERE username='ta'"); DB=$(Q "SELECT did FROM identity_wallets WHERE username='tb'")
. "$W/test/lib/pair_in_person.sh"; pair_in_person "$A" 1111 "$B" 2222 || exit 1
store(){ call POST /api/demipass/store "$A" '{"name":"'$1'","value":"'$1'-value-zz9"}'; Q "SELECT id FROM blindkey_secrets WHERE name='$1' AND did='$DA'"; }
send(){ pin "$A" 1111 "transfer:$1"; call POST /api/demipass/transfer "$A" '{"secret":"'$2'","to":"tb"'"${3:-}"'}'; [ "$CODE" = 202 ] && TID=$(echo "$BODY" | J transfer.id); }
due(){ X "UPDATE secret_transfers SET execute_at='2000-01-01T00:00:00.000Z' WHERE id=$1"; }
owner(){ Q "SELECT CASE did WHEN '$DA' THEN 'A' WHEN '$DB' THEN 'B' ELSE did END FROM blindkey_secrets WHERE id=$1"; }

# ── default delay, start notices ──
call GET /api/identity/transfer-delay "$A"; [ "$(echo "$BODY" | J delay_sec)" = 3600 ] && ok "the default transfer delay is 1 hour" || fail "default: $BODY"
S1=$(store one); MA=$(mails ta); MB=$(mails tb)
send $S1 one
EXP=$(echo "$BODY" | J transfer.execute_at)
[ "$CODE" = 202 ] && python3 -c "import sys,datetime as d; t=d.datetime.fromisoformat(sys.argv[1].replace('Z','+00:00')); n=d.datetime.now(d.timezone.utc); sys.exit(0 if 3590 < (t-n).total_seconds() <= 3600 else 1)" "$EXP" \
  && [ "$(owner $S1)" = A ] && ok "a transfer is recorded pending (202), due in 1 hour; the secret stays A's meanwhile" || fail "start: $CODE $BODY"
[ "$(mails ta)" = $((MA+1)) ] && [ "$(mails tb)" = $((MB+1)) ] && ok "both sides are mailed when it starts" || fail "start mails: ta $MA→$(mails ta) tb $MB→$(mails tb)"
call GET /api/demipass/transfers "$B"; [ "$(echo "$BODY" | J transfers.0.direction)" = incoming ] && [ "$(echo "$BODY" | J transfers.0.can_cancel)" = True ] && ok "B sees it incoming, cancellable" || fail "B list: $BODY"
send $S1 one; [ "$CODE" = 409 ] && ok "a second transfer of the same secret while one waits → 409" || fail "second: $CODE $BODY"

# ── cancel from either side ──
MA=$(mails ta); MB=$(mails tb)
call POST /api/demipass/transfers/$TID/cancel "$B"; [ "$CODE" = 200 ] && [ "$(echo "$BODY" | J transfer.status)" = cancelled ] && ok "the recipient cancels it" || fail "B cancel: $CODE $BODY"
due $TID; sleep 1.2; [ "$(owner $S1)" = A ] && [ "$(Q "SELECT status FROM secret_transfers WHERE id=$TID")" = cancelled ] && ok "…a cancelled transfer never happens, even when its time passes" || fail "cancelled moved"
[ "$(mails ta)" = $((MA+1)) ] && [ "$(mails tb)" = $((MB+1)) ] && ok "both sides are mailed on a cancel" || fail "cancel mails"
send $S1 one; call POST /api/demipass/transfers/$TID/cancel "$A"; [ "$CODE" = 200 ] && ok "the sender cancels it" || fail "A cancel: $CODE $BODY"
call POST /api/demipass/transfers/$TID/cancel "$A"; [ "$CODE" = 409 ] && ok "cancelling twice → 409" || fail "re-cancel: $CODE"

# ── carried out by the sweep, on its own ──
send $S1 one; MA=$(mails ta); MB=$(mails tb); due $TID; sleep 1.5
[ "$(Q "SELECT status FROM secret_transfers WHERE id=$TID")" = done ] && [ "$(owner $S1)" = B ] && ok "when due, the sweep carries it out (nobody has to call anything)" || fail "sweep: $(Q "SELECT status||'|'||COALESCE(error,'') FROM secret_transfers WHERE id=$TID") owner $(owner $S1)"
[ "$(mails ta)" = $((MA+1)) ] && [ "$(mails tb)" = $((MB+1)) ] && ok "both sides are mailed when it completes" || fail "done mails"
call POST /api/demipass/transfers/$TID/cancel "$B"; [ "$CODE" = 409 ] && ok "a completed transfer cannot be cancelled" || fail "cancel done: $CODE"

# ── checked again at the moment it happens ──
S2=$(store two); send $S2 two
call POST /api/network/people/remove "$B" '{"username":"ta"}'
MA=$(mails ta); due $TID; sleep 1.5
[ "$(Q "SELECT status FROM secret_transfers WHERE id=$TID")" = failed ] && [ "$(owner $S2)" = A ] && echo "$(Q "SELECT error FROM secret_transfers WHERE id=$TID")" | grep -q "confirmed in person" \
  && ok "the contact was removed meanwhile → failed, nothing moved" || fail "recheck: $(Q "SELECT status||'|'||COALESCE(error,'') FROM secret_transfers WHERE id=$TID")"
[ "$(mails ta)" = $((MA+1)) ] && ok "…and the sender is told why" || fail "failed mail"
pair_in_person "$A" 1111 "$B" 2222
S3=$(store three); send $S3 three
call POST /api/demipass/store "$B" '{"name":"three","value":"b-own-three-zz"}'
due $TID; sleep 1.5
[ "$(Q "SELECT status FROM secret_transfers WHERE id=$TID")" = failed ] && [ "$(owner $S3)" = A ] && ok "B took the name meanwhile → failed, nothing moved (no clobber)" || fail "name recheck: $(Q "SELECT status FROM secret_transfers WHERE id=$TID")"
S4=$(store four); send $S4 four; X "UPDATE blindkey_secrets SET frozen=1 WHERE id=$S4"; due $TID; sleep 1.5
[ "$(Q "SELECT status FROM secret_transfers WHERE id=$TID")" = failed ] && [ "$(owner $S4)" = A ] && ok "frozen meanwhile → failed" || fail "frozen recheck"

# ── the delay setting ──
call PUT /api/identity/transfer-delay "$A" '{"delay_sec":86400}'; [ "$CODE" = 200 ] && ok "raising the delay is free" || fail "raise: $CODE $BODY"
S5=$(store five); send $S5 five
python3 -c "import sys,datetime as d; t=d.datetime.fromisoformat(sys.argv[1].replace('Z','+00:00')); n=d.datetime.now(d.timezone.utc); sys.exit(0 if 86390 < (t-n).total_seconds() <= 86400 else 1)" "$(echo "$BODY" | J transfer.execute_at)" && ok "…and applies to the next transfer" || fail "raised delay: $BODY"
call PUT /api/identity/transfer-delay "$A" '{"delay_sec":600}'; [ "$CODE" = 403 ] && [ "$(echo "$BODY" | J intent)" = "transfer-delay:0" ] && ok "lowering it takes the PIN" || fail "lower: $CODE $BODY"
pin "$A" 1111 transfer-delay:0; call PUT /api/identity/transfer-delay "$A" '{"delay_sec":600}'; [ "$CODE" = 200 ] && ok "…with the PIN it is lowered" || fail "lower pin: $CODE $BODY"
for v in 0 299 604801 '"x"'; do call PUT /api/identity/transfer-delay "$A" '{"delay_sec":'$v'}'; [ "$CODE" = 400 ] || fail "bound $v: $CODE"; done; ok "5 minutes to 7 days, nothing else"

echo; [ $fails = 0 ] && echo "ALL OK" || echo "$fails failure(s)"; exit $fails
