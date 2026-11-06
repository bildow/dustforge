#!/bin/bash
# Per-recipient daily bound (Aaron 2026-11-06): no identity sends more than 5 messages to one recipient per day, unless
# the send runs on an approved request for an elevated secret. "35 to one inbox is a loop, not correspondence."
# server.js on a throwaway DB, a stand-in SMTP server on 127.0.0.1 (accepts mail, refuses *reject* recipients, offers
# no STARTTLS, so DemiPass smtp_auth — which requires TLS — reaches it and stops before AUTH). No communal warmup cap.
set -u
W=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
S=$(mktemp -d /tmp/dustforge-rcpt-cap.XXXXXX)
PORT=${PORT:-3813}; SMTPP=${SMTPP:-3814}; API=http://127.0.0.1:$PORT
[ -d "$W/node_modules" ] || export NODE_PATH=${NODE_PATH:-/home/flimflam/project/dustforge/node_modules}
export IDENTITY_MASTER_KEY=$(python3 -c 'import secrets;print(secrets.token_hex(32))') DB_PATH=$S/dustforge.db PORT \
  STALWART_HOST=127.0.0.1 STALWART_PORT=1 SMTP_RELAY_HOST= SMTP_HOST=127.0.0.1 SMTP_PORT=$SMTPP MAIL_WARMUP_START_UTC=
cd "$W"
node -e '
const fs = require("fs");
require("net").createServer(s => { s.write("220 fake\r\n"); let buf = "", data = false;
  s.on("data", d => { buf += d; let i; while ((i = buf.indexOf("\r\n")) >= 0) { const line = buf.slice(0, i); buf = buf.slice(i + 2);
    if (data) { if (line === ".") { data = false; fs.appendFileSync(process.argv[2], "DELIVERED\n"); s.write("250 queued\r\n"); } continue; }
    const v = line.slice(0, 4).toUpperCase(); fs.appendFileSync(process.argv[2], v + "\n");
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
for (const u of ["mailer", "owner-a"]) { const id = identity.createIdentity(); const enc = id.encrypted_private_key || id.encryptedPrivateKey;
  db.prepare("INSERT INTO identity_wallets (did, username, email, encrypted_private_key, balance_cents, password_hash) VALUES (?, ?, ?, ?, 100000, ?)").run(id.did, u, u + "@dustforge.com", enc, process.argv[1]);
  db.prepare("INSERT INTO identity_transactions (did, amount_cents, type, description, balance_after) VALUES (?, 100000, ?, ?, 100000)").run(id.did, "topup", "smoke"); }' "$H"
fails=0; ok(){ echo "ok   $*"; }; fail(){ echo "FAIL $*"; fails=$((fails+1)); }
J(){ python3 -c 'import json,sys; d=json.load(sys.stdin); v=d
for k in sys.argv[1].split("."):
    v = v[int(k)] if isinstance(v, list) else (v or {}).get(k)
print(v)' "$1"; }
Q(){ python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); r=c.execute(sys.argv[2]).fetchone(); print(r[0] if r else '')" "$DB_PATH" "$1"; }
# call → CODE, BODY, RR (X-Mail-Recipient-Remaining)
call(){ local m=$1 p=$2 t=$3 b=${4:-}
  local out; out=$(curl -s -D "$S/h" -o - -w '\n%{http_code}' -X "$m" "$API$p" -H 'Content-Type: application/json' ${t:+-H "Authorization: Bearer $t"} ${b:+-d "$b"})
  CODE=${out##*$'\n'}; BODY=${out%$'\n'*}; RR=$(grep -i '^x-mail-recipient-remaining:' "$S/h" | tr -d '\r' | awk '{print $2}'); }
login(){ call POST /api/identity/auth-fingerprint "" '{"username":"'$1'","password":"hunter22","scope":"transact","expires_in":"1h"}'; echo "$BODY" | J token; }
T=$(login mailer); A=$(login owner-a); AG=$(login owner-a)
MD=$(Q "SELECT did FROM identity_wallets WHERE username='mailer'"); AD=$(Q "SELECT did FROM identity_wallets WHERE username='owner-a'")
bal(){ Q "SELECT balance_cents FROM identity_wallets WHERE username='$1'"; }
cnt(){ Q "SELECT COALESCE((SELECT sent FROM email_recipient_daily WHERE day=date('now') AND did='$1' AND rcpt='$2'),0)"; }
delivered(){ grep -c DELIVERED "$S/smtp.log" 2>/dev/null || echo 0; }
SEND(){ call POST /api/email/send "$T" '{"to":"'$1'","subject":"s","body":"b"}'; }

# ── unit: the recipient is its mailbox, not its spelling ──
node -e '
const c = require("./mail_recipient_cap"); const eq = (a, b) => { if (a !== b) { console.log("FAIL canonical", a, "!=", b); process.exitCode = 1; } };
eq(c.canonicalRecipient("Aaron.X+loop@GoogleMail.com"), "aaronx@gmail.com");
eq(c.canonicalRecipient("\"Aaron\" <aaronx@gmail.com>"), "aaronx@gmail.com");
eq(c.canonicalRecipient("kyle.m+a@hotmail.com"), "kyle.m@hotmail.com");
eq(c.recipientList("a@x.io, A@X.io ,b@x.io").join(","), "a@x.io,b@x.io");' && ok "canonical recipient: case, display name, +tag and Gmail dots fold to one inbox" || fail "canonical"

# ── /api/email/send ──
B0=$(bal mailer)
for i in 1 2 3 4 5; do
  case $i in 1) a=aaronx@gmail.com;; 2) a=Aaron.X@gmail.com;; 3) a=aaronx+loop@gmail.com;; 4) a=aaron.x@googlemail.com;; 5) a=AARONX@GMAIL.COM;; esac
  SEND "$a"; [ "$CODE" = 200 ] && [ "$RR" = $((5-i)) ] || fail "send $i ($a): $CODE $BODY rr=$RR"
done
[ "$(cnt "$MD" aaronx@gmail.com)" = 5 ] && [ "$(delivered)" = 5 ] && ok "5 sends to one inbox under 5 spellings → all 200, X-Mail-Recipient-Remaining 4…0" || fail "five: cnt $(cnt "$MD" aaronx@gmail.com) delivered $(delivered)"
B1=$(bal mailer); D1=$(delivered)
SEND "a.a.r.o.n.x+6@gmail.com"
[ "$CODE" = 429 ] && [ "$RR" = 0 ] && [ "$(echo "$BODY" | J recipient)" = aaronx@gmail.com ] && [ "$(bal mailer)" = "$B1" ] && [ "$(delivered)" = "$D1" ] && [ "$(cnt "$MD" aaronx@gmail.com)" = 5 ] \
  && ok "the 6th to that inbox → 429 naming it, header 0, nothing charged, nothing sent" || fail "sixth: $CODE $BODY rr=$RR bal $B1→$(bal mailer)"
call POST /api/email/send "$T" '{"to":"aaronx@gmail.com","subject":"s"}'
[ "$CODE" = 400 ] && ok "…a malformed call to it still gets 400 (validation first), not 429" || fail "400 first: $CODE"
SEND "other@example.com,aaronx@gmail.com"   # (no space: call() passes the body unquoted)
[ "$CODE" = 429 ] && [ "$(cnt "$MD" other@example.com)" = 0 ] && [ "$(delivered)" = "$D1" ] && ok "a multi-recipient send with one capped inbox → 429, all or none (the other recipient is not counted)" || fail "multi: $CODE cnt $(cnt "$MD" other@example.com)"
SEND "other@example.com"; [ "$CODE" = 200 ] && [ "$RR" = 4 ] && ok "another recipient is unaffected (200, 4 left for it)" || fail "other: $CODE rr=$RR"
call POST /api/email/send "$A" '{"to":"aaronx@gmail.com","subject":"s","body":"b"}'
[ "$CODE" = 200 ] && ok "the bound is per identity: another identity can still write to that inbox" || fail "per identity: $CODE $BODY"
B2=$(bal mailer)
SEND "reject-me@example.com"
[ "$CODE" = 502 ] && [ "$(cnt "$MD" reject-me@example.com)" = 0 ] && [ "$RR" = 5 ] && [ "$(bal mailer)" = "$B2" ] && ok "a send the mail server refuses → 502, refunded, and it does not count against the recipient (header back to 5)" || fail "refused: $CODE cnt $(cnt "$MD" reject-me@example.com) rr=$RR"

# ── /api/relay/forward ──
call POST /api/relay/create "$T" '{"forward_to":"aaronx@gmail.com"}'; [ "$CODE" = 200 ] || fail "relay create: $CODE $BODY"
call POST /api/relay/create "$T" '{"forward_to":"fresh@example.com"}'
B3=$(bal mailer)
call POST /api/relay/forward "$T" '{"subject":"fw","body":"b"}'
R1=$(echo "$BODY" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(" ".join(r["forward_to"]+"="+r["status"] for r in d["results"]))')
[ "$CODE" = 200 ] && echo "$R1" | grep -q "aaronx@gmail.com=skipped" && echo "$R1" | grep -q "fresh@example.com=sent" && [ "$(cnt "$MD" fresh@example.com)" = 1 ] && [ $(( B3 - $(bal mailer) )) = 10 ] \
  && ok "/relay/forward: the capped inbox is skipped (not charged), the fresh one is sent and counted" || fail "relay: $CODE $R1 charged $(( B3 - $(bal mailer) ))"

# ── DemiPass smtp_auth ──
call POST /api/identity/pin "$A" '{"pin":"4321","password":"hunter22"}'
pin(){ call POST /api/identity/gate/verify "$A" '{"gate":"pin","pin":"4321","intent":"'$1'"}'; [ "$CODE" = 200 ] || fail "pin $1: $CODE $BODY"; }
call POST /api/demipass/store "$A" '{"name":"mail","value":"alice:SMTP-PASSWORD-xyz","secret_type":"password"}'
ML=$(Q "SELECT id FROM blindkey_secrets WHERE name='mail'"); MR=$(Q "SELECT ref_code FROM blindkey_secrets WHERE id=$ML")
pin "scope:$ML"; call POST /api/demipass/context/add "$A" '{"secret_name":"mail","context_name":"local","action_type":"smtp_auth","target_host_pattern":"127.0.0.1"}'
[ "$CODE" = 200 ] || fail "smtp scope: $CODE $BODY"
SMTPCALL(){ echo '{"ref":"'$MR'","action":"smtp_auth","context":"local","params":{"smtp_host":"127.0.0.1","smtp_port":'$SMTPP',"to":"'$1'","subject":"s","body":"b"}'"${2:-}"'}'; }
python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute(\"INSERT INTO email_recipient_daily (day,did,rcpt,sent) VALUES (date('now'),?,'loop@example.com',5) ON CONFLICT(day,did,rcpt) DO UPDATE SET sent=5\", (sys.argv[2],)); c.commit()" "$DB_PATH" "$AD"
: >"$S/smtp.log"
call POST /api/demipass/use "$AG" "$(SMTPCALL loop@example.com)"
[ "$CODE" = 429 ] && [ ! -s "$S/smtp.log" ] && [ "$(echo "$BODY" | J recipient)" = loop@example.com ] && ok "smtp_auth on a standard secret, inbox at 5 today → 429 before any connection" || fail "smtp std capped: $CODE $BODY $(tr '\n' ' ' <"$S/smtp.log")"
call POST /api/demipass/use "$AG" "$(SMTPCALL newbox@example.com)"; sleep 0.3
[ "$CODE" = 200 ] && grep -q EHLO "$S/smtp.log" && [ "$(cnt "$AD" newbox@example.com)" = 0 ] && ok "smtp_auth to a fresh inbox reaches the server; the send failed (no STARTTLS), so it is not counted" || fail "smtp fresh: $CODE $BODY cnt $(cnt "$AD" newbox@example.com)"
call POST /api/demipass/gate-policy "$A" '{"ref":"'$MR'","security_depth":"elevated"}'; [ "$CODE" = 200 ] || fail "elevate: $CODE $BODY"
call POST /api/demipass/use "$AG" "$(SMTPCALL loop@example.com)"; AP=$(echo "$BODY" | J approval_id)
[ "$CODE" = 202 ] || fail "park: $CODE $BODY"
pin "approval-open:$AP"; call POST /api/demipass/approvals/$AP/open "$A"; CD=$(echo "$BODY" | J code)
call POST /api/demipass/approvals/$AP/approve "$A" '{"code":"'$CD'"}'; [ "$CODE" = 200 ] || fail "approve: $CODE $BODY"
: >"$S/smtp.log"
call POST /api/demipass/use "$AG" "$(SMTPCALL loop@example.com ",\"approval_id\":$AP")"; sleep 0.3
[ "$CODE" = 200 ] && grep -q EHLO "$S/smtp.log" && [ "$(cnt "$AD" loop@example.com)" = 5 ] && ok "elevated secret + approved request → past the bound (reaches the server), not counted" || fail "smtp elevated approved: $CODE $BODY"

echo; [ $fails = 0 ] && echo "ALL OK" || echo "$fails failure(s)"; exit $fails
