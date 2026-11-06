#!/bin/bash
# Vouching (red team item 6): C, who met both A and B in person (QR), introduces them; both accept with their PIN →
# confirmed contacts (verified_via='vouch', vouched_by C). Only first-hand QR links vouch (no chains); the voucher
# states it with its PIN; an introduction lapses if the voucher's own links end; decline/withdraw; agents never.
set -u
W=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
S=$(mktemp -d /tmp/dustforge-vouch-smoke.XXXXXX)
PORT=${PORT:-3843}; SMTPP=${SMTPP:-3844}; API=http://127.0.0.1:$PORT
[ -d "$W/node_modules" ] || export NODE_PATH=${NODE_PATH:-/home/flimflam/project/dustforge/node_modules}
export IDENTITY_MASTER_KEY=$(python3 -c 'import secrets;print(secrets.token_hex(32))') DB_PATH=$S/dustforge.db PORT \
  STALWART_HOST=127.0.0.1 STALWART_PORT=1 SMTP_RELAY_HOST= SMTP_HOST=127.0.0.1 SMTP_PORT=$SMTPP
cd "$W"
node -e '
const fs = require("fs");
require("net").createServer(s => { s.write("220 fake\r\n"); let buf = "", data = false, rcpt = "";
  s.on("data", d => { buf += d; let i; while ((i = buf.indexOf("\r\n")) >= 0) { const line = buf.slice(0, i); buf = buf.slice(i + 2);
    if (data) { if (line === ".") { data = false; fs.appendFileSync(process.argv[2], rcpt + "\n"); s.write("250 queued\r\n"); } continue; }
    const v = line.slice(0, 4).toUpperCase(); if (v === "RCPT") rcpt = (line.match(/<([^>]+)>/) || [])[1] || "";
    if (v === "EHLO" || v === "HELO") s.write("250 fake\r\n"); else if (v === "DATA") { data = true; s.write("354 go\r\n"); }
    else if (v === "QUIT") { s.write("221 bye\r\n"); s.end(); } else s.write("250 ok\r\n"); } });
  s.on("error", () => {}); }).listen(+process.argv[1], "127.0.0.1");' $SMTPP "$S/mail.log" & SM=$!
node server.js >"$S/server.log" 2>&1 & SRV=$!
trap 'kill $SRV $SM 2>/dev/null; rm -rf "$S"' EXIT
for i in $(seq 1 40); do curl -s -o /dev/null "$API/" && break; sleep 0.5; done
kill -0 $SRV 2>/dev/null || { echo "server died:"; tail -5 "$S/server.log"; exit 1; }
H=$(printf '%s' hunter22 | sha256sum | cut -d' ' -f1)
node -e '
const identity = require("./identity"); const Database = require("better-sqlite3"); const db = new Database(process.env.DB_PATH);
for (const c of ["idempotency_key TEXT", "provenance TEXT DEFAULT '"'"'organic'"'"'"]) { try { db.exec("ALTER TABLE identity_transactions ADD COLUMN " + c); } catch (_) {} }
for (const u of ["va", "vb", "vc", "vd", "vg"]) { const id = identity.createIdentity(); const enc = id.encrypted_private_key || id.encryptedPrivateKey;
  db.prepare("INSERT INTO identity_wallets (did, username, email, encrypted_private_key, balance_cents, password_hash) VALUES (?, ?, ?, ?, 100000, ?)").run(id.did, u, u + "@example.com", enc, process.argv[1]);
  db.prepare("INSERT INTO identity_transactions (did, amount_cents, type, description, balance_after) VALUES (?, 100000, ?, ?, 100000)").run(id.did, "topup", "smoke"); }' "$H"
fails=0; ok(){ echo "ok   $*"; }; fail(){ echo "FAIL $*"; fails=$((fails+1)); }
J(){ python3 -c 'import json,sys; d=json.load(sys.stdin); v=d
for k in sys.argv[1].split("."):
    v = v[int(k)] if isinstance(v, list) else (v or {}).get(k)
print(v)' "$1"; }
Q(){ python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); r=c.execute(sys.argv[2]).fetchone(); print(r[0] if r else '')" "$DB_PATH" "$1"; }
call(){ local m=$1 p=$2 t=$3 b=${4:-}
  BODY=$(curl -s -o - -w '\n%{http_code}' -X "$m" "$API$p" -H 'Content-Type: application/json' ${t:+-H "Authorization: Bearer $t"} ${b:+-d "$b"})
  CODE=${BODY##*$'\n'}; BODY=${BODY%$'\n'*}; }
login(){ call POST /api/identity/auth-fingerprint "" '{"username":"'$1'","password":"hunter22","scope":"transact","expires_in":"1h"}'; echo "$BODY" | J token; }
pin(){ call POST /api/identity/gate/verify "$1" '{"gate":"pin","pin":"'$2'","intent":"'$3'"}'; [ "$CODE" = 200 ] || fail "pin $3: $CODE $BODY"; }
did(){ Q "SELECT did FROM identity_wallets WHERE username='$1'"; }
peer(){ Q "SELECT COALESCE(verified_via,'none')||'|'||COALESCE(vouched_by,'') FROM network_peers WHERE status='active' AND ((did_a='$(did $1)' AND did_b='$(did $2)') OR (did_a='$(did $2)' AND did_b='$(did $1)'))"; }
mails(){ sleep 0.5; grep -c "^$1@example.com$" "$S/mail.log" 2>/dev/null || echo 0; }
A=$(login va); B=$(login vb); C=$(login vc); D=$(login vd); G=$(login vg)
for t in "$A:1111" "$B:2222" "$C:3333" "$D:4444" "$G:5555"; do call POST /api/identity/pin "${t%%:*}" '{"pin":"'${t##*:}'","password":"hunter22"}'; done
. "$W/test/lib/pair_in_person.sh"
pair_in_person "$C" 3333 "$A" 1111 && pair_in_person "$C" 3333 "$B" 2222 && pair_in_person "$C" 3333 "$D" 4444 || exit 1
DC=$(did vc)

# ── who may vouch ──
call POST /api/network/vouch "$A" '{"a":"vb","b":"vc"}'; [ "$CODE" = 403 ] && [ "$(echo "$BODY" | J pair_required)" = True ] && ok "A has not met B in person → cannot vouch for B" || fail "A vouch: $CODE $BODY"
call POST /api/network/vouch "$C" '{"a":"va","b":"va"}'; [ "$CODE" = 400 ] && ok "introducing someone to themselves → 400" || fail "self: $CODE"
call POST /api/network/vouch "$C" '{"a":"va","b":"vb"}'; [ "$CODE" = 403 ] && [ "$(echo "$BODY" | J intent)" = vouch:0 ] && ok "the voucher's word takes the voucher's PIN" || fail "vouch pin: $CODE $BODY"
MA=$(mails va); MB=$(mails vb)
pin "$C" 3333 vouch:0; call POST /api/network/vouch "$C" '{"a":"va","b":"vb","note":"my sister and my colleague"}'; V=$(echo "$BODY" | J vouch.id)
[ "$CODE" = 200 ] && [ "$(echo "$BODY" | J vouch.status)" = pending ] && ok "C, who met both in person, introduces A and B" || fail "vouch: $CODE $BODY"
[ "$(mails va)" = $((MA+1)) ] && [ "$(mails vb)" = $((MB+1)) ] && ok "both introduced people are mailed" || fail "vouch mails"
pin "$C" 3333 vouch:0; call POST /api/network/vouch "$C" '{"a":"vb","b":"va"}'; [ "$CODE" = 409 ] && ok "the same two again while one waits → 409" || fail "dup: $CODE $BODY"

# ── acceptance ──
call POST /api/demipass/store "$A" '{"name":"wifi","value":"wifi-pass-zz71"}'; SID=$(Q "SELECT id FROM blindkey_secrets WHERE name='wifi'")
call POST /api/network/vouches/$V/accept "$C"; [ "$CODE" = 403 ] && ok "the voucher cannot accept on their behalf" || fail "voucher accept: $CODE"
call POST /api/network/vouches/$V/accept "$A"; [ "$CODE" = 403 ] && [ "$(echo "$BODY" | J intent)" = "vouch:$V" ] && ok "accepting takes the PIN (vouch:<id>)" || fail "accept pin: $CODE $BODY"
pin "$A" 1111 "vouch:$V"; call POST /api/network/vouches/$V/accept "$A"; [ "$CODE" = 200 ] && [ "$(echo "$BODY" | J connected)" = False ] && ok "A accepts; not confirmed until B does too" || fail "A accept: $CODE $BODY"
pin "$A" 1111 "share:$SID"; call POST /api/demipass/shares "$A" '{"secret":"wifi","to":"vb"}'; [ "$CODE" = 403 ] && ok "…no share yet" || fail "share half: $CODE"
pin "$B" 2222 "vouch:$V"; call POST /api/network/vouches/$V/accept "$B"
[ "$CODE" = 200 ] && [ "$(echo "$BODY" | J connected)" = True ] && [ "$(peer va vb)" = "vouch|$DC" ] && ok "B accepts → confirmed contacts, verified_via=vouch, vouched_by=C" || fail "B accept: $CODE $BODY $(peer va vb)"
pin "$A" 1111 "share:$SID"; call POST /api/demipass/shares "$A" '{"secret":"wifi","to":"vb"}'; { [ "$CODE" = 200 ] || [ "$CODE" = 201 ]; } && ok "A can now share with B" || fail "share vouched: $CODE $BODY"
call GET /api/network "$A"; python3 -c 'import json,sys; d=json.loads(sys.argv[1]); p=[x for x in d["people"] if x["username"]=="vb"][0]; sys.exit(0 if p["confirmed"] and p["confirmed_via"]=="vouch" and p["vouched_by"]=="vc" else 1)' "$BODY" && ok "A's people list shows B confirmed by C's vouch" || fail "network view: $BODY"
pin "$C" 3333 vouch:0; call POST /api/network/vouch "$C" '{"a":"va","b":"vb"}'; [ "$CODE" = 409 ] && ok "already confirmed → 409" || fail "already: $CODE"

# ── no chains ──
pin "$A" 1111 vouch:0; call POST /api/network/vouch "$A" '{"a":"vb","b":"vc"}'; [ "$CODE" = 403 ] && ok "A met B only through a vouch → A cannot vouch for B (no chains)" || fail "chain: $CODE $BODY"

# ── decline, withdraw, lapse ──
pin "$C" 3333 vouch:0; call POST /api/network/vouch "$C" '{"a":"va","b":"vd"}'; V2=$(echo "$BODY" | J vouch.id)
call POST /api/network/vouches/$V2/decline "$D"; [ "$CODE" = 200 ] && [ "$(echo "$BODY" | J vouch.status)" = declined ] && ok "an introduced person declines" || fail "decline: $CODE $BODY"
pin "$A" 1111 "vouch:$V2"; call POST /api/network/vouches/$V2/accept "$A"; [ "$CODE" = 409 ] && ok "…and it cannot be accepted after" || fail "accept declined: $CODE"
pin "$C" 3333 vouch:0; call POST /api/network/vouch "$C" '{"a":"va","b":"vd"}'; V3=$(echo "$BODY" | J vouch.id)
call POST /api/network/vouches/$V3/decline "$C"; [ "$(echo "$BODY" | J vouch.status)" = withdrawn ] && ok "the voucher withdraws" || fail "withdraw: $BODY"
pin "$C" 3333 vouch:0; call POST /api/network/vouch "$C" '{"a":"va","b":"vd"}'; V4=$(echo "$BODY" | J vouch.id)
call POST /api/network/people/remove "$C" '{"username":"vd"}'
pin "$A" 1111 "vouch:$V4"; call POST /api/network/vouches/$V4/accept "$A"
[ "$CODE" = 409 ] && [ "$(Q "SELECT status FROM contact_vouches WHERE id=$V4")" = withdrawn ] && ok "the voucher's own link to D ended → the introduction lapses" || fail "lapse: $CODE $BODY"
call POST /api/network/vouches/$V4/accept "$G"; [ "$CODE" = 404 ] && ok "a stranger cannot see or accept it" || fail "stranger: $CODE"

# ── agents never ──
call POST /api/network/requests "$C" '{"to":"vg","as":"agent"}'; R=$(echo "$BODY" | J request.id); pin "$G" 5555 "join:$R"; call POST /api/network/requests/$R/accept "$G"
call POST /api/network/vouch "$G" '{"a":"va","b":"vb"}'; [ "$CODE" = 403 ] && ok "an agent cannot vouch" || fail "agent vouch: $CODE"

echo; [ $fails = 0 ] && echo "ALL OK" || echo "$fails failure(s)"; exit $fails
