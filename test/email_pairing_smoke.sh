#!/bin/bash
# Email-code pairing (email_pairing.js; Aaron's ruling 2026-11-07, threat model item 6) through the real server on a
# throwaway DB with a fake SMTP sink (mail.log). People A (inviter), B, C, D (PINs); an agent silicon G.
#   - A sends a link (to a username or an address); the reply never carries the link; the link goes only by mail;
#     own address, an agent and a missing name are refused;
#   - B opens it signed in: B's PIN first (pair:<id>), then B alone sees a server-random 6-digit code; an agent cannot
#     open it; a second wallet cannot open it after B; a wrong token is 404;
#   - A types B's code: the code is checked before the PIN; 3 wrong codes cancel; A's replies never hold the code;
#   - confirmed: contacts with verified_via 'email-code', both mailed; DD works, shares are refused (qr/vouch only);
#   - legacy: a contact already confirmed in person (a pre-seeded 'qr' row) stays 'qr' after an email pairing.
set -u
W=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd); ROOT=$W
S=$(mktemp -d /tmp/dustforge-epair-smoke.XXXXXX)
PORT=${PORT:-3831}; SMTP_PORT=${SMTP_PORT:-3832}; API=http://127.0.0.1:$PORT
[ -d "$W/node_modules" ] || export NODE_PATH=${NODE_PATH:-/home/flimflam/project/dustforge/node_modules}
export IDENTITY_MASTER_KEY=$(python3 -c 'import secrets;print(secrets.token_hex(32))') DB_PATH=$S/dustforge.db PORT \
  STALWART_HOST=127.0.0.1 STALWART_PORT=1 SMTP_RELAY_HOST= SMTP_HOST=127.0.0.1 SMTP_PORT
cd "$W"
node -e '
const net = require("net"), fs = require("fs"); const [smtpPort, dir] = process.argv.slice(1);
net.createServer(sock => { let data = false, buf = "", msg = ""; sock.write("220 fake ESMTP\r\n");
  sock.on("data", chunk => { buf += chunk.toString(); let i;
    while ((i = buf.indexOf("\r\n")) >= 0) { const line = buf.slice(0, i); buf = buf.slice(i + 2);
      if (data) { if (line === ".") { data = false; fs.appendFileSync(dir + "/mail.log", msg + "\n=====\n"); msg = ""; sock.write("250 ok\r\n"); } else msg += line + "\n"; continue; }
      const v = line.slice(0, 4).toUpperCase();
      if (v === "EHLO" || v === "HELO") sock.write("250 fake\r\n"); else if (v === "DATA") { data = true; sock.write("354 go\r\n"); }
      else if (v === "QUIT") sock.end("221 bye\r\n"); else sock.write("250 ok\r\n"); } }); }).listen(Number(smtpPort), "127.0.0.1");' "$SMTP_PORT" "$S" & FAKE=$!
node server.js >"$S/server.log" 2>&1 & SRV=$!
trap 'kill $SRV $FAKE 2>/dev/null; rm -rf "$S"' EXIT
for i in $(seq 1 40); do curl -s -o /dev/null "$API/api/health" && break; sleep 0.5; done
kill -0 $SRV 2>/dev/null || { echo "server died:"; tail -5 "$S/server.log"; exit 1; }
fails=0; ok(){ echo "ok   $*"; }; fail(){ echo "FAIL $*"; fails=$((fails+1)); }
J(){ python3 -c 'import json,sys; d=json.load(sys.stdin); v=d
for k in sys.argv[1].split("."):
    v = v[int(k)] if isinstance(v, list) else (v or {}).get(k)
print(v)' "$1"; }
Q(){ python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); r=c.execute(sys.argv[2]).fetchone(); print(r[0] if r else '')" "$DB_PATH" "$1"; }
call(){ local m=$1 p=$2 t=$3 b=${4:-}
  BODY=$(curl -s -o - -w '\n%{http_code}' -X "$m" "$API$p" -H 'Content-Type: application/json' ${t:+-H "Authorization: Bearer $t"} ${b:+-d "$b"})
  CODE=${BODY##*$'\n'}; BODY=${BODY%$'\n'*}; }
H=$(printf '%s' hunter22 | sha256sum | cut -d' ' -f1)
node -e '
const identity = require("./identity"); const Database = require("better-sqlite3");
const db = new Database(process.env.DB_PATH);
for (const u of ["pa", "pb", "pc", "pd", "pe", "pf", "agentg"]) { const id = identity.createIdentity();
  db.prepare("INSERT INTO identity_wallets (did, username, email, encrypted_private_key, balance_cents, password_hash) VALUES (?, ?, ?, ?, 1000, ?)").run(id.did, u, u + "@dustforge.com", id.encrypted_private_key || id.encryptedPrivateKey, process.argv[1]);
  db.prepare("INSERT INTO identity_transactions (did, amount_cents, type, description, balance_after) VALUES (?, 1000, ?, ?, 1000)").run(id.did, "topup", "smoke"); }
const owner = db.prepare("SELECT did FROM identity_wallets WHERE username = ?").get("pd").did;
const f = db.prepare("INSERT INTO fleets (owner_did, name, slug) VALUES (?, ?, ?)").run(owner, "d fleet", "d-fleet").lastInsertRowid;
db.prepare("INSERT INTO fleet_silicons (fleet_id, member_did, handle, silicon_id, status, created_by_fleet) VALUES (?, (SELECT did FROM identity_wallets WHERE username = ?), ?, ?, ?, 1)").run(f, "agentg", "agentg", "sil_epair", "active");' "$H"
did(){ Q "SELECT did FROM identity_wallets WHERE username='$1'"; }
login(){ call POST /api/identity/auth-fingerprint "" '{"username":"'$1'","password":"hunter22","scope":"transact","expires_in":"1h"}'; echo "$BODY" | J token; }
A=$(login pa); B=$(login pb); C=$(login pc); D=$(login pd); E=$(login pe); F=$(login pf); G=$(login agentg)
for t in "$A" "$B" "$C" "$D" "$E" "$F"; do call POST /api/identity/pin "$t" '{"pin":"4321","password":"hunter22"}'; [ "$CODE" = 200 ] || fail "pin: $CODE $BODY"; done
call POST /api/identity/pin "$G" '{"pin":"4321","password":"hunter22"}'
pin(){ call POST /api/identity/gate/verify "$1" '{"gate":"pin","pin":"4321","intent":"'$2'"}'; [ "$CODE" = 200 ] || fail "pin $2: $CODE $BODY"; }
mailtoken(){ sleep 0.6; python3 - "$S/mail.log" "$1" <<'EOF'
import sys, re
blocks = open(sys.argv[1]).read().split("\n=====\n") if __import__("os").path.exists(sys.argv[1]) else []
for b in reversed(blocks):
    if ("To: " + sys.argv[2]) in b or sys.argv[2] in b.split("\n\n")[0]:
        body = re.sub(r"=\r?\n", "", b)
        m = re.search(r"epair=3D(\d+\.[A-Za-z0-9_-]{22})|epair=(\d+\.[A-Za-z0-9_-]{22})", body)
        if m: print(m.group(1) or m.group(2)); break
EOF
}

# ── A sends ─────────────────────────────────────────────────────────────────────────────────────────────────────────
call POST /api/network/pair/email "$A" '{"to":"pa@dustforge.com"}'; [ "$CODE" = 400 ] && ok "own address refused" || fail "own: $CODE $BODY"
call POST /api/network/pair/email "$A" '{"to":"agentg"}'; [ "$CODE" = 403 ] && ok "an agent is refused (people only)" || fail "agent target: $CODE $BODY"
call POST /api/network/pair/email "$A" '{"to":"nobody-here"}'; [ "$CODE" = 404 ] && ok "an unknown username is refused" || fail "unknown: $CODE"
call POST /api/network/pair/email "$G" '{"to":"pb"}'; [ "$CODE" = 403 ] && ok "an agent cannot send a link" || fail "agent sender: $CODE"
call POST /api/network/pair/email "$A" '{"to":"pb"}'; ID=$(echo "$BODY" | J pair_id)
[ "$CODE" = 201 ] && ! echo "$BODY" | grep -q "epair=" && [ "$(echo "$BODY" | J code)" = None ] && ok "A sends a link to pb (201); the reply holds no link and no code" || fail "send: $CODE $BODY"
TOK=$(mailtoken pb@dustforge.com); [ -n "$TOK" ] && ok "the link went by mail to pb@dustforge.com" || fail "no link in mail.log"

# ── B opens it ──────────────────────────────────────────────────────────────────────────────────────────────────────
call POST /api/network/pair/email/join "$B" '{"token":"'"${ID}"'.AAAAAAAAAAAAAAAAAAAAAA"}'; [ "$CODE" = 404 ] && ok "a wrong token → 404" || fail "wrong token: $CODE"
call POST /api/network/pair/email/join "$G" '{"token":"'"$TOK"'"}'; [ "$CODE" = 403 ] && ok "an agent cannot open it" || fail "agent join: $CODE"
pin "$C" "pair:$ID"; call POST /api/network/pair/email/join "$C" '{"token":"'"$TOK"'"}'
[ "$CODE" = 409 ] && echo "$BODY" | grep -q "pb's wallet" && [ "$(Q "SELECT status FROM email_pairings WHERE id=$ID")" = sent ] && ok "a link sent to @pb: another wallet (a forwarded email) cannot open it" || fail "target bind: $CODE $BODY"
call POST /api/network/pair/email/join "$B" '{"token":"'"$TOK"'"}'
[ "$CODE" = 403 ] && [ "$(echo "$BODY" | J intent)" = "pair:$ID" ] && [ "$(Q "SELECT status FROM email_pairings WHERE id=$ID")" = sent ] && ok "opening it takes B's PIN first (nothing bound before)" || fail "join no pin: $CODE $BODY"
pin "$B" "pair:$ID"; call POST /api/network/pair/email/join "$B" '{"token":"https://demipass.com/vault-mobile.html#epair='"$TOK"'"}'
BCODE=$(echo "$BODY" | J code)
[ "$CODE" = 200 ] && [[ "$BCODE" =~ ^[0-9]{6}$ ]] && [ "$(echo "$BODY" | J role)" = joiner ] && ok "B opened it (the whole URL works) and B's screen shows the code" || fail "join: $CODE $BODY"
call GET /api/network/pair/email "$A"; A1=$CODE; AL=$(echo "$BODY" | python3 -c 'import json,sys; print(len([p for p in json.load(sys.stdin)["pairings"] if p["status"]=="joined"]))')
call GET /api/network/pair/email "$B"; B1=$CODE; BL=$(echo "$BODY" | python3 -c 'import json,sys; print(len([p for p in json.load(sys.stdin)["pairings"] if p["role"]=="joiner"]))')
[ "$A1" = 200 ] && [ "$B1" = 200 ] && [ "$AL" = 1 ] && [ "$BL" = 1 ] && ok "GET /api/network/pair/email answers (200) and lists the pairing for A and for B" || fail "list route: $A1 $B1 $AL $BL"
call GET /api/network/pair/email/$ID "$A"
[ "$(echo "$BODY" | J code)" = None ] && [ "$(echo "$BODY" | J type_code)" = True ] && [ "$(echo "$BODY" | J other)" = pb ] && [ "$(echo "$BODY" | J sent_to_user)" = pb ] && ok "A sees it was sent to @pb and opened by @pb, never the code" || fail "A view: $BODY"
call GET /api/network/pair/email "$A"; ! echo "$BODY" | grep -q "$BCODE" && ok "A's list does not hold the code" || fail "code in A's list"

# ── A types the code ────────────────────────────────────────────────────────────────────────────────────────────────
call POST /api/network/pair/email/$ID/confirm "$B" '{"code":"'"$BCODE"'"}'; [ "$CODE" = 403 ] && ok "the one who opened it cannot confirm (A types it)" || fail "B confirm: $CODE"
W1=$(printf '%06d' $(( (10#$BCODE + 1) % 1000000 )))
call POST /api/network/pair/email/$ID/confirm "$A" '{"code":"'"$W1"'"}'
[ "$CODE" = 403 ] && [ "$(echo "$BODY" | J code_tries_left)" = 2 ] && ! echo "$BODY" | grep -q "$BCODE" && ok "a wrong code → 403, 2 tries left, the code is not named" || fail "wrong 1: $CODE $BODY"
call POST /api/network/pair/email/$ID/confirm "$A" '{"code":"'"$BCODE"'"}'
[ "$CODE" = 403 ] && [ "$(echo "$BODY" | J intent)" = "pair:$ID" ] && ok "the right code, then A's PIN" || fail "no pin: $CODE $BODY"
pin "$A" "pair:$ID"; call POST /api/network/pair/email/$ID/confirm "$A" '{"code":"'"$BCODE"'"}'
[ "$CODE" = 200 ] && [ "$(echo "$BODY" | J connected)" = True ] && ok "confirmed" || fail "confirm: $CODE $BODY"
PA=$(did pa); PB=$(did pb); LO=$(python3 -c "import sys;a,b=sorted(sys.argv[1:]);print(a)" "$PA" "$PB"); HI=$(python3 -c "import sys;a,b=sorted(sys.argv[1:]);print(b)" "$PA" "$PB")
[ "$(Q "SELECT verified_via || '/' || status FROM network_peers WHERE did_a='$LO' AND did_b='$HI'")" = email-code/active ] && ok "a contact now, verified_via email-code" || fail "peer row: $(Q "SELECT verified_via FROM network_peers WHERE did_a='$LO' AND did_b='$HI'")"
sleep 0.6; [ "$(grep -c "is now a confirmed contact" "$S/mail.log")" -ge 2 ] && ok "both were mailed" || fail "completion mail"
call GET /api/network "$A"; python3 -c 'import json,sys; d=json.loads(sys.argv[1]); p=[x for x in d["people"] if x["username"]=="pb"][0]; sys.exit(0 if p["confirmed"] and p["confirmed_via"]=="email-code" and p["can_share"] is False else 1)' "$BODY" \
  && ok "A's network: pb confirmed by email code, can_share false" || fail "network view: $BODY"
call POST /api/demipass/store "$A" '{"name":"epair-secret","value":"zzzzzzzzzz-epair-1","secret_type":"api_key"}'
call POST /api/blindkey/shares "$A" '{"secret":"epair-secret","to":"pb"}'
[ "$CODE" = 403 ] && [ "$(echo "$BODY" | J pair_required)" = True ] && ok "shares still need pairing in person (email-code is not enough)" || fail "share: $CODE $BODY"

# ── three wrong codes cancel ────────────────────────────────────────────────────────────────────────────────────────
call POST /api/network/pair/email "$A" '{"to":"pc@dustforge.com"}'; ID2=$(echo "$BODY" | J pair_id); TOK2=$(mailtoken pc@dustforge.com)
pin "$C" "pair:$ID2"; call POST /api/network/pair/email/join "$C" '{"token":"'"$TOK2"'"}'; CC=$(echo "$BODY" | J code)
for k in 1 2 3; do WC=$(printf '%06d' $(( (10#$CC + k) % 1000000 ))); call POST /api/network/pair/email/$ID2/confirm "$A" '{"code":"'"$WC"'"}'; done
[ "$(echo "$BODY" | J status)" = cancelled ] && [ "$(Q "SELECT status || '/' || COALESCE(code,'null') FROM email_pairings WHERE id=$ID2")" = cancelled/null ] && ok "3 wrong codes cancel it (code erased)" || fail "3 wrong: $BODY"
call POST /api/network/pair/email/$ID2/confirm "$A" '{"code":"'"$CC"'"}'; [ "$CODE" = 409 ] && ok "…and the right code no longer works" || fail "after cancel: $CODE"

# ── mail-bomb: one mailbox, many spellings → at most 5 links a day (3 per sender); display names and lists refused ──────────────────
n400=0; for v in 'x1<victim@gmail.com>' 'Victim <victim@gmail.com>' 'victim@gmail.com, other@example.com' '"v" <victim@gmail.com>' 'victim@gmail.com;x@y.com' 'grp: victim@gmail.com;'; do
  call POST /api/network/pair/email "$F" "$(python3 -c 'import json,sys; print(json.dumps({"to":sys.argv[1]}))' "$v")"; [ "$CODE" = 400 ] && n400=$((n400+1)); done
[ "$n400" = 6 ] && ok "display names, lists and groups are refused (one bare mailbox only)" || fail "bare mailbox: $n400/6"
for v in victim@gmail.com Victim@Gmail.com v.ictim@gmail.com vi.ctim@gmail.com victim+1@gmail.com victim+a.b@gmail.com victim@googlemail.com V.I.C.T.I.M@gmail.com victim+zz@googlemail.com vic.tim@gmail.com victi.m@gmail.com victim+q@gmail.com VICTIM@GMAIL.COM v.i.ctim@gmail.com victim+x@gmail.com vict.im+y@gmail.com; do
  for who in "$C" "$D" "$E"; do call POST /api/network/pair/email "$who" '{"to":"'"$v"'"}'; [ "$CODE" = 201 ] && { call POST /api/network/pair/email/$(echo "$BODY" | J pair_id)/cancel "$who"; }; done
done
sleep 0.8
[ "$(Q "SELECT COUNT(*) FROM email_pairings WHERE to_canon='victim@gmail.com'")" = 5 ] && ok "16 spellings of one Gmail inbox (+tags, dots, case, googlemail), 3 senders, cancels: 5 links in all" || fail "per-mailbox cap: $(Q "SELECT COUNT(*) FROM email_pairings WHERE to_canon='victim@gmail.com'")"
[ "$(Q "SELECT MAX(n) FROM (SELECT COUNT(*) AS n FROM email_pairings WHERE to_canon='victim@gmail.com' GROUP BY inviter_did)")" -le 3 ] && ok "…no one sender more than 3 of them (one wallet can't use up a person's day)" || fail "per-pair cap"
[ "$(grep -c -i -E "^To: .*@(gmail|googlemail)\.com" "$S/mail.log")" -le 5 ] && ok "…and at most 5 mails reached it" || fail "mails to victim: $(grep -c -i -E '^To: .*@(gmail|googlemail)' "$S/mail.log")"
for k in $(seq 1 10); do call POST /api/network/pair/email "$F" '{"to":"u'$k'@example.org"}'; [ "$CODE" = 201 ] && call POST /api/network/pair/email/$(echo "$BODY" | J pair_id)/cancel "$F"; done
call POST /api/network/pair/email "$F" '{"to":"u11@example.org"}'; [ "$CODE" = 429 ] && ok "a sender gets 10 links a day, cancelled ones included" || fail "sender cap: $CODE $BODY"

# ── an address invite tells A whether the opener's own address is the one it went to ────────────────────────────────
call POST /api/network/pair/email "$A" '{"to":"pe@dustforge.com"}'; IE=$(echo "$BODY" | J pair_id); TE=$(mailtoken pe@dustforge.com)
pin "$E" "pair:$IE"; call POST /api/network/pair/email/join "$E" '{"token":"'"$TE"'"}'; EC=$(echo "$BODY" | J code)
call GET /api/network/pair/email/$IE "$A"; [ "$(echo "$BODY" | J opener_matches_address)" = True ] && ok "by address: the opener's own address matches → opener_matches_address true" || fail "match true: $BODY"
call POST /api/network/pair/email "$A" '{"to":"stranger@example.net"}'; IX=$(echo "$BODY" | J pair_id); TX=$(mailtoken stranger@example.net)
pin "$C" "pair:$IX"; call POST /api/network/pair/email/join "$C" '{"token":"'"$TX"'"}'
call GET /api/network/pair/email/$IX "$A"; [ "$(echo "$BODY" | J opener_matches_address)" = False ] && [ "$(echo "$BODY" | J other)" = pc ] && ok "a forwarded address link opened by @pc → opener_matches_address false (the app warns)" || fail "match false: $BODY"
call POST /api/network/pair/email/$IX/cancel "$A"
# A recovery email is set unverified: it must not make a forwarded link's opener "match" (#75 re-review).
python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute(\"UPDATE identity_wallets SET recovery_email='spoof.target@example.net' WHERE username='pd'\"); c.commit()" "$DB_PATH"
call POST /api/network/pair/email "$A" '{"to":"spoof.target@example.net"}'; IS=$(echo "$BODY" | J pair_id); TS=$(mailtoken spoof.target@example.net)
pin "$D" "pair:$IS"; call POST /api/network/pair/email/join "$D" '{"token":"'"$TS"'"}'
call GET /api/network/pair/email/$IS "$A"; [ "$(echo "$BODY" | J opener_matches_address)" = False ] && ok "an unverified recovery email set to the target address does not count as a match" || fail "recovery spoof: $BODY"
call POST /api/network/pair/email/$IS/cancel "$A"
# The opener became an agent between opening and A's confirm → refused inside the transaction.
python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); f=c.execute(\"SELECT id FROM fleets WHERE slug='d-fleet'\").fetchone()[0]; c.execute(\"INSERT INTO fleet_silicons (fleet_id, member_did, handle, silicon_id, status, created_by_fleet) VALUES (?, (SELECT did FROM identity_wallets WHERE username='pe'), 'pe', 'sil_pe', 'active', 0)\", (f,)); c.commit()" "$DB_PATH"
pin "$A" "pair:$IE"; call POST /api/network/pair/email/$IE/confirm "$A" '{"code":"'"$EC"'"}'
[ "$CODE" = 409 ] && [ "$(Q "SELECT COUNT(*) FROM network_peers WHERE (did_a=(SELECT did FROM identity_wallets WHERE username='pe') OR did_b=(SELECT did FROM identity_wallets WHERE username='pe')) AND verified_via='email-code'")" = 0 ] \
  && ok "the opener turned agent before the confirm → 409, nothing paired" || fail "agent recheck: $CODE $BODY"

# ── a vouch raises an email-code pair (A–pb) to 'vouch' ─────────────────────────────────────────────────────────────
source "$ROOT/test/lib/pair_in_person.sh"
pair_in_person "$C" 4321 "$A" 4321; pair_in_person "$C" 4321 "$B" 4321
pin "$C" "vouch:0"; call POST /api/network/vouch "$C" '{"a":"pa","b":"pb","note":"smoke"}'; VC=$CODE; VID=$(echo "$BODY" | J vouch.id); [ "$VID" = None ] && VID=$(echo "$BODY" | J id)
{ [ "$VC" = 200 ] || [ "$VC" = 201 ]; } && ok "a vouch for an email-code pair is accepted (not 'already confirmed')" || fail "vouch on email-code: $VC $BODY"
pin "$A" "vouch:$VID"; call POST /api/network/vouches/$VID/accept "$A"; pin "$B" "vouch:$VID"; call POST /api/network/vouches/$VID/accept "$B"
[ "$(Q "SELECT verified_via FROM network_peers WHERE did_a='$LO' AND did_b='$HI'")" = vouch ] && ok "…and once both accept, A–pb is 'vouch' (shares open)" || fail "vouch upgrade: $(Q "SELECT verified_via FROM network_peers WHERE did_a='$LO' AND did_b='$HI'") $BODY"

# ── legacy: a contact confirmed in person stays 'qr' ────────────────────────────────────────────────────────────────
PD=$(did pd); LO2=$(python3 -c "import sys;print(sorted(sys.argv[1:])[0])" "$PA" "$PD"); HI2=$(python3 -c "import sys;print(sorted(sys.argv[1:])[1])" "$PA" "$PD")
python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute(\"INSERT INTO network_peers (did_a, did_b, request_id, verified_via, verified_at) VALUES (?, ?, NULL, 'qr', '2026-11-01T00:00:00Z')\", (sys.argv[2], sys.argv[3])); c.commit()" "$DB_PATH" "$LO2" "$HI2"
call POST /api/network/pair/email "$A" '{"to":"pd"}'; ID3=$(echo "$BODY" | J pair_id); TOK3=$(mailtoken pd@dustforge.com)
pin "$D" "pair:$ID3"; call POST /api/network/pair/email/join "$D" '{"token":"'"$TOK3"'"}'; DC=$(echo "$BODY" | J code)
pin "$A" "pair:$ID3"; call POST /api/network/pair/email/$ID3/confirm "$A" '{"code":"'"$DC"'"}'
[ "$CODE" = 200 ] && [ "$(Q "SELECT verified_via || '/' || verified_at FROM network_peers WHERE did_a='$LO2' AND did_b='$HI2'")" = "qr/2026-11-01T00:00:00Z" ] \
  && ok "a contact already confirmed in person stays 'qr' (no downgrade)" || fail "downgrade: $CODE $(Q "SELECT verified_via FROM network_peers WHERE did_a='$LO2' AND did_b='$HI2'")"
grep -q "$BCODE" "$S/server.log" && fail "a code reached the server log" || ok "no code in the server log"

[ $fails -gt 0 ] && { echo "--- server.log"; grep -i -m8 "error" "$S/server.log"; }
echo "$fails failure(s)"; exit $(( fails > 0 ))
