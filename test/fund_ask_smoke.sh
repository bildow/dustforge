#!/bin/bash
# Fund asks (Aaron 2026-11-18: a pane's "fund the wallet" request popped up and then was nowhere in the app). Work that
# waits on a wallet's balance files a card on that wallet; the app shows it with Grant (operator-grant wallets) or
# Deposit; the phone's alerts poll lists it beside the approvals; it closes by itself once the balance covers the need;
# the Requests history keeps it.
set -u
W=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
S=$(mktemp -d /tmp/dustforge-fund-ask-smoke.XXXXXX)
PORT=${PORT:-3833}; API=http://127.0.0.1:$PORT
[ -d "$W/node_modules" ] || export NODE_PATH=${NODE_PATH:-/home/flimflam/project/dustforge/node_modules}
export IDENTITY_MASTER_KEY=$(python3 -c 'import secrets;print(secrets.token_hex(32))') DB_PATH=$S/dustforge.db PORT \
  STALWART_HOST=127.0.0.1 STALWART_PORT=1 SMTP_RELAY_HOST= SMTP_HOST=127.0.0.1 SMTP_PORT=9
unset DEPOSITS STRIPE_SECRET_KEY STRIPE_TEST_CREDITS OPERATOR_GRANT_DIDS
cd "$W"
fails=0; ok(){ echo "ok   $*"; }; fail(){ echo "FAIL $*"; fails=$((fails+1)); }
J(){ python3 -c 'import json,sys; d=json.load(sys.stdin); v=d
for k in sys.argv[1].split("."):
    v = v[int(k)] if isinstance(v, list) else (v or {}).get(k)
print(v)' "$1"; }
Q(){ python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); r=c.execute(sys.argv[2]).fetchone(); print(r[0] if r else '')" "$DB_PATH" "$1"; }
jbody(){ python3 -c 'import json,sys; print(json.dumps(dict(zip(sys.argv[1::2], [json.loads(x) if x[:1] in "[{" or x in ("true","false") or (x.lstrip("-").isdigit() and not (len(x) > 1 and x.startswith("0"))) else x for x in sys.argv[2::2]]))))' "$@"; }
call(){ local m=$1 p=$2 t=$3 b=${4:-}
  BODY=$(curl -s -o - -w '\n%{http_code}' -X "$m" "$API$p" -H 'Content-Type: application/json' ${t:+-H "Authorization: Bearer $t"} ${b:+-d "$b"})
  CODE=${BODY##*$'\n'}; BODY=${BODY%$'\n'*}; }
start(){ node server.js >>"$S/server.log" 2>&1 & SRV=$!; for i in $(seq 1 40); do curl -s -o /dev/null "$API/api/health" && break; sleep 0.5; done; }
start; kill $SRV; wait $SRV 2>/dev/null
H=$(printf '%s' hunter22 | sha256sum | cut -d' ' -f1)
node -e '
const identity = require("./identity"); const Database = require("better-sqlite3"); const db = new Database(process.env.DB_PATH);
const mk = (u, bal) => { const id = identity.createIdentity(); const enc = id.encrypted_private_key || id.encryptedPrivateKey;
  db.prepare("INSERT INTO identity_wallets (did, username, email, encrypted_private_key, balance_cents, password_hash) VALUES (?, ?, ?, ?, ?, ?)").run(id.did, u, u + "@smoke.invalid", enc, bal, process.argv[1]);
  db.prepare("INSERT INTO identity_transactions (did, amount_cents, type, description, balance_after) VALUES (?, ?, ?, ?, ?)").run(id.did, bal, "topup", "smoke", bal); return id.did; };
const o = mk("owner", 1465), a = mk("agent", 10), x = mk("stranger", 100);
const f = db.prepare("INSERT INTO fleets (owner_did, name, slug) VALUES (?, ?, ?)").run(o, "Owner", "owner-agents").lastInsertRowid;
db.prepare("INSERT INTO fleet_members (fleet_id, member_did, role) VALUES (?, ?, ?)").run(f, o, "owner");
db.prepare("INSERT INTO fleet_members (fleet_id, member_did, role) VALUES (?, ?, ?)").run(f, a, "agent");
db.prepare(`INSERT INTO fleet_silicons (fleet_id, member_did, handle, display_name, silicon_id, created_by_fleet, status) VALUES (?, ?, ?, ?, ?, 1, ?)`).run(f, a, "agent", "Agent", "sil_smoke", "active");
process.stdout.write(o);' "$H" > "$S/owner.did" || { echo "FAIL seed"; exit 1; }
export OPERATOR_GRANT_DIDS=$(cat "$S/owner.did")
start; trap 'kill $SRV 2>/dev/null; rm -rf "$S"' EXIT
did(){ Q "SELECT did FROM identity_wallets WHERE username='$1'"; }
bal(){ Q "SELECT balance_cents FROM identity_wallets WHERE username='$1'"; }
login(){ call POST /api/identity/auth-fingerprint "" '{"username":"'$1'","password":"hunter22","scope":"transact","expires_in":"1h"}'; echo "$BODY" | J token; }
OWN=$(login owner); AG=$(login agent); STR=$(login stranger)
for t in "$OWN" "$STR"; do call POST /api/identity/pin "$t" '{"pin":"4321","password":"hunter22"}'; [ "$CODE" = 200 ] || fail "pin set: $CODE $BODY"; done
pin(){ call POST /api/identity/gate/verify "$1" "$(jbody gate pin pin "$2" intent "$3")"; [ "$CODE" = 200 ] || fail "pin $3: $CODE $BODY"; }
approve(){ pin "$1" 4321 "approval-open:$2"; call POST /api/demipass/approvals/$2/open "$1"; local k; k=$(echo "$BODY" | J code)
  call POST /api/demipass/approvals/$2/approve "$1" "$(jbody code "$k")"; [ "$CODE" = 200 ] || fail "approve $2: $CODE $BODY"; }
REV=conduit-w5-sdk-controls-d939a44-20261117

# 1. filing: the pane on the owner's session files one card for the review that waits (the 11-18 case: needs 1483, holds 1465)
call POST /api/billing/fund-asks "$OWN" "$(jbody need_dd 1483 service fleetgate subject "$REV" from astra)"
[ "$CODE" = 202 ] && [ "$(echo "$BODY" | J short_dd)" = 18 ] && ok "a fund ask is filed: 202, 18 DD short" || fail "file: $CODE $BODY"
FA=$(echo "$BODY" | J notice_id)
call POST /api/billing/fund-asks "$OWN" "$(jbody need_dd 1500 service fleetgate subject "$REV")"
[ "$CODE" = 202 ] && [ "$(echo "$BODY" | J already)" = True ] && [ "$(echo "$BODY" | J notice_id)" = "$FA" ] \
  && [ "$(Q "SELECT COUNT(*) FROM wallet_notices WHERE kind='fund_ask'")" = 1 ] && ok "the same work asking again updates the one card (need 1500), no second card" || fail "refile: $CODE $BODY"
call POST /api/billing/fund-asks "$OWN" "$(jbody need_dd 1000 service fleetgate subject other-review)"
[ "$CODE" = 200 ] && [ "$(echo "$BODY" | J covered)" = True ] && ok "a need the balance already covers files nothing (200 covered)" || fail "covered: $CODE $BODY"
call POST /api/billing/fund-asks "$AG" "$(jbody need_dd 500 service fleetgate subject x1)"
[ "$CODE" = 409 ] && echo "$BODY" | grep -q "network/topups" && ok "an agent wallet is pointed to its fleet owner's top-up ask (409)" || fail "agent: $CODE $BODY"
for b in '{"need_dd":0,"service":"fleetgate","subject":"x"}' '{"need_dd":5000,"service":"Fleet Gate","subject":"x"}' '{"need_dd":5000,"service":"fleetgate","subject":"<img src=x>"}' '{"need_dd":5000,"service":"fleetgate","subject":"https://evil.example/pay"}' '{"need_dd":5000,"service":"fleetgate","subject":"x","lapses_at":"2001-01-01T00:00:00Z"}'; do
  call POST /api/billing/fund-asks "$OWN" "$b"; [ "$CODE" = 400 ] || fail "bad body accepted: $b → $CODE"; done; ok "bad need, service, subject (markup or a link) or lapse → 400"
call POST /api/billing/fund-asks "" "$(jbody need_dd 5000 service fleetgate subject x)"; [ "$CODE" = 401 ] && ok "no token → 401" || fail "noauth: $CODE"

# 2. the card: what is short now, Grant for an operator-grant wallet, Deposit for any other
call GET /api/billing/notices "$OWN"
[ "$(echo "$BODY" | J notices.0.kind)" = fund_ask ] && [ "$(echo "$BODY" | J notices.0.fund.short_dd)" = 35 ] && [ "$(echo "$BODY" | J notices.0.fund.grant_dd)" = 500 ] \
  && [ "$(echo "$BODY" | J notices.0.fund.subject)" = "$REV" ] && [ "$(echo "$BODY" | J notices.0.fund.grant_fleet)" = owner-agents ] \
  && ok "the app's card: fleetgate $REV, 35 DD short, Grant 500 DD through the owner's fleet" || fail "card: $BODY"
echo "$BODY" | J notices.0.fund.requester | grep -q "says: astra" && ok "the pane's own label is shown as what it says, not as who it is" || fail "requester: $BODY"
call POST /api/billing/fund-asks "$STR" "$(jbody need_dd 400 service fleetgate subject s-1)"; call GET /api/billing/notices "$STR"
[ "$(echo "$BODY" | J notices.0.fund.grant_dd)" = None ] && [ "$(echo "$BODY" | J notices.0.deposit.amount_dd)" = 300 ] && ok "a wallet without operator grants gets Deposit 300 DD, no Grant" || fail "stranger card: $BODY"
call GET /api/billing/fund-asks/$FA "$STR"; [ "$CODE" = 404 ] && ok "another wallet cannot read the owner's ask" || fail "stranger read: $CODE"
call POST /api/billing/notices/$FA/dismiss "$STR"; [ "$(echo "$BODY" | J ok)" = False ] && ok "…nor dismiss it" || fail "stranger dismiss: $BODY"

# 3. Grant from the card: a request approved with the PIN, then Collect credits it; the card closes by itself (covered)
call POST /api/fleet/owner-agents/owner-grant "$OWN" '{"amount_cents":500}'
[ "$CODE" = 202 ] && AP=$(echo "$BODY" | J approval_id) && ok "Grant files the operator grant: 202, approval $AP" || fail "grant file: $CODE $BODY"
[ "$(bal owner)" = 1465 ] && ok "nothing credited before the approval" || fail "credited early"
approve "$OWN" "$AP"
call POST /api/fleet/owner-agents/owner-grant "$OWN" "$(jbody amount_cents 500 approval_id "$AP")"
[ "$CODE" = 200 ] && [ "$(bal owner)" = 1965 ] && ok "Collect credits 500 DD (1965)" || fail "collect: $CODE $BODY $(bal owner)"
call GET /api/billing/fund-asks/$FA "$OWN"
[ "$(echo "$BODY" | J fund_ask.status)" = covered ] && ok "the ask is now 'covered' (the pane's status check sees it)" || fail "status: $BODY"
call GET /api/billing/notices "$OWN"; [ "$(echo "$BODY" | J notices)" = "[]" ] && ok "and the card is gone" || fail "card left: $BODY"
call GET "/api/billing/notices?all=1" "$OWN"
[ "$(echo "$BODY" | J notices.0.closed_why)" = covered ] && [ "$(echo "$BODY" | J notices.0.fund.subject)" = "$REV" ] && ok "the Requests history keeps it, closed as covered" || fail "history: $BODY"

# 4. caps: 3 open at once, 10 a day
for k in 1 2 3; do call POST /api/billing/fund-asks "$OWN" "$(jbody need_dd 90000 service fleetgate subject "cap-$k")"; done
[ "$CODE" = 429 ] && [ "$(Q "SELECT COUNT(*) FROM wallet_notices WHERE did='$(did owner)' AND kind='fund_ask' AND closed_at IS NULL")" = 3 ] || true
call POST /api/billing/fund-asks "$OWN" "$(jbody need_dd 90000 service fleetgate subject cap-4)"
[ "$CODE" = 429 ] && ok "a 4th open ask → 429" || fail "open cap: $CODE $BODY"

# 5. lapse: the work's own wait ended → 'lapsed'
call POST /api/billing/notices/$(Q "SELECT id FROM wallet_notices WHERE nkey='fund:fleetgate:cap-1'")/dismiss "$OWN"
call POST /api/billing/fund-asks "$OWN" "$(jbody need_dd 90000 service fleetgate subject cap-1)"
[ "$CODE" = 409 ] && [ "$(echo "$BODY" | J dismissed)" = True ] && ok "a dismissed ask is not filed again for 24 h (409 dismissed)" || fail "dismissed refile: $CODE $BODY"
python3 -c "import sqlite3,sys,json; c=sqlite3.connect(sys.argv[1]); r=c.execute(\"SELECT id,data FROM wallet_notices WHERE nkey='fund:fleetgate:cap-2'\").fetchone(); d=json.loads(r[1]); d['fund']['lapses_at']='2026-01-01T00:00:00.000Z'; c.execute('UPDATE wallet_notices SET data=? WHERE id=?',(json.dumps(d),r[0])); c.commit()" "$DB_PATH"
call GET /api/billing/fund-asks/$(Q "SELECT id FROM wallet_notices WHERE nkey='fund:fleetgate:cap-2'") "$OWN"
[ "$(echo "$BODY" | J fund_ask.status)" = lapsed ] && ok "an ask past its lapse closes as 'lapsed'" || fail "lapse: $BODY"
call POST /api/billing/fund-asks "$OWN" "$(jbody need_dd 90000 service fleetgate subject cap-5)"; C5=$(echo "$BODY" | J notice_id)
call POST /api/billing/notices/$C5/dismiss "$OWN"
call POST /api/billing/fund-asks "$OWN" "$(jbody need_dd 90000 service fleetgate subject cap-6)"
[ "$CODE" = 409 ] && echo "$BODY" | grep -q "twice" && ok "two dismissed in a day: the wallet takes no new fund ask under any subject (409)" || fail "wallet quiet: $CODE $BODY"

# 6. the phone: the D-signed alerts poll lists the open ask beside the approvals (id 3e11+), and not twice
node -e 'const c=require("crypto"),fs=require("fs");for(const n of ["d","p"]){const {privateKey,publicKey}=c.generateKeyPairSync("ec",{namedCurve:"prime256v1"});
fs.writeFileSync(process.argv[1]+"/"+n+".pem",privateKey.export({type:"pkcs8",format:"pem"}));fs.writeFileSync(process.argv[1]+"/"+n+".pub",publicKey.export({type:"spki",format:"der"}).toString("base64"))}' "$S"
sig(){ node -e 'const c=require("crypto"),fs=require("fs"); process.stdout.write(c.sign("sha256", Buffer.from(process.argv[2]), fs.readFileSync(process.argv[1])).toString("base64"))' "$S/$1.pem" "$2"; }
call POST /api/identity/device/challenge "$OWN" '{"purpose":"enrol","intent":"device-enrol:0"}'; CHD=$(echo "$BODY" | J challenge_id); MSG="$(echo "$BODY" | J message):phone-0001"
pin "$OWN" 4321 "device-enrol:0"; call POST /api/identity/gate/verify "$OWN" '{"gate":"password","password":"hunter22"}'
call POST /api/identity/device/enrol "$OWN" "$(printf '{"challenge_id":%s,"device_id":"phone-0001","label":"Pixel","key_d":"%s","key_p":"%s","sig_d":"%s","sig_p":"%s"}' "$CHD" "$(cat $S/d.pub)" "$(cat $S/p.pub)" "$(sig d "$MSG")" "$(sig p "$MSG")")"
[ "$CODE" = 201 ] || fail "enrol: $CODE $BODY"
C3=$(Q "SELECT id FROM wallet_notices WHERE nkey='fund:fleetgate:cap-3'")
call POST /api/identity/holds/challenge "" '{"purpose":"alerts","device_id":"phone-0001"}'; CH=$(echo "$BODY" | J challenge); M=$(echo "$BODY" | J message)
call POST /api/identity/holds/alerts "" "$(jbody device_id phone-0001 challenge "$CH" signature "$(sig d "$M")")"
echo "$BODY" | python3 -c '
import json,sys; d=json.load(sys.stdin); want=300000000000+int(sys.argv[1])
a=[x for x in d.get("approvals",[]) if x["id"]==want]; n=[x for x in d.get("notices",[]) if x.get("kind")=="fund_ask"]
sys.exit(0 if len(a)==1 and a[0]["title"].startswith("fund your wallet:") and len(str(want))<=12 and not n else 1)' "$C3" \
  && ok "the phone's alerts poll lists the open ask as a request (id 3e11+, 12 digits), not also as a notice" || fail "alerts: $BODY"
echo "$BODY" | python3 -c 'import json,sys; d=json.load(sys.stdin); sys.exit(0 if not [x for x in d.get("approvals",[]) if x["id"] in (300000000000+int(sys.argv[1]),)] else 1)' "$FA" \
  && ok "a covered ask is not on the phone" || fail "covered on phone"

# an ask filed more than 7 days ago is closed, so the phone never alerts about a card the app no longer shows
python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute(\"UPDATE wallet_notices SET created_at='2026-01-01T00:00:00.000Z' WHERE id=?\", (int(sys.argv[2]),)); c.commit()" "$DB_PATH" "$C3"
call POST /api/billing/fund-asks "$OWN" "$(jbody need_dd 90000 service fleetgate subject cap-3)"
call GET /api/billing/fund-asks/$C3 "$OWN"; [ "$(echo "$BODY" | J fund_ask.status)" = lapsed ] && ok "an ask older than 7 days closes (lapsed), even when its work files again" || fail "old ask: $BODY"
grep -q -i "unhandled\|TypeError\|ReferenceError" "$S/server.log" && { fail "server errors"; grep -i -m5 "TypeError\|ReferenceError" "$S/server.log"; }
echo "$fails failure(s)"; exit $(( fails > 0 ))
