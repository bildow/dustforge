#!/bin/bash
# Red team items 15 and 16 (found by the #47 review, 2026-11-05): a token alone handed a secret to any outside agent
# (POST /api/blindkey/delegate), and moved DD to any wallet (POST /api/wallet/transfer). server.js on a throwaway DB.
set -u
W=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
S=$(mktemp -d /tmp/dustforge-rt1516.XXXXXX)
PORT=${PORT:-3801}; API=http://127.0.0.1:$PORT
[ -d "$W/node_modules" ] || export NODE_PATH=${NODE_PATH:-/home/flimflam/project/dustforge/node_modules}
export IDENTITY_MASTER_KEY=$(python3 -c 'import secrets;print(secrets.token_hex(32))') DB_PATH=$S/dustforge.db PORT \
  STALWART_HOST=127.0.0.1 STALWART_PORT=1 SMTP_RELAY_HOST= SMTP_HOST=127.0.0.1 SMTP_PORT=9
cd "$W"
node server.js >"$S/server.log" 2>&1 & SRV=$!
trap 'kill $SRV 2>/dev/null; rm -rf "$S"' EXIT
for i in $(seq 1 40); do curl -s -o /dev/null "$API/" && break; sleep 0.5; done
kill -0 $SRV 2>/dev/null || { echo "server died:"; tail -5 "$S/server.log"; exit 1; }
H=$(printf '%s' hunter22 | sha256sum | cut -d' ' -f1)
node -e '
const identity = require("./identity"); const Database = require("better-sqlite3"); const db = new Database(process.env.DB_PATH);
for (const c of ["idempotency_key TEXT", "provenance TEXT DEFAULT '"'"'organic'"'"'"]) { try { db.exec("ALTER TABLE identity_transactions ADD COLUMN " + c); } catch (_) {} }
for (const u of ["owner-a", "agent-f", "owner-b", "agent-g"]) { const id = identity.createIdentity(); const enc = id.encrypted_private_key || id.encryptedPrivateKey;
  db.prepare("INSERT INTO identity_wallets (did, username, email, encrypted_private_key, balance_cents, password_hash) VALUES (?, ?, ?, ?, 100000, ?)").run(id.did, u, u + "@dustforge.com", enc, process.argv[1]);
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
A=$(login owner-a); AG=$(login owner-a); F=$(login agent-f); B=$(login owner-b); G=$(login agent-g)
call POST /api/identity/pin "$A" '{"pin":"4321","password":"hunter22"}'
did(){ Q "SELECT did FROM identity_wallets WHERE username='$1'"; }
# agent-f joins A's fleet, agent-g joins B's (each accepts: consented fleet_silicons)
call POST /api/network/requests "$A" '{"to":"agent-f","as":"agent"}'; R=$(echo "$BODY" | J request.id); call POST /api/network/requests/$R/accept "$F"
call POST /api/network/requests "$B" '{"to":"agent-g","as":"agent"}'; R=$(echo "$BODY" | J request.id); call POST /api/network/requests/$R/accept "$G"
call POST /api/demipass/store "$A" '{"name":"svc","value":"svc-token-zz95","secret_type":"api_key","host":"repo.dustroot.com"}'
SID=$(Q "SELECT id FROM blindkey_secrets WHERE name='svc'")
DG=$(did agent-g); DF=$(did agent-f)

# ── item 15 ──
call POST /api/demipass/delegate "$AG" '{"secret_name":"svc","delegate_did":"'$DG'"}'
[ "$CODE" = 403 ] && [ "$(echo "$BODY" | J intent)" = "scope:$SID" ] && [ "$(Q "SELECT COUNT(*) FROM demipass_delegations WHERE delegate_did='$DG'")" = 0 ] \
  && ok "15: delegating to ANOTHER owner's agent with a token alone → 403, PIN asked, nothing granted" || fail "outside agent: $CODE $BODY"
call POST /api/identity/gate/verify "$A" '{"gate":"pin","pin":"4321","intent":"scope:'$SID'"}'
call POST /api/demipass/delegate "$A" '{"secret_name":"svc","delegate_did":"'$DG'"}'
[ "$CODE" = 200 ] && ok "15: …the owner, with the PIN, can" || fail "outside agent with pin: $CODE $BODY"
# agent-f joined through the network: a wallet a token alone can invite in — outside (#48 review: laundering)
call POST /api/demipass/delegate "$AG" '{"secret_name":"svc","delegate_did":"'$DF'"}'
[ "$CODE" = 403 ] && ok "15: a network-joined agent of the owner's fleet is outside: token alone → 403 (PIN)" || fail "laundered agent: $CODE $BODY"
SLUG=$(Q "SELECT slug FROM fleets WHERE owner_did='$(did owner-a)'")
call POST /api/fleet/$SLUG/silicons/agent-f/delegate "$AG" '{"secret_name":"svc"}'; [ "$CODE" = 403 ] && ok "15: …nor through the fleet delegate route" || fail "fleet delegate laundered: $CODE $BODY"
call POST /api/fleet/$SLUG/silicons/agent-f/refill "$AG" '{"amount_cents":500}'; [ "$CODE" = 403 ] && ok "16: …and no refill to it on a token alone" || fail "refill laundered: $CODE $BODY"
call PATCH /api/fleet/$SLUG/silicons/agent-f "$AG" '{"refill_enabled":true,"refill_amount_cents":500,"refill_threshold_cents":100}'; [ "$CODE" = 403 ] && ok "16: …nor automatic refills switched on for it" || fail "auto refill laundered: $CODE $BODY"
# an agent the fleet itself made (it holds that wallet's key) stays the owner's own
python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute(\"UPDATE fleet_silicons SET joined_via='owner' WHERE member_did=?\", (sys.argv[2],)); c.commit()" "$DB_PATH" "$DF"
call POST /api/demipass/delegate "$AG" '{"secret_name":"svc","delegate_did":"'$DF'"}'
[ "$CODE" = 200 ] && ok "15: delegating to an agent the owner's fleet made still works from the owner's session" || fail "own agent: $CODE $BODY"
python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute(\"UPDATE fleet_silicons SET status='left' WHERE member_did=?\", (sys.argv[2],)); c.commit()" "$DB_PATH" "$DF" 2>/dev/null
call POST /api/demipass/store "$A" '{"name":"svc2","value":"svc2-token-zz96","secret_type":"api_key","host":"repo.dustroot.com"}'
call POST /api/demipass/delegate "$AG" '{"secret_name":"svc2","delegate_did":"'$DF'"}'
[ "$CODE" = 403 ] && ok "15: an agent that left the owner's fleet is an outside agent again (PIN)" || fail "left agent: $CODE $BODY"

# ── item 16 ──
B0=$(Q "SELECT balance_cents FROM identity_wallets WHERE username='owner-a'")
call POST /api/wallet/transfer "$AG" '{"from_did":"'$(did owner-a)'","to_did":"'$(did owner-b)'","amount_cents":5000}'
[ "$CODE" = 410 ] && [ "$(Q "SELECT balance_cents FROM identity_wallets WHERE username='owner-a'")" = "$B0" ] && ok "16: /api/wallet/transfer is retired (410), no DD moved" || fail "wallet transfer: $CODE $BODY"
call POST /api/wallet/transfer/secure "$AG" '{"from_did":"'$(did owner-a)'","to_did":"'$(did owner-b)'","amount_cents":5000}'
[ "$CODE" = 410 ] && [ "$(Q "SELECT balance_cents FROM identity_wallets WHERE username='owner-a'")" = "$B0" ] && ok "16: /api/wallet/transfer/secure is retired too" || fail "transfer secure: $CODE $BODY"

! grep -qE "svc-token-zz95|svc2-token-zz96" "$S/server.log" && ok "no value in the server log" || fail "value in log"
echo; [ $fails = 0 ] && echo "ALL OK" || echo "$fails FAILED"; exit $fails
