#!/bin/bash
# A one-off operator grant to the fleet owner's own wallet is a REQUEST the owner approves in the app (Aaron 2026-11-08):
# not permitted outside OPERATOR_GRANT_DIDS; files 202 (critical, named); collects once after approval; idempotent;
# capped; only the owner's own tokens.
set -u
W=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
S=$(mktemp -d /tmp/dustforge-ogrant-smoke.XXXXXX)
PORT=${PORT:-3822}; API=http://127.0.0.1:$PORT
[ -d "$W/node_modules" ] || export NODE_PATH=${NODE_PATH:-/home/flimflam/project/dustforge/node_modules}
export IDENTITY_MASTER_KEY=$(python3 -c 'import secrets;print(secrets.token_hex(32))') DB_PATH=$S/dustforge.db PORT \
  STALWART_HOST=127.0.0.1 STALWART_PORT=1 SMTP_RELAY_HOST= SMTP_HOST=127.0.0.1 SMTP_PORT=9
cd "$W"
fails=0; ok(){ echo "ok   $*"; }; fail(){ echo "FAIL $*"; fails=$((fails+1)); }
J(){ python3 -c 'import json,sys; d=json.load(sys.stdin); v=d
for k in sys.argv[1].split("."):
    v = v[int(k)] if isinstance(v, list) else (v or {}).get(k)
print(v)' "$1"; }
Q(){ python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); r=c.execute(sys.argv[2]).fetchone(); print(r[0] if r else '')" "$DB_PATH" "$1"; }
call(){ local m=$1 p=$2 t=$3 b=${4:-}
  BODY=$(curl -s -o - -w '\n%{http_code}' -X "$m" "$API$p" -H 'Content-Type: application/json' ${t:+-H "Authorization: Bearer $t"} ${b:+-d "$b"})
  CODE=${BODY##*$'\n'}; BODY=${BODY%$'\n'*}; }
start(){ node server.js >>"$S/server.log" 2>&1 & SRV=$!; for i in $(seq 1 40); do curl -s -o /dev/null "$API/api/health" && break; sleep 0.5; done; }
start; trap 'kill $SRV 2>/dev/null; rm -rf "$S"' EXIT
H=$(printf '%s' hunter22 | sha256sum | cut -d' ' -f1)
node -e '
const identity = require("./identity"); const Database = require("better-sqlite3"); const db = new Database(process.env.DB_PATH);
const mk = (u, bal) => { const id = identity.createIdentity(); db.prepare("INSERT INTO identity_wallets (did, username, email, encrypted_private_key, balance_cents, password_hash) VALUES (?, ?, ?, ?, ?, ?)").run(id.did, u, u+"@dustforge.com", id.encrypted_private_key || id.encryptedPrivateKey, bal, process.argv[1]);
  db.prepare("INSERT INTO identity_transactions (did, amount_cents, type, description, balance_after) VALUES (?, ?, ?, ?, ?)").run(id.did, bal, "topup", "smoke", bal); return id.did; };
const o = mk("owner", 100); const m = mk("member", 100);
const f = db.prepare("INSERT INTO fleets (owner_did, name, slug) VALUES (?, ?, ?)").run(o, "Owner", "owner-agents").lastInsertRowid;
db.prepare("INSERT INTO fleet_members (fleet_id, member_did, role) VALUES (?, ?, ?)").run(f, m, "admin");' "$H"
did(){ Q "SELECT did FROM identity_wallets WHERE username='$1'"; }
bal(){ Q "SELECT balance_cents FROM identity_wallets WHERE username='$1'"; }
login(){ call POST /api/identity/auth-fingerprint "" '{"username":"'$1'","password":"hunter22","scope":"transact","expires_in":"1h"}'; echo "$BODY" | J token; }
OWN=$(login owner); MEM=$(login member)
call POST /api/identity/pin "$OWN" '{"pin":"4321","password":"hunter22"}'
call POST /api/fleet/owner-agents/owner-grant "$OWN" '{"amount_cents":30000}'; [ "$CODE" = 403 ] && ok "not in OPERATOR_GRANT_DIDS → 403" || fail "not permitted: $CODE $BODY"
kill $SRV; wait $SRV 2>/dev/null; export OPERATOR_GRANT_DIDS="$(did owner)"; start; OWN=$(login owner); MEM=$(login member)
call POST /api/fleet/owner-agents/owner-grant "$MEM" '{"amount_cents":30000}'; [ "$CODE" = 403 ] && ok "a fleet admin who is not the owner cannot ask" || fail "member: $CODE $BODY"
call POST /api/fleet/owner-agents/owner-grant "$OWN" '{"amount_cents":100001}'; [ "$CODE" = 400 ] && ok "above the per-grant cap → 400" || fail "cap: $CODE"
B0=$(bal owner)
call POST /api/fleet/owner-agents/owner-grant "$OWN" '{"amount_cents":30000}'; AP=$(echo "$BODY" | J approval_id)
[ "$CODE" = 202 ] && [ "$(Q "SELECT depth FROM use_approvals WHERE id=$AP")" = critical ] && [ "$(Q "SELECT summary FROM use_approvals WHERE id=$AP")" = "operator grant of 30000 DD to your own wallet" ] && [ "$(bal owner)" = "$B0" ] \
  && ok "the grant is a request on the owner's phone: 202, critical, named; nothing credited yet" || fail "request: $CODE $BODY"
call POST /api/fleet/owner-agents/owner-grant "$OWN" '{"amount_cents":30000,"approval_id":'$AP'}'; [ "$CODE" = 202 ] && ok "collecting before approval: still pending" || fail "early: $CODE"
call POST /api/identity/gate/verify "$OWN" '{"gate":"pin","pin":"4321","intent":"approval-open:'$AP'"}'; call POST /api/demipass/approvals/$AP/open "$OWN"; K=$(echo "$BODY" | J code)
call POST /api/demipass/approvals/$AP/approve "$OWN" '{"code":"'$K'"}'; [ "$CODE" = 200 ] || fail "approve: $CODE $BODY"
call POST /api/fleet/owner-agents/owner-grant "$OWN" '{"amount_cents":20000,"approval_id":'$AP'}'; [ "$CODE" = 409 ] && ok "the approval binds the amount (20000 instead of 30000 → 409)" || fail "binding: $CODE"
call POST /api/fleet/owner-agents/owner-grant "$OWN" '{"amount_cents":30000,"approval_id":'$AP'}'
[ "$CODE" = 200 ] && [ "$(bal owner)" = $((B0 + 30000)) ] && [ "$(Q "SELECT COUNT(*) FROM identity_transactions WHERE type='operator_grant' AND amount_cents=30000")" = 1 ] && ok "approved: 30000 DD credited to the owner's wallet, one ledger row" || fail "collect: $CODE $BODY bal $(bal owner)"
call POST /api/fleet/owner-agents/owner-grant "$OWN" '{"amount_cents":30000,"approval_id":'$AP'}'; [ "$CODE" = 410 ] && [ "$(bal owner)" = $((B0 + 30000)) ] && ok "once only (again → 410, no second credit)" || fail "replay: $CODE bal $(bal owner)"
# ── the scheduled grant: arming or raising it is a request too (#82 review); off or lower is one tap ──────────────────
ap_and_save(){ local id=$1 body=$2
  call POST /api/identity/gate/verify "$OWN" '{"gate":"pin","pin":"4321","intent":"approval-open:'$id'"}'; call POST /api/demipass/approvals/$id/open "$OWN"; local k; k=$(echo "$BODY" | J code)
  call POST /api/demipass/approvals/$id/approve "$OWN" '{"code":"'$k'"}'; call PUT /api/fleet/owner-agents/owner-refill "$OWN" "$(python3 -c 'import json,sys; b=json.loads(sys.argv[1]); b["approval_id"]=int(sys.argv[2]); print(json.dumps(b))' "$body" "$id")"; }
ARM='{"cadence":"weekly","amount_cents":10000,"enabled":true,"funding":"operator_grant"}'
call PUT /api/fleet/owner-agents/owner-refill "$OWN" "$ARM"; R1=$(echo "$BODY" | J approval_id)
[ "$CODE" = 202 ] && [ "$(Q "SELECT COALESCE(enabled,0) FROM wallet_refill_rules WHERE did='$(did owner)'")" != 1 ] && [ "$(Q "SELECT summary FROM use_approvals WHERE id=$R1")" = "scheduled refill of 10000 DD weekly to your own wallet" ] \
  && ok "arming the scheduled grant with a token alone files a request; nothing armed" || fail "arm: $CODE $BODY"
ap_and_save "$R1" "$ARM"; [ "$CODE" = 200 ] && [ "$(Q "SELECT enabled || ':' || amount_cents FROM wallet_refill_rules WHERE did='$(did owner)'")" = "1:10000" ] && ok "approved: armed at 10000 weekly" || fail "armed: $CODE $BODY"
call PUT /api/fleet/owner-agents/owner-refill "$OWN" '{"cadence":"weekly","amount_cents":5000,"enabled":true,"funding":"operator_grant"}'; [ "$CODE" = 200 ] && ok "lowering it: one tap, no request" || fail "lower: $CODE $BODY"
call PUT /api/fleet/owner-agents/owner-refill "$OWN" '{"cadence":"daily","amount_cents":5000,"enabled":true,"funding":"operator_grant"}'; [ "$CODE" = 202 ] && ok "weekly → daily is a raise: a request" || fail "cadence raise: $CODE $BODY"
call PUT /api/fleet/owner-agents/owner-refill "$OWN" '{"cadence":"weekly","amount_cents":20000,"enabled":true,"funding":"operator_grant"}'; [ "$CODE" = 202 ] && ok "a higher amount is a request" || fail "amount raise: $CODE $BODY"
call PUT /api/fleet/owner-agents/owner-refill "$OWN" '{"cadence":"weekly","amount_cents":10000000,"enabled":true,"funding":"operator_grant"}'; [ "$CODE" = 400 ] && ok "above 100,000 DD a run → 400 (was 10,000,000)" || fail "cap: $CODE"
call PUT /api/fleet/owner-agents/owner-refill "$OWN" '{"cadence":"weekly","amount_cents":5000,"enabled":false,"funding":"operator_grant"}'; [ "$CODE" = 200 ] && [ "$(Q "SELECT enabled FROM wallet_refill_rules WHERE did='$(did owner)'")" = 0 ] && ok "turning it off: one tap" || fail "off: $CODE $BODY"
echo "$fails failure(s)"; exit $(( fails > 0 ))
