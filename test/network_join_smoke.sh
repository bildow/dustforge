#!/bin/bash
# Who answers for a wallet (service_tenants.js personFor; Aaron 2026-11-19): an agent wallet that joins a person's fleet
# by request (network_routes.js `join`, kept its own key) is theirs to answer for — its consents land on their phone.
# Before: such a wallet had nobody and every consent was refused. Also: the pending reply names whose app approves,
# a join request reaches the owner's phone alert list, and the accept card says what the owner takes on.
set -u
W=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
S=$(mktemp -d /tmp/dustforge-network-join-smoke.XXXXXX)
PORT=${PORT:-3839}; API=http://127.0.0.1:$PORT
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
jbody(){ python3 -c 'import json,sys; print(json.dumps(dict(zip(sys.argv[1::2], [json.loads(x) if x[:1] in "[{" or x in ("true","false") or (x.lstrip("-").isdigit() and not (len(x) > 1 and x.startswith("0"))) else x for x in sys.argv[2::2]]))))' "$@"; }
call(){ local m=$1 p=$2 t=$3 b=${4:-}
  BODY=$(curl -s -o - -w '\n%{http_code}' -X "$m" "$API$p" -H 'Content-Type: application/json' ${t:+-H "Authorization: Bearer $t"} ${b:+-d "$b"})
  CODE=${BODY##*$'\n'}; BODY=${BODY%$'\n'*}; }
start(){ node server.js >>"$S/server.log" 2>&1 & SRV=$!; for i in $(seq 1 40); do curl -s -o /dev/null "$API/api/health" && break; sleep 0.5; done; }
start; kill $SRV; wait $SRV 2>/dev/null
H=$(printf '%s' hunter22 | sha256sum | cut -d' ' -f1)
# Seed (a legacy DB: these rows predate this change). aaron owns fleet aaron-agents with: fg (created by the fleet, the
# service's wallet), made (created by the fleet), oldnet (joined through the network: created_by_fleet 0, no creator
# row — before this change nobody answered for it). kyle is a person with no fleet. felix is a self-made wallet
# (organic signup) in no fleet — Kyle's Felix.
node -e '
const identity = require("./identity"); const Database = require("better-sqlite3"); const db = new Database(process.env.DB_PATH);
const mk = (u, bal) => { const id = identity.createIdentity(); const enc = id.encrypted_private_key || id.encryptedPrivateKey;
  db.prepare("INSERT INTO identity_wallets (did, username, email, encrypted_private_key, balance_cents, password_hash) VALUES (?, ?, ?, ?, ?, ?)").run(id.did, u, u + "@smoke.invalid", enc, bal, process.argv[1]);
  db.prepare("INSERT INTO identity_transactions (did, amount_cents, type, description, balance_after) VALUES (?, ?, ?, ?, ?)").run(id.did, bal, "topup", "smoke", bal); return id.did; };
const aaron = mk("aaron", 10000); mk("kyle", 10000); mk("felix", 500);
const f1 = db.prepare("INSERT INTO fleets (owner_did, name, slug) VALUES (?, ?, ?)").run(aaron, "Aaron agents", "aaron-agents").lastInsertRowid;
let n = 0;
for (const [u, made, via] of [["fg", 1, "owner"], ["made", 1, "owner"], ["oldnet", 0, "network"]]) { const did = mk(u, 500);
  db.prepare("INSERT INTO fleet_silicons (fleet_id, member_did, handle, silicon_id, status, created_by_fleet, joined_via) VALUES (?, ?, ?, ?, ?, ?, ?)").run(f1, did, u, "sil_smoke" + (n++), "active", made, via); }
db.prepare("DELETE FROM wallet_creators WHERE did = (SELECT did FROM identity_wallets WHERE username = ?)").run("oldnet");' "$H" || { echo "FAIL seed"; exit 1; }
start; trap 'kill $SRV 2>/dev/null; rm -rf "$S"' EXIT
did(){ Q "SELECT did FROM identity_wallets WHERE username='$1'"; }
login(){ call POST /api/identity/auth-fingerprint "" '{"username":"'$1'","password":"hunter22","scope":"transact","expires_in":"2h"}'; echo "$BODY" | J token; }
mint(){ node -e '
const identity = require("./identity"); const Database = require("better-sqlite3");
const db = new Database(process.env.DB_PATH); const w = db.prepare("SELECT did, encrypted_private_key FROM identity_wallets WHERE username = ?").get(process.argv[1]);
process.stdout.write(identity.createTokenForIdentity(w.encrypted_private_key, w.did, { scope: "transact", expiresIn: "2h", metadata: { auth_method: "fleet_owner_mint", fleet: process.argv[2], username: process.argv[1] } }));' "$1" "$2"; }
AA=$(login aaron); KY=$(login kyle); FX=$(login felix); ON=$(login oldnet); FG=$(mint fg aaron-agents); MD=$(mint made aaron-agents)
for t in "$AA" "$KY"; do call POST /api/identity/pin "$t" '{"pin":"4321","password":"hunter22"}'; [ "$CODE" = 200 ] || fail "pin set: $CODE $BODY"; done
pin(){ call POST /api/identity/gate/verify "$1" "$(jbody gate pin pin "$2" intent "$3")"; [ "$CODE" = 200 ] || fail "pin $3: $CODE $BODY"; }
approve(){ pin "$1" 4321 "approval-open:$2"; call POST /api/demipass/approvals/$2/open "$1"; local k; k=$(echo "$BODY" | J code)
  call POST /api/demipass/approvals/$2/approve "$1" "$(jbody code "$k")"; [ "$CODE" = 200 ] || fail "approve $2: $CODE $BODY"; }
owner_of(){ Q "SELECT w.username FROM use_approvals a JOIN identity_wallets w ON w.did = a.owner_did WHERE a.id = $1"; }
# the service: fg registers conduit, aaron (its creator) approves
call POST /api/services/register "$FG" '{"slug":"conduit","name":"Conduit"}'; R1=$(echo "$BODY" | J approval_id); approve "$AA" "$R1"
call POST /api/services/register "$FG" "$(jbody slug conduit name Conduit approval_id "$R1")"; [ "$CODE" = 201 ] || fail "tenant: $CODE $BODY"

echo "== 1. a self-made wallet in no fleet answers for itself; one in a fleet it joined through the network has that fleet's owner"
call POST /api/services/consent "$FX" '{"service":"conduit","daily_cap_dd":30}'
[ "$CODE" = 202 ] && A0=$(echo "$BODY" | J approval_id) && [ "$(owner_of "$A0")" = felix ] && [ "$(echo "$BODY" | J owner)" = felix ] && [ "$(echo "$BODY" | J approver)" = felix ] && ok "felix (no fleet, no creator) consents for itself: card $A0 is addressed to felix and the reply says so" || fail "felix alone: $CODE $BODY"
echo "$BODY" | J next | grep -q "^Park this call. felix approves it in their DemiPass app (Requests); then" && ok "the pending reply names whose app approves" || fail "next: $(echo "$BODY" | J next)"
call POST /api/services/consent "$ON" '{"service":"conduit","daily_cap_dd":5}'
[ "$CODE" = 202 ] && A1=$(echo "$BODY" | J approval_id) && [ "$(owner_of "$A1")" = aaron ] && [ "$(echo "$BODY" | J owner)" = aaron ] && ok "legacy: oldnet (joined aaron's fleet through the network, no creator row) → its card $A1 goes to aaron (was 403 'no person')" || fail "oldnet: $CODE $BODY"
call POST /api/services/consent "$MD" '{"service":"conduit","daily_cap_dd":5}'
[ "$CODE" = 202 ] && A2=$(echo "$BODY" | J approval_id) && [ "$(owner_of "$A2")" = aaron ] && ok "a silicon the fleet created still answers to its creator (card $A2 → aaron)" || fail "made: $CODE $BODY"

echo "== 2. felix asks to join kyle's fleet by name; the request reaches kyle's phone list and his cards"
call POST /api/network/requests "$FX" '{"to":"kyle","as":"join","handle":"felix"}'
[ "$CODE" = 201 ] || [ "$CODE" = 200 ] && RID=$(echo "$BODY" | J request.id) && [ -n "$RID" ] && [ "$RID" != None ] && ok "join request $RID filed by username" || { fail "join: $CODE $BODY"; RID=$(Q "SELECT id FROM network_requests ORDER BY id DESC LIMIT 1"); }
call POST /api/network/requests "$FX" '{"to":"kyle@smoke.invalid","as":"join"}'; [ "$CODE" = 409 ] && echo "$BODY" | grep -q "already asked" && ok "asking again by email: 409, the first request waits" || fail "re-ask: $CODE $BODY"
call GET /api/network "$KY"; [ "$(echo "$BODY" | J incoming.0.id)" = "$RID" ] && [ "$(echo "$BODY" | J incoming.0.from)" = felix ] && ok "kyle's network lists the incoming request from felix" || fail "incoming: $BODY"
echo "$BODY" | J incoming.0.effect | grep -q "You answer for it: its consents to pay services (and its registrations) come to your Requests, approved with your PIN; what it spends comes from its own wallet" && ok "the accept card says what kyle takes on" || fail "effect: $(echo "$BODY" | J incoming.0.effect)"
call GET /api/network "$FX"; echo "$BODY" | J outgoing.0.effect | grep -q "kyle answers for this wallet: its consents to pay services land in their Requests" && ok "felix's side of the card names who will answer for it" || fail "felix effect: $(echo "$BODY" | J outgoing.0.effect)"
AL=$(node -e '
const Database = require("better-sqlite3"); const db = new Database(process.env.DB_PATH);
const noop = () => {}; const app = { get: noop, post: noop, use: noop, put: noop, delete: noop };
const m = require("./network_routes")({ app, db, billing: require("./billing"), fleetBilling: require("./fleet_billing"), rateLimitStandard: noop, getBearerIdentity: noop,
  gateSession: noop, gateFresh: noop, gateMissing: noop, spendSingleUse: noop, barrelGuardedTransfer: noop, transferRefusal: noop, sendMail: noop, log: noop });
const kyle = db.prepare("SELECT did FROM identity_wallets WHERE username = ?").get("kyle").did;
console.log(JSON.stringify(m.alertsFor(kyle)));' 2>&1)
echo "$AL" | python3 -c 'import json,sys; a=json.load(sys.stdin); r=a[0]; assert r["kind"]=="network" and r["id"]==400000000000+int(sys.argv[1]) and r["title"]=="agent felix asks to join your fleet" and r["requester"]=="felix" and "You answer for it" in r["summary"], a' "$RID" && ok "the phone alert list carries the join request (id 4e11+$RID, kind network, headline + effect)" || fail "alerts: $AL"

echo "== 3. kyle accepts; from then on he answers for felix"
call POST /api/network/requests/$RID/accept "$KY"; [ "$CODE" = 200 ] && [ "$(echo "$BODY" | J member)" = felix ] && ok "kyle accepted: felix is an agent of fleet $(echo "$BODY" | J fleet)" || fail "accept: $CODE $BODY"
call GET /api/network "$FX"; [ "$(echo "$BODY" | J member_of.owner)" = kyle ] && ok "felix sees itself as a member of kyle's fleet (keeps its own key)" || fail "member_of: $BODY"
call POST /api/services/consent "$FX" '{"service":"conduit","daily_cap_dd":30}'
[ "$CODE" = 202 ] && A3=$(echo "$BODY" | J approval_id) && [ "$(owner_of "$A3")" = kyle ] && [ "$(echo "$BODY" | J approver)" = kyle ] && ok "felix's consent card $A3 is addressed to kyle; the reply says 'kyle approves it'" || fail "felix→kyle: $CODE $BODY"
[ "$(Q "SELECT status FROM use_approvals WHERE id = $A0")" = pending ] && ok "the earlier self-addressed card $A0 is untouched (it expires on its own)" || fail "A0 status: $(Q "SELECT status FROM use_approvals WHERE id = $A0")"
approve "$KY" "$A3"
call POST /api/services/consent "$FX" "$(jbody service conduit daily_cap_dd 30 approval_id "$A3")"; [ "$CODE" = 201 ] && CID=$(echo "$BODY" | J consent_id) && ok "kyle approved → consent $CID (approved_by kyle)" || fail "consent: $CODE $BODY"
[ "$(Q "SELECT w.username FROM service_consents c JOIN identity_wallets w ON w.did = c.approved_by WHERE c.id = $CID")" = kyle ] || fail "approved_by is not kyle"
call POST /api/services/token "$FX" '{"service":"conduit","ttl":"1h"}'; [ "$CODE" = 201 ] && ok "felix mints its Conduit token (the consent is live under kyle)" || fail "token: $CODE $BODY"
call POST /api/services/consent "$FX" "$(jbody service conduit daily_cap_dd 30 approval_id "$A0")"; [ "$CODE" = 409 ] || [ "$CODE" = 403 ] && ok "the self-addressed card $A0 cannot be redeemed now that kyle answers ($CODE)" || fail "stale card: $CODE $BODY"

echo "== 4. felix leaves the fleet: kyle no longer answers, the consent he approved is dead, felix is its own person again"
call POST /api/network/leave-fleet "$FX"; [ "$CODE" = 200 ] && [ "$(echo "$BODY" | J signed_out)" = False ] && ok "left (kept its key: not signed out)" || fail "leave: $CODE $BODY"
call POST /api/services/token "$FX" '{"service":"conduit","ttl":"1h"}'; [ "$CODE" = 403 ] && [ "$(echo "$BODY" | J consent_required)" = True ] && ok "no live consent after leaving (approved under kyle)" || fail "token after leave: $CODE $BODY"
call POST /api/services/consent "$FX" '{"service":"conduit","daily_cap_dd":30}'
[ "$CODE" = 202 ] && A4=$(echo "$BODY" | J approval_id) && [ "$(owner_of "$A4")" = felix ] && ok "a new consent is felix's own again (card $A4 → felix)" || fail "after leave: $CODE $BODY"

echo "== 5. the refusal with nobody to answer says what to do"
node -e '
const Database = require("better-sqlite3"); const db = new Database(process.env.DB_PATH);
db.prepare("UPDATE fleets SET status = ? WHERE slug = ?").run("closed", "aaron-agents");'
call POST /api/services/consent "$ON" '{"service":"conduit","daily_cap_dd":5}'
[ "$CODE" = 403 ] && echo "$BODY" | J fix | grep -q "demipass_fleet_join" && ok "a network-joined agent of a closed fleet: 403 with the fix (ask to join a person's fleet)" || fail "closed fleet: $CODE $BODY"
echo "== done: $fails failure(s)"; exit $(( fails > 0 ))
