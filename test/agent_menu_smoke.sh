#!/bin/bash
# End-to-end smoke of the agent menu and access requests (test/agent_menu_smoke.sh): boots server.js on a
# throwaway DB + random master key with an owner (O), an agent (A) in O's fleet, an outsider (X) and a second
# owner (P). Covers: GET /menu (own, shared, can_ask, calls), the compact menu on every DemiPass error (signed in
# and signed out), access requests (fleet members only, duplicate → same id, per-pair cap, silicon refused),
# the owner's card in /fill/pending, approval only with a PIN proof for access:<id> and only by the owner, deny,
# then using the shared secret by NAME (no owner_did, no context) through request-token and one-call /use, and
# the 409 with refs when two owners share the same name. No network, nothing persists.
set -u
W=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
S=$(mktemp -d /tmp/dustforge-menu-smoke.XXXXXX)
PORT=${PORT:-3779}; API=http://127.0.0.1:$PORT
[ -d "$W/node_modules" ] || export NODE_PATH=${NODE_PATH:-/home/flimflam/project/dustforge/node_modules}
export IDENTITY_MASTER_KEY=$(python3 -c 'import secrets;print(secrets.token_hex(32))') DB_PATH=$S/dustforge.db PORT STALWART_HOST=127.0.0.1 STALWART_PORT=1 SMTP_RELAY_HOST=
cd "$W"
node server.js >"$S/server.log" 2>&1 & SRV=$!
trap 'kill $SRV 2>/dev/null; rm -rf "$S"' EXIT
for i in $(seq 1 40); do curl -s -o /dev/null "$API/" && break; sleep 0.5; done
kill -0 $SRV 2>/dev/null || { echo "server died:"; tail -5 "$S/server.log"; exit 1; }
SIL='silicon:menu-smoke-token-0123456789'
node -e '
const identity = require("./identity"); const Database = require("better-sqlite3"); const crypto = require("crypto");
const db = new Database(process.env.DB_PATH);
try { db.exec("ALTER TABLE identity_wallets ADD COLUMN password_hash TEXT"); } catch (_) {}
const h = crypto.createHash("sha256").update("hunter22").digest("hex"); const dids = {};
for (const u of ["owner", "agent", "outsider", "other"]) {
  const id = identity.createIdentity(); dids[u] = id.did;
  db.prepare("INSERT INTO identity_wallets (did, username, email, encrypted_private_key, balance_cents, password_hash) VALUES (?, ?, ?, ?, 100000, ?)")
    .run(id.did, u, u + "@dustforge.com", id.encrypted_private_key || id.encryptedPrivateKey, h);
  db.prepare("INSERT INTO identity_transactions (did, amount_cents, type, description, balance_after) VALUES (?, 100000, ?, ?, 100000)").run(id.did, "test_grant", "smoke");
}
const f = db.prepare("INSERT INTO fleets (owner_did, name, slug) VALUES (?, ?, ?)").run(dids.owner, "Owner agents", "owner-agents").lastInsertRowid;
db.prepare("INSERT INTO fleet_silicons (fleet_id, member_did, handle, silicon_id) VALUES (?, ?, ?, ?)").run(f, dids.agent, "agent", "sil_menu_smoke_1");
db.prepare("INSERT INTO silicon_agents (agent_name, did, carbon_did, token_hash) VALUES (?, ?, ?, ?)")
  .run("owner-bot", "did:silicon:menu-smoke", dids.owner, crypto.createHash("sha256").update(process.argv[1]).digest("hex"));
' "$SIL"
fails=0; ok(){ echo "ok   $*"; }; fail(){ echo "FAIL $*"; fails=$((fails+1)); }
J(){ python3 -c 'import json,sys; d=json.load(sys.stdin); v=d
for k in sys.argv[1].split("."):
    v = v[int(k)] if isinstance(v, list) else (v or {}).get(k)
print(v)' "$1"; }
call(){ # method path token body → sets CODE and BODY
  local m=$1 p=$2 t=$3 b=${4:-}
  BODY=$(curl -s -o - -w '\n%{http_code}' -X "$m" "$API$p" -H 'Content-Type: application/json' ${t:+-H "Authorization: Bearer $t"} ${b:+-d "$b"})
  CODE=${BODY##*$'\n'}; BODY=${BODY%$'\n'*}
}
login(){ call POST /api/identity/auth-fingerprint "" '{"username":"'$1'","password":"hunter22","scope":"transact","expires_in":"1h"}'; echo "$BODY" | J token; }
O=$(login owner); O2=$(login owner); A=$(login agent); X=$(login outsider); P=$(login other)
[ -n "$O" ] && [ "$O" != None ] && [ "$A" != None ] && [ "$X" != None ] && [ "$P" != None ] && ok "four wallets signed in" || { fail "login"; exit 1; }
call POST /api/identity/pin "$O" '{"pin":"4321","password":"hunter22"}'; [ "$CODE" = 200 ] && ok "owner PIN set" || fail "pin: $CODE $BODY"

call POST /api/demipass/store "$O" '{"name":"svc-token","value":"value-owner-1","secret_type":"api_key"}'
REF=$(echo "$BODY" | J ref); [ "$CODE" = 200 ] && ok "owner stores svc-token ($REF)" || fail "store: $CODE $BODY"
call POST /api/demipass/store "$O" '{"name":"other-token","value":"value-owner-2","secret_type":"api_key"}'

# ── menu ──
call GET /api/demipass/menu "$A"
[ "$CODE" = 200 ] && [ "$(echo "$BODY" | J you.username)" = agent ] && [ "$(echo "$BODY" | J shared_with_you)" = "[]" ] && [ "$(echo "$BODY" | J can_ask.0)" = owner ] && [ -n "$(echo "$BODY" | J calls.use)" ] \
  && ok "agent menu: nothing shared yet, can ask 'owner', lists the calls" || fail "agent menu: $CODE $BODY"
call GET /api/demipass/menu "$O"
[ "$(echo "$BODY" | J your_secrets.1.name)" = svc-token ] && [ "$(echo "$BODY" | J your_secrets.1.actions.0)" = http_header ] && ok "owner menu lists own secrets with their actions" || fail "owner menu: $BODY"
echo "$BODY" | grep -q 'value-owner' && fail "menu leaked a secret value" || ok "menu never carries a secret value"
call GET /api/demipass/menu ""
[ "$CODE" = 401 ] && [ -n "$(echo "$BODY" | J menu.sign_in)" ] && ok "signed out: 401 with how to sign in" || fail "signed-out menu: $CODE $BODY"

# ── the compact menu rides on every DemiPass error ──
call POST /api/demipass/request-token "$A" '{"name":"svc-token"}'
[ "$CODE" = 404 ] && [ "$(echo "$BODY" | J menu.can_ask.0)" = owner ] && [ -n "$(echo "$BODY" | J menu.calls.ask_for_access)" ] && [ "$(echo "$BODY" | J menu.full_menu)" = "GET /api/demipass/menu" ] \
  && ok "a 404 carries the compact menu (who to ask, how)" || fail "error menu: $CODE $BODY"
H=$(curl -s -D - -o /dev/null "$API/api/demipass/menu" -H "Authorization: Bearer $A" | tr -d '\r' | sed -n 's/^X-DemiPass-Menu: //Ip')
[ "$H" = "GET /api/demipass/menu" ] && ok "X-DemiPass-Menu header on DemiPass replies" || fail "header: '$H'"
call POST /api/identity/pin "$A" '{"pin":"12"}'
[ "$CODE" = 400 ] && [ "$(echo "$BODY" | J menu)" = None ] && ok "routes outside DemiPass are untouched" || fail "non-demipass: $BODY"

# ── access requests ──
call POST /api/demipass/access-requests "$X" '{"owner":"owner","secret":"svc-token","reason":"please"}'
[ "$CODE" = 403 ] && [ "$(echo "$BODY" | J you_can_ask)" = "[]" ] && ok "an outsider (not in owner's fleet) cannot ask" || fail "outsider: $CODE $BODY"
call POST /api/demipass/access-requests "$SIL" '{"owner":"owner","secret":"svc-token"}'
[ "$CODE" = 403 ] && ok "a silicon token cannot file access requests" || fail "silicon: $CODE $BODY"
call POST /api/demipass/access-requests "$A" '{"owner":"nobody-here","secret":"svc-token"}'
[ "$CODE" = 403 ] && [ "$(echo "$BODY" | J you_can_ask.0)" = owner ] && ok "unknown owner → 403 listing who it can ask" || fail "unknown owner: $CODE $BODY"
call POST /api/demipass/access-requests "$A" '{"owner":"owner","secret":"svc-token","reason":"Stringline‮ pane control"}'
RQ=$(echo "$BODY" | J request_id)
[ "$CODE" = 201 ] && [ "$(echo "$BODY" | J status)" = pending ] && [ -n "$(echo "$BODY" | J next)" ] && ok "fleet member asks → 201 pending, told what happens next" || fail "ask: $CODE $BODY"
call POST /api/demipass/access-requests "$A" '{"owner":"owner","secret":"svc-token","reason":"again"}'
[ "$CODE" = 200 ] && [ "$(echo "$BODY" | J request_id)" = "$RQ" ] && [ "$(echo "$BODY" | J already_pending)" = True ] && ok "the same request again → the same id" || fail "dup: $CODE $BODY"
for n in 2 3 4 5; do call POST /api/demipass/access-requests "$A" '{"owner":"owner","secret":"cap-'$n'"}'; done
call POST /api/demipass/access-requests "$A" '{"owner":"owner","secret":"cap-6"}'
[ "$CODE" = 429 ] && ok "at most 5 pending requests per agent and owner" || fail "cap: $CODE $BODY"

call GET /api/demipass/fill/pending "$O"
N=$(echo "$BODY" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["access_requests"]))')
CARD=$(echo "$BODY" | python3 -c 'import json,sys; r=[x for x in json.load(sys.stdin)["access_requests"] if x["id"]=='$RQ'][0]; print(r["requester"], r["match"]["ref"], r["intent"], "‮" in r["reason"])')
[ "$N" = 5 ] && [ "$CARD" = "agent $REF access:$RQ False" ] && ok "owner's app sees the cards: requester, matching secret, intent; bidi stripped" || fail "card: $N $CARD"
call GET /api/demipass/access-requests "$A"
[ "$(echo "$BODY" | J incoming)" = "[]" ] && [ "$(echo "$BODY" | J outgoing.0.status)" = pending ] && ok "agent sees its outgoing requests, no incoming" || fail "outgoing: $BODY"

call POST /api/demipass/access-requests/$RQ/approve "$A"
[ "$CODE" = 404 ] && ok "the agent cannot approve its own request" || fail "self-approve: $CODE $BODY"
call POST /api/demipass/access-requests/$RQ/approve "$O"
[ "$CODE" = 403 ] && [ "$(echo "$BODY" | J missing.0)" = pin ] && [ "$(echo "$BODY" | J intent)" = "access:$RQ" ] && ok "approve without PIN → 403 missing [pin], intent access:$RQ" || fail "no pin: $CODE $BODY"
call POST /api/identity/gate/verify "$O" '{"gate":"pin","pin":"4321","intent":"fill:'$RQ'"}'
call POST /api/demipass/access-requests/$RQ/approve "$O"
[ "$CODE" = 403 ] && ok "a PIN proof for another intent does not approve" || fail "wrong intent: $CODE $BODY"
call POST /api/identity/gate/verify "$O" '{"gate":"pin","pin":"4321","intent":"access:'$RQ'"}'
[ "$CODE" = 200 ] && ok "PIN verified for access:$RQ" || fail "verify: $CODE $BODY"
call POST /api/demipass/access-requests/$RQ/approve "$O2"
[ "$CODE" = 403 ] && ok "the proof opens only the session that typed the PIN" || fail "other session: $CODE $BODY"
call POST /api/demipass/access-requests/$RQ/approve "$O"
[ "$CODE" = 200 ] && [ "$(echo "$BODY" | J ref)" = "$REF" ] && ok "owner approves with the PIN → delegation $(echo "$BODY" | J delegation_id)" || fail "approve: $CODE $BODY"
call POST /api/demipass/access-requests/$RQ/approve "$O"
[ "$CODE" = 409 ] && ok "a decided request cannot be approved twice" || fail "twice: $CODE $BODY"
DQ=$(curl -s "$API/api/demipass/access-requests" -H "Authorization: Bearer $O" | python3 -c 'import json,sys; print([x["id"] for x in json.load(sys.stdin)["incoming"]][0])')
call POST /api/demipass/access-requests/$DQ/deny "$O"
[ "$CODE" = 200 ] && [ "$(echo "$BODY" | J status)" = denied ] && ok "owner denies another request" || fail "deny: $CODE $BODY"

# ── using the shared secret by name ──
call GET /api/demipass/menu "$A"
[ "$(echo "$BODY" | J shared_with_you.0.name)" = svc-token ] && [ "$(echo "$BODY" | J shared_with_you.0.owner)" = owner ] && [ "$(echo "$BODY" | J shared_with_you.0.ref)" = "$REF" ] \
  && ok "the agent's menu now lists svc-token, shared by owner, with its ref" || fail "menu after approve: $BODY"
call POST /api/demipass/request-token "$A" '{"name":"svc-token"}'
[ "$CODE" = 200 ] && [ "$(echo "$BODY" | J delegated)" = True ] && [ "$(echo "$BODY" | J context)" = default ] && [ "$(echo "$BODY" | J action)" = http_header ] \
  && ok "request-token by NAME alone: owner, context and action filled in" || fail "by name: $CODE $BODY"
call POST /api/demipass/use "$A" '{"name":"svc-token","params":{"url":"http://127.0.0.1:9/x"}}'
[ "$CODE" = 403 ] && echo "$BODY" | grep -q 'not in whitelist' && [ "$(echo "$BODY" | J menu.shared_with_you.0.name)" = svc-token ] \
  && ok "one-call /use by name reaches the use step (host check) and the error carries the menu" || fail "one-call: $CODE $BODY"
TOKS=$(python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); print(c.execute(\"SELECT COUNT(*) FROM blindkey_use_tokens u JOIN identity_wallets w ON w.did=u.did WHERE w.username='agent' AND u.delegation_id IS NOT NULL\").fetchone()[0])" "$DB_PATH")
[ "$TOKS" -ge 2 ] && ok "both went through use-tokens bound to the delegation" || fail "use tokens: $TOKS"
call POST /api/demipass/use "$A" '{"ref":"'$REF'","params":{"url":"http://127.0.0.1:9/x"}}'
[ "$CODE" = 403 ] && echo "$BODY" | grep -q 'not in whitelist' && ok "one-call /use by ref works the same" || fail "one-call ref: $CODE $BODY"
call POST /api/demipass/use "$A" '{"name":"other-token","params":{"url":"http://127.0.0.1:9/x"}}'
[ "$CODE" = 404 ] && ok "a secret that was not shared stays out of reach" || fail "not shared: $CODE $BODY"
grep -h 'value-owner' "$S/server.log" >/dev/null && fail "server log holds a secret value" || ok "no secret value in the server log"

# ── two owners share the same name → 409 with refs ──
call POST /api/demipass/store "$P" '{"name":"svc-token","value":"value-other-1","secret_type":"api_key"}'
PREF=$(echo "$BODY" | J ref)
AD=$(python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); print(c.execute(\"SELECT did FROM identity_wallets WHERE username='agent'\").fetchone()[0])" "$DB_PATH")
call POST /api/demipass/delegate "$P" '{"secret_name":"svc-token","delegate_did":"'$AD'"}'
call POST /api/demipass/request-token "$A" '{"name":"svc-token"}'
[ "$CODE" = 409 ] && echo "$BODY" | grep -q "$REF" && echo "$BODY" | grep -q "$PREF" && ok "two owners share 'svc-token' → 409 listing both refs" || fail "ambiguous: $CODE $BODY"
call POST /api/demipass/request-token "$A" '{"ref":"'$PREF'"}'
[ "$CODE" = 200 ] && ok "the ref picks one" || fail "ref pick: $CODE $BODY"

# ── review findings (PR #32 round 1) ──
SQ(){ python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); r=c.execute(sys.argv[2]).fetchall(); c.commit(); print(r[0][0] if r and r[0] else '')" "$DB_PATH" "$1"; }
call POST /api/demipass/access-requests "$A" '{"owner":"owner","secret":"'$REF'","reason":"same secret, other wording"}'
RQ2=$(echo "$BODY" | J request_id)
call POST /api/identity/gate/verify "$O" '{"gate":"pin","pin":"4321","intent":"access:'$RQ2'"}'
call POST /api/demipass/access-requests/$RQ2/approve "$O"; D2=$(echo "$BODY" | J delegation_id)
ACT=$(SQ "SELECT COUNT(*) FROM demipass_delegations d JOIN blindkey_secrets s ON s.id=d.secret_id JOIN identity_wallets w ON w.did=d.delegate_did WHERE w.username='agent' AND s.ref_code='$REF' AND d.status='active'")
[ "$CODE" = 200 ] && [ "$ACT" = 1 ] && ok "approving the same secret twice keeps ONE active delegation (id $D2)" || fail "dup delegation: $CODE active=$ACT $BODY"
call POST /api/demipass/delegate/revoke "$O" '{"delegate_did":"'$AD'","secret_name":"svc-token"}'
call POST /api/demipass/request-token "$A" '{"ref":"'$REF'"}'
[ "$CODE" = 403 ] && ok "one revoke by name ends the access" || fail "after revoke: $CODE $BODY"
python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); s=c.execute(\"SELECT id FROM blindkey_secrets WHERE ref_code=?\",(sys.argv[2],)).fetchone()[0]; o=c.execute(\"SELECT did FROM identity_wallets WHERE username='owner'\").fetchone()[0]; [c.execute(\"INSERT INTO demipass_delegations (owner_did, delegate_did, secret_id, context_id, status) VALUES (?,?,?,NULL,'active')\",(o,sys.argv[3],s)) for _ in range(2)]; c.commit()" "$DB_PATH" "$REF" "$AD"
call POST /api/demipass/delegate/revoke "$O" '{"delegate_did":"'$AD'","secret_name":"svc-token"}'
call POST /api/demipass/request-token "$A" '{"ref":"'$REF'"}'
[ "$CODE" = 403 ] && ok "legacy duplicate rows: a revoke by name ends them all" || fail "legacy dups: $CODE $BODY"
call POST /api/demipass/access-requests "$A" '{"owner":"owner","secret":"svc-token","reason":"third time"}'
RQ3=$(echo "$BODY" | J request_id)
call POST /api/identity/gate/verify "$O" '{"gate":"pin","pin":"4321","intent":"access:'$RQ3'"}'
call POST /api/demipass/access-requests/$RQ3/approve "$O"; D3=$(echo "$BODY" | J delegation_id)
call POST /api/demipass/delegate/revoke "$O" '{"delegation_id":'$D3'}'
call POST /api/demipass/request-token "$A" '{"ref":"'$REF'"}'
[ "$CODE" = 403 ] && ok "the delegation id approve reports is the one that, revoked, ends the access" || fail "reported id: $D3 $CODE $BODY"

OD=$(SQ "SELECT did FROM identity_wallets WHERE username='owner'")
call POST /api/demipass/request-token "$X" '{"name":"svc-token","owner_did":"'$OD'"}'; C1=$CODE; B1=$(echo "$BODY" | J error)
call POST /api/demipass/request-token "$X" '{"name":"no-such-secret","owner_did":"'$OD'"}'
[ "$C1" = 403 ] && [ "$CODE" = 403 ] && [ "$B1" = "$(echo "$BODY" | J error)" ] && ! echo "$BODY" | grep -q '"contexts"' \
  && ok "an outsider naming owner_did gets the same 403 for a real and a missing secret, no context names" || fail "owner_did oracle: $C1 / $CODE $BODY"

SQ "INSERT INTO silicon_permissions (agent_name, permission_type, resource, granted_by) VALUES ('owner-bot', 'secret:use', 'other-token', 'smoke')" >/dev/null
call GET /api/demipass/menu "$SIL"
NAMES=$(echo "$BODY" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(",".join(s["name"] for s in d["your_secrets"]))')
[ "$CODE" = 200 ] && [ "$NAMES" = other-token ] && [ "$(echo "$BODY" | J can_ask)" = "[]" ] && ok "a silicon token's menu lists only the secret it may use" || fail "silicon menu: $NAMES $BODY"
call POST /api/demipass/request-token "$SIL" '{"ref":"DP-none-1"}'
echo "$BODY" | grep -q 'svc-token' && fail "silicon error menu leaked svc-token" || ok "a silicon token's error menu leaks nothing else"

SID=$(SQ "SELECT id FROM blindkey_secrets WHERE ref_code='$REF'")
SQ "INSERT INTO blindkey_contexts (secret_id, context_name, action_type, target_url_pattern, allowed_by, status) VALUES ($SID, 'billing', 'http_header', 'https://billing.example/*', 'smoke', 'active')" >/dev/null
call POST /api/demipass/request-token "$O" '{"ref":"'$REF'"}'
[ "$CODE" = 400 ] && [ "$(echo "$BODY" | J contexts.1)" != None ] && ok "a ref with two contexts and no target asks which one instead of picking" || fail "ref contexts: $CODE $BODY"
call POST /api/demipass/request-token "$O" '{"ref":"'$REF'","target_url":"https://other.example/x"}'
[ "$CODE" = 200 ] && [ "$(echo "$BODY" | J context)" = default ] && ok "…but a target only one context fits picks that one" || fail "fit by url: $CODE $BODY"
call POST /api/demipass/request-token "$O" '{"ref":"'$REF'","target_url":"https://billing.example/x"}'
[ "$CODE" = 400 ] && ok "…and a target both fit still asks" || fail "both fit: $CODE $BODY"

echo; [ $fails = 0 ] && echo "ALL OK" || { echo "$fails FAILED"; exit 1; }
