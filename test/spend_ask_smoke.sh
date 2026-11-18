#!/bin/bash
# Spend plans (spend_asks.js, Aaron 2026-11-18): a pane's multi-step spend asked ONCE as one card (every step, the
# total), approved with the PIN; a consent step then draws on the plan with no second card; the rest is tracked.
set -u
W=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
S=$(mktemp -d /tmp/dustforge-spend-ask-smoke.XXXXXX)
PORT=${PORT:-3837}; API=http://127.0.0.1:$PORT
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
# Legacy fixture: a DB from before this change has no spend_asks table; the next boot adds it.
python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute('DROP TABLE IF EXISTS spend_asks'); c.commit()" "$DB_PATH"
H=$(printf '%s' hunter22 | sha256sum | cut -d' ' -f1)
node -e '
const identity = require("./identity"); const Database = require("better-sqlite3"); const db = new Database(process.env.DB_PATH);
const mk = (u, bal) => { const id = identity.createIdentity(); const enc = id.encrypted_private_key || id.encryptedPrivateKey;
  db.prepare("INSERT INTO identity_wallets (did, username, email, encrypted_private_key, balance_cents, password_hash) VALUES (?, ?, ?, ?, ?, ?)").run(id.did, u, u + "@smoke.invalid", enc, bal, process.argv[1]);
  db.prepare("INSERT INTO identity_transactions (did, amount_cents, type, description, balance_after) VALUES (?, ?, ?, ?, ?)").run(id.did, bal, "topup", "smoke", bal); return id.did; };
const owner = mk("owner", 10000); mk("stranger", 1000);
const f1 = db.prepare("INSERT INTO fleets (owner_did, name, slug) VALUES (?, ?, ?)").run(owner, "Owner agents", "owner-agents").lastInsertRowid;
let n = 0; for (const u of ["fg", "agent"]) { const did = mk(u, 100);
  db.prepare("INSERT INTO fleet_silicons (fleet_id, member_did, handle, silicon_id, status, created_by_fleet, joined_via) VALUES (?, ?, ?, ?, ?, 1, ?)").run(f1, did, u, "sil_smoke" + (n++), "active", "owner"); }' "$H" || { echo "FAIL seed"; exit 1; }
start; trap 'kill $SRV 2>/dev/null; rm -rf "$S"' EXIT
[ "$(Q "SELECT COUNT(*) FROM sqlite_master WHERE name='spend_asks'")" = 1 ] && ok "legacy DB without the table boots and gains it" || fail "no spend_asks table"
did(){ Q "SELECT did FROM identity_wallets WHERE username='$1'"; }
login(){ call POST /api/identity/auth-fingerprint "" '{"username":"'$1'","password":"hunter22","scope":"transact","expires_in":"2h"}'; echo "$BODY" | J token; }
mint(){ node -e '
const identity = require("./identity"); const Database = require("better-sqlite3");
const db = new Database(process.env.DB_PATH); const w = db.prepare("SELECT did, encrypted_private_key FROM identity_wallets WHERE username = ?").get(process.argv[1]);
process.stdout.write(identity.createTokenForIdentity(w.encrypted_private_key, w.did, { scope: "transact", expiresIn: "2h", metadata: { auth_method: "fleet_owner_mint", fleet: process.argv[2], username: process.argv[1] } }));' "$1" "$2"; }
OWN=$(login owner); STR=$(login stranger); FG=$(mint fg owner-agents); AG=$(mint agent owner-agents)
for t in "$OWN" "$STR"; do call POST /api/identity/pin "$t" '{"pin":"4321","password":"hunter22"}'; [ "$CODE" = 200 ] || fail "pin set: $CODE $BODY"; done
pin(){ call POST /api/identity/gate/verify "$1" "$(jbody gate pin pin "$2" intent "$3")"; [ "$CODE" = 200 ] || fail "pin $3: $CODE $BODY"; }
approve(){ pin "$1" 4321 "approval-open:$2"; call POST /api/demipass/approvals/$2/open "$1"; local k; k=$(echo "$BODY" | J code)
  call POST /api/demipass/approvals/$2/approve "$1" "$(jbody code "$k")"; [ "$CODE" = 200 ] || fail "approve $2: $CODE $BODY"; }
# a tenant to consent to: fg registers itself, the owner approves
call POST /api/services/register "$FG" '{"slug":"fleetgate","name":"FLEETGATE"}'; R1=$(echo "$BODY" | J approval_id); approve "$OWN" "$R1"
call POST /api/services/register "$FG" "$(jbody slug fleetgate name FLEETGATE approval_id "$R1")"; [ "$CODE" = 201 ] || fail "tenant: $CODE $BODY"

PLAN='{"purpose":"Wave 5 real-payment acceptance","steps":[{"kind":"provision","dd":1000,"label":"create agent conduit-keys","handle":"conduit-keys"},{"kind":"consent","dd":0,"label":"consent to fleetgate 2 DD/day","service":"fleetgate","daily_cap_dd":2},{"kind":"charge","dd":2,"label":"one 2 DD release charge","service":"fleetgate"}]}'
# 1. file: one card, nothing recorded until the PIN approves it
NAP=$(Q "SELECT COUNT(*) FROM use_approvals")
call POST /api/billing/spend-asks "$OWN" "$PLAN"
[ "$CODE" = 202 ] && A=$(echo "$BODY" | J approval_id) && [ "$(echo "$BODY" | J depth)" = critical ] && echo "$BODY" | J next | grep -q "Do not ask in chat" && ok "a plan files ONE critical card (approval $A); the reply says not to ask in chat" || fail "file: $CODE $BODY"
[ "$(Q "SELECT COUNT(*) FROM spend_asks")" = 0 ] && ok "nothing recorded before the approval" || fail "recorded early"
Q "SELECT summary FROM use_approvals WHERE id=$A" | grep -q '^spend plan 1002 DD + consents up to 2 DD/day (3 steps) for "Wave 5 real-payment acc' && ok "the card's summary leads with the total, the consent caps and the step count; a consent step is named from its checked fields" || fail "summary: $(Q "SELECT summary FROM use_approvals WHERE id=$A")"
call GET /api/blindkey/approvals/$A "$OWN"; [ "$(echo "$BODY" | J approval.call.body.steps.0.handle)" = conduit-keys ] && [ "$(echo "$BODY" | J approval.call.body.total_dd)" = 1002 ] && ok "the bound call carries the full step list (what the PIN signs)" || fail "bound: $BODY"
call POST /api/billing/spend-asks "$OWN" "$(python3 -c 'import json,sys; d=json.loads(sys.argv[1]); d["approval_id"]=int(sys.argv[2]); print(json.dumps(d))' "$PLAN" "$A")"; [ "$CODE" = 202 ] && ok "before the approval: still pending (202)" || fail "early: $CODE"
# 2. approve → the plan
approve "$OWN" "$A"
call POST /api/billing/spend-asks "$OWN" "$(python3 -c 'import json,sys; d=json.loads(sys.argv[1]); d["approval_id"]=int(sys.argv[2]); print(json.dumps(d))' "$PLAN" "$A")"
[ "$CODE" = 201 ] && SA=$(echo "$BODY" | J spend_ask_id) && [ "$(echo "$BODY" | J status)" = approved ] && [ "$(echo "$BODY" | J total_dd)" = 1002 ] && [ "$(echo "$BODY" | J steps.1.n)" = 2 ] && ok "approved → spend plan $SA, 1002 DD, 3 numbered steps" || fail "plan: $CODE $BODY"
call POST /api/billing/spend-asks "$OWN" "$(python3 -c 'import json,sys; d=json.loads(sys.argv[1]); d["steps"][2]["dd"]=50; d["approval_id"]=int(sys.argv[2]); print(json.dumps(d))' "$PLAN" "$A")"
[ "$CODE" = 409 ] && ok "a changed plan cannot ride the same approval (409: bound to what was approved)" || fail "rebind: $CODE $BODY"
# 3. the consent step draws on the plan: no second card; never above the step's cap; once
NAP=$(Q "SELECT COUNT(*) FROM use_approvals")
call POST /api/services/consent "$OWN" "$(jbody service fleetgate daily_cap_dd 3 spend_ask_id "$SA")"; [ "$CODE" = 409 ] && echo "$BODY" | grep -q "at most 2" && ok "a consent above the step's cap is refused (409)" || fail "over cap: $CODE $BODY"
call POST /api/services/consent "$OWN" "$(jbody service fleetgate daily_cap_dd 2 spend_ask_id "$SA")"
[ "$CODE" = 201 ] && [ "$(echo "$BODY" | J daily_cap_dd)" = 2 ] && [ "$(Q "SELECT COUNT(*) FROM use_approvals")" = "$NAP" ] && [ "$(Q "SELECT approval_id FROM service_consents WHERE payer_did='$(did owner)'")" = "$A" ] \
  && ok "the consent is granted on the plan's approval: 201, no new card, approval_id = the plan's" || fail "consent: $CODE $BODY approvals $(Q "SELECT COUNT(*) FROM use_approvals") vs $NAP"
call GET /api/billing/spend-asks/$SA "$OWN"; [ -n "$(echo "$BODY" | J steps.1.covered_at)" ] && [ "$(echo "$BODY" | J steps.1.covered_at)" != None ] && ok "the plan shows step 2 covered" || fail "covered: $BODY"
call POST /api/services/consent "$OWN" "$(jbody service fleetgate daily_cap_dd 2 spend_ask_id "$SA")"; [ "$CODE" = 409 ] && ok "the step is used once (409 the second time)" || fail "reuse: $CODE $BODY"
call POST /api/services/consent "$OWN" "$(jbody service fleetgate daily_cap_dd 2)"; [ "$CODE" = 202 ] && ok "without spend_ask_id a consent still files its own card (202)" || fail "plain consent: $CODE $BODY"
# 4. other wallets: nothing of the plan
call GET /api/billing/spend-asks/$SA "$STR"; [ "$CODE" = 404 ] && ok "a stranger cannot read the plan" || fail "stranger read: $CODE"
call POST /api/services/consent "$STR" "$(jbody service fleetgate daily_cap_dd 1 spend_ask_id "$SA")"; [ "$CODE" = 409 ] && ok "…nor consent on it" || fail "stranger consent: $CODE $BODY"
call POST /api/billing/spend-asks/$SA/close "$STR"; [ "$CODE" = 404 ] && ok "…nor close it" || fail "stranger close: $CODE"
# 5. progress and close
call POST /api/billing/spend-asks/$SA/progress "$OWN" '{"step":1,"note":"token request 7 filed"}'; [ "$CODE" = 200 ] && [ "$(echo "$BODY" | J steps.0.note)" = "token request 7 filed" ] && ok "progress on a step is recorded" || fail "progress: $CODE $BODY"
call POST /api/billing/spend-asks/$SA/progress "$OWN" '{"step":9}'; [ "$CODE" = 400 ] && ok "a step the plan has not → 400" || fail "bad step: $CODE"
call POST /api/billing/spend-asks/$SA/close "$OWN"; [ "$(echo "$BODY" | J status)" = closed ] && ok "the payer closes the plan" || fail "close: $CODE $BODY"
call POST /api/services/consent "$OWN" "$(jbody service fleetgate daily_cap_dd 1 spend_ask_id "$SA")"; [ "$CODE" = 409 ] && echo "$BODY" | grep -q closed && ok "a closed plan covers nothing" || fail "closed cover: $CODE $BODY"
call GET /api/billing/spend-asks "$OWN"; [ "$(echo "$BODY" | J spend_asks.0.status)" = closed ] && ok "the list keeps it (30 days)" || fail "list: $BODY"
# 6. an agent's plan waits on its fleet owner; a worker/silicon token cannot file one
call POST /api/billing/spend-asks "$AG" '{"purpose":"agent plan","steps":[{"kind":"charge","dd":5,"label":"five"}]}'
[ "$CODE" = 202 ] && [ "$(Q "SELECT owner_did FROM use_approvals WHERE id=$(echo "$BODY" | J approval_id)")" = "$(did owner)" ] && ok "an agent's plan is a card on its fleet owner's phone" || fail "agent plan: $CODE $BODY"
for b in '{"purpose":"x","steps":[]}' '{"purpose":"x","steps":[{"kind":"wire","dd":1,"label":"a"}]}' '{"purpose":"x","steps":[{"kind":"consent","dd":0,"label":"a","service":"fleetgate"}]}' '{"purpose":"<b>","steps":[{"kind":"charge","dd":1,"label":"a"}]}' '{"purpose":"x","steps":[{"kind":"charge","dd":1,"label":"a"}],"valid_days":99}'; do
  call POST /api/billing/spend-asks "$OWN" "$b"; [ "$CODE" = 400 ] || fail "bad plan accepted: $b → $CODE $BODY"; done; ok "bad purpose, kind, consent step, steps or valid_days → 400"
call POST /api/billing/spend-asks "" '{"purpose":"x","steps":[{"kind":"charge","dd":1,"label":"a"}]}'; [ "$CODE" = 401 ] && ok "no token → 401" || fail "noauth: $CODE"
call POST /api/identity/auth-fingerprint "" '{"username":"owner","password":"hunter22","scope":"read","expires_in":"1h"}'; RD=$(echo "$BODY" | J token)
call POST /api/billing/spend-asks "$RD" '{"purpose":"x","steps":[{"kind":"charge","dd":1,"label":"a"}]}'; [ "$CODE" = 403 ] && ok "a read-scope token cannot file a plan (403)" || fail "read scope: $CODE $BODY"
call POST /api/billing/spend-asks "$OWN" '{"purpose":"x","steps":[{"kind":"consent","dd":1,"label":"a","service":"fleetgate","daily_cap_dd":500000}]}'; [ "$CODE" = 400 ] && echo "$BODY" | grep -q "daily_cap_dd: 1 to 100000" && ok "a consent step above a consent's own cap (100000) → 400" || fail "consent cap: $CODE $BODY"
grep -q -i "TypeError\|ReferenceError" "$S/server.log" && { fail "server errors"; grep -i -m5 "TypeError\|ReferenceError" "$S/server.log"; }
echo "$fails failure(s)"; exit $(( fails > 0 ))
