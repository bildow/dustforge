#!/bin/bash
# Limit lifts (Aaron 2026-11-15: "a way for a worker / agent / pane to dynamically request a limit lift on a battery of
# calls or project branch it's working on").
#   - An agent at its limit gets a 429 that names the lift route. It asks (POST /api/identity/limits/lift: limiter,
#     extra calls per window, minutes, label, reason) → 202, an approval of kind limit-lift in its owner's app.
#   - The owner approves (PIN to open, code to approve); the agent repeats the call with approval_id → 201, the lift.
#   - Only that key's limit rises, by exactly `extra`, until the lift expires or is ended (owner or holder).
#   - Changed fields don't redeem the approval; one approval grants one lift; bad input is refused before asking.
set -u
W=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
S=$(mktemp -d /tmp/dustforge-limit-lift.XXXXXX)
PORT=${PORT:-3875}; API=http://127.0.0.1:$PORT
[ -d "$W/node_modules" ] || export NODE_PATH=${NODE_PATH:-/home/flimflam/project/dustforge/node_modules}
export IDENTITY_MASTER_KEY=$(python3 -c 'import secrets;print(secrets.token_hex(32))') DB_PATH=$S/dustforge.db PORT \
  STALWART_HOST=127.0.0.1 STALWART_PORT=1 SMTP_RELAY_HOST= SMTP_HOST=127.0.0.1 SMTP_PORT=9 \
  USE_RATE_LIMIT_MAX=5
cd "$W"
node server.js >>"$S/server.log" 2>&1 & SRV=$!
for i in $(seq 1 40); do curl -s -o /dev/null "$API/" && break; sleep 0.5; done
kill -0 $SRV 2>/dev/null || { echo "server died:"; tail -5 "$S/server.log"; exit 1; }
trap 'kill $SRV 2>/dev/null; [ -n "${KEEP:-}" ] || rm -rf "$S"' EXIT
H=$(printf '%s' hunter22 | sha256sum | cut -d' ' -f1)
SIL='silicon:limit-lift-smoke-token-0123456789'; SIL2='silicon:limit-lift-smoke-other-0123456789'
node -e '
const identity = require("./identity"), crypto = require("crypto"); const Database = require("better-sqlite3"); const db = new Database(process.env.DB_PATH);
const id = identity.createIdentity(); const enc = id.encrypted_private_key || id.encryptedPrivateKey;
db.prepare("INSERT INTO identity_wallets (did, username, email, encrypted_private_key, balance_cents, password_hash) VALUES (?, ?, ?, ?, 100000, ?)").run(id.did, "ll-owner", "ll-owner@dustforge.com", enc, process.argv[1]);
const h = (t) => crypto.createHash("sha256").update(t).digest("hex");
db.prepare("INSERT INTO silicon_agents (agent_name, did, carbon_did, token_hash) VALUES (?, ?, ?, ?)").run("indexer", "did:silicon:llidx", id.did, h(process.argv[2]));
db.prepare("INSERT INTO silicon_agents (agent_name, did, carbon_did, token_hash) VALUES (?, ?, ?, ?)").run("other", "did:silicon:llother", id.did, h(process.argv[3]));' "$H" "$SIL" "$SIL2"

fails=0; ok(){ echo "ok   $*"; }; fail(){ echo "FAIL $*"; fails=$((fails+1)); }
J(){ python3 -c 'import json,sys; d=json.load(sys.stdin); v=d
for k in sys.argv[1].split("."):
    v = v[int(k)] if isinstance(v, list) else (v or {}).get(k)
print(v if not isinstance(v,(dict,list)) else json.dumps(v))' "$1"; }
Q(){ python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); r=c.execute(sys.argv[2]).fetchone(); print(r[0] if r else '')" "$DB_PATH" "$1"; }
X(){ python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute(sys.argv[2]); c.commit()" "$DB_PATH" "$1"; }
call(){ local m=$1 p=$2 t=$3 b=${4:-}
  BODY=$(curl -s -o - -w '\n%{http_code}' -X "$m" "$API$p" -H 'Content-Type: application/json' ${t:+-H "Authorization: Bearer $t"} ${b:+-d "$b"})
  CODE=${BODY##*$'\n'}; BODY=${BODY%$'\n'*}; }
pin(){ call POST /api/identity/gate/verify "$A" '{"gate":"pin","pin":"4321","intent":"'$1'"}'; }
approve(){ pin "approval-open:$1"; call POST /api/demipass/approvals/$1/open "$A"; local C; C=$(echo "$BODY" | J code)
  call POST /api/demipass/approvals/$1/approve "$A" '{"code":"'$C'"}'; }
use(){ call POST /api/demipass/request-token "$1" '{"ref":"DP-NONE-x","action":"ssh_exec"}'; }   # counted by the per-agent /use budget

call POST /api/identity/auth-fingerprint "" '{"username":"ll-owner","password":"hunter22","scope":"transact","expires_in":"1h"}'
A=$(echo "$BODY" | J token); [ "$A" != None ] && ok "owner signed in" || { fail "login $CODE $BODY"; exit 1; }
call POST /api/identity/pin "$A" '{"pin":"4321","password":"hunter22"}'

# The agent runs into its own /use budget (5 here); the 429 names the lift route.
n=0; for i in $(seq 1 10); do use "$SIL"; [ "$CODE" = 429 ] && break; n=$((n+1)); done
[ "$CODE" = 429 ] && [ "$(echo "$BODY" | J lift.limiter)" = use ] && ok "at its limit (after $n calls) the 429 names the lift route (limiter use)" || fail "429: $CODE $BODY"

# Bad asks are refused before anything reaches the phone.
LIFT='{"limiter":"use","extra":20,"minutes":30,"label":"branch feat/reindex","reason":"re-index 40k entries"}'
call POST /api/identity/limits/lift "$SIL" '{"limiter":"strict","extra":5,"label":"x"}'; [ "$CODE" = 400 ] && ok "an unliftable limiter: 400" || fail "limiter: $CODE"
call POST /api/identity/limits/lift "$SIL" '{"limiter":"use","extra":999999,"label":"x"}'; [ "$CODE" = 400 ] && ok "too many extra calls: 400" || fail "extra: $CODE"
call POST /api/identity/limits/lift "$SIL" '{"limiter":"use","extra":5,"minutes":9999,"label":"x"}'; [ "$CODE" = 400 ] && ok "too long: 400" || fail "minutes: $CODE"
call POST /api/identity/limits/lift "$SIL" '{"limiter":"use","extra":5,"label":"<script>"}'; [ "$CODE" = 400 ] && ok "a label outside the plain set: 400" || fail "label: $CODE"
call POST /api/identity/limits/lift "" "$LIFT"; [ "$CODE" = 401 ] && ok "not signed in: 401" || fail "anon: $CODE"
[ "$(Q "SELECT COUNT(*) FROM use_approvals")" = 0 ] && ok "none of those filed an approval" || fail "approvals filed by bad asks"

# The ask → the owner's approval.
call POST /api/identity/limits/lift "$SIL" "$LIFT"
AP=$(echo "$BODY" | J approval_id)
[ "$CODE" = 202 ] && [ "$AP" != None ] && ok "the agent's ask files approval $AP in the owner's app" || fail "ask: $CODE $BODY"
SUM=$(Q "SELECT summary FROM use_approvals WHERE id=$AP"); [ -z "$SUM" ] && SUM=$(Q "SELECT params FROM use_approvals WHERE id=$AP")
echo "$SUM" | grep -q "branch feat/reindex" && ok "the card names the agent's label: $(echo "$SUM" | cut -c1-110)" || fail "summary: $SUM"
call POST /api/identity/limits/lift "$SIL" "$(echo "$LIFT" | sed 's/"extra":20/"extra":20,"approval_id":'$AP'/')"
[ "$CODE" = 202 ] || [ "$CODE" = 403 ] && ok "not usable before the owner approves ($CODE)" || fail "early redeem: $CODE $BODY"
approve "$AP"; [ "$CODE" = 200 ] && ok "the owner approves (PIN to open, code to approve)" || fail "approve: $CODE $BODY"
call POST /api/identity/limits/lift "$SIL" "$(echo "$LIFT" | sed 's/"extra":20/"extra":2000,"approval_id":'$AP'/')"
[ "$CODE" = 409 ] || [ "$CODE" = 403 ] && ok "more calls than approved don't redeem it ($CODE)" || fail "widened redeem: $CODE $BODY"
call POST /api/identity/limits/lift "$SIL2" "$(echo "$LIFT" | sed 's/"extra":20/"extra":20,"approval_id":'$AP'/')"
[ "$CODE" != 201 ] && ok "another agent can't redeem it ($CODE)" || fail "other agent redeemed: $BODY"
call POST /api/identity/limits/lift "$SIL" "$(echo "$LIFT" | sed 's/"extra":20/"extra":20,"approval_id":'$AP'/')"
LID=$(echo "$BODY" | J lift.id)
[ "$CODE" = 201 ] && [ "$(echo "$BODY" | J lift.active)" = True ] && [ "$(echo "$BODY" | J lift.extra)" = 20 ] && ok "redeemed: lift $LID, +20 per window, active" || fail "redeem: $CODE $BODY"
call POST /api/identity/limits/lift "$SIL" "$(echo "$LIFT" | sed 's/"extra":20/"extra":20,"approval_id":'$AP'/')"
[ "$CODE" != 201 ] && ok "one approval grants one lift ($CODE on reuse)" || fail "reuse granted twice"

# The lift raises exactly that agent's limit.
use "$SIL"; [ "$CODE" != 429 ] && ok "the agent goes on past its old limit" || fail "still limited: $CODE $BODY"
m=1; for i in $(seq 1 40); do use "$SIL"; [ "$CODE" = 429 ] && break; m=$((m+1)); done
[ "$CODE" = 429 ] && [ "$m" -ge 18 ] && [ "$m" -le 21 ] && ok "…by exactly the approved 20 (then 429 again after $m more)" || fail "lifted by $m ($CODE)"
for i in $(seq 1 6); do use "$SIL2"; done; [ "$CODE" = 429 ] && ok "another agent of the same wallet is not lifted" || fail "other agent lifted: $CODE"

# Listing and ending.
call GET /api/identity/limits/lifts "$A"; [ "$(echo "$BODY" | J lifts.0.label)" = "branch feat/reindex" ] && ok "the owner sees the lift" || fail "owner list: $BODY"
call GET /api/identity/limits/lifts "$SIL2"; [ "$(echo "$BODY" | J lifts)" = "[]" ] && ok "another agent doesn't see it" || fail "other list: $BODY"
call POST /api/identity/limits/lifts/$LID/end "$SIL2"; [ "$CODE" = 404 ] && ok "another agent can't end it" || fail "other end: $CODE"
call POST /api/identity/limits/lifts/$LID/end "$A"; [ "$CODE" = 200 ] && [ "$(echo "$BODY" | J lift.ended_by)" = owner ] && ok "the owner ends it early" || fail "end: $CODE $BODY"
[ "$(Q "SELECT COUNT(*) FROM demipass_security_events WHERE event_type IN ('limit_lift_granted','limit_lift_ended')")" = 2 ] && ok "granted and ended are logged" || fail "events"

# An expired lift lifts nothing.
X "INSERT INTO limit_lifts (owner_did, holder_key, holder_label, requester_key, limiter, extra, label, created_at, expires_at) SELECT owner_did, holder_key, holder_label, requester_key, 'use', 500, 'old', '2020-01-01T00:00:00Z', '2020-01-01T01:00:00Z' FROM limit_lifts WHERE id=$LID"
sleep 6; use "$SIL"; [ "$CODE" = 429 ] && ok "an expired lift lifts nothing" || fail "expired lift counted: $CODE"

# Legacy fixture: a limit_lifts table from before requester_key gains it.
kill $SRV; wait $SRV 2>/dev/null
X "ALTER TABLE limit_lifts RENAME TO limit_lifts_old"
X "CREATE TABLE limit_lifts (id INTEGER PRIMARY KEY AUTOINCREMENT, owner_did TEXT NOT NULL, holder_key TEXT NOT NULL, holder_label TEXT, limiter TEXT NOT NULL, extra INTEGER NOT NULL, label TEXT NOT NULL, reason TEXT, approval_id INTEGER, created_at TEXT NOT NULL, expires_at TEXT NOT NULL, ended_at TEXT, ended_by TEXT)"
node server.js >>"$S/server.log" 2>&1 & SRV=$!
for i in $(seq 1 40); do curl -s -o /dev/null "$API/" && break; sleep 0.5; done
[ "$(Q "SELECT COUNT(*) FROM pragma_table_info('limit_lifts') WHERE name='requester_key'")" = 1 ] && ok "legacy: a table from before requester_key gains the column at start" || fail "legacy column"
call GET /api/identity/limits/lifts "$A"; [ "$CODE" = 200 ] && ok "legacy: the list still answers" || fail "legacy list: $CODE"

V=public/vault-mobile.html
grep -q 'onclick="loadLifts()"' $V && grep -q "'/api/identity/limits/lifts/'+Number(id)+'/end'" $V && ok "app: Settings lists lifts and ends one" || fail "app"

echo; [ $fails = 0 ] && echo "ALL PASSED" || echo "$fails failure(s)"; exit $fails
