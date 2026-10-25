#!/bin/bash
# End-to-end smoke of browser fill (test/browser_fill_smoke.sh, contract docs/browser-fill-api.md): boots server.js
# on a throwaway DB + random master key, creates one wallet and one silicon, then drives the real HTTP routes with
# two sessions of the same account — E (the extension, which asks) and W (the phone wallet, which approves with
# the PIN). Covers origin binding (exact, https only, http for localhost), store's origins/login fields, the
# candidates list, request → 428 → approve → redeem once, approval only from another session and only with a PIN
# proof for this fill's intent, deny, expiry, unbind/freeze after approval, and the silicon path: an explicit
# action:browser_fill grant (never admin:full), re-checked at redeem. Asserts the value never appears in any
# reply but the one redeem. Needs node_modules (or NODE_PATH). No network, nothing persists.
set -u
W=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
S=$(mktemp -d /tmp/dustforge-fill-smoke.XXXXXX)
PORT=${PORT:-3778}; API=http://127.0.0.1:$PORT
[ -d "$W/node_modules" ] || export NODE_PATH=${NODE_PATH:-/home/flimflam/project/dustforge/node_modules}
export IDENTITY_MASTER_KEY=$(python3 -c 'import secrets;print(secrets.token_hex(32))') DB_PATH=$S/dustforge.db PORT STALWART_HOST=127.0.0.1 STALWART_PORT=1 SMTP_RELAY_HOST=
cd "$W"
node server.js >"$S/server.log" 2>&1 & SRV=$!
trap 'kill $SRV 2>/dev/null; rm -rf "$S"' EXIT
for i in $(seq 1 40); do curl -s -o /dev/null "$API/" && break; sleep 0.5; done
kill -0 $SRV 2>/dev/null || { echo "server died:"; tail -5 "$S/server.log"; exit 1; }
PW=hunter22; H=$(printf '%s' "$PW" | sha256sum | cut -d' ' -f1)
SIL='silicon:fill-smoke-token-0123456789'
node -e '
const identity = require("./identity"); const Database = require("better-sqlite3"); const crypto = require("crypto");
const id = identity.createIdentity(); const enc = id.encrypted_private_key || id.encryptedPrivateKey;
const db = new Database(process.env.DB_PATH);
try { db.exec("ALTER TABLE identity_wallets ADD COLUMN password_hash TEXT"); } catch (_) {}
db.prepare("INSERT INTO identity_wallets (did, username, email, encrypted_private_key, balance_cents, password_hash, recovery_email) VALUES (?, ?, ?, ?, 100000, ?, ?)")
  .run(id.did, "filltester", "filltester@dustforge.com", enc, process.argv[1], "f@example.com");
db.prepare("INSERT INTO silicon_agents (agent_name, did, carbon_did, token_hash) VALUES (?, ?, ?, ?)")
  .run("fleet-a1", "did:silicon:fill-smoke", id.did, crypto.createHash("sha256").update(process.argv[2]).digest("hex"));
' "$H" "$SIL"
fails=0; ok(){ echo "ok   $*"; }; fail(){ echo "FAIL $*"; fails=$((fails+1)); }
J(){ python3 -c 'import json,sys; d=json.load(sys.stdin); v=d
for k in sys.argv[1].split("."):
    v = v[int(k)] if isinstance(v, list) else (v or {}).get(k)
print(v)' "$1"; }
SQL(){ python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute(sys.argv[2]); c.commit()" "$DB_PATH" "$1"; }
ALL="$S/replies.log"; : >"$ALL"
call(){ # method path token body → sets CODE and BODY; every reply is kept to prove where the value appears
  local m=$1 p=$2 t=$3 b=${4:-}
  BODY=$(curl -s -o - -w '\n%{http_code}' -X "$m" "$API$p" -H 'Content-Type: application/json' ${t:+-H "Authorization: Bearer $t"} ${b:+-d "$b"})
  CODE=${BODY##*$'\n'}; BODY=${BODY%$'\n'*}; printf '%s %s %s\n' "$m" "$p" "$BODY" >>"$ALL"
}
login(){ call POST /api/identity/auth-fingerprint "" '{"username":"filltester","password":"hunter22","scope":"transact","expires_in":"1h"}'; echo "$BODY" | J token; }
E=$(login); Wt=$(login); [ -n "$E" ] && [ "$E" != None ] && [ "$Wt" != "$E" ] && ok "two sessions: extension E, wallet W" || { fail "login: $CODE $BODY"; exit 1; }
call POST /api/identity/pin "$Wt" '{"pin":"4321","password":"hunter22"}'; [ "$CODE" = 200 ] && ok "vault PIN set" || fail "pin set: $CODE $BODY"

VAL='correct-horse-battery-9'
ORIG=https://login.example.com
# ── store: origins + login ──
call POST /api/blindkey/store "$E" '{"name":"example-login","value":"'$VAL'","secret_type":"password","origins":["http://evil.example.com"]}'
[ "$CODE" = 400 ] && ok "store refuses a plain-http origin that is not localhost" || fail "http origin: $CODE $BODY"
call POST /api/blindkey/store "$E" '{"name":"example-login","value":"'$VAL'","secret_type":"password","origins":["https://login.example.com/signin?x=1","http://localhost:8080/a"],"login":"me@example.com"}'
[ "$CODE" = 200 ] && [ "$(echo "$BODY" | J origins.0)" = "$ORIG" ] && [ "$(echo "$BODY" | J origins.1)" = http://localhost:8080 ] && ok "store binds normalized origins (path and query dropped, localhost http kept)" || fail "store: $CODE $BODY"
REF=$(echo "$BODY" | J ref)
python3 - "$DB_PATH" "$REF" <<'PY2' && ok "a website login gets no default context (no ssh_exec/http use to any host)" || fail "website login got a default context"
import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); n=c.execute("SELECT COUNT(*) FROM blindkey_contexts x JOIN blindkey_secrets s ON s.id=x.secret_id WHERE s.ref_code=?", (sys.argv[2],)).fetchone()[0]; sys.exit(0 if n==0 else 1)
PY2
call POST /api/blindkey/store "$E" '{"name":"example-login","value":"'$VAL'","secret_type":"password"}'
call GET "/api/blindkey/fill/candidates?origin=$ORIG" "$E"
[ "$(echo "$BODY" | J candidates.0.ref)" = "$REF" ] && [ "$(echo "$BODY" | J candidates.0.username)" = me@example.com ] && ok "re-store without origins/login keeps both; candidates list it with its login" || fail "keep on re-store: $BODY"
call GET "/api/blindkey/fill/candidates?origin=https://example.com" "$E"
[ "$(echo "$BODY" | J candidates)" = "[]" ] && ok "a different origin (parent domain) has no candidates — exact match only" || fail "exact: $BODY"

# ── request → pending → approve with PIN on W → redeem once on E ──
call POST /api/blindkey/fill/request "$E" '{"ref":"'$REF'","origin":"https://login.example.com.evil.io"}'
[ "$CODE" = 403 ] && ok "request for an unbound origin → 403 (lookalike host)" || fail "unbound: $CODE $BODY"
call POST /api/blindkey/fill/request "$E" '{"ref":"'$REF'","origin":"'$ORIG'","client_label":"Chrome on flimflam"}'
[ "$CODE" = 201 ] && [ "$(echo "$BODY" | J status)" = pending ] && ok "carbon request → 201 pending" || fail "request: $CODE $BODY"
RID=$(echo "$BODY" | J request_id)
call POST /api/blindkey/fill/redeem "$E" '{"request_id":"'$RID'"}'; [ "$CODE" = 428 ] && ok "redeem before approval → 428 approval_pending" || fail "428: $CODE $BODY"
call GET /api/blindkey/fill/pending "$Wt"
FID=$(echo "$BODY" | J requests.0.id); [ "$(echo "$BODY" | J requests.0.origin)" = "$ORIG" ] && [ "$(echo "$BODY" | J requests.0.own_session)" = False ] && [ "$(echo "$BODY" | J requests.0.client_label)" = "Chrome on flimflam" ] && ok "wallet sees the pending fill (origin, label, not its own)" || fail "pending: $BODY"
call POST /api/blindkey/fill/$FID/approve "$E"; [ "$CODE" = 409 ] && ok "the asking session cannot approve its own fill" || fail "self-approve: $CODE $BODY"
call POST /api/blindkey/fill/$FID/approve "$Wt"
[ "$CODE" = 403 ] && [ "$(echo "$BODY" | J missing.0)" = pin ] && [ "$(echo "$BODY" | J intent)" = "fill:$FID" ] && ok "approve without PIN → 403 missing [pin], intent fill:$FID" || fail "approve no pin: $CODE $BODY"
call POST /api/identity/gate/verify "$Wt" '{"gate":"pin","pin":"4321","intent":"reveal:1"}'
call POST /api/blindkey/fill/$FID/approve "$Wt"; [ "$CODE" = 403 ] && ok "a PIN proof for another intent does not approve the fill" || fail "wrong intent: $CODE $BODY"
call POST /api/identity/gate/verify "$E" '{"gate":"pin","pin":"4321","intent":"fill:'$FID'"}'
call POST /api/blindkey/fill/$FID/approve "$Wt"; [ "$CODE" = 403 ] && ok "a PIN proof in the asking session does not approve from the wallet" || fail "cross-session proof: $CODE $BODY"
call POST /api/identity/gate/verify "$Wt" '{"gate":"pin","pin":"4321","intent":"fill:'$FID'"}'; [ "$CODE" = 200 ] && ok "PIN verified on W for fill:$FID" || fail "verify: $CODE $BODY"
call POST /api/blindkey/fill/$FID/approve "$Wt"; [ "$CODE" = 200 ] && ok "wallet approves with the PIN" || fail "approve: $CODE $BODY"
python3 - "$DB_PATH" "$FID" <<'PY' && ok "the PIN proof was spent by the approval" || fail "proof not spent"
import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); n=c.execute("SELECT COUNT(*) FROM gate_verifications WHERE gate_type='pin' AND intent=?", ('fill:'+sys.argv[2],)).fetchone()[0]
# the proof minted in session E for the same intent is still there (never usable from W); W's was deleted
sys.exit(0 if n == 1 else 1)
PY
call POST /api/blindkey/fill/redeem "$Wt" '{"request_id":"'$RID'"}'; [ "$CODE" = 404 ] && ok "another session cannot redeem the fill (404, as if absent)" || fail "W redeem: $CODE $BODY"
BEFORE=$(grep -c -- "$VAL" "$ALL")
call POST /api/blindkey/fill/redeem "$E" '{"request_id":"'$RID'"}'
[ "$CODE" = 200 ] && [ "$(echo "$BODY" | J value)" = "$VAL" ] && [ "$(echo "$BODY" | J username)" = me@example.com ] && [ "$(echo "$BODY" | J origin)" = "$ORIG" ] && ok "the asking session redeems value + login + origin" || fail "redeem: $CODE $BODY"
call POST /api/blindkey/fill/redeem "$E" '{"request_id":"'$RID'"}'; [ "$CODE" = 410 ] && [ "$(echo "$BODY" | J error)" = already_redeemed ] && ok "second redeem → 410 already_redeemed" || fail "twice: $CODE $BODY"
call POST /api/blindkey/fill/$FID/approve "$Wt"; [ "$CODE" = 409 ] && ok "a redeemed request cannot be approved again" || fail "re-approve: $CODE $BODY"

# ── deny, expiry ──
call POST /api/blindkey/fill/request "$E" '{"name":"example-login","origin":"http://localhost:8080"}'; R2=$(echo "$BODY" | J request_id)
call GET /api/blindkey/fill/pending "$Wt"; F2=$(echo "$BODY" | J requests.0.id)
call POST /api/blindkey/fill/$F2/deny "$Wt"; [ "$CODE" = 200 ] && ok "wallet denies" || fail "deny: $CODE $BODY"
call POST /api/blindkey/fill/redeem "$E" '{"request_id":"'$R2'"}'; [ "$CODE" = 403 ] && [ "$(echo "$BODY" | J error)" = denied ] && ok "denied fill → 403 denied" || fail "denied redeem: $CODE $BODY"
call POST /api/blindkey/fill/request "$E" '{"ref":"'$REF'","origin":"'$ORIG'"}'; R3=$(echo "$BODY" | J request_id)
SQL "UPDATE blindkey_fill_requests SET expires_at = '2020-01-01T00:00:00.000Z' WHERE request_code = '$R3'"
call POST /api/blindkey/fill/redeem "$E" '{"request_id":"'$R3'"}'; [ "$CODE" = 410 ] && [ "$(echo "$BODY" | J error)" = expired ] && ok "expired request → 410 expired" || fail "expired: $CODE $BODY"
call GET /api/blindkey/fill/pending "$Wt"; [ "$(echo "$BODY" | J requests)" = "[]" ] && ok "expired and decided requests leave the wallet list" || fail "pending after: $BODY"

# ── approval then unbind / freeze stops the fill ──
approve(){ # request id → approves it on W with the PIN
  call GET /api/blindkey/fill/pending "$Wt"; local f; f=$(echo "$BODY" | J requests.0.id)
  call POST /api/identity/gate/verify "$Wt" '{"gate":"pin","pin":"4321","intent":"fill:'$f'"}'; call POST /api/blindkey/fill/$f/approve "$Wt"; }
call POST /api/blindkey/fill/request "$E" '{"ref":"'$REF'","origin":"'$ORIG'"}'; R4=$(echo "$BODY" | J request_id); approve
call POST /api/blindkey/origins "$E" '{"ref":"'$REF'","origins":["http://localhost:8080"],"mode":"set"}'; [ "$CODE" = 200 ] && ok "owner rebinds origins (set)" || fail "origins set: $CODE $BODY"
call POST /api/blindkey/fill/redeem "$E" '{"request_id":"'$R4'"}'; [ "$CODE" = 403 ] && ok "origin unbound after approval → redeem refused" || fail "unbound redeem: $CODE $BODY"
call POST /api/blindkey/origins "$E" '{"ref":"'$REF'","origins":["'$ORIG'"],"mode":"add"}'
[ "$(echo "$BODY" | J origins.1)" = "$ORIG" ] && ok "origins add keeps the existing ones" || fail "origins add: $BODY"
call POST /api/blindkey/fill/request "$E" '{"ref":"'$REF'","origin":"'$ORIG'"}'; R5=$(echo "$BODY" | J request_id); approve
SQL "UPDATE blindkey_secrets SET frozen = 1 WHERE ref_code = '$REF'"
call POST /api/blindkey/fill/redeem "$E" '{"request_id":"'$R5'"}'; [ "$CODE" = 423 ] && ok "frozen after approval → redeem 423" || fail "frozen: $CODE $BODY"
call POST /api/blindkey/fill/request "$E" '{"ref":"'$REF'","origin":"'$ORIG'"}'; [ "$CODE" = 423 ] && ok "frozen secret → request 423" || fail "frozen request: $CODE $BODY"
SQL "UPDATE blindkey_secrets SET frozen = 0 WHERE ref_code = '$REF'"

# ── silicon: explicit grant only, re-checked at redeem ──
call GET "/api/blindkey/fill/candidates?origin=$ORIG" "$SIL"; [ "$(echo "$BODY" | J candidates)" = "[]" ] && ok "silicon without a grant sees no candidates" || fail "sil candidates: $BODY"
call POST /api/blindkey/fill/request "$SIL" '{"ref":"'$REF'","origin":"'$ORIG'"}'; [ "$CODE" = 403 ] && ok "silicon without a grant → 403" || fail "sil no grant: $CODE $BODY"
SQL "INSERT INTO silicon_permissions (agent_name, permission_type, resource) VALUES ('fleet-a1', 'admin:full', '*')"
call POST /api/blindkey/fill/request "$SIL" '{"ref":"'$REF'","origin":"'$ORIG'"}'; [ "$CODE" = 403 ] && ok "admin:full does not imply browser_fill" || fail "admin:full: $CODE $BODY"
SQL "INSERT INTO silicon_permissions (agent_name, permission_type, resource) VALUES ('fleet-a1', 'action:browser_fill', '$REF')"
call GET "/api/blindkey/fill/candidates?origin=$ORIG" "$SIL"; [ "$(echo "$BODY" | J candidates.0.ref)" = "$REF" ] && ok "silicon with action:browser_fill on the ref sees it" || fail "sil candidates granted: $BODY"
call POST /api/blindkey/fill/request "$SIL" '{"ref":"'$REF'","origin":"https://example.com"}'; [ "$CODE" = 403 ] && ok "silicon grant does not widen the origin binding" || fail "sil origin: $CODE $BODY"
call POST /api/blindkey/fill/request "$SIL" '{"ref":"'$REF'","origin":"'$ORIG'"}'
[ "$CODE" = 201 ] && [ "$(echo "$BODY" | J status)" = approved ] && ok "silicon with the grant → approved without the phone" || fail "sil request: $CODE $BODY"
SR=$(echo "$BODY" | J request_id)
call POST /api/blindkey/fill/redeem "$E" '{"request_id":"'$SR'"}'; [ "$CODE" = 404 ] && ok "the owner's own session cannot redeem the silicon's fill" || fail "carbon redeems silicon fill: $CODE $BODY"
call POST /api/blindkey/fill/redeem "$SIL" '{"request_id":"'$SR'"}'; [ "$CODE" = 200 ] && [ "$(echo "$BODY" | J value)" = "$VAL" ] && ok "silicon redeems its fill" || fail "sil redeem: $CODE $BODY"
call POST /api/blindkey/fill/request "$SIL" '{"ref":"'$REF'","origin":"'$ORIG'"}'; SR2=$(echo "$BODY" | J request_id)
SQL "UPDATE silicon_permissions SET status = 'revoked' WHERE permission_type = 'action:browser_fill'"
call POST /api/blindkey/fill/redeem "$SIL" '{"request_id":"'$SR2'"}'; [ "$CODE" = 403 ] && ok "grant revoked after request → redeem refused" || fail "revoked: $CODE $BODY"
call POST /api/blindkey/origins "$SIL" '{"ref":"'$REF'","origins":["https://attacker.example"],"mode":"add"}'; [ "$CODE" = 403 ] && ok "silicon cannot bind origins" || fail "sil origins: $CODE $BODY"
call GET /api/blindkey/fill/pending "$SIL"; [ "$CODE" = 403 ] && ok "silicon cannot list or approve fills" || fail "sil pending: $CODE $BODY"

# ── grants: action:browser_fill only from the owner, approved with the PIN (review 2026-10-25, blockers 1+2) ──
VAL2='grant-only-value-77'
call POST /api/blindkey/store "$E" '{"name":"agent-login","value":"'$VAL2'","secret_type":"password","origins":["'$ORIG'"],"login":"bot@example.com"}'; REF2=$(echo "$BODY" | J ref)
call POST /api/blindkey/silicon/register "$E" '{"agent_name":"stolen1","permissions":["action:browser_fill"]}'
[ "$CODE" = 400 ] && ok "register refuses action:browser_fill (granted per login, with the PIN)" || fail "register with browser_fill: $CODE $BODY"
call POST /api/blindkey/silicon/register "$SIL" '{"agent_name":"child1"}'
[ "$CODE" = 403 ] && ok "a silicon cannot register agents" || fail "silicon register: $CODE $BODY"
call POST /api/blindkey/silicon/permissions "$SIL" '{"agent_name":"fleet-a1","permission_type":"action:browser_fill","resource":"*"}'
[ "$CODE" = 403 ] && ok "a silicon cannot grant itself browser_fill" || fail "silicon self-grant: $CODE $BODY"
call POST /api/blindkey/silicon/permissions "$SIL" '{"agent_name":"fleet-a1","permission_type":"admin:full"}'
[ "$CODE" = 403 ] && ok "a silicon cannot grant itself anything" || fail "silicon self-grant admin: $CODE $BODY"
call POST /api/blindkey/silicon/permissions "$E" '{"agent_name":"fleet-a1","permission_type":"action:browser_fill","resource":"'$REF2'"}'
[ "$CODE" = 202 ] && [ "$(echo "$BODY" | J status)" = pending ] && ok "owner's browser_fill grant waits for the wallet" || fail "grant request: $CODE $BODY"
GID=$(echo "$BODY" | J grant_request_id)
call POST /api/blindkey/fill/request "$SIL" '{"ref":"'$REF2'","origin":"'$ORIG'"}'; [ "$CODE" = 403 ] && ok "pending grant gives the agent nothing" || fail "pending grant fill: $CODE $BODY"
call GET /api/blindkey/fill/pending "$Wt"
[ "$(echo "$BODY" | J grants.0.intent)" = "grant:$GID" ] && [ "$(echo "$BODY" | J grants.0.agent_name)" = fleet-a1 ] && ok "wallet lists the grant with intent grant:$GID" || fail "wallet grants: $BODY"
call POST /api/blindkey/silicon/grants/$GID/approve "$Wt"; [ "$CODE" = 403 ] && [ "$(echo "$BODY" | J intent)" = "grant:$GID" ] && ok "approving a grant without the PIN → 403 + intent" || fail "grant no pin: $CODE $BODY"
call POST /api/identity/gate/verify "$Wt" '{"gate":"pin","pin":"4321","intent":"fill:'$GID'"}'
call POST /api/blindkey/silicon/grants/$GID/approve "$Wt"; [ "$CODE" = 403 ] && ok "a PIN proof for another intent does not approve a grant" || fail "grant wrong intent: $CODE $BODY"
call POST /api/identity/gate/verify "$Wt" '{"gate":"pin","pin":"4321","intent":"grant:'$GID'"}'; [ "$CODE" = 200 ] || fail "grant verify: $CODE $BODY"
call POST /api/blindkey/silicon/grants/$GID/approve "$Wt"; [ "$CODE" = 200 ] && ok "grant approved with the PIN" || fail "grant approve: $CODE $BODY"
call POST /api/blindkey/silicon/grants/$GID/approve "$Wt"; [ "$CODE" = 409 ] && ok "a decided grant cannot be approved again" || fail "grant re-approve: $CODE $BODY"
call POST /api/blindkey/fill/request "$SIL" '{"ref":"'$REF2'","origin":"'$ORIG'"}'; GR=$(echo "$BODY" | J request_id)
call POST /api/blindkey/fill/redeem "$SIL" '{"request_id":"'$GR'"}'; [ "$CODE" = 200 ] && [ "$(echo "$BODY" | J value)" = "$VAL2" ] && ok "approved grant: the agent fills that login" || fail "granted fill: $CODE $BODY"
call POST /api/blindkey/fill/request "$SIL" '{"ref":"'$REF'","origin":"'$ORIG'"}'; [ "$CODE" = 403 ] && ok "the grant covers only the login it names" || fail "grant scope: $CODE $BODY"
call POST /api/blindkey/silicon/permissions "$E" '{"agent_name":"fleet-a1","permission_type":"action:browser_fill","resource":"*"}'; GID2=$(echo "$BODY" | J grant_request_id)
call POST /api/blindkey/silicon/grants/$GID2/deny "$Wt"; [ "$CODE" = 200 ] && ok "deny a grant (no PIN needed)" || fail "grant deny: $CODE $BODY"
call POST /api/blindkey/fill/request "$SIL" '{"ref":"'$REF'","origin":"'$ORIG'"}'; [ "$CODE" = 403 ] && ok "denied grant gives nothing" || fail "denied grant: $CODE $BODY"
call POST /api/blindkey/silicon/grants/$GID2/approve "$SIL"; [ "$CODE" = 403 ] && ok "a silicon cannot decide grants" || fail "silicon decides grant: $CODE $BODY"

# ── re-audit 771caab: token reset drops fill grants; agents fill standard-depth logins only ──
call POST /api/blindkey/silicon/token/reset "$SIL" '{"agent_name":"fleet-a1"}'; [ "$CODE" = 403 ] && ok "a silicon cannot reset an agent's token" || fail "silicon reset: $CODE $BODY"
call DELETE /api/blindkey/silicon/permissions "$SIL" '{"agent_name":"fleet-a1","permission_type":"action:browser_fill","resource":"'$REF2'"}'; [ "$CODE" = 403 ] && ok "a silicon cannot revoke grants" || fail "silicon revoke: $CODE $BODY"
call POST /api/blindkey/silicon/token/reset "$E" '{"agent_name":"fleet-a1"}'
NSIL=$(echo "$BODY" | J token); [ "$CODE" = 200 ] && [ "$(echo "$BODY" | J browser_fill_grants_revoked)" = 1 ] && ok "token reset revokes the agent's fill grants" || fail "reset: $CODE $(echo "$BODY" | J browser_fill_grants_revoked)"
call POST /api/blindkey/fill/request "$NSIL" '{"ref":"'$REF2'","origin":"'$ORIG'"}'; [ "$CODE" = 403 ] && ok "the re-keyed agent cannot fill until granted again" || fail "re-keyed fill: $CODE $BODY"
SIL=$NSIL
call POST /api/blindkey/store "$E" '{"name":"deep-login","value":"deep-value-1","secret_type":"password","origins":["'$ORIG'"]}'; DREF=$(echo "$BODY" | J ref)
SQL "UPDATE blindkey_secrets SET security_depth = 'elevated' WHERE ref_code = '$DREF'"
call POST /api/blindkey/silicon/permissions "$E" '{"agent_name":"fleet-a1","permission_type":"action:browser_fill","resource":"'$DREF'"}'; [ "$CODE" = 403 ] && ok "no grant request for a login that needs more than the PIN" || fail "deep grant: $CODE $BODY"
SQL "INSERT INTO silicon_permissions (agent_name, permission_type, resource) VALUES ('fleet-a1', 'action:browser_fill', '*')"
call POST /api/blindkey/fill/request "$SIL" '{"ref":"'$DREF'","origin":"'$ORIG'"}'; [ "$CODE" = 403 ] && ok "a * grant does not cover a login raised above standard depth" || fail "deep fill: $CODE $BODY"
SQL "UPDATE silicon_permissions SET status = 'revoked' WHERE agent_name = 'fleet-a1' AND resource = '*'"
call POST /api/blindkey/silicon/permissions "$E" '{"agent_name":"fleet-a1","permission_type":"action:browser_fill","resource":"agent-login"}'
[ "$CODE" = 202 ] && [ "$(echo "$BODY" | J resource)" = "$REF2" ] && ok "a grant asked by name is stored by ref" || fail "grant by name: $CODE $BODY"
call POST /api/blindkey/silicon/grants/$(echo "$BODY" | J grant_request_id)/deny "$Wt"

# ── re-audit cf93dd9: a waiting grant does not survive a re-key ──
call POST /api/blindkey/silicon/permissions "$E" '{"agent_name":"fleet-a1","permission_type":"action:browser_fill","resource":"'$REF2'"}'; PG=$(echo "$BODY" | J grant_request_id)
call POST /api/blindkey/silicon/token/reset "$E" '{"agent_name":"fleet-a1"}'; SIL=$(echo "$BODY" | J token)
call POST /api/identity/gate/verify "$Wt" '{"gate":"pin","pin":"4321","intent":"grant:'$PG'"}'
call POST /api/blindkey/silicon/grants/$PG/approve "$Wt"; [ "$CODE" = 409 ] && ok "a grant asked before a token reset cannot be approved after it" || fail "pending grant after reset: $CODE $BODY"
call POST /api/blindkey/fill/request "$SIL" '{"ref":"'$REF2'","origin":"'$ORIG'"}'; [ "$CODE" = 403 ] && ok "…and the re-keyed agent gets nothing" || fail "re-key fill: $CODE $BODY"
call POST /api/blindkey/silicon/permissions "$E" '{"agent_name":"fleet-a1","permission_type":"action:browser_fill","resource":"'$REF2'"}'; PG=$(echo "$BODY" | J grant_request_id)
SQL "UPDATE silicon_agents SET token_hash = 'rekeyed-elsewhere' WHERE agent_name = 'fleet-a1'"
call POST /api/identity/gate/verify "$Wt" '{"gate":"pin","pin":"4321","intent":"grant:'$PG'"}'
call POST /api/blindkey/silicon/grants/$PG/approve "$Wt"; [ "$CODE" = 409 ] && ok "approval checks the agent's token, whatever re-keyed it" || fail "token-bound grant: $CODE $BODY"
call POST /api/blindkey/store "$E" '{"name":"'$REF2'","value":"decoy-1","secret_type":"password","origins":["https://evil.example.net"]}'
call POST /api/blindkey/silicon/token/reset "$E" '{"agent_name":"fleet-a1"}'; SIL=$(echo "$BODY" | J token)
SQL "INSERT INTO silicon_permissions (agent_name, permission_type, resource) VALUES ('fleet-a1', 'action:browser_fill', '$REF2')"
call GET "/api/blindkey/fill/candidates?origin=https://evil.example.net" "$SIL"; [ "$(echo "$BODY" | J candidates)" = "[]" ] && ok "a grant by ref does not match a login named like that ref" || fail "ref/name collision: $BODY"

# ── website logins keep their binding (review should-fix 3+4) ──
CTX(){ python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); print(c.execute('SELECT COUNT(*) FROM blindkey_contexts x JOIN blindkey_secrets s ON s.id=x.secret_id WHERE s.name=?', (sys.argv[2],)).fetchone()[0])" "$DB_PATH" "$1"; }
call POST /api/blindkey/store "$E" '{"name":"agent-login","value":"changed-pass-1","secret_type":"password"}'
[ "$CODE" = 200 ] && [ "$(CTX agent-login)" = 0 ] && ok "re-storing a website login without origins adds no default context" || fail "re-store context: $CODE ctx=$(CTX agent-login)"
call POST /api/blindkey/store "$E" '{"name":"rot","value":"old-pass-1","secret_type":"password","origins":["'$ORIG'"],"login":"r@example.com"}'
call POST /api/blindkey/rotate "$E" '{"name":"rot","new_value":"new-pass-1"}'; [ "$CODE" = 200 ] || fail "rotate: $CODE $BODY"
call GET "/api/blindkey/fill/candidates?origin=$ORIG" "$E"
python3 -c 'import json,sys; c=json.load(sys.stdin)["candidates"]; r=[x for x in c if x["name"].startswith("rot")]; sys.exit(0 if len(r)==1 and r[0]["ref"] and r[0]["username"]=="r@example.com" else 1)' <<<"$BODY" && ok "after rotate: one candidate, the new version, origins and login carried" || fail "rotate candidates: $BODY"
RREF=$(python3 -c 'import json,sys; print([x["ref"] for x in json.load(sys.stdin)["candidates"] if x["name"].startswith("rot")][0])' <<<"$BODY")
call POST /api/blindkey/fill/request "$E" '{"ref":"'$RREF'","origin":"'$ORIG'"}'; [ "$CODE" = 201 ] && ok "the rotated login is fillable by its ref" || fail "rotated request: $CODE $BODY"
call POST /api/blindkey/fill/request "$E" '{"name":"rot","origin":"'$ORIG'"}'; [ "$CODE" = 404 ] && ok "the superseded version is not fillable during the grace period" || fail "old version fill: $CODE $BODY"

# ── labels, pending cap, rate limit (review should-fix 5, nits) ──
call POST /api/blindkey/fill/request "$E" '{"ref":"'$REF'","origin":"'$ORIG'","client_label":"Chrome‮​moorhsalf"}'
call GET /api/blindkey/fill/pending "$Wt"
python3 -c 'import json,sys; ls=[r["client_label"] for r in json.load(sys.stdin)["requests"]]; sys.exit(0 if "Chromemoorhsalf" in ls and not any(ch in "".join(ls) for ch in "‮​") else 1)' <<<"$BODY" && ok "client_label loses bidi and zero-width characters" || fail "label: $BODY"
for i in $(seq 1 25); do call POST /api/blindkey/fill/request "$E" '{"ref":"'$REF'","origin":"'$ORIG'"}'; [ "$CODE" = 429 ] && break; done
call GET /api/blindkey/fill/pending "$Wt"; NP=$(python3 -c 'import json,sys; print(len(json.load(sys.stdin)["requests"]))' <<<"$BODY")
call POST /api/blindkey/fill/request "$E" '{"ref":"'$REF'","origin":"'$ORIG'"}'
[ "$CODE" = 429 ] && [ "$NP" = 20 ] && ok "at most 20 fill requests wait at once" || fail "pending cap: $CODE pending=$NP"
for i in $(seq 1 505); do curl -s -o /dev/null "$API/api/blindkey/fill/pending" -H "Authorization: Bearer $Wt"; done
call GET /api/blindkey/list "$E"; [ "$CODE" = 200 ] && ok "500+ fill polls do not exhaust the standard limit (/list still 200)" || fail "rate limit shared: $CODE"

# ── withdraw by the asking session; re-saving a deleted name (extension re-audit 2026-10-25) ──
call GET /api/blindkey/fill/pending "$Wt"   # the cap check above left 20 waiting: clear them first
for f in $(python3 -c 'import json,sys; print(" ".join(str(r["id"]) for r in json.load(sys.stdin)["requests"]))' <<<"$BODY"); do call POST /api/blindkey/fill/$f/deny "$Wt"; done
call POST /api/blindkey/fill/request "$E" '{"ref":"'$REF'","origin":"'$ORIG'"}'; WR=$(echo "$BODY" | J request_id)
call POST /api/blindkey/fill/withdraw "$Wt" '{"request_id":"'$WR'"}'; [ "$CODE" = 404 ] && ok "another session cannot withdraw the request" || fail "withdraw other session: $CODE $BODY"
call POST /api/blindkey/fill/withdraw "$E" '{"request_id":"'$WR'"}'; [ "$CODE" = 200 ] && [ "$(echo "$BODY" | J status)" = withdrawn ] && ok "the asking session withdraws its request" || fail "withdraw: $CODE $BODY"
call GET /api/blindkey/fill/pending "$Wt"; [ "$(echo "$BODY" | J requests)" = "[]" ] && ok "a withdrawn request leaves the wallet" || fail "withdrawn still listed: $BODY"
call POST /api/blindkey/fill/redeem "$E" '{"request_id":"'$WR'"}'; [ "$CODE" = 410 ] && [ "$(echo "$BODY" | J error)" = withdrawn ] && ok "a withdrawn request cannot be redeemed" || fail "redeem withdrawn: $CODE $BODY"
call POST /api/blindkey/store "$E" '{"name":"gone-login","value":"first-1","secret_type":"password","origins":["'$ORIG'"]}'
call DELETE /api/blindkey/delete "$E" '{"name":"gone-login"}'; [ "$CODE" = 200 ] || fail "delete: $CODE $BODY"
call POST /api/blindkey/store "$E" '{"name":"gone-login","value":"second-2","secret_type":"password","origins":["'$ORIG'"]}'
call GET "/api/blindkey/fill/candidates?origin=$ORIG" "$E"
python3 -c 'import json,sys; sys.exit(0 if any(c["name"]=="gone-login" for c in json.load(sys.stdin)["candidates"]) else 1)' <<<"$BODY" && ok "re-saving a deleted login's name makes a live, fillable entry" || fail "dead-name store: $BODY"

# ── dead and rotated names (PR #18 review) ──
call POST /api/blindkey/store "$E" '{"name":"tw","value":"tw-1","secret_type":"password"}'
TWID=$(python3 -c "import sqlite3,sys; print(sqlite3.connect(sys.argv[1]).execute(\"SELECT id FROM blindkey_secrets WHERE name='tw'\").fetchone()[0])" "$DB_PATH")
call DELETE /api/blindkey/delete "$E" '{"name":"tw"}'
call POST /api/blindkey/store "$E" '{"name":"tw~'$TWID'","value":"squatter","secret_type":"password"}'
call POST /api/blindkey/store "$E" '{"name":"tw","value":"tw-2","secret_type":"password"}'; [ "$CODE" = 200 ] && ok "a live row named <name>~<id> cannot block re-storing <name>" || fail "squat: $CODE $BODY"
call POST /api/blindkey/store "$E" '{"name":"aws","value":"aws-1","secret_type":"api_key"}'
call POST /api/blindkey/rotate "$E" '{"name":"aws","new_value":"aws-2"}'
call POST /api/blindkey/store "$E" '{"name":"aws","value":"aws-x","secret_type":"api_key"}'
[ "$CODE" = 409 ] && echo "$BODY" | grep -q aws_v2 && ok "storing a name in its rotation grace → 409 naming the current version" || fail "rotating store: $CODE $BODY"
SQL "UPDATE blindkey_secrets SET status = 'retired' WHERE name = 'aws'"
call POST /api/blindkey/store "$E" '{"name":"aws","value":"aws-y","secret_type":"api_key"}'
[ "$CODE" = 409 ] && echo "$BODY" | grep -q aws_v2 && ok "storing a rotated-away name → 409 naming the current version (no unreachable twin)" || fail "retired store: $CODE $BODY"
call POST /api/blindkey/store "$E" '{"name":"aws_v2","value":"aws-z","secret_type":"api_key"}'; [ "$CODE" = 200 ] && ok "storing under the current version works" || fail "current version store: $CODE $BODY"

# ── rotation link, not name patterns (PR #18 re-review) ──
call POST /api/blindkey/store "$E" '{"name":"stripe","value":"s-1","secret_type":"api_key"}'
call POST /api/blindkey/store "$E" '{"name":"stripe_v2","value":"s2-1","secret_type":"api_key"}'
call DELETE /api/blindkey/delete "$E" '{"name":"stripe_v2"}'
call POST /api/blindkey/store "$E" '{"name":"stripe_v2","value":"s2-2","secret_type":"api_key"}'; [ "$CODE" = 200 ] && ok "an unrelated deleted <name>_v2 can be stored again" || fail "stripe_v2: $CODE $BODY"
call POST /api/blindkey/store "$E" '{"name":"k","value":"k-1","secret_type":"api_key"}'
call POST /api/blindkey/rotate "$E" '{"name":"k","new_value":"k-2"}'; call POST /api/blindkey/rotate "$E" '{"name":"k","new_value":"k-3"}'
SQL "UPDATE blindkey_secrets SET status = 'retired' WHERE name IN ('k', 'k_v2')"
call DELETE /api/blindkey/delete "$E" '{"name":"k_v3"}'
call POST /api/blindkey/store "$E" '{"name":"k","value":"k-new","secret_type":"api_key"}'; [ "$CODE" = 200 ] && ok "a name whose whole lineage is dead can be stored again" || fail "k store: $CODE $BODY"
call POST /api/blindkey/rotate "$E" '{"name":"k","new_value":"k-new-2"}'; [ "$CODE" = 200 ] && ok "…and rotated (dead k_v2 moved aside, no UNIQUE 500)" || fail "k rotate: $CODE $BODY"
call POST /api/blindkey/store "$E" '{"name":"z","value":"z-1","secret_type":"api_key"}'
call POST /api/blindkey/rotate "$E" '{"name":"z","new_value":"z-2"}'
call POST /api/blindkey/store "$E" '{"name":"z_v3","value":"user-named","secret_type":"api_key"}'
call POST /api/blindkey/rotate "$E" '{"name":"z","new_value":"z-3"}'
[ "$CODE" = 200 ] && python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); n={r[0]:r[1] for r in c.execute(\"SELECT name,status FROM blindkey_secrets WHERE name LIKE 'z%'\")}; sys.exit(0 if n.get('z_v3')=='active' and n.get('z_v4')=='active' else 1)" "$DB_PATH" && ok "rotation steps over a live secret named like its next version" || fail "z rotate: $CODE $BODY"

# ── where the value appeared ──
AFTER=$(grep -c -- "$VAL" "$ALL")
[ "$BEFORE" = 0 ] && [ "$AFTER" = 2 ] && ok "the value appears in exactly the two redeem replies, nowhere else" || fail "value appeared before=$BEFORE after=$AFTER"
python3 - "$DB_PATH" <<'PY' && ok "security events: secret_filled, fill_origin_refused, fill_blocked_silicon" || fail "security events missing"
import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); have={r[0] for r in c.execute("SELECT DISTINCT event_type FROM demipass_security_events")}
missing={'secret_filled','fill_origin_refused','fill_blocked_silicon'}-have; print('missing:',missing) if missing else None; sys.exit(1 if missing else 0)
PY
grep -q -- "$VAL" "$S/server.log" && fail "the value reached the server log" || ok "the value never reached the server log"
echo "$fails failure(s)"; [ "$fails" = 0 ]
