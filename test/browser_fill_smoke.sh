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

# ── where the value appeared ──
AFTER=$(grep -c -- "$VAL" "$ALL")
[ "$BEFORE" = 0 ] && [ "$AFTER" = 2 ] && ok "the value appears in exactly the two redeem replies, nowhere else" || fail "value appeared before=$BEFORE after=$AFTER"
python3 - "$DB_PATH" <<'PY' && ok "security events: secret_filled, fill_origin_refused, fill_blocked_silicon" || fail "security events missing"
import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); have={r[0] for r in c.execute("SELECT DISTINCT event_type FROM demipass_security_events")}
missing={'secret_filled','fill_origin_refused','fill_blocked_silicon'}-have; print('missing:',missing) if missing else None; sys.exit(1 if missing else 0)
PY
grep -q -- "$VAL" "$S/server.log" && fail "the value reached the server log" || ok "the value never reached the server log"
echo "$fails failure(s)"; [ "$fails" = 0 ]
