#!/bin/bash
# Agent token requests (silicon_token_requests.js), on a throwaway DB:
#   - a fleet member files a request for an agent's token (with its own claim_secret_hash, or gets a claim secret);
#     an outsider cannot; a network-joined agent, an admin scope, a 4th waiting request are refused;
#   - only the fleet owner sees and decides it, with the PIN (silicon-token:<id>); the claim answers 202 before;
#   - the claim hands the token over once (it works as the agent), a wrong secret is 404, a second claim 410;
#   - a denied request cannot be claimed; an approved token nobody claims in time is revoked.
# No network beyond 127.0.0.1.
set -u
W=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
S=$(mktemp -d /tmp/dustforge-silreq-smoke.XXXXXX)
PORT=${PORT:-3794}; API=http://127.0.0.1:$PORT
[ -d "$W/node_modules" ] || export NODE_PATH=${NODE_PATH:-/home/flimflam/project/dustforge/node_modules}
export IDENTITY_MASTER_KEY=$(python3 -c 'import secrets;print(secrets.token_hex(32))') DB_PATH=$S/dustforge.db PORT \
  STALWART_HOST=127.0.0.1 STALWART_PORT=1 SMTP_RELAY_HOST= SMTP_HOST=127.0.0.1 SMTP_PORT=9
cd "$W"
node server.js >"$S/server.log" 2>&1 & SRV=$!
trap 'kill $SRV 2>/dev/null; rm -rf "$S"' EXIT
for i in $(seq 1 40); do curl -s -o /dev/null "$API/api/health" && break; sleep 0.5; done
kill -0 $SRV 2>/dev/null || { echo "server died:"; tail -5 "$S/server.log"; exit 1; }
H=$(printf '%s' hunter22 | sha256sum | cut -d' ' -f1)
node -e '
const identity = require("./identity"); const Database = require("better-sqlite3"); const db = new Database(process.env.DB_PATH);
for (const u of ["owner-a", "brainy", "outsider-x", "conduit", "netjoin", "sib"]) { const id = identity.createIdentity(); const enc = id.encrypted_private_key || id.encryptedPrivateKey;
  db.prepare("INSERT INTO identity_wallets (did, username, email, encrypted_private_key, balance_cents, password_hash) VALUES (?, ?, ?, ?, 100000, ?)").run(id.did, u, u + "@dustforge.com", enc, process.argv[1]);
  db.prepare("INSERT INTO identity_transactions (did, amount_cents, type, description, balance_after) VALUES (?, 100000, ?, ?, 100000)").run(id.did, "topup", "smoke"); }' "$H"
fails=0; ok(){ echo "ok   $*"; }; fail(){ echo "FAIL $*"; fails=$((fails+1)); }
J(){ python3 -c 'import json,sys; d=json.load(sys.stdin); v=d
for k in sys.argv[1].split("."):
    v = v[int(k)] if isinstance(v, list) else (v or {}).get(k)
print(v)' "$1"; }
Q(){ python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); r=c.execute(sys.argv[2]).fetchone(); print(r[0] if r else '')" "$DB_PATH" "$1"; }
X(){ python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute(sys.argv[2]); c.commit()" "$DB_PATH" "$1"; }
call(){ local m=$1 p=$2 t=$3 b=${4:-}
  BODY=$(curl -s -o - -w '\n%{http_code}' -X "$m" "$API$p" -H 'Content-Type: application/json' ${t:+-H "Authorization: Bearer $t"} ${b:+-d "$b"})
  CODE=${BODY##*$'\n'}; BODY=${BODY%$'\n'*}; }
login(){ call POST /api/identity/auth-fingerprint "" '{"username":"'$1'","password":"hunter22","scope":"transact","expires_in":"1h"}'; echo "$BODY" | J token; }
A=$(login owner-a); B=$(login brainy); O=$(login outsider-x)
call POST /api/identity/pin "$A" '{"pin":"4321","password":"hunter22"}'
call POST /api/fleet/create "$A" '{"name":"Aaron Agents","slug":"aaron-agents"}'; [ "$CODE" = 200 ] || fail "fleet create: $CODE $BODY"
node -e '
const Database = require("better-sqlite3"); const db = new Database(process.env.DB_PATH); const fb = require("./fleet_billing");
const fid = db.prepare("SELECT id FROM fleets WHERE slug = ?").get("aaron-agents").id;
const did = u => db.prepare("SELECT did FROM identity_wallets WHERE username = ?").get(u).did;
db.prepare("INSERT OR IGNORE INTO fleet_members (fleet_id, member_did, role) VALUES (?, ?, ?)").run(fid, did("brainy"), "agent");
// brainy joined by consent (network accept): an active fleet_silicons row. outsider-x is only "invited" (fleet_members, no consent).
fb.upsertSilicon(db, { fleetId: fid, memberDid: did("brainy"), handle: "brainy" }); db.prepare("UPDATE fleet_silicons SET joined_via = ? WHERE handle = ?").run("network", "brainy");
db.prepare("INSERT OR IGNORE INTO fleet_members (fleet_id, member_did, role) VALUES (?, ?, ?)").run(fid, did("outsider-x"), "agent");
for (const h of ["conduit", "netjoin", "sib"]) { fb.upsertSilicon(db, { fleetId: fid, memberDid: did(h), handle: h }); db.prepare("UPDATE fleet_silicons SET created_by_fleet = 1 WHERE handle = ?").run(h); }
db.prepare("UPDATE fleet_silicons SET joined_via = ? WHERE handle = ?").run("network", "netjoin");'
PIN(){ call POST /api/identity/gate/verify "$A" '{"gate":"pin","pin":"4321","intent":"'$1'"}'; }
R=/api/fleet/aaron-agents/silicons/conduit/token-requests

umask 077; SECRET=$(python3 -c 'import secrets;print(secrets.token_urlsafe(24))'); SH=$(printf '%s' "$SECRET" | sha256sum | cut -d' ' -f1)
call POST $R "$O" '{"label":"x"}'; [ "$CODE" = 403 ] && ok "a wallet only 'invited' (fleet_members, no consent) cannot ask (threat model item 17)" || fail "invited outsider: $CODE $BODY"
call POST /api/fleet/aaron-agents/silicons/netjoin/token-requests "$B" '{}'; [ "$CODE" = 403 ] && ok "an agent that joined through the network keeps its own key: refused" || fail "network: $CODE"
call POST $R "$B" '{"scope":"admin"}'; [ "$CODE" = 400 ] && ok "admin scope → 400" || fail "admin scope: $CODE"
call POST $R "$B" '{"claim_secret_hash":"xyz"}'; [ "$CODE" = 400 ] && ok "a malformed claim_secret_hash → 400" || fail "bad hash: $CODE"
call POST $R "$B" '{"scope":"transact","expires_in":"30d","label":"conduit container","claim_secret_hash":"'$SH'"}'
R1=$(echo "$BODY" | J request_id)
[ "$CODE" = 202 ] && [ "$(echo "$BODY" | J claim_secret)" = None ] && ok "a fleet-mate files it with its own claim_secret_hash: 202, no secret handed out" || fail "file: $CODE $BODY"
call POST $R "$A" '{"scope":"read","expires_in":"1h"}'; R2=$(echo "$BODY" | J request_id); C2=$(echo "$BODY" | J claim_secret)
[ "$CODE" = 202 ] && [ ${#C2} -ge 30 ] && ok "without a hash, a claim secret is generated and returned once" || fail "file 2: $CODE $BODY"

call POST /api/silicon-token-requests/$R1/claim "" '{"claim_secret":"'$SECRET'"}'; [ "$CODE" = 202 ] && ok "claim before the owner decides → 202 pending" || fail "early claim: $CODE $BODY"
call POST /api/silicon-token-requests/$R1/claim "" '{"claim_secret":"nope"}'; [ "$CODE" = 404 ] && ok "a wrong claim secret → 404" || fail "wrong secret: $CODE"
call GET /api/silicon-token-requests "$A"; [ "$(echo "$BODY" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["requests"]))')" = 2 ] && [ "$(echo "$BODY" | J requests.1.says_it_is)" = "conduit container" ] \
  && ok "the owner sees both, with what the asker says it is for" || fail "list: $BODY"
call GET /api/silicon-token-requests "$B"; [ "$(echo "$BODY" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["requests"]))')" = 0 ] && ok "the asker sees none to decide" || fail "asker list: $BODY"
call GET /api/silicon-token-requests "$A"; [ "$(echo "$BODY" | J requests.1.requester_role)" = outside_agent ] && [ "$(echo "$BODY" | J requests.0.requester_role)" = owner ] \
  && ok "the card says when ANOTHER agent asks for this agent's token" || fail "role: $BODY"
call POST $R "$B" '{"expires_in":"10m"}'; [ "$CODE" = 400 ] && ok "a lifetime under an hour → 400" || fail "10m: $CODE"
call POST /api/silicon-token-requests/$R1/approve "$B" '{}'; [ "$CODE" = 404 ] && ok "the asker cannot approve" || fail "asker approve: $CODE"
call POST /api/silicon-token-requests/$R1/approve "$A" '{}'
[ "$CODE" = 403 ] && [ "$(echo "$BODY" | J intent)" = "silicon-token:$R1" ] && ok "approving needs the PIN (intent silicon-token:$R1)" || fail "no pin: $CODE $BODY"
PIN "silicon-token:$R1"; call POST /api/silicon-token-requests/$R1/approve "$A" '{}'; [ "$CODE" = 200 ] && ok "approved with the PIN" || fail "approve: $CODE $BODY"
call POST /api/silicon-token-requests/$R1/claim "" '{"claim_secret":"'$SECRET'"}'
TOK=$(echo "$BODY" | J token)
[ "$CODE" = 200 ] && [ "$(echo "$BODY" | J handle)" = conduit ] && ok "claimed once with the claim secret" || fail "claim: $CODE $(echo "$BODY" | head -c 200)"
SUB=$(python3 -c 'import sys,json,base64; p=sys.argv[1].split(".")[1]; p+="="*(-len(p)%4); print(json.loads(base64.urlsafe_b64decode(p))["sub"])' "$TOK")
[ "$SUB" = "$(Q "SELECT did FROM identity_wallets WHERE username='conduit'")" ] && ok "the token is conduit's" || fail "sub: $SUB"
call GET /api/demipass/list "$TOK"; [ "$CODE" = 200 ] && ok "…and works as conduit" || fail "use: $CODE $BODY"
call POST /api/fleet/aaron-agents/silicons/conduit/token "$TOK" '{}'; [ "$CODE" = 403 ] && ok "…but cannot run the fleet (fleet_owner_mint)" || fail "fleet mint with it: $CODE"
call POST /api/silicon-token-requests/$R1/claim "" '{"claim_secret":"'$SECRET'"}'; [ "$CODE" = 410 ] && ok "a second claim → 410" || fail "reclaim: $CODE"
# #99 review M1: an agent token reads no decided-approval history and no 30-day scan-request history
call GET "/api/demipass/approvals?limit=200" "$TOK"; [ "$CODE" = 200 ] && [ "$(echo "$BODY" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(len(d["recent"]), len(d["incoming"]))')" = "0 0" ] && ! echo "$BODY" | grep -q '"call"\|"binding"\|"unwrap"\|"summary"\|"purpose"' && ok "an agent token gets no approval history (recent, incoming empty), limit or not; outgoing without calls" || fail "agent approvals: $CODE $(echo "$BODY" | head -c 200)"
call GET "/api/demipass/leak-scan/token-requests?all=1" "$TOK"; [ "$CODE" = 200 ] && ! echo "$BODY" | grep -q '"status":"\(claimed\|denied\|expired\|approved\)"' && ok "…and ?all=1 shows it only what waits" || fail "agent scan history: $BODY"
call POST /api/fleet/aaron-agents/silicons/sib/token-requests "$TOK" '{}'
[ "$CODE" = 403 ] && [ "$(Q "SELECT COUNT(*) FROM silicon_token_requests WHERE handle='sib'")" = 0 ] && ok "a fleet-minted token cannot ask for a fleet-created sibling's token" || fail "minted asks: $CODE $BODY"
call GET /api/silicon-token-requests "$TOK"; [ "$CODE" = 403 ] && ok "…nor list the owner's requests" || fail "minted lists: $CODE"
[ "$(Q "SELECT sealed FROM silicon_token_requests WHERE id=$R1")" = None ] && ok "nothing of the token is kept after the claim" || fail "sealed kept"

call POST /api/silicon-token-requests/$R2/deny "$A" '{}'; [ "$CODE" = 200 ] || fail "deny: $CODE"
call POST /api/fleet/aaron-agents/silicons/conduit/token-requests/$R2/claim "" '{"claim_secret":"'$C2'"}'; [ "$CODE" = 410 ] && ok "a denied request cannot be claimed (fleet path too)" || fail "denied claim: $CODE $BODY"

# An approved token nobody claims in time is revoked.
call POST $R "$A" '{"expires_in":"9999d"}'; R3=$(echo "$BODY" | J request_id); C3=$(echo "$BODY" | J claim_secret)
[ "$(Q "SELECT expires_in FROM silicon_token_requests WHERE id=$R3")" = 30d ] && ok "9999d asked: the card and the token say 30d (the transact ceiling)" || fail "cap: $(Q "SELECT expires_in FROM silicon_token_requests WHERE id=$R3")"
PIN "silicon-token:$R3"; call POST /api/silicon-token-requests/$R3/approve "$A" '{}'; [ "$CODE" = 200 ] || fail "approve 3: $CODE $BODY"
JTI=$(Q "SELECT token_jti FROM silicon_token_requests WHERE id=$R3")
X "UPDATE silicon_token_requests SET expires_at='2000-01-01T00:00:00.000Z' WHERE id=$R3"
call GET /api/silicon-token-requests "$A"
[ "$(Q "SELECT status FROM silicon_token_requests WHERE id=$R3")" = expired ] && [ "$(Q "SELECT revoked FROM issued_tokens WHERE jti='$JTI'")" = 1 ] \
  && ok "unclaimed past its hour: expired, and its token revoked" || fail "expiry: $(Q "SELECT status FROM silicon_token_requests WHERE id=$R3") revoked=$(Q "SELECT revoked FROM issued_tokens WHERE jti='$JTI'")"
call POST /api/silicon-token-requests/$R3/claim "" '{"claim_secret":"'$C3'"}'; [ "$CODE" = 410 ] && ok "…and cannot be claimed" || fail "expired claim: $CODE"

for i in 1 2 3; do call POST $R "$B" '{}'; done; call POST $R "$B" '{}'
[ "$CODE" = 429 ] && ok "a 4th waiting request for one agent → 429" || fail "cap: $CODE"

[ $fails -gt 0 ] && { echo "--- server.log"; grep -i -m5 "error" "$S/server.log"; }
# #79 review: the filer must still be in the fleet when the owner approves; an outside wallet is labelled as one.
call POST /api/fleet/aaron-agents/silicons/sib/token-requests "$B" '{"scope":"read","expires_in":"1h"}'; RX=$(echo "$BODY" | J request_id)
call GET /api/silicon-token-requests "$A"; echo "$BODY" | python3 -c 'import json,sys; d=json.load(sys.stdin); r=[x for x in (d.get("requests") or []) if x.get("id")==int(sys.argv[1])]; sys.exit(0 if r and r[0].get("requester_role")=="outside_agent" else 1)' "$RX" \
  && ok "a network-joined filer is shown as a wallet the fleet did not create" || fail "role: $BODY"
python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute(\"UPDATE fleet_silicons SET status='removed' WHERE handle='brainy'\"); c.commit()" "$DB_PATH"
PIN "silicon-token:$RX"; call POST /api/silicon-token-requests/$RX/approve "$A" '{}'
[ "$CODE" = 409 ] && ok "a filer that has left the fleet: its request cannot be approved" || fail "left filer approve: $CODE $BODY"
echo "$fails failure(s)"; exit $(( fails > 0 ))
