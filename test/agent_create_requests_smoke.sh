#!/bin/bash
# Agent creation requests (silicon_token_requests.js with `create`), on a throwaway DB with a fake Stalwart:
#   - a fleet member asks the owner to create a new agent and give it a token; an outsider cannot; a handle that
#     exists, a second request for the same handle, a bad `create` and a fleet that cannot pay are refused;
#   - the owner sees "create" on the card and approves with the PIN; the fleet creates the agent exactly like the
#     owner's own create (created_by_fleet, charged like a provision) and mints its first token;
#   - the claim hands over the token and the DID once (never the mailbox password: PR #84 review); it works as the agent;
#   - a handle taken meanwhile, or a mailbox that cannot be made, leaves no agent, no charge and the request waiting;
#   - PR #84 review: a create racing the request is charged once; a claim while creating waits (202); an interrupted
#     creation is ended by the sweep; a non-owner learns nothing about the payer.
# No network beyond 127.0.0.1.
set -u
W=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
S=$(mktemp -d /tmp/dustforge-agentcreate-smoke.XXXXXX)
PORT=${PORT:-3795}; API=http://127.0.0.1:$PORT; SPORT=${SPORT:-3796}
[ -d "$W/node_modules" ] || export NODE_PATH=${NODE_PATH:-/home/flimflam/project/dustforge/node_modules}
# A fake Stalwart: POST /api/principal makes a mailbox unless $S/stalwart-down exists.
cat > "$S/stalwart.py" <<'PY'
import http.server, json, os, sys
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_POST(self):
        n = int(self.headers.get('Content-Length') or 0); self.rfile.read(n)
        if os.path.exists(os.path.join(sys.argv[2], 'stalwart-slow')):
            import time; time.sleep(4)
        down = os.path.exists(os.path.join(sys.argv[2], 'stalwart-down'))
        body = json.dumps({'error': 'down', 'title': 'stalwart down'} if down else {'data': 4242}).encode()
        self.send_response(500 if down else 200); self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body))); self.end_headers(); self.wfile.write(body)
http.server.ThreadingHTTPServer(('127.0.0.1', int(sys.argv[1])), H).serve_forever()
PY
python3 "$S/stalwart.py" "$SPORT" "$S" & STW=$!
export IDENTITY_MASTER_KEY=$(python3 -c 'import secrets;print(secrets.token_hex(32))') DB_PATH=$S/dustforge.db PORT \
  STALWART_HOST=127.0.0.1 STALWART_PORT=$SPORT SMTP_RELAY_HOST= SMTP_HOST=127.0.0.1 SMTP_PORT=9
cd "$W"
node server.js >"$S/server.log" 2>&1 & SRV=$!
trap 'kill $SRV $STW 2>/dev/null; rm -rf "$S"' EXIT
for i in $(seq 1 40); do curl -s -o /dev/null "$API/api/health" && break; sleep 0.5; done
kill -0 $SRV 2>/dev/null || { echo "server died:"; tail -5 "$S/server.log"; exit 1; }
H=$(printf '%s' hunter22 | sha256sum | cut -d' ' -f1)
node -e '
const identity = require("./identity"); const Database = require("better-sqlite3"); const db = new Database(process.env.DB_PATH);
for (const u of ["owner-a", "brainy", "outsider-x", "conduit"]) { const id = identity.createIdentity(); const enc = id.encrypted_private_key || id.encryptedPrivateKey;
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
fb.upsertSilicon(db, { fleetId: fid, memberDid: did("brainy"), handle: "brainy" }); db.prepare("UPDATE fleet_silicons SET joined_via = ? WHERE handle = ?").run("network", "brainy");
db.prepare("INSERT OR IGNORE INTO fleet_members (fleet_id, member_did, role) VALUES (?, ?, ?)").run(fid, did("outsider-x"), "agent");
fb.upsertSilicon(db, { fleetId: fid, memberDid: did("conduit"), handle: "conduit" }); db.prepare("UPDATE fleet_silicons SET created_by_fleet = 1 WHERE handle = ?").run("conduit");'
PIN(){ call POST /api/identity/gate/verify "$A" '{"gate":"pin","pin":"4321","intent":"'$1'"}'; }
P=/api/fleet/aaron-agents/silicons/provisioner/token-requests
OWNER=$(Q "SELECT did FROM identity_wallets WHERE username='owner-a'")
# Provisions are paid by the fleet's payer: its own wallet when it has one, else the owner (fleet_routes.js createCheck).
PAYER=$(Q "SELECT COALESCE(wallet_did, owner_did) FROM fleets WHERE slug='aaron-agents'")
X "INSERT INTO identity_transactions (did, amount_cents, type, description, balance_after) VALUES ('$PAYER', 50000, 'topup', 'smoke', 50000)"
bal(){ Q "SELECT COALESCE(SUM(amount_cents),0) FROM identity_transactions WHERE did='$PAYER'"; }

# ── filing ──
call POST $P "$O" '{"create":{}}'; [ "$CODE" = 403 ] && ok "a wallet only 'invited' (no consent) cannot ask for a new agent" || fail "invited outsider: $CODE $BODY"
call POST /api/fleet/aaron-agents/silicons/conduit/token-requests "$A" '{"create":{}}'; [ "$CODE" = 409 ] && ok "create for a handle that exists → 409" || fail "existing handle: $CODE $BODY"
call POST $P "$A" '{"create":[1]}'; [ "$CODE" = 400 ] && ok "create must be an object → 400" || fail "bad create: $CODE"
call POST $P "$A" '{"create":{"username":"x!"}}'; [ "$CODE" = 400 ] && ok "a bad username → 400 (checked at filing)" || fail "bad username: $CODE $BODY"
call POST $P "$A" '{}'; [ "$CODE" = 404 ] && ok "without create, an unknown handle stays 404 (no creation by accident)" || fail "no create: $CODE"
call POST $P "$A" '{"create":{"display_name":"LichenOS provisioner"},"scope":"transact","expires_in":"30d","label":"boltcluster provisioning agent"}'
R1=$(echo "$BODY" | J request_id); C1=$(echo "$BODY" | J claim_secret)
[ "$CODE" = 202 ] && [ ${#C1} -ge 30 ] && ok "the owner files 'create @provisioner': 202, a claim secret once" || fail "file: $CODE $BODY"
call POST $P "$B" '{"create":{}}'; [ "$CODE" = 409 ] && ok "a second request to create the same handle → 409" || fail "dup: $CODE $BODY"
call POST /api/fleet/aaron-agents/silicons/helper-two/token-requests "$B" '{"create":{},"scope":"read","expires_in":"1h"}'; R2=$(echo "$BODY" | J request_id); C2=$(echo "$BODY" | J claim_secret)
[ "$CODE" = 202 ] && ok "a consented member (network-joined) may ask too" || fail "member file: $CODE $BODY"
call GET /api/silicon-token-requests "$A"
echo "$BODY" | python3 -c '
import json,sys; d={r["id"]: r for r in json.load(sys.stdin)["requests"]}; r1=d[int(sys.argv[1])]; r2=d[int(sys.argv[2])]
assert r1["creates"] is True and r1["username"]=="provisioner" and r1["display_name"]=="LichenOS provisioner" and r1["cost_dd"]==1000, r1
assert r2["creates"] is True and r2["requester_role"]=="outside_agent", r2' "$R1" "$R2" \
  && ok "the owner's card says create, the mailbox, the cost, and who asks (an outside wallet in red)" || fail "card: $BODY"

# ── approving ──
call POST /api/silicon-token-requests/$R1/approve "$B" '{}'; [ "$CODE" = 404 ] && ok "the asker cannot approve" || fail "asker approve: $CODE"
call POST /api/silicon-token-requests/$R1/approve "$A" '{}'
[ "$CODE" = 403 ] && [ "$(echo "$BODY" | J intent)" = "silicon-token:$R1" ] && ok "approving needs the PIN (silicon-token:$R1)" || fail "no pin: $CODE $BODY"
call POST /api/silicon-token-requests/$R1/claim "" '{"claim_secret":"'$C1'"}'; [ "$CODE" = 202 ] && ok "claim before approval → 202" || fail "early claim: $CODE"
B0=$(bal); PIN "silicon-token:$R1"; call POST /api/silicon-token-requests/$R1/approve "$A" '{}'
NEWDID=$(echo "$BODY" | J created.did)
[ "$CODE" = 200 ] && [ "${NEWDID#did:key:}" != "$NEWDID" ] && ok "approved with the PIN: @provisioner created ($NEWDID)" || fail "approve: $CODE $BODY"
[ "$(Q "SELECT created_by_fleet FROM fleet_silicons WHERE handle='provisioner'")" = 1 ] && [ "$(Q "SELECT COALESCE(joined_via,'') FROM fleet_silicons WHERE handle='provisioner'")" != network ] \
  && ok "…fleet-created (created_by_fleet = 1), like the owner's own create" || fail "created_by_fleet: $(Q "SELECT created_by_fleet, joined_via FROM fleet_silicons WHERE handle='provisioner'")"
[ "$(Q "SELECT provenance FROM identity_transactions WHERE did='$NEWDID' AND type='account_created'")" = fleet_provisioned ] && [ $(( B0 - $(bal) )) = 1000 ] \
  && ok "…charged like a provision (1000 DD from the fleet's payer)" || fail "charge: $B0 → $(bal)"
PIN "silicon-token:$R1"; call POST /api/silicon-token-requests/$R1/approve "$A" '{}'; [ "$CODE" = 409 ] && ok "a second approval makes no second agent → 409" || fail "re-approve: $CODE $BODY"
[ "$(Q "SELECT COUNT(*) FROM identity_wallets WHERE username LIKE 'provisioner%'")" = 1 ] && ok "…one wallet only" || fail "wallets: $(Q "SELECT COUNT(*) FROM identity_wallets WHERE username LIKE 'provisioner%'")"

# ── claiming ──
call POST /api/silicon-token-requests/$R1/claim "" '{"claim_secret":"'$C1'"}'
TOK=$(echo "$BODY" | J token)
[ "$CODE" = 200 ] && [ "$(echo "$BODY" | J created)" = True ] && [ "$(echo "$BODY" | J did)" = "$NEWDID" ] && [ "$(echo "$BODY" | J email)" = provisioner@dustforge.com ] \
  && [ "$(echo "$BODY" | J password_once)" = None ] && ok "claimed once: token and DID — and no mailbox password (it would be a full sign-in)" || fail "claim: $CODE $(echo "$BODY" | head -c 200)"
SUB=$(python3 -c 'import sys,json,base64; p=sys.argv[1].split(".")[1]; p+="="*(-len(p)%4); print(json.loads(base64.urlsafe_b64decode(p))["sub"])' "$TOK")
[ "$SUB" = "$NEWDID" ] && ok "the token is the new agent's" || fail "sub: $SUB"
call GET /api/demipass/list "$TOK"; [ "$CODE" = 200 ] && ok "…and works as @provisioner" || fail "use: $CODE $BODY"
call POST /api/silicon-token-requests/$R1/claim "" '{"claim_secret":"'$C1'"}'; [ "$CODE" = 410 ] && ok "a second claim → 410" || fail "reclaim: $CODE"
[ "$(Q "SELECT sealed FROM silicon_token_requests WHERE id=$R1")" = None ] && ok "nothing of the token or password is kept after the claim" || fail "sealed kept"

# ── the fleet changed meanwhile: nothing is made ──
call POST /api/fleet/aaron-agents/silicons/taken-later/token-requests "$A" '{"create":{}}'; R3=$(echo "$BODY" | J request_id)
node -e '
const Database = require("better-sqlite3"); const db = new Database(process.env.DB_PATH); const fb = require("./fleet_billing");
const fid = db.prepare("SELECT id FROM fleets WHERE slug = ?").get("aaron-agents").id;
fb.upsertSilicon(db, { fleetId: fid, memberDid: db.prepare("SELECT did FROM identity_wallets WHERE username = ?").get("outsider-x").did, handle: "taken-later" });'
PIN "silicon-token:$R3"; call POST /api/silicon-token-requests/$R3/approve "$A" '{}'
[ "$CODE" = 409 ] && [ "$(Q "SELECT COUNT(*) FROM identity_wallets WHERE username='taken-later'")" = 0 ] && ok "a handle taken since the request: 409, no agent made" || fail "taken: $CODE $BODY"

# ── the mailbox cannot be made: no agent, the request waits again ──
touch "$S/stalwart-down"
B1=$(bal); PIN "silicon-token:$R2"; call POST /api/silicon-token-requests/$R2/approve "$A" '{}'
[ "$CODE" != 200 ] && [ "$(Q "SELECT status FROM silicon_token_requests WHERE id=$R2")" = pending ] && [ "$(Q "SELECT COUNT(*) FROM identity_wallets WHERE username='helper-two'")" = 0 ] && [ "$(bal)" = "$B1" ] \
  && ok "mail server down: no agent, no charge, the request waits again ($CODE)" || fail "stalwart down: $CODE $BODY status=$(Q "SELECT status FROM silicon_token_requests WHERE id=$R2")"
rm -f "$S/stalwart-down"
PIN "silicon-token:$R2"; call POST /api/silicon-token-requests/$R2/approve "$A" '{}'; [ "$CODE" = 200 ] && ok "…approved again once it is back" || fail "re-approve: $CODE $BODY"
call POST /api/fleet/aaron-agents/silicons/helper-two/token-requests/$R2/claim "" '{"claim_secret":"'$C2'"}'; [ "$CODE" = 200 ] && [ "$(echo "$BODY" | J scope)" = read ] && ok "…and claimed on the fleet path" || fail "claim 2: $CODE"

# ── PR #84 review: a create racing the request is charged once; a claim while creating waits ──
X "UPDATE fleets SET max_agents = 50 WHERE slug = 'aaron-agents'"
call POST /api/fleet/aaron-agents/silicons/race-a/token-requests "$A" '{"create":{"username":"race-a-req"}}'; R4=$(echo "$BODY" | J request_id); C4=$(echo "$BODY" | J claim_secret)
touch "$S/stalwart-slow"; B2=$(bal); PIN "silicon-token:$R4"
( call POST /api/silicon-token-requests/$R4/approve "$A" '{}'; echo "$CODE $BODY" > "$S/approve4" ) & AP=$!
sleep 1.5
call POST /api/silicon-token-requests/$R4/claim "" '{"claim_secret":"'$C4'"}'; [ "$CODE" = 202 ] && [ "$(echo "$BODY" | J status)" = creating ] && ok "a claim while the agent is being created → 202 (keep polling)" || fail "creating claim: $CODE $BODY"
call POST /api/fleet/aaron-agents/silicons "$A" '{"handle":"race-a","create":{"username":"race-a-own"}}'; OWNCODE=$CODE
wait $AP; rm -f "$S/stalwart-slow"; read -r ACODE ABODY < "$S/approve4"
AGENTS=$(Q "SELECT COUNT(*) FROM fleet_silicons WHERE handle='race-a'"); ORPH=$(Q "SELECT COUNT(*) FROM identity_wallets w WHERE username LIKE 'race-a-%' AND NOT EXISTS (SELECT 1 FROM fleet_silicons s WHERE s.member_did = w.did)")
# Whichever finishes first makes the agent; the other is refused inside its own transaction, uncharged. The request
# is approved if it won, and waits again if it lost.
ST4=$(Q "SELECT status FROM silicon_token_requests WHERE id=$R4")
{ { [ "$ACODE" = 200 ] && [ "$ST4" = approved ] && [ "$OWNCODE" = 409 ]; } || { [ "$ACODE" != 200 ] && [ "$ST4" = pending ] && [ "$OWNCODE" = 200 ]; }; } \
  && [ "$AGENTS" = 1 ] && [ "$ORPH" = 0 ] && [ $(( B2 - $(bal) )) = 1000 ] \
  && ok "a create racing the request: one agent, charged once, no orphan wallet, the loser refused uncharged (owner $OWNCODE, request $ACODE → $ST4)" || fail "race: agents=$AGENTS orphans=$ORPH charged=$(( B2 - $(bal) )) own=$OWNCODE approve=$ACODE $ABODY status=$(Q "SELECT status FROM silicon_token_requests WHERE id=$R4")"

# ── PR #84 review: an interrupted creation does not stay stuck ──
call POST /api/fleet/aaron-agents/silicons/crash-a/token-requests "$A" '{"create":{}}'; R5=$(echo "$BODY" | J request_id)
X "UPDATE silicon_token_requests SET status='creating', decided_at='2000-01-01T00:00:00.000Z' WHERE id=$R5"
call GET /api/silicon-token-requests "$A"
[ "$(Q "SELECT status FROM silicon_token_requests WHERE id=$R5")" = expired ] && ok "a creation interrupted mid-way (no agent) is ended by the sweep: expired" || fail "stuck: $(Q "SELECT status FROM silicon_token_requests WHERE id=$R5")"
call POST /api/fleet/aaron-agents/silicons/crash-a/token-requests "$A" '{"create":{}}'; [ "$CODE" = 202 ] && ok "…and the handle can be asked for again" || fail "re-file: $CODE $BODY"

# ── a fleet that cannot pay is told when asking (capacity raised, so it is the balance that refuses) ──
X "UPDATE fleets SET max_agents = 50 WHERE slug = 'aaron-agents'"
X "INSERT INTO identity_transactions (did, amount_cents, type, description, balance_after) VALUES ('$PAYER', -$(bal), 'adjust', 'smoke', 0)"
call POST /api/fleet/aaron-agents/silicons/too-poor/token-requests "$A" '{"create":{}}'; [ "$CODE" = 402 ] && ok "a fleet that cannot pay for an agent: 402 to the owner" || fail "poor: $CODE $BODY"
call POST /api/fleet/aaron-agents/silicons/too-poor-b/token-requests "$B" '{"create":{}}'
[ "$CODE" = 409 ] && ! echo "$BODY" | grep -q payer && ok "…a non-owner learns only that it cannot be asked now (no payer, no balance)" || fail "poor non-owner: $CODE $BODY"

[ $fails -gt 0 ] && { echo "--- server.log"; grep -i -m5 "error" "$S/server.log"; }
echo "$fails failure(s)"; exit $(( fails > 0 ))
