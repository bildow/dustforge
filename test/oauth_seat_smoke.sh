#!/bin/bash
# End-to-end smoke of the OAuth 2.1 seat front (oauth_seat.js) on server.js with a throwaway DB: dynamic client
# registration → authorize (owner login + PIN + seat/scope consent) → code → token → the token verifies at the Conduit
# tenant (POST /api/services/verify) with auth_method oauth_seat, seat and resource → refresh rotation and replay →
# the owner's delegation revoke ends the grant and its access token → the token opens nothing at DemiPass itself →
# no token or secret value in the server log.
set -u
W=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
S=$(mktemp -d /tmp/dustforge-oauth-smoke.XXXXXX)
PORT=${PORT:-3791}; API=http://127.0.0.1:$PORT
[ -d "$W/node_modules" ] || export NODE_PATH=${NODE_PATH:-/home/flimflam/project/dustforge/node_modules}
export IDENTITY_MASTER_KEY=$(python3 -c 'import secrets;print(secrets.token_hex(32))') DB_PATH=$S/dustforge.db PORT \
  STALWART_HOST=127.0.0.1 STALWART_PORT=1 SMTP_RELAY_HOST= SMTP_HOST=127.0.0.1 SMTP_PORT=9 PUBLIC_API_URL=$API \
  OAUTH_REDIRECT_ALLOWLIST=https://claude.ai/api/mcp/auth_callback
cd "$W"
node server.js >"$S/server.log" 2>&1 & SRV=$!
trap 'kill $SRV 2>/dev/null; rm -rf "$S"' EXIT
for i in $(seq 1 40); do curl -s -o /dev/null "$API/" && break; sleep 0.5; done
kill -0 $SRV 2>/dev/null || { echo "server died:"; tail -5 "$S/server.log"; exit 1; }
H=$(printf '%s' hunter22 | sha256sum | cut -d' ' -f1)
node -e '
const identity = require("./identity"); const Database = require("better-sqlite3"); const crypto = require("crypto");
const db = new Database(process.env.DB_PATH);
for (const c of ["idempotency_key TEXT", "provenance TEXT DEFAULT '"'"'organic'"'"'"]) { try { db.exec("ALTER TABLE identity_transactions ADD COLUMN " + c); } catch (_) {} }
const mk = (u) => { const id = identity.createIdentity(); db.prepare("INSERT INTO identity_wallets (did, username, email, encrypted_private_key, balance_cents, password_hash) VALUES (?, ?, ?, ?, 100000, ?)").run(id.did, u, u + "@dustforge.com", id.encrypted_private_key, process.argv[1]); db.prepare("INSERT INTO identity_transactions (did, amount_cents, type, description, balance_after) VALUES (?, 100000, ?, ?, 100000)").run(id.did, "topup", "smoke"); return id.did; };
const owner = mk("owner-a"), seat = mk("seat-fable"), svc = mk("conduit-svc"), stranger = mk("other-x");
const fleetId = Number(db.prepare("INSERT INTO fleets (owner_did, name, slug) VALUES (?, ?, ?)").run(owner, "A fleet", "a-fleet").lastInsertRowid);
db.prepare("INSERT INTO fleet_silicons (fleet_id, member_did, handle, display_name, silicon_id, status, created_by_fleet, joined_via) VALUES (?, ?, ?, ?, ?, ?, 1, ?)").run(fleetId, seat, "seat-fable", "Claude.ai seat", "sil_" + crypto.randomBytes(8).toString("hex"), "active", "owner");
const tid = Number(db.prepare("INSERT INTO service_tenants (slug, name, service_did, owner_did, status, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)").run("conduit", "Conduit", svc, owner, "active", "smoke", new Date().toISOString()).lastInsertRowid);
for (const a of ["read", "post", "ack", "forward"]) db.prepare("INSERT INTO service_actions (tenant_id, action, scope, measured_cost_dd, max_cost_dd, depth, open, status, updated_at) VALUES (?, ?, ?, 1, ?, ?, 1, ?, ?)").run(tid, a, a, a === "post" ? 100 : 1, "standard", "active", new Date().toISOString());
db.prepare("INSERT INTO service_consents (payer_did, tenant_id, daily_cap_dd, approved_by, created_at) VALUES (?, ?, 500, ?, ?)").run(seat, tid, owner, new Date().toISOString());
console.log(JSON.stringify({ owner, seat, svc, stranger }));' "$H" > "$S/seed.json"
SEAT_DID=$(python3 -I -c 'import json,sys;print(json.load(open(sys.argv[1]))["seat"])' "$S/seed.json")
fails=0; ok(){ echo "ok   $*"; }; fail(){ echo "FAIL $*"; fails=$((fails+1)); }
J(){ python3 -I -c 'import json,sys
d=json.load(sys.stdin);
for k in sys.argv[1].split("."):
  d=d[int(k)] if isinstance(d,list) else d.get(k)
  if d is None: break
print("" if d is None else (json.dumps(d) if isinstance(d,(dict,list)) else d))' "$1"; }
login(){ curl -s -X POST "$API/api/identity/auth-fingerprint" -H 'content-type: application/json' -d "{\"username\":\"$1\",\"password\":\"hunter22\",\"scope\":\"transact\",\"expires_in\":\"1h\"}" | J token; }
OWNER=$(login owner-a); TENANT=$(login conduit-svc); STRANGER=$(login other-x)
[ -n "$OWNER" ] && [ -n "$TENANT" ] && ok "owner and tenant signed in" || fail "sign-in"
# The owner sets a vault PIN (the authorize screen takes it).
R=$(curl -s -X POST "$API/api/identity/pin" -H "authorization: Bearer $OWNER" -H 'content-type: application/json' -d '{"pin":"2468","password":"hunter22"}')
[ "$(echo "$R" | J pin_set)" = "True" ] && ok "owner PIN set" || fail "owner PIN set: $R"

# ── discovery and registration ──────────────────────────────────────────────────────────────────────────────────────
META=$(curl -s "$API/.well-known/oauth-authorization-server")
[ "$(echo "$META" | J issuer)" = "$API" ] && [ "$(echo "$META" | J code_challenge_methods_supported)" = '["S256"]' ] && ok "AS metadata: issuer $API, S256" || fail "metadata: $META"
REG=$(curl -s -X POST "$API/oauth/register" -H 'content-type: application/json' -d '{"client_name":"Claude","redirect_uris":["https://claude.ai/api/mcp/auth_callback"],"grant_types":["authorization_code","refresh_token"],"response_types":["code"],"token_endpoint_auth_method":"client_secret_basic"}')
CID=$(echo "$REG" | J client_id); CSEC=$(echo "$REG" | J client_secret)
[ -n "$CID" ] && [ -n "$CSEC" ] && ok "client registered" || fail "register: $REG"
BAD=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$API/oauth/register" -H 'content-type: application/json' -d '{"redirect_uris":["https://evil.example/cb"]}')
[ "$BAD" = 400 ] && ok "foreign redirect_uri refused at registration" || fail "foreign redirect accepted ($BAD)"

# ── authorize: owner login + PIN + consent ──────────────────────────────────────────────────────────────────────────
VER=$(python3 -I -c 'import secrets;print(secrets.token_urlsafe(48))'); CHAL=$(printf '%s' "$VER" | python3 -I -c 'import sys,hashlib,base64;print(base64.urlsafe_b64encode(hashlib.sha256(sys.stdin.read().encode()).digest()).rstrip(b"=").decode())')
CB=https%3A%2F%2Fclaude.ai%2Fapi%2Fmcp%2Fauth_callback; RES=https%3A%2F%2Fconduit.dustroot.com%2Fmcp
PAGE=$(curl -s -c "$S/jar" "$API/oauth/authorize?response_type=code&client_id=$CID&redirect_uri=$CB&state=st9&code_challenge=$CHAL&code_challenge_method=S256&resource=$RES&scope=read%20post%20ack")
RID=$(echo "$PAGE" | grep -o 'dpa_[A-Za-z0-9_-]*' | head -1)
[ -n "$RID" ] && ok "authorize page served (request $RID)" || fail "authorize page: $(echo "$PAGE" | head -c 300)"
R=$(curl -s -X POST "$API/oauth/authorize/login" -H 'content-type: application/json' -d "{\"request_id\":\"$RID\",\"username\":\"owner-a\",\"password\":\"hunter22\"}")
[ "$(echo "$R" | J error)" = "wrong_client" ] && ok "a step without the page's cookie is refused" || fail "no-cookie step: $R"
R=$(curl -s -b "$S/jar" -X POST "$API/oauth/authorize/login" -H 'content-type: application/json' -d "{\"request_id\":\"$RID\",\"username\":\"owner-a\",\"password\":\"wrong\"}")
[ "$(echo "$R" | J error)" = "invalid_login" ] && ok "wrong password refused" || fail "wrong password: $R"
R=$(curl -s -b "$S/jar" -X POST "$API/oauth/authorize/login" -H 'content-type: application/json' -d "{\"request_id\":\"$RID\",\"username\":\"owner-a\",\"password\":\"hunter22\"}")
[ "$(echo "$R" | J next)" = "pin" ] && ok "owner signed in on the authorize page" || fail "login: $R"
R=$(curl -s -b "$S/jar" -X POST "$API/oauth/authorize/pin" -H 'content-type: application/json' -d "{\"request_id\":\"$RID\",\"pin\":\"1111\"}")
[ "$(echo "$R" | J error)" = "wrong_pin" ] && ok "wrong PIN refused (counted by the wallet's lockout)" || fail "wrong pin: $R"
R=$(curl -s -b "$S/jar" -X POST "$API/oauth/authorize/pin" -H 'content-type: application/json' -d "{\"request_id\":\"$RID\",\"pin\":\"2468\"}")
[ "$(echo "$R" | J seats.0.handle)" = "seat-fable" ] && [ "$(echo "$R" | J seats.0.consent_ok)" = "True" ] && ok "PIN accepted; seat-fable offered with its consent" || fail "pin: $R"
R=$(curl -s -b "$S/jar" -X POST "$API/oauth/authorize/decide" -H 'content-type: application/json' -d "{\"request_id\":\"$RID\",\"approve\":true,\"seat\":\"seat-fable\",\"scopes\":[\"read\",\"post\",\"ack\"]}")
REDIR=$(echo "$R" | J redirect); CODE=$(printf '%s' "$REDIR" | grep -o 'code=dpz_[A-Za-z0-9_-]*' | cut -d= -f2)
case "$REDIR" in https://claude.ai/api/mcp/auth_callback\?*state=st9*) ok "redirected to the Claude callback with the state";; *) fail "redirect: $REDIR";; esac
[ -n "$CODE" ] && ok "authorization code issued" || fail "no code"
N=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM service_delegations WHERE delegate_did='$SEAT_DID' AND status='active'")
[ "$N" = 3 ] && ok "owner's use-only delegations (read, post, ack) granted to the seat" || fail "delegations: $N"

# ── token ───────────────────────────────────────────────────────────────────────────────────────────────────────────
TOK=$(curl -s -X POST "$API/oauth/token" -u "$CID:$CSEC" -d "grant_type=authorization_code&code=$CODE&redirect_uri=https://claude.ai/api/mcp/auth_callback&code_verifier=$VER&resource=https://conduit.dustroot.com/mcp")
AT=$(echo "$TOK" | J access_token); RT=$(echo "$TOK" | J refresh_token)
[ -n "$AT" ] && [ -n "$RT" ] && [ "$(echo "$TOK" | J scope)" = "read post ack" ] && ok "access + refresh token issued, scope read post ack" || fail "token: $TOK"
EXP=$(echo "$TOK" | J expires_in); [ "$EXP" -le 3600 ] && ok "access token lives at most 1 h ($EXP s)" || fail "expires_in $EXP"
CLAIMS=$(printf '%s' "$AT" | cut -d. -f2 | python3 -I -c 'import sys,base64,json;s=sys.stdin.read().strip();print(json.dumps(json.loads(base64.urlsafe_b64decode(s+"="*(-len(s)%4)))))')
[ "$(echo "$CLAIMS" | J iss)" = "demipass-svc" ] && [ "$(echo "$CLAIMS" | J aud)" = "svc:conduit" ] && [ "$(echo "$CLAIMS" | J sub)" = "$SEAT_DID" ] && ok "token is the seat's Conduit service token (iss demipass-svc, aud svc:conduit, sub seat)" || fail "claims: $CLAIMS"
# Conduit verifies it as any service token and learns, from the signed payload, that it is a web seat's.
V=$(curl -s -X POST "$API/api/services/verify" -H "authorization: Bearer $TENANT" -H 'content-type: application/json' -d "{\"token\":\"$AT\",\"action\":\"read\"}")
[ "$(echo "$V" | J ok)" = "True" ] && [ "$(echo "$V" | J auth_method)" = "oauth_seat" ] && [ "$(echo "$V" | J seat)" = "seat-fable" ] && [ "$(echo "$V" | J resource)" = "https://conduit.dustroot.com/mcp" ] && [ "$(echo "$V" | J wallet)" = "$SEAT_DID" ] && ok "tenant verify: ok, auth_method oauth_seat, seat seat-fable, resource, wallet = seat" || fail "verify read: $V"
[ "$(echo "$V" | J via)" = "delegation" ] && ok "verify: authority via the owner's delegation" || fail "via: $(echo "$V" | J via)"
V=$(curl -s -X POST "$API/api/services/verify" -H "authorization: Bearer $TENANT" -H 'content-type: application/json' -d "{\"token\":\"$AT\",\"action\":\"forward\"}")
[ "$(echo "$V" | J ok)" = "False" ] && ok "verify forward (not granted): refused" || fail "forward allowed: $V"
# An ordinary service token says service_token.
ST=$(curl -s -X POST "$API/api/services/token" -H "authorization: Bearer $STRANGER" -H 'content-type: application/json' -d '{"service":"conduit"}' | J error)
case "$ST" in *consent*) ok "a stranger without consent cannot mint a Conduit token (unchanged)";; *) fail "stranger mint: $ST";; esac
# The access token opens nothing at DemiPass.
C=$(curl -s -o /dev/null -w '%{http_code}' "$API/api/fleets/mine" -H "authorization: Bearer $AT")
[ "$C" = 401 ] && ok "access token refused by a DemiPass route ($C)" || fail "DemiPass route accepted the seat token ($C)"
C=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$API/api/oauth/grants/1/revoke" -H "authorization: Bearer $AT")
[ "$C" = 401 ] && ok "access token cannot manage grants" || fail "grant route accepted the seat token ($C)"
# Replaying the code revokes the grant.
R=$(curl -s -X POST "$API/oauth/token" -u "$CID:$CSEC" -d "grant_type=authorization_code&code=$CODE&redirect_uri=https://claude.ai/api/mcp/auth_callback&code_verifier=$VER")
[ "$(echo "$R" | J error)" = "invalid_grant" ] && ok "code replay refused" || fail "code replay: $R"
V=$(curl -s -X POST "$API/api/services/verify" -H "authorization: Bearer $TENANT" -H 'content-type: application/json' -d "{\"token\":\"$AT\",\"action\":\"read\"}")
[ "$(echo "$V" | J ok)" = "False" ] && ok "after the replay the access token no longer verifies" || fail "token still alive after replay: $V"

# ── second grant: refresh, then the owner revokes the delegation in the app ─────────────────────────────────────────
authorize(){ VER=$(python3 -I -c 'import secrets;print(secrets.token_urlsafe(48))'); CHAL=$(printf '%s' "$VER" | python3 -I -c 'import sys,hashlib,base64;print(base64.urlsafe_b64encode(hashlib.sha256(sys.stdin.read().encode()).digest()).rstrip(b"=").decode())')
  PAGE=$(curl -s -c "$S/jar" "$API/oauth/authorize?response_type=code&client_id=$CID&redirect_uri=$CB&state=s2&code_challenge=$CHAL&code_challenge_method=S256&resource=$RES"); RID=$(echo "$PAGE" | grep -o 'dpa_[A-Za-z0-9_-]*' | head -1)
  curl -s -o /dev/null -b "$S/jar" -X POST "$API/oauth/authorize/login" -H 'content-type: application/json' -d "{\"request_id\":\"$RID\",\"username\":\"owner-a\",\"password\":\"hunter22\"}"
  curl -s -o /dev/null -b "$S/jar" -X POST "$API/oauth/authorize/pin" -H 'content-type: application/json' -d "{\"request_id\":\"$RID\",\"pin\":\"2468\"}"
  R=$(curl -s -b "$S/jar" -X POST "$API/oauth/authorize/decide" -H 'content-type: application/json' -d "{\"request_id\":\"$RID\",\"approve\":true,\"seat\":\"seat-fable\"}")
  CODE=$(echo "$R" | J redirect | grep -o 'code=dpz_[A-Za-z0-9_-]*' | cut -d= -f2)
  curl -s -X POST "$API/oauth/token" -u "$CID:$CSEC" -d "grant_type=authorization_code&code=$CODE&redirect_uri=https://claude.ai/api/mcp/auth_callback&code_verifier=$VER"; }
TOK=$(authorize); AT=$(echo "$TOK" | J access_token); RT=$(echo "$TOK" | J refresh_token)
[ -n "$RT" ] && ok "second grant issued" || fail "second grant: $TOK"
R=$(curl -s -X POST "$API/oauth/token" -u "$CID:$CSEC" -d "grant_type=refresh_token&refresh_token=$RT")
AT2=$(echo "$R" | J access_token); RT2=$(echo "$R" | J refresh_token)
[ -n "$AT2" ] && [ -n "$RT2" ] && [ "$RT2" != "$RT" ] && ok "refresh rotated" || fail "refresh: $R"
R=$(curl -s -X POST "$API/oauth/token" -u "$CID:$CSEC" -d "grant_type=refresh_token&refresh_token=$RT")
[ "$(echo "$R" | J error)" = "invalid_grant" ] && ok "replayed refresh token refused and the grant ended" || fail "refresh replay: $R"
V=$(curl -s -X POST "$API/api/services/verify" -H "authorization: Bearer $TENANT" -H 'content-type: application/json' -d "{\"token\":\"$AT2\",\"action\":\"read\"}")
[ "$(echo "$V" | J ok)" = "False" ] && ok "the rotated access token died with the grant" || fail "token alive after refresh replay: $V"
TOK=$(authorize); AT=$(echo "$TOK" | J access_token)
DID_ID=$(sqlite3 "$DB_PATH" "SELECT id FROM service_delegations WHERE delegate_did='$SEAT_DID' AND scope='read' AND status='active' ORDER BY id DESC LIMIT 1")
R=$(curl -s -X POST "$API/api/services/delegations/$DID_ID/revoke" -H "authorization: Bearer $OWNER")
[ "$(echo "$R" | J oauth_grants_revoked)" = 1 ] && ok "owner revoked the 'read' delegation in the app: 1 OAuth grant ended" || fail "delegation revoke: $R"
V=$(curl -s -X POST "$API/api/services/verify" -H "authorization: Bearer $TENANT" -H 'content-type: application/json' -d "{\"token\":\"$AT\",\"action\":\"read\"}")
[ "$(echo "$V" | J ok)" = "False" ] && ok "its access token no longer verifies" || fail "token alive after delegation revoke: $V"
G=$(curl -s "$API/api/oauth/grants" -H "authorization: Bearer $OWNER")
[ "$(echo "$G" | J grants.0.status)" = "revoked" ] && ok "owner's grant list shows the revocation" || fail "grants: $G"

# ── the owner removes the seat from the fleet: the fleet cut kills the token at once, the grant ends ────────────────
TOK=$(authorize); AT=$(echo "$TOK" | J access_token)
V=$(curl -s -X POST "$API/api/services/verify" -H "authorization: Bearer $TENANT" -H 'content-type: application/json' -d "{\"token\":\"$AT\",\"action\":\"read\"}")
[ "$(echo "$V" | J ok)" = "True" ] && ok "third grant verifies" || fail "third grant: $V"
sqlite3 "$DB_PATH" "UPDATE fleet_silicons SET handle='seat-renamed' WHERE member_did='$SEAT_DID'"
V=$(curl -s -X POST "$API/api/services/verify" -H "authorization: Bearer $TENANT" -H 'content-type: application/json' -d "{\"token\":\"$AT\",\"action\":\"read\"}")
[ "$(echo "$V" | J ok)" = "True" ] && [ "$(echo "$V" | J seat)" = "" ] && ok "a handle the wallet no longer holds is not echoed as seat" || fail "renamed seat: $V"
sqlite3 "$DB_PATH" "UPDATE fleet_silicons SET handle='seat-fable' WHERE member_did='$SEAT_DID'"
R=$(curl -s -X DELETE "$API/api/fleet/a-fleet/silicons/seat-fable" -H "authorization: Bearer $OWNER")
[ "$(echo "$R" | J ok)" = "True" ] && ok "owner removed seat-fable from the fleet" || fail "remove: $R"
V=$(curl -s -X POST "$API/api/services/verify" -H "authorization: Bearer $TENANT" -H 'content-type: application/json' -d "{\"token\":\"$AT\",\"action\":\"read\"}")
[ "$(echo "$V" | J ok)" = "False" ] && ok "its access token is dead at once (fleet cut applies to oauth_seat)" || fail "token alive after removal: $V"
G=$(curl -s "$API/api/oauth/grants" -H "authorization: Bearer $OWNER")
[ "$(echo "$G" | J grants.0.status)" = "revoked" ] && ok "the grant ended with the removal" || fail "grant after removal: $G"

# ── nothing secret in the log ───────────────────────────────────────────────────────────────────────────────────────
if grep -q "$CSEC\|dpo_\|dpz_\|$(printf '%s' "$AT" | cut -c1-24)" "$S/server.log"; then fail "a secret value appears in the server log"; else ok "no client secret, code, refresh or access token in the server log"; fi
echo; [ $fails -eq 0 ] && echo "ALL OK" || { echo "$fails FAILED"; tail -20 "$S/server.log"; exit 1; }
