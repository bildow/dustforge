#!/bin/bash
# "Write agent instruction files" (wallet_settings.js, Aaron 2026-11-18): off until the person enables it in the app;
# an agent token cannot set it; a pane's onboarding reads it (GET /api/identity/pane-rules), an agent wallet reads its
# creator's answer; each change is a security event; a DB from before this change gains the table.
set -u
W=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
S=$(mktemp -d /tmp/dustforge-wallet-settings-smoke.XXXXXX)
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
call(){ local m=$1 p=$2 t=$3 b=${4:-}
  BODY=$(curl -s -o - -w '\n%{http_code}' -X "$m" "$API$p" -H 'Content-Type: application/json' ${t:+-H "Authorization: Bearer $t"} ${b:+-d "$b"})
  CODE=${BODY##*$'\n'}; BODY=${BODY%$'\n'*}; }
start(){ node server.js >>"$S/server.log" 2>&1 & SRV=$!; for i in $(seq 1 40); do curl -s -o /dev/null "$API/api/health" && break; sleep 0.5; done; }
start; kill $SRV; wait $SRV 2>/dev/null
python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute('DROP TABLE IF EXISTS wallet_settings'); c.commit()" "$DB_PATH"
H=$(printf '%s' hunter22 | sha256sum | cut -d' ' -f1)
node -e '
const identity = require("./identity"); const Database = require("better-sqlite3"); const db = new Database(process.env.DB_PATH);
const mk = (u, bal) => { const id = identity.createIdentity(); const enc = id.encrypted_private_key || id.encryptedPrivateKey;
  db.prepare("INSERT INTO identity_wallets (did, username, email, encrypted_private_key, balance_cents, password_hash) VALUES (?, ?, ?, ?, ?, ?)").run(id.did, u, u + "@smoke.invalid", enc, bal, process.argv[1]); return id.did; };
const owner = mk("owner", 1000); mk("stranger", 100);
const f1 = db.prepare("INSERT INTO fleets (owner_did, name, slug) VALUES (?, ?, ?)").run(owner, "Owner agents", "owner-agents").lastInsertRowid;
const a = mk("agent", 100);
db.prepare("INSERT INTO fleet_silicons (fleet_id, member_did, handle, silicon_id, status, created_by_fleet, joined_via) VALUES (?, ?, ?, ?, ?, 1, ?)").run(f1, a, "agent", "sil_smoke0", "active", "owner");' "$H" || { echo "FAIL seed"; exit 1; }
start; trap 'kill $SRV 2>/dev/null; rm -rf "$S"' EXIT
[ "$(Q "SELECT COUNT(*) FROM sqlite_master WHERE name='wallet_settings'")" = 1 ] && ok "legacy DB without the table boots and gains it" || fail "no table"
login(){ call POST /api/identity/auth-fingerprint "" '{"username":"'$1'","password":"hunter22","scope":"transact","expires_in":"2h"}'; echo "$BODY" | J token; }
mint(){ node -e '
const identity = require("./identity"); const Database = require("better-sqlite3");
const db = new Database(process.env.DB_PATH); const w = db.prepare("SELECT did, encrypted_private_key FROM identity_wallets WHERE username = ?").get(process.argv[1]);
process.stdout.write(identity.createTokenForIdentity(w.encrypted_private_key, w.did, { scope: "transact", expiresIn: "2h", metadata: { auth_method: "fleet_owner_mint", fleet: process.argv[2], username: process.argv[1] } }));' "$1" "$2"; }
OWN=$(login owner); STR=$(login stranger); AG=$(mint agent owner-agents)
call GET /api/identity/settings "$OWN"; [ "$CODE" = 200 ] && [ "$(echo "$BODY" | J settings.agent_rules_write.enabled)" = False ] && ok "off by default" || fail "default: $CODE $BODY"
call GET /api/identity/pane-rules "$OWN"; [ "$(echo "$BODY" | J enabled)" = False ] && echo "$BODY" | J next | grep -q "Enable" && ok "a pane's onboarding is told to have it enabled in the app" || fail "pane-rules off: $BODY"
call GET /api/identity/pane-rules "$AG"; [ "$(echo "$BODY" | J enabled)" = False ] && [ "$(echo "$BODY" | J person)" = "your fleet owner" ] && ok "an agent wallet reads its fleet owner's answer (off)" || fail "agent pane-rules: $BODY"
call POST /api/identity/settings/agent-rules-write "$AG" '{"enabled":true}'; [ "$CODE" = 403 ] && ok "an agent token cannot enable it (403)" || fail "agent set: $CODE $BODY"
DEV=$(node -e '
const identity = require("./identity"); const Database = require("better-sqlite3");
const db = new Database(process.env.DB_PATH); const w = db.prepare("SELECT did, encrypted_private_key FROM identity_wallets WHERE username = ?").get("owner");
process.stdout.write(identity.createTokenForIdentity(w.encrypted_private_key, w.did, { scope: "transact", expiresIn: "2h", metadata: { auth_method: "device", username: "owner" } }));')
call POST /api/identity/settings/agent-rules-write "$DEV" '{"enabled":true}'; [ "$CODE" = 403 ] && ok "a pane's device-flow session of the owner cannot enable it for itself (403)" || fail "device set: $CODE $BODY"
call GET /api/identity/settings "$DEV"; [ "$(echo "$BODY" | J settings.agent_rules_write.enabled)" = False ] && ok "…and it stays off" || fail "device read: $BODY"
RF=$(node -e '
const identity = require("./identity"); const Database = require("better-sqlite3");
const db = new Database(process.env.DB_PATH); const w = db.prepare("SELECT did, encrypted_private_key FROM identity_wallets WHERE username = ?").get("owner");
process.stdout.write(identity.createTokenForIdentity(w.encrypted_private_key, w.did, { scope: "transact", expiresIn: "2h", metadata: { auth_method: "refresh", username: "owner" } }));')
call POST /api/identity/settings/agent-rules-write "$RF" '{"enabled":true}'; [ "$CODE" = 403 ] && [ "$(echo "$BODY" | J sign_in_again)" = True ] && ok "a refresh lineage without a recorded origin is sent to sign in again (403)" || fail "legacy refresh: $CODE $BODY"
call POST /api/identity/settings/agent-rules-write "$OWN" '{"enabled":"yes"}'; [ "$CODE" = 400 ] && ok "enabled must be a boolean" || fail "bad body: $CODE"
call POST /api/identity/settings/agent-rules-write "$OWN" '{"enabled":true}'; [ "$CODE" = 200 ] && [ "$(echo "$BODY" | J agent_rules_write.enabled)" = True ] && ok "the person enables it" || fail "enable: $CODE $BODY"
call GET /api/identity/pane-rules "$AG"; [ "$(echo "$BODY" | J enabled)" = True ] && ok "…and the agent wallet now reads enabled" || fail "agent after: $BODY"
call GET /api/identity/pane-rules "$STR"; [ "$(echo "$BODY" | J enabled)" = False ] && ok "another person's wallet is still off" || fail "stranger: $BODY"
python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute(\"UPDATE fleet_silicons SET created_by_fleet=0, joined_via='network' WHERE handle='agent'\"); c.execute(\"DELETE FROM wallet_creators WHERE did=(SELECT did FROM identity_wallets WHERE username='agent')\"); c.commit()" "$DB_PATH"
call GET /api/identity/pane-rules "$AG"; [ "$(echo "$BODY" | J enabled)" = False ] && [ "$(echo "$BODY" | J person)" = None ] && ok "an agent nobody created has no person to answer: not enabled, never its own row" || fail "orphan: $BODY"
python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute(\"UPDATE fleet_silicons SET created_by_fleet=1, joined_via='owner' WHERE handle='agent'\"); c.commit()" "$DB_PATH"
[ "$(Q "SELECT COUNT(*) FROM demipass_security_events WHERE event_type='agent_rules_write_enabled'")" = 1 ] && ok "the change is a security event" || fail "no event"
call POST /api/identity/settings/agent-rules-write "$OWN" '{"enabled":false}'; [ "$(echo "$BODY" | J agent_rules_write.enabled)" = False ] && ok "…and can be turned off" || fail "disable: $BODY"
call GET /api/identity/settings ""; [ "$CODE" = 401 ] && ok "no token → 401" || fail "noauth: $CODE"
grep -q -i "TypeError\|ReferenceError" "$S/server.log" && { fail "server errors"; grep -i -m3 "TypeError\|ReferenceError" "$S/server.log"; }
echo "$fails failure(s)"; exit $(( fails > 0 ))
