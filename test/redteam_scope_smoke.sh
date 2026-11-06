#!/bin/bash
# Red team items 2, 12, 13 (tome decisions/2026-11-05-THREAT-MODEL-demipass-red-team-v0.1.md): the scope of a secret is
# the owner's, an agent never widens it, a secret with no scope goes nowhere, and every connection /use makes leaves an
# egress row first — so a refused use is proven to have made none. server.js on a throwaway DB; /use's fetch() to
# repo.dustroot.com goes to a local stand-in.
set -u
W=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
S=$(mktemp -d /tmp/dustforge-redteam-smoke.XXXXXX)
PORT=${PORT:-3789}; UP_PORT=${UP_PORT:-3790}; API=http://127.0.0.1:$PORT
[ -d "$W/node_modules" ] || export NODE_PATH=${NODE_PATH:-/home/flimflam/project/dustforge/node_modules}
export IDENTITY_MASTER_KEY=$(python3 -c 'import secrets;print(secrets.token_hex(32))') DB_PATH=$S/dustforge.db PORT \
  STALWART_HOST=127.0.0.1 STALWART_PORT=1 SMTP_RELAY_HOST= SMTP_HOST=127.0.0.1 SMTP_PORT=9 TEST_UPSTREAM=http://127.0.0.1:$UP_PORT
cd "$W"
node -e 'require("http").createServer((q, r) => { q.resume(); q.on("end", () => { r.writeHead(200, { "content-type": "application/json" }); r.end("{\"ok\":true}"); }); }).listen(+process.argv[1], "127.0.0.1");' $UP_PORT & UP=$!
node --require ./test/fixtures/upstream-redirect.js server.js >"$S/server.log" 2>&1 & SRV=$!
trap 'kill $SRV $UP 2>/dev/null; rm -rf "$S"' EXIT
for i in $(seq 1 40); do curl -s -o /dev/null "$API/" && break; sleep 0.5; done
kill -0 $SRV 2>/dev/null || { echo "server died:"; tail -5 "$S/server.log"; exit 1; }
H=$(printf '%s' hunter22 | sha256sum | cut -d' ' -f1)
node -e '
const identity = require("./identity"); const Database = require("better-sqlite3"); const db = new Database(process.env.DB_PATH);
for (const c of ["idempotency_key TEXT", "provenance TEXT DEFAULT '"'"'organic'"'"'"]) { try { db.exec("ALTER TABLE identity_transactions ADD COLUMN " + c); } catch (_) {} }
for (const u of ["owner-a", "person-k"]) { const id = identity.createIdentity(); const enc = id.encrypted_private_key || id.encryptedPrivateKey;
  db.prepare("INSERT INTO identity_wallets (did, username, email, encrypted_private_key, balance_cents, password_hash) VALUES (?, ?, ?, ?, 100000, ?)").run(id.did, u, u + "@dustforge.com", enc, process.argv[1]);
  db.prepare("INSERT INTO identity_transactions (did, amount_cents, type, description, balance_after) VALUES (?, 100000, ?, ?, 100000)").run(id.did, "topup", "smoke"); }' "$H"
fails=0; ok(){ echo "ok   $*"; }; fail(){ echo "FAIL $*"; fails=$((fails+1)); }
J(){ python3 -c 'import json,sys; d=json.load(sys.stdin); v=d
for k in sys.argv[1].split("."):
    v = v[int(k)] if isinstance(v, list) else (v or {}).get(k)
print(v)' "$1"; }
Q(){ python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); r=c.execute(sys.argv[2]).fetchone(); print(r[0] if r else '')" "$DB_PATH" "$1"; }
call(){ local m=$1 p=$2 t=$3 b=${4:-}
  BODY=$(curl -s -o - -w '\n%{http_code}' -X "$m" "$API$p" -H 'Content-Type: application/json' ${t:+-H "Authorization: Bearer $t"} ${b:+-d "$b"})
  CODE=${BODY##*$'\n'}; BODY=${BODY%$'\n'*}; }
login(){ call POST /api/identity/auth-fingerprint "" '{"username":"'$1'","password":"hunter22","scope":"transact","expires_in":"1h"}'; echo "$BODY" | J token; }
pin(){ call POST /api/identity/gate/verify "$1" '{"gate":"pin","pin":"'$2'","intent":"'$3'"}'; [ "$CODE" = 200 ] || fail "pin $3: $CODE $BODY"; }
egress(){ Q "SELECT COUNT(*) FROM blindkey_events WHERE event_type='egress' AND secret_id=$1"; }
A=$(login owner-a); AG=$(login owner-a); K=$(login person-k)
call POST /api/identity/pin "$A" '{"pin":"4321","password":"hunter22"}'; call POST /api/identity/pin "$K" '{"pin":"8765","password":"hunter22"}'
call POST /api/demipass/store "$A" '{"name":"svc","value":"svc-token-value-1234","secret_type":"api_key","host":"repo.dustroot.com"}'; REF=$(echo "$BODY" | J ref)
SID=$(Q "SELECT id FROM blindkey_secrets WHERE ref_code='$REF'")

# ── item 2: the scope decides where the secret goes; a refused use makes no connection ──
[ "$(Q "SELECT target_url_pattern FROM blindkey_contexts WHERE secret_id=$SID")" = "https://repo.dustroot.com/*" ] && ok "a host given at store binds the scope to it" || fail "store scope"
call POST /api/demipass/use "$AG" '{"ref":"'$REF'","params":{"url":"https://repo.dustroot.com/x"}}'
[ "$CODE" = 200 ] && [ "$(egress $SID)" = 1 ] && ok "an in-scope use connects, and the egress row is written first" || fail "in scope: $CODE $BODY egress=$(egress $SID)"
call POST /api/demipass/use "$AG" '{"ref":"'$REF'","params":{"url":"https://api.github.com/x"}}'
[ "$CODE" = 403 ] && [ "$(egress $SID)" = 1 ] && ok "a host off the secret's scope (but on the global list) → 403, no connection (no egress row)" || fail "off scope: $CODE egress=$(egress $SID)"
call POST /api/demipass/use "$AG" '{"ref":"'$REF'","params":{"url":"https://evil.example.com/x"}}'
[ "$CODE" = 403 ] && [ "$(egress $SID)" = 1 ] && ok "the agent's own host → 403, no connection" || fail "own host: $CODE egress=$(egress $SID)"

# ── item 13: widening needs the owner's PIN; agents and delegates never ──
CID=$(Q "SELECT id FROM blindkey_contexts WHERE secret_id=$SID")
call POST /api/demipass/context/add "$AG" '{"secret_name":"svc","context_name":"gh","action_type":"http_header","target_url_pattern":"https://api.github.com/*"}'
[ "$CODE" = 403 ] && [ "$(echo "$BODY" | J intent)" = "scope:$SID" ] && ok "the owner's own second token (device-login case) adding a scope → 403, PIN asked" || fail "agent add: $CODE $BODY"
call PATCH /api/demipass/context/$CID "$AG" '{"target_url_pattern":"*"}'
[ "$CODE" = 403 ] && ok "widening an existing scope to '*' without the PIN → 403" || fail "agent widen: $CODE $BODY"
[ "$(Q "SELECT target_url_pattern FROM blindkey_contexts WHERE id=$CID")" = "https://repo.dustroot.com/*" ] && ok "…and nothing changed" || fail "widen leaked"
call PATCH /api/demipass/context/$CID "$AG" '{"max_uses":100}'
[ "$CODE" = 200 ] && ok "narrowing (a use cap) stays open to the owner's tokens" || fail "narrow: $CODE $BODY"
call PATCH /api/demipass/context/$CID "$AG" '{"max_uses":0}'
[ "$CODE" = 403 ] && ok "lifting the cap again is widening → PIN" || fail "lift cap: $CODE"
pin "$A" 4321 "scope:$SID"
call POST /api/demipass/context/add "$A" '{"secret_name":"svc","context_name":"gh","action_type":"http_header","target_url_pattern":"https://api.github.com/*"}'
[ "$CODE" = 200 ] && ok "the owner, with the PIN, widens it" || fail "owner add: $CODE $BODY"
# a delegate (person share) tries to widen its own entry
call POST /api/network/requests "$A" '{"to":"person-k","as":"person"}'; R=$(echo "$BODY" | J request.id); call POST /api/network/requests/$R/accept "$K"
pin "$A" 4321 "share:$SID"; call POST /api/demipass/shares "$A" '{"secret":"svc","to":"person-k"}'; SH=$(echo "$BODY" | J share.id)
pin "$K" 8765 "share-accept:$SH"; call POST /api/demipass/shares/$SH/accept "$K"
B0=$(Q "SELECT COUNT(*) FROM demipass_security_events WHERE severity='critical'")
call PATCH /api/demipass/context/$CID "$K" '{"target_url_pattern":"*"}'
[ "$CODE" = 403 ] && [ "$(Q "SELECT COUNT(*) FROM demipass_security_events WHERE event_type='scope_widen_denied' AND severity='critical'")" -gt 0 ] && ok "a delegate PATCHing its entry's scope → 403 and a critical audit event" || fail "delegate patch: $CODE $BODY"
call POST /api/demipass/context/add "$K" "{\"secret_name\":\"svc\",\"context_name\":\"k\",\"action_type\":\"http_header\",\"target_url_pattern\":\"*\"}"
[ "$CODE" = 404 ] || [ "$CODE" = 403 ] && ok "a delegate cannot add a scope to it" || fail "delegate add: $CODE"
E1=$(egress $SID); call POST /api/demipass/use "$K" '{"ref":"'$REF'","params":{"url":"https://evil.example.com/x"}}'
{ [ "$CODE" = 403 ] || [ "$CODE" = 400 ]; } && [ "$(egress $SID)" = "$E1" ] && ok "the delegate's use off-scope → refused, no connection" || fail "delegate off scope: $CODE"
pin "$K" 8765 "scope:$SID"; call PATCH /api/demipass/context/$CID "$K" '{"target_url_pattern":"*"}'
[ "$CODE" = 403 ] && ok "even with its own PIN, a delegate's widening → 403" || fail "delegate pin widen: $CODE $BODY"

# ── item 12: no scope, no use ──
call PATCH /api/demipass/context/$CID "$A" '{"status":"revoked"}'
GID=$(Q "SELECT id FROM blindkey_contexts WHERE secret_id=$SID AND context_name='gh'"); call PATCH /api/demipass/context/$GID "$A" '{"status":"revoked"}'
python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute('DELETE FROM blindkey_contexts WHERE secret_id=?', (int(sys.argv[2]),)); c.commit()" "$DB_PATH" "$SID"
E0=$(egress $SID)
call POST /api/demipass/use "$A" '{"ref":"'$REF'","params":{"url":"https://repo.dustroot.com/x"}}'
[ "$CODE" = 403 ] || [ "$CODE" = 400 ] && [ "$(egress $SID)" = "$E0" ] && ok "a secret with no scope → refused, no connection (was: usable anywhere)" || fail "no scope: $CODE $BODY"

echo; [ $fails = 0 ] && echo "ALL OK" || echo "$fails FAILED"; exit $fails
