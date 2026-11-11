#!/bin/bash
# Smoke, on a throwaway DB, for vault pools (Aaron 2026-11-11): list with counts, add, move a secret between pools,
# remove a pool only when empty; another wallet's secret is never moved.
# No network beyond 127.0.0.1.
set -u
W=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
S=$(mktemp -d /tmp/dustforge-vault-pools-smoke.XXXXXX)
PORT=${PORT:-3799}; API=http://127.0.0.1:$PORT
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
for (const [u, bal] of [["owner-a", 100000], ["other-x", 100000], ["bench-w", 0]]) { const id = identity.createIdentity(); const enc = id.encrypted_private_key || id.encryptedPrivateKey;
  db.prepare("INSERT INTO identity_wallets (did, username, email, encrypted_private_key, balance_cents, password_hash) VALUES (?, ?, ?, ?, ?, ?)").run(id.did, u, u + "@dustforge.com", enc, bal, process.argv[1]);
  if (bal) db.prepare("INSERT INTO identity_transactions (did, amount_cents, type, description, balance_after) VALUES (?, ?, ?, ?, ?)").run(id.did, bal, "topup", "smoke", bal); }' "$H"
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
A=$(login owner-a); X=$(login other-x)
mk(){ python3 -c 'import json,sys,secrets; n,c=sys.argv[1:3]; b={"name":n,"value":"v-"+secrets.token_urlsafe(12),"secret_type":"api_key"}; b.update({"category":c} if c else {}); print(json.dumps(b))' "$1" "$2"; }
call POST /api/demipass/store "$A" "$(mk openai-key api)"; R1=$(echo "$BODY" | J ref)
call POST /api/demipass/store "$A" "$(mk loose-key '')"; R2=$(echo "$BODY" | J ref)
call POST /api/demipass/store "$X" "$(mk xs-key api)"; RX=$(echo "$BODY" | J ref)
PJ(){ python3 -c 'import json,sys; d=json.load(sys.stdin); print(" ".join(p["name"]+":"+str(p["count"]) for p in d["pools"]), "u:"+str(d["uncategorized"]))'; }
call GET /api/demipass/pools "$A"; [ "$(echo "$BODY" | PJ)" = "api:1 u:1" ] && ok "pools come from the secrets' categories, with counts (and the uncategorized)" || fail "pools: $BODY"
call POST /api/demipass/pools "$A" '{"name":"Test Env"}'; [ "$CODE" = 201 ] && [ "$(echo "$BODY" | PJ)" = "api:1 test-env:0 u:1" ] && ok "a new pool (spaces → dashes) shows while empty" || fail "add: $CODE $BODY"
call POST /api/demipass/pools "$A" '{"name":"bad/name"}'; A1=$CODE; call POST /api/demipass/pools "$A" '{"name":"uncategorized"}'
[ "$A1" = 400 ] && [ "$CODE" = 400 ] && ok "bad pool names are refused" || fail "bad names: $A1 $CODE"
call POST "/api/demipass/secrets/$R1/pool" "$A" '{"pool":"test-env"}'
[ "$CODE" = 200 ] && [ "$(echo "$BODY" | J from)" = api ] && [ "$(echo "$BODY" | PJ)" = "test-env:1 u:1" ] && ok "a secret moved from api to test-env; api (never added, now empty) is gone" || fail "move: $CODE $BODY"
call GET /api/demipass/dashboard "$A"; [ "$(echo "$BODY" | python3 -c 'import json,sys; print({s["name"]:s["category"] for s in json.load(sys.stdin)["secrets"]}["openai-key"])')" = test-env ] && ok "the vault shows it in its new pool" || fail "dashboard: $BODY"
call DELETE /api/demipass/pools/test-env "$A"; [ "$CODE" = 409 ] && [ "$(echo "$BODY" | J count)" = 1 ] && ok "a pool that holds a secret cannot be removed" || fail "delete full: $CODE $BODY"
call POST "/api/demipass/secrets/$R1/pool" "$A" '{"pool":"api"}'; call DELETE /api/demipass/pools/test-env "$A"
[ "$CODE" = 200 ] && [ "$(echo "$BODY" | PJ)" = "api:1 u:1" ] && ok "moved back, the empty pool is removed" || fail "delete empty: $CODE $BODY"
call DELETE /api/demipass/pools/test-env "$A"; [ "$CODE" = 404 ] && ok "removing it again → 404" || fail "delete twice: $CODE"
call POST "/api/demipass/secrets/$R2/pool" "$A" '{"pool":"uncategorized"}'; [ "$CODE" = 200 ] && [ "$(echo "$BODY" | J pool)" = None ] && ok "'uncategorized' takes a secret out of every pool" || fail "uncat: $CODE $BODY"
call POST "/api/demipass/secrets/$RX/pool" "$A" '{"pool":"mine"}'; A1=$CODE; call POST "/api/demipass/secrets/not-a-ref/pool" "$A" '{"pool":"x"}'
[ "$A1" = 404 ] && [ "$CODE" = 400 ] && [ "$(Q "SELECT category FROM blindkey_secrets WHERE ref_code='$RX'")" = api ] && ok "someone else's secret cannot be moved (404); a bad ref → 400" || fail "other: $A1 $CODE"
call GET /api/demipass/pools ""; [ "$CODE" = 401 ] && ok "pools need a session" || fail "anon: $CODE"
echo; [ $fails = 0 ] && echo "vault_pools_smoke: all passed" || { echo "vault_pools_smoke: $fails FAILED"; exit 1; }
