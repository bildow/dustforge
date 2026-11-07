#!/bin/bash
# /api/identity/transactions is private: no token → 403, another wallet → 403, the wallet itself → 200 (its rows).
set -u
W=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
S=$(mktemp -d /tmp/dustforge-txpriv-smoke.XXXXXX)
PORT=${PORT:-3816}; API=http://127.0.0.1:$PORT
[ -d "$W/node_modules" ] || export NODE_PATH=${NODE_PATH:-/home/flimflam/project/dustforge/node_modules}
export IDENTITY_MASTER_KEY=$(python3 -c 'import secrets;print(secrets.token_hex(32))') DB_PATH=$S/dustforge.db PORT \
  STALWART_HOST=127.0.0.1 STALWART_PORT=1 SMTP_RELAY_HOST= SMTP_HOST=127.0.0.1 SMTP_PORT=9
cd "$W"
node server.js >"$S/server.log" 2>&1 & SRV=$!
trap 'kill $SRV 2>/dev/null; rm -rf "$S"' EXIT
for i in $(seq 1 40); do curl -s -o /dev/null "$API/api/health" && break; sleep 0.5; done
fails=0; ok(){ echo "ok   $*"; }; fail(){ echo "FAIL $*"; fails=$((fails+1)); }
node -e '
const identity = require("./identity"); const Database = require("better-sqlite3"); const crypto = require("crypto");
const db = new Database(process.env.DB_PATH);
for (const u of ["alice", "bob"]) { const id = identity.createIdentity();
  db.prepare("INSERT INTO identity_wallets (did, username, email, encrypted_private_key, balance_cents, password_hash) VALUES (?, ?, ?, ?, 50, ?)").run(id.did, u, u + "@dustforge.com", id.encrypted_private_key || id.encryptedPrivateKey, crypto.createHash("sha256").update("hunter22").digest("hex"));
  db.prepare("INSERT INTO identity_transactions (did, amount_cents, type, description, balance_after) VALUES (?, 50, ?, ?, 50)").run(id.did, "topup", "secret-ish note " + u); }'
login(){ curl -s -X POST "$API/api/identity/auth-fingerprint" -H 'content-type: application/json' -d '{"username":"'$1'","password":"hunter22","scope":"read","expires_in":"1h"}' | python3 -c 'import json,sys; print(json.load(sys.stdin).get("token"))'; }
A=$(login alice); B=$(login bob)
DA=$(python3 -c "import sqlite3; print(sqlite3.connect('$DB_PATH').execute(\"SELECT did FROM identity_wallets WHERE username='alice'\").fetchone()[0])")
c(){ curl -s -o "$S/out" -w '%{http_code}' "$API/api/identity/transactions?did=$DA" ${1:+-H "Authorization: Bearer $1"}; }
[ "$(c)" = 403 ] && ! grep -q "secret-ish" "$S/out" && ok "no token → 403, nothing listed" || fail "anonymous: $(cat "$S/out")"
[ "$(c "$B")" = 403 ] && ok "another wallet → 403" || fail "other: $(cat "$S/out")"
[ "$(c "$A")" = 200 ] && grep -q "secret-ish note alice" "$S/out" && ok "the wallet itself → 200, its rows" || fail "own: $(cat "$S/out")"
echo "$fails failure(s)"; exit $(( fails > 0 ))
