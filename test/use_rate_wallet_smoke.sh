#!/bin/bash
# /request-token and /use are limited per wallet, not per address (Aaron 2026-11-12): two wallets behind one address
# each get their own budget; a caller without a valid token is limited by address; a per-address ceiling still holds.
# Limits are lowered for the test (USE_RATE_LIMIT_MAX=5, USE_RATE_IP_CEILING=15). No schema change.
set -u
W=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
S=$(mktemp -d /tmp/dustforge-userate-smoke.XXXXXX)
PORT=${PORT:-3931}; API=http://127.0.0.1:$PORT
[ -d "$W/node_modules" ] || export NODE_PATH=${NODE_PATH:-/home/flimflam/project/dustforge/node_modules}
export IDENTITY_MASTER_KEY=$(python3 -c 'import secrets;print(secrets.token_hex(32))') DB_PATH=$S/dustforge.db PORT \
  STALWART_HOST=127.0.0.1 STALWART_PORT=1 SMTP_RELAY_HOST= SMTP_HOST=127.0.0.1 SMTP_PORT=9 USE_RATE_LIMIT_MAX=5 USE_RATE_IP_CEILING=15
cd "$W"
( exec node server.js >"$S/server.log" 2>&1 ) & SRV=$!
trap 'kill $SRV 2>/dev/null; rm -rf "$S"' EXIT
for i in $(seq 1 40); do curl -s -o /dev/null "$API/" && break; sleep 0.5; done
kill -0 $SRV 2>/dev/null || { echo "server died:"; tail -5 "$S/server.log"; exit 1; }
H=$(printf '%s' hunter22 | sha256sum | cut -d' ' -f1)
node -e '
const identity = require("./identity"); const Database = require("better-sqlite3"); const db = new Database(process.env.DB_PATH);
for (const c of ["idempotency_key TEXT", "provenance TEXT DEFAULT '"'"'organic'"'"'"]) { try { db.exec("ALTER TABLE identity_transactions ADD COLUMN " + c); } catch (_) {} }
for (const u of ["wallet-a", "wallet-b", "wallet-c"]) { const id = identity.createIdentity(); const enc = id.encrypted_private_key || id.encryptedPrivateKey;
  db.prepare("INSERT INTO identity_wallets (did, username, email, encrypted_private_key, balance_cents, password_hash) VALUES (?, ?, ?, ?, 100000, ?)").run(id.did, u, u + "@dustforge.com", enc, process.argv[1]);
  db.prepare("INSERT INTO identity_transactions (did, amount_cents, type, description, balance_after) VALUES (?, 100000, ?, ?, 100000)").run(id.did, "topup", "smoke"); }' "$H"
fails=0; ok(){ echo "ok   $*"; }; fail(){ echo "FAIL $*"; fails=$((fails+1)); }
login(){ curl -s -X POST "$API/api/identity/auth-fingerprint" -H 'content-type: application/json' -d '{"username":"'$1'","password":"hunter22","scope":"transact","expires_in":"1h"}' | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])'; }
A=$(login wallet-a); B=$(login wallet-b); Cw=$(login wallet-c)
RT(){ curl -s -o /dev/null -w '%{http_code}' -X POST "$API/api/demipass/request-token" -H 'content-type: application/json' ${1:+-H "Authorization: Bearer $1"} -d '{"ref":"DP-NONE-xxxxxxxx-00000000","action":"http_header"}'; }
codes=""; for i in 1 2 3 4 5; do codes="$codes $(RT "$A")"; done
! echo "$codes" | grep -q 429 && [ "$(RT "$A")" = 429 ] && ok "wallet A: 5 requests answered, the 6th refused (its own budget)" || fail "A: $codes"
codes=""; for i in 1 2 3 4 5; do codes="$codes $(RT "$B")"; done
! echo "$codes" | grep -q 429 && ok "wallet B behind the same address still has its full budget (was: shared per address)" || fail "B: $codes"
U=$(curl -s -X POST "$API/api/demipass/use" -H 'content-type: application/json' -H "Authorization: Bearer $A" -d '{}' -w ' %{http_code}'); echo "$U" | grep -q "429" && echo "$U" | grep -q "this wallet" && ok "/use shares the wallet's budget (A already spent it)" || fail "use: $U"
codes=""; for i in 1 2; do codes="$codes $(RT "")"; done
! echo "$codes" | grep -q 429 && ok "no token: limited by address, separately from the wallets" || fail "anon: $codes"
X=$(RT "not-a-real-token"); [ "$X" != 429 ] && ok "an invalid token is keyed by address (cannot pick its own bucket)" || fail "fake token: $X"
# A keeps retrying past its own limit: its refused retries must not use up the address (#103 review M1)
for i in $(seq 1 20); do RT "$A" >/dev/null; done
X=$(RT "$Cw"); [ "$X" != 429 ] && ok "wallet A retrying 20 times after its 429s does not lock out another wallet (C)" || fail "retry lockout: $X"
# counted against the address: A 5 + B 5 + anon 2 + fake 1 + C 1 = 14 (A's refused retries and /use never reach it);
# one more C passes (15), the next is over the ceiling
RT "$Cw" >/dev/null
C=$(curl -s -X POST "$API/api/demipass/request-token" -H 'content-type: application/json' -H "Authorization: Bearer $Cw" -d '{}' -w ' %{http_code}')
echo "$C" | grep -q "429" && echo "$C" | grep -q "this address" && ok "the per-address ceiling still holds across wallets" || fail "ceiling: $C"
echo; [ $fails = 0 ] && echo "ALL OK" || echo "$fails FAILED"; exit $fails
