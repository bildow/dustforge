#!/bin/bash
# Smoke, on a throwaway DB, for two gateway defects found in the FLEETGATE facts check (2026-11-14):
#   G2  checkTokenRevocation failed OPEN: a database fault in the revocation lookup answered "not revoked". It now
#       fails closed: while the lookup cannot run, tokens are refused; once it can, they work again.
#   Op  POST /api/fleet/:slug/board/:project/operators checked only the signature and a fleet_members role. An operator
#       spends the owner's DD (project billing), uncapped, so: live token, the owner's own sign-in (no worker), transact
#       scope, the fleet OWNER only, an existing active wallet, and the owner's PIN for that exact grant.
# No network beyond 127.0.0.1.
set -u
W=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
S=$(mktemp -d /tmp/dustforge-gwdefects-smoke.XXXXXX)
PORT=${PORT:-3795}; API=http://127.0.0.1:$PORT
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
for (const u of ["owner-a", "admin-b", "op-c", "project-bench"]) { const id = identity.createIdentity(); const enc = id.encrypted_private_key || id.encryptedPrivateKey;
  db.prepare("INSERT INTO identity_wallets (did, username, email, encrypted_private_key, balance_cents, password_hash) VALUES (?, ?, ?, ?, 100000, ?)").run(id.did, u, u + "@dustforge.com", enc, u === "project-bench" ? null : process.argv[1]);
  db.prepare("INSERT INTO identity_transactions (did, amount_cents, type, description, balance_after) VALUES (?, 100000, ?, ?, 100000)").run(id.did, "topup", "smoke"); }' "$H"
fails=0; ok(){ echo "ok   $*"; }; fail(){ echo "FAIL $*"; fails=$((fails+1)); }
J(){ python3 -c 'import json,sys; d=json.load(sys.stdin); v=d
for k in sys.argv[1].split("."):
    v = v[int(k)] if isinstance(v, list) else (v or {}).get(k)
print(v)' "$1"; }
Q(){ python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); r=c.execute(sys.argv[2]).fetchone(); c.commit(); print(r[0] if r else '')" "$DB_PATH" "$1"; }
X(){ python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute(sys.argv[2]); c.commit()" "$DB_PATH" "$1"; }
call(){ local m=$1 p=$2 t=$3 b=${4:-}
  BODY=$(curl -s -o - -w '\n%{http_code}' -X "$m" "$API$p" -H 'Content-Type: application/json' ${t:+-H "Authorization: Bearer $t"} ${b:+-d "$b"})
  CODE=${BODY##*$'\n'}; BODY=${BODY%$'\n'*}; }
login(){ call POST /api/identity/auth-fingerprint "" '{"username":"'$1'","password":"hunter22","scope":"'${2:-transact}'","expires_in":"1h"}'; echo "$BODY" | J token; }
DID(){ Q "SELECT did FROM identity_wallets WHERE username='$1'"; }
A=$(login owner-a); AR=$(login owner-a read); B=$(login admin-b)
call POST /api/identity/pin "$A" '{"pin":"4321","password":"hunter22"}'
PIN(){ call POST /api/identity/gate/verify "$A" '{"gate":"pin","pin":"4321","intent":"'$1'"}'; }

# ── G2: the revocation lookup fails closed ──
call GET /api/identity/ledger "$A"; [ "$CODE" = 200 ] && ok "a live token works" || fail "baseline: $CODE $BODY"
X "ALTER TABLE token_revocations RENAME TO token_revocations_away"
call GET /api/identity/ledger "$A"
[ "$CODE" = 401 ] && echo "$BODY" | grep -q "could not be checked" && ok "while the revocation lookup fails, the token is refused (fails closed; was: let through)" || fail "G2 open: $CODE $BODY"
grep -q "\[revocation\] lookup failed" "$S/server.log" && ok "…and the server logs it" || fail "no log line"
X "ALTER TABLE token_revocations_away RENAME TO token_revocations"
call GET /api/identity/ledger "$A"; [ "$CODE" = 200 ] && ok "once the lookup works again, the same token works" || fail "recovery: $CODE $BODY"
R=$(node -e 'const b=require("./billing"); const db={prepare(){throw new Error("SQLITE_IOERR")}}; process.stdout.write(JSON.stringify(b.checkTokenRevocation(db,{jti:"x",sub:"did:x",iat:1})))')
echo "$R" | grep -q '"revoked":true' && ok "unit: a throwing database answers revoked:true ($R)" || fail "unit: $R"

# ── the add-operator guard ──
call POST /api/fleet/create "$A" '{"name":"Fleet One","slug":"fleet-one"}'; [ "$CODE" = 200 ] || fail "fleet create: $CODE $BODY"
FID=$(Q "SELECT id FROM fleets WHERE slug='fleet-one'"); BENCH=$(DID project-bench); C=$(DID op-c); BD=$(DID admin-b)
X "INSERT INTO fleet_projects (fleet_id, project, owner_did, wallet_did, lane_address) VALUES ($FID, 'bench', '$BENCH', '$BENCH', 'bench.claude@dustforge.com')"
X "INSERT OR IGNORE INTO fleet_members (fleet_id, member_did, role) VALUES ($FID, '$BD', 'admin')"
PID=$(Q "SELECT id FROM fleet_projects WHERE project='bench'")
OPS(){ Q "SELECT COUNT(*) FROM fleet_project_operators WHERE project_id=$PID"; }
ADD(){ call POST /api/fleet/fleet-one/board/bench/operators "$1" '{"operator_did":"'$2'"}'; }

ADD "$A" "$C"; [ "$CODE" = 403 ] && echo "$BODY" | grep -q "project-operator:$PID\"" && [ "$(OPS)" = 0 ] && ok "the owner without the PIN → 403 asking for the PIN (intent project-operator:<project id>), nothing added" || fail "no pin: $CODE $BODY"
ADD "$AR" "$C"; [ "$CODE" = 403 ] && [ "$(OPS)" = 0 ] && ok "a read-scope owner token → 403 (was: accepted)" || fail "read scope: $CODE $BODY"
ADD "$B" "$C"; [ "$CODE" = 403 ] && echo "$BODY" | grep -q "owner" && [ "$(OPS)" = 0 ] && ok "a fleet admin → 403: an operator spends the owner's DD (was: accepted)" || fail "admin: $CODE $BODY"
ADD "$A" "did:key:zNotAWallet"; [ "$CODE" = 404 ] && ok "an operator that is not a wallet → 404 (was: stored)" || fail "nonexistent: $CODE $BODY"
WK=$(curl -s -X POST "$API/api/silicons/workers" -H 'content-type: application/json' -H "Authorization: Bearer $A" -d '{"name":"op-wk","mint":true}' | python3 -c 'import json,sys; d=json.load(sys.stdin); print((d.get("minted") or {}).get("token",""))')
[ -n "$WK" ] && { ADD "$WK" "$C"; [ "$CODE" = 403 ] && [ "$(OPS)" = 0 ] && ok "the owner's worker token → 403 (was: accepted)" || fail "worker: $CODE $BODY"; } || fail "could not mint a worker"
RV=$(login owner-a); RJ=$(python3 -c 'import sys,json,base64; p=sys.argv[1].split(".")[1]; print(json.loads(base64.urlsafe_b64decode(p+"="*(-len(p)%4)))["jti"])' "$RV")
call POST /api/identity/tokens/revoke "$RV" '{"jti":"'$RJ'"}'; [ "$CODE" = 200 ] || fail "revoke: $CODE $BODY"
ADD "$RV" "$C"; [ "$CODE" = 401 ] && [ "$(OPS)" = 0 ] && ok "a revoked owner token → 401 (was: accepted)" || fail "revoked: $CODE $BODY"
PIN "project-operator:$PID"; [ "$CODE" = 200 ] || fail "pin verify: $CODE $BODY"
ADD "$A" "$C"; [ "$CODE" = 200 ] && [ "$(OPS)" = 1 ] && ok "the owner with a fresh PIN for this grant → added" || fail "with pin: $CODE $BODY"
ADD "$A" "$BD"; [ "$CODE" = 403 ] && [ "$(OPS)" = 1 ] && ok "the PIN opens one grant: the next operator asks again" || fail "pin reuse: $CODE $BODY"
call DELETE "/api/fleet/fleet-one/board/bench/operators/$C" "$AR"; [ "$CODE" = 403 ] && [ "$(OPS)" = 1 ] && ok "removing needs a live transact sign-in too (read scope → 403)" || fail "delete read: $CODE $BODY"
call DELETE "/api/fleet/fleet-one/board/bench/operators/$C" "$B"; [ "$CODE" = 200 ] && [ "$(OPS)" = 0 ] && ok "an admin may remove an operator (narrows spending; no PIN)" || fail "delete admin: $CODE $BODY"

echo; [ $fails = 0 ] && echo "ALL OK" || echo "$fails FAILED"; exit $fails
