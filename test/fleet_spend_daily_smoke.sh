#!/bin/bash
# Daily spend per wallet (Aaron 2026-11-14): GET /api/fleet/:slug/spend/daily gives the fleet owner one line per wallet
# per UTC day (calls, DD, by action) read from the ledger. Refunds net against their action; transfers are not spend;
# only the owner reads it, and only wallets that are this fleet's (active silicons, project wallets the owner made).
set -u
W=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
S=$(mktemp -d /tmp/dustforge-spend-smoke.XXXXXX)
PORT=${PORT:-3933}; API=http://127.0.0.1:$PORT
[ -d "$W/node_modules" ] || export NODE_PATH=${NODE_PATH:-/home/flimflam/project/dustforge/node_modules}
export IDENTITY_MASTER_KEY=$(python3 -c 'import secrets;print(secrets.token_hex(32))') DB_PATH=$S/dustforge.db PORT \
  STALWART_HOST=127.0.0.1 STALWART_PORT=1 SMTP_RELAY_HOST= SMTP_HOST=127.0.0.1 SMTP_PORT=9
cd "$W"
( exec node server.js >"$S/server.log" 2>&1 ) & SRV=$!
trap 'kill $SRV 2>/dev/null; rm -rf "$S"' EXIT
for i in $(seq 1 40); do curl -s -o /dev/null "$API/" && break; sleep 0.5; done
kill -0 $SRV 2>/dev/null || { echo "server died:"; tail -5 "$S/server.log"; exit 1; }
H=$(printf '%s' hunter22 | sha256sum | cut -d' ' -f1)
node -e '
const identity = require("./identity"); const Database = require("better-sqlite3"); const db = new Database(process.env.DB_PATH);
const D = {};
for (const u of ["owner-a", "admin-b", "mci", "bench", "stranger", "otherproj"]) { const id = identity.createIdentity(); D[u] = id.did;
  db.prepare("INSERT INTO identity_wallets (did, username, email, encrypted_private_key, balance_cents, password_hash) VALUES (?, ?, ?, ?, 100000, ?)").run(id.did, u, u + "@dustforge.com", id.encrypted_private_key || id.encryptedPrivateKey, process.argv[1]); }
const f = db.prepare("INSERT INTO fleets (owner_did, name, slug) VALUES (?, ?, ?)").run(D["owner-a"], "A agents", "a-agents").lastInsertRowid;
const g = db.prepare("INSERT INTO fleets (owner_did, name, slug) VALUES (?, ?, ?)").run(D["admin-b"], "B agents", "b-agents").lastInsertRowid;
db.prepare("INSERT INTO fleet_members (fleet_id, member_did, role) VALUES (?, ?, ?)").run(f, D["admin-b"], "admin");
db.prepare("INSERT INTO fleet_silicons (fleet_id, member_did, handle, silicon_id) VALUES (?, ?, ?, ?)").run(f, D.mci, "mci", "sil_mci");
db.prepare("INSERT INTO fleet_silicons (fleet_id, member_did, handle, silicon_id) VALUES (?, ?, ?, ?)").run(g, D.stranger, "stranger", "sil_str");
db.prepare("INSERT INTO fleet_projects (fleet_id, project, owner_did, lane_address, wallet_did) VALUES (?, ?, ?, ?, ?)").run(f, "bench", D["owner-a"], "bench.x@dustforge.com", D.bench);
db.prepare("INSERT INTO fleet_projects (fleet_id, project, owner_did, lane_address, wallet_did) VALUES (?, ?, ?, ?, ?)").run(f, "otherproj", D["admin-b"], "o.x@dustforge.com", D.otherproj);
const tx = db.prepare("INSERT INTO identity_transactions (did, amount_cents, type, description, balance_after, created_at) VALUES (?, ?, ?, ?, 0, ?)");
const day = (n, t) => new Date(Date.now() - n * 86400000).toISOString().slice(0, 10) + " " + t;
const today = (t) => day(0, t);
for (let i = 0; i < 3; i++) tx.run(D.mci, -1, "api_call_compute", "API call: api_call_compute", today("00:00:0" + i));
tx.run(D.mci, 1, "api_call_compute_refund", "Refund: /use ended by a server restart (started x)", today("00:00:05"));
tx.run(D.mci, -2, "service_transfer_out", "service conduit/post cost 1 + 0% sc_abc (requested by x)", today("00:00:06"));
tx.run(D.mci, -10, "meter_charge", "meter eval-rig/provision x1 mc_1", today("00:00:07"));
tx.run(D.mci, -500, "transfer_out", "to someone", today("00:00:08"));
tx.run(D.mci, -50, "api_call_compute", "origination narrative generation", today("00:00:09"));
tx.run(D.mci, 400, "topup", "top-up", today("00:00:10"));
tx.run(D.mci, -10, "api_call_compute", "API call: api_call_compute", day(2, "23:59:59"));
tx.run(D.mci, -10, "api_call_compute", "API call: api_call_compute", day(6, "00:00:00"));
tx.run(D.mci, -10, "api_call_compute", "API call: api_call_compute", day(7, "23:59:59"));
tx.run(D.bench, -10, "email_send", "API call: email_send", today("00:00:11"));
tx.run(D.stranger, -1, "api_call_compute", "API call: api_call_compute", today("00:00:12"));
tx.run(D.otherproj, -1, "api_call_compute", "API call: api_call_compute", today("00:00:13"));
' "$H"
fails=0; ok(){ echo "ok   $*"; }; fail(){ echo "FAIL $*"; fails=$((fails+1)); }
login(){ curl -s -X POST "$API/api/identity/auth-fingerprint" -H 'content-type: application/json' -d '{"username":"'$1'","password":"hunter22","scope":"read","expires_in":"1h"}' | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])'; }
A=$(login owner-a); B=$(login admin-b); M=$(login mci)
get(){ curl -s -o "$S/out" -w '%{http_code}' "$API/api/fleet/$1/spend/daily$2" ${3:+-H "Authorization: Bearer $3"}; }
P(){ python3 -c "import json,sys; d=json.load(open('$S/out')); print($1)"; }

C=$(get a-agents "?wallets=mci,bench,nope" "$A")
[ "$C" = 200 ] && [ "$(P '[w["name"] for w in d["wallets"]]')" = "['mci', 'bench']" ] && [ "$(P 'd["not_found"]')" = "['nope']" ] \
  && ok "owner: mci and bench in the asked order; an unknown name is reported, not an error" || fail "owner: $C $(cat "$S/out")"
T=$(P 'd["wallets"][0]["days"][0]')
[ "$(P 'd["wallets"][0]["days"][0]["by_action"]["use"]')" = "{'calls': 3, 'refunded': 1, 'dd': 2}" ] && ok "today's /use: 3 calls, 1 refunded, 2 DD net" || fail "use: $T"
[ "$(P 'd["wallets"][0]["days"][0]["by_action"]["conduit/post"]["dd"]')" = 2 ] && [ "$(P 'd["wallets"][0]["days"][0]["by_action"]["meter:eval-rig/provision"]["dd"]')" = 10 ] \
  && ok "service and meter charges are named by their action (conduit/post, meter:eval-rig/provision)" || fail "actions: $T"
[ "$(P 'd["wallets"][0]["days"][0]["by_action"]["api_call_compute"]["dd"]')" = 50 ] && ok "a non-/use debit of the same type keeps its ledger type (not counted as a /use)" || fail "narrative: $T"
[ "$(P 'sorted(d["wallets"][0]["days"][0]["by_action"])')" = "['api_call_compute', 'conduit/post', 'meter:eval-rig/provision', 'use']" ] \
  && ok "transfers out and top-ups are not spend" || fail "not-spend: $T"
[ "$(P '(d["wallets"][0]["days"][0]["calls"], d["wallets"][0]["days"][0]["dd"])')" = "(6, 64)" ] && ok "the day's line: 6 calls, 64 DD" || fail "totals: $T"
[ "$(P 'len(d["wallets"][0]["days"])')" = 3 ] && ok "7 UTC days: today, 2 days ago and the 6th day back from its first second; the 7th day back is out" || fail "window: $(P 'd["wallets"][0]["days"]')"
[ "$(P 'd["wallets"][1]["days"][0]["by_action"]')" = "{'email_send': {'calls': 1, 'refunded': 0, 'dd': 10}}" ] && ok "the bench project wallet's own line" || fail "bench: $(cat "$S/out")"

C=$(get a-agents "" "$A"); N=$(P '[w["name"] for w in d["wallets"]]')
[ "$C" = 200 ] && [ "$N" = "['mci', 'bench']" ] && ok "all wallets: only this fleet's (not another fleet's silicon, not a project wallet someone else made)" || fail "all: $C $N"
C=$(get a-agents "?days=1&wallets=mci" "$A"); [ "$C" = 200 ] && [ "$(P 'len(d["wallets"][0]["days"])')" = 1 ] && ok "?days=1 is today only" || fail "days=1: $(cat "$S/out")"
C=$(get a-agents "" "$B"); [ "$C" = 403 ] && ok "a fleet admin is refused: ledgers are the owner's to read" || fail "admin: $C"
C=$(get a-agents "" "$M"); [ "$C" = 403 ] && ok "a silicon of the fleet is refused" || fail "silicon: $C"
C=$(get a-agents "" ""); [ "$C" = 401 ] && ok "no token: 401" || fail "anon: $C"
C=$(get b-agents "" "$A"); [ "$C" = 403 ] && ok "another fleet's spend is refused" || fail "other fleet: $C"

echo; [ $fails = 0 ] && echo "ALL OK" || echo "$fails FAILED"; exit $fails
