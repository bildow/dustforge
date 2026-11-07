#!/bin/bash
# Smoke of the DemiPass meter (meter.js) through the real server, on a throwaway DB:
#   - /api/meter/rates and /api/meter/key are public; the key is a did:key (Ed25519);
#   - POST /api/meter/charge needs the wallet's own transact token (none → 401; read scope, a fleet worker or a silicon
#     token → 403), bills units × rate (201), and the
#     receipt verifies OFFLINE from the issuer did:key alone;
#   - the same receipt_sha256 again → 200 replayed, same charge_id, no second debit; other units → 409;
#   - bad tenant/sku/units/hash → 400; too little DD → 402 with nothing recorded;
#   - /api/meter/verify: valid + on_record; an edited receipt is invalid;
#   - after a restart the issuer is the same and the old receipt still verifies;
#   - /api/meter/charges lists only the caller's charges.
# No network beyond 127.0.0.1.
set -u
W=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
S=$(mktemp -d /tmp/dustforge-meter-smoke.XXXXXX)
PORT=${PORT:-3798}; API=http://127.0.0.1:$PORT
[ -d "$W/node_modules" ] || export NODE_PATH=${NODE_PATH:-/home/flimflam/project/dustforge/node_modules}
export IDENTITY_MASTER_KEY=$(python3 -c 'import secrets;print(secrets.token_hex(32))') DB_PATH=$S/dustforge.db PORT \
  STALWART_HOST=127.0.0.1 STALWART_PORT=1 SMTP_RELAY_HOST= SMTP_HOST=127.0.0.1 SMTP_PORT=9
cd "$W"
start(){ node server.js >>"$S/server.log" 2>&1 & SRV=$!
  for i in $(seq 1 40); do curl -s -o /dev/null "$API/api/health" && break; sleep 0.5; done
  kill -0 $SRV 2>/dev/null || { echo "server died:"; tail -5 "$S/server.log"; exit 1; }; }
start
trap 'kill $SRV 2>/dev/null; rm -rf "$S"' EXIT
fails=0; ok(){ echo "ok   $*"; }; fail(){ echo "FAIL $*"; fails=$((fails+1)); }
J(){ python3 -c 'import json,sys
v = json.load(sys.stdin)
for k in sys.argv[1].split("."):
    v = v[int(k)] if isinstance(v, list) else (v or {}).get(k)
print(v)' "$1"; }
Q(){ python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); r=c.execute(sys.argv[2]).fetchone(); print(r[0] if r else '')" "$DB_PATH" "$1"; }

node -e '
const identity = require("./identity"); const Database = require("better-sqlite3"); const crypto = require("crypto");
const db = new Database(process.env.DB_PATH);
for (const [u, bal] of [["bench", 1000], ["poor", 5]]) {
  const id = identity.createIdentity();
  db.prepare("INSERT INTO identity_wallets (did, username, email, encrypted_private_key, balance_cents, password_hash) VALUES (?, ?, ?, ?, ?, ?)")
    .run(id.did, u, u + "@dustforge.com", id.encrypted_private_key || id.encryptedPrivateKey, bal, crypto.createHash("sha256").update("hunter22").digest("hex"));
  db.prepare("INSERT INTO identity_transactions (did, amount_cents, type, description, balance_after) VALUES (?, ?, ?, ?, ?)").run(id.did, bal, "test_grant", "smoke", bal);
}'
login(){ curl -s -X POST "$API/api/identity/auth-fingerprint" -H 'content-type: application/json' -d '{"username":"'$1'","password":"hunter22","scope":"'$2'","expires_in":"1h"}' | J token; }
TOK=$(login bench transact); POOR=$(login poor transact); READ=$(login bench read)
[ -n "$TOK" ] && [ "$TOK" != None ] && [ "$READ" != None ] || { echo "FAIL sign-in"; exit 1; }
BAL(){ Q "SELECT balance_cents FROM identity_wallets WHERE username='$1'"; }
# A worker token (wrk claim, its own spend cap in fleet_billing) and a silicon token (acts for its carbon) for bench.
WRK=$(node -e '
const identity = require("./identity"); const Database = require("better-sqlite3"); const crypto = require("crypto");
const db = new Database(process.env.DB_PATH); const w = db.prepare("SELECT did, encrypted_private_key FROM identity_wallets WHERE username = ?").get("bench");
db.prepare("INSERT INTO silicon_agents (agent_name, did, carbon_did, token_hash) VALUES (?, ?, ?, ?)").run("meter-sil", "did:key:zMeterSil", w.did, crypto.createHash("sha256").update("silicon:meter-smoke").digest("hex"));
process.stdout.write(identity.createTokenForIdentity(w.encrypted_private_key, w.did, { scope: "transact", expiresIn: "1h", metadata: { wrk: "w-smoke", wname: "smoke", auth_method: "worker" } }));')
H1=$(printf receipt-one | sha256sum | cut -d' ' -f1)

CODE=$(curl -s -o "$S/rates" -w '%{http_code}' "$API/api/meter/rates")
[ "$CODE" = 200 ] && [ "$(J rates.eval-rig.provision < "$S/rates")" = 10 ] && ok "rates are public (eval-rig/provision = 10 DD)" || fail "rates: $CODE"
curl -s "$API/api/meter/key" > "$S/key"; ISSUER=$(J issuer < "$S/key")
[[ "$ISSUER" == did:key:z6Mk* ]] && ok "the meter key is a public Ed25519 did:key" || fail "key: $(cat "$S/key")"

C(){ CODE=$(curl -s -o "$S/out" -w '%{http_code}' -X POST "$API/api/meter/charge" ${2:+-H "Authorization: Bearer $2"} -H 'content-type: application/json' -d "$1"); }
BODY='{"tenant":"eval-rig","sku":"provision","units":3,"receipt_sha256":"'$H1'"}'
C "$BODY"; [ "$CODE" = 401 ] && ok "no token → 401" || fail "no token: $CODE"
C "$BODY" "$READ"; [ "$CODE" = 403 ] && ok "read-scope token → 403" || fail "read scope: $CODE"
C "$BODY" "$WRK"; [ "$CODE" = 403 ] && ok "a fleet worker token → 403 (its spend cap lives in fleet billing)" || fail "worker: $CODE $(cat "$S/out")"
C "$BODY" "silicon:meter-smoke"; [ "$CODE" = 403 ] && ok "a silicon token → 403 (only a wallet's own token charges)" || fail "silicon: $CODE $(cat "$S/out")"
B0=$(BAL bench)
C "$BODY" "$TOK"; cp "$S/out" "$S/first"; CID=$(J charge_id < "$S/first")
[ "$CODE" = 201 ] && [ "$(J dd < "$S/first")" = 30 ] && [ "$(BAL bench)" = $((B0 - 30)) ] && [ "$(J issuer < "$S/first")" = "$ISSUER" ] \
  && ok "charge: 3 × 10 DD billed to the caller (201, $CID)" || fail "charge: $CODE $(cat "$S/out")"
[ "$(Q "SELECT COUNT(*) FROM identity_transactions WHERE type='meter_charge' AND amount_cents=-30")" = 1 ] && ok "one meter_charge row in identity_transactions" || fail "tx rows"

# Offline: nothing from this server but the issuer did:key in the receipt.
node -e '
const crypto = require("crypto"); const identity = require("./identity");
const r = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"));
const issuer = JSON.parse(r.receipt).issuer;
const pub = crypto.createPublicKey({ key: identity.didToPublicKey(issuer), format: "der", type: "spki" });
process.exit(crypto.verify(null, Buffer.from(r.receipt, "utf8"), pub, Buffer.from(r.sig, "base64url")) ? 0 : 1);' "$S/first" \
  && ok "the receipt verifies offline from its issuer did:key" || fail "offline verify"

C "$BODY" "$TOK"; [ "$CODE" = 200 ] && [ "$(J replayed < "$S/out")" = True ] && [ "$(J charge_id < "$S/out")" = "$CID" ] && [ "$(BAL bench)" = $((B0 - 30)) ] \
  && ok "the same receipt again → 200 replayed, same charge, no second debit" || fail "replay: $CODE $(cat "$S/out")"
C '{"tenant":"eval-rig","sku":"provision","units":4,"receipt_sha256":"'$H1'"}' "$TOK"; [ "$CODE" = 409 ] && ok "same receipt, other units → 409" || fail "409: $CODE"
bad=0; for b in '{"tenant":"nope","sku":"provision","units":1,"receipt_sha256":"'$H1'"}' '{"tenant":"eval-rig","sku":"x","units":1,"receipt_sha256":"'$H1'"}' \
  '{"tenant":"eval-rig","sku":"score","units":0,"receipt_sha256":"'$H1'"}' '{"tenant":"eval-rig","sku":"score","units":1,"receipt_sha256":"zz"}'; do
  C "$b" "$TOK"; [ "$CODE" = 400 ] || bad=1; done
[ $bad = 0 ] && ok "bad tenant / sku / units / hash → 400" || fail "validation"
C '{"tenant":"eval-rig","sku":"score","units":1,"receipt_sha256":"'$H1'"}' "$POOR"
[ "$CODE" = 402 ] && [ "$(BAL poor)" = 5 ] && [ "$(Q "SELECT COUNT(*) FROM meter_charges WHERE did=(SELECT did FROM identity_wallets WHERE username='poor')")" = 0 ] \
  && ok "too little DD → 402, nothing billed or recorded" || fail "402: $CODE $(cat "$S/out")"

V(){ CODE=$(curl -s -o "$S/v" -w '%{http_code}' -X POST "$API/api/meter/verify" -H 'content-type: application/json' -d "$1"); }
VB=$(python3 -c 'import json,sys; r=json.load(open(sys.argv[1])); print(json.dumps({"receipt":r["receipt"],"sig":r["sig"]}))' "$S/first")
V "$VB"; [ "$CODE" = 200 ] && [ "$(J valid < "$S/v")" = True ] && [ "$(J on_record < "$S/v")" = True ] && ok "verify: valid and on record" || fail "verify: $CODE $(cat "$S/v")"
V "$(python3 -c 'import json,sys; r=json.load(open(sys.argv[1])); print(json.dumps({"receipt":r["receipt"].replace("\"dd\":30","\"dd\":1"),"sig":r["sig"]}))' "$S/first")"
[ "$(J valid < "$S/v")" = False ] && ok "verify: an edited receipt is invalid" || fail "tamper: $(cat "$S/v")"

kill $SRV; wait $SRV 2>/dev/null; start
[ "$(curl -s "$API/api/meter/key" | J issuer)" = "$ISSUER" ] && { V "$VB"; [ "$(J valid < "$S/v")" = True ]; } \
  && ok "after a restart: same issuer, the old receipt still verifies" || fail "restart: issuer or verify changed"

curl -s "$API/api/meter/charges" -H "Authorization: Bearer $TOK" > "$S/list"
[ "$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))["charges"]))' "$S/list")" = 1 ] && [ "$(J charges.0.charge_id < "$S/list")" = "$CID" ] \
  && ok "charges lists the caller's one charge" || fail "list: $(cat "$S/list")"
[ "$(curl -s "$API/api/meter/charges" -H "Authorization: Bearer $POOR" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["charges"]))')" = 0 ] && ok "…and not to another caller" || fail "list leak"

[ $fails -gt 0 ] && { echo "--- server.log"; grep -i -m5 "error" "$S/server.log"; }
echo "$fails failure(s)"; exit $(( fails > 0 ))
