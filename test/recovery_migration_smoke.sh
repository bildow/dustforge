#!/bin/bash
# Item 9 step 1 on a pre-existing database (the migration-fixture rule): the previous main runs first on a fresh DB,
# a phone is linked and a biometric proof made there; then this code starts on the same DB. The new columns
# (device_keys.revoked_via, device_gate_proofs.device_id, identity_wallets.password_must_change) and tables appear,
# the phone linked before still counts, and it can cancel a hold (a PIN reset by password) without a session.
set -u
W=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
S=$(mktemp -d /tmp/dustforge-recovery-migr.XXXXXX)
PORT=${PORT:-3861}; API=http://127.0.0.1:$PORT
[ -d "$W/node_modules" ] || export NODE_PATH=${NODE_PATH:-/home/flimflam/project/dustforge/node_modules}
export IDENTITY_MASTER_KEY=$(python3 -c 'import secrets;print(secrets.token_hex(32))') DB_PATH=$S/dustforge.db PORT HOLD_SWEEP_MS=500 \
  STALWART_HOST=127.0.0.1 STALWART_PORT=1 SMTP_RELAY_HOST= SMTP_HOST=127.0.0.1 SMTP_PORT=9
# The main before item 9 (#58 merged, bf5f75f): its DB has none of the item 9 tables or columns.
BASE=${BASE_REF:-bf5f75f}
mkdir -p "$S/old"; git -C "$W" archive "$BASE" | tar -x -C "$S/old"
SRV=; trap 'kill $SRV 2>/dev/null; rm -rf "$S"' EXIT
boot(){ (cd "$1" && exec node server.js >>"$S/server.log" 2>&1) & SRV=$!; for i in $(seq 1 60); do curl -s -o /dev/null "$API/api/health" && break; sleep 0.5; done; sleep 1; }
boot "$S/old"
H=$(printf '%s' hunter22 | sha256sum | cut -d' ' -f1)
(cd "$W" && node -e '
const identity = require("./identity"); const Database = require("better-sqlite3"); const db = new Database(process.env.DB_PATH);
const id = identity.createIdentity(); const enc = id.encrypted_private_key || id.encryptedPrivateKey;
db.prepare("INSERT INTO identity_wallets (did, username, email, encrypted_private_key, balance_cents, password_hash) VALUES (?, ?, ?, ?, 0, ?)").run(id.did, "owner-a", "owner-a@dustforge.com", enc, process.argv[1]);' "$H")
fails=0; ok(){ echo "ok   $*"; }; fail(){ echo "FAIL $*"; fails=$((fails+1)); }
J(){ python3 -c 'import json,sys; d=json.load(sys.stdin); v=d
for k in sys.argv[1].split("."): v=(v or {}).get(k)
print(v)' "$1"; }
Q(){ python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); r=c.execute(sys.argv[2]).fetchone(); print(r[0] if r else '')" "$DB_PATH" "$1"; }
call(){ local m=$1 p=$2 t=$3 b=${4:-}
  BODY=$(curl -s -o - -w '\n%{http_code}' -X "$m" "$API$p" -H 'Content-Type: application/json' ${t:+-H "Authorization: Bearer $t"} ${b:+-d "$b"})
  CODE=${BODY##*$'\n'}; BODY=${BODY%$'\n'*}; }
login(){ call POST /api/identity/auth-fingerprint "" '{"username":"owner-a","password":"hunter22","scope":"transact","expires_in":"1h"}'; echo "$BODY" | J token; }
sig(){ node -e 'const c=require("crypto"),fs=require("fs"); process.stdout.write(c.sign("sha256", Buffer.from(process.argv[2]), fs.readFileSync(process.argv[1])).toString("base64"))' "$S/$1.pem" "$2"; }
node -e 'const c = require("crypto"), fs = require("fs");
for (const k of ["d", "p"]) { const { privateKey, publicKey } = c.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  fs.writeFileSync(process.argv[1] + "/" + k + ".pem", privateKey.export({ type: "pkcs8", format: "pem" }));
  fs.writeFileSync(process.argv[1] + "/" + k + ".pub", publicKey.export({ type: "spki", format: "der" }).toString("base64")); }' "$S"
A=$(login); call POST /api/identity/pin "$A" '{"pin":"4321","password":"hunter22"}'
call POST /api/identity/device/challenge "$A" '{"purpose":"enrol","intent":"device-enrol:0"}'; ECH=$(echo "$BODY" | J challenge_id); EM="$(echo "$BODY" | J message):phone-old01"
call POST /api/identity/gate/verify "$A" '{"gate":"pin","pin":"4321","intent":"device-enrol:0"}'; call POST /api/identity/gate/verify "$A" '{"gate":"password","password":"hunter22"}'
call POST /api/identity/device/enrol "$A" '{"challenge_id":'$ECH',"device_id":"phone-old01","label":"old","key_d":"'$(cat $S/d.pub)'","key_p":"'$(cat $S/p.pub)'","sig_d":"'$(sig d "$EM")'","sig_p":"'$(sig p "$EM")'"}'
[ "$CODE" = 201 ] && ok "old code: a phone linked" || fail "old enrol: $CODE $BODY"
call POST /api/identity/device/challenge "$A" '{"purpose":"gate","intent":"unlock:0"}'; GM=$(echo "$BODY" | J message); GC=$(echo "$BODY" | J challenge_id)
call POST /api/identity/gate/verify "$A" '{"gate":"device","intent":"unlock:0","challenge_id":'$GC',"signature":"'$(sig p "$GM")'"}'; [ "$CODE" = 200 ] || fail "old bio: $CODE"
[ "$(Q "SELECT COUNT(*) FROM pragma_table_info('device_keys') WHERE name='revoked_via'")" = 0 ] && ok "old schema has no revoked_via (a real legacy DB)" || fail "not legacy"
kill $SRV; wait $SRV 2>/dev/null
boot "$W"
for c in "device_keys revoked_via" "device_gate_proofs device_id" "identity_wallets password_must_change" "blindkey_use_tokens executing_until" "recovery_guardians change_id"; do set -- $c
  [ "$(Q "SELECT COUNT(*) FROM pragma_table_info('$1') WHERE name='$2'")" = 1 ] || fail "column $1.$2 missing"; done
[ "$(Q "SELECT COUNT(*) FROM sqlite_master WHERE name IN ('account_holds','hold_challenges','recovery_guardians','recovery_email_history','recovery_challenges')")" = 5 ] && ok "new code on the old DB: columns and tables added" || fail "tables"
[ "$(Q "SELECT COUNT(*) FROM device_gate_proofs WHERE device_id IS NULL")" -ge 1 ] && ok "old biometric proofs keep working rows (device_id NULL)" || fail "old proofs"
A=$(login); call POST /api/identity/pin "$A" '{"pin":"5555","password":"hunter22"}'; HR=$(echo "$BODY" | J hold_id)
[ "$CODE" = 202 ] && ok "the phone linked under the old code counts: a PIN reset by password now waits" || fail "R0 on migrated: $CODE $BODY"
call POST /api/identity/holds/challenge "" '{"purpose":"cancel","device_id":"phone-old01","hold_id":"'$HR'"}'; CH=$(echo "$BODY" | J challenge); MSG=$(echo "$BODY" | J message)
call POST /api/identity/holds/$HR/cancel "" '{"device_id":"phone-old01","challenge":"'$CH'","signature":"'$(sig p "$MSG")'"}'
[ "$CODE" = 200 ] && ok "…and that old phone cancels it without a session" || fail "cancel on migrated: $CODE $BODY"
echo; [ $fails = 0 ] && echo "ALL PASS" || { echo "$fails FAILED"; exit 1; }
