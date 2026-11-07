#!/bin/bash
# Item 9 step 2 — recovery guardians (design v1.1 § Setup — guardians; tests R4, R5). server.js on a throwaway DB;
# phones simulated with node crypto; in-person pairings seeded in network_peers (verified_via 'qr' / 'vouch').
#   R4  naming needs the owner's phone; eligibility: not a vouched-only contact, not an agent wallet, not the owner,
#       not an unpaired person, not someone without a phone; naming takes PIN + the owner's phone; the set is active
#       only when all three accept (each with their PIN + phone); then the last phone stays
#   R5  a change of an active set waits 48 h and is cancelable from the owner's phone (its invitations go); due and
#       fully accepted, it applies; one not accepted in time fails it (nothing changes); a guardian leaves at once;
#       removing the set ([]) goes through the 48 h too
set -u
W=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
S=$(mktemp -d /tmp/dustforge-guardians.XXXXXX)
PORT=${PORT:-3871}; API=http://127.0.0.1:$PORT
[ -d "$W/node_modules" ] || export NODE_PATH=${NODE_PATH:-/home/flimflam/project/dustforge/node_modules}
export IDENTITY_MASTER_KEY=$(python3 -c 'import secrets;print(secrets.token_hex(32))') DB_PATH=$S/dustforge.db PORT HOLD_SWEEP_MS=500 \
  STALWART_HOST=127.0.0.1 STALWART_PORT=1 SMTP_RELAY_HOST= SMTP_HOST=127.0.0.1 SMTP_PORT=9
cd "$W"
(exec node server.js >"$S/server.log" 2>&1) & SRV=$!
trap 'kill $SRV 2>/dev/null; [ -n "${KEEP:-}" ] || rm -rf "$S"' EXIT
for i in $(seq 1 60); do curl -s -o /dev/null "$API/api/health" && break; sleep 0.5; done
kill -0 $SRV 2>/dev/null || { echo "server died:"; tail -5 "$S/server.log"; exit 1; }
sleep 1
H=$(printf '%s' hunter22 | sha256sum | cut -d' ' -f1)
node -e '
const identity = require("./identity"); const Database = require("better-sqlite3"); const db = new Database(process.env.DB_PATH);
const pinGate = require("./pin_gate");
for (const u of ["owner", "g1", "g2", "g3", "g4", "vouched", "agent", "stranger", "nophone"]) { const id = identity.createIdentity(); const enc = id.encrypted_private_key || id.encryptedPrivateKey;
  db.prepare("INSERT INTO identity_wallets (did, username, email, encrypted_private_key, balance_cents, password_hash, pin_hash, pin_set_at) VALUES (?, ?, ?, ?, 0, ?, ?, ?)")
    .run(id.did, u, u + "@dustforge.com", enc, process.argv[1], pinGate.hashPin("4321"), "2026-01-01 00:00:00.000"); }' "$H"
fails=0; ok(){ echo "ok   $*"; }; fail(){ echo "FAIL $*"; fails=$((fails+1)); }
J(){ python3 -c 'import json,sys; d=json.load(sys.stdin); v=d
for k in sys.argv[1].split("."):
    v = v[int(k)] if isinstance(v, list) else (v or {}).get(k)
print(v)' "$1"; }
Q(){ python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); r=c.execute(sys.argv[2]).fetchone(); print(r[0] if r else '')" "$DB_PATH" "$1"; }
X(){ python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute(sys.argv[2]); c.commit()" "$DB_PATH" "$1"; }
call(){ local m=$1 p=$2 t=$3 b=${4:-}
  BODY=$(curl -s -o - -w '\n%{http_code}' -X "$m" "$API$p" -H 'Content-Type: application/json' -H "X-Forwarded-For: 10.$((RANDOM%250)).$((RANDOM%250)).$((RANDOM%250+1))" ${t:+-H "Authorization: Bearer $t"} ${b:+-d "$b"})
  CODE=${BODY##*$'\n'}; BODY=${BODY%$'\n'*}; }
iso(){ python3 -c "import datetime,sys; print((datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(seconds=float(sys.argv[1]))).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3]+'Z')" "$1"; }
did(){ Q "SELECT did FROM identity_wallets WHERE username='$1'"; }
login(){ call POST /api/identity/auth-fingerprint "" '{"username":"'$1'","password":"hunter22","scope":"transact","expires_in":"1h"}'; echo "$BODY" | J token; }
pin(){ call POST /api/identity/gate/verify "$1" '{"gate":"pin","pin":"4321","intent":"'$2'"}'; [ "$CODE" = 200 ] || fail "pin $2: $CODE $BODY"; }
keys(){ node -e 'const c = require("crypto"), fs = require("fs");
for (const k of ["d", "p"]) { const { privateKey, publicKey } = c.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  fs.writeFileSync(process.argv[1] + "/" + process.argv[2] + k + ".pem", privateKey.export({ type: "pkcs8", format: "pem" }));
  fs.writeFileSync(process.argv[1] + "/" + process.argv[2] + k + ".pub", publicKey.export({ type: "spki", format: "der" }).toString("base64")); }' "$S" "$1"; }
sig(){ node -e 'const c=require("crypto"),fs=require("fs"); process.stdout.write(c.sign("sha256", Buffer.from(process.argv[2]), fs.readFileSync(process.argv[1])).toString("base64"))' "$S/$1.pem" "$2"; }
phone(){ keys "$1"; for k in D P; do X "INSERT INTO device_keys (did, device_id, kind, public_key, label, enrolled_at) VALUES ('$(did $1)', 'phone-$1', '$k', '$(cat $S/$1$(echo $k | tr DP dp).pub)', '$1', '$(iso -864000)')"; done; }
pair(){ local a b; a=$(did $1); b=$(did $2); [[ "$a" > "$b" ]] && { local t=$a; a=$b; b=$t; }
  X "INSERT INTO network_peers (did_a, did_b, status, verified_via, verified_at) VALUES ('$a', '$b', 'active', '$3', '$(iso 0)')"; }
# the user's phone approves (D) the decision <kind>:<id> about <bind>, after the session is unlocked; prints the body fields
approve(){ local tok=$1 user=$2 intent=$3 bind=$4
  call POST /api/identity/gate/verify "$tok" '{"gate":"pin","pin":"4321","intent":"unlock:0"}'
  call POST /api/identity/device/challenge "$tok" '{"purpose":"approve","intent":"'$intent'","bind":"'$bind'"}'
  echo '"device_challenge_id":'$(echo "$BODY" | J challenge_id)',"device_signature":"'$(sig ${user}d "$(echo "$BODY" | J message)")'"'; }
for u in g1 g2 g3 g4 vouched agent stranger; do phone $u; done
for u in g1 g2 g3 g4; do pair owner $u qr; done; pair owner vouched vouch; pair owner agent qr; pair owner nophone qr
X "INSERT INTO fleet_silicons (fleet_id, member_did, handle, silicon_id, status) VALUES (1, '$(did agent)', 'agent', 'sil_test0001', 'active')"
O=$(login owner)
# ── R4 ──
call POST /api/identity/guardians "$O" '{"guardians":["g1","g2","g3"]}'
[ "$CODE" = 409 ] && echo "$BODY" | grep -q "link your phone" && ok "R4 naming guardians needs the owner's linked phone" || fail "R4 no phone: $CODE $BODY"
phone owner
for case in "vouched:introduction" "agent:in person" "owner:own guardian" "stranger:in person" "nophone:phone linked" "nosuchuser:in person"; do who=${case%%:*}; why=${case#*:}
  call POST /api/identity/guardians "$O" '{"guardians":["g1","g2","'$who'"]}'
  [ "$CODE" = 409 ] && echo "$BODY" | grep -q "$why" && ok "R4 refused as a guardian: $who" || fail "R4 $who: $CODE $BODY"; done
call POST /api/identity/guardians "$O" '{"guardians":["g1","g2","g3"]}'; [ "$CODE" = 403 ] && [ "$(echo "$BODY" | J intent)" = guardian-set:0 ] && ok "R4 naming takes the PIN (guardian-set:0)" || fail "R4 pin: $CODE $BODY"
pin "$O" guardian-set:0; call POST /api/identity/guardians "$O" '{"guardians":["g1","g2","g3"]}'
{ [ "$CODE" = 428 ] || [ "$CODE" = 423 ]; } && ok "R4 …and the owner's phone (unlocked, device signature)" || fail "R4 phone sig: $CODE $BODY"
BIND(){ python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); r=sorted((c.execute('SELECT did FROM identity_wallets WHERE username=?',(u,)).fetchone()[0],u) for u in sys.argv[2:]); print(','.join(u+'='+d for d,u in r))" "$DB_PATH" "$@"; }
pin "$O" guardian-set:0; F=$(approve "$O" owner guardian-set:0 "$(BIND g1 g2 g3)")
call POST /api/identity/guardians "$O" '{"guardians":["g1","g2","g3"],'"$F"'}'
[ "$CODE" = 201 ] && ok "R4 three guardians invited" || fail "R4 invite: $CODE $BODY"
acc(){ local T; T=$(login $1); call GET /api/identity/guardians "$T"; local id; id=$(echo "$BODY" | python3 -c "import json,sys; d=json.load(sys.stdin); print([g['id'] for g in d['guarding'] if g['status']=='invited'][-1])")
  pin "$T" guardian-accept:$id; local F2; F2=$(approve "$T" $1 guardian-accept:$id owner)
  call POST /api/identity/guardians/$id/accept "$T" '{'"$F2"'}'; }
acc g1; acc g2
call GET /api/identity/guardians "$O"; [ "$(echo "$BODY" | J active)" = False ] && ok "R4 not active with two of three accepted" || fail "R4 2/3: $BODY"
T1=$(login g1); call GET /api/identity/guardians "$T1"
echo "$BODY" | grep -q '"owner":"owner"' && ! echo "$BODY" | grep -q '"g2"\|"g3"' && ok "R4 a guardian sees the owner's name, never the other guardians" || fail "R4 guardian view: $BODY"
acc g3; [ "$(echo "$BODY" | J set_active)" = True ] && ok "R4 the third acceptance makes the set active" || fail "R4 3/3: $CODE $BODY"
call POST /api/identity/device/challenge "$O" '{"purpose":"gate","intent":"device-revoke:0"}'; M=$(echo "$BODY" | J message); C=$(echo "$BODY" | J challenge_id)
call POST /api/identity/gate/verify "$O" '{"gate":"device","intent":"device-revoke:0","challenge_id":'$C',"signature":"'$(sig ownerp "$M")'"}'
pin "$O" device-revoke:0; call DELETE /api/identity/devices/phone-owner "$O"
[ "$CODE" = 409 ] && ok "R4 with guardians active the owner's last phone stays" || fail "R4 last phone: $CODE $BODY"
X "UPDATE device_gate_proofs SET used = 1"

# ── R5 ──
change(){ pin "$O" guardian-set:0; local F3; F3=$(approve "$O" owner guardian-set:0 "$( [ -n "$2" ] && BIND $(echo $2 | tr , ' '))"); call POST /api/identity/guardians "$O" '{"guardians":'$1','"$F3"'}'; HOLD=$(echo "$BODY" | J hold_id); }
change '["g1","g2","g4"]' "g1,g2,g4"
[ "$CODE" = 202 ] && [ "$(Q "SELECT COUNT(*) FROM recovery_guardians WHERE owner_did='$(did owner)' AND status='active'")" = 3 ] && ok "R5 changing an active set waits 48 h (202); the set is unchanged meanwhile" || fail "R5 change: $CODE $BODY"
acc g4
call POST /api/identity/holds/challenge "" '{"purpose":"cancel","device_id":"phone-owner","hold_id":"'$HOLD'"}'; CH=$(echo "$BODY" | J challenge); MSG=$(echo "$BODY" | J message)
call POST /api/identity/holds/$HOLD/cancel "" '{"device_id":"phone-owner","challenge":"'$CH'","signature":"'$(sig ownerp "$MSG")'"}'
[ "$CODE" = 200 ] && [ "$(Q "SELECT COUNT(*) FROM recovery_guardians WHERE guardian_did='$(did g4)' AND status IN ('invited','accepted','active')")" = 0 ] && ok "R5 canceled from the owner's phone: the new guardian's acceptance goes, the set stays" || fail "R5 cancel: $CODE $BODY"
change '["g1","g2","g4"]' "g1,g2,g4"; acc g4
X "UPDATE account_holds SET ready_at='$(iso -1)' WHERE id='$HOLD'"; sleep 2
[ "$(Q "SELECT status FROM account_holds WHERE id='$HOLD'")" = completed ] && [ "$(Q "SELECT COUNT(*) FROM recovery_guardians WHERE owner_did='$(did owner)' AND status='active' AND guardian_did='$(did g4)'")" = 1 ] \
  && [ "$(Q "SELECT COUNT(*) FROM recovery_guardians WHERE guardian_did='$(did g3)' AND status='active'")" = 0 ] && ok "R5 due and fully accepted: g4 in, g3 out" || fail "R5 apply: $(Q "SELECT status||' '||COALESCE(note,'') FROM account_holds WHERE id='$HOLD'")"
change '["g1","g2","g3"]' "g1,g2,g3"
X "UPDATE account_holds SET ready_at='$(iso -1)' WHERE id='$HOLD'"; sleep 2
[ "$(Q "SELECT status FROM account_holds WHERE id='$HOLD'")" = failed ] && [ "$(Q "SELECT COUNT(*) FROM recovery_guardians WHERE guardian_did='$(did g4)' AND status='active'")" = 1 ] && ok "R5 a new guardian who did not accept in time fails the change; nothing changes" || fail "R5 unaccepted: $(Q "SELECT status FROM account_holds WHERE id='$HOLD'")"
change '[]' ""
[ "$CODE" = 202 ] && ok "R5 removing the set also waits 48 h" || fail "R5 remove: $CODE $BODY"
call POST /api/identity/holds/challenge "" '{"purpose":"cancel","device_id":"phone-owner","hold_id":"'$HOLD'"}'; CH=$(echo "$BODY" | J challenge); MSG=$(echo "$BODY" | J message)
call POST /api/identity/holds/$HOLD/cancel "" '{"device_id":"phone-owner","challenge":"'$CH'","signature":"'$(sig ownerp "$MSG")'"}'
[ "$CODE" = 200 ] && [ "$(Q "SELECT COUNT(*) FROM recovery_guardians WHERE owner_did='$(did owner)' AND status='active'")" = 3 ] && ok "R5 …and canceled from the owner's phone, the set stays" || fail "R5 remove cancel: $CODE $BODY"
# M1: a guardian who leaves while a change that keeps them waits is not put back by it
change '["g1","g2","g4"]' "g1,g2,g4"
T2=$(login g2); call GET /api/identity/guardians "$T2"; G2ID=$(echo "$BODY" | python3 -c "import json,sys; d=json.load(sys.stdin); print([g['id'] for g in d['guarding'] if g['status']=='active'][0])")
call POST /api/identity/guardians/$G2ID/leave "$T2"
X "UPDATE account_holds SET ready_at='$(iso -1)' WHERE id='$HOLD'"; sleep 2
[ "$(Q "SELECT COUNT(*) FROM recovery_guardians WHERE guardian_did='$(did g2)' AND status='active'")" = 0 ] && [ "$(Q "SELECT status FROM account_holds WHERE id='$HOLD'")" = failed ] && ok "#60 M1: a guardian who left is not put back by a waiting change (it fails)" || fail "M1: $(Q "SELECT status||' '||COALESCE(note,'') FROM account_holds WHERE id='$HOLD'")"
# M2: the owner cannot drop a guardian by removing the contact; a guardian removing the owner leaves
call POST /api/network/people/remove "$O" '{"username":"g1"}'
[ "$CODE" = 409 ] && [ "$(Q "SELECT COUNT(*) FROM recovery_guardians WHERE guardian_did='$(did g1)' AND status='active'")" = 1 ] && ok "#60 M2: the owner removing a guardian's contact is refused (change the guardians first)" || fail "M2 owner remove: $CODE $BODY"
T1=$(login g1); call POST /api/network/people/remove "$T1" '{"username":"owner"}'
[ "$CODE" = 200 ] && [ "$(Q "SELECT COUNT(*) FROM recovery_guardians WHERE guardian_did='$(did g1)' AND status='active'")" = 0 ] && ok "#60 M2: a guardian removing the owner's contact leaves" || fail "M2 guardian remove: $CODE $BODY"
T4=$(login g4); call GET /api/identity/guardians "$T4"; GID=$(echo "$BODY" | python3 -c "import json,sys; d=json.load(sys.stdin); print([g['id'] for g in d['guarding'] if g['status']=='active'][0])")
call POST /api/identity/guardians/$GID/leave "$T4"
call GET /api/identity/guardians "$O"; [ "$(echo "$BODY" | J active)" = False ] && ok "R5 a guardian leaves at once; the set is no longer complete" || fail "R5 leave: $BODY"
change '[]' ""
[ "$CODE" = 409 ] && [ "$(Q "SELECT COUNT(*) FROM recovery_guardians WHERE owner_did='$(did owner)' AND status='active'")" = 0 ] && ok "R5 with every guardian gone there is nothing left to remove" || fail "R5 empty: $CODE $BODY"
A=$(login agent); call POST /api/identity/guardians "$A" '{"guardians":["g1","g2","g3"]}'; [ "$CODE" = 403 ] && ok "R4 an agent wallet cannot set guardians" || fail "R4 agent sets: $CODE"
echo; [ $fails = 0 ] && echo "ALL PASS" || { echo "$fails FAILED"; exit 1; }
