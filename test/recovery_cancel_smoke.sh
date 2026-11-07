#!/bin/bash
# Item 9 step 1 — the cancel path, tested before any recovery code exists (design v1.1, tome
# decisions/2026-11-07-demipass-item9-social-recovery-design.md). server.js on a throwaway DB; phones simulated with
# node crypto (P-256 D and P keys). Recovery holds are seeded in the DB (their creating routes come in step 3).
#   C1  an eligible phone's presence key cancels a recovery with no session; it stays canceled
#   C2  cancel refused: session only, D instead of P, replayed/expired challenge, another account's phone, a phone
#       removed 8 days before the start, a phone removed with a phone's presence; allowed: removed 2 days before, and
#       removed after the start. Every refusal is the same answer
#   C3  cancel works while pending and at quorum (the race with completion is tested with completion, step 3)
#   C4  a phone linked < 48 h removes no other phone; the last phone stays while guardians are set
#   C5  R0: a PIN reset with the password waits; the phone still works; a cancel ends every session and forces a new
#       password; uncanceled at 48 h it applies and unlinks; password + presence applies at once
#   C6  E1: a waiting phone can do nothing; cancel removes it; an established phone approves it at once; due → linked
#   C7  E2: a recovery-email change waits and is cancelable; with an established phone's presence it applies at once
#   C9  alerts: a D-signed, session-less call lists the account's waiting changes; another account's phone sees none
set -u
W=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
S=$(mktemp -d /tmp/dustforge-recovery-cancel.XXXXXX)
PORT=${PORT:-3851}; API=http://127.0.0.1:$PORT
[ -d "$W/node_modules" ] || export NODE_PATH=${NODE_PATH:-/home/flimflam/project/dustforge/node_modules}
export IDENTITY_MASTER_KEY=$(python3 -c 'import secrets;print(secrets.token_hex(32))') DB_PATH=$S/dustforge.db PORT HOLD_SWEEP_MS=500 \
  STALWART_HOST=127.0.0.1 STALWART_PORT=1 SMTP_RELAY_HOST= SMTP_HOST=127.0.0.1 SMTP_PORT=9
cd "$W"
node server.js >"$S/server.log" 2>&1 & SRV=$!
trap 'kill $SRV 2>/dev/null; [ -n "${KEEP:-}" ] || rm -rf "$S"' EXIT
for i in $(seq 1 60); do curl -s -o /dev/null "$API/api/health" && break; sleep 0.5; done
kill -0 $SRV 2>/dev/null || { echo "server died:"; tail -5 "$S/server.log"; exit 1; }
sleep 1
H=$(printf '%s' hunter22 | sha256sum | cut -d' ' -f1)
node -e '
const identity = require("./identity"); const Database = require("better-sqlite3"); const db = new Database(process.env.DB_PATH);
for (const c of ["idempotency_key TEXT", "provenance TEXT DEFAULT '"'"'organic'"'"'"]) { try { db.exec("ALTER TABLE identity_transactions ADD COLUMN " + c); } catch (_) {} }
for (const u of ["owner-a", "owner-b"]) { const id = identity.createIdentity(); const enc = id.encrypted_private_key || id.encryptedPrivateKey;
  db.prepare("INSERT INTO identity_wallets (did, username, email, encrypted_private_key, balance_cents, password_hash) VALUES (?, ?, ?, ?, 100000, ?)").run(id.did, u, u + "@dustforge.com", enc, process.argv[1]);
  db.prepare("INSERT INTO identity_transactions (did, amount_cents, type, description, balance_after) VALUES (?, 100000, ?, ?, 100000)").run(id.did, "topup", "smoke"); }' "$H"
fails=0; ok(){ echo "ok   $*"; }; fail(){ echo "FAIL $*"; fails=$((fails+1)); }
J(){ python3 -c 'import json,sys; d=json.load(sys.stdin); v=d
for k in sys.argv[1].split("."):
    v = v[int(k)] if isinstance(v, list) else (v or {}).get(k)
print(v)' "$1"; }
Q(){ python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); r=c.execute(sys.argv[2]).fetchone(); print(r[0] if r else '')" "$DB_PATH" "$1"; }
X(){ python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute(sys.argv[2]); c.commit()" "$DB_PATH" "$1"; }
call(){ local m=$1 p=$2 t=$3 b=${4:-}
  # each call from its own client address (trust proxy 1): the strict limiter is per IP, and this test makes many calls
  BODY=$(curl -s -o - -w '\n%{http_code}' -X "$m" "$API$p" -H 'Content-Type: application/json' -H "X-Forwarded-For: 10.$((RANDOM%250)).$((RANDOM%250)).$((RANDOM%250+1))" ${t:+-H "Authorization: Bearer $t"} ${b:+-d "$b"})
  CODE=${BODY##*$'\n'}; BODY=${BODY%$'\n'*}; }
login(){ call POST /api/identity/auth-fingerprint "" '{"username":"'${1:-owner-a}'","password":"hunter22","scope":"transact","expires_in":"1h"}'; echo "$BODY" | J token; }
pin(){ call POST /api/identity/gate/verify "$1" '{"gate":"pin","pin":"'${3:-4321}'","intent":"'$2'"}'; [ "$CODE" = 200 ] || fail "pin $2: $CODE $BODY"; }
pw(){ call POST /api/identity/gate/verify "$1" '{"gate":"password","password":"hunter22"}'; }
iso(){ python3 -c "import datetime,sys; print((datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(seconds=float(sys.argv[1]))).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3]+'Z')" "$1"; }
DID_A=$(Q "SELECT did FROM identity_wallets WHERE username='owner-a'"); DID_B=$(Q "SELECT did FROM identity_wallets WHERE username='owner-b'")
# phones: <name>d / <name>p key pairs
keys(){ node -e '
const c = require("crypto"), fs = require("fs");
for (const k of ["d", "p"]) { const { privateKey, publicKey } = c.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  fs.writeFileSync(process.argv[1] + "/" + process.argv[2] + k + ".pem", privateKey.export({ type: "pkcs8", format: "pem" }));
  fs.writeFileSync(process.argv[1] + "/" + process.argv[2] + k + ".pub", publicKey.export({ type: "spki", format: "der" }).toString("base64")); }' "$S" "$1"; }
sig(){ node -e 'const c=require("crypto"),fs=require("fs"); process.stdout.write(c.sign("sha256", Buffer.from(process.argv[2]), fs.readFileSync(process.argv[1])).toString("base64"))' "$S/$1.pem" "$2"; }
for p in pa pb pc pc2 pd px pr8 prd pr2 pra; do keys $p; done
# a phone row straight into the DB (for times the API cannot make): <phone> <did> <device_id> <enrolled_at> [revoked_at] [revoked_via]
seedphone(){ local rv=NULL rvia=NULL; [ -n "${5:-}" ] && rv="'$5'"; [ -n "${6:-}" ] && rvia="'$6'"
  for k in D P; do local f=$S/$1$(echo $k | tr DP dp).pub
    X "INSERT INTO device_keys (did, device_id, kind, public_key, label, enrolled_at, revoked_at, revoked_via) VALUES ('$2', '$3', '$k', '$(cat $f)', '$1', '$4', $rv, $rvia)"; done; }
# a seeded hold: <id> <did> <kind> <status> <created_at>
seedhold(){ X "INSERT INTO account_holds (id, did, kind, status, created_at, ready_at, payload) VALUES ('$1', '$2', '$3', '$4', '$5', '$(iso 172800)', '{}')"; }
# session-less: hch <purpose> <device_id> [hold] → CH, MSG ; cancel <hold> <device_id> <keyfile>
hch(){ call POST /api/identity/holds/challenge "" '{"purpose":"'$1'","device_id":"'$2'","hold_id":"'${3:-}'"}'; CH=$(echo "$BODY" | J challenge); MSG=$(echo "$BODY" | J message); }
cancel(){ hch cancel "$2" "$1"; [ "$CODE" = 200 ] || return 0; call POST /api/identity/holds/$1/cancel "" '{"device_id":"'$2'","challenge":"'$CH'","signature":"'$(sig $3 "$MSG")'"}'; }
NOT='{"error":"not available from this phone"}'
# session gate challenge signed by a key: gch <token> <key> <intent>
gch(){ call POST /api/identity/device/challenge "$1" '{"purpose":"gate","intent":"'$3'"}'; GCH=$(echo "$BODY" | J challenge_id); GSG=$(sig $2 "$(echo "$BODY" | J message)"); }

A=$(login); call POST /api/identity/pin "$A" '{"pin":"4321","password":"hunter22"}'
# the first phone links at once (no phone yet)
call POST /api/identity/device/challenge "$A" '{"purpose":"enrol","intent":"device-enrol:0"}'; ECH=$(echo "$BODY" | J challenge_id); EM="$(echo "$BODY" | J message):phone-aaaa1"
pin "$A" device-enrol:0; pw "$A"
call POST /api/identity/device/enrol "$A" '{"challenge_id":'$ECH',"device_id":"phone-aaaa1","label":"A","key_d":"'$(cat $S/pad.pub)'","key_p":"'$(cat $S/pap.pub)'","sig_d":"'$(sig pad "$EM")'","sig_p":"'$(sig pap "$EM")'"}'
[ "$CODE" = 201 ] && ok "setup: the first phone links at once (201)" || fail "first enrol: $CODE $BODY"
seedphone px "$DID_B" phone-xxxx1 "$(iso -864000)"

# ── C1 ──
NOWI=$(iso 0); seedhold 100000000001 "$DID_A" recovery quorum "$NOWI"
cancel 100000000001 phone-aaaa1 pap
[ "$CODE" = 200 ] && [ "$(Q "SELECT status FROM account_holds WHERE id='100000000001'")" = canceled ] && [ "$(Q "SELECT canceled_by FROM account_holds WHERE id='100000000001'")" = phone-aaaa1 ] \
  && ok "C1 the phone's presence key cancels a recovery at quorum, no session" || fail "C1 cancel: $CODE $BODY"
[ "$(Q "SELECT COUNT(*) FROM demipass_security_events WHERE event_type='account_hold_canceled'")" = 1 ] && ok "C1 a critical event is logged" || fail "C1 event"
cancel 100000000001 phone-aaaa1 pap; [ "$CODE" = 404 ] && [ "$(Q "SELECT status FROM account_holds WHERE id='100000000001'")" = canceled ] && ok "C1 a canceled hold stays canceled (nothing left to cancel)" || fail "C1 again: $CODE"

# ── C2 ──
START=$(iso -3600); seedhold 100000000002 "$DID_A" recovery pending "$START"
call POST /api/identity/holds/100000000002/cancel "$A" '{}'; [ "$CODE" = 404 ] && [ "$BODY" = "$NOT" ] && ok "C2 a session alone cancels nothing (same answer)" || fail "C2 session: $CODE $BODY"
seedhold 100000000009 "$DID_A" recovery pending "$(iso 0)"
hch cancel phone-aaaa1 100000000009; call POST /api/identity/holds/100000000009/cancel "" '{"device_id":"phone-aaaa1","challenge":"'$CH'","signature":"'$(sig pad "$MSG")'"}'
[ "$CODE" = 404 ] && [ "$BODY" = "$NOT" ] && ok "C2 the device key D (no presence) cancels nothing" || fail "C2 D: $CODE $BODY"
for i in 1 2 3; do call POST /api/identity/holds/100000000009/cancel "" '{"device_id":"phone-aaaa1","challenge":"'$CH'","signature":"AAAA"}'; done
call POST /api/identity/holds/100000000009/cancel "" '{"device_id":"phone-aaaa1","challenge_id":1,"signature":"AAAA"}'
call POST /api/identity/holds/100000000009/cancel "" '{"device_id":"phone-aaaa1","challenge":"'$CH'","signature":"'$(sig pap "$MSG")'"}'
[ "$CODE" = 200 ] && ok "C2 junk signatures do not spend the owner's challenge: the real cancel still lands (#59 H2)" || fail "C2 junk spent it: $CODE $BODY"
call POST /api/identity/holds/100000000002/cancel "" '{"device_id":"phone-aaaa1","challenge":"'$CH'","signature":"'$(sig pap "$MSG")'"}'
[ "$CODE" = 404 ] && ok "C2 a spent challenge cannot be replayed, not even on another hold" || fail "C2 replay: $CODE"
hch cancel phone-aaaa1 100000000002; X "UPDATE hold_challenges SET expires_at='$(iso -1)' WHERE nonce='$CH'"
call POST /api/identity/holds/100000000002/cancel "" '{"device_id":"phone-aaaa1","challenge":"'$CH'","signature":"'$(sig pap "$MSG")'"}'
[ "$CODE" = 404 ] && ok "C2 an expired challenge is refused" || fail "C2 expired: $CODE"
hch cancel phone-xxxx1 100000000002; [ "$CODE" = 404 ] && [ "$BODY" = "$NOT" ] && ok "C2 another account's phone gets no challenge for this hold (same answer)" || fail "C2 other account: $CODE $BODY"
seedphone pr8 "$DID_A" phone-rev8d "$(iso -2592000)" "$(iso $((-3600-8*86400)))" password
cancel 100000000002 phone-rev8d pr8p; [ "$CODE" = 404 ] && [ "$BODY" = "$NOT" ] && ok "C2 a phone removed 8 days before the start cannot cancel" || fail "C2 rev 8d: $CODE $BODY"
seedphone prd "$DID_A" phone-revdev "$(iso -2592000)" "$(iso $((-3600-86400)))" device
cancel 100000000002 phone-revdev prdp; [ "$CODE" = 404 ] && ok "C2 a phone removed with a phone's presence gets no grace" || fail "C2 rev via device: $CODE"
[ "$(Q "SELECT status FROM account_holds WHERE id='100000000002'")" = pending ] && ok "C2 after all that the hold still waits" || fail "C2 status"
seedphone pr2 "$DID_A" phone-rev2d "$(iso -2592000)" "$(iso $((-3600-2*86400)))" password
cancel 100000000002 phone-rev2d pr2p; [ "$CODE" = 200 ] && ok "C2/C3 a phone removed (password) 2 days before the start still cancels it, while pending" || fail "C2 rev 2d: $CODE $BODY"
seedhold 100000000003 "$DID_A" recovery pending "$(iso -7200)"
seedphone pra "$DID_A" phone-revaft "$(iso -2592000)" "$(iso -60)" password
cancel 100000000003 phone-revaft prap; [ "$CODE" = 200 ] && ok "C2 a phone removed after the start still cancels it (H2)" || fail "C2 rev after: $CODE $BODY"
[ "$(Q "SELECT COUNT(*) FROM demipass_security_events WHERE event_type='hold_cancel_refused'")" -ge 3 ] && ok "C2 refused cancels are logged" || fail "C2 refusal events"

# ── C9 alerts ──
seedhold 100000000004 "$DID_A" recovery pending "$(iso 0)"
hch alerts phone-aaaa1; call POST /api/identity/holds/alerts "" '{"device_id":"phone-aaaa1","challenge":"'$CH'","signature":"'$(sig pad "$MSG")'"}'
[ "$CODE" = 200 ] && echo "$BODY" | grep -q '"id":"100000000004"' && ok "C9 a D-signed, session-less alerts call lists the waiting recovery" || fail "C9 alerts: $CODE $BODY"
hch alerts phone-aaaa1; call POST /api/identity/holds/alerts "" '{"device_id":"phone-aaaa1","challenge":"'$CH'","signature":"'$(sig pap "$MSG")'"}'
[ "$CODE" = 404 ] && ok "C9 alerts need D (a P signature is not accepted there)" || fail "C9 alerts P: $CODE"
hch alerts phone-xxxx1; call POST /api/identity/holds/alerts "" '{"device_id":"phone-xxxx1","challenge":"'$CH'","signature":"'$(sig pxd "$MSG")'"}'
[ "$CODE" = 200 ] && [ "$(echo "$BODY" | J holds)" = "[]" ] && ok "C9 another account's phone sees none of this account's holds" || fail "C9 other: $CODE $BODY"
cancel 100000000004 phone-aaaa1 pap

# ── C6 E1 ──
A=$(login)
call POST /api/identity/device/challenge "$A" '{"purpose":"enrol","intent":"device-enrol:0"}'; ECH=$(echo "$BODY" | J challenge_id); EM="$(echo "$BODY" | J message):phone-cccc1"
pin "$A" device-enrol:0; pw "$A"
call POST /api/identity/device/enrol "$A" '{"challenge_id":'$ECH',"device_id":"phone-cccc1","label":"C","key_d":"'$(cat $S/pcd.pub)'","key_p":"'$(cat $S/pcp.pub)'","sig_d":"'$(sig pcd "$EM")'","sig_p":"'$(sig pcp "$EM")'"}'
HC=$(echo "$BODY" | J hold_id)
[ "$CODE" = 202 ] && [ "$(echo "$BODY" | J pending)" = True ] && [ "$(Q "SELECT COUNT(*) FROM device_keys WHERE device_id='phone-cccc1'")" = 0 ] && ok "C6 with a phone linked, a new phone waits 48 h (202) and holds no keys" || fail "C6 pending: $CODE $BODY"
hch alerts phone-cccc1; [ "$CODE" = 404 ] && ok "C6 the waiting phone can do nothing (no challenge)" || fail "C6 waiting acts: $CODE"
call GET /api/identity/devices "$A"; [ "$(echo "$BODY" | J pending.0.hold_id)" = "$HC" ] && ok "C6 the owner sees it waiting" || fail "C6 list: $BODY"
cancel "$HC" phone-aaaa1 pap; [ "$CODE" = 200 ] && [ "$(Q "SELECT COUNT(*) FROM device_keys WHERE device_id='phone-cccc1'")" = 0 ] && ok "C6 canceled from the linked phone: never linked" || fail "C6 cancel: $CODE $BODY"
enrol_pending(){ call POST /api/identity/device/challenge "$A" '{"purpose":"enrol","intent":"device-enrol:0"}'; ECH=$(echo "$BODY" | J challenge_id); EM="$(echo "$BODY" | J message):$1"
  pin "$A" device-enrol:0; pw "$A"
  call POST /api/identity/device/enrol "$A" '{"challenge_id":'$ECH',"device_id":"'$1'","label":"'$2'","key_d":"'$(cat $S/${2}d.pub)'","key_p":"'$(cat $S/${2}p.pub)'","sig_d":"'$(sig ${2}d "$EM")'","sig_p":"'$(sig ${2}p "$EM")'"}'
  HOLD=$(echo "$BODY" | J hold_id); }
enrol_pending phone-bbbb1 pb
hch enrol-approve phone-aaaa1 "$HOLD"; call POST /api/identity/holds/$HOLD/approve-enrol "" '{"device_id":"phone-aaaa1","challenge":"'$CH'","signature":"'$(sig pap "$MSG")'"}'
[ "$CODE" = 404 ] && ok "C6 a phone linked < 48 h cannot approve a new one" || fail "C6 young approve: $CODE $BODY"
X "UPDATE device_keys SET enrolled_at='$(iso -259200)' WHERE device_id='phone-aaaa1'"
hch enrol-approve phone-aaaa1 "$HOLD"
FP=$(Q "SELECT payload FROM account_holds WHERE id='$HOLD'" | python3 -c "import json,sys,hashlib; print(hashlib.sha256(json.load(sys.stdin)['key_d'].encode()).hexdigest()[:16])")
echo "$MSG" | grep -q ":$HOLD:$FP:pb:" && ok "C6 the approval names the new phone by its key fingerprint, not only its label (#59 M4)" || fail "C6 fp: $MSG / $FP"
call POST /api/identity/holds/$HOLD/approve-enrol "" '{"device_id":"phone-aaaa1","challenge":"'$CH'","signature":"'$(sig pap "$MSG")'"}'
[ "$CODE" = 200 ] && [ "$(Q "SELECT COUNT(*) FROM device_keys WHERE device_id='phone-bbbb1' AND revoked_at IS NULL")" = 2 ] && ok "C6 an established phone's presence links the new phone at once" || fail "C6 approve: $CODE $BODY"
enrol_pending phone-cccc2 pc2; X "UPDATE account_holds SET ready_at='$(iso -1)' WHERE id='$HOLD'"; sleep 2
[ "$(Q "SELECT COUNT(*) FROM device_keys WHERE device_id='phone-cccc2' AND revoked_at IS NULL")" = 2 ] && [ "$(Q "SELECT status FROM account_holds WHERE id='$HOLD'")" = completed ] && ok "C6 uncanceled at 48 h, the waiting phone is linked" || fail "C6 due: $(Q "SELECT status||' '||COALESCE(note,'') FROM account_holds WHERE id='$HOLD'")"

# ── C4 young phone, removal by password waits, last phone ──
bio(){ call POST /api/identity/device/challenge "$A" '{"purpose":"gate","intent":"device-revoke:0"}'; local m c; m=$(echo "$BODY" | J message); c=$(echo "$BODY" | J challenge_id)
  call POST /api/identity/gate/verify "$A" '{"gate":"device","intent":"device-revoke:0","challenge_id":'$c',"signature":"'$(sig $1 "$m")'"}'; }
bio pbp; pin "$A" device-revoke:0; call DELETE /api/identity/devices/phone-aaaa1 "$A"
[ "$CODE" = 403 ] && echo "$BODY" | grep -q "48 hours" && [ "$(Q "SELECT COUNT(*) FROM device_keys WHERE device_id='phone-aaaa1' AND revoked_at IS NULL")" = 2 ] && ok "C4 a phone linked < 48 h cannot remove another (H3)" || fail "C4 young revoke: $CODE $BODY"
X "UPDATE device_gate_proofs SET used = 1"
pin "$A" device-revoke:0; pw "$A"; call DELETE /api/identity/devices/phone-cccc2 "$A"; HU=$(echo "$BODY" | J hold_id)
[ "$CODE" = 202 ] && [ "$(Q "SELECT COUNT(*) FROM device_keys WHERE device_id='phone-cccc2' AND revoked_at IS NULL")" = 2 ] && ok "C4 removing a phone with password + PIN alone waits 48 h (202), the phone stays (#59 H1)" || fail "C4 pw removal: $CODE $BODY"
pin "$A" device-revoke:0; pw "$A"; call DELETE /api/identity/devices/phone-bbbb1 "$A"; HU2=$(echo "$BODY" | J hold_id)
pin "$A" device-revoke:0; pw "$A"; call DELETE /api/identity/devices/phone-aaaa1 "$A"; HU3=$(echo "$BODY" | J hold_id)
enrol_pending phone-dddd9 pd
{ [ "$CODE" = 202 ] || [ "$CODE" = 409 ]; } && [ "$(Q "SELECT COUNT(*) FROM device_keys WHERE device_id='phone-dddd9'")" = 0 ] && ok "C4 with every phone's removal waiting, a new phone is not linked: password + PIN cannot strip the phones and link their own at once" || fail "C4 strip+link: $CODE $BODY"
[ "$CODE" = 202 ] && cancel "$HOLD" phone-aaaa1 pap
for h in $HU2 $HU3; do cancel "$h" phone-aaaa1 pap; [ "$CODE" = 200 ] || fail "C4 cancel unlink $h: $CODE $BODY"; done
[ "$(Q "SELECT COUNT(DISTINCT device_id) FROM device_keys WHERE did='$DID_A' AND revoked_at IS NULL")" = 3 ] && ok "C4 removals canceled from the phone: all phones stay" || fail "C4 after cancel"
X "UPDATE account_holds SET ready_at='$(iso -1)' WHERE id='$HU'"; sleep 2
[ "$(Q "SELECT revoked_via FROM device_keys WHERE device_id='phone-cccc2' LIMIT 1")" = password ] && ok "C4 uncanceled at 48 h the removal applies (revoked_via password)" || fail "C4 due unlink: $(Q "SELECT status||' '||COALESCE(note,'') FROM account_holds WHERE id='$HU'")"
bio pap; pin "$A" device-revoke:0; call DELETE /api/identity/devices/phone-bbbb1 "$A"
[ "$CODE" = 200 ] && [ "$(Q "SELECT revoked_via FROM device_keys WHERE device_id='phone-bbbb1' LIMIT 1")" = device ] && ok "C4 an established phone's presence removes another at once (revoked_via device)" || fail "C4 bio removal: $CODE $BODY"
X "INSERT INTO recovery_guardians (owner_did, guardian_did, status, invited_at) VALUES ('$DID_A', '$DID_B', 'active', '$(iso 0)')"
bio pap; pin "$A" device-revoke:0; call DELETE /api/identity/devices/phone-aaaa1 "$A"
[ "$CODE" = 409 ] && [ "$(Q "SELECT COUNT(*) FROM device_keys WHERE device_id='phone-aaaa1' AND revoked_at IS NULL")" = 2 ] && ok "C4 with guardians set, the last phone cannot be removed (even by itself)" || fail "C4 last phone: $CODE $BODY"
X "DELETE FROM recovery_guardians"; X "UPDATE device_gate_proofs SET used = 1"

# ── C7 E2 ──
call POST /api/identity/set-recovery-email "$A" '{"recovery_email":"new-addr@example.com","password":"hunter22"}'; HE=$(echo "$BODY" | J hold_id)
[ "$CODE" = 202 ] && [ "$(Q "SELECT COALESCE(recovery_email,'') FROM identity_wallets WHERE username='owner-a'")" = "" ] && ok "C7 a recovery-email change waits (202), nothing changed yet" || fail "C7 pending: $CODE $BODY"
cancel "$HE" phone-aaaa1 pap; [ "$CODE" = 200 ] && [ "$(Q "SELECT COALESCE(recovery_email,'') FROM identity_wallets WHERE username='owner-a'")" = "" ] && ok "C7 canceled from the phone: unchanged" || fail "C7 cancel: $CODE $BODY"
gch "$A" pap recovery-email:0
call POST /api/identity/set-recovery-email "$A" '{"recovery_email":"mine@example.com","password":"hunter22","device_challenge_id":'$GCH',"device_signature":"'$GSG'"}'
[ "$CODE" = 200 ] && [ "$(Q "SELECT recovery_email FROM identity_wallets WHERE username='owner-a'")" = mine@example.com ] && ok "C7 with an established phone's presence it applies at once" || fail "C7 with phone: $CODE $BODY"

# ── C5 R0 ──
A=$(login); A2=$(login)
call POST /api/identity/pin "$A" '{"pin":"5555","password":"hunter22"}'; HR=$(echo "$BODY" | J hold_id)
[ "$CODE" = 202 ] && [ "$(echo "$BODY" | J pending)" = True ] && ok "C5 a PIN reset with the password waits 48 h while a phone is linked (202)" || fail "C5 pending: $CODE $BODY"
pin "$A" unlock:0 4321; [ "$(Q "SELECT COUNT(*) FROM device_keys WHERE device_id='phone-aaaa1' AND revoked_at IS NULL")" = 2 ] && ok "C5 meanwhile the old PIN and the phone keep working" || fail "C5 meanwhile"
call POST /api/identity/pin "$A" '{"pin":"5556","password":"hunter22"}'; [ "$CODE" = 409 ] && ok "C5 one PIN reset waits at a time (409)" || fail "C5 second: $CODE $BODY"
cancel "$HR" phone-aaaa1 pap
call GET /api/identity/holds "$A2"
[ "$CODE" = 401 ] && [ "$(Q "SELECT password_must_change FROM identity_wallets WHERE username='owner-a'")" = 1 ] && ok "C5 canceling it signs out every session and forces a new password" || fail "C5 after cancel: $CODE $(Q "SELECT password_must_change FROM identity_wallets WHERE username='owner-a'")"
call POST /api/identity/auth-fingerprint "" '{"username":"owner-a","password":"hunter22","scope":"transact","expires_in":"1h"}'
[ "$(echo "$BODY" | J password_must_change)" = True ] && ok "C5 the next sign-in says the password must change" || fail "C5 login flag: $BODY"
A=$(echo "$BODY" | J token)
call POST /api/identity/pin "$A" '{"pin":"6666","password":"hunter22"}'
[ "$CODE" = 403 ] && [ "$(echo "$BODY" | J password_must_change)" = True ] && ok "C5 until the password changes, nothing more starts from it (#59 M1)" || fail "C5 must-change: $CODE $BODY"
call POST /api/identity/set-recovery-email "$A" '{"recovery_email":"x2@example.com","password":"hunter22"}'; [ "$CODE" = 403 ] || fail "C5 must-change email: $CODE"
X "UPDATE identity_wallets SET password_must_change = 0 WHERE username='owner-a'"   # (the reset-password route clears it)
enrol_pending phone-dddd8 pd; HE1=$HOLD
call POST /api/identity/pin "$A" '{"pin":"6666","password":"hunter22"}'; HR=$(echo "$BODY" | J hold_id)
X "UPDATE account_holds SET ready_at='$(iso -1)' WHERE id='$HR'"; sleep 2
[ "$(Q "SELECT status FROM account_holds WHERE id='$HR'")" = completed ] && [ "$(Q "SELECT COUNT(*) FROM device_keys WHERE did='$DID_A' AND revoked_at IS NULL")" = 0 ] && ok "C5 uncanceled at 48 h it applies and unlinks every phone" || fail "C5 due: $(Q "SELECT status||' '||COALESCE(note,'') FROM account_holds WHERE id='$HR'")"
[ "$(Q "SELECT status FROM account_holds WHERE id='$HE1'")" = canceled ] && ok "C5 a phone waiting to be linked goes with the reset (#59 M3)" || fail "C5 enrol hold after reset: $(Q "SELECT status FROM account_holds WHERE id='$HE1'")"
A=$(login); pin "$A" unlock:0 6666
# a phone again (first: at once), then password + presence resets at once
call POST /api/identity/device/challenge "$A" '{"purpose":"enrol","intent":"device-enrol:0"}'; ECH=$(echo "$BODY" | J challenge_id); EM="$(echo "$BODY" | J message):phone-dddd1"
pin "$A" device-enrol:0 6666; pw "$A"
call POST /api/identity/device/enrol "$A" '{"challenge_id":'$ECH',"device_id":"phone-dddd1","label":"D","key_d":"'$(cat $S/pdd.pub)'","key_p":"'$(cat $S/pdp.pub)'","sig_d":"'$(sig pdd "$EM")'","sig_p":"'$(sig pdp "$EM")'"}'
[ "$CODE" = 201 ] || fail "C5 relink: $CODE $BODY"
gch "$A" pdp pin-reset:0
call POST /api/identity/pin "$A" '{"pin":"7777","password":"hunter22","device_challenge_id":'$GCH',"device_signature":"'$GSG'"}'
[ "$CODE" = 200 ] && [ "$(echo "$BODY" | J phones_unlinked)" -ge 1 ] && ok "C5 password + a linked phone's presence resets at once (and unlinks, as before)" || fail "C5 immediate: $CODE $BODY"
[ "$(Q "SELECT COUNT(*) FROM account_holds WHERE did='$DID_A' AND kind='pin-reset' AND status='pending'")" = 0 ] || fail "C5 stray hold"

echo; [ $fails = 0 ] && echo "ALL PASS" || { echo "$fails FAILED"; exit 1; }
