#!/bin/bash
# Dormancy lock + device keys + PIN rules (red team items 4b and 8; tome build spec v1). server.js on a throwaway DB;
# the phone's two Keystore keys are simulated with node crypto (P-256, DER ECDSA signatures, as Android produces).
#   (a) once a phone is enrolled, an approval needs its device key: a session token alone (the owner's own device
#       login, an agent's) approves nothing; a key that is not enrolled is refused
#   (b) the presence key's signature over a gate challenge is a PIN proof for exactly that intent: it opens X once,
#       not Y; a replayed challenge is refused
#   (c) an elevated request opens without a new PIN while this session's unlock is fresh; a critical one never does;
#       locking ends it
#   (d) 5 wrong PINs in a session end that session (its token 401, its refresh token dead); other sessions live
#   (e) the dormancy setting: 60–3600 s, shortening free, lengthening takes the PIN
#   (f) a revoked device's signatures are refused at once
#   (g) a phone links with an emailed code instead of the password; {check:true} says the factors are ready, spends
#       nothing, and links nothing
set -u
W=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
S=$(mktemp -d /tmp/dustforge-device-smoke.XXXXXX)
PORT=${PORT:-3797}; UP_PORT=${UP_PORT:-3798}; API=http://127.0.0.1:$PORT
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
const id = identity.createIdentity(); const enc = id.encrypted_private_key || id.encryptedPrivateKey;
db.prepare("INSERT INTO identity_wallets (did, username, email, encrypted_private_key, balance_cents, password_hash) VALUES (?, ?, ?, ?, 100000, ?)").run(id.did, "owner-a", "owner-a@dustforge.com", enc, process.argv[1]);
db.prepare("INSERT INTO identity_transactions (did, amount_cents, type, description, balance_after) VALUES (?, 100000, ?, ?, 100000)").run(id.did, "topup", "smoke");' "$H"
fails=0; ok(){ echo "ok   $*"; }; fail(){ echo "FAIL $*"; fails=$((fails+1)); }
J(){ python3 -c 'import json,sys; d=json.load(sys.stdin); v=d
for k in sys.argv[1].split("."):
    v = v[int(k)] if isinstance(v, list) else (v or {}).get(k)
print(v)' "$1"; }
Q(){ python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); r=c.execute(sys.argv[2]).fetchone(); print(r[0] if r else '')" "$DB_PATH" "$1"; }
call(){ local m=$1 p=$2 t=$3 b=${4:-}
  BODY=$(curl -s -o - -w '\n%{http_code}' -X "$m" "$API$p" -H 'Content-Type: application/json' ${t:+-H "Authorization: Bearer $t"} ${b:+-d "$b"})
  CODE=${BODY##*$'\n'}; BODY=${BODY%$'\n'*}; }
LOGIN_JSON=""
login(){ call POST /api/identity/auth-fingerprint "" '{"username":"owner-a","password":"hunter22","scope":"transact","expires_in":"1h"}'; LOGIN_JSON=$BODY; echo "$BODY" | J token; }
pin(){ call POST /api/identity/gate/verify "$1" '{"gate":"pin","pin":"4321","intent":"'$2'"}'; [ "$CODE" = 200 ] || fail "pin $2: $CODE $BODY"; }
# the phone: keys and signatures
node -e '
const c = require("crypto"), fs = require("fs");
for (const n of ["d", "p", "x"]) { const { privateKey, publicKey } = c.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  fs.writeFileSync(process.argv[1] + "/" + n + ".pem", privateKey.export({ type: "pkcs8", format: "pem" }));
  fs.writeFileSync(process.argv[1] + "/" + n + ".pub", publicKey.export({ type: "spki", format: "der" }).toString("base64")); }' "$S"
sig(){ node -e 'const c=require("crypto"),fs=require("fs"); process.stdout.write(c.sign("sha256", Buffer.from(process.argv[2]), fs.readFileSync(process.argv[1])).toString("base64"))' "$S/$1.pem" "$2"; }
# challenge → signature, for a purpose/intent; sets CH (id) and SG (signature); extra = text appended after ":"
# open an approval request as the phone would: the device key signs each fetch of the code (#47 code-bypass fix)
dopen(){ local tok=$1 id=$2; local bind; bind=$(Q "SELECT binding FROM use_approvals WHERE id=$id")
  chsign "$tok" d approve "approval-open:$id" "$bind"
  call POST /api/demipass/approvals/$id/open "$tok" '{"device_challenge_id":'$CH',"device_signature":"'$SG'"}'; }
chsign(){ local tok=$1 key=$2 purpose=$3 intent=$4 extra=${5:-}
  if [ "$purpose" = approve ]; then call POST /api/identity/device/challenge "$tok" '{"purpose":"approve","intent":"'$intent'","bind":"'$extra'"}'; extra=""
  else call POST /api/identity/device/challenge "$tok" '{"purpose":"'$purpose'","intent":"'$intent'"}'; fi
  CH=$(echo "$BODY" | J challenge_id); local msg; msg=$(echo "$BODY" | J message); [ -n "$extra" ] && msg="$msg:$extra"; SG=$(sig $key "$msg"); }

A=$(login); A2=$(login); AG=$(login)   # A = the phone app; A2 = another session of the owner (browser); AG = an agent's device login
call POST /api/identity/pin "$A" '{"pin":"4321","password":"hunter22"}'

# ── enrol ──
chsign "$A" d enrol device-enrol:0 phone-0001; CHD=$CH; SGD=$SG; SGP=$(sig p "$(Q "SELECT 'demipass:enrol:'||did||':'||session||':'||intent||':'||nonce FROM device_challenges WHERE id=$CHD"):phone-0001")
ENROL(){ printf '{"challenge_id":%s,"device_id":"phone-0001","label":"Pixel","key_d":"%s","key_p":"%s","sig_d":"%s","sig_p":"%s"}' "$CHD" "$(cat $S/d.pub)" "$(cat $S/p.pub)" "$SGD" "$SGP"; }
call POST /api/identity/device/enrol "$A" "$(ENROL)"; [ "$CODE" = 403 ] && [ "$(echo "$BODY" | J intent)" = device-enrol:0 ] && ok "enrolling a phone takes the PIN" || fail "enrol no pin: $CODE $BODY"
pin "$A" device-enrol:0; call POST /api/identity/device/enrol "$A" "$(ENROL)"
[ "$CODE" = 403 ] && [ "$(echo "$BODY" | J missing.0)" = twofa ] && [ "$(echo "$BODY" | J or.twofa)" = password ] && ok "…and a second factor, an emailed code or the password: knowing the PIN alone plants no device (#47 H1)" || fail "enrol no second factor: $CODE $BODY"
call POST /api/identity/gate/verify "$A" '{"gate":"password","password":"hunter22"}'; call POST /api/identity/device/enrol "$A" "$(ENROL)"
[ "$CODE" = 201 ] && [ "$(Q "SELECT COUNT(*) FROM device_keys WHERE device_id='phone-0001' AND revoked_at IS NULL")" = 2 ] && ok "a phone enrols two keys (device D, presence P), each signing the challenge" || fail "enrol: $CODE $BODY"
pin "$A" device-enrol:0; call POST /api/identity/device/enrol "$A" "$(ENROL)"; { [ "$CODE" = 403 ] || [ "$CODE" = 409 ]; } && ok "an enrol challenge works once, and an active device id cannot be enrolled over" || fail "enrol replay: $CODE"
call POST /api/identity/device/challenge "$AG" '{"purpose":"approve","intent":"approval:1"}'; [ "$CODE" = 200 ] && ok "(an agent session can ask for a challenge — it cannot sign one)" || fail "agent challenge: $CODE"

# ── (a) approvals need the phone ──
call POST /api/demipass/store "$A" '{"name":"hook","value":"hook-token-zz90","secret_type":"api_key","host":"repo.dustroot.com"}'; HK=$(echo "$BODY" | J ref)
call POST /api/demipass/gate-policy "$A" '{"ref":"'$HK'","security_depth":"elevated"}'
USE='{"ref":"'$HK'","params":{"url":"https://repo.dustroot.com/hook","method":"GET"}}'
call POST /api/demipass/use "$AG" "$USE"; AP=$(echo "$BODY" | J approval_id); [ "$CODE" = 202 ] || fail "park: $CODE $BODY"
pin "$A2" "approval-open:$AP"; call POST /api/demipass/approvals/$AP/open "$A2"
[ "$CODE" = 423 ] && [ -z "$(echo "$BODY" | J code | grep -v None)" ] && ok "(a) a locked session gets no approval code (423)" || fail "a locked open: $CODE $BODY"
pin "$A2" unlock:0; call POST /api/demipass/approvals/$AP/open "$A2"
[ "$CODE" = 428 ] && [ "$(echo "$BODY" | J code)" = None ] && ok "(a) unlocked but without the phone's device signature → no code (428): a laptop with the PIN or a copied token cannot read it out to an agent" || fail "a code bypass: $CODE $BODY"
call POST /api/demipass/use "$AG" "$(echo "$USE" | sed 's/}$/,"approval_id":'$AP',"approval_code":"000000"}/')"; [ "$CODE" = 409 ] || [ "$CODE" = 403 ] || fail "a: unopened code redeem $CODE"
dopen "$A2" $AP; C2=$(echo "$BODY" | J code); [ "$CODE" = 200 ] && [ -n "$C2" ] && ok "(a) the linked phone's signature fetches the code" || fail "a dopen: $CODE $BODY"
call POST /api/demipass/approvals/$AP/approve "$A2" '{"code":"'$C2'"}'
[ "$CODE" = 428 ] && [ "$(echo "$BODY" | J device_required)" = True ] && ok "(a) approving needs its own device signature too (428)" || fail "a no sig: $CODE $BODY"
BIND=$(Q "SELECT binding FROM use_approvals WHERE id=$AP")
chsign "$A2" x approve "approval:$AP" "$BIND"
call POST /api/demipass/approvals/$AP/approve "$A2" '{"code":"'$C2'","device_challenge_id":'$CH',"device_signature":"'$SG'"}'
[ "$CODE" = 403 ] && [ "$(Q "SELECT status FROM use_approvals WHERE id=$AP")" = pending ] && ok "(a) a key that is not enrolled is refused, nothing approved" || fail "a foreign key: $CODE $BODY"
dopen "$A2" $AP; C2=$(echo "$BODY" | J code); chsign "$A2" d approve "approval:$AP" "$BIND"
call POST /api/demipass/approvals/$AP/approve "$A2" '{"code":"'$C2'","device_challenge_id":'$CH',"device_signature":"'$SG'"}'
[ "$CODE" = 200 ] && [ "$(Q "SELECT status FROM use_approvals WHERE id=$AP")" = approved ] && ok "(a) signed by the enrolled device key → approved" || fail "a signed: $CODE $BODY"
call POST /api/demipass/use "$AG" "$(echo "$USE" | sed 's/}$/,"approval_id":'$AP'}/')"; [ "$CODE" = 200 ] && ok "(a) …and the agent's parked call runs once" || fail "a run: $CODE $BODY"
call POST /api/demipass/use "$AG" "$(echo "$USE" | sed 's#/hook#/hookB#')"; APB=$(echo "$BODY" | J approval_id)
pin "$A2" "approval-open:$APB"; dopen "$A2" $APB; CB=$(echo "$BODY" | J code)
chsign "$A2" d approve "approval:$APB" "$BIND"   # the phone was shown the OTHER request's binding
call POST /api/demipass/approvals/$APB/approve "$A2" '{"code":"'$CB'","device_challenge_id":'$CH',"device_signature":"'$SG'"}'
[ "$CODE" = 409 ] && [ "$(Q "SELECT status FROM use_approvals WHERE id=$APB")" = pending ] && ok "(a) a signature over another decision's binding approves nothing (409)" || fail "a wrong bind: $CODE $BODY"

# ── (b) biometric = a PIN proof for exactly one intent ──
call POST /api/demipass/use "$AG" "$(echo "$USE" | sed 's#/hook#/hook2#')"; AP2=$(echo "$BODY" | J approval_id)
chsign "$A" p gate "approval-open:$AP2"; GCH=$CH; GSG=$SG
call POST /api/identity/gate/verify "$A" '{"gate":"device","intent":"approval-open:999","challenge_id":'$GCH',"signature":"'$GSG'"}'
[ "$CODE" = 403 ] && ok "(b) a presence signature for one intent does not open another" || fail "b other intent: $CODE $BODY"
chsign "$A" p gate "approval-open:$AP2"; GCH=$CH; GSG=$SG
call POST /api/identity/gate/verify "$A" '{"gate":"device","intent":"approval-open:'$AP2'","challenge_id":'$GCH',"signature":"'$GSG'"}'
[ "$CODE" = 200 ] && [ "$(echo "$BODY" | J via)" = biometric ] || fail "b verify: $CODE $BODY"
chsign "$A" p gate unlock:0; call POST /api/identity/gate/verify "$A" '{"gate":"device","intent":"unlock:0","challenge_id":'$CH',"signature":"'$SG'"}'
dopen "$A" $AP2; [ "$CODE" = 200 ] && ok "(b) the phone's biometric opens the request — no PIN typed" || fail "b open: $CODE $BODY"
call POST /api/identity/gate/verify "$A" '{"gate":"device","intent":"approval-open:'$AP2'","challenge_id":'$GCH',"signature":"'$GSG'"}'
[ "$CODE" = 403 ] && ok "(b) a replayed challenge is refused" || fail "b replay: $CODE"
chsign "$A" d gate "approval-open:$AP2"; call POST /api/identity/gate/verify "$A" '{"gate":"device","intent":"approval-open:'$AP2'","challenge_id":'$CH',"signature":"'$SG'"}'
[ "$CODE" = 403 ] && ok "(b) the device key (no user presence) is not a PIN" || fail "b D as P: $CODE"

# ── (c) dormancy: an elevated open rides on a fresh unlock; critical never does ──
call POST /api/demipass/use "$AG" "$(echo "$USE" | sed 's#/hook#/hook3#')"; AP3=$(echo "$BODY" | J approval_id)
call POST /api/identity/lock/now "$A2"
call POST /api/demipass/approvals/$AP3/open "$A2"; [ "$CODE" = 403 ] && ok "(c) a locked session opens nothing without the PIN" || fail "c locked: $CODE"
pin "$A2" unlock:0; call GET /api/identity/lock "$A2"; [ "$(echo "$BODY" | J unlocked)" = True ] || fail "c unlock state: $BODY"
dopen "$A2" $AP3; [ "$CODE" = 200 ] && ok "(c) after unlocking (PIN or biometric) an elevated request opens without another PIN" || fail "c elevated: $CODE $BODY"
call POST /api/demipass/store "$A" '{"name":"crit","value":"crit-token-zz91","secret_type":"api_key","host":"repo.dustroot.com"}'; CR=$(echo "$BODY" | J ref)
call POST /api/demipass/gate-policy "$A" '{"ref":"'$CR'","security_depth":"critical"}'
call POST /api/demipass/use "$AG" '{"ref":"'$CR'","params":{"url":"https://repo.dustroot.com/c","method":"GET"}}'; AP4=$(echo "$BODY" | J approval_id)
call POST /api/demipass/approvals/$AP4/open "$A2"; [ "$CODE" = 403 ] && ok "(c) a critical request asks again even while unlocked" || fail "c critical: $CODE $BODY"
call POST /api/identity/lock/now "$A2"
call POST /api/demipass/use "$AG" "$(echo "$USE" | sed 's#/hook#/hook5#')"; AP5=$(echo "$BODY" | J approval_id)
call POST /api/demipass/approvals/$AP5/open "$A2"; [ "$CODE" = 403 ] && ok "(c) locking ends the unlock" || fail "c lock now: $CODE"
python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute(\"UPDATE session_unlocks SET last_active_at='2020-01-01T00:00:00.000Z'\"); c.commit()" "$DB_PATH"
pin "$A2" unlock:0; python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute(\"UPDATE session_unlocks SET last_active_at=strftime('%Y-%m-%dT%H:%M:%fZ','now','-301 seconds')\"); c.commit()" "$DB_PATH"
call POST /api/demipass/approvals/$AP5/open "$A2"; [ "$CODE" = 403 ] && ok "(c) idle past the lock time (300 s) → locked again" || fail "c idle: $CODE"
call POST /api/identity/lock/ping "$A2"; [ "$(echo "$BODY" | J unlocked)" = False ] && ok "(c) a ping never revives a stale unlock" || fail "c ping: $BODY"

# ── (e) the dormancy setting ──
call PUT /api/identity/lock "$A" '{"lock_after_sec":30}'; [ "$CODE" = 400 ] && ok "(e) under 60 s refused" || fail "e low: $CODE"
call PUT /api/identity/lock "$A" '{"lock_after_sec":120}'; [ "$CODE" = 200 ] && ok "(e) shortening needs no PIN" || fail "e shorten: $CODE $BODY"
call PUT /api/identity/lock "$A" '{"lock_after_sec":900}'; [ "$CODE" = 403 ] && [ "$(echo "$BODY" | J intent)" = lock-setting:0 ] && ok "(e) lengthening takes the PIN" || fail "e lengthen: $CODE $BODY"
pin "$A" lock-setting:0; call PUT /api/identity/lock "$A" '{"lock_after_sec":900}'; [ "$CODE" = 200 ] || fail "e lengthen pin: $CODE"
call PUT /api/identity/lock "$AG" '{"lock_after_sec":3600}'; [ "$CODE" = 403 ] && ok "(e) …and an agent session cannot lengthen it without the PIN" || fail "e agent: $CODE"

# ── (f) device revoke ──
call DELETE /api/identity/devices/phone-0001 "$A"; [ "$CODE" = 403 ] || fail "f revoke no pin: $CODE"
python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute(\"DELETE FROM gate_verifications WHERE gate_type='password'\"); c.commit()" "$DB_PATH"   # the enrolment's password proof has lapsed
pin "$A" device-revoke:0; call DELETE /api/identity/devices/phone-0001 "$A"
[ "$CODE" = 403 ] && echo "$BODY" | grep -q password && ok "(f) removing a phone takes more than the PIN (password or a linked phone's biometric)" || fail "f pin only: $CODE $BODY"
call POST /api/identity/gate/verify "$A" '{"gate":"password","password":"hunter22"}'; call DELETE /api/identity/devices/phone-0001 "$A"
[ "$CODE" = 202 ] && [ "$(echo "$BODY" | J pending)" = True ] && ok "(f) with the password (no phone) the removal waits 48 h, cancelable from the phone (item 9 #59 H1)" || fail "f pw revoke: $CODE $BODY"
chsign "$A" p gate "device-revoke:0"; call POST /api/identity/gate/verify "$A" '{"gate":"device","intent":"device-revoke:0","challenge_id":'$CH',"signature":"'$SG'"}'
pin "$A" device-revoke:0; call DELETE /api/identity/devices/phone-0001 "$A"; [ "$CODE" = 200 ] && ok "(f) the phone's own biometric removes it at once" || fail "f revoke: $CODE $BODY"
chsign "$A" p gate "reveal:1"; call POST /api/identity/gate/verify "$A" '{"gate":"device","intent":"reveal:1","challenge_id":'$CH',"signature":"'$SG'"}'
[ "$CODE" = 403 ] && ok "(f) a revoked phone's biometric is refused at once" || fail "f revoked P: $CODE"

# ── (d) 5 wrong PINs end the session — every token of it, refreshed ones too — and only that session ──
UNLOCK="UPDATE identity_wallets SET pin_failures = 0, pin_locked_until = NULL, pin_lock_count = 0"
SQLX(){ python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute(sys.argv[2]); c.commit()" "$DB_PATH" "$1"; }
X=$(login); for i in 1 2 3 4; do call POST /api/identity/gate/verify "$X" '{"gate":"pin","pin":"0000","intent":"reveal:1"}'; done
call POST /api/identity/gate/verify "$A" '{"gate":"pin","pin":"0000","intent":"reveal:1"}'
call GET /api/identity/lock "$A"; [ "$CODE" = 200 ] && ok "(d) 4 misses elsewhere + 1 here do not end this session (#47 L6)" || fail "d L6: $CODE"
SQLX "$UNLOCK"
call POST /api/identity/auth-fingerprint "" '{"username":"owner-a","password":"hunter22","scope":"transact","expires_in":"1h"}'; B0=$(echo "$BODY" | J token); R0=$(echo "$BODY" | J refresh_token)
call POST /api/identity/refresh "" '{"refresh_token":"'$R0'"}'; B1=$(echo "$BODY" | J token); R1=$(echo "$BODY" | J refresh_token)
[ -n "$B1" ] && [ "$B1" != None ] || fail "d: refresh did not mint"
for i in 1 2 3 4 5; do call POST /api/identity/gate/verify "$B1" '{"gate":"pin","pin":"0000","intent":"reveal:1"}'; done
call GET /api/identity/lock "$B1"; C1=$CODE; call GET /api/identity/lock "$B0"; C0=$CODE
[ "$C1" = 401 ] && [ "$C0" = 401 ] && ok "(d) the 5th wrong PIN ends the session: the refreshed token AND the one it came from (#47 M1)" || fail "d session: B1 $C1 B0 $C0"
call POST /api/identity/refresh "" '{"refresh_token":"'$R1'"}'; [ "$CODE" = 401 ] && ok "(d) …and its refresh chain is dead" || fail "d refresh: $CODE $BODY"
call GET /api/identity/lock "$A"; [ "$CODE" = 200 ] && ok "(d) other sessions keep going" || fail "d others: $CODE"

# ── (g) linking with an emailed code, no password (the owner never types a vault value) ──
node -e '
const identity = require("./identity"); const Database = require("better-sqlite3"); const db = new Database(process.env.DB_PATH);
const id = identity.createIdentity(); const enc = id.encrypted_private_key || id.encryptedPrivateKey;
db.prepare("INSERT INTO identity_wallets (did, username, email, encrypted_private_key, balance_cents, password_hash) VALUES (?, ?, ?, ?, 100000, ?)").run(id.did, "owner-g", "owner-g@dustforge.com", enc, process.argv[1]);' "$H"
glogin(){ call POST /api/identity/auth-fingerprint "" '{"username":"owner-g","password":"hunter22","scope":"transact","expires_in":"1h"}'; echo "$BODY" | J token; }
G0=$(glogin); G=$(glogin); DG=$(Q "SELECT did FROM identity_wallets WHERE username='owner-g'")
call POST /api/identity/pin "$G0" '{"pin":"4321","password":"hunter22"}'
call POST /api/identity/device/enrol "$G" '{"check":true}'
[ "$CODE" = 403 ] && [ "$(echo "$BODY" | J missing.0)" = twofa ] && [ "$(echo "$BODY" | J missing.1)" = pin ] && ok "(g) a fresh session is asked for an emailed code (or the password) and the PIN" || fail "g missing: $CODE $BODY"
call POST /api/identity/request-2fa "" '{"did":"'$DG'"}'; call POST /api/identity/gate/verify "$G" '{"gate":"twofa","code":"'$(Q "SELECT code FROM identity_2fa_codes WHERE did='$DG' ORDER BY id DESC LIMIT 1")'"}'
[ "$CODE" = 403 ] && ok "(g) a sign-in code (asked for with no session) is no gate code" || fail "g login code as gate: $CODE $BODY"
call POST /api/identity/request-2fa "$G" '{"did":"'$DG'"}'; call POST /api/identity/gate/verify "$G" '{"gate":"twofa","code":"'$(Q "SELECT code FROM identity_2fa_codes WHERE did='$DG' ORDER BY id DESC LIMIT 1")'"}'
[ "$CODE" = 200 ] || fail "g twofa: $CODE $BODY"
call POST /api/identity/device/enrol "$G" '{"check":true}'; [ "$CODE" = 403 ] && [ "$(echo "$BODY" | J missing.0)" = pin ] && ok "(g) the emailed code stands in for the password; the PIN is still needed" || fail "g pin left: $CODE $BODY"
G2=$(glogin); call POST /api/identity/device/enrol "$G2" '{"check":true}'; [ "$CODE" = 403 ] && [ "$(echo "$BODY" | J missing.0)" = twofa ] && ok "(g) the code counts for the session that verified it, not another" || fail "g other session: $CODE $BODY"
pin "$G" device-enrol:0; call POST /api/identity/device/enrol "$G" '{"check":true}'
[ "$CODE" = 200 ] && [ "$(echo "$BODY" | J ready)" = True ] && [ "$(Q "SELECT COUNT(*) FROM device_keys WHERE did='$DG'")" = 0 ] && ok "(g) {check:true}: ready, and nothing linked" || fail "g check: $CODE $BODY"
node -e '
const c = require("crypto"), fs = require("fs");
for (const n of ["gd", "gp"]) { const { privateKey, publicKey } = c.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  fs.writeFileSync(process.argv[1] + "/" + n + ".pem", privateKey.export({ type: "pkcs8", format: "pem" }));
  fs.writeFileSync(process.argv[1] + "/" + n + ".pub", publicKey.export({ type: "spki", format: "der" }).toString("base64")); }' "$S"
call POST /api/identity/device/challenge "$G" '{"purpose":"enrol","intent":"device-enrol:0"}'; GCH=$(echo "$BODY" | J challenge_id); GM="$(echo "$BODY" | J message):phone-g001"
call POST /api/identity/device/enrol "$G" "$(printf '{"challenge_id":%s,"device_id":"phone-g001","label":"Moto","key_d":"%s","key_p":"%s","sig_d":"%s","sig_p":"%s"}' "$GCH" "$(cat $S/gd.pub)" "$(cat $S/gp.pub)" "$(sig gd "$GM")" "$(sig gp "$GM")")"
[ "$CODE" = 201 ] && [ "$(Q "SELECT COUNT(*) FROM device_keys WHERE device_id='phone-g001' AND revoked_at IS NULL")" = 2 ] && ok "(g) …the check left the PIN proof unspent: the phone links on it, with no password typed anywhere" || fail "g enrol: $CODE $BODY"
# A forwarding rule made in the last 48 hours (a session token alone can make one) could carry the code elsewhere.
G3=$(glogin); call POST /api/relay/create "$G3" '{"forward_to":"someone@example.org"}'; [ "$CODE" = 200 ] || fail "g relay: $CODE $BODY"
call POST /api/identity/request-2fa "$G3" '{"did":"'$DG'"}'; call POST /api/identity/gate/verify "$G3" '{"gate":"twofa","code":"'$(Q "SELECT code FROM identity_2fa_codes WHERE did='$DG' ORDER BY id DESC LIMIT 1")'"}'
call POST /api/identity/device/enrol "$G3" '{"check":true}'
[ "$CODE" = 403 ] && [ "$(echo "$BODY" | J missing.0)" = password ] && [ "$(echo "$BODY" | J or)" = None ] && ok "(g) a forwarding rule active under 48 h: an emailed code no longer counts, the password does (#63 H1)" || fail "g relay blocks code: $CODE $BODY"
python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute(\"UPDATE forward_relays SET activated_at=NULL, created_at=datetime('now','-3 days')\"); c.commit()" "$DB_PATH"
G4=$(glogin); call POST /api/identity/request-2fa "$G4" '{"did":"'$DG'"}'; call POST /api/identity/gate/verify "$G4" '{"gate":"twofa","code":"'$(Q "SELECT code FROM identity_2fa_codes WHERE did='$DG' ORDER BY id DESC LIMIT 1")'"}'
call POST /api/identity/device/enrol "$G4" '{"check":true}'
[ "$CODE" = 403 ] && [ "$(echo "$BODY" | J missing.0)" = pin ] && ok "(g) a forwarding rule active for 48 h or more (the owner's own, long-standing; a legacy row with no activated_at): the emailed code counts" || fail "g old relay: $CODE $BODY"
call DELETE /api/relay/remove "$G3" '{"id":'$(Q "SELECT id FROM forward_relays LIMIT 1")'}'; call POST /api/relay/create "$G3" '{"forward_to":"someone@example.org"}'
call POST /api/identity/device/enrol "$G3" '{"check":true}'
[ "$CODE" = 403 ] && [ "$(echo "$BODY" | J missing.0)" = password ] && ok "(g) …and re-activating an old rule counts as new (its 48 h start again)" || fail "g relay reactivate: $CODE $BODY"
# create → code → remove → link: the removed rule still counts (#63 re-review H1)
G5=$(glogin); call POST /api/identity/request-2fa "$G5" '{"did":"'$DG'"}'; TC=$(Q "SELECT code FROM identity_2fa_codes WHERE did='$DG' ORDER BY id DESC LIMIT 1")
call DELETE /api/relay/remove "$G5" '{"id":'$(Q "SELECT id FROM forward_relays LIMIT 1")'}'; [ "$(Q "SELECT status FROM forward_relays LIMIT 1")" = inactive ] || fail "g remove: $CODE $BODY"
call POST /api/identity/gate/verify "$G5" '{"gate":"twofa","code":"'$TC'"}'; call POST /api/identity/device/enrol "$G5" '{"check":true}'
[ "$CODE" = 403 ] && [ "$(echo "$BODY" | J missing.0)" = password ] && ok "(g) …and removing the rule after the code went out does not clear it" || fail "g relay removed: $CODE $BODY"

! grep -qE "hook-token-zz90|crit-token-zz91" "$S/server.log" && ok "no value in the server log" || fail "value in log"
echo; [ $fails = 0 ] && echo "ALL OK" || echo "$fails FAILED"; exit $fails
