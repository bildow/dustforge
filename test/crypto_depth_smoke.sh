#!/bin/bash
# Cryptographic depth (red team item 1). A simulated phone (its keys in files: D, P and the wrap key W) links, registers
# W, and the owner raises a secret to elevated: it is wrapped, so
#   - the database file holds no plaintext, and the host-key paths (reveal, rotate-blind, transfer) refuse it;
#   - an agent's /use parks for approval; the phone approves with an unwrap made for that one request; the agent's
#     call runs once with the value (the upstream sees it); the approval cannot be used again;
#   - a heap snapshot of the server outside the approval window holds no plaintext;
#   - a code read aloud cannot open it; a restart loses pending one-use keys (asked again);
#   - lowering to standard needs the phone's unwrap; then it is host-readable again (reveal works).
set -u
W=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
S=$(mktemp -d /tmp/dustforge-crypto-depth.XXXXXX)
PORT=${PORT:-3853}; UP_PORT=${UP_PORT:-3854}; API=http://127.0.0.1:$PORT
[ -d "$W/node_modules" ] || export NODE_PATH=${NODE_PATH:-/home/flimflam/project/dustforge/node_modules}
export IDENTITY_MASTER_KEY=$(python3 -c 'import secrets;print(secrets.token_hex(32))') DB_PATH=$S/dustforge.db PORT \
  STALWART_HOST=127.0.0.1 STALWART_PORT=1 SMTP_RELAY_HOST= SMTP_HOST=127.0.0.1 SMTP_PORT=9 TEST_UPSTREAM=http://127.0.0.1:$UP_PORT
cd "$W"
node -e 'const fs=require("fs"); require("http").createServer((q, r) => { q.resume(); q.on("end", () => { fs.appendFileSync(process.argv[2], (q.headers.authorization || "-") + "\n"); r.writeHead(200, { "content-type": "application/json" }); r.end("{\"ok\":true}"); }); }).listen(+process.argv[1], "127.0.0.1");' $UP_PORT "$S/up.auth" & UP=$!
start(){ node --require ./test/fixtures/upstream-redirect.js --heapsnapshot-signal=SIGUSR2 --diagnostic-dir="$S" server.js >>"$S/server.log" 2>&1 & SRV=$!
  for i in $(seq 1 40); do curl -s -o /dev/null "$API/" && break; sleep 0.5; done; kill -0 $SRV 2>/dev/null || { echo "server died:"; tail -5 "$S/server.log"; exit 1; }; }
start
trap 'kill $SRV $UP 2>/dev/null; rm -rf "$S"' EXIT
H=$(printf '%s' hunter22 | sha256sum | cut -d' ' -f1)
node -e '
const identity = require("./identity"); const Database = require("better-sqlite3"); const db = new Database(process.env.DB_PATH);
for (const c of ["idempotency_key TEXT", "provenance TEXT DEFAULT '"'"'organic'"'"'"]) { try { db.exec("ALTER TABLE identity_transactions ADD COLUMN " + c); } catch (_) {} }
for (const u of ["cd-owner", "cd-nophone"]) { const id = identity.createIdentity(); const enc = id.encrypted_private_key || id.encryptedPrivateKey;
  db.prepare("INSERT INTO identity_wallets (did, username, email, encrypted_private_key, balance_cents, password_hash) VALUES (?, ?, ?, ?, 100000, ?)").run(id.did, u, u + "@dustforge.com", enc, process.argv[1]);
  db.prepare("INSERT INTO identity_transactions (did, amount_cents, type, description, balance_after) VALUES (?, 100000, ?, ?, 100000)").run(id.did, "topup", "smoke"); }' "$H"
fails=0; ok(){ echo "ok   $*"; }; fail(){ echo "FAIL $*"; fails=$((fails+1)); }
J(){ python3 -c 'import json,sys; d=json.load(sys.stdin); v=d
for k in sys.argv[1].split("."):
    v = v[int(k)] if isinstance(v, list) else (v or {}).get(k)
print(v if not isinstance(v,(dict,list)) else json.dumps(v))' "$1"; }
Q(){ python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); r=c.execute(sys.argv[2]).fetchone(); print(r[0] if r else '')" "$DB_PATH" "$1"; }
call(){ local m=$1 p=$2 t=$3 b=${4:-}
  BODY=$(curl -s -o - -w '\n%{http_code}' -X "$m" "$API$p" -H 'Content-Type: application/json' ${t:+-H "Authorization: Bearer $t"} ${b:+-d "$b"})
  CODE=${BODY##*$'\n'}; BODY=${BODY%$'\n'*}; }
login(){ call POST /api/identity/auth-fingerprint "" '{"username":"'$1'","password":"hunter22","scope":"transact","expires_in":"1h"}'; echo "$BODY" | J token; }
pin(){ call POST /api/identity/gate/verify "$1" '{"gate":"pin","pin":"4321","intent":"'$2'"}'; [ "$CODE" = 200 ] || fail "pin $2: $CODE $BODY"; }
# the phone: D (approvals), P (presence), W (wrap; RSA-2048, OAEP-SHA1 as the Android Keystore does it)
node -e '
const c = require("crypto"), fs = require("fs");
for (const n of ["d", "p"]) { const { privateKey, publicKey } = c.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  fs.writeFileSync(process.argv[1] + "/" + n + ".pem", privateKey.export({ type: "pkcs8", format: "pem" }));
  fs.writeFileSync(process.argv[1] + "/" + n + ".pub", publicKey.export({ type: "spki", format: "der" }).toString("base64")); }
const w = c.generateKeyPairSync("rsa", { modulusLength: 2048 });
fs.writeFileSync(process.argv[1] + "/w.pem", w.privateKey.export({ type: "pkcs8", format: "pem" }));
fs.writeFileSync(process.argv[1] + "/w.pub", w.publicKey.export({ type: "spki", format: "der" }).toString("base64"));' "$S"
sig(){ node -e 'const c=require("crypto"),fs=require("fs"); process.stdout.write(c.sign("sha256", Buffer.from(process.argv[2]), fs.readFileSync(process.argv[1])).toString("base64"))' "$S/$1.pem" "$2"; }
# what the phone's Keystore does on Approve: unwrap the data key with W, re-encrypt it to the request's one-use key
# what the phone does (DemiPassDevice.unwrap): open the wrap with W → data key || binding; refuse unless the binding names
# the secret its own prompt shows (did, ref, name); re-encrypt only the data key to the request's one-use key
rewrap(){ node -e 'const c=require("crypto"),fs=require("fs"); const o={padding:c.constants.RSA_PKCS1_OAEP_PADDING,oaepHash:"sha1"};
  const sealed=c.privateDecrypt({key:fs.readFileSync(process.argv[1]),...o},Buffer.from(process.argv[2],"base64"));
  const want=c.createHash("sha256").update("dp-wrap:v1|"+process.argv[4]+"|"+process.argv[5]+"|"+process.argv[6]).digest();
  if (sealed.length!==64 || !c.timingSafeEqual(sealed.subarray(32),want)) { process.stdout.write("REFUSED"); process.exit(0); }
  process.stdout.write(c.publicEncrypt({key:Buffer.from(process.argv[3],"base64"),format:"der",type:"spki",...o},sealed.subarray(0,32)).toString("base64"))' "$S/w.pem" "$1" "$2" "$3" "$4" "$5"; }
devsign(){ local tok=$1 intent=$2 bind=$3   # → CH SG
  call POST /api/identity/device/challenge "$tok" "$(python3 -c 'import json,sys; print(json.dumps({"purpose":"approve","intent":sys.argv[1],"bind":sys.argv[2]}))' "$intent" "$bind")"
  CH=$(echo "$BODY" | J challenge_id); SG=$(sig d "$(echo "$BODY" | J message)"); }

A=$(login cd-owner); AG=$(login cd-owner); N=$(login cd-nophone)
call POST /api/identity/pin "$A" '{"pin":"4321","password":"hunter22"}'; call POST /api/identity/pin "$N" '{"pin":"4321","password":"hunter22"}'
DA=$(Q "SELECT did FROM identity_wallets WHERE username='cd-owner'")
# link the phone (as device_keys_smoke does)
call POST /api/identity/device/challenge "$A" '{"purpose":"enrol","intent":"device-enrol:0"}'; CHD=$(echo "$BODY" | J challenge_id); MSG=$(echo "$BODY" | J message)
pin "$A" device-enrol:0; call POST /api/identity/gate/verify "$A" '{"gate":"password","password":"hunter22"}'
call POST /api/identity/device/enrol "$A" "$(printf '{"challenge_id":%s,"device_id":"phone-cd01","label":"Pixel","key_d":"%s","key_p":"%s","sig_d":"%s","sig_p":"%s"}' "$CHD" "$(cat $S/d.pub)" "$(cat $S/p.pub)" "$(sig d "$MSG:phone-cd01")" "$(sig p "$MSG:phone-cd01")")"
[ "$CODE" = 201 ] || { fail "enrol: $CODE $BODY"; exit 1; }
pin "$A" unlock:0
FP=$(python3 -c 'import base64,hashlib,sys; print(hashlib.sha256(base64.b64decode(open(sys.argv[1]).read())).hexdigest())' "$S/w.pub")
call POST /api/identity/device/wrap-key "$A" '{"device_id":"phone-cd01","key_w":"'$(cat $S/w.pub)'"}'
[ "$CODE" = 428 ] && [ "$(echo "$BODY" | J challenge.bind)" = "$FP" ] && ok "registering a wrap key needs the phone's device-key signature over its fingerprint" || fail "wrap-key 428: $CODE $BODY"
devsign "$A" wrap-key:0 "$FP"; call POST /api/identity/device/wrap-key "$A" '{"device_id":"phone-cd01","key_w":"'$(cat $S/w.pub)'","device_challenge_id":'$CH',"device_signature":"'$SG'"}'
[ "$CODE" = 200 ] && ok "the phone's wrap key W is registered" || fail "wrap-key: $CODE $BODY"

# ── raise: wrapped ──
umask 077; python3 -c 'import secrets;print("cdseed-" + secrets.token_urlsafe(18))' > "$S/seed"; V=$(cat "$S/seed")
call POST /api/demipass/store "$A" '{"name":"vaultroot","value":"'$V'","secret_type":"api_key","host":"repo.dustroot.com"}'
SID=$(Q "SELECT id FROM blindkey_secrets WHERE name='vaultroot'"); REF=$(Q "SELECT ref_code FROM blindkey_secrets WHERE id=$SID")
call POST /api/demipass/gate-policy "$A" '{"name":"vaultroot","security_depth":"elevated"}'
[ "$CODE" = 200 ] && [ "$(echo "$BODY" | J wrapped)" = True ] && [ "$(Q "SELECT encrypted_value||'|'||wrap_state FROM blindkey_secrets WHERE id=$SID")" = "dpwrap:v1|device" ] && [ "$(Q "SELECT COUNT(*) FROM secret_wraps WHERE secret_id=$SID")" = 1 ] \
  && ok "raising to elevated wraps it to the phone: the host copy is replaced by a marker" || fail "raise: $CODE $BODY"
python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute('PRAGMA wal_checkpoint(TRUNCATE)')" "$DB_PATH"
! grep -qaF -- "$V" "$DB_PATH" "$DB_PATH-wal" 2>/dev/null && ok "the database file (and its WAL) holds no plaintext of it" || fail "plaintext in the DB file"
call POST /api/demipass/reveal "$A" '{"name":"vaultroot"}'; [ "$CODE" = 409 ] && [ "$(echo "$BODY" | J wrapped)" = True ] && ok "reveal refuses a wrapped secret (the host cannot read it)" || fail "reveal: $CODE $BODY"
call POST /api/demipass/gate-policy "$N" '{"name":"x","security_depth":"elevated"}' >/dev/null
call POST /api/demipass/store "$N" '{"name":"np","value":"np-value-zz123"}'; call POST /api/demipass/gate-policy "$N" '{"name":"np","security_depth":"elevated"}'
[ "$CODE" = 200 ] && [ "$(echo "$BODY" | J wrapped)" = False ] && echo "$BODY" | grep -q "no linked phone" && ok "without a phone's wrap key: elevated by approval only, and the answer says the host can still read it" || fail "no phone: $CODE $BODY"

# ── heap outside any approval window ──
snap(){ rm -f "$S"/*.heapsnapshot; kill -USR2 $SRV; for i in $(seq 1 60); do ls "$S"/*.heapsnapshot >/dev/null 2>&1 && sleep 1 && break; sleep 0.5; done; ls "$S"/*.heapsnapshot 2>/dev/null | head -1; }
HS=$(snap); [ -n "$HS" ] && ! grep -qaF -- "$V" "$HS" && ok "a heap snapshot of the server outside an approval window holds no plaintext" || fail "heap before: ${HS:-no snapshot}"

# ── an agent's use: approval with the phone's unwrap ──
USE='{"ref":"'$REF'","params":{"url":"https://repo.dustroot.com/api/v1/user","method":"GET"}}'
call POST /api/demipass/use "$AG" "$USE"; AP=$(echo "$BODY" | J approval_id)
for i in $(seq 1 20); do [ -n "$(Q "SELECT COALESCE(eph_pub,'') FROM use_approvals WHERE id=$AP")" ] && break; sleep 0.2; done   # made off the event loop
[ "$CODE" = 202 ] && [ -n "$(Q "SELECT eph_pub FROM use_approvals WHERE id=$AP")" ] && ok "the agent's /use parks; the request has a one-use key (private half in memory only)" || fail "park: $CODE $BODY"
call GET /api/demipass/approvals "$A"; UN=$(echo "$BODY" | python3 -c 'import json,sys; d=json.load(sys.stdin); a=[x for x in d["incoming"] if x["id"]=='$AP'][0]; print(json.dumps(a.get("unwrap")))')
EPH=$(echo "$UN" | J eph_pub); WD=$(echo "$UN" | python3 -c 'import json,sys; print(json.load(sys.stdin)["wraps"]["'$FP'"])')
[ -n "$EPH" ] && [ -n "$WD" ] && ok "the owner's approval view carries the one-use key and the phone's wrap" || fail "view: $UN"
# What the real phone checks before it unwraps (DeviceBridge.unwrap): did, ref and name present and the secret's own.
[ "$(echo "$UN" | J ref)" = "$(Q "SELECT ref_code FROM blindkey_secrets WHERE id=(SELECT secret_id FROM use_approvals WHERE id=$AP)")" ] && [ -n "$(echo "$UN" | J ref)" ] \
  && [ "$(echo "$UN" | J name)" = "$(Q "SELECT name FROM blindkey_secrets WHERE id=(SELECT secret_id FROM use_approvals WHERE id=$AP)")" ] && [ "$(echo "$UN" | J did)" = "$(Q "SELECT did FROM blindkey_secrets WHERE id=(SELECT secret_id FROM use_approvals WHERE id=$AP)")" ] \
  && ok "…and names the secret as the phone requires (did, ref, name: approval 34 failed without the ref)" || fail "unwrap names: $UN"
BIND=$(Q "SELECT binding FROM use_approvals WHERE id=$AP")
devsign "$A" "approval-open:$AP" "$BIND"; call POST /api/demipass/approvals/$AP/open "$A" '{"device_challenge_id":'$CH',"device_signature":"'$SG'"}'; CODEV=$(echo "$BODY" | J code)
[ "$CODE" = 200 ] || fail "open: $CODE $BODY"
call POST /api/demipass/use "$AG" "${USE%\}},\"approval_id\":$AP,\"approval_code\":\"$CODEV\"}"
[ "$CODE" = 409 ] && [ "$(echo "$BODY" | J wrapped)" = True ] && ok "a code read aloud cannot open a wrapped secret (only the phone's Approve can)" || fail "code path: $CODE $BODY"
devsign "$A" "approval:$AP" "$BIND"; call POST /api/demipass/approvals/$AP/approve "$A" '{"code":"'$CODEV'","device_challenge_id":'$CH',"device_signature":"'$SG'"}'
[ "$CODE" = 428 ] && [ "$(echo "$BODY" | J unwrap_required)" = True ] && ok "approving without the phone's unwrap → 428 (a session or a device signature alone opens nothing)" || fail "no unwrap: $CODE $BODY"
UW=$(rewrap "$WD" "$EPH" "$DA" "$REF" vaultroot)
# a doctored page (a compromised host) hands the phone another secret's wrap under this request's name: the phone refuses
call POST /api/demipass/store "$A" '{"name":"other-secret","value":"other-value-zz7781","secret_type":"api_key"}'
call POST /api/demipass/gate-policy "$A" '{"name":"other-secret","security_depth":"critical"}'
OREF=$(Q "SELECT ref_code FROM blindkey_secrets WHERE name='other-secret'"); OWD=$(Q "SELECT wrapped_dek FROM secret_wraps w JOIN blindkey_secrets s ON s.id=w.secret_id WHERE s.name='other-secret'")
[ "$(rewrap "$OWD" "$EPH" "$DA" "$REF" vaultroot)" = REFUSED ] && [ "$(rewrap "$OWD" "$EPH" "$DA" "$OREF" other-secret)" != REFUSED ] \
  && ok "the phone opens a wrap only for the secret its own prompt names (a doctored page cannot swap in another secret)" || fail "binding"
devsign "$A" "approval:$AP" "$BIND"; call POST /api/demipass/approvals/$AP/approve "$A" '{"code":"'$CODEV'","device_challenge_id":'$CH',"device_signature":"'$SG'","unwrap":"'$UW'"}'
[ "$CODE" = 200 ] && ok "the phone approves with its unwrap (the data key re-encrypted to this request's one-use key)" || fail "approve: $CODE $BODY"
: > "$S/up.auth"
call POST /api/demipass/use "$AG" "${USE%\}},\"approval_id\":$AP}"
[ "$CODE" = 200 ] && grep -qF -- "$V" "$S/up.auth" && ! echo "$BODY" | grep -qF -- "$V" && ok "the agent's approved call runs once with the value (the upstream gets it; the agent does not)" || fail "use: $CODE $BODY"
[ "$(Q "SELECT COALESCE(unwrap_blob,'') FROM use_approvals WHERE id=$AP")" = "" ] && ok "…the unwrap is cleared from the approval" || fail "unwrap kept"
call POST /api/demipass/use "$AG" "${USE%\}},\"approval_id\":$AP}"; [ "$CODE" = 410 ] && ok "…and the approval cannot be used again" || fail "reuse: $CODE"
sleep 1; HS=$(snap); [ -n "$HS" ] && ! grep -qaF -- "$V" "$HS" && ok "a heap snapshot after the use holds no plaintext again" || fail "heap after: ${HS:-no snapshot}"

# ── restart: pending one-use keys are gone ──
call POST /api/demipass/use "$AG" '{"ref":"'$REF'","params":{"url":"https://repo.dustroot.com/api/v1/repos","method":"GET"}}'; AP2=$(echo "$BODY" | J approval_id)
kill $SRV; wait $SRV 2>/dev/null; start; A=$(login cd-owner); pin "$A" unlock:0
BIND2=$(Q "SELECT binding FROM use_approvals WHERE id=$AP2")
devsign "$A" "approval-open:$AP2" "$BIND2"; call POST /api/demipass/approvals/$AP2/open "$A" '{"device_challenge_id":'$CH',"device_signature":"'$SG'"}'; C2=$(echo "$BODY" | J code)
devsign "$A" "approval:$AP2" "$BIND2"; call POST /api/demipass/approvals/$AP2/approve "$A" '{"code":"'$C2'","device_challenge_id":'$CH',"device_signature":"'$SG'","unwrap":"'$UW'"}'
[ "$CODE" = 409 ] && [ "$(echo "$BODY" | J ask_again)" = True ] && ok "after a restart a pending request's one-use key is gone → 409, asked again (nothing on disk could open it)" || fail "restart: $CODE $BODY"

# ── transfer refused; lowering needs the phone ──
call POST /api/network/requests "$A" '{"to":"cd-nophone","as":"person"}' >/dev/null
call POST /api/demipass/transfer "$A" '{"secret":"vaultroot","to":"cd-nophone"}'; { [ "$CODE" = 409 ] || [ "$CODE" = 403 ]; } && ok "a wrapped secret is not transferred (it would arrive unreadable)" || fail "transfer: $CODE $BODY"
tfa(){ call POST /api/identity/request-2fa "$A" '{"did":"'$DA'"}'; call POST /api/identity/gate/verify "$A" '{"gate":"twofa","code":"'$(Q "SELECT code FROM identity_2fa_codes WHERE did='$DA' ORDER BY id DESC LIMIT 1")'"}'; }
tfa; pin "$A" "gate-policy:$SID"; call POST /api/demipass/gate-policy "$A" '{"name":"vaultroot","security_depth":"standard"}'
[ "$CODE" = 428 ] && [ "$(echo "$BODY" | J unwrap_required)" = True ] && ok "lowering to standard needs the phone's unwrap" || fail "lower no unwrap: $CODE $BODY"
call POST /api/demipass/wrap/unwrap-session "$A" '{"secret":"vaultroot"}'; US=$(echo "$BODY" | J unwrap_session); EPH3=$(echo "$BODY" | J eph_pub)
WD3=$(echo "$BODY" | python3 -c 'import json,sys; print(json.load(sys.stdin)["wraps"]["'$FP'"])'); UW3=$(rewrap "$WD3" "$EPH3" "$DA" "$REF" vaultroot)
tfa; pin "$A" "gate-policy:$SID"; call POST /api/demipass/gate-policy "$A" '{"name":"vaultroot","security_depth":"standard","unwrap_session":"'$US'","unwrap":"'$UW3'"}'
[ "$CODE" = 200 ] && [ "$(Q "SELECT COALESCE(wrap_state,'none') FROM blindkey_secrets WHERE id=$SID")" = none ] && [ "$(Q "SELECT COUNT(*) FROM secret_wraps WHERE secret_id=$SID")" = 0 ] && ok "with the phone's unwrap it is lowered: host-readable again, wraps gone" || fail "lower: $CODE $BODY"
pin "$A" "reveal:$SID"; call POST /api/demipass/reveal "$A" '{"name":"vaultroot"}'
[ "$CODE" = 200 ] && echo "$BODY" | grep -qF -- "$V" && ok "…and reveal returns the same value (nothing lost through the round trip)" || fail "reveal after lower: $CODE"

# ── rotation of a wrapped secret: the new version is wrapped for its (moved) ref; session cap ──
call POST /api/demipass/store "$A" '{"name":"rotme","value":"rot-value-one-zz55","secret_type":"api_key"}'
call POST /api/demipass/gate-policy "$A" '{"name":"rotme","security_depth":"elevated"}'
RID=$(Q "SELECT id FROM blindkey_secrets WHERE name='rotme'"); RREF=$(Q "SELECT ref_code FROM blindkey_secrets WHERE id=$RID")
tfa; pin "$A" "rotate:$RID"; call POST /api/demipass/rotate "$A" '{"name":"rotme","new_value":"rot-value-two-zz66","grace_period_minutes":5}'
NID=$(Q "SELECT id FROM blindkey_secrets WHERE ref_code='$RREF'"); NNAME=$(Q "SELECT name FROM blindkey_secrets WHERE id=$NID")
NWD=$(Q "SELECT wrapped_dek FROM secret_wraps WHERE secret_id=$NID")
[ "$CODE" = 200 ] && [ "$(echo "$BODY" | J wrapped)" = True ] && [ "$(Q "SELECT wrap_state FROM blindkey_secrets WHERE id=$NID")" = device ] && [ "$(rewrap "$NWD" "$EPH3" "$DA" "$RREF" "$NNAME")" != REFUSED ] \
  && ok "rotating a wrapped secret wraps the new version, sealed for the ref it now holds" || fail "rotate wrapped: $CODE $BODY"
( for i in $(seq 1 12); do curl -s -o /dev/null -w '%{http_code}\n' -X POST "$API/api/demipass/wrap/unwrap-session" -H 'Content-Type: application/json' -H "Authorization: Bearer $A" -d '{"secret":"other-secret"}' & done; wait ) > "$S/burst"
[ "$(grep -c '^200$' "$S/burst")" = 3 ] && ok "a burst of 12 unwrap sessions gets exactly 3 (slots reserved before the keys are made, off the event loop)" || fail "burst: $(sort "$S/burst" | uniq -c | tr '\n' ' ')"
# names the phone can show are wrapped; the server and phone validators agree (a long name; a non-ASCII name → empty slug)
LONG=$(python3 -c 'print("n"*64)')
call POST /api/demipass/store "$A" '{"name":"'$LONG'","value":"long-name-value-zz12","secret_type":"api_key"}'
call POST /api/demipass/gate-policy "$A" '{"name":"'$LONG'","security_depth":"elevated"}'
[ "$(echo "$BODY" | J wrapped)" = True ] && ok "a 64-character name (the store maximum) is wrapped — the phone accepts up to 100 (other routes allow names that long)" || fail "long name: $BODY"
call POST /api/demipass/store "$A" '{"name":"密码钥匙","value":"cjk-name-value-zz13","secret_type":"api_key"}'
call POST /api/demipass/gate-policy "$A" '{"name":"密码钥匙","security_depth":"elevated"}'; CJK_REF=$(Q "SELECT ref_code FROM blindkey_secrets WHERE name='密码钥匙'")
[ "$(echo "$BODY" | J wrapped)" = True ] && [[ "$CJK_REF" =~ ^DP-[A-Z]+--[0-9a-f]{8}$ ]] && ok "a non-ASCII name (empty ref slug $CJK_REF) is wrapped — the phone accepts an empty slug" || fail "cjk: $CJK_REF $BODY"
node -e 'const r=/^DP-[A-Z]{2,6}-[A-Za-z0-9]{0,16}-[0-9a-f]{8}$/, n=/^[^\u0000-\u001f\u007f-\u009f]{1,100}$/u; process.exit(r.test(process.argv[1]) && n.test(process.argv[2]) && !n.test("x".repeat(101)) && !n.test("a\nb") ? 0 : 1)' "$CJK_REF" "$LONG" \
  && grep -q 'DP-\[A-Z\]{2,6}-\[A-Za-z0-9\]{0,16}-\[0-9a-f\]{8}' /home/flimflam/project/demipass-android/app/src/main/java/com/dustforge/demipass/DeviceBridge.java \
  && ok "the phone's REF/NAME patterns are the server's (checked against the app source)" || fail "validators drift"

# raising a secret whose older version is still in rotation grace wraps that version too (its ref moved; host loses it)
call POST /api/demipass/store "$A" '{"name":"graced","value":"graced-old-value-zz21","secret_type":"api_key"}'
GID=$(Q "SELECT id FROM blindkey_secrets WHERE name='graced'")
call POST /api/demipass/rotate "$A" '{"name":"graced","new_value":"graced-new-value-zz22","grace_period_minutes":43200}'
GNEW=$(Q "SELECT name FROM blindkey_secrets WHERE name LIKE 'graced_v%' AND status='active'")
call POST /api/demipass/gate-policy "$A" '{"name":"'$GNEW'","security_depth":"elevated"}'
[ "$(Q "SELECT status||'|'||COALESCE(wrap_state,'host')||'|'||encrypted_value FROM blindkey_secrets WHERE id=$GID")" = "rotating|device|dpwrap:v1" ] \
  && ok "the older version in its rotation grace is wrapped too (no host copy left of a value the provider still accepts)" || fail "grace sibling: $(Q "SELECT status||'|'||COALESCE(wrap_state,'host') FROM blindkey_secrets WHERE id=$GID")"

echo; [ $fails = 0 ] && echo "ALL OK" || echo "$fails failure(s)"; exit $fails
