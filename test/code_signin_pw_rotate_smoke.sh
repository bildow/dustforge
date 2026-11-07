#!/bin/bash
# Code sign-in + blind account-password rotation (server.js /api/identity/login-code/*, /api/identity/password/rotate-blind).
# server.js on a throwaway DB, Stalwart's admin API stubbed (GET/PATCH /api/principal/<name>), the phone simulated with
# node crypto (P-256, as Android).
#   code sign-in: the same reply for a real and an unknown username; the emailed code signs in (transact, refresh,
#     auth_method email_code, a twofa proof, no password proof); every failure is the same 401; a forwarding rule under
#     48 h withholds the code and refuses one issued before it.
#   rotation: agent tokens refused; the PIN; the linked phone's signature (423 locked → 428 challenge → signed);
#     account hash AND mailbox secret set to the same new hash; the vault entries holding the old account or old
#     mailbox password get new versions (ref kept) holding the new one; others untouched; an elevated copy is named,
#     not changed; a mail server that fails leaves everything as it was; none matching → stored as a new secret.
set -u
W=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
S=$(mktemp -d /tmp/dustforge-pwrot-smoke.XXXXXX)
PORT=${PORT:-3811}; ST_PORT=${ST_PORT:-3812}; API=http://127.0.0.1:$PORT
[ -d "$W/node_modules" ] || export NODE_PATH=${NODE_PATH:-/home/flimflam/project/dustforge/node_modules}
export NODE_ENV=test PW_ROTATE_SWEEP_MS=1000 PW_ROTATE_SWEEP_AFTER_SEC=1 PW_ROTATE_SCAN_PAUSE_MS=1500 IDENTITY_MASTER_KEY=$(python3 -c 'import secrets;print(secrets.token_hex(32))') DB_PATH=$S/dustforge.db PORT \
  STALWART_HOST=127.0.0.1 STALWART_PORT=$ST_PORT SMTP_RELAY_HOST= SMTP_HOST=127.0.0.1 SMTP_PORT=9
cd "$W"
ACCT='acct-pass-Q9z!w'; MAILPW='mail-pass-7Kq#v'
# Stalwart stub: principals in $S/stalwart.json. POST /__mode {"patch": "ok" | "fail" (500, nothing applied) |
# "apply500" (applies, then answers 500) | "down" (applies the PATCH, then every request fails until "ok") |
# "slow" / "late" (the change lands, and is answered, after 3 s / 11.5 s)}.
cat > "$S/stalwart.js" <<'EOF'
const http = require('http'), fs = require('fs'); const f = process.argv[2]; let mode = 'ok';
http.createServer((q, r) => { let b = ''; q.on('data', c => b += c); q.on('end', () => {
  const st = JSON.parse(fs.readFileSync(f, 'utf8')); const m = /^\/api\/principal\/([^/?]+)$/.exec(q.url);
  if (q.url === '/__mode') { mode = JSON.parse(b).patch; r.end('{}'); return; }
  if (!m) { r.writeHead(404); r.end('{}'); return; }
  const name = decodeURIComponent(m[1]);
  if (mode === 'down-now') { r.writeHead(500); r.end('{}'); return; }
  if (q.method === 'GET') { r.writeHead(200, { 'content-type': 'application/json' }); r.end(JSON.stringify(st[name] ? { data: { secrets: [st[name]] } } : { error: 'notFound', item: name })); return; }
  if (q.method === 'PATCH' && (mode === 'slow' || mode === 'late')) {   // the change lands after 3 s / 11.5 s (the client times out at 10 s)
    const wait = mode === 'slow' ? 3000 : 11500; mode = 'ok';
    setTimeout(() => { const st2 = JSON.parse(fs.readFileSync(f, 'utf8')); for (const o of JSON.parse(b)) if (o.field === 'secrets') st2[name] = o.value[0];
      fs.writeFileSync(f, JSON.stringify(st2)); try { r.writeHead(200, { 'content-type': 'application/json' }); r.end('{"data":null}'); } catch (_) {} }, wait); return; }
  if (q.method === 'PATCH') { if (mode === 'fail') { r.writeHead(500); r.end('{}'); return; }
    const ops = JSON.parse(b); for (const o of ops) if (o.field === 'secrets') st[name] = o.value[0];
    fs.writeFileSync(f, JSON.stringify(st));
    if (mode === 'apply500') { r.writeHead(500); r.end('{}'); return; }
    if (mode === 'down') { mode = 'down-now'; r.writeHead(500); r.end('{}'); return; }
    r.writeHead(200, { 'content-type': 'application/json' }); r.end('{"data":null}'); return; }
  r.writeHead(405); r.end('{}'); }); }).listen(+process.argv[3], '127.0.0.1');
EOF
printf '{"owner":"{PLAIN}%s","appw":"$app$phone${PLAIN}app-pass-22x"}' "$MAILPW" > "$S/stalwart.json"
node "$S/stalwart.js" "$S/stalwart.json" $ST_PORT & STUB=$!
node server.js >"$S/server.log" 2>&1 & SRV=$!
trap 'kill $SRV $STUB 2>/dev/null; rm -rf "$S"' EXIT
for i in $(seq 1 40); do curl -s -o /dev/null "$API/" && break; sleep 0.5; done
kill -0 $SRV 2>/dev/null || { echo "server died:"; tail -5 "$S/server.log"; exit 1; }
node -e '
const identity = require("./identity"); const Database = require("better-sqlite3"); const pw = require("./passwords");
(async () => { const db = new Database(process.env.DB_PATH);
for (const [u, p] of [["owner", process.argv[1]], ["solo", "solo-pass-3Rt!"], ["appw", "appw-acct-pass-1"]]) {
  const id = identity.createIdentity(); const enc = id.encrypted_private_key || id.encryptedPrivateKey;
  db.prepare("INSERT INTO identity_wallets (did, username, email, encrypted_private_key, balance_cents, password_hash) VALUES (?, ?, ?, ?, 100000, ?)").run(id.did, u, u + "@dustforge.com", enc, await pw.hashPassword(p));
  db.prepare("INSERT INTO identity_transactions (did, amount_cents, type, description, balance_after) VALUES (?, 100000, ?, ?, 100000)").run(id.did, "topup", "smoke"); } })();' "$ACCT"
sleep 1
fails=0; ok(){ echo "ok   $*"; }; fail(){ echo "FAIL $*"; fails=$((fails+1)); }
J(){ python3 -c 'import json,sys; d=json.load(sys.stdin); v=d
for k in sys.argv[1].split("."):
    v = v[int(k)] if isinstance(v, list) else (v or {}).get(k)
print(v)' "$1"; }
Q(){ python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); r=c.execute(sys.argv[2]).fetchone(); print(r[0] if r else '')" "$DB_PATH" "$1"; }
call(){ local m=$1 p=$2 t=$3 b=${4:-}
  BODY=$(curl -s -o - -w '\n%{http_code}' -X "$m" "$API$p" -H 'Content-Type: application/json' ${t:+-H "Authorization: Bearer $t"} ${b:+-d "$b"})
  CODE=${BODY##*$'\n'}; BODY=${BODY%$'\n'*}; }
jb(){ python3 -c 'import json,sys; print(json.dumps(dict(zip(sys.argv[1::2], sys.argv[2::2]))))' "$@"; }
login(){ call POST /api/identity/auth-fingerprint "" "$(jb username "$1" password "$2" scope transact expires_in 2h)"; echo "$BODY" | J token; }
OWN=$(login owner "$ACCT"); [ "$OWN" != None ] || { echo "FAIL owner sign-in: $BODY"; exit 1; }
DID=$(Q "SELECT did FROM identity_wallets WHERE username='owner'")
# Decrypt a vault value the way the server does (test only: proves the new value without any API returning it).
val(){ node -e 'const c=require("crypto");const k=Buffer.from(process.env.IDENTITY_MASTER_KEY,"hex").slice(0,32);const d=Buffer.from(process.argv[1],"base64");
const x=c.createDecipheriv("aes-256-gcm",k,d.slice(0,16));x.setAuthTag(d.slice(16,32));process.stdout.write(Buffer.concat([x.update(d.slice(32)),x.final()]).toString())' "$(Q "$1")"; }
verifies(){ node -e 'require("./passwords").verifyPassword(process.argv[1], process.argv[2], { stalwart: true }).then(r => process.exit(r.ok === true ? 0 : 1))' "$1" "$2"; }

# ── code sign-in ──────────────────────────────────────────────────────────────────────────────────────────────────
call POST /api/identity/login-code/request "" '{"username":"owner"}'; R1=$BODY; C1=$CODE
call POST /api/identity/login-code/request "" '{"username":"nobody-here"}'
[ "$C1" = 200 ] && [ "$CODE" = 200 ] && [ "$R1" = "$BODY" ] && ok "asking for a code: the same answer for a real and an unknown username" || fail "enumeration (request): $C1 $CODE"
sleep 0.5; LC=$(Q "SELECT code FROM identity_2fa_codes WHERE did='$DID' AND purpose='login' AND used=0 ORDER BY id DESC LIMIT 1")
[ -n "$LC" ] && ok "a login code was issued for the real account" || fail "no code issued"
WRONG=$([ "$LC" = 000000 ] && echo 000001 || echo 000000)
call POST /api/identity/login-code/verify "" "$(jb username owner code $WRONG)"; W1="$CODE $BODY"
call POST /api/identity/login-code/verify "" "$(jb username nobody-here code $WRONG)"
[ "$W1" = "$CODE $BODY" ] && [ "$CODE" = 401 ] && ok "a wrong code and an unknown user get the same 401 (no attempts count)" || fail "enumeration (verify): [$W1] [$CODE $BODY]"
call POST /api/identity/login-code/verify "" "$(jb username owner code "$LC")"; CT=$(echo "$BODY" | J token)
[ "$CODE" = 200 ] && [ "$(echo "$BODY" | J auth_method)" = email_code ] && [ "$(echo "$BODY" | J scope)" = transact ] && [ "$(echo "$BODY" | J refresh_token)" != None ] \
  && ok "the emailed code signs in (transact, refresh token, auth_method email_code)" || fail "code sign-in: $CODE $BODY"
SID=$(python3 -c 'import json,base64,sys; p=sys.argv[1].split(".")[1]; print(json.loads(base64.urlsafe_b64decode(p+"="*(-len(p)%4)))["sid"])' "$CT")
[ "$(Q "SELECT COUNT(*) FROM gate_verifications WHERE session='$SID' AND gate_type='twofa'")" = 1 ] && [ "$(Q "SELECT COUNT(*) FROM gate_verifications WHERE session='$SID' AND gate_type='password'")" = 0 ] \
  && ok "…recording a twofa proof for that session and no password proof" || fail "gates after code sign-in"
call POST /api/identity/login-code/verify "" "$(jb username owner code "$LC")"; [ "$CODE" = 401 ] && ok "a code signs in once" || fail "code reuse: $CODE"
# forwarding rule under 48 h
call POST /api/identity/login-code/request "" '{"username":"owner"}'; sleep 0.5
LC2=$(Q "SELECT code FROM identity_2fa_codes WHERE did='$DID' AND purpose='login' AND used=0 ORDER BY id DESC LIMIT 1")
call POST /api/relay/create "$OWN" '{"forward_to":"someone@example.com"}'; [ "$CODE" = 200 ] || fail "relay create: $CODE $BODY"
call POST /api/identity/login-code/verify "" "$(jb username owner code "$LC2")"
[ "$CODE" = 403 ] && echo "$BODY" | grep -q forwarding && ok "a code issued before a new forwarding rule is refused" || fail "fresh forward verify: $CODE $BODY"
N0=$(Q "SELECT COUNT(*) FROM identity_2fa_codes WHERE did='$DID' AND purpose='login'")
call POST /api/identity/login-code/request "" '{"username":"owner"}'; sleep 0.5
[ "$CODE" = 200 ] && [ "$R1" = "$BODY" ] && [ "$(Q "SELECT COUNT(*) FROM identity_2fa_codes WHERE did='$DID' AND purpose='login'")" = "$N0" ] \
  && ok "under a new forwarding rule no code is issued (same reply)" || fail "fresh forward request: $CODE"
python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute(\"UPDATE forward_relays SET activated_at=datetime('now','-3 days'), created_at=datetime('now','-3 days')\"); c.commit()" "$DB_PATH"

# ── vault entries holding the old passwords ─────────────────────────────────────────────────────────────────────
storej(){ call POST /api/blindkey/store "$1" "$2"; [ "$CODE" = 200 ] || [ "$CODE" = 201 ] || fail "store: $CODE $BODY"; }
store(){ storej "$OWN" "$(python3 -c 'import json,sys; d=dict(zip(sys.argv[1::2], sys.argv[2::2])); d["secret_type"]="password"; print(json.dumps(d))' "$@")"; }
store name dustforge-acct value "$ACCT" provider dustforge          # this account's own entry (provider)
store name stalwart-imap value "$MAILPW"                             # the mailbox's own entry (name)
store name other-pw value 'unrelated-pw-55x'                         # an unrelated password
store name elev-copy value "$ACCT" provider dustforge                # made elevated below
storej "$OWN" "$(python3 -c 'import json,sys; print(json.dumps({"name":"gmail-login","value":sys.argv[1],"secret_type":"password","provider":"google","fill_origins":["https://accounts.google.com"]}))' "$ACCT")"   # a reused password, another service
storej "$OWN" "$(python3 -c 'import json,sys; print(json.dumps({"name":"site-login","value":sys.argv[1],"secret_type":"password"}))' "$ACCT")"   # same value, nothing ties it
storej "$OWN" "$(python3 -c 'import json,sys; print(json.dumps({"name":"forgejo-login","value":sys.argv[1],"secret_type":"password","fill_origins":["https://repo.dustroot.com"]}))' "$ACCT")"   # Forgejo has its own accounts (round-2 L-a)
storej "$OWN" "$(python3 -c 'import json,sys; print(json.dumps({"name":"uname-only","value":sys.argv[1],"secret_type":"password","login":"owner"}))' "$ACCT")"   # a fill username alone ties nothing (L-a)
X(){ python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute(sys.argv[2]); c.commit()" "$DB_PATH" "$1"; }
X "UPDATE blindkey_secrets SET security_depth='elevated' WHERE name='elev-copy'"
REF_A=$(Q "SELECT ref_code FROM blindkey_secrets WHERE name='dustforge-acct'"); REF_M=$(Q "SELECT ref_code FROM blindkey_secrets WHERE name='stalwart-imap'")

# ── rotation: who ───────────────────────────────────────────────────────────────────────────────────────────────
mintas(){ node -e 'const identity=require("./identity"),Database=require("better-sqlite3");const db=new Database(process.env.DB_PATH);const w=db.prepare("SELECT did,encrypted_private_key FROM identity_wallets WHERE username=?").get(process.argv[1]);
process.stdout.write(identity.createTokenForIdentity(w.encrypted_private_key,w.did,{scope:"transact",expiresIn:"1h",metadata:JSON.parse(process.argv[2])}))' "$1" "$2"; }
bad=0; for meta in '{"auth_method":"fleet_owner_mint","fleet":"x"}' '{"auth_method":"device","sid":"sdev1"}' '{"agent_label":"pane-7","sid":"sag1"}' '{"auth_method":"worker","wrk":"w1"}'; do
  call POST /api/identity/password/rotate-blind "$(mintas owner "$meta")" '{}'; [ "$CODE" = 403 ] || { bad=1; echo "  $meta → $CODE"; }; done
call POST /api/identity/auth-fingerprint "" "$(jb username owner password "$ACCT" scope write)"; call POST /api/identity/password/rotate-blind "$(echo "$BODY" | J token)" '{}'; [ "$CODE" = 403 ] || bad=1
[ $bad = 0 ] && ok "refused: fleet-minted, device-login (agent), agent-labelled and worker tokens, and below transact (L1)" || fail "agent/scope refusals"
call POST /api/identity/password/rotate-blind "$OWN" '{}'; [ "$CODE" = 403 ] && ok "no PIN set → refused" || fail "no pin set: $CODE $BODY"
call POST /api/identity/pin "$OWN" "$(jb pin 4321 password "$ACCT")"; [ "$CODE" = 200 ] || fail "set pin: $CODE $BODY"
call POST /api/identity/password/rotate-blind "$OWN" '{}'
[ "$CODE" = 403 ] && [ "$(echo "$BODY" | J intent)" = pw-rotate:0 ] && ok "the PIN is asked for (intent pw-rotate:0)" || fail "pin missing: $CODE $BODY"
pin(){ call POST /api/identity/gate/verify "$1" '{"gate":"pin","pin":"4321","intent":"'$2'"}'; [ "$CODE" = 200 ] || fail "pin $2: $CODE $BODY"; }
node -e 'const c=require("crypto"),fs=require("fs");for(const n of ["d","p"]){const {privateKey,publicKey}=c.generateKeyPairSync("ec",{namedCurve:"prime256v1"});
fs.writeFileSync(process.argv[1]+"/"+n+".pem",privateKey.export({type:"pkcs8",format:"pem"}));fs.writeFileSync(process.argv[1]+"/"+n+".pub",publicKey.export({type:"spki",format:"der"}).toString("base64"))}' "$S"
sig(){ node -e 'const c=require("crypto"),fs=require("fs"); process.stdout.write(c.sign("sha256", Buffer.from(process.argv[2]), fs.readFileSync(process.argv[1])).toString("base64"))' "$S/$1.pem" "$2"; }
call POST /api/identity/device/challenge "$OWN" '{"purpose":"enrol","intent":"device-enrol:0"}'; CHD=$(echo "$BODY" | J challenge_id); MSG="$(echo "$BODY" | J message):phone-0001"
pin "$OWN" device-enrol:0; call POST /api/identity/gate/verify "$OWN" "$(jb gate password password "$ACCT")"
call POST /api/identity/device/enrol "$OWN" "$(printf '{"challenge_id":%s,"device_id":"phone-0001","label":"Pixel","key_d":"%s","key_p":"%s","sig_d":"%s","sig_p":"%s"}' "$CHD" "$(cat $S/d.pub)" "$(cat $S/p.pub)" "$(sig d "$MSG")" "$(sig p "$MSG")")"
[ "$CODE" = 201 ] || fail "enrol: $CODE $BODY"
pin "$OWN" pw-rotate:0; call POST /api/identity/password/rotate-blind "$OWN" '{}'
{ [ "$CODE" = 423 ] || [ "$CODE" = 428 ]; } && ok "with a phone linked, the PIN alone does not rotate (423 / 428)" || fail "phone required: $CODE $BODY"
call POST /api/identity/device/challenge "$OWN" '{"purpose":"gate","intent":"unlock:0"}'; CH=$(echo "$BODY" | J challenge_id)
call POST /api/identity/gate/verify "$OWN" "$(printf '{"gate":"device","challenge_id":%s,"signature":"%s","intent":"unlock:0"}' "$CH" "$(sig p "$(echo "$BODY" | J message)")")"; [ "$CODE" = 200 ] || fail "unlock: $CODE $BODY"
dsign(){ call POST /api/identity/device/challenge "$OWN" '{"purpose":"approve","intent":"pw-rotate:0","bind":"account-password"}'; DCH=$(echo "$BODY" | J challenge_id); DSG=$(sig d "$(echo "$BODY" | J message)"); }
rot(){ pin "$OWN" pw-rotate:0; dsign; call POST /api/identity/password/rotate-blind "$OWN" "$(printf '{"device_challenge_id":%s,"device_signature":"%s"%s}' "$DCH" "$DSG" "${1:-}")"; }
mbx(){ python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$S/stalwart.json" "${1:-owner}"; }
mode(){ curl -s -X POST "http://127.0.0.1:$ST_PORT/__mode" -d '{"patch":"'$1'"}' >/dev/null; }
OLDH=$(Q "SELECT password_hash FROM identity_wallets WHERE did='$DID'")

# ── M1: one password change at a time ───────────────────────────────────────────────────────────────────────────
X "INSERT INTO account_password_locks (did, holder, claimed_at, expires_at) VALUES ('$DID', 'test-hold', datetime('now'), '2099-01-01T00:00:00Z')"
X "INSERT INTO password_reset_tokens (did, username, token, expires_at) VALUES ('$DID', 'owner', 'lock-test-token-1', '2099-01-01T00:00:00Z')"
rot; R1=$CODE; call POST /api/identity/reset-password "" "$(jb token lock-test-token-1 new_password reset-chosen-pw-1)"
[ "$R1" = 409 ] && [ "$CODE" = 409 ] && [ "$(Q "SELECT used FROM password_reset_tokens WHERE token='lock-test-token-1'")" = 0 ] \
  && ok "while the account's password lock is held: rotate → 409 and reset → 409 (the link stays usable) (M1)" || fail "lock: rotate $R1 reset $CODE"
X "DELETE FROM account_password_locks"; X "UPDATE password_reset_tokens SET used=1 WHERE token='lock-test-token-1'"

# ── mail server refuses: nothing moves (never decided inline; the sweep writes the old secret back, then fails it) ──
waitrow(){ for i in $(seq 1 ${2:-40}); do [ "$(Q "SELECT status FROM account_password_rotations WHERE id=$1")" = pending ] || break; sleep 1; done; Q "SELECT status FROM account_password_rotations WHERE id=$1"; }
lastrow(){ Q "SELECT id FROM account_password_rotations ORDER BY id DESC LIMIT 1"; }
mode fail; rot; FID=$(lastrow)
[ "$CODE" = 202 ] && [ "$(echo "$BODY" | J pending)" = True ] && ! echo "$BODY" | grep -q "nothing changed" && ok "the mail server refuses (500): held pending, not 'nothing changed' (round-2 P3)" || fail "fail inline: $CODE $BODY"
mode ok; ST=$(waitrow "$FID")
[ "$ST" = failed ] && [ "$(Q "SELECT password_hash FROM identity_wallets WHERE did='$DID'")" = "$OLDH" ] && [ "$(Q "SELECT name FROM blindkey_secrets WHERE ref_code='$REF_A'")" = dustforge-acct ] \
  && [ "$(mbx)" = "{PLAIN}$MAILPW" ] && [ "$(Q "SELECT COALESCE(fresh_enc,'wiped') FROM account_password_rotations WHERE id=$FID")" = wiped ] \
  && ok "…the sweep (past every timeout) writes the old secret back and fails it: account, mailbox, vault unchanged, password wiped" || fail "fail sweep: $ST"

LID=$(lastrow); MAILPW_H=$(mbx)
# ── L-b: the lock lost during a long vault scan stops the rotation before anything changes ──────────────────────
pin "$OWN" pw-rotate:0; dsign
( call POST /api/identity/password/rotate-blind "$OWN" "$(printf '{"device_challenge_id":%s,"device_signature":"%s"}' "$DCH" "$DSG")"; echo "$CODE" > "$S/lb.code" ) &
BG=$!; sleep 0.8; X "UPDATE account_password_locks SET holder='someone-else' WHERE did='$DID'"; wait $BG; X "DELETE FROM account_password_locks"
[ "$(cat "$S/lb.code")" = 409 ] && [ "$(lastrow)" = "$LID" ] && [ "$(Q "SELECT password_hash FROM identity_wallets WHERE did='$DID'")" = "$OLDH" ] && [ "$(mbx)" = "$MAILPW_H" ] \
  && ok "a rotation whose lock was taken mid-scan stops: 409, no pending row, nothing changed (round-2 L-b)" || fail "L-b: $(cat "$S/lb.code") rows $(lastrow) vs $LID"

# ── L-e: a guardian recovery part-way through completing blocks rotation and reset ──────────────────────────────
X "INSERT INTO account_holds (id, did, kind, status, created_at, expires_at, payload, note) VALUES ('900000000001', '$DID', 'recovery', 'completing', datetime('now'), '2099-01-01T00:00:00Z', '{}', 'completing:2099-01-01T00:00:00Z')"
X "INSERT INTO password_reset_tokens (did, username, token, expires_at) VALUES ('$DID', 'owner', 'le-test-token-1', '2099-01-01T00:00:00Z')"
rot; R1=$CODE; call POST /api/identity/reset-password "" "$(jb token le-test-token-1 new_password reset-chosen-pw-2)"
[ "$R1" = 409 ] && [ "$CODE" = 409 ] && ok "while a recovery is completing: rotate → 409, reset → 409 (round-2 L-e)" || fail "L-e: rotate $R1 reset $CODE"
X "DELETE FROM account_holds WHERE id='900000000001'"; X "UPDATE password_reset_tokens SET used=1 WHERE token='le-test-token-1'"

# ── the rotation ────────────────────────────────────────────────────────────────────────────────────────────────
mode apply500; rot; R="$BODY"
[ "$CODE" = 200 ] && [ "$(echo "$R" | J mailbox)" = changed ] && ok "the mail server applies the change but answers 500: re-read, it took → rotated (M2)" || fail "rotate: $CODE $R"
mode ok
NEWH=$(Q "SELECT password_hash FROM identity_wallets WHERE did='$DID'")
[ "$NEWH" != "$OLDH" ] && [ "$NEWH" = "$(mbx)" ] && [[ "$NEWH" == '$scrypt$'* ]] && ok "account hash and mailbox secret are the same new scrypt hash (never split)" || fail "hashes: split or unchanged"
NA=$(val "SELECT encrypted_value FROM blindkey_secrets WHERE ref_code='$REF_A'"); NM=$(val "SELECT encrypted_value FROM blindkey_secrets WHERE ref_code='$REF_M'")
[ "$(Q "SELECT name FROM blindkey_secrets WHERE ref_code='$REF_A'")" = dustforge-acct_v2 ] && [ "$(Q "SELECT name FROM blindkey_secrets WHERE ref_code='$REF_M'")" = stalwart-imap_v2 ] \
  && [ "$NA" = "$NM" ] && [ "$NA" != "$ACCT" ] && verifies "$NA" "$NEWH" && ok "this account's own entries (by provider, by name) hold the new password, refs kept (_v2)" || fail "moved secrets"
[ "$(val "SELECT encrypted_value FROM blindkey_secrets WHERE name='gmail-login'")" = "$ACCT" ] && [ "$(Q "SELECT COUNT(*) FROM blindkey_secrets WHERE name LIKE 'gmail-login_v%' OR name LIKE 'site-login_v%'")" = 0 ] \
  && [ "$(Q "SELECT COUNT(*) FROM blindkey_secrets WHERE name LIKE 'forgejo-login_v%' OR name LIKE 'uname-only_v%'")" = 0 ] \
  && [ "$(echo "$R" | python3 -c 'import json,sys; print(sorted(json.load(sys.stdin)["candidates"]))')" = "['forgejo-login', 'gmail-login', 'site-login', 'uname-only']" ] \
  && ok "candidates, untouched: a reused password for another service, an untied one, a Forgejo (repo.dustroot.com) login, a username-only one (H1, L-a)" || fail "H1 candidates: $R"
GR=$(Q "SELECT CAST((julianday(rotate_expires_at) - julianday('now')) AS INTEGER) FROM blindkey_secrets WHERE name='dustforge-acct'")
[ "${GR:-0}" -ge 2 ] && ok "the moved entries' old values are kept for days (≈$((GR+1)) d), not a minute (H1)" || fail "grace: $GR"
echo "$R" | grep -q -F -- "$NA" && fail "the reply carries the new password" || ok "the reply never carries the password"
[ "$(val "SELECT encrypted_value FROM blindkey_secrets WHERE name='other-pw'")" = unrelated-pw-55x ] && ok "an unrelated password is untouched" || fail "other-pw changed"
[ "$(echo "$R" | python3 -c 'import json,sys; d=json.load(sys.stdin); print([x["name"] for x in d["skipped"]], sorted(d["still_hold_old_password"]))')" = "['elev-copy'] ['elev-copy', 'forgejo-login', 'gmail-login', 'site-login', 'uname-only']" ] \
  && ok "the reply names what still holds the old password: candidates and the elevated copy (L3)" || fail "L3 report: $R"
call POST /api/identity/auth-fingerprint "" "$(jb username owner password "$ACCT" scope transact)"; [ "$CODE" = 401 ] && ok "the old password no longer signs in" || fail "old pw: $CODE"
call POST /api/identity/auth-fingerprint "" "$(jb username owner password "$NA" scope transact)"; [ "$CODE" = 200 ] && ok "the new one (from the vault) does" || fail "new pw: $CODE $BODY"
call GET /api/identity/devices "$OWN"; [ "$CODE" = 200 ] && ok "sessions kept by default" || fail "session cut: $CODE"
pin "$OWN" pw-rotate:0; call POST /api/identity/password/rotate-blind "$OWN" "$(printf '{"device_challenge_id":%s,"device_signature":"%s"}' "$DCH" "$DSG")"
[ "$CODE" = 403 ] && ok "a device signature works once" || fail "sig replay: $CODE $BODY"

# ── a PATCH that lands after the client gave up (11.5 s > the 10 s timeout) ─────────────────────────────────────
LH0=$(Q "SELECT password_hash FROM identity_wallets WHERE did='$DID'")
mode late; rot; LID=$(lastrow)
[ "$CODE" = 202 ] && [ "$(Q "SELECT status FROM account_password_rotations WHERE id=$LID")" = pending ] && ok "late PATCH: the timeout reads the old secret, stays pending (202) instead of failing (round-2 P3)" || fail "late inline: $CODE $BODY"
ST=$(waitrow "$LID")
[ "$ST" = done ] && [ "$(Q "SELECT password_hash FROM identity_wallets WHERE did='$DID'")" = "$(mbx)" ] && [ "$(mbx)" != "$LH0" ] \
  && verifies "$(val "SELECT encrypted_value FROM blindkey_secrets WHERE ref_code='$REF_A'")" "$(mbx)" \
  && ok "…it lands at 11.5 s; the sweep sees it and settles: account + vault follow the mailbox (no password nobody has)" || fail "late settle: $ST"

mode slow; rot; [ "$CODE" = 200 ] && [ "$(echo "$BODY" | J rotated)" = True ] && [ "$(Q "SELECT password_hash FROM identity_wallets WHERE did='$DID'")" = "$(mbx)" ] \
  && ok "a slow PATCH (3 s, inside the timeout) rotates inline" || fail "slow: $CODE $BODY"

# ── M2: the mail server goes away mid-change → held pending, settled by the sweep ─────────────────────────────
H2=$(Q "SELECT password_hash FROM identity_wallets WHERE did='$DID'")
mode down; rot
[ "$CODE" = 202 ] && [ "$(echo "$BODY" | J pending)" = True ] && ! echo "$BODY" | grep -q "nothing changed" && [ "$(Q "SELECT status FROM account_password_rotations ORDER BY id DESC LIMIT 1")" = pending ] \
  && [ -n "$(Q "SELECT fresh_enc FROM account_password_rotations ORDER BY id DESC LIMIT 1")" ] && ok "applied, then unreachable: 202 pending, never 'nothing changed'; the new password held encrypted (M2)" || fail "pending: $CODE $BODY"
rot; [ "$CODE" = 409 ] && ok "another rotation waits while one is pending" || fail "second while pending: $CODE"
mode ok; for i in $(seq 1 40); do [ "$(Q "SELECT status FROM account_password_rotations ORDER BY id DESC LIMIT 1")" = pending ] || break; sleep 1; done
[ "$(Q "SELECT status FROM account_password_rotations ORDER BY id DESC LIMIT 1")" = done ] && [ "$(Q "SELECT password_hash FROM identity_wallets WHERE did='$DID'")" = "$(mbx)" ] \
  && [ "$(Q "SELECT password_hash FROM identity_wallets WHERE did='$DID'")" != "$H2" ] && [ -z "$(Q "SELECT COALESCE(fresh_enc,'') FROM account_password_rotations ORDER BY id DESC LIMIT 1")" ] \
  && verifies "$(val "SELECT encrypted_value FROM blindkey_secrets WHERE ref_code='$REF_A'")" "$(mbx)" \
  && ok "the sweep re-read the mailbox (it took) and settled: account + vault follow, pending password wiped" || fail "sweep settle: $(Q "SELECT status || ' ' || COALESCE(report,'') FROM account_password_rotations ORDER BY id DESC LIMIT 1")"
# a pending row whose account password changed meanwhile, mailbox on the rotation's hash: the mailbox follows the account (M1 rollback)
CURH=$(Q "SELECT password_hash FROM identity_wallets WHERE did='$DID'")
node -e '
const Database = require("better-sqlite3"); const db = new Database(process.env.DB_PATH); const fs = require("fs");
const st = JSON.parse(fs.readFileSync(process.argv[1], "utf8")); st.owner = "$scrypt$ln=15,r=8,p=1$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g"; fs.writeFileSync(process.argv[1], JSON.stringify(st));
db.prepare("INSERT INTO account_password_rotations (did, status, fresh_enc, prior, new_hash, old_hash, plan, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
  .run(process.argv[2], "pending", process.argv[3], "{PLAIN}whatever", st.owner, "$scrypt$not-the-current-one", JSON.stringify({ username: "owner", moved: [] }), new Date(Date.now() - 20000).toISOString());' "$S/stalwart.json" "$DID" "$(Q "SELECT encrypted_value FROM blindkey_secrets WHERE name='other-pw'")"
for i in $(seq 1 40); do [ "$(Q "SELECT status FROM account_password_rotations ORDER BY id DESC LIMIT 1")" = pending ] || break; sleep 1; done
[ "$(Q "SELECT status FROM account_password_rotations ORDER BY id DESC LIMIT 1")" = failed ] && [ "$(mbx)" = "$CURH" ] && [ "$(Q "SELECT password_hash FROM identity_wallets WHERE did='$DID'")" = "$CURH" ] \
  && ok "a rotation overtaken by another change: the mailbox is set to the account's CURRENT hash, not the stale prior (M1)" || fail "rollback rule: $(Q "SELECT status || ' ' || COALESCE(report,'') FROM account_password_rotations ORDER BY id DESC LIMIT 1")"

# ── L-c: a row that never settles ends (abandoned): its password kept in the vault, owner + operator told ─────
node -e '
const Database = require("better-sqlite3"); const db = new Database(process.env.DB_PATH);
db.prepare("INSERT INTO account_password_rotations (did, status, fresh_enc, prior, new_hash, old_hash, plan, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
  .run(process.argv[1], "pending", process.argv[2], "{PLAIN}whatever", "$scrypt$x", "$scrypt$y", JSON.stringify({ username: "owner", moved: [] }), "2020-01-01T00:00:00Z");' "$DID" "$(Q "SELECT encrypted_value FROM blindkey_secrets WHERE name='other-pw'")"
AID=$(lastrow); ST=$(waitrow "$AID")
[ "$ST" = abandoned ] && [ "$(val "SELECT encrypted_value FROM blindkey_secrets WHERE name='account-password-unconfirmed-owner-$AID'")" = unrelated-pw-55x ] \
  && [ "$(Q "SELECT COUNT(*) FROM demipass_security_events WHERE event_type='password_rotate_abandoned' AND caller_did='$DID'")" = 1 ] && [ "$(Q "SELECT COALESCE(fresh_enc,'wiped') FROM account_password_rotations WHERE id=$AID")" = wiped ] \
  && ok "a row pending past its maximum age is abandoned: password moved to the vault (unconfirmed), critical event, no longer blocking (round-2 L-c)" || fail "L-c: $ST"

# ── L3: cut_sessions ────────────────────────────────────────────────────────────────────────────────────────────
OWN2=$(login owner "$(val "SELECT encrypted_value FROM blindkey_secrets WHERE ref_code='$REF_A'")")
rot ',"cut_sessions":true'
[ "$CODE" = 200 ] && echo "$BODY" | J sessions | grep -q "^cut" && { call GET /api/identity/devices "$OWN2"; [ "$CODE" = 401 ]; } && ok "cut_sessions:true signs out everywhere (L3)" || fail "cut: $CODE $BODY"

# ── an app password in the mailbox is never matched; none tied → stored as a new entry ─────────────────────────
APW=$(login appw appw-acct-pass-1); storej "$APW" '{"name":"stalwart-app","value":"app-pass-22x","secret_type":"password"}'
call POST /api/identity/pin "$APW" "$(jb pin 4321 password appw-acct-pass-1)"; pin "$APW" pw-rotate:0
call POST /api/identity/password/rotate-blind "$APW" '{}'
[ "$CODE" = 200 ] && [ "$(echo "$BODY" | J stored_as.name)" = account-password-appw ] && [ "$(val "SELECT encrypted_value FROM blindkey_secrets WHERE name='stalwart-app'")" = app-pass-22x ] \
  && ok "a mailbox app password (\$app\$) is not matched: its vault entry is untouched (H1)" || fail "app pw: $CODE $BODY"
SOLO=$(login solo 'solo-pass-3Rt!'); call POST /api/identity/pin "$SOLO" "$(jb pin 4321 password 'solo-pass-3Rt!')"
pin "$SOLO" pw-rotate:0; call POST /api/identity/password/rotate-blind "$SOLO" '{}'
SN=$(echo "$BODY" | J stored_as.name)
[ "$CODE" = 200 ] && [ "$(echo "$BODY" | J mailbox)" = "no mailbox" ] && [ "$SN" = account-password-solo ] && verifies "$(val "SELECT encrypted_value FROM blindkey_secrets WHERE name='$SN'")" "$(Q "SELECT password_hash FROM identity_wallets WHERE username='solo'")" \
  && ok "nothing held the old password → the new one is stored as account-password-solo (never known to nobody)" || fail "solo: $CODE $BODY"
grep -q -F -- "$NA" "$S/server.log" && fail "a new password reached the server log" || ok "no password in the server log"

[ $fails -gt 0 ] && { echo "--- server.log"; grep -i -m8 "error" "$S/server.log"; }
echo "$fails failure(s)"; exit $(( fails > 0 ))
