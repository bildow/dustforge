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
export IDENTITY_MASTER_KEY=$(python3 -c 'import secrets;print(secrets.token_hex(32))') DB_PATH=$S/dustforge.db PORT \
  STALWART_HOST=127.0.0.1 STALWART_PORT=$ST_PORT SMTP_RELAY_HOST= SMTP_HOST=127.0.0.1 SMTP_PORT=9
cd "$W"
ACCT='acct-pass-Q9z!w'; MAILPW='mail-pass-7Kq#v'
# Stalwart stub: principals in $S/stalwart.json; POST /__mode {"patch":"ok"|"fail"} makes PATCH fail (500).
cat > "$S/stalwart.js" <<'EOF'
const http = require('http'), fs = require('fs'); const f = process.argv[2]; let mode = 'ok';
http.createServer((q, r) => { let b = ''; q.on('data', c => b += c); q.on('end', () => {
  const st = JSON.parse(fs.readFileSync(f, 'utf8')); const m = /^\/api\/principal\/([^/?]+)$/.exec(q.url);
  if (q.url === '/__mode') { mode = JSON.parse(b).patch; r.end('{}'); return; }
  if (!m) { r.writeHead(404); r.end('{}'); return; }
  const name = decodeURIComponent(m[1]);
  if (q.method === 'GET') { r.writeHead(200, { 'content-type': 'application/json' }); r.end(JSON.stringify(st[name] ? { data: { secrets: [st[name]] } } : { error: 'notFound', item: name })); return; }
  if (q.method === 'PATCH') { if (mode === 'fail') { r.writeHead(500); r.end('{}'); return; }
    const ops = JSON.parse(b); for (const o of ops) if (o.field === 'secrets') st[name] = o.value[0];
    fs.writeFileSync(f, JSON.stringify(st)); r.writeHead(200, { 'content-type': 'application/json' }); r.end('{"data":null}'); return; }
  r.writeHead(405); r.end('{}'); }); }).listen(+process.argv[3], '127.0.0.1');
EOF
printf '{"owner":"{PLAIN}%s"}' "$MAILPW" > "$S/stalwart.json"
node "$S/stalwart.js" "$S/stalwart.json" $ST_PORT & STUB=$!
node server.js >"$S/server.log" 2>&1 & SRV=$!
trap 'kill $SRV $STUB 2>/dev/null; rm -rf "$S"' EXIT
for i in $(seq 1 40); do curl -s -o /dev/null "$API/" && break; sleep 0.5; done
kill -0 $SRV 2>/dev/null || { echo "server died:"; tail -5 "$S/server.log"; exit 1; }
node -e '
const identity = require("./identity"); const Database = require("better-sqlite3"); const pw = require("./passwords");
(async () => { const db = new Database(process.env.DB_PATH);
for (const [u, p] of [["owner", process.argv[1]], ["solo", "solo-pass-3Rt!"]]) {
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
store(){ call POST /api/blindkey/store "$OWN" "$(jb name "$1" value "$2" secret_type password)"; [ "$CODE" = 200 ] || [ "$CODE" = 201 ] || fail "store $1: $CODE $BODY"; }
store acct-copy "$ACCT"; store imap-copy "$MAILPW"; store other-pw 'unrelated-pw-55x'; store elev-copy "$ACCT"
python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute(\"UPDATE blindkey_secrets SET security_depth='elevated' WHERE name='elev-copy'\"); c.commit()" "$DB_PATH"
REF_A=$(Q "SELECT ref_code FROM blindkey_secrets WHERE name='acct-copy'"); REF_M=$(Q "SELECT ref_code FROM blindkey_secrets WHERE name='imap-copy'")

# ── rotation: who, PIN, phone ──────────────────────────────────────────────────────────────────────────────────
AGT=$(node -e 'const identity=require("./identity"),Database=require("better-sqlite3");const db=new Database(process.env.DB_PATH);const w=db.prepare("SELECT did,encrypted_private_key FROM identity_wallets WHERE username=?").get("owner");
process.stdout.write(identity.createTokenForIdentity(w.encrypted_private_key,w.did,{scope:"transact",expiresIn:"1h",metadata:{auth_method:"fleet_owner_mint",fleet:"x"}}))')
call POST /api/identity/password/rotate-blind "$AGT" '{}'; [ "$CODE" = 403 ] && ok "an agent token cannot rotate the account password" || fail "agent: $CODE $BODY"
call POST /api/identity/password/rotate-blind "$OWN" '{}'; [ "$CODE" = 403 ] && ok "no PIN set → refused" || fail "no pin set: $CODE $BODY"
call POST /api/identity/pin "$OWN" "$(jb pin 4321 password "$ACCT")"; [ "$CODE" = 200 ] || fail "set pin: $CODE $BODY"
call POST /api/identity/password/rotate-blind "$OWN" '{}'
[ "$CODE" = 403 ] && [ "$(echo "$BODY" | J intent)" = pw-rotate:0 ] && ok "the PIN is asked for (intent pw-rotate:0)" || fail "pin missing: $CODE $BODY"
pin(){ call POST /api/identity/gate/verify "$1" '{"gate":"pin","pin":"4321","intent":"'$2'"}'; [ "$CODE" = 200 ] || fail "pin $2: $CODE $BODY"; }
# link a phone (as device_keys_smoke): D and P keys, PIN + password gate
node -e 'const c=require("crypto"),fs=require("fs");for(const n of ["d","p"]){const {privateKey,publicKey}=c.generateKeyPairSync("ec",{namedCurve:"prime256v1"});
fs.writeFileSync(process.argv[1]+"/"+n+".pem",privateKey.export({type:"pkcs8",format:"pem"}));fs.writeFileSync(process.argv[1]+"/"+n+".pub",publicKey.export({type:"spki",format:"der"}).toString("base64"))}' "$S"
sig(){ node -e 'const c=require("crypto"),fs=require("fs"); process.stdout.write(c.sign("sha256", Buffer.from(process.argv[2]), fs.readFileSync(process.argv[1])).toString("base64"))' "$S/$1.pem" "$2"; }
call POST /api/identity/device/challenge "$OWN" '{"purpose":"enrol","intent":"device-enrol:0"}'; CHD=$(echo "$BODY" | J challenge_id); MSG="$(echo "$BODY" | J message):phone-0001"
pin "$OWN" device-enrol:0; call POST /api/identity/gate/verify "$OWN" "$(jb gate password password "$ACCT")"
call POST /api/identity/device/enrol "$OWN" "$(printf '{"challenge_id":%s,"device_id":"phone-0001","label":"Pixel","key_d":"%s","key_p":"%s","sig_d":"%s","sig_p":"%s"}' "$CHD" "$(cat $S/d.pub)" "$(cat $S/p.pub)" "$(sig d "$MSG")" "$(sig p "$MSG")")"
[ "$CODE" = 201 ] || fail "enrol: $CODE $BODY"
pin "$OWN" pw-rotate:0; call POST /api/identity/password/rotate-blind "$OWN" '{}'
{ [ "$CODE" = 423 ] || [ "$CODE" = 428 ]; } && ok "with a phone linked, the PIN alone does not rotate (phone locked → 423 / signature → 428)" || fail "phone required: $CODE $BODY"
# unlock with the presence key, then the device key signs the decision
call POST /api/identity/device/challenge "$OWN" '{"purpose":"gate","intent":"unlock:0"}'; CH=$(echo "$BODY" | J challenge_id)
call POST /api/identity/gate/verify "$OWN" "$(printf '{"gate":"device","challenge_id":%s,"signature":"%s","intent":"unlock:0"}' "$CH" "$(sig p "$(echo "$BODY" | J message)")")"; [ "$CODE" = 200 ] || fail "unlock: $CODE $BODY"
dsign(){ call POST /api/identity/device/challenge "$OWN" '{"purpose":"approve","intent":"pw-rotate:0","bind":"account-password"}'; DCH=$(echo "$BODY" | J challenge_id); DSG=$(sig d "$(echo "$BODY" | J message)"); }
OLDH=$(Q "SELECT password_hash FROM identity_wallets WHERE did='$DID'")
# a mail server that refuses the change: nothing moves
curl -s -X POST "http://127.0.0.1:$ST_PORT/__mode" -d '{"patch":"fail"}' >/dev/null
pin "$OWN" pw-rotate:0; dsign; call POST /api/identity/password/rotate-blind "$OWN" "$(printf '{"device_challenge_id":%s,"device_signature":"%s"}' "$DCH" "$DSG")"
[ "$CODE" = 503 ] && [ "$(Q "SELECT password_hash FROM identity_wallets WHERE did='$DID'")" = "$OLDH" ] && [ "$(Q "SELECT name FROM blindkey_secrets WHERE ref_code='$REF_A'")" = acct-copy ] \
  && [ "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["owner"])' "$S/stalwart.json")" = "{PLAIN}$MAILPW" ] && ok "the mail server refuses → 503, account, mailbox and vault all unchanged" || fail "mail fail: $CODE $BODY"
curl -s -X POST "http://127.0.0.1:$ST_PORT/__mode" -d '{"patch":"ok"}' >/dev/null
pin "$OWN" pw-rotate:0; dsign; call POST /api/identity/password/rotate-blind "$OWN" "$(printf '{"device_challenge_id":%s,"device_signature":"%s"}' "$DCH" "$DSG")"; R="$BODY"
[ "$CODE" = 200 ] && [ "$(echo "$R" | J mailbox)" = changed ] && ok "PIN + phone signature → rotated" || fail "rotate: $CODE $R"
NEWH=$(Q "SELECT password_hash FROM identity_wallets WHERE did='$DID'"); MBX=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["owner"])' "$S/stalwart.json")
[ "$NEWH" != "$OLDH" ] && [ "$NEWH" = "$MBX" ] && [[ "$NEWH" == '$scrypt$'* ]] && ok "account hash and mailbox secret are the same new scrypt hash (never split)" || fail "hashes: split or unchanged"
NA=$(val "SELECT encrypted_value FROM blindkey_secrets WHERE ref_code='$REF_A'"); NM=$(val "SELECT encrypted_value FROM blindkey_secrets WHERE ref_code='$REF_M'")
[ "$(Q "SELECT name FROM blindkey_secrets WHERE ref_code='$REF_A'")" = acct-copy_v2 ] && [ "$(Q "SELECT name FROM blindkey_secrets WHERE ref_code='$REF_M'")" = imap-copy_v2 ] \
  && [ "$NA" = "$NM" ] && [ "$NA" != "$ACCT" ] && verifies "$NA" "$NEWH" && ok "the entries that held the old account / mailbox password now hold the new one, refs kept (_v2)" || fail "moved secrets"
echo "$R" | grep -q -F -- "$NA" && fail "the reply carries the new password" || ok "the reply never carries the password"
[ "$(val "SELECT encrypted_value FROM blindkey_secrets WHERE name='other-pw'")" = unrelated-pw-55x ] && [ "$(Q "SELECT COUNT(*) FROM blindkey_secrets WHERE name LIKE 'other-pw_v%'")" = 0 ] && ok "an unrelated password is untouched" || fail "other-pw changed"
[ "$(echo "$R" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(sorted(x["name"] for x in d["secrets_moved"]), [x["name"] for x in d["skipped"]])')" = "['acct-copy', 'imap-copy'] ['elev-copy']" ] \
  && [ "$(val "SELECT encrypted_value FROM blindkey_secrets WHERE name='elev-copy'")" = "$ACCT" ] && ok "the reply names what moved and what was skipped (the elevated copy, unchanged)" || fail "report: $R"
call POST /api/identity/auth-fingerprint "" "$(jb username owner password "$ACCT" scope transact)"; [ "$CODE" = 401 ] && ok "the old password no longer signs in" || fail "old pw: $CODE"
call POST /api/identity/auth-fingerprint "" "$(jb username owner password "$NA" scope transact)"; [ "$CODE" = 200 ] && ok "the new one (from the vault) does" || fail "new pw: $CODE $BODY"
call GET /api/identity/devices "$OWN"; [ "$CODE" = 200 ] && ok "sessions are kept (the owner's token still works)" || fail "session cut: $CODE"
pin "$OWN" pw-rotate:0; call POST /api/identity/password/rotate-blind "$OWN" "$(printf '{"device_challenge_id":%s,"device_signature":"%s"}' "$DCH" "$DSG")"
[ "$CODE" = 403 ] && ok "a device signature works once" || fail "sig replay: $CODE $BODY"
# none matching → stored as a new secret (a wallet with no mailbox and no vault copy)
SOLO=$(login solo 'solo-pass-3Rt!'); call POST /api/identity/pin "$SOLO" "$(jb pin 4321 password 'solo-pass-3Rt!')"
pin "$SOLO" pw-rotate:0; call POST /api/identity/password/rotate-blind "$SOLO" '{}'
SN=$(echo "$BODY" | J stored_as.name)
[ "$CODE" = 200 ] && [ "$(echo "$BODY" | J mailbox)" = "no mailbox" ] && [ "$SN" = account-password-solo ] && verifies "$(val "SELECT encrypted_value FROM blindkey_secrets WHERE name='$SN'")" "$(Q "SELECT password_hash FROM identity_wallets WHERE username='solo'")" \
  && ok "nothing held the old password → the new one is stored as account-password-solo (never known to nobody)" || fail "solo: $CODE $BODY"
grep -q -F -- "$NA" "$S/server.log" && fail "the new password reached the server log" || ok "no password in the server log"

[ $fails -gt 0 ] && { echo "--- server.log"; grep -i -m8 "error" "$S/server.log"; }
echo "$fails failure(s)"; exit $(( fails > 0 ))
