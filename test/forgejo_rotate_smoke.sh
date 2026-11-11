#!/bin/bash
# No network beyond 127.0.0.1.
set -u
W=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
S=$(mktemp -d /tmp/dustforge-forgejo-rotate-smoke.XXXXXX)
PORT=${PORT:-3802}; API=http://127.0.0.1:$PORT
[ -d "$W/node_modules" ] || export NODE_PATH=${NODE_PATH:-/home/flimflam/project/dustforge/node_modules}
export FORGEJO_ROTATE_TEST_HOST=127.0.0.1:3803 IDENTITY_MASTER_KEY=$(python3 -c 'import secrets;print(secrets.token_hex(32))') DB_PATH=$S/dustforge.db PORT \
  STALWART_HOST=127.0.0.1 STALWART_PORT=1 SMTP_RELAY_HOST= SMTP_HOST=127.0.0.1 SMTP_PORT=9
cd "$W"
node server.js >"$S/server.log" 2>&1 & SRV=$!

for i in $(seq 1 40); do curl -s -o /dev/null "$API/api/health" && break; sleep 0.5; done
kill -0 $SRV 2>/dev/null || { echo "server died:"; tail -5 "$S/server.log"; exit 1; }
H=$(printf '%s' hunter22 | sha256sum | cut -d' ' -f1)
node -e '
const identity = require("./identity"); const Database = require("better-sqlite3"); const db = new Database(process.env.DB_PATH);
for (const [u, bal] of [["owner-a", 100000], ["other-x", 100000], ["bench-w", 0]]) { const id = identity.createIdentity(); const enc = id.encrypted_private_key || id.encryptedPrivateKey;
  db.prepare("INSERT INTO identity_wallets (did, username, email, encrypted_private_key, balance_cents, password_hash) VALUES (?, ?, ?, ?, ?, ?)").run(id.did, u, u + "@dustforge.com", enc, bal, process.argv[1]);
  if (bal) db.prepare("INSERT INTO identity_transactions (did, amount_cents, type, description, balance_after) VALUES (?, ?, ?, ?, ?)").run(id.did, bal, "topup", "smoke", bal); }' "$H"
fails=0; ok(){ echo "ok   $*"; }; fail(){ echo "FAIL $*"; fails=$((fails+1)); }
J(){ python3 -c 'import json,sys; d=json.load(sys.stdin); v=d
for k in sys.argv[1].split("."):
    v = v[int(k)] if isinstance(v, list) else (v or {}).get(k)
print(v)' "$1"; }
Q(){ python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); r=c.execute(sys.argv[2]).fetchone(); print(r[0] if r else '')" "$DB_PATH" "$1"; }
call(){ local m=$1 p=$2 t=$3 b=${4:-}
  BODY=$(curl -s -o - -w '\n%{http_code}' -X "$m" "$API$p" -H 'Content-Type: application/json' ${t:+-H "Authorization: Bearer $t"} ${b:+-d "$b"})
  CODE=${BODY##*$'\n'}; BODY=${BODY%$'\n'*}; }
login(){ call POST /api/identity/auth-fingerprint "" '{"username":"'$1'","password":"hunter22","scope":"transact","expires_in":"1h"}'; echo "$BODY" | J token; }
A=$(login owner-a); X=$(login other-x)
# A mock Forgejo: admin token "adm-token-xyz" may set a user's password; GET /api/v1/user checks basic auth against it.
cat > "$S/forge.js" <<'JS'
const http = require('http'); const fs = require('fs'); const st = process.argv[2];
let pw = { aaron: 'old-password-123' }; let refuse = false;
http.createServer((req, res) => { let b = ''; req.on('data', c => { b += c; }); req.on('end', () => {
  const j = (s, o) => { res.writeHead(s, { 'content-type': 'application/json' }); res.end(JSON.stringify(o)); };
  if (fs.existsSync(st + '.refuse')) refuse = true; else refuse = false;
  if (req.method === 'PATCH' && req.url === '/api/v1/admin/users/aaron') {
    if (req.headers.authorization !== 'token adm-token-xyz') return j(403, { message: 'not an admin' });
    if (refuse) return j(422, { message: 'nope' });
    pw.aaron = JSON.parse(b).password; fs.writeFileSync(st, String(pw.aaron.length)); return j(200, { login: 'aaron' });
  }
  if (req.method === 'GET' && req.url === '/api/v1/user') {
    const [u, p] = Buffer.from(String(req.headers.authorization || '').replace(/^Basic /, ''), 'base64').toString().split(':');
    return pw[u] && pw[u] === p ? j(200, { login: u }) : j(401, { message: 'bad' });
  }
  j(404, {});
}); }).listen(3803, '127.0.0.1');
JS
node "$S/forge.js" "$S/forge.state" & FORGE=$!; trap 'kill $SRV $FORGE 2>/dev/null; rm -rf "$S"' EXIT; sleep 0.5
st(){ call POST /api/demipass/store "$1" "$(python3 -c 'import json,sys; print(json.dumps({"name":sys.argv[1],"value":sys.argv[2],"secret_type":sys.argv[3]}))' "$2" "$3" "$4")"; echo "$BODY" | J ref; }
LOGIN=$(st "$A" forgejo-aaron-web-login old-password-123 password); ADM=$(st "$A" forgejo-aaron-api-token adm-token-xyz api_key); XADM=$(st "$X" x-admin adm-token-xyz api_key)
B='"base_url":"http://127.0.0.1:3803","username":"aaron"'
call POST /api/demipass/rotate-blind/forgejo "$A" '{"ref":"'$LOGIN'","admin_ref":"'$ADM'",'"$B"'}'
[ "$CODE" = 200 ] && [ "$(echo "$BODY" | J signed_in)" = True ] && [ "$(echo "$BODY" | J new_ref)" = "$LOGIN" ] && [ "$(cat "$S/forge.state")" = 32 ] \
  && [ "$(Q "SELECT status FROM blindkey_secrets WHERE name='forgejo-aaron-web-login'")" = rotating ] && [ "$(Q "SELECT version FROM blindkey_secrets WHERE ref_code='$LOGIN'")" = 2 ] \
  && ! echo "$BODY" | grep -q "old-password-123" && ok "blind rotation: Forgejo set to a 32-char random password that signs in; the vault entry rotated under the same ref; no value returned" || fail "rotate: $CODE $BODY"
touch "$S/forge.state.refuse"; V0=$(Q "SELECT version FROM blindkey_secrets WHERE ref_code='$LOGIN'")
call POST /api/demipass/rotate-blind/forgejo "$A" '{"ref":"'$LOGIN'","admin_ref":"'$ADM'",'"$B"'}'
[ "$CODE" = 502 ] && [ "$(echo "$BODY" | J changed)" = False ] && [ "$(Q "SELECT version FROM blindkey_secrets WHERE ref_code='$LOGIN'")" = "$V0" ] && ok "Forgejo refusing the change leaves the vault as it was (changed: false)" || fail "refused: $CODE $BODY"
rm -f "$S/forge.state.refuse"
call POST /api/demipass/rotate-blind/forgejo "$A" '{"ref":"'$LOGIN'","admin_ref":"'$ADM'","base_url":"https://evil.example","username":"aaron"}'; A1=$CODE
call POST /api/demipass/rotate-blind/forgejo "$A" '{"ref":"'$LOGIN'","admin_ref":"'$ADM'","base_url":"http://repo.dustroot.com","username":"aaron"}'; A2=$CODE
call POST /api/demipass/rotate-blind/forgejo "$A" '{"ref":"'$LOGIN'","admin_ref":"'$XADM'",'"$B"'}'; A3=$CODE
call POST /api/demipass/rotate-blind/forgejo "$A" '{"ref":"'$LOGIN'","admin_ref":"'$ADM'","base_url":"http://127.0.0.1:3803","username":"bad name"}'; A4=$CODE
[ "$A1" = 400 ] && [ "$A2" = 400 ] && [ "$A3" = 404 ] && [ "$A4" = 400 ] && ok "only https on the Forgejo hosts; only the owner's own admin token; a valid username" || fail "refusals: $A1 $A2 $A3 $A4"
call POST /api/demipass/rotate-blind/forgejo "$X" '{"ref":"'$LOGIN'","admin_ref":"'$XADM'",'"$B"'}'; [ "$CODE" = 404 ] && ok "someone else cannot rotate my login" || fail "other: $CODE"
echo; [ $fails = 0 ] && echo "forgejo_rotate_smoke: all passed" || { echo "forgejo_rotate_smoke: $fails FAILED"; exit 1; }
