#!/bin/bash
# No network beyond 127.0.0.1.
set -u
W=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
S=$(mktemp -d /tmp/dustforge-forgejo-rotate-smoke.XXXXXX)
PORT=${PORT:-3802}; API=http://127.0.0.1:$PORT
[ -d "$W/node_modules" ] || export NODE_PATH=${NODE_PATH:-/home/flimflam/project/dustforge/node_modules}
export NODE_ENV=test FORGEJO_ROTATE_TEST_HOST=127.0.0.1:3803 IDENTITY_MASTER_KEY=$(python3 -c 'import secrets;print(secrets.token_hex(32))') DB_PATH=$S/dustforge.db PORT \
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
# Modes (files): .refuse → 422; .drop → the PATCH is applied and the connection dropped; .ldap → user from an external source.
cat > "$S/forge.js" <<'JS'
const http = require('http'); const fs = require('fs'); const st = process.argv[2];
let pw = { aaron: 'old-password-123', kyle: 'kyle-pass-456' };
http.createServer((req, res) => { let b = ''; req.on('data', c => { b += c; }); req.on('end', () => {
  const j = (s, o) => { res.writeHead(s, { 'content-type': 'application/json' }); res.end(JSON.stringify(o)); };
  const admin = req.headers.authorization === 'token adm-token-xyz';
  const m = /^\/api\/v1\/(admin\/)?users\/([^/]+)$/.exec(req.url);
  if (req.method === 'GET' && m && !m[1]) { if (!admin) return j(403, {}); return pw[m[2]] ? j(200, { login: m[2], login_name: m[2], source_id: fs.existsSync(st + '.ldap') ? 2 : 0 }) : j(404, {}); }
  if (req.method === 'PATCH' && m && m[1]) {
    if (!admin) return j(403, { message: 'not an admin' });
    if (fs.existsSync(st + '.refuse')) return j(422, { message: 'nope' });
    pw[m[2]] = JSON.parse(b).password; fs.writeFileSync(st + '.' + m[2], String(pw[m[2]].length));
    if (fs.existsSync(st + '.drop')) return req.socket.destroy();
    return j(200, { login: m[2] });
  }
  if (req.method === 'GET' && req.url === '/api/v1/user') {
    const [u, p] = Buffer.from(String(req.headers.authorization || '').replace(/^Basic /, ''), 'base64').toString().split(':');
    return pw[u] && pw[u] === p ? j(200, { login: u }) : j(401, { message: 'bad' });
  }
  j(404, {});
}); }).listen(3803, '127.0.0.1');
JS
node "$S/forge.js" "$S/forge" & FORGE=$!; trap 'kill $SRV $FORGE 2>/dev/null; rm -rf "$S"' EXIT; sleep 0.5
st(){ call POST /api/demipass/store "$1" "$(python3 -c 'import json,sys; print(json.dumps({"name":sys.argv[1],"value":sys.argv[2],"secret_type":sys.argv[3]}))' "$2" "$3" "$4")"; echo "$BODY" | J ref; }
SQ(){ python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute(sys.argv[2]); c.commit()" "$DB_PATH" "$1"; }
LOGIN=$(st "$A" forgejo-aaron-web-login old-password-123 password); ADM=$(st "$A" forgejo-aaron-api-token adm-token-xyz api_key)
BANK=$(st "$A" bank-login bank-secret-789 password); XADM=$(st "$X" x-admin adm-token-xyz api_key)
for r in "$ADM" "$XADM"; do SQ "INSERT INTO blindkey_contexts (secret_id, context_name, action_type, target_url_pattern, target_host_pattern, allowed_by, status) SELECT id, 'forgejo-api', 'http_header', 'https://repo.dustroot.com/api/v1/*', 'repo.dustroot.com', did, 'active' FROM blindkey_secrets WHERE ref_code='$r'"; done
B='"base_url":"http://127.0.0.1:3803","username":"aaron"'
SIL="silicon:$(python3 -c 'import secrets;print(secrets.token_hex(16))')"
python3 -c "import sqlite3,sys,hashlib; c=sqlite3.connect(sys.argv[1]); d=c.execute(\"SELECT did FROM identity_wallets WHERE username='owner-a'\").fetchone()[0]; c.execute('INSERT INTO silicon_agents (agent_name, did, carbon_did, token_hash) VALUES (?, ?, ?, ?)', ('bot-1', 'did:key:zBot1', d, hashlib.sha256(sys.argv[2].encode()).hexdigest())); c.commit()" "$DB_PATH" "$SIL"
call POST /api/demipass/rotate-blind/forgejo "$SIL" '{"ref":"'$LOGIN'","admin_ref":"'$ADM'",'"$B"'}'
[ "$CODE" = 403 ] && [ ! -e "$S/forge.aaron" ] && ok "an agent token never rotates its owner's login (nothing sent to Forgejo)" || fail "agent: $CODE $BODY"
call POST /api/demipass/rotate-blind/forgejo "$A" '{"ref":"'$BANK'","admin_ref":"'$ADM'","base_url":"http://127.0.0.1:3803","username":"kyle"}'
[ "$CODE" = 409 ] && [ ! -e "$S/forge.kyle" ] && [ "$(Q "SELECT status FROM blindkey_secrets WHERE ref_code='$BANK'")" = active ] && ok "an unrelated secret (not a Forgejo login) cannot be used to reset someone: 409, nothing changed" || fail "bank: $CODE $BODY"
call POST /api/demipass/rotate-blind/forgejo "$A" '{"ref":"'$LOGIN'","admin_ref":"'$ADM'",'"$B"'}'
[ "$CODE" = 200 ] && [ "$(echo "$BODY" | J signed_in)" = True ] && [ "$(echo "$BODY" | J new_ref)" = "$LOGIN" ] && [ "$(cat "$S/forge.aaron")" = 32 ] \
  && [ "$(Q "SELECT version || '/' || COALESCE(account_username,'') FROM blindkey_secrets WHERE ref_code='$LOGIN'")" = "2/aaron" ] && [ "$(Q "SELECT COUNT(*) FROM blindkey_secrets WHERE name LIKE '%-pending-%'")" = 0 ] \
  && ! echo "$BODY" | grep -q "old-password-123" && ok "blind rotation: a 32-char random password that signs in; same ref; the login is now bound to aaron; no pending entry left; no value returned" || fail "rotate: $CODE $BODY"
call POST /api/demipass/rotate-blind/forgejo "$A" '{"ref":"'$LOGIN'","admin_ref":"'$ADM'","base_url":"http://127.0.0.1:3803","username":"kyle"}'
[ "$CODE" = 409 ] && ok "a bound login cannot be pointed at another user" || fail "rebind: $CODE $BODY"
call POST /api/demipass/rotate-blind/forgejo "$A" '{"ref":"'$LOGIN'","admin_ref":"'$ADM'",'"$B"'}'; A1=$CODE
call POST /api/demipass/rotate-blind/forgejo "$A" '{"ref":"'$LOGIN'","admin_ref":"'$ADM'","base_url":"http://127.0.0.1:3803","username":"kyle"}'; A2=$CODE
[ "$A1" = 200 ] && [ "$A2" = 409 ] && [ "$(Q "SELECT version || '/' || COALESCE(account_username,'') FROM blindkey_secrets WHERE ref_code='$LOGIN'")" = "3/aaron" ] && [ ! -e "$S/forge.kyle" ] \
  && ok "…and stays bound through every rotation (v3 is still aaron's; kyle is never reset)" || fail "rebind after 2nd rotation: $A1 $A2 $(Q "SELECT version || '/' || COALESCE(account_username,'') FROM blindkey_secrets WHERE ref_code='$LOGIN'")"
touch "$S/forge.refuse"; V0=$(Q "SELECT version FROM blindkey_secrets WHERE ref_code='$LOGIN'")
call POST /api/demipass/rotate-blind/forgejo "$A" '{"ref":"'$LOGIN'","admin_ref":"'$ADM'",'"$B"'}'
[ "$CODE" = 502 ] && [ "$(echo "$BODY" | J changed)" = False ] && [ "$(Q "SELECT version FROM blindkey_secrets WHERE ref_code='$LOGIN'")" = "$V0" ] && [ "$(Q "SELECT COUNT(*) FROM blindkey_secrets WHERE name LIKE '%-pending-%'")" = 0 ] \
  && ok "Forgejo refusing the change leaves the vault as it was (no pending entry kept)" || fail "refused: $CODE $BODY"
rm -f "$S/forge.refuse"; touch "$S/forge.drop"
call POST /api/demipass/rotate-blind/forgejo "$A" '{"ref":"'$LOGIN'","admin_ref":"'$ADM'",'"$B"'}'
[ "$CODE" = 502 ] && [ "$(Q "SELECT COUNT(*) FROM blindkey_secrets WHERE name LIKE 'forgejo-aaron-web-login-pending-%' AND status='active'")" = 1 ] \
  && ok "the connection dropping after Forgejo applied it: the new password is kept in a pending vault entry (never lost)" || fail "drop: $CODE $BODY"
rm -f "$S/forge.drop"; SQ "DELETE FROM blindkey_secrets WHERE name LIKE '%-pending-%'"
touch "$S/forge.ldap"; call POST /api/demipass/rotate-blind/forgejo "$A" '{"ref":"'$LOGIN'","admin_ref":"'$ADM'",'"$B"'}'; A1=$CODE; rm -f "$S/forge.ldap"
SQ "UPDATE blindkey_secrets SET frozen = 1 WHERE ref_code='$ADM'"; call POST /api/demipass/rotate-blind/forgejo "$A" '{"ref":"'$LOGIN'","admin_ref":"'$ADM'",'"$B"'}'; A2=$CODE; SQ "UPDATE blindkey_secrets SET frozen = 0 WHERE ref_code='$ADM'"
SQ "UPDATE blindkey_contexts SET target_url_pattern='https://repo.dustroot.com/api/v1/repos/*' WHERE secret_id=(SELECT id FROM blindkey_secrets WHERE ref_code='$ADM')"
call POST /api/demipass/rotate-blind/forgejo "$A" '{"ref":"'$LOGIN'","admin_ref":"'$ADM'",'"$B"'}'; A3=$CODE
[ "$A1" = 409 ] && [ "$A2" = 423 ] && [ "$A3" = 403 ] && ok "an externally-authenticated user, a frozen admin token, and a token whose scope does not reach the admin API are refused" || fail "guards: $A1 $A2 $A3"
call POST /api/demipass/rotate-blind/forgejo "$A" '{"ref":"'$LOGIN'","admin_ref":"'$ADM'","base_url":"https://evil.example","username":"aaron"}'; A1=$CODE
call POST /api/demipass/rotate-blind/forgejo "$A" '{"ref":"'$LOGIN'","admin_ref":"'$ADM'","base_url":"https://repo.dustroot.com:3000","username":"aaron"}'; A2=$CODE
call POST /api/demipass/rotate-blind/forgejo "$A" '{"ref":"'$LOGIN'","admin_ref":"'$XADM'",'"$B"'}'; A3=$CODE
[ "$A1" = 400 ] && [ "$A2" = 400 ] && [ "$A3" = 404 ] && ok "only https on the Forgejo hosts (no other port); only the owner's own admin token" || fail "refusals: $A1 $A2 $A3"
call POST /api/demipass/rotate-blind/forgejo "$X" '{"ref":"'$LOGIN'","admin_ref":"'$XADM'",'"$B"'}'; [ "$CODE" = 404 ] && ok "someone else cannot rotate my login" || fail "other: $CODE"
echo; [ $fails = 0 ] && echo "forgejo_rotate_smoke: all passed" || { echo "forgejo_rotate_smoke: $fails FAILED"; exit 1; }
