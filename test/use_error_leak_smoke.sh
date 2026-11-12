#!/bin/bash
# A secret value never comes back in an error (2026-11-12, found reviewing #104): a header_prefix with a control
# character made fetch throw an error quoting the header (value included), which /use returned and stored.
set -u
W=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
S=$(mktemp -d /tmp/dustforge-use-leak-smoke.XXXXXX)
PORT=${PORT:-3951}; UP_PORT=${UP_PORT:-3952}; API=http://127.0.0.1:$PORT
[ -d "$W/node_modules" ] || export NODE_PATH=${NODE_PATH:-/home/flimflam/project/dustforge/node_modules}
export IDENTITY_MASTER_KEY=$(python3 -c 'import secrets;print(secrets.token_hex(32))') DB_PATH=$S/dustforge.db PORT \
  STALWART_HOST=127.0.0.1 STALWART_PORT=1 SMTP_RELAY_HOST= SMTP_HOST=127.0.0.1 SMTP_PORT=9 \
  TEST_UPSTREAM=http://127.0.0.1:$UP_PORT TEST_UPSTREAM_HOSTS=repo.dustroot.com,server.dustroot.com UP_LOG=$S/upstream.log
cd "$W"
SEC='dash-token-value-7f3a19c2e5'
node -e '
const http = require("http"), fs = require("fs");
http.createServer((req, res) => { req.resume(); req.on("end", () => { fs.appendFileSync(process.env.UP_LOG, req.method + " " + req.url + "\n"); res.writeHead(200, { "content-type": "application/json" }); res.end(JSON.stringify({ path: req.url, method: req.method, seen: req.headers.authorization || "" })); }); })
  .listen(+process.argv[1], "127.0.0.1");' $UP_PORT & UP=$!
node --require ./test/fixtures/upstream-redirect.js server.js >"$S/server.log" 2>&1 & SRV=$!
trap 'kill $SRV $UP 2>/dev/null; rm -rf "$S"' EXIT
for i in $(seq 1 40); do curl -s -o /dev/null "$API/" && break; sleep 0.5; done
kill -0 $SRV 2>/dev/null || { echo "server died:"; tail -5 "$S/server.log"; exit 1; }
H=$(printf '%s' hunter22 | sha256sum | cut -d' ' -f1)
node -e '
const identity = require("./identity"); const Database = require("better-sqlite3");
const db = new Database(process.env.DB_PATH);
for (const c of ["idempotency_key TEXT", "provenance TEXT DEFAULT '"'"'organic'"'"'"]) { try { db.exec("ALTER TABLE identity_transactions ADD COLUMN " + c); } catch (_) {} }
const mk = (u) => { const id = identity.createIdentity(); const enc = id.encrypted_private_key || id.encryptedPrivateKey;
  db.prepare("INSERT INTO identity_wallets (did, username, email, encrypted_private_key, balance_cents, password_hash) VALUES (?, ?, ?, ?, 100000, ?)").run(id.did, u, u + "@dustforge.com", enc, process.argv[1]);
  db.prepare("INSERT INTO identity_transactions (did, amount_cents, type, description, balance_after) VALUES (?, 100000, ?, ?, 100000)").run(id.did, "topup", "smoke"); return id.did; };
const a = mk("owner-a"), b = mk("agent-b");
// B is a linked silicon of A'"'"'s fleet (its own wallet, joined by the owner; created_by_fleet 0 — Brain'"'"'s shape).
const f = db.prepare("INSERT INTO fleets (owner_did, name, slug) VALUES (?, ?, ?)").run(a, "Owner A", "owner-agents").lastInsertRowid;
db.prepare("INSERT INTO fleet_silicons (fleet_id, member_did, handle, silicon_id, status, created_by_fleet, joined_via) VALUES (?, ?, ?, ?, ?, 0, ?)").run(f, b, "agent-b", "sil_scope_b", "active", "owner");' "$H"
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
pin(){ call POST /api/identity/gate/verify "$1" '{"gate":"pin","pin":"'$2'","intent":"'$3'"}'; [ "$CODE" = 200 ] || fail "pin $3: $CODE $BODY"; }
egress(){ Q "SELECT COUNT(*) FROM blindkey_events WHERE event_type='egress' AND secret_id=$1"; }
hits(){ [ -f "$UP_LOG" ] && wc -l <"$UP_LOG" || echo 0; }
A=$(login owner-a); AG=$(login owner-a); B=$(login agent-b)
BDID=$(Q "SELECT did FROM identity_wallets WHERE username='agent-b'")
call POST /api/identity/pin "$A" '{"pin":"4321","password":"hunter22"}'
call POST /api/demipass/store "$A" '{"name":"dash-token","value":"'$SEC'","secret_type":"api_key"}'; REF=$(echo "$BODY" | J ref)
leaks(){ echo "$1" | grep -qF "$SEC" || echo "$1" | grep -qF "${SEC:0:12}"; }
# direct mode (owner), header_prefix with NUL / CR-LF, header_name with CR-LF
for P in '"\u0000"' '"Bearer \r\nX-Evil: 1"'; do
  call POST /api/demipass/use "$A" '{"ref":"'$REF'","action":"http_header","params":{"url":"https://server.dustroot.com/x","header_prefix":'"$P"'}}'
  [ "$CODE" = 400 ] && ! leaks "$BODY" && ok "direct /use, header_prefix $P: 400 before any request, no value" || fail "direct prefix $P: $CODE $BODY"
done
call POST /api/demipass/use "$A" '{"ref":"'$REF'","action":"http_header","params":{"url":"https://server.dustroot.com/x","header_name":"X-A\r\nX-B"}}'
[ "$CODE" = 400 ] && ! leaks "$BODY" && ok "direct /use, header_name with CR-LF: 400" || fail "direct name: $CODE $BODY"
for P in '{"header_name":"Host"}' '{"header_name":"proxy-authorization"}' '{"header_prefix":"Bearer \u0100"}'; do
  call POST /api/demipass/use "$A" '{"ref":"'$REF'","action":"http_header","params":{"url":"https://server.dustroot.com/x",'"${P:1:-1}"'}}'
  [ "$CODE" = 400 ] && ! leaks "$BODY" && ok "refused: $P" || fail "not refused $P: $CODE $BODY"
done
for P in '{"header_name":"X-Api-Key","header_prefix":""}' '{"header_name":"Authorization","header_prefix":"token "}' '{"header_name":"Cookie","header_prefix":"session="}'; do
  call POST /api/demipass/use "$A" '{"ref":"'$REF'","action":"http_header","params":{"url":"https://server.dustroot.com/x",'"${P:1:-1}"'}}'
  [ "$CODE" = 200 ] && ok "still works: $P" || fail "legit broke $P: $CODE $BODY"
done
# use-token mode (as an agent would)
call POST /api/demipass/request-token "$A" '{"ref":"'$REF'","action":"http_header","target_url":"https://server.dustroot.com/x"}'; UT=$(echo "$BODY" | J use_token)
call POST /api/demipass/use "$A" '{"use_token":"'$UT'","action":"http_header","params":{"header_prefix":"\u0000"}}'
[ "$CODE" = 400 ] && ! leaks "$BODY" && ok "use-token /use, header_prefix NUL: 400, no value" || fail "use-token prefix: $CODE $BODY"
# a stored value that itself is not a valid header value: the fetch error is scrubbed
BAD='bad-value-'$(python3 -c 'import secrets;print(secrets.token_hex(8))')
python3 -c 'import json,sys; print(json.dumps({"name":"bad-hdr","value":sys.argv[1]+"\u0001tail","secret_type":"api_key"}))' "$BAD" > "$S/bad.json"
curl -s -o /dev/null -X POST "$API/api/demipass/store" -H 'content-type: application/json' -H "Authorization: Bearer $A" -d @"$S/bad.json"; rm -f "$S/bad.json"
BREF=$(Q "SELECT ref_code FROM blindkey_secrets WHERE name='bad-hdr'")
if [ -n "$BREF" ]; then
  call POST /api/demipass/use "$A" '{"ref":"'$BREF'","action":"http_header","params":{"url":"https://server.dustroot.com/x"}}'
  ! echo "$BODY" | grep -qF "$BAD" && ok "a value fetch refuses as a header: the error is scrubbed ($CODE)" || fail "value in error: $BODY"
else ok "(store refused a control character in the value: nothing to scrub)"; fi
OUT=$(python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); print('\n'.join(r[0] or '' for r in c.execute('SELECT error_summary FROM secret_outcomes')))" "$DB_PATH")
! echo "$OUT" | grep -qF "$SEC" && ! echo "$OUT" | grep -qF "$BAD" && ok "secret_outcomes holds no value" || fail "outcomes: $OUT"
! grep -qF "$SEC" "$S/server.log" && ok "the server log holds no value" || fail "log"
echo; [ $fails = 0 ] && echo "ALL OK" || echo "$fails FAILED"; exit $fails
