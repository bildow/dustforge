#!/bin/bash
# Leak scanner smoke (red team item 5): a seeded vault value planted in a file trips the scanner (plain and JSON-escaped),
# a clean tree passes, the scanner's output never contains the value, scan tokens are minted with the PIN only and are
# good only for scanning, another owner's values are not matched, a revoked token is refused, every hit is critical.
set -u
W=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
S=$(mktemp -d /tmp/dustforge-leakscan-smoke.XXXXXX)
PORT=${PORT:-3791}; API=http://127.0.0.1:$PORT
[ -d "$W/node_modules" ] || export NODE_PATH=${NODE_PATH:-/home/flimflam/project/dustforge/node_modules}
export IDENTITY_MASTER_KEY=$(python3 -c 'import secrets;print(secrets.token_hex(32))') DB_PATH=$S/dustforge.db PORT \
  STALWART_HOST=127.0.0.1 STALWART_PORT=1 SMTP_RELAY_HOST= SMTP_HOST=127.0.0.1 SMTP_PORT=9
cd "$W"
node server.js >"$S/server.log" 2>&1 & SRV=$!
trap 'kill $SRV 2>/dev/null; rm -rf "$S"' EXIT
for i in $(seq 1 40); do curl -s -o /dev/null "$API/" && break; sleep 0.5; done
kill -0 $SRV 2>/dev/null || { echo "server died:"; tail -5 "$S/server.log"; exit 1; }
H=$(printf '%s' hunter22 | sha256sum | cut -d' ' -f1)
node -e '
const identity = require("./identity"); const Database = require("better-sqlite3"); const db = new Database(process.env.DB_PATH);
for (const c of ["idempotency_key TEXT", "provenance TEXT DEFAULT '"'"'organic'"'"'"]) { try { db.exec("ALTER TABLE identity_transactions ADD COLUMN " + c); } catch (_) {} }
for (const u of ["owner-a", "other-x"]) { const id = identity.createIdentity(); const enc = id.encrypted_private_key || id.encryptedPrivateKey;
  db.prepare("INSERT INTO identity_wallets (did, username, email, encrypted_private_key, balance_cents, password_hash) VALUES (?, ?, ?, ?, 100000, ?)").run(id.did, u, u + "@dustforge.com", enc, process.argv[1]);
  db.prepare("INSERT INTO identity_transactions (did, amount_cents, type, description, balance_after) VALUES (?, 100000, ?, ?, 100000)").run(id.did, "topup", "smoke"); }' "$H"
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
call POST /api/identity/pin "$A" '{"pin":"4321","password":"hunter22"}'
# the seed: random, with a quote so its JSON-escaped form differs; kept in a 0600 file, never echoed
umask 077; python3 -c 'import secrets;print("seed-" + secrets.token_urlsafe(12) + "\"q")' > "$S/seed"
python3 -c 'import json,sys; print(json.dumps({"name":"seeded","value":open(sys.argv[1]).read().strip(),"secret_type":"api_key"}))' "$S/seed" > "$S/store.json"
curl -s -o /dev/null -X POST "$API/api/demipass/store" -H 'content-type: application/json' -H "Authorization: Bearer $A" -d @"$S/store.json"; rm -f "$S/store.json"
REF=$(Q "SELECT ref_code FROM blindkey_secrets WHERE name='seeded'")
call POST /api/demipass/store "$A" '{"name":"tiny","value":"abc1234","secret_type":"api_key"}'
# a tree: a plain leak, a JSON-escaped leak (a transcript line), the short value, and a clean file
mkdir -p "$S/tree/sub" "$S/clean"
python3 - "$S" <<'PY'
import json,sys; S=sys.argv[1]; v=open(S+'/seed').read().strip()
open(S+'/tree/notes.md','w').write('line one\nthe token is '+v+' oops\nline three\n')
open(S+'/tree/sub/transcript.jsonl','w').write(json.dumps({"tool_result": "output: "+v})+'\n')
open(S+'/tree/short.txt','w').write('abc1234 is short\n')
open(S+'/clean/ok.md','w').write('nothing to see\n')
PY

# minting
call POST /api/demipass/leak-scan/tokens "$A" '{"label":"ci"}'; [ "$CODE" = 403 ] && [ "$(echo "$BODY" | J intent)" = "scan-token:0" ] && ok "a scan token needs the owner's PIN" || fail "mint no pin: $CODE $BODY"
call POST /api/identity/gate/verify "$A" '{"gate":"pin","pin":"4321","intent":"scan-token:0"}'
call POST /api/demipass/leak-scan/tokens "$A" '{"label":"ci"}'
[ "$CODE" = 201 ] || fail "mint: $CODE"
echo "$BODY" | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])' > "$S/scantok"; chmod 600 "$S/scantok"
TID=$(echo "$BODY" | J id)
[ "$(Q "SELECT COUNT(*) FROM leak_scan_tokens WHERE token_hash LIKE 'dpscan_%'")" = 0 ] && ok "the scan token is stored hashed" || fail "token stored raw"
call GET /api/demipass/menu "" ; curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $(cat "$S/scantok")" "$API/api/demipass/menu" | grep -q 401 && ok "a scan token is good for nothing but scanning (Bearer → 401)" || fail "scan token as bearer"

# scanning
OUT=$(DEMIPASS_URL=$API DEMIPASS_SCAN_TOKEN_FILE="$S/scantok" node bin/leak-scan.js "$S/tree" 2>&1); RC=$?
[ $RC = 1 ] && echo "$OUT" | grep -q "LEAK  $REF  seeded  at $S/tree/notes.md:" && echo "$OUT" | grep -q "transcript.jsonl" && ok "the seeded value trips the scanner — plain and JSON-escaped (exit 1, ref + file:lines)" || fail "seed: rc=$RC $OUT"
! echo "$OUT" | grep -qF -- "$(cat "$S/seed")" && ! echo "$OUT" | grep -qF -- "$(sed 's/"/\\"/' "$S/seed")" && ok "the scanner's output never contains the value" || fail "value printed"
! echo "$OUT" | grep -q tiny && ok "values shorter than 8 characters are not matched (oracle bound)" || fail "short matched"
OUT=$(DEMIPASS_URL=$API DEMIPASS_SCAN_TOKEN_FILE="$S/scantok" node bin/leak-scan.js "$S/clean" 2>&1); RC=$?
[ $RC = 0 ] && echo "$OUT" | grep -q "0 hits" && ok "a clean tree passes (exit 0)" || fail "clean: rc=$RC $OUT"
[ "$(Q "SELECT COUNT(*) FROM demipass_security_events WHERE event_type='leak_scan_hit' AND severity='critical'")" -ge 2 ] && ok "every hit is a critical security event" || fail "hit events"
! grep -qF -- "$(cat "$S/seed")" "$S/server.log" && [ "$(Q "SELECT COUNT(*) FROM blindkey_events WHERE detail LIKE '%seed-%'")" = 0 ] && ok "no value in the server log or the events" || fail "value logged"
# another owner's session finds nothing of A's
python3 -c 'import json,sys; print(json.dumps({"chunks":[{"id":"t","text":open(sys.argv[1]).read()}]}))' "$S/tree/notes.md" > "$S/body.json"
H2=$(curl -s -X POST "$API/api/demipass/leak-scan" -H 'content-type: application/json' -H "Authorization: Bearer $X" -d @"$S/body.json" | J hits); rm -f "$S/body.json"
[ "$H2" = "[]" ] && ok "another owner scanning the same text matches only their own values (none)" || fail "cross-owner: $H2"
# a 1.5 MB body is accepted (its own parser, not the global 100 kB one)
python3 -c 'import json; print(json.dumps({"chunks":[{"id":"big","text":"x"*1500000}]}))' > "$S/big.json"
C=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$API/api/demipass/leak-scan" -H 'content-type: application/json' -H "Authorization: Scan $(cat "$S/scantok")" -d @"$S/big.json"); rm -f "$S/big.json"
[ "$C" = 200 ] && ok "a 1.5 MB scan body is accepted" || fail "big body: $C"
# revoke
call DELETE /api/demipass/leak-scan/tokens/$TID "$A"
OUT=$(DEMIPASS_URL=$API DEMIPASS_SCAN_TOKEN_FILE="$S/scantok" node bin/leak-scan.js "$S/tree" 2>&1); RC=$?
[ $RC = 2 ] && echo "$OUT" | grep -q "401" && ok "a revoked scan token is refused (exit 2)" || fail "revoked: rc=$RC $OUT"

echo; [ $fails = 0 ] && echo "ALL OK" || echo "$fails FAILED"; exit $fails
