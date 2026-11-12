#!/bin/bash
# Leak scanner smoke (red team item 5): a seeded vault value planted in a file trips the scanner (plain and JSON-escaped),
# a clean tree passes, the scanner's output never contains the value, scan tokens are minted with the PIN only and are
# good only for scanning, another owner's values are not matched, every hit is critical. No session token scans (no
# oracle for agents); the first hit revokes the token (one positive answer per token). Tokens can be requested by
# whoever acts for the owner and approved in the app with the PIN; the requester claims them once (--request).
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
mint(){ call POST /api/identity/gate/verify "$A" '{"gate":"pin","pin":"4321","intent":"scan-token:0"}'; call POST /api/demipass/leak-scan/tokens "$A" '{"label":"'$1'"}'
  [ "$CODE" = 201 ] || fail "mint: $CODE"; echo "$BODY" | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])' > "$S/$1.tok"; chmod 600 "$S/$1.tok"; }
mint ci; TID=$(echo "$BODY" | J id)
[ "$(Q "SELECT COUNT(*) FROM leak_scan_tokens WHERE token_hash LIKE 'dpscan_%'")" = 0 ] && ok "the scan token is stored hashed" || fail "token stored raw"
curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $(cat "$S/ci.tok")" "$API/api/demipass/menu" | grep -q 401 && ok "a scan token is good for nothing but scanning (Bearer → 401)" || fail "scan token as bearer"
SCAN(){ DEMIPASS_URL=$API DEMIPASS_SCAN_TOKEN_FILE="$S/$1.tok" node bin/leak-scan.js "${@:2}" 2>&1; }

# no session token scans
python3 -c 'import json,sys; print(json.dumps({"chunks":[{"id":"t","text":open(sys.argv[1]).read()}]}))' "$S/tree/notes.md" > "$S/body.json"
C=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$API/api/demipass/leak-scan" -H 'content-type: application/json' -H "Authorization: Bearer $A" -d @"$S/body.json")
[ "$C" = 403 ] && ok "the owner's own session token cannot scan (no oracle for an agent holding it)" || fail "bearer scan: $C"
OUT=$(DEMIPASS_URL=$API DEMIPASS_TOKEN=$A node bin/leak-scan.js "$S/tree" 2>&1); RC=$?
[ $RC = 2 ] && ok "…and the client will not scan without a scan token" || fail "client bearer: rc=$RC $OUT"

# clean first, then the leak
OUT=$(SCAN ci "$S/clean"); RC=$?
[ $RC = 0 ] && echo "$OUT" | grep -q "clean" && ok "a clean tree passes (exit 0)" || fail "clean: rc=$RC $OUT"
python3 -c 'import json; print(json.dumps({"chunks":[{"id":"big","text":"x"*1500000}]}))' > "$S/big.json"
C=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$API/api/demipass/leak-scan" -H 'content-type: application/json' -H "Authorization: Scan $(cat "$S/ci.tok")" -d @"$S/big.json"); rm -f "$S/big.json"
[ "$C" = 200 ] && ok "a 1.5 MB scan body is accepted" || fail "big body: $C"
OUT=$(SCAN ci "$S/tree"); RC=$?
[ $RC = 1 ] && echo "$OUT" | grep -q "LEAK" && ! echo "$OUT" | grep -q "seeded\|$REF\|notes.md" && ok "the seeded value trips the scanner (exit 1) — and the scanner is told only leak, not which secret or where" || fail "leak: rc=$RC $OUT"
call GET /api/demipass/leak-scan/tokens "$A"; HID=$(echo "$BODY" | python3 -c 'import json,sys; print(json.load(sys.stdin)["hits"][0]["id"])')
echo "$BODY" | grep -q '"seeded"' && ! echo "$BODY" | grep -q "notes.md\|chunk\|count" && ok "the token listing names the secret found — never where or how often (an agent signed in as the owner reads it too)" || fail "listing: $BODY"
call GET "/api/demipass/security-events?severity=critical" "$A"; ! echo "$BODY" | grep -q "notes.md\|\"chunk\"\|\"count\"" && ok "…nor do the security events" || fail "events leak chunks: $(echo "$BODY" | head -c 300)"
call POST /api/demipass/leak-scan/hits/$HID "$A" '{}'; [ "$CODE" = 403 ] && [ "$(echo "$BODY" | J intent)" = "scan-hits:$HID" ] && ok "where it was found takes the PIN" || fail "hits pin: $CODE $BODY"
call POST /api/identity/gate/verify "$A" '{"gate":"pin","pin":"4321","intent":"scan-hits:'$HID'"}'; call POST /api/demipass/leak-scan/hits/$HID "$A" '{}'
[ "$CODE" = 200 ] && echo "$BODY" | grep -q "notes.md" && ! echo "$BODY" | grep -qF -- "$(cat "$S/seed")" && ok "…with it, the owner sees which secret and where (never the value)" || fail "hits: $CODE $BODY"
! echo "$OUT" | grep -qF -- "$(cat "$S/seed")" && ! echo "$OUT" | grep -qF -- "$(sed 's/"/\\"/' "$S/seed")" && ok "the scanner's output never contains the value" || fail "value printed"
! echo "$OUT" | grep -q tiny && ok "values shorter than 8 characters are not matched (oracle bound)" || fail "short matched"
echo "$OUT" | grep -q "revoked" && [ "$(Q "SELECT revoked_reason FROM leak_scan_tokens WHERE id=$TID")" = hit ] && ok "the first hit revokes the token (stop the line; one positive answer per token)" || fail "revoke on hit: $OUT"
# The rest of that run (Aaron 2026-11-11): for 30 minutes the token keeps scanning; further copies are kept for the
# owner behind the PIN, the token listing an agent session reads never changes (#92 review H1), and the answer is the
# same whatever is sent (a clean file answers "leak" too: no oracle).
H0=$(Q "SELECT COUNT(*) FROM leak_scan_hits WHERE token_id=$TID"); HITS(){ python3 -c 'import json,sys; print(json.dumps(json.load(sys.stdin).get("hits")))'; }
call GET /api/demipass/leak-scan/tokens "$A"; L0=$(echo "$BODY" | HITS | md5sum)
OUT=$(SCAN ci "$S/clean"); RC=$?
[ $RC = 1 ] && echo "$OUT" | grep -q "NOT CHECKED" && [ "$(Q "SELECT COUNT(*) FROM leak_scan_drain_finds WHERE token_id=$TID")" = 0 ] && ok "during the drain a clean file gets the same answer; the scanner says it did not check this tree" || fail "drain clean: rc=$RC $OUT"
mkdir -p "$S/second"; cp "$S/tree/notes.md" "$S/second/other-place.md"
OUT=$(SCAN ci "$S/second"); RC=$?
call GET /api/demipass/leak-scan/tokens "$A"
[ $RC = 1 ] && [ "$(Q "SELECT COUNT(*) FROM leak_scan_hits WHERE token_id=$TID")" = "$H0" ] && [ "$(echo "$BODY" | HITS | md5sum)" = "$L0" ] && [ "$(Q "SELECT COUNT(*) FROM leak_scan_drain_finds WHERE token_id=$TID")" = 1 ] \
  && ok "…a copy found in the drain is kept apart: the hit list and token listing do not change (no guessing oracle)" || fail "drain second: rc=$RC $OUT"
HID1=$(Q "SELECT id FROM leak_scan_hits WHERE token_id=$TID ORDER BY id LIMIT 1")
call POST /api/identity/gate/verify "$A" '{"gate":"pin","pin":"4321","intent":"scan-hits:'$HID1'"}'; call POST /api/demipass/leak-scan/hits/$HID1 "$A" '{}'
[ "$CODE" = 200 ] && echo "$BODY" | grep -q "other-place.md" && echo "$BODY" | grep -q found_later_in_the_run && ok "…and shown with the first hit behind the PIN (\"where?\" names every copy of the run)" || fail "where drained: $CODE $BODY"
# One run of the shipped scanner goes on past its first hit and records a copy in a later batch (#92 review H2).
mint onerun; OR1=$(echo "$BODY" | J id); mkdir -p "$S/onerun"
python3 -c 'import sys; v=open(sys.argv[1]).read().strip(); open(sys.argv[2]+"/a-first.txt","w").write("key: "+v+"\n"+("x"*80+"\n")*21000); open(sys.argv[2]+"/b-later.txt","w").write("again: "+v+"\n")' "$S/seed" "$S/onerun"
OUT=$(SCAN onerun "$S/onerun"); RC=$?
[ $RC = 1 ] && [ "$(Q "SELECT COUNT(*) FROM leak_scan_hits WHERE token_id=$OR1")" = 1 ] && Q "SELECT found FROM leak_scan_drain_finds WHERE token_id=$OR1" | grep -q "b-later.txt" && echo "$OUT" | grep -q "the rest of the run was scanned" \
  && ok "one scanner run continues past its first hit: the later file's copy is recorded for the owner" || fail "one run: rc=$RC $OUT"
# The owner can stop a draining token at once (#92 review M1).
call POST /api/identity/gate/verify "$A" '{"gate":"pin","pin":"4321","intent":"scan-token:'$OR1'"}'; call DELETE /api/demipass/leak-scan/tokens/$OR1 "$A"; A1=$CODE
OUT=$(SCAN onerun "$S/clean"); RC=$?
[ "$A1" = 200 ] && [ $RC = 2 ] && [ "$(Q "SELECT revoked_reason FROM leak_scan_tokens WHERE id=$OR1")" = owner ] && ok "…and the owner can stop a draining token: it scans nothing more" || fail "stop drain: $A1 rc=$RC $OUT"
python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute('UPDATE leak_scan_tokens SET drain_until=? WHERE id=?', ('2000-01-01T00:00:00.000Z', int(sys.argv[2]))); c.commit()" "$DB_PATH" "$TID"
OUT=$(SCAN ci "$S/clean"); RC=$?
[ $RC = 2 ] && echo "$OUT" | grep -q "found a leak and was revoked" && ok "…after the drain window it scans nothing more until a new one is approved" || fail "after drain: rc=$RC $OUT"
mint json; mkdir -p "$S/t2"; cp "$S/tree/sub/transcript.jsonl" "$S/t2/"
OUT=$(SCAN json "$S/t2"); RC=$?
[ $RC = 1 ] && ok "the JSON-escaped form (a transcript line) is found too" || fail "json form: rc=$RC $OUT"
# a binary file holding the value is scanned, not skipped (#45 review M2)
mint bin; mkdir -p "$S/t3"; python3 -c 'import sys; open(sys.argv[2],"wb").write(b"\x00\x01binary\x00 "+open(sys.argv[1]).read().strip().encode()+b" \x00tail")' "$S/seed" "$S/t3/blob.bin"
OUT=$(SCAN bin --strict "$S/t3"); RC=$?; [ $RC = 1 ] && ok "a binary file holding a value is scanned (latin1), not skipped" || fail "binary: rc=$RC $OUT"
mint u16; mkdir -p "$S/t4"; python3 -c 'import sys; open(sys.argv[2],"wb").write(("\ufeffkey="+open(sys.argv[1]).read().strip()+"\n").encode("utf-16-le"))' "$S/seed" "$S/t4/notes-utf16.txt"
OUT=$(SCAN u16 --strict "$S/t4"); RC=$?; [ $RC = 1 ] && ok "a value in a UTF-16 file is found" || fail "utf16: rc=$RC $OUT"
# one scan answer cannot be split into per-chunk bits (#45 review H1): many chunks, one boolean
mint orc; python3 - "$S/seed" "$S/orc.json" <<'PY2'
import json,sys; v=open(sys.argv[1]).read().strip()
chunks=[{"id":"c%d"%i,"text":"guess-%d"%i} for i in range(12)]; chunks[5]["text"]+=" "+v
json.dump({"chunks":chunks},open(sys.argv[2],"w"))
PY2
R=$(curl -s -X POST "$API/api/demipass/leak-scan" -H 'content-type: application/json' -H "Authorization: Scan $(cat "$S/orc.tok")" -d @"$S/orc.json"); rm -f "$S/orc.json"
[ "$(echo "$R" | J leak)" = True ] && [ "$(echo "$R" | J hits)" = None ] && ! echo "$R" | grep -q '"c5"' && ok "12 chunks, one hidden value: the scanner learns only 'leak' — no chunk, no count, no name" || fail "oracle: $R"
# a token's daily scan count is capped
mint cap; X(){ python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute(sys.argv[2]); c.commit()" "$DB_PATH" "$1"; }
X "UPDATE leak_scan_tokens SET day=date('now'), requests_today=150 WHERE label='cap'"
OUT=$(SCAN cap "$S/clean"); RC=$?; [ $RC = 2 ] && echo "$OUT" | grep -q "150 scans" && ok "a token makes at most 150 scans a day (one-by-one guessing is slow)" || fail "cap: rc=$RC $OUT"
# incremental: only what was appended, offsets kept
mint inc; mkdir -p "$S/logs"; echo '{"line":"nothing"}' > "$S/logs/t.jsonl"
OUT=$(DEMIPASS_URL=$API DEMIPASS_SCAN_TOKEN_FILE="$S/inc.tok" node bin/leak-scan.js --incremental "$S/inc.state" "$S/logs" 2>&1); RC=$?
[ $RC = 0 ] && [ -s "$S/inc.state" ] && ok "incremental: a clean run saves per-file offsets" || fail "inc 1: rc=$RC $OUT"
OUT=$(DEMIPASS_URL=$API DEMIPASS_SCAN_TOKEN_FILE="$S/inc.tok" node bin/leak-scan.js --incremental "$S/inc.state" "$S/logs" 2>&1); echo "$OUT" | grep -q "0 files, 0 bytes" && ok "…an unchanged file is not sent again" || fail "inc 2: $OUT"
python3 -c 'import json,sys; open(sys.argv[2],"a").write(json.dumps({"tool_result":open(sys.argv[1]).read().strip()})+"\n")' "$S/seed" "$S/logs/t.jsonl"
OUT=$(DEMIPASS_URL=$API DEMIPASS_SCAN_TOKEN_FILE="$S/inc.tok" node bin/leak-scan.js --incremental "$S/inc.state" "$S/logs" 2>&1); RC=$?
[ $RC = 1 ] && ok "…a value appended later is found" || fail "inc 3: rc=$RC $OUT"
[ "$(Q "SELECT COUNT(*) FROM demipass_security_events WHERE event_type='leak_scan_hit' AND severity='critical'")" -ge 2 ] && ok "every hit is a critical security event" || fail "hit events"
! grep -qF -- "$(cat "$S/seed")" "$S/server.log" && [ "$(Q "SELECT COUNT(*) FROM blindkey_events WHERE detail LIKE '%seed-%'")" = 0 ] && ok "no value in the server log or the events" || fail "value logged"
# another owner's token finds nothing of A's
call POST /api/identity/pin "$X" '{"pin":"9876","password":"hunter22"}'; call POST /api/identity/gate/verify "$X" '{"gate":"pin","pin":"9876","intent":"scan-token:0"}'
call POST /api/demipass/leak-scan/tokens "$X" '{"label":"x"}'; XT=$(echo "$BODY" | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')
H2=$(curl -s -X POST "$API/api/demipass/leak-scan" -H 'content-type: application/json' -H "Authorization: Scan $XT" -d @"$S/body.json" | J leak); rm -f "$S/body.json"
[ "$H2" = False ] && ok "another owner scanning the same text matches only their own values (none)" || fail "cross-owner: $H2"
mint rv; RV=$(echo "$BODY" | J id); call POST /api/identity/gate/verify "$A" '{"gate":"pin","pin":"4321","intent":"scan-token:'$RV'"}'; call DELETE /api/demipass/leak-scan/tokens/$RV "$A"
OUT=$(SCAN rv "$S/clean"); RC=$?; [ $RC = 2 ] && echo "$OUT" | grep -q "401" && ok "a revoked scan token is refused (exit 2)" || fail "revoked: rc=$RC $OUT"

# token requests: asked by whoever acts for A, approved in A's app, claimed once by the asker
AG=$(login owner-a)   # an agent's session of A (it holds no PIN proof, and never types one)
call POST /api/demipass/leak-scan/token-requests "$AG" '{"labels":["ci-dustforge","ci-demipass"]}'; RQ=$(echo "$BODY" | J request_id); CS=$(echo "$BODY" | J claim_secret)
[ "$CODE" = 202 ] && [ -n "$CS" ] && ok "an agent session of A asks for two scan tokens (202, a claim secret only it holds)" || fail "request: $CODE $BODY"
call POST /api/demipass/leak-scan/token-requests/$RQ/claim "" '{"claim_secret":"'$CS'"}'; [ "$CODE" = 202 ] && ok "claiming before the owner decides → 202 waiting" || fail "claim early: $CODE"
call GET /api/demipass/leak-scan/token-requests "$A"; [ "$(echo "$BODY" | J requests.0.id)" = "$RQ" ] && ok "A's app lists the request" || fail "list: $BODY"
call POST /api/demipass/leak-scan/token-requests/$RQ/approve "$AG"; [ "$CODE" = 403 ] && ok "the asking session cannot approve its own request without the PIN" || fail "self approve: $CODE"
call POST /api/demipass/leak-scan/token-requests/$RQ/approve "$A"; [ "$CODE" = 403 ] && [ "$(echo "$BODY" | J intent)" = "scan-approve:$RQ" ] && ok "approving takes the PIN (scan-approve:<id>)" || fail "approve pin: $CODE $BODY"
call POST /api/identity/gate/verify "$A" '{"gate":"pin","pin":"4321","intent":"scan-approve:'$RQ'"}'; call POST /api/demipass/leak-scan/token-requests/$RQ/approve "$A"
[ "$CODE" = 200 ] && ok "A approves in the app" || fail "approve: $CODE $BODY"
call POST /api/demipass/leak-scan/token-requests/$RQ/claim "" '{"claim_secret":"wrong-wrong-wrong"}'; [ "$CODE" = 404 ] && ok "a wrong claim secret gets nothing" || fail "wrong claim: $CODE"
call POST /api/demipass/leak-scan/token-requests/$RQ/claim "" '{"claim_secret":"'$CS'"}'
[ "$CODE" = 200 ] && [ "$(echo "$BODY" | J tokens.1.label)" = ci-demipass ] && [ "$(Q "SELECT COALESCE(sealed,'') FROM leak_scan_token_requests WHERE id=$RQ")" = "" ] && ok "the asker claims both tokens once; nothing sealed is kept" || fail "claim: $CODE"
call POST /api/demipass/leak-scan/token-requests/$RQ/claim "" '{"claim_secret":"'$CS'"}'; [ "$CODE" = 410 ] && ok "…a second claim gets nothing (410)" || fail "reclaim: $CODE"
call GET "/api/demipass/leak-scan/token-requests?all=1" "$A"; echo "$BODY" | python3 -c 'import json,sys; r=[x for x in json.load(sys.stdin)["requests"] if x["id"]==int(sys.argv[1])]; sys.exit(0 if r and r[0]["status"]=="claimed" else 1)' "$RQ" && ok "?all=1 still lists a claimed request (the app finds it by number)" || fail "all=1: $BODY"
call GET /api/demipass/leak-scan/token-requests "$A"; echo "$BODY" | grep -q "\"id\":$RQ," && fail "plain list shows a claimed request" || ok "…the plain list stays pending-only"
# A request waits a day for the owner (not 15 minutes), and the scanner that asked picks it up on a later run:
# --request --no-wait leaves a 0600 pending file and exits 3; --claim writes the token once approved (Aaron 2026-11-11).
mkdir -p "$S/pend"; OUT=$(DEMIPASS_URL=$API DEMIPASS_TOKEN="$AG" node bin/leak-scan.js --request --no-wait "$S/pend" pane-later 2>&1); RC=$?
PF=$(ls "$S/pend"/.pending-*.json 2>/dev/null | head -1); RQP=$(basename "$PF" .json | sed 's/.pending-//')
[ $RC = 3 ] && [ -n "$PF" ] && [ "$(stat -c %a "$PF")" = 600 ] && [ ! -e "$S/pend/pane-later.token" ] && ok "--request --no-wait: a 0600 pending file, exit 3 (waiting for the owner)" || fail "no-wait: rc=$RC $OUT"
python3 -c "import sqlite3,sys,datetime; c=sqlite3.connect(sys.argv[1]); e=c.execute('SELECT expires_at FROM leak_scan_token_requests WHERE id=?', (int(sys.argv[2]),)).fetchone()[0]; d=datetime.datetime.fromisoformat(e.replace('Z','+00:00'))-datetime.datetime.now(datetime.timezone.utc); sys.exit(0 if d.total_seconds()>23*3600 else 1)" "$DB_PATH" "$RQP" && ok "…the request waits a day for the owner" || fail "request ttl"
OUT=$(DEMIPASS_URL=$API node bin/leak-scan.js --claim "$S/pend" 2>&1); [ $? = 3 ] && ok "--claim before the owner decides: still waiting (exit 3)" || fail "claim early: $OUT"
call POST /api/identity/gate/verify "$A" '{"gate":"pin","pin":"4321","intent":"scan-approve:'$RQP'"}'; call POST /api/demipass/leak-scan/token-requests/$RQP/approve "$A"
OUT=$(DEMIPASS_URL=$API node bin/leak-scan.js --claim "$S/pend" 2>&1); RC=$?
[ $RC = 0 ] && [ -s "$S/pend/pane-later.token" ] && [ "$(stat -c %a "$S/pend/pane-later.token")" = 600 ] && [ -z "$(ls "$S/pend"/.pending-*.json 2>/dev/null)" ] \
  && ok "…after the owner approves, the next --claim writes the token (0600) and clears the pending file" || fail "claim: rc=$RC $OUT"
call POST /api/demipass/leak-scan/token-requests "$AG" '{"labels":["nope"]}'; RQ2=$(echo "$BODY" | J request_id); CS2=$(echo "$BODY" | J claim_secret)
call POST /api/demipass/leak-scan/token-requests/$RQ2/deny "$A"; call POST /api/demipass/leak-scan/token-requests/$RQ2/claim "" '{"claim_secret":"'$CS2'"}'
[ "$CODE" = 410 ] && ok "a denied request yields nothing" || fail "deny: $CODE"
# the client's --request mode: writes 0600 files, prints no token
( DEMIPASS_URL=$API DEMIPASS_TOKEN=$AG node bin/leak-scan.js --request "$S/tokdir" pane-start > "$S/req.out" 2>&1; echo $? > "$S/req.rc" ) &
for i in $(seq 1 20); do RQ3=$(Q "SELECT id FROM leak_scan_token_requests WHERE labels='[\"pane-start\"]' AND status='pending'"); [ -n "$RQ3" ] && break; sleep 0.5; done
call POST /api/identity/gate/verify "$A" '{"gate":"pin","pin":"4321","intent":"scan-approve:'$RQ3'"}'; call POST /api/demipass/leak-scan/token-requests/$RQ3/approve "$A"
for i in $(seq 1 30); do [ -f "$S/req.rc" ] && break; sleep 0.5; done
[ "$(cat "$S/req.rc" 2>/dev/null)" = 0 ] && [ "$(stat -c %a "$S/tokdir/pane-start.token")" = 600 ] && ! grep -q dpscan_ "$S/req.out" \
  && ok "leak-scan --request: approved in the app, token written 0600, never printed" || fail "--request: rc=$(cat "$S/req.rc" 2>/dev/null) $(cat "$S/req.out")"
OUT=$(DEMIPASS_URL=$API DEMIPASS_SCAN_TOKEN_FILE="$S/tokdir/pane-start.token" node bin/leak-scan.js "$S/clean" 2>&1); [ $? = 0 ] && ok "…and the claimed token scans" || fail "claimed scan: $OUT"

# ── the deploy gate (ops/deploy-identity/dustforge-deploy) against a throwaway origin and live checkout ──
G=$S/gate; mkdir -p "$G/stub"; git init -q --bare "$G/origin.git"
git clone -q "$G/origin.git" "$G/work" 2>/dev/null; git -C "$G/work" config user.email t@t; git -C "$G/work" config user.name t
echo '{"name":"x"}' > "$G/work/package.json"; echo hello > "$G/work/a.txt"; git -C "$G/work" add -A; git -C "$G/work" commit -qm one; git -C "$G/work" push -q origin HEAD:main 2>/dev/null
git clone -q -b main "$G/origin.git" "$G/live" 2>/dev/null; mkdir -p "$G/live/data"; sqlite3 "$G/live/data/dustforge.db" 'create table t(x)'
printf '#!/bin/sh\nexit 0\n' > "$G/stub/systemd-run"; chmod +x "$G/stub/systemd-run"
sed -e "s#^export PATH=.*#export PATH=$G/stub:\$PATH LC_ALL=C#" -e "s#^REPO=.*#REPO=$G/live#" -e "s#^BK=.*#BK=$G/bk#" -e "s#^STATE=.*#STATE=$G/state#" \
    -e "s#^SCANNER=.*#SCANNER=$W/bin/leak-scan.js#" -e "s#^SCAN_TOKEN=.*#SCAN_TOKEN=$G/scan.token#" ops/deploy-identity/dustforge-deploy > "$G/deploy"; chmod +x "$G/deploy"
DEPLOY(){ DEMIPASS_URL=$API bash "$G/deploy" "$1" 2>&1; }
tip(){ git -C "$G/work" rev-parse HEAD; }
python3 -c 'import sys; open(sys.argv[2],"w").write("config:\n  key: "+open(sys.argv[1]).read().strip()+"\n")' "$S/seed" "$G/work/leak.yml"
git -C "$G/work" add -A; git -C "$G/work" commit -qm leak; git -C "$G/work" push -q origin HEAD:main 2>/dev/null
OUT=$(DEPLOY "$(tip)"); RC=$?
[ $RC = 3 ] && echo "$OUT" | grep -q "no scan token" && [ "$(git -C "$G/live" rev-parse HEAD)" != "$(tip)" ] && ok "deploy gate: no scan token → refused (fail closed)" || fail "gate no token: rc=$RC $OUT"
mint gate; cp "$S/gate.tok" "$G/scan.token"; chmod 600 "$G/scan.token"
OUT=$(DEPLOY "$(tip)"); RC=$?
[ $RC = 3 ] && echo "$OUT" | grep -q "a vault value is in this commit" && [ "$(git -C "$G/live" rev-parse HEAD)" != "$(tip)" ] && ! echo "$OUT" | grep -qF -- "$(cat "$S/seed")" \
  && ok "deploy gate: a commit carrying a vault value → refused, never prints the value, nothing merged" || fail "gate leak: rc=$RC $OUT"
git -C "$G/work" rm -q leak.yml; echo "hello again" > "$G/work/a.txt"; git -C "$G/work" commit -qam fix; git -C "$G/work" push -q origin HEAD:main 2>/dev/null
OUT=$(DEPLOY "$(tip)"); RC=$?
[ $RC = 3 ] && echo "$OUT" | grep -q "scan could not run\|revoked\|already found a leak\|NOT CHECKED" && ok "deploy gate: the token that found the leak is revoked — nothing deploys until a new one is placed" || fail "gate after hit: rc=$RC $OUT"
# a type change (a symlink replaced by a file holding the value) is scanned too (#45 review M1)
mint gate3; cp "$S/gate3.tok" "$G/scan.token"
ln -s a.txt "$G/work/cfg.env"; git -C "$G/work" add -A; git -C "$G/work" commit -qm link; git -C "$G/work" push -q origin HEAD:main 2>/dev/null
DEPLOY "$(tip)" >/dev/null 2>&1   # the link commit deploys (nothing secret in it)
rm "$G/work/cfg.env"; python3 -c 'import sys; open(sys.argv[2],"w").write("API_KEY="+open(sys.argv[1]).read().strip()+"\n")' "$S/seed" "$G/work/cfg.env"
git -C "$G/work" add -A; git -C "$G/work" commit -qm typechange; git -C "$G/work" push -q origin HEAD:main 2>/dev/null
OUT=$(DEPLOY "$(tip)"); RC=$?; [ $RC = 3 ] && echo "$OUT" | grep -q "a vault value is in this commit" && ok "deploy gate: a symlink turned into a file holding a value (type change) is caught" || fail "gate typechange: rc=$RC $OUT"
git -C "$G/work" rm -q cfg.env; echo "third" > "$G/work/a.txt"; git -C "$G/work" commit -qam fix2; git -C "$G/work" push -q origin HEAD:main 2>/dev/null
mint gate2; cp "$S/gate2.tok" "$G/scan.token"
OUT=$(DEPLOY "$(tip)"); RC=$?
[ $RC = 0 ] && [ "$(git -C "$G/live" rev-parse HEAD)" = "$(tip)" ] && ok "deploy gate: the cleaned commit with a new token → deployed (only the changed files are scanned)" || fail "gate clean: rc=$RC $OUT"

# owner-only management; an approved request nobody claims revokes its tokens (#45 review L1, L3)
LIVE=$(Q "SELECT id FROM leak_scan_tokens WHERE revoked_at IS NULL ORDER BY id LIMIT 1")
call DELETE /api/demipass/leak-scan/tokens/$LIVE "$AG"; [ "$CODE" = 403 ] && [ "$(echo "$BODY" | J intent)" = "scan-token:$LIVE" ] && ok "revoking a scan token takes the PIN (an agent signed in as the owner cannot stop the deploy gate)" || fail "agent revoke: $CODE $BODY"
call POST /api/demipass/leak-scan/token-requests "$AG" '{"labels":["lapse"]}'; RQL=$(echo "$BODY" | J request_id)
call POST /api/identity/gate/verify "$A" '{"gate":"pin","pin":"4321","intent":"scan-approve:'$RQL'"}'; call POST /api/demipass/leak-scan/token-requests/$RQL/approve "$A"
python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute(\"UPDATE leak_scan_token_requests SET expires_at='2000-01-01T00:00:00.000Z' WHERE id=?\", (int(sys.argv[2]),)); c.commit()" "$DB_PATH" "$RQL"
call GET /api/demipass/leak-scan/token-requests "$A"
[ "$(Q "SELECT revoked_reason FROM leak_scan_tokens WHERE request_id=$RQL")" = unclaimed ] && [ "$(Q "SELECT COALESCE(sealed,'') FROM leak_scan_token_requests WHERE id=$RQL")" = "" ] && ok "an approved request nobody claimed in time: its token is revoked and nothing sealed is kept" || fail "unclaimed: $(Q "SELECT revoked_reason FROM leak_scan_tokens WHERE request_id=$RQL")"

echo; [ $fails = 0 ] && echo "ALL OK" || echo "$fails FAILED"; exit $fails
