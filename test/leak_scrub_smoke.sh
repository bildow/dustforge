#!/bin/bash
# Scrub smoke ("contained": a leaked value overwritten wherever the scrubber finds it, not rotated — Aaron 2026-11-11).
# Legacy fixture first: the database is made by main's server (the leak tables and vault without the new columns, a scan
# token minted there); this branch's server then opens it. A scrub token is asked for one entry and approved with the
# PIN; it finds only that entry (raw, JSON-escaped once and twice, \u-escaped), across window borders; the client
# overwrites copies in place (same size, same inode, JSONL still parses), leaves binary copies, prints no value. Scan and
# scrub tokens are not interchangeable; a finished, expired or other-owner scrub is refused; contained shows in the
# listing and a later scan hit clears it.
set -u
W=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
S=$(mktemp -d /tmp/dustforge-scrub-smoke.XXXXXX)
PORT=${PORT:-3793}; API=http://127.0.0.1:$PORT
NM=/home/flimflam/project/dustforge/node_modules; [ -d "$W/node_modules" ] && NM=$W/node_modules
export NODE_PATH=$NM
export IDENTITY_MASTER_KEY=$(python3 -c 'import secrets;print(secrets.token_hex(32))') DB_PATH=$S/dustforge.db PORT \
  STALWART_HOST=127.0.0.1 STALWART_PORT=1 SMTP_RELAY_HOST= SMTP_HOST=127.0.0.1 SMTP_PORT=9
SRV=; trap 'kill $SRV 2>/dev/null; [ -n "${KEEP:-}" ] || rm -rf "$S"' EXIT
start(){ ( cd "$1" && exec node server.js >"$S/server-$2.log" 2>&1 ) & SRV=$!
  for i in $(seq 1 60); do curl -s -o /dev/null "$API/" && break; sleep 0.5; done
  kill -0 $SRV 2>/dev/null || { echo "server ($2) died:"; tail -5 "$S/server-$2.log"; exit 1; }; }
stop(){ kill $SRV 2>/dev/null; wait $SRV 2>/dev/null; SRV=; }
fails=0; ok(){ echo "ok   $*"; }; fail(){ echo "FAIL $*"; fails=$((fails+1)); }
J(){ python3 -c 'import json,sys; d=json.load(sys.stdin); v=d
for k in sys.argv[1].split("."):
    v = v[int(k)] if isinstance(v, list) else (v or {}).get(k)
print(v)' "$1"; }
Q(){ python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); r=c.execute(sys.argv[2]).fetchone(); print(r[0] if r and r[0] is not None else '')" "$DB_PATH" "$1"; }
call(){ local m=$1 p=$2 t=$3 b=${4:-}
  BODY=$(curl -s -o - -w '\n%{http_code}' -X "$m" "$API$p" -H 'Content-Type: application/json' ${t:+-H "Authorization: Bearer $t"} ${b:+-d "$b"})
  CODE=${BODY##*$'\n'}; BODY=${BODY%$'\n'*}; }
login(){ call POST /api/identity/auth-fingerprint "" '{"username":"'$1'","password":"hunter22","scope":"transact","expires_in":"1h"}'; echo "$BODY" | J token; }

# ── legacy: main's server makes the database ──
mkdir -p "$S/old"; git -C "$W" archive origin/main | tar -x -C "$S/old"
start "$S/old" old
H=$(printf '%s' hunter22 | sha256sum | cut -d' ' -f1)
( cd "$W" && node -e '
const identity = require("./identity"); const Database = require("better-sqlite3"); const db = new Database(process.env.DB_PATH);
for (const c of ["idempotency_key TEXT", "provenance TEXT DEFAULT '"'"'organic'"'"'"]) { try { db.exec("ALTER TABLE identity_transactions ADD COLUMN " + c); } catch (_) {} }
for (const u of ["owner-a", "other-x"]) { const id = identity.createIdentity(); const enc = id.encrypted_private_key || id.encryptedPrivateKey;
  db.prepare("INSERT INTO identity_wallets (did, username, email, encrypted_private_key, balance_cents, password_hash) VALUES (?, ?, ?, ?, 100000, ?)").run(id.did, u, u + "@dustforge.com", enc, process.argv[1]);
  db.prepare("INSERT INTO identity_transactions (did, amount_cents, type, description, balance_after) VALUES (?, 100000, ?, ?, 100000)").run(id.did, "topup", "smoke"); }' "$H" )
A=$(login owner-a); X=$(login other-x)
call POST /api/identity/pin "$A" '{"pin":"4321","password":"hunter22"}'
umask 077
# the leaked value: a quote, a backslash and a non-ASCII letter, so every escaped form differs; never echoed
python3 -c 'import secrets;print("lk-" + secrets.token_urlsafe(10) + "\"\\é" + secrets.token_urlsafe(4))' > "$S/seed"
python3 -c 'import secrets;print("keep-" + secrets.token_urlsafe(14))' > "$S/other"
python3 -c 'import secrets;print("xx-" + secrets.token_urlsafe(14))' > "$S/xval"
store(){ python3 -c 'import json,sys; print(json.dumps({"name":sys.argv[2],"value":open(sys.argv[1]).read().rstrip("\n"),"secret_type":"password"}))' "$1" "$2" > "$S/st.json"
  curl -s -o /dev/null -X POST "$API/api/demipass/store" -H 'content-type: application/json' -H "Authorization: Bearer $3" -d @"$S/st.json"; rm -f "$S/st.json"; }
store "$S/seed" leaky "$A"; store "$S/other" kept "$A"; store "$S/xval" xs "$X"
REF=$(Q "SELECT ref_code FROM blindkey_secrets WHERE name='leaky'"); XREF=$(Q "SELECT ref_code FROM blindkey_secrets WHERE name='xs'")
call POST /api/identity/gate/verify "$A" '{"gate":"pin","pin":"4321","intent":"scan-token:0"}'; call POST /api/demipass/leak-scan/tokens "$A" '{"label":"legacy"}'
echo "$BODY" | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])' > "$S/legacy.tok"
stop
[ -n "$REF" ] && [ -s "$S/legacy.tok" ] && [ -z "$(Q "SELECT name FROM pragma_table_info('leak_scan_tokens') WHERE name='scrub_secret_id'")" ] && ok "legacy: main's server made the vault, the leak tables (no scrub columns) and a scan token" || fail "legacy setup"

# ── this branch on the same database ──
start "$W" new
A=$(login owner-a); AG=$(login owner-a); X=$(login other-x)
[ "$(Q "SELECT COUNT(*) FROM pragma_table_info('leak_scan_tokens') WHERE name IN ('scrub_secret_id','expires_at')")" = 2 ] \
  && [ "$(Q "SELECT COUNT(*) FROM pragma_table_info('leak_scan_token_requests') WHERE name='scrub_secret_id'")" = 1 ] \
  && [ "$(Q "SELECT COUNT(*) FROM pragma_table_info('blindkey_secrets') WHERE name IN ('leak_contained_at','leak_contained_note')")" = 2 ] && ok "the new columns are added to the legacy tables" || fail "migration"
mkdir -p "$S/clean"; echo "nothing here" > "$S/clean/a.md"
OUT=$(DEMIPASS_URL=$API DEMIPASS_SCAN_TOKEN_FILE="$S/legacy.tok" node "$W/bin/leak-scan.js" "$S/clean" 2>&1); [ $? = 0 ] && ok "the legacy scan token still scans" || fail "legacy token: $OUT"

# ── asking ──
call POST /api/demipass/leak-scan/token-requests "$AG" '{"scrub_ref":"'$XREF'"}'; [ "$CODE" = 404 ] && ok "a scrub of another owner's entry → 404" || fail "other ref: $CODE"
call POST /api/demipass/leak-scan/token-requests "$AG" '{"scrub_ref":"'$REF'","labels":["x"]}'; [ "$CODE" = 400 ] && ok "scrub_ref with labels → 400 (the server names the token)" || fail "labels+ref: $CODE"
mkdir -p "$S/tok"
OUT=$(DEMIPASS_URL=$API DEMIPASS_TOKEN="$AG" node "$W/bin/leak-scan.js" --scrub-request --no-wait "$S/tok" "$REF" 2>&1); RC=$?
RQ=$(basename "$(ls "$S/tok"/.pending-*.json)" .json | sed 's/.pending-//')
[ $RC = 3 ] && [ -n "$RQ" ] && ok "--scrub-request --no-wait: asked, waiting for the owner (exit 3)" || fail "scrub request: rc=$RC $OUT"
call GET /api/demipass/leak-scan/token-requests "$A"
[ "$(echo "$BODY" | J requests.0.scrub.name)" = leaky ] && [ "$(echo "$BODY" | J requests.0.labels.0)" = "scrub-$REF" ] && ok "the owner's app sees which entry the scrub is for" || fail "listing: $BODY"
call POST /api/identity/gate/verify "$A" '{"gate":"pin","pin":"4321","intent":"scan-approve:'$RQ'"}'; call POST /api/demipass/leak-scan/token-requests/$RQ/approve "$A"
[ "$CODE" = 200 ] && ok "the owner approves with the PIN" || fail "approve: $CODE $BODY"
OUT=$(DEMIPASS_URL=$API node "$W/bin/leak-scan.js" --claim "$S/tok" 2>&1); STOK="$S/tok/scrub-$REF.token"
[ -s "$STOK" ] && [ "$(stat -c %a "$STOK")" = 600 ] && ok "--claim writes the scrub token (0600)" || fail "claim: $OUT"
TID=$(Q "SELECT id FROM leak_scan_tokens WHERE label='scrub-$REF'")
[ -n "$(Q "SELECT expires_at FROM leak_scan_tokens WHERE id=$TID")" ] && ok "a scrub token expires" || fail "no expiry"

# ── not interchangeable ──
python3 -c 'import json; print(json.dumps({"chunks":[{"id":"0","text":"hello"}]}))' > "$S/b.json"
C=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$API/api/demipass/leak-scan" -H 'content-type: application/json' -H "Authorization: Scan $(cat "$STOK")" -d @"$S/b.json"); [ "$C" = 403 ] && ok "a scrub token cannot scan (no oracle over the other entries)" || fail "scrub as scan: $C"
C=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$API/api/demipass/leak-scan/scrub" -H 'content-type: application/json' -H "Authorization: Scan $(cat "$S/legacy.tok")" -d @"$S/b.json"); [ "$C" = 403 ] && ok "a scan token cannot scrub" || fail "scan as scrub: $C"
C=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$API/api/demipass/leak-scan/scrub" -H 'content-type: application/json' -H "Authorization: Bearer $A" -d @"$S/b.json"); [ "$C" = 403 ] && ok "a session token cannot scrub" || fail "bearer scrub: $C"

# ── the tree ──
T=$S/tree; mkdir -p "$T/sub" "$T/node_modules"
python3 - "$S" <<'PY'
import json,sys,os; S=sys.argv[1]; v=open(S+'/seed').read().rstrip('\n'); k=open(S+'/other').read().rstrip('\n'); x=open(S+'/xval').read().rstrip('\n')
T=S+'/tree'
open(T+'/notes.md','w').write('line one\nthe password is '+v+' oops, again: '+v+'\nkept '+k+' and '+x+'\n')
inner=json.dumps({"command":"login --pw "+v})
with open(T+'/sub/t.jsonl','w') as f:
    f.write(json.dumps({"type":"tool_result","content":"out: "+v})+'\n')                      # once escaped
    f.write(json.dumps({"type":"tool_use","input":inner})+'\n')                               # twice escaped
    f.write(json.dumps({"type":"py","content":"x "+v}, ensure_ascii=True)+'\n')               # \u escaped
    f.write(json.dumps({"type":"keep","content":k})+'\n')
# a copy straddling the 256 KiB window border, plus multi-byte text before it
pad='é'*((256*1024-10)//2)
open(T+'/big.log','w').write(pad+'xx'+v+'yy\n'+'tail\n')
open(T+'/blob.bin','wb').write(b'\x00\x01header'+v.encode()+b'\x00tail')
open(T+'/node_modules/skip.txt','w').write(v)
os.symlink(T+'/notes.md', T+'/link.md')
PY
before(){ for f in notes.md sub/t.jsonl big.log blob.bin; do [ -e "$T/$f" ] && stat -c "%n %s %i" "$T/$f"; done; }
B0=$(before); SUM0=$(cat "$T/notes.md" "$T/sub/t.jsonl" "$T/big.log" | sha256sum)
SCRUB(){ DEMIPASS_URL=$API DEMIPASS_SCAN_TOKEN_FILE="$1" node "$W/bin/leak-scan.js" --scrub "${@:2}" 2>&1; }
OUT=$(SCRUB "$STOK" --dry-run "$T"); RC=$?
[ $RC = 1 ] && [ "$(cat "$T/notes.md" "$T/sub/t.jsonl" "$T/big.log" | sha256sum)" = "$SUM0" ] && echo "$OUT" | grep -q "notes.md: 2 copies (dry run)" && echo "$OUT" | grep -q "t.jsonl: 3 copies" && echo "$OUT" | grep -q "big.log: 1 copy" \
  && ok "--dry-run finds raw, once-escaped, twice-escaped, \\u-escaped and border-straddling copies and writes nothing" || fail "dry run: rc=$RC $OUT"
echo "$OUT" | grep -q "blob.bin: 1 copy in a binary file" && ok "…a binary copy is reported, not written" || fail "binary: $OUT"
echo "$OUT" | grep -q "skip.txt\|link.md" && fail "node_modules or a symlink was read" || ok "…node_modules and symlinks are not entered"
# the real run, without the binary file (so the run can finish contained)
mv "$T/blob.bin" "$S/blob.bin"
OUT=$(SCRUB "$STOK" "$T"); RC=$?
python3 - "$S" <<'PY' && ok "the copies are gone; every JSONL line still parses; the other entry's and other owner's values are untouched" || fail "after scrub"
import json,sys; S=sys.argv[1]; v=open(S+'/seed').read().rstrip('\n'); k=open(S+'/other').read().rstrip('\n'); x=open(S+'/xval').read().rstrip('\n'); T=S+'/tree'
esc=lambda t: json.dumps(t)[1:-1]
forms=[v, esc(v), esc(esc(v)), json.dumps(v, ensure_ascii=True)[1:-1]]
allt=''.join(open(T+f, encoding='utf-8').read() for f in ['/notes.md','/sub/t.jsonl','/big.log'])
assert not any(f in allt for f in forms), 'a copy is left'
for l in open(T+'/sub/t.jsonl'): json.loads(l)
assert json.loads(json.loads(open(T+'/sub/t.jsonl').readlines()[1])['input'])['command'].startswith('login --pw ***')
assert k in allt and x in allt
PY
[ "$(before | grep -v blob.bin)" = "$(echo "$B0" | grep -v blob.bin)" ] && ok "every file keeps its size and inode (an appending process is not cut off)" || fail "size/inode changed"
! echo "$OUT" | grep -qF -- "$(head -c 12 "$S/seed")" && ok "the scrubber prints no part of the value" || fail "value printed"
[ $RC = 0 ] && echo "$OUT" | grep -q "is contained" && [ -n "$(Q "SELECT leak_contained_at FROM blindkey_secrets WHERE name='leaky'")" ] && ok "the run finished with nothing left: the entry is contained" || fail "contained: rc=$RC $OUT"
call GET /api/blindkey/list "$A"; echo "$BODY" | python3 -c 'import json,sys; d=json.load(sys.stdin); s=[x for x in d["secrets"] if x["name"]=="leaky"][0]; sys.exit(0 if s.get("leak_contained_at") else 1)' && ok "…and the vault listing shows when" || fail "listing: $(echo "$BODY" | head -c 200)"
[ "$(Q "SELECT revoked_reason FROM leak_scan_tokens WHERE id=$TID")" = scrubbed ] && ok "the finished scrub token is spent" || fail "not spent"
OUT=$(SCRUB "$STOK" "$T"); [ $? != 0 ] && echo "$OUT" | grep -q 401 && ok "…and refused after (401)" || fail "reuse: $OUT"

# ── a later scan that finds the value clears contained ──
call POST /api/identity/gate/verify "$A" '{"gate":"pin","pin":"4321","intent":"scan-token:0"}'; call POST /api/demipass/leak-scan/tokens "$A" '{"label":"after"}'
echo "$BODY" | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])' > "$S/after.tok"
mkdir -p "$S/again"; cp "$S/seed" "$S/again/found.txt"
DEMIPASS_URL=$API DEMIPASS_SCAN_TOKEN_FILE="$S/after.tok" node "$W/bin/leak-scan.js" "$S/again" >/dev/null 2>&1
[ -z "$(Q "SELECT leak_contained_at FROM blindkey_secrets WHERE name='leaky'")" ] && ok "a later scan hit clears contained" || fail "still contained after a hit"

# ── a run that leaves copies is not contained; an expired token is refused ──
call POST /api/demipass/leak-scan/token-requests "$AG" '{"scrub_ref":"'$REF'"}'; RQ2=$(echo "$BODY" | J request_id); CS2=$(echo "$BODY" | J claim_secret)
call POST /api/identity/gate/verify "$A" '{"gate":"pin","pin":"4321","intent":"scan-approve:'$RQ2'"}'; call POST /api/demipass/leak-scan/token-requests/$RQ2/approve "$A"
call POST /api/demipass/leak-scan/token-requests/$RQ2/claim "" '{"claim_secret":"'$CS2'"}'; echo "$BODY" | python3 -c 'import json,sys; print(json.load(sys.stdin)["tokens"][0]["token"])' > "$S/s2.tok"
mkdir -p "$S/bin"; mv "$S/blob.bin" "$S/bin/"
OUT=$(SCRUB "$S/s2.tok" "$S/bin"); RC=$?
[ $RC = 1 ] && echo "$OUT" | grep -q "not marked contained" && [ -z "$(Q "SELECT leak_contained_at FROM blindkey_secrets WHERE name='leaky'")" ] && ok "a run that leaves a copy (binary) is not contained" || fail "left copies: rc=$RC $OUT"
call POST /api/demipass/leak-scan/token-requests "$AG" '{"scrub_ref":"'$REF'"}'; RQ3=$(echo "$BODY" | J request_id); CS3=$(echo "$BODY" | J claim_secret)
call POST /api/identity/gate/verify "$A" '{"gate":"pin","pin":"4321","intent":"scan-approve:'$RQ3'"}'; call POST /api/demipass/leak-scan/token-requests/$RQ3/approve "$A"
call POST /api/demipass/leak-scan/token-requests/$RQ3/claim "" '{"claim_secret":"'$CS3'"}'; echo "$BODY" | python3 -c 'import json,sys; print(json.load(sys.stdin)["tokens"][0]["token"])' > "$S/s3.tok"
python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute(\"UPDATE leak_scan_tokens SET expires_at='2000-01-01T00:00:00.000Z' WHERE label=? AND revoked_at IS NULL\", ('scrub-'+sys.argv[2],)); c.commit()" "$DB_PATH" "$REF"
C=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$API/api/demipass/leak-scan/scrub" -H 'content-type: application/json' -H "Authorization: Scan $(cat "$S/s3.tok")" -d @"$S/b.json"); [ "$C" = 401 ] && ok "an expired scrub token is refused" || fail "expired: $C"
grep -qF -- "$(head -c 12 "$S/seed")" "$S"/server-new.log && fail "the value reached the server log" || ok "the value never reaches the server log"

echo; [ $fails = 0 ] && echo "ALL OK" || echo "$fails FAILED"; exit $fails
