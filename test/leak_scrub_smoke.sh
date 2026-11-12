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
REF=$(Q "SELECT ref_code FROM blindkey_secrets WHERE name='leaky'"); echo "$REF" > "$S/ref"; XREF=$(Q "SELECT ref_code FROM blindkey_secrets WHERE name='xs'")
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

# helpers: a scan hit on a file (a fresh PIN-minted scan token), and a whole scrub-token round (ask, approve, claim)
scanhit(){ call POST /api/identity/gate/verify "$A" '{"gate":"pin","pin":"4321","intent":"scan-token:0"}'; call POST /api/demipass/leak-scan/tokens "$A" '{"label":"hit"}'
  echo "$BODY" | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])' > "$S/hit.tok"
  DEMIPASS_URL=$API DEMIPASS_SCAN_TOKEN_FILE="$S/hit.tok" node "$W/bin/leak-scan.js" "$1" >/dev/null 2>&1; }
scrubtok(){ call POST /api/demipass/leak-scan/token-requests "$AG" '{"scrub_ref":"'$2'"}'; local rq=$(echo "$BODY" | J request_id) cs=$(echo "$BODY" | J claim_secret)
  call POST /api/identity/gate/verify "$A" '{"gate":"pin","pin":"4321","intent":"scrub-approve:'$rq'"}'; call POST /api/demipass/leak-scan/token-requests/$rq/approve "$A"
  call POST /api/demipass/leak-scan/token-requests/$rq/claim "" '{"claim_secret":"'$cs'"}'; echo "$BODY" | python3 -c 'import json,sys; print(json.load(sys.stdin)["tokens"][0]["token"])' > "$S/$1.tok"; }
SCRUB(){ DEMIPASS_URL=$API DEMIPASS_SCAN_TOKEN_FILE="$1" node "$W/bin/leak-scan.js" --scrub "${@:2}" 2>&1; }

# ── asking ──
call POST /api/demipass/leak-scan/token-requests "$AG" '{"scrub_ref":"'$XREF'"}'; [ "$CODE" = 404 ] && ok "a scrub of another owner's entry → 404" || fail "other ref: $CODE"
call POST /api/demipass/leak-scan/token-requests "$AG" '{"scrub_ref":"'$REF'","labels":["x"]}'; [ "$CODE" = 400 ] && ok "scrub_ref with labels → 400 (the server names the token)" || fail "labels+ref: $CODE"
call POST /api/demipass/leak-scan/token-requests "$AG" '{"scrub_ref":"'$REF'"}'; [ "$CODE" = 409 ] && ok "an entry the scanner never found cannot be scrubbed (no new oracle over a value that never leaked)" || fail "unleaked: $CODE $BODY"
mkdir -p "$S/hit1"; cp "$S/seed" "$S/hit1/f.txt"; scanhit "$S/hit1"
[ -n "$(Q "SELECT leak_seen_at FROM blindkey_secrets WHERE name='leaky'")" ] && ok "a scan hit records when the entry was seen" || fail "leak_seen_at"
mkdir -p "$S/tok"
OUT=$(DEMIPASS_URL=$API DEMIPASS_TOKEN="$AG" node "$W/bin/leak-scan.js" --scrub-request --no-wait "$S/tok" "$REF" 2>&1); RC=$?
RQ=$(basename "$(ls "$S/tok"/.pending-*.json)" .json | sed 's/.pending-//')
[ $RC = 3 ] && [ -n "$RQ" ] && ok "--scrub-request --no-wait: asked, waiting for the owner (exit 3)" || fail "scrub request: rc=$RC $OUT"
call GET /api/demipass/leak-scan/token-requests "$A"
[ "$(echo "$BODY" | J requests.0.scrub.name)" = leaky ] && [ "$(echo "$BODY" | J requests.0.kind)" = scrub ] && [ "$(echo "$BODY" | J requests.0.intent)" = "scrub-approve:$RQ" ] && ok "the owner's app sees a scrub (its own kind and PIN intent) and which entry" || fail "listing: $BODY"
grep -q "kind===.scrub.&&q.scrub" "$W/public/vault-mobile.html" && grep -q "in effect, the value" "$W/public/vault-mobile.html" && ok "the app's card for a scrub says the scrubber learns where the value is" || fail "card"
call POST /api/identity/gate/verify "$A" '{"gate":"pin","pin":"4321","intent":"scan-approve:'$RQ'"}'; call POST /api/demipass/leak-scan/token-requests/$RQ/approve "$A"
[ "$CODE" = 403 ] && [ "$(echo "$BODY" | J intent)" = "scrub-approve:$RQ" ] && ok "a PIN for a scan approval does not approve a scrub" || fail "scan pin on scrub: $CODE $BODY"
call POST /api/identity/gate/verify "$A" '{"gate":"pin","pin":"4321","intent":"scrub-approve:'$RQ'"}'; call POST /api/demipass/leak-scan/token-requests/$RQ/approve "$A"
[ "$CODE" = 200 ] && ok "the owner approves with the PIN (scrub-approve)" || fail "approve: $CODE $BODY"
TID=$(Q "SELECT id FROM leak_scan_tokens WHERE label='scrub-$REF'"); E0=$(Q "SELECT expires_at FROM leak_scan_tokens WHERE id=$TID")
sleep 1
OUT=$(DEMIPASS_URL=$API node "$W/bin/leak-scan.js" --claim "$S/tok" 2>&1); STOK="$S/tok/scrub-$REF.token"
[ -s "$STOK" ] && [ "$(stat -c %a "$STOK")" = 600 ] && ok "--claim writes the scrub token (0600)" || fail "claim: $OUT"
python3 -c "import sys,datetime as d; e=d.datetime.fromisoformat(sys.argv[1].replace('Z','+00:00'))-d.datetime.now(d.timezone.utc); sys.exit(0 if 23*3600 < e.total_seconds() <= 24*3600 else 1)" "$(Q "SELECT expires_at FROM leak_scan_tokens WHERE id=$TID")" && [ "$E0" != "$(Q "SELECT expires_at FROM leak_scan_tokens WHERE id=$TID")" ] && ok "a scrub token's day starts at its claim" || fail "ttl: $E0 → $(Q "SELECT expires_at FROM leak_scan_tokens WHERE id=$TID")"

# ── not interchangeable ──
python3 -c 'import json; print(json.dumps({"chunks":[{"id":"0","text":"hello"}]}))' > "$S/b.json"
C=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$API/api/demipass/leak-scan" -H 'content-type: application/json' -H "Authorization: Scan $(cat "$STOK")" -d @"$S/b.json"); [ "$C" = 403 ] && ok "a scrub token cannot scan (no oracle over the other entries)" || fail "scrub as scan: $C"
C=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$API/api/demipass/leak-scan/scrub" -H 'content-type: application/json' -H "Authorization: Scan $(cat "$S/legacy.tok")" -d @"$S/b.json"); [ "$C" = 403 ] && ok "a scan token cannot scrub" || fail "scan as scrub: $C"
C=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$API/api/demipass/leak-scan/scrub" -H 'content-type: application/json' -H "Authorization: Bearer $A" -d @"$S/b.json"); [ "$C" = 403 ] && ok "a session token cannot scrub" || fail "bearer scrub: $C"
python3 -c 'print("{\"chunks\":[{\"id\":\"0\",\"text\":\"" + "x"*2500000 + "\"}]}")' > "$S/huge.json"
C=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$API/api/demipass/leak-scan/scrub" -H 'content-type: application/json' -H "Authorization: Bearer $A" --data-binary @"$S/huge.json"); [ "$C" = 403 ] && ok "no scan token: refused before the 2 MiB body is read" || fail "huge bearer: $C"

# ── the tree ──
T=$S/tree; mkdir -p "$T/sub" "$T/node_modules"
python3 - "$S" <<'PY'
import json,sys,os; S=sys.argv[1]; v=open(S+'/seed').read().rstrip('\n'); k=open(S+'/other').read().rstrip('\n'); x=open(S+'/xval').read().rstrip('\n')
T=S+'/tree'
open(T+'/notes.md','w').write('line one\nthe password is '+v+' oops, again: '+v+v+'\nkept '+k+' and '+x+'\n')   # two touching copies
inner=json.dumps({"command":"login --pw "+v})
with open(T+'/sub/t.jsonl','w') as f:
    f.write(json.dumps({"type":"tool_result","content":"out: "+v})+'\n')                      # once escaped
    f.write(json.dumps({"type":"tool_use","input":inner})+'\n')                               # twice escaped
    f.write(json.dumps({"type":"py","content":"x "+v}, ensure_ascii=True)+'\n')               # \u escaped
    f.write(json.dumps({"type":"keep","content":k})+'\n')
# a stray Latin-1 byte before a JSONL copy: offsets must not shift (#98 review H2)
with open(T+'/latin.jsonl','wb') as f:
    f.write(b'{"a":"caf\xe9 \xe9\xe9"}\n'); f.write(json.dumps({"type":"x","content":"pw "+v}).encode()+b'\n'); f.write(b'{"b":"end"}\n')
# a copy straddling the 192 KiB window border, plus multi-byte text before it
pad='é'*((192*1024-10)//2)
open(T+'/big.log','w').write(pad+'xx'+v+'yy\n'+'tail\n')
open(T+'/blob.bin','wb').write(b'\x00\x01header'+v.encode()+b'\x00tail')
open(T+'/zeros.db','wb').write(b'\x00'*400000)                                               # JSON-escapes ×6 (#98 review M3)
open(T+'/node_modules/skip.txt','w').write(v)
os.symlink(T+'/notes.md', T+'/link.md')
PY
before(){ for f in notes.md sub/t.jsonl latin.jsonl big.log; do stat -c "%n %s %i" "$T/$f"; done; }
B0=$(before); SUM0=$(cat "$T/notes.md" "$T/sub/t.jsonl" "$T/big.log" "$T/latin.jsonl" | sha256sum)
OUT=$(SCRUB "$STOK" --dry-run "$T"); RC=$?
[ $RC = 1 ] && [ "$(cat "$T/notes.md" "$T/sub/t.jsonl" "$T/big.log" "$T/latin.jsonl" | sha256sum)" = "$SUM0" ] && echo "$OUT" | grep -q "notes.md: 2 copies (dry run)" && echo "$OUT" | grep -q "t.jsonl: 3 copies" && echo "$OUT" | grep -q "big.log: 1 copy" && echo "$OUT" | grep -q "latin.jsonl: 1 copy" \
  && ok "--dry-run finds raw, once/twice/\\u-escaped, border-straddling and non-UTF-8-neighbour copies (touching copies as one) and writes nothing" || fail "dry run: rc=$RC $OUT"
echo "$OUT" | grep -q "blob.bin: 1 copy in a binary file" && ! echo "$OUT" | grep -q "zeros.db" && ok "…a binary copy is reported, not written; a 400 kB file of zeros goes through (no 413)" || fail "binary: $OUT"
echo "$OUT" | grep -q "NOT READ.*node_modules" && ok "…a skipped directory is named as not read" || fail "skipped dir: $OUT"
mv "$T/blob.bin" "$S/blob.bin"
OUT=$(SCRUB "$STOK" "$T"); RC=$?
[ $RC = 1 ] && echo "$OUT" | grep -q "not marked contained (1 paths were not read)" && ok "a run that skipped a directory is not contained" || fail "skip not contained: rc=$RC $OUT"
[ -z "$(Q "SELECT leak_contained_at FROM blindkey_secrets WHERE name='leaky'")" ] && ok "…and the vault says so" || fail "marked"
python3 - "$S" <<'PY' && ok "the copies are gone; every JSONL line still parses (also after a non-UTF-8 byte); the other entry's and other owner's values are untouched" || fail "after scrub"
import json,sys; S=sys.argv[1]; v=open(S+'/seed').read().rstrip('\n'); k=open(S+'/other').read().rstrip('\n'); x=open(S+'/xval').read().rstrip('\n'); T=S+'/tree'
esc=lambda t: json.dumps(t)[1:-1]
forms=[v, esc(v), esc(esc(v)), json.dumps(v, ensure_ascii=True)[1:-1]]
allt=''.join(open(T+f, encoding='utf-8').read() for f in ['/notes.md','/sub/t.jsonl','/big.log'])+open(T+'/latin.jsonl','rb').read().decode('latin1')
assert not any(f in allt for f in forms), 'a copy is left'
assert v[:4] not in open(T+'/latin.jsonl','rb').read().decode('latin1'), 'a prefix is left'
for l in open(T+'/sub/t.jsonl'): json.loads(l)
for l in open(T+'/latin.jsonl','rb').read().split(b'\n')[1:]:
    if l: json.loads(l)
assert json.loads(json.loads(open(T+'/sub/t.jsonl').readlines()[1])['input'])['command'].startswith('login --pw ***')
assert k in allt and x in allt
PY
[ "$(before)" = "$B0" ] && ok "every file keeps its size and inode (an appending process is not cut off)" || fail "size/inode changed"
! echo "$OUT" | grep -qF -- "$(head -c 12 "$S/seed")" && ok "the scrubber prints no part of the value" || fail "value printed"
OUT=$(SCRUB "$STOK" "$T"); [ $? != 0 ] && echo "$OUT" | grep -q 401 && ok "the finished scrub token is spent (401 after)" || fail "reuse: $OUT"

# ── contained: a full run with nothing left ──
scrubtok s2 "$REF"
OUT=$(SCRUB "$S/s2.tok" --all "$T"); RC=$?
[ $RC = 0 ] && echo "$OUT" | grep -q "is contained" && [ -n "$(Q "SELECT leak_contained_at FROM blindkey_secrets WHERE name='leaky'")" ] && ! grep -qF -- "$(head -c 12 "$S/seed")" "$T/node_modules/skip.txt" && ok "--all reads the skipped directory too; nothing left → contained" || fail "contained: rc=$RC $OUT"
call GET /api/blindkey/list "$A"; echo "$BODY" | python3 -c 'import json,sys; d=json.load(sys.stdin); s=[x for x in d["secrets"] if x["name"]=="leaky"][0]; sys.exit(0 if s.get("leak_contained_at") else 1)' && ok "…and the vault listing shows when" || fail "listing: $(echo "$BODY" | head -c 200)"
mkdir -p "$S/again"; cp "$S/seed" "$S/again/found.txt"; scanhit "$S/again"
[ -z "$(Q "SELECT leak_contained_at FROM blindkey_secrets WHERE name='leaky'")" ] && ok "a later scan hit clears contained" || fail "still contained after a hit"

# ── not contained: copies left, nothing read, or seen again while it worked ──
scrubtok s3 "$REF"; mkdir -p "$S/bin"; mv "$S/blob.bin" "$S/bin/"
OUT=$(SCRUB "$S/s3.tok" "$S/bin"); RC=$?
[ $RC = 1 ] && echo "$OUT" | grep -q "not marked contained (1 copies were left)" && ok "a run that leaves a copy (binary) is not contained" || fail "left copies: rc=$RC $OUT"
scrubtok s4 "$REF"
C=$(curl -s -o "$S/fin.json" -w '%{http_code}' -X POST "$API/api/demipass/leak-scan/scrub/finish" -H 'content-type: application/json' -H "Authorization: Scan $(cat "$S/s4.tok")" -d '{"files_read":0,"files_changed":0,"copies_masked":0,"copies_left":0,"paths_not_read":0}')
[ "$C" = 200 ] && [ "$(J contained < "$S/fin.json")" = False ] && ok "a finish that read no files is not contained" || fail "zero finish: $C $(cat "$S/fin.json")"
scrubtok s5 "$REF"; mkdir -p "$S/t5"; cp "$S/seed" "$S/t5/a.txt"; sleep 1
mkdir -p "$S/again2"; cp "$S/seed" "$S/again2/b.txt"; scanhit "$S/again2"
OUT=$(SCRUB "$S/s5.tok" "$S/t5"); RC=$?
[ $RC = 1 ] && echo "$OUT" | grep -q "a scan found the value again" && ok "a scan hit while the scrub worked → not contained" || fail "seen since: rc=$RC $OUT"

# ── bound to the one row and the value approved (#98 review H1) ──
scrubtok s6 "$REF"; scrubtok s7 "$REF"
call POST /api/demipass/rotate "$A" "$(python3 -c 'import json,secrets; print(json.dumps({"name":"kept","new_value":"kept2-"+secrets.token_urlsafe(14)}))')"
mkdir -p "$S/t6"; cp "$S/other" "$S/t6/old-kept.txt"
OUT=$(SCRUB "$S/s6.tok" --dry-run "$S/t6"); RC=$?
[ $RC = 0 ] && echo "$OUT" | grep -q "found 0" && ok "after another entry is rotated, the scrub token still finds only its own value" || fail "fan-out: rc=$RC $OUT"
python3 -c 'import secrets; print("leaky2-" + secrets.token_urlsafe(14))' > "$S/seed2"
call POST /api/demipass/rotate "$A" "$(python3 -c 'import json,sys; print(json.dumps({"name":"leaky","new_value":open(sys.argv[1]).read().strip()}))' "$S/seed2")"
mkdir -p "$S/t7"; cp "$S/seed" "$S/t7/old.txt"; cp "$S/seed2" "$S/t7/new.txt"
OUT=$(SCRUB "$S/s7.tok" --dry-run "$S/t7"); RC=$?
[ $RC = 1 ] && echo "$OUT" | grep -q "old.txt: 1 copy" && ! echo "$OUT" | grep -q "new.txt" && ok "after its own entry is rotated, the token finds the leaked (approved) value, never the new one" || fail "rotated own: rc=$RC $OUT"
# the approved row's value replaced in place (same row id): the token stops
NEWID=$(Q "SELECT id FROM blindkey_secrets WHERE ref_code='$REF' AND status='active'")
call POST /api/demipass/leak-scan/token-requests "$AG" '{"scrub_ref":"'$REF'"}'; [ "$CODE" = 409 ] && ok "the rotated-in value never leaked: it cannot be scrubbed on the old value's record" || fail "new value scrubbable: $CODE"
mkdir -p "$S/h2"; cp "$S/seed2" "$S/h2/f.txt"; scanhit "$S/h2"; scrubtok s9 "$REF"
python3 -c 'import secrets; print("leaky3-" + secrets.token_urlsafe(14))' > "$S/seed3"
( cd "$W" && node -e '
const Database = require("better-sqlite3"); const db = new Database(process.env.DB_PATH);
// what the server would write: its own encryption of a new value, put in place in the approved row
const enc = db.prepare("SELECT encrypted_value FROM blindkey_secrets WHERE name = ?").get("kept");
db.prepare("UPDATE blindkey_secrets SET encrypted_value = ? WHERE id = ?").run(enc.encrypted_value, Number(process.argv[1]));' "$NEWID" )
OUT=$(SCRUB "$S/s9.tok" --dry-run "$S/t7"); RC=$?
[ $RC = 2 ] && echo "$OUT" | grep -q "410.*value changed" && ok "the approved row's value replaced in place: the token stops (410)" || fail "changed: rc=$RC $OUT"

# ── a long value across a window border (#98 review M2) ──
python3 -c 'import secrets; print("-----BEGIN KEY-----" + secrets.token_urlsafe(2200) + "-----END KEY-----")' > "$S/pem"
store "$S/pem" pem "$A"; PREF=$(Q "SELECT ref_code FROM blindkey_secrets WHERE name='pem'")
mkdir -p "$S/hp"; cp "$S/pem" "$S/hp/k.txt"; scanhit "$S/hp"; scrubtok sp "$PREF"
mkdir -p "$S/tp"; python3 -c 'import sys; v=open(sys.argv[1]).read().strip(); open(sys.argv[2],"w").write("a"*(192*1024-1500)+v+"\nend\n")' "$S/pem" "$S/tp/long.txt"
OUT=$(SCRUB "$S/sp.tok" --dry-run "$S/tp"); RC=$?
[ $RC = 1 ] && echo "$OUT" | grep -q "long.txt: 1 copy" && ok "a 3 kB value straddling a window border is found" || fail "long value: rc=$RC $OUT"

# ── re-review: N1 bytes not characters, N2 a value replaced after its hit, N3 no offline check, N4 packed files ──
python3 -c 'import secrets;print("nl-" + secrets.token_urlsafe(14))' > "$S/nval"; store "$S/nval" nl "$A"; NREF=$(Q "SELECT ref_code FROM blindkey_secrets WHERE name='nl'"); echo "$NREF" > "$S/nref"
mkdir -p "$S/hu"; cp "$S/nval" "$S/hu/f.txt"; scanhit "$S/hu"; scrubtok sN "$NREF"
mkdir -p "$S/tn"
python3 - "$S" <<'PY'
import sys,gzip; S=sys.argv[1]; v=open(S+'/nval').read().strip(); T=S+'/tn'
open(T+'/tui.log','w').write(('│'+'─'*200+'│\n')*9000 + 'pw '+v+'\n')               # 5.4 MB of 3-byte characters
open(T+'/ja.md','w').write(('日本語のテキスト'*40+'\n')*6000 + 'pw '+v+'\n')
# a UTF-8 copy and a Latin-1-only neighbour in one window with stray bytes (re-review L: counts must not cancel)
open(T+'/mixed.txt','wb').write(b'caf\xe9 \xff\n' + v.encode() + b'\n' + b'x\xe9y\n')
open(T+'/hi.bin','wb').write(bytes([0x80])*1500000)                                    # no character boundary anywhere
with gzip.open(T+'/old.log.gz','wt') as g: g.write('pw '+v+'\n')
PY
OUT=$(timeout 120 bash -c "DEMIPASS_URL=$API DEMIPASS_SCAN_TOKEN_FILE=$S/sN.tok node $W/bin/leak-scan.js --scrub $S/tn" 2>&1); RC=$?
echo "$OUT" | grep -q "tui.log: 1 copy" && echo "$OUT" | grep -q "ja.md: 1 copy" && ! echo "$OUT" | grep -q 413 && ok "5–6 MB of multi-byte text goes through (batches counted in bytes) and its copies are masked" || fail "N1: rc=$RC $OUT"
echo "$OUT" | grep -q "mixed.txt: 1 copy" && ! grep -qF -- "$(head -c 12 "$S/nval")" "$S/tn/mixed.txt" && ok "a UTF-8 copy among stray bytes is masked exactly" || fail "mixed: $OUT"
echo "$OUT" | grep -q "NOT READ.*old.log.gz (gzip" && echo "$OUT" | grep -q "not marked contained" && ok "a gzip file is not read and the run is not contained" || fail "N4: $OUT"
[ $RC = 1 ] && ok "…and a file of continuation bytes does not stall the run" || fail "hi.bin: rc=$RC"
python3 - "$DB_PATH" "$S" <<'PY' && ok "the stored fingerprints cannot be checked from the database alone, and a spent token keeps none" || fail "N3"
import sqlite3,sys,hmac,hashlib; c=sqlite3.connect(sys.argv[1]); S=sys.argv[2]; v=open(S+'/nval').read().strip()
rows=c.execute("SELECT token_hash, scrub_value_mac, revoked_at FROM leak_scan_tokens WHERE scrub_secret_id IS NOT NULL").fetchall()
for th,mac,rev in rows:
    if mac: assert mac not in (hmac.new(th.encode(), v.encode(), hashlib.sha256).hexdigest(),), 'mac keyed by the token hash'
    if rev: assert mac is None, 'a spent token keeps its fingerprint'
seen=c.execute("SELECT leak_seen_mac FROM blindkey_secrets WHERE ref_code=? AND status='active'", (open(S+'/nref').read().strip(),)).fetchone()[0]
assert seen and seen != hashlib.sha256(v.encode()).hexdigest()
PY
store "$S/xval" up1 "$A"; mkdir -p "$S/hup"; cp "$S/xval" "$S/hup/f.txt"; scanhit "$S/hup"
python3 -c 'import secrets; print("up2-" + secrets.token_urlsafe(14))' > "$S/up2"; sleep 1; store "$S/up2" up1 "$A"
UREF=$(Q "SELECT ref_code FROM blindkey_secrets WHERE name='up1'")
call POST /api/demipass/leak-scan/token-requests "$AG" '{"scrub_ref":"'$UREF'"}'; [ "$CODE" = 409 ] && ok "a value replaced in place after its hit cannot be scrubbed on the old value's record" || fail "N2: $CODE $BODY"
C=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$API/api/demipass/leak-scan/scrub" -H 'content-type: application/json' -H "Authorization: Scan bogus-token" --data-binary @"$S/huge.json"); [ "$C" = 401 ] && ok "an unknown scan token is refused before the body is read" || fail "L1: $C"
scrubtok sF "$NREF"
C=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$API/api/demipass/leak-scan/scrub/finish" -H 'content-type: application/json' -H "Authorization: Scan $(cat "$S/sF.tok")" -d '{"files_read":3,"files_changed":0,"copies_masked":0,"copies_left":0}'); [ "$C" = 400 ] && ok "finish must say how many paths were not read" || fail "paths_not_read: $C"

# ── expiry ──
scrubtok s8 "$NREF"
python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute(\"UPDATE leak_scan_tokens SET expires_at='2000-01-01T00:00:00.000Z' WHERE token_hash=?\", (sys.argv[2],)); c.commit()" "$DB_PATH" "$(tr -d '\n' < "$S/s8.tok" | sha256sum | cut -d' ' -f1)"
C=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$API/api/demipass/leak-scan/scrub" -H 'content-type: application/json' -H "Authorization: Scan $(cat "$S/s8.tok")" -d @"$S/b.json"); [ "$C" = 401 ] && ok "an expired scrub token is refused" || fail "expired: $C"
grep -qF -- "$(head -c 12 "$S/seed")" "$S"/server-new.log && fail "the value reached the server log" || ok "the value never reaches the server log"

echo; [ $fails = 0 ] && echo "ALL OK" || echo "$fails FAILED"; exit $fails
