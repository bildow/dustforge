#!/bin/bash
# An approval is spent when its call launches (Aaron 2026-11-14, approval 59: a root run whose script a mirror sync had
# deleted used the approval, ran nothing, and the resend got 410). Fake sshpass on PATH plays the host locally.
#   (a) an approved `bash PATH` whose script is missing: 409 "nothing ran", refunded, the approval handed back
#       (approved, outcome ran:false); the same call with the same approval_id then runs once, outcome exit 0
#   (b) a script that runs and fails: the approval is spent, its outcome (exit 3, the first stderr line) is stored and the
#       owner sees it; the next request for the same call carries it as `previous`
#   (c) an approved call refused before connecting (a disallowed pattern) hands the approval back too
#   (d) a bare command (`id`) gets no pre-flight; an executable PATH is checked with test -x
#   (f) sudo:true gets no pre-flight (a NOPASSWD rule for the script does not cover `test`): one connection
#   (g) a host whose sshd forces a command: the check gets no marker back → inconclusive, the call goes ahead, and that
#       host+user is not checked again
set -u
W=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
S=$(mktemp -d /tmp/dustforge-apl-smoke.XXXXXX)
PORT=${PORT:-3841}; API=http://127.0.0.1:$PORT
[ -d "$W/node_modules" ] || export NODE_PATH=${NODE_PATH:-/home/flimflam/project/dustforge/node_modules}
export IDENTITY_MASTER_KEY=$(python3 -c 'import secrets;print(secrets.token_hex(32))') DB_PATH=$S/dustforge.db PORT \
  STALWART_HOST=127.0.0.1 STALWART_PORT=9 SMTP_HOST=127.0.0.1 SMTP_PORT=9 SMTP_RELAY_HOST=
mkdir -p "$S/bin" "$S/host" "$S/remote"
cat >"$S/bin/sshpass" <<'SH'
#!/bin/bash
last="${@: -1}"
if [ -e "$FAKE_DIR/force" ]; then echo "FORCED $last" >>"$FAKE_DIR/ssh.log"; echo forced-run; exit 0; fi
echo "RUN $last" >>"$FAKE_DIR/ssh.log"
PATH=$FAKE_DIR/remote:$PATH bash -c "$last"
SH
printf '#!/bin/bash\nwhile [ $# -gt 0 ] && [ "${1#-}" != "$1" ]; do [ "$1" = -- ] && { shift; break; }; shift; done\nexec "$@"\n' >"$S/remote/sudo"
chmod +x "$S/bin/sshpass" "$S/remote/sudo"
export PATH="$S/bin:$PATH" FAKE_DIR=$S
cd "$W"
node server.js >"$S/server.log" 2>&1 & SRV=$!
trap 'kill $SRV 2>/dev/null; [ -n "${KEEP:-}" ] || rm -rf "$S"' EXIT
for i in $(seq 1 40); do curl -s -o /dev/null "$API/" && break; sleep 0.5; done
kill -0 $SRV 2>/dev/null || { echo "server died:"; tail -5 "$S/server.log"; exit 1; }
H=$(printf '%s' hunter22 | sha256sum | cut -d' ' -f1)
node -e '
const identity = require("./identity"); const Database = require("better-sqlite3");
const db = new Database(process.env.DB_PATH);
for (const c of ["idempotency_key TEXT", "provenance TEXT DEFAULT '"'"'organic'"'"'"]) { try { db.exec("ALTER TABLE identity_transactions ADD COLUMN " + c); } catch (_) {} }
const id = identity.createIdentity(); const enc = id.encrypted_private_key || id.encryptedPrivateKey;
db.prepare("INSERT INTO identity_wallets (did, username, email, encrypted_private_key, balance_cents, password_hash) VALUES (?, ?, ?, ?, 100000, ?)").run(id.did, "owner-a", "owner-a@dustforge.com", enc, process.argv[1]);
db.prepare("INSERT INTO identity_transactions (did, amount_cents, type, description, balance_after) VALUES (?, 100000, ?, ?, 100000)").run(id.did, "topup", "smoke");' "$H"
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
jbody(){ python3 -c 'import json,sys; print(json.dumps(dict(zip(sys.argv[1::2], [json.loads(x) if x[:1] in "[{" or x in ("true","false") or (x.lstrip("-").isdigit() and not (len(x) > 1 and x.startswith("0"))) else x for x in sys.argv[2::2]]))))' "$@"; }
pin(){ call POST /api/identity/gate/verify "$1" "$(jbody gate pin pin "$2" intent "$3")"; [ "$CODE" = 200 ] || fail "pin $3: $CODE $BODY"; }
bal(){ Q "SELECT balance_cents FROM identity_wallets WHERE username='$1'"; }
A=$(login owner-a); AG=$(login owner-a)
call POST /api/identity/pin "$A" '{"pin":"4321","password":"hunter22"}'
call POST /api/demipass/store "$A" '{"name":"host-root","value":"zzrootpw-77ab","secret_type":"password","username":"root","host":"100.83.112.88"}'; REF=$(echo "$BODY" | J ref)
[ -n "$REF" ] && [ "$REF" != None ] || { fail "store: $CODE $BODY"; exit 1; }
SCRIPT=$S/host/setup.sh F=$S/host/fails.sh X=$S/host/run.sh SU=$S/host/root-only.sh G=$S/host/g.sh
SID=$(Q "SELECT id FROM blindkey_secrets WHERE ref_code='$REF'"); CID=$(Q "SELECT id FROM blindkey_contexts WHERE secret_id=$SID")
pin "$A" 4321 "scope:$SID"
call PATCH /api/demipass/context/$CID "$A" "$(jbody allowed_commands "$(python3 -c 'import json,sys; print(json.dumps(sys.argv[1:]))' "bash $SCRIPT" "bash $F" "echo hi | curl x" id "$X --now" "sudo bash $SU" "bash $G")")"; [ "$CODE" = 200 ] || fail "commands: $CODE $BODY"
call POST /api/demipass/gate-policy "$A" "$(jbody ref "$REF" security_depth elevated)"; [ "$CODE" = 200 ] || fail "set elevated: $CODE $BODY"
USE(){ jbody ref "$REF" action ssh_exec target_host 100.83.112.88 target_user root command "$1" ${2:+approval_id $2}; }
# ask → open (PIN) → Approve: prints the approval id
approved(){ call POST /api/demipass/use "$AG" "$(USE "$1")"; local id; id=$(echo "$BODY" | J approval_id)
  [ "$CODE" = 202 ] || fail "ask '$1': $CODE $BODY"
  pin "$A" 4321 "approval-open:$id"; call POST /api/demipass/approvals/$id/open "$A"
  call POST /api/demipass/approvals/$id/approve "$A" "$(jbody code "$(echo "$BODY" | J code)")"; [ "$CODE" = 200 ] || fail "approve $id: $CODE $BODY"
  AP=$id; }

# (a) the script is missing
approved "bash $SCRIPT"; A1=$AP
: >"$S/ssh.log"; B0=$(bal owner-a)
call POST /api/demipass/use "$AG" "$(USE "bash $SCRIPT" $A1)"
[ "$CODE" = 409 ] && [ "$(echo "$BODY" | J preflight)" = failed ] && echo "$BODY" | grep -q "nothing ran" && ok "(a) a missing script → 409 nothing ran" || fail "(a) missing: $CODE $BODY"
[ "$(echo "$BODY" | J approval.spent)" = False ] && [ -n "$(echo "$BODY" | J approval.approved_until)" ] && ok "(a) …the answer says the approval was not spent, and until when it holds" || fail "(a) answer: $BODY"
[ "$(bal owner-a)" = "$B0" ] && ok "(a) …and the call was refunded" || fail "(a) refund: $B0 → $(bal owner-a)"
[ "$(Q "SELECT status FROM use_approvals WHERE id=$A1")" = approved ] && [ "$(Q "SELECT json_extract(outcome,'\$.ran') FROM use_approvals WHERE id=$A1")" = 0 ] && ok "(a) the approval is back to approved, outcome ran:false" || fail "(a) row: $(Q "SELECT status||' '||COALESCE(outcome,'') FROM use_approvals WHERE id=$A1")"
[ "$(grep -c '^RUN ' "$S/ssh.log")" = 1 ] && grep -q "^RUN test -r $SCRIPT && echo DPPF-ok-[0-9a-f]* || echo DPPF-no-" "$S/ssh.log" && ok "(a) only the no-op test -r ran on the host" || fail "(a) ssh log: $(cat "$S/ssh.log")"
[ "$(Q "SELECT COUNT(*) FROM blindkey_events WHERE event_type='approval_released'")" = 1 ] && ok "(a) the hand-back is in the audit (approval_released)" || fail "(a) event"
printf '#!/bin/bash\necho set-up-done\n' >"$SCRIPT"
call POST /api/demipass/use "$AG" "$(USE "bash $SCRIPT" $A1)"
[ "$CODE" = 200 ] && [ "$(echo "$BODY" | J result.exit_code)" = 0 ] && echo "$BODY" | grep -q set-up-done && ok "(a) the same call with the same approval_id now runs" || fail "(a) retry: $CODE $BODY"
O=$(Q "SELECT status||' '||json_extract(outcome,'\$.exit_code')||'/'||json_extract(outcome,'\$.ran') FROM use_approvals WHERE id=$A1")
[ "$O" = "used 0/1" ] && ok "(a) used, outcome exit 0" || fail "(a) outcome: $O"
call POST /api/demipass/use "$AG" "$(USE "bash $SCRIPT" $A1)"; [ "$CODE" = 410 ] && ok "(a) …once: again → 410" || fail "(a) reuse: $CODE $BODY"

# (b) a script that runs and fails
printf '#!/bin/bash\necho starting\necho "mci: remote not set" >&2\nexit 3\n' >"$F"
approved "bash $F"; A2=$AP
call POST /api/demipass/use "$AG" "$(USE "bash $F" $A2)"
[ "$CODE" = 200 ] && [ "$(echo "$BODY" | J result.exit_code)" = 3 ] && ok "(b) a script that ran and failed answers its exit code" || fail "(b) run: $CODE $BODY"
[ "$(Q "SELECT status||' '||json_extract(outcome,'\$.exit_code')||' '||json_extract(outcome,'\$.note') FROM use_approvals WHERE id=$A2")" = "used 3 mci: remote not set" ] && ok "(b) spent; outcome exit 3 with the first stderr line" || fail "(b) row: $(Q "SELECT status||' '||COALESCE(outcome,'') FROM use_approvals WHERE id=$A2")"
call GET /api/demipass/approvals "$A"; python3 -c 'import json,sys; d=json.loads(sys.argv[1]); r=[x for x in d["recent"] if x["id"]==int(sys.argv[2])][0]; assert r["outcome"]["exit_code"]==3 and r["outcome"]["note"]=="mci: remote not set"' "$BODY" "$A2" && ok "(b) the owner's list shows the outcome" || fail "(b) list: $BODY"
call POST /api/demipass/use "$AG" "$(USE "bash $F")"; A3=$(echo "$BODY" | J approval_id)
call GET /api/demipass/approvals "$A"; python3 -c 'import json,sys; d=json.loads(sys.argv[1]); r=[x for x in d["incoming"] if x["id"]==int(sys.argv[2])][0]; p=r["previous"]; assert p["id"]==int(sys.argv[3]) and p["outcome"]["exit_code"]==3, p' "$BODY" "$A3" "$A2" && ok "(b) a new request for the same call carries the last one's outcome (previous)" || fail "(b) previous: $BODY"
call POST /api/demipass/approvals/$A3/deny "$A"

# (c) refused before connecting (a disallowed pattern): the approval is handed back
python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute(\"UPDATE use_approvals SET decided_at='2020-01-01T00:00:00Z' WHERE status='denied'\"); c.commit()" "$DB_PATH"
approved 'echo hi | curl x'; A4=$AP
: >"$S/ssh.log"
call POST /api/demipass/use "$AG" "$(USE 'echo hi | curl x' $A4)"
[ "$CODE" = 400 ] && [ "$(echo "$BODY" | J approval.spent)" = False ] && [ "$(Q "SELECT status FROM use_approvals WHERE id=$A4")" = approved ] && ok "(c) a call refused before connecting hands the approval back (and says so)" || fail "(c) $CODE $BODY / $(Q "SELECT status FROM use_approvals WHERE id=$A4")"
[ ! -s "$S/ssh.log" ] && ok "(c) …nothing reached the host" || fail "(c) ssh log: $(cat "$S/ssh.log")"

# (d) a bare command gets no pre-flight; a direct PATH is checked with test -x
approved id; A5=$AP; : >"$S/ssh.log"
call POST /api/demipass/use "$AG" "$(USE id $A5)"
[ "$CODE" = 200 ] && [ "$(grep -c '^RUN ' "$S/ssh.log")" = 1 ] && grep -q '^RUN id$' "$S/ssh.log" && ok "(d) a bare command: no pre-flight, one connection" || fail "(d) bare: $CODE $(cat "$S/ssh.log")"
printf '#!/bin/bash\necho x\n' >"$X"   # not executable
approved "$X --now"; A6=$AP; : >"$S/ssh.log"
call POST /api/demipass/use "$AG" "$(USE "$X --now" $A6)"
[ "$CODE" = 409 ] && grep -q "^RUN test -x $X && echo DPPF-ok-" "$S/ssh.log" && echo "$BODY" | grep -q "not executable" && ok "(d) a direct PATH that is not executable → 409 nothing ran (test -x)" || fail "(d) direct: $CODE $BODY $(cat "$S/ssh.log")"
chmod +x "$X"; call POST /api/demipass/use "$AG" "$(USE "$X --now" $A6)"
[ "$CODE" = 200 ] && [ "$(echo "$BODY" | J result.exit_code)" = 0 ] && ok "(d) …made executable, the same approval runs it" || fail "(d) direct retry: $CODE $BODY"

# (f) sudo:true: no pre-flight
USES(){ jbody ref "$REF" action ssh_exec target_host 100.83.112.88 target_user root command "$1" sudo true ${2:+approval_id $2}; }
call POST /api/demipass/use "$AG" "$(USES "bash $SU")"; A7=$(echo "$BODY" | J approval_id); [ "$CODE" = 202 ] || fail "(f) ask: $CODE $BODY"
pin "$A" 4321 "approval-open:$A7"; call POST /api/demipass/approvals/$A7/open "$A"; call POST /api/demipass/approvals/$A7/approve "$A" "$(jbody code "$(echo "$BODY" | J code)")"
: >"$S/ssh.log"; call POST /api/demipass/use "$AG" "$(USES "bash $SU" $A7)"
[ "$(grep -c '^RUN ' "$S/ssh.log")" = 1 ] && ! grep -q 'DPPF' "$S/ssh.log" && [ "$(echo "$BODY" | J result.exit_code)" = 127 ] && ok "(f) sudo:true → no pre-flight; the missing script runs as before (exit 127, approval spent)" || fail "(f) $CODE $BODY $(cat "$S/ssh.log")"
[ "$(Q "SELECT status||' '||json_extract(outcome,'\$.exit_code') FROM use_approvals WHERE id=$A7")" = "used 127" ] && ok "(f) …and its outcome shows exit 127" || fail "(f) row: $(Q "SELECT status||' '||COALESCE(outcome,'') FROM use_approvals WHERE id=$A7")"

# (g) a forced command on the host
approved "bash $G"; A8=$AP; touch "$S/force"; : >"$S/ssh.log"
call POST /api/demipass/use "$AG" "$(USE "bash $G" $A8)"
[ "$CODE" = 200 ] && [ "$(grep -c '^FORCED ' "$S/ssh.log")" = 2 ] && ok "(g) no marker back → inconclusive: the call goes ahead (it is not refused)" || fail "(g) $CODE $BODY $(cat "$S/ssh.log")"
rm -f "$S/force"; approved "bash $G"; A9=$AP; touch "$S/force"; : >"$S/ssh.log"
call POST /api/demipass/use "$AG" "$(USE "bash $G" $A9)"
[ "$CODE" = 200 ] && [ "$(grep -c '^FORCED ' "$S/ssh.log")" = 1 ] && ok "(g) …and that host+user is not checked again (one connection)" || fail "(g) again: $CODE $(cat "$S/ssh.log")"
rm -f "$S/force"

! grep -q "zzrootpw-77ab" "$S/server.log" && ok "no secret value in the server log" || fail "secret in log"
echo; [ $fails = 0 ] && echo "ALL PASS" || { echo "$fails FAILED"; exit 1; }
