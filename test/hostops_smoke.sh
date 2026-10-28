#!/bin/bash
# End-to-end smoke of DemiPass host operations (test/hostops_smoke.sh). Boots server.js on a throwaway DB with a
# fake `sshpass` and `ssh-keyscan` first on its PATH. The fakes run nothing: they log the exact remote command line
# that would reach the host (and whether host-key pinning was on), check the pinned known_hosts file, and answer from
# fixed replies (a job's state lives in a file the test flips). Two accounts: the owner (has the vault PIN, stores
# the SSH password, delegates it) and an agent (the delegate). Covers: not covered → 202 request, nothing run or
# charged; approval needs the PIN for hostop:<id>, never from the asking side; one-time grant runs once; windows of
# typed shapes; jobs start/poll/finish/cancel; refusals explain the nearest shape; pinned key enforced; output
# redacted; closing a window ends authority. Needs node_modules (or NODE_PATH). No network.
set -u
W=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
S=$(mktemp -d /tmp/dustforge-hostops-smoke.XXXXXX)
PORT=${PORT:-3781}; API=http://127.0.0.1:$PORT
[ -d "$W/node_modules" ] || export NODE_PATH=${NODE_PATH:-/home/flimflam/project/dustforge/node_modules}
F=$S/fake; mkdir -p "$F/bin"
printf 'fixture-host-key-ed25519-%s' "$RANDOM" | base64 -w0 > "$F/key.b64"
cat > "$F/bin/sshpass" <<EOF
#!/bin/bash
F=$F
EOF
cat >> "$F/bin/sshpass" <<'EOF'
remote="${@: -1}"; target="${@: -2:1}"; known=""; strict=""
for a in "$@"; do case "$a" in UserKnownHostsFile=*) known="${a#UserKnownHostsFile=}";; StrictHostKeyChecking=yes) strict=1;; esac; done
printf '%s\t%s\t%s\n' "$target" "${strict:-NOSTRICT}" "$remote" >> "$F/calls.log"
if [ -z "$strict" ] || [ ! -f "$known" ] || ! grep -q "ssh-ed25519 $(cat "$F/key.b64")" "$known"; then echo "Host key verification failed." >&2; exit 255; fi
case "$remote" in
  "sudo -n systemd-run --unit=dp-hostop-"*) u=${remote#*--unit=dp-hostop-}; u=${u%% *}; echo running > "$F/job-$u"; exit 0;;
  "sudo -n systemctl show dp-hostop-"*) u=${remote#*show dp-hostop-}; u=${u%% *}; st=$(cat "$F/job-$u" 2>/dev/null || echo gone)
    case "$st" in
      running) printf 'LoadState=loaded\nActiveState=active\nSubState=running\nResult=success\nExecMainStatus=0\n';;
      done:0) printf 'LoadState=loaded\nActiveState=active\nSubState=exited\nResult=success\nExecMainStatus=0\n';;
      done:*) printf 'LoadState=loaded\nActiveState=failed\nSubState=failed\nResult=exit-code\nExecMainStatus=%s\n' "${st#done:}";;
      *) printf 'LoadState=not-found\nActiveState=inactive\nSubState=dead\nResult=success\nExecMainStatus=0\n';;
    esac
    printf -- '---journal---\nflight log for unit %s\n' "$u"; exit 0;;
  "sudo -n systemctl stop dp-hostop-"*) u=${remote#*stop dp-hostop-}; echo stopped > "$F/job-$u"; exit 0;;
  *"'exit-3'"*) echo "failing as asked" >&2; exit 3;;
  *) echo "ran: $remote"; echo "credential seen by the host: $SSHPASS"; exit 0;;
esac
EOF
cat > "$F/bin/ssh-keyscan" <<EOF
#!/bin/bash
addr="\${@: -1}"; echo "# \$addr:22 SSH-2.0-fake"; echo "\$addr ssh-ed25519 \$(cat $F/key.b64)"
EOF
chmod +x "$F/bin/sshpass" "$F/bin/ssh-keyscan"; : > "$F/calls.log"
export IDENTITY_MASTER_KEY=$(python3 -c 'import secrets;print(secrets.token_hex(32))') DB_PATH=$S/dustforge.db PORT STALWART_HOST=127.0.0.1 STALWART_PORT=1 SMTP_RELAY_HOST=
cd "$W"
PATH="$F/bin:$PATH" node server.js >"$S/server.log" 2>&1 & SRV=$!
trap 'kill $SRV 2>/dev/null; rm -rf "$S"' EXIT
for i in $(seq 1 40); do curl -s -o /dev/null "$API/" && break; sleep 0.5; done
kill -0 $SRV 2>/dev/null || { echo "server died:"; tail -5 "$S/server.log"; exit 1; }
H=$(printf '%s' hunter22 | sha256sum | cut -d' ' -f1)
node -e '
const identity = require("./identity"); const Database = require("better-sqlite3");
const db = new Database(process.env.DB_PATH);
try { db.exec("ALTER TABLE identity_wallets ADD COLUMN password_hash TEXT"); } catch (_) {}
for (const c of ["idempotency_key TEXT", "provenance TEXT DEFAULT '"'"'organic'"'"'"]) { try { db.exec("ALTER TABLE identity_transactions ADD COLUMN " + c); } catch (_) {} }
for (const u of ["owner-o", "agent-b"]) {
  const id = identity.createIdentity(); const enc = id.encrypted_private_key || id.encryptedPrivateKey;
  db.prepare("INSERT INTO identity_wallets (did, username, email, encrypted_private_key, balance_cents, password_hash) VALUES (?, ?, ?, ?, 1000, ?)").run(id.did, u, u + "@dustforge.com", enc, process.argv[1]);
  db.prepare("INSERT INTO identity_transactions (did, amount_cents, type, description, balance_after) VALUES (?, 1000, ?, ?, 1000)").run(id.did, "topup", "smoke");
}' "$H"
fails=0; ok(){ echo "ok   $*"; }; fail(){ echo "FAIL $*"; fails=$((fails+1)); }
J(){ python3 -c 'import json,sys; d=json.load(sys.stdin); v=d
for k in sys.argv[1].split("."):
    v = v[int(k)] if isinstance(v, list) else (v or {}).get(k)
print(v)' "$1"; }
Q(){ python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); r=c.execute(sys.argv[2]).fetchone(); print(r[0] if r else '')" "$DB_PATH" "$1"; }
SQL(){ python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute(sys.argv[2]); c.commit()" "$DB_PATH" "$1"; }
call(){ local m=$1 p=$2 t=$3 b=${4:-}
  BODY=$(curl -s -o - -w '\n%{http_code}' -X "$m" "$API$p" -H 'Content-Type: application/json' ${t:+-H "Authorization: Bearer $t"} ${b:+-d "$b"})
  CODE=${BODY##*$'\n'}; BODY=${BODY%$'\n'*}; }
login(){ call POST /api/identity/auth-fingerprint "" "{\"username\":\"$1\",\"password\":\"hunter22\",\"scope\":\"transact\",\"expires_in\":\"1h\"}"; echo "$BODY" | J token; }
calls(){ wc -l < "$F/calls.log" | tr -d ' '; }
BAL(){ Q "SELECT balance_cents FROM identity_wallets WHERE username='$1'"; }
OWN=$(login owner-o); AG=$(login agent-b)
[ -n "$OWN" ] && [ "$OWN" != None ] && [ -n "$AG" ] && [ "$AG" != None ] && ok "owner and agent signed in" || { fail "login: $CODE $BODY"; exit 1; }
AGDID=$(Q "SELECT did FROM identity_wallets WHERE username='agent-b'")
call POST /api/identity/pin "$OWN" '{"pin":"2468","password":"hunter22"}'; [ "$CODE" = 200 ] || fail "owner pin: $CODE $BODY"
call POST /api/blindkey/store "$OWN" '{"name":"host-ssh","value":"Fixture-Pass-91","secret_type":"password"}'; [ "$CODE" = 200 ] || [ "$CODE" = 201 ] || fail "store: $CODE $BODY"
REF=$(Q "SELECT ref_code FROM blindkey_secrets WHERE name='host-ssh'")
call POST /api/blindkey/delegate "$OWN" "{\"secret_name\":\"host-ssh\",\"delegate_did\":\"$AGDID\"}"; [ "$CODE" = 200 ] || [ "$CODE" = 201 ] && ok "owner delegated host-ssh ($REF) to the agent" || fail "delegate: $CODE $BODY"
RUN(){ printf '{"ref":"%s","host":"10.0.0.5","argv":%s%s}' "$REF" "$1" "${2:+,$2}"; }

# ── nothing runs without a window ─────────────────────────────────────────────────────────────────────
call POST /api/demipass/hostops/run "$AG" "$(RUN '["incus","list"]')"; [ "$CODE" = 400 ] && echo "$BODY" | grep -q "user" && ok "unregistered host without a login → 400 (say which user)" || fail "no user: $CODE $BODY"
B0=$(BAL agent-b)
call POST /api/demipass/hostops/run "$AG" "$(RUN '["incus","list"]' '"user":"apple"')"
[ "$CODE" = 202 ] && [ "$(echo "$BODY" | J status)" = needs_approval ] && ok "not covered → 202 needs_approval" || fail "first run: $CODE $BODY"
R1=$(echo "$BODY" | J request_id)
[ "$(calls)" = 0 ] && ok "…nothing reached the host" || fail "calls before approval: $(cat "$F/calls.log")"
[ "$(BAL agent-b)" = "$B0" ] && ok "…and nothing was charged" || fail "charged for a request: $B0 → $(BAL agent-b)"
call POST /api/demipass/hostops/run "$AG" "$(RUN '["incus","list"]' '"user":"apple"')"; [ "$(echo "$BODY" | J request_id)" = "$R1" ] && ok "the same ask reuses its pending request" || fail "dedupe: $BODY"
call POST /api/demipass/hostops/run "$AG" "$(RUN '["source","/etc/profile"]' '"user":"apple"')"; [ "$CODE" = 202 ] && [ "$(calls)" = 0 ] && ok "a builtin-style argv is only ever a request, never a run" || fail "source argv: $CODE $BODY"
call POST /api/demipass/hostops/run "$AG" "$(RUN '["incus","two words"]' '"user":"apple"')"; [ "$CODE" = 400 ] && ok "argv words with spaces → 400" || fail "space argv: $CODE $BODY"
call POST /api/demipass/hostops/run "$AG" '{"ref":"DP-PWD-nothere-00000000","host":"10.0.0.5","user":"apple","argv":["incus","list"]}'; [ "$CODE" = 403 ] && ok "a credential the caller may not use → 403" || fail "bad ref: $CODE $BODY"

# ── the owner decides on the phone ────────────────────────────────────────────────────────────────────
call GET /api/demipass/hostops/pending "$OWN"
[ "$(echo "$BODY" | J requests.0.intent)" = "hostop:$R1" ] && [ "$(echo "$BODY" | J requests.0.host_is_new)" = True ] && echo "$BODY" | J requests.0.fingerprint | grep -q '^SHA256:' && ok "owner's wallet lists the request with intent hostop:$R1 and the host key fingerprint" || fail "pending: $BODY"
call GET /api/demipass/hostops/pending "$AG"; [ "$(echo "$BODY" | J requests)" = "[]" ] && ok "the agent's wallet shows nothing to decide" || fail "agent pending: $BODY"
call POST /api/demipass/hostops/requests/$R1/approve "$AG" '{}'; [ "$CODE" = 404 ] && ok "the agent cannot approve its own request" || fail "agent approve: $CODE $BODY"
call POST /api/demipass/hostops/requests/$R1/approve "$OWN" '{}'
[ "$CODE" = 403 ] && [ "$(echo "$BODY" | J intent)" = "hostop:$R1" ] && echo "$BODY" | J missing | grep -q pin && ok "approve without the PIN → 403 missing pin, intent hostop:$R1" || fail "approve no pin: $CODE $BODY"
call POST /api/identity/gate/verify "$OWN" '{"gate":"pin","pin":"2468","intent":"hostop:999"}'
call POST /api/demipass/hostops/requests/$R1/approve "$OWN" '{}'; [ "$CODE" = 403 ] && ok "a PIN typed for another intent does not approve" || fail "cross intent: $CODE $BODY"
call POST /api/identity/gate/verify "$OWN" "{\"gate\":\"pin\",\"pin\":\"2468\",\"intent\":\"hostop:$R1\"}"; [ "$CODE" = 200 ] || fail "verify: $CODE $BODY"
call POST /api/demipass/hostops/requests/$R1/approve "$OWN" '{}'
[ "$CODE" = 200 ] && [ "$(echo "$BODY" | J window.max_runs)" = 1 ] && ok "approved: a one-time grant (one run, one hour); host registered with its key pinned" || fail "approve: $CODE $BODY"
[ "$(Q "SELECT COUNT(*) FROM hostops_hosts WHERE address='10.0.0.5' AND ssh_user='apple'")" = 1 ] || fail "host not registered"
call POST /api/demipass/hostops/requests/$R1/approve "$OWN" '{}'; [ "$CODE" = 409 ] && ok "a decided request cannot be approved twice" || fail "double approve: $CODE $BODY"

# ── the one-time grant runs exactly once ──────────────────────────────────────────────────────────────
B1=$(BAL agent-b)
call POST /api/demipass/hostops/run "$AG" "$(RUN '["incus","list"]')"
[ "$CODE" = 200 ] && [ "$(echo "$BODY" | J run.status)" = succeeded ] && [ "$(echo "$BODY" | J run.exit_code)" = 0 ] && ok "covered → ran (status succeeded, exit 0)" || fail "run once: $CODE $BODY"
echo "$BODY" | J run.stdout | grep -q '\[REDACTED\]' && ! echo "$BODY" | grep -q 'Fixture-Pass-91' && ok "the credential is redacted from the output" || fail "redaction: $BODY"
LAST=$(tail -1 "$F/calls.log")
[ "$(printf '%s' "$LAST" | cut -f1)" = "apple@10.0.0.5" ] && [ "$(printf '%s' "$LAST" | cut -f2)" = 1 ] && [ "$(printf '%s' "$LAST" | cut -f3)" = "'incus' 'list'" ] && ok "the host received exactly 'incus' 'list' with host-key pinning on" || fail "remote line: $LAST"
[ "$(BAL agent-b)" = "$((B1 - 1))" ] && ok "one run = one compute call charged to the agent" || fail "charge: $B1 → $(BAL agent-b)"
call POST /api/demipass/hostops/run "$AG" "$(RUN '["incus","list"]')"; [ "$CODE" = 202 ] && ok "the one-time grant is used up: asks again" || fail "second run: $CODE $BODY"

# ── a window of typed shapes ──────────────────────────────────────────────────────────────────────────
SHAPES='[{"name":"flight","mode":"job","sudo":true,"max_seconds":10800,"argv":["/usr/local/sbin/agent-ssd-flight.sh",{"slot":"container","enum":["brain2","soul2","triadic2"]},{"slot":"stamp","match":"^[0-9]{8}T[0-9]{4}Z$"},{"literal":"precopy","optional":true}]},{"name":"delete-failed-copy","sudo":true,"argv":["incus","delete",{"slot":"container","enum":["brain-agentssd-failed-20261023T0105Z"]}]},{"name":"pool-create","sudo":true,"argv":["incus","storage","create",{"slot":"pool","type":"word"},"dir",{"slot":"src","type":"path","prefix":"source=","under":["/srv/agent-ssd/"]}]},{"name":"fails","argv":["/bin/false","exit-3"]}]'
call POST /api/demipass/hostops/requests "$AG" "{\"kind\":\"window\",\"ref\":\"$REF\",\"host\":\"10.0.0.5\",\"label\":\"SSD migration\",\"reason\":\"finish the move\",\"duration_hours\":72,\"shapes\":$SHAPES}"
[ "$CODE" = 202 ] && ok "agent asks for a 72 h window with 4 shapes" || fail "window request: $CODE $BODY"
R2=$(echo "$BODY" | J request_id)
call POST /api/demipass/hostops/requests "$AG" "{\"kind\":\"window\",\"ref\":\"$REF\",\"host\":\"10.0.0.5\",\"label\":\"x\",\"duration_hours\":72,\"shapes\":[{\"name\":\"bad\",\"mode\":\"job\",\"argv\":[\"x\"]}]}"
[ "$CODE" = 400 ] && echo "$BODY" | grep -q "needs sudo" && ok "an invalid shape is refused at request time, with the reason" || fail "bad shape: $CODE $BODY"
call POST /api/identity/gate/verify "$OWN" "{\"gate\":\"pin\",\"pin\":\"2468\",\"intent\":\"hostop:$R2\"}"
call POST /api/demipass/hostops/requests/$R2/approve "$OWN" '{"duration_hours":200}'; [ "$CODE" = 400 ] && ok "approval cannot lengthen the requested window" || fail "longer: $CODE $BODY"
call POST /api/demipass/hostops/requests/$R2/approve "$OWN" '{"duration_hours":48}'
[ "$CODE" = 200 ] && [ "$(echo "$BODY" | J window.max_runs)" = 0 ] && ok "owner approves it, shortened to 48 h" || fail "approve window: $CODE $BODY"
WID=$(echo "$BODY" | J window.id)
call POST /api/demipass/hostops/run "$AG" "$(RUN '["incus","storage","create","agent-ssd","dir","source=/srv/agent-ssd/incus"]')"
[ "$CODE" = 200 ] && [ "$(tail -1 "$F/calls.log" | cut -f3)" = "sudo -n -- 'incus' 'storage' 'create' 'agent-ssd' 'dir' 'source=/srv/agent-ssd/incus'" ] && ok "the Incus pool command (source=…) runs as typed words under sudo" || fail "pool: $CODE $BODY / $(tail -1 "$F/calls.log")"
N=$(calls)
call POST /api/demipass/hostops/run "$AG" "$(RUN '["/usr/local/sbin/agent-ssd-flight.sh","brain3","20261028T1200Z"]')"
[ "$CODE" = 202 ] && [ "$(echo "$BODY" | J explain.nearest.shape)" = flight ] && echo "$BODY" | J explain.nearest.reason | grep -q 'is not one of brain2|soul2|triadic2' && ok "outside the shape → 202 explaining the nearest shape and why" || fail "explain: $CODE $BODY"
call POST /api/demipass/hostops/run "$AG" "$(RUN '["incus","storage","create","--force","dir","source=/srv/agent-ssd/x"]')"; [ "$CODE" = 202 ] && ok "a slot value starting with - is never accepted" || fail "dash slot: $CODE $BODY"
call POST /api/demipass/hostops/run "$AG" "$(RUN '["incus","storage","create","p","dir","source=/srv/agent-ssd/../etc"]')"; [ "$CODE" = 202 ] && ok "a path slot refuses .." || fail "dotdot: $CODE $BODY"
[ "$(calls)" = "$N" ] && ok "…none of those reached the host" || fail "refusals reached host"
call POST /api/demipass/hostops/run "$AG" "$(RUN '["/bin/false","exit-3"]')"; [ "$(echo "$BODY" | J run.status)" = failed ] && [ "$(echo "$BODY" | J run.exit_code)" = 3 ] && ok "a failing command reports status failed, exit 3" || fail "exit 3: $CODE $BODY"

# ── jobs ──────────────────────────────────────────────────────────────────────────────────────────────
call POST /api/demipass/hostops/run "$AG" "$(RUN '["/usr/local/sbin/agent-ssd-flight.sh","brain2","20261028T1200Z","precopy"]')"
JOB=$(echo "$BODY" | J run.id)
[ "$CODE" = 200 ] && [ "$(echo "$BODY" | J run.status)" = running ] && ok "flight brain2 starts as a job (run $JOB)" || fail "job start: $CODE $BODY"
[ "$(tail -1 "$F/calls.log" | cut -f3)" = "sudo -n systemd-run --unit=dp-hostop-$JOB --remain-after-exit --quiet --property=RuntimeMaxSec=10800 -- '/usr/local/sbin/agent-ssd-flight.sh' 'brain2' '20261028T1200Z' 'precopy'" ] && ok "…as a transient unit capped at 10800 s" || fail "job line: $(tail -1 "$F/calls.log")"
SQL "UPDATE hostops_runs SET polled_at = 0 WHERE id = $JOB"
call GET /api/demipass/hostops/runs/$JOB "$AG"; [ "$(echo "$BODY" | J run.status)" = running ] && echo "$BODY" | J run.stdout | grep -q "flight log" && ok "poll: still running, journal tail shown" || fail "poll running: $BODY"
echo done:0 > "$F/job-$JOB"; SQL "UPDATE hostops_runs SET polled_at = 0 WHERE id = $JOB"
call GET /api/demipass/hostops/runs/$JOB "$AG"; [ "$(echo "$BODY" | J run.status)" = succeeded ] && [ "$(echo "$BODY" | J run.exit_code)" = 0 ] && ok "poll: finished, succeeded, exit 0" || fail "poll done: $BODY"
[ "$(tail -1 "$F/calls.log" | cut -f3)" = "sudo -n systemctl stop dp-hostop-$JOB" ] && ok "…and the finished unit was collected" || fail "collect: $(tail -1 "$F/calls.log")"
call GET /api/demipass/hostops/runs/$JOB "$OWN"; [ "$CODE" = 200 ] && ok "the owner sees the agent's run receipt" || fail "owner run view: $CODE"
call POST /api/demipass/hostops/run "$AG" "$(RUN '["/usr/local/sbin/agent-ssd-flight.sh","soul2","20261028T1200Z"]')"; JOB2=$(echo "$BODY" | J run.id)
call POST /api/demipass/hostops/runs/$JOB2/cancel "$AG" '{}'; [ "$CODE" = 200 ] && [ "$(echo "$BODY" | J run.status)" = cancelled ] && [ "$(cat "$F/job-$JOB2")" = stopped ] && ok "a running job can be cancelled" || fail "cancel: $CODE $BODY"

# ── pinned key, closing, credentials ──────────────────────────────────────────────────────────────────
printf 'other-host-key' | base64 -w0 > "$F/key.b64"
call POST /api/demipass/hostops/run "$AG" "$(RUN '["incus","delete","brain-agentssd-failed-20261023T0105Z"]')"
[ "$(echo "$BODY" | J run.status)" = failed ] && echo "$BODY" | J run.stderr | grep -q "Host key verification failed" && ok "a host presenting another key is refused (pinned key)" || fail "key change: $CODE $BODY"
call POST /api/demipass/hostops/windows/$WID/close "$OWN" '{}'; [ "$(echo "$BODY" | J window.status)" = closed ] && ok "the owner closes the window" || fail "close: $CODE $BODY"
N=$(calls)
call POST /api/demipass/hostops/run "$AG" "$(RUN '["incus","storage","create","agent-ssd","dir","source=/srv/agent-ssd/incus"]')"; [ "$CODE" = 202 ] && [ "$(calls)" = "$N" ] && ok "after closing, nothing runs: back to a request" || fail "after close: $CODE $BODY"
call POST /api/demipass/hostops/requests/$(echo "$BODY" | J request_id)/deny "$OWN" '{}'; [ "$(echo "$BODY" | J status)" = denied ] && ok "the owner can deny without a PIN" || fail "deny: $BODY"
call POST /api/blindkey/store "$OWN" '{"name":"api-key","value":"sk-fixture-0001","secret_type":"api_key"}'
APIREF=$(Q "SELECT ref_code FROM blindkey_secrets WHERE name='api-key'")
call POST /api/demipass/hostops/run "$OWN" "{\"ref\":\"$APIREF\",\"host\":\"10.0.0.5\",\"user\":\"apple\",\"argv\":[\"incus\",\"list\"]}"; [ "$CODE" = 400 ] && ok "only password credentials drive host operations" || fail "api key cred: $CODE $BODY"
grep -q 'Fixture-Pass-91' "$S/server.log" && fail "the credential appears in the server log" || ok "the credential never appears in the server log"
python3 - "$DB_PATH" <<'PY' && ok "no stored receipt contains the credential" || fail "credential stored in a receipt"
import sqlite3,sys; c=sqlite3.connect(sys.argv[1])
n=c.execute("SELECT COUNT(*) FROM hostops_runs WHERE stdout LIKE '%Fixture-Pass-91%' OR stderr LIKE '%Fixture-Pass-91%'").fetchone()[0]; sys.exit(1 if n else 0)
PY
echo "$fails failure(s)"; [ "$fails" = 0 ]
