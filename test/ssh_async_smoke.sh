#!/bin/bash
# ssh_exec no longer blocks the process (2026-11-07). Before, sshRun was execFileSync: every ssh call froze the whole
# API for its duration, and a remote command that called this API back (the deploy leak gate's scan, a scan-token
# claim) deadlocked until the 30 s kill (exit 255, nothing done). Fake sshpass on PATH plays the host locally.
#   (a) a remote command that calls the API back completes (no deadlock)
#   (b) while a slow ssh call runs, other requests are answered at once
#   (c) one use-token redeemed twice at the same time runs once: the second gets 410 "already in use"
#   (d) two blind rotations of one secret at the same time: the second gets 409
#   (e) #58 review H1: a client that disconnects mid-run does not free its token for a second run
#   (f) #58 review M2: a scope with max_uses 1, two direct calls at once → one runs, one 403
#   (g) #58 review: git_clone runs async; the token is never in git's argv; the clone directory is 0700
set -u
W=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
S=$(mktemp -d /tmp/dustforge-sshasync-smoke.XXXXXX)
PORT=${PORT:-3833}; API=http://127.0.0.1:$PORT
[ -d "$W/node_modules" ] || export NODE_PATH=${NODE_PATH:-/home/flimflam/project/dustforge/node_modules}
export IDENTITY_MASTER_KEY=$(python3 -c 'import secrets;print(secrets.token_hex(32))') DB_PATH=$S/dustforge.db PORT \
  STALWART_HOST=127.0.0.1 STALWART_PORT=9 SMTP_HOST=127.0.0.1 SMTP_PORT=9 SMTP_RELAY_HOST=
mkdir -p "$S/bin" "$S/remote"
cat >"$S/bin/sshpass" <<'SH'
#!/bin/bash
echo "ARGV $*" >>"$FAKE_DIR/ssh.log"
last="${@: -1}"
if [ "$last" = "bash -s" ]; then PATH=$FAKE_DIR/remote:$PATH bash -s; else PATH=$FAKE_DIR/remote:$PATH bash -c "$last"; fi
SH
printf '#!/bin/bash\nS_=0\nwhile [ $# -gt 0 ] && [ "${1#-}" != "$1" ]; do case "$1" in --) shift; break;; -S) S_=1; shift;; *) shift;; esac; done\n[ $S_ = 1 ] && read -r pw\nsleep 2\nexec "$@"\n' >"$S/remote/sudo"
printf '#!/bin/bash\ncat >>"$FAKE_DIR/chpasswd.in"\n' >"$S/remote/chpasswd"
cat >"$S/bin/git" <<'SH'
#!/bin/bash
echo "ARGV $*" >>"$FAKE_DIR/git.log"
echo "ASKPASS $("$GIT_ASKPASS" 'Username for https://github.com: ')" >>"$FAKE_DIR/git.log"
dest="${@: -1}"; echo "DESTMODE $(stat -c %a "$dest")" >>"$FAKE_DIR/git.log"; sleep 1; echo "Cloning into '$dest'..."
SH
chmod +x "$S/bin/sshpass" "$S/remote/sudo" "$S/remote/chpasswd" "$S/bin/git"
export PATH="$S/bin:$PATH" FAKE_DIR=$S
cd "$W"
node server.js >"$S/server.log" 2>&1 & SRV=$!
trap 'kill $SRV 2>/dev/null; [ -n "${KEEP:-}" ] || rm -rf "$S"' EXIT
for i in $(seq 1 40); do curl -s -o /dev/null "$API/" && break; sleep 0.5; done
kill -0 $SRV 2>/dev/null || { echo "server died:"; tail -5 "$S/server.log"; exit 1; }
node -e '
const identity = require("./identity"), Database = require("better-sqlite3"), crypto = require("crypto");
const db = new Database(process.env.DB_PATH);
try { db.exec("ALTER TABLE identity_wallets ADD COLUMN password_hash TEXT"); } catch (_) {}
const id = identity.createIdentity();
db.prepare("INSERT INTO identity_wallets (did, username, email, encrypted_private_key, balance_cents, password_hash) VALUES (?, ?, ?, ?, 100000, ?)")
  .run(id.did, "owner", "owner@dustforge.com", id.encrypted_private_key || id.encryptedPrivateKey, crypto.createHash("sha256").update("ownerpass1").digest("hex"));
const key = Buffer.from(process.env.IDENTITY_MASTER_KEY, "hex").slice(0, 32);
const seal = (v) => { const iv = crypto.randomBytes(16), c = crypto.createCipheriv("aes-256-gcm", key, iv); const e = Buffer.concat([c.update(v, "utf8"), c.final()]); return Buffer.concat([iv, c.getAuthTag(), e]).toString("base64"); };
db.prepare("INSERT INTO blindkey_secrets (did, name, secret_type, encrypted_value, status, ref_code, account_username) VALUES (?, ?, ?, ?, ?, ?, ?)").run(id.did, "box", "password", seal("boxpass-1"), "active", "DP-PWD-box-0001", "deploy");
const sid = db.prepare("SELECT id FROM blindkey_secrets WHERE ref_code = ?").get("DP-PWD-box-0001").id;
db.prepare("INSERT INTO blindkey_contexts (secret_id, context_name, action_type, target_url_pattern, target_host_pattern, allowed_by) VALUES (?, ?, ?, ?, ?, ?)").run(sid, "default", "ssh_exec", "*", "*", id.did);
db.prepare("INSERT INTO blindkey_secrets (did, name, secret_type, encrypted_value, status, ref_code) VALUES (?, ?, ?, ?, ?, ?)").run(id.did, "once", "password", seal("oncepass-1"), "active", "DP-PWD-once-0001");
const oid = db.prepare("SELECT id FROM blindkey_secrets WHERE ref_code = ?").get("DP-PWD-once-0001").id;
db.prepare("INSERT INTO blindkey_contexts (secret_id, context_name, action_type, target_url_pattern, target_host_pattern, allowed_by, max_uses) VALUES (?, ?, ?, ?, ?, ?, 1)").run(oid, "default", "ssh_exec", "*", "*", id.did);
db.prepare("INSERT INTO blindkey_secrets (did, name, secret_type, encrypted_value, status, ref_code) VALUES (?, ?, ?, ?, ?, ?)").run(id.did, "gitkey", "api_key", seal("ghp_SECRETTOKEN123"), "active", "DP-API-gitkey-0001");
const gid = db.prepare("SELECT id FROM blindkey_secrets WHERE ref_code = ?").get("DP-API-gitkey-0001").id;
db.prepare("INSERT INTO blindkey_contexts (secret_id, context_name, action_type, target_url_pattern, target_host_pattern, allowed_by) VALUES (?, ?, ?, ?, ?, ?)").run(gid, "mine", "git_clone", "https://github.com/bildow/*", null, id.did);
db.prepare("INSERT INTO identity_transactions (did, amount_cents, type) VALUES (?, 100000, ?)").run(id.did, "credit");'
fails=0; ok(){ echo "ok   $*"; }; fail(){ echo "FAIL $*"; fails=$((fails+1)); }
TOK=$(curl -s -X POST "$API/api/identity/auth-fingerprint" -H 'Content-Type: application/json' -d '{"username":"owner","password":"ownerpass1","scope":"transact"}' | python3 -c 'import json,sys;print(json.load(sys.stdin).get("token",""))')
use(){ curl -s -o "$S/$2.json" -w '%{http_code}' -m 60 -X POST "$API/api/blindkey/use" -H 'Content-Type: application/json' -H "Authorization: Bearer $TOK" -d "$1"; }
JO(){ python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); r=d.get("result") or {}; print(r.get(sys.argv[2], d.get(sys.argv[2], "")))' "$S/$1.json" "$2" 2>/dev/null; }

# (a) the remote command calls this API back
t0=$(date +%s)
C=$(use '{"name":"box","action":"ssh_exec","target_host":"100.83.112.88","target_user":"deploy","command":"curl -s -m 20 -o /dev/null -w CALLBACK=%{http_code} http://127.0.0.1:'$PORT'/"}' a)
dt=$(( $(date +%s) - t0 ))
[ "$C" = 200 ] && JO a stdout | grep -q 'CALLBACK=200' && [ $dt -lt 15 ] && ok "(a) a remote command that calls the API back completes (${dt}s, no deadlock)" || fail "(a) callback: $C ${dt}s $(cat "$S/a.json" | head -c 300)"
# (b) a slow ssh call (sudo -S takes 2 s here) does not stall other requests
use '{"name":"box","action":"ssh_exec","target_host":"100.83.112.88","target_user":"deploy","command":"sleep 4","stdin":"x"}' b >/dev/null & BG=$!
sleep 1
t0=$(date +%s%N); H=$(curl -s -o /dev/null -w '%{http_code}' -m 10 "$API/"); dms=$(( ($(date +%s%N) - t0) / 1000000 ))
[ "$H" = 200 ] && [ $dms -lt 1500 ] && ok "(b) the API answers while a 4 s ssh call runs (${dms} ms)" || fail "(b) stalled: $H ${dms} ms"
wait $BG
# (c) one use-token, two redemptions at the same time
UT=$(curl -s -X POST "$API/api/blindkey/request-token" -H 'Content-Type: application/json' -H "Authorization: Bearer $TOK" -d '{"ref":"DP-PWD-box-0001","target_host":"100.83.112.88","action":"ssh_exec"}' | python3 -c 'import json,sys;print(json.load(sys.stdin).get("use_token",""))')
[ -n "$UT" ] || fail "(c) no use-token: $(curl -s -X POST "$API/api/blindkey/request-token" -H "Content-Type: application/json" -H "Authorization: Bearer $TOK" -d "{\"ref\":\"DP-PWD-box-0001\",\"target_host\":\"100.83.112.88\",\"action\":\"ssh_exec\"}" | head -c 300)"
: >"$S/ssh.log"
use '{"use_token":"'$UT'","target_user":"deploy","command":"sleep 3"}' c1 >"$S/c1.code" & P1=$!
sleep 0.5
C2=$(use '{"use_token":"'$UT'","target_user":"deploy","command":"echo second"}' c2)
wait $P1; C1=$(cat "$S/c1.code")
runs=$(grep -c '^ARGV' "$S/ssh.log")
[ "$C1" = 200 ] && [ "$C2" = 410 ] && grep -q "already in use" "$S/c2.json" && [ "$runs" = 1 ] && ok "(c) the same use-token twice at once: one runs (200), the other 410, ssh ran once" || fail "(c) double redemption: $C1 / $C2 $(cat "$S/c2.json") runs=$runs"
C3=$(use '{"use_token":"'$UT'","target_user":"deploy","command":"echo third"}' c3)
[ "$C3" = 410 ] && ok "(c) after it ran, the token is spent (410)" || fail "(c) reuse after: $C3 $(cat "$S/c3.json")"
# (d) two blind rotations of one secret at once
rot(){ curl -s -o "$S/$2.json" -w '%{http_code}' -m 60 -X POST "$API/api/blindkey/rotate-blind" -H 'Content-Type: application/json' -H "Authorization: Bearer $TOK" -d "$1"; }
rot '{"ref":"DP-PWD-box-0001","target_host":"100.83.112.88"}' r1 >"$S/r1.code" & P1=$!
sleep 0.5
R2=$(rot '{"ref":"DP-PWD-box-0001","target_host":"100.83.112.88"}' r2)
wait $P1; R1=$(cat "$S/r1.code")
[ "$R1" = 200 ] && [ "$R2" = 409 ] && ok "(d) a second rotation of the same secret while one runs → 409; the first completes" || fail "(d) rotations: $R1 $(head -c 200 "$S/r1.json") / $R2 $(head -c 200 "$S/r2.json")"
# (e) disconnect mid-run
UT=$(curl -s -X POST "$API/api/blindkey/request-token" -H 'Content-Type: application/json' -H "Authorization: Bearer $TOK" -d '{"name":"box_v2","target_host":"100.83.112.88","action":"ssh_exec"}' | python3 -c 'import json,sys;print(json.load(sys.stdin).get("use_token",""))')
: >"$S/ssh.log"
curl -s -o /dev/null -m 1 -X POST "$API/api/blindkey/use" -H 'Content-Type: application/json' -H "Authorization: Bearer $TOK" -d '{"use_token":"'$UT'","target_user":"deploy","command":"sleep 4"}'
E2=$(use '{"use_token":"'$UT'","target_user":"deploy","command":"echo second"}' e2)
runs=$(grep -c '^ARGV' "$S/ssh.log")
[ "$E2" = 410 ] && [ "$runs" = 1 ] && ok "(e) the first client gone, its ssh still running: the token is still held (410), ssh ran once" || fail "(e) after disconnect: $E2 runs=$runs $(head -c 200 "$S/e2.json")"
sleep 4
# (f) max_uses 1, two direct calls at once
: >"$S/ssh.log"
use '{"name":"once","action":"ssh_exec","target_host":"100.83.112.88","target_user":"deploy","command":"sleep 2"}' f1 >"$S/f1.code" & P1=$!
sleep 0.5
F2=$(use '{"name":"once","action":"ssh_exec","target_host":"100.83.112.88","target_user":"deploy","command":"echo again"}' f2)
wait $P1; F1=$(cat "$S/f1.code"); runs=$(grep -c '^ARGV' "$S/ssh.log")
[ "$F1" = 200 ] && [ "$F2" = 403 ] && [ "$runs" = 1 ] && ok "(f) max_uses 1 and two calls at once: one runs, the other 403" || fail "(f) max_uses race: $F1 / $F2 runs=$runs $(head -c 200 "$S/f2.json")"
# (g) git clone
G=$(use '{"ref":"DP-API-gitkey-0001","action":"git_clone","params":{"repo_url":"https://github.com/bildow/demo"}}' g)
if [ "$G" = 200 ] && grep -q '"cloned":true' "$S/g.json"; then
  ! grep '^ARGV' "$S/git.log" | grep -q SECRETTOKEN && grep -q '^ASKPASS ghp_SECRETTOKEN123$' "$S/git.log" && grep -q '^DESTMODE 700$' "$S/git.log" \
    && ok "(g) git_clone: token not in argv, given through GIT_ASKPASS; the clone directory is 0700" || fail "(g) git: $(cat "$S/git.log")"
else fail "(g) git_clone: $G $(head -c 300 "$S/g.json")"; fi
echo; [ $fails = 0 ] && echo "ALL PASS" || { echo "$fails FAILED"; exit 1; }
