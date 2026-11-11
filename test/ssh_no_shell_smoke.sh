#!/bin/bash
# Smoke of /api/blindkey/rotate-blind and the SSH helper (sshRun): nothing a caller sends reaches a shell on this
# server. Boots server.js on a throwaway DB with a fake sshpass on PATH that logs its arguments and plays the remote
# host locally (fake sudo + chpasswd). Checks: a target_host carrying a shell command is refused and runs nothing;
# a host off the SSH whitelist and a bad target_user are refused; a rotation hands chpasswd exactly
# "<user>:<new password>" even when the current password is full of shell metacharacters; no password appears in
# sshpass's arguments (SSHPASS carries it); nothing is written under /tmp; a command starting with "-" is refused
# and ssh always gets "--" before user@host (ssh parses options after the destination: -oProxyCommand would run
# here); a stored password with a NUL is refused without being echoed; a 403 doesn't list the whitelist. No network.
set -u
W=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
S=$(mktemp -d /tmp/dustforge-ssh-smoke.XXXXXX)
PORT=${PORT:-3821}; API=http://127.0.0.1:$PORT
[ -d "$W/node_modules" ] || export NODE_PATH=${NODE_PATH:-/home/flimflam/project/dustforge/node_modules}
export IDENTITY_MASTER_KEY=$(python3 -c 'import secrets;print(secrets.token_hex(32))') DB_PATH=$S/dustforge.db PORT \
  STALWART_HOST=127.0.0.1 STALWART_PORT=9 SMTP_HOST=127.0.0.1 SMTP_PORT=9 SMTP_RELAY_HOST=
mkdir -p "$S/bin" "$S/remote"
cat >"$S/bin/sshpass" <<'SH'
#!/bin/bash
echo "ARGV $*" >>"$FAKE_DIR/ssh.log"; echo "SSHPASS_SET ${SSHPASS:+yes}" >>"$FAKE_DIR/ssh.log"
last="${@: -1}"
if [ "$last" = "bash -s" ]; then PATH=$FAKE_DIR/remote:$PATH bash -s; else PATH=$FAKE_DIR/remote:$PATH bash -c "$last"; fi
SH
cat >"$S/remote/sudo" <<'SH'
#!/bin/bash
# A stand-in sudo for a host where sudo needs a password. -S reads it from stdin (logged) and records a timestamp;
# -v then exits; -n runs only with a timestamp ("a password is required" otherwise). FAKE_SUDO_NOPASSWD: a NOPASSWD
# rule — it never reads stdin and never needs a timestamp.
S_=0; V_=0; N_=0
while [ $# -gt 0 ] && [ "${1#-}" != "$1" ]; do case "$1" in --) shift; break;; -p) shift 2;; -S) S_=1; shift;; -v) V_=1; shift;; -n) N_=1; shift;; *) shift;; esac; done
TS="$FAKE_DIR/sudo.ts"
if [ -n "${FAKE_SUDO_NOPASSWD:-}" ]; then [ $V_ = 1 ] && exit 0; exec "$@"; fi
if [ $S_ = 1 ]; then read -r pw; printf '%s' "$pw" >"$FAKE_DIR/sudo.pw"; touch "$TS"; [ $V_ = 1 ] && exit 0; exec "$@"; fi
if [ $N_ = 1 ] && [ ! -e "$TS" ]; then echo "sudo: a password is required" >&2; exit 1; fi
exec "$@"
SH
cat >"$S/remote/chpasswd" <<'SH'
#!/bin/bash
cat >>"$FAKE_DIR/chpasswd.in"
SH
chmod +x "$S/bin/sshpass" "$S/remote/sudo" "$S/remote/chpasswd"
export PATH="$S/bin:$PATH" FAKE_DIR=$S
cd "$W"
node server.js >"$S/server.log" 2>&1 & SRV=$!
trap 'kill $SRV 2>/dev/null; [ -n "${KEEP:-}" ] || rm -rf "$S"' EXIT
for i in $(seq 1 40); do curl -s -o /dev/null "$API/" && break; sleep 0.5; done
kill -0 $SRV 2>/dev/null || { echo "server died:"; tail -5 "$S/server.log"; exit 1; }
CUR='a$b`c"d'"'"'e\f !x'
CUR="$CUR" node -e '
const identity = require("./identity"), Database = require("better-sqlite3"), crypto = require("crypto");
const db = new Database(process.env.DB_PATH);
try { db.exec("ALTER TABLE identity_wallets ADD COLUMN password_hash TEXT"); } catch (_) {}
const id = identity.createIdentity();
db.prepare("INSERT INTO identity_wallets (did, username, email, encrypted_private_key, balance_cents, password_hash) VALUES (?, ?, ?, ?, 1000, ?)")
  .run(id.did, "owner", "owner@dustforge.com", id.encrypted_private_key || id.encryptedPrivateKey, crypto.createHash("sha256").update("ownerpass1").digest("hex"));
const key = Buffer.from(process.env.IDENTITY_MASTER_KEY, "hex").slice(0, 32);
const seal = (v) => { const iv = crypto.randomBytes(16), c = crypto.createCipheriv("aes-256-gcm", key, iv); const e = Buffer.concat([c.update(v, "utf8"), c.final()]); return Buffer.concat([iv, c.getAuthTag(), e]).toString("base64"); };
const add = db.prepare("INSERT INTO blindkey_secrets (did, name, secret_type, encrypted_value, status, ref_code) VALUES (?, ?, ?, ?, ?, ?)");
add.run(id.did, "box", "password", seal(process.env.CUR), "active", "DP-PWD-box-0001");
add.run(id.did, "nul", "password", seal("nulpw\u0000tail"), "active", "DP-PWD-nul-0001");
// An explicit scope (no scope, no use — red team item 12); a legacy command list (NULL = any command).
for (const ref of ["DP-PWD-box-0001", "DP-PWD-nul-0001"]) { const sid = db.prepare("SELECT id FROM blindkey_secrets WHERE ref_code = ?").get(ref).id;
  db.prepare("INSERT INTO blindkey_contexts (secret_id, context_name, action_type, target_url_pattern, target_host_pattern, allowed_by) VALUES (?, ?, ?, ?, ?, ?)").run(sid, "default", "ssh_exec", "*", "*", id.did); }
db.prepare("INSERT INTO identity_transactions (did, amount_cents, type) VALUES (?, 1000, ?)").run(id.did, "credit");'
fails=0; ok(){ echo "ok   $*"; }; fail(){ echo "FAIL $*"; fails=$((fails+1)); }
TOK=$(curl -s -X POST "$API/api/identity/auth-fingerprint" -H 'Content-Type: application/json' -d '{"username":"owner","password":"ownerpass1","scope":"transact"}' | python3 -c 'import json,sys;print(json.load(sys.stdin).get("token",""))')

# Owner rotations are approved in the DemiPass app (#96 review H1): RA = the call, approved with the owner's PIN, then repeated.
curl -s -o /dev/null -X POST "$API/api/identity/pin" -H 'Content-Type: application/json' -H "Authorization: Bearer $TOK" -d '{"pin":"4321","password":"ownerpass1"}'
_j(){ python3 -c 'import json,sys; print(json.load(sys.stdin).get(sys.argv[1],""))' "$1"; }
_p(){ curl -s -X POST "$API$1" -H 'Content-Type: application/json' -H "Authorization: Bearer $TOK" ${2:+-d "$2"}; }
RA(){ local body=$1 out=$2 c id k
  c=$(curl -s -o "$out" -w '%{http_code}' -m 60 -X POST "$API/api/blindkey/rotate-blind" -H 'Content-Type: application/json' -H "Authorization: Bearer $TOK" -d "$body")
  [ "$c" = 202 ] || { echo "$c"; return; }
  id=$(_j approval_id <"$out"); _p /api/identity/gate/verify '{"gate":"pin","pin":"4321","intent":"approval-open:'$id'"}' >/dev/null
  k=$(_p /api/demipass/approvals/$id/open | _j code); _p /api/demipass/approvals/$id/approve '{"code":"'$k'"}' >/dev/null
  curl -s -o "$out" -w '%{http_code}' -m 60 -X POST "$API/api/blindkey/rotate-blind" -H 'Content-Type: application/json' -H "Authorization: Bearer $TOK" \
    -d "$(python3 -c 'import json,sys; b=json.loads(sys.argv[1]); b["approval_id"]=int(sys.argv[2]); print(json.dumps(b))' "$body" "$id")"; }
rot(){ RA "$1" "$S/last.json"; }
before=$(ls /tmp | grep -c '^\.dp_')

MARK=$S/pwned
BODY=$(python3 -c 'import json,sys; print(json.dumps({"ref":"DP-PWD-box-0001","target_host":"100.83.112.88;touch "+sys.argv[1]+";#"}))' "$MARK")
C=$(rot "$BODY"); [ "$C" = 403 ] && [ ! -e "$MARK" ] && ok "shell in target_host: refused ($C), nothing ran" || fail "target_host injection: $C, marker $([ -e "$MARK" ] && echo created)"
BODY=$(python3 -c 'import json,sys; print(json.dumps({"ref":"DP-PWD-box-0001","target_host":"100.83.112.88","target_user":"root;touch "+sys.argv[1]}))' "$MARK")
C=$(rot "$BODY"); [ "$C" = 400 ] && [ ! -e "$MARK" ] && ok "shell in target_user: refused ($C), nothing ran" || fail "target_user injection: $C"
C=$(rot '{"ref":"DP-PWD-box-0001","target_host":"10.9.9.9"}'); [ "$C" = 403 ] && ok "host off the SSH whitelist refused" || fail "unlisted host: $C"
[ ! -s "$S/ssh.log" ] && ok "sshpass never ran for a refused request" || fail "sshpass ran: $(cat "$S/ssh.log")"

C=$(rot '{"ref":"DP-PWD-box-0001","target_host":"100.83.112.88","target_user":"deploy"}')
[ "$C" = 200 ] && ok "rotation answered 200" || fail "rotation: $C $(cat "$S/last.json")"
NEW=$(node -e '
const Database = require("better-sqlite3"), crypto = require("crypto"); const db = new Database(process.env.DB_PATH);
const r = db.prepare("SELECT encrypted_value FROM blindkey_secrets WHERE status = ? ORDER BY id DESC LIMIT 1").get("active");
const d = Buffer.from(r.encrypted_value, "base64"), k = Buffer.from(process.env.IDENTITY_MASTER_KEY, "hex").slice(0, 32);
const x = crypto.createDecipheriv("aes-256-gcm", k, d.slice(0, 16)); x.setAuthTag(d.slice(16, 32)); process.stdout.write(Buffer.concat([x.update(d.slice(32)), x.final()]).toString());')
[ -n "$NEW" ] && [ "$(cat "$S/chpasswd.in")" = "deploy:$NEW" ] && ok "chpasswd got exactly deploy:<new password>" || fail "chpasswd got: $(cat "$S/chpasswd.in" 2>/dev/null)"
[ "$(cat "$S/sudo.pw")" = "$CUR" ] && ok "sudo got the current password intact, metacharacters and all" || fail "sudo got a different password"
[ -n "$NEW" ] && ! grep -qF -- "$NEW" "$S/ssh.log" && ! grep -qF -- "$CUR" "$S/ssh.log" && ok "no password in sshpass's arguments" || fail "a password in sshpass's arguments"
[ "$(grep -c 'SSHPASS_SET yes' "$S/ssh.log")" = 2 ] && ok "SSHPASS carried the password (change + verify)" || fail "SSHPASS: $(grep SSHPASS "$S/ssh.log")"
[ "$(ls /tmp | grep -c '^\.dp_')" = "$before" ] && ok "nothing written under /tmp" || fail "new /tmp/.dp_ files"

# ssh reads options after the destination: a command starting with "-" (e.g. -oProxyCommand=…) must never reach it.
use(){ curl -s -o "$S/use.json" -w '%{http_code}' -X POST "$API/api/blindkey/use" -H 'Content-Type: application/json' -H "Authorization: Bearer $TOK" -d "$1"; }
: >"$S/ssh.log"
C=$(use "{\"name\":\"box\",\"action\":\"ssh_exec\",\"target_host\":\"100.83.112.88\",\"target_user\":\"deploy\",\"command\":\"-oProxyCommand=sh -c 'touch $MARK'\"}")
[ "$C" = 400 ] && [ ! -e "$MARK" ] && [ ! -s "$S/ssh.log" ] && ok "command starting with - refused (400), ssh never ran" || fail "leading-dash command: $C $(cat "$S/use.json")"
C=$(use '{"name":"box","action":"ssh_exec","target_host":"100.83.112.88","target_user":"deploy","command":"echo hi"}')
grep -q '^ARGV -e ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 -- deploy@100.83.112.88 echo hi$' "$S/ssh.log" && ok "ssh gets -- before user@host" || fail "ssh argv: $(cat "$S/ssh.log") ($C)"
# sudo modes. stdin carries text the command reads; the password is sent only in the owner's sudo:'password' mode.
J1(){ python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); r=d.get("result") or {}; print(r.get(sys.argv[2], d.get(sys.argv[2], "")))' "$S/use.json" "$1" 2>/dev/null; }
: >"$S/ssh.log"; rm -f "$S/sudo.pw" "$S/sudo.ts"
C=$(use '{"name":"box","action":"ssh_exec","target_host":"100.83.112.88","target_user":"deploy","command":"cat","sudo":true,"stdin":"x"}')
[ "$C" = 200 ] && [ "$(J1 exit_code)" = 1 ] && J1 stderr | grep -q "password is required" && [ ! -e "$S/sudo.pw" ] && ok "sudo:true sends no password: on a host that wants one it fails cleanly" || fail "sudo true pw-host: $C $(cat "$S/use.json")"
grep -qF -- "-- deploy@100.83.112.88 sudo -n -- cat" "$S/ssh.log" && ok "sudo:true is sudo -n -- <command>" || fail "sudo argv: $(cat "$S/ssh.log")"
: >"$S/ssh.log"; rm -f "$S/sudo.ts"
C=$(use '{"name":"box","action":"ssh_exec","target_host":"100.83.112.88","target_user":"deploy","command":"cat","sudo":"password","stdin":"relay block $(touch /tmp/never) `x` \"q\"\n"}')
OUT=$(J1 stdout)
[ "$C" = 200 ] && [ "$(cat "$S/sudo.pw" 2>/dev/null)" = "$NEW" ] && [ "$OUT" = 'relay block $(touch /tmp/never) `x` "q"' ] && [ ! -e /tmp/never ] && ok "sudo:'password' (owner): the password reaches sudo -S -v on stdin, the command gets only the stdin text" || fail "sudo password: $C $(cat "$S/use.json")"
grep -qF -- "IFS= read -r DP_SUDO_PW" "$S/ssh.log" && grep -qF -- "sudo -n -- cat; exit" "$S/ssh.log" && ! grep -qF -- "$NEW" "$S/ssh.log" && ok "the wrap reads the line itself, runs sudo -n, keeps the last sudo from being exec'd; no password in argv" || fail "wrap argv: $(cat "$S/ssh.log")"
export FAKE_SUDO_NOPASSWD=1; rm -f "$S/sudo.ts"
C=$(use '{"name":"box","action":"ssh_exec","target_host":"100.83.112.88","target_user":"deploy","command":"base64","sudo":"password"}')
[ "$C" = 200 ] && [ -z "$(J1 stdout | tr -d '\n')" ] && ok "a NOPASSWD sudo never passes the password line to the command (base64 prints nothing)" || fail "nopasswd leak: $C $(J1 stdout | head -c 12)"
C=$(use '{"name":"box","action":"ssh_exec","target_host":"100.83.112.88","target_user":"deploy","command":"cat","sudo":true,"stdin":"via nopasswd"}')
[ "$C" = 200 ] && [ "$(J1 stdout)" = "via nopasswd" ] && ok "sudo:true works where a NOPASSWD rule allows it" || fail "nopasswd true: $C $(cat "$S/use.json")"
unset FAKE_SUDO_NOPASSWD
C=$(use '{"name":"box","action":"ssh_exec","target_host":"100.83.112.88","target_user":"deploy","command":"cat","stdin":"plain text"}')
[ "$C" = 200 ] && [ "$(J1 stdout)" = "plain text" ] && ok "stdin without sudo reaches the command" || fail "stdin: $C $(cat "$S/use.json")"
# a delegate (an agent the owner delegated the box password to) may use sudo:true, never sudo:'password'
node -e '
const identity = require("./identity"), Database = require("better-sqlite3"), crypto = require("crypto");
const db = new Database(process.env.DB_PATH); const id = identity.createIdentity();
db.prepare("INSERT INTO identity_wallets (did, username, email, encrypted_private_key, balance_cents, password_hash) VALUES (?, ?, ?, ?, 1000, ?)")
  .run(id.did, "helper", "helper@dustforge.com", id.encrypted_private_key || id.encryptedPrivateKey, crypto.createHash("sha256").update("helperpass1").digest("hex"));
db.prepare("INSERT INTO identity_transactions (did, amount_cents, type) VALUES (?, 1000, ?)").run(id.did, "credit");
const o = db.prepare("SELECT did FROM identity_wallets WHERE username = ?").get("owner").did;
const cur = db.prepare("SELECT id, ref_code FROM blindkey_secrets WHERE did = ? AND status = ? AND (name = ? OR name LIKE ?) ORDER BY version DESC LIMIT 1").get(o, "active", "box", "box_v%");
const s = cur.id; require("fs").writeFileSync(process.env.DB_PATH + ".boxref", cur.ref_code);
db.prepare("INSERT INTO demipass_delegations (owner_did, delegate_did, secret_id, context_id, status) VALUES (?, ?, ?, NULL, ?)").run(o, id.did, s, "active");
const ctx = db.prepare("SELECT COUNT(*) AS n FROM blindkey_contexts WHERE secret_id = ?").get(s).n;
if (!ctx) db.prepare("INSERT INTO blindkey_contexts (secret_id, context_name, action_type, target_url_pattern, target_host_pattern, allowed_by) VALUES (?, ?, ?, ?, ?, ?)").run(s, "default", "ssh_exec", "*", "*", o);'
BOXREF=$(cat "$DB_PATH.boxref")
HTOK=$(curl -s -X POST "$API/api/identity/auth-fingerprint" -H 'Content-Type: application/json' -d '{"username":"helper","password":"helperpass1","scope":"transact"}' | python3 -c 'import json,sys;print(json.load(sys.stdin).get("token",""))')
huse(){ curl -s -o "$S/use.json" -w '%{http_code}' -X POST "$API/api/blindkey/use" -H 'Content-Type: application/json' -H "Authorization: Bearer $HTOK" -d "$1"; }
rm -f "$S/sudo.pw"
C=$(huse '{"ref":"'$BOXREF'","action":"ssh_exec","target_host":"100.83.112.88","target_user":"deploy","command":"cat","sudo":"password"}')
[ "$C" = 403 ] && grep -q "for the secret's owner" "$S/use.json" && [ ! -e "$S/sudo.pw" ] && ok "a delegate asking for sudo:'password' → 403, no password sent" || fail "delegate password: $C $(cat "$S/use.json")"
C=$(huse '{"ref":"'$BOXREF'","action":"ssh_exec","target_host":"100.83.112.88","target_user":"deploy","command":"cat","sudo":true,"stdin":"d"}')
[ "$C" = 200 ] && [ ! -e "$S/sudo.pw" ] && ok "a delegate may use sudo:true (no password sent; the host's NOPASSWD rules decide)" || fail "delegate true: $C $(cat "$S/use.json")"
rm -f "$S/sudo.pw"
C=$(use '{"name":"box","action":"ssh_exec","target_host":"100.83.112.88","target_user":"deploy","command":"cat","sudo":"password"}')
[ "$C" = 403 ] && grep -q "delegated or shared" "$S/use.json" && [ ! -e "$S/sudo.pw" ] && ok "while the secret is delegated, even the owner's sudo:'password' is refused (a holder could have planted a hook)" || fail "owner password while delegated: $C $(cat "$S/use.json")"
# ── forced commands (red team items 2, 3): a new SSH entry runs nothing until its owner lists commands with the PIN ──
call(){ local m=$1 p=$2 b=${3:-}; BODY=$(curl -s -o - -w '\n%{http_code}' -X "$m" "$API$p" -H 'Content-Type: application/json' -H "Authorization: Bearer $TOK" ${b:+-d "$b"}); CODE=${BODY##*$'\n'}; BODY=${BODY%$'\n'*}; }
call POST /api/identity/pin '{"pin":"4321","password":"ownerpass1"}'
call POST /api/demipass/store '{"name":"fc","value":"fc-pass-1","secret_type":"password","username":"deploy","host":"100.83.112.88"}'
FREF=$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["ref"])' "$BODY")
FSID=$(python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); print(c.execute('SELECT id FROM blindkey_secrets WHERE ref_code=?',(sys.argv[2],)).fetchone()[0])" "$DB_PATH" "$FREF")
FCID=$(python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); print(c.execute('SELECT id FROM blindkey_contexts WHERE secret_id=?',(int(sys.argv[2]),)).fetchone()[0])" "$DB_PATH" "$FSID")
: >"$S/ssh.log"
FC(){ use "{\"ref\":\"$FREF\",\"action\":\"ssh_exec\",\"target_host\":\"100.83.112.88\",\"command\":\"$1\"}"; }
C=$(FC "id"); [ "$C" = 403 ] && grep -q "no commands are allowed" "$S/use.json" && [ ! -s "$S/ssh.log" ] && ok "a new SSH entry runs nothing (forced commands by default), ssh never started" || fail "fc default: $C $(cat "$S/use.json")"
call PATCH /api/demipass/context/$FCID '{"allowed_commands":["uptime","systemctl status *"]}'
[ "$CODE" = 202 ] && echo "$BODY" | grep -q approval_pending && ok "adding commands is widening → a request the owner approves on the phone (PIN there)" || fail "fc add no pin: $CODE $BODY"
call POST /api/identity/gate/verify "{\"gate\":\"pin\",\"pin\":\"4321\",\"intent\":\"scope:$FSID\"}"
call PATCH /api/demipass/context/$FCID '{"allowed_commands":["uptime","systemctl status *"]}'; [ "$CODE" = 200 ] && ok "with the PIN the owner lists uptime and 'systemctl status *'" || fail "fc add: $CODE $BODY"
C=$(FC "uptime"); [ "$C" = 200 ] && grep -q -- "-- deploy@100.83.112.88 uptime$" "$S/ssh.log" && ok "a listed command runs" || fail "fc uptime: $C $(cat "$S/use.json")"
C=$(FC "systemctl status dustforge"); [ "$C" = 200 ] && ok "a 'prefix *' entry allows plain words after the prefix" || fail "fc prefix: $C"
: >"$S/ssh.log"
for bad in "uptime; cat /etc/shadow" "systemctl status x;rm -rf /" "systemctl status a && id" "rm -rf /srv" "uptime > /tmp/x"; do
  C=$(FC "$bad"); [ "$C" = 403 ] || { fail "fc bad '$bad': $C"; continue; }; done
[ ! -s "$S/ssh.log" ] && ok "commands off the list (chained, redirected, other) → 403, ssh never started" || fail "fc bad ran: $(cat "$S/ssh.log")"
call PATCH /api/demipass/context/$FCID '{"allowed_commands":["uptime"]}'; [ "$CODE" = 200 ] && ok "removing a command (narrowing) needs no PIN" || fail "fc narrow: $CODE $BODY"
C=$(use '{"name":"box","action":"ssh_exec","target_host":"100.83.112.88","target_user":"deploy","command":"cat","sudo":"yes"}'); [ "$C" = 400 ] && ok "sudo must be true or 'password'" || fail "sudo type: $C"
C=$(use '{"name":"box","action":"ssh_exec","target_host":"100.83.112.88","target_user":"deploy","command":"cat","sudo":"password","key_name":"k"}'); [ "$C" = 403 ] && ok "sudo:'password' with key_name refused" || fail "sudo key_name: $C"
BIG=$(python3 -c 'print("x"*70000)'); C=$(use "{\"name\":\"box\",\"action\":\"ssh_exec\",\"target_host\":\"100.83.112.88\",\"target_user\":\"deploy\",\"command\":\"cat\",\"stdin\":\"$BIG\"}"); [ "$C" = 400 ] && ok "stdin over 64 KiB refused" || fail "big stdin: $C"
C=$(rot '{"ref":"DP-PWD-nul-0001","target_host":"100.83.112.88","target_user":"deploy"}')
grep -q 'tail' "$S/last.json" && fail "a stored password leaked into the error: $(cat "$S/last.json")" || ok "a password ssh can't take is refused without echoing it ($C)"
C=$(rot '{"ref":"DP-PWD-box-0001","target_host":"10.9.9.9"}'); grep -q '100\.' "$S/last.json" && fail "403 lists whitelisted hosts" || ok "a refused host doesn't learn the whitelist"

echo; [ $fails = 0 ] && echo "ssh no-shell smoke: all ok" || { echo "ssh no-shell smoke: $fails failed"; exit 1; }
