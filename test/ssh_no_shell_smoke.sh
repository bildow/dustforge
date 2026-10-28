#!/bin/bash
# Smoke of /api/blindkey/rotate-blind and the SSH helper (sshRun): nothing a caller sends reaches a shell on this
# server. Boots server.js on a throwaway DB with a fake sshpass on PATH that logs its arguments and plays the remote
# host locally (fake sudo + chpasswd). Checks: a target_host carrying a shell command is refused and runs nothing;
# a host off the SSH whitelist and a bad target_user are refused; a rotation hands chpasswd exactly
# "<user>:<new password>" even when the current password is full of shell metacharacters; no password appears in
# sshpass's arguments (SSHPASS carries it); nothing is written under /tmp. No network.
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
if [ "$last" = "bash -s" ]; then PATH=$FAKE_DIR/remote:$PATH bash -s; else bash -c "$last"; fi
SH
cat >"$S/remote/sudo" <<'SH'
#!/bin/bash
read -r pw; printf '%s' "$pw" >"$FAKE_DIR/sudo.pw"; shift; exec "$@"
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
add.run(id.did, "box", "password", seal(process.env.CUR), "active", "DP-PWD-box-0001");'
fails=0; ok(){ echo "ok   $*"; }; fail(){ echo "FAIL $*"; fails=$((fails+1)); }
TOK=$(curl -s -X POST "$API/api/identity/auth-fingerprint" -H 'Content-Type: application/json' -d '{"username":"owner","password":"ownerpass1","scope":"transact"}' | python3 -c 'import json,sys;print(json.load(sys.stdin).get("token",""))')
rot(){ curl -s -o "$S/last.json" -w '%{http_code}' -X POST "$API/api/blindkey/rotate-blind" -H 'Content-Type: application/json' -H "Authorization: Bearer $TOK" -d "$1"; }
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

echo; [ $fails = 0 ] && echo "ssh no-shell smoke: all ok" || { echo "ssh no-shell smoke: $fails failed"; exit 1; }
