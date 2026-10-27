#!/bin/bash
# Smoke of the password reset (POST /api/identity/forgot-password + /reset-password): boots server.js on a throwaway
# DB with a fake SMTP server and a fake Stalwart admin API, and checks that the reset link is actually mailed (to the
# recovery email when set, else the @dustforge.com address), never written to the server log, still works after the
# wallet is renamed (the mailbox is the current username), and that a reset also updates the local password hash.
# A dead SMTP server still answers 200 and logs the failure without the link. No network.
set -u
W=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
S=$(mktemp -d /tmp/dustforge-reset-smoke.XXXXXX)
PORT=${PORT:-3781}; SMTP_PORT=${SMTP_PORT:-3782}; STW_PORT=${STW_PORT:-3783}; API=http://127.0.0.1:$PORT
[ -d "$W/node_modules" ] || export NODE_PATH=${NODE_PATH:-/home/flimflam/project/dustforge/node_modules}
export IDENTITY_MASTER_KEY=$(python3 -c 'import secrets;print(secrets.token_hex(32))') DB_PATH=$S/dustforge.db PORT \
  STALWART_HOST=127.0.0.1 STALWART_PORT=$STW_PORT SMTP_RELAY_HOST= SMTP_HOST=127.0.0.1 SMTP_PORT
cd "$W"
# Fake SMTP (appends each message to mail.log) and fake Stalwart (appends "PATCH <name> <body>" to stalwart.log).
node -e '
const net = require("net"), http = require("http"), fs = require("fs");
const [smtpPort, stwPort, dir] = process.argv.slice(1);
net.createServer(sock => {
  let data = false, buf = "", msg = "";
  sock.write("220 fake ESMTP\r\n");
  sock.on("data", chunk => {
    buf += chunk.toString();
    let i;
    while ((i = buf.indexOf("\r\n")) >= 0) {
      const line = buf.slice(0, i); buf = buf.slice(i + 2);
      if (data) {
        if (line === ".") { data = false; fs.appendFileSync(dir + "/mail.log", msg + "\n=====\n"); msg = ""; sock.write("250 ok\r\n"); }
        else msg += line + "\n";
        continue;
      }
      const v = line.slice(0, 4).toUpperCase();
      if (v === "EHLO" || v === "HELO") sock.write("250 fake\r\n");
      else if (v === "DATA") { data = true; sock.write("354 go\r\n"); }
      else if (v === "QUIT") { sock.end("221 bye\r\n"); }
      else sock.write("250 ok\r\n");
    }
  });
}).listen(Number(smtpPort), "127.0.0.1");
http.createServer((req, res) => {
  let b = ""; req.on("data", c => b += c);
  req.on("end", () => {
    if (req.method === "PATCH") fs.appendFileSync(dir + "/stalwart.log", "PATCH " + decodeURIComponent(req.url.split("/").pop()) + " " + b + "\n");
    res.writeHead(req.method === "PATCH" ? 200 : 404, { "content-type": "application/json" });
    res.end(req.method === "PATCH" ? "{\"data\":null}" : "{}");
  });
}).listen(Number(stwPort), "127.0.0.1");
' "$SMTP_PORT" "$STW_PORT" "$S" & FAKE=$!
node server.js >"$S/server.log" 2>&1 & SRV=$!
trap 'kill $SRV $FAKE 2>/dev/null; rm -rf "$S"' EXIT
for i in $(seq 1 40); do curl -s -o /dev/null "$API/" && break; sleep 0.5; done
kill -0 $SRV 2>/dev/null || { echo "server died:"; tail -5 "$S/server.log"; exit 1; }
OLD=oldpass11; H=$(printf '%s' "$OLD" | sha256sum | cut -d' ' -f1)
node -e '
const identity = require("./identity"); const Database = require("better-sqlite3");
const db = new Database(process.env.DB_PATH);
try { db.exec("ALTER TABLE identity_wallets ADD COLUMN password_hash TEXT"); } catch (_) {}
const id = identity.createIdentity();
db.prepare("INSERT INTO identity_wallets (did, username, email, encrypted_private_key, balance_cents, password_hash) VALUES (?, ?, ?, ?, 0, ?)")
  .run(id.did, "reset-old", "reset-old@dustforge.com", id.encrypted_private_key || id.encryptedPrivateKey, process.argv[1]);
' "$H"
fails=0; ok(){ echo "ok   $*"; }; fail(){ echo "FAIL $*"; fails=$((fails+1)); }
Q(){ python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); r=c.execute(sys.argv[2]).fetchone(); print(r[0] if r else '')" "$DB_PATH" "$1"; }
post(){ curl -s -o /dev/null -w '%{http_code}' -X POST "$API$1" -H 'Content-Type: application/json' -d "$2"; }
wait_for(){ for i in $(seq 1 20); do grep -q "$2" "$1" 2>/dev/null && return 0; sleep 0.25; done; return 1; }

# 1. The link is mailed to the @dustforge.com address, and kept out of the log.
[ "$(post /api/identity/forgot-password '{"username":"reset-old"}')" = 200 ] && ok "forgot-password 200" || fail "forgot-password not 200"
TOK=$(Q "select token from password_reset_tokens where username='reset-old' order by id desc limit 1")
wait_for "$S/mail.log" "$TOK" && ok "reset link mailed" || fail "reset link not mailed"
grep -qi '^To: reset-old@dustforge.com' "$S/mail.log" && ok "sent to the account address" || fail "wrong recipient: $(grep -i '^To:' "$S/mail.log")"
wait_for "$S/server.log" "link emailed to reset-old@dustforge.com" && ok "send logged" || fail "send not logged"
grep -q "$TOK" "$S/server.log" && fail "reset link written to the server log" || ok "link not in the server log"

# 2. Renamed since the link was sent: the reset changes the mailbox of the CURRENT username, and the local hash.
python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute(\"update identity_wallets set username='reset-new', email='reset-new@dustforge.com' where username='reset-old'\"); c.commit()" "$DB_PATH"
[ "$(post /api/identity/reset-password "{\"token\":\"$TOK\",\"new_password\":\"newpass22\"}")" = 200 ] && ok "reset-password 200" || fail "reset-password not 200"
grep -q '^PATCH reset-new .*newpass22' "$S/stalwart.log" && ok "mailbox of the current username updated" || fail "stalwart saw: $(cat "$S/stalwart.log" 2>/dev/null)"
grep -q '^PATCH reset-old' "$S/stalwart.log" && fail "old username patched" || ok "old username not touched"
NH=$(printf '%s' newpass22 | sha256sum | cut -d' ' -f1)
[ "$(Q "select password_hash from identity_wallets where username='reset-new'")" = "$NH" ] && ok "local password hash updated" || fail "local hash still old"
[ "$(Q "select used from password_reset_tokens where token='$TOK'")" = 1 ] && ok "token spent" || fail "token not spent"
[ "$(post /api/identity/reset-password "{\"token\":\"$TOK\",\"new_password\":\"again333\"}")" = 400 ] && ok "spent token refused" || fail "spent token reused"

# 3. A recovery email takes precedence.
python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute(\"update identity_wallets set recovery_email='someone@example.com' where username='reset-new'\"); c.commit()" "$DB_PATH"
post /api/identity/forgot-password '{"username":"reset-new"}' >/dev/null
TOK2=$(Q "select token from password_reset_tokens where username='reset-new' order by id desc limit 1")
wait_for "$S/mail.log" "$TOK2" && grep -qi '^To: someone@example.com' "$S/mail.log" && ok "sent to the recovery email" || fail "recovery email not used"

# 4. SMTP down: still 200, the failure is logged, the link is not.
kill $FAKE 2>/dev/null; wait $FAKE 2>/dev/null
[ "$(post /api/identity/forgot-password '{"username":"reset-new"}')" = 200 ] && ok "forgot-password 200 with SMTP down" || fail "not 200 with SMTP down"
TOK3=$(Q "select token from password_reset_tokens where username='reset-new' order by id desc limit 1")
wait_for "$S/server.log" "email to someone@example.com failed" && ok "failure logged" || fail "failure not logged"
grep -q "$TOK3" "$S/server.log" && fail "link logged on failure" || ok "link not logged on failure"

echo; [ $fails = 0 ] && echo "password reset smoke: all ok" || echo "password reset smoke: $fails FAILED"
exit $fails
