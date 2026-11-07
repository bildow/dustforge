#!/bin/bash
# Threat model items 6a/6b: a mail forwarding rule must not become an account takeover, and the owner hears about it.
# server.js on a throwaway DB, fake SMTP (mail.log) and fake Stalwart admin API; the phone simulated (P-256).
#   legacy: a password_reset_tokens table from before (no sent_to) keeps its rows; such a link counts as mailbox-sent.
#   6a: under a forwarding rule younger than 48 h (no recovery email): no reset link is sent; a link sent before is
#       refused; a sign-in code is neither sent (request-2fa, login-code) nor accepted (verify, login-code/verify);
#       turning a rule on kills the live mailbox links and codes; a link to a recovery email still works; at 48 h it
#       all works again.
#   6b: turning a rule on takes the PIN on a wallet with one (re-saving an active rule does not); the owner is mailed
#       at the recovery address too; the linked phone's alerts call lists the rule for 48 hours.
set -u
W=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
S=$(mktemp -d /tmp/dustforge-fwd-smoke.XXXXXX)
PORT=${PORT:-3821}; SMTP_PORT=${SMTP_PORT:-3822}; STW_PORT=${STW_PORT:-3823}; API=http://127.0.0.1:$PORT
[ -d "$W/node_modules" ] || export NODE_PATH=${NODE_PATH:-/home/flimflam/project/dustforge/node_modules}
export IDENTITY_MASTER_KEY=$(python3 -c 'import secrets;print(secrets.token_hex(32))') DB_PATH=$S/dustforge.db PORT \
  STALWART_HOST=127.0.0.1 STALWART_PORT=$STW_PORT SMTP_RELAY_HOST= SMTP_HOST=127.0.0.1 SMTP_PORT
cd "$W"
node -e '
const net = require("net"), http = require("http"), fs = require("fs");
const [smtpPort, stwPort, dir] = process.argv.slice(1);
net.createServer(sock => { let data = false, buf = "", msg = ""; sock.write("220 fake ESMTP\r\n");
  sock.on("data", chunk => { buf += chunk.toString(); let i;
    while ((i = buf.indexOf("\r\n")) >= 0) { const line = buf.slice(0, i); buf = buf.slice(i + 2);
      if (data) { if (line === ".") { data = false; fs.appendFileSync(dir + "/mail.log", msg + "\n=====\n"); msg = ""; sock.write("250 ok\r\n"); } else msg += line + "\n"; continue; }
      const v = line.slice(0, 4).toUpperCase();
      if (v === "EHLO" || v === "HELO") sock.write("250 fake\r\n"); else if (v === "DATA") { data = true; sock.write("354 go\r\n"); }
      else if (v === "QUIT") sock.end("221 bye\r\n"); else sock.write("250 ok\r\n"); } }); }).listen(Number(smtpPort), "127.0.0.1");
http.createServer((req, res) => { let b = ""; req.on("data", c => b += c); req.on("end", () => {
  res.writeHead(req.method === "PATCH" ? 200 : 404, { "content-type": "application/json" }); res.end(req.method === "PATCH" ? "{\"data\":null}" : "{}"); }); })
  .listen(Number(stwPort), "127.0.0.1");' "$SMTP_PORT" "$STW_PORT" "$S" & FAKE=$!
# legacy fixture: the reset table as main had it, one live row (no sent_to)
python3 - "$DB_PATH" <<'EOF'
import sqlite3, sys
c = sqlite3.connect(sys.argv[1])
c.executescript("""CREATE TABLE password_reset_tokens (id INTEGER PRIMARY KEY AUTOINCREMENT, did TEXT NOT NULL, username TEXT NOT NULL,
  token TEXT NOT NULL UNIQUE, expires_at TEXT NOT NULL, used INTEGER DEFAULT 0, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
INSERT INTO password_reset_tokens (did, username, token, expires_at) VALUES ('did:key:zLegacy', 'legacy', 'legacy-token-0001', '2099-01-01T00:00:00Z');""")
c.commit()
EOF
node server.js >"$S/server.log" 2>&1 & SRV=$!
trap 'kill $SRV $FAKE 2>/dev/null; rm -rf "$S"' EXIT
for i in $(seq 1 40); do curl -s -o /dev/null "$API/" && break; sleep 0.5; done
kill -0 $SRV 2>/dev/null || { echo "server died:"; tail -5 "$S/server.log"; exit 1; }
fails=0; ok(){ echo "ok   $*"; }; fail(){ echo "FAIL $*"; fails=$((fails+1)); }
J(){ python3 -c 'import json,sys; d=json.load(sys.stdin); v=d
for k in sys.argv[1].split("."):
    v = v[int(k)] if isinstance(v, list) else (v or {}).get(k)
print(v)' "$1"; }
Q(){ python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); r=c.execute(sys.argv[2]).fetchone(); print(r[0] if r else '')" "$DB_PATH" "$1"; }
X(){ python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute(sys.argv[2]); c.commit()" "$DB_PATH" "$1"; }
call(){ local m=$1 p=$2 t=$3 b=${4:-}
  BODY=$(curl -s -o - -w '\n%{http_code}' -X "$m" "$API$p" -H 'Content-Type: application/json' ${t:+-H "Authorization: Bearer $t"} ${b:+-d "$b"})
  CODE=${BODY##*$'\n'}; BODY=${BODY%$'\n'*}; }
jb(){ python3 -c 'import json,sys; print(json.dumps(dict(zip(sys.argv[1::2], sys.argv[2::2]))))' "$@"; }
[ "$(Q "SELECT COUNT(*) FROM pragma_table_info('password_reset_tokens') WHERE name='sent_to'")" = 1 ] && [ "$(Q "SELECT used || '/' || COALESCE(sent_to,'null') FROM password_reset_tokens WHERE token='legacy-token-0001'")" = 0/null ] \
  && ok "legacy reset table: the old row is kept, sent_to added (NULL)" || fail "legacy migration"
node -e '
const identity = require("./identity"); const Database = require("better-sqlite3"); const pw = require("./passwords");
(async () => { const db = new Database(process.env.DB_PATH);
for (const [u, rec] of [["victim", ""], ["withrec", "withrec-owner@example.org"], ["owner", "owner-rec@example.org"], ["person", ""]]) {
  const id = identity.createIdentity(); const enc = id.encrypted_private_key || id.encryptedPrivateKey;
  db.prepare("INSERT INTO identity_wallets (did, username, email, encrypted_private_key, balance_cents, password_hash, recovery_email) VALUES (?, ?, ?, ?, 100000, ?, ?)").run(id.did, u, u + "@dustforge.com", enc, await pw.hashPassword("pass-" + u + "-9!"), rec);
  db.prepare("INSERT INTO identity_transactions (did, amount_cents, type, description, balance_after) VALUES (?, 100000, ?, ?, 100000)").run(id.did, "topup", "smoke"); } })();'
sleep 1
login(){ call POST /api/identity/auth-fingerprint "" "$(jb username "$1" password "pass-$1-9!" scope transact expires_in 2h)"; echo "$BODY" | J token; }
# victim is a fleet agent of owner (no PIN, no recovery email, no phone: the token path, item 6a's clock); person is a
# person with none of those (#70 review L4).
X "INSERT INTO fleets (owner_did, name, slug) VALUES ((SELECT did FROM identity_wallets WHERE username='owner'), 'Owner agents', 'owner-agents')"
X "INSERT INTO fleet_silicons (fleet_id, member_did, handle, silicon_id, status, created_by_fleet, joined_via) VALUES ((SELECT id FROM fleets WHERE slug='owner-agents'), (SELECT did FROM identity_wallets WHERE username='victim'), 'victim', 'sil_fwd1', 'active', 1, 'owner')"
V=$(login victim); R=$(login withrec); O=$(login owner); P=$(login person)
VD=$(Q "SELECT did FROM identity_wallets WHERE username='victim'"); OD=$(Q "SELECT did FROM identity_wallets WHERE username='owner'")
age(){ X "UPDATE forward_relays SET activated_at=datetime('now','-3 days'), created_at=datetime('now','-3 days') WHERE did=(SELECT did FROM identity_wallets WHERE username='$1')"; }
resets(){ Q "SELECT COUNT(*) FROM password_reset_tokens WHERE did=(SELECT did FROM identity_wallets WHERE username='$1')"; }

# ── 6a ──
call POST /api/identity/forgot-password "" '{"username":"victim"}'; sleep 0.3; LINK1=$(Q "SELECT token FROM password_reset_tokens WHERE did='$VD' AND used=0")
[ -n "$LINK1" ] && [ "$(Q "SELECT sent_to FROM password_reset_tokens WHERE token='$LINK1'")" = mailbox ] && ok "a reset link records where it went (mailbox)" || fail "sent_to"
call POST /api/identity/request-2fa "" "$(jb did "$VD")"; LC=$(Q "SELECT code FROM identity_2fa_codes WHERE did='$VD' AND purpose='login' AND used=0")
call POST /api/relay/create "$V" '{"forward_to":"attacker@example.net"}'
[ "$CODE" = 200 ] && ok "a session token turns on a forward on a fleet agent's wallet (no PIN: the token path)" || fail "relay create: $CODE $BODY"
sleep 1.5; grep -q "an agent turned on mail forwarding" "$S/mail.log" && grep -q "owner-rec@example.org" "$S/mail.log" && ok "…and its fleet owner is mailed (L4)" || fail "fleet owner notice"
[ "$(Q "SELECT used FROM password_reset_tokens WHERE token='$LINK1'")" = 1 ] && [ "$(Q "SELECT COUNT(*) FROM identity_2fa_codes WHERE did='$VD' AND purpose='login' AND used=0")" = 0 ] \
  && ok "turning a rule on kills the live mailbox reset link and sign-in code" || fail "kill on activate"
call POST /api/identity/reset-password "" "$(jb token "$LINK1" new_password brandnew-pass-1)"; [ "$CODE" = 400 ] && ok "…so that link no longer resets" || fail "old link: $CODE $BODY"
N=$(resets victim); call POST /api/identity/forgot-password "" '{"username":"victim"}'; sleep 0.3
[ "$CODE" = 200 ] && [ "$(resets victim)" = "$N" ] && ok "under a forward < 48 h and no recovery email: no reset link (same reply)" || fail "withheld: $CODE $(resets victim) vs $N"
NC=$(Q "SELECT COUNT(*) FROM identity_2fa_codes WHERE did='$VD'")
call POST /api/identity/request-2fa "" "$(jb did "$VD")"
[ "$CODE" = 200 ] && [ "$(echo "$BODY" | J emailed)" = True ] && [ "$(Q "SELECT COUNT(*) FROM identity_2fa_codes WHERE did='$VD'")" = "$NC" ] \
  && ok "request-2fa (no session): the ordinary reply, and no code exists or is sent under a fresh forward (L5)" || fail "request-2fa: $CODE $BODY"
X "INSERT INTO identity_2fa_codes (did, code, expires_at, purpose) VALUES ('$VD', '424242', datetime('now','+10 minutes'), 'login')"
call POST /api/identity/verify "" "$(jb did "$VD" code 424242 scope transact)"; [ "$CODE" = 403 ] && ok "verify: a right code is refused under a fresh forward" || fail "verify: $CODE $BODY"
call POST /api/identity/login-code/request "" '{"username":"victim"}'; [ "$(Q "SELECT COUNT(*) FROM identity_2fa_codes WHERE did='$VD' AND used=0")" = 0 ] && ok "login-code: none issued either" || fail "login-code issued"
X "INSERT INTO password_reset_tokens (did, username, token, expires_at) VALUES ('$VD', 'victim', 'legacy-style-0002', '2099-01-01T00:00:00Z')"
call POST /api/identity/reset-password "" "$(jb token legacy-style-0002 new_password brandnew-pass-2)"
[ "$CODE" = 403 ] && [ "$(Q "SELECT used FROM password_reset_tokens WHERE token='legacy-style-0002'")" = 1 ] && ok "a link with no sent_to (from before) counts as mailbox-sent: refused and killed" || fail "legacy link: $CODE $BODY"
call POST /api/relay/create "$R" '{"forward_to":"someone@example.net"}'
call POST /api/identity/forgot-password "" '{"username":"withrec"}'; sleep 0.3
RL=$(Q "SELECT token FROM password_reset_tokens WHERE did=(SELECT did FROM identity_wallets WHERE username='withrec') AND used=0")
[ -n "$RL" ] && [ "$(Q "SELECT sent_to FROM password_reset_tokens WHERE token='$RL'")" = recovery ] && ok "with a recovery email the link still goes (to it) under a fresh forward" || fail "recovery link not sent"
call POST /api/identity/reset-password "" "$(jb token "$RL" new_password brandnew-pass-3)"; [ "$CODE" = 200 ] && ok "…and resets" || fail "recovery reset: $CODE $BODY"
age victim; X "UPDATE password_reset_tokens SET created_at=datetime('now','-2 hours') WHERE did='$VD'"   # past the 5-minute mail limit
call POST /api/identity/forgot-password "" '{"username":"victim"}'; sleep 0.3; LINK2=$(Q "SELECT token FROM password_reset_tokens WHERE did='$VD' AND used=0")
call POST /api/identity/reset-password "" "$(jb token "$LINK2" new_password brandnew-pass-4)"; A1=$CODE
call POST /api/identity/request-2fa "" "$(jb did "$VD")"
[ -n "$LINK2" ] && [ "$A1" = 200 ] && [ "$CODE" = 200 ] && ok "once the rule is 48 h old, reset links and codes work again" || fail "aged: link=$LINK2 reset=$A1 code=$CODE"

call POST /api/relay/create "$P" '{"forward_to":"p-fwd@example.org"}'
[ "$CODE" = 409 ] && [ "$(echo "$BODY" | J need)" = recovery_email_or_phone ] && ok "a person with no recovery email and no phone cannot turn a forward on (L4)" || fail "L4: $CODE $BODY"

# ── 6b ──
call POST /api/identity/pin "$O" "$(jb pin 4321 password pass-owner-9!)"; [ "$CODE" = 200 ] || fail "pin set: $CODE"
call POST /api/relay/create "$O" '{"forward_to":"owner-fwd@example.org"}'
[ "$CODE" = 403 ] && [ "$(echo "$BODY" | J intent)" = forward:0 ] && [ "$(Q "SELECT COUNT(*) FROM forward_relays WHERE did='$OD'")" = 0 ] && ok "a wallet with a PIN: turning a forward on asks for it (forward:0), nothing created" || fail "pin required: $CODE $BODY"
AGT=$(node -e 'const identity=require("./identity"),Database=require("better-sqlite3");const db=new Database(process.env.DB_PATH);const w=db.prepare("SELECT did,encrypted_private_key FROM identity_wallets WHERE username=?").get("owner");
process.stdout.write(identity.createTokenForIdentity(w.encrypted_private_key,w.did,{scope:"transact",expiresIn:"1h",metadata:{auth_method:"fleet_owner_mint",fleet:"x"}}))')
call POST /api/relay/create "$AGT" '{"forward_to":"owner-fwd@example.org"}'; [ "$CODE" = 403 ] && ok "an agent token cannot turn one on for that wallet" || fail "agent: $CODE"
: > "$S/mail.log"
X "INSERT INTO identity_2fa_codes (did, code, expires_at, purpose) VALUES ('$OD', '515151', datetime('now','+10 minutes'), 'gate')"
call POST /api/identity/gate/verify "$O" '{"gate":"pin","pin":"4321","intent":"forward:0"}'
call POST /api/relay/create "$O" '{"forward_to":"owner-fwd@example.org"}'; [ "$CODE" = 200 ] && ok "with the PIN it turns on" || fail "with pin: $CODE $BODY"
[ "$(Q "SELECT used FROM identity_2fa_codes WHERE code='515151'")" = 1 ] && ok "turning it on kills the live gate code too (M4)" || fail "gate code alive"
call POST /api/identity/request-2fa "$O" "$(jb did "$OD")"; G1=$CODE
X "INSERT INTO identity_2fa_codes (did, code, expires_at, purpose) VALUES ('$OD', '525252', datetime('now','+10 minutes'), 'gate')"
call POST /api/identity/gate/verify "$O" '{"gate":"twofa","code":"525252"}'
[ "$G1" = 409 ] && [ "$CODE" = 409 ] && ok "the owner's own gate code: not sent, and not accepted, under a fresh forward (M4)" || fail "M4 gate: request $G1 verify $CODE $BODY"
call GET /api/identity/holds "$O"; [ "$(echo "$BODY" | J notices.0.forward_to)" = owner-fwd@example.org ] && ok "the vault page's signed-in holds call carries the notice too (M3)" || fail "holds notices: $BODY"
call POST /api/relay/create "$O" '{"forward_to":"owner-fwd@example.org","label":"gmail"}'; [ "$CODE" = 200 ] && ok "re-saving an active rule needs no PIN (nothing new is copied)" || fail "resave: $CODE $BODY"
sleep 1.5
grep -q "owner-rec@example.org" "$S/mail.log" && grep -q "forwarding" "$S/mail.log" && ok "the owner is mailed at the recovery address (outside the rule)" || fail "notice mail: $(grep -c ===== "$S/mail.log" 2>/dev/null) mails"
[ "$(Q "SELECT COUNT(*) FROM demipass_security_events WHERE event_type='forward_rule_activated' AND caller_did='$OD'")" = 1 ] && ok "one activation event (the re-save is not one)" || fail "events"
# phone: enrol, then the D-signed alerts call lists the new rule
node -e 'const c=require("crypto"),fs=require("fs");for(const n of ["d","p"]){const {privateKey,publicKey}=c.generateKeyPairSync("ec",{namedCurve:"prime256v1"});
fs.writeFileSync(process.argv[1]+"/"+n+".pem",privateKey.export({type:"pkcs8",format:"pem"}));fs.writeFileSync(process.argv[1]+"/"+n+".pub",publicKey.export({type:"spki",format:"der"}).toString("base64"))}' "$S"
sig(){ node -e 'const c=require("crypto"),fs=require("fs"); process.stdout.write(c.sign("sha256", Buffer.from(process.argv[2]), fs.readFileSync(process.argv[1])).toString("base64"))' "$S/$1.pem" "$2"; }
call POST /api/identity/device/challenge "$O" '{"purpose":"enrol","intent":"device-enrol:0"}'; CHD=$(echo "$BODY" | J challenge_id); MSG="$(echo "$BODY" | J message):phone-0001"
call POST /api/identity/gate/verify "$O" '{"gate":"pin","pin":"4321","intent":"device-enrol:0"}'; call POST /api/identity/gate/verify "$O" "$(jb gate password password pass-owner-9!)"
call POST /api/identity/device/enrol "$O" "$(printf '{"challenge_id":%s,"device_id":"phone-0001","label":"Pixel","key_d":"%s","key_p":"%s","sig_d":"%s","sig_p":"%s"}' "$CHD" "$(cat $S/d.pub)" "$(cat $S/p.pub)" "$(sig d "$MSG")" "$(sig p "$MSG")")"
[ "$CODE" = 201 ] || fail "enrol: $CODE $BODY"
alerts(){ call POST /api/identity/holds/challenge "" '{"purpose":"alerts","device_id":"phone-0001"}'; local ch m; ch=$(echo "$BODY" | J challenge); m=$(echo "$BODY" | J message)
  call POST /api/identity/holds/alerts "" "$(jb device_id phone-0001 challenge "$ch" signature "$(sig d "$m")")"; }
alerts; [ "$CODE" = 200 ] && [ "$(echo "$BODY" | J notices.0.kind)" = forward ] && [ "$(echo "$BODY" | J notices.0.forward_to)" = owner-fwd@example.org ] \
  && ok "the phone's alerts call lists the new forward" || fail "alerts: $CODE $BODY"
age owner; alerts; [ "$(echo "$BODY" | python3 -c 'import json,sys; print(len(json.load(sys.stdin).get("notices",[])))')" = 0 ] && ok "…for 48 hours only" || fail "aged notice: $BODY"

[ $fails -gt 0 ] && { echo "--- server.log"; grep -i -m8 "error" "$S/server.log"; }
echo "$fails failure(s)"; exit $(( fails > 0 ))
