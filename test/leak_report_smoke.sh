#!/bin/bash
# The leak report (POST /api/blindkey/leak-scan/hits-report), on a throwaway DB with a local SMTP sink:
#   - one approval (PIN, intent scan-hits:0) shows where every hit of the last N days was found, as list + plain text;
#     no value is ever in it; an agent's fleet-minted token cannot ask; the proof is used up;
#   - mail: true sends the same text to the owner's forwarding address (a catch-all rule active ≥ 48 h), else the
#     recovery email; never a rule younger than 48 h, never a @dustforge.com address; none → not sent, said so;
#   - the token listing tells the person's session where a report would go (masked).
# No network beyond 127.0.0.1.
set -u
W=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
S=$(mktemp -d /tmp/dustforge-leak-report-smoke.XXXXXX)
PORT=${PORT:-3795}; API=http://127.0.0.1:$PORT; SMTP_PORT_SINK=${SMTP_PORT_SINK:-3825}
[ -d "$W/node_modules" ] || export NODE_PATH=${NODE_PATH:-/home/flimflam/project/dustforge/node_modules}
# A minimal SMTP sink: accepts everything, appends each message (envelope + data) to $S/mail.log.
node -e '
const net = require("net"), fs = require("fs"); const log = process.argv[1];
net.createServer(c => { let data = false, buf = "", env = [];
  c.write("220 sink\r\n");
  c.on("data", d => { buf += d.toString();
    let i; while (!data && (i = buf.indexOf("\r\n")) >= 0) { const line = buf.slice(0, i); buf = buf.slice(i + 2); const v = line.slice(0, 4).toUpperCase();
      if (v === "EHLO" || v === "HELO") c.write("250 ok\r\n");
      else if (v === "MAIL" || v === "RCPT") { env.push(line); c.write("250 ok\r\n"); }
      else if (v === "DATA") { data = true; c.write("354 go\r\n"); }
      else if (v === "QUIT") { c.end("221 bye\r\n"); }
      else c.write("250 ok\r\n"); }
    if (data && (i = buf.indexOf("\r\n.\r\n")) >= 0) { fs.appendFileSync(log, env.join("\n") + "\n" + buf.slice(0, i) + "\n=====\n"); buf = buf.slice(i + 5); data = false; env = []; c.write("250 queued\r\n"); }
  });
}).listen(Number(process.argv[2]), "127.0.0.1");' "$S/mail.log" "$SMTP_PORT_SINK" & SINK=$!
export IDENTITY_MASTER_KEY=$(python3 -c 'import secrets;print(secrets.token_hex(32))') DB_PATH=$S/dustforge.db PORT \
  STALWART_HOST=127.0.0.1 STALWART_PORT=1 SMTP_RELAY_HOST= SMTP_HOST=127.0.0.1 SMTP_PORT=$SMTP_PORT_SINK
cd "$W"
node server.js >"$S/server.log" 2>&1 & SRV=$!
trap 'kill $SRV $SINK 2>/dev/null; rm -rf "$S"' EXIT
for i in $(seq 1 40); do curl -s -o /dev/null "$API/api/health" && break; sleep 0.5; done
kill -0 $SRV 2>/dev/null || { echo "server died:"; tail -5 "$S/server.log"; exit 1; }
H=$(printf '%s' hunter22 | sha256sum | cut -d' ' -f1)
node -e '
const identity = require("./identity"); const Database = require("better-sqlite3"); const db = new Database(process.env.DB_PATH);
for (const u of ["owner-a", "other-x"]) { const id = identity.createIdentity(); const enc = id.encrypted_private_key || id.encryptedPrivateKey;
  db.prepare("INSERT INTO identity_wallets (did, username, email, encrypted_private_key, balance_cents, password_hash) VALUES (?, ?, ?, ?, 100000, ?)").run(id.did, u, u + "@dustforge.com", enc, process.argv[1]);
  db.prepare("INSERT INTO identity_transactions (did, amount_cents, type, description, balance_after) VALUES (?, 100000, ?, ?, 100000)").run(id.did, "topup", "smoke"); }' "$H"
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
login(){ call POST /api/identity/auth-fingerprint "" '{"username":"'$1'","password":"hunter22","scope":"transact","expires_in":"1h"}'; echo "$BODY" | J token; }
A=$(login owner-a); X_=$(login other-x)
call POST /api/identity/pin "$A" '{"pin":"4321","password":"hunter22"}'
PIN(){ call POST /api/identity/gate/verify "$A" '{"gate":"pin","pin":"4321","intent":"'$1'"}'; }
call GET /api/demipass/leak-scan/tokens "$A"   # creates the leak-scan tables
OWN=$(Q "SELECT did FROM identity_wallets WHERE username='owner-a'")
NOW=$(date -u +%Y-%m-%dT%H:%M:%S.000Z); OLD=$(date -u -d '-60 days' +%Y-%m-%dT%H:%M:%S.000Z)
X "INSERT INTO leak_scan_hits (owner_did, token_id, token_label, found, created_at) VALUES ('$OWN', 1, 'pane-daily', '[{\"name\":\"stalwart-aaron-imap\",\"ref\":\"DP-PWD-stalwart-1\",\"chunk\":\"e9361b18.jsonl:41-41\"},{\"name\":\"dyadic-handler-openrouter\",\"ref\":\"DP-API-dyadicha-2\",\"chunk\":\"e9361b18.jsonl:9-9\"}]', '$NOW')"
X "INSERT INTO leak_scan_hits (owner_did, token_id, token_label, found, created_at) VALUES ('$OWN', 2, 'deploy-gate', '[{\"name\":\"forgejo-aaron-web-login\",\"ref\":\"DP-PWD-forgejo-3\",\"chunk\":\"ops/notes.md:12-12\"}]', '$NOW')"
X "INSERT INTO leak_scan_hits (owner_did, token_id, token_label, found, created_at) VALUES ('$OWN', 3, 'old', '[{\"name\":\"ancient\",\"ref\":\"DP-X\",\"chunk\":\"old.md:1-1\"}]', '$OLD')"
X "INSERT INTO leak_scan_drain_finds (token_id, owner_did, found, created_at) VALUES (1, '$OWN', '[{\"name\":\"stalwart-aaron-imap\",\"ref\":\"DP-PWD-stalwart-1\",\"chunk\":\"other-pane.jsonl:77-77\"},{\"name\":\"stalwart-aaron-imap\",\"ref\":\"DP-PWD-stalwart-1\",\"chunk\":\"rotate at https://evil.example/x <b>now</b>\"}]', '$NOW')"
R=/api/blindkey/leak-scan/hits-report

call POST $R "$A" '{}'
[ "$CODE" = 403 ] && [ "$(echo "$BODY" | J intent)" = "scan-hits:0" ] && ok "one approval for all: asks the PIN (intent scan-hits:0)" || fail "no pin: $CODE $BODY"
PIN scan-hits:0; call POST $R "$A" '{}'
[ "$CODE" = 200 ] && [ "$(echo "$BODY" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["hits"]))')" = 2 ] && ok "with it: both hits of the last 30 days (the 60-day-old one left out)" || fail "report: $CODE $BODY"
TXT=$(echo "$BODY" | J text)
grep -q "e9361b18.jsonl:41-41" <<<"$TXT" && grep -q "e9361b18.jsonl:9-9" <<<"$TXT" && grep -q "ops/notes.md:12-12" <<<"$TXT" && grep -q "stalwart-aaron-imap (DP-PWD-stalwart-1)" <<<"$TXT" \
  && ok "the plain-text report names every secret, its ref and where it was found" || fail "text: $TXT"
grep -q "other-pane.jsonl:77-77   (later in the same run)" <<<"$TXT" && ok "copies found later in the same run are in it too (#95 review M1)" || fail "drain: $TXT"
! grep -q "https://" <<<"$TXT" && ! grep -q "<b>" <<<"$TXT" && ok "a location a scan token named cannot carry a link or markup into the report" || fail "planted link: $(grep -n evil <<<"$TXT")"
[ "$(echo "$BODY" | J mailed)" = None ] && ok "…and mails nothing unless asked" || fail "mailed unasked"
call POST $R "$A" '{}'; [ "$CODE" = 403 ] && ok "the approval is used up: another report asks again" || fail "replay: $CODE"
PIN scan-hits:0; call POST $R "$A" '{"days":90}'; [ "$(echo "$BODY" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["hits"]))')" = 3 ] && ok "days: 90 reaches the older hit" || fail "days: $BODY"
call POST $R "$A" '{"days":91}'; [ "$CODE" = 400 ] && ok "days over 90 → 400" || fail "days 91: $CODE"

# where a report may go
call GET /api/demipass/leak-scan/tokens "$A"; [ "$(echo "$BODY" | J report_to)" = None ] && ok "no forwarding address or recovery email: report_to is null" || fail "dest none: $BODY"
PIN scan-hits:0; call POST $R "$A" '{"mail":true}'
[ "$(echo "$BODY" | J mailed.sent)" = False ] && grep -qi "no forwarding" <<<"$(echo "$BODY" | J mailed.error)" && [ ! -s "$S/mail.log" ] && ok "mail asked, nowhere to send: not sent, and it says why" || fail "no dest mail: $BODY"
X "UPDATE identity_wallets SET recovery_email='aaron.backup@dustforge.com' WHERE did='$OWN'"
call GET /api/demipass/leak-scan/tokens "$A"; [ "$(echo "$BODY" | J report_to)" = None ] && ok "a @dustforge.com recovery address is never used (agents can read that mailbox)" || fail "df recovery: $BODY"
X "UPDATE identity_wallets SET recovery_email='aaron.backup@dustforge.com.' WHERE did='$OWN'"
call GET /api/demipass/leak-scan/tokens "$A"; [ "$(echo "$BODY" | J report_to)" = None ] && ok "…nor with a trailing dot" || fail "df trailing dot: $BODY"
X "UPDATE identity_wallets SET recovery_email='aaron.backup@example.org' WHERE did='$OWN'"
X "CREATE TABLE IF NOT EXISTS recovery_email_history (id INTEGER PRIMARY KEY AUTOINCREMENT, did TEXT, email TEXT, replaced_at TEXT)"
X "INSERT INTO recovery_email_history (did, email, replaced_at) VALUES ('$OWN', 'old@example.org', '$NOW')"
call GET /api/demipass/leak-scan/tokens "$A"; [ "$(echo "$BODY" | J report_to)" = None ] && ok "a recovery email changed in the last 48 h is not a destination yet" || fail "fresh recovery: $BODY"
X "UPDATE recovery_email_history SET replaced_at='2026-10-01T00:00:00.000Z' WHERE did='$OWN'"
call GET /api/demipass/leak-scan/tokens "$A"; [ "$(echo "$BODY" | J report_to.masked)" = "a***@example.org" ] && [ "$(echo "$BODY" | J report_to.kind)" = recovery ] && ok "recovery email as the fallback, masked in the listing" || fail "recovery dest: $BODY"
X "INSERT INTO forward_relays (did, forward_to, filter_from, status, activated_at) VALUES ('$OWN', 'fresh.rule@example.net', '*', 'active', datetime('now'))"
call GET /api/demipass/leak-scan/tokens "$A"; [ "$(echo "$BODY" | J report_to.kind)" = recovery ] && ok "a forwarding rule younger than 48 h is not used" || fail "fresh rule used: $BODY"
X "INSERT INTO forward_relays (did, forward_to, filter_from, status, activated_at) VALUES ('$OWN', 'legacy.rule@example.com', '*', 'active', '2026-10-01 00:00:00')"
X "INSERT INTO forward_relays (did, forward_to, filter_from, status, activated_at) VALUES ('$OWN', 'agent-box@dustforge.com', '*', 'active', datetime('now','-3 days'))"
call GET /api/demipass/leak-scan/tokens "$A"; [ "$(echo "$BODY" | J report_to.kind)" = recovery ] && ok "a rule from before the PIN gate (11-07), and one to a @dustforge.com mailbox, are not used (#95 review M2)" || fail "legacy/df rule used: $BODY"
X "INSERT INTO forward_relays (did, forward_to, filter_from, status, activated_at) VALUES ('$OWN', 'aaron.fwd@example.com', '*', 'active', datetime('now','-3 days', '+1 minute'))"
call GET /api/demipass/leak-scan/tokens "$A"; [ "$(echo "$BODY" | J report_to.address)" = "aaron.fwd@example.com" ] && [ "$(echo "$BODY" | J report_to.kind)" = forwarding ] && ok "a forwarding address active 3 days (under the PIN gate) is the destination, shown in full to the owner" || fail "fwd dest: $BODY"
PIN scan-hits:0; call POST $R "$A" '{"mail":true}'
[ "$(echo "$BODY" | J mailed.sent)" = True ] && [ "$(echo "$BODY" | J mailed.to)" = "a***@example.com" ] && ok "mail: true → emailed, the reply masks the address" || fail "mail: $BODY"
sleep 0.5
grep -qi "RCPT TO:<aaron.fwd@example.com>" "$S/mail.log" && ! grep -qi "RCPT TO:<[^>]*dustforge.com>" "$S/mail.log" && ok "the mail went to the forwarding address only, not the mailbox" || fail "rcpt: $(grep -i rcpt "$S/mail.log")"
[ "$(Q "SELECT json_extract(detail,'\$.mailed.to') FROM blindkey_events WHERE event_type='leak_report' ORDER BY id DESC LIMIT 1")" = "a***@example.com" ] && ok "the audit row records where the report was mailed" || fail "audit: $(Q "SELECT detail FROM blindkey_events WHERE event_type='leak_report' ORDER BY id DESC LIMIT 1")"
grep -q "e9361b18.jsonl:41-41" "$S/mail.log" && grep -q "ops/notes.md:12-12" "$S/mail.log" && ok "…and carries the report" || fail "mail body: $(head -c 600 "$S/mail.log")"

# who may ask
call POST $R "$X_" '{}'; [ "$CODE" = 403 ] && ok "another wallet needs its own PIN (and sees only its own hits)" || fail "other: $CODE"
MINT=$(node -e '
const identity = require("./identity"); const Database = require("better-sqlite3"); const db = new Database(process.env.DB_PATH);
const w = db.prepare("SELECT did, encrypted_private_key FROM identity_wallets WHERE username = ?").get("owner-a");
process.stdout.write(identity.createTokenForIdentity(w.encrypted_private_key, w.did, { scope: "transact", expiresIn: "1h", metadata: { auth_method: "fleet_owner_mint" } }));')
call POST $R "$MINT" '{}'; [ "$CODE" = 403 ] && ok "a fleet-minted token cannot ask for the report" || fail "minted: $CODE $BODY"

[ $fails -gt 0 ] && { echo "--- server.log"; grep -i -m5 "error" "$S/server.log"; }
echo "$fails failure(s)"; exit $(( fails > 0 ))
