#!/bin/bash
# End-to-end smoke of security depth on use (use_approvals.js, docs/approvals.md): server.js on a throwaway DB, /use's
# fetch() to repo.dustroot.com sent to a local stand-in. Owner A (PIN), person K (PIN, a share of A's secret).
#   - standard: /use works as before;
#   - elevated: the first /use parks (202 approval_pending, request id, refunded), the same call again returns the
#     same request, no code exists before the owner opens it, the agent's /use with the current code acts once,
#     Approve (code sent by the app) lets the next /use act once, a request binds the exact call, three wrong codes
#     cancel it (critical event), deny and expiry end it, a code is valid only for its own request and ~1 minute;
#   - critical: the PIN opens the request screen; Approve only from the session that opened it; reveal takes an
#     approved request + the PIN;
#   - shares inherit depth: K's /use on A's elevated secret parks on A's approval; nobody else can use K's request;
#   - audit on both accounts; no secret value or code in the server log.
set -u
W=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
S=$(mktemp -d /tmp/dustforge-approvals-smoke.XXXXXX)
PORT=${PORT:-3787}; UP_PORT=${UP_PORT:-3788}; API=http://127.0.0.1:$PORT
[ -d "$W/node_modules" ] || export NODE_PATH=${NODE_PATH:-/home/flimflam/project/dustforge/node_modules}
export IDENTITY_MASTER_KEY=$(python3 -c 'import secrets;print(secrets.token_hex(32))') DB_PATH=$S/dustforge.db PORT \
  STALWART_HOST=127.0.0.1 STALWART_PORT=1 SMTP_RELAY_HOST= SMTP_HOST=127.0.0.1 SMTP_PORT=9 TEST_UPSTREAM=http://127.0.0.1:$UP_PORT
cd "$W"
SEC='elevated-forge-token-91c2e4'
node -e '
const http = require("http");
http.createServer((req, res) => { req.resume(); req.on("end", () => { res.writeHead(200, { "content-type": "application/json" }); res.end(JSON.stringify({ path: req.url, seen: req.headers.authorization || "" })); }); })
  .listen(+process.argv[1], "127.0.0.1");' $UP_PORT & UP=$!
node --require ./test/fixtures/upstream-redirect.js server.js >"$S/server.log" 2>&1 & SRV=$!
trap 'kill $SRV $UP 2>/dev/null; rm -rf "$S"' EXIT
for i in $(seq 1 40); do curl -s -o /dev/null "$API/" && break; sleep 0.5; done
kill -0 $SRV 2>/dev/null || { echo "server died:"; tail -5 "$S/server.log"; exit 1; }
H=$(printf '%s' hunter22 | sha256sum | cut -d' ' -f1)
node -e '
const identity = require("./identity"); const Database = require("better-sqlite3");
const db = new Database(process.env.DB_PATH);
for (const c of ["idempotency_key TEXT", "provenance TEXT DEFAULT '"'"'organic'"'"'"]) { try { db.exec("ALTER TABLE identity_transactions ADD COLUMN " + c); } catch (_) {} }
for (const u of ["owner-a", "person-k", "other-x"]) {
  const id = identity.createIdentity(); const enc = id.encrypted_private_key || id.encryptedPrivateKey;
  db.prepare("INSERT INTO identity_wallets (did, username, email, encrypted_private_key, balance_cents, password_hash) VALUES (?, ?, ?, ?, 100000, ?)").run(id.did, u, u + "@dustforge.com", enc, process.argv[1]);
  db.prepare("INSERT INTO identity_transactions (did, amount_cents, type, description, balance_after) VALUES (?, 100000, ?, ?, 100000)").run(id.did, "topup", "smoke");
}' "$H"
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
# the code a request shows at a given 30-s step offset (0 = now), computed from its key like the server does
codeat(){ python3 -c "
import sqlite3,sys,hmac,hashlib,time
c=sqlite3.connect(sys.argv[1]); k=c.execute('SELECT code_key FROM use_approvals WHERE id=?',(int(sys.argv[2]),)).fetchone()[0]
sid,req=c.execute('SELECT secret_id, requester_did FROM use_approvals WHERE id=?',(int(sys.argv[2]),)).fetchone()
st=int(time.time()//30)+int(sys.argv[3]); m=hmac.new(bytes.fromhex(k), f'dp-approval:{sys.argv[2]}:{sid}:{req}:{st}'.encode(), hashlib.sha256).digest()
print(str(int.from_bytes(m[:4],'big')%1000000).zfill(6))" "$DB_PATH" "$1" "${2:-0}"; }
bal(){ Q "SELECT balance_cents FROM identity_wallets WHERE username='$1'"; }
aopen(){ pin "$A" 4321 "approval-open:$1"; call POST /api/demipass/approvals/$1/open "$A"; }
A=$(login owner-a); A2=$(login owner-a); AG=$(login owner-a); K=$(login person-k); X=$(login other-x)
call POST /api/identity/pin "$A" '{"pin":"4321","password":"hunter22"}'; call POST /api/identity/pin "$K" '{"pin":"8765","password":"hunter22"}'
call POST /api/network/requests "$A" '{"to":"person-k","as":"person"}'; R=$(echo "$BODY" | J request.id); call POST /api/network/requests/$R/accept "$K"
call POST /api/demipass/store "$A" "$(jbody name forge-token value "$SEC" secret_type api_key)"; REF=$(echo "$BODY" | J ref)
SID=$(Q "SELECT id FROM blindkey_secrets WHERE ref_code='$REF'")
USE(){ jbody ref "$REF" params "{\"url\":\"https://repo.dustroot.com/$1\",\"method\":\"GET\"}" ${2:+approval_id $2} ${3:+approval_code $3} ${4:+purpose "$4"}; }

# ── standard ──
call POST /api/demipass/use "$AG" "$(USE std)"; [ "$CODE" = 200 ] && ok "standard: /use acts at once" || fail "standard: $CODE $BODY"

# ── elevated ──
call POST /api/demipass/gate-policy "$A" "$(jbody ref "$REF" security_depth elevated)"; [ "$CODE" = 200 ] || fail "set elevated: $CODE $BODY"
B0=$(bal owner-a)
call POST /api/demipass/use "$AG" "$(USE deploy "" "" "deploy the site")"
AP=$(echo "$BODY" | J approval_id)
[ "$CODE" = 202 ] && [ "$(echo "$BODY" | J status)" = approval_pending ] && [ -n "$AP" ] && echo "$BODY" | grep -q "Park this task" && ok "elevated: the first /use parks — 202 approval_pending, request $AP, told to park" || fail "park: $CODE $BODY"
[ "$(bal owner-a)" = "$((B0-10))" ] && ok "a parked /use is charged like any /use (10 DD; no refund, so the DD ledger stays whole)" || fail "charge: $B0 → $(bal owner-a)"
[ "$(Q "SELECT summary FROM use_approvals WHERE id=$AP")" = "http_header https://repo.dustroot.com/deploy" ] && [ "$(Q "SELECT json_extract(bound_call,'$.body.params.url') FROM use_approvals WHERE id=$AP")" = "https://repo.dustroot.com/deploy" ] && [ "$(Q "SELECT purpose FROM use_approvals WHERE id=$AP")" = "deploy the site" ] && ok "the request names the exact call and the purpose" || fail "summary: $(Q "SELECT summary||' | '||purpose FROM use_approvals WHERE id=$AP")"
[ -n "$(Q "SELECT notified_at FROM use_approvals WHERE id=$AP")" ] && ok "the owner was notified (mail: an approval is pending, nothing else)" || fail "notify"
call POST /api/demipass/use "$AG" "$(USE deploy)"; [ "$CODE" = 202 ] && [ "$(echo "$BODY" | J approval_id)" = "$AP" ] && ok "the same call again returns the same request (no pile of requests)" || fail "dedupe: $CODE $BODY"
call POST /api/demipass/use "$AG" "$(USE deploy "$AP")"; [ "$CODE" = 202 ] && ok "with approval_id but no approval yet → still 202, no new request" || fail "pending w/ id: $CODE"
call POST /api/demipass/use "$AG" "$(USE deploy "$AP" 123456)"; [ "$CODE" = 409 ] && echo "$BODY" | grep -q "not opened" && ok "before the owner opens it no code exists (409)" || fail "pre-open code: $CODE $BODY"
call GET /api/demipass/approvals "$A"; [ "$(echo "$BODY" | J incoming.0.id)" = "$AP" ] && ! echo "$BODY" | grep -q '"code"' && ok "the owner's app lists it (no code in the list)" || fail "list: $BODY"
call POST /api/demipass/approvals/$AP/open "$X"; [ "$CODE" = 404 ] && ok "another wallet cannot open it" || fail "X open: $CODE"
call POST /api/demipass/approvals/$AP/open "$AG"; [ "$CODE" = 403 ] && [ "$(echo "$BODY" | J intent)" = "approval-open:$AP" ] && ok "an agent signed in as the owner cannot open it: the PIN opens every request (elevated too)" || fail "agent open: $CODE $BODY"
aopen $AP; C1=$(echo "$BODY" | J code)
[ "$(echo "$BODY" | J approval.call.body.params.url)" = "https://repo.dustroot.com/deploy" ] && ok "the screen shows the full bound call, not only a summary" || fail "call shown: $BODY"
[ "$CODE" = 200 ] && [[ $C1 =~ ^[0-9]{6}$ ]] && [ "$C1" = "$(codeat $AP 0)" ] && ok "opening the screen starts a 6-digit code bound to request $AP" || fail "open: $CODE $BODY"
WRONG=$( [ "$C1" = 000000 ] && echo 111111 || echo 000000 )
call POST /api/demipass/use "$AG" "$(USE deploy "$AP" $WRONG)"; [ "$CODE" = 403 ] && [ "$(echo "$BODY" | J attempts_left)" = 2 ] && ok "a wrong code → 403, 2 tries left" || fail "wrong1: $CODE $BODY"
OLD=$(codeat $AP -3); [ "$OLD" != "$(codeat $AP 0)" ] && [ "$OLD" != "$(codeat $AP -1)" ] && { call POST /api/demipass/use "$AG" "$(USE deploy "$AP" $OLD)"; [ "$CODE" = 403 ] && ok "a code from 90 s ago no longer works" || fail "old code: $CODE"; } || ok "(old-code check skipped: collision)"
call POST /api/demipass/use "$AG" "$(USE other "$AP" "$(codeat $AP 0)")"; [ "$CODE" = 409 ] && echo "$BODY" | grep -q "different call" && ok "the approval binds the exact call: another URL with its code → 409" || fail "binding: $CODE $BODY"
call POST /api/demipass/use "$AG" "$(USE deploy "$AP" "$(codeat $AP 0)")"
[ "$CODE" = 200 ] && [ "$(echo "$BODY" | J result.status)" = 200 ] && ! echo "$BODY" | grep -qF "$SEC" && ok "the agent's /use with the current code acts (code read out in another channel)" || fail "code use: $CODE $BODY"
call POST /api/demipass/use "$AG" "$(USE deploy "$AP" "$(codeat $AP 0)")"; [ "$CODE" = 410 ] && ok "one use per approval: again → 410" || fail "reuse: $CODE $BODY"

# Approve path: the app sends the code; the agent then acts once with only the approval_id
call POST /api/demipass/use "$AG" "$(USE build)"; AP2=$(echo "$BODY" | J approval_id)
call POST /api/demipass/approvals/$AP2/approve "$A" "$(jbody code 000000)"; [ "$CODE" = 409 ] && ok "Approve before opening → 409" || fail "approve unopened: $CODE"
aopen $AP2; CC=$(echo "$BODY" | J code)
call POST /api/demipass/approvals/$AP2/approve "$AG" "$(jbody code "$CC")"; [ "$CODE" = 403 ] && ok "Approve only from the session that opened it with the PIN (an agent's token cannot)" || fail "agent approve: $CODE $BODY"
call POST /api/demipass/approvals/$AP2/approve "$A" "$(jbody code "$CC")"; [ "$CODE" = 200 ] && [ "$(echo "$BODY" | J approval.status)" = approved ] && ok "Approve (code sent by the app, nobody typed it)" || fail "approve: $CODE $BODY"
call POST /api/demipass/use "$AG" "$(USE build "$AP")"; [ "$CODE" = 404 ] || [ "$CODE" = 409 ] || [ "$CODE" = 410 ] && ok "another request's id does not open this call" || fail "cross id: $CODE"
call POST /api/demipass/use "$AG" "$(USE build "$AP2" "$C1")"; [ "$CODE" = 200 ] && ok "after Approve the next /use acts (a stray code field is ignored once approved)" || fail "approved use: $CODE $BODY"
call POST /api/demipass/use "$AG" "$(USE build "$AP2")"; [ "$CODE" = 410 ] && ok "…once" || fail "approved reuse: $CODE"

# three wrong codes cancel; deny; expiry
call POST /api/demipass/use "$AG" "$(USE c3)"; AP3=$(echo "$BODY" | J approval_id); aopen $AP3; G=$(echo "$BODY" | J code)
BAD=$( [ "$G" = 999999 ] && echo 888888 || echo 999999 )
for i in 1 2 3; do call POST /api/demipass/use "$AG" "$(USE c3 "$AP3" $BAD)"; done
[ "$CODE" = 403 ] && [ "$(echo "$BODY" | J cancelled)" = True ] && [ "$(Q "SELECT status FROM use_approvals WHERE id=$AP3")" = cancelled ] && ok "three wrong codes cancel the request" || fail "cancel: $CODE $BODY"
[ "$(Q "SELECT COUNT(*) FROM demipass_security_events WHERE event_type='approval_cancelled_wrong_codes' AND severity='critical'")" = 1 ] && ok "…logged critical" || fail "critical log"
call POST /api/demipass/use "$AG" "$(USE c3 "$AP3" "$(codeat $AP3 0)")"; [ "$CODE" = 410 ] && ok "a cancelled request stays dead, right code or not" || fail "after cancel: $CODE"
call POST /api/demipass/use "$AG" "$(USE dn)"; AP4=$(echo "$BODY" | J approval_id); call POST /api/demipass/approvals/$AP4/deny "$A"
call POST /api/demipass/use "$AG" "$(USE dn "$AP4")"; [ "$CODE" = 410 ] && ok "denied → the agent gets 410" || fail "deny: $CODE $BODY"
call POST /api/demipass/use "$AG" "$(USE dn2)"; [ "$CODE" = 429 ] && [ -n "$(echo "$BODY" | J cooldown_until)" ] && ok "after a denial the requester waits 10 minutes before asking this owner again (red team 4a)" || fail "cooldown: $CODE $BODY"
call GET /api/demipass/approvals "$A"; echo "$BODY" | grep -q '"status":"denied"' && ok "the denial stays visible in the owner's history" || fail "deny history"
python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute(\"UPDATE use_approvals SET decided_at='2020-01-01T00:00:00Z' WHERE status='denied'\"); c.commit()" "$DB_PATH"
call POST /api/demipass/use "$AG" "$(USE ex)"; AP5=$(echo "$BODY" | J approval_id)
python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute(\"UPDATE use_approvals SET expires_at='2020-01-01T00:00:00Z' WHERE id=?\", (int(sys.argv[2]),)); c.commit()" "$DB_PATH" "$AP5"
call POST /api/demipass/use "$AG" "$(USE ex "$AP5")"; [ "$CODE" = 410 ] && ok "after 5 minutes a request expires" || fail "expire: $CODE $BODY"

# the raw body is bound: an extra top-level field (e.g. a command a path reads from the top level) → 409
call POST /api/demipass/use "$AG" "$(USE raw)"; RW=$(echo "$BODY" | J approval_id); aopen $RW; call POST /api/demipass/approvals/$RW/approve "$A" "$(jbody code "$(echo "$BODY" | J code)")"
call POST /api/demipass/use "$AG" "$(jbody ref "$REF" params '{"url":"https://repo.dustroot.com/raw","method":"GET"}' command "cat /etc/shadow" approval_id "$RW")"
[ "$CODE" = 409 ] && ok "a field added outside params (top level) breaks the binding → 409" || fail "raw binding: $CODE $BODY"
call POST /api/demipass/use "$AG" "$(jbody ref "$REF" params '{"url":"https://repo.dustroot.com/raw","method":"DELETE"}' approval_id "$RW")"
[ "$CODE" = 409 ] && ok "another method → 409" || fail "method binding: $CODE"
call POST /api/demipass/use "$AG" "$(USE raw "$RW")"; [ "$CODE" = 200 ] && ok "the exact approved call acts" || fail "raw exact: $CODE $BODY"
# a call the owner could misread is refused before it is offered
call POST /api/demipass/use "$AG" "$(jbody ref "$REF" command "rm -rf /srv/data" params '{"url":"https://repo.dustroot.com/amb","command":"uptime"}')"
[ "$CODE" = 400 ] && echo "$BODY" | grep -q "ambiguous" && ok "the same key with different values at the top level and in params → 400 ambiguous (the headline could misname it)" || fail "ambiguous: $CODE $BODY"
call POST /api/demipass/use "$AG" "$(jbody ref "$REF" params '{"url":"https://repo.dustroot.com/pp","__proto__":{"x":1}}')"
[ "$CODE" = 400 ] && ok "a __proto__ key → 400" || fail "proto: $CODE $BODY"
# key_name may not bring in an elevated secret through a standard one
call POST /api/demipass/store "$A" '{"name":"std-pw","value":"zzzzstdpw1","secret_type":"password","username":"root","host":"100.83.112.88"}'
call POST /api/demipass/use "$AG" '{"name":"std-pw","action":"ssh_exec","target_host":"100.83.112.88","target_user":"root","command":"id","key_name":"forge-token"}'
[ "$CODE" = 403 ] && echo "$BODY" | grep -q "key_name secret 'forge-token' is elevated" && ok "an elevated secret cannot ride in as key_name of a standard one" || fail "key_name: $CODE $BODY"
# per-requester cap
for i in 1 2 3 4 5 6; do call POST /api/demipass/use "$AG" "$(USE cap$i)"; done
[ "$CODE" = 429 ] && ok "at most 5 requests per requester wait on an owner (the 6th → 429)" || fail "cap: $CODE $BODY"
python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute(\"UPDATE use_approvals SET status='expired' WHERE status='pending'\"); c.commit()" "$DB_PATH"

# shares inherit the depth
pin "$A" 4321 "share:$SID"; call POST /api/demipass/shares "$A" '{"secret":"forge-token","to":"person-k"}'; SH=$(echo "$BODY" | J share.id)
pin "$K" 8765 "share-accept:$SH"; call POST /api/demipass/shares/$SH/accept "$K"
call POST /api/demipass/use "$K" "$(USE kuse)"; KP=$(echo "$BODY" | J approval_id)
[ "$CODE" = 202 ] && [ "$(Q "SELECT owner_did FROM use_approvals WHERE id=$KP")" = "$(Q "SELECT did FROM identity_wallets WHERE username='owner-a'")" ] && ok "K's /use on A's elevated secret parks on A's approval (depth inherited)" || fail "share inherit: $CODE $BODY"
call POST /api/demipass/gate-policy "$K" "$(jbody ref "$REF" security_depth standard)"; [ "$CODE" = 404 ] && ok "K cannot lower A's depth" || fail "K lower: $CODE"
call POST /api/demipass/approvals/$KP/open "$K"; [ "$CODE" = 404 ] && ok "K cannot open (approve) its own request" || fail "K self-open: $CODE"
aopen $KP; call POST /api/demipass/approvals/$KP/approve "$A" "$(jbody code "$(echo "$BODY" | J code)")"
call POST /api/demipass/use "$AG" "$(USE kuse "$KP")"; [ "$CODE" = 404 ] && ok "nobody else can spend K's approval" || fail "steal: $CODE"
call POST /api/demipass/use "$K" "$(USE kuse "$KP")"; [ "$CODE" = 200 ] && ok "K's /use acts after A approves" || fail "K approved: $CODE $BODY"
call GET /api/demipass/approvals "$K"; [ "$(echo "$BODY" | J outgoing.0.status)" = used ] && ok "K's account shows its request (audit on the requester's side)" || fail "K audit: $BODY"
call GET /api/demipass/approvals "$A"; echo "$BODY" | grep -q "\"id\":$KP" && ok "A's account shows it too (owner's side)" || fail "A audit"

# ── critical ──
call POST /api/demipass/gate-policy "$A" "$(jbody ref "$REF" security_depth critical)"; [ "$CODE" = 200 ] && ok "the owner raises it to critical (no SMS needed any more; not a lowering)" || fail "set critical: $CODE $BODY"
call POST /api/demipass/use "$AG" "$(USE crit)"; CP=$(echo "$BODY" | J approval_id); [ "$CODE" = 202 ] || fail "crit park: $CODE"
call POST /api/demipass/approvals/$CP/open "$A"; [ "$CODE" = 403 ] && [ "$(echo "$BODY" | J intent)" = "approval-open:$CP" ] && ok "critical: opening the request needs the PIN (intent approval-open:$CP)" || fail "crit open: $CODE $BODY"
pin "$A" 4321 "approval-open:$CP"; call POST /api/demipass/approvals/$CP/open "$A"; CK=$(echo "$BODY" | J code)
[ "$CODE" = 200 ] && ok "with the PIN it opens" || fail "crit open pin: $CODE $BODY"
call POST /api/demipass/approvals/$CP/approve "$A2" "$(jbody code "$CK")"; [ "$CODE" = 403 ] && ok "critical: Approve only from the session that opened it with the PIN" || fail "crit other session: $CODE $BODY"
call POST /api/demipass/approvals/$CP/approve "$A" "$(jbody code "$(codeat $CP 0)")"; [ "$CODE" = 200 ] && ok "approved from that session" || fail "crit approve: $CODE $BODY"
call POST /api/demipass/use "$AG" "$(USE crit "$CP")"; [ "$CODE" = 200 ] && ok "the critical use acts once approved" || fail "crit use: $CODE"
# reveal on critical: an approved request + the PIN
call POST /api/demipass/reveal "$A" '{"name":"forge-token"}'; RP=$(echo "$BODY" | J approval_id)
[ "$CODE" = 202 ] && [ "$(Q "SELECT kind FROM use_approvals WHERE id=$RP")" = reveal ] && ok "critical reveal first asks for an approval (request $RP)" || fail "crit reveal: $CODE $BODY"
pin "$A" 4321 "approval-open:$RP"; call POST /api/demipass/approvals/$RP/open "$A"; call POST /api/demipass/approvals/$RP/approve "$A" "$(jbody code "$(echo "$BODY" | J code)")"
call POST /api/demipass/reveal "$A" "$(jbody name forge-token approval_id "$RP")"; [ "$CODE" = 403 ] && [ "$(echo "$BODY" | J missing.0)" = pin ] && [ "$(Q "SELECT status FROM use_approvals WHERE id=$RP")" = approved ] && ok "…then the PIN, and asking for the PIN does not spend the approval" || fail "crit reveal pin: $CODE $BODY"
RI=$(echo "$BODY" | J intent)
call POST /api/identity/request-2fa "$A" "$(jbody did "$(Q "SELECT did FROM identity_wallets WHERE username='owner-a'")")"
TFA=$(Q "SELECT code FROM identity_2fa_codes WHERE did=(SELECT did FROM identity_wallets WHERE username='owner-a') ORDER BY id DESC LIMIT 1")
call POST /api/identity/gate/verify "$A" "$(jbody gate twofa code "$TFA")"; [ "$CODE" = 200 ] || fail "twofa: $CODE $BODY"
pin "$A" 4321 "$RI"
call POST /api/demipass/reveal "$A" "$(jbody name forge-token approval_id "$RP")"; [ "$CODE" = 200 ] && [ "$(echo "$BODY" | J value)" = "$SEC" ] && ok "approval + PIN (+ the email code critical keeps) → the value" || fail "crit reveal: $CODE $(echo "$BODY" | head -c 200)"

# ── nothing in the log ──
grep -qF -- "$SEC" "$S/server.log" && fail "secret value in the server log" || ok "no secret value in the server log"
[ "$(Q "SELECT COUNT(*) FROM blindkey_events WHERE detail LIKE '%code_key%' OR detail LIKE '%$C1%'")" = 0 ] && ok "no code or code key in blindkey_events" || fail "code in events"

echo; [ $fails = 0 ] && echo "ALL OK" || echo "$fails FAILED"; exit $fails
