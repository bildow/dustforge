#!/bin/bash
# End-to-end smoke of person-to-person shares, ownership transfer, vault types and owner deposits
# (secret_sharing.js, secret_types.js; contract docs/sharing.md). Boots server.js on a throwaway DB with /use's
# fetch() to repo.dustroot.com sent to a local stand-in upstream, creates owner A (PIN), person K (PIN), stranger X,
# fleet agent F, and drives the real routes. Checks, among others:
#   - types: an unknown type is refused (400), aliases map (ssh_key → ssh_credential), a PEM key with no type is
#     inferred ssh_credential with a DP-SSH- ref; manual-entry fields (username, host, note, if_absent) are kept;
#   - deposit: the owner of a fleet deposits into its agent (SDK body shape, target_silicon); never into a person;
#   - shares: only to a person you are connected to, PIN-gated, inert until accepted; use-only through /use (the
#     value never in a response); the person's own silicon agent needs secret:use like any other; reveal needs the
#     owner's PIN-gated grant and then the person's own PIN, once per granted reveal; revoke, decline, expiry and a
#     use-token minted before the revoke all end access;
#   - membership grants nothing: a connected person or a fleet agent without a share gets 403 and an empty menu;
#   - transfer: PIN-gated, the ref stays, the old owner keeps use-only access the new owner sees and can revoke,
#     every other delegation and outstanding use-token ends, a name taken in the new vault needs new_name;
#   - a ref names one owner's secret: a caller with a same-named secret of their own still reaches the ref's;
#   - no secret value in the server log.
# No network beyond 127.0.0.1.
set -u
W=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
S=$(mktemp -d /tmp/dustforge-sharing-smoke.XXXXXX)
PORT=${PORT:-3783}; UP_PORT=${UP_PORT:-3784}; API=http://127.0.0.1:$PORT
[ -d "$W/node_modules" ] || export NODE_PATH=${NODE_PATH:-/home/flimflam/project/dustforge/node_modules}
export IDENTITY_MASTER_KEY=$(python3 -c 'import secrets;print(secrets.token_hex(32))') DB_PATH=$S/dustforge.db PORT \
  STALWART_HOST=127.0.0.1 STALWART_PORT=1 SMTP_RELAY_HOST= SMTP_HOST=127.0.0.1 SMTP_PORT=9 TEST_UPSTREAM=http://127.0.0.1:$UP_PORT \
  DUSTFORGE_ADMIN_KEY=smoke-admin-key-0123456789abcdef BLINDKEY_SSH_HOSTS_EXTRA='203.0.113.7, bad host;rm'
cd "$W"
SEC_A='A-forge-tok"en-7f3e9c1d2b'          # A's http secret (a quote in it: the JSON-escaped form must be redacted too)
SEC_K='K-own-forge-token-55aa66bb'         # K's own secret with the same name
SEC_KB='kyle-racknerd-pw-Zq81!x'           # the credential received raw, deposited by A and transferred to K
SEC_DUP='dup-value-A-0001'

node -e '
const http = require("http");
http.createServer((req, res) => { req.resume(); req.on("end", () => {
  if (req.url.startsWith("/echo-secret")) { res.writeHead(200, { "content-type": "application/json" }); return res.end(JSON.stringify({ seen: req.headers.authorization || "" })); }
  res.writeHead(404); res.end("nope"); }); }).listen(+process.argv[1], "127.0.0.1");' $UP_PORT & UP=$!
node --require ./test/fixtures/upstream-redirect.js server.js >"$S/server.log" 2>&1 & SRV=$!
trap 'kill $SRV $UP 2>/dev/null; rm -rf "$S"' EXIT
for i in $(seq 1 40); do curl -s -o /dev/null "$API/" && break; sleep 0.5; done
kill -0 $SRV 2>/dev/null || { echo "server died:"; tail -5 "$S/server.log"; exit 1; }

PW=hunter22; H=$(printf '%s' "$PW" | sha256sum | cut -d' ' -f1)
SIL_K='silicon:sharing-smoke-k-agent-0123456789'
node -e '
const identity = require("./identity"); const Database = require("better-sqlite3"); const crypto = require("crypto");
const db = new Database(process.env.DB_PATH);
for (const c of ["idempotency_key TEXT", "provenance TEXT DEFAULT '"'"'organic'"'"'"]) { try { db.exec("ALTER TABLE identity_transactions ADD COLUMN " + c); } catch (_) {} }
const out = {};
for (const [u, bal] of [["owner-a", 100000], ["person-k", 100000], ["stranger-x", 100000], ["agent-f", 100000]]) {
  const id = identity.createIdentity(); const enc = id.encrypted_private_key || id.encryptedPrivateKey;
  db.prepare("INSERT INTO identity_wallets (did, username, email, encrypted_private_key, balance_cents, password_hash) VALUES (?, ?, ?, ?, ?, ?)")
    .run(id.did, u, u + "@dustforge.com", enc, bal, process.argv[1]);
  db.prepare("INSERT INTO identity_transactions (did, amount_cents, type, description, balance_after) VALUES (?, ?, ?, ?, ?)").run(id.did, bal, "topup", "smoke", bal);
  out[u] = id.did;
}
db.prepare("INSERT INTO silicon_agents (agent_name, did, carbon_did, token_hash) VALUES (?, ?, ?, ?)")
  .run("k-agent", "did:silicon:k-agent", out["person-k"], crypto.createHash("sha256").update(process.argv[2]).digest("hex"));
db.prepare("INSERT INTO silicon_permissions (agent_name, permission_type, resource) VALUES (?, ?, ?)").run("k-agent", "action:http_header", "*");
' "$H" "$SIL_K"

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
jbody(){ python3 -c 'import json,sys; print(json.dumps(dict(zip(sys.argv[1::2], [json.loads(x) if x[:1] in "[{" or x in ("true","false") or x.lstrip("-").isdigit() else x for x in sys.argv[2::2]]))))' "$@"; }
pin(){ call POST /api/identity/gate/verify "$1" "$(jbody gate pin pin "$2" intent "$3")"; [ "$CODE" = 200 ] || fail "pin $3: $CODE $BODY"; }
did(){ Q "SELECT did FROM identity_wallets WHERE username='$1'"; }
kaccept(){ pin "$K" 8765 "share-accept:$1"; call POST /api/demipass/shares/$1/accept "$K"; }
noval(){ for v in "$SEC_A" "$SEC_K" "$SEC_KB" "$SEC_DUP"; do case "$BODY" in *"$v"*) return 1;; esac; done; return 0; }
A=$(login owner-a); K=$(login person-k); X=$(login stranger-x); F=$(login agent-f)
[ -n "$A" ] && [ "$A" != None ] && [ -n "$K" ] && [ "$K" != None ] && ok "four wallets signed in" || { fail "login: $CODE $BODY"; exit 1; }
call POST /api/identity/pin "$A" '{"pin":"4321","password":"hunter22"}'; [ "$CODE" = 200 ] || fail "pin A: $CODE $BODY"
call POST /api/identity/pin "$K" '{"pin":"8765","password":"hunter22"}'; [ "$CODE" = 200 ] || fail "pin K: $CODE $BODY"
DA=$(did owner-a); DK=$(did person-k); DX=$(did stranger-x); DF=$(did agent-f)

# ── network: A–K and A–X are people connected; F joins A's fleet ──
for who in person-k stranger-x; do
  call POST /api/network/requests "$A" "$(jbody to $who as person)"; R=$(echo "$BODY" | J request.id)
  T=$([ $who = person-k ] && echo "$K" || echo "$X"); call POST /api/network/requests/$R/accept "$T"; [ "$CODE" = 200 ] || fail "connect $who: $CODE $BODY"
done
call POST /api/network/requests "$A" '{"to":"agent-f","as":"agent"}'; R=$(echo "$BODY" | J request.id)
call POST /api/network/requests/$R/accept "$F"; [ "$CODE" = 200 ] && ok "A is connected to K and X (people) and F joined A's fleet" || fail "fleet join: $CODE $BODY"
. "$W/test/lib/pair_in_person.sh"; pair_in_person "$A" 4321 "$K" 8765 && ok "A and K paired in person (QR, both PINs): a confirmed contact"

# ── vault types and manual-entry fields ──
call POST /api/demipass/store "$A" '{"name":"t-bogus","value":"zzzzzzzz1","secret_type":"bogus"}'
[ "$CODE" = 400 ] && echo "$BODY" | grep -q ssh_credential && ok "unknown type → 400 listing the vault types (not relabelled api_key)" || fail "bogus type: $CODE $BODY"
call POST /api/demipass/store "$A" '{"name":"t-sshkey","value":"-----BEGIN OPENSSH PRIVATE KEY-----\nAAAAB3NzaC1yc2E\n-----END OPENSSH PRIVATE KEY-----"}'
[ "$(echo "$BODY" | J secret_type)" = ssh_credential ] && [ "$(echo "$BODY" | J type_inferred)" = True ] && [[ $(echo "$BODY" | J ref) == DP-SSH-* ]] && ok "a PEM key with no type → ssh_credential, DP-SSH- ref" || fail "infer: $BODY"
[ "$(Q "SELECT action_type FROM blindkey_contexts c JOIN blindkey_secrets s ON s.id=c.secret_id WHERE s.name='t-sshkey'")" = ssh_exec ] && ok "its default context is ssh_exec (was http_header)" || fail "ssh ctx"
call POST /api/demipass/store "$A" '{"name":"t-alias","value":"zzzzzzzz2","secret_type":"ssh_key"}'; [ "$(echo "$BODY" | J secret_type)" = ssh_credential ] && ok "the app's old 'ssh_key' → ssh_credential" || fail "alias: $BODY"
call POST /api/demipass/store "$A" '{"name":"t-token","value":"zzzzzzzz3","secret_type":"token"}'; [ "$(echo "$BODY" | J secret_type)" = token ] && [[ $(echo "$BODY" | J ref) == DP-TKN-* ]] && ok "'token' stays token (DP-TKN-)" || fail "token: $BODY"
call POST /api/demipass/store "$A" '{"name":"t-api","value":"sk-or-v1-abcdef0123456789"}'; [ "$(echo "$BODY" | J secret_type)" = api_key ] && ok "no type, provider-shaped value → api_key" || fail "api: $BODY"

# The credential Kyle sent raw, entered by hand: password, username, host, labels, note — refusing to overwrite.
KB=$(jbody name kyle-racknerd value "$SEC_KB" secret_type password username root host 203.0.113.7 labels '["owner-kyle","received-raw"]' note "Kyle's RackNerd root. Received raw over Matrix 2026-11-05; Kyle rotates it when he chooses." if_absent true)
call POST /api/demipass/store "$A" "$KB"
[ "$CODE" = 200 ] && [[ $(echo "$BODY" | J ref) == DP-PWD-* ]] && [ "$(echo "$BODY" | J username)" = root ] && [ "$(echo "$BODY" | J host)" = 203.0.113.7 ] && noval && ok "manual entry: password, username root, host kept; value not echoed" || fail "manual: $CODE $BODY"
REF_KB=$(echo "$BODY" | J ref)
[ "$(Q "SELECT target_host_pattern FROM blindkey_contexts c JOIN blindkey_secrets s ON s.id=c.secret_id WHERE s.name='kyle-racknerd'")" = 203.0.113.7 ] && ok "its default ssh_exec context is bound to that host, not '*'" || fail "host bind"
[ "$(Q "SELECT account_username||'|'||labels||'|'||substr(note,1,21) FROM blindkey_secrets WHERE name='kyle-racknerd'")" = 'root|["owner-kyle","received-raw"]|Kyle'"'"'s RackNerd root.' ] && ok "username, labels and note stored" || fail "fields: $(Q "SELECT account_username||'|'||labels||'|'||note FROM blindkey_secrets WHERE name='kyle-racknerd'")"
call POST /api/demipass/store "$A" "$KB"; [ "$CODE" = 409 ] && ok "if_absent: storing the same name again → 409, nothing overwritten" || fail "if_absent: $CODE $BODY"
grep -q "203.0.113.7" <(node -e 'process.env.BLINDKEY_SSH_HOSTS_EXTRA="203.0.113.7, bad host;rm"; console.log(String(process.env.BLINDKEY_SSH_HOSTS_EXTRA).split(",").map(h=>h.trim()).filter(h=>/^[A-Za-z0-9.:-]{1,253}$/.test(h)).join(" "))') && ok "BLINDKEY_SSH_HOSTS_EXTRA parses (malformed entries dropped)" || fail "extra hosts"

# ── deposit: owner into its own agent, never into a person ──
call POST /api/demipass/store "$X" '{"name":"x-thing","value":"zzzzzzzz9"}'
call POST /api/demipass/deposit "$A" '{"name":"f-key","value":"zzzzzzzz4","target_silicon":"agent-f"}'
[ "$CODE" = 403 ] && ok "F joined through the network (its vault stays its own) → deposit refused" || fail "deposit network F: $CODE $BODY"
python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute(\"UPDATE fleet_silicons SET joined_via='owner', created_by_fleet=1 WHERE member_did=?\", (sys.argv[2],)); c.commit()" "$DB_PATH" "$DF"
call POST /api/demipass/deposit "$A" '{"name":"f-key","value":"zzzzzzzz4","target_silicon":"agent-f"}'
[ "$CODE" = 200 ] && [ "$(Q "SELECT did FROM blindkey_secrets WHERE name='f-key'")" = "$DF" ] && [[ $(echo "$BODY" | J ref) == DP-API-* ]] && ok "SDK-shaped deposit (target_silicon) into an agent A made → 200 with a ref" || fail "deposit F: $CODE $BODY"
call POST /api/demipass/deposit "$A" '{"name":"f-key","value":"zzzzzzzz4b","target_silicon":"agent-f"}'; [ "$CODE" = 409 ] && ok "a deposit never overwrites a secret already in the agent's vault" || fail "deposit overwrite: $CODE $BODY"
# H1: X makes a fleet, adds K to fleet_members without asking, then tries to deposit over K's secret
call POST /api/demipass/store "$K" '{"name":"k-github","value":"zzzzzzzzkg"}'
python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute(\"INSERT INTO fleets (owner_did, name, slug) VALUES (?, 'x fleet', 'x-fleet')\", (sys.argv[2],)); fid=c.execute(\"SELECT id FROM fleets WHERE slug='x-fleet'\").fetchone()[0]; c.execute(\"INSERT INTO fleet_members (fleet_id, member_did, role) VALUES (?, ?, 'agent')\", (fid, sys.argv[3])); c.commit()" "$DB_PATH" "$DX" "$DK"
call POST /api/demipass/deposit "$X" '{"name":"k-github","value":"zzzzzzzzXX","target_username":"person-k"}'
[ "$CODE" = 403 ] && [ "$(Q "SELECT COUNT(*) FROM blindkey_secrets WHERE did='$DK' AND name='k-github'")" = 1 ] && ok "a fleet that added K to fleet_members without asking cannot deposit into K's vault" || fail "H1 deposit: $CODE $BODY"
call POST /api/demipass/delegate "$X" "$(jbody secret_name x-thing delegate_did "$DK")"; [ "$CODE" = 403 ] && ok "…nor push a live delegation onto K (K is a person, not an agent)" || fail "H1 delegate: $CODE $BODY"
call POST /api/demipass/deposit "$A" '{"name":"k-key","value":"zzzzzzzz5","target_username":"person-k"}'; [ "$CODE" = 403 ] && ok "deposit into a person's vault → 403 (share or transfer instead)" || fail "deposit K: $CODE $BODY"
call POST /api/demipass/deposit "$X" '{"name":"x-key","value":"zzzzzzzz6","target_silicon":"agent-f"}'; [ "$CODE" = 403 ] && ok "deposit into someone else's agent → 403" || fail "deposit X→F: $CODE $BODY"
call POST /api/demipass/deposit "$A" '{"name":"f-bad","value":"zzzzzzzz7","target_silicon":"agent-f","secret_type":"nope"}'; [ "$CODE" = 400 ] && ok "deposit with an unknown type → 400" || fail "deposit type: $CODE $BODY"
BODY=$(curl -s -X POST "$API/api/demipass/deposit" -H 'content-type: application/json' -H "x-admin-key: $DUSTFORGE_ADMIN_KEY" -d "$(jbody name adm-key value zzzzzzzz8 target_did "$DK")")
[ "$(echo "$BODY" | J ok)" = True ] && ok "admin deposit still works" || fail "admin deposit: $BODY"

# ── shares ──
call POST /api/demipass/store "$A" "$(jbody name forge-token value "$SEC_A" secret_type api_key)"; REF_A=$(echo "$BODY" | J ref)
SID_A=$(Q "SELECT id FROM blindkey_secrets WHERE ref_code='$REF_A'")
USE_A=$(jbody ref "$REF_A" params '{"url":"https://repo.dustroot.com/echo-secret","method":"GET"}')
call POST /api/demipass/delegate "$A" "$(jbody secret_name forge-token delegate_did "$DK")"; [ "$CODE" = 409 ] && ok "/delegate to a person in your network → 409, pointing at shares" || fail "delegate person: $CODE $BODY"
call POST /api/demipass/shares "$A" '{"secret":"forge-token","to":"agent-f"}'; [ "$CODE" = 409 ] && ok "share with an agent → 409 (agents get /delegate)" || fail "share agent: $CODE $BODY"
call POST /api/demipass/shares "$F" '{"secret":"f-key","to":"owner-a"}'; [ "$CODE" = 403 ] || [ "$CODE" = 404 ] && ok "an agent wallet cannot share with a person through shares" || fail "agent shares: $CODE $BODY"
call POST /api/demipass/shares "$SIL_K" '{"secret":"forge-token","to":"owner-a"}'; [ "$CODE" = 403 ] && ok "a silicon: token cannot share" || fail "silicon share: $CODE $BODY"
call POST /api/demipass/shares "$K" '{"secret":"forge-token","to":"owner-a"}'; [ "$CODE" = 404 ] && ok "K cannot share A's secret" || fail "not owner: $CODE $BODY"
# a stranger: register one not connected to A
call POST /api/demipass/shares "$X" '{"secret":"x-thing","to":"person-k"}'; [ "$CODE" = 403 ] && ok "share with someone you are not connected to → 403" || fail "unconnected: $CODE $BODY"
call POST /api/demipass/shares "$A" '{"secret":"forge-token","to":"person-k","expires_in_days":0}'; [ "$CODE" = 400 ] && ok "a share always expires (0 days → 400)" || fail "days0: $CODE $BODY"
call POST /api/demipass/shares "$A" '{"secret":"forge-token","to":"person-k","note":"for your fleet"}'
[ "$CODE" = 403 ] && [ "$(echo "$BODY" | J intent)" = "share:$SID_A" ] && ok "share without the PIN → 403 naming intent share:$SID_A" || fail "share pin: $CODE $BODY"
pin "$A" 4321 "share:$SID_A"
call POST /api/demipass/shares "$A" '{"secret":"forge-token","to":"person-k","note":"for your fleet"}'
SH=$(echo "$BODY" | J share.id)
[ "$CODE" = 201 ] && [ "$(echo "$BODY" | J share.state)" = offered ] && [ "$(echo "$BODY" | J share.use_only)" = True ] && ok "A offers K a use-only share (PIN) → offered" || fail "offer: $CODE $BODY"
call POST /api/demipass/use "$K" "$USE_A"; [ "$CODE" = 403 ] && ok "before K accepts, the offer opens nothing (/use → 403)" || fail "pre-accept use: $CODE $BODY"
call GET /api/demipass/menu "$K"; echo "$BODY" | grep -q shares_waiting_for_you && [ "$(echo "$BODY" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["shared_with_you"]))')" = 0 ] && ok "K's menu says a share waits; nothing is shared yet" || fail "K menu: $BODY"
call GET /api/demipass/shares "$K"; [ "$(echo "$BODY" | J waiting_for_you)" = 1 ] && [ "$(echo "$BODY" | J received.0.owner)" = owner-a ] && noval && ok "K sees the offer from owner-a (no value)" || fail "K list: $BODY"
call POST /api/demipass/shares/$SH/accept "$X"; [ "$CODE" = 404 ] && ok "X cannot accept K's share" || fail "X accept: $CODE $BODY"
call POST /api/demipass/shares/$SH/accept "$SIL_K"; [ "$CODE" = 403 ] && ok "K's silicon agent cannot accept for K" || fail "sil accept: $CODE $BODY"
call POST /api/demipass/shares/$SH/accept "$K"; [ "$CODE" = 403 ] && [ "$(echo "$BODY" | J intent)" = "share-accept:$SH" ] && ok "accepting needs K's PIN (intent share-accept:$SH)" || fail "accept pin: $CODE $BODY"
KDEV=$(node -e 'const identity=require("./identity"),Database=require("better-sqlite3");const db=new Database(process.env.DB_PATH);const w=db.prepare("SELECT * FROM identity_wallets WHERE username=?").get("person-k");console.log(identity.createTokenForIdentity(w.encrypted_private_key,w.did,{scope:"transact",expiresIn:"1h",metadata:{username:w.username,auth_method:"device",agent_label:"k-laptop-agent"}}))')
call POST /api/demipass/shares/$SH/accept "$KDEV"; [ "$CODE" = 403 ] && ok "an agent signed in as K (device login) cannot accept without K's PIN" || fail "device accept: $CODE $BODY"
kaccept $SH; [ "$CODE" = 200 ] && [ "$(echo "$BODY" | J share.state)" = active ] && ok "K accepts with the PIN — the one step on K's side" || fail "accept: $CODE $BODY"
kaccept $SH; [ "$CODE" = 409 ] && ok "accepting twice → 409" || fail "accept2: $CODE"
call POST /api/demipass/use "$K" "$USE_A"
[ "$CODE" = 200 ] && [ "$(echo "$BODY" | J result.status)" = 200 ] && echo "$BODY" | grep -q REDACTED && noval && ok "K reaches A's secret through /use; the upstream echo comes back [REDACTED], the value is in no response" || fail "K use: $CODE $BODY"
[ "$(Q "SELECT use_count FROM demipass_delegations WHERE id=$SH")" = 1 ] && ok "the share counts the use" || fail "use_count"
# K's agents act as K with a token of K's (device login); K2 stands for one. silicon: tokens are refused by /use's
# auth today for every secret, shared or own (pre-existing; not changed here), and cannot hold a share either.
K2=$(login person-k)
call POST /api/demipass/use "$K2" "$USE_A"; [ "$CODE" = 200 ] && noval && ok "an agent signed in as K (another K token) reaches it the same way, never the value" || fail "K2 use: $CODE $BODY"
call POST /api/demipass/use "$SIL_K" "$USE_A"; [ "$CODE" = 401 ] || [ "$CODE" = 403 ] && ok "a silicon: token of K's → refused" || fail "sil use: $CODE $BODY"
call POST /api/demipass/shares/$SH/reveal "$K"; [ "$CODE" = 403 ] && [ "$(echo "$BODY" | J use_only)" = True ] && ok "reveal on a use-only share → 403" || fail "reveal use-only: $CODE $BODY"
call POST /api/demipass/reveal "$K" "$(jbody ref "$REF_A")"; [ "$CODE" = 404 ] && ok "the owner's reveal route does not open a shared secret" || fail "owner reveal by K: $CODE $BODY"

# membership grants nothing
call POST /api/demipass/use "$X" "$USE_A"; [ "$CODE" = 403 ] && noval && ok "X, connected to A but not shared with, → 403" || fail "X use: $CODE $BODY"
call POST /api/demipass/use "$F" "$USE_A"; [ "$CODE" = 403 ] && ok "F, an agent in A's fleet, without a delegation → 403" || fail "F use: $CODE $BODY"
call GET /api/demipass/menu "$F"; ! echo "$BODY" | grep -q forge-token && ok "F's menu does not list A's secret" || fail "F menu: $BODY"
call GET /api/demipass/menu "$X"; ! echo "$BODY" | grep -q forge-token && ok "X's menu does not list A's secret" || fail "X menu: $BODY"

# reveal grant
call POST /api/demipass/shares/$SH/reveal-grant "$K" '{"allow":true}'; [ "$CODE" = 404 ] && ok "K cannot grant itself a reveal" || fail "self grant: $CODE"
call POST /api/demipass/shares/$SH/reveal-grant "$A" '{"allow":true}'; [ "$CODE" = 403 ] && [ "$(echo "$BODY" | J intent)" = "reveal-grant:$SH" ] && ok "a reveal grant needs A's PIN (intent reveal-grant:$SH)" || fail "grant pin: $CODE $BODY"
pin "$A" 4321 "reveal-grant:$SH"
call POST /api/demipass/shares/$SH/reveal-grant "$A" '{"allow":true}'; [ "$(echo "$BODY" | J share.reveals_left)" = 1 ] && ok "A allows one reveal" || fail "grant: $CODE $BODY"
call POST /api/demipass/shares/$SH/reveal "$K"; [ "$CODE" = 403 ] && [ "$(echo "$BODY" | J intent)" = "share-reveal:$SH" ] && ok "K's reveal needs K's own PIN" || fail "reveal pin: $CODE $BODY"
pin "$K" 8765 "share-reveal:$SH"
call POST /api/demipass/shares/$SH/reveal "$K"; [ "$CODE" = 200 ] && [ "$(echo "$BODY" | J value)" = "$SEC_A" ] && [ "$(echo "$BODY" | J reveals_left)" = 0 ] && ok "K sees the value once" || fail "reveal: $CODE $(echo "$BODY" | head -c 200)"
pin "$K" 8765 "share-reveal:$SH"
call POST /api/demipass/shares/$SH/reveal "$K"; [ "$CODE" = 403 ] && ok "a second reveal → 403 (the grant was for one)" || fail "reveal2: $CODE"
[ "$(Q "SELECT COUNT(*) FROM demipass_security_events WHERE event_type='secret_revealed' AND severity='critical' AND caller_did='$DK'")" = 1 ] && ok "the reveal is a critical security event on K" || fail "reveal event: $(Q "SELECT COUNT(*) FROM demipass_security_events WHERE event_type='secret_revealed'")"
[ "$(Q "SELECT COUNT(*) FROM ticks WHERE did='$DA' AND note LIKE '%REVEALED to person-k%'")" = 1 ] && ok "and A's ledger records that K saw it" || fail "owner tick"
[ "$(Q "SELECT group_concat(event_type) FROM (SELECT event_type FROM blindkey_events WHERE secret_id=$SID_A AND event_type LIKE 'share_%' ORDER BY id)")" = "share_offered,share_accepted,share_reveal_granted,share_revealed" ] && ok "blindkey_events: offered, accepted, reveal granted, revealed" || fail "events: $(Q "SELECT group_concat(event_type) FROM blindkey_events WHERE secret_id=$SID_A")"
call GET /api/demipass/shares/$SH/audit "$A"
EV=$(echo "$BODY" | python3 -c 'import json,sys; print(",".join(e["event"]+"/"+str(e["by"]) for e in json.load(sys.stdin)["events"]))')
[ "$EV" = "share_offered/owner-a,share_accepted/person-k,delegation_used/person-k,delegation_used/person-k,share_reveal_granted/owner-a,share_revealed/person-k" ] && noval && ok "the share's audit: who offered, accepted, used, granted and revealed, and when" || fail "audit: $EV"
call GET /api/demipass/shares/$SH/audit "$X"; [ "$CODE" = 404 ] && ok "a third wallet cannot read the audit" || fail "audit X: $CODE"
pin "$A" 4321 "reveal-grant:$SH"; call POST /api/demipass/shares/$SH/reveal-grant "$A" '{"allow":true,"minutes":5}'
python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute('UPDATE demipass_delegations SET reveal_until=? WHERE id=?', ('2020-01-01T00:00:00.000Z', int(sys.argv[2]))); c.commit()" "$DB_PATH" "$SH"
pin "$K" 8765 "share-reveal:$SH"
call POST /api/demipass/shares/$SH/reveal "$K"; [ "$CODE" = 403 ] && echo "$BODY" | grep -q "has closed" && ok "a reveal grant is time-boxed: after its window → 403" || fail "lapsed: $CODE $BODY"
call POST /api/demipass/shares/$SH/reveal-grant "$A" '{"allow":true,"minutes":5000}'; [ "$CODE" = 400 ] && ok "a reveal window longer than a day → 400" || fail "minutes: $CODE"

# revoke ends it, including a use-token minted before the revoke
call POST /api/demipass/request-token "$K" "$(jbody ref "$REF_A" target_url https://repo.dustroot.com/echo-secret)"; UT=$(echo "$BODY" | J use_token)
[ -n "$UT" ] && [ "$UT" != None ] || fail "token: $CODE $BODY"
call POST /api/demipass/shares/$SH/revoke "$A"; [ "$(echo "$BODY" | J share.state)" = revoked ] && ok "A revokes the share" || fail "revoke: $CODE $BODY"
call POST /api/demipass/use "$K" "$(jbody use_token "$UT" params '{"url":"https://repo.dustroot.com/echo-secret","method":"GET"}')"; [ "$CODE" = 403 ] && ok "a use-token K minted before the revoke no longer works" || fail "stale token: $CODE $BODY"
call POST /api/demipass/use "$K" "$USE_A"; [ "$CODE" = 403 ] && ok "K → 403 after the revoke" || fail "post-revoke: $CODE"
# re-offer, then decline; re-offer, accept, expire
pin "$A" 4321 "share:$SID_A"; call POST /api/demipass/shares "$A" '{"secret":"forge-token","to":"person-k"}'; SH2=$(echo "$BODY" | J share.id)
call POST /api/demipass/shares/$SH2/decline "$K"; [ "$(echo "$BODY" | J share.state)" = declined ] && ok "K declines a new offer" || fail "decline: $CODE $BODY"
pin "$A" 4321 "share:$SID_A"; call POST /api/demipass/shares "$A" '{"secret":"forge-token","to":"person-k","expires_in_days":1}'; SH3=$(echo "$BODY" | J share.id)
kaccept $SH3
python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute('UPDATE demipass_delegations SET expires_at=? WHERE id=?', ('2020-01-01T00:00:00.000Z', int(sys.argv[2]))); c.commit()" "$DB_PATH" "$SH3"
call POST /api/demipass/use "$K" "$USE_A"; [ "$CODE" = 403 ] && ok "an expired share → 403" || fail "expired: $CODE $BODY"

# a ref names one owner's secret, even when the caller has one with the same name
pin "$A" 4321 "share:$SID_A"; call POST /api/demipass/shares "$A" '{"secret":"forge-token","to":"person-k"}'; SH4=$(echo "$BODY" | J share.id)
kaccept $SH4
call POST /api/demipass/store "$K" "$(jbody name forge-token value "$SEC_K" secret_type api_key)"
BA=$(Q "SELECT use_count FROM blindkey_secrets WHERE id=$SID_A"); BK=$(Q "SELECT use_count FROM blindkey_secrets WHERE did='$DK' AND name='forge-token'")
call POST /api/demipass/use "$K" "$USE_A"
[ "$CODE" = 200 ] && [ "$(Q "SELECT use_count FROM blindkey_secrets WHERE id=$SID_A")" = $((BA+1)) ] && [ "$(Q "SELECT use_count FROM blindkey_secrets WHERE did='$DK' AND name='forge-token'")" = "$BK" ] && ok "K's call with A's ref uses A's secret, not K's same-named one" || fail "same-name ref: $CODE $BODY (A $BA→$(Q "SELECT use_count FROM blindkey_secrets WHERE id=$SID_A"), K $BK)"

# ── transfer: the raw-received credential goes to K; A keeps use-only access ──
call POST /api/demipass/store "$A" '{"name":"kb-panel","value":"kb-panel-token-0099","secret_type":"api_key"}'; REF_P=$(echo "$BODY" | J ref)
SID_P=$(Q "SELECT id FROM blindkey_secrets WHERE ref_code='$REF_P'")
call POST /api/demipass/delegate "$A" "$(jbody secret_name kb-panel delegate_did "$DF")"; [ "$CODE" = 200 ] || fail "delegate F: $CODE $BODY"
call POST /api/demipass/request-token "$A" "$(jbody ref "$REF_P" target_url https://repo.dustroot.com/echo-secret)"; UTA=$(echo "$BODY" | J use_token)
call POST /api/demipass/transfer "$A" '{"secret":"kb-panel","to":"agent-f"}'; [ "$CODE" = 409 ] && ok "transfer to an agent → 409" || fail "transfer agent: $CODE $BODY"
call POST /api/demipass/transfer "$X" '{"secret":"x-thing","to":"person-k"}'; [ "$CODE" = 403 ] && ok "transfer to someone you are not connected to → 403" || fail "transfer unconnected: $CODE $BODY"
call POST /api/demipass/transfer "$A" '{"secret":"kb-panel","to":"person-k"}'; [ "$CODE" = 403 ] && [ "$(echo "$BODY" | J intent)" = "transfer:$SID_P" ] && ok "transfer needs A's PIN (intent transfer:$SID_P)" || fail "transfer pin: $CODE $BODY"
pin "$A" 4321 "transfer:$SID_P"
call POST /api/demipass/transfer "$A" '{"secret":"kb-panel","to":"person-k"}'
KEPT=$(echo "$BODY" | J kept.id)
[ "$CODE" = 200 ] && [ "$(echo "$BODY" | J ref)" = "$REF_P" ] && [ "$(echo "$BODY" | J ended_delegations)" = 1 ] && [ "$(echo "$BODY" | J kept.state)" = active ] && ok "A → K transfer: same ref, F's delegation ended, A keeps a use-only share" || fail "transfer: $CODE $BODY"
[ "$(Q "SELECT did FROM blindkey_secrets WHERE id=$SID_P")" = "$DK" ] && ok "the secret is in K's vault" || fail "owner"
call POST /api/demipass/use "$A" "$(jbody use_token "$UTA" params '{"url":"https://repo.dustroot.com/echo-secret","method":"GET"}')"; { [ "$CODE" = 403 ] || [ "$CODE" = 410 ]; } && ok "a use-token A minted before the transfer no longer works" || fail "pre-transfer token: $CODE $BODY"
call POST /api/demipass/use "$F" "$(jbody ref "$REF_P" params '{"url":"https://repo.dustroot.com/echo-secret","method":"GET"}')"; [ "$CODE" = 403 ] && ok "F's old delegation from A no longer opens it" || fail "F after transfer: $CODE"
call POST /api/demipass/use "$A" "$(jbody ref "$REF_P" params '{"url":"https://repo.dustroot.com/echo-secret","method":"GET"}')"; [ "$CODE" = 200 ] && echo "$BODY" | grep -q REDACTED && ok "A reaches it through the kept share, same ref" || fail "A kept use: $CODE $BODY"
call POST /api/demipass/reveal "$A" '{"name":"kb-panel"}'; [ "$CODE" = 404 ] && ok "A can no longer reveal it" || fail "A reveal after: $CODE"
call GET /api/demipass/shares "$K"; [ "$(echo "$BODY" | J given.0.via)" = transfer ] && [ "$(echo "$BODY" | J given.0.recipient)" = owner-a ] && ok "K sees A's kept access (via transfer) — nothing for K to accept" || fail "K given: $BODY"
call POST /api/demipass/shares/$KEPT/revoke "$K"; [ "$CODE" = 200 ] && ok "K can revoke A's kept access" || fail "K revoke kept: $CODE $BODY"
call POST /api/demipass/use "$A" "$(jbody ref "$REF_P" params '{"url":"https://repo.dustroot.com/echo-secret","method":"GET"}')"; [ "$CODE" = 403 ] && ok "then A → 403" || fail "A after K revoke: $CODE"
SID_KB=$(Q "SELECT id FROM blindkey_secrets WHERE ref_code='$REF_KB'"); pin "$A" 4321 "transfer:$SID_KB"
call POST /api/demipass/transfer "$A" '{"secret":"kyle-racknerd","to":"person-k","keep":"use"}'
[ "$CODE" = 200 ] && [ "$(Q "SELECT did||'|'||account_username||'|'||target_host_pattern FROM blindkey_secrets s JOIN blindkey_contexts c ON c.secret_id=s.id WHERE s.id=$SID_KB")" = "$DK|root|203.0.113.7" ] && ok "the raw-received RackNerd entry moves to K with its user, host binding and note" || fail "kb transfer: $CODE $BODY"
# name collision
call POST /api/demipass/store "$K" "$(jbody name dup value zzzzzzzzk1)"; call POST /api/demipass/store "$A" "$(jbody name dup value "$SEC_DUP")"
SID_D=$(Q "SELECT id FROM blindkey_secrets WHERE did='$DA' AND name='dup'")
call POST /api/demipass/transfer "$A" '{"secret":"dup","to":"person-k"}'; [ "$CODE" = 403 ] && ok "whether K has a name is not answered before the PIN" || fail "dup pre-pin: $CODE $BODY"
pin "$A" 4321 "transfer:$SID_D"; call POST /api/demipass/transfer "$A" '{"secret":"dup","to":"person-k"}'; [ "$CODE" = 409 ] && [ "$(echo "$BODY" | J name_taken)" = True ] && ok "a name K already uses → 409, nothing moved" || fail "dup: $CODE $BODY"
pin "$A" 4321 "transfer:$SID_D"; call POST /api/demipass/transfer "$A" '{"secret":"dup","to":"person-k","new_name":"dup_v9"}'; [ "$CODE" = 400 ] && ok "new_name ending in _v<n> → 400 (could shadow K's own secret)" || fail "v-suffix: $CODE $BODY"
pin "$A" 4321 "transfer:$SID_D"; call POST /api/demipass/transfer "$A" '{"secret":"dup","to":"person-k","new_name":"dup-from-a","keep":"none"}'
[ "$CODE" = 200 ] && [ "$(echo "$BODY" | J name)" = dup-from-a ] && [ "$(echo "$BODY" | J kept)" = None ] && ok "with new_name it lands as dup-from-a; keep:none leaves A nothing" || fail "dup new_name: $CODE $BODY"

# a versioned name lands as its plain base name, version 1 (never shadowing K's own same-named secret)
call POST /api/demipass/store "$A" '{"name":"rot_v3","value":"zzzzzzzzr3"}'; python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute(\"UPDATE blindkey_secrets SET version=3 WHERE did=? AND name='rot_v3'\", (sys.argv[2],)); c.commit()" "$DB_PATH" "$DA"
SID_R=$(Q "SELECT id FROM blindkey_secrets WHERE did='$DA' AND name='rot_v3'"); pin "$A" 4321 "transfer:$SID_R"
call POST /api/demipass/transfer "$A" '{"secret":"rot_v3","to":"person-k","keep":"none"}'
[ "$CODE" = 200 ] && [ "$(Q "SELECT name||'|'||version FROM blindkey_secrets WHERE id=$SID_R")" = "rot|1" ] && ok "rot_v3 (v3) lands in K's vault as 'rot', version 1" || fail "M1: $CODE $BODY $(Q "SELECT name||'|'||version FROM blindkey_secrets WHERE id=$SID_R")"
# mid-rotation: refused
call POST /api/demipass/store "$A" '{"name":"spin","value":"zzzzzzzzs1"}'; call POST /api/demipass/store "$A" '{"name":"spin_v2","value":"zzzzzzzzs2"}'
python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute(\"UPDATE blindkey_secrets SET status='rotating', rotate_expires_at=datetime('now','+1 hour') WHERE did=? AND name='spin'\", (sys.argv[2],)); c.execute(\"UPDATE blindkey_secrets SET version=2 WHERE did=? AND name='spin_v2'\", (sys.argv[2],)); c.commit()" "$DB_PATH" "$DA"
call POST /api/demipass/transfer "$A" '{"secret":"spin","to":"person-k"}'; [ "$CODE" = 409 ] && echo "$BODY" | grep -q rotat && ok "a secret mid-rotation cannot be transferred" || fail "M2: $CODE $BODY"
# /use with name + owner_did reaches the owner's secret even when the caller has one with that name
BA=$(Q "SELECT use_count FROM blindkey_secrets WHERE id=$SID_A")
call POST /api/demipass/use "$K" "$(jbody name forge-token owner_did "$DA" params '{"url":"https://repo.dustroot.com/echo-secret","method":"GET"}')"
[ "$CODE" = 200 ] && [ "$(Q "SELECT use_count FROM blindkey_secrets WHERE id=$SID_A")" = $((BA+1)) ] && ok "/use {name, owner_did} uses the owner's secret, not K's same-named one" || fail "L2: $CODE $BODY"

# ── plaintext ──
for v in "$SEC_A" "$SEC_K" "$SEC_KB" "$SEC_DUP"; do grep -qF -- "$v" "$S/server.log" && fail "a secret value is in the server log"; done; ok "no secret value in the server log"
[ "$(Q "SELECT COUNT(*) FROM blindkey_events WHERE detail LIKE '%Zq81%' OR detail LIKE '%7f3e9c1d%'")" = 0 ] && ok "none in blindkey_events either" || fail "value in events"

echo; [ $fails = 0 ] && echo "ALL OK" || echo "$fails FAILED"; exit $fails
