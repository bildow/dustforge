#!/bin/bash
# Smoke of per-scope HTTP methods and scope changes approved on the phone (2026-11-11: Brain's dashboard token).
# server.js on a throwaway DB; /use's fetch() to repo.dustroot.com and server.dustroot.com sent to a local stand-in
# that logs every request. Owner A (PIN), the owner's own agent session AG (same wallet, no PIN), agent B (a linked
# silicon of A's fleet, like Brain).
#   - legacy: a scope row made before the column (allowed_methods NULL) still allows every method;
#   - AG adds scope 'brain-panel' = http_header, GET only, one exact URL, handed to B: 202 approval_pending (kind
#     scope, critical, waits a day); the owner opens it with the PIN and approves; the same call with approval_id
#     creates the scope and the delegation, once;
#   - B: GET on that URL acts (server.dustroot.com is on the host list, the path is exact); POST is refused before any
#     connection (no egress row, no upstream hit); the sibling path and the default scope are refused;
#   - narrowing the methods needs no PIN; widening parks on the phone; rotation carries the list;
#   - no secret value in the server log.
set -u
W=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
S=$(mktemp -d /tmp/dustforge-scope-methods-smoke.XXXXXX)
PORT=${PORT:-3793}; UP_PORT=${UP_PORT:-3794}; API=http://127.0.0.1:$PORT
[ -d "$W/node_modules" ] || export NODE_PATH=${NODE_PATH:-/home/flimflam/project/dustforge/node_modules}
export IDENTITY_MASTER_KEY=$(python3 -c 'import secrets;print(secrets.token_hex(32))') DB_PATH=$S/dustforge.db PORT \
  STALWART_HOST=127.0.0.1 STALWART_PORT=1 SMTP_RELAY_HOST= SMTP_HOST=127.0.0.1 SMTP_PORT=9 \
  TEST_UPSTREAM=http://127.0.0.1:$UP_PORT TEST_UPSTREAM_HOSTS=repo.dustroot.com,server.dustroot.com UP_LOG=$S/upstream.log
cd "$W"
SEC='dash-token-value-7f3a19c2e5'
node -e '
const http = require("http"), fs = require("fs");
http.createServer((req, res) => { req.resume(); req.on("end", () => { fs.appendFileSync(process.env.UP_LOG, req.method + " " + req.url + "\n"); res.writeHead(200, { "content-type": "application/json" }); res.end(JSON.stringify({ path: req.url, method: req.method, seen: req.headers.authorization || "" })); }); })
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
const mk = (u) => { const id = identity.createIdentity(); const enc = id.encrypted_private_key || id.encryptedPrivateKey;
  db.prepare("INSERT INTO identity_wallets (did, username, email, encrypted_private_key, balance_cents, password_hash) VALUES (?, ?, ?, ?, 100000, ?)").run(id.did, u, u + "@dustforge.com", enc, process.argv[1]);
  db.prepare("INSERT INTO identity_transactions (did, amount_cents, type, description, balance_after) VALUES (?, 100000, ?, ?, 100000)").run(id.did, "topup", "smoke"); return id.did; };
const a = mk("owner-a"), b = mk("agent-b");
// B is a linked silicon of A'"'"'s fleet (its own wallet, joined by the owner; created_by_fleet 0 — Brain'"'"'s shape).
const f = db.prepare("INSERT INTO fleets (owner_did, name, slug) VALUES (?, ?, ?)").run(a, "Owner A", "owner-agents").lastInsertRowid;
db.prepare("INSERT INTO fleet_silicons (fleet_id, member_did, handle, silicon_id, status, created_by_fleet, joined_via) VALUES (?, ?, ?, ?, ?, 0, ?)").run(f, b, "agent-b", "sil_scope_b", "active", "owner");' "$H"
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
pin(){ call POST /api/identity/gate/verify "$1" '{"gate":"pin","pin":"'$2'","intent":"'$3'"}'; [ "$CODE" = 200 ] || fail "pin $3: $CODE $BODY"; }
egress(){ Q "SELECT COUNT(*) FROM blindkey_events WHERE event_type='egress' AND secret_id=$1"; }
hits(){ [ -f "$UP_LOG" ] && wc -l <"$UP_LOG" || echo 0; }
A=$(login owner-a); AG=$(login owner-a); B=$(login agent-b)
BDID=$(Q "SELECT did FROM identity_wallets WHERE username='agent-b'")
call POST /api/identity/pin "$A" '{"pin":"4321","password":"hunter22"}'
call POST /api/demipass/store "$A" '{"name":"dash-token","value":"'$SEC'","secret_type":"api_key"}'; REF=$(echo "$BODY" | J ref)
SID=$(Q "SELECT id FROM blindkey_secrets WHERE ref_code='$REF'")
[ -n "$SID" ] && ok "stored dash-token ($REF), default scope: http_header on any allowed host, any method" || fail "store: $CODE $BODY"
[ "$(Q "SELECT allowed_methods IS NULL FROM blindkey_contexts WHERE secret_id=$SID AND context_name='default'")" = 1 ] && ok "a scope made without a method list has NULL (any method)" || fail "default methods: $(Q "SELECT allowed_methods FROM blindkey_contexts WHERE secret_id=$SID")"

# ── legacy: a scope from before the column allows every method ──
call POST /api/demipass/use "$AG" '{"ref":"'$REF'","params":{"url":"https://repo.dustroot.com/legacy","method":"POST","body":{"a":1}}}'
[ "$CODE" = 200 ] && [ "$(echo "$BODY" | J result.body.method)" = POST ] && ok "legacy scope (NULL methods): POST acts as before" || fail "legacy post: $CODE $BODY"
[ "$(echo "$BODY" | J result.body.seen)" = "Bearer [REDACTED]" ] && ok "the value went out as the header and came back redacted" || fail "redaction: $BODY"

# ── the owner's agent adds a GET-only scope on one URL, handed to B: a request on the phone ──
ADD='{"secret_name":"dash-token","context_name":"brain-panel","action_type":"http_header","target_url_pattern":"https://server.dustroot.com/api/panel/brain","allowed_methods":["get"],"delegate_did":"'$BDID'","ask_owner":true}'
call POST /api/demipass/context/add "$AG" '{"secret_name":"dash-token","context_name":"x","action_type":"ssh_exec","allowed_methods":["GET"]}'
[ "$CODE" = 400 ] && ok "allowed_methods on an ssh_exec scope → 400" || fail "methods on ssh: $CODE $BODY"
call POST /api/demipass/context/add "$AG" '{"secret_name":"dash-token","context_name":"x","action_type":"http_header","allowed_methods":["FETCH"]}'
[ "$CODE" = 400 ] && ok "an unknown method → 400" || fail "bad method: $CODE $BODY"
call POST /api/demipass/context/add "$AG" '{"secret_name":"dash-token","context_name":"x","action_type":"http_header","delegate_did":"did:key:zNobody"}'
[ "$CODE" = 404 ] && ok "an unknown delegate → 404 before anything is asked" || fail "bad delegate: $CODE $BODY"
call POST /api/demipass/context/add "$AG" "${ADD%,\"ask_owner\":true\}}}"
[ "$CODE" = 403 ] && [ "$(echo "$BODY" | J intent)" = "scope:$SID" ] && echo "$BODY" | grep -q "ask_owner" && ok "without the PIN (and without ask_owner): the PIN challenge, which names ask_owner" || fail "bare add: $CODE $BODY"
call POST /api/demipass/context/add "$AG" "$ADD"; AP=$(echo "$BODY" | J approval_id)
[ "$CODE" = 202 ] && [ "$(echo "$BODY" | J status)" = approval_pending ] && [ -n "$AP" ] && [ "$AP" != None ] && ok "agent adds the scope → 202 approval_pending, request $AP" || fail "add parks: $CODE $BODY"
[ "$(Q "SELECT kind||'/'||depth FROM use_approvals WHERE id=$AP")" = "scope/critical" ] && ok "kind scope, critical (the PIN opens it)" || fail "kind/depth: $(Q "SELECT kind||'/'||depth FROM use_approvals WHERE id=$AP")"
SUMMARY=$(Q "SELECT summary FROM use_approvals WHERE id=$AP"); echo "$SUMMARY" | grep -q "new scope 'brain-panel': http_header GET only on https://server.dustroot.com/api/panel/brain, handed to agent" && ok "the card names it: $SUMMARY" || fail "summary: $SUMMARY"
[ "$(Q "SELECT json_extract(bound_call,'$.body.allowed_methods[0]')||'|'||json_extract(bound_call,'$.body.delegate_did') FROM use_approvals WHERE id=$AP")" = "get|$BDID" ] && ok "the request binds the exact change (methods, delegate)" || fail "bound: $(Q "SELECT bound_call FROM use_approvals WHERE id=$AP")"
WAIT=$(python3 -c "import sqlite3,sys,datetime; c=sqlite3.connect(sys.argv[1]); a,b=c.execute('SELECT created_at, expires_at FROM use_approvals WHERE id=?',(int(sys.argv[2]),)).fetchone(); f=lambda s: datetime.datetime.fromisoformat(s.replace('Z','+00:00')); print(int((f(b)-f(a)).total_seconds()))" "$DB_PATH" "$AP")
[ "$WAIT" -ge 86000 ] && ok "it waits a day for the owner ($WAIT s)" || fail "wait: $WAIT s"
[ "$(Q "SELECT COUNT(*) FROM blindkey_contexts WHERE secret_id=$SID")" = 1 ] && [ -z "$(Q "SELECT id FROM demipass_delegations WHERE delegate_did='$BDID'")" ] && ok "nothing granted yet" || fail "granted early"
call POST /api/demipass/context/add "$AG" "$ADD"; [ "$CODE" = 202 ] && [ "$(echo "$BODY" | J approval_id)" = "$AP" ] && ok "asking again returns the same request" || fail "dedupe: $CODE $BODY"
call GET /api/demipass/approvals "$A"; [ "$(echo "$BODY" | J incoming.0.id)" = "$AP" ] && [ "$(echo "$BODY" | J incoming.0.kind)" = scope ] && ok "the owner's app lists it" || fail "list: $BODY"
call POST /api/demipass/approvals/$AP/open "$AG"; [ "$CODE" = 403 ] && [ "$(echo "$BODY" | J intent)" = "approval-open:$AP" ] && ok "the agent's own session cannot open it: the PIN does" || fail "agent open: $CODE $BODY"
pin "$A" 4321 "approval-open:$AP"; call POST /api/demipass/approvals/$AP/open "$A"; K=$(echo "$BODY" | J code)
[ "$CODE" = 200 ] && [ "$(echo "$BODY" | J approval.call.body.context_name)" = brain-panel ] && ok "opened with the PIN: the full change is on the screen" || fail "open: $CODE $BODY"
call POST /api/demipass/approvals/$AP/approve "$A" '{"code":"'$K'"}'; [ "$CODE" = 200 ] && ok "approved on the phone" || fail "approve: $CODE $BODY"
call POST /api/demipass/context/add "$AG" "${ADD%\}},\"approval_id\":$AP}"
CID=$(Q "SELECT id FROM blindkey_contexts WHERE secret_id=$SID AND context_name='brain-panel'")
[ "$CODE" = 200 ] && [ -n "$CID" ] && [ "$(echo "$BODY" | J context.allowed_methods.0)" = GET ] && [ "$(echo "$BODY" | J delegate_did)" = "$BDID" ] && ok "with approval_id: scope created (GET only), handed to B (delegation $(echo "$BODY" | J delegation_id))" || fail "apply: $CODE $BODY"
[ "$(Q "SELECT allowed_methods FROM blindkey_contexts WHERE id=$CID")" = '["GET"]' ] && ok "stored upper-case, deduplicated" || fail "stored: $(Q "SELECT allowed_methods FROM blindkey_contexts WHERE id=$CID")"
[ "$(Q "SELECT context_id FROM demipass_delegations WHERE delegate_did='$BDID' AND secret_id=$SID")" = "$CID" ] && ok "the delegation is bound to that scope alone" || fail "delegation ctx: $(Q "SELECT context_id FROM demipass_delegations WHERE delegate_did='$BDID'")"
call POST /api/demipass/context/add "$AG" "${ADD%\}},\"approval_id\":$AP}"; [ "$CODE" = 410 ] && ok "…once" || fail "reuse: $CODE $BODY"
call GET "/api/blindkey/contexts?secret_name=dash-token" "$A"
[ "$(echo "$BODY" | python3 -c 'import json,sys; d=json.load(sys.stdin); print({c["context_name"]: c["allowed_methods"] for c in d["contexts"]})')" = "{'default': None, 'brain-panel': ['GET']}" ] && ok "the scope list shows the methods" || fail "list methods: $BODY"

# ── B uses it: GET on the exact path acts, nothing else does ──
E0=$(egress $SID); H0=$(hits)
call POST /api/demipass/request-token "$B" '{"ref":"'$REF'","context":"brain-panel","target_url":"https://server.dustroot.com/api/panel/brain"}'; T=$(echo "$BODY" | J use_token)
[ "$CODE" = 200 ] && [ -n "$T" ] && [ "$T" != None ] || fail "B token: $CODE $BODY"
call POST /api/demipass/use "$B" '{"use_token":"'$T'","params":{"url":"https://server.dustroot.com/api/panel/brain","method":"GET"}}'
[ "$CODE" = 200 ] && [ "$(echo "$BODY" | J result.body.path)" = "/api/panel/brain" ] && [ "$(echo "$BODY" | J result.body.method)" = GET ] && ok "B: GET https://server.dustroot.com/api/panel/brain acts (host on the list, path exact)" || fail "B get: $CODE $BODY"
[ "$(egress $SID)" = $((E0 + 1)) ] && [ "$(hits)" = $((H0 + 1)) ] && ok "one egress row, one upstream hit" || fail "egress $(egress $SID) hits $(hits)"
call POST /api/demipass/request-token "$B" '{"ref":"'$REF'","context":"brain-panel","target_url":"https://server.dustroot.com/api/panel/brain"}'; T=$(echo "$BODY" | J use_token)
call POST /api/demipass/use "$B" '{"use_token":"'$T'","params":{"url":"https://server.dustroot.com/api/panel/brain","method":"POST","body":{"x":1}}}'
[ "$CODE" = 403 ] && echo "$BODY" | grep -q "allows only GET" && ok "B: POST → 403, named" || fail "B post: $CODE $BODY"
[ "$(egress $SID)" = $((E0 + 1)) ] && [ "$(hits)" = $((H0 + 1)) ] && ok "…before any connection: no egress row, no upstream hit" || fail "post leaked: egress $(egress $SID) hits $(hits)"
[ "$(Q "SELECT COUNT(*) FROM demipass_security_events WHERE event_type='method_not_allowed'")" = 1 ] && ok "a method_not_allowed event" || fail "event"
# on an elevated secret the refusal comes before the owner is asked: no approval request is made for a call that cannot run
call POST /api/demipass/gate-policy "$A" '{"ref":"'$REF'","security_depth":"elevated"}'; [ "$CODE" = 200 ] || fail "set elevated: $CODE $BODY"
call POST /api/demipass/request-token "$B" '{"ref":"'$REF'","context":"brain-panel","target_url":"https://server.dustroot.com/api/panel/brain"}'; T=$(echo "$BODY" | J use_token)
call POST /api/demipass/use "$B" '{"use_token":"'$T'","params":{"url":"https://server.dustroot.com/api/panel/brain","method":"POST"}}'
[ "$CODE" = 403 ] && echo "$BODY" | grep -q "allows only GET" && [ "$(Q "SELECT COUNT(*) FROM use_approvals WHERE kind='use'")" = 0 ] && ok "elevated: POST refused before any approval is requested" || fail "elevated post: $CODE $(Q "SELECT COUNT(*) FROM use_approvals WHERE kind='use'") $BODY"
call POST /api/demipass/use "$AG" '{"ref":"'$REF'","context":"brain-panel","params":{"url":"https://server.dustroot.com/api/panel/brain","method":"POST"}}'
[ "$CODE" = 403 ] && [ "$(Q "SELECT COUNT(*) FROM use_approvals WHERE kind='use'")" = 0 ] && ok "…on the one-call path too" || fail "elevated direct post: $CODE $BODY"
python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute(\"UPDATE blindkey_secrets SET security_depth='standard' WHERE id=?\", (int(sys.argv[2]),)); c.commit()" "$DB_PATH" "$SID"   # back to standard (lowering takes PIN + 2FA; test only)
call POST /api/demipass/request-token "$B" '{"ref":"'$REF'","context":"brain-panel","target_url":"https://server.dustroot.com/api/panel/brain2b"}'
[ "$CODE" = 403 ] && ok "B: the sibling path /api/panel/brain2b → 403 (exact pattern)" || fail "B brain2b: $CODE $BODY"
call POST /api/demipass/request-token "$B" '{"ref":"'$REF'","context":"default","target_url":"https://repo.dustroot.com/anything"}'
[ "$CODE" = 403 ] && ok "B: the default scope → 403 (the delegation is for brain-panel)" || fail "B default: $CODE $BODY"
call POST /api/demipass/request-token "$B" '{"ref":"'$REF'","context":"brain-panel","target_url":"https://server.dustroot.com/api/panel/brain?x=1"}'
[ "$CODE" = 403 ] && ok "B: a query string on the exact pattern → 403" || fail "B query: $CODE $BODY"

# ── the owner's agent: fewer methods needs nothing; more parks; rotation carries the list ──
call PATCH /api/demipass/context/$CID "$AG" '{"allowed_methods":["GET","POST"]}'
[ "$CODE" = 403 ] && ok "adding POST without the PIN → the PIN challenge (the app answers it)" || fail "widen bare: $CODE $BODY"
call PATCH /api/demipass/context/$CID "$AG" '{"allowed_methods":["GET","POST"],"ask_owner":true}'
[ "$CODE" = 202 ] && [ "$(Q "SELECT allowed_methods FROM blindkey_contexts WHERE id=$CID")" = '["GET"]' ] && ok "adding POST without the PIN → a request on the phone; nothing changed ($(Q "SELECT summary FROM use_approvals WHERE id=$(echo "$BODY" | J approval_id)"))" || fail "widen: $CODE $BODY"
call PATCH /api/demipass/context/$CID "$AG" '{"allowed_methods":null,"ask_owner":true}'
[ "$CODE" = 202 ] && ok "lifting the list (any method) → a request on the phone" || fail "lift: $CODE $BODY"
call PATCH /api/demipass/context/$CID "$AG" '{"allowed_methods":[]}'
[ "$CODE" = 200 ] && [ "$(Q "SELECT allowed_methods FROM blindkey_contexts WHERE id=$CID")" = '[]' ] && ok "narrowing to no method: no PIN" || fail "narrow: $CODE $BODY"
call POST /api/demipass/request-token "$B" '{"ref":"'$REF'","context":"brain-panel","target_url":"https://server.dustroot.com/api/panel/brain"}'; T=$(echo "$BODY" | J use_token)
call POST /api/demipass/use "$B" '{"use_token":"'$T'","params":{"url":"https://server.dustroot.com/api/panel/brain","method":"GET"}}'
[ "$CODE" = 403 ] && echo "$BODY" | grep -q "no methods are allowed" && ok "B: GET now refused (nothing allowed)" || fail "B none: $CODE $BODY"

# ── a scope edit's approval is bound to that scope: a sibling with the same pattern gets its own request ──
pin "$A" 4321 "scope:$SID"; call POST /api/demipass/context/add "$A" '{"secret_name":"dash-token","context_name":"brain-panel-2","action_type":"http_header","target_url_pattern":"https://server.dustroot.com/api/panel/brain","allowed_methods":["GET"]}'
C2=$(Q "SELECT id FROM blindkey_contexts WHERE secret_id=$SID AND context_name='brain-panel-2'"); [ "$CODE" = 200 ] && [ -n "$C2" ] || fail "sibling add: $CODE $BODY"
call PATCH /api/demipass/context/$CID "$AG" '{"allowed_methods":["GET","POST"],"ask_owner":true}'; R1=$(echo "$BODY" | J approval_id)
call PATCH /api/demipass/context/$C2 "$AG" '{"allowed_methods":["GET","POST"],"ask_owner":true}'; R2=$(echo "$BODY" | J approval_id)
[ "$CODE" = 202 ] && [ -n "$R1" ] && [ "$R1" != "$R2" ] && [ "$(Q "SELECT json_extract(bound_call,'$.body.context_id') FROM use_approvals WHERE id=$R2")" = "$C2" ] && ok "the same widening on a sibling scope is a different request, bound to the scope id ($R1 vs $R2)" || fail "sibling binding: $CODE $R1 $R2 $BODY"

call PATCH /api/demipass/context/$C2 "$AG" '{"context_name":"brain-panel-renamed","ask_owner":true}'; R3=$(echo "$BODY" | J approval_id)
[ "$CODE" = 202 ] && [ "$(Q "SELECT json_extract(bound_call,'$.body.context_name')||'|'||json_extract(bound_call,'$.body.current_context_name') FROM use_approvals WHERE id=$R3")" = "brain-panel-renamed|brain-panel-2" ] && ok "a rename binds the asked name next to the current one" || fail "rename binding: $CODE $(Q "SELECT bound_call FROM use_approvals WHERE id=$R3")"
# a pending scope request on a phone-wrapped secret survives a restart (it needs no one-use key)
python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute(\"UPDATE blindkey_secrets SET wrap_state='device' WHERE id=?\", (int(sys.argv[2]),)); c.commit()" "$DB_PATH" "$SID"
kill $SRV; wait $SRV 2>/dev/null; node --require ./test/fixtures/upstream-redirect.js server.js >>"$S/server.log" 2>&1 & SRV=$!
for i in $(seq 1 40); do curl -s -o /dev/null "$API/" && break; sleep 0.5; done
[ "$(Q "SELECT status FROM use_approvals WHERE id=$R3")" = pending ] && ok "after a restart the scope request on a wrapped secret is still pending" || fail "restart expired it: $(Q "SELECT status FROM use_approvals WHERE id=$R3")"
python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute(\"UPDATE blindkey_secrets SET wrap_state=NULL WHERE id=?\", (int(sys.argv[2]),)); c.commit()" "$DB_PATH" "$SID"
A=$(login owner-a); AG=$(login owner-a); B=$(login agent-b)

# ── http_body honours the list too ──
pin "$A" 4321 "scope:$SID"; call POST /api/demipass/context/add "$A" '{"secret_name":"dash-token","context_name":"put-body","action_type":"http_body","target_url_pattern":"https://repo.dustroot.com/hook","allowed_methods":["PUT"]}'
[ "$CODE" = 200 ] && [ "$(echo "$BODY" | J context.allowed_methods.0)" = PUT ] || fail "body scope add: $CODE $BODY"
H1=$(hits)
call POST /api/demipass/request-token "$AG" '{"ref":"'$REF'","context":"put-body","action":"http_body","target_url":"https://repo.dustroot.com/hook"}'; T=$(echo "$BODY" | J use_token)
call POST /api/demipass/use "$AG" '{"use_token":"'$T'","params":{"url":"https://repo.dustroot.com/hook","method":"POST","body_template":{"k":"{{secret}}"}}}'
[ "$CODE" = 403 ] && echo "$BODY" | grep -q "allows only PUT" && [ "$(hits)" = "$H1" ] && ok "http_body: POST on a PUT-only scope → 403, no upstream hit" || fail "body post: $CODE $(hits)/$H1 $BODY"

# ── rotation carries the list (the ref moves to the new version) ──
call POST /api/blindkey/rotate "$A" '{"name":"dash-token","new_value":"dash-token-value-2-9b1e4c"}'
NSID=$(Q "SELECT id FROM blindkey_secrets WHERE did='$(Q "SELECT did FROM identity_wallets WHERE username='owner-a'")' AND name LIKE 'dash-token%' AND status='active' ORDER BY id DESC LIMIT 1")
[ "$CODE" = 200 ] && [ "$NSID" != "$SID" ] && [ "$(Q "SELECT allowed_methods FROM blindkey_contexts WHERE secret_id=$NSID AND context_name='brain-panel'")" = '[]' ] && [ "$(Q "SELECT allowed_methods IS NULL FROM blindkey_contexts WHERE secret_id=$NSID AND context_name='default'")" = 1 ] && ok "rotation carries each scope's method list (the narrowed [] and the legacy NULL) to the new version" || fail "rotate: $CODE $NSID $(Q "SELECT allowed_methods FROM blindkey_contexts WHERE secret_id=$NSID AND context_name='brain-panel'")"

# ── an outside caller gets nothing; no value in the log ──
call POST /api/demipass/context/add "$B" "$ADD"; [ "$CODE" = 404 ] || [ "$CODE" = 403 ] && ok "B cannot add a scope to A's secret ($CODE)" || fail "B add: $CODE $BODY"
! grep -q "$SEC" "$S/server.log" && ok "no secret value in the server log" || fail "value in log"
[ $fails = 0 ] && echo "ALL OK" || { echo "$fails FAILED"; exit 1; }
