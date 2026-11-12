#!/bin/bash
# Smoke of DemiPass as a GitHub App (github_app.js, Aaron 2026-11-12): a GitHub App private key in custody, scopes of
# kind github_app_token, installation tokens minted per /use, recorded, revoked.
# Legacy fixture first: the database is made by main's server before this branch (6de5e78), with a scope and a
# delegation bound to it; this branch then opens it (blindkey_contexts rebuilt so its CHECK admits github_app_token —
# same rows, same ids, the delegation still resolves, the legacy use still works).
# api.github.com is a local stand-in (test/fixtures/github-standin.js behind TEST_UPSTREAM_HOSTS) that checks the
# app JWT (RS256, iss, iat −60 s, exp ≤ 10 min) and mints/revokes ghs_ tokens. Owner A (PIN), A's own agent session AG
# (no PIN), agent B (a linked silicon of A's fleet).
#   - store: an RSA .pem with its App ID (a bad .pem or no App ID refused, the value never echoed); no default scope;
#     never revealed; deposit refuses the type;
#   - AG adds scope 'reviewers' (installation, two exact repos, contents+pull_requests write, ≤ 1800 s) handed to B:
#     202 approval kind scope; the owner approves with the PIN; the same call with approval_id applies it, once;
#   - B mints: a subset (one repo, contents:read) → a token for exactly that; the defaults → the whole scope; each a
#     metered use (10 DD) and a security event naming wallet, scope, repos, permissions, expiry; expiry recorded and
#     listed by /expiring; a wrong repo, a wider permission, a longer TTL refused before any connection;
#   - widening the scope parks on the phone; narrowing applies and revokes the scope's live tokens;
#   - the installation's ceiling: GitHub's 422 → 403 "reinstall", refunded; a token wider than asked is revoked, not
#     handed out; an elevated key parks each mint as an approval and is never wrapped;
#   - the git credential helper answers git with x-access-token and a fresh token, for github.com only;
#   - revocation: our TTL passing, deleting the delegation, deleting the scope → DELETE /installation/token;
#   - rotation carries the App ID and the scope; no key, JWT or token in the server log or the database in clear.
set -u
W=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
S=$(mktemp -d /tmp/dustforge-github-app-smoke.XXXXXX)
PORT=${PORT:-3871}; UP_PORT=${UP_PORT:-3872}; API=http://127.0.0.1:$PORT
NM=/home/flimflam/project/dustforge/node_modules; [ -d "$W/node_modules" ] && NM=$W/node_modules
export NODE_PATH=$NM
export IDENTITY_MASTER_KEY=$(python3 -c 'import secrets;print(secrets.token_hex(32))') DB_PATH=$S/dustforge.db PORT \
  STALWART_HOST=127.0.0.1 STALWART_PORT=1 SMTP_RELAY_HOST= SMTP_HOST=127.0.0.1 SMTP_PORT=9 \
  TEST_UPSTREAM=http://127.0.0.1:$UP_PORT TEST_UPSTREAM_HOSTS=repo.dustroot.com,api.github.com GITHUB_TOKEN_SWEEP_MS=1000
LEGACY=6de5e78a0644a6934fa34db1d16f9c3c348b8311   # main before this branch
SRV=; UP=
trap 'kill $SRV $UP 2>/dev/null; [ -n "${KEEP:-}" ] || rm -rf "$S"' EXIT
start(){ ( cd "$1" && exec node ${3:+--require "$W/test/fixtures/upstream-redirect.js"} server.js >>"$S/server-$2.log" 2>&1 ) & SRV=$!
  for i in $(seq 1 60); do curl -s -o /dev/null "$API/" && break; sleep 0.5; done
  kill -0 $SRV 2>/dev/null || { echo "server ($2) died:"; tail -5 "$S/server-$2.log"; exit 1; }; }
stop(){ kill $SRV 2>/dev/null; wait $SRV 2>/dev/null; SRV=; }
fails=0; ok(){ echo "ok   $*"; }; fail(){ echo "FAIL $*"; fails=$((fails+1)); }
J(){ python3 -c 'import json,sys; d=json.load(sys.stdin); v=d
for k in sys.argv[1].split("."):
    v = v[int(k)] if isinstance(v, list) else (v or {}).get(k)
print(v)' "$1"; }
Q(){ python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); r=c.execute(sys.argv[2]).fetchone(); print(r[0] if r and r[0] is not None else '')" "$DB_PATH" "$1"; }
call(){ local m=$1 p=$2 t=$3 b=${4:-}
  BODY=$(curl -s -o - -w '\n%{http_code}' -X "$m" "$API$p" -H 'Content-Type: application/json' ${t:+-H "Authorization: Bearer $t"} ${b:+-d "$b"})
  CODE=${BODY##*$'\n'}; BODY=${BODY%$'\n'*}; }
# a body from a file (the .pem never goes on a command line)
callf(){ BODY=$(curl -s -o - -w '\n%{http_code}' -X "$1" "$API$2" -H 'Content-Type: application/json' -H "Authorization: Bearer $3" -d @"$4"); CODE=${BODY##*$'\n'}; BODY=${BODY%$'\n'*}; rm -f "$4"; }
login(){ call POST /api/identity/auth-fingerprint "" '{"username":"'$1'","password":"hunter22","scope":"transact","expires_in":"1h"}'; echo "$BODY" | J token; }
pin(){ call POST /api/identity/gate/verify "$1" '{"gate":"pin","pin":"'$2'","intent":"'$3'"}'; [ "$CODE" = 200 ] || fail "pin $3: $CODE $BODY"; }
hits(){ local n=0; [ -f "$S/upstream.log" ] && n=$(grep -c -- "${1:-.}" "$S/upstream.log"); echo "${n:-0}"; }
mints(){ hits 'access_tokens'; }
revokes(){ hits 'DELETE /installation/token known'; }
waitfor(){ for i in $(seq 1 40); do [ "$(eval "$1")" = "$2" ] && return 0; sleep 0.25; done; return 1; }
# the response's token, written to a file (never printed); prints only whether it is one the stand-in minted
keep_token(){ echo "$BODY" | python3 -c 'import json,sys; t=(json.load(sys.stdin).get("result") or {}).get("token") or ""; open(sys.argv[1],"w").write(t)' "$S/$1"
  python3 -c 'import sys; t=open(sys.argv[1]).read(); print("minted" if t and t in open(sys.argv[2]).read().split() else "no")' "$S/$1" "$S/tokens" 2>/dev/null || echo no; }
umask 077

# ── keys: two RSA app keys (the second for rotation), public halves for the stand-in; never printed ──
( cd "$W" && node -e '
const c = require("crypto"), fs = require("fs"), d = process.argv[1];
for (const n of ["", "2"]) { const k = c.generateKeyPairSync("rsa", { modulusLength: 2048, privateKeyEncoding: { type: "pkcs1", format: "pem" }, publicKeyEncoding: { type: "spki", format: "pem" } });
  fs.writeFileSync(d + "/app" + n + ".pem", k.privateKey); fs.writeFileSync(d + "/app" + n + ".pub", k.publicKey); }
const ec = c.generateKeyPairSync("ec", { namedCurve: "prime256v1", privateKeyEncoding: { type: "pkcs8", format: "pem" }, publicKeyEncoding: { type: "spki", format: "pem" } });
fs.writeFileSync(d + "/ec.pem", ec.privateKey);' "$S" )
echo 424242 > "$S/app_id"; : > "$S/tokens"
node "$W/test/fixtures/github-standin.js" $UP_PORT "$S" & UP=$!

# ── legacy: main's server makes the database: a scope, and a delegation bound to it ──
mkdir -p "$S/old"; git -C "$W" archive $LEGACY | tar -x -C "$S/old"
start "$S/old" old with-upstream
H=$(printf '%s' hunter22 | sha256sum | cut -d' ' -f1)
( cd "$W" && node -e '
const identity = require("./identity"); const Database = require("better-sqlite3"); const db = new Database(process.env.DB_PATH);
for (const c of ["idempotency_key TEXT", "provenance TEXT DEFAULT '"'"'organic'"'"'"]) { try { db.exec("ALTER TABLE identity_transactions ADD COLUMN " + c); } catch (_) {} }
const mk = (u) => { const id = identity.createIdentity(); const enc = id.encrypted_private_key || id.encryptedPrivateKey;
  db.prepare("INSERT INTO identity_wallets (did, username, email, encrypted_private_key, balance_cents, password_hash) VALUES (?, ?, ?, ?, 100000, ?)").run(id.did, u, u + "@dustforge.com", enc, process.argv[1]);
  db.prepare("INSERT INTO identity_transactions (did, amount_cents, type, description, balance_after) VALUES (?, 100000, ?, ?, 100000)").run(id.did, "topup", "smoke"); return id.did; };
const a = mk("owner-a"), b = mk("agent-b");
const f = db.prepare("INSERT INTO fleets (owner_did, name, slug) VALUES (?, ?, ?)").run(a, "Owner A", "owner-agents").lastInsertRowid;
db.prepare("INSERT INTO fleet_silicons (fleet_id, member_did, handle, silicon_id, status, created_by_fleet, joined_via) VALUES (?, ?, ?, ?, ?, 0, ?)").run(f, b, "agent-b", "sil_gha_b", "active", "owner");' "$H" )
A=$(login owner-a); B=$(login agent-b)
BDID=$(Q "SELECT did FROM identity_wallets WHERE username='agent-b'")
call POST /api/identity/pin "$A" '{"pin":"4321","password":"hunter22"}'
call POST /api/demipass/store "$A" '{"name":"legacy-tok","value":"legacy-value-5c1e9a77b2","secret_type":"api_key"}'; LREF=$(echo "$BODY" | J ref)
LSID=$(Q "SELECT id FROM blindkey_secrets WHERE ref_code='$LREF'")
pin "$A" 4321 "scope:$LSID"; call POST /api/demipass/delegate "$A" '{"secret_name":"legacy-tok","delegate_did":"'$BDID'","context_name":"default"}'
LCTX=$(Q "SELECT id FROM blindkey_contexts WHERE secret_id=$LSID AND context_name='default'"); LDEL=$(Q "SELECT id FROM demipass_delegations WHERE secret_id=$LSID AND delegate_did='$BDID'")
NCTX=$(Q "SELECT COUNT(*) FROM blindkey_contexts")
stop
[ -n "$LCTX" ] && [ -n "$LDEL" ] && [ "$(Q "SELECT context_id FROM demipass_delegations WHERE id=$LDEL")" = "$LCTX" ] && Q "SELECT sql FROM sqlite_master WHERE name='blindkey_contexts'" | grep -q "'database_connect')" \
  && ! Q "SELECT sql FROM sqlite_master WHERE name='blindkey_contexts'" | grep -q github_app_token \
  && ok "legacy: main's server made the vault — a scope ($LCTX, CHECK without github_app_token) and a delegation bound to it ($LDEL)" || fail "legacy setup ($LCTX/$LDEL)"

# ── this branch on the same database ──
start "$W" new with-upstream
A=$(login owner-a); AG=$(login owner-a); B=$(login agent-b)
SQL=$(Q "SELECT sql FROM sqlite_master WHERE name='blindkey_contexts'")
echo "$SQL" | grep -q "'database_connect', 'github_app_token')" && [ "$(Q "SELECT COUNT(*) FROM pragma_table_info('blindkey_contexts') WHERE name='github_app'")" = 1 ] \
  && ok "the legacy table is rebuilt: its CHECK admits github_app_token, the github_app column is there" || fail "migration: $SQL"
[ "$(Q "SELECT COUNT(*) FROM blindkey_contexts")" = "$NCTX" ] && [ "$(Q "SELECT context_id FROM demipass_delegations WHERE id=$LDEL")" = "$LCTX" ] \
  && [ "$(Q "SELECT context_name FROM blindkey_contexts WHERE id=$LCTX")" = default ] && [ -z "$(Q "SELECT 1 FROM pragma_foreign_key_check")" ] \
  && [ "$(Q "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_bc_secret' AND tbl_name='blindkey_contexts'")" = 1 ] \
  && ok "same scopes ($NCTX), same ids, the delegation still points at its scope, no foreign key problem, the index rebuilt" || fail "rows/ids after rebuild"
python3 -c "
import sqlite3,sys; c=sqlite3.connect(sys.argv[1])
try: c.execute(\"INSERT INTO blindkey_contexts (secret_id, context_name, action_type, allowed_by) VALUES (1, 'junk', 'teleport', 'x')\"); print('accepted')
except sqlite3.IntegrityError: print('refused')" "$DB_PATH" | grep -q refused && ok "…and the CHECK still refuses an unknown action" || fail "CHECK lost"
grep -q "blindkey_contexts rebuilt to admit github_app_token" "$S/server-new.log" && ok "the rebuild is logged once" || fail "rebuild log"
call POST /api/demipass/use "$B" '{"ref":"'$LREF'","action":"http_header","params":{"url":"https://repo.dustroot.com/legacy","method":"GET"}}'
[ "$CODE" = 200 ] && [ "$(echo "$BODY" | J result.body.path)" = /legacy ] && ok "B's legacy delegated use still acts after the rebuild" || fail "legacy use: $CODE $BODY"
stop; start "$W" new2 with-upstream
[ "$(grep -c 'rebuilt to admit' "$S/server-new2.log")" = 0 ] && ok "a second start leaves the rebuilt table alone" || fail "rebuilt twice"
A=$(login owner-a); AG=$(login owner-a); B=$(login agent-b)

# ── store the app key ──
storebody(){ python3 -c 'import json,sys; d={"name":sys.argv[2],"value":open(sys.argv[1]).read(),"secret_type":"github_app_key"}
if sys.argv[3]: d["github_app_id"]=sys.argv[3]
print(json.dumps(d))' "$1" "$2" "$3" > "$S/st.json"; }
storebody "$S/app.pem" demipass-app ""; callf POST /api/demipass/store "$A" "$S/st.json"
[ "$CODE" = 400 ] && echo "$BODY" | grep -q "github_app_id" && ok "no App ID → 400 (field github_app_id)" || fail "no app id: $CODE $BODY"
storebody "$S/ec.pem" demipass-app 424242; callf POST /api/demipass/store "$A" "$S/st.json"
[ "$CODE" = 400 ] && echo "$BODY" | grep -q "RSA" && ! echo "$BODY" | grep -q "BEGIN PRIVATE\|MI" && ok "an EC key → 400, named, nothing of it echoed" || fail "ec key: $CODE $BODY"
printf '{"name":"demipass-app","value":"-----BEGIN RSA PRIVATE KEY-----\\nnot-a-key-zz91\\n-----END RSA PRIVATE KEY-----","secret_type":"github_app_key","github_app_id":"424242"}' > "$S/st.json"; callf POST /api/demipass/store "$A" "$S/st.json"
[ "$CODE" = 400 ] && ! echo "$BODY" | grep -q "not-a-key-zz91" && ok "a damaged .pem → 400, not echoed" || fail "bad pem: $CODE $BODY"
storebody "$S/app.pem" demipass-app 424242; callf POST /api/demipass/store "$A" "$S/st.json"; REF=$(echo "$BODY" | J ref)
SID=$(Q "SELECT id FROM blindkey_secrets WHERE ref_code='$REF'")
[ "$CODE" = 200 ] && [[ "$REF" == DP-GHA-* ]] && [ "$(echo "$BODY" | J github_app_id)" = 424242 ] && ok "stored the app key ($REF) with its App ID" || fail "store: $CODE $BODY"
[ "$(Q "SELECT json_extract(metadata,'$.github_app_id') FROM blindkey_secrets WHERE id=$SID")" = 424242 ] && [ "$(Q "SELECT COUNT(*) FROM blindkey_contexts WHERE secret_id=$SID")" = 0 ] \
  && ok "the App ID is on the entry; no default scope (a GitHub App key has none until its owner adds one)" || fail "metadata/default ctx"
pin "$A" 4321 "reveal:$SID"; call POST /api/demipass/reveal "$A" '{"ref":"'$REF'"}'
[ "$CODE" = 403 ] && echo "$BODY" | grep -q "never revealed" && ok "reveal → 403: a GitHub App key is never shown" || fail "reveal: $CODE $BODY"
storebody "$S/app.pem" demipass-app 424242; python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); d["secret_type"]="api_key"; d.pop("github_app_id"); json.dump(d,open(sys.argv[1],"w"))' "$S/st.json"; callf POST /api/demipass/store "$A" "$S/st.json"
[ "$CODE" = 409 ] && ok "re-storing it as another type → 409 (delete it first)" || fail "type change: $CODE $BODY"
storebody "$S/app.pem" pushed 424242; python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); d["target_did"]=sys.argv[2]; json.dump(d,open(sys.argv[1],"w"))' "$S/st.json" "$BDID"; callf POST /api/demipass/deposit "$A" "$S/st.json"
[ "$CODE" = 400 ] && ok "deposit refuses the type (only its owner stores it)" || fail "deposit: $CODE $BODY"

# ── the owner's agent adds a scope handed to B: a request on the phone ──
GH='{"installation_id":"777","repositories":["bildow/brain","bildow/Dustforge"],"permissions":{"contents":"write","pull_requests":"write"},"max_ttl_seconds":1800}'
call POST /api/demipass/context/add "$AG" '{"secret_name":"demipass-app","context_name":"x","action_type":"http_header","target_url_pattern":"https://api.github.com/*"}'
[ "$CODE" = 400 ] && ok "an http_header scope on the app key → 400 (only github_app_token)" || fail "http on app key: $CODE $BODY"
call POST /api/demipass/context/add "$AG" '{"secret_name":"legacy-tok","context_name":"x","action_type":"github_app_token","github_app":'"$GH"'}'
[ "$CODE" = 400 ] && ok "github_app_token on another kind of entry → 400" || fail "gh on api key: $CODE $BODY"
call POST /api/demipass/context/add "$AG" '{"secret_name":"demipass-app","context_name":"x","action_type":"github_app_token","github_app":{"installation_id":"777","repositories":["bildow/*"],"permissions":{"contents":"read"}}}'
[ "$CODE" = 400 ] && ok "a wildcard repository → 400 (exact names)" || fail "wildcard: $CODE $BODY"
call POST /api/demipass/context/add "$AG" '{"secret_name":"demipass-app","context_name":"x","action_type":"github_app_token","github_app":{"installation_id":"777","repositories":["bildow/brain"],"permissions":{"contents":"admin"}}}'
[ "$CODE" = 400 ] && ok "a permission level other than read/write → 400" || fail "admin level: $CODE $BODY"
ADD='{"secret_name":"demipass-app","context_name":"reviewers","action_type":"github_app_token","github_app":'"$GH"',"delegate_did":"'$BDID'","ask_owner":true}'
call POST /api/demipass/context/add "$AG" "$ADD"; AP=$(echo "$BODY" | J approval_id)
[ "$CODE" = 202 ] && [ "$(Q "SELECT kind||'/'||depth FROM use_approvals WHERE id=$AP")" = scope/critical ] && ok "AG adds it → 202, approval $AP of kind scope" || fail "add parks: $CODE $BODY"
SUMMARY=$(Q "SELECT summary FROM use_approvals WHERE id=$AP"); echo "$SUMMARY" | grep -q "new GitHub scope 'reviewers' for agent .*: bildow/brain, bildow/Dustforge; contents:write, pull_req" && ok "the card names repos and permissions: $SUMMARY" || fail "summary: $SUMMARY"
[ "$(Q "SELECT COUNT(*) FROM blindkey_contexts WHERE secret_id=$SID")" = 0 ] && ok "nothing granted yet" || fail "granted early"
pin "$A" 4321 "approval-open:$AP"; call POST /api/demipass/approvals/$AP/open "$A"; K=$(echo "$BODY" | J code)
[ "$(echo "$BODY" | J approval.call.body.github_app.installation_id)" = 777 ] && ok "opened with the PIN: the whole GitHub scope is on the screen" || fail "open: $CODE $BODY"
call POST /api/demipass/approvals/$AP/approve "$A" '{"code":"'$K'"}'; [ "$CODE" = 200 ] || fail "approve: $CODE $BODY"
call POST /api/demipass/context/add "$AG" "${ADD%\}},\"approval_id\":$AP}"
CID=$(Q "SELECT id FROM blindkey_contexts WHERE secret_id=$SID AND context_name='reviewers'")
[ "$CODE" = 200 ] && [ -n "$CID" ] && [ "$(echo "$BODY" | J context.github_app.repositories.1)" = bildow/dustforge ] && [ "$(echo "$BODY" | J delegate_did)" = "$BDID" ] \
  && ok "with approval_id: scope $CID created (repos as exact lower-case names), handed to B" || fail "apply: $CODE $BODY"
[ "$(Q "SELECT context_id FROM demipass_delegations WHERE delegate_did='$BDID' AND secret_id=$SID")" = "$CID" ] && ok "the delegation is bound to that scope alone" || fail "delegation ctx"
call POST /api/demipass/context/add "$AG" "${ADD%\}},\"approval_id\":$AP}"; [ "$CODE" = 410 ] && ok "…once" || fail "reuse: $CODE"

# ── B mints ──
BAL(){ Q "SELECT balance_cents FROM identity_wallets WHERE did='$BDID'"; }
M0=$(mints); B0=$(BAL)
call POST /api/demipass/request-token "$B" '{"ref":"'$REF'","context":"reviewers"}'; T=$(echo "$BODY" | J use_token)
call POST /api/demipass/use "$B" '{"use_token":"'$T'","params":{"repositories":["bildow/brain"],"permissions":{"contents":"read"},"ttl_seconds":600}}'
[ "$CODE" = 200 ] && [ "$(keep_token t1)" = minted ] && ok "B: request-token + use → an installation token the stand-in minted" || fail "mint: $CODE $(echo "$BODY" | head -c 300)"
[ "$(echo "$BODY" | J result.repositories)" = "['bildow/brain']" ] && [ "$(echo "$BODY" | J result.permissions.contents)" = read ] && [ "$(echo "$BODY" | J result.git.username)" = x-access-token ] \
  && ok "…covering exactly bildow/brain, contents:read; git user x-access-token" || fail "subset: $BODY"
tail -1 "$S/upstream.log" | grep -q "POST /app/installations/777/access_tokens jwt=ok repos=brain perms=contents:read ua=DemiPass api=2022-11-28" \
  && ok "GitHub saw a valid app JWT (RS256, iss 424242, iat −60 s, exp ≤ 10 min) and exactly that request" || fail "upstream: $(tail -1 "$S/upstream.log")"
EXP=$(echo "$BODY" | J result.expires_at); TID=$(echo "$BODY" | J result.token_id)
python3 -c "import sys,datetime; e=datetime.datetime.fromisoformat(sys.argv[1].replace('Z','+00:00')); d=(e-datetime.datetime.now(datetime.timezone.utc)).total_seconds(); sys.exit(0 if 590<=d<=601 else 1)" "$EXP" \
  && [ "$(Q "SELECT expires_at FROM github_app_tokens WHERE id=$TID")" = "$EXP" ] && ok "its expiry is the asked 600 s (under GitHub's hour), recorded ($EXP)" || fail "expiry: $EXP"
[ "$(BAL)" = $((B0 - 10)) ] && ok "metered: B paid 10 DD for the mint" || fail "billing: $B0 → $(BAL)"
EV=$(Q "SELECT context_json FROM demipass_security_events WHERE event_type='github_app_token_minted' ORDER BY id DESC LIMIT 1")
python3 -c "import json,sys; c=json.loads(sys.argv[1]); sys.exit(0 if c['wallet']==sys.argv[2] and c['scope']=='reviewers' and c['repositories']==['bildow/brain'] and c['permissions'].get('contents')=='read' and c['expires_at']==sys.argv[3] else 1)" "$EV" "$BDID" "$EXP" \
  && ok "a security event names wallet, scope, repositories, permissions and expiry" || fail "event: $EV"
call GET /api/demipass/expiring "$A"; [ "$(echo "$BODY" | J github_tokens.0.id)" = "$TID" ] && [ "$(echo "$BODY" | J github_tokens.0.scope)" = reviewers ] && ! echo "$BODY" | grep -q ghs_ \
  && ok "/expiring lists the live token for the owner (scope, expiry; never the token)" || fail "expiring A: $BODY"
call GET /api/demipass/expiring "$B"; [ "$(echo "$BODY" | J total_github_tokens)" = 1 ] && ok "…and for the agent that minted it" || fail "expiring B: $BODY"
call POST /api/demipass/use "$B" '{"ref":"'$REF'","context":"reviewers","action":"github_app_token"}'
[ "$CODE" = 200 ] && [ "$(keep_token t2)" = minted ] && [ "$(echo "$BODY" | J result.permissions.pull_requests)" = write ] && [ "$(echo "$BODY" | J result.repositories)" = "['bildow/brain', 'bildow/dustforge']" ] \
  && ok "one call (ref), nothing asked → the whole scope: both repos, contents+pull_requests write" || fail "defaults: $CODE $(echo "$BODY" | head -c 300)"

# ── refused before any connection ──
M1=$(mints); E1=$(Q "SELECT COUNT(*) FROM blindkey_events WHERE event_type='egress' AND secret_id=$SID")
try(){ call POST /api/demipass/use "$B" '{"ref":"'$REF'","context":"reviewers","action":"github_app_token","params":'"$1"'}'; }
try '{"repositories":["bildow/secrets"]}'
[ "$CODE" = 403 ] && echo "$BODY" | grep -q "'bildow/secrets' is not in this scope" && ok "a repository off the scope → 403, named" || fail "wrong repo: $CODE $BODY"
try '{"permissions":{"administration":"write"}}'; [ "$CODE" = 403 ] && echo "$BODY" | grep -q "beyond this scope" && ok "a permission off the scope → 403" || fail "wider perm: $CODE $BODY"
try '{"permissions":{"contents":"admin"}}'; [ "$CODE" = 403 ] && ok "a level above write → 403" || fail "admin level: $CODE $BODY"
try '{"ttl_seconds":3600}'; [ "$CODE" = 403 ] && echo "$BODY" | grep -q "at most 1800" && ok "a TTL beyond the scope's 1800 s → 403" || fail "ttl: $CODE $BODY"
[ "$(mints)" = "$M1" ] && [ "$(Q "SELECT COUNT(*) FROM blindkey_events WHERE event_type='egress' AND secret_id=$SID")" = "$E1" ] \
  && ok "…all before any connection: no egress row, no request to GitHub" || fail "leaked to github: $(mints)/$M1"
[ "$(Q "SELECT COUNT(*) FROM demipass_security_events WHERE event_type='github_scope_refused'")" = 4 ] && ok "four github_scope_refused events" || fail "refused events"

# ── the git credential helper ──
OUT=$(printf 'protocol=https\nhost=github.com\npath=bildow/brain.git\n\n' | DEMIPASS_URL=$API DEMIPASS_TOKEN=$B DEMIPASS_GITHUB_REF=$REF DEMIPASS_GITHUB_SCOPE=reviewers node "$W/bin/git-credential-demipass.js" get 2>&1)
printf '%s' "$OUT" | python3 -c 'import sys; o=sys.stdin.read().splitlines(); t=open(sys.argv[1]).read().split(); sys.exit(0 if o[0]=="username=x-access-token" and o[1].startswith("password=") and o[1][9:] in t else 1)' "$S/tokens" \
  && ok "credential helper: git gets username=x-access-token and a fresh token as the password" || fail "helper output (not shown)"
tail -1 "$S/upstream.log" | grep -q "repos=brain perms=contents:write,pull_requests:write" && ok "…for just the repo git asked about (useHttpPath)" || fail "helper repos: $(tail -1 "$S/upstream.log")"
OUT=$(printf 'protocol=https\nhost=gitlab.com\npath=x/y.git\n\n' | DEMIPASS_URL=$API DEMIPASS_TOKEN=$B DEMIPASS_GITHUB_REF=$REF node "$W/bin/git-credential-demipass.js" get 2>&1)
[ -z "$OUT" ] && ok "…and nothing for another host" || fail "helper other host"

# ── widening parks, narrowing applies (and revokes what the scope minted) ──
call PATCH /api/demipass/context/$CID "$AG" '{"github_app":{"installation_id":"777","repositories":["bildow/brain","bildow/dustforge","bildow/tome"],"permissions":{"contents":"write","pull_requests":"write"},"max_ttl_seconds":1800},"ask_owner":true}'
[ "$CODE" = 202 ] && [ "$(Q "SELECT kind FROM use_approvals WHERE id=$(echo "$BODY" | J approval_id)")" = scope ] && ! Q "SELECT github_app FROM blindkey_contexts WHERE id=$CID" | grep -q tome \
  && ok "a third repository → a request on the phone (kind scope); nothing changed" || fail "widen repos: $CODE $BODY"
call PATCH /api/demipass/context/$CID "$AG" '{"github_app":{"installation_id":"777","repositories":["bildow/brain","bildow/dustforge"],"permissions":{"contents":"write","pull_requests":"write","issues":"write"},"max_ttl_seconds":1800},"ask_owner":true}'
[ "$CODE" = 202 ] && ok "a new permission → a request on the phone" || fail "widen perms: $CODE $BODY"
call PATCH /api/demipass/context/$CID "$AG" '{"github_app":{"installation_id":"778","repositories":["bildow/brain"],"permissions":{"contents":"read"},"max_ttl_seconds":600},"ask_owner":true}'
[ "$CODE" = 202 ] && ok "another installation (however narrow) → a request on the phone" || fail "other installation: $CODE $BODY"
LIVE=$(Q "SELECT COUNT(*) FROM github_app_tokens WHERE context_id=$CID AND status='live'"); R0=$(revokes)
call PATCH /api/demipass/context/$CID "$AG" '{"github_app":{"installation_id":"777","repositories":["bildow/brain","bildow/dustforge"],"permissions":{"contents":"write","pull_requests":"read"},"max_ttl_seconds":1800}}'
[ "$CODE" = 200 ] && [ "$(Q "SELECT json_extract(github_app,'$.permissions.pull_requests') FROM blindkey_contexts WHERE id=$CID")" = read ] && ok "write → read on pull_requests: a narrowing, applied without the PIN" || fail "narrow: $CODE $BODY"
waitfor "Q \"SELECT COUNT(*) FROM github_app_tokens WHERE context_id=$CID AND status='live'\"" 0 && [ "$(revokes)" = $((R0 + LIVE)) ] \
  && ok "…and the $LIVE tokens it had minted were revoked at GitHub (DELETE /installation/token)" || fail "narrow revoke: $(revokes)/$R0+$LIVE"
[ "$(Q "SELECT COUNT(*) FROM github_app_tokens WHERE context_id=$CID AND token_enc IS NOT NULL")" = 0 ] && ok "…their ciphertext erased" || fail "token_enc kept"

# ── the installation is the ceiling; a too-wide answer is never handed out ──
pin "$A" 4321 "scope:$SID"; call POST /api/demipass/context/add "$A" '{"secret_name":"demipass-app","context_name":"issues","action_type":"github_app_token","github_app":{"installation_id":"777","repositories":["bildow/brain"],"permissions":{"issues":"write"},"max_ttl_seconds":300}}'
CID2=$(Q "SELECT id FROM blindkey_contexts WHERE secret_id=$SID AND context_name='issues'"); [ "$CODE" = 200 ] && [ -n "$CID2" ] || fail "owner add issues: $CODE $BODY"
echo issues > "$S/ceiling"; A0=$(Q "SELECT balance_cents FROM identity_wallets WHERE username='owner-a'"); N0=$(Q "SELECT COUNT(*) FROM github_app_tokens")
call POST /api/demipass/use "$A" '{"ref":"'$REF'","context":"issues","action":"github_app_token"}'
[ "$CODE" = 403 ] && echo "$BODY" | grep -q "reinstalls the app" && [ "$(echo "$BODY" | J refunded_dd)" = 10 ] && [ "$(Q "SELECT balance_cents FROM identity_wallets WHERE username='owner-a'")" = "$A0" ] \
  && [ "$(Q "SELECT COUNT(*) FROM github_app_tokens")" = "$N0" ] && ok "beyond the installation: GitHub's 422 → 403 'the owner reinstalls', refunded, no token" || fail "ceiling: $CODE $BODY"
rm -f "$S/ceiling"; touch "$S/wide"; R0=$(revokes)
call POST /api/demipass/use "$A" '{"ref":"'$REF'","context":"issues","action":"github_app_token"}'
[ "$CODE" = 502 ] && echo "$BODY" | grep -q "wider than asked" && ! echo "$BODY" | grep -q ghs_ && [ "$(revokes)" = $((R0 + 1)) ] \
  && [ "$(Q "SELECT status FROM github_app_tokens ORDER BY id DESC LIMIT 1")" = revoked ] && ok "a token wider than asked: revoked at once, not handed out" || fail "wide: $CODE $BODY"
rm -f "$S/wide"

# ── an elevated key: never wrapped; each mint waits for the owner ──
call POST /api/demipass/gate-policy "$A" '{"ref":"'$REF'","security_depth":"elevated"}'
[ "$CODE" = 200 ] && [ "$(Q "SELECT COALESCE(wrap_state,'') FROM blindkey_secrets WHERE id=$SID")" = "" ] && ok "elevated: the key stays unwrapped (mints are unattended) — $(echo "$BODY" | J wrap_note | head -c 90)" || fail "elevated: $CODE $BODY"
M2=$(mints); call POST /api/demipass/use "$A" '{"ref":"'$REF'","context":"issues","action":"github_app_token"}'
[ "$CODE" = 202 ] && [ "$(mints)" = "$M2" ] && ok "…and a mint parks as an approval request; GitHub is not called" || fail "elevated mint: $CODE $BODY"
python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute(\"UPDATE blindkey_secrets SET security_depth='standard', gate_policy=NULL WHERE id=?\", (int(sys.argv[2]),)); c.commit()" "$DB_PATH" "$SID"

# ── revocation: our TTL, the delegation, the scope ──
call POST /api/demipass/use "$B" '{"ref":"'$REF'","context":"reviewers","action":"github_app_token"}'; keep_token t3 >/dev/null; T3=$(echo "$BODY" | J result.token_id)
R0=$(revokes); python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute(\"UPDATE github_app_tokens SET expires_at='2000-01-01T00:00:00.000Z' WHERE id=?\", (int(sys.argv[2]),)); c.commit()" "$DB_PATH" "$T3"
waitfor "Q \"SELECT status FROM github_app_tokens WHERE id=$T3\"" revoked && [ "$(revokes)" = $((R0 + 1)) ] && [ "$(Q "SELECT revoke_wanted FROM github_app_tokens WHERE id=$T3")" = "expired (scope TTL)" ] \
  && ok "the scope's TTL passing before GitHub's hour → revoked by the sweep" || fail "ttl revoke: $(Q "SELECT status FROM github_app_tokens WHERE id=$T3")"
call POST /api/demipass/use "$B" '{"ref":"'$REF'","context":"reviewers","action":"github_app_token"}'; T4=$(echo "$BODY" | J result.token_id)
DID=$(Q "SELECT id FROM demipass_delegations WHERE delegate_did='$BDID' AND secret_id=$SID"); R0=$(revokes)
call POST /api/demipass/delegate/revoke "$A" '{"delegation_id":'$DID'}'
[ "$CODE" = 200 ] && [ "$(echo "$BODY" | J github_tokens_revoked)" = 1 ] && waitfor "Q \"SELECT status FROM github_app_tokens WHERE id=$T4\"" revoked && [ "$(revokes)" = $((R0 + 1)) ] \
  && ok "revoking B's delegation → its live token revoked at GitHub now" || fail "delegation revoke: $CODE $BODY"
call POST /api/demipass/use "$B" '{"ref":"'$REF'","context":"reviewers","action":"github_app_token"}'; [ "$CODE" = 403 ] && ok "…and B mints nothing more" || fail "B after revoke: $CODE"
call POST /api/demipass/use "$A" '{"ref":"'$REF'","context":"reviewers","action":"github_app_token","params":{"repositories":["bildow/dustforge"]}}'; T5=$(echo "$BODY" | J result.token_id)
[ "$CODE" = 200 ] && [ -z "$(Q "SELECT delegation_id FROM github_app_tokens WHERE id=$T5")" ] || fail "owner mint: $CODE $BODY"
R0=$(revokes); call DELETE /api/demipass/context/$CID "$A"
[ "$CODE" = 200 ] && waitfor "Q \"SELECT status FROM github_app_tokens WHERE id=$T5\"" revoked && [ "$(revokes)" = $((R0 + 1)) ] && ok "deleting the scope → the owner's own live token revoked too" || fail "scope delete: $CODE $BODY"
[ "$(Q "SELECT COUNT(*) FROM github_app_tokens WHERE status='live'")" = 0 ] && [ "$(Q "SELECT COUNT(*) FROM github_app_tokens WHERE token_enc IS NOT NULL")" = 0 ] && ok "no live token left, no token ciphertext kept" || fail "leftovers"

# ── rotation carries the App ID and the scopes ──
python3 -c 'import json,sys; print(json.dumps({"name":"demipass-app","new_value":"not a pem"}))' > "$S/rot.json"; callf POST /api/blindkey/rotate "$A" "$S/rot.json"
[ "$CODE" = 400 ] && ok "rotating to something that is not a .pem → 400" || fail "rotate junk: $CODE $BODY"
cp "$S/app2.pem" "$S/x"; python3 -c 'import json,sys; print(json.dumps({"name":"demipass-app","new_value":open(sys.argv[1]).read()}))' "$S/x" > "$S/rot.json"; rm -f "$S/x"; callf POST /api/blindkey/rotate "$A" "$S/rot.json"
NSID=$(Q "SELECT id FROM blindkey_secrets WHERE ref_code='$REF'")
[ "$CODE" = 200 ] && [ "$NSID" != "$SID" ] && [ "$(Q "SELECT json_extract(metadata,'$.github_app_id') FROM blindkey_secrets WHERE id=$NSID")" = 424242 ] \
  && [ "$(Q "SELECT json_extract(github_app,'$.installation_id') FROM blindkey_contexts WHERE secret_id=$NSID AND context_name='issues'")" = 777 ] && ok "rotated: the new key keeps the App ID and the scope's GitHub configuration" || fail "rotate: $CODE $BODY"
call POST /api/demipass/use "$A" '{"ref":"'$REF'","context":"issues","action":"github_app_token"}'
[ "$CODE" = 200 ] && tail -1 "$S/upstream.log" | grep -q "jwt=ok" && ok "…and mints, signed by the new key" || fail "mint after rotate: $CODE $(tail -1 "$S/upstream.log")"

# ── nothing in clear: no key, JWT or token in the server log or the database ──
stop
python3 - "$S" <<'PY' && ok "no app key, JWT or installation token in the server logs or the database (incl. WAL) in clear" || fail "a credential leaked (which: above)"
import sys, os, glob
d = sys.argv[1]
needles = []
for f in ('app.pem', 'app2.pem'):
    body = [l for l in open(os.path.join(d, f)).read().splitlines() if l and not l.startswith('-----')]
    needles += [(f + ' line', body[3]), (f + ' line', body[-2])]
needles += [('jwt', l.split('.')[2]) for l in open(os.path.join(d, 'jwt.seen')).read().split()]
needles += [('jwt claims', l.split('.')[1]) for l in open(os.path.join(d, 'jwt.seen')).read().split()]
needles += [('token', t) for t in open(os.path.join(d, 'tokens')).read().split()]
files = glob.glob(os.path.join(d, 'server-*.log')) + glob.glob(os.path.join(d, 'dustforge.db*'))
bad = 0
for f in files:
    data = open(f, 'rb').read()
    for what, n in needles:
        if n.encode() in data: print('  found a', what, 'in', os.path.basename(f)); bad += 1
print('  checked %d needles (%d tokens, %d JWTs) in %d files' % (len(needles), sum(1 for w, _ in needles if w == 'token'), sum(1 for w, _ in needles if w == 'jwt'), len(files)))
sys.exit(1 if bad else 0)
PY
[ $fails = 0 ] && echo "ALL OK" || { echo "$fails FAILED"; exit 1; }
