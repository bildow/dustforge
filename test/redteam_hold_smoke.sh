#!/bin/bash
# The #43 review's probes, re-run as regressions (review HOLD 2026-11-05; tome red team items 2, 3, 11, 12, 13, 14).
# server.js on a throwaway DB; a stand-in sshpass on PATH (logs, never connects), a stand-in SMTP server on 127.0.0.1
# with no STARTTLS, and a stand-in upstream for repo.dustroot.com that records the bytes it receives. No network.
#   C1  smtp_auth: a host off the scope or off the SMTP list → refused, nothing sent; no STARTTLS → no AUTH at all
#   H1  database_connect / git_clone: a URL off the scope → refused, no egress row
#   H2  sudo:true is matched as "sudo <command>"
#   H3  key_name: the second secret needs its own scope and the same command on its own list
#   M1  "prefix *" words: no leading "-", no ".."    M2  stdin only for an entry ending " <stdin"
#   P2  /deposit with contexts: refused before anything is stored; with the PIN it goes through in one call
#   L   a scope PATCHed into ssh_exec starts from [] (nothing runs)
#   14  an approved call reaches the upstream as the bytes the owner approved, not the agent's serialization
set -u
W=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
S=$(mktemp -d /tmp/dustforge-redteam-hold.XXXXXX)
PORT=${PORT:-3793}; UP_PORT=${UP_PORT:-3794}; SMTP_FAKE_PORT=${SMTP_FAKE_PORT:-3795}; API=http://127.0.0.1:$PORT
[ -d "$W/node_modules" ] || export NODE_PATH=${NODE_PATH:-/home/flimflam/project/dustforge/node_modules}
export IDENTITY_MASTER_KEY=$(python3 -c 'import secrets;print(secrets.token_hex(32))') DB_PATH=$S/dustforge.db PORT \
  STALWART_HOST=127.0.0.1 STALWART_PORT=1 SMTP_RELAY_HOST= SMTP_HOST=127.0.0.1 SMTP_PORT=9 TEST_UPSTREAM=http://127.0.0.1:$UP_PORT FAKE_DIR=$S
cd "$W"
mkdir -p "$S/bin"
cat >"$S/bin/sshpass" <<'SH'
#!/bin/bash
echo "RUN ${@: -1}" >>"$FAKE_DIR/ssh.log"; echo ran
SH
chmod +x "$S/bin/sshpass"
node -e '
const fs = require("fs");
require("http").createServer((q, r) => { const b = []; q.on("data", c => b.push(c)); q.on("end", () => { fs.writeFileSync(process.argv[2], Buffer.concat(b)); fs.appendFileSync(process.argv[2] + ".paths", q.url + "\n"); if (q.url.startsWith("/repos/bildow/bounce")) { r.writeHead(302, { location: "https://example.com/" }); return r.end(); } r.writeHead(200, { "content-type": "application/json" }); r.end("{\"ok\":true}"); }); })
  .listen(+process.argv[1], "127.0.0.1");' $UP_PORT "$S/up.body" & UP=$!
node -e '
const fs = require("fs");
require("net").createServer(s => { s.write("220 fake\r\n"); let buf = "";
  s.on("data", d => { buf += d; let i; while ((i = buf.indexOf("\r\n")) >= 0) { const line = buf.slice(0, i); buf = buf.slice(i + 2); fs.appendFileSync(process.argv[2], line.split(" ")[0] + "\n");
    const v = line.slice(0, 4).toUpperCase();
    if (v === "EHLO") s.write("250-fake\r\n250 AUTH PLAIN LOGIN\r\n"); else if (v === "STAR") s.write("502 not supported\r\n"); else if (v === "AUTH") s.write("235 ok\r\n"); else if (v === "QUIT") { s.write("221 bye\r\n"); s.end(); } else s.write("250 ok\r\n"); } });
  s.on("error", () => {}); }).listen(+process.argv[1], "127.0.0.1");' $SMTP_FAKE_PORT "$S/smtp.log" & SM=$!
PATH="$S/bin:$PATH" node --require ./test/fixtures/upstream-redirect.js server.js >"$S/server.log" 2>&1 & SRV=$!
trap 'kill $SRV $UP $SM 2>/dev/null; rm -rf "$S"' EXIT
for i in $(seq 1 40); do curl -s -o /dev/null "$API/" && break; sleep 0.5; done
kill -0 $SRV 2>/dev/null || { echo "server died:"; tail -5 "$S/server.log"; exit 1; }
H=$(printf '%s' hunter22 | sha256sum | cut -d' ' -f1)
node -e '
const identity = require("./identity"); const Database = require("better-sqlite3"); const db = new Database(process.env.DB_PATH);
for (const c of ["idempotency_key TEXT", "provenance TEXT DEFAULT '"'"'organic'"'"'"]) { try { db.exec("ALTER TABLE identity_transactions ADD COLUMN " + c); } catch (_) {} }
for (const u of ["owner-a", "agent-f"]) { const id = identity.createIdentity(); const enc = id.encrypted_private_key || id.encryptedPrivateKey;
  db.prepare("INSERT INTO identity_wallets (did, username, email, encrypted_private_key, balance_cents, password_hash) VALUES (?, ?, ?, ?, 100000, ?)").run(id.did, u, u + "@dustforge.com", enc, process.argv[1]);
  db.prepare("INSERT INTO identity_transactions (did, amount_cents, type, description, balance_after) VALUES (?, 100000, ?, ?, 100000)").run(id.did, "topup", "smoke"); }' "$H"
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
pin(){ call POST /api/identity/gate/verify "$A" '{"gate":"pin","pin":"4321","intent":"'$1'"}'; [ "$CODE" = 200 ] || fail "pin $1: $CODE $BODY"; }
sid(){ Q "SELECT id FROM blindkey_secrets WHERE name='$1'"; }
egress(){ Q "SELECT COUNT(*) FROM blindkey_events WHERE event_type='egress' AND secret_id=$1"; }
runs(){ [ -f "$S/ssh.log" ] && wc -l <"$S/ssh.log" | tr -d ' ' || echo 0; }
A=$(login owner-a); AG=$(login owner-a); F=$(login agent-f)
call POST /api/identity/pin "$A" '{"pin":"4321","password":"hunter22"}'
HOST=100.83.112.88

# ── SSH: forced commands as matched (H2, M1, M2) ──
call POST /api/demipass/store "$A" '{"name":"box","value":"box-pw-zz81","secret_type":"password","username":"root","host":"'$HOST'"}'
BOX=$(sid box); BC=$(Q "SELECT id FROM blindkey_contexts WHERE secret_id=$BOX")
pin "scope:$BOX"; call PATCH /api/demipass/context/$BC "$A" '{"allowed_commands":["ls /srv *","sudo systemctl restart dustforge","tee -a /srv/app.log <stdin"]}'
[ "$CODE" = 200 ] || fail "set commands: $CODE $BODY"
SSH(){ call POST /api/demipass/use "$AG" "$(python3 -c 'import json,sys; b={"name":"box","action":"ssh_exec","target_host":sys.argv[1],"target_user":"root","command":sys.argv[2]}
if sys.argv[3]: b["sudo"]=json.loads(sys.argv[3])
if sys.argv[4]: b["stdin"]=sys.argv[4]
print(json.dumps(b))' "$HOST" "$1" "${2:-}" "${3:-}")"; }
R0=$(runs); SSH "ls /srv x" true
[ "$CODE" = 403 ] && [ "$(runs)" = "$R0" ] && ok "H2: sudo:true on an entry listed without sudo → 403, nothing ran" || fail "sudo bypass: $CODE $BODY"
SSH "systemctl restart dustforge" true; [ "$CODE" = 200 ] && tail -1 "$S/ssh.log" | grep -q "sudo -n -- systemctl restart dustforge" && ok "H2: a listed \"sudo …\" entry runs with sudo:true" || fail "sudo listed: $CODE $BODY"
R0=$(runs); SSH "systemctl restart dustforge"; [ "$CODE" = 403 ] && [ "$(runs)" = "$R0" ] && ok "H2: …and the same command without sudo is not on the list" || fail "plain of sudo entry: $CODE"
R0=$(runs); SSH "ls /srv -la"; [ "$CODE" = 403 ] && [ "$(runs)" = "$R0" ] && ok "M1: a wildcard word starting with '-' → 403" || fail "option: $CODE"
R0=$(runs); SSH "ls /srv ../../root"; [ "$CODE" = 403 ] && [ "$(runs)" = "$R0" ] && ok "M1: a wildcard word with '..' → 403" || fail "dotdot: $CODE"
SSH "ls /srv /etc/hosts"; [ "$CODE" = 200 ] && ok "M1: an absolute path still matches '*' (documented)" || fail "abs path: $CODE $BODY"
R0=$(runs); SSH "ls /srv x" "" "id"; [ "$CODE" = 403 ] && echo "$BODY" | grep -q stdin && [ "$(runs)" = "$R0" ] && ok "M2: stdin on an entry without \" <stdin\" → 403" || fail "stdin: $CODE $BODY"
SSH "tee -a /srv/app.log" "" "a line"; [ "$CODE" = 200 ] && ok "M2: stdin on an entry that opts in runs" || fail "stdin opt-in: $CODE $BODY"

# ── key_name: its own scope and list (H3) ──
call POST /api/demipass/store "$A" '{"name":"rootkey","value":"rootkey-pw-zz82","secret_type":"password","username":"root","host":"'$HOST'"}'
RK=$(sid rootkey); call PATCH /api/demipass/context/$(Q "SELECT id FROM blindkey_contexts WHERE secret_id=$RK") "$A" '{"status":"revoked"}'
R0=$(runs); E0=$(egress $RK)
call POST /api/demipass/use "$AG" '{"name":"box","action":"ssh_exec","target_host":"'$HOST'","target_user":"root","command":"ls /srv x","key_name":"rootkey"}'
[ "$CODE" = 403 ] && echo "$BODY" | grep -q "key_name secret 'rootkey'" && [ "$(runs)" = "$R0" ] && [ "$(egress $RK)" = "$E0" ] && ok "H3: a key_name secret with only revoked scopes → 403, nothing ran" || fail "key_name scope: $CODE $BODY"
RC=$(Q "SELECT id FROM blindkey_contexts WHERE secret_id=$RK"); pin "scope:$RK"; call PATCH /api/demipass/context/$RC "$A" '{"status":"active","allowed_commands":["id"]}'
call POST /api/demipass/use "$AG" '{"name":"box","action":"ssh_exec","target_host":"'$HOST'","target_user":"root","command":"ls /srv x","key_name":"rootkey"}'
[ "$CODE" = 403 ] && echo "$BODY" | grep -q "key_name secret 'rootkey'" && ok "H3: …active, but the command is not on the key's own list → 403" || fail "key_name cmd: $CODE $BODY"
pin "scope:$RK"; call PATCH /api/demipass/context/$RC "$A" '{"allowed_commands":["id","ls /srv *"]}'
call POST /api/demipass/use "$AG" '{"name":"box","action":"ssh_exec","target_host":"'$HOST'","target_user":"root","command":"ls /srv x","key_name":"rootkey"}'
[ "$CODE" = 200 ] && [ "$(egress $RK)" = "$((E0+1))" ] && ok "H3: on both lists it runs, and the key secret gets its own egress row" || fail "key_name ok: $CODE $BODY egress=$(egress $RK)"

# ── smtp_auth (C1) ──
call POST /api/demipass/store "$A" '{"name":"mail","value":"alice:SMTP-PASSWORD-xyz","secret_type":"password"}'
ML=$(sid mail)
pin "scope:$ML"; call POST /api/demipass/context/add "$A" '{"secret_name":"mail","context_name":"gmail","action_type":"smtp_auth","target_host_pattern":"smtp.gmail.com"}'
pin "scope:$ML"; call POST /api/demipass/context/add "$A" '{"secret_name":"mail","context_name":"local","action_type":"smtp_auth","target_host_pattern":"127.0.0.1"}'
pin "scope:$ML"; call POST /api/demipass/context/add "$A" '{"secret_name":"mail","context_name":"any","action_type":"smtp_auth","target_host_pattern":"*"}'
SMTP(){ call POST /api/demipass/use "$AG" '{"ref":"'$(Q "SELECT ref_code FROM blindkey_secrets WHERE id=$ML")'","action":"smtp_auth","context":"'$1'","params":{"smtp_host":"'$2'","smtp_port":'$SMTP_FAKE_PORT',"to":"x@example.com","subject":"s"}}'; }
E0=$(egress $ML); SMTP gmail 127.0.0.2
[ "$CODE" = 403 ] && [ "$(egress $ML)" = "$E0" ] && [ ! -s "$S/smtp.log" ] && ok "C1: smtp_host off the scope's host pattern → 403, nothing sent" || fail "smtp off scope: $CODE $BODY"
SMTP any 127.0.0.2; [ "$CODE" = 403 ] && [ "$(egress $ML)" = "$E0" ] && ok "C1: a '*' scope still never reaches a host off the SMTP list" || fail "smtp off list: $CODE $BODY"
SMTP local 127.0.0.1; sleep 0.3
[ "$CODE" = 200 ] && [ "$(echo "$BODY" | J result.sent)" = False ] && grep -q EHLO "$S/smtp.log" && ! grep -q AUTH "$S/smtp.log" \
  && ok "C1: a server offering no STARTTLS never sees AUTH (requireTLS)" || fail "requireTLS: $CODE $BODY $(cat "$S/smtp.log" 2>/dev/null | tr '\n' ' ')"

# ── database_connect / git_clone (H1, M4) ──
call POST /api/demipass/store "$A" '{"name":"dbkey","value":"db-key-zz83","secret_type":"api_key"}'; DK=$(sid dbkey)
pin "scope:$DK"; call POST /api/demipass/context/add "$A" '{"secret_name":"dbkey","context_name":"good","action_type":"database_connect","target_url_pattern":"https://good.supabase.co/*"}'
call POST /api/demipass/use "$AG" '{"name":"dbkey","action":"database_connect","context":"good","target_url":"https://attacker.supabase.co/functions/v1/x","params":{"query":"select 1"}}'
[ "$CODE" = 403 ] && [ "$(egress $DK)" = 0 ] && ok "H1: database_connect to a URL off the scope (same listed suffix) → 403, no connection" || fail "db scope: $CODE $BODY"
call POST /api/demipass/store "$A" '{"name":"gitkey","value":"git-key-zz84","secret_type":"api_key"}'; GK=$(sid gitkey); GREF=$(Q "SELECT ref_code FROM blindkey_secrets WHERE id=$GK")
pin "scope:$GK"; call POST /api/demipass/context/add "$A" '{"secret_name":"gitkey","context_name":"mine","action_type":"git_clone","target_url_pattern":"https://github.com/bildow/*"}'
call POST /api/demipass/use "$AG" '{"ref":"'$GREF'","action":"git_clone","context":"mine","params":{"repo_url":"https://github.com/evil/x"}}'
[ "$CODE" = 403 ] && [ "$(egress $GK)" = 0 ] && ok "H1: git_clone of a repo off the scope → 403, no clone" || fail "git scope: $CODE $BODY"
call POST /api/demipass/request-token "$AG" '{"name":"gitkey","context":"mine","action":"git_clone","target_url":"https://github.com/bildow/ok"}'; GT=$(echo "$BODY" | J use_token)
call POST /api/demipass/use "$AG" '{"use_token":"'$GT'","params":{"repo_url":"https://github.com/evil/x"}}'
[ "$CODE" = 403 ] && [ "$(egress $GK)" = 0 ] && ok "H1: a token for an in-scope repo cannot clone another repo_url" || fail "git token swap: $CODE $BODY"

# ── deposit with contexts (Codex P2) ──
call POST /api/network/requests "$A" '{"to":"agent-f","as":"agent"}'; R=$(echo "$BODY" | J request.id); call POST /api/network/requests/$R/accept "$F"
python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute(\"UPDATE fleet_silicons SET joined_via='owner'\"); c.commit()" "$DB_PATH"
DEP='{"name":"f-ssh","value":"f-ssh-pw-zz85","secret_type":"password","target_silicon":"agent-f","contexts":[{"context_name":"box","action_type":"ssh_exec","target_host_pattern":"'$HOST'","allowed_commands":["uptime"]}]}'
call POST /api/demipass/deposit "$A" "$DEP"
[ "$CODE" = 403 ] && [ "$(echo "$BODY" | J intent)" = "scope:0" ] && [ -z "$(sid f-ssh)" ] && ok "P2: a scoped deposit without the PIN → 403 before anything is stored" || fail "deposit no pin: $CODE $BODY sid=$(sid f-ssh)"
pin "scope:0"; call POST /api/demipass/deposit "$A" "$DEP"
[ "$CODE" = 200 ] && [ "$(echo "$BODY" | J contexts_created)" = 1 ] && [ "$(Q "SELECT command_allowlist FROM blindkey_contexts c JOIN blindkey_secrets s ON s.id=c.secret_id WHERE s.name='f-ssh'")" = '["uptime"]' ] \
  && ok "P2: with the PIN the same deposit goes through, scope and commands set" || fail "deposit pin: $CODE $BODY"

# ── a scope that becomes ssh_exec starts from [] ──
call POST /api/demipass/store "$A" '{"name":"svc","value":"svc-token-zz86","secret_type":"api_key","host":"repo.dustroot.com"}'; SV=$(sid svc); SC=$(Q "SELECT id FROM blindkey_contexts WHERE secret_id=$SV")
pin "scope:$SV"; call PATCH /api/demipass/context/$SC "$A" '{"action_type":"ssh_exec","target_host_pattern":"'$HOST'"}'
[ "$CODE" = 200 ] && [ "$(Q "SELECT command_allowlist FROM blindkey_contexts WHERE id=$SC")" = "[]" ] && ok "a scope PATCHed into ssh_exec gets [] (nothing runs), not legacy any-command" || fail "patch to ssh: $CODE $(Q "SELECT command_allowlist FROM blindkey_contexts WHERE id=$SC")"

# ── item 14: the approved bytes ──
call POST /api/demipass/store "$A" '{"name":"hook","value":"hook-token-zz87","secret_type":"api_key","host":"repo.dustroot.com"}'; HK=$(Q "SELECT ref_code FROM blindkey_secrets WHERE name='hook'")
call POST /api/demipass/gate-policy "$A" '{"ref":"'$HK'","security_depth":"elevated"}'; [ "$CODE" = 200 ] || fail "elevate: $CODE $BODY"
HOOK='{"ref":"'$HK'","params":{"url":"https://repo.dustroot.com/hook","method":"POST","body":{"z":1,"a":{"y":2,"b":3}}}'
call POST /api/demipass/use "$AG" "$HOOK}"; AP=$(echo "$BODY" | J approval_id); [ "$CODE" = 202 ] || fail "park: $CODE $BODY"
pin "approval-open:$AP"; call POST /api/demipass/approvals/$AP/open "$A"; CD=$(echo "$BODY" | J code)
call POST /api/demipass/approvals/$AP/approve "$A" '{"code":"'$CD'"}'; [ "$CODE" = 200 ] || fail "approve: $CODE $BODY"
rm -f "$S/up.body"; call POST /api/demipass/use "$AG" "$HOOK,\"approval_id\":$AP}"
[ "$CODE" = 200 ] && [ "$(cat "$S/up.body")" = '{"a":{"b":3,"y":2},"z":1}' ] && ok "14: the upstream receives the approved call's bytes (as shown to the owner), not the agent's key order" || fail "approved bytes: $CODE $BODY up=$(cat "$S/up.body" 2>/dev/null)"

# ── N1: a URL scope cannot be walked out of ──
call POST /api/demipass/store "$A" '{"name":"gh","value":"gh-token-zz88","secret_type":"api_key"}'; GH=$(sid gh); GHR=$(Q "SELECT ref_code FROM blindkey_secrets WHERE id=$GH")
pin "scope:$GH"; call POST /api/demipass/context/add "$A" '{"secret_name":"gh","context_name":"repos","action_type":"http_header","target_url_pattern":"https://repo.dustroot.com/repos/bildow/*"}'
GHUSE(){ call POST /api/demipass/use "$AG" "$(python3 -c 'import json,sys; print(json.dumps({"ref":sys.argv[1],"context":"repos","params":{"url":sys.argv[2],"method":"POST"}}))' "$GHR" "$1")"; }
rm -f "$S/up.body.paths"
for u in 'https://repo.dustroot.com/repos/bildow/../../user/keys' 'https://repo.dustroot.com/repos/bildow/%2e%2e/%2E%2e/user/keys' 'https://repo.dustroot.com/repos/bildow\..\..\user/keys' \
         'http://repo.dustroot.com/repos/bildow/x' 'https://u:p@repo.dustroot.com/repos/bildow/x' 'https://repo.dustroot.com.evil.example/repos/bildow/x'; do
  GHUSE "$u"; [ "$CODE" = 403 ] || fail "N1 escaped with $u: $CODE $BODY"
done
[ ! -s "$S/up.body.paths" ] && [ "$(egress $GH)" = 0 ] && ok "N1: ../, %2e%2e, backslashes, http, user@ and a lookalike host → 403, the upstream never asked" || fail "N1: upstream saw $(cat "$S/up.body.paths" 2>/dev/null | tr '\n' ' ')"
GHUSE 'https://repo.dustroot.com/repos/bildow/x/../y?q=1'
[ "$CODE" = 200 ] && [ "$(cat "$S/up.body.paths")" = "/repos/bildow/y?q=1" ] && [ "$(Q "SELECT json_extract(detail,'\$.target') FROM blindkey_events WHERE event_type='egress' AND secret_id=$GH")" = "https://repo.dustroot.com/repos/bildow/y?q=1" ] \
  && ok "N1: an in-scope URL is requested and logged as resolved" || fail "N1 in scope: $CODE $BODY $(cat "$S/up.body.paths" 2>/dev/null)"

for u in 'https://repo.dustroot.com/repos/bildow/..%2f..%2fuser/keys' 'https://repo.dustroot.com/repos/bildow/%252e%252e/x' 'https://repo.dustroot.com/repos/bildow/%5Cx'; do
  rm -f "$S/up.body.paths"; GHUSE "$u"; { [ "$CODE" = 403 ] && [ ! -s "$S/up.body.paths" ]; } || fail "encoded separator reached upstream: $u $CODE"
done; ok "follow-up 1: %2f, %252e and %5c in the path are never sent"
# legacy stored patterns (made before 11-05): no scheme still means https; an http:// pattern now matches nothing
python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute(\"UPDATE blindkey_contexts SET target_url_pattern='repo.dustroot.com/repos/bildow/*' WHERE secret_id=? AND context_name='repos'\", (int(sys.argv[2]),)); c.commit()" "$DB_PATH" "$GH"
rm -f "$S/up.body.paths"; GHUSE 'https://repo.dustroot.com/repos/bildow/z'; [ "$CODE" = 200 ] && ok "a legacy pattern without a scheme still matches https" || fail "legacy no-scheme: $CODE $BODY"
python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute(\"UPDATE blindkey_contexts SET target_url_pattern='http://repo.dustroot.com/*' WHERE secret_id=? AND context_name='repos'\", (int(sys.argv[2]),)); c.commit()" "$DB_PATH" "$GH"
GHUSE 'https://repo.dustroot.com/repos/bildow/z'; [ "$CODE" = 403 ] && ok "a legacy http:// pattern fails closed (its owner re-scopes it to https)" || fail "legacy http: $CODE"

# a redirecting upstream: refused (502), and the token is spent and counted — it cannot re-send for its 30 s
python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute(\"UPDATE blindkey_contexts SET target_url_pattern='https://repo.dustroot.com/repos/bildow/*' WHERE secret_id=? AND context_name='repos'\", (int(sys.argv[2]),)); c.commit()" "$DB_PATH" "$GH"
call POST /api/demipass/request-token "$AG" '{"name":"gh","context":"repos","target_url":"https://repo.dustroot.com/repos/bildow/bounce"}'; BT=$(echo "$BODY" | J use_token)
U0=$(Q "SELECT use_count FROM blindkey_contexts WHERE secret_id=$GH AND context_name='repos'")
call POST /api/demipass/use "$AG" '{"use_token":"'$BT'","method":"POST"}'; C1=$CODE
call POST /api/demipass/use "$AG" '{"use_token":"'$BT'","method":"POST"}'
[ "$C1" = 502 ] && [ "$CODE" = 410 ] && [ "$(Q "SELECT use_count FROM blindkey_contexts WHERE secret_id=$GH AND context_name='repos'")" = "$((U0+1))" ] \
  && ok "a redirect is refused (502) and spends + counts the token; a re-send → 410" || fail "redirect token: $C1 then $CODE $BODY"

# ── N2: rotate-blind only to a host the scope covers ──
R0=$(runs); call POST /api/demipass/rotate-blind "$AG" '{"ref":"'$(Q "SELECT ref_code FROM blindkey_secrets WHERE id=$BOX")'","target_host":"100.69.1.78","target_user":"root"}'
[ "$CODE" = 403 ] && [ "$(runs)" = "$R0" ] && ok "N2: rotate-blind to a host off the secret's scope → 403, no SSH" || fail "N2: $CODE $BODY runs=$(runs)"

call POST /api/demipass/rotate-blind "$AG" '{"ref":"'$(Q "SELECT ref_code FROM blindkey_secrets WHERE id=$BOX")'","target_host":"'$HOST'","target_user":"someoneelse"}'
[ "$CODE" = 403 ] && echo "$BODY" | grep -q "password of 'root'" && [ "$(runs)" = "$R0" ] && ok "follow-up 3: rotate-blind of another account than the secret's → 403" || fail "rotate user: $CODE $BODY"

call POST /api/demipass/store "$A" '{"name":"nouser","value":"nouser-pw-zz89","secret_type":"password","host":"'$HOST'"}'
call POST /api/demipass/rotate-blind "$AG" '{"ref":"'$(Q "SELECT ref_code FROM blindkey_secrets WHERE name='nouser'")'","target_host":"'$HOST'"}'
[ "$CODE" = 400 ] && echo "$BODY" | grep -q "name the account" && [ "$(runs)" = "$R0" ] && ok "rotate-blind of a secret with no stored account: the caller must name it (no silent root)" || fail "rotate no user: $CODE $BODY"

# ── N5: frozen means frozen; unfreezing takes the PIN ──
call POST /api/demipass/request-token "$AG" '{"name":"box","action":"ssh_exec","target_host":"'$HOST'"}'; FT=$(echo "$BODY" | J use_token)
call POST /api/demipass/freeze "$AG" '{"name":"box","freeze":true}'; [ "$CODE" = 200 ] || fail "freeze: $CODE $BODY"
R0=$(runs); SSH "ls /srv x"; [ "$CODE" = 403 ] && echo "$BODY" | grep -q frozen && [ "$(runs)" = "$R0" ] && ok "N5: a frozen secret runs nothing" || fail "N5 frozen use: $CODE $BODY"
call POST /api/demipass/use "$AG" '{"name":"rootkey","action":"ssh_exec","target_host":"'$HOST'","target_user":"root","command":"ls /srv x","key_name":"box"}'
[ "$CODE" = 403 ] && [ "$(runs)" = "$R0" ] && ok "N5: …nor rides in as key_name" || fail "N5 key_name: $CODE $BODY"
call POST /api/demipass/use "$AG" '{"use_token":"'$FT'","target_user":"root","command":"ls /srv x"}'
[ "$CODE" = 423 ] && [ "$(runs)" = "$R0" ] && ok "follow-up 2: a token issued before the freeze dies with it" || fail "frozen token: $CODE $BODY"
call POST /api/demipass/freeze "$AG" '{"name":"box","freeze":false}'; [ "$CODE" = 403 ] && ok "N5: unfreezing without the PIN → 403" || fail "N5 unfreeze no pin: $CODE $BODY"
pin "scope:$BOX"; call POST /api/demipass/freeze "$A" '{"name":"box","freeze":false}'; [ "$CODE" = 200 ] && ok "N5: the owner unfreezes with the PIN" || fail "N5 unfreeze: $CODE $BODY"

! grep -qE "gh-token-zz88|box-pw-zz81|rootkey-pw-zz82|SMTP-PASSWORD-xyz|db-key-zz83|git-key-zz84|f-ssh-pw-zz85|hook-token-zz87" "$S/server.log" && ok "no value in the server log" || fail "value in log"
echo; [ $fails = 0 ] && echo "ALL OK" || echo "$fails FAILED"; exit $fails
