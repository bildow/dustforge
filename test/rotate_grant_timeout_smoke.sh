#!/bin/bash
# Aaron 2026-11-11: (1) SSH blind rotation is the owner's, from their own session; an agent rotates only an entry its
# owner delegated to it with rotation allowed (may_rotate). (2) /use waits on its target for the delegation's own limit
# (default 30 s, owner-set up to 180 s); a call DemiPass cuts off at that limit is answered 504 and not charged.
# Fake sshpass on PATH plays the host locally. A legacy demipass_delegations table (before the two new columns) is
# seeded before the server starts.
set -u
W=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
S=$(mktemp -d /tmp/dustforge-rotgrant-smoke.XXXXXX)
PORT=${PORT:-3841}; API=http://127.0.0.1:$PORT
[ -d "$W/node_modules" ] || export NODE_PATH=${NODE_PATH:-/home/flimflam/project/dustforge/node_modules}
export IDENTITY_MASTER_KEY=$(python3 -c 'import secrets;print(secrets.token_hex(32))') DB_PATH=$S/dustforge.db PORT \
  STALWART_HOST=127.0.0.1 STALWART_PORT=9 SMTP_HOST=127.0.0.1 SMTP_PORT=9 SMTP_RELAY_HOST=
mkdir -p "$S/bin" "$S/remote"
cat >"$S/bin/sshpass" <<'SH'
#!/bin/bash
echo "ARGV $*" >>"$FAKE_DIR/ssh.log"
last="${@: -1}"
if [ "$last" = "bash -s" ]; then PATH=$FAKE_DIR/remote:$PATH exec bash -s; else PATH=$FAKE_DIR/remote:$PATH exec bash -c "$last"; fi
SH
printf '#!/bin/bash\nS_=0\nwhile [ $# -gt 0 ] && [ "${1#-}" != "$1" ]; do case "$1" in --) shift; break;; -S) S_=1; shift;; *) shift;; esac; done\n[ $S_ = 1 ] && read -r pw\nexec "$@"\n' >"$S/remote/sudo"
printf '#!/bin/bash\ncat >>"$FAKE_DIR/chpasswd.in"\n' >"$S/remote/chpasswd"
chmod +x "$S/bin/sshpass" "$S/remote/sudo" "$S/remote/chpasswd"
export PATH="$S/bin:$PATH" FAKE_DIR=$S
cd "$W"

# Legacy fixture: the delegations table as it stood before timeout_seconds / may_rotate, with one live row.
node -e '
const Database = require("better-sqlite3"); const db = new Database(process.env.DB_PATH);
db.exec(`CREATE TABLE demipass_delegations (id INTEGER PRIMARY KEY AUTOINCREMENT, owner_did TEXT NOT NULL, delegate_did TEXT NOT NULL,
  secret_id INTEGER NOT NULL, context_id INTEGER, status TEXT DEFAULT \u0027active\u0027 CHECK(status IN (\u0027active\u0027,\u0027suspended\u0027,\u0027revoked\u0027)),
  max_uses INTEGER DEFAULT 0, use_count INTEGER DEFAULT 0, granted_by TEXT DEFAULT \u0027owner\u0027, granted_at TEXT DEFAULT CURRENT_TIMESTAMP,
  revoked_at TEXT, expires_at TEXT, delegate_kind TEXT DEFAULT \u0027agent\u0027, offer_state TEXT DEFAULT \u0027\u0027, UNIQUE(owner_did, delegate_did, secret_id, context_id))`);
db.prepare("INSERT INTO demipass_delegations (owner_did, delegate_did, secret_id) VALUES (?, ?, ?)").run("did:key:legacyowner", "did:key:legacyagent", 999);'

node server.js >"$S/server.log" 2>&1 & SRV=$!
trap 'kill $SRV 2>/dev/null; [ -n "${KEEP:-}" ] || rm -rf "$S"' EXIT
for i in $(seq 1 40); do curl -s -o /dev/null "$API/" && break; sleep 0.5; done
kill -0 $SRV 2>/dev/null || { echo "server died:"; tail -5 "$S/server.log"; exit 1; }
SIL='silicon:rotgrant-smoke-token-0123456789'
node -e '
const identity = require("./identity"), Database = require("better-sqlite3"), crypto = require("crypto");
const db = new Database(process.env.DB_PATH);
try { db.exec("ALTER TABLE identity_wallets ADD COLUMN password_hash TEXT"); } catch (_) {}
const h = crypto.createHash("sha256").update("hunter22").digest("hex"), dids = {};
for (const u of ["owner", "agent", "agent2", "outsider"]) {
  const id = identity.createIdentity(); dids[u] = id.did;
  db.prepare("INSERT INTO identity_wallets (did, username, email, encrypted_private_key, balance_cents, password_hash) VALUES (?, ?, ?, ?, 100000, ?)")
    .run(id.did, u, u + "@dustforge.com", id.encrypted_private_key || id.encryptedPrivateKey, h);
  db.prepare("INSERT INTO identity_transactions (did, amount_cents, type, description, balance_after) VALUES (?, 100000, ?, ?, 100000)").run(id.did, "test_grant", "smoke");
}
const f = db.prepare("INSERT INTO fleets (owner_did, name, slug) VALUES (?, ?, ?)").run(dids.owner, "Owner agents", "owner-agents").lastInsertRowid;
for (const u of ["agent", "agent2"]) db.prepare("INSERT INTO fleet_silicons (fleet_id, member_did, handle, silicon_id, created_by_fleet) VALUES (?, ?, ?, ?, 1)").run(f, dids[u], u, "sil_rg_" + u);
const of = db.prepare("INSERT INTO fleets (owner_did, name, slug) VALUES (?, ?, ?)").run(dids.outsider, "Outside", "outside").lastInsertRowid;
db.prepare("INSERT INTO silicon_agents (agent_name, did, carbon_did, token_hash) VALUES (?, ?, ?, ?)")
  .run("owner-bot", "did:silicon:rotgrant", dids.owner, crypto.createHash("sha256").update(process.argv[1]).digest("hex"));
const key = Buffer.from(process.env.IDENTITY_MASTER_KEY, "hex").slice(0, 32);
const seal = (v) => { const iv = crypto.randomBytes(16), c = crypto.createCipheriv("aes-256-gcm", key, iv); const e = Buffer.concat([c.update(v, "utf8"), c.final()]); return Buffer.concat([iv, c.getAuthTag(), e]).toString("base64"); };
for (const [name, ref, acct] of [["box", "DP-PWD-box-0001", "deploy"], ["laptop", "DP-PWD-laptop-0001", "aaron"]]) {
  db.prepare("INSERT INTO blindkey_secrets (did, name, secret_type, encrypted_value, status, ref_code, account_username) VALUES (?, ?, ?, ?, ?, ?, ?)").run(dids.owner, name, "password", seal(name + "pass-1"), "active", ref, acct);
  const sid = db.prepare("SELECT id FROM blindkey_secrets WHERE ref_code = ?").get(ref).id;
  db.prepare("INSERT INTO blindkey_contexts (secret_id, context_name, action_type, target_url_pattern, target_host_pattern, allowed_by) VALUES (?, ?, ?, ?, ?, ?)").run(sid, "default", "ssh_exec", "*", "100.83.112.88", dids.owner);
}
const box = db.prepare("SELECT id FROM blindkey_secrets WHERE ref_code = ?").get("DP-PWD-box-0001").id;
// An outside agent holding a delegation (made as the PIN path would): it never gets rotation.
db.prepare("INSERT INTO demipass_delegations (owner_did, delegate_did, secret_id) VALUES (?, ?, ?)").run(dids.owner, dids.outsider, box);
require("fs").writeFileSync(process.env.FAKE_DIR + "/dids.json", JSON.stringify(dids));
' "$SIL"
fails=0; ok(){ echo "ok   $*"; }; fail(){ echo "FAIL $*"; fails=$((fails+1)); }
J(){ python3 -c 'import json,sys; d=json.load(sys.stdin); v=d
for k in sys.argv[1].split("."):
    v = v[int(k)] if isinstance(v, list) else (v or {}).get(k)
print(v)' "$1"; }
call(){ local m=$1 p=$2 t=$3 b=${4:-}
  BODY=$(curl -s -m 60 -o - -w '\n%{http_code}' -X "$m" "$API$p" -H 'Content-Type: application/json' ${t:+-H "Authorization: Bearer $t"} ${b:+-d "$b"})
  CODE=${BODY##*$'\n'}; BODY=${BODY%$'\n'*}; }
login(){ call POST /api/identity/auth-fingerprint "" '{"username":"'$1'","password":"hunter22","scope":"transact","expires_in":"1h"}'; echo "$BODY" | J token; }
DID(){ python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$S/dids.json" "$1"; }
BAL(){ node -e 'const db=new (require("better-sqlite3"))(process.env.DB_PATH,{readonly:true}); console.log(db.prepare("SELECT COALESCE(SUM(amount_cents),0) AS b FROM identity_transactions WHERE did = ?").get(process.argv[1]).b)' "$1"; }
SQ(){ node -e 'const db=new (require("better-sqlite3"))(process.env.DB_PATH); const r=db.prepare(process.argv[1]).all(); console.log(JSON.stringify(r))' "$1"; }
O=$(login owner); A=$(login agent); A2=$(login agent2); X=$(login outsider)
[ "$O" != None ] && [ "$A" != None ] && [ "$A2" != None ] && [ "$X" != None ] && ok "four wallets signed in" || { fail login; exit 1; }
AG=$(DID agent); AG2=$(DID agent2); OUT=$(DID outsider)

# ── legacy fixture ──
R=$(SQ "SELECT timeout_seconds, may_rotate FROM demipass_delegations WHERE delegate_did = 'did:key:legacyagent'")
[ "$R" = '[{"timeout_seconds":null,"may_rotate":0}]' ] && ok "legacy delegation row: new columns added, defaults (30 s, no rotation)" || fail "legacy: $R"

# ── delegations ──
call POST /api/demipass/delegate "$O" '{"secret_name":"box","delegate_did":"'$AG'"}'; D1=$(echo "$BODY" | J delegation_id)
[ "$CODE" = 200 ] && ok "owner delegates box to its agent (#$D1)" || fail "delegate: $CODE $BODY"
call POST /api/demipass/delegate "$O" '{"secret_name":"box","delegate_did":"'$AG2'"}'; D2=$(echo "$BODY" | J delegation_id)
call POST /api/demipass/delegate "$O" '{"secret_name":"laptop","delegate_did":"'$AG'"}'; D3=$(echo "$BODY" | J delegation_id)
DOUT=$(SQ "SELECT id FROM demipass_delegations WHERE delegate_did = '$OUT'" | python3 -c 'import json,sys;print(json.load(sys.stdin)[0]["id"])')

# ── rotation: who ──
ROT(){ call POST /api/demipass/rotate-blind "$1" '{"ref":"'$2'","target_host":"100.83.112.88","target_user":"'${3:-deploy}'"}'; }
ROT "$A" DP-PWD-box-0001
[ "$CODE" = 403 ] && ok "an agent with a plain delegation cannot rotate (403)" || fail "agent no grant: $CODE $BODY"
ROT "$SIL" DP-PWD-laptop-0001 aaron
[ "$CODE" = 403 ] && ok "a silicon token on the owner's wallet cannot rotate the owner's login (403)" || fail "silicon: $CODE $BODY"
ROT "$X" DP-PWD-laptop-0001 aaron; C1=$CODE; ROT "$X" DP-PWD-nope-0001; C2=$CODE
[ "$C1" = 403 ] && [ "$C2" = 403 ] && ok "another wallet gets the same 403 for a real ref and a made-up one" || fail "outsider: $C1 $C2"

# ── settings: who may change them ──
call PATCH /api/demipass/delegations/$D1 "$A" '{"may_rotate":true}'
[ "$CODE" = 404 ] && ok "the agent cannot grant itself rotation" || fail "self-grant: $CODE $BODY"
call PATCH /api/demipass/delegations/$D1 "$SIL" '{"timeout_seconds":180}'
[ "$CODE" = 403 ] && ok "a silicon token cannot change the owner's grants" || fail "silicon settings: $CODE $BODY"
call PATCH /api/demipass/delegations/$DOUT "$O" '{"may_rotate":true}'
[ "$CODE" = 403 ] && ok "rotation is never given to an outside agent" || fail "outside grant: $CODE $BODY"
for t in 4 181 '"60"' 30.5; do call PATCH /api/demipass/delegations/$D1 "$O" '{"timeout_seconds":'$t'}'; [ "$CODE" = 400 ] || fail "timeout $t accepted: $CODE"; done
ok "timeout_seconds outside 5–180 (or not a whole number) is refused"
call PATCH /api/demipass/delegations/$D1 "$O" '{"may_rotate":true}'
[ "$CODE" = 200 ] && [ "$(echo "$BODY" | J may_rotate)" = True ] && ok "owner grants its agent rotation of box" || fail "grant: $CODE $BODY"

# ── rotation by the agent ──
ROT "$A" DP-PWD-laptop-0001 aaron
[ "$CODE" = 403 ] && ok "the grant covers only box: the agent still cannot rotate laptop" || fail "laptop: $CODE $BODY"
ROT "$A" DP-PWD-box-0001
NEWREF=$(echo "$BODY" | J new_ref)
[ "$CODE" = 200 ] && [ "$(echo "$BODY" | J rotated_by)" = delegate ] && [ "$(echo "$BODY" | J delegations_transferred)" = 3 ] \
  && ok "the agent rotates box under its grant; its, agent2's and the outside delegation move to the new version" || fail "agent rotate: $CODE $BODY"
R=$(SQ "SELECT d.id, s.ref_code, d.may_rotate FROM demipass_delegations d JOIN blindkey_secrets s ON s.id = d.secret_id WHERE d.id IN ($D1, $D2) ORDER BY d.id")
[ "$R" = "[{\"id\":$D1,\"ref_code\":\"$NEWREF\",\"may_rotate\":1},{\"id\":$D2,\"ref_code\":\"$NEWREF\",\"may_rotate\":0}]" ] && ok "delegations point at $NEWREF; the grant moved with them" || fail "moved: $R"
call POST /api/demipass/use "$A" '{"ref":"'$NEWREF'","action":"ssh_exec","target_host":"100.83.112.88","target_user":"deploy","command":"echo still-mine"}'
[ "$CODE" = 200 ] && echo "$BODY" | grep -q still-mine && ok "the agent still uses box after rotating it" || fail "use after rotate: $CODE $BODY"
ROT "$A2" "$NEWREF"
[ "$CODE" = 403 ] && ok "agent2 (delegated, no rotation grant) cannot rotate" || fail "agent2: $CODE $BODY"
ROT "$O" DP-PWD-laptop-0001 aaron
[ "$CODE" = 200 ] && [ "$(echo "$BODY" | J rotated_by)" = owner ] && ok "the owner rotates their own login from their session" || fail "owner: $CODE $BODY"

# ── /use timeout ──
call GET /api/demipass/delegations "$O"
echo "$BODY" | python3 -c 'import json,sys; d={x["id"]:x for x in json.load(sys.stdin)["delegations"]}; x=d['$D1']; sys.exit(0 if x["timeout_seconds"]==30 and x["may_rotate"] is True else 1)' \
  && ok "listing shows timeout 30 s by default and the rotation grant" || fail "listing: $BODY"
call PATCH /api/demipass/delegations/$D1 "$O" '{"timeout_seconds":180}'
[ "$CODE" = 200 ] && [ "$(echo "$BODY" | J timeout_seconds)" = 180 ] && ok "owner sets the agent's limit to 180 s" || fail "180: $CODE $BODY"
call PATCH /api/demipass/delegations/$D1 "$O" '{"timeout_seconds":5}'
B0=$(BAL "$AG"); t0=$(date +%s)
call POST /api/demipass/use "$A" '{"ref":"'$NEWREF'","action":"ssh_exec","target_host":"100.83.112.88","target_user":"deploy","command":"sleep 9"}'
dt=$(( $(date +%s) - t0 )); B1=$(BAL "$AG")
[ "$CODE" = 504 ] && [ "$(echo "$BODY" | J cut_off)" = True ] && [ "$(echo "$BODY" | J timeout_seconds)" = 5 ] && [ $dt -ge 5 ] && [ $dt -lt 15 ] \
  && ok "a call past the 5 s limit is cut off: 504 after ${dt}s" || fail "cut off: $CODE ${dt}s $BODY"
[ "$B0" = "$B1" ] && [ "$(echo "$BODY" | J refunded_dd)" = 10 ] && ok "the cut-off call is not charged (balance $B0 → $B1, 10 DD back)" || fail "charged: $B0 → $B1 $BODY"
R=$(SQ "SELECT type, amount_cents FROM identity_transactions WHERE did = '$AG' ORDER BY id DESC LIMIT 2")
echo "$R" | grep -q api_call_compute_refund && ok "the refund is its own ledger row" || fail "ledger: $R"
call POST /api/demipass/use "$A2" '{"ref":"'$NEWREF'","action":"ssh_exec","target_host":"100.83.112.88","target_user":"deploy","command":"sleep 7"}'
[ "$CODE" = 200 ] && ok "agent2's delegation keeps the 30 s default: a 7 s call completes" || fail "agent2 7s: $CODE $BODY"
B0=$(BAL "$AG")
call POST /api/demipass/use "$A" '{"ref":"'$NEWREF'","action":"ssh_exec","target_host":"100.83.112.88","target_user":"deploy","command":"echo quick"}'
B1=$(BAL "$AG")
[ "$CODE" = 200 ] && [ $((B0 - B1)) = 10 ] && ok "a call that completes is charged as before (10 DD)" || fail "normal charge: $CODE $B0 → $B1"

grep -q "boxpass\|laptoppass" "$S/server.log" && fail "a password reached the server log" || ok "no password in the server log"
[ $fails = 0 ] && echo "rotate_grant_timeout_smoke: all passed" || { echo "rotate_grant_timeout_smoke: $fails failure(s)"; exit 1; }
