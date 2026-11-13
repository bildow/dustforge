#!/bin/bash
# A charged /use that a restart or crash kills is refunded once at the next start (EVAL 2026-11-13: eight calls killed
# by two deploys kept their charge). A call that answered leaves nothing behind and stays charged.
# Fake sshpass on PATH plays the host locally.
set -u
W=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
S=$(mktemp -d /tmp/dustforge-restart-refund-smoke.XXXXXX)
PORT=${PORT:-3847}; API=http://127.0.0.1:$PORT
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

start(){ node server.js >>"$S/server.log" 2>&1 & SRV=$!; for i in $(seq 1 40); do curl -s -o /dev/null "$API/" && break; sleep 0.5; done; }
start
trap 'kill $SRV 2>/dev/null; [ -n "${KEEP:-}" ] || rm -rf "$S"' EXIT
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
O=$(login owner); [ "$O" != None ] && ok "owner signed in" || { fail login; exit 1; }
OD=$(DID owner)
INF(){ SQ "SELECT COUNT(*) AS n FROM use_inflight" | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["n"])'; }
USE(){ curl -s -m 60 -o "$S/$1.out" -w '%{http_code}' -X POST "$API/api/demipass/use" -H 'Content-Type: application/json' -H "Authorization: Bearer $O" \
  -d '{"ref":"DP-PWD-box-0001","action":"ssh_exec","target_host":"100.83.112.88","target_user":"deploy","command":"'"$2"'"}'; }

# ── a call that answers: charged once, nothing left in flight ──
B0=$(BAL "$OD"); C=$(USE quick "echo hi"); B1=$(BAL "$OD")
[ "$C" = 200 ] && [ "$B1" -lt "$B0" ] && [ "$(INF)" = 0 ] && ok "an answered call is charged ($((B0-B1)) DD) and leaves no in-flight row" || fail "quick: $C $B0->$B1 inflight=$(INF) $(head -c 200 "$S/quick.out")"
COST=$((B0-B1))

# ── a call killed mid-flight (SIGKILL, like a crash or a deploy's restart) ──
USE slow "sleep 15" >/dev/null & CU=$!
for i in $(seq 1 30); do [ "$(INF)" = 1 ] && break; sleep 0.2; done
B2=$(BAL "$OD"); [ "$(INF)" = 1 ] && [ $((B1-B2)) = $COST ] && ok "while it runs, the charged call holds one in-flight row" || fail "inflight: $(INF) $B1->$B2"
kill -9 $SRV; wait $SRV 2>/dev/null; wait $CU 2>/dev/null
[ "$(INF)" = 1 ] && [ "$(BAL "$OD")" = "$B2" ] && ok "killed: the charge stays and the row survives the crash" || fail "after kill: $(INF) $(BAL "$OD")"
start
[ "$(INF)" = 0 ] && [ "$(BAL "$OD")" = "$B1" ] && ok "at the next start the killed call is refunded ($COST DD) and its row removed" || fail "restart refund: inflight=$(INF) bal=$(BAL "$OD") want $B1"
SQ "SELECT description FROM identity_transactions WHERE did = '$OD' AND type = 'api_call_compute_refund'" | grep -q "ended by a server restart" && ok "…recorded as a refund for a call a restart ended" || fail "refund row: $(SQ "SELECT type, description FROM identity_transactions WHERE did = '$OD' ORDER BY id DESC LIMIT 3")"
grep -q "use_inflight: refunded 1 of 1" "$S/server.log" && ok "…and the start-up log says so" || fail "log: $(grep use_inflight "$S/server.log")"

# ── refunded once only: another restart changes nothing ──
kill $SRV; wait $SRV 2>/dev/null; start
[ "$(BAL "$OD")" = "$B1" ] && [ "$(SQ "SELECT COUNT(*) AS n FROM identity_transactions WHERE did = '$OD' AND type = 'api_call_compute_refund'" | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["n"])')" = 1 ] && ok "a second restart does not refund it again" || fail "double refund: $(BAL "$OD")"

# ── a call cut off at its own limit (30 s here) refunds itself once and leaves no row for a restart to refund again ──
B3=$(BAL "$OD"); C=$(USE cut "sleep 40")
[ "$C" = 504 ] && grep -q '"cut_off":true' "$S/cut.out" && [ "$(BAL "$OD")" = "$B3" ] && [ "$(INF)" = 0 ] && ok "a cut-off call is refunded by itself and leaves no in-flight row" || fail "cut: $C bal $B3->$(BAL "$OD") inflight=$(INF) $(head -c 200 "$S/cut.out")"
kill $SRV; wait $SRV 2>/dev/null; start
[ "$(BAL "$OD")" = "$B3" ] && ok "…and a restart after it refunds nothing more" || fail "cut double: $(BAL "$OD") want $B3"
echo; [ $fails = 0 ] && echo "ALL OK" || echo "$fails FAILED"; exit $fails
