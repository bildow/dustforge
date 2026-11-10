#!/bin/bash
# Smoke, on a throwaway DB, for removing a project (Aaron 2026-11-09: "a button under projects (cost centers) to remove
# that project from my wallet, and if it has a balance it needs to return to my total balance"):
#   DELETE /api/fleet/:slug/projects/:project asks for the PIN (intent project-remove:<id>), then in one step returns the
#   board-minted wallet's DD to the owner and drops the row, its operators and the wallet's membership; a project billing
#   the owner's own wallet is removed with nothing to move; a wallet that is someone's own account (or shared by two
#   projects) with DD in it is refused before the PIN, nothing moved; unknown → 404; outsider → 403.
# No network beyond 127.0.0.1.
# No network beyond 127.0.0.1.
set -u
W=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
S=$(mktemp -d /tmp/dustforge-project-remove-smoke.XXXXXX)
PORT=${PORT:-3794}; API=http://127.0.0.1:$PORT
[ -d "$W/node_modules" ] || export NODE_PATH=${NODE_PATH:-/home/flimflam/project/dustforge/node_modules}
export IDENTITY_MASTER_KEY=$(python3 -c 'import secrets;print(secrets.token_hex(32))') DB_PATH=$S/dustforge.db PORT \
  STALWART_HOST=127.0.0.1 STALWART_PORT=1 SMTP_RELAY_HOST= SMTP_HOST=127.0.0.1 SMTP_PORT=9
cd "$W"
node server.js >"$S/server.log" 2>&1 & SRV=$!
trap 'kill $SRV 2>/dev/null; rm -rf "$S"' EXIT
for i in $(seq 1 40); do curl -s -o /dev/null "$API/api/health" && break; sleep 0.5; done
kill -0 $SRV 2>/dev/null || { echo "server died:"; tail -5 "$S/server.log"; exit 1; }
H=$(printf '%s' hunter22 | sha256sum | cut -d' ' -f1)
node -e '
const identity = require("./identity"); const Database = require("better-sqlite3"); const db = new Database(process.env.DB_PATH);
for (const [u, bal] of [["owner-a", 100000], ["other-x", 100000], ["project-bench", 5000], ["project-ops", 0], ["project-pair", 700], ["indie-w", 900]]) { const id = identity.createIdentity(); const enc = id.encrypted_private_key || id.encryptedPrivateKey;
  db.prepare("INSERT INTO identity_wallets (did, username, email, encrypted_private_key, balance_cents, password_hash) VALUES (?, ?, ?, ?, ?, ?)").run(id.did, u, u + "@dustforge.com", enc, bal, process.argv[1]);
  if (bal) db.prepare("INSERT INTO identity_transactions (did, amount_cents, type, description, balance_after) VALUES (?, ?, ?, ?, ?)").run(id.did, bal, "topup", "smoke", bal); }' "$H"
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
BAL(){ Q "SELECT COALESCE(SUM(amount_cents),0) FROM identity_transactions WHERE did=(SELECT did FROM identity_wallets WHERE username='$1')"; }
A=$(login owner-a); X=$(login other-x)
call POST /api/identity/pin "$A" '{"pin":"4321","password":"hunter22"}'
PIN(){ call POST /api/identity/gate/verify "$A" '{"gate":"pin","pin":"4321","intent":"'$1'"}'; }


call POST /api/fleet/create "$A" '{"name":"Aaron Agents","slug":"fleet-one"}'; [ "$CODE" = 200 ] || fail "fleet create: $CODE $BODY"
python3 - "$DB_PATH" <<'EOF2'
import sqlite3,sys
c=sqlite3.connect(sys.argv[1]); fid=c.execute("SELECT id FROM fleets WHERE slug='fleet-one'").fetchone()[0]
d=lambda u: c.execute("SELECT did FROM identity_wallets WHERE username=?", (u,)).fetchone()[0]
a=d('owner-a')
def proj(name, wallet, member=True):
    c.execute("INSERT INTO fleet_projects (fleet_id, project, owner_did, wallet_did, lane_address) VALUES (?, ?, ?, ?, ?)", (fid, name, wallet, wallet, name + '.claude@dustforge.com'))
    if member: c.execute("INSERT OR IGNORE INTO fleet_members (fleet_id, member_did, role) VALUES (?, ?, 'agent')", (fid, wallet))
    pid=c.execute("SELECT id FROM fleet_projects WHERE fleet_id=? AND project=?", (fid, name)).fetchone()[0]
    c.execute("INSERT INTO fleet_project_operators (project_id, operator_did) VALUES (?, ?)", (pid, a))
proj('bench', d('project-bench')); proj('ops', d('project-ops'))
proj('pair', d('project-pair')); proj('pair2', d('project-pair'))        # one wallet behind two projects
proj('indie', d('indie-w'))                                              # someone's own account, not minted by the board
c.execute("INSERT INTO fleet_projects (fleet_id, project, owner_did, wallet_did, lane_address) VALUES (?, 'mine', ?, ?, 'mine@dustforge.com')", (fid, a, a))
c.execute("INSERT INTO wallet_refill_rules (did, amount_cents, enabled) VALUES (?, 100, 1)", (d('project-bench'),))
c.commit()
EOF2
PID=$(Q "SELECT id FROM fleet_projects WHERE project='bench'")
A0=$(BAL owner-a)
call DELETE /api/fleet/fleet-one/projects/bench "$A"
[ "$CODE" = 403 ] && [ "$(echo "$BODY" | J intent)" = "project-remove:$PID" ] && [ "$(BAL project-bench)" = 5000 ] && [ -n "$(Q "SELECT id FROM fleet_projects WHERE project='bench'")" ] \
  && ok "remove without the PIN → 403 missing pin (intent project-remove:$PID), nothing moved, row kept" || fail "no pin: $CODE $BODY"
PIN "project-remove:$PID"; call DELETE /api/fleet/fleet-one/projects/bench "$A"
[ "$CODE" = 200 ] && [ "$(echo "$BODY" | J returned_cents)" = 5000 ] && [ "$(BAL project-bench)" = 0 ] && [ "$(BAL owner-a)" = $((A0 + 5000)) ] \
  && [ "$(echo "$BODY" | J balance_after)" = $((A0 + 5000)) ] && ok "with the PIN: bench removed, its 5000 DD back in the owner's wallet" || fail "remove: $CODE $BODY bench=$(BAL project-bench) owner=$(BAL owner-a)"
[ -z "$(Q "SELECT id FROM fleet_projects WHERE project='bench'")" ] && [ "$(Q "SELECT COUNT(*) FROM fleet_project_operators WHERE project_id=$PID")" = 0 ] \
  && [ "$(Q "SELECT COUNT(*) FROM fleet_members WHERE member_did=(SELECT did FROM identity_wallets WHERE username='project-bench')")" = 0 ] \
  && [ "$(Q "SELECT enabled FROM wallet_refill_rules WHERE did=(SELECT did FROM identity_wallets WHERE username='project-bench')")" = 0 ] \
  && ok "row, operators, the wallet's fleet membership and its refill rule are gone" || fail "leftovers"
[ "$(Q "SELECT COUNT(*) FROM identity_transactions WHERE type IN ('project_removed_out','project_removed_in')")" = 2 ] && ok "the return is two ledger rows (out of the project, into the owner)" || fail "ledger rows"
call DELETE /api/fleet/fleet-one/projects/bench "$A"; [ "$CODE" = 404 ] && ok "removed twice → 404" || fail "twice: $CODE"
call GET /api/fleet/fleet-one/overview "$A"
[ "$(echo "$BODY" | python3 -c 'import json,sys; print(sorted(p["project"] for p in json.load(sys.stdin).get("projects",[])))')" = "['indie', 'mine', 'ops', 'pair', 'pair2']" ] \
  && ok "the board no longer lists bench" || fail "board: $(echo "$BODY" | head -c 300)"

PID=$(Q "SELECT id FROM fleet_projects WHERE project='ops'"); A1=$(BAL owner-a)
PIN "project-remove:$PID"; call DELETE /api/fleet/fleet-one/projects/ops "$A"
[ "$CODE" = 200 ] && [ "$(echo "$BODY" | J returned_cents)" = 0 ] && [ "$(BAL owner-a)" = "$A1" ] && ok "an empty project wallet: removed, nothing to move" || fail "ops: $CODE $BODY"
PID=$(Q "SELECT id FROM fleet_projects WHERE project='mine'")
PIN "project-remove:$PID"; call DELETE /api/fleet/fleet-one/projects/mine "$A"
[ "$CODE" = 200 ] && [ "$(BAL owner-a)" = "$A1" ] && [ "$(Q "SELECT COUNT(*) FROM fleet_members WHERE member_did=(SELECT did FROM identity_wallets WHERE username='owner-a')")" = 1 ] \
  && ok "a project billing my own wallet: removed, my membership and balance untouched" || fail "mine: $CODE $BODY"

PID=$(Q "SELECT id FROM fleet_projects WHERE project='indie'")
PIN "project-remove:$PID"; call DELETE /api/fleet/fleet-one/projects/indie "$A"
[ "$CODE" = 409 ] && [ "$(BAL indie-w)" = 900 ] && [ -n "$(Q "SELECT id FROM fleet_projects WHERE project='indie'")" ] && [ "$(BAL owner-a)" = "$A1" ] \
  && ok "someone's own wallet holding DD → 409, nothing taken, row kept" || fail "indie: $CODE $BODY"
call DELETE /api/fleet/fleet-one/projects/indie "$A"
[ "$CODE" = 409 ] && ok "…and that refusal comes before the PIN (no PIN asked for a removal that cannot happen)" || fail "indie order: $CODE $BODY"
PID=$(Q "SELECT id FROM fleet_projects WHERE project='pair'")
PIN "project-remove:$PID"; call DELETE /api/fleet/fleet-one/projects/pair "$A"
[ "$CODE" = 409 ] && [ "$(BAL project-pair)" = 700 ] && ok "a wallet behind two projects → 409, its DD stay" || fail "pair: $CODE $BODY"

call DELETE /api/fleet/fleet-one/projects/nope "$A"; [ "$CODE" = 404 ] && ok "unknown project → 404" || fail "404: $CODE"
call DELETE /api/fleet/fleet-one/projects/pair2 "$X"; [ "$CODE" = 403 ] && [ "$(BAL project-pair)" = 700 ] && ok "someone outside the fleet → 403" || fail "outsider: $CODE"

echo; [ $fails = 0 ] && echo "project_remove_smoke: all passed" || { echo "project_remove_smoke: $fails FAILED"; exit 1; }
