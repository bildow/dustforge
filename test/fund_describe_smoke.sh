#!/bin/bash
# Smoke, on a throwaway DB, for the three 2026-11-07 defects:
#   - a project's own wallet can be funded from the owner's wallet: POST /api/fleet/:slug/projects/:project/fund asks for
#     the PIN (403 missing pin, intent project-fund:<id>), moves the DD with it, and the PIN proof is used up;
#     own-wallet / unknown / bad amount / too little DD / not the owner are refused with nothing moved;
#   - a description (or note) holding the secret's own value is refused at store time;
#   - POST /api/blindkey/leak-scan/descriptions (PIN) names descriptions holding another vault value, never printing the
#     value, and with redact cuts the values out (list no longer carries them).
# No network beyond 127.0.0.1.
set -u
W=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
S=$(mktemp -d /tmp/dustforge-fund-describe-smoke.XXXXXX)
PORT=${PORT:-3793}; API=http://127.0.0.1:$PORT
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
for (const [u, bal] of [["owner-a", 100000], ["other-x", 100000], ["bench-w", 0]]) { const id = identity.createIdentity(); const enc = id.encrypted_private_key || id.encryptedPrivateKey;
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

# ── project funding ─────────────────────────────────────────────────────────────────────────────────────────────────
call POST /api/fleet/create "$A" '{"name":"Aaron Agents","slug":"fleet-one"}'; [ "$CODE" = 200 ] || fail "fleet create: $CODE $BODY"
python3 - "$DB_PATH" <<'EOF'
import sqlite3,sys
c=sqlite3.connect(sys.argv[1]); fid=c.execute("SELECT id FROM fleets WHERE slug='fleet-one'").fetchone()[0]
a=c.execute("SELECT did FROM identity_wallets WHERE username='owner-a'").fetchone()[0]
b=c.execute("SELECT did FROM identity_wallets WHERE username='bench-w'").fetchone()[0]
c.execute("INSERT INTO fleet_projects (fleet_id, project, owner_did, wallet_did, lane_address) VALUES (?, 'bench', ?, ?, 'bench@dustforge.com')", (fid, a, b))
c.execute("INSERT INTO fleet_projects (fleet_id, project, owner_did, wallet_did, lane_address) VALUES (?, 'mine', ?, ?, 'mine@dustforge.com')", (fid, a, a))
c.commit()
EOF
PID=$(Q "SELECT id FROM fleet_projects WHERE project='bench'")
A0=$(BAL owner-a)
call POST /api/fleet/fleet-one/projects/bench/fund "$A" '{"amount_cents":5040}'
[ "$CODE" = 403 ] && [ "$(echo "$BODY" | J intent)" = "project-fund:$PID" ] && [ "$(echo "$BODY" | J missing.0)" = pin ] && [ "$(BAL bench-w)" = 0 ] \
  && ok "fund without the PIN → 403 missing pin (intent project-fund:$PID), nothing moved" || fail "no pin: $CODE $BODY"
PIN "project-fund:$PID"; call POST /api/fleet/fleet-one/projects/bench/fund "$A" '{"amount_cents":5040}'
[ "$CODE" = 200 ] && [ "$(BAL bench-w)" = 5040 ] && [ "$(BAL owner-a)" = $((A0 - 5040)) ] && [ "$(echo "$BODY" | J wallet_balance_cents)" = 5040 ] \
  && ok "with the PIN: 5040 DD from the owner into bench" || fail "fund: $CODE $BODY bench=$(BAL bench-w)"
call POST /api/fleet/fleet-one/projects/bench/fund "$A" '{"amount_cents":10}'
[ "$CODE" = 403 ] && [ "$(BAL bench-w)" = 5040 ] && ok "the PIN proof is used up: a second funding asks again" || fail "replay: $CODE $BODY"
call GET /api/fleet/fleet-one/overview "$A"
[ "$(echo "$BODY" | python3 -c 'import json,sys; d=json.load(sys.stdin); print([p["wallet_balance_cents"] for p in d.get("projects",[]) if p["project"]=="bench"][0])')" = 5040 ] \
  && ok "the fleet board shows bench at 5040 DD" || fail "board: $(echo "$BODY" | head -c 300)"
call POST /api/fleet/fleet-one/projects/mine/fund "$A" '{"amount_cents":10}'; [ "$CODE" = 409 ] && ok "a project billing my own wallet → 409" || fail "own: $CODE $BODY"
call POST /api/fleet/fleet-one/projects/nope/fund "$A" '{"amount_cents":10}'; [ "$CODE" = 404 ] && ok "unknown project → 404" || fail "404: $CODE"
call POST /api/fleet/fleet-one/projects/bench/fund "$A" '{"amount_cents":0}'; [ "$CODE" = 400 ] && ok "amount 0 → 400" || fail "400: $CODE"
PIN "project-fund:$PID"; call POST /api/fleet/fleet-one/projects/bench/fund "$A" '{"amount_cents":10000000}'
[ "$CODE" = 402 ] && [ "$(BAL bench-w)" = 5040 ] && [ "$(BAL owner-a)" = $((A0 - 5040)) ] && ok "more than the owner holds → 402, nothing moved" || fail "402: $CODE $BODY"
call POST /api/fleet/fleet-one/projects/bench/fund "$X" '{"amount_cents":10}'; [ "$CODE" = 403 ] && [ "$(BAL bench-w)" = 5040 ] && ok "someone outside the fleet → 403" || fail "outsider: $CODE"

# ── descriptions ────────────────────────────────────────────────────────────────────────────────────────────────────
umask 077
python3 -c 'import secrets;print("v1-" + secrets.token_urlsafe(14))' > "$S/v1"; python3 -c 'import secrets;print("v2-" + secrets.token_urlsafe(14))' > "$S/v2"
mk(){ python3 -c 'import json,sys; v1=open(sys.argv[1]).read().strip(); v2=open(sys.argv[2]).read().strip(); n,val,desc,note=sys.argv[3:7]
f=lambda x: x.replace("V1",v1).replace("V2",v2)
print(json.dumps({"name":n,"value":f(val),"description":f(desc),"note":f(note),"secret_type":"api_key"}))' "$S/v1" "$S/v2" "$@"; }
call POST /api/demipass/store "$A" "$(mk leaky1 V1 'Unified to V1 on 07-07' '')"
[ "$CODE" = 400 ] && [ "$(echo "$BODY" | J field)" = description ] && [ -z "$(Q "SELECT id FROM blindkey_secrets WHERE name='leaky1'")" ] \
  && ok "a description holding the secret's own value is refused (400), nothing stored" || fail "own desc: $CODE $BODY"
call POST /api/demipass/store "$A" "$(mk leaky2 V1 'imap login' 'old one was V1')"
[ "$CODE" = 400 ] && ok "…in the note too" || fail "own note: $CODE $BODY"
call POST /api/demipass/store "$A" "$(mk shared V2 'the shared login' '')"; [ "$CODE" = 200 ] || fail "store shared: $CODE $BODY"
call POST /api/demipass/store "$A" "$(mk imap V1 'Unified to V2 2026-07-07' '')"
[ "$CODE" = 200 ] && ok "another secret's value in a description is not refused at store time (no oracle)" || fail "cross store: $CODE $BODY"
call POST /api/blindkey/leak-scan/descriptions "$A" '{"redact":false}'
[ "$CODE" = 403 ] && [ "$(echo "$BODY" | J intent)" = "scan-descriptions:0" ] && ok "the description check asks for the PIN" || fail "check no pin: $CODE $BODY"
PIN "scan-descriptions:0"; call POST /api/blindkey/leak-scan/descriptions "$A" '{"redact":false}'
[ "$CODE" = 200 ] && [ "$(echo "$BODY" | J found.0.name)" = imap ] && [ "$(echo "$BODY" | J found.0.holds_value_of.0)" = shared ] && ! grep -qF "$(cat "$S/v2")" <<<"$BODY" \
  && ok "check: imap's description holds the value of shared, named, the value never printed" || fail "check: $CODE"
[ -n "$(Q "SELECT id FROM blindkey_secrets WHERE name='imap' AND instr(description, '$(cat "$S/v2")') > 0")" ] && ok "…a check alone changes nothing" || fail "check changed data"
call GET /api/demipass/list "$A"; grep -qF "$(cat "$S/v2")" <<<"$BODY" && ok "(before: list carries the value in imap's description)" || fail "fixture: list did not carry it"
IMAP_ID=$(Q "SELECT id FROM blindkey_secrets WHERE name='imap'")
call POST /api/blindkey/leak-scan/descriptions "$A" '{"redact_ids":["x"]}'; [ "$CODE" = 400 ] && ok "redact_ids must be ids" || fail "bad ids: $CODE"
PIN "scan-descriptions:1"; call POST /api/blindkey/leak-scan/descriptions "$A" '{"redact_ids":['$IMAP_ID']}'
[ "$CODE" = 200 ] && [ "$(echo "$BODY" | J redacted.0)" = imap ] && ok "redact the picked row with the PIN" || fail "redact: $CODE $BODY"
call GET /api/demipass/list "$A"
! grep -qF "$(cat "$S/v2")" <<<"$BODY" && grep -q 'Unified to \[secret value removed\] 2026-07-07' <<<"$BODY" \
  && ok "after: list no longer carries the value; the rest of the description is kept" || fail "after redact: $(grep -o '"description":"[^"]*"' <<<"$BODY" | head -3)"
PIN "scan-descriptions:0"; call POST /api/blindkey/leak-scan/descriptions "$A" '{}'
[ "$CODE" = 200 ] && [ "$(echo "$BODY" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["found"]))')" = 0 ] && ok "a second check finds nothing" || fail "recheck: $BODY"
call POST /api/blindkey/leak-scan/descriptions "$X" '{"redact_ids":['$IMAP_ID']}'; [ "$CODE" = 403 ] && ok "another wallet needs its own PIN (and only sees its own)" || fail "other: $CODE"
# A note holding another value is found too; an unpicked row is left alone.
call POST /api/demipass/store "$A" "$(mk noted V1 'fine' 'the other one is V2')"; [ "$CODE" = 200 ] || fail "store noted: $CODE $BODY"
PIN "scan-descriptions:0"; call POST /api/blindkey/leak-scan/descriptions "$A" '{}'
[ "$(echo "$BODY" | J found.0.name)" = noted ] && [ "$(echo "$BODY" | J found.0.fields.0)" = note ] && ok "a note holding another secret's value is found" || fail "note: $BODY"
NOTED_ID=$(echo "$BODY" | J found.0.id)
PIN "scan-descriptions:1"; call POST /api/blindkey/leak-scan/descriptions "$A" '{"redact_ids":['$NOTED_ID']}'
[ -z "$(Q "SELECT id FROM blindkey_secrets WHERE name='noted' AND instr(note, '$(cat "$S/v2")') > 0")" ] && ok "…and cut out of the note" || fail "note redact"
# Rotating copies the description without the old value.
call POST /api/demipass/store "$A" "$(mk rot V2 'rot' '')"; [ "$CODE" = 200 ] || fail "store rot: $CODE"
python3 - "$DB_PATH" "$S/v2" <<'PY'
import sqlite3,sys
c=sqlite3.connect(sys.argv[1]); v=open(sys.argv[2]).read().strip()
c.execute("UPDATE blindkey_secrets SET description=? WHERE name='rot'", ("was "+v+" before",)); c.commit()
PY
python3 -c 'import secrets;print("v3-" + secrets.token_urlsafe(14))' > "$S/v3"
call POST /api/demipass/rotate "$A" "$(python3 -c 'import json,sys; print(json.dumps({"name":"rot","new_value":open(sys.argv[1]).read().strip()}))' "$S/v3")"
NEWD=$(Q "SELECT description FROM blindkey_secrets WHERE name LIKE 'rot%' AND status='active' ORDER BY id DESC LIMIT 1")
[ "$CODE" = 200 ] && ! grep -qF "$(cat "$S/v2")" <<<"$NEWD" && grep -q 'secret value removed' <<<"$NEWD" && ok "a rotation copies the description without the old value" || fail "rotate: $CODE $BODY / $NEWD"

[ $fails -gt 0 ] && { echo "--- server.log"; grep -i -m5 "error" "$S/server.log"; }
echo "$fails failure(s)"; exit $(( fails > 0 ))
