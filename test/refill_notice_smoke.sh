#!/bin/bash
# A refill rule that cannot run tells the wallet that pays (Aaron 2026-11-15): the scheduler pass raises one notice,
# the app lists it with the deposit it needs, the phone's holds/alerts payload carries it, it is dismissable by its
# owner only. A card-funded owner rule asks for a deposit. Card deposits: off by default (503), the switch, test mode.
set -u
W=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
S=$(mktemp -d /tmp/dustforge-refill-notice-smoke.XXXXXX)
PORT=${PORT:-3831}; API=http://127.0.0.1:$PORT
[ -d "$W/node_modules" ] || export NODE_PATH=${NODE_PATH:-/home/flimflam/project/dustforge/node_modules}
export IDENTITY_MASTER_KEY=$(python3 -c 'import secrets;print(secrets.token_hex(32))') DB_PATH=$S/dustforge.db PORT \
  STALWART_HOST=127.0.0.1 STALWART_PORT=1 SMTP_RELAY_HOST= SMTP_HOST=127.0.0.1 SMTP_PORT=9 FLEET_PASS_FIRST_MS=1500
unset DEPOSITS STRIPE_SECRET_KEY STRIPE_TEST_CREDITS
cd "$W"
fails=0; ok(){ echo "ok   $*"; }; fail(){ echo "FAIL $*"; fails=$((fails+1)); }
J(){ python3 -c 'import json,sys; d=json.load(sys.stdin); v=d
for k in sys.argv[1].split("."):
    v = v[int(k)] if isinstance(v, list) else (v or {}).get(k)
print(v)' "$1"; }
Q(){ python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); r=c.execute(sys.argv[2]).fetchone(); print(r[0] if r else '')" "$DB_PATH" "$1"; }
call(){ local m=$1 p=$2 t=$3 b=${4:-}
  BODY=$(curl -s -o - -w '\n%{http_code}' -X "$m" "$API$p" -H 'Content-Type: application/json' ${t:+-H "Authorization: Bearer $t"} ${b:+-d "$b"})
  CODE=${BODY##*$'\n'}; BODY=${BODY%$'\n'*}; }
start(){ node server.js >>"$S/server.log" 2>&1 & SRV=$!; for i in $(seq 1 40); do curl -s -o /dev/null "$API/api/health" && break; sleep 0.5; done; }
waitfor(){ for i in $(seq 1 30); do [ "$(Q "$1")" = "$2" ] && return 0; sleep 0.5; done; return 1; }
# Boot once for the schema, then seed: wallets, a fleet, an agent with an auto-refill, a card-funded owner rule.
start; kill $SRV; wait $SRV 2>/dev/null
H=$(printf '%s' hunter22 | sha256sum | cut -d' ' -f1)
node -e '
const identity = require("./identity"); const Database = require("better-sqlite3"); const db = new Database(process.env.DB_PATH);
const mk = (u, bal) => { const id = identity.createIdentity(); db.prepare("INSERT INTO identity_wallets (did, username, email, encrypted_private_key, balance_cents, password_hash) VALUES (?, ?, ?, ?, ?, ?)").run(id.did, u, u + "@smoke.invalid", id.encrypted_private_key || id.encryptedPrivateKey, bal, process.argv[1]);
  db.prepare("INSERT INTO identity_transactions (did, amount_cents, type, description, balance_after) VALUES (?, ?, ?, ?, ?)").run(id.did, bal, "topup", "smoke", bal); return id.did; };
const o = mk("owner", 100), a = mk("agent", 10), x = mk("stranger", 100);
const f = db.prepare("INSERT INTO fleets (owner_did, name, slug) VALUES (?, ?, ?)").run(o, "Owner", "owner-agents").lastInsertRowid;
db.prepare("INSERT INTO fleet_members (fleet_id, member_did, role) VALUES (?, ?, ?)").run(f, o, "owner");
db.prepare("INSERT INTO fleet_members (fleet_id, member_did, role) VALUES (?, ?, ?)").run(f, a, "agent");
db.prepare(`INSERT INTO fleet_silicons (fleet_id, member_did, handle, display_name, silicon_id, refill_enabled, refill_threshold_cents, refill_amount_cents, created_by_fleet, status)
            VALUES (?, ?, ?, ?, ?, 1, 50, 500, 1, ?)`).run(f, a, "agent", "Agent", "sil_smoke", "active");
db.prepare("INSERT INTO wallet_refill_rules (did, cadence, amount_cents, funding, enabled, next_run_at) VALUES (?, ?, ?, ?, 1, ?)").run(x, "weekly", 2000, "stripe", "2026-01-01T00:00:00.000Z");' "$H" \
  || { echo "FAIL seed"; exit 1; }
start; trap 'kill $SRV 2>/dev/null; rm -rf "$S"' EXIT
did(){ Q "SELECT did FROM identity_wallets WHERE username='$1'"; }
login(){ call POST /api/identity/auth-fingerprint "" '{"username":"'$1'","password":"hunter22","scope":"transact","expires_in":"1h"}'; echo "$BODY" | J token; }
OWN=$(login owner); AG=$(login agent); STR=$(login stranger)

# 1. the owner (100 DD) cannot pay the agent's 500 DD refill → one notice, deposit 400
waitfor "SELECT COUNT(*) FROM wallet_notices WHERE did='$(did owner)' AND kind='refill_failed'" 1 && ok "the first scheduler pass raised one refill_failed notice for the owner" || fail "no notice: $(tail -3 $S/server.log)"
call GET /api/billing/notices "$OWN"
[ "$CODE" = 200 ] && [ "$(echo "$BODY" | J notices.0.title)" = "Refill of @agent failed: deposit needed" ] && [ "$(echo "$BODY" | J notices.0.deposit.amount_dd)" = 400 ] \
  && ok "the app lists it: 'Refill of @agent failed: deposit needed', deposit 400 DD" || fail "list: $CODE $BODY"
echo "$BODY" | J notices.0.text | grep -q "your wallet holds 100 DD" && ok "the text says what the paying wallet holds" || fail "text: $BODY"
call GET /api/billing/notices "$AG"; [ "$(echo "$BODY" | J notices)" = "[]" ] && ok "the agent gets no notice about its owner's wallet" || fail "agent: $BODY"
call GET /api/identity/holds "$OWN"; echo "$BODY" | python3 -c 'import json,sys; d=json.load(sys.stdin); n=[x for x in d["notices"] if x.get("kind")=="refill_failed"]; sys.exit(0 if len(n)==1 and str(n[0]["notice_id"]).isdigit() else 1)' \
  && ok "the holds/alerts notices (what the phone polls) carry it, with a numeric notice_id" || fail "holds: $BODY"
sleep 1; [ "$(Q "SELECT COUNT(*) FROM wallet_notices WHERE did='$(did owner)'")" = 1 ] && ok "still one notice (not one per pass)" || fail "repeated"
# 2. card-funded owner rule: a deposit_due notice, nothing credited, schedule moved on
waitfor "SELECT COUNT(*) FROM wallet_notices WHERE did='$(did stranger)' AND kind='deposit_due'" 1 && [ "$(Q "SELECT balance_cents FROM identity_wallets WHERE username='stranger'")" = 100 ] \
  && [ "$(Q "SELECT next_run_at > '2026-01-02' FROM wallet_refill_rules WHERE did='$(did stranger)'")" = 1 ] \
  && ok "a due card-funded refill asks for a deposit (deposit_due), credits nothing, and moves its schedule" || fail "deposit_due"
# 3. dismiss: only the notice's own wallet
NID=$(Q "SELECT id FROM wallet_notices WHERE did='$(did owner)'")
call POST /api/billing/notices/$NID/dismiss "$STR"; [ "$(echo "$BODY" | J ok)" = False ] && ok "another wallet cannot dismiss it" || fail "stranger dismiss: $CODE $BODY"
call POST /api/billing/notices/$NID/dismiss "$OWN"; [ "$(echo "$BODY" | J ok)" = True ] && ok "the owner dismisses it" || fail "dismiss: $BODY"
# 4. deposits: off by default
call GET /api/billing/deposit ""; [ "$(echo "$BODY" | J enabled)" = False ] && [ "$(echo "$BODY" | J mode)" = off ] && ok "GET /api/billing/deposit: off by default, amounts listed" || fail "cfg: $BODY"
call POST /api/billing/deposit "$OWN" '{"amount_usd_cents":1000}'; [ "$CODE" = 503 ] && echo "$BODY" | grep -q "not switched on" && ok "POST while off → 503 'not switched on yet'" || fail "off: $CODE $BODY"
call POST /api/billing/deposit "" '{"amount_usd_cents":1000}'; [ "$CODE" = 401 ] && ok "no token → 401" || fail "noauth: $CODE"
kill $SRV; wait $SRV 2>/dev/null; export DEPOSITS=test STRIPE_SECRET_KEY=sk_test_smoke_not_a_key; start; OWN=$(login owner)
call GET /api/billing/deposit ""; [ "$(echo "$BODY" | J enabled)" = True ] && [ "$(echo "$BODY" | J credits_dd)" = False ] && ok "DEPOSITS=test with a test key: on, and says it credits no DD" || fail "test cfg: $BODY"
call POST /api/billing/deposit "$OWN" '{"amount_usd_cents":777}'; [ "$CODE" = 400 ] && ok "an amount outside the list → 400" || fail "amount: $CODE $BODY"
grep -q "sk_test_smoke" "$S/server.log" && fail "the key reached the log" || ok "no key in the server log"
echo "$fails failure(s)"; exit $(( fails > 0 ))
