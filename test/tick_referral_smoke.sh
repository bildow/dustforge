#!/bin/bash
# Smoke of the Buoy tick fee and the referrer's tick share after the DD redenomination (1 DD = $0.001):
#   - a member tick costs 0.1 DD, billed 10 DD per 100 ticks;
#   - the referrer earns 10% of that fee (1 DD per 100 ticks), with the remainder carried — never more
#     than the referred member paid, so two linked accounts cannot mint DD by ticking;
#   - an unauthenticated tick is free and earns nobody anything.
# Boots server.js on a throwaway DB. No network.
set -u
W=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
S=$(mktemp -d /tmp/dustforge-tick-smoke.XXXXXX)
PORT=${PORT:-3795}; API=http://127.0.0.1:$PORT
[ -d "$W/node_modules" ] || export NODE_PATH=${NODE_PATH:-/home/flimflam/project/dustforge/node_modules}
export IDENTITY_MASTER_KEY=$(python3 -c 'import secrets;print(secrets.token_hex(32))') DB_PATH=$S/dustforge.db PORT \
  STALWART_HOST=127.0.0.1 STALWART_PORT=1 SMTP_RELAY_HOST= SMTP_HOST=127.0.0.1 SMTP_PORT=9
cd "$W"
node server.js >"$S/server.log" 2>&1 & SRV=$!
trap 'kill $SRV 2>/dev/null; rm -rf "$S"' EXIT
for i in $(seq 1 40); do curl -s -o /dev/null "$API/" && break; sleep 0.5; done
kill -0 $SRV 2>/dev/null || { echo "server died:"; tail -5 "$S/server.log"; exit 1; }
fails=0; ok(){ echo "ok   $*"; }; fail(){ echo "FAIL $*"; fails=$((fails+1)); }
Q(){ python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); r=c.execute(sys.argv[2]).fetchone(); print(r[0] if r else '')" "$DB_PATH" "$1"; }

node -e '
const identity = require("./identity"); const Database = require("better-sqlite3"); const crypto = require("crypto");
const db = new Database(process.env.DB_PATH);
const h = crypto.createHash("sha256").update("hunter22").digest("hex"); const dids = {};
for (const u of ["referrer", "member"]) {
  const id = identity.createIdentity(); dids[u] = id.did;
  db.prepare("INSERT INTO identity_wallets (did, username, email, encrypted_private_key, balance_cents, password_hash, referred_by) VALUES (?, ?, ?, ?, 100000, ?, ?)")
    .run(id.did, u, u + "@dustforge.com", id.encrypted_private_key || id.encryptedPrivateKey, h, u === "member" ? dids.referrer : "");
  db.prepare("INSERT INTO identity_transactions (did, amount_cents, type, description, balance_after) VALUES (?, 100000, ?, ?, 100000)").run(id.did, "test_grant", "smoke");
}'
TOK=$(curl -s -X POST "$API/api/identity/auth-fingerprint" -H 'content-type: application/json' \
  -d '{"username":"member","password":"hunter22","scope":"transact","expires_in":"1h"}' | python3 -c 'import json,sys; print(json.load(sys.stdin).get("token",""))')
[ -n "$TOK" ] || { echo "FAIL member sign-in"; exit 1; }

codes=$(for i in $(seq 1 250); do curl -s -o /dev/null -w "%{http_code}\n" -X POST "$API/api/tick" -H "authorization: Bearer $TOK" -H 'content-type: application/json' -d '{"note":"smoke"}'; done | sort | uniq -c | tr -s ' ')
[ "$codes" = " 250 200" ] && ok "250 member ticks accepted" || fail "tick codes: $codes"

MB=$(Q "SELECT balance_cents FROM identity_wallets WHERE username='member'")
RB=$(Q "SELECT balance_cents FROM identity_wallets WHERE username='referrer'")
[ "$MB" = 99980 ] && ok "member paid 20 DD for 250 ticks (10 DD per 100, 50 pending)" || fail "member balance $MB"
[ "$RB" = 100002 ] && ok "referrer earned 2 DD — 10% of the 20 DD fee" || fail "referrer balance $RB"
[ "$(Q "SELECT accumulated FROM referral_accumulators")" = 50 ] && ok "the 0.5 DD remainder is carried (50 hundredths)" || fail "accumulator $(Q "SELECT accumulated FROM referral_accumulators")"
[ "$(Q "SELECT COUNT(*) FROM identity_transactions WHERE type='tick_referral_share'")" = 2 ] && ok "two 1 DD payouts" || fail "payout rows"
paid=$(( 100000 - MB )); earned=$(( RB - 100000 ))
[ $earned -le $paid ] && ok "share ($earned DD) never exceeds the fee paid ($paid DD)" || fail "mint: earned $earned > paid $paid"

curl -s -o /dev/null -X POST "$API/api/tick" -H 'content-type: application/json' -d '{"note":"anon"}'
[ "$(Q "SELECT balance_cents FROM identity_wallets WHERE username='referrer'")" = 100002 ] && ok "an anonymous tick earns no share" || fail "anon share"

[ $fails -gt 0 ] && { echo "--- server.log"; grep -v "^\[dd\]" "$S/server.log" | grep -m3 -i -E "error|constraint"; }
echo "$fails failure(s)"; exit $(( fails > 0 ))
