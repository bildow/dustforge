#!/bin/bash
# Renew token (silicon_renew.js, Aaron 2026-11-12), on a throwaway DB. Legacy fixture first: main's server makes the
# database (wallets without the delivery-key columns, a fleet, agents, and a token the owner minted for @claude there);
# this branch's server then opens it.
#   - only the fleet owner's own session renews: an agent's token is refused, another wallet's fleet is 404, a silicon
#     not in the fleet 404, a network-joined agent 403, an admin scope 400;
#   - no delivery key → 409 before any PIN; the PIN (silicon-renew:<id>) is required;
#   - after `token-pickup.js --init` (with the agent's main-era token), the renewal answers {ok, delivery_id,
#     expires_at} and never the token; the pickup opens it to a live token for @claude's DID with the right scope and
#     expiry, written 0600; the listing is unauthenticated, non-consuming, the newest 3, rate-limited, and drops a
#     revoked token;
#   - neither any answer, the pickup's output, the server log, the security events nor the database file holds the token;
#   - the card's token status is 'expiring' with hours_left under 24 h;
#   - with a linked phone: a locked app renews nothing, and the phone signs "renew <fleet>/<handle>:<scope>:<expiry> to key <fp>".
# No network beyond 127.0.0.1.
set -u
W=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
S=$(mktemp -d /tmp/dustforge-renew-smoke.XXXXXX)
PORT=${PORT:-3817}; API=http://127.0.0.1:$PORT
NM=/home/flimflam/project/dustforge/node_modules; [ -d "$W/node_modules" ] && NM=$W/node_modules
export NODE_PATH=$NM
export IDENTITY_MASTER_KEY=$(python3 -c 'import secrets;print(secrets.token_hex(32))') DB_PATH=$S/dustforge.db PORT \
  STALWART_HOST=127.0.0.1 STALWART_PORT=1 SMTP_RELAY_HOST= SMTP_HOST=127.0.0.1 SMTP_PORT=9
SRV=; trap 'kill $SRV 2>/dev/null; [ -n "${KEEP:-}" ] || rm -rf "$S"' EXIT
start(){ ( cd "$1" && exec node server.js >"$S/server-$2.log" 2>&1 ) & SRV=$!
  for i in $(seq 1 60); do curl -s -o /dev/null "$API/" && break; sleep 0.5; done
  kill -0 $SRV 2>/dev/null || { echo "server ($2) died:"; tail -5 "$S/server-$2.log"; exit 1; }; }
stop(){ kill $SRV 2>/dev/null; wait $SRV 2>/dev/null; SRV=; }
fails=0; ok(){ echo "ok   $*"; }; fail(){ echo "FAIL $*"; fails=$((fails+1)); }
J(){ python3 -c 'import json,sys; d=json.load(sys.stdin); v=d
for k in sys.argv[1].split("."):
    v = v[int(k)] if isinstance(v, list) else (v or {}).get(k)
print(v)' "$1"; }
Q(){ python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); r=c.execute(sys.argv[2]).fetchone(); print(r[0] if r and r[0] is not None else '')" "$DB_PATH" "$1"; }
X(){ python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute(sys.argv[2]); c.commit()" "$DB_PATH" "$1"; }
# Every answer is kept (0600) so the end can check that none of them holds the renewed token.
umask 077; : > "$S/answers"
call(){ local m=$1 p=$2 t=$3 b=${4:-}
  BODY=$(curl -s -o - -w '\n%{http_code}' -X "$m" "$API$p" -H 'Content-Type: application/json' ${t:+-H "Authorization: Bearer $t"} ${b:+-d "$b"})
  CODE=${BODY##*$'\n'}; BODY=${BODY%$'\n'*}; printf '%s\n' "$BODY" >> "$S/answers"; }
login(){ call POST /api/identity/auth-fingerprint "" '{"username":"'$1'","password":"hunter22","scope":"transact","expires_in":"1h"}'; echo "$BODY" | J token; }
PICKUP(){ DEMIPASS_URL=$API node "$W/bin/token-pickup.js" "$@" 2>&1 | tee -a "$S/answers"; return ${PIPESTATUS[0]}; }

# ── legacy: main's server makes the database ──
mkdir -p "$S/old"; git -C "$W" archive origin/main | tar -x -C "$S/old"
start "$S/old" old
H=$(printf '%s' hunter22 | sha256sum | cut -d' ' -f1)
( cd "$S/old" && node -e '
const identity = require("./identity"); const Database = require("better-sqlite3"); const db = new Database(process.env.DB_PATH);
for (const c of ["idempotency_key TEXT", "provenance TEXT DEFAULT '"'"'organic'"'"'"]) { try { db.exec("ALTER TABLE identity_transactions ADD COLUMN " + c); } catch (_) {} }
for (const u of ["owner-a", "outsider-x", "claude", "netjoin", "brief", "stranger"]) { const id = identity.createIdentity(); const enc = id.encrypted_private_key || id.encryptedPrivateKey;
  db.prepare("INSERT INTO identity_wallets (did, username, email, encrypted_private_key, balance_cents, password_hash) VALUES (?, ?, ?, ?, 100000, ?)").run(id.did, u, u + "@dustforge.com", enc, process.argv[1]);
  db.prepare("INSERT INTO identity_transactions (did, amount_cents, type, description, balance_after) VALUES (?, 100000, ?, ?, 100000)").run(id.did, "topup", "smoke"); }' "$H" )
A=$(login owner-a); O=$(login outsider-x)
call POST /api/identity/pin "$A" '{"pin":"4321","password":"hunter22"}'
call POST /api/fleet/create "$A" '{"name":"Aaron Agents","slug":"aaron-agents"}'; [ "$CODE" = 200 ] || fail "fleet create: $CODE $BODY"
call POST /api/fleet/create "$O" '{"name":"Other","slug":"other-fleet"}'; [ "$CODE" = 200 ] || fail "other fleet create: $CODE $BODY"
( cd "$S/old" && node -e '
const Database = require("better-sqlite3"); const db = new Database(process.env.DB_PATH); const fb = require("./fleet_billing");
const fid = db.prepare("SELECT id FROM fleets WHERE slug = ?").get("aaron-agents").id;
const did = u => db.prepare("SELECT did FROM identity_wallets WHERE username = ?").get(u).did;
for (const h of ["claude", "netjoin", "brief"]) { fb.upsertSilicon(db, { fleetId: fid, memberDid: did(h), handle: h }); db.prepare("UPDATE fleet_silicons SET created_by_fleet = 1 WHERE handle = ?").run(h); }
db.prepare("UPDATE fleet_silicons SET joined_via = ? WHERE handle = ?").run("network", "netjoin");' )
# @claude's token, minted by the owner on main (what the agent holds today): kept in a 0600 file, never echoed.
call POST /api/fleet/aaron-agents/silicons/claude/token "$A" '{"scope":"transact","expires_in":"7d"}'
echo "$BODY" | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])' > "$S/claude-old.tok"
stop
[ -s "$S/claude-old.tok" ] && [ -z "$(Q "SELECT name FROM pragma_table_info('identity_wallets') WHERE name='delivery_public_key'")" ] \
  && [ -z "$(Q "SELECT name FROM sqlite_master WHERE name='token_deliveries'")" ] && ok "legacy: main's server made the wallets (no delivery-key column), the fleet and @claude's token" || fail "legacy setup"

# ── this branch on the same database ──
start "$W" new
[ "$(Q "SELECT COUNT(*) FROM pragma_table_info('identity_wallets') WHERE name IN ('delivery_public_key','delivery_key_set_at')")" = 2 ] \
  && [ "$(Q "SELECT name FROM sqlite_master WHERE name='token_deliveries'")" = token_deliveries ] && ok "the delivery-key columns and token_deliveries are added to the legacy database" || fail "migration"
A=$(login owner-a); O=$(login outsider-x)
CT=$(cat "$S/claude-old.tok")
call GET /api/demipass/list "$CT"; [ "$CODE" = 200 ] && ok "the main-era agent token still works" || fail "legacy token: $CODE $BODY"
SID=$(Q "SELECT id FROM fleet_silicons WHERE handle='claude'")
CDID=$(Q "SELECT did FROM identity_wallets WHERE username='claude'")
R=/api/fleet/aaron-agents/silicons/claude/renew-token
PIN(){ call POST /api/identity/gate/verify "$A" '{"gate":"pin","pin":"4321","intent":"'$1'"}'; }

# ── who may renew ──
call POST $R "" '{}'; [ "$CODE" = 401 ] && ok "no session → 401" || fail "anon: $CODE"
call POST $R "$CT" '{}'; [ "$CODE" = 403 ] && ok "the agent's own (fleet-minted) session is refused" || fail "agent session: $CODE $BODY"
call POST $R "$O" '{}'; [ "$CODE" = 404 ] && ok "another wallet: the fleet is 404 to it" || fail "outsider: $CODE $BODY"
call POST /api/fleet/other-fleet/silicons/claude/renew-token "$A" '{}'; [ "$CODE" = 404 ] && ok "a fleet the caller does not own → 404" || fail "wrong fleet: $CODE $BODY"
call POST /api/fleet/aaron-agents/silicons/stranger/renew-token "$A" '{}'; [ "$CODE" = 404 ] && ok "a wallet not in the fleet → 404" || fail "not in fleet: $CODE"
call POST /api/fleet/aaron-agents/silicons/netjoin/renew-token "$A" '{}'; [ "$CODE" = 403 ] && ok "a network-joined agent keeps its own key → 403" || fail "network: $CODE"
call POST $R "$A" '{"scope":"admin"}'; [ "$CODE" = 400 ] && ok "admin scope → 400 (capped at transact)" || fail "admin: $CODE"
call POST $R "$A" '{"expires_in":"10m"}'; [ "$CODE" = 400 ] && ok "under an hour → 400" || fail "10m: $CODE"
call POST $R "$A" '{}'
[ "$CODE" = 409 ] && [ "$(echo "$BODY" | J no_delivery_key)" = True ] && echo "$BODY" | grep -q 'token-pickup.js --init' && ok "no delivery key → 409 with what to do, before any PIN" || fail "no key: $CODE $BODY"

# ── the agent registers its delivery key with its own (main-era) token ──
call POST /api/identity/delivery-key "$CT" '{"public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}'; [ "$CODE" = 400 ] && ok "a low-order (all-zero) key is refused" || fail "zero key: $CODE"
call POST /api/identity/delivery-key "" '{"public_key":"x"}'; [ "$CODE" = 401 ] && ok "registering needs a session" || fail "anon key: $CODE"
OUT=$(DEMIPASS_TOKEN_FILE="$S/claude-old.tok" PICKUP --init "$S/agent"); RC=$?
[ $RC = 0 ] && [ "$(stat -c %a "$S/agent/delivery.key")" = 600 ] && [ "$(cat "$S/agent/did")" = "$CDID" ] && ok "--init: keypair made (private key 0600), public key registered for @claude's DID" || fail "init: $RC $OUT"
echo "$OUT" | grep -q "PRIVATE" && fail "--init printed the private key" || ok "--init prints no key"
[ -n "$(Q "SELECT delivery_public_key FROM identity_wallets WHERE username='claude'")" ] || fail "key not stored"

# ── the PIN, then the renewal ──
call POST $R "$A" '{}'
[ "$CODE" = 403 ] && [ "$(echo "$BODY" | J intent)" = "silicon-renew:$SID" ] && ok "renewing needs the PIN (intent silicon-renew:$SID)" || fail "no pin: $CODE $BODY"
PIN "silicon-renew:999"; call POST $R "$A" '{}'; [ "$CODE" = 403 ] && ok "a PIN for another agent's renewal does not open this one" || fail "wrong intent: $CODE"
T0=$(date +%s)
PIN "silicon-renew:$SID"; call POST $R "$A" '{}'
DID1=$(echo "$BODY" | J delivery_id); EXP1=$(echo "$BODY" | J expires_at)
[ "$CODE" = 200 ] && [ "$(echo "$BODY" | J ok)" = True ] && [ "$DID1" != None ] && [ "$EXP1" != None ] && ok "renewed with the PIN: {ok, delivery_id, expires_at}" || fail "renew: $CODE $BODY"
echo "$BODY" | python3 -c 'import json,sys; d=json.load(sys.stdin); sys.exit(1 if "token" in d or any(isinstance(v,str) and v.count(".")==2 and len(v)>100 for v in d.values()) else 0)' \
  && ok "the answer has no token field and no JWT" || fail "answer carries a token: $(echo "$BODY" | head -c 80)"
call POST $R "$A" '{}'; [ "$CODE" = 403 ] && ok "the PIN proof is spent: a second renewal asks again" || fail "replay: $CODE"
[ "$(Q "SELECT event_type FROM demipass_security_events WHERE event_type='silicon_token_renewed' ORDER BY id DESC LIMIT 1")" = silicon_token_renewed ] && ok "a security event is logged" || fail "no event"

# ── the pickup ──
call GET "/api/identity/token-deliveries?did=$CDID" ""; N1=$(echo "$BODY" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["deliveries"]))')
call GET "/api/identity/token-deliveries?did=$CDID" ""; N2=$(echo "$BODY" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["deliveries"]))')
[ "$N1" = 1 ] && [ "$N2" = 1 ] && [ "$(echo "$BODY" | J deliveries.0.sealed.alg)" = X25519-HKDF-SHA256-A256GCM ] && ok "listing needs no session and consumes nothing (sealed blobs only)" || fail "listing: $N1 $N2 $BODY"
call GET "/api/identity/token-deliveries?did=nope" ""; [ "$CODE" = 400 ] && ok "a malformed did → 400" || fail "bad did: $CODE"
OUT=$(PICKUP "$S/agent"); RC=$?
[ $RC = 0 ] && [ "$(stat -c %a "$S/agent/token")" = 600 ] && ok "pickup wrote <dir>/token (0600): $OUT" || fail "pickup: $RC $OUT"
NT=$(cat "$S/agent/token")
python3 - "$NT" "$CDID" "$T0" "$EXP1" <<'PY' && ok "the token is @claude's: transact, 30 days, fleet_owner_mint, expiry as answered" || fail "claims"
import sys, json, base64, datetime
tok, did, t0, exp1 = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
p = tok.split(".")[1]; p += "=" * (-len(p) % 4); c = json.loads(base64.urlsafe_b64decode(p))
want = t0 + 30 * 86400
e = datetime.datetime.fromisoformat(exp1.replace("Z", "+00:00")).timestamp()
sys.exit(0 if c["sub"] == did and c["scope"] == "transact" and abs(c["exp"] - want) < 120 and int(e) == c["exp"] and c.get("auth_method") == "fleet_owner_mint" else 1)
PY
call GET /api/demipass/list "$NT"; [ "$CODE" = 200 ] && ok "…and it works as @claude" || fail "use: $CODE"
call POST /api/fleet/aaron-agents/silicons/claude/renew-token "$NT" '{}'; [ "$CODE" = 403 ] && ok "…but cannot renew itself (agent session)" || fail "self renew: $CODE"
OUT=$(PICKUP "$S/agent"); echo "$OUT" | grep -q "already holds" && ok "a second pickup leaves the same token in place" || fail "re-pickup: $OUT"

# ── nobody else ever saw it ──
grep -qF "$NT" "$S/answers" && fail "an answer or the pickup's output held the token" || ok "no answer and no pickup output holds the token"
grep -qF "$NT" "$S"/server-*.log && fail "the server log holds the token" || ok "the server log does not hold the token"
grep -qaF "$NT" "$DB_PATH"* && fail "the database holds the token in clear" || ok "the database never holds the token in clear (sealed only)"
[ -z "$(Q "SELECT id FROM demipass_security_events WHERE context_json LIKE '%$(echo "$NT" | cut -d. -f3 | head -c 30)%'")" ] && ok "nor do the security events" || fail "event holds it"

# ── scope and lifetime caps, newest few, revocation ──
PIN "silicon-renew:$SID"; call POST $R "$A" '{"expires_in":"9999d"}'
[ "$CODE" = 200 ] && [ "$(echo "$BODY" | J expires_in)" = 30d ] && ok "9999d asked: capped at the transact ceiling (30d)" || fail "cap: $CODE $BODY"
PIN "silicon-renew:$SID"; call POST $R "$A" '{"scope":"read","expires_in":"2h"}'
[ "$CODE" = 200 ] && [ "$(echo "$BODY" | J scope)" = read ] && ok "a lower scope can be asked for" || fail "read: $CODE $BODY"
PIN "silicon-renew:$SID"; call POST $R "$A" '{"expires_in":"3h"}'; LAST=$(echo "$BODY" | J delivery_id)
call GET "/api/identity/token-deliveries?did=$CDID" ""
[ "$(echo "$BODY" | python3 -c 'import json,sys; d=json.load(sys.stdin)["deliveries"]; print(len(d), d[0]["id"])')" = "3 $LAST" ] && ok "the listing gives the newest 3, newest first" || fail "newest: $BODY"
X "UPDATE issued_tokens SET revoked = 1 WHERE jti = (SELECT token_jti FROM token_deliveries WHERE id = $LAST)"
call GET "/api/identity/token-deliveries?did=$CDID" ""; [ "$(echo "$BODY" | J deliveries.0.id)" != "$LAST" ] && ok "a revoked token is no longer handed out" || fail "revoked listed: $BODY"
X "UPDATE token_deliveries SET expires_at = '2000-01-01T00:00:00.000Z' WHERE id = $DID1"
call GET "/api/identity/token-deliveries?did=$CDID" ""; [ -z "$(Q "SELECT id FROM token_deliveries WHERE id = $DID1")" ] && ok "a delivery ends with its token (purged)" || fail "expired kept"

# ── the card: under 24 h is 'expiring', in hours ──
call POST /api/fleet/aaron-agents/silicons/brief/token "$A" '{"scope":"transact","expires_in":"5h"}'
call GET /api/fleet/aaron-agents/overview "$A"
echo "$BODY" | python3 -c '
import json,sys; d=json.load(sys.stdin); s=[x for x in d["silicons"] if x["handle"]=="brief"][0]["token"]; c=[x for x in d["silicons"] if x["handle"]=="claude"][0]
sys.exit(0 if s["status"]=="expiring" and 4.8 < s["hours_left"] <= 5 and s["days_left"] == 0.2 and c["delivery_key"]["set"] is True else 1)' \
  && ok "the card: 5 h left is expiring, hours_left ≈ 5; @claude's card shows its delivery key" || fail "card: $(echo "$BODY" | head -c 300)"
grep -qF "$NT" "$S/answers" && fail "the overview held the token" || true

# ── with a linked phone, the renewal also takes its device signature over what is decided ──
node -e '
const c = require("crypto"), fs = require("fs");
for (const n of ["d", "p"]) { const { privateKey, publicKey } = c.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  fs.writeFileSync(process.argv[1] + "/" + n + ".pem", privateKey.export({ type: "pkcs8", format: "pem" }));
  fs.writeFileSync(process.argv[1] + "/" + n + ".pub", publicKey.export({ type: "spki", format: "der" }).toString("base64")); }' "$S"
sig(){ node -e 'const c=require("crypto"),fs=require("fs"); process.stdout.write(c.sign("sha256", Buffer.from(process.argv[2]), fs.readFileSync(process.argv[1])).toString("base64"))' "$S/$1.pem" "$2"; }
call POST /api/identity/device/challenge "$A" '{"purpose":"enrol","intent":"device-enrol:0"}'; CHD=$(echo "$BODY" | J challenge_id); M="$(echo "$BODY" | J message):phone-0001"
PIN device-enrol:0; call POST /api/identity/gate/verify "$A" '{"gate":"password","password":"hunter22"}'
call POST /api/identity/device/enrol "$A" "$(printf '{"challenge_id":%s,"device_id":"phone-0001","label":"Pixel","key_d":"%s","key_p":"%s","sig_d":"%s","sig_p":"%s"}' "$CHD" "$(cat $S/d.pub)" "$(cat $S/p.pub)" "$(sig d "$M")" "$(sig p "$M")")"
[ "$CODE" = 201 ] || fail "enrol: $CODE $BODY"
PIN "silicon-renew:$SID"; call POST $R "$A" '{}'; [ "$CODE" = 423 ] && ok "phone linked: a locked app renews nothing (423)" || fail "locked: $CODE $BODY"
PIN unlock:0; call POST $R "$A" '{}'
FP=$(Q "SELECT key_fingerprint FROM token_deliveries ORDER BY id DESC LIMIT 1")
[ "$CODE" = 428 ] && [ "$(echo "$BODY" | J challenge.bind)" = "renew aaron-agents/claude:transact:30d to key $FP" ] && [ "$(echo "$BODY" | J challenge.intent)" = "silicon-renew:$SID" ] \
  && ok "…unlocked, it needs the phone to sign \"renew aaron-agents/claude:transact:30d to key $FP\"" || fail "428: $CODE $BODY"
call POST /api/identity/device/challenge "$A" '{"purpose":"approve","intent":"silicon-renew:'$SID'","bind":"renew aaron-agents/claude:transact:7d to key '$FP'"}'
CH=$(echo "$BODY" | J challenge_id); SG=$(sig d "$(echo "$BODY" | J message)")
call POST $R "$A" '{"device_challenge_id":'$CH',"device_signature":"'$SG'"}'; [ "$CODE" = 409 ] && ok "a signature over another lifetime (7d) does not renew 30d" || fail "bind mismatch: $CODE $BODY"
call POST /api/identity/device/challenge "$A" '{"purpose":"approve","intent":"silicon-renew:'$SID'","bind":"renew aaron-agents/claude:transact:30d to key '$FP'"}'
CH=$(echo "$BODY" | J challenge_id); SG=$(sig d "$(echo "$BODY" | J message)")
call POST $R "$A" '{"device_challenge_id":'$CH',"device_signature":"'$SG'"}'; [ "$CODE" = 200 ] && ok "signed by the linked phone (and the PIN): renewed" || fail "signed renew: $CODE $BODY"

# ── the pickup listing is rate-limited (60 / 15 min per address) ──
for i in $(seq 1 70); do C=$(curl -s -o /dev/null -w '%{http_code}' "$API/api/identity/token-deliveries?did=$CDID"); [ "$C" = 429 ] && break; done
[ "$C" = 429 ] && ok "the unauthenticated listing is rate-limited (429)" || fail "no rate limit: $C"

[ $fails -gt 0 ] && { echo "--- server.log"; grep -i -m5 "error" "$S/server-new.log"; }
echo "$fails failure(s)"; exit $(( fails > 0 ))
