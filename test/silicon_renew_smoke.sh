#!/bin/bash
# Renew token (silicon_renew.js, Aaron 2026-11-12; PR #100 review round 2), on a throwaway DB. Legacy fixture first:
# main's server makes the database (wallets and fleet_silicons without the new columns, no delivery tables, a fleet,
# agents, @claude's own sign-in token and an owner-minted "shown" token); this branch's server then opens it.
#   - only the fleet owner's own session renews: an agent's token, the owner's own device login (agent_label) are
#     refused; another wallet's fleet is 404, a silicon not in the fleet 404, network-joined 403, admin scope 400;
#   - no delivery key → 409 before any PIN; the PIN (silicon-renew:<id>) is required and spent once;
#   - delivery key (review rounds 2-3): a token someone other than the agent saw (the owner's mint, main-era or new; a
#     request a sibling filed, or the owner filed without a claim_secret_hash) cannot ask for one, and the refusal names
#     the way in; EVERY key — the first too — waits for the owner's PIN (silicon-key:<id>) + phone, except a first key
#     asked with the agent's own token request (filed by itself, or by the owner with its claim_secret_hash); one ask
#     waits at a time (another → 429), one mail per 3 h; the card shows who asked (token kind, address); an ask whose
#     token is revoked (jti, revoke-all) cannot be approved; an approved change can be undone for 6 h (PIN
#     silicon-key-revert:<id> + phone), revoking what the dropped key received; legacy round-1/2 tables get their columns;
#   - after a renewal: {ok, delivery_id (random), expires_at}, never the token; the public listing gives only
#     {id, epk, iv, tag, ciphertext} (M3); the pickup opens it to a live, correctly signed token for @claude's DID with
#     the right scope and expiry, written 0600, and acknowledges it; a forged token sealed to the key is refused (L1);
#   - the card says "awaiting pickup" (old token's status) until the pickup or the token's first use (M1);
#   - the pickup never replaces a newer token nor narrows the scope without --allow-narrower: either way the delivery
#     is declined (revoked) and the card says so; a group-readable token file is tightened and replaced;
#   - the listing drops a revoked token, also by the revoke-all cut with no issued_tokens row (L6), ends with the token,
#     is rate-limited per address+DID (another DID still answers) (L3);
#   - neither any answer, the pickup's output, the server log, the security events nor the database file holds a
#     delivered token;
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
# Every answer is kept (0600) so the end can check that none of them holds a delivered token.
umask 077; : > "$S/answers"; : > "$S/delivered"
call(){ local m=$1 p=$2 t=$3 b=${4:-}
  BODY=$(curl -s -o - -w '\n%{http_code}' -X "$m" "$API$p" -H 'Content-Type: application/json' ${t:+-H "Authorization: Bearer $t"} ${b:+-d "$b"})
  CODE=${BODY##*$'\n'}; BODY=${BODY%$'\n'*}; printf '%s\n' "$BODY" >> "$S/answers"; }
login(){ call POST /api/identity/auth-fingerprint "" '{"username":"'$1'","password":"hunter22","scope":"transact","expires_in":"'${2:-1h}'"}'; echo "$BODY" | J token; }
PICKUP(){ DEMIPASS_URL=$API node "$W/bin/token-pickup.js" "$@" 2>&1 | tee -a "$S/answers"; return ${PIPESTATUS[0]}; }
keep(){ cat "$1" >> "$S/delivered"; }   # a delivered token, for the leak checks at the end (0600 file)
claims(){ python3 -c 'import sys,json,base64; p=open(sys.argv[1]).read().strip().split(".")[1]; p+="="*(-len(p)%4); c=json.loads(base64.urlsafe_b64decode(p)); print(c.get(sys.argv[2]))' "$1" "$2"; }

# ── legacy: main's server makes the database ──
mkdir -p "$S/old"; git -C "$W" archive origin/main | tar -x -C "$S/old"
start "$S/old" old
H=$(printf '%s' hunter22 | sha256sum | cut -d' ' -f1)
( cd "$S/old" && node -e '
const identity = require("./identity"); const Database = require("better-sqlite3"); const db = new Database(process.env.DB_PATH);
for (const c of ["idempotency_key TEXT", "provenance TEXT DEFAULT '"'"'organic'"'"'"]) { try { db.exec("ALTER TABLE identity_transactions ADD COLUMN " + c); } catch (_) {} }
for (const u of ["owner-a", "outsider-x", "claude", "netjoin", "brief", "stranger", "carl", "bot2"]) { const id = identity.createIdentity(); const enc = id.encrypted_private_key || id.encryptedPrivateKey;
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
for (const h of ["claude", "netjoin", "brief", "carl", "bot2"]) { fb.upsertSilicon(db, { fleetId: fid, memberDid: did(h), handle: h }); db.prepare("UPDATE fleet_silicons SET created_by_fleet = 1 WHERE handle = ?").run(h); }
db.prepare("UPDATE fleet_silicons SET joined_via = ? WHERE handle = ?").run("network", "netjoin");' )
# @claude's tokens on main, kept in 0600 files, never echoed: its own sign-in, and one the owner minted on the subpage
# ("Mint a 30-day token": its value was shown on the owner's screen).
login claude 7d > "$S/claude-own.tok"
call POST /api/fleet/aaron-agents/silicons/claude/token "$A" '{"scope":"transact","expires_in":"7d"}'
echo "$BODY" | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])' > "$S/claude-shown.tok"
# Tables as round 1 / round 2 of this branch made them (never deployed; review round 3 L4): the new server adds columns.
X "CREATE TABLE token_deliveries (id INTEGER PRIMARY KEY AUTOINCREMENT, did TEXT NOT NULL, fleet_id INTEGER NOT NULL, silicon_row INTEGER NOT NULL, owner_did TEXT NOT NULL, scope TEXT NOT NULL, token_jti TEXT NOT NULL, key_fingerprint TEXT NOT NULL, epk TEXT NOT NULL, iv TEXT NOT NULL, tag TEXT NOT NULL, ciphertext TEXT NOT NULL, created_at TEXT NOT NULL, expires_at TEXT NOT NULL)"
X "INSERT INTO token_deliveries (did, fleet_id, silicon_row, owner_did, scope, token_jti, key_fingerprint, epk, iv, tag, ciphertext, created_at, expires_at) VALUES ('did:key:zLegacyRow', 0, 0, 'x', 'transact', 'legacyjti', 'x', 'x', 'x', 'x', 'x', '2026-01-01T00:00:00.000Z', '2099-01-01T00:00:00.000Z')"
X "CREATE TABLE delivery_key_changes (id INTEGER PRIMARY KEY AUTOINCREMENT, did TEXT NOT NULL, public_key TEXT NOT NULL, fingerprint TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending', auth_method TEXT DEFAULT '', ip TEXT DEFAULT '', requested_at TEXT NOT NULL, expires_at TEXT NOT NULL, decided_at TEXT DEFAULT NULL, decided_by TEXT DEFAULT NULL)"
stop
[ -s "$S/claude-own.tok" ] && [ -s "$S/claude-shown.tok" ] && [ -z "$(Q "SELECT name FROM pragma_table_info('identity_wallets') WHERE name='delivery_public_key'")" ] \
  && [ -z "$(Q "SELECT name FROM pragma_table_info('token_deliveries') WHERE name='pub_id'")" ] && [ -z "$(Q "SELECT name FROM pragma_table_info('silicon_token_requests') WHERE name='claim_hash_given'")" ] \
  && [ -z "$(Q "SELECT name FROM pragma_table_info('fleet_silicons') WHERE name='token_owner_warned_jti'")" ] && ok "legacy: main's server made the wallets, the fleet, @claude's own and shown tokens (no new columns; round-1/2 shaped tables)" || fail "legacy setup"

# ── this branch on the same database ──
start "$W" new
[ "$(Q "SELECT COUNT(*) FROM pragma_table_info('identity_wallets') WHERE name IN ('delivery_public_key','delivery_key_set_at','delivery_key_changed_at')")" = 3 ] \
  && [ "$(Q "SELECT COUNT(*) FROM sqlite_master WHERE name IN ('token_deliveries','delivery_key_changes')")" = 2 ] \
  && [ "$(Q "SELECT COUNT(*) FROM pragma_table_info('fleet_silicons') WHERE name='token_owner_warned_jti'")" = 1 ] \
  && [ "$(Q "SELECT COUNT(*) FROM pragma_table_info('identity_wallets') WHERE name IN ('delivery_key_previous','delivery_key_previous_until')")" = 2 ] \
  && [ "$(Q "SELECT COUNT(*) FROM pragma_table_info('silicon_token_requests') WHERE name='claim_hash_given'")" = 1 ] && ok "the new columns and tables are added to the legacy database" || fail "migration"
[ "$(Q "SELECT COUNT(*) FROM pragma_table_info('token_deliveries') WHERE name IN ('pub_id','iat','acked_at','ack')")" = 4 ] && [ -n "$(Q "SELECT pub_id FROM token_deliveries WHERE token_jti='legacyjti'")" ] \
  && [ "$(Q "SELECT COUNT(*) FROM pragma_table_info('delivery_key_changes') WHERE name IN ('ask_jti','ask_iat','ask_fleet','first_key','mailed_at')")" = 5 ] \
  && ok "round-1/2 shaped token_deliveries and delivery_key_changes get their columns; an old row gets a random id (L4)" || fail "round-1 tables"
A=$(login owner-a); O=$(login outsider-x)
CT=$(cat "$S/claude-own.tok")
call GET /api/demipass/list "$CT"; [ "$CODE" = 200 ] && ok "the main-era agent token still works" || fail "legacy token: $CODE $BODY"
SID=$(Q "SELECT id FROM fleet_silicons WHERE handle='claude'")
CDID=$(Q "SELECT did FROM identity_wallets WHERE username='claude'")
R=/api/fleet/aaron-agents/silicons/claude/renew-token
PIN(){ call POST /api/identity/gate/verify "$A" '{"gate":"pin","pin":"4321","intent":"'$1'"}'; }
RENEW(){ PIN "silicon-renew:$SID"; call POST $R "$A" "${1:-{\}}"; }
OV(){ call GET /api/fleet/aaron-agents/overview "$A"; echo "$BODY" | python3 -c 'import json,sys; d=json.load(sys.stdin); s=[x for x in d["silicons"] if x["handle"]==sys.argv[1]][0]
v=s
for k in sys.argv[2].split("."): v=(v or {}).get(k)
print(v)' "$1" "$2"; }

# ── who may renew ──
call POST $R "" '{}'; [ "$CODE" = 401 ] && ok "no session → 401" || fail "anon: $CODE"
call POST $R "$CT" '{}'; { [ "$CODE" = 403 ] || [ "$CODE" = 404 ]; } && ok "the agent's own sign-in is refused (not the fleet owner: $CODE)" || fail "agent session: $CODE $BODY"
call POST $R "$(cat "$S/claude-shown.tok")" '{}'; [ "$CODE" = 403 ] && ok "a fleet-minted agent token is refused" || fail "minted: $CODE"
DEV=$(cd "$W" && node -e '
const identity = require("./identity"); const Database = require("better-sqlite3"); const db = new Database(process.env.DB_PATH);
const w = db.prepare("SELECT * FROM identity_wallets WHERE username = ?").get("owner-a");
process.stdout.write(identity.createTokenForIdentity(w.encrypted_private_key, w.did, { scope: "transact", expiresIn: "1h", metadata: { auth_method: "device", agent_label: "some-agent", sid: "smoke-dev" } }));')
call POST $R "$DEV" '{}'; [ "$CODE" = 403 ] && ok "an agent's device login on the owner's own wallet is refused (L2)" || fail "device login: $CODE $BODY"
call POST $R "$O" '{}'; [ "$CODE" = 404 ] && ok "another wallet: the fleet is 404 to it" || fail "outsider: $CODE $BODY"
call POST /api/fleet/other-fleet/silicons/claude/renew-token "$A" '{}'; [ "$CODE" = 404 ] && ok "a fleet the caller does not own → 404" || fail "wrong fleet: $CODE $BODY"
call POST /api/fleet/aaron-agents/silicons/stranger/renew-token "$A" '{}'; [ "$CODE" = 404 ] && ok "a wallet not in the fleet → 404" || fail "not in fleet: $CODE"
call POST /api/fleet/aaron-agents/silicons/netjoin/renew-token "$A" '{}'; [ "$CODE" = 403 ] && ok "a network-joined agent keeps its own key → 403" || fail "network: $CODE"
call POST $R "$A" '{"scope":"admin"}'; [ "$CODE" = 400 ] && ok "admin scope → 400 (capped at transact)" || fail "admin: $CODE"
call POST $R "$A" '{"expires_in":"10m"}'; [ "$CODE" = 400 ] && ok "under an hour → 400" || fail "10m: $CODE"
call POST $R "$A" '{}'
[ "$CODE" = 409 ] && [ "$(echo "$BODY" | J no_delivery_key)" = True ] && echo "$BODY" | grep -q 'token-pickup.js --init' && ok "no delivery key → 409 with what to do, before any PIN" || fail "no key: $CODE $BODY"

# ── the delivery key (H1) ──
call POST /api/identity/delivery-key "$CT" '{"public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}'; [ "$CODE" = 400 ] && ok "a low-order (all-zero) key is refused" || fail "zero key: $CODE"
call POST /api/identity/delivery-key "" '{"public_key":"x"}'; [ "$CODE" = 401 ] && ok "registering needs a session" || fail "anon key: $CODE"
OUT=$(DEMIPASS_TOKEN_FILE="$S/claude-shown.tok" PICKUP --init "$S/shown"); RC=$?
[ $RC = 2 ] && echo "$OUT" | grep -q "handed to someone other than the agent" && [ -z "$(Q "SELECT delivery_public_key FROM identity_wallets WHERE username='claude'")" ] \
  && ok "a main-era owner-minted token (its value was shown) cannot register a key" || fail "shown legacy: $RC $OUT"
call POST /api/fleet/aaron-agents/silicons/claude/token "$A" '{"scope":"transact","expires_in":"1h"}'; echo "$BODY" | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])' > "$S/shown2.tok"
OUT=$(DEMIPASS_TOKEN_FILE="$S/shown2.tok" PICKUP --init "$S/shown"); RC=$?
[ $RC = 2 ] && [ "$(claims "$S/shown2.tok" shown)" = True ] && ok "…nor a new one (marked shown)" || fail "shown new: $RC $OUT"
echo "$OUT" | grep -q "claim_secret_hash" && ok "…and the refusal names the way in (an owner-filed request with the agent's claim_secret_hash) (L3)" || fail "howto: $OUT"
node "$W/bin/token-pickup.js" --help | grep -q "claim_secret_hash" && ok "token-pickup --help explains it too" || fail "--help"
# H1 (round 3): the FIRST key also waits for the owner — whoever gets there first with a live token chooses nothing.
OUT=$(DEMIPASS_TOKEN_FILE="$S/claude-own.tok" PICKUP --init "$S/agent"); RC=$?
CH0=$(Q "SELECT id FROM delivery_key_changes WHERE status='pending' AND first_key=1 ORDER BY id DESC LIMIT 1")
[ $RC = 0 ] && [ -z "$(Q "SELECT delivery_public_key FROM identity_wallets WHERE username='claude'")" ] && [ -n "$CH0" ] && echo "$OUT" | grep -q "tell them this fingerprint" \
  && [ "$(stat -c %a "$S/agent/delivery.key")" = 600 ] && [ "$(cat "$S/agent/did")" = "$CDID" ] && ok "--init with the agent's own sign-in: the first key waits for the owner (nothing pinned), private key 0600" || fail "init: $RC $OUT"
echo "$OUT" | grep -q "PRIVATE" && fail "--init printed the private key" || ok "--init prints no key"
[ "$(Q "SELECT COUNT(*) FROM delivery_key_changes WHERE id=$CH0 AND mailed_at IS NOT NULL")" = 1 ] && [ "$(OV claude delivery_key.pending.first)" = True ] && [ "$(OV claude delivery_key.set)" = False ] \
  && ok "the owner is mailed and the card shows 'key waiting for you' (first key)" || fail "first key card"
call POST $R "$A" '{}'; [ "$CODE" = 409 ] && [ -n "$(echo "$BODY" | J key_waiting | grep -v None)" ] && ok "no renewal before the owner approves a key: 409 names the waiting key" || fail "renew before approval: $CODE $BODY"
OUT=$(DEMIPASS_TOKEN_FILE="$S/claude-own.tok" PICKUP --init "$S/agent"); echo "$OUT" | grep -q "waiting for the fleet owner" && [ "$(Q "SELECT COUNT(*) FROM delivery_key_changes WHERE did='$CDID' AND status='pending'")" = 1 ] && ok "--init again: the same ask, not a second one" || fail "re-init: $OUT"
# M2: a different key while one waits → 429 (it does not replace the waiting ask, and mails nobody).
LEAK=$(login claude); printf '%s\n' "$LEAK" > "$S/leak.tok"
OUT=$(DEMIPASS_TOKEN_FILE="$S/leak.tok" PICKUP --init "$S/attacker"); RC=$?
[ $RC = 2 ] && echo "$OUT" | grep -q "(429)" && [ "$(Q "SELECT status FROM delivery_key_changes WHERE id=$CH0")" = pending ] && [ "$(Q "SELECT COUNT(*) FROM delivery_key_changes WHERE did='$CDID'")" = 1 ] \
  && ok "another key while one waits → 429: the waiting ask is neither replaced nor buried (M2)" || fail "flood: $RC $OUT"
for i in 1 2 3 4 5; do K=$(node -e 'const c=require("crypto");console.log(c.createPublicKey(c.generateKeyPairSync("x25519").privateKey).export({format:"jwk"}).x)'); call POST /api/identity/delivery-key "$LEAK" '{"public_key":"'$K'"}'; done
[ "$CODE" = 429 ] && [ "$(Q "SELECT COUNT(*) FROM delivery_key_changes WHERE did='$CDID'")" = 1 ] && [ "$(Q "SELECT COUNT(*) FROM delivery_key_changes WHERE mailed_at IS NOT NULL")" = 1 ] && ok "a flood of asks: still one ask, one mail" || fail "flood rows"
[ "$(OV claude delivery_key.pending.auth_method)" = fingerprint ] && [ -n "$(OV claude delivery_key.pending.ip | grep -v None)" ] && ok "the card shows who asked: the token kind and the address" || fail "asker on card"
call POST /api/fleet/aaron-agents/silicons/claude/delivery-key/$CH0/approve "$A" '{}'
[ "$CODE" = 403 ] && [ "$(echo "$BODY" | J intent)" = "silicon-key:$SID" ] && ok "approving the first key needs the PIN (silicon-key:$SID)" || fail "first approve no pin: $CODE $BODY"
PIN "silicon-key:$SID"; call POST /api/fleet/aaron-agents/silicons/claude/delivery-key/$CH0/approve "$A" '{}'
K1=$(Q "SELECT delivery_public_key FROM identity_wallets WHERE username='claude'")
[ "$CODE" = 200 ] && [ -n "$K1" ] && [ "$(echo "$BODY" | J first_key)" = True ] && [ "$(OV claude delivery_key.set_at)" != None ] && ok "approved with the PIN: the first key is set" || fail "first approve: $CODE $BODY"
OUT=$(DEMIPASS_TOKEN_FILE="$S/claude-own.tok" PICKUP --init "$S/agent"); echo "$OUT" | grep -q "already registered" && ok "--init again: the same key, unchanged" || fail "re-init set: $OUT"
# A copy of a live agent token (here: another of its own sign-ins) asks for its own key: pending, nothing changes.
OUT=$(DEMIPASS_TOKEN_FILE="$S/leak.tok" PICKUP --init "$S/attacker"); RC=$?
CH1=$(Q "SELECT id FROM delivery_key_changes WHERE status='pending' ORDER BY id DESC LIMIT 1")
[ $RC = 0 ] && echo "$OUT" | grep -q "waiting for the fleet owner" && [ "$(Q "SELECT delivery_public_key FROM identity_wallets WHERE username='claude'")" = "$K1" ] && [ -n "$CH1" ] \
  && ok "a different key from a copied token is only pending: the pinned key stays" || fail "replace: $RC $OUT"
[ "$(Q "SELECT severity FROM demipass_security_events WHERE event_type='delivery_key_change_asked' ORDER BY id DESC LIMIT 1")" = warn ] \
  && [ "$(Q "SELECT COUNT(*) FROM delivery_key_changes WHERE did='$CDID' AND mailed_at IS NOT NULL")" = 1 ] && ok "…logged (warn); no second mail within 3 h of the first (M2)" || fail "change event"
[ "$(OV claude delivery_key.pending.id)" = "$CH1" ] && [ "$(OV claude delivery_key.set_at)" != None ] && [ "$(OV claude delivery_key.changed_at)" = None ] && ok "the card shows the waiting change and 'key set <time>'" || fail "card pending"

# ── whose token request makes the agent's own token (M1) ──
REQ(){ call POST /api/fleet/aaron-agents/silicons/$1/token-requests "$2" "$3"; RQ=$(echo "$BODY" | J request_id); SEC=$(echo "$BODY" | J claim_secret)
  PIN "silicon-token:$RQ"; call POST /api/silicon-token-requests/$RQ/approve "$A" '{}'; [ "$CODE" = 200 ] || fail "approve request $RQ: $CODE $BODY"; }
CLAIM(){ call POST /api/silicon-token-requests/$RQ/claim "" '{"claim_secret":"'$1'"}'; echo "$BODY" | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])' > "$2"; }
B2=$(login bot2)
REQ carl "$B2" '{"label":"routine"}'; CLAIM "$SEC" "$S/carl-sib.tok"
OUT=$(DEMIPASS_TOKEN_FILE="$S/carl-sib.tok" PICKUP --init "$S/carl-sib"); RC=$?
[ $RC = 2 ] && echo "$OUT" | grep -q "403" && [ "$(claims "$S/carl-sib.tok" agent_own)" = None ] && [ -z "$(Q "SELECT id FROM delivery_key_changes WHERE did=(SELECT did FROM identity_wallets WHERE username='carl')")" ] \
  && ok "a sibling agent's request for @carl (claimed in clear by the sibling) cannot set @carl's key" || fail "sibling: $RC $OUT"
REQ carl "$A" '{}'; CLAIM "$SEC" "$S/carl-owner-clear.tok"
OUT=$(DEMIPASS_TOKEN_FILE="$S/carl-owner-clear.tok" PICKUP --init "$S/carl-clear"); RC=$?
[ $RC = 2 ] && [ "$(claims "$S/carl-owner-clear.tok" agent_own)" = None ] && ok "nor the owner's request without a claim_secret_hash (its claim secret was handed out in clear)" || fail "owner clear: $RC $OUT"
python3 -c 'import secrets;print(secrets.token_urlsafe(24))' > "$S/carl.secret"; CH_HASH=$(tr -d '\n' < "$S/carl.secret" | sha256sum | cut -d' ' -f1)
REQ carl "$A" '{"claim_secret_hash":"'$CH_HASH'"}'; CLAIM "$(cat "$S/carl.secret")" "$S/carl-own.tok"
CARL=$(Q "SELECT did FROM identity_wallets WHERE username='carl'")
OUT=$(DEMIPASS_TOKEN_FILE="$S/carl-own.tok" PICKUP --init "$S/carl"); RC=$?
CHL=$(Q "SELECT id FROM delivery_key_changes WHERE did='$CARL' AND status='pending'")
[ $RC = 0 ] && [ "$(claims "$S/carl-own.tok" agent_own)" = True ] && echo "$OUT" | grep -q "waiting for the fleet owner" && [ -z "$(Q "SELECT delivery_public_key FROM identity_wallets WHERE did='$CARL'")" ] && [ -n "$CHL" ] \
  && ok "the owner's request with the agent's claim_secret_hash is the agent's own (it may ask), but its first key still waits for the owner (round 4 H1)" || fail "owner hash: $RC $OUT"
# Round-4 H1 attack: a leaked copy of carl's sign-in files a request "for itself" with the attacker's hash; the owner approves it.
LEAKC=$(login carl); printf '%s' attacker-secret-456 > "$S/att.secret"; AH=$(printf '%s' attacker-secret-456 | sha256sum | cut -d' ' -f1)
REQ carl "$LEAKC" '{"claim_secret_hash":"'$AH'","label":"claude pickup"}'; CLAIM attacker-secret-456 "$S/carl-att.tok"
OUT=$(DEMIPASS_TOKEN_FILE="$S/carl-att.tok" PICKUP --init "$S/carl-att"); RC=$?
[ $RC = 2 ] && echo "$OUT" | grep -q "(429)" && [ "$(Q "SELECT status FROM delivery_key_changes WHERE id=$CHL")" = pending ] && [ -z "$(Q "SELECT delivery_public_key FROM identity_wallets WHERE did='$CARL'")" ] \
  && ok "a self-filed request's token (agent_own) sets no key: it queues behind the waiting ask (429); the real ask is not superseded" || fail "self-request attack: $RC $OUT"
# A key travels IN a request only with its fingerprint on the owner's card/phone; claimed, it supersedes a waiting ask — loudly.
OUT=$(DEMIPASS_TOKEN="$LEAKC" PICKUP --request "$S/carl-att2" aaron-agents carl); RQ=$(cat "$S/carl-att2/request" 2>/dev/null); AFP=$(echo "$OUT" | sed -n 's/.*with key \([0-9a-f]*\).*/\1/p')
call GET /api/silicon-token-requests "$A"
[ -n "$AFP" ] && [ "$(echo "$BODY" | python3 -c 'import json,sys; print([r for r in json.load(sys.stdin)["requests"] if r["id"]==int(sys.argv[1])][0].get("delivery_key_fp"))' "$RQ")" = "$AFP" ] \
  && ok "a request carrying a key shows its fingerprint to the owner" || fail "request key fp: $OUT $BODY"
PIN "silicon-token:$RQ"; call POST /api/silicon-token-requests/$RQ/approve "$A" '{}'
OUT=$(DEMIPASS_URL=$API node "$W/bin/token-pickup.js" --claim "$S/carl-att2" 2>&1 | tee -a "$S/answers")
[ "$(Q "SELECT status FROM delivery_key_changes WHERE id=$CHL")" = superseded ] && echo "$OUT" | grep -q "delivery key $AFP is set" \
  && [ -n "$(Q "SELECT id FROM demipass_security_events WHERE event_type='delivery_key_set' AND instr(context_json, '\"superseded\":[{\"id\":$CHL') > 0")" ] \
  && ok "claimed: the key the owner approved with the request is set; the waiting ask it overtook is logged (and the owner mailed), not silently dropped" || fail "claim key: $OUT"
# The way in, proper: --material on the agent, the owner files with it, the agent claims.
MAT=$(DEMIPASS_URL=$API node "$W/bin/token-pickup.js" --material "$S/brief" 2>/dev/null)
BFP=$(echo "$MAT" | J fingerprint)
REQ brief "$A" "$(echo "$MAT" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(json.dumps({"claim_secret_hash": d["claim_secret_hash"], "delivery_key": d["delivery_key"], "expires_in": "1h"}))')"
OUT=$(DEMIPASS_URL=$API node "$W/bin/token-pickup.js" --claim "$S/brief" "$RQ" 2>&1 | tee -a "$S/answers"); RC=$?
[ $RC = 0 ] && [ "$(stat -c %a "$S/brief/token")" = 600 ] && [ "$(claims "$S/brief/token" agent_own)" = True ] && [ ! -e "$S/brief/claim.secret" ] \
  && [ "$(Q "SELECT delivery_public_key FROM identity_wallets WHERE username='brief'")" != "" ] && echo "$OUT" | grep -q "delivery key $BFP is set" \
  && ok "--material + an owner-filed request + --claim: the agent's token (0600) and its key set in one owner approval" || fail "material way in: $RC $OUT"
OUT=$(DEMIPASS_TOKEN_FILE="$S/carl-own.tok" PICKUP --request "$S/carl-minted" aaron-agents carl); RC=$?
[ $RC = 2 ] && echo "$OUT" | grep -q "403" && ok "a fleet-minted token cannot file a request (--help says so)" || fail "minted files: $RC $OUT"
node "$W/bin/token-pickup.js" --help | grep -q "fleet-minted" && node "$W/bin/token-pickup.js" --help | grep -q 'carry no "agent_own" mark' && ok "--help: fleet-minted tokens cannot file; pre-change claimed tokens need a new request (L5)" || fail "--help L5"

# ── the PIN, then the renewal: it goes to the pinned key ──
call POST $R "$A" '{}'
[ "$CODE" = 403 ] && [ "$(echo "$BODY" | J intent)" = "silicon-renew:$SID" ] && ok "renewing needs the PIN (intent silicon-renew:$SID)" || fail "no pin: $CODE $BODY"
PIN "silicon-renew:999"; call POST $R "$A" '{}'; [ "$CODE" = 403 ] && ok "a PIN for another agent's renewal does not open this one" || fail "wrong intent: $CODE"
[ "$(OV claude token.status)" = valid ] || fail "own 7d token: $(OV claude token.status)"
T0=$(date +%s)
RENEW; DID1=$(echo "$BODY" | J delivery_id); EXP1=$(echo "$BODY" | J expires_at)
[ "$CODE" = 200 ] && [ "$(echo "$BODY" | J ok)" = True ] && [ "$EXP1" != None ] && ! [[ "$DID1" =~ ^[0-9]+$ ]] && [ ${#DID1} -ge 12 ] && ok "renewed with the PIN: {ok, delivery_id (random, not a counter), expires_at}" || fail "renew: $CODE $BODY"
echo "$BODY" | python3 -c 'import json,sys; d=json.load(sys.stdin); sys.exit(1 if "token" in d or any(isinstance(v,str) and v.count(".")==2 and len(v)>100 for v in d.values()) else 0)' \
  && ok "the answer has no token field and no JWT" || fail "answer carries a token: $(echo "$BODY" | head -c 80)"
call POST $R "$A" '{}'; [ "$CODE" = 403 ] && ok "the PIN proof is spent: a second renewal asks again" || fail "replay: $CODE"
[ "$(Q "SELECT event_type FROM demipass_security_events WHERE event_type='silicon_token_renewed' ORDER BY id DESC LIMIT 1")" = silicon_token_renewed ] && ok "a security event is logged" || fail "no event"
[ "$(OV claude token.awaiting_pickup.since)" != None ] && [ "$(OV claude token.status)" = valid ] && [ "$(OV claude token.days_left)" = 6.9 ] \
  && ok "the card says 'renewed, awaiting pickup' and still counts the held token (7 d), not the renewal (M1)" || fail "awaiting: $(OV claude token)"

# ── the public listing: only the sealed blob (M3) ──
call GET "/api/identity/token-deliveries?did=$CDID" ""; L1=$BODY
call GET "/api/identity/token-deliveries?did=$CDID" ""
echo "$BODY" | python3 -c 'import json,sys; d=json.load(sys.stdin)["deliveries"]; sys.exit(0 if len(d)==1 and sorted(d[0])==["ciphertext","epk","id","iv","tag"] and d[0]["id"]==sys.argv[1] else 1)' "$DID1" \
  && [ "$L1" = "$BODY" ] && ok "listing: no session, nothing consumed, and only {id, epk, iv, tag, ciphertext} — no scope, expiry or times" || fail "listing: $BODY"
call GET "/api/identity/token-deliveries?did=nope" ""; [ "$CODE" = 400 ] && ok "a malformed did → 400" || fail "bad did: $CODE"
OUT=$(PICKUP "$S/attacker"); RC=$?; [ $RC = 2 ] && [ ! -e "$S/attacker/token" ] && ok "the copied token's key cannot open the renewal" || fail "attacker: $RC $OUT"

# ── the pickup ──
OUT=$(PICKUP "$S/agent"); RC=$?
[ $RC = 0 ] && [ "$(stat -c %a "$S/agent/token")" = 600 ] && ok "pickup wrote <dir>/token (0600): $OUT" || fail "pickup: $RC $OUT"
cp "$S/agent/token" "$S/t1"; keep "$S/t1"
python3 - "$(cat "$S/t1")" "$CDID" "$T0" "$EXP1" <<'PY' && ok "the token is @claude's: transact, 30 days, fleet_owner_mint + renewed, expiry as answered" || fail "claims"
import sys, json, base64, datetime
tok, did, t0, exp1 = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
p = tok.split(".")[1]; p += "=" * (-len(p) % 4); c = json.loads(base64.urlsafe_b64decode(p))
e = datetime.datetime.fromisoformat(exp1.replace("Z", "+00:00")).timestamp()
sys.exit(0 if c["sub"] == did and c["scope"] == "transact" and abs(c["exp"] - (t0 + 30 * 86400)) < 120 and int(e) == c["exp"] and c.get("auth_method") == "fleet_owner_mint" and c.get("renewed") else 1)
PY
[ -n "$(Q "SELECT acked_at FROM token_deliveries WHERE pub_id='$DID1'")" ] && [ -z "$(Q "SELECT ciphertext FROM token_deliveries WHERE pub_id='$DID1'")" ] \
  && [ "$(OV claude token.awaiting_pickup)" = None ] && [ "$(OV claude token.days_left)" = 29.9 ] && ok "acknowledged: the card counts the renewal now, the sealed copy is emptied" || fail "ack: $(OV claude token)"
call GET "/api/identity/token-deliveries?did=$CDID" ""; [ "$(echo "$BODY" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["deliveries"]))')" = 0 ] && ok "a picked-up delivery is no longer listed" || fail "acked listed: $BODY"
call GET /api/demipass/list "$(cat "$S/t1")"; [ "$CODE" = 200 ] && ok "…and it works as @claude" || fail "use: $CODE"
call POST $R "$(cat "$S/t1")" '{}'; [ "$CODE" = 403 ] && ok "…but cannot renew itself (agent session)" || fail "self renew: $CODE"
OUT=$(PICKUP "$S/agent"); RC=$?; [ $RC = 3 ] && ok "a second pickup: nothing new" || fail "re-pickup: $RC $OUT"

# ── a forged token sealed to the agent's key is refused: the signature is checked against the did:key (L1) ──
( cd "$W" && node -e '
const c = require("crypto"), Database = require("better-sqlite3"); const db = new Database(process.env.DB_PATH);
const did = process.argv[1], w = db.prepare("SELECT delivery_public_key FROM identity_wallets WHERE did = ?").get(did);
const b = (o) => Buffer.from(JSON.stringify(o)).toString("base64url"); const now = Math.floor(Date.now() / 1000);
const forged = b({ alg: "EdDSA", typ: "JWT" }) + "." + b({ sub: did, scope: "transact", iat: now + 5, exp: now + 86400, jti: "forged" }) + "." + c.randomBytes(64).toString("base64url");
const id = c.randomBytes(12).toString("base64url"), rec = Buffer.from(w.delivery_public_key, "base64url");
const { publicKey, privateKey } = c.generateKeyPairSync("x25519"); const epk = Buffer.from(publicKey.export({ format: "jwk" }).x, "base64url");
const sh = c.diffieHellman({ privateKey, publicKey: c.createPublicKey({ key: { kty: "OKP", crv: "X25519", x: w.delivery_public_key }, format: "jwk" }) });
const key = Buffer.from(c.hkdfSync("sha256", sh, Buffer.concat([epk, rec]), Buffer.from("demipass-token-delivery-v1:" + did + ":" + id), 32));
const iv = c.randomBytes(12), ci = c.createCipheriv("aes-256-gcm", key, iv, { authTagLength: 16 }); ci.setAAD(Buffer.from(did + ":" + id));
const ct = Buffer.concat([ci.update(JSON.stringify({ v: 1, did, delivery_id: id, token: forged })), ci.final()]);
db.prepare("INSERT INTO token_deliveries (pub_id, did, fleet_id, silicon_row, owner_did, scope, token_jti, iat, key_fingerprint, epk, iv, tag, ciphertext, created_at, expires_at) VALUES (?, ?, 0, 0, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
  .run(id, did, "x", "transact", "forged", now + 5, "x", epk.toString("base64url"), iv.toString("base64url"), ci.getAuthTag().toString("base64url"), ct.toString("base64url"), new Date().toISOString(), new Date(Date.now() + 86400000).toISOString());' "$CDID" )
OUT=$(PICKUP "$S/agent"); RC=$?
[ $RC = 2 ] && echo "$OUT" | grep -q "not a live token signed for" && cmp -s "$S/agent/token" "$S/t1" && ok "a forged token sealed to the key (bad signature) is refused, the held token kept" || fail "forged: $RC $OUT"
X "DELETE FROM token_deliveries WHERE token_jti='forged'"

# ── first use acknowledges too (M1) ──
sleep 1.1; RENEW; D2=$(echo "$BODY" | J delivery_id)
OUT=$(PICKUP "$S/agent"); cp "$S/agent/token" "$S/t2"; keep "$S/t2"
X "UPDATE token_deliveries SET acked_at = NULL, ack = NULL WHERE pub_id='$D2'"
[ "$(OV claude token.awaiting_pickup.since)" != None ] || fail "un-acked for the test"
call GET /api/demipass/list "$(cat "$S/t2")"
[ "$CODE" = 200 ] && [ "$(Q "SELECT ack FROM token_deliveries WHERE pub_id='$D2'")" = used ] && [ "$(OV claude token.awaiting_pickup)" = None ] && ok "a renewed token's first use counts as picked up" || fail "use ack: $CODE $(Q "SELECT ack FROM token_deliveries WHERE pub_id='$D2'")"

# ── the pickup never replaces a newer token, nor narrows the scope unasked (M2); a loose file is tightened (L7) ──
sleep 1.1; RENEW; D3=$(echo "$BODY" | J delivery_id); J3=$(Q "SELECT token_jti FROM token_deliveries WHERE pub_id='$D3'")
sleep 1.1; login claude 2h > "$S/agent/token"   # the agent signed in itself after the renewal: a newer token
cp "$S/agent/token" "$S/newer"
OUT=$(PICKUP "$S/agent"); RC=$?
[ $RC = 0 ] && cmp -s "$S/agent/token" "$S/newer" && echo "$OUT" | grep -q "holds a newer token" && [ "$(Q "SELECT revoked FROM issued_tokens WHERE jti='$J3'")" = 1 ] && [ "$(Q "SELECT ack FROM token_deliveries WHERE pub_id='$D3'")" = declined ] \
  && ok "a newer token held is kept; the older delivery is declined and revoked (nobody holds it)" || fail "newer kept: $RC $OUT"
sleep 1.1; RENEW '{"scope":"read","expires_in":"2h"}'; [ "$CODE" = 200 ] && [ "$(echo "$BODY" | J scope)" = read ] || fail "read renew: $CODE $BODY"
D4=$(echo "$BODY" | J delivery_id)
OUT=$(PICKUP "$S/agent"); RC=$?
[ $RC = 0 ] && cmp -s "$S/agent/token" "$S/newer" && echo "$OUT" | grep -q "narrower" && ok "a read delivery does not replace the transact token held" || fail "narrower: $RC $OUT"
[ "$(Q "SELECT ack FROM token_deliveries WHERE pub_id='$D4'")" = declined ] && [ "$(OV claude token.awaiting_pickup)" = None ] && [ "$(OV claude token.renewal_declined.at)" != None ] \
  && ok "…it is declined, not left 'awaiting pickup': the card says the renewal was declined (L5)" || fail "narrow decline card: $(OV claude token)"
sleep 1.1; RENEW '{"scope":"read","expires_in":"2h"}'
chmod 640 "$S/agent/token"
OUT=$(PICKUP --allow-narrower "$S/agent"); RC=$?
[ $RC = 0 ] && [ "$(claims "$S/agent/token" scope)" = read ] && [ "$(stat -c %a "$S/agent/token")" = 600 ] && ok "--allow-narrower takes it; a group-readable token file is replaced with 0600, not refused" || fail "allow-narrower/L7: $RC $OUT $(stat -c %a "$S/agent/token")"
keep "$S/agent/token"

# ── nobody else ever saw a delivered token ──
leaked=0; while read -r t; do [ -z "$t" ] && continue
  grep -qF "$t" "$S/answers" && { fail "an answer or the pickup's output held a delivered token"; leaked=1; }
  grep -qF "$t" "$S"/server-*.log && { fail "the server log holds a delivered token"; leaked=1; }
  grep -qaF "$t" "$DB_PATH"* && { fail "the database holds a delivered token in clear"; leaked=1; }
  [ -z "$(Q "SELECT id FROM demipass_security_events WHERE instr(context_json, '$(echo "$t" | cut -d. -f3 | head -c 30)') > 0")" ] || { fail "an event holds one"; leaked=1; }
done < "$S/delivered"
[ $leaked = 0 ] && [ "$(wc -l < "$S/delivered")" -ge 3 ] && ok "no answer, pickup output, server log, security event or database file holds any delivered token"

# ── caps, newest few, revocation by jti and by the revoke-all cut (L6) ──
RENEW '{"expires_in":"9999d"}'
[ "$CODE" = 200 ] && [ "$(echo "$BODY" | J expires_in)" = 30d ] && ok "9999d asked: capped at the transact ceiling (30d)" || fail "cap: $CODE $BODY"
RENEW '{"expires_in":"3h"}'; RENEW '{"expires_in":"4h"}'; RENEW '{"expires_in":"5h"}'; LAST=$(echo "$BODY" | J delivery_id)
call GET "/api/identity/token-deliveries?did=$CDID" ""
[ "$(echo "$BODY" | python3 -c 'import json,sys; d=json.load(sys.stdin)["deliveries"]; print(len(d), d[0]["id"])')" = "3 $LAST" ] && ok "the listing gives the newest 3, newest first" || fail "newest: $BODY"
X "UPDATE issued_tokens SET revoked = 1 WHERE jti = (SELECT token_jti FROM token_deliveries WHERE pub_id = '$LAST')"
call GET "/api/identity/token-deliveries?did=$CDID" ""; [ "$(echo "$BODY" | J deliveries.0.id)" != "$LAST" ] && ok "a revoked token is no longer handed out" || fail "revoked listed: $BODY"
X "DELETE FROM issued_tokens WHERE jti IN (SELECT token_jti FROM token_deliveries WHERE did = '$CDID')"
X "INSERT OR REPLACE INTO token_revocations (did, revoke_before) VALUES ('$CDID', $(( $(date +%s) + 5 )))"
call GET "/api/identity/token-deliveries?did=$CDID" ""; [ "$(echo "$BODY" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["deliveries"]))')" = 0 ] \
  && ok "revoke-all cuts the deliveries by their own iat, with no issued_tokens row (L6)" || fail "cut: $BODY"
X "DELETE FROM token_revocations WHERE did = '$CDID'"
X "UPDATE token_deliveries SET expires_at = '2000-01-01T00:00:00.000Z' WHERE pub_id = '$LAST'"
call GET "/api/identity/token-deliveries?did=$CDID" ""; [ -z "$(Q "SELECT id FROM token_deliveries WHERE pub_id = '$LAST'")" ] && ok "a delivery ends with its token (purged)" || fail "expired kept"

# ── the owner decides a key change: deny, then approve with the PIN; undo within 6 h (H1, L2) ──
# The revoke-all cut of the L6 step above also ended the copied token's waiting ask (L1, by iat).
[ "$(Q "SELECT status FROM delivery_key_changes WHERE id=$CH1")" = revoked ] && ok "a revoke-all cut ends a waiting ask asked before it (L1, by iat)" || fail "cut ask: $(Q "SELECT status FROM delivery_key_changes WHERE id=$CH1")"
LEAK=$(login claude); printf '%s\n' "$LEAK" > "$S/leak.tok"; DEMIPASS_TOKEN_FILE="$S/leak.tok" PICKUP --init "$S/attacker" >/dev/null
CH1=$(Q "SELECT id FROM delivery_key_changes WHERE did='$CDID' AND status='pending' ORDER BY id DESC LIMIT 1")
call POST /api/fleet/aaron-agents/silicons/claude/delivery-key/$CH1/approve "$CT" '{}'; { [ "$CODE" = 403 ] || [ "$CODE" = 404 ]; } && ok "the agent cannot approve its own key change" || fail "agent approves: $CODE"
call POST /api/fleet/aaron-agents/silicons/claude/delivery-key/$CH1/approve "$O" '{}'; [ "$CODE" = 404 ] && ok "another wallet cannot (404)" || fail "outsider approves: $CODE"
call POST /api/fleet/aaron-agents/silicons/claude/delivery-key/$CH1/deny "$A" '{}'
[ "$CODE" = 200 ] && [ "$(Q "SELECT status FROM delivery_key_changes WHERE id=$CH1")" = denied ] && [ "$(OV claude delivery_key.pending)" = None ] && ok "denied: the change is gone, the pinned key stays" || fail "deny: $CODE"
call GET /api/demipass/list "$LEAK"; [ "$CODE" = 401 ] && ok "…and the token that asked is signed out: it cannot ask again (round-4 M1)" || fail "asker alive after deny: $CODE"
call POST /api/identity/delivery-key "$LEAK" '{"public_key":"'$(node -e 'const c=require("crypto");console.log(c.createPublicKey(c.generateKeyPairSync("x25519").privateKey).export({format:"jwk"}).x)')'"}'; [ "$CODE" = 401 ] || fail "re-ask with the denied token: $CODE"
LEAK3=$(login claude); call POST /api/identity/delivery-key "$LEAK3" '{"public_key":"'$(node -e 'const c=require("crypto");console.log(c.createPublicKey(c.generateKeyPairSync("x25519").privateKey).export({format:"jwk"}).x)')'"}'; CHM=$(echo "$BODY" | J change_id)
[ "$CODE" = 202 ] && [ -n "$(Q "SELECT mailed_at FROM delivery_key_changes WHERE id=$CHM")" ] && ok "the next ask after a deny is always mailed (inside the 3 h cap)" || fail "mail after deny: $CODE $(Q "SELECT mailed_at FROM delivery_key_changes WHERE id=$CHM")"
call POST /api/fleet/aaron-agents/silicons/claude/delivery-key/$CHM/deny "$A" '{}'; [ "$CODE" = 200 ] || fail "deny 2: $CODE"
OUT=$(DEMIPASS_TOKEN_FILE="$S/claude-own.tok" PICKUP --init --rotate "$S/agent"); CH2=$(Q "SELECT id FROM delivery_key_changes WHERE status='pending' ORDER BY id DESC LIMIT 1")
[ -s "$S/agent/delivery.key.pending" ] && [ -n "$CH2" ] && ok "--rotate asks for a new key; the old one stays in use meanwhile" || fail "rotate: $OUT"
call POST /api/fleet/aaron-agents/silicons/claude/delivery-key/$CH2/approve "$A" '{}'
[ "$CODE" = 403 ] && [ "$(echo "$BODY" | J intent)" = "silicon-key:$SID" ] && ok "approving a key change needs the PIN (silicon-key:$SID)" || fail "approve no pin: $CODE $BODY"
PIN "silicon-key:$SID"; call POST /api/fleet/aaron-agents/silicons/claude/delivery-key/$CH2/approve "$A" '{}'
[ "$CODE" = 200 ] && [ "$(Q "SELECT delivery_public_key FROM identity_wallets WHERE username='claude'")" != "$K1" ] && [ "$(OV claude delivery_key.changed_at)" != None ] \
  && ok "approved: the new key is set, the card says 'key changed <time>'" || fail "approve: $CODE $BODY"
[ "$(OV claude delivery_key.previous.fingerprint)" != None ] && ok "the previous key is kept, for the owner to undo the change" || fail "previous kept"
sleep 1.1; RENEW; [ "$CODE" = 200 ] && ok "an owner-approved key takes renewals at once (no cooldown: the revert covers a wrong approval) (L2)" || fail "renew after approve: $CODE $BODY"
JN=$(Q "SELECT token_jti FROM token_deliveries ORDER BY id DESC LIMIT 1")
OLDKEY=$(sha256sum < "$S/agent/delivery.key"); NEWKEY=$(sha256sum < "$S/agent/delivery.key.pending")
mv "$S/agent/delivery.key.pending" "$S/agent/delivery.key.new"   # as if a swap was cut off right after its first step
OUT=$(PICKUP --allow-narrower "$S/agent"); RC=$?
[ $RC = 0 ] && [ ! -e "$S/agent/delivery.key.new" ] && [ "$(sha256sum < "$S/agent/delivery.key")" = "$NEWKEY" ] && [ "$(sha256sum < "$S/agent/delivery.key.prev")" = "$OLDKEY" ] && [ "$(claims "$S/agent/token" scope)" = transact ] \
  && ok "the renewal opens with the new key, even from a swap cut off midway (.new); the old key is kept as .prev (L4)" || fail "new key pickup: $RC $OUT"
cp "$S/agent/token" "$S/tn"; keep "$S/tn"
# whoever holds the new key asks for yet another key with the token it received
call POST /api/identity/delivery-key "$(cat "$S/tn")" '{"public_key":"'$(node -e 'const c=require("crypto");console.log(c.createPublicKey(c.generateKeyPairSync("x25519").privateKey).export({format:"jwk"}).x)')'"}'; CHX=$(echo "$BODY" | J change_id)
[ "$CODE" = 202 ] || fail "ask with the renewed token: $CODE $BODY"
call POST /api/fleet/aaron-agents/silicons/claude/delivery-key/revert "$A" '{}'
[ "$CODE" = 403 ] && [ "$(echo "$BODY" | J intent)" = "silicon-key-revert:$SID" ] && ok "undoing it needs the PIN (silicon-key-revert:$SID)" || fail "revert no pin: $CODE $BODY"
PIN "silicon-key-revert:$SID"; call POST /api/fleet/aaron-agents/silicons/claude/delivery-key/revert "$A" '{}'
[ "$CODE" = 200 ] && [ "$(Q "SELECT delivery_public_key FROM identity_wallets WHERE username='claude'")" = "$K1" ] && [ "$(Q "SELECT revoked FROM issued_tokens WHERE jti='$JN'")" = 1 ] && [ "$(OV claude delivery_key.previous)" = None ] \
  && ok "undone within 6 h: back to the previous key, and the token sealed to the dropped key is revoked" || fail "revert: $CODE $BODY"
call GET /api/demipass/list "$(cat "$S/tn")"; [ "$CODE" = 401 ] && ok "…that token no longer works" || fail "reverted token: $CODE"
[ "$(Q "SELECT status FROM delivery_key_changes WHERE id=$CHX")" = revoked ] && ok "…and an ask made with it ends at once (revoked)" || fail "ask after revert: $(Q "SELECT status FROM delivery_key_changes WHERE id=$CHX")"
call GET /api/demipass/list "$(cat "$S/claude-own.tok")"; [ "$CODE" = 401 ] && [ "$(Q "SELECT status FROM delivery_key_changes WHERE id=$CH2")" = reverted ] \
  && ok "…and the token (session) that asked for the dropped key is signed out; the change is marked undone (round-4 M1)" || fail "asker alive after revert: $CODE"
PIN "silicon-key-revert:$SID"; call POST /api/fleet/aaron-agents/silicons/claude/delivery-key/revert "$A" '{}'; [ "$CODE" = 409 ] && ok "nothing left to undo → 409" || fail "second revert: $CODE"
sleep 1.1; RENEW; OUT=$(PICKUP "$S/agent"); RC=$?
[ $RC = 0 ] && echo "$OUT" | grep -q "wrote" && ok "after the undo the agent's previous key (kept as .prev) opens the next renewal" || fail "pickup after revert: $RC $OUT"
cp "$S/agent/token" "$S/tr"; keep "$S/tr"

# ── a key that changes between the phone's yes and the mint is not sealed to (round-4 L1) ──
OTHER=$(node -e 'const c=require("crypto");console.log(c.createPublicKey(c.generateKeyPairSync("x25519").privateKey).export({format:"jwk"}).x)')
X "CREATE TRIGGER race_key AFTER DELETE ON gate_verifications WHEN old.intent = 'silicon-renew:$SID' BEGIN UPDATE identity_wallets SET delivery_public_key = '$OTHER' WHERE did = '$CDID'; END"
N0=$(Q "SELECT COUNT(*) FROM token_deliveries"); RENEW
[ "$CODE" = 409 ] && echo "$BODY" | grep -q "changed meanwhile" && [ "$(Q "SELECT delivery_public_key FROM identity_wallets WHERE did='$CDID'")" = "$K1" ] && [ "$(Q "SELECT COUNT(*) FROM token_deliveries")" = "$N0" ] \
  && ok "the key changed inside the renewal (after the PIN was spent): 409, nothing minted or sealed, all rolled back" || fail "race: $CODE $BODY"
X "DROP TRIGGER race_key"

# ── the card: under 24 h is 'expiring', in hours ──
call POST /api/fleet/aaron-agents/silicons/brief/token "$A" '{"scope":"transact","expires_in":"5h"}'
call GET /api/fleet/aaron-agents/overview "$A"
echo "$BODY" | python3 -c '
import json,sys; d=json.load(sys.stdin); s=[x for x in d["silicons"] if x["handle"]=="brief"][0]["token"]
sys.exit(0 if s["status"]=="expiring" and 4.8 < s["hours_left"] <= 5 and s["days_left"] == 0.2 else 1)' \
  && ok "the card: 5 h left is expiring, hours_left ≈ 5" || fail "card: $(echo "$BODY" | head -c 300)"

# ── an ask whose token is revoked meanwhile cannot be approved (L1) ──
login claude > "$S/ask.tok"; DEMIPASS_TOKEN_FILE="$S/ask.tok" PICKUP --init "$S/l1" >/dev/null
CHR=$(Q "SELECT id FROM delivery_key_changes WHERE did='$CDID' AND status='pending' ORDER BY id DESC LIMIT 1")
[ "$(OV claude delivery_key.pending.id)" = "$CHR" ] || fail "L1 ask pending"
X "UPDATE issued_tokens SET revoked = 1 WHERE jti = (SELECT ask_jti FROM delivery_key_changes WHERE id = $CHR)"
[ "$(OV claude delivery_key.pending)" = None ] && ok "the asking token revoked (its jti): the card drops the ask" || fail "L1 card"
PIN "silicon-key:$SID"; call POST /api/fleet/aaron-agents/silicons/claude/delivery-key/$CHR/approve "$A" '{}'
[ "$CODE" = 409 ] && [ "$(Q "SELECT status FROM delivery_key_changes WHERE id=$CHR")" = revoked ] && ok "…and it cannot be approved (409, revoked)" || fail "L1 approve: $CODE $BODY"
login claude > "$S/ask2.tok"; DEMIPASS_TOKEN_FILE="$S/ask2.tok" PICKUP --init "$S/l1b" >/dev/null
CHR2=$(Q "SELECT id FROM delivery_key_changes WHERE did='$CDID' AND status='pending' ORDER BY id DESC LIMIT 1")
sleep 1.1; call POST /api/identity/tokens/revoke-all "$(cat "$S/ask2.tok")" '{}'; [ "$CODE" = 200 ] || fail "revoke-all: $CODE $BODY"
X "UPDATE delivery_key_changes SET ask_jti = '' WHERE id = $CHR2"   # only the revoke-all cut (by iat) can tell now
[ "$(OV claude delivery_key.pending)" = None ] && ok "the card applies the routes' own check: an ask cut by revoke-all is not shown (round-4 L3)" || fail "card shows a dead ask"
PIN "silicon-key:$SID"; call POST /api/fleet/aaron-agents/silicons/claude/delivery-key/$CHR2/approve "$A" '{}'
[ "$CODE" = 409 ] && [ "$(Q "SELECT status FROM delivery_key_changes WHERE id=$CHR2")" = revoked ] && ok "revoke-all by the agent ends a waiting ask from before it" || fail "L1 revoke-all: $CODE $BODY"

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
# A key change too: the phone signs "key <fleet>/<handle> to <fingerprint>".
login claude > "$S/leak2.tok"; DEMIPASS_TOKEN_FILE="$S/leak2.tok" PICKUP --init "$S/other" >/dev/null
CH3=$(Q "SELECT id FROM delivery_key_changes WHERE status='pending' ORDER BY id DESC LIMIT 1"); FP3=$(Q "SELECT fingerprint FROM delivery_key_changes WHERE id=$CH3")
PIN "silicon-key:$SID"; call POST /api/fleet/aaron-agents/silicons/claude/delivery-key/$CH3/approve "$A" '{}'
[ "$CODE" = 428 ] && [ "$(echo "$BODY" | J challenge.bind)" = "key aaron-agents/claude to $FP3" ] && ok "…and a key change needs the phone to sign \"key aaron-agents/claude to $FP3\"" || fail "key 428: $CODE $BODY"

# A request carrying a key: the phone signs its fingerprint with the request (round-4 H1).
B2b=$(login bot2); MAT2=$(DEMIPASS_URL=$API node "$W/bin/token-pickup.js" --material "$S/bot2" 2>/dev/null); FP2=$(echo "$MAT2" | J fingerprint)
call POST /api/fleet/aaron-agents/silicons/bot2/token-requests "$B2b" "$(echo "$MAT2" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(json.dumps({"claim_secret_hash": d["claim_secret_hash"], "delivery_key": d["delivery_key"], "expires_in": "1h"}))')"; RQ2=$(echo "$BODY" | J request_id)
PIN "silicon-token:$RQ2"; call POST /api/silicon-token-requests/$RQ2/approve "$A" '{}'
[ "$CODE" = 428 ] && [ "$(echo "$BODY" | J challenge.bind)" = "aaron-agents/bot2:transact:1h asked by bot2 key $FP2" ] && ok "…and a request carrying a key makes the phone sign \"… key $FP2\"" || fail "request key bind: $CODE $BODY"

# ── the pickup listing is rate-limited per address + DID; another DID still answers (L3) ──
for i in $(seq 1 70); do C=$(curl -s -o /dev/null -w '%{http_code}' "$API/api/identity/token-deliveries?did=$CDID"); [ "$C" = 429 ] && break; done
C2=$(curl -s -o /dev/null -w '%{http_code}' "$API/api/identity/token-deliveries?did=did:key:zSomeoneElse")
[ "$C" = 429 ] && [ "$C2" = 200 ] && ok "the unauthenticated listing is rate-limited per DID (429), another DID still answers" || fail "rate limit: $C $C2"

[ $fails -gt 0 ] && { echo "--- server.log"; grep -i -m5 "error" "$S/server-new.log"; }
echo "$fails failure(s)"; exit $(( fails > 0 ))
