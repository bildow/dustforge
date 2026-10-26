#!/bin/bash
# End-to-end smoke of the wallet network (network_routes.js, contract docs/network.md): boots server.js on a throwaway
# DB + random master key, creates four wallets — owner A (vault PIN), person K (no PIN), agent F (no PIN), agent G
# (PIN) — and drives the real HTTP routes: person requests (dedupe, accept, decline, withdraw, who may decide), an
# agent asking to join A's fleet, A inviting G (accept needs G's PIN, intent join:<id>), one fleet per agent, leaving,
# a fleet created on first join, and DD sends: only to connections, two steps, PIN for intent send:<id> when the
# sender has one, bound to the session that started it, spent once. Silicon tokens are refused. No network.
set -u
W=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
S=$(mktemp -d /tmp/dustforge-network-smoke.XXXXXX)
PORT=${PORT:-3779}; API=http://127.0.0.1:$PORT
[ -d "$W/node_modules" ] || export NODE_PATH=${NODE_PATH:-/home/flimflam/project/dustforge/node_modules}
export IDENTITY_MASTER_KEY=$(python3 -c 'import secrets;print(secrets.token_hex(32))') DB_PATH=$S/dustforge.db PORT STALWART_HOST=127.0.0.1 STALWART_PORT=1 SMTP_RELAY_HOST=
cd "$W"
node server.js >"$S/server.log" 2>&1 & SRV=$!
trap 'kill $SRV 2>/dev/null; rm -rf "$S"' EXIT
for i in $(seq 1 40); do curl -s -o /dev/null "$API/" && break; sleep 0.5; done
kill -0 $SRV 2>/dev/null || { echo "server died:"; tail -5 "$S/server.log"; exit 1; }
PW=hunter22; H=$(printf '%s' "$PW" | sha256sum | cut -d' ' -f1)
SIL='silicon:network-smoke-token-0123456789'
node -e '
const identity = require("./identity"); const Database = require("better-sqlite3"); const crypto = require("crypto");
const db = new Database(process.env.DB_PATH);
try { db.exec("ALTER TABLE identity_wallets ADD COLUMN password_hash TEXT"); } catch (_) {}
// Prod has these (added outside server.js); a fresh DB does not.
for (const c of ["idempotency_key TEXT", "provenance TEXT DEFAULT 'organic'"]) { try { db.exec("ALTER TABLE identity_transactions ADD COLUMN " + c); } catch (_) {} }
const out = {};
for (const [u, bal] of [["owner-a", 100000], ["person-k", 5000], ["agent-f", 0], ["agent-g", 0], ["stranger-s", 0], ["legacy-l", 300]]) {
  const id = identity.createIdentity(); const enc = id.encrypted_private_key || id.encryptedPrivateKey;
  db.prepare("INSERT INTO identity_wallets (did, username, email, encrypted_private_key, balance_cents, password_hash) VALUES (?, ?, ?, ?, ?, ?)")
    .run(id.did, u, u + "@dustforge.com", enc, bal, process.argv[1]);
  if (bal) db.prepare("INSERT INTO identity_transactions (did, amount_cents, type, description, balance_after) VALUES (?, ?, ?, ?, ?)").run(id.did, bal, "topup", "smoke", bal);
  out[u] = id.did;
}
db.prepare("INSERT INTO silicon_agents (agent_name, did, carbon_did, token_hash) VALUES (?, ?, ?, ?)")
  .run("net-a1", "did:silicon:net-smoke", out["owner-a"], crypto.createHash("sha256").update(process.argv[2]).digest("hex"));
' "$H" "$SIL"
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
bal(){ Q "SELECT balance_cents FROM identity_wallets WHERE username='$1'"; }
A=$(login owner-a); A2=$(login owner-a); K=$(login person-k); F=$(login agent-f); G=$(login agent-g); X=$(login stranger-s)
[ -n "$A" ] && [ "$A" != None ] && [ -n "$G" ] && [ "$G" != None ] && ok "five wallets signed in" || { fail "login: $CODE $BODY"; exit 1; }
call POST /api/identity/pin "$A" '{"pin":"4321","password":"hunter22"}'; [ "$CODE" = 200 ] || fail "pin A: $CODE $BODY"
call POST /api/identity/pin "$G" '{"pin":"8765","password":"hunter22"}'; [ "$CODE" = 200 ] || fail "pin G: $CODE $BODY"

# ── who may use it ──
call GET /api/network "$SIL"; [ "$CODE" = 403 ] && ok "a silicon: token (acts for its carbon) is refused" || fail "silicon: $CODE $BODY"
call GET /api/network ""; [ "$CODE" = 401 ] && ok "no token → 401" || fail "anon: $CODE"

# ── person: request, dedupe, accept ──
call POST /api/network/requests "$A" '{"to":"nobody-here","as":"person"}'; [ "$CODE" = 404 ] && ok "unknown wallet → 404" || fail "404: $CODE $BODY"
call POST /api/network/requests "$A" '{"to":"owner-a","as":"person"}'; [ "$CODE" = 400 ] && ok "own wallet → 400" || fail "self: $CODE $BODY"
call POST /api/network/requests "$A" '{"to":"person-k","as":"friend"}'; [ "$CODE" = 400 ] && ok "unknown kind → 400" || fail "kind: $CODE $BODY"
call POST /api/network/requests "$A" '{"to":"person-k@dustforge.com","as":"person","note":"hi Kyle‮"}'
[ "$CODE" = 201 ] && [ "$(echo "$BODY" | J request.direction)" = outgoing ] && [ "$(echo "$BODY" | J request.note)" = "hi Kyle" ] && ok "A asks K (by email) to connect → 201; bidi characters stripped from the note" || fail "person req: $CODE $BODY"
RK=$(echo "$BODY" | J request.id)
call POST /api/network/requests "$A" '{"to":"person-k","as":"person"}'; [ "$CODE" = 409 ] && ok "asking again while it waits → 409" || fail "dup: $CODE $BODY"
call POST /api/network/requests "$K" '{"to":"owner-a","as":"person"}'; [ "$CODE" = 409 ] && [ "$(echo "$BODY" | J request.id)" = "$RK" ] && ok "the other side asking back → 409 pointing at the waiting request" || fail "reverse: $CODE $BODY"
call POST /api/network/requests/$RK/accept "$A"; [ "$CODE" = 403 ] && ok "the asker cannot accept its own request" || fail "self-accept: $CODE $BODY"
call POST /api/network/requests/$RK/accept "$X"; [ "$CODE" = 404 ] && ok "a third wallet cannot see or accept it" || fail "third: $CODE $BODY"
call GET /api/network "$K"; [ "$(echo "$BODY" | J incoming.0.id)" = "$RK" ] && [ "$(echo "$BODY" | J incoming.0.from)" = owner-a ] && ok "K sees the incoming request" || fail "K incoming: $BODY"
call POST /api/network/requests/$RK/accept "$K"; [ "$CODE" = 200 ] && [ "$(echo "$BODY" | J kind)" = person ] && ok "K accepts (no PIN needed for a contact)" || fail "accept: $CODE $BODY"
call POST /api/network/requests/$RK/accept "$K"; [ "$CODE" = 409 ] && ok "accepting twice → 409" || fail "twice: $CODE $BODY"
call GET /api/network "$A"; [ "$(echo "$BODY" | J people.0.username)" = person-k ] && ok "A lists K under people" || fail "A people: $BODY"
call POST /api/network/requests "$A" '{"to":"person-k","as":"person"}'; [ "$CODE" = 409 ] && ok "already connected → 409" || fail "connected: $CODE $BODY"

# ── decline + withdraw ──
call POST /api/network/requests "$X" '{"to":"owner-a","as":"person"}'; RX=$(echo "$BODY" | J request.id)
call POST /api/network/requests/$RX/decline "$X"; [ "$CODE" = 403 ] && ok "the asker cannot decline (it withdraws)" || fail "decl own: $CODE $BODY"
call POST /api/network/requests/$RX/decline "$A"; [ "$CODE" = 200 ] && ok "A declines S" || fail "decline: $CODE $BODY"
call POST /api/network/requests "$F" '{"to":"stranger-s","as":"person"}'; RX=$(echo "$BODY" | J request.id)
call POST /api/network/requests/$RX/withdraw "$X"; [ "$CODE" = 403 ] && ok "the target cannot withdraw" || fail "wd target: $CODE $BODY"
call POST /api/network/requests/$RX/withdraw "$F"; [ "$CODE" = 200 ] && ok "F withdraws its request" || fail "withdraw: $CODE $BODY"
call POST /api/network/requests/$RX/accept "$X"; [ "$CODE" = 409 ] && ok "a withdrawn request cannot be accepted" || fail "accept withdrawn: $CODE $BODY"

# ── send DD to a person ──
call POST /api/network/transfers "$A" '{"to":"stranger-s","amount_cents":5}'; [ "$CODE" = 403 ] && ok "sending to a wallet you are not connected to → 403" || fail "unconnected: $CODE $BODY"
call POST /api/network/transfers "$A" '{"to":"person-k","amount_cents":0}'; [ "$CODE" = 400 ] && ok "amount 0 → 400" || fail "amt0: $CODE"
call POST /api/network/transfers "$A" '{"to":"person-k","amount_cents":2.5}'; [ "$CODE" = 400 ] && ok "fractional amount → 400" || fail "amt frac: $CODE"
A0=$(bal owner-a); K0=$(bal person-k)
call POST /api/network/transfers "$A" '{"to":"person-k","amount_cents":50,"note":"lunch"}'
[ "$CODE" = 201 ] && [ "$(echo "$BODY" | J transfer.needs_pin)" = True ] && ok "A starts a 50 DD send → 201, needs PIN" || fail "start: $CODE $BODY"
T1=$(echo "$BODY" | J transfer.id)
[ "$(bal owner-a)" = "$A0" ] && ok "nothing moved yet" || fail "moved early"
call POST /api/network/transfers/$T1/confirm "$A"
[ "$CODE" = 403 ] && [ "$(echo "$BODY" | J missing.0)" = pin ] && [ "$(echo "$BODY" | J intent)" = "send:$T1" ] && ok "confirm without PIN → 403 missing [pin], intent send:$T1" || fail "no pin: $CODE $BODY"
call POST /api/identity/gate/verify "$A" '{"gate":"pin","pin":"4321","intent":"send:999999"}'
call POST /api/network/transfers/$T1/confirm "$A"; [ "$CODE" = 403 ] && ok "a PIN proof for another transfer does not confirm this one" || fail "wrong intent: $CODE $BODY"
call POST /api/network/transfers/$T1/confirm "$A2"; [ "$CODE" = 404 ] && ok "another session of A cannot confirm it (404)" || fail "other session: $CODE $BODY"
call POST /api/identity/gate/verify "$A" '{"gate":"pin","pin":"1111","intent":"send:'$T1'"}'; [ "$CODE" = 403 ] && ok "wrong PIN → 403 (never 401)" || fail "wrong pin: $CODE"
call POST /api/identity/gate/verify "$A" '{"gate":"pin","pin":"4321","intent":"send:'$T1'"}'; [ "$CODE" = 200 ] || fail "verify: $CODE $BODY"
call POST /api/network/transfers/$T1/confirm "$A"
[ "$CODE" = 200 ] && [ "$(echo "$BODY" | J status)" = sent ] && ok "confirm with the PIN → sent" || fail "confirm: $CODE $BODY"
[ "$(bal owner-a)" = $((A0-50)) ] && [ "$(bal person-k)" = $((K0+50)) ] && ok "A −50, K +50" || fail "balances: $(bal owner-a) $(bal person-k)"
call POST /api/network/transfers/$T1/confirm "$A"; [ "$CODE" = 409 ] && ok "confirming again → 409, no second debit" || fail "again: $CODE $BODY"
[ "$(bal owner-a)" = $((A0-50)) ] || fail "second debit happened"
LT=$(Q "SELECT description FROM identity_transactions WHERE type='transfer_in' AND did=(SELECT did FROM identity_wallets WHERE username='person-k') ORDER BY id DESC"); [ "$LT" = "Transfer from owner-a: lunch" ] && ok "K's ledger reads '$LT'" || fail "ledger text: $LT"
call POST /api/network/transfers "$A" '{"to":"person-k","amount_cents":7}'; T2=$(echo "$BODY" | J transfer.id)
call POST /api/network/transfers/$T2/cancel "$A"; [ "$CODE" = 200 ] && ok "a started send can be cancelled" || fail "cancel: $CODE"
call POST /api/identity/gate/verify "$A" '{"gate":"pin","pin":"4321","intent":"send:'$T2'"}'
call POST /api/network/transfers/$T2/confirm "$A"; [ "$CODE" = 409 ] && ok "a cancelled send cannot be confirmed" || fail "confirm cancelled: $CODE $BODY"
call POST /api/network/transfers "$A" '{"to":"person-k","amount_cents":3}'; T3=$(echo "$BODY" | J transfer.id)
python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute(\"UPDATE network_transfers SET expires_at='2000-01-01T00:00:00Z' WHERE id=?\",(sys.argv[2],)); c.commit()" "$DB_PATH" "$T3"
call POST /api/network/transfers/$T3/confirm "$A"; [ "$CODE" = 410 ] && ok "an expired send → 410" || fail "expired: $CODE $BODY"
K1=$(bal person-k); A1=$(bal owner-a)
call POST /api/network/transfers "$K" '{"to":"owner-a","amount_cents":10}'; TK=$(echo "$BODY" | J transfer.id)
[ "$(echo "$BODY" | J transfer.needs_pin)" = False ] && ok "K (no PIN set) → needs_pin false" || fail "K needs_pin: $BODY"
call POST /api/network/transfers/$TK/confirm "$K"; [ "$CODE" = 200 ] && [ "$(bal person-k)" = $((K1-10)) ] && [ "$(bal owner-a)" = $((A1+10)) ] && ok "K sends A 10 DD without a PIN (none set)" || fail "K send: $CODE $BODY"
call POST /api/network/transfers "$K" '{"to":"owner-a","amount_cents":999999}'; TB=$(echo "$BODY" | J transfer.id)
call POST /api/network/transfers/$TB/confirm "$K"; [ "$CODE" = 402 ] || [ "$CODE" = 403 ] && ok "more than the balance → refused ($CODE), nothing moved" || fail "overdraw: $CODE $BODY"
[ "$(bal person-k)" = $((K1-10)) ] || fail "overdraw moved DD"

# ── agent asks to join A's fleet ──
call POST /api/network/requests "$F" '{"to":"owner-a","as":"join","note":"Felix here"}'
[ "$CODE" = 201 ] && RF=$(echo "$BODY" | J request.id) && ok "F asks to join A's fleet → 201" || fail "join req: $CODE $BODY"
call GET /api/network "$A"; [ "$(echo "$BODY" | J incoming.0.kind)" = join ] && [ "$(echo "$BODY" | J incoming.0.needs_pin)" = False ] && ok "A sees it; no PIN needed to take an agent in" || fail "A sees join: $BODY"
call POST /api/network/requests/$RF/accept "$A"
[ "$CODE" = 200 ] && [ "$(echo "$BODY" | J handle)" = agent-f ] && ok "A accepts → F is @agent-f in A's fleet" || fail "accept join: $CODE $BODY"
SLUG=$(echo "$BODY" | J fleet)
call GET /api/fleet/$SLUG/overview "$A"; [ "$(echo "$BODY" | J silicons.0.handle)" = agent-f ] && ok "the Fleet overview lists @agent-f (fleet $SLUG made on first join)" || fail "overview: $CODE $BODY"
call GET /api/network "$F"; [ "$(echo "$BODY" | J member_of.owner)" = owner-a ] && ok "F sees it is in owner-a's fleet" || fail "F member_of: $BODY"
call POST /api/network/requests "$F" '{"to":"person-k","as":"join"}'; [ "$CODE" = 409 ] && ok "an agent already in a fleet cannot ask to join another → 409" || fail "second fleet: $CODE $BODY"
call POST /api/network/requests "$F" '{"to":"person-k","as":"agent"}'; [ "$CODE" = 409 ] && ok "an agent in a fleet cannot own one → 409" || fail "agent owns: $CODE $BODY"
call POST /api/network/requests "$K" '{"to":"owner-a","as":"agent"}'; [ "$CODE" = 409 ] && ok "a wallet running a fleet cannot be invited as an agent → 409" || fail "owner as agent: $CODE $BODY"
F0=$(bal agent-f)
call POST /api/network/transfers "$A" '{"to":"agent-f","amount_cents":25}'; TF=$(echo "$BODY" | J transfer.id)
call POST /api/identity/gate/verify "$A" '{"gate":"pin","pin":"4321","intent":"send:'$TF'"}'
call POST /api/network/transfers/$TF/confirm "$A"; [ "$CODE" = 200 ] && [ "$(bal agent-f)" = $((F0+25)) ] && ok "A sends its agent F 25 DD" || fail "A→F: $CODE $BODY"
call POST /api/network/transfers "$F" '{"to":"owner-a","amount_cents":5}'; TF2=$(echo "$BODY" | J transfer.id)
call POST /api/network/transfers/$TF2/confirm "$F"; [ "$CODE" = 200 ] && ok "F (no PIN) sends its fleet owner 5 DD" || fail "F→A: $CODE $BODY"
call POST /api/network/transfers "$F" '{"to":"person-k","amount_cents":1}'; [ "$CODE" = 403 ] && ok "F cannot send to A's contact K (not F's connection)" || fail "F→K: $CODE $BODY"

# ── A invites G as an agent: G has a PIN, so accepting needs it ──
call POST /api/network/requests "$A" '{"to":"agent-g","as":"agent","handle":"agent-f"}'; RG=$(echo "$BODY" | J request.id)
[ "$CODE" = 201 ] && ok "A invites G with a handle already taken" || fail "invite G: $CODE $BODY"
call GET /api/network "$G"; [ "$(echo "$BODY" | J incoming.0.needs_pin)" = True ] && [ "$(echo "$BODY" | J incoming.0.intent)" = "join:$RG" ] && ok "G sees needs_pin, intent join:$RG, and what it hands over" || fail "G view: $BODY"
call POST /api/network/requests/$RG/accept "$G"; [ "$CODE" = 403 ] && [ "$(echo "$BODY" | J missing.0)" = pin ] && ok "G accepting without the PIN → 403 missing [pin]" || fail "G no pin: $CODE $BODY"
call POST /api/identity/gate/verify "$G" '{"gate":"pin","pin":"8765","intent":"join:'$RG'"}'
call POST /api/network/requests/$RG/accept "$G"; [ "$CODE" = 200 ] && [ "$(echo "$BODY" | J handle)" = agent-f-2 ] && ok "G accepts with the PIN → @agent-f-2 (taken handle suffixed)" || fail "G accept: $CODE $BODY"

# ── leave, and join another fleet ──
call POST /api/network/leave-fleet "$F"; [ "$CODE" = 200 ] && [ "$(echo "$BODY" | J signed_out)" = False ] && ok "F leaves A's fleet (joined through the network: kept its key, stays signed in)" || fail "leave: $CODE $BODY"
call GET /api/network "$F"; [ "$CODE" = 200 ] && ok "F's own session still works after leaving" || fail "F session after leave: $CODE"
call POST /api/network/transfers "$A" '{"to":"agent-f","amount_cents":1}'; [ "$CODE" = 403 ] && ok "after leaving, A and F are no longer connected" || fail "post-leave: $CODE $BODY"
call POST /api/network/requests "$K" '{"to":"agent-f","as":"agent"}'; RK2=$(echo "$BODY" | J request.id)
call POST /api/network/requests/$RK2/accept "$F"; [ "$CODE" = 200 ] && [ "$(echo "$BODY" | J owner)" = person-k ] && ok "K (no fleet yet) invites F; F accepts → K's fleet is created, F in it" || fail "K fleet: $CODE $BODY"
call GET /api/fleets/mine "$K"; [ "$(echo "$BODY" | J fleets.0.role)" = owner ] && ok "K now owns a fleet (Fleet tab works for K)" || fail "K fleets: $BODY"
call POST /api/network/people/remove "$K" '{"username":"owner-a"}'; [ "$CODE" = 200 ] && ok "K removes A as a contact" || fail "remove: $CODE"
call POST /api/network/transfers "$A" '{"to":"person-k","amount_cents":1}'; [ "$CODE" = 403 ] && ok "after removal, A cannot send K DD" || fail "post-remove: $CODE"
# ── review round 1 regressions ──
call POST /api/network/requests "$G" '{"to":"stranger-s","as":"join"}'; [ "$CODE" = 403 ] && ok "a wallet with a PIN cannot send 'join' (stolen-token takeover closed)" || fail "join with pin: $CODE $BODY"
call POST /api/network/requests "$X" '{"to":"owner-a","as":"person"}'; RC=$(echo "$BODY" | J request.id)
call POST /api/network/requests/$RC/decline "$A"
call POST /api/network/requests "$X" '{"to":"owner-a","as":"person"}'; [ "$CODE" = 429 ] && ok "asking again right after a decline → 429 (cooldown)" || fail "cooldown: $CODE $BODY"
call POST /api/network/requests "$K" '{"to":"stranger-s","as":"person"}'; RW=$(echo "$BODY" | J request.id)
call POST /api/network/requests/$RW/withdraw "$K"
call POST /api/network/requests "$K" '{"to":"stranger-s","as":"person"}'; [ "$CODE" = 429 ] && ok "request → withdraw → request again → 429 (no mail loop)" || fail "withdraw loop: $CODE $BODY"
# legacy route: a silicon added without consent stays pending and gets nothing
call POST /api/fleet/$SLUG/silicons "$A" '{"handle":"stranger","did":"'$(Q "SELECT did FROM identity_wallets WHERE username='stranger-s'")'"}'
[ "$(echo "$BODY" | J mode)" = pending_claim ] && ok "legacy add without proof → pending_claim" || fail "legacy add: $CODE $BODY"
call POST /api/fleet/$SLUG/silicons/stranger/token "$A" '{"scope":"transact","expires_in":"1h"}'; [ "$CODE" = 409 ] && ok "no token minted for a silicon that has not confirmed (was: any wallet's token)" || fail "pending mint: $CODE $BODY"
call POST /api/fleet/$SLUG/silicons/stranger/refill "$A" '{"amount_cents":5}'; [ "$CODE" = 409 ] && ok "no refill to an unconfirmed silicon" || fail "pending refill: $CODE"
call GET /api/fleet/$SLUG/silicons/stranger "$A"; [ "$CODE" = 409 ] && ok "no detail view of an unconfirmed silicon" || fail "pending detail: $CODE"
call DELETE /api/fleet/$SLUG/silicons/stranger "$A"; [ "$CODE" = 200 ] && ok "an unconfirmed silicon can be removed" || fail "pending delete: $CODE $BODY"
call POST /api/fleet/create "$(curl -s -X POST $API/api/identity/auth-fingerprint -H 'Content-Type: application/json' -d '{"username":"stranger-s","password":"hunter22","scope":"read","expires_in":"1h"}' | J token)" '{"name":"x","slug":"read-fleet"}'
[ "$CODE" = 403 ] && ok "/api/fleet/create refuses a read-scope token" || fail "fleet create read: $CODE $BODY"
# G joined through the network: the owner mints nothing for it
call POST /api/fleet/$SLUG/silicons/agent-f-2/token "$A" '{"scope":"transact","expires_in":"1h"}'; [ "$CODE" = 403 ] && ok "no owner-minted token for an agent that joined through the network" || fail "mint network agent: $CODE $BODY"
call POST /api/fleet/$SLUG/silicons/agent-f-2/workers "$A" '{"name":"w1"}'; [ "$CODE" = 403 ] && ok "no owner-made workers for it either" || fail "worker network agent: $CODE $BODY"
call POST /api/network/leave-fleet "$G"; [ "$CODE" = 200 ] && ok "G leaves A's fleet with its own token" || fail "G leave: $CODE"
# legacy: A links L with L's own token (A holds L's key from then on), mints for it, makes a worker
L=$(login legacy-l); LDID=$(Q "SELECT did FROM identity_wallets WHERE username='legacy-l'")
call POST /api/fleet/$SLUG/silicons "$A" '{"handle":"legacy-l","did":"'$LDID'","member_token":"'$L'"}'; [ "$(echo "$BODY" | J mode)" = linked ] && ok "legacy link with L's own token" || fail "legacy link: $CODE $BODY"
call POST /api/fleet/$SLUG/silicons/legacy-l/token "$A" '{"scope":"transact","expires_in":"1h"}'; LM=$(echo "$BODY" | J token)
[ "$CODE" = 200 ] && ok "A mints a token for L (owner holds the key)" || fail "mint L: $CODE $BODY"
call POST /api/fleet/$SLUG/silicons/legacy-l/workers "$A" '{"name":"lw1"}'; WID=$(echo "$BODY" | J worker.worker_id)
call POST /api/fleet/$SLUG/silicons/legacy-l/workers/$WID/token "$A" '{"scope":"transact","expires_in":"1h"}'; LW=$(echo "$BODY" | J token)
[ "$CODE" = 200 ] && [ -n "$LW" ] && [ "$LW" != None ] && ok "A makes a worker for L" || fail "worker L: $CODE $BODY"
call POST /api/network/requests "$LM" '{"to":"person-k","as":"join"}'; [ "$CODE" = 403 ] && ok "a minted token cannot send fleet requests for L" || fail "minted join: $CODE $BODY"
call POST /api/network/leave-fleet "$LM"; [ "$CODE" = 403 ] && ok "a minted token cannot make L leave" || fail "minted leave: $CODE"
call POST /api/fleet/create "$LM" '{"name":"x","slug":"minted-fleet"}'; [ "$CODE" = 403 ] && ok "a minted token cannot create a fleet for L" || fail "minted create: $CODE $BODY"
call POST /api/identity/device/approve "$LM" '{"user_code":"ABCD-EFGH"}'; [ "$CODE" = 403 ] && ok "a minted token cannot approve a device login (no laundering)" || fail "minted device approve: $CODE $BODY"
call POST /api/blindkey/silicon/register "$LM" '{"agent_name":"evil-l"}'; [ "$CODE" = 403 ] && ok "a minted token cannot register a silicon: agent for L" || fail "minted register: $CODE $BODY"
call POST /api/network/leave-fleet "$L"; [ "$CODE" = 200 ] && [ "$(echo "$BODY" | J signed_out)" = True ] && ok "L leaves; the owner held its key → signed out everywhere" || fail "L leave: $CODE $BODY"
call GET /api/network "$LM"; [ "$CODE" = 401 ] && ok "A's minted token for L died" || fail "cut: $CODE $BODY"
call GET /api/network "$LW"; [ "$CODE" = 401 ] && ok "A's worker token for L died" || fail "worker cut: $CODE $BODY"
call POST /api/wallet/transfer "$LM" '{"from_did":"'$LDID'","to_did":"'$(Q "SELECT did FROM identity_wallets WHERE username='owner-a'")'","amount_cents":1}'
[ "$CODE" = 401 ] && ok "the dead minted token cannot move DD through /api/wallet/transfer" || fail "legacy transfer with cut token: $CODE $BODY"
call POST /api/fleet/$SLUG/fund "$LM" '{"amount_cents":1}'; [ "$CODE" = 401 ] && ok "nor through /api/fleet/:slug/fund" || fail "fund with cut token: $CODE $BODY"
L=$(login legacy-l); call GET /api/network "$L"; [ "$CODE" = 200 ] && ok "L signs in again" || fail "L relogin: $CODE"
# owner removal revokes the workers the owner made: re-link L, make a worker, remove L
call POST /api/fleet/$SLUG/silicons "$A" '{"handle":"legacy-l2","did":"'$LDID'","member_token":"'$L'"}'; [ "$(echo "$BODY" | J mode)" = linked ] || fail "re-link L: $CODE $BODY"
call POST /api/fleet/$SLUG/silicons/legacy-l2/workers "$A" '{"name":"lw2"}'; WID2=$(echo "$BODY" | J worker.worker_id)
call POST /api/fleet/$SLUG/silicons/legacy-l2/workers/$WID2/token "$A" '{"scope":"transact","expires_in":"1h"}'; LW2=$(echo "$BODY" | J token)
call DELETE /api/fleet/$SLUG/silicons/legacy-l2 "$A"; [ "$CODE" = 200 ] || fail "remove L: $CODE"
call GET /api/network "$LW2"; [ "$CODE" = 401 ] && ok "owner removal revokes the workers the owner made" || fail "removal worker: $CODE $BODY"
# a network member: the owner sees only what is between them, cannot touch its own workers or contact email
call POST /api/network/requests "$A" '{"to":"stranger-s","as":"agent","handle":"s-net"}'; RN=$(echo "$BODY" | J request.id)
X=$(login stranger-s); call POST /api/network/requests/$RN/accept "$X"; [ "$CODE" = 200 ] || fail "S joins: $CODE $BODY"
call POST /api/silicons/workers "$X" '{"name":"sown"}'; SWID=$(echo "$BODY" | J worker.worker_id)
call GET /api/fleet/$SLUG/silicons/s-net "$A"; [ "$(echo "$BODY" | J workers)" = "[]" ] && [ "$(echo "$BODY" | J secrets.own)" = "[]" ] && ok "owner's view of a network agent: no own secrets, no own workers" || fail "narrow view: $BODY"
call POST /api/fleet/$SLUG/silicons/s-net/workers/$SWID/revoke "$A"; [ "$CODE" = 404 ] && ok "owner cannot revoke the agent's own worker" || fail "revoke own worker: $CODE $BODY"
call PATCH /api/fleet/$SLUG/silicons/s-net "$A" '{"contact_email":"owner@evil.example"}'; [ "$CODE" = 403 ] && ok "owner cannot redirect the agent's contact email" || fail "patch email: $CODE $BODY"
call POST /api/fleet/$SLUG/silicons "$A" '{"handle":"s-other","did":"'$(Q "SELECT did FROM identity_wallets WHERE username='stranger-s'")'"}'; [ "$CODE" = 409 ] && ok "legacy re-add of an active member under another handle → 409 (no limbo)" || fail "limbo: $CODE $BODY"
call DELETE /api/fleet/$SLUG/silicons/s-net "$A"
call POST /api/fleet/$SLUG/silicons "$A" '{"handle":"s-net","did":"'$(Q "SELECT did FROM identity_wallets WHERE username='stranger-s'")'"}'; [ "$CODE" = 409 ] && ok "a removed network agent cannot be re-added through a claim link (flip to owner-held refused)" || fail "flip: $CODE $BODY"
# claim links: GET shows, POST joins
call POST /api/fleet/$SLUG/silicons "$A" '{"handle":"claimer","did":"'$(Q "SELECT did FROM identity_wallets WHERE username='person-k'")'"}'
[ "$(echo "$BODY" | J mode)" = pending_claim ] || ok "(K runs a fleet: legacy add refused, as it should: $CODE)"
CODE_K=claimtestcode123; H=$(node -e "console.log(require('./fleet_billing').hashToken(process.argv[1]))" "$CODE_K")
python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute(\"UPDATE fleet_silicons SET handle='g-claim', status='pending_claim', joined_via='owner', claim_code=?, claim_expires_at='2999-01-01T00:00:00Z' WHERE member_did=(SELECT did FROM identity_wallets WHERE username='agent-g') AND fleet_id=(SELECT id FROM fleets WHERE slug=?)\", (sys.argv[2], sys.argv[3])); c.commit()" "$DB_PATH" "$H" "$SLUG"
curl -s -o /dev/null "$API/api/fleet/claim/$CODE_K"; [ "$(Q "SELECT status FROM fleet_silicons WHERE handle='g-claim'")" = pending_claim ] && ok "opening a claim link (GET) does not join" || fail "GET joined"
curl -s -o /dev/null -X POST "$API/api/fleet/claim/$CODE_K"; [ "$(Q "SELECT status FROM fleet_silicons WHERE handle='g-claim'")" = active ] && ok "the confirm button (POST) joins" || fail "POST claim: $(Q "SELECT status FROM fleet_silicons WHERE handle='g-claim'")"
# an owner with agents (K owns a fleet with F) cannot join, even via a second empty fleet trick
call POST /api/network/requests "$A" '{"to":"person-k","as":"agent"}'; [ "$CODE" = 409 ] && ok "K runs a fleet with an agent → cannot be invited (any owned fleet counts)" || fail "owner join: $CODE $BODY"
# barrel before the PIN: stranger-s has no inner-ring signals and a balance → 403 barrel without a PIN prompt
python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute(\"UPDATE identity_wallets SET balance_cents=500 WHERE username='stranger-s'\"); c.commit()" "$DB_PATH"
call POST /api/network/requests "$X" '{"to":"agent-g","as":"person"}'; RS=$(echo "$BODY" | J request.id); call POST /api/network/requests/$RS/accept "$G"
call POST /api/network/transfers "$G" '{"to":"stranger-s","amount_cents":150}'; TG=$(echo "$BODY" | J transfer.id)
call POST /api/network/transfers/$TG/confirm "$G"
[ "$CODE" = 403 ] && [ "$(echo "$BODY" | J required_tier)" = double ] && [ "$(echo "$BODY" | J missing)" = None ] && ok "over 100 DD below the double barrel → refused before any PIN prompt" || fail "barrel first: $CODE $BODY"
# F is an agent in K's fleet: a fleet F creates cannot take agents through the legacy route either
call POST /api/fleet/create "$F" '{"name":"f-own","slug":"f-own"}'; [ "$CODE" = 200 ] || fail "F create: $CODE $BODY"
call POST /api/fleet/f-own/silicons "$F" '{"handle":"s1","did":"'$(Q "SELECT did FROM identity_wallets WHERE username='stranger-s'")'","member_token":"'$X'"}'
[ "$CODE" = 409 ] && ok "an agent's own fleet cannot take agents (legacy route, even with the member's token)" || fail "agent owner legacy: $CODE $BODY"
grep -qiE 'pin.*(4321|8765)|"pin":"' "$S/server.log" && fail "a PIN reached the server log" || ok "no PIN in the server log"
echo "$fails failure(s)"; [ "$fails" = 0 ]
