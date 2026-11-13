#!/bin/bash
# Smoke of POST /api/services/charge-on-request (service_tenants.js; FleetEngine F1b) through the real server, throwaway DB.
# A wallet asks a tenant for work by a Conduit message, not a service token. Conduit's post charge (idempotency key
# requestKey(recipient wallet, message sha256, nonce)) is the proof; the payer's consent must have opted in
# (on_request_cap_dd). People (PIN 4321): owner (fleet owner), ext (the payer), nocon (no consent to the tenant).
# Silicons of owner's fleet: fe (tenant fleetengine), cd (tenant conduit), ot (tenant othersvc).
# Adversarial: forged receipt, a request for another tenant, other bytes, stale, replayed request id, no consent, a
# consent without the opt-in, over the per-request cap, revoked consent, revoked Conduit token, elevated action.
# Legacy: service_consents / service_charges tables from before this change keep their rows and gain the columns (NULL).
set -u
W=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
S=$(mktemp -d /tmp/dustforge-cor-smoke.XXXXXX)
PORT=${PORT:-3802}; API=http://127.0.0.1:$PORT
[ -d "$W/node_modules" ] || export NODE_PATH=${NODE_PATH:-/home/flimflam/project/dustforge/node_modules}
export IDENTITY_MASTER_KEY=$(python3 -c 'import secrets;print(secrets.token_hex(32))') DB_PATH=$S/dustforge.db PORT \
  STALWART_HOST=127.0.0.1 STALWART_PORT=1 SMTP_RELAY_HOST= SMTP_HOST=127.0.0.1 SMTP_PORT=9
cd "$W"
fails=0; ok(){ echo "ok   $*"; }; fail(){ echo "FAIL $*"; fails=$((fails+1)); }
J(){ python3 -c 'import json,sys; d=json.load(sys.stdin); v=d
for k in sys.argv[1].split("."):
    v = v[int(k)] if isinstance(v, list) else (v or {}).get(k)
print(v)' "$1"; }
Q(){ python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); r=c.execute(sys.argv[2]).fetchone(); print(r[0] if r else '')" "$DB_PATH" "$1"; }
SQ(){ python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute(sys.argv[2]); c.commit()" "$DB_PATH" "$1"; }
call(){ local m=$1 p=$2 t=$3 b=${4:-}
  BODY=$(curl -s -o - -w '\n%{http_code}' -X "$m" "$API$p" -H 'Content-Type: application/json' ${t:+-H "Authorization: Bearer $t"} ${b:+-d "$b"})
  CODE=${BODY##*$'\n'}; BODY=${BODY%$'\n'*}; }
jbody(){ python3 -c 'import json,sys; print(json.dumps(dict(zip(sys.argv[1::2], [json.loads(x) if x[:1] in "[{" or x in ("true","false") or (x.lstrip("-").isdigit() and not (len(x) > 1 and x.startswith("0"))) else x for x in sys.argv[2::2]]))))' "$@"; }
withid(){ python3 -c 'import json,sys; b=json.loads(sys.argv[1]); b["approval_id"]=int(sys.argv[2]); print(json.dumps(b))' "$1" "$2"; }

# ── legacy fixture: the consent and charge tables as main had them before this change ───────────────────────────────
python3 - "$DB_PATH" <<'EOF'
import sqlite3, sys
c = sqlite3.connect(sys.argv[1])
c.executescript("""CREATE TABLE service_consents (id INTEGER PRIMARY KEY AUTOINCREMENT, payer_did TEXT NOT NULL, tenant_id INTEGER NOT NULL,
  daily_cap_dd INTEGER NOT NULL, approved_by TEXT NOT NULL, approval_id INTEGER, status TEXT NOT NULL DEFAULT 'active', created_at TEXT NOT NULL, revoked_at TEXT);
INSERT INTO service_consents (payer_did, tenant_id, daily_cap_dd, approved_by, created_at) VALUES ('did:key:zLegacyPayer', 99, 500, 'did:key:zLegacyPayer', '2026-11-07T00:00:00Z');
CREATE TABLE service_charges (id INTEGER PRIMARY KEY AUTOINCREMENT, charge_id TEXT NOT NULL UNIQUE, tenant_id INTEGER NOT NULL, payer_did TEXT NOT NULL,
  payee_did TEXT NOT NULL, action TEXT NOT NULL, cost_dd INTEGER NOT NULL, margin_pct INTEGER NOT NULL, dd INTEGER NOT NULL, token_jti TEXT NOT NULL,
  delegation_id INTEGER, idempotency_key TEXT NOT NULL, receipt TEXT NOT NULL, sig TEXT NOT NULL, created_at TEXT NOT NULL, follows_charge_id TEXT, follow_ups TEXT,
  UNIQUE (tenant_id, idempotency_key));
INSERT INTO service_charges (charge_id, tenant_id, payer_did, payee_did, action, cost_dd, margin_pct, dd, token_jti, idempotency_key, receipt, sig, created_at)
  VALUES ('sc_legacy0000000000000000', 99, 'did:key:zLegacyPayer', 'did:key:zLegacySvc', 'post', 2, 20, 3, 'abcdef0123', 'legacy-key-0001', '{}', 'x', '2026-11-07T00:00:00Z');""")
c.commit()
EOF

curl -s -o /dev/null -m 2 "$API/api/health" && { echo "port $PORT is already serving: refusing to test someone else's server (PORT=…)"; exit 1; }
node server.js >>"$S/server.log" 2>&1 & SRV=$!
for i in $(seq 1 40); do curl -s -o /dev/null "$API/api/health" && break; sleep 0.5; done
kill -0 $SRV 2>/dev/null || { echo "server died:"; tail -5 "$S/server.log"; exit 1; }
trap 'kill $SRV 2>/dev/null; rm -rf "$S"' EXIT

[ "$(Q "SELECT COALESCE(on_request_cap_dd,'null') || '/' || status FROM service_consents WHERE payer_did='did:key:zLegacyPayer'")" = null/active ] \
  && [ "$(Q "SELECT COALESCE(request_charge_id,'null') FROM service_charges WHERE charge_id='sc_legacy0000000000000000'")" = null ] \
  && ok "legacy: an old consent and an old charge are kept and gain the new columns (NULL: no Conduit requests)" || fail "legacy columns"
SQ "DELETE FROM service_consents WHERE payer_did='did:key:zLegacyPayer'"; SQ "DELETE FROM service_charges WHERE charge_id='sc_legacy0000000000000000'"

H=$(printf '%s' hunter22 | sha256sum | cut -d' ' -f1)
node -e '
const identity = require("./identity"); const Database = require("better-sqlite3");
const db = new Database(process.env.DB_PATH);
const mk = (u, bal) => { const id = identity.createIdentity(); const enc = id.encrypted_private_key || id.encryptedPrivateKey;
  db.prepare("INSERT INTO identity_wallets (did, username, email, encrypted_private_key, balance_cents, password_hash) VALUES (?, ?, ?, ?, ?, ?)").run(id.did, u, u + "@dustforge.com", enc, bal, process.argv[1]);
  db.prepare("INSERT INTO identity_transactions (did, amount_cents, type, description, balance_after) VALUES (?, ?, ?, ?, ?)").run(id.did, bal, "topup", "smoke", bal);
  return id.did; };
const owner = mk("owner", 10000); mk("ext", 5000); mk("nocon", 1000);
const f1 = db.prepare("INSERT INTO fleets (owner_did, name, slug) VALUES (?, ?, ?)").run(owner, "Owner agents", "owner-agents").lastInsertRowid;
let n = 0;
for (const u of ["fe", "cd", "ot"]) { const did = mk(u, 100);
  db.prepare("INSERT INTO fleet_silicons (fleet_id, member_did, handle, silicon_id, status, created_by_fleet, joined_via) VALUES (?, ?, ?, ?, ?, 1, ?)").run(f1, did, u, "sil_smoke" + (n++), "active", "owner"); }' "$H"
did(){ Q "SELECT did FROM identity_wallets WHERE username='$1'"; }
bal(){ Q "SELECT balance_cents FROM identity_wallets WHERE username='$1'"; }
login(){ call POST /api/identity/auth-fingerprint "" '{"username":"'$1'","password":"hunter22","scope":"'${2:-transact}'","expires_in":"2h"}'; echo "$BODY" | J token; }
mint(){ node -e '
const identity = require("./identity"); const Database = require("better-sqlite3");
const db = new Database(process.env.DB_PATH); const w = db.prepare("SELECT did, encrypted_private_key FROM identity_wallets WHERE username = ?").get(process.argv[1]);
process.stdout.write(identity.createTokenForIdentity(w.encrypted_private_key, w.did, { scope: "transact", expiresIn: "2h", metadata: { auth_method: "fleet_owner_mint", fleet: process.argv[2], username: process.argv[1] } }));' "$1" "$2"; }
OWN=$(login owner); EXT=$(login ext); NOC=$(login nocon)
FE=$(mint fe owner-agents); CD=$(mint cd owner-agents); OT=$(mint ot owner-agents)
[ "$OWN" != None ] && [ "$EXT" != None ] || { echo "FAIL sign-in"; exit 1; }
for t in "$OWN" "$EXT" "$NOC"; do call POST /api/identity/pin "$t" '{"pin":"4321","password":"hunter22"}'; [ "$CODE" = 200 ] || fail "pin set: $CODE $BODY"; done
pin(){ call POST /api/identity/gate/verify "$1" "$(jbody gate pin pin "$2" intent "$3")"; [ "$CODE" = 200 ] || fail "pin $3: $CODE $BODY"; }
approve(){ pin "$1" 4321 "approval-open:$2"; call POST /api/demipass/approvals/$2/open "$1"; local k; k=$(echo "$BODY" | J code)
  call POST /api/demipass/approvals/$2/approve "$1" "$(jbody code "$k")"; [ "$CODE" = 200 ] || fail "approve $2: $CODE $BODY"; }
# Ask (202), approve as $4, repeat with approval_id. $1 method, $2 path, $3 token, $4 approver token, $5 body JSON.
asked(){ call "$1" "$2" "$3" "$5"; AQ=$(echo "$BODY" | J approval_id); [ "$CODE" = 202 ] || return 1
  approve "$4" "$AQ"; call "$1" "$2" "$3" "$(withid "$5" "$AQ")"; }

# ── tenants, prices ─────────────────────────────────────────────────────────────────────────────────────────────
for p in "fleetengine fe" "conduit cd" "othersvc ot"; do set -- $p
  asked POST /api/services/register "$OWN" "$OWN" "$(jbody slug "$1" name "$1" service_did "$(did "$2")")"; [ "$CODE" = 201 ] || fail "register $1: $CODE $BODY"; done
call PUT /api/services/fleetengine/actions "$FE" '{"actions":[{"action":"job","scope":"job","measured_cost_dd":10,"max_cost_dd":1000},{"action":"step","scope":"job","measured_cost_dd":100,"max_cost_dd":250},{"action":"admin","scope":"admin","measured_cost_dd":5,"depth":"elevated","open":false}]}'
[ "$CODE" = 200 ] || fail "fe prices: $CODE $BODY"
asked PUT /api/services/fleetengine/actions "$FE" "$OWN" '{"actions":[{"action":"job","follow_ups":["step"]}]}'; [ "$CODE" = 200 ] || fail "fe follow_ups: $CODE $BODY"
call PUT /api/services/conduit/actions "$CD" '{"actions":[{"action":"post","scope":"post","measured_cost_dd":1,"max_cost_dd":100}]}'; [ "$CODE" = 200 ] || fail "cd prices: $CODE $BODY"
call PUT /api/services/othersvc/actions "$OT" '{"actions":[{"action":"job","scope":"job","measured_cost_dd":10,"max_cost_dd":1000}]}'; [ "$CODE" = 200 ] || fail "ot prices: $CODE $BODY"

# ── consents: Conduit for posting; fleetengine WITHOUT the opt-in first ─────────────────────────────────────────
asked POST /api/services/consent "$EXT" "$EXT" '{"service":"conduit","daily_cap_dd":1000}'; [ "$CODE" = 201 ] || fail "ext conduit consent: $CODE $BODY"
asked POST /api/services/consent "$NOC" "$NOC" '{"service":"conduit","daily_cap_dd":1000}'; [ "$CODE" = 201 ] || fail "nocon conduit consent: $CODE $BODY"
asked POST /api/services/consent "$EXT" "$EXT" '{"service":"fleetengine","daily_cap_dd":3000}'; [ "$CODE" = 201 ] || fail "ext fe consent: $CODE $BODY"
asked POST /api/services/consent "$EXT" "$EXT" '{"service":"othersvc","daily_cap_dd":3000,"on_request_cap_dd":500}'; [ "$CODE" = 201 ] || fail "ext ot consent: $CODE $BODY"

# The payer's Conduit service token; Conduit verifies it for post.
ctok(){ call POST /api/services/token "$1" '{"service":"conduit","cap_dd":500}'; CT=$(echo "$BODY" | J token); CTID=$(echo "$BODY" | J token_id)
  call POST /api/services/verify "$CD" "$(jbody token "$CT" action post)"; [ "$CODE" = 200 ] || fail "cd verify: $CODE $BODY"; }
sha(){ printf '%s' "$1" | sha256sum | cut -d' ' -f1; }
rkey(){ node -e 'process.stdout.write(require("./service_tenants").requestKey(process.argv[1], process.argv[2], process.argv[3]))' "$1" "$2" "$3"; }
# Conduit charges a post of message $1 with nonce $2 addressed to wallet $3, on token $CTID → RC (charge id).
post(){ call POST /api/services/charge "$CD" "$(jbody action post cost_dd 1 token_id "$CTID" idempotency_key "$(rkey "$3" "$(sha "$1")" "$2")")"; RC=$(echo "$BODY" | J charge_id)
  [ "$CODE" = 201 ] || fail "conduit post charge: $CODE $BODY"; }
COR(){ call POST /api/services/charge-on-request "$1" "$2"; }
ctok "$EXT"
MSG='run audit on atlas/fleetengine main'; MS=$(sha "$MSG")
post "$MSG" nonce-0001 "$(did fe)"; RC1=$RC

COR "$FE" "$(jbody action job cost_dd 10 idempotency_key cor-0001 request_charge_id "$RC1" message_sha256 "$MS" request_nonce nonce-0001)"
[ "$CODE" = 402 ] && [ "$(echo "$BODY" | J on_request_required)" = True ] && ok "a consent that did not opt in is never charged on a Conduit request (402 on_request_required)" || fail "no opt-in: $CODE $BODY"
call POST /api/services/consent "$EXT" '{"service":"fleetengine","daily_cap_dd":3000,"on_request_cap_dd":3001}'; [ "$CODE" = 400 ] && ok "on_request_cap_dd above the daily cap is refused" || fail "orc > cap: $CODE"
call POST /api/services/consent "$EXT" '{"service":"fleetengine","daily_cap_dd":3000,"on_request_cap_dd":500}'; OQ=$(echo "$BODY" | J approval_id)
[ "$CODE" = 202 ] && Q "SELECT summary FROM use_approvals WHERE id=$OQ" | grep -q "Conduit requests up to 500 DD each" && ok "the opt-in is part of what the person approves (named on the card)" || fail "opt-in card: $CODE $(Q "SELECT summary FROM use_approvals WHERE id=$OQ")"
call POST /api/services/consent "$EXT" "$(withid '{"service":"fleetengine","daily_cap_dd":3000,"on_request_cap_dd":900}' "$OQ")"; A1=$CODE
approve "$EXT" "$OQ"; call POST /api/services/consent "$EXT" "$(withid '{"service":"fleetengine","daily_cap_dd":3000,"on_request_cap_dd":500}' "$OQ")"
[ "$A1" != 201 ] && [ "$CODE" = 201 ] && [ "$(echo "$BODY" | J on_request_cap_dd)" = 500 ] && ok "approved as asked (500 DD a request); a different cap on the same approval is not accepted" || fail "opt-in consent: $A1 $CODE $BODY"

# ── the happy path ──────────────────────────────────────────────────────────────────────────────────────────────
N0=$(Q "SELECT COUNT(*) FROM service_charges"); E0=$(bal ext)
COR "$FE" "$(jbody action job cost_dd 10 request_charge_id "$RC1" message_sha256 "$MS" request_nonce nonce-0001 dry_run true)"
[ "$CODE" = 200 ] && [ "$(echo "$BODY" | J would_charge_dd)" = 12 ] && [ "$(echo "$BODY" | J payer)" = "$(did ext)" ] && [ "$(Q "SELECT COUNT(*) FROM service_charges")" = "$N0" ] \
  && ok "dry run: what it would charge and who pays, nothing written" || fail "dry: $CODE $BODY"
COR "$FE" "$(jbody action job cost_dd 10 idempotency_key cor-0001 request_charge_id "$RC1" message_sha256 "$MS" request_nonce nonce-0001)"; ORG=$(echo "$BODY" | J charge_id)
[ "$CODE" = 201 ] && [ "$(echo "$BODY" | J requested_by)" = "$RC1" ] && [ "$(echo "$BODY" | J payer)" = "$(did ext)" ] && [ "$(echo "$BODY" | J dd)" = 12 ] \
  && [ "$(echo "$BODY" | J follow_up_dd)" = 488 ] && [ "$(bal ext)" = $((E0 - 12)) ] \
  && ok "charged on the Conduit request: ext pays 12 DD, no service token; follow-up budget = 500 − 12" || fail "cor: $CODE $BODY"
R=$(echo "$BODY" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(json.dumps({"receipt":d["receipt"],"sig":d["sig"]}))')
call POST /api/services/receipts/verify "" "$R"
[ "$(echo "$BODY" | J valid)" = True ] && [ "$(echo "$BODY" | J charge.requested_by)" = "$RC1" ] && [ "$(echo "$BODY" | J charge.message_sha256)" = "$MS" ] \
  && ok "the receipt verifies offline and names the Conduit charge and message it was made on" || fail "receipt: $BODY"
COR "$FE" "$(jbody action job cost_dd 10 idempotency_key cor-0001 request_charge_id "$RC1" message_sha256 "$MS" request_nonce nonce-0001)"
[ "$CODE" = 200 ] && [ "$(echo "$BODY" | J replayed)" = True ] && [ "$(bal ext)" = $((E0 - 12)) ] && ok "a retry with the same key replays (no second debit)" || fail "replay: $CODE $BODY"
COR "$FE" "$(jbody action job cost_dd 10 idempotency_key cor-0002 request_charge_id "$RC1" message_sha256 "$MS" request_nonce nonce-0001)"
[ "$CODE" = 409 ] && [ "$(echo "$BODY" | J charge_id)" = "$ORG" ] && [ "$(bal ext)" = $((E0 - 12)) ] && ok "a replayed request_charge_id under a new key: 409, one origin per Conduit request" || fail "replayed request: $CODE $BODY"

# ── follow-ups of a request origin ──────────────────────────────────────────────────────────────────────────────
C(){ call POST /api/services/charge "$FE" "$1"; }
C "$(jbody action step cost_dd 100 follow_up_of "$ORG" idempotency_key cor-fu-0001)"; A1=$CODE
C "$(jbody action step cost_dd 250 follow_up_of "$ORG" idempotency_key cor-fu-0002)"; A2=$CODE      # 120 + 300 = 420 of 488
C "$(jbody action step cost_dd 100 follow_up_of "$ORG" idempotency_key cor-fu-0003)"; A3=$CODE      # + 120 > 488
[ "$A1" = 201 ] && [ "$A2" = 201 ] && [ "$A3" = 402 ] && [ "$(echo "$BODY" | J follow_up_budget_exceeded)" = True ] && [ "$(bal ext)" = $((E0 - 12 - 420)) ] \
  && ok "follow-ups bill as usual and stop at the per-request cap (origin + follow-ups ≤ 500)" || fail "cor follow-ups: $A1 $A2 $A3 $BODY"
TJ=$(Q "SELECT token_jti FROM service_charges WHERE charge_id='$ORG'")
C "$(jbody action job cost_dd 10 token_id "$TJ" idempotency_key cor-ord-0001)"; A1=$CODE
C "$(jbody action step cost_dd 10 token_id "$TJ" dry_run true)"; A2=$CODE
[ "$A1" = 403 ] && [ "$A2" = 403 ] && ok "the per-request row cannot be used for an ordinary charge (never verified for any action)" || fail "ordinary on request row: $A1 $A2"

# ── adversarial ─────────────────────────────────────────────────────────────────────────────────────────────────
M2='second request'; MS2=$(sha "$M2")
post "$M2" nonce-0002 "$(did ot)"; RCO=$RC          # a message to othersvc
COR "$FE" "$(jbody action job cost_dd 10 idempotency_key cor-adv-0001 request_charge_id "$RCO" message_sha256 "$MS2" request_nonce nonce-0002)"; A1=$CODE
COR "$OT" "$(jbody action job cost_dd 10 idempotency_key cor-adv-0002 request_charge_id "$RC1" message_sha256 "$MS" request_nonce nonce-0001)"; A2=$CODE
[ "$A1" = 403 ] && [ "$A2" = 403 ] && ok "a request to another tenant is not this tenant's to charge (either way round)" || fail "other tenant: $A1 $A2"
post "$M2" nonce-0003 "$(did fe)"; RC3=$RC
COR "$FE" "$(jbody action job cost_dd 10 idempotency_key cor-adv-0003 request_charge_id "$RC3" message_sha256 "$(sha 'other bytes')" request_nonce nonce-0003)"; A1=$CODE
COR "$FE" "$(jbody action job cost_dd 10 idempotency_key cor-adv-0004 request_charge_id "$RC3" message_sha256 "$MS2" request_nonce nonce-9999)"; A2=$CODE
[ "$A1" = 403 ] && [ "$A2" = 403 ] && ok "other message bytes, or another nonce: 403 (the Conduit charge binds both)" || fail "bytes/nonce: $A1 $A2"
# Forged: a row nobody here signed, keyed exactly right; and a real row whose payer was rewritten.
FK=$(rkey "$(did fe)" "$MS2" nonce-forged)
SQ "INSERT INTO service_charges (charge_id, tenant_id, payer_did, payee_did, action, cost_dd, margin_pct, dd, token_jti, idempotency_key, receipt, sig, created_at)
    VALUES ('sc_f0f0f0f0f0f0f0f0f0f0f0f0', (SELECT id FROM service_tenants WHERE slug='conduit'), '$(did ext)', '$(did cd)', 'post', 1, 20, 2, '$CTID', '$FK',
    '{\"charge_id\":\"sc_f0f0f0f0f0f0f0f0f0f0f0f0\",\"service\":\"conduit\",\"payer\":\"$(did ext)\",\"action\":\"post\",\"idempotency_key\":\"$FK\",\"token_id\":\"$CTID\"}', 'AAAA', strftime('%Y-%m-%dT%H:%M:%fZ','now'))"
COR "$FE" "$(jbody action job cost_dd 10 idempotency_key cor-adv-0005 request_charge_id sc_f0f0f0f0f0f0f0f0f0f0f0f0 message_sha256 "$MS2" request_nonce nonce-forged)"; A1=$CODE
post "$M2" nonce-0004 "$(did fe)"; RC4=$RC
SQ "UPDATE service_charges SET payer_did='$(did nocon)' WHERE charge_id='$RC4'"
COR "$FE" "$(jbody action job cost_dd 10 idempotency_key cor-adv-0006 request_charge_id "$RC4" message_sha256 "$MS2" request_nonce nonce-0004)"; A2=$CODE
[ "$A1" = 403 ] && [ "$A2" = 403 ] && [ "$(bal nocon)" = 1000 ] && ok "a forged Conduit row (bad signature) or a rewritten payer: 403, nobody charged" || fail "forged: $A1 $A2 $BODY"
post "$M2" nonce-0005 "$(did fe)"; RC5=$RC
SQ "UPDATE service_charges SET created_at='$(python3 -c 'import datetime as d; print((d.datetime.utcnow()-d.timedelta(minutes=11)).isoformat()+"Z")')' WHERE charge_id='$RC5'"
COR "$FE" "$(jbody action job cost_dd 10 idempotency_key cor-adv-0007 request_charge_id "$RC5" message_sha256 "$MS2" request_nonce nonce-0005)"
[ "$CODE" = 403 ] && echo "$BODY" | grep -q 'older than 10 minutes' && ok "a Conduit request older than 10 minutes: 403" || fail "stale: $CODE $BODY"
COR "$FE" "$(jbody action job cost_dd 10 idempotency_key cor-0001 request_charge_id "$RC1" message_sha256 "$MS" request_nonce nonce-0001)"
SQ "UPDATE service_charges SET created_at='2026-01-01T00:00:00.000Z' WHERE charge_id='$RC1'"
COR "$FE" "$(jbody action job cost_dd 10 idempotency_key cor-0001 request_charge_id "$RC1" message_sha256 "$MS" request_nonce nonce-0001)"
[ "$CODE" = 200 ] && [ "$(echo "$BODY" | J replayed)" = True ] && ok "…but a retry of a charge already made still replays after the window" || fail "late replay: $CODE $BODY"
post "$M2" nonce-0006 "$(did fe)"; RC6=$RC
COR "$FE" "$(jbody action job cost_dd 450 idempotency_key cor-adv-0008 request_charge_id "$RC6" message_sha256 "$MS2" request_nonce nonce-0006)"
[ "$CODE" = 402 ] && [ "$(echo "$BODY" | J on_request_cap_exceeded)" = True ] && ok "over the per-request cap (450 → 540 > 500): 402" || fail "over cap: $CODE $BODY"
COR "$FE" "$(jbody action admin cost_dd 5 idempotency_key cor-adv-0009 request_charge_id "$RC6" message_sha256 "$MS2" request_nonce nonce-0006)"
[ "$CODE" = 403 ] && ok "an elevated action is never charged on a Conduit request" || fail "elevated: $CODE $BODY"
COR "$CD" "$(jbody action post cost_dd 1 idempotency_key cor-adv-0010 request_charge_id "$RC6" message_sha256 "$MS2" request_nonce nonce-0006)"; A1=$CODE
COR "$EXT" "$(jbody action job cost_dd 10 idempotency_key cor-adv-0011 request_charge_id "$RC6" message_sha256 "$MS2" request_nonce nonce-0006)"; A2=$CODE
[ "$A1" = 400 ] && [ "$A2" = 403 ] && ok "Conduit cannot charge on its own requests; a non-tenant cannot call the route" || fail "callers: $A1 $A2"
# No consent at all: nocon posts to fleetengine.
ctok "$NOC"; post "$M2" nonce-0007 "$(did fe)"; RC7=$RC
COR "$FE" "$(jbody action job cost_dd 10 idempotency_key cor-adv-0012 request_charge_id "$RC7" message_sha256 "$MS2" request_nonce nonce-0007)"
[ "$CODE" = 402 ] && [ "$(echo "$BODY" | J consent_required)" = True ] && [ "$(bal nocon)" -ge 997 ] && ok "a payer with no consent to the tenant: 402" || fail "no consent: $CODE $BODY"

# ── withdrawal: consent revoked, opt-in dropped, Conduit token revoked ─────────────────────────────────────────
ctok "$EXT"; post "$M2" nonce-0008 "$(did fe)"; RC8=$RC
COR "$FE" "$(jbody action job cost_dd 10 idempotency_key cor-w-0001 request_charge_id "$RC8" message_sha256 "$MS2" request_nonce nonce-0008)"; ORG8=$(echo "$BODY" | J charge_id)
[ "$CODE" = 201 ] || fail "origin 8: $CODE $BODY"
CID=$(Q "SELECT id FROM service_consents WHERE payer_did='$(did ext)' AND tenant_id=(SELECT id FROM service_tenants WHERE slug='fleetengine') AND status='active'")
call POST /api/services/consents/$CID/revoke "$EXT"; [ "$CODE" = 200 ] || fail "revoke consent: $CODE"
C "$(jbody action step cost_dd 10 follow_up_of "$ORG8" idempotency_key cor-w-0002)"; A1=$CODE
post "$M2" nonce-0009 "$(did fe)"; RC9=$RC
COR "$FE" "$(jbody action job cost_dd 10 idempotency_key cor-w-0003 request_charge_id "$RC9" message_sha256 "$MS2" request_nonce nonce-0009)"; A2=$CODE
COR "$FE" "$(jbody action job cost_dd 10 idempotency_key cor-w-0001 request_charge_id "$RC8" message_sha256 "$MS2" request_nonce nonce-0008)"; A3=$CODE
[ "$A1" = 402 ] && [ "$A2" = 402 ] && [ "$A3" = 409 ] && ok "consent revoked: follow-ups and new requests 402; the origin's replay is no go-ahead (409)" || fail "revoked consent: $A1 $A2 $A3"
asked POST /api/services/consent "$EXT" "$EXT" '{"service":"fleetengine","daily_cap_dd":3000}'; [ "$CODE" = 201 ] || fail "re-consent w/o opt-in: $CODE"
C "$(jbody action step cost_dd 10 follow_up_of "$ORG8" idempotency_key cor-w-0004)"
[ "$CODE" = 402 ] && [ "$(echo "$BODY" | J on_request_required)" = True ] && ok "a new consent without the opt-in does not revive request work" || fail "opt-in dropped: $CODE $BODY"
asked POST /api/services/consent "$EXT" "$EXT" '{"service":"fleetengine","daily_cap_dd":3000,"on_request_cap_dd":500}'; [ "$CODE" = 201 ] || fail "re-consent: $CODE"
C "$(jbody action step cost_dd 10 follow_up_of "$ORG8" idempotency_key cor-w-0005)"; [ "$CODE" = 201 ] || fail "follow-up after re-consent: $CODE $BODY"
post "$M2" nonce-0010 "$(did fe)"; RC10=$RC
call POST /api/services/token/revoke "$EXT" "$(jbody token_id "$CTID")"; [ "$CODE" = 200 ] || fail "revoke conduit token: $CODE"
COR "$FE" "$(jbody action job cost_dd 10 idempotency_key cor-w-0006 request_charge_id "$RC10" message_sha256 "$MS2" request_nonce nonce-0010)"; A1=$CODE
C "$(jbody action step cost_dd 10 follow_up_of "$ORG8" idempotency_key cor-w-0007)"; A2=$CODE
[ "$A1" = 401 ] && [ "$A2" = 401 ] && ok "the Conduit token that posted it revoked: no new charge on its requests, and their follow-ups stop" || fail "revoked conduit token: $A1 $A2 $BODY"

grep -q "$CT" "$S/server.log" && fail "a service token reached the server log" || ok "no token in the server log"
[ $fails -gt 0 ] && { echo "--- server.log"; grep -i -m8 "error" "$S/server.log"; }
echo "$fails failure(s)"; exit $(( fails > 0 ))
