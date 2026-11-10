#!/bin/bash
# End-to-end smoke of service tenants (service_tenants.js, docs/service-tenants.md) through the real server, throwaway DB.
# People (PINs): owner (has a fleet), otherowner (another fleet), ext (an outside wallet), poor (5 DD). Silicons of owner's
# fleet: fg (FLEETGATE's wallet), cd (Conduit's), agent. A silicon of otherowner's fleet: stranger.
#   - legacy: a use_approvals table from before this change (no service_key) keeps its rows and gains the column;
#   - legacy: a service_tenants table from before endpoint/mcp_server keeps its row and gains both (''); connect
#     (PUT /api/services/:slug/connect) waits on the tenant owner's approval, validates the URL, and is listed;
#   - a charge retried with another token of the same wallet replays; another wallet's token with that key → 409;
#   - registration, consent to pay, and weakening a gate each wait on a person's approval in the app (PIN to open):
#     a token alone asks, never grants (#68 review H1, M3);
#   - prices: cost + margin, public; service tokens: audience-locked, refused by every other DemiPass route;
#   - verify: wallet, token id, scope, depth, via — never a username or email, not even in a 202 (M1);
#   - charge: only for an action verified on that token (M2); debit + credit together, both rows carry the token;
#     replay/conflict; 402 for no consent, no money, token cap, daily cap; the receipt verifies offline, only as a
#     service receipt;
#   - delegation: only to your own fleet's agents (H2); the delegate's elevated call waits on the owner, bound to that
#     authority; pairwise principal; revoke, parent-token revoke and fleet removal end access (M4).
set -u
W=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
S=$(mktemp -d /tmp/dustforge-svc-smoke.XXXXXX)
PORT=${PORT:-3801}; API=http://127.0.0.1:$PORT
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
call(){ local m=$1 p=$2 t=$3 b=${4:-}
  BODY=$(curl -s -o - -w '\n%{http_code}' -X "$m" "$API$p" -H 'Content-Type: application/json' ${t:+-H "Authorization: Bearer $t"} ${b:+-d "$b"})
  CODE=${BODY##*$'\n'}; BODY=${BODY%$'\n'*}; }
jbody(){ python3 -c 'import json,sys; print(json.dumps(dict(zip(sys.argv[1::2], [json.loads(x) if x[:1] in "[{" or x in ("true","false") or (x.lstrip("-").isdigit() and not (len(x) > 1 and x.startswith("0"))) else x for x in sys.argv[2::2]]))))' "$@"; }

# ── legacy fixture: use_approvals as main had it (no service_key), with one pending secret request ──────────────────
python3 - "$DB_PATH" <<'EOF'
import sqlite3, sys
c = sqlite3.connect(sys.argv[1])
c.executescript("""CREATE TABLE use_approvals (id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL DEFAULT 'use', secret_id INTEGER NOT NULL,
  owner_did TEXT NOT NULL, requester_did TEXT NOT NULL, requester_label TEXT DEFAULT '', delegation_id INTEGER, depth TEXT NOT NULL,
  purpose TEXT DEFAULT '', summary TEXT DEFAULT '', binding TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending', code_key TEXT NOT NULL,
  created_at TEXT NOT NULL, expires_at TEXT NOT NULL, opened_at TEXT, opened_session TEXT, opened_via TEXT, approved_at TEXT, approved_via TEXT,
  used_at TEXT, decided_at TEXT, wrong_codes INTEGER DEFAULT 0, notified_at TEXT, bound_call TEXT DEFAULT '', eph_pub TEXT DEFAULT NULL, unwrap_blob TEXT DEFAULT NULL);
INSERT INTO use_approvals (secret_id, owner_did, requester_did, depth, binding, code_key, created_at, expires_at, status)
  VALUES (7, 'did:key:zLegacyOwner', 'did:key:zLegacyAgent', 'elevated', 'b1', 'aa', '2026-11-01T00:00:00Z', '2026-11-01T00:05:00Z', 'used');
CREATE TABLE service_tenants (id INTEGER PRIMARY KEY AUTOINCREMENT, slug TEXT NOT NULL UNIQUE, name TEXT NOT NULL, service_did TEXT NOT NULL UNIQUE,
  owner_did TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'active', created_by TEXT NOT NULL, approval_id INTEGER, created_at TEXT NOT NULL);
INSERT INTO service_tenants (slug, name, service_did, owner_did, created_by, created_at)
  VALUES ('legacy-svc', 'Legacy', 'did:key:zLegacySvc', 'did:key:zLegacyOwner', 'did:key:zLegacyOwner', '2026-11-07T00:00:00Z');""")
c.commit()
EOF

start(){ node server.js >>"$S/server.log" 2>&1 & SRV=$!
  for i in $(seq 1 40); do curl -s -o /dev/null "$API/api/health" && break; sleep 0.5; done
  kill -0 $SRV 2>/dev/null || { echo "server died:"; tail -5 "$S/server.log"; exit 1; }; }
start
trap 'kill $SRV 2>/dev/null; rm -rf "$S"' EXIT

[ "$(Q "SELECT COUNT(*) FROM pragma_table_info('use_approvals') WHERE name='service_key'")" = 1 ] && [ "$(Q "SELECT status || '/' || COALESCE(service_key,'null') FROM use_approvals WHERE id=1")" = used/null ] \
  && ok "legacy use_approvals: the old row is kept, service_key added (NULL)" || fail "legacy migration"
call GET /api/services/legacy-svc ""
[ "$CODE" = 200 ] && [ "$(echo "$BODY" | J endpoint)" = None ] && [ "$(echo "$BODY" | J mcp_server)" = None ] \
  && [ "$(Q "SELECT COUNT(*) FROM pragma_table_info('service_tenants') WHERE name IN ('endpoint','mcp_server')")" = 2 ] \
  && ok "legacy service_tenants: the old row is kept, endpoint and mcp_server added (empty → null in the view)" || fail "legacy tenants: $CODE $BODY"
python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute(\"DELETE FROM service_tenants WHERE slug='legacy-svc'\"); c.commit()" "$DB_PATH"

H=$(printf '%s' hunter22 | sha256sum | cut -d' ' -f1)
node -e '
const identity = require("./identity"); const Database = require("better-sqlite3");
const db = new Database(process.env.DB_PATH);
const mk = (u, bal) => { const id = identity.createIdentity(); const enc = id.encrypted_private_key || id.encryptedPrivateKey;
  db.prepare("INSERT INTO identity_wallets (did, username, email, encrypted_private_key, balance_cents, password_hash) VALUES (?, ?, ?, ?, ?, ?)").run(id.did, u, u + "@dustforge.com", enc, bal, process.argv[1]);
  db.prepare("INSERT INTO identity_transactions (did, amount_cents, type, description, balance_after) VALUES (?, ?, ?, ?, ?)").run(id.did, bal, "topup", "smoke", bal);
  return id.did; };
const owner = mk("owner", 10000), other = mk("otherowner", 1000);
mk("ext", 1000); mk("poor", 5);
const f1 = db.prepare("INSERT INTO fleets (owner_did, name, slug) VALUES (?, ?, ?)").run(owner, "Owner agents", "owner-agents").lastInsertRowid;
const f2 = db.prepare("INSERT INTO fleets (owner_did, name, slug) VALUES (?, ?, ?)").run(other, "Other", "other-agents").lastInsertRowid;
let n = 0;
for (const [u, f, bal] of [["fg", f1, 100], ["cd", f1, 100], ["agent", f1, 500], ["stranger", f2, 500]]) {
  const did = mk(u, bal);
  db.prepare("INSERT INTO fleet_silicons (fleet_id, member_did, handle, silicon_id, status, created_by_fleet, joined_via) VALUES (?, ?, ?, ?, ?, 1, ?)").run(f, did, u, "sil_smoke" + (n++), "active", "owner");
}' "$H"
did(){ Q "SELECT did FROM identity_wallets WHERE username='$1'"; }
bal(){ Q "SELECT balance_cents FROM identity_wallets WHERE username='$1'"; }
login(){ call POST /api/identity/auth-fingerprint "" '{"username":"'$1'","password":"hunter22","scope":"'${2:-transact}'","expires_in":"2h"}'; echo "$BODY" | J token; }
# A silicon's token as its fleet owner mints it (fleet_owner_mint): how agents sign in.
mint(){ node -e '
const identity = require("./identity"); const Database = require("better-sqlite3");
const db = new Database(process.env.DB_PATH); const w = db.prepare("SELECT did, encrypted_private_key FROM identity_wallets WHERE username = ?").get(process.argv[1]);
process.stdout.write(identity.createTokenForIdentity(w.encrypted_private_key, w.did, { scope: "transact", expiresIn: "2h", metadata: { auth_method: "fleet_owner_mint", fleet: process.argv[2], username: process.argv[1] } }));' "$1" "$2"; }
OWN=$(login owner); EXT=$(login ext); POOR=$(login poor); EXTR=$(login ext read)
FG=$(mint fg owner-agents); CD=$(mint cd owner-agents); AG=$(mint agent owner-agents); STR=$(mint stranger other-agents)
[ "$OWN" != None ] && [ "$EXT" != None ] || { echo "FAIL sign-in"; exit 1; }
OTH=$(login otherowner)
for t in "$OWN" "$OTH" "$EXT" "$POOR"; do call POST /api/identity/pin "$t" '{"pin":"4321","password":"hunter22"}'; [ "$CODE" = 200 ] || fail "pin set: $CODE $BODY"; done
pin(){ call POST /api/identity/gate/verify "$1" "$(jbody gate pin pin "$2" intent "$3")"; [ "$CODE" = 200 ] || fail "pin $3: $CODE $BODY"; }

# Approve request $2 as person token $1 (PIN 4321): open with the PIN, approve with the screen's code.
approve(){ pin "$1" 4321 "approval-open:$2"; call POST /api/demipass/approvals/$2/open "$1"; local k; k=$(echo "$BODY" | J code)
  call POST /api/demipass/approvals/$2/approve "$1" "$(jbody code "$k")"; [ "$CODE" = 200 ] || fail "approve $2: $CODE $BODY"; }
# Ask (202 → approval id), approve as $3, repeat with approval_id. $1 path, $2 token, $3 approver token, $4 body JSON.
asked(){ call POST "$1" "$2" "$4"; AQ=$(echo "$BODY" | J approval_id); [ "$CODE" = 202 ] || return 1
  approve "$3" "$AQ"; call POST "$1" "$2" "$(python3 -c 'import json,sys; b=json.loads(sys.argv[1]); b["approval_id"]=int(sys.argv[2]); print(json.dumps(b))' "$4" "$AQ")"; }
noname(){ ! echo "$BODY" | grep -q -E '"owner"|"ext"|"otherowner"|@dustforge.com|'"$(did owner)"; }

# ── registration (approved on the owner's phone) ────────────────────────────────────────────────────────────────
call POST /api/services/register "$EXT" "$(jbody slug fleetgate service_did "$(did fg)")"; [ "$CODE" = 403 ] && ok "a stranger cannot register someone else's wallet as a tenant" || fail "ext register fg: $CODE $BODY"
call POST /api/services/register "$FG" '{"slug":"fleetgate","name":"FLEETGATE"}'; R1=$(echo "$BODY" | J approval_id)
[ "$CODE" = 202 ] && [ "$(Q "SELECT owner_did FROM use_approvals WHERE id=$R1")" = "$(did owner)" ] && [ "$(Q "SELECT COUNT(*) FROM service_tenants")" = 0 ] && noname \
  && ok "a silicon asking to register itself waits on its fleet owner's approval (202, nothing registered, no name in the reply)" || fail "fg register ask: $CODE $BODY"
call POST /api/services/register "$FG" "$(jbody slug fleetgate name FLEETGATE approval_id "$R1")"; [ "$CODE" = 202 ] && ok "…repeating before approval: still pending" || fail "fg early: $CODE"
approve "$OWN" "$R1"; call POST /api/services/register "$FG" "$(jbody slug fleetgate name FLEETGATE approval_id "$R1")"
[ "$CODE" = 201 ] && [ "$(Q "SELECT owner_did FROM service_tenants WHERE slug='fleetgate'")" = "$(did owner)" ] && ok "approved: FLEETGATE registered, owned by the fleet owner" || fail "fg register: $CODE $BODY"
call POST /api/services/register "$AG" "$(jbody slug conduit service_did "$(did cd)")"; [ "$CODE" = 403 ] && ok "an agent token cannot register another silicon" || fail "agent register cd: $CODE $BODY"
asked /api/services/register "$OWN" "$OWN" "$(jbody slug conduit name Conduit service_did "$(did cd)")"
[ "$CODE" = 201 ] && [ "$(echo "$BODY" | J owner_is_you)" = True ] && ok "the owner registers its own silicon as Conduit (own approval)" || fail "owner register cd: $CODE $BODY"
call POST /api/services/register "$OWN" "$(jbody slug conduit service_did "$(did agent)")"; [ "$CODE" = 409 ] && ok "a taken slug → 409" || fail "dup slug: $CODE"
call POST /api/services/register "$EXT" '{"slug":"demipass"}'; [ "$CODE" = 400 ] && ok "reserved slugs are refused" || fail "reserved: $CODE"

# ── prices ──────────────────────────────────────────────────────────────────────────────────────────────────────
FGA='{"actions":[{"action":"submit","scope":"submit","measured_cost_dd":20},{"action":"review","scope":"submit","measured_cost_dd":100,"max_cost_dd":300},{"action":"sign-charter","scope":"charter","measured_cost_dd":5,"depth":"elevated","open":false},{"action":"broadcast","scope":"broadcast","measured_cost_dd":5,"depth":"elevated"}]}'
call PUT /api/services/fleetgate/actions "$EXT" "$FGA"; [ "$CODE" = 403 ] && ok "only the tenant (or its owner) sets prices" || fail "ext prices: $CODE"
call PUT /api/services/fleetgate/actions "$FG" "$FGA"; [ "$CODE" = 200 ] || fail "fg prices: $CODE $BODY"
call PUT /api/services/conduit/actions "$CD" '{"actions":[{"action":"post","scope":"post","measured_cost_dd":2}]}'; [ "$CODE" = 200 ] || fail "cd prices: $CODE $BODY"
call GET /api/services/fleetgate ""
[ "$CODE" = 200 ] && [ "$(echo "$BODY" | J margin_pct)" = 20 ] && [ "$(echo "$BODY" | python3 -c 'import json,sys; a={x["action"]:x for x in json.load(sys.stdin)["actions"]}; print(a["submit"]["price_dd"], a["review"]["max_price_dd"])')" = "24 360" ] \
  && ok "public price list: measured cost + 20% margin (submit 20 → 24; review max 300 → 360)" || fail "price list: $CODE $BODY"

# ── where callers connect (registry: endpoint + mcp_server; every change waits on the tenant owner) ─────────────
call PUT /api/services/fleetgate/connect "$EXT" '{"endpoint":"https://evil.example/door"}'; [ "$CODE" = 403 ] && ok "only the tenant (or its owner) sets where callers connect" || fail "ext connect: $CODE"
bad=0; for e in 'http://evil.example/door' 'https://u:p@repo.example/door' 'https://repo.example/door?x=1' 'ftp://repo.example' 'nope' \
    'http://x.ts.net\\@evil.com/door' 'HTTPS://Repo.Example/door' 'http://evil.ts.net.attacker.com/door' 'https://repo.example/a b'; do
  call PUT /api/services/fleetgate/connect "$FG" "$(jbody endpoint "$e")"; [ "$CODE" = 400 ] || { bad=1; echo "  $e → $CODE"; }; done
call PUT /api/services/fleetgate/connect "$FG" '{"mcp_server":"demipass fleetgate"}'; [ "$CODE" = 400 ] || bad=1
call PUT /api/services/fleetgate/connect "$FG" '{"mcp_server":"evilpkg#x"}'; [ "$CODE" = 403 ] || { bad=1; echo "  third-party mcp → $CODE"; }
[ $bad = 0 ] && ok "endpoint: https (http only on *.ts.net), plain normal-form ASCII, no credentials/query/backslash; mcp_server first-party package#bin" || fail "connect validation"
CB='{"endpoint":"https://repo.example/-/fleetgate/door/","mcp_server":"demipass#fleetgate-mcp"}'
call PUT /api/services/fleetgate/connect "$FG" "$CB"; CQ=$(echo "$BODY" | J approval_id)
[ "$CODE" = 202 ] && [ "$(Q "SELECT owner_did FROM use_approvals WHERE id=$CQ")" = "$(did owner)" ] && [ "$(Q "SELECT endpoint FROM service_tenants WHERE slug='fleetgate'")" = "" ] \
  && ok "a connect change waits on the tenant owner's approval (202, nothing changed)" || fail "connect ask: $CODE $BODY"
approve "$OWN" "$CQ"; call PUT /api/services/fleetgate/connect "$FG" "$(python3 -c 'import json,sys; b=json.loads(sys.argv[1]); b["approval_id"]=int(sys.argv[2]); print(json.dumps(b))' "$CB" "$CQ")"
[ "$CODE" = 200 ] && [ "$(echo "$BODY" | J endpoint)" = https://repo.example/-/fleetgate/door ] && [ "$(echo "$BODY" | J mcp_server)" = demipass#fleetgate-mcp ] \
  && ok "approved: endpoint (trailing / trimmed) and mcp_server set" || fail "connect: $CODE $BODY"
call GET /api/services ""; [ "$(echo "$BODY" | python3 -c 'import json,sys; print([t.get("endpoint") for t in json.load(sys.stdin)["tenants"] if t["slug"]=="fleetgate"][0])')" = https://repo.example/-/fleetgate/door ] \
  && ok "the public registry lists the endpoint (clients read it; nothing hard-codes a URL)" || fail "registry: $BODY"
call PUT /api/services/fleetgate/connect "$FG" '{"endpoint":"https://repo.example/-/fleetgate/door"}'; [ "$CODE" = 200 ] && [ "$(echo "$BODY" | J unchanged)" = True ] && ok "the same values again: no approval asked" || fail "unchanged: $CODE $BODY"
call PUT /api/services/conduit/connect "$OWN" '{"endpoint":"http://phasewhip.taildb5a42.ts.net:8080"}'; [ "$CODE" = 202 ] && ok "http on a tailnet *.ts.net host is allowed (and still waits on approval)" || fail "ts.net: $CODE $BODY"

# ── consent to pay (approved by the person who answers for the wallet) ─────────────────────────────────────────
call POST /api/services/token "$EXT" '{"service":"fleetgate"}'; [ "$CODE" = 403 ] && [ "$(echo "$BODY" | J consent_required)" = True ] && ok "no service token without consent to pay that service" || fail "mint w/o consent: $CODE $BODY"
call POST /api/services/consent "$AG" '{"service":"fleetgate","daily_cap_dd":5000}'; AGC=$(echo "$BODY" | J approval_id)
[ "$CODE" = 202 ] && [ "$(Q "SELECT owner_did FROM use_approvals WHERE id=$AGC")" = "$(did owner)" ] && [ "$(Q "SELECT COUNT(*) FROM service_consents")" = 0 ] \
  && ok "an agent's consent to pay waits on its fleet owner (a token alone grants nothing)" || fail "agent consent ask: $CODE $BODY"
call POST /api/services/consent "$OWN" '{"service":"fleetgate","daily_cap_dd":100000}'; OC=$(echo "$BODY" | J approval_id)
call POST /api/services/consent "$OWN" "$(jbody service fleetgate daily_cap_dd 100000 approval_id "$OC")"
[ "$CODE" = 202 ] && [ "$(Q "SELECT COUNT(*) FROM service_consents WHERE payer_did='$(did owner)'")" = 0 ] && ok "a person's own token can ask but not grant (the PIN/phone approves)" || fail "owner consent unapproved: $CODE"
asked /api/services/consent "$EXT" "$EXT" '{"service":"fleetgate","daily_cap_dd":1000}'; [ "$CODE" = 201 ] && ok "ext consents to pay FLEETGATE up to 1000 DD/day (own approval)" || fail "ext consent: $CODE $BODY"
asked /api/services/consent "$POOR" "$POOR" '{"service":"fleetgate","daily_cap_dd":1000}'; [ "$CODE" = 201 ] || fail "poor consent: $CODE $BODY"
approve "$OWN" "$AGC"; call POST /api/services/consent "$AG" "$(jbody service fleetgate daily_cap_dd 5000 approval_id "$AGC")"; [ "$CODE" = 201 ] && ok "the owner approves its agent's consent" || fail "agent consent: $CODE $BODY"
asked /api/services/consent "$AG" "$OWN" '{"service":"conduit","daily_cap_dd":500}'; [ "$CODE" = 201 ] || fail "agent conduit consent: $CODE $BODY"

# ── service tokens ──────────────────────────────────────────────────────────────────────────────────────────────
call POST /api/services/token "$EXTR" '{"service":"fleetgate"}'; [ "$CODE" = 403 ] && ok "a read-scope token mints no service token" || fail "read mint: $CODE"
call POST /api/services/token "$EXT" '{"service":"fleetgate","cap_dd":1001}'; [ "$CODE" = 400 ] && ok "a token's cap cannot exceed the daily consent" || fail "cap>consent: $CODE"
call POST /api/services/token "$EXT" '{"service":"fleetgate"}'; ST=$(echo "$BODY" | J token); TID=$(echo "$BODY" | J token_id)
[ "$CODE" = 201 ] && [ "$(echo "$BODY" | J audience)" = svc:fleetgate ] && [ "$(echo "$BODY" | J cap_dd)" = 500 ] && ok "ext mints a fleetgate service token (aud svc:fleetgate, cap 500 DD)" || fail "mint: $CODE $BODY"
bad=0; for p in /api/meter/charges /api/services/charges /api/blindkey/menu /api/blindkey/approvals; do call GET $p "$ST"; [ "$CODE" = 401 ] || { bad=1; echo "  $p → $CODE"; }; done
call POST /api/services/token "$ST" '{"service":"fleetgate"}'; [ "$CODE" = 401 ] || bad=1
[ $bad = 0 ] && ok "a service token opens no DemiPass route (it can't be spent as the caller by the tenant)" || fail "service token accepted somewhere"

# ── verify ──────────────────────────────────────────────────────────────────────────────────────────────────────
V(){ call POST /api/services/verify "$1" "$2"; }
V "$EXT" "$(jbody token "$ST" action submit)"; [ "$CODE" = 403 ] && ok "a wallet that is not a tenant cannot verify" || fail "non-tenant verify: $CODE"
V "$CD" "$(jbody token "$ST" action post)"; [ "$CODE" = 401 ] && ok "another tenant cannot use a fleetgate token (audience)" || fail "aud: $CODE $BODY"
V "$FG" "$(jbody token "$ST" action submit)"
[ "$CODE" = 200 ] && [ "$(echo "$BODY" | J wallet)" = "$(did ext)" ] && [ "$(echo "$BODY" | J token_id)" = "$TID" ] && [ "$(echo "$BODY" | J depth)" = standard ] \
  && [ "$(echo "$BODY" | J via)" = own ] && [ "$(echo "$BODY" | J scope)" = transact ] && ok "verify: wallet, token id, scope, depth, via=own" || fail "verify: $CODE $BODY"
noname && ok "verify carries no username or email" || fail "verify leaks a name: $BODY"
V "$FG" "$(jbody token "$ST" action sign-charter)"; [ "$CODE" = 403 ] && ok "a closed scope (charter) is refused to an outside wallet" || fail "closed scope: $CODE $BODY"

# ── charge ──────────────────────────────────────────────────────────────────────────────────────────────────────
C(){ call POST /api/services/charge "$1" "$2"; }
call POST /api/services/token "$EXT" '{"service":"fleetgate"}'; ST2=$(echo "$BODY" | J token); TID2=$(echo "$BODY" | J token_id)
C "$FG" "$(jbody action submit cost_dd 20 token_id "$TID2" idempotency_key k-unverified-1)"; [ "$CODE" = 403 ] && ok "no charge on a token the tenant never verified" || fail "unverified charge: $CODE $BODY"
C "$FG" "$(jbody action review cost_dd 300 token_id "$TID" idempotency_key k-notverified-review)"; A1=$CODE
C "$FG" "$(jbody action sign-charter cost_dd 5 token_id "$TID" idempotency_key k-notverified-sign)"
[ "$A1" = 403 ] && [ "$CODE" = 403 ] && ok "a charge only for an action verified on that token (review, sign-charter → 403)" || fail "unverified action: $A1 $CODE"
E0=$(bal ext); F0=$(bal fg)
C "$FG" "$(jbody action submit cost_dd 20 token_id "$TID" idempotency_key pr-submit-0001)"; echo "$BODY" > "$S/first"; CID=$(echo "$BODY" | J charge_id)
[ "$CODE" = 201 ] && [ "$(echo "$BODY" | J dd)" = 24 ] && [ "$(bal ext)" = $((E0 - 24)) ] && [ "$(bal fg)" = $((F0 + 24)) ] \
  && ok "charge: 20 + 20% = 24 DD, ext −24, FLEETGATE +24 (201 $CID)" || fail "charge: $CODE $BODY"
[ "$(Q "SELECT COUNT(*) FROM identity_transactions WHERE token_jti='$TID' AND type IN ('service_transfer_out','service_transfer_in')")" = 2 ] \
  && [ "$(Q "SELECT token_jti FROM service_charges WHERE charge_id='$CID'")" = "$TID" ] && ok "the charge row and both ledger rows carry the caller's token id" || fail "token attribution"
node -e '
const crypto = require("crypto"); const identity = require("./identity");
const r = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8")); const rc = JSON.parse(r.receipt);
const pub = crypto.createPublicKey({ key: identity.didToPublicKey(rc.issuer), format: "der", type: "spki" });
const ok = crypto.verify(null, Buffer.from("dustforge-service-charge:v1\n" + r.receipt, "utf8"), pub, Buffer.from(r.sig, "base64url"));
const bare = crypto.verify(null, Buffer.from(r.receipt, "utf8"), pub, Buffer.from(r.sig, "base64url"));
process.exit(ok && !bare && rc.token_id === process.argv[2] ? 0 : 1);' "$S/first" "$TID" \
  && ok "the receipt verifies offline from its issuer did:key (domain-separated) and names the token" || fail "offline receipt"
VB=$(python3 -c 'import json,sys; r=json.load(open(sys.argv[1])); print(json.dumps({"receipt":r["receipt"],"sig":r["sig"]}))' "$S/first")
call POST /api/services/receipts/verify "" "$VB"; A1=$(echo "$BODY" | J on_record)
call POST /api/meter/verify "" "$VB"; [ "$A1" = True ] && [ "$(echo "$BODY" | J valid)" = False ] && ok "receipts/verify: on record; the meter's verify refuses it (no cross-type receipts)" || fail "receipt domains: $A1 $BODY"
C "$FG" "$(jbody action submit cost_dd 20 token_id "$TID" idempotency_key pr-submit-0001)"
[ "$CODE" = 200 ] && [ "$(echo "$BODY" | J replayed)" = True ] && [ "$(bal ext)" = $((E0 - 24)) ] && ok "a retry (same key) → 200 replayed, no second debit" || fail "replay: $CODE $BODY"
C "$FG" "$(jbody action submit cost_dd 19 token_id "$TID" idempotency_key pr-submit-0001)"; [ "$CODE" = 409 ] && ok "same key, other cost → 409" || fail "409: $CODE"
V "$FG" "$(jbody token "$ST" action review)"
C "$FG" "$(jbody action review cost_dd 301 token_id "$TID" idempotency_key pr-review-0001)"; [ "$CODE" = 400 ] && ok "cost above the action's max_cost_dd → 400" || fail "max cost: $CODE"
C "$FG" "$(jbody action review cost_dd 250 token_id "$TID" idempotency_key pr-review-0001)"; [ "$CODE" = 201 ] && [ "$(echo "$BODY" | J dd)" = 300 ] && ok "a variable-cost review: 250 measured → 300 billed" || fail "review: $CODE $BODY"
C "$FG" "$(jbody action review cost_dd 200 token_id "$TID" idempotency_key pr-review-0002)"
[ "$CODE" = 402 ] && [ "$(echo "$BODY" | J cap_exceeded)" = True ] && ok "the token's spend cap (500 DD) → 402 cap_exceeded" || fail "cap: $CODE $BODY"
call POST /api/services/token "$EXT" '{"service":"fleetgate","cap_dd":1000}'; ST3=$(echo "$BODY" | J token); TID3=$(echo "$BODY" | J token_id)
V "$FG" "$(jbody token "$ST3" action review)"; C "$FG" "$(jbody action review cost_dd 300 token_id "$TID3" idempotency_key pr-review-0003)"; A1=$CODE
C "$FG" "$(jbody action review cost_dd 300 token_id "$TID3" idempotency_key pr-review-0004)"
[ "$A1" = 201 ] && [ "$CODE" = 402 ] && [ "$(echo "$BODY" | J daily_cap_exceeded)" = True ] && ok "the daily consent (1000 DD) → 402 daily_cap_exceeded (324 + 360 + 360 > 1000)" || fail "daily cap: $A1 $CODE $BODY"
call POST /api/services/token "$POOR" '{"service":"fleetgate"}'; PT=$(echo "$BODY" | J token); PTID=$(echo "$BODY" | J token_id)
V "$FG" "$(jbody token "$PT" action submit)"; C "$FG" "$(jbody action submit cost_dd 20 token_id "$PTID" idempotency_key poor-0001)"
[ "$CODE" = 402 ] && [ "$(bal poor)" = 5 ] && [ "$(Q "SELECT COUNT(*) FROM service_charges WHERE token_jti='$PTID'")" = 0 ] && ok "too little DD → 402 for the caller, nothing written" || fail "402: $CODE $BODY"
V "$FG" "$(jbody token "$ST2" action submit)"
E1=$(bal ext); C "$FG" "$(jbody action submit cost_dd 20 token_id "$TID2" idempotency_key pr-submit-0001)"
[ "$CODE" = 200 ] && [ "$(echo "$BODY" | J replayed)" = True ] && [ "$(echo "$BODY" | J charge_id)" = "$CID" ] && [ "$(bal ext)" = "$E1" ] \
  && ok "a retry with ANOTHER token of the same wallet replays the charge (no debit) — a re-minted token can finish a paid call" || fail "same-wallet replay: $CODE $BODY"
C "$FG" "$(jbody action submit cost_dd 20 token_id "$PTID" idempotency_key pr-submit-0001)"
[ "$CODE" = 409 ] && [ "$(bal poor)" = 5 ] && ok "another wallet's token with that key → 409 (never someone else's charge)" || fail "other-wallet replay: $CODE $BODY"
call POST /api/services/token/revoke "$EXT" "$(jbody token_id "$TID2")"; [ "$CODE" = 200 ] || fail "revoke: $CODE $BODY"
C "$FG" "$(jbody action submit cost_dd 20 token_id "$TID2" idempotency_key pr-submit-0001)"
[ "$CODE" = 409 ] && ok "a revoked token gets no replay (never a go-ahead for a token its wallet withdrew)" || fail "revoked replay: $CODE $BODY"
C "$FG" "$(jbody action submit cost_dd 20 token_id "$TID2" idempotency_key after-revoke-1)"; A1=$CODE
V "$FG" "$(jbody token "$ST2" action submit)"; [ "$A1" = 401 ] && [ "$CODE" = 401 ] && ok "a revoked service token: verify and charge → 401" || fail "revoked: $A1 $CODE"
EXT2=$(login ext); asked /api/services/consent "$EXT2" "$EXT2" '{"service":"conduit","daily_cap_dd":100}' >/dev/null
call POST /api/services/token "$EXT2" '{"service":"conduit"}'; ECT=$(echo "$BODY" | J token)
EJ=$(python3 -c 'import json,base64,sys; p=sys.argv[1].split(".")[1]; print(json.loads(base64.urlsafe_b64decode(p+"="*(-len(p)%4)))["jti"])' "$EXT2")
call POST /api/identity/tokens/revoke "$EXT2" "$(jbody jti "$EJ")"; [ "$CODE" = 200 ] || fail "parent revoke: $CODE $BODY"
V "$CD" "$(jbody token "$ECT" action post)"; [ "$CODE" = 401 ] && ok "revoking the token that minted it kills the service token" || fail "parent revoke: $CODE $BODY"

# ── delegation and depth ────────────────────────────────────────────────────────────────────────────────────────
call POST /api/services/token "$AG" '{"service":"fleetgate"}'; AT=$(echo "$BODY" | J token); [ "$CODE" = 201 ] || fail "agent mint: $CODE $BODY"
V "$FG" "$(jbody token "$AT" action sign-charter)"; [ "$CODE" = 403 ] && ok "an agent without a delegation cannot sign" || fail "agent closed: $CODE"
V "$FG" "$(jbody token "$AT" action broadcast)"; [ "$CODE" = 403 ] && echo "$BODY" | grep -q delegation && ok "an agent on its own account cannot take an elevated action (nobody to approve)" || fail "agent own elevated: $CODE $BODY"
call POST /api/services/delegate "$AG" "$(jbody service fleetgate scope charter delegate_did "$(did stranger)")"; [ "$CODE" = 403 ] && ok "agents do not hand on a scope" || fail "agent delegate: $CODE"
call POST /api/services/delegate "$OTH" "$(jbody service fleetgate scope broadcast delegate_did "$(did agent)")"; [ "$CODE" = 403 ] && ok "a stranger cannot push a scope onto someone else's agent (H2)" || fail "stranger push: $CODE $BODY"
call POST /api/services/delegate "$OWN" "$(jbody service fleetgate scope submit delegate_did "$(did stranger)")"; [ "$CODE" = 403 ] && ok "…nor the owner onto another fleet's agent" || fail "owner → stranger: $CODE"
call POST /api/services/delegate "$EXT" "$(jbody service fleetgate scope charter delegate_did "$(did agent)")"; [ "$CODE" = 403 ] && ok "a closed scope is delegated by the tenant owner only" || fail "ext delegate closed: $CODE"
call POST /api/services/delegate "$OWN" "$(jbody service fleetgate scope charter delegate_did "$(did agent)")"; DG=$(echo "$BODY" | J delegation_id)
[ "$CODE" = 201 ] && [ "$(echo "$BODY" | J use_only)" = True ] && ok "owner → own silicon: charter delegated, use-only" || fail "delegate: $CODE $BODY"
CALL='{"charter":"release-controller","digest":"27df94c7d0d1"}'
V "$FG" "$(jbody token "$AT" action sign-charter call "$CALL")"; AP=$(echo "$BODY" | J approval_id)
[ "$CODE" = 202 ] && [ "$(Q "SELECT owner_did FROM use_approvals WHERE id=$AP")" = "$(did owner)" ] && [ "$(Q "SELECT service_key FROM use_approvals WHERE id=$AP")" = svc:fleetgate:sign-charter ] \
  && ok "the delegate's elevated call parks on the OWNER's approval (202, request $AP)" || fail "elevated: $CODE $BODY"
noname && [ "$(echo "$BODY" | J owner)" = None ] && ok "the 202 a tenant sees names nobody (M1)" || fail "202 leaks: $BODY"
call GET /api/demipass/approvals "$OWN"; echo "$BODY" | grep -q "fleetgate · sign-charter" && ok "the owner's app lists it as 'fleetgate · sign-charter'" || fail "owner list: $BODY"
call POST /api/demipass/approvals/$AP/open "$AG"; { [ "$CODE" = 403 ] || [ "$CODE" = 404 ]; } && ok "the agent cannot open its own request" || fail "agent open: $CODE"
approve "$OWN" "$AP"
V "$FG" "$(jbody token "$AT" action sign-charter call '{"charter":"release-controller","digest":"000000000000"}' approval_id "$AP")"; [ "$CODE" = 409 ] && ok "the approval binds the exact call (another digest → 409)" || fail "binding: $CODE $BODY"
V "$FG" "$(jbody token "$AT" action sign-charter call "$CALL" approval_id "$AP")"
[ "$CODE" = 200 ] && [ "$(echo "$BODY" | J via)" = delegation ] && [ "$(echo "$BODY" | J depth)" = elevated ] && [[ "$(echo "$BODY" | J principal)" == pp_* ]] && noname \
  && ok "approved: verify passes via delegation, a pairwise principal, never the owner" || fail "approved verify: $CODE $BODY"
V "$FG" "$(jbody token "$AT" action sign-charter call "$CALL" approval_id "$AP")"; [ "$CODE" = 410 ] && ok "one call per approval (again → 410)" || fail "reuse: $CODE"
V "$FG" "$(jbody token "$AT" action sign-charter call "$CALL")"; AP2=$(echo "$BODY" | J approval_id); approve "$OWN" "$AP2"
call POST /api/services/delegate "$OWN" "$(jbody service fleetgate scope charter delegate_did "$(did agent)")"
V "$FG" "$(jbody token "$AT" action sign-charter call "$CALL" approval_id "$AP2")"; [ "$CODE" = 409 ] && ok "an approval given under one delegation does not redeem under another (bound to the authority)" || fail "authority binding: $CODE $BODY"
call POST /api/services/token "$AG" '{"service":"conduit"}'; ACT=$(echo "$BODY" | J token)
call POST /api/services/delegate "$OWN" "$(jbody service conduit scope post delegate_did "$(did agent)")"
V "$CD" "$(jbody token "$ACT" action post)"; PR1=$(echo "$BODY" | J principal)
call POST /api/services/delegate "$OWN" "$(jbody service fleetgate scope submit delegate_did "$(did agent)")"
V "$FG" "$(jbody token "$AT" action submit)"; PR2=$(echo "$BODY" | J principal)
[[ "$PR1" == pp_* ]] && [[ "$PR2" == pp_* ]] && [ "$PR1" != "$PR2" ] && ok "the principal is pairwise: the same owner looks different at Conduit and FLEETGATE" || fail "pairwise: $PR1 $PR2"
DG2=$(Q "SELECT id FROM service_delegations WHERE scope='charter' AND status='active'")
call POST /api/services/delegations/$DG2/revoke "$AG"; [ "$CODE" = 404 ] && ok "the delegate cannot revoke (or see) the owner's delegation" || fail "agent revoke: $CODE"
call POST /api/services/delegations/$DG2/revoke "$OWN"; [ "$CODE" = 200 ] || fail "revoke deleg: $CODE"
V "$FG" "$(jbody token "$AT" action sign-charter call "$CALL")"; [ "$CODE" = 403 ] && ok "after revoke the agent's charter calls are refused" || fail "after revoke: $CODE $BODY"
call POST /api/services/token "$EXT" '{"service":"fleetgate"}'; ET4=$(echo "$BODY" | J token)
V "$FG" "$(jbody token "$ET4" action broadcast call '{"to":"all"}')"; EP=$(echo "$BODY" | J approval_id)
[ "$CODE" = 202 ] && [ "$(Q "SELECT owner_did FROM use_approvals WHERE id=$EP")" = "$(did ext)" ] && noname && ok "a person on their own account: the elevated call waits on their own phone, unnamed" || fail "person own elevated: $CODE $BODY"

# ── weakening a gate (the owner approves exactly that change) ───────────────────────────────────────────────────
call PUT /api/services/fleetgate/actions "$FG" '{"actions":[{"action":"sign-charter","measured_cost_dd":6}]}'
[ "$CODE" = 200 ] && [ "$(Q "SELECT depth || '/' || scope || '/' || open FROM service_actions WHERE action='sign-charter'")" = elevated/charter/0 ] && ok "a price change keeps depth, scope and closedness" || fail "price keep: $CODE $BODY"
call PUT /api/services/fleetgate/actions "$FG" '{"actions":[{"action":"sign-charter","measured_cost_dd":5,"depth":"standard"}]}'; W1=$(echo "$BODY" | J approval_id)
[ "$CODE" = 202 ] && [ "$(Q "SELECT owner_did FROM use_approvals WHERE id=$W1")" = "$(did owner)" ] && ok "the tenant lowering a depth waits on the owner's approval" || fail "lower: $CODE $BODY"
call PUT /api/services/fleetgate/actions "$FG" '{"actions":[{"action":"sign-charter","retired":true}]}'
call PUT /api/services/fleetgate/actions "$FG" '{"actions":[{"action":"sign-charter","scope":"charter","measured_cost_dd":5,"depth":"standard","open":true}]}'
[ "$CODE" = 202 ] && [ "$(Q "SELECT depth || '/' || status FROM service_actions WHERE action='sign-charter'")" = elevated/retired ] && ok "retire + re-add weaker is caught (M3)" || fail "retire trick: $CODE $BODY"
call PUT /api/services/fleetgate/actions "$FG" '{"actions":[{"action":"merge-now","scope":"submit","measured_cost_dd":1}]}'
[ "$CODE" = 202 ] && ok "adding an action to a delegated scope waits on the owner (it widens the delegation)" || fail "widen: $CODE $BODY"
approve "$OWN" "$W1"; call PUT /api/services/fleetgate/actions "$FG" "$(jbody actions '[{"action":"sign-charter","measured_cost_dd":5,"depth":"standard"}]' approval_id "$W1")"
[ "$CODE" = 200 ] && [ "$(Q "SELECT depth FROM service_actions WHERE action='sign-charter'")" = standard ] && ok "approved: exactly that change applies" || fail "approved lower: $CODE $BODY"

# ── requests wait long enough to be seen (Aaron 2026-11-08) ─────────────────────────────────────────────────────
call POST /api/services/register "$OWN" '{"slug":"ttl-probe","name":"ttl"}'; GR=$(echo "$BODY" | J approval_id)
HRS=$(python3 -c "import sqlite3,datetime as d; r=sqlite3.connect('$DB_PATH').execute('SELECT created_at, expires_at FROM use_approvals WHERE id=$GR').fetchone(); a,b=[d.datetime.fromisoformat(x.replace('Z','+00:00')) for x in r]; print(round((b-a).total_seconds()/3600))")
[ "$HRS" = 24 ] && ok "a DemiPass grant waits a day for the owner (not 5 minutes)" || fail "grant TTL: $HRS h"
[ "$(Q "SELECT summary FROM use_approvals WHERE id=$GR")" = "register service ttl-probe (ttl)" ] && ok "the card names what is granted" || fail "summary: $(Q "SELECT summary FROM use_approvals WHERE id=$GR")"
V "$FG" "$(jbody token "$ET4" action broadcast call '{"to":"elevated-ttl"}')"; EAP=$(echo "$BODY" | J approval_id)
MIN=$(python3 -c "import sqlite3,datetime as d; r=sqlite3.connect('$DB_PATH').execute('SELECT created_at, expires_at FROM use_approvals WHERE id=$EAP').fetchone(); a,b=[d.datetime.fromisoformat(x.replace('Z','+00:00')) for x in r]; print(round((b-a).total_seconds()/60))")
[ "$MIN" = 60 ] && ok "an elevated action's request waits an hour (codes still rotate every 30 s)" || fail "action TTL: $MIN min"

# ── fleet removal ends an agent's service access (M4) ──────────────────────────────────────────────────────────
call POST /api/services/token "$AG" '{"service":"conduit"}'; ACT2=$(echo "$BODY" | J token)
call DELETE /api/fleet/owner-agents/silicons/agent "$OWN"; [ "$CODE" = 200 ] || fail "remove agent: $CODE $BODY"
V "$CD" "$(jbody token "$ACT2" action post)"; [ "$CODE" = 401 ] && ok "removed from the fleet: its service tokens die with its fleet tokens" || fail "fleet cut: $CODE $BODY"
AGS=$(login agent); call POST /api/identity/pin "$AGS" '{"pin":"1111","password":"hunter22"}'
call POST /api/services/consent "$AGS" '{"service":"conduit","daily_cap_dd":400}'; N1=$(echo "$BODY" | J approval_id)
[ "$CODE" = 202 ] && [ "$(Q "SELECT owner_did FROM use_approvals WHERE id=$N1")" = "$(did owner)" ] \
  && ok "a created agent that left still answers to its creator: it cannot approve its own consent (N1)" || fail "N1: $CODE $BODY approver=$(Q "SELECT owner_did FROM use_approvals WHERE id=$N1")"
# Re-linked into an accomplice's fleet (its removed row is deleted there), then removed again: still its creator's.
call POST /api/fleet/other-agents/silicons "$OTH" "$(jbody handle relinked did "$(did agent)" member_token "$AGS")"; [ "$CODE" = 200 ] || [ "$CODE" = 201 ] || fail "relink: $CODE $BODY"
[ "$(Q "SELECT COUNT(*) FROM fleet_silicons WHERE member_did='$(did agent)' AND created_by_fleet=1")" = 0 ] || fail "relink did not clear the creator row (test premise)"
call DELETE /api/fleet/other-agents/silicons/relinked "$OTH"
AGS2=$(login agent); call POST /api/services/consent "$AGS2" '{"service":"conduit","daily_cap_dd":300}'; N2=$(echo "$BODY" | J approval_id)
[ "$CODE" = 202 ] && [ "$(Q "SELECT owner_did FROM use_approvals WHERE id=$N2")" = "$(did owner)" ] \
  && ok "re-linked elsewhere and removed again: still its creator's to approve (wallet_creators)" || fail "relink N1: $CODE $BODY approver=$(Q "SELECT owner_did FROM use_approvals WHERE id=$N2")"

# ── listings ────────────────────────────────────────────────────────────────────────────────────────────────────
call GET /api/services/charges "$EXT"; [ "$(echo "$BODY" | J paid.0.token_id)" = "$TID3" ] && [ "$(echo "$BODY" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["paid"]))')" = 3 ] \
  && ok "ext's charges: 3, each with its token id" || fail "ext charges: $BODY"
call GET /api/services/charges "$FG"; [ "$(echo "$BODY" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["received"]))')" = 3 ] && ok "FLEETGATE sees what it received" || fail "fg received: $BODY"
call GET /api/services/charges "$POOR"; [ "$(echo "$BODY" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(len(d["paid"]), "received" in d)')" = "0 False" ] && ok "…and nobody else does" || fail "poor charges: $BODY"
grep -q "$ST" "$S/server.log" && fail "a service token reached the server log" || ok "no token in the server log"

# ── a day-long queue cannot be filled from one DID (#77 M3) ──────────────────────────────────────────────────────
OWN=$(login owner); n202=0; last=""
for k in $(seq 1 12); do call POST /api/services/register "$OWN" "$(jbody slug "spam-$k" name "label-$k")"; [ "$CODE" = 202 ] && n202=$((n202+1)); last=$CODE; done
[ "$n202" -le 10 ] && [ "$last" = 429 ] && ok "the owner's own DID holds at most 10 waiting grants, whatever labels it uses" || fail "grant cap: $n202 then $last"

# ── the owner's phone hears of every pending request (the D-signed alerts call) ──────────────────────────────────
node -e 'const c=require("crypto"),fs=require("fs");for(const n of ["d","p"]){const {privateKey,publicKey}=c.generateKeyPairSync("ec",{namedCurve:"prime256v1"});
fs.writeFileSync(process.argv[1]+"/"+n+".pem",privateKey.export({type:"pkcs8",format:"pem"}));fs.writeFileSync(process.argv[1]+"/"+n+".pub",publicKey.export({type:"spki",format:"der"}).toString("base64"))}' "$S"
sig(){ node -e 'const c=require("crypto"),fs=require("fs"); process.stdout.write(c.sign("sha256", Buffer.from(process.argv[2]), fs.readFileSync(process.argv[1])).toString("base64"))' "$S/$1.pem" "$2"; }
OWN=$(login owner)
call POST /api/identity/device/challenge "$OWN" '{"purpose":"enrol","intent":"device-enrol:0"}'; CHD=$(echo "$BODY" | J challenge_id); MSG="$(echo "$BODY" | J message):phone-0001"
pin "$OWN" 4321 "device-enrol:0"; call POST /api/identity/gate/verify "$OWN" '{"gate":"password","password":"hunter22"}'
call POST /api/identity/device/enrol "$OWN" "$(printf '{"challenge_id":%s,"device_id":"phone-0001","label":"Pixel","key_d":"%s","key_p":"%s","sig_d":"%s","sig_p":"%s"}' "$CHD" "$(cat $S/d.pub)" "$(cat $S/p.pub)" "$(sig d "$MSG")" "$(sig p "$MSG")")"
[ "$CODE" = 201 ] || fail "enrol: $CODE $BODY"
PR=$(Q "SELECT id FROM use_approvals WHERE status='pending' AND service_key='svc:demipass:register' ORDER BY id DESC LIMIT 1")
call POST /api/fleet/owner-agents/silicons/fg/token-requests "$OWN" '{"scope":"transact","expires_in":"7d"}'; STR_ID=$(echo "$BODY" | J request_id)
[ -n "$STR_ID" ] && [ "$STR_ID" != None ] || fail "#78 token request: $CODE $BODY"
call POST /api/identity/holds/challenge "" '{"purpose":"alerts","device_id":"phone-0001"}'; CH=$(echo "$BODY" | J challenge); M=$(echo "$BODY" | J message)
call POST /api/identity/holds/alerts "" "$(jbody device_id phone-0001 challenge "$CH" signature "$(sig d "$M")")"
echo "$BODY" | python3 -c 'import json,sys; d=json.load(sys.stdin); ids={x["id"] for x in d.get("approvals",[])}; sys.exit(0 if int(sys.argv[1]) in ids and 100000000000+int(sys.argv[2]) in ids else 1)' "$PR" "$STR_ID" \
  && ok "the phone's alerts call lists pending requests: a grant, and an agent token request (#78)" || fail "alerts approvals: $BODY"
python3 -c "import sqlite3,sys,datetime; c=sqlite3.connect(sys.argv[1]); c.execute(\"UPDATE device_keys SET revoked_at=?, revoked_via='recovery' WHERE device_id='phone-0001'\", (datetime.datetime.utcnow().isoformat()+'Z',)); c.commit()" "$DB_PATH"
call POST /api/identity/holds/challenge "" '{"purpose":"alerts","device_id":"phone-0001"}'; CH=$(echo "$BODY" | J challenge); M=$(echo "$BODY" | J message)
call POST /api/identity/holds/alerts "" "$(jbody device_id phone-0001 challenge "$CH" signature "$(sig d "$M")")"
[ "$CODE" = 200 ] && [ "$(echo "$BODY" | python3 -c 'import json,sys; print(len(json.load(sys.stdin).get("approvals",[])))')" = 0 ] && ok "a removed phone (still in its hold-cancel grace) is not told what waits (#77 M2)" || fail "removed phone: $CODE $BODY"

[ $fails -gt 0 ] && { echo "--- server.log"; grep -i -m8 "error" "$S/server.log"; }
echo "$fails failure(s)"; exit $(( fails > 0 ))
