#!/bin/bash
# End-to-end smoke of the vault PIN gate (test/pin_gate_smoke.sh): boots server.js on a throwaway DB + random
# master key, creates one wallet through identity.js (password checked by the local sha256 fallback because
# Stalwart is pointed at a closed port), then drives the real HTTP routes with TWO sessions (two tokens, two
# jtis) of the same account: set / verify / lockout / change PIN, reveal gating, single-use and per-session
# proofs, the PIN floor on reveal, step-up before a policy downgrade, legacy 'fingerprint' policies.
# Needs node_modules (or NODE_PATH). No network, nothing persists.
set -u
W=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
S=$(mktemp -d /tmp/dustforge-pin-smoke.XXXXXX)
PORT=${PORT:-3777}; API=http://127.0.0.1:$PORT
[ -d "$W/node_modules" ] || export NODE_PATH=${NODE_PATH:-/home/flimflam/project/dustforge/node_modules}
export IDENTITY_MASTER_KEY=$(python3 -c 'import secrets;print(secrets.token_hex(32))') DB_PATH=$S/dustforge.db PORT STALWART_HOST=127.0.0.1 STALWART_PORT=1 SMTP_RELAY_HOST=
cd "$W"
node server.js >"$S/server.log" 2>&1 & SRV=$!
trap 'kill $SRV 2>/dev/null; rm -rf "$S"' EXIT
for i in $(seq 1 40); do curl -s -o /dev/null "$API/" && break; sleep 0.5; done
kill -0 $SRV 2>/dev/null || { echo "server died:"; tail -5 "$S/server.log"; exit 1; }
PW=hunter22; H=$(printf '%s' "$PW" | sha256sum | cut -d' ' -f1)
node -e '
const identity = require("./identity"); const Database = require("better-sqlite3");
const id = identity.createIdentity(); const enc = id.encrypted_private_key || id.encryptedPrivateKey;
const db = new Database(process.env.DB_PATH);
try { db.exec("ALTER TABLE identity_wallets ADD COLUMN password_hash TEXT"); } catch (_) {}
db.prepare("INSERT INTO identity_wallets (did, username, email, encrypted_private_key, balance_cents, password_hash, recovery_email) VALUES (?, ?, ?, ?, 100000, ?, ?)")
  .run(id.did, "pintester", "pintester@dustforge.com", enc, process.argv[1], "p@example.com");
console.log("wallet:", id.did.slice(0, 24) + "…");
' "$H"
fails=0; ok(){ echo "ok   $*"; }; fail(){ echo "FAIL $*"; fails=$((fails+1)); }
J(){ python3 -c 'import json,sys; d=json.load(sys.stdin); v=d
for k in sys.argv[1].split("."):
    v = v[int(k)] if isinstance(v, list) else v.get(k)
print(v)' "$1"; }
SQL(){ python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute(sys.argv[2]); c.commit()" "$DB_PATH" "$1"; }
call(){ # method path token body → sets CODE and BODY
  local m=$1 p=$2 t=$3 b=${4:-}
  BODY=$(curl -s -o - -w '\n%{http_code}' -X "$m" "$API$p" -H 'Content-Type: application/json' ${t:+-H "Authorization: Bearer $t"} ${b:+-d "$b"})
  CODE=${BODY##*$'\n'}; BODY=${BODY%$'\n'*}
}
login(){ call POST /api/identity/auth-fingerprint "" '{"username":"pintester","password":"hunter22","scope":"transact","expires_in":"1h"}'; echo "$BODY" | J token; }
TK=$(login); [ -n "$TK" ] && [ "$TK" != None ] && ok "login: session A (transact token)" || { fail "login A: $CODE $BODY"; exit 1; }
TK2=$(login); [ -n "$TK2" ] && [ "$TK2" != "$TK" ] && ok "login: session B (second token, own jti)" || { fail "login B: $CODE $BODY"; exit 1; }

# ── set-up and basics ─────────────────────────────────────────────────────────────────────────────────
call GET /api/identity/gate/status "$TK"; [ "$(echo "$BODY" | J pin_set)" = False ] && ok "gate/status: pin_set=false on a fresh account" || fail "gate/status: $BODY"
[ "$(echo "$BODY" | J pin_single_use)" = True ] && ok "gate/status: pin_single_use advertised" || fail "pin_single_use: $BODY"
echo "$BODY" | J presets.standard.reveal.0 | grep -q '^pin$' && ok "standard preset reveal gate is pin" || fail "preset: $(echo "$BODY" | J presets.standard.reveal)"
call POST /api/blindkey/store "$TK" '{"name":"sightless","value":"s3cret-value","secret_type":"password"}'; [ "$CODE" = 200 ] || [ "$CODE" = 201 ] && ok "store a secret" || fail "store: $CODE $BODY"
call POST /api/blindkey/reveal "$TK" '{"name":"sightless"}'; [ "$CODE" = 403 ] && [ "$(echo "$BODY" | J missing.0)" = pin ] && ok "reveal without PIN → 403 missing [pin]" || fail "reveal: $CODE $BODY"
call POST /api/identity/gate/verify "$TK" '{"gate":"pin","pin":"1234"}'; [ "$CODE" = 409 ] && ok "verify pin before one exists → 409" || fail "verify-no-pin: $CODE $BODY"
# no PIN set: the standard policy cannot be lowered either (the floor cannot be proven, so it cannot be moved)
call POST /api/blindkey/gate-policy "$TK" '{"name":"sightless","gate_policy":{"reveal":[],"rotate":[],"delete":[],"use":[]}}'
[ "$CODE" = 200 ] && [ "$(echo "$BODY" | J effective.reveal.0)" = pin ] && ok "custom reveal:[] accepted but effective reveal keeps pin (floor)" || fail "floor: $CODE $BODY"
echo "$BODY" | J note | grep -q "always required" && ok "reply says the PIN cannot be removed from reveal" || fail "floor note: $BODY"
call POST /api/blindkey/reveal "$TK" '{"name":"sightless"}'; [ "$CODE" = 403 ] && ok "reveal still gated after the reveal:[] policy" || fail "floor reveal: $CODE $BODY"
call POST /api/blindkey/gate-policy "$TK" '{"name":"sightless","security_depth":"standard"}'; [ "$CODE" = 200 ] && ok "back to standard (no weakening: same effective policy)" || fail "std: $CODE $BODY"
call POST /api/identity/pin "$TK" '{"pin":"12"}'; [ "$CODE" = 400 ] && ok "set: 2-digit PIN refused" || fail "short pin: $CODE"
call POST /api/identity/pin "$TK" '{"pin":"1234"}'; [ "$CODE" = 400 ] && ok "set: password required" || fail "no pw: $CODE $BODY"
call POST /api/identity/pin "$TK" '{"pin":"1234","password":"wrong"}'; [ "$CODE" = 403 ] && ok "set: wrong password → 403 (never 401)" || fail "wrong pw: $CODE $BODY"
call POST /api/identity/pin "$TK" '{"pin":"1234","password":"hunter22"}'; [ "$CODE" = 200 ] && [ "$(echo "$BODY" | J changed)" = False ] && ok "set PIN with password" || fail "set pin: $CODE $BODY"
call GET /api/identity/gate/status "$TK"; [ "$(echo "$BODY" | J pin_set)" = True ] && ok "gate/status: pin_set=true" || fail "status after set: $BODY"
call POST /api/blindkey/reveal "$TK" '{"name":"sightless"}'; [ "$CODE" = 403 ] && ok "reveal still gated after setting the PIN" || fail "reveal after set: $CODE"
call POST /api/identity/gate/verify "$TK" '{"gate":"pin","pin":"9999"}'; [ "$CODE" = 403 ] && [ "$(echo "$BODY" | J attempts_left)" = 4 ] && ok "wrong PIN → 403, 4 tries left" || fail "wrong pin: $CODE $BODY"

# ── a proof belongs to one session and one action ─────────────────────────────────────────────────────
call POST /api/identity/gate/verify "$TK" '{"gate":"pin","pin":"1234"}'; [ "$CODE" = 200 ] && [ "$(echo "$BODY" | J single_use)" = True ] && ok "correct PIN in A → proof (single use)" || fail "verify: $CODE $BODY"
call GET /api/identity/gate/status "$TK"; [ "$(echo "$BODY" | J fresh.pin)" = True ] && ok "gate/status A: fresh.pin=true" || fail "fresh A: $BODY"
call GET /api/identity/gate/status "$TK2"; [ "$(echo "$BODY" | J fresh.pin)" = False ] && ok "gate/status B: fresh.pin=false (A's proof is not B's)" || fail "fresh B: $BODY"
call POST /api/blindkey/reveal "$TK2" '{"name":"sightless"}'; [ "$CODE" = 403 ] && ok "session B cannot reveal on A's PIN" || fail "cross-session: $CODE $BODY"
call POST /api/blindkey/reveal "$TK" '{"name":"sightless"}'; [ "$CODE" = 200 ] && [ "$(echo "$BODY" | J value)" = s3cret-value ] && ok "session A reveals → value" || fail "reveal: $CODE $BODY"
call POST /api/blindkey/reveal "$TK" '{"name":"sightless"}'; [ "$CODE" = 403 ] && [ "$(echo "$BODY" | J missing.0)" = pin ] && ok "second reveal in A → 403 (proof spent by the first)" || fail "single-use: $CODE $BODY"
call GET /api/identity/gate/status "$TK"; [ "$(echo "$BODY" | J fresh.pin)" = False ] && ok "gate/status A: fresh.pin=false after the reveal" || fail "spent: $BODY"

# ── lockout: no new proofs, and every held proof dies ─────────────────────────────────────────────────
call POST /api/identity/gate/verify "$TK" '{"gate":"pin","pin":"1234"}'; [ "$CODE" = 200 ] && ok "A holds a fresh proof" || fail "pre-lock verify: $CODE"
for i in 1 2 3 4; do call POST /api/identity/gate/verify "$TK2" '{"gate":"pin","pin":"0000"}'; done
[ "$CODE" = 403 ] && [ "$(echo "$BODY" | J attempts_left)" = 1 ] && ok "four misses in B → 1 try left" || fail "misses: $CODE $BODY"
call POST /api/identity/gate/verify "$TK2" '{"gate":"pin","pin":"0000"}'; [ "$CODE" = 429 ] && ok "fifth miss → 429 locked" || fail "lock: $CODE $BODY"
call POST /api/blindkey/reveal "$TK" '{"name":"sightless"}'; [ "$CODE" = 403 ] && ok "A's pre-lock proof is void: reveal → 403 while locked" || fail "locked reveal: $CODE $BODY"
call POST /api/identity/gate/verify "$TK" '{"gate":"pin","pin":"1234"}'; [ "$CODE" = 429 ] && [ "$(echo "$BODY" | J locked_for_seconds)" -gt 800 ] && ok "correct PIN while locked → 429 (~15 min)" || fail "locked-correct: $CODE $BODY"
call POST /api/identity/pin "$TK" '{"pin":"5678","current_pin":"1234"}'; [ "$CODE" = 429 ] && ok "change with current PIN while locked → 429" || fail "change-locked: $CODE"
call GET /api/identity/gate/status "$TK"; [ "$(echo "$BODY" | J pin_locked_for_seconds)" -gt 800 ] && ok "gate/status reports the lock" || fail "status lock: $BODY"
SQL "UPDATE identity_wallets SET pin_locked_until=NULL WHERE username='pintester'"   # the 15 minutes pass

# ── changing the PIN voids proofs earned with the old one ─────────────────────────────────────────────
call POST /api/identity/pin "$TK" '{"pin":"5678","current_pin":"1111"}'; [ "$CODE" = 403 ] && ok "change with wrong current PIN → 403" || fail "change-wrong: $CODE $BODY"
call POST /api/identity/gate/verify "$TK2" '{"gate":"pin","pin":"1234"}'; [ "$CODE" = 200 ] && ok "B holds a proof under the old PIN" || fail "B verify: $CODE $BODY"
call POST /api/identity/pin "$TK" '{"pin":"5678","current_pin":"1234"}'; [ "$CODE" = 200 ] && [ "$(echo "$BODY" | J changed)" = True ] && ok "A changes the PIN with the current PIN" || fail "change: $CODE $BODY"
call POST /api/blindkey/reveal "$TK2" '{"name":"sightless"}'; [ "$CODE" = 403 ] && ok "B's old-PIN proof is void after the change" || fail "stale after change: $CODE $BODY"
call POST /api/identity/gate/verify "$TK" '{"gate":"pin","pin":"1234"}'; [ "$CODE" = 403 ] && ok "old PIN no longer works" || fail "old pin: $CODE"
call POST /api/identity/gate/verify "$TK" '{"gate":"pin","pin":"5678"}'; [ "$CODE" = 200 ] && ok "new PIN works" || fail "new pin: $CODE $BODY"
call POST /api/identity/pin "$TK" '{"pin":"2468","password":"hunter22"}'; [ "$CODE" = 200 ] && ok "forgotten PIN: change with password" || fail "change-pw: $CODE $BODY"
call POST /api/blindkey/reveal "$TK" '{"name":"sightless"}'; [ "$CODE" = 403 ] && ok "A's proof died with the password-reset too" || fail "stale after reset: $CODE $BODY"

# ── policy changes: raising is free, lowering means opening the lock first ────────────────────────────
call POST /api/blindkey/gate-policy "$TK" '{"name":"sightless","gate_policy":{"reveal":["fingerprint","twofa"],"rotate":[],"delete":[],"use":[]}}'
[ "$CODE" = 200 ] && [ "$(echo "$BODY" | J effective.reveal.0)" = pin ] && ok "legacy 'fingerprint' in a custom policy reads as pin (raising: no proof needed)" || fail "legacy policy: $CODE $BODY"
call POST /api/blindkey/gate-policy "$TK" '{"name":"sightless","security_depth":"standard"}'
[ "$CODE" = 403 ] && echo "$BODY" | J missing | grep -q "pin" && echo "$BODY" | J missing | grep -q "twofa" && ok "lowering reveal (pin+twofa → pin) with no proofs → 403 missing pin + twofa" || fail "downgrade unproven: $CODE $BODY"
echo "$BODY" | J weakens | grep -q reveal && ok "403 names the weakened action" || fail "weakens: $BODY"
call POST /api/identity/gate/verify "$TK" '{"gate":"pin","pin":"2468"}'; [ "$CODE" = 200 ] || fail "verify for downgrade: $CODE"
call POST /api/blindkey/gate-policy "$TK" '{"name":"sightless","security_depth":"standard"}'
[ "$CODE" = 403 ] && [ "$(echo "$BODY" | J missing)" = "['twofa']" ] && ok "PIN alone is not enough: still missing twofa (PIN proof kept, not spent by the refusal)" || fail "downgrade pin-only: $CODE $BODY"
call POST /api/blindkey/gate-policy "$TK2" '{"name":"sightless","security_depth":"standard"}'
[ "$CODE" = 403 ] && echo "$BODY" | J missing | grep -q "pin" && ok "session B cannot lower it on A's PIN" || fail "downgrade cross-session: $CODE $BODY"
SQL "INSERT INTO identity_2fa_codes (did, code, expires_at) SELECT did, '424242', datetime('now', '+10 minutes') FROM identity_wallets WHERE username='pintester'"   # the emailed code
call POST /api/identity/gate/verify "$TK" '{"gate":"twofa","code":"424242"}'; [ "$CODE" = 200 ] && ok "email code verified in A" || fail "twofa: $CODE $BODY"
call POST /api/blindkey/gate-policy "$TK" '{"name":"sightless","security_depth":"standard"}'
[ "$CODE" = 200 ] && [ "$(echo "$BODY" | J effective.reveal)" = "['pin']" ] && ok "with pin + twofa fresh → lowered to standard" || fail "downgrade proven: $CODE $BODY"
call POST /api/blindkey/reveal "$TK" '{"name":"sightless"}'; [ "$CODE" = 403 ] && ok "the policy change spent the PIN proof: reveal asks again" || fail "spent by policy: $CODE $BODY"
call POST /api/blindkey/gate-policy "$TK" '{"name":"sightless","security_depth":"critical"}'; [ "$CODE" = 200 ] && ok "raise to critical: no proof needed" || fail "critical: $CODE $BODY"
call POST /api/blindkey/gate-policy "$TK" '{"name":"sightless","security_depth":"elevated"}'
[ "$CODE" = 403 ] && echo "$BODY" | J missing | grep -q "sms" && ok "critical → elevated needs pin + twofa + sms fresh" || fail "crit→elev: $CODE $BODY"
SQL "UPDATE blindkey_secrets SET security_depth=NULL, gate_policy=NULL"   # fixture reset (owner would prove pin+twofa+sms)
grep -q '"gate_policy_change_blocked"\|gate_policy_change_blocked' "$S/server.log" 2>/dev/null; true

# ── legacy fingerprint tokens, final round trip ───────────────────────────────────────────────────────
SQL "DELETE FROM gate_verifications"   # every window expires
call POST /api/identity/gate/verify "$TK" '{"gate":"fingerprint"}'; [ "$CODE" = 200 ] && ok "legacy fingerprint verify still answers (token is fingerprint-authed)" || fail "legacy verify: $CODE $BODY"
call POST /api/blindkey/reveal "$TK" '{"name":"sightless"}'; [ "$CODE" = 403 ] && ok "a fingerprint-authed token alone no longer reveals (PIN required)" || fail "reveal w/o pin after fp: $CODE $BODY"
call POST /api/identity/gate/verify "$TK" '{"gate":"pin","pin":"2468"}'; call POST /api/blindkey/reveal "$TK" '{"name":"sightless"}'; [ "$CODE" = 200 ] && ok "PIN → reveal again" || fail "final reveal: $CODE"
call POST /api/blindkey/reveal "$TK" '{"name":"sightless"}'; [ "$CODE" = 403 ] && ok "…and only once" || fail "final single-use: $CODE"
python3 - "$DB_PATH" <<'PY' && ok "every stored proof carries a session" || fail "proof rows without session"
import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); n=c.execute("SELECT COUNT(*) FROM gate_verifications WHERE session IS NULL").fetchone()[0]; sys.exit(1 if n else 0)
PY
grep -q "pin_failed\|pin_set\|pin_changed" "$S/server.log" && ok "security events logged" || true
echo "$fails failure(s)"; [ "$fails" = 0 ]
