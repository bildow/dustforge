#!/bin/bash
# QR pairing (red team item 6, queue 4): contacts confirmed in person; shares and secret transfers only between them.
# server.js on a throwaway DB. Wallets: A (shows the QR), B (scans it), C (a third person), N (no PIN), G (an agent).
#   - the QR token: 5-minute, one join, random 12-digit id; own code / wrong secret / second scanner refused; wrong
#     codes count against the one presenting them (10 an hour), never against the pairing
#   - both screens show the same 6-digit code naming this pairing and these two wallets
#   - each side confirms with its PIN (intent pair:<id>); once a phone is linked, also its device key over "<other>|<code>"
#   - both confirmed → a contact with verified_via='qr'; a contact made by name request cannot be shared with
#   - cancel (codes differ) and expiry end it; agents and PIN-less wallets cannot pair
set -u
W=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
S=$(mktemp -d /tmp/dustforge-pairing-smoke.XXXXXX)
PORT=${PORT:-3823}; API=http://127.0.0.1:$PORT
[ -d "$W/node_modules" ] || export NODE_PATH=${NODE_PATH:-/home/flimflam/project/dustforge/node_modules}
export IDENTITY_MASTER_KEY=$(python3 -c 'import secrets;print(secrets.token_hex(32))') DB_PATH=$S/dustforge.db PORT \
  STALWART_HOST=127.0.0.1 STALWART_PORT=1 SMTP_RELAY_HOST= SMTP_HOST=127.0.0.1 SMTP_PORT=9
cd "$W"
node server.js >"$S/server.log" 2>&1 & SRV=$!
trap 'kill $SRV 2>/dev/null; rm -rf "$S"' EXIT
for i in $(seq 1 40); do curl -s -o /dev/null "$API/" && break; sleep 0.5; done
kill -0 $SRV 2>/dev/null || { echo "server died:"; tail -5 "$S/server.log"; exit 1; }
H=$(printf '%s' hunter22 | sha256sum | cut -d' ' -f1)
node -e '
const identity = require("./identity"); const Database = require("better-sqlite3"); const db = new Database(process.env.DB_PATH);
for (const c of ["idempotency_key TEXT", "provenance TEXT DEFAULT '"'"'organic'"'"'"]) { try { db.exec("ALTER TABLE identity_transactions ADD COLUMN " + c); } catch (_) {} }
for (const u of ["pa", "pb", "pc", "pn", "pg"]) { const id = identity.createIdentity(); const enc = id.encrypted_private_key || id.encryptedPrivateKey;
  db.prepare("INSERT INTO identity_wallets (did, username, email, encrypted_private_key, balance_cents, password_hash) VALUES (?, ?, ?, ?, 100000, ?)").run(id.did, u, u + "@dustforge.com", enc, process.argv[1]);
  db.prepare("INSERT INTO identity_transactions (did, amount_cents, type, description, balance_after) VALUES (?, 100000, ?, ?, 100000)").run(id.did, "topup", "smoke"); }' "$H"
fails=0; ok(){ echo "ok   $*"; }; fail(){ echo "FAIL $*"; fails=$((fails+1)); }
J(){ python3 -c 'import json,sys; d=json.load(sys.stdin); v=d
for k in sys.argv[1].split("."):
    v = v[int(k)] if isinstance(v, list) else (v or {}).get(k)
print(v)' "$1"; }
Q(){ python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); r=c.execute(sys.argv[2]).fetchone(); print(r[0] if r else '')" "$DB_PATH" "$1"; }
X(){ python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute(sys.argv[2]); c.commit()" "$DB_PATH" "$1"; }
call(){ local m=$1 p=$2 t=$3 b=${4:-}
  BODY=$(curl -s -o - -w '\n%{http_code}' -X "$m" "$API$p" -H 'Content-Type: application/json' ${t:+-H "Authorization: Bearer $t"} ${b:+-d "$b"})
  CODE=${BODY##*$'\n'}; BODY=${BODY%$'\n'*}; }
login(){ call POST /api/identity/auth-fingerprint "" '{"username":"'$1'","password":"hunter22","scope":"transact","expires_in":"1h"}'; echo "$BODY" | J token; }
pin(){ call POST /api/identity/gate/verify "$1" '{"gate":"pin","pin":"'$2'","intent":"'$3'"}'; [ "$CODE" = 200 ] || fail "pin $3: $CODE $BODY"; }
did(){ Q "SELECT did FROM identity_wallets WHERE username='$1'"; }
A=$(login pa); B=$(login pb); C=$(login pc); N=$(login pn); G=$(login pg)
for t in "$A:1111" "$B:2222" "$C:3333" "$G:5555"; do call POST /api/identity/pin "${t%%:*}" '{"pin":"'${t##*:}'","password":"hunter22"}'; done
DA=$(did pa); DB=$(did pb); DC=$(did pc)
# G is an agent: an active silicon of A's fleet (made the way the network makes it)
call POST /api/network/requests "$A" '{"to":"pg","as":"agent"}'; R=$(echo "$BODY" | J request.id); pin "$G" 5555 "join:$R"; call POST /api/network/requests/$R/accept "$G"
[ "$CODE" = 200 ] || fail "agent join: $CODE $BODY"
# A and B are also contacts by name request (the old, phishable way)
call POST /api/network/requests "$A" '{"to":"pb","as":"person"}'; R=$(echo "$BODY" | J request.id); call POST /api/network/requests/$R/accept "$B"
call POST /api/demipass/store "$A" '{"name":"wifi","value":"wifi-pass-zz91","secret_type":"password"}'; SID=$(Q "SELECT id FROM blindkey_secrets WHERE name='wifi'")
pin "$A" 1111 "share:$SID"; call POST /api/demipass/shares "$A" '{"secret":"wifi","to":"pb"}'
[ "$CODE" = 403 ] && [ "$(echo "$BODY" | J pair_required)" = True ] && ok "a contact made by name request cannot be shared with (pair_required)" || fail "share unconfirmed: $CODE $BODY"
pin "$A" 1111 "transfer:$SID"; call POST /api/demipass/transfer "$A" '{"secret":"wifi","to":"pb"}'
[ "$CODE" = 403 ] && [ "$(echo "$BODY" | J pair_required)" = True ] && ok "…nor transferred to" || fail "transfer unconfirmed: $CODE $BODY"

# ── who may pair ──
call POST /api/network/pair/start "$N"; [ "$CODE" = 403 ] && [ "$(echo "$BODY" | J pin_required)" = True ] && ok "a wallet without a PIN cannot pair (it could not confirm)" || fail "no pin: $CODE $BODY"
call POST /api/network/pair/start "$G"; [ "$CODE" = 403 ] && echo "$BODY" | grep -q agent && ok "an agent wallet cannot pair" || fail "agent: $CODE $BODY"
# (fleet-minted tokens exist only for agents, refused just above; pairing.js also refuses the mint claim itself)

# ── the QR ──
call POST /api/network/pair/start "$A"; P=$(echo "$BODY" | J pair_id); TOK=$(echo "$BODY" | J token); QR=$(echo "$BODY" | J qr)
[ "$CODE" = 200 ] && [[ "$QR" == "https://demipass.com/pair#$TOK" ]] && [[ "$TOK" =~ ^$P\.[A-Za-z0-9_-]{22}$ ]] && [ "$(Q "SELECT secret_hash FROM contact_pairings WHERE id=$P")" != "${TOK#*.}" ] \
  && ok "start → a QR URL with the token in the fragment; the server keeps only the secret's hash" || fail "start: $CODE $BODY"
call POST /api/network/pair/join "$A" '{"token":"'$TOK'"}'; [ "$CODE" = 400 ] && ok "scanning your own code → 400" || fail "own: $CODE $BODY"
call POST /api/network/pair/join "$C" '{"token":"'$P'.AAAAAAAAAAAAAAAAAAAAAA"}'; [ "$CODE" = 403 ] && [ "$(Q "SELECT status FROM contact_pairings WHERE id=$P")" = open ] && ok "a wrong secret for the id → 403, the pairing stays open" || fail "wrong: $CODE"
call POST /api/network/pair/join "$B" '{"token":"'$QR'"}'   # the whole scanned URL works
CB=$(echo "$BODY" | J code); [ "$CODE" = 200 ] && [[ "$CB" =~ ^[0-9]{6}$ ]] && [ "$(echo "$BODY" | J other)" = pa ] && ok "B scans it: B's screen shows pa and a 6-digit code" || fail "join: $CODE $BODY"
call GET /api/network/pair/$P "$A"; [ "$(echo "$BODY" | J code)" = "$CB" ] && [ "$(echo "$BODY" | J other)" = pb ] && [ "$(echo "$BODY" | J status)" = joined ] && ok "A's screen shows pb and the same code" || fail "A view: $BODY"
EXP=$(python3 -c 'import hmac,hashlib,sys; m=hmac.new(sys.argv[1].encode(),("dp-pair:%s:%s:%s"%(sys.argv[2],sys.argv[3],sys.argv[4])).encode(),hashlib.sha256).digest(); print("%06d"%(int.from_bytes(m[:4],"big")%1000000))' "${TOK#*.}" "$P" "$DA" "$DB")
[ "$EXP" = "$CB" ] && ok "the code is HMAC(secret, pairing id, both DIDs): it names this pairing and these two wallets" || fail "code derivation: $EXP vs $CB"
call POST /api/network/pair/join "$C" '{"token":"'$TOK'"}'; [ "$CODE" = 409 ] && ok "a second scanner of the same QR → 409 (one join per QR)" || fail "second: $CODE $BODY"
call GET /api/network/pair/$P "$C"; [ "$CODE" = 404 ] && ok "a third wallet cannot read the pairing" || fail "C read: $CODE"

# ── confirm ──
call POST /api/demipass/shares "$A" '{"secret":"wifi","to":"pb"}'; [ "$CODE" = 403 ] || fail "share mid-pairing: $CODE"
call POST /api/network/pair/$P/confirm "$A" '{}'; [ "$CODE" = 403 ] && [ "$(echo "$BODY" | J intent)" = "pair:$P" ] && ok "confirming needs the PIN (intent pair:<id>)" || fail "confirm no pin: $CODE $BODY"
pin "$A" 1111 "pair:$P"; call POST /api/network/pair/$P/confirm "$A" '{}'
[ "$CODE" = 200 ] && [ "$(echo "$BODY" | J you_confirmed)" = True ] && [ "$(echo "$BODY" | J connected)" = False ] && ok "A confirms; not a confirmed contact until B does too" || fail "A confirm: $CODE $BODY"
pin "$A" 1111 "share:$SID"; call POST /api/demipass/shares "$A" '{"secret":"wifi","to":"pb"}'; [ "$CODE" = 403 ] && ok "…still no share after one side" || fail "share half: $CODE"
pin "$B" 2222 "pair:$P"; call POST /api/network/pair/$P/confirm "$B" '{}'
[ "$CODE" = 200 ] && [ "$(echo "$BODY" | J connected)" = True ] && [ "$(Q "SELECT verified_via FROM network_peers WHERE (did_a='$DA' AND did_b='$DB') OR (did_a='$DB' AND did_b='$DA')")" = qr ] \
  && ok "B confirms → confirmed contacts (network_peers.verified_via = qr)" || fail "B confirm: $CODE $BODY"
pin "$A" 1111 "share:$SID"; call POST /api/demipass/shares "$A" '{"secret":"wifi","to":"pb"}'; SH=$(echo "$BODY" | J share.id)
[ "$CODE" = 200 ] || [ "$CODE" = 201 ] && ok "a share to the confirmed contact goes through" || fail "share confirmed: $CODE $BODY"
call POST /api/network/pair/$P/cancel "$A" '{}'; [ "$CODE" = 409 ] && ok "a confirmed pairing cannot be cancelled (remove the contact instead)" || fail "cancel done: $CODE"

# ── removal takes the confirmation away (through the real routes — #52 review) ──
call POST /api/network/people/remove "$B" '{"username":"pa"}'; [ "$CODE" = 200 ] || fail "remove: $CODE $BODY"
pin "$B" 2222 "share-accept:$SH"; call POST /api/demipass/shares/$SH/accept "$B"
[ "$CODE" = 403 ] && [ "$(echo "$BODY" | J pair_required)" = True ] && ok "a pending share is not taken once the contact is removed" || fail "accept removed: $CODE $BODY"
call POST /api/network/requests "$A" '{"to":"pb","as":"person"}'; R=$(echo "$BODY" | J request.id); call POST /api/network/requests/$R/accept "$B"
[ "$CODE" = 200 ] || fail "re-add by name: $CODE $BODY"
pin "$B" 2222 "share-accept:$SH"; call POST /api/demipass/shares/$SH/accept "$B"
[ "$CODE" = 403 ] && [ "$(Q "SELECT COALESCE(verified_via,'none') FROM network_peers WHERE (did_a='$DA' AND did_b='$DB') OR (did_a='$DB' AND did_b='$DA')")" = none ] \
  && ok "re-added by name request: a contact again, but not confirmed — no share rights until they pair again" || fail "re-add keeps confirmation: $CODE $BODY"
pair_again(){ call POST /api/network/pair/start "$A"; local p=$(echo "$BODY" | J pair_id) t=$(echo "$BODY" | J token)
  call POST /api/network/pair/join "$B" '{"token":"'$t'"}'; pin "$A" 1111 "pair:$p"; call POST /api/network/pair/$p/confirm "$A" '{}'; pin "$B" 2222 "pair:$p"; call POST /api/network/pair/$p/confirm "$B" '{}'; }
pair_again; [ "$(echo "$BODY" | J connected)" = True ] || fail "pair again: $CODE $BODY"
pin "$B" 2222 "share-accept:$SH"; call POST /api/demipass/shares/$SH/accept "$B"; [ "$CODE" = 200 ] && ok "…paired in person again, the share is taken" || fail "accept: $CODE $BODY"

# ── mismatch, expiry, guessing ──
call POST /api/network/pair/start "$C"; P2=$(echo "$BODY" | J pair_id); T2=$(echo "$BODY" | J token)
call POST /api/network/pair/join "$A" '{"token":"'$T2'"}'
call POST /api/network/pair/$P2/cancel "$A" '{"mismatch":true}'; [ "$CODE" = 200 ] && [ "$(echo "$BODY" | J status)" = cancelled ] && ok "codes differ → either side cancels" || fail "mismatch: $CODE $BODY"
[ "$(Q "SELECT COUNT(*) FROM security_events WHERE event_type='pairing_code_mismatch'" 2>/dev/null || echo 1)" -ge 1 ] || fail "mismatch event"
pin "$C" 3333 "pair:$P2"; call POST /api/network/pair/$P2/confirm "$C" '{}'; [ "$CODE" = 409 ] && ok "…and nobody can confirm it afterwards" || fail "confirm cancelled: $CODE"
call POST /api/network/pair/start "$C"; P3=$(echo "$BODY" | J pair_id); T3=$(echo "$BODY" | J token); call POST /api/network/pair/join "$A" '{"token":"'$T3'"}'
X "UPDATE contact_pairings SET expires_at='2000-01-01T00:00:00.000Z' WHERE id=$P3"
pin "$C" 3333 "pair:$P3"; call POST /api/network/pair/$P3/confirm "$C" '{}'; [ "$CODE" = 409 ] && echo "$BODY" | grep -q expired && ok "an expired pairing cannot be confirmed" || fail "expired: $CODE $BODY"
call POST /api/network/pair/start "$C"; P4=$(echo "$BODY" | J pair_id); T4=$(echo "$BODY" | J token)
[[ "$P4" =~ ^[1-9][0-9]{11}$ ]] && ok "pairing ids are random 12-digit numbers (not enumerable)" || fail "id shape: $P4"
for i in 1 2 3 4 5 6 7 8 9 10; do call POST /api/network/pair/join "$B" '{"token":"'$P4'.BBBBBBBBBBBBBBBBBBBBB'$((i%10))'"}'; done
[ "$(Q "SELECT status FROM contact_pairings WHERE id=$P4")" = open ] && ok "wrong codes from another wallet never cancel someone's pairing (#52 review)" || fail "victim cancelled: $(Q "SELECT status FROM contact_pairings WHERE id=$P4")"
call POST /api/network/pair/join "$B" '{"token":"'$T4'"}'
[ "$CODE" = 429 ] && ok "…the guesser is refused after 10 wrong codes in an hour (even with a right one)" || fail "guesser limit: $CODE $BODY"
X "DELETE FROM contact_pairing_misses"
call POST /api/network/pair/join "$B" '{"token":"'$T4'"}'; [ "$CODE" = 200 ] && ok "…and the owner's pairing still works for a real scan" || fail "after guessing: $CODE $BODY"
call POST /api/network/pair/$P4/cancel "$C" '{}'
for i in 1 2 3; do call POST /api/network/pair/start "$B"; done; call POST /api/network/pair/start "$B"
[ "$CODE" = 429 ] && ok "at most 3 open pairings per wallet" || fail "open cap: $CODE"

# ── a linked phone signs the confirmation (red team 4b) ──
node -e '
const c = require("crypto"), fs = require("fs");
for (const n of ["d", "p"]) { const { privateKey, publicKey } = c.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  fs.writeFileSync(process.argv[1] + "/" + n + ".pem", privateKey.export({ type: "pkcs8", format: "pem" }));
  fs.writeFileSync(process.argv[1] + "/" + n + ".pub", publicKey.export({ type: "spki", format: "der" }).toString("base64")); }' "$S"
sig(){ node -e 'const c=require("crypto"),fs=require("fs"); process.stdout.write(c.sign("sha256", Buffer.from(process.argv[2]), fs.readFileSync(process.argv[1])).toString("base64"))' "$S/$1.pem" "$2"; }
call POST /api/identity/device/challenge "$C" '{"purpose":"enrol","intent":"device-enrol:0"}'; CHD=$(echo "$BODY" | J challenge_id); MSG=$(echo "$BODY" | J message)
SGD=$(sig d "$MSG:phone-cccc"); SGP=$(sig p "$MSG:phone-cccc")
pin "$C" 3333 device-enrol:0; call POST /api/identity/gate/verify "$C" '{"gate":"password","password":"hunter22"}'
call POST /api/identity/device/enrol "$C" "$(printf '{"challenge_id":%s,"device_id":"phone-cccc","label":"C phone","key_d":"%s","key_p":"%s","sig_d":"%s","sig_p":"%s"}' "$CHD" "$(cat $S/d.pub)" "$(cat $S/p.pub)" "$SGD" "$SGP")"
[ "$CODE" = 201 ] || fail "enrol C: $CODE $BODY"
call POST /api/network/pair/start "$C"; P5=$(echo "$BODY" | J pair_id); T5=$(echo "$BODY" | J token); call POST /api/network/pair/join "$A" '{"token":"'$T5'"}'
pin "$C" 3333 unlock:0
pin "$C" 3333 "pair:$P5"; call POST /api/network/pair/$P5/confirm "$C" '{}'
[ "$CODE" = 428 ] && [ "$(echo "$BODY" | J challenge.bind)" = "pa|$(Q "SELECT code FROM contact_pairings WHERE id=$P5")" ] && ok "with a linked phone, the PIN alone does not confirm: 428, the phone signs \"<other>|<code>\"" || fail "device required: $CODE $BODY"
BIND=$(echo "$BODY" | J challenge.bind)
call POST /api/identity/device/challenge "$C" '{"purpose":"approve","intent":"pair:'$P5'","bind":"pa|000000"}'; CH=$(echo "$BODY" | J challenge_id); SG=$(sig d "$(echo "$BODY" | J message)")
pin "$C" 3333 "pair:$P5"; call POST /api/network/pair/$P5/confirm "$C" '{"device_challenge_id":'$CH',"device_signature":"'$SG'"}'
[ "$CODE" = 409 ] && ok "a signature over another code is refused (409)" || fail "wrong bind: $CODE $BODY"
call POST /api/identity/device/challenge "$C" '{"purpose":"approve","intent":"pair:'$P5'","bind":"'"$BIND"'"}'; CH=$(echo "$BODY" | J challenge_id); SG=$(sig d "$(echo "$BODY" | J message)")
pin "$C" 3333 "pair:$P5"; call POST /api/network/pair/$P5/confirm "$C" '{"device_challenge_id":'$CH',"device_signature":"'$SG'"}'
[ "$CODE" = 200 ] && [ "$(echo "$BODY" | J you_confirmed)" = True ] && ok "…the phone's signature over this pairing's name and code confirms it" || fail "device confirm: $CODE $BODY"

echo; [ $fails = 0 ] && echo "ALL OK" || echo "$fails failure(s)"; exit $fails
