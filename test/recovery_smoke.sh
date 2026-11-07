#!/bin/bash
# Item 9 step 3 — guardian recovery end to end (design v1.1; tests R1–R3, R6–R8, C3, C8). server.js on a throwaway DB
# with a fake Stalwart (the mailbox password is set first, fail closed); phones simulated with node crypto; the owner's
# guardians seeded (their setup is tested in recovery_guardians_smoke).
set -u
W=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
S=$(mktemp -d /tmp/dustforge-recovery.XXXXXX)
PORT=${PORT:-3881}; STP=${STP:-3882}; API=http://127.0.0.1:$PORT
[ -d "$W/node_modules" ] || export NODE_PATH=${NODE_PATH:-/home/flimflam/project/dustforge/node_modules}
export IDENTITY_MASTER_KEY=$(python3 -c 'import secrets;print(secrets.token_hex(32))') DB_PATH=$S/dustforge.db PORT HOLD_SWEEP_MS=500 \
  STALWART_HOST=127.0.0.1 STALWART_PORT=$STP SMTP_RELAY_HOST= SMTP_HOST=127.0.0.1 SMTP_PORT=9
cd "$W"
# fake Stalwart: logs each PATCH; $S/stalwart.fail holds how many of the next PATCHes answer 500
node -e 'const fs=require("fs"); require("http").createServer((q, r) => { let b=""; q.on("data", c => b += c); q.on("end", () => {
  const f = process.argv[2] + "/stalwart.fail"; let n = 0; try { n = +fs.readFileSync(f, "utf8"); } catch (_) {}
  if (q.method === "GET") { r.writeHead(200); return r.end(JSON.stringify({ data: { secrets: ["PRIOR-SECRET"] } })); }
  if (n > 0) fs.writeFileSync(f, String(n - 1));
  let v = ""; try { v = JSON.parse(b)[0].value[0]; } catch (_) {}
  fs.appendFileSync(process.argv[2] + "/stalwart.log", q.method + " " + q.url + " " + (n > 0 ? 500 : 200) + " " + (v === "PRIOR-SECRET" ? "prior" : "new") + "\n"); r.writeHead(n > 0 ? 500 : 200); r.end("{}"); }); }).listen(+process.argv[1], "127.0.0.1");' $STP "$S" & STW=$!
(exec node server.js >"$S/server.log" 2>&1) & SRV=$!
trap 'kill $SRV $STW 2>/dev/null; [ -n "${KEEP:-}" ] || rm -rf "$S"' EXIT
for i in $(seq 1 60); do curl -s -o /dev/null "$API/api/health" && break; sleep 0.5; done
kill -0 $SRV 2>/dev/null || { echo "server died:"; tail -5 "$S/server.log"; exit 1; }
sleep 1
H=$(printf '%s' hunter22 | sha256sum | cut -d' ' -f1)
node -e '
(async () => {
const identity = require("./identity"); const Database = require("better-sqlite3"); const db = new Database(process.env.DB_PATH);
const pinGate = require("./pin_gate"), passwords = require("./passwords");
const ph = await passwords.hashPassword("hunter22");   // a current salted hash: sign-in never asks the (fake) mail server
for (const u of ["owner", "lonely", "g1", "g2", "g3", "g4"]) { const id = identity.createIdentity(); const enc = id.encrypted_private_key || id.encryptedPrivateKey;
  db.prepare("INSERT INTO identity_wallets (did, username, email, encrypted_private_key, balance_cents, password_hash, pin_hash, pin_set_at) VALUES (?, ?, ?, ?, 0, ?, ?, ?)")
    .run(id.did, u, u + "@dustforge.com", enc, ph, pinGate.hashPin("4321"), "2026-01-01 00:00:00.000"); }
})()'
fails=0; ok(){ echo "ok   $*"; }; fail(){ echo "FAIL $*"; fails=$((fails+1)); }
J(){ python3 -c 'import json,sys; d=json.load(sys.stdin); v=d
for k in sys.argv[1].split("."):
    v = v[int(k)] if isinstance(v, list) else (v or {}).get(k)
print(v)' "$1"; }
Q(){ python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); r=c.execute(sys.argv[2]).fetchone(); print(r[0] if r else '')" "$DB_PATH" "$1"; }
X(){ python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute(sys.argv[2]); c.commit()" "$DB_PATH" "$1"; }
call(){ local m=$1 p=$2 t=$3 b=${4:-}
  BODY=$(curl -s -o - -w '\n%{http_code}' -X "$m" "$API$p" -H 'Content-Type: application/json' -H "X-Forwarded-For: 10.$((RANDOM%250)).$((RANDOM%250)).$((RANDOM%250+1))" ${t:+-H "Authorization: Bearer $t"} ${b:+-d "$b"})
  CODE=${BODY##*$'\n'}; BODY=${BODY%$'\n'*}; }
iso(){ python3 -c "import datetime,sys; print((datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(seconds=float(sys.argv[1]))).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3]+'Z')" "$1"; }
did(){ Q "SELECT did FROM identity_wallets WHERE username='$1'"; }
login(){ call POST /api/identity/auth-fingerprint "" '{"username":"'$1'","password":"'${2:-hunter22}'","scope":"transact","expires_in":"1h"}'; echo "$BODY" | J token; }
keys(){ node -e 'const c = require("crypto"), fs = require("fs");
for (const k of ["d", "p"]) { const { privateKey, publicKey } = c.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  fs.writeFileSync(process.argv[1] + "/" + process.argv[2] + k + ".pem", privateKey.export({ type: "pkcs8", format: "pem" }));
  fs.writeFileSync(process.argv[1] + "/" + process.argv[2] + k + ".pub", publicKey.export({ type: "spki", format: "der" }).toString("base64")); }' "$S" "$1"; }
sig(){ node -e 'const c=require("crypto"),fs=require("fs"); process.stdout.write(c.sign("sha256", Buffer.from(process.argv[2]), fs.readFileSync(process.argv[1])).toString("base64"))' "$S/$1.pem" "$2"; }
phone(){ keys "$1"; for k in D P; do X "INSERT INTO device_keys (did, device_id, kind, public_key, label, enrolled_at) VALUES ('$(did $1)', 'phone-$1', '$k', '$(cat $S/$1$(echo $k | tr DP dp).pub)', '$1', '${2:-$(iso -864000)}')"; done; }
pair(){ local a b; a=$(did $1); b=$(did $2); [[ "$a" > "$b" ]] && { local t=$a; a=$b; b=$t; }; X "INSERT INTO network_peers (did_a, did_b, status, verified_via, verified_at) VALUES ('$a', '$b', 'active', 'qr', '$(iso -864000)')"; }
guard(){ X "INSERT INTO recovery_guardians (owner_did, guardian_did, status, invited_at, accepted_at) VALUES ('$(did $1)', '$(did $2)', 'active', '$(iso -864000)', '$(iso -864000)')"; }
fp(){ python3 -c "import hashlib,sys; print(hashlib.sha256(open(sys.argv[1]).read().strip().encode()).hexdigest()[:16])" "$S/$1d.pub"; }
for u in owner g1 g2 g3; do phone $u; done
for g in g1 g2 g3; do pair owner $g; guard owner $g; done
X "INSERT INTO blindkey_secrets (did, name, secret_type, encrypted_value, status, ref_code, security_depth) VALUES ('$(did owner)', 'root-pw', 'password', 'dpwrap:v1', 'active', 'DP-PWD-rootpw-00000001', 'elevated')"
OLD=$(login owner)
# start: <account> <newphone> → RID, CODE6, FP
start(){ keys "$2"; call POST /api/identity/recovery/challenge "" '{"account":"'$1'"}'; local n m; n=$(echo "$BODY" | J challenge); m=$(echo "$BODY" | J message)
  call POST /api/identity/recovery/start "" '{"account":"'$1'","challenge":"'$n'","device_id":"newphone-'$2'","label":"New '$2'","key_d":"'$(cat $S/${2}d.pub)'","key_p":"'$(cat $S/${2}p.pub)'","sig_d":"'$(sig ${2}d "$m:newphone-${2}")'","sig_p":"'$(sig ${2}p "$m:newphone-${2}")'"}'
  RID=$(echo "$BODY" | J request_id); CODE6=$(echo "$BODY" | J code); FP=$(fp $2); }
# a guardian approves <rid> with <code>
gapprove(){ local T; T=$(login $1); call POST /api/identity/gate/verify "$T" '{"gate":"pin","pin":"4321","intent":"recovery-approve:'$2'"}'
  call POST /api/identity/gate/verify "$T" '{"gate":"pin","pin":"4321","intent":"unlock:0"}'
  local fpv; fpv=${4:-$FP}
  call POST /api/identity/device/challenge "$T" '{"purpose":"approve","intent":"recovery-approve:'$2'","bind":"'$2'|'$fpv'|'$3'"}'
  local c m; c=$(echo "$BODY" | J challenge_id); m=$(echo "$BODY" | J message)
  call POST /api/identity/recovery/$2/approve "$T" '{"code":"'$3'","device_challenge_id":'$c',"device_signature":"'$(sig ${1}d "$m")'"}'; }
complete(){ call POST /api/identity/recovery/$1/complete-challenge "" '{"device_id":"newphone-'$2'"}'; local n m; n=$(echo "$BODY" | J challenge); m=$(echo "$BODY" | J message)
  [ -z "$n" ] || [ "$n" = None ] && return 0
  call POST /api/identity/recovery/$1/complete "" '{"device_id":"newphone-'$2'","challenge":"'$n'","sig_d":"'$(sig ${2}d "$m")'","sig_p":"'$(sig ${2}p "$m")'","new_password":"brand-new-pass-1"}'; }
ownercancel(){ call POST /api/identity/holds/challenge "" '{"purpose":"cancel","device_id":"phone-owner","hold_id":"'$1'"}'; local n m; n=$(echo "$BODY" | J challenge); m=$(echo "$BODY" | J message)
  call POST /api/identity/holds/$1/cancel "" '{"device_id":"phone-owner","challenge":"'$n'","signature":"'$(sig ownerp "$m")'"}'; }
due(){ X "UPDATE account_holds SET ready_at='$(iso -1)' WHERE id='$1'"; }

# ── R6 ──
call POST /api/identity/recovery/challenge "" '{"account":"nobody-here"}'; n=$(echo "$BODY" | J challenge); m=$(echo "$BODY" | J message); keys px
call POST /api/identity/recovery/start "" '{"account":"nobody-here","challenge":"'$n'","device_id":"newphone-px","key_d":"'$(cat $S/pxd.pub)'","key_p":"'$(cat $S/pxp.pub)'","sig_d":"'$(sig pxd "$m:newphone-px")'","sig_p":"'$(sig pxp "$m:newphone-px")'"}'
[ "$CODE" = 404 ] && ok "R6 an unknown account: 404 (names are public anyway)" || fail "R6 unknown: $CODE $BODY"
start lonely pl; K1=$(echo "$BODY" | python3 -c "import json,sys; print(sorted(json.load(sys.stdin)))")
start owner pa; K2=$(echo "$BODY" | python3 -c "import json,sys; print(sorted(json.load(sys.stdin)))")
[ "$CODE" = 202 ] && [ "$K1" = "$K2" ] && ! echo "$BODY" | grep -q 'g1\|g2\|g3' && ok "R6 the same 202 with or without guardians, and no guardian names" || fail "R6 shape: $K1 vs $K2 $BODY"
RA=$RID; CA=$CODE6; FA=$FP
[ "$(Q "SELECT COUNT(*) FROM demipass_security_events WHERE event_type='account_hold_started' AND caller_did='$(did owner)'")" -ge 1 ] && ok "R6 the owner is alerted at start" || fail "R6 alert"

# ── R7: what a guardian sees ──
T1=$(login g1); call GET /api/identity/recovery/asks "$T1"
echo "$BODY" | grep -q '"owner":"owner"' && ! echo "$BODY" | grep -qi 'root-pw\|balance\|g2\|g3\|code_hash\|key_d' && ok "R7 a guardian sees the owner's name and the new phone's code — no secrets, balances, other guardians or the code" || fail "R7 view: $BODY"

# ── R3 ──
gapprove g1 $RA 000000; [ "$CODE" = 403 ] || fail "R3 wrong 1: $CODE"
gapprove g2 $RA 000001; [ "$CODE" = 403 ] || fail "R3 wrong 2: $CODE"
gapprove g3 $RA 000002
[ "$CODE" = 403 ] && [ "$(Q "SELECT status FROM account_holds WHERE id='$RA'")" = canceled ] && ok "R3 three wrong codes across guardians cancel the request" || fail "R3 cancel: $CODE $BODY"
start owner pb; RB=$RID; CB=$CODE6
gapprove g1 $RB $CB 0000000000000000; [ "$CODE" = 409 ] && [ "$(Q "SELECT status FROM account_holds WHERE id='$RB'")" = pending ] && ok "R3 an approval signed for another phone's key code is refused (it binds this new phone)" || fail "R3 bind: $CODE $BODY"

# ── R2 ──
gapprove g1 $RB $CB; [ "$CODE" = 200 ] && [ "$(echo "$BODY" | J status)" = pending ] && ok "R2 one approval: still pending" || fail "R2 one: $CODE $BODY"
due $RB; complete $RB pb; [ "$CODE" = 409 ] || [ "$CODE" = 404 ] && ok "R2 one approval cannot complete" || fail "R2 one complete: $CODE $BODY"
gapprove g2 $RB $CB; [ "$(echo "$BODY" | J status)" = quorum ] && ok "R2 the second approval: quorum, 48 h start now" || fail "R2 quorum: $CODE $BODY"
complete $RB pb; [ "$CODE" = 409 ] && echo "$BODY" | grep -q "48 hours" && ok "R2 before the 48 h are over: refused" || fail "R2 early: $CODE $BODY"

# ── C8: withdraw below quorum stops the clock; decline cancels ──
T2=$(login g2); call POST /api/identity/recovery/$RB/withdraw "$T2"
[ "$(echo "$BODY" | J status)" = pending ] && [ "$(Q "SELECT COALESCE(ready_at,'') FROM account_holds WHERE id='$RB'")" = "" ] && ok "C8 a withdraw below quorum clears the clock" || fail "C8 withdraw: $BODY"
gapprove g2 $RB $CB; [ "$(echo "$BODY" | J status)" = quorum ] || fail "C8 re-approve: $BODY"
start owner pc; RC=$RID
T3=$(login g3); call POST /api/identity/gate/verify "$T3" '{"gate":"pin","pin":"4321","intent":"recovery-approve:'$RC'"}'; call POST /api/identity/recovery/$RC/decline "$T3"
[ "$CODE" = 200 ] && [ "$(Q "SELECT status FROM account_holds WHERE id='$RC'")" = canceled ] && ok "C8 a guardian's decline cancels it" || fail "C8 decline: $CODE $BODY"

# ── C3: past ready_at, the owner's phone still cancels until completion starts; then completion is refused ──
start owner pd; RD=$RID; CD=$CODE6; gapprove g1 $RD $CD; gapprove g3 $RD $CD; due $RD
ownercancel $RD; [ "$CODE" = 200 ] || fail "C3 cancel: $CODE $BODY"
complete $RD pd; { [ "$CODE" = 404 ] || [ "$CODE" = 409 ]; } && [ "$(Q "SELECT status FROM account_holds WHERE id='$RD'")" = canceled ] && ok "C3 canceled after the 48 h but before completing: completion refused" || fail "C3 complete after cancel: $CODE $BODY"

# ── #61 re-review M4: junk starts neither block nor displace a real request ──
for i in 1 2 3 4 5 6; do start owner pj$i; [ "$CODE" = 202 ] || fail "M4 junk $i: $CODE $BODY"; done
[ "$(Q "SELECT status FROM account_holds WHERE id='$RB'")" = quorum ] && ok "M4 six unapproved starts later the real (approved) request is untouched" || fail "M4 displaced: $(Q "SELECT status FROM account_holds WHERE id='$RB'")"
# ── M2: a guardian whose account just linked a phone cannot approve ──
start owner pe; RE=$RID; CE=$CODE6
X "UPDATE device_keys SET enrolled_at='$(iso -86400)' WHERE device_id='phone-g3'"
gapprove g3 $RE $CE; [ "$CODE" = 403 ] && echo "$BODY" | grep -q "7 days" && ok "M2 a guardian whose phone was linked in the last 7 days cannot approve" || fail "M2: $CODE $BODY"
X "UPDATE device_keys SET enrolled_at='$(iso -864000)' WHERE device_id='phone-g3'"

# ── R1: complete ──
due $RB; echo 1 >"$S/stalwart.fail"; complete $RB pb
[ "$CODE" = 503 ] && [ "$(Q "SELECT status FROM account_holds WHERE id='$RB'")" = quorum ] && [ "$(Q "SELECT COUNT(*) FROM device_keys WHERE device_id='phone-owner' AND revoked_at IS NULL")" = 2 ] && [ "$(grep -c PATCH "$S/stalwart.log")" = 2 ] && tail -1 "$S/stalwart.log" | grep -q " prior$" \
  && ok "R1 the mail server answered unclearly: the mailbox was put back (2nd PATCH), nothing changed (503), still ready and cancelable" || fail "R1 stalwart fail: $CODE $BODY $(cat "$S/stalwart.log")"
echo 2 >"$S/stalwart.fail"; complete $RB pb
[ "$CODE" = 503 ] && [ "$(Q "SELECT status FROM account_holds WHERE id='$RB'")" = completing ] && ok "R1 neither the change nor the undo confirmed: it stays completing (no cancel can split it)" || fail "R1 stuck: $CODE $(Q "SELECT status FROM account_holds WHERE id='$RB'")"
ownercancel $RB; [ "$CODE" = 404 ] && ok "R1 …a cancel cannot land on it now" || fail "R1 cancel on completing: $CODE"
complete $RB pb; [ "$CODE" = 409 ] && ok "R1 …and a retry right away waits a minute" || fail "R1 early retry: $CODE $BODY"
X "UPDATE account_holds SET note='completing:$(iso -120)' WHERE id='$RB'"
complete $RB pb
[ "$CODE" = 200 ] && [ "$(echo "$BODY" | J completed)" = True ] && ok "R1 two approvals and 48 h later, the new phone completes it" || fail "R1 complete: $CODE $BODY"
echo "$BODY" | grep -q '"wrapped_lost":\["root-pw"\]' && ok "R8 the wrapped secret is reported lost, by name only" || fail "R8 lost: $BODY"
grep -q "PATCH /api/principal/owner" "$S/stalwart.log" && ok "R1 the mailbox password was set first" || fail "R1 stalwart log"
[ "$(Q "SELECT COUNT(*) FROM device_keys WHERE device_id='phone-owner' AND revoked_at IS NULL")" = 0 ] && [ "$(Q "SELECT COUNT(*) FROM device_keys WHERE device_id='newphone-pb' AND revoked_at IS NULL")" = 2 ] && ok "R1 the old phone is unlinked, the new one linked" || fail "R1 devices"
call GET /api/identity/holds "$OLD"; [ "$CODE" = 401 ] && ok "R1 old sessions are dead" || fail "R1 old session: $CODE"
NEW=$(login owner brand-new-pass-1); [ -n "$NEW" ] && [ "$NEW" != None ] && ok "R1 the new password signs in" || fail "R1 new password"
[ -z "$(login owner hunter22 | grep -v None)" ] && ok "R1 the old password does not" || fail "R1 old password still works"
[ "$(Q "SELECT COALESCE(pin_hash,'') FROM identity_wallets WHERE username='owner'")" = "" ] && ok "R1 the PIN is cleared (set a new one)" || fail "R1 pin"
[ "$(Q "SELECT status FROM account_holds WHERE id='$RE'")" = canceled ] && ok "R1 other waiting recoveries are canceled" || fail "R1 other recoveries: $(Q "SELECT status FROM account_holds WHERE id='$RE'")"
complete $RB pb; { [ "$CODE" = 404 ] || [ "$CODE" = 409 ]; } && ok "R1 a completed recovery cannot run twice" || fail "R1 twice: $CODE"
echo; [ $fails = 0 ] && echo "ALL PASS" || { echo "$fails FAILED"; exit 1; }
