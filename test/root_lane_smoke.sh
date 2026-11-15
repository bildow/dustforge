#!/bin/bash
# The root lane and the operator act (2026-11-14 root-lane adversarial review; ops/root-lane/).
#   - /use ssh_exec on the alias `racknerd-self` connects to ::1 (IPv6 loopback; racknerd masquerades IPv4 loopback), and only for the root lane's owner, in their own
#     session, with the entry wrapped to their phone (each call a tap), as root, with no key_name and no sudo;
#   - the alias is not a host anywhere else (rotate-blind), and loopback cannot be added to the host set by the
#     environment (BLINDKEY_SSH_HOSTS_EXTRA);
#   - POST /api/demipass/operator-act: the owner's phone approves one exact script (path + sha256) by a named route;
#     nobody else can ask; the approval is used once.
# A simulated phone (as crypto_depth_smoke) and a fake sshpass on PATH (as rotate_grant_timeout_smoke) play the parts.
set -u
W=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
S=$(mktemp -d /tmp/dustforge-root-lane.XXXXXX)
PORT=${PORT:-3871}; API=http://127.0.0.1:$PORT
[ -d "$W/node_modules" ] || export NODE_PATH=${NODE_PATH:-/home/flimflam/project/dustforge/node_modules}
export IDENTITY_MASTER_KEY=$(python3 -c 'import secrets;print(secrets.token_hex(32))') DB_PATH=$S/dustforge.db PORT \
  STALWART_HOST=127.0.0.1 STALWART_PORT=1 SMTP_RELAY_HOST= SMTP_HOST=127.0.0.1 SMTP_PORT=9 \
  BLINDKEY_SSH_HOSTS_EXTRA='127.0.0.1,localhost,racknerd-self,::1,127.0.1.1,10.0.0.9,0,2130706433,0x7f000001,0177.0.0.1,localhost.,ip6-localhost,localtest.me,100.73.251.12,010.0.0.9'
mkdir -p "$S/bin"
cat >"$S/bin/sshpass" <<'SH'
#!/bin/bash
echo "ARGV $*" >>"$FAKE_DIR/ssh.log"
echo "PW ${SSHPASS:-}" >>"$FAKE_DIR/ssh.pw"
last="${@: -1}"
if [ "$last" = "id -u" ]; then echo 0; else bash -c "$last"; fi
SH
chmod +x "$S/bin/sshpass"
export PATH="$S/bin:$PATH" FAKE_DIR=$S
cd "$W"
start(){ node server.js >>"$S/server.log" 2>&1 & SRV=$!
  for i in $(seq 1 40); do curl -s -o /dev/null "$API/" && break; sleep 0.5; done; kill -0 $SRV 2>/dev/null || { echo "server died:"; tail -5 "$S/server.log"; exit 1; }; }
start
trap 'kill $SRV 2>/dev/null; [ -n "${KEEP:-}" ] || rm -rf "$S"' EXIT
H=$(printf '%s' hunter22 | sha256sum | cut -d' ' -f1)
SIL='silicon:root-lane-smoke-token-0123456789'
node -e '
const identity = require("./identity"), crypto = require("crypto"); const Database = require("better-sqlite3"); const db = new Database(process.env.DB_PATH);
for (const c of ["idempotency_key TEXT", "provenance TEXT DEFAULT '"'"'organic'"'"'"]) { try { db.exec("ALTER TABLE identity_transactions ADD COLUMN " + c); } catch (_) {} }
const dids = {};
for (const u of ["rl-owner", "rl-other"]) { const id = identity.createIdentity(); const enc = id.encrypted_private_key || id.encryptedPrivateKey; dids[u] = id.did;
  db.prepare("INSERT INTO identity_wallets (did, username, email, encrypted_private_key, balance_cents, password_hash) VALUES (?, ?, ?, ?, 100000, ?)").run(id.did, u, u + "@dustforge.com", enc, process.argv[1]);
  db.prepare("INSERT INTO identity_transactions (did, amount_cents, type, description, balance_after) VALUES (?, 100000, ?, ?, 100000)").run(id.did, "topup", "smoke"); }
db.prepare("INSERT INTO silicon_agents (agent_name, did, carbon_did, token_hash) VALUES (?, ?, ?, ?)")
  .run("owner-bot", "did:silicon:rootlane", dids["rl-owner"], crypto.createHash("sha256").update(process.argv[2]).digest("hex"));' "$H" "$SIL"
DA=$(python3 -c "import sqlite3,sys; print(sqlite3.connect(sys.argv[1]).execute(\"SELECT did FROM identity_wallets WHERE username='rl-owner'\").fetchone()[0])" "$DB_PATH")
# The root lane's owner is named before the server starts (as the host's environment would).
kill $SRV; wait $SRV 2>/dev/null; export DUSTFORGE_ROOT_LANE_OWNER_DID=$DA; start

fails=0; ok(){ echo "ok   $*"; }; fail(){ echo "FAIL $*"; fails=$((fails+1)); }
J(){ python3 -c 'import json,sys; d=json.load(sys.stdin); v=d
for k in sys.argv[1].split("."):
    v = v[int(k)] if isinstance(v, list) else (v or {}).get(k)
print(v if not isinstance(v,(dict,list)) else json.dumps(v))' "$1"; }
Q(){ python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); r=c.execute(sys.argv[2]).fetchone(); print(r[0] if r else '')" "$DB_PATH" "$1"; }
X(){ python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute(sys.argv[2]); c.commit()" "$DB_PATH" "$1"; }
call(){ local m=$1 p=$2 t=$3 b=${4:-}
  BODY=$(curl -s -o - -w '\n%{http_code}' -X "$m" "$API$p" -H 'Content-Type: application/json' ${t:+-H "Authorization: Bearer $t"} ${b:+-d "$b"})
  CODE=${BODY##*$'\n'}; BODY=${BODY%$'\n'*}; }
login(){ call POST /api/identity/auth-fingerprint "" '{"username":"'$1'","password":"hunter22","scope":"transact","expires_in":"1h"}'; echo "$BODY" | J token; }
pin(){ call POST /api/identity/gate/verify "$1" '{"gate":"pin","pin":"4321","intent":"'$2'"}'; [ "$CODE" = 200 ] || fail "pin $2: $CODE $BODY"; }
node -e '
const c = require("crypto"), fs = require("fs");
for (const n of ["d", "p"]) { const { privateKey, publicKey } = c.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  fs.writeFileSync(process.argv[1] + "/" + n + ".pem", privateKey.export({ type: "pkcs8", format: "pem" }));
  fs.writeFileSync(process.argv[1] + "/" + n + ".pub", publicKey.export({ type: "spki", format: "der" }).toString("base64")); }
const w = c.generateKeyPairSync("rsa", { modulusLength: 2048 });
fs.writeFileSync(process.argv[1] + "/w.pem", w.privateKey.export({ type: "pkcs8", format: "pem" }));
fs.writeFileSync(process.argv[1] + "/w.pub", w.publicKey.export({ type: "spki", format: "der" }).toString("base64"));' "$S"
sig(){ node -e 'const c=require("crypto"),fs=require("fs"); process.stdout.write(c.sign("sha256", Buffer.from(process.argv[2]), fs.readFileSync(process.argv[1])).toString("base64"))' "$S/$1.pem" "$2"; }
rewrap(){ node -e 'const c=require("crypto"),fs=require("fs"); const o={padding:c.constants.RSA_PKCS1_OAEP_PADDING,oaepHash:"sha1"};
  const sealed=c.privateDecrypt({key:fs.readFileSync(process.argv[1]),...o},Buffer.from(process.argv[2],"base64"));
  const want=c.createHash("sha256").update("dp-wrap:v1|"+process.argv[4]+"|"+process.argv[5]+"|"+process.argv[6]).digest();
  if (sealed.length!==64 || !c.timingSafeEqual(sealed.subarray(32),want)) { process.stdout.write("REFUSED"); process.exit(0); }
  process.stdout.write(c.publicEncrypt({key:Buffer.from(process.argv[3],"base64"),format:"der",type:"spki",...o},sealed.subarray(0,32)).toString("base64"))' "$S/w.pem" "$1" "$2" "$3" "$4" "$5"; }
devsign(){ local tok=$1 intent=$2 bind=$3   # → CH SG
  call POST /api/identity/device/challenge "$tok" "$(python3 -c 'import json,sys; print(json.dumps({"purpose":"approve","intent":sys.argv[1],"bind":sys.argv[2]}))' "$intent" "$bind")"
  CH=$(echo "$BODY" | J challenge_id); SG=$(sig d "$(echo "$BODY" | J message)"); }

A=$(login rl-owner); N=$(login rl-other)
[ "$A" != None ] && [ "$N" != None ] && ok "owner and another wallet signed in; the root lane's owner is the owner's DID" || { fail login; exit 1; }
call POST /api/identity/pin "$A" '{"pin":"4321","password":"hunter22"}'
call POST /api/identity/device/challenge "$A" '{"purpose":"enrol","intent":"device-enrol:0"}'; CHD=$(echo "$BODY" | J challenge_id); MSG=$(echo "$BODY" | J message)
pin "$A" device-enrol:0; call POST /api/identity/gate/verify "$A" '{"gate":"password","password":"hunter22"}'
call POST /api/identity/device/enrol "$A" "$(printf '{"challenge_id":%s,"device_id":"phone-rl01","label":"Pixel","key_d":"%s","key_p":"%s","sig_d":"%s","sig_p":"%s"}' "$CHD" "$(cat $S/d.pub)" "$(cat $S/p.pub)" "$(sig d "$MSG:phone-rl01")" "$(sig p "$MSG:phone-rl01")")"
[ "$CODE" = 201 ] || { fail "enrol: $CODE $BODY"; exit 1; }
pin "$A" unlock:0
FP=$(python3 -c 'import base64,hashlib,sys; print(hashlib.sha256(base64.b64decode(open(sys.argv[1]).read())).hexdigest())' "$S/w.pub")
call POST /api/identity/device/wrap-key "$A" '{"device_id":"phone-rl01","key_w":"'$(cat $S/w.pub)'"}'
devsign "$A" wrap-key:0 "$FP"; call POST /api/identity/device/wrap-key "$A" '{"device_id":"phone-rl01","key_w":"'$(cat $S/w.pub)'","device_challenge_id":'$CH',"device_signature":"'$SG'"}'
[ "$CODE" = 200 ] && ok "the owner's phone is linked with a wrap key" || { fail "wrap-key: $CODE $BODY"; exit 1; }

# Secrets: the owner's root entry (wrapped), the owner's unwrapped entry, another wallet's entry; scopes set directly.
scope(){ local sid=$1 name=$2 host=$3; X "INSERT INTO blindkey_contexts (secret_id, context_name, action_type, target_url_pattern, target_host_pattern, allowed_by) VALUES ($sid, '$name', 'ssh_exec', '*', '$host', 'smoke')"; }
store(){ local tok=$1 name=$2 val=$3; call POST /api/demipass/store "$tok" '{"name":"'$name'","value":"'$val'","secret_type":"password"}'; }
umask 077; RV=$(python3 -c 'import secrets;print("rlroot-" + secrets.token_urlsafe(18))')
store "$A" rootlane "$RV"; RID=$(Q "SELECT id FROM blindkey_secrets WHERE name='rootlane'"); RREF=$(Q "SELECT ref_code FROM blindkey_secrets WHERE id=$RID")
X "UPDATE blindkey_secrets SET account_username='root' WHERE id=$RID"; scope $RID self racknerd-self
call POST /api/demipass/gate-policy "$A" '{"name":"rootlane","security_depth":"elevated"}'
[ "$CODE" = 200 ] && [ "$(Q "SELECT wrap_state FROM blindkey_secrets WHERE id=$RID")" = device ] && ok "the root entry is elevated and wrapped to the phone" || fail "raise: $CODE $BODY"
store "$A" plainroot plainroot-value-zz91; PID=$(Q "SELECT id FROM blindkey_secrets WHERE name='plainroot'"); PREF=$(Q "SELECT ref_code FROM blindkey_secrets WHERE id=$PID")
X "UPDATE blindkey_secrets SET account_username='root' WHERE id=$PID"; scope $PID self racknerd-self; scope $PID lo 127.0.0.1; scope $PID lan 10.0.0.9
store "$N" otherroot otherroot-value-zz92; OID=$(Q "SELECT id FROM blindkey_secrets WHERE name='otherroot'"); OREF=$(Q "SELECT ref_code FROM blindkey_secrets WHERE id=$OID")
X "UPDATE blindkey_secrets SET account_username='root' WHERE id=$OID"; scope $OID self racknerd-self

USE(){ python3 -c 'import json,sys; b={"ref":sys.argv[1],"action":"ssh_exec","context":sys.argv[2],"params":{"target_host":sys.argv[3],"command":"id -u","target_user":sys.argv[4]}}
if len(sys.argv) > 5 and sys.argv[5]: b["params"].update(json.loads(sys.argv[5]))
print(json.dumps(b))' "$@"; }
WITH(){ python3 -c 'import json,sys; b=json.loads(sys.argv[1]); b["approval_id"]=int(sys.argv[2]); print(json.dumps(b))' "$1" "$2"; }
# The phone approves a parked request; with $3 = secret ref and name it also unwraps it for that request.
approve(){ local ap=$1 ref=${2:-} name=${3:-} BIND UN EPH WD UW extra=""
  for i in $(seq 1 20); do [ -n "$(Q "SELECT COALESCE(eph_pub,'') FROM use_approvals WHERE id=$ap")" ] && break; [ -z "$ref" ] && break; sleep 0.2; done
  BIND=$(Q "SELECT binding FROM use_approvals WHERE id=$ap")
  [ "$(Q "SELECT depth FROM use_approvals WHERE id=$ap")" = critical ] && pin "$A" "approval-open:$ap"   # critical: the PIN every time
  devsign "$A" "approval-open:$ap" "$BIND"; call POST /api/demipass/approvals/$ap/open "$A" '{"device_challenge_id":'$CH',"device_signature":"'$SG'"}'; local CODEV; CODEV=$(echo "$BODY" | J code)
  if [ -n "$ref" ]; then
    call GET /api/demipass/approvals "$A"; UN=$(echo "$BODY" | python3 -c 'import json,sys; d=json.load(sys.stdin); a=[x for x in d["incoming"] if x["id"]=='$ap'][0]; print(json.dumps(a.get("unwrap")))')
    EPH=$(echo "$UN" | J eph_pub); WD=$(echo "$UN" | python3 -c 'import json,sys; print(json.load(sys.stdin)["wraps"]["'$FP'"])')
    UW=$(rewrap "$WD" "$EPH" "$DA" "$ref" "$name"); extra=',"unwrap":"'$UW'"'
  fi
  devsign "$A" "approval:$ap" "$BIND"; call POST /api/demipass/approvals/$ap/approve "$A" '{"code":"'$CODEV'","device_challenge_id":'$CH',"device_signature":"'$SG'"'"$extra"'}'
  [ "$CODE" = 200 ] || fail "approve $ap: $CODE $BODY"; }

# ── the root lane ──
: > "$S/ssh.log"
B=$(USE "$RREF" self racknerd-self root); call POST /api/demipass/use "$A" "$B"; AP=$(echo "$BODY" | J approval_id)
[ "$CODE" = 202 ] && [ "$AP" != None ] && ok "the owner's root-lane call parks for the phone (wrapped entry)" || fail "park: $CODE $BODY"
approve "$AP" "$RREF" rootlane
call POST /api/demipass/use "$A" "$(WITH "$B" "$AP")"
[ "$CODE" = 200 ] && grep -q -- "-- root@::1 id -u" "$S/ssh.log" && grep -qxF "PW $RV" "$S/ssh.pw" && ! echo "$BODY" | grep -qF -- "$RV" \
  && ok "…approved with the phone's unwrap: it logs in to root@::1 with the stored password, never shown" || fail "lane: $CODE $BODY $(cat $S/ssh.log)"
grep -q -- "-o PubkeyAuthentication=no" "$S/ssh.log" && ok "…by password alone (no key is offered)" || fail "pubkey: $(cat $S/ssh.log)"

# refusals BEFORE the phone is asked (#119 review M5): a call that could never run pages nobody and unwraps nothing
X "INSERT INTO blindkey_contexts (secret_id, context_name, action_type, target_url_pattern, target_host_pattern, allowed_by) VALUES ($RID, 'wild', 'ssh_exec', '*', '*', 'smoke')"
for v in 'self|aaron||' 'self|root|{"sudo":true}|sudo' 'self|root|{"key_name":"somekey"}|key_name' 'wild|root||a wildcard scope'; do
  IFS='|' read -r cx u p why <<<"$v"
  n0=$(Q "SELECT COUNT(*) FROM use_approvals")
  : > "$S/ssh.log"; B=$(USE "$RREF" "$cx" racknerd-self "$u" "$p"); call POST /api/demipass/use "$A" "$B"
  [ "$CODE" = 403 ] && [ "$(Q "SELECT COUNT(*) FROM use_approvals")" = "$n0" ] && [ ! -s "$S/ssh.log" ] \
    && ok "root lane as '$u'${why:+ with $why} → 403 before the phone is asked (no approval filed, nothing connects)" || fail "lane $u $why: $CODE $BODY"
done

: > "$S/ssh.log"
call POST /api/demipass/use "$SIL" "$(USE "$RREF" self racknerd-self root)"
[ "$CODE" != 200 ] && [ "$CODE" != 202 ] && [ ! -s "$S/ssh.log" ] && ok "a silicon token on the owner's wallet cannot use the root lane ($CODE)" || fail "silicon: $CODE $BODY"
call POST /api/demipass/use "$A" "$(USE "$PREF" self racknerd-self root)"
[ "$CODE" = 403 ] && echo "$BODY" | grep -q "wrapped" && [ ! -s "$S/ssh.log" ] && ok "the owner's entry that is not wrapped to the phone → 403" || fail "unwrapped: $CODE $BODY"
call POST /api/demipass/use "$N" "$(USE "$OREF" self racknerd-self root)"
[ "$CODE" = 403 ] && echo "$BODY" | grep -q "one wallet" && [ ! -s "$S/ssh.log" ] && ok "another wallet's entry scoped to the alias → 403" || fail "other wallet: $CODE $BODY"
[ "$(Q "SELECT COUNT(*) FROM demipass_security_events WHERE event_type='root_lane_refused'")" -ge 2 ] && ok "…each refusal is a critical security event" || fail "events: $(Q "SELECT COUNT(*) FROM demipass_security_events WHERE event_type='root_lane_refused'")"

# ── loopback is not a host otherwise ──
bad=0
for h in 127.0.0.1 0 2130706433 0x7f000001 0177.0.0.1 localhost. ip6-localhost localtest.me 127.0.1.1 100.73.251.12 010.0.0.9 ::1 '[::1]' 0:0:0:0:0:0:0:1 ::ffff:127.0.0.1; do
  X "INSERT INTO blindkey_contexts (secret_id, context_name, action_type, target_url_pattern, target_host_pattern, allowed_by) VALUES ($PID, 'h-$h', 'ssh_exec', '*', '$h', 'smoke')"
  : > "$S/ssh.log"; call POST /api/demipass/use "$A" "$(USE "$PREF" "h-$h" "$h" root)"
  { [ "$CODE" = 200 ] || [ -s "$S/ssh.log" ]; } && { bad=1; echo "  $h → $CODE connected=$([ -s "$S/ssh.log" ] && echo yes || echo no)"; }
done
[ $bad = 0 ] && ok "loopback in any spelling (0, 2130706433, 0x7f000001, 0177.0.0.1, localhost., ip6-localhost, ::1 in four spellings, a name), the box's own tailnet IP, an octal-looking IP: refused although named in BLINDKEY_SSH_HOSTS_EXTRA" || fail "loopback extra"
[ "$(grep -c "BLINDKEY_SSH_HOSTS_EXTRA: '" "$S/server.log")" -ge 26 ] && ok "…each ignored entry is named in the server log at start" || fail "boot warnings: $(grep -c "BLINDKEY_SSH_HOSTS_EXTRA: '" "$S/server.log")"
: > "$S/ssh.log"; call POST /api/demipass/use "$A" "$(USE "$PREF" lan 10.0.0.9 root)"
[ "$CODE" = 200 ] && grep -q -- "-- root@10.0.0.9" "$S/ssh.log" && ok "…while a plain public-or-private IPv4 in it is accepted" || fail "extra host: $CODE $BODY"
: > "$S/ssh.log"
call POST /api/demipass/rotate-blind "$A" '{"ref":"'$PREF'","target_host":"racknerd-self","target_user":"root","context":"self"}'
[ "$CODE" = 403 ] && echo "$BODY" | grep -q "not in SSH whitelist" && [ ! -s "$S/ssh.log" ] && ok "rotate-blind refuses the alias (it is not a host)" || fail "rotate alias: $CODE $BODY"

# ── operator act ──
SHA=$(printf 'apply' | sha256sum | cut -d' ' -f1)
C40=$(printf 'commit' | sha1sum | cut -d' ' -f1); SC=$(printf 'confirm' | sha256sum | cut -d' ' -f1); SR=$(printf 'rollback' | sha256sum | cut -d' ' -f1)
OA='{"host":"192.3.84.103","script_path":"/opt/dustforge/ops/root-lane/apply.sh","script_sha256":"'$SHA'","route":"phasewhip-mirror-key","commit":"'$C40'","companions_sha256":["'$SC'","'$SR'"],"purpose":"if the lane login fails"}'
call POST /api/demipass/operator-act "" "$OA"; [ "$CODE" = 401 ] && ok "operator act: no token → 401" || fail "oa anon: $CODE"
call POST /api/demipass/operator-act "$N" "$OA"; [ "$CODE" = 403 ] && ok "another wallet cannot ask for an operator act" || fail "oa other: $CODE $BODY"
call POST /api/demipass/operator-act "$SIL" "$OA"; [ "$CODE" = 403 ] && ok "an agent token on the owner's wallet cannot either" || fail "oa silicon: $CODE $BODY"
bad=0
for b in '"host":"10.0.0.9"' '"script_path":"/opt/dustforge/ops/../../etc/x"' '"script_path":"/tmp/x.sh"' '"script_sha256":"ABC"' '"route":"curl"' '"commit":"abc"' '"companions_sha256":["xyz"]' '"purpose":"'"$(printf 'p%.0s' {1..201})"'"'; do
  call POST /api/demipass/operator-act "$A" "$(python3 -c 'import json,sys; b=json.loads(sys.argv[1]); b.update(json.loads("{"+sys.argv[2]+"}")); print(json.dumps(b))' "$OA" "$b")"
  [ "$CODE" = 400 ] || { bad=1; echo "  $b → $CODE"; }
done
[ $bad = 0 ] && ok "operator act: another host, a path outside ops/ or scripts/ (or with ..), a bad sha256, an unknown route, a bad commit or companion sha256, a purpose over 200 → 400" || fail "oa validation"
call POST /api/demipass/operator-act "$A" "$OA"; OAP=$(echo "$BODY" | J approval_id)
[ "$CODE" = 202 ] && ok "the owner's operator act parks for the phone" || fail "oa park: $CODE $BODY"
call GET /api/demipass/approvals "$A"; SUM=$(echo "$BODY" | python3 -c 'import json,sys; d=json.load(sys.stdin); a=[x for x in d["incoming"] if x["id"]=='$OAP'][0]; print(a.get("summary","") + " | " + a.get("purpose",""))')
echo "$SUM" | grep -q "ops/root-lane/apply.sh as root on racknerd via phasewhip-mirror-key" && echo "$SUM" | grep -q "${SHA:0:12}" && echo "$SUM" | grep -q "${C40:0:10}" && echo "$SUM" | grep -q "if the lane login fails" \
  && ok "…its card names the script, the host, the route, the commit, the sha256 and the purpose" || fail "oa card: $SUM"
OB=$(WITH "$OA" "$OAP")
call POST /api/demipass/operator-act "$A" "$(python3 -c 'import json,sys; b=json.loads(sys.argv[1]); b["script_sha256"]="0"*64; print(json.dumps(b))' "$OB")"
[ "$CODE" != 200 ] && ok "an approval id redeemed with another sha256 does not pass ($CODE)" || fail "oa swap: $CODE $BODY"
for f in '"commit":"'"$(printf '1%.0s' {1..40})"'"' '"companions_sha256":["'$SR'","'$SC'"]'; do
  call POST /api/demipass/operator-act "$A" "$(python3 -c 'import json,sys; b=json.loads(sys.argv[1]); b.update(json.loads("{"+sys.argv[2]+"}")); print(json.dumps(b))' "$OB" "$f")"
  [ "$CODE" = 409 ] || fail "oa swap $f: $CODE"
done
ok "…nor with another commit or companion list (409: both bound)"
call POST /api/demipass/operator-act "$A" "$(python3 -c 'import json,sys; b=json.loads(sys.argv[1]); del b["companions_sha256"]; print(json.dumps(b))' "$OA")"
[ "$CODE" = 400 ] && ok "…and the root-lane apply is never approved without its two companion scripts (400)" || fail "oa no companions: $CODE $BODY"
[ "$(Q "SELECT depth FROM use_approvals WHERE id=$OAP")" = critical ] && ok "…and it is asked at critical depth (the PIN every time)" || fail "oa depth: $(Q "SELECT depth FROM use_approvals WHERE id=$OAP")"
approve "$OAP"
# Redeemed with another purpose (purpose is not part of the binding): the record keeps the one the card showed (#119 re-review).
call POST /api/demipass/operator-act "$A" "$(python3 -c 'import json,sys; b=json.loads(sys.argv[1]); b["purpose"]="dry run only - nothing changes"; print(json.dumps(b))' "$OB")"
[ "$CODE" = 200 ] && [ "$(echo "$BODY" | J approved)" = True ] && [ "$(echo "$BODY" | J script_sha256)" = "$SHA" ] && [ "$(echo "$BODY" | J purpose)" = "if the lane login fails" ] \
  && ok "…approved: the answer is the consent record (script, sha256, route, commit), with the purpose the card showed" || fail "oa approved: $CODE $BODY"
T=$(Q "SELECT note FROM ticks WHERE note LIKE 'Operator act approved%' ORDER BY id DESC LIMIT 1")
echo "$T" | grep -q "if the lane login fails" && ! echo "$T" | grep -q "dry run" && ok "…and the ledger tick records the card's purpose, not the redeeming call's" || fail "oa tick: $T"
[ "$(Q "SELECT COUNT(*) FROM demipass_security_events WHERE event_type='operator_act_approved'")" = 1 ] && ok "…logged once as a security event" || fail "oa event"
call POST /api/demipass/operator-act "$A" "$OB"; [ "$CODE" != 200 ] && ok "…and the approval is spent ($CODE on reuse)" || fail "oa reuse: $CODE"

echo; [ $fails = 0 ] && echo "ALL PASSED" || { echo "$fails FAILED"; tail -20 "$S/server.log"; exit 1; }
