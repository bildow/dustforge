#!/bin/bash
# Edit and search in the vault (Aaron 2026-11-15: "a way to edit a secret and search for one on the GUI").
#   - POST /api/demipass/edit: the owner, signed in as a person, replaces a value it never sees (typed, or copied from
#     another of its entries). Same entry (the ref stays), scopes carry over, the owner's own agents' delegations move,
#     a person's share or an outside agent's delegation ends only after confirm_left. The old version retires at once.
#     PIN always; the entry's rotate factors (elevated: + email code); critical: + an approved request (kind 'edit',
#     which never asks the phone for an unwrap). A copy never lowers a value's depth. No value in any reply or row.
#   - /rotate now moves the owner's own agents' delegations too (as /rotate-blind has since 2026-11-11).
#   - dashboard: username (was always null), seen_by_person_at, attention (leaked after written; last use failed).
#   - legacy fixture: a database from before seen_by_person_at starts, gets the column, and its rows read NULL.
set -u
W=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
S=$(mktemp -d /tmp/dustforge-vault-edit.XXXXXX)
PORT=${PORT:-3873}; API=http://127.0.0.1:$PORT
[ -d "$W/node_modules" ] || export NODE_PATH=${NODE_PATH:-/home/flimflam/project/dustforge/node_modules}
export IDENTITY_MASTER_KEY=$(python3 -c 'import secrets;print(secrets.token_hex(32))') DB_PATH=$S/dustforge.db PORT \
  STALWART_HOST=127.0.0.1 STALWART_PORT=1 SMTP_RELAY_HOST= SMTP_HOST=127.0.0.1 SMTP_PORT=9
cd "$W"
start(){ node server.js >>"$S/server.log" 2>&1 & SRV=$!
  for i in $(seq 1 40); do curl -s -o /dev/null "$API/" && break; sleep 0.5; done; kill -0 $SRV 2>/dev/null || { echo "server died:"; tail -5 "$S/server.log"; exit 1; }; }
stop(){ kill $SRV 2>/dev/null; wait $SRV 2>/dev/null; }
start
trap 'kill $SRV 2>/dev/null; [ -n "${KEEP:-}" ] || rm -rf "$S"' EXIT
H=$(printf '%s' hunter22 | sha256sum | cut -d' ' -f1)
SIL='silicon:vault-edit-smoke-token-0123456789'
node -e '
const identity = require("./identity"), crypto = require("crypto"); const Database = require("better-sqlite3"); const db = new Database(process.env.DB_PATH);
for (const c of ["idempotency_key TEXT", "provenance TEXT DEFAULT '"'"'organic'"'"'"]) { try { db.exec("ALTER TABLE identity_transactions ADD COLUMN " + c); } catch (_) {} }
for (const u of ["ve-owner", "ve-other", "ve-agent", "ve-outside"]) { const id = identity.createIdentity(); const enc = id.encrypted_private_key || id.encryptedPrivateKey;
  db.prepare("INSERT INTO identity_wallets (did, username, email, encrypted_private_key, balance_cents, password_hash) VALUES (?, ?, ?, ?, 100000, ?)").run(id.did, u, u + "@dustforge.com", enc, process.argv[1]);
  db.prepare("INSERT INTO identity_transactions (did, amount_cents, type, description, balance_after) VALUES (?, 100000, ?, ?, 100000)").run(id.did, "topup", "smoke"); }
const did = (u) => db.prepare("SELECT did FROM identity_wallets WHERE username = ?").get(u).did;
db.prepare("INSERT INTO silicon_agents (agent_name, did, carbon_did, token_hash) VALUES (?, ?, ?, ?)").run("owner-bot", "did:silicon:veown", did("ve-owner"), crypto.createHash("sha256").update(process.argv[2]).digest("hex"));
// The owner fleet made ve-agent (its own agent); ve-outside is just another wallet.
const f = db.prepare("INSERT INTO fleets (owner_did, name, slug) VALUES (?, ?, ?)").run(did("ve-owner"), "ve", "ve-fleet").lastInsertRowid;
db.prepare("INSERT INTO fleet_silicons (fleet_id, member_did, handle, silicon_id, status, created_by_fleet, joined_via) VALUES (?, ?, ?, ?, ?, 1, ?)").run(f, did("ve-agent"), "ve-agent", "sil_veagent01", "active", "owner");' "$H" "$SIL"

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
sess(){ python3 -c 'import base64,json,sys; p=sys.argv[1].split(".")[1]; d=json.loads(base64.urlsafe_b64decode(p+"="*(-len(p)%4))); print(d.get("sid") or d.get("jti"))' "$1"; }
twofa(){ X "INSERT INTO gate_verifications (did, gate_type, session, verified_at) VALUES ('$DA', 'twofa', '$(sess "$1")', strftime('%Y-%m-%d %H:%M:%f', 'now'))"; }
EDIT(){ python3 -c 'import json,sys; b=json.loads(sys.argv[1]); print(json.dumps(b))' "$1"; }
node -e '
const c = require("crypto"), fs = require("fs");
for (const n of ["d", "p"]) { const { privateKey, publicKey } = c.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  fs.writeFileSync(process.argv[1] + "/" + n + ".pem", privateKey.export({ type: "pkcs8", format: "pem" }));
  fs.writeFileSync(process.argv[1] + "/" + n + ".pub", publicKey.export({ type: "spki", format: "der" }).toString("base64")); }
const w = c.generateKeyPairSync("rsa", { modulusLength: 2048 });
fs.writeFileSync(process.argv[1] + "/w.pem", w.privateKey.export({ type: "pkcs8", format: "pem" }));
fs.writeFileSync(process.argv[1] + "/w.pub", w.publicKey.export({ type: "spki", format: "der" }).toString("base64"));' "$S"
sig(){ node -e 'const c=require("crypto"),fs=require("fs"); process.stdout.write(c.sign("sha256", Buffer.from(process.argv[2]), fs.readFileSync(process.argv[1])).toString("base64"))' "$S/$1.pem" "$2"; }
devsign(){ local tok=$1 intent=$2 bind=$3
  call POST /api/identity/device/challenge "$tok" "$(python3 -c 'import json,sys; print(json.dumps({"purpose":"approve","intent":sys.argv[1],"bind":sys.argv[2]}))' "$intent" "$bind")"
  CH=$(echo "$BODY" | J challenge_id); SG=$(sig d "$(echo "$BODY" | J message)"); }

A=$(login ve-owner); N=$(login ve-other)
DA=$(Q "SELECT did FROM identity_wallets WHERE username='ve-owner'"); DAG=$(Q "SELECT did FROM identity_wallets WHERE username='ve-agent'"); DOUT=$(Q "SELECT did FROM identity_wallets WHERE username='ve-outside'")
[ "$A" != None ] && [ "$N" != None ] && ok "owner and another wallet signed in" || { fail login; exit 1; }
call POST /api/identity/pin "$A" '{"pin":"4321","password":"hunter22"}'
call POST /api/identity/device/challenge "$A" '{"purpose":"enrol","intent":"device-enrol:0"}'; CHD=$(echo "$BODY" | J challenge_id); MSG=$(echo "$BODY" | J message)
pin "$A" device-enrol:0; call POST /api/identity/gate/verify "$A" '{"gate":"password","password":"hunter22"}'
call POST /api/identity/device/enrol "$A" "$(printf '{"challenge_id":%s,"device_id":"phone-ve01","label":"Pixel","key_d":"%s","key_p":"%s","sig_d":"%s","sig_p":"%s"}' "$CHD" "$(cat $S/d.pub)" "$(cat $S/p.pub)" "$(sig d "$MSG:phone-ve01")" "$(sig p "$MSG:phone-ve01")")"
[ "$CODE" = 201 ] || { fail "enrol: $CODE $BODY"; exit 1; }
pin "$A" unlock:0
FP=$(python3 -c 'import base64,hashlib,sys; print(hashlib.sha256(base64.b64decode(open(sys.argv[1]).read())).hexdigest())' "$S/w.pub")
call POST /api/identity/device/wrap-key "$A" '{"device_id":"phone-ve01","key_w":"'$(cat $S/w.pub)'"}'
devsign "$A" wrap-key:0 "$FP"; call POST /api/identity/device/wrap-key "$A" '{"device_id":"phone-ve01","key_w":"'$(cat $S/w.pub)'","device_challenge_id":'$CH',"device_signature":"'$SG'"}'
[ "$CODE" = 200 ] && ok "the owner's phone is linked with a wrap key" || { fail "wrap-key: $CODE $BODY"; exit 1; }

scope(){ X "INSERT INTO blindkey_contexts (secret_id, context_name, action_type, target_url_pattern, target_host_pattern, allowed_by) VALUES ($1, '$2', 'ssh_exec', '*', '$3', 'smoke')"; }
store(){ call POST /api/demipass/store "$1" '{"name":"'$2'","value":"'$3'","secret_type":"password"}'; }
deleg(){ X "INSERT INTO demipass_delegations (owner_did, delegate_did, secret_id, context_id, status) VALUES ('$DA', '$1', $2, ${3:-NULL}, 'active')"; }
umask 077
OLDV=$(python3 -c 'import secrets;print("veold-" + secrets.token_urlsafe(16))'); NEWV=$(python3 -c 'import secrets;print("venew-" + secrets.token_urlsafe(16))')
SRCV=$(python3 -c 'import secrets;print("vesrc-" + secrets.token_urlsafe(16))')
store "$A" ve-ssh "$OLDV"; T1=$(Q "SELECT id FROM blindkey_secrets WHERE name='ve-ssh'"); REF1=$(Q "SELECT ref_code FROM blindkey_secrets WHERE id=$T1")
X "UPDATE blindkey_secrets SET account_username='apple' WHERE id=$T1"; scope $T1 box 192.3.84.103; C1=$(Q "SELECT id FROM blindkey_contexts WHERE secret_id=$T1")
deleg "$DAG" $T1 $C1; DG_OWN=$(Q "SELECT id FROM demipass_delegations WHERE delegate_did='$DAG'")
deleg "$DOUT" $T1 $C1; DG_OUT=$(Q "SELECT id FROM demipass_delegations WHERE delegate_did='$DOUT'")

# ── who may edit ──
call POST /api/demipass/edit "" "$(EDIT '{"ref":"'$REF1'","new_value":"x"}')"
[ "$CODE" = 401 ] && ok "no token → 401" || fail "no token: $CODE"
call POST /api/demipass/edit "$SIL" "$(EDIT '{"ref":"'$REF1'","new_value":"'$NEWV'"}')"
[ "$CODE" = 403 ] && ok "an agent (silicon) token → 403" || fail "silicon: $CODE $BODY"
call POST /api/identity/device/code "" '{"agent_label":"some-pane","scope":"transact"}'; DC=$(echo "$BODY" | J device_code)
X "UPDATE device_auth SET status='approved', approved_did='$DA' WHERE device_code='$DC'"
call POST /api/identity/device/token "" '{"device_code":"'$DC'"}'; DEVT=$(echo "$BODY" | J access_token); [ "$DEVT" = None ] && DEVT=$(echo "$BODY" | J token)
call POST /api/demipass/edit "$DEVT" "$(EDIT '{"ref":"'$REF1'","new_value":"'$NEWV'"}')"
[ "$DEVT" != None ] && [ "$CODE" = 403 ] && echo "$BODY" | grep -q "device sign-in" && ok "the owner's wallet through a device-login (an agent's sign-in) → 403: an edit is a person's act" || fail "device: $DEVT $CODE $BODY"
call POST /api/demipass/edit "$N" "$(EDIT '{"ref":"'$REF1'","new_value":"'$NEWV'"}')"
[ "$CODE" = 404 ] && ok "another wallet → 404 (not its entry)" || fail "other: $CODE $BODY"
call POST /api/demipass/edit "$A" "$(EDIT '{"ref":"'$REF1'","new_value":"'$NEWV'","from_ref":"'$REF1'"}')"
[ "$CODE" = 400 ] && ok "new_value and from_ref together → 400" || fail "both: $CODE"
# ── grants that would not follow: said first, before any factor ──
call POST /api/demipass/edit "$A" "$(EDIT '{"ref":"'$REF1'","new_value":"'$NEWV'"}')"; LT=$(echo "$BODY" | J left_token)
[ "$CODE" = 409 ] && [ "$(echo "$BODY" | J left)" = 1 ] && [ "$LT" != None ] && echo "$BODY" | grep -q "an outside agent's delegation" && ok "an outside agent's grant would end → 409 left=1 with a left_token, named rightly, before the PIN is asked" || fail "left: $CODE $BODY"
call POST /api/demipass/edit "$A" "$(EDIT '{"ref":"'$REF1'","new_value":"'$NEWV'","confirm_left":true}')"
[ "$CODE" = 400 ] && ok "…a bare confirm_left:true is not a confirmation (400)" || fail "bare confirm: $CODE $BODY"
# a grant added after the 409: the old token no longer confirms (the set it named changed)
deleg "$DOUT" $T1; DG_OUT2=$(Q "SELECT MAX(id) FROM demipass_delegations WHERE delegate_did='$DOUT'")
call POST /api/demipass/edit "$A" "$(EDIT '{"ref":"'$REF1'","new_value":"'$NEWV'","confirm_left":"'$LT'"}')"
[ "$CODE" = 409 ] && [ "$(echo "$BODY" | J left)" = 2 ] && ok "…a token for an older set of grants is refused: 409 again, now left=2" || fail "stale token: $CODE $BODY"
X "DELETE FROM demipass_delegations WHERE id=$DG_OUT2"
call POST /api/demipass/edit "$A" "$(EDIT '{"ref":"'$REF1'","new_value":"'$NEWV'","confirm_left":"'$LT'"}')"
[ "$CODE" = 403 ] && [ "$(echo "$BODY" | J intent)" = "edit:$T1" ] && echo "$BODY" | J missing | grep -q pin && ok "…with the token: the PIN is asked, for this edit only (intent edit:$T1)" || fail "pin ask: $CODE $BODY"
pin "$A" "edit:$T1"
call POST /api/demipass/edit "$A" "$(EDIT '{"ref":"'$REF1'","new_value":"'$NEWV'","confirm_left":"'$LT'"}')"
NEWNAME=$(echo "$BODY" | J new_name); T1B=$(Q "SELECT id FROM blindkey_secrets WHERE ref_code='$REF1'")
[ "$CODE" = 200 ] && [ "$NEWNAME" = ve-ssh_v2 ] && [ "$(echo "$BODY" | J ref)" = "$REF1" ] && ok "standard: PIN → 200; same entry: the ref stays, now on version 2" || fail "edit: $CODE $BODY"
! echo "$BODY" | grep -qF -- "$NEWV" && ! echo "$BODY" | grep -qF -- "$OLDV" && ok "…the reply holds neither value" || fail "value in reply"
[ "$(Q "SELECT status FROM blindkey_secrets WHERE id=$T1")" = retired ] && [ -z "$(Q "SELECT encrypted_value FROM blindkey_secrets WHERE id=$T1")" ] && ok "…the old version is retired at once, its value erased" || fail "old: $(Q "SELECT status FROM blindkey_secrets WHERE id=$T1")"
[ "$(Q "SELECT COUNT(*) FROM blindkey_contexts WHERE secret_id=$T1B AND status='active' AND target_host_pattern='192.3.84.103'")" = 1 ] && ok "…the scope carried over" || fail "scope"
[ "$(Q "SELECT secret_id FROM demipass_delegations WHERE id=$DG_OWN")" = "$T1B" ] && [ "$(Q "SELECT context_id FROM demipass_delegations WHERE id=$DG_OWN")" = "$(Q "SELECT id FROM blindkey_contexts WHERE secret_id=$T1B")" ] && ok "…the owner's own agent's delegation moved to the new version and its scope" || fail "own deleg: $(Q "SELECT secret_id FROM demipass_delegations WHERE id=$DG_OWN")"
[ "$(Q "SELECT secret_id FROM demipass_delegations WHERE id=$DG_OUT")" = "$T1" ] && [ "$(Q "SELECT status FROM demipass_delegations WHERE id=$DG_OUT")" = revoked ] && [ "$(echo "$BODY" | J delegations_ended)" = 1 ] && ok "…the outside agent's stayed with the old version and is revoked: ended, as confirmed" || fail "outside deleg: $(Q "SELECT status FROM demipass_delegations WHERE id=$DG_OUT")"
[ "$(Q "SELECT COUNT(*) FROM blindkey_events WHERE event_type='delegation_revoked' AND detail LIKE '%\"delegation_id\":$DG_OUT,%' AND detail LIKE '%\"via\":\"edit\"%'")" = 1 ] && ok "…revoked through the revoke path: its own delegation_revoked event (via edit)" || fail "revoke event"
[ -n "$(Q "SELECT seen_by_person_at FROM blindkey_secrets WHERE id=$T1B")" ] && [ "$(echo "$BODY" | J seen_by_person)" = True ] && ok "…the new version is marked as seen by a person (a blind rotation is offered next)" || fail "seen"
[ "$(Q "SELECT COUNT(*) FROM blindkey_events WHERE event_type='secret_edited' AND secret_id=$T1B")" = 1 ] && [ "$(Q "SELECT COUNT(*) FROM ticks WHERE did='$DA' AND tags LIKE '%demipass:edit%'")" = 1 ] && ok "…a ledger event and a tick record the edit" || fail "ledger"
pin "$A" "reveal:$T1B"; call POST /api/demipass/reveal "$A" '{"ref":"'$REF1'"}'
[ "$CODE" = 200 ] && [ "$(echo "$BODY" | J value)" = "$NEWV" ] && ok "…and the entry now holds the typed value (owner's reveal, PIN)" || fail "reveal: $CODE"
call POST /api/demipass/edit "$A" "$(EDIT '{"ref":"'$REF1'","new_value":"'$NEWV'2"}')"
[ "$CODE" = 403 ] && ok "the PIN proof was spent: the next edit asks again" || fail "pin reuse: $CODE $BODY"

# ── the 409 counts exactly what is revoked: an own agent's delegation whose scope is no longer active ends too ──
store "$A" ve-sg sg-old-zz82; SG1=$(Q "SELECT id FROM blindkey_secrets WHERE name='ve-sg'"); SGREF=$(Q "SELECT ref_code FROM blindkey_secrets WHERE id=$SG1")
scope $SG1 gone 192.3.84.103; CG=$(Q "SELECT id FROM blindkey_contexts WHERE secret_id=$SG1"); deleg "$DAG" $SG1 $CG; DG_SG=$(Q "SELECT MAX(id) FROM demipass_delegations WHERE secret_id=$SG1")
X "UPDATE blindkey_contexts SET status='revoked' WHERE id=$CG"
call POST /api/demipass/edit "$A" "$(EDIT '{"ref":"'$SGREF'","new_value":"sg-new-zz83"}')"; LT2=$(echo "$BODY" | J left_token)
[ "$CODE" = 409 ] && [ "$(echo "$BODY" | J left)" = 1 ] && echo "$BODY" | grep -q "whose scope is no longer active" && ok "an own agent's delegation whose scope was revoked is counted and named as ending" || fail "scope-gone count: $CODE $BODY"
pin "$A" "edit:$SG1"; call POST /api/demipass/edit "$A" "$(EDIT '{"ref":"'$SGREF'","new_value":"sg-new-zz83","confirm_left":"'$LT2'"}')"
[ "$CODE" = 200 ] && [ "$(Q "SELECT status FROM demipass_delegations WHERE id=$DG_SG")" = revoked ] && [ "$(echo "$BODY" | J delegations_ended)" = 1 ] && ok "…and exactly that one is revoked" || fail "scope-gone revoke: $CODE $BODY"
# ── validated before anything is spent: a version-name conflict refuses with the PIN proof intact ──
store "$A" ve-cf cf-old-zz84; CF=$(Q "SELECT id FROM blindkey_secrets WHERE name='ve-cf'"); CFREF=$(Q "SELECT ref_code FROM blindkey_secrets WHERE id=$CF")
store "$A" ve-cf_v2 someone-named-it-zz85
pin "$A" "edit:$CF"; call POST /api/demipass/edit "$A" "$(EDIT '{"ref":"'$CFREF'","new_value":"cf-new-zz86"}')"
[ "$CODE" = 409 ] && ok "a version name already taken by a live entry → 409 before any factor is spent" || fail "conflict: $CODE $BODY"
X "UPDATE blindkey_secrets SET status='deleted' WHERE name='ve-cf_v2'"
call POST /api/demipass/edit "$A" "$(EDIT '{"ref":"'$CFREF'","new_value":"cf-new-zz86"}')"
[ "$CODE" = 200 ] && ok "…the same PIN proof then completes the edit (it was not spent by the refusal)" || fail "conflict pin: $CODE $BODY"

# ── copy from another entry (from_ref) ──
store "$A" ve-src "$SRCV"; SRC=$(Q "SELECT id FROM blindkey_secrets WHERE name='ve-src'"); SREF=$(Q "SELECT ref_code FROM blindkey_secrets WHERE id=$SRC")
X "UPDATE blindkey_secrets SET account_username='apple' WHERE id=$SRC"
store "$A" ve-tgt tgt-old-value-zz71; TG=$(Q "SELECT id FROM blindkey_secrets WHERE name='ve-tgt'"); TREF=$(Q "SELECT ref_code FROM blindkey_secrets WHERE id=$TG")
X "UPDATE blindkey_secrets SET account_username='root' WHERE id=$TG"
[ "$(Q "SELECT seen_by_person_at IS NOT NULL FROM blindkey_secrets WHERE id=$SRC")" = 1 ] && ok "a stored value is marked seen (it came in from outside the vault)" || fail "store seen"
pin "$A" "edit:$TG"; call POST /api/demipass/edit "$A" "$(EDIT '{"ref":"'$TREF'","from_ref":"'$SREF'"}')"
[ "$CODE" = 409 ] && echo "$BODY" | grep -q "same login" && ok "copy between entries for different logins → 409" || fail "account: $CODE $BODY"
X "UPDATE blindkey_secrets SET account_username='apple' WHERE id=$TG"
deleg "$DAG" $SRC
call POST /api/demipass/edit "$A" "$(EDIT '{"ref":"'$TREF'","from_ref":"'$SREF'","retire_source":true}')"
[ "$CODE" = 409 ] && echo "$BODY" | grep -q "delegated or shared" && ok "retiring a source that is delegated → 409" || fail "retire deleg: $CODE $BODY"
X "UPDATE demipass_delegations SET status='revoked' WHERE secret_id=$SRC"
X "UPDATE blindkey_secrets SET security_depth='elevated' WHERE id=$SRC"
call POST /api/demipass/edit "$A" "$(EDIT '{"ref":"'$TREF'","from_ref":"'$SREF'"}')"
[ "$CODE" = 409 ] && echo "$BODY" | grep -q "lower the value's depth" && ok "copying an elevated value into a standard entry → 409 (a copy never lowers depth)" || fail "depth: $CODE $BODY"
X "UPDATE blindkey_secrets SET security_depth='standard' WHERE id=$SRC"
# a custom policy is compared as a policy (#124 review H1): reveal needing more than the entry's is refused
X "UPDATE blindkey_secrets SET security_depth='custom', gate_policy='{\"reveal\":[\"pin\",\"twofa\",\"sms\"],\"rotate\":[],\"delete\":[],\"use\":[]}' WHERE id=$SRC"
call POST /api/demipass/edit "$A" "$(EDIT '{"ref":"'$TREF'","from_ref":"'$SREF'"}')"
[ "$CODE" = 409 ] && [ "$(echo "$BODY" | J weaker)" = reveal ] && ok "a custom-policy source (reveal: PIN + code + SMS) into a standard entry → 409 (the copy would be easier to reveal)" || fail "custom reveal: $CODE $BODY"
X "UPDATE blindkey_secrets SET gate_policy='{\"reveal\":[\"pin\"],\"rotate\":[],\"delete\":[],\"use\":[\"twofa\"]}' WHERE id=$SRC"
call POST /api/demipass/edit "$A" "$(EDIT '{"ref":"'$TREF'","from_ref":"'$SREF'"}')"
[ "$CODE" = 409 ] && [ "$(echo "$BODY" | J weaker)" = use ] && ok "…and a custom use gate the entry lacks → 409" || fail "custom use: $CODE $BODY"
X "UPDATE blindkey_secrets SET security_depth='standard', gate_policy=NULL WHERE id=$SRC"
# a leaked source is refused (#124 review L3): the warning would not follow the value
X "INSERT INTO leak_scan_hits (owner_did, token_label, found, created_at) VALUES ('$DA', 'smoke', '[{\"name\":\"ve-src\",\"ref\":\"$SREF\",\"chunk\":\"x\"}]', '2999-01-01T00:00:00.000Z')"
call POST /api/demipass/edit "$A" "$(EDIT '{"ref":"'$TREF'","from_ref":"'$SREF'"}')"
[ "$CODE" = 409 ] && [ "$(echo "$BODY" | J leaked)" = True ] && ok "a source whose leak was logged after it was written → 409 (rotate it instead)" || fail "leaked src: $CODE $BODY"
X "DELETE FROM leak_scan_hits WHERE created_at='2999-01-01T00:00:00.000Z'"
X "UPDATE blindkey_secrets SET seen_by_person_at=NULL WHERE id=$SRC"
call POST /api/demipass/edit "$A" "$(EDIT '{"ref":"'$TREF'","from_ref":"'$SREF'","retire_source":true}')"   # the PIN typed above is still fresh: every refusal so far came before the factors
[ "$CODE" = 403 ] && { pin "$A" "edit:$TG"; call POST /api/demipass/edit "$A" "$(EDIT '{"ref":"'$TREF'","from_ref":"'$SREF'","retire_source":true}')"; }
TGB=$(Q "SELECT id FROM blindkey_secrets WHERE ref_code='$TREF'")
[ "$CODE" = 200 ] && [ "$(echo "$BODY" | J source_retired)" = True ] && ! echo "$BODY" | grep -qF -- "$SRCV" && ok "copy with retire_source → 200; the reply holds no value" || fail "copy: $CODE $BODY"
[ "$(Q "SELECT status FROM blindkey_secrets WHERE id=$SRC")" = deleted ] && [ -z "$(Q "SELECT encrypted_value FROM blindkey_secrets WHERE id=$SRC")" ] && ok "…the source is deleted, its value erased" || fail "src gone"
[ "$(Q "SELECT seen_by_person_at FROM blindkey_secrets WHERE id=$TGB")" = None ] && ok "…a copy is as seen as its source (here: never seen)" || fail "copy seen: $(Q "SELECT seen_by_person_at FROM blindkey_secrets WHERE id=$TGB")"
pin "$A" "reveal:$TGB"; call POST /api/demipass/reveal "$A" '{"ref":"'$TREF'"}'
[ "$(echo "$BODY" | J value)" = "$SRCV" ] && ok "…and the entry holds the source's value" || fail "copied value"
# a source of another type, or a frozen one, is refused
call POST /api/demipass/store "$A" '{"name":"ve-key","value":"key-zz78","secret_type":"api_key"}'; KREF=$(Q "SELECT ref_code FROM blindkey_secrets WHERE name='ve-key'")
call POST /api/demipass/edit "$A" "$(EDIT '{"ref":"'$TREF'","from_ref":"'$KREF'"}')"
[ "$CODE" = 409 ] && echo "$BODY" | grep -q "same type" && ok "copying an api_key into a password entry → 409" || fail "type: $CODE $BODY"
store "$A" ve-fz fz-zz79; FZ=$(Q "SELECT id FROM blindkey_secrets WHERE name='ve-fz'"); FZREF=$(Q "SELECT ref_code FROM blindkey_secrets WHERE id=$FZ"); X "UPDATE blindkey_secrets SET frozen=1 WHERE id=$FZ"
call POST /api/demipass/edit "$A" "$(EDIT '{"ref":"'$TREF'","from_ref":"'$FZREF'"}')"
[ "$CODE" = 409 ] && echo "$BODY" | grep -q frozen && ok "copying from a frozen entry → 409 (no way past the breaker)" || fail "frozen src: $CODE $BODY"
call POST /api/demipass/rotate "$A" '{"name":"ve-fz","new_value":"fz-new-zz80"}'
[ "$CODE" = 200 ] && [ "$(Q "SELECT frozen FROM blindkey_secrets WHERE name='ve-fz_v2'")" = 1 ] && ok "a frozen entry's new version stays frozen (/rotate used to unfreeze it)" || fail "frozen carry: $CODE $(Q "SELECT frozen FROM blindkey_secrets WHERE name='ve-fz_v2'")"
# a wrapped source cannot be read by the server
store "$A" ve-wsrc wrapped-src-zz72; WS=$(Q "SELECT id FROM blindkey_secrets WHERE name='ve-wsrc'"); WSREF=$(Q "SELECT ref_code FROM blindkey_secrets WHERE id=$WS")
call POST /api/demipass/gate-policy "$A" '{"name":"ve-wsrc","security_depth":"elevated"}'
call POST /api/demipass/edit "$A" "$(EDIT '{"ref":"'$TREF'","from_ref":"'$WSREF'"}')"
[ "$CODE" = 409 ] && [ "$(echo "$BODY" | J wrapped)" = True ] && ok "a source wrapped to the phone → 409 (the server cannot read it)" || fail "wrapped src: $CODE $BODY"

# ── elevated (wrapped): PIN + email code; critical: + an approved request that never asks for an unwrap ──
store "$A" ve-elev elev-old-zz73; EL=$(Q "SELECT id FROM blindkey_secrets WHERE name='ve-elev'"); EREF=$(Q "SELECT ref_code FROM blindkey_secrets WHERE id=$EL")
call POST /api/demipass/gate-policy "$A" '{"name":"ve-elev","security_depth":"elevated"}'
[ "$(Q "SELECT wrap_state FROM blindkey_secrets WHERE id=$EL")" = device ] || fail "elevated not wrapped"
EV=$(python3 -c 'import secrets;print("veelev-" + secrets.token_urlsafe(16))')
pin "$A" "edit:$EL"; call POST /api/demipass/edit "$A" "$(EDIT '{"ref":"'$EREF'","new_value":"'$EV'"}')"
[ "$CODE" = 403 ] && echo "$BODY" | J missing | grep -q twofa && ok "elevated: the PIN alone is not enough — the email code is asked" || fail "elev: $CODE $BODY"
# a wrap that fails after the pre-check (here: the phone's wrap key is unusable) → 409 and nothing changes (#124 review M2)
KW=$(Q "SELECT public_key FROM device_wrap_keys WHERE did='$DA'"); X "UPDATE device_wrap_keys SET public_key='bm90LWEta2V5' WHERE did='$DA'"
n0=$(Q "SELECT COUNT(*) FROM blindkey_secrets WHERE name LIKE 've-elev%'"); pv=$(Q "SELECT COUNT(*) FROM gate_verifications WHERE gate_type='pin' AND intent='edit:$EL'")
twofa "$A"; call POST /api/demipass/edit "$A" "$(EDIT '{"ref":"'$EREF'","new_value":"'$EV'"}')"
[ "$CODE" = 409 ] && [ "$(echo "$BODY" | J wrapped)" = False ] && [ "$(Q "SELECT status FROM blindkey_secrets WHERE id=$EL")" = active ] && [ "$(Q "SELECT wrap_state FROM blindkey_secrets WHERE id=$EL")" = device ] \
  && [ "$(Q "SELECT COUNT(*) FROM blindkey_secrets WHERE name LIKE 've-elev%'")" = "$n0" ] && ok "a wrap failure after the pre-check → 409; the old wrapped version stays, no host-readable new version" || fail "wrap fail: $CODE $BODY"
[ "$(Q "SELECT COUNT(*) FROM gate_verifications WHERE gate_type='pin' AND intent='edit:$EL'")" = "$pv" ] && ok "…and the PIN proof is not spent by the refused edit (rolled back with it)" || fail "pin spent on rollback"
X "UPDATE device_wrap_keys SET public_key='$KW' WHERE did='$DA'"
twofa "$A"; call POST /api/demipass/edit "$A" "$(EDIT '{"ref":"'$EREF'","new_value":"'$EV'"}')"
[ "$CODE" = 403 ] && { pin "$A" "edit:$EL"; call POST /api/demipass/edit "$A" "$(EDIT '{"ref":"'$EREF'","new_value":"'$EV'"}')"; }
ELB=$(Q "SELECT id FROM blindkey_secrets WHERE ref_code='$EREF'")
[ "$CODE" = 200 ] && [ "$(Q "SELECT wrap_state FROM blindkey_secrets WHERE id=$ELB")" = device ] && [ "$(echo "$BODY" | J wrapped)" = True ] && ok "…PIN + code → 200, and the new version is wrapped to the phone again" || fail "elev edit: $CODE $BODY"
store "$A" ve-crit crit-old-zz74; CR=$(Q "SELECT id FROM blindkey_secrets WHERE name='ve-crit'"); CREF=$(Q "SELECT ref_code FROM blindkey_secrets WHERE id=$CR")
call POST /api/demipass/gate-policy "$A" '{"name":"ve-crit","security_depth":"critical"}'
[ "$(Q "SELECT security_depth FROM blindkey_secrets WHERE id=$CR")" = critical ] || fail "critical not set: $BODY"
CV=$(python3 -c 'import secrets;print("vecrit-" + secrets.token_urlsafe(16))')
call POST /api/demipass/edit "$A" "$(EDIT '{"ref":"'$CREF'","new_value":"'$CV'"}')"; AP=$(echo "$BODY" | J approval_id)
[ "$CODE" = 202 ] && [ "$(Q "SELECT kind FROM use_approvals WHERE id=$AP")" = edit ] && ok "critical: an approval request (kind edit) is filed first" || fail "crit park: $CODE $BODY"
sleep 0.5
[ -z "$(Q "SELECT COALESCE(eph_pub,'') FROM use_approvals WHERE id=$AP")" ] && ! grep -qF -- "$CV" <(Q "SELECT bound_call FROM use_approvals WHERE id=$AP") && ok "…no one-use key: the phone is never asked to unwrap the old value; the new value is not in the request" || fail "eph on edit"
BIND=$(Q "SELECT binding FROM use_approvals WHERE id=$AP")
pin "$A" "approval-open:$AP"; devsign "$A" "approval-open:$AP" "$BIND"; call POST /api/demipass/approvals/$AP/open "$A" '{"device_challenge_id":'$CH',"device_signature":"'$SG'"}'; CODEV=$(echo "$BODY" | J code)
devsign "$A" "approval:$AP" "$BIND"; call POST /api/demipass/approvals/$AP/approve "$A" '{"code":"'$CODEV'","device_challenge_id":'$CH',"device_signature":"'$SG'"}'
[ "$CODE" = 200 ] && ok "…the owner approves it on the phone without an unwrap" || fail "approve: $CODE $BODY"
call POST /api/demipass/edit "$A" '{"ref":"'$CREF'","new_value":"another-value-zz81","approval_id":'$AP'}'
[ "$CODE" = 409 ] && [ "$(Q "SELECT status FROM use_approvals WHERE id=$AP")" = approved ] && ok "…an approval for one typed value cannot be redeemed with another (an HMAC of the value is bound)" || fail "value bind: $CODE $BODY"
B='{"ref":"'$CREF'","new_value":"'$CV'","approval_id":'$AP'}'
call POST /api/demipass/edit "$A" "$B"
[ "$CODE" = 403 ] && [ "$(Q "SELECT status FROM use_approvals WHERE id=$AP")" = approved ] && ok "…then the PIN and code are still asked, and the approval is not spent by asking" || fail "crit gates: $CODE $BODY"
twofa "$A"; pin "$A" "edit:$CR"; call POST /api/demipass/edit "$A" "$B"
[ "$CODE" = 200 ] && [ "$(Q "SELECT status FROM use_approvals WHERE id=$AP")" = used ] && ok "…approved + PIN + code → 200; the approval is used" || fail "crit edit: $CODE $BODY"

# ── /rotate now carries the owner's own agents' delegations ──
store "$A" ve-rot rot-old-zz75; RO=$(Q "SELECT id FROM blindkey_secrets WHERE name='ve-rot'"); deleg "$DAG" $RO
call POST /api/demipass/rotate "$A" '{"name":"ve-rot","new_value":"rot-new-zz76"}'
ROB=$(Q "SELECT id FROM blindkey_secrets WHERE name='ve-rot_v2'")
[ -n "$(Q "SELECT seen_by_person_at FROM blindkey_secrets WHERE id=${ROB:-0}")" ] && [ "$(Q "SELECT seen_by_person_at FROM blindkey_secrets WHERE id=${ROB:-0}")" != None ] && ok "/rotate with a value the caller typed marks the new version seen" || fail "rotate seen"
[ "$CODE" = 200 ] && [ "$(Q "SELECT secret_id FROM demipass_delegations WHERE secret_id IN ($RO, ${ROB:-0}) AND delegate_did='$DAG'")" = "$ROB" ] && [ "$(echo "$BODY" | J delegations_transferred)" = 1 ] && ok "/rotate moves the owner's own agent's delegation to the new version" || fail "rotate deleg: $CODE $BODY"

# ── dashboard: username, seen, attention ──
store "$A" ve-leaky leaky-zz77; LK=$(Q "SELECT id FROM blindkey_secrets WHERE name='ve-leaky'"); LREF=$(Q "SELECT ref_code FROM blindkey_secrets WHERE id=$LK")
X "UPDATE blindkey_secrets SET created_at=datetime('now','-2 days') WHERE id=$LK"
X "INSERT INTO leak_scan_hits (owner_did, token_label, found, created_at) VALUES ('$DA', 'smoke', '[{\"name\":\"ve-leaky\",\"ref\":\"$LREF\",\"chunk\":\"x\"}]', '$(date -u +%Y-%m-%dT%H:%M:%S.000Z)')"
X "INSERT INTO secret_outcomes (secret_id, did, action_type, outcome, error_summary) VALUES ($T1B, '$DA', 'ssh_exec', 'failure', 'auth failed')"
X "UPDATE blindkey_secrets SET seen_by_person_at=NULL WHERE id=$LK"
call GET /api/demipass/dashboard "$A"
DASH=$BODY
call GET /api/demipass/dashboard "$SIL"
echo "$BODY" | python3 -c 'import json,sys; d=json.load(sys.stdin); s=d.get("secrets") or []; sys.exit(0 if s and not any(k in x for x in s for k in ("attention","seen_by_person_at","wrapped")) else 1)' \
  && ok "an agent token reading the dashboard gets no attention, seen_by_person_at or wrapped" || fail "agent dashboard: $(echo "$BODY" | head -c 200)"
att(){ echo "$DASH" | python3 -c 'import json,sys; d=json.load(sys.stdin); s=[x for x in d["secrets"] if x["ref"]==sys.argv[1]][0]; print(",".join(a["reason"] for a in s.get("attention",[])) or "-"); ' "$1"; }
fld(){ echo "$DASH" | python3 -c 'import json,sys; d=json.load(sys.stdin); s=[x for x in d["secrets"] if x["ref"]==sys.argv[1]][0]; print(s.get(sys.argv[2]))' "$1" "$2"; }
[ "$(att "$LREF")" = leaked ] && ok "attention: a value written before its logged leak → leaked" || fail "leaked: $(att "$LREF")"
[ "$(att "$REF1")" = last_use_failed ] && ok "attention: its last use failed → last_use_failed" || fail "failed: $(att "$REF1")"
[ "$(att "$TREF")" = - ] && ok "…an entry with neither shows nothing" || fail "clean: $(att "$TREF")"
[ "$(fld "$REF1" username)" = apple ] && ok "dashboard: the bound account shows (it was always null before)" || fail "username: $(fld "$REF1" username)"
[ "$(fld "$REF1" seen_by_person_at)" != None ] && [ "$(fld "$LREF" seen_by_person_at)" = None ] && ok "dashboard: seen_by_person_at shows who has been seen" || fail "seen dash"
for v in "$OLDV" "$NEWV" "$SRCV" "$EV" "$CV"; do echo "$DASH" | grep -qF -- "$v" && fail "a value in the dashboard"; done
ok "the dashboard holds no value"
sleep 1
leak=0; for f in "$DB_PATH" "$DB_PATH-wal"; do [ -f "$f" ] || continue; for v in "$NEWV" "$SRCV" "$EV" "$CV"; do grep -qaF -- "$v" "$f" && leak=1; done; done
[ $leak = 0 ] && ok "no edited or copied value is in the database file in the clear (events, ticks, approvals included)" || fail "plaintext value in the database"

# ── legacy fixture: a database from before seen_by_person_at ──
stop
python3 - "$DB_PATH" <<'PY'
import sqlite3, sys
c = sqlite3.connect(sys.argv[1])
c.execute("ALTER TABLE blindkey_secrets DROP COLUMN seen_by_person_at")
c.execute("INSERT INTO blindkey_secrets (did, name, secret_type, encrypted_value, status, version, ref_code) VALUES ((SELECT did FROM identity_wallets WHERE username='ve-owner'), 've-legacy', 'password', '', 'active', 1, 'DP-PWD-legacy-00000001')")
c.commit()
PY
[ "$(Q "SELECT COUNT(*) FROM pragma_table_info('blindkey_secrets') WHERE name='seen_by_person_at'")" = 0 ] || fail "legacy fixture did not drop the column"
start
[ "$(Q "SELECT COUNT(*) FROM pragma_table_info('blindkey_secrets') WHERE name='seen_by_person_at'")" = 1 ] && [ "$(Q "SELECT COALESCE(seen_by_person_at,'NULL') FROM blindkey_secrets WHERE name='ve-legacy'")" = NULL ] \
  && ok "legacy fixture: a database without seen_by_person_at starts, gains the column, and old rows read NULL" || fail "legacy column"
A=$(login ve-owner); call GET /api/demipass/dashboard "$A"
[ "$CODE" = 200 ] && echo "$BODY" | grep -q DP-PWD-legacy-00000001 && ok "…and the dashboard lists the legacy row" || fail "legacy dashboard: $CODE"

echo; [ $fails = 0 ] && echo "ALL PASSED" || { echo "$fails failure(s)"; exit 1; }
