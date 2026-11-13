#!/bin/bash
# Rate limits count per wallet; the address counts only traffic that is not signed in (Aaron 2026-11-12/13). Two
# wallets behind one address each get their own budget, on /use and on every other limiter; a caller without a valid
# token is limited by address. Limits are lowered for the test. No schema change.
set -u
W=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
S=$(mktemp -d /tmp/dustforge-userate-smoke.XXXXXX)
PORT=${PORT:-3931}; API=http://127.0.0.1:$PORT
[ -d "$W/node_modules" ] || export NODE_PATH=${NODE_PATH:-/home/flimflam/project/dustforge/node_modules}
export IDENTITY_MASTER_KEY=$(python3 -c 'import secrets;print(secrets.token_hex(32))') DB_PATH=$S/dustforge.db PORT \
  STALWART_HOST=127.0.0.1 STALWART_PORT=1 SMTP_RELAY_HOST= SMTP_HOST=127.0.0.1 SMTP_PORT=9 USE_RATE_LIMIT_MAX=5 USE_RATE_IP_CEILING=15 RATE_STANDARD_MAX=4 RATE_STRICT_MAX=3
cd "$W"
( exec node server.js >"$S/server.log" 2>&1 ) & SRV=$!
trap 'kill $SRV 2>/dev/null; rm -rf "$S"' EXIT
for i in $(seq 1 40); do curl -s -o /dev/null "$API/" && break; sleep 0.5; done
kill -0 $SRV 2>/dev/null || { echo "server died:"; tail -5 "$S/server.log"; exit 1; }
H=$(printf '%s' hunter22 | sha256sum | cut -d' ' -f1)
node -e '
const identity = require("./identity"); const Database = require("better-sqlite3"); const db = new Database(process.env.DB_PATH);
for (const c of ["idempotency_key TEXT", "provenance TEXT DEFAULT '"'"'organic'"'"'"]) { try { db.exec("ALTER TABLE identity_transactions ADD COLUMN " + c); } catch (_) {} }
for (const u of ["wallet-a", "wallet-b", "wallet-c"]) { const id = identity.createIdentity(); const enc = id.encrypted_private_key || id.encryptedPrivateKey;
  db.prepare("INSERT INTO identity_wallets (did, username, email, encrypted_private_key, balance_cents, password_hash) VALUES (?, ?, ?, ?, 100000, ?)").run(id.did, u, u + "@dustforge.com", enc, process.argv[1]);
  db.prepare("INSERT INTO identity_transactions (did, amount_cents, type, description, balance_after) VALUES (?, 100000, ?, ?, 100000)").run(id.did, "topup", "smoke"); }' "$H"
fails=0; ok(){ echo "ok   $*"; }; fail(){ echo "FAIL $*"; fails=$((fails+1)); }
login(){ curl -s -X POST "$API/api/identity/auth-fingerprint" -H 'content-type: application/json' -d '{"username":"'$1'","password":"hunter22","scope":"transact","expires_in":"1h"}' | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])'; }
A=$(login wallet-a); B=$(login wallet-b); Cw=$(login wallet-c)
RT(){ curl -s -o /dev/null -w '%{http_code}' -X POST "$API/api/demipass/request-token" -H 'content-type: application/json' ${1:+-H "Authorization: Bearer $1"} -d '{"ref":"DP-NONE-xxxxxxxx-00000000","action":"http_header"}'; }
codes=""; for i in 1 2 3 4 5; do codes="$codes $(RT "$A")"; done
! echo "$codes" | grep -q 429 && [ "$(RT "$A")" = 429 ] && ok "wallet A: 5 requests answered, the 6th refused (its own budget)" || fail "A: $codes"
codes=""; for i in 1 2 3 4 5; do codes="$codes $(RT "$B")"; done
! echo "$codes" | grep -q 429 && ok "wallet B behind the same address still has its full budget (was: shared per address)" || fail "B: $codes"
U=$(curl -s -X POST "$API/api/demipass/use" -H 'content-type: application/json' -H "Authorization: Bearer $A" -d '{}' -w ' %{http_code}'); echo "$U" | grep -q "429" && echo "$U" | grep -q "this wallet" && ok "/use shares the wallet's budget (A already spent it)" || fail "use: $U"
codes=""; for i in 1 2; do codes="$codes $(RT "")"; done
! echo "$codes" | grep -q 429 && ok "no token: limited by address, separately from the wallets" || fail "anon: $codes"
X=$(RT "not-a-real-token"); [ "$X" != 429 ] && ok "an invalid token is keyed by address (cannot pick its own bucket)" || fail "fake token: $X"
# A keeps retrying past its own limit: its refused retries must not use up the address (#103 review M1)
for i in $(seq 1 20); do RT "$A" >/dev/null; done
X=$(RT "$Cw"); [ "$X" != 429 ] && ok "wallet A retrying 20 times after its 429s does not lock out another wallet (C)" || fail "retry lockout: $X"
# Signed-in traffic never counts against the address: wallets A, B and C have made 30+ requests from it, yet the
# not-signed-in budget (5) has only anon 2 + fake 1 = 3 used: two more pass, the next is refused as "this address".
codes=""; for i in 1 2; do codes="$codes $(RT "")"; done
X=$(curl -s -X POST "$API/api/demipass/request-token" -H 'content-type: application/json' -d '{}' -w ' %{http_code}')
! echo "$codes" | grep -q 429 && echo "$X" | grep -q 429 && echo "$X" | grep -q "this address, not signed in" && ok "the address counts only traffic that is not signed in (30+ signed-in requests did not use it up)" || fail "anon floor: $codes / $X"
X=$(RT "$Cw"); [ "$X" != 429 ] && ok "…and a signed-in wallet with budget left is still answered from that address" || fail "C after anon floor: $X"

# ── every other limiter (rateLimitStandard here, max 4) counts per wallet too ──
LT(){ curl -s -o /dev/null -w '%{http_code}' "$API/api/blindkey/leak-scan/tokens" ${1:+-H "Authorization: Bearer $1"}; }
codes=""; for i in 1 2 3 4; do codes="$codes $(LT "$A")"; done
! echo "$codes" | grep -q 429 && [ "$(LT "$A")" = 429 ] && ok "a standard-limited route: wallet A gets its 4, the 5th is refused" || fail "standard A: $codes"
codes=""; for i in 1 2 3 4; do codes="$codes $(LT "$B")"; done
! echo "$codes" | grep -q 429 && ok "…wallet B from the same address still gets its own 4 (was: one budget per address)" || fail "standard B: $codes"
M=$(curl -s "$API/api/blindkey/leak-scan/tokens" -H "Authorization: Bearer $A"); echo "$M" | grep -q "this wallet" && ok "…and the refusal says it is the wallet's budget" || fail "standard msg: $M"
codes=""; for i in 1 2 3 4; do codes="$codes $(LT "forged.$i.token")"; done
[ "$(LT "forged.9.token")" = 429 ] && ok "forged tokens are counted by address: they cannot each pick a fresh budget" || fail "forged: $codes"

# ── a strict-limited route (max 3) that is not signed in: per address ──
FP(){ curl -s -o /dev/null -w '%{http_code}' -X POST "$API/api/identity/forgot-password" -H 'content-type: application/json' -d '{"username":"nobody-'$1'"}'; }
codes=""; for i in 1 2 3; do codes="$codes $(FP $i)"; done
! echo "$codes" | grep -q 429 && [ "$(FP 4)" = 429 ] && ok "a not-signed-in strict route is limited per address" || fail "strict anon: $codes"

# ── a validly signed token the server never issued is not "signed in" (#107 review CRITICAL) ──
# A did:key JWT verifies against the key in its own sub, so anyone can sign one: it must count by address.
MINT(){ node -e '
const crypto = require("crypto"); const identity = require(process.argv[1] + "/identity");
const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519", { publicKeyEncoding: { type: "spki", format: "der" }, privateKeyEncoding: { type: "pkcs8", format: "der" } });
const b = (o) => Buffer.from(JSON.stringify(o)).toString("base64url"), now = Math.floor(Date.now() / 1000);
const si = b({ alg: "EdDSA", typ: "JWT" }) + "." + b({ sub: identity.publicKeyToDID(publicKey), scope: "transact", iss: "civitasvox", iat: now, exp: now + 3600, jti: crypto.randomBytes(8).toString("hex") });
process.stdout.write(si + "." + crypto.sign(null, Buffer.from(si), crypto.createPrivateKey({ key: privateKey, format: "der", type: "pkcs8" })).toString("base64url"));' "$PWD"; }
FP2(){ curl -s -o /dev/null -w '%{http_code}' -X POST "$API/api/identity/forgot-password" -H 'content-type: application/json' -H "Authorization: Bearer $(MINT)" -d '{"username":"nobody-self"}'; }
codes=""; for i in 1 2 3 4; do codes="$codes $(FP2)"; done
[ -z "$(echo $codes | tr " " "\n" | grep -v "^429$")" ] && ok "self-signed did:key tokens (never issued) get the address's spent strict budget, not fresh ones: $codes" || fail "self-minted bypass: $codes"

# ── silicons count under their owner wallet on the general limiters (#107 review HIGH) ──
SIL=""; for i in 1 2; do SIL="$SIL $(curl -s -X POST "$API/api/blindkey/silicon/register" -H 'content-type: application/json' -H "Authorization: Bearer $Cw" -d '{"agent_name":"rl-bot'$i'"}' | python3 -c 'import json,sys; print(json.load(sys.stdin).get("token",""))')"; done
codes=""; for t in $SIL; do for i in 1 2; do codes="$codes $(LT "$t")"; done; done; codes="$codes $(LT "$Cw")"
echo "$codes" | grep -q 429 && ok "wallet C's silicons share C's standard budget (registering silicons does not multiply it): $codes" || fail "silicon multiplication: $codes"


echo; [ $fails = 0 ] && echo "ALL OK" || echo "$fails FAILED"; exit $fails
