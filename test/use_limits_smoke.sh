#!/bin/bash
# Smoke of the /use size limits (use_limits.js) end to end: server.js on a throwaway DB, its fetch() to
# repo.dustroot.com sent to a local stand-in upstream (test/fixtures/upstream-redirect.js). Checks:
#   - an upstream body just under the 2 MiB limit round-trips byte for byte (sha256), multi-byte text included;
#   - an upstream body over the limit → 413 JSON naming the limit, whether it declares Content-Length or streams
#     chunked; never a dropped connection or a 500; it is charged (the upstream call was made);
#   - the secret echoed by the upstream comes back [REDACTED];
#   - a request body under 1 MiB reaches the upstream whole; one over 1 MiB → 413 JSON naming the limit, not charged;
#   - the real FLEETGATE size (~300 kB diff) goes through;
#   - an upstream redirect (302, 307) is refused with 502 and the secret never reaches the redirect target,
#     in direct and token mode.
# No network beyond 127.0.0.1.
set -u
W=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
S=$(mktemp -d /tmp/dustforge-use-limits-smoke.XXXXXX)
PORT=${PORT:-3794}; UP_PORT=${UP_PORT:-3796}; API=http://127.0.0.1:$PORT
[ -d "$W/node_modules" ] || export NODE_PATH=${NODE_PATH:-/home/flimflam/project/dustforge/node_modules}
export IDENTITY_MASTER_KEY=$(python3 -c 'import secrets;print(secrets.token_hex(32))') DB_PATH=$S/dustforge.db PORT \
  STALWART_HOST=127.0.0.1 STALWART_PORT=1 SMTP_RELAY_HOST= SMTP_HOST=127.0.0.1 SMTP_PORT=9 TEST_UPSTREAM=http://127.0.0.1:$UP_PORT
cd "$W"
SECRET='forge-tok"en-0123456789'
LIMIT=$(node -e 'console.log(require("./use_limits").USE_MAX_RESPONSE_BYTES)')

# Stand-in upstream. /bytes/N: N bytes of mixed UTF-8 text (sha256 in X-Sha256); add ?chunked to drop Content-Length.
# /echo-secret: JSON echoing the secret it was sent. POST /echo: how many body bytes arrived.
node -e '
const http = require("http"), crypto = require("crypto"); let leaks = 0;
function text(n) { const u = Buffer.from("diff --git a/x b/x\n+é \"q\" \\ ✓ {}\n"); const b = Buffer.alloc(n, 0x61); for (let i = 0; i + u.length <= n; i += u.length) u.copy(b, i); return b; }
http.createServer((req, res) => {
  const u = new URL(req.url, "http://x"); let got = 0;
  req.on("data", c => got += c.length); req.on("end", () => {
    if (u.pathname === "/bounce" || u.pathname === "/bounce307") { res.writeHead(u.pathname === "/bounce" ? 302 : 307, { location: "http://127.0.0.1:" + process.argv[1] + "/leak" }); return res.end(); }
    if (u.pathname === "/leak") { leaks++; res.writeHead(200, { "content-type": "application/json" }); return res.end("{}"); }
    if (u.pathname === "/leak-count") { res.writeHead(200); return res.end(String(leaks)); }
    const m = u.pathname.match(/^\/bytes\/(\d+)$/);
    if (m) { const b = text(+m[1]); const h = { "content-type": "text/plain; charset=utf-8", "x-sha256": crypto.createHash("sha256").update(b).digest("hex") };
      if (!u.searchParams.has("chunked")) h["content-length"] = b.length;
      res.writeHead(200, h); for (let i = 0; i < b.length; i += 65536) res.write(b.subarray(i, i + 65536)); return res.end(); }
    if (u.pathname === "/echo-secret") { res.writeHead(200, { "content-type": "application/json" }); return res.end(JSON.stringify({ seen: req.headers.authorization })); }
    if (u.pathname === "/echo") { res.writeHead(200, { "content-type": "application/json" }); return res.end(JSON.stringify({ received_bytes: got })); }
    res.writeHead(404); res.end("nope");
  });
}).listen(+process.argv[1], "127.0.0.1");' $UP_PORT & UP=$!
node --require ./test/fixtures/upstream-redirect.js server.js >"$S/server.log" 2>&1 & SRV=$!
trap 'kill $SRV $UP 2>/dev/null; rm -rf "$S"' EXIT
for i in $(seq 1 40); do curl -s -o /dev/null "$API/" && break; sleep 0.5; done
kill -0 $SRV 2>/dev/null || { echo "server died:"; tail -5 "$S/server.log"; exit 1; }
fails=0; ok(){ echo "ok   $*"; }; fail(){ echo "FAIL $*"; fails=$((fails+1)); }
J(){ python3 -c 'import json,sys; d=json.load(sys.stdin); v=d
for k in sys.argv[1].split("."):
    v = v[int(k)] if isinstance(v, list) else (v or {}).get(k)
print(v)' "$1"; }
Q(){ python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); r=c.execute(sys.argv[2]).fetchone(); print(r[0] if r else '')" "$DB_PATH" "$1"; }

node -e '
const identity = require("./identity"); const Database = require("better-sqlite3"); const crypto = require("crypto");
const db = new Database(process.env.DB_PATH); const id = identity.createIdentity();
db.prepare("INSERT INTO identity_wallets (did, username, email, encrypted_private_key, balance_cents, password_hash) VALUES (?, ?, ?, ?, 100000, ?)")
  .run(id.did, "owner", "owner@dustforge.com", id.encrypted_private_key || id.encryptedPrivateKey, crypto.createHash("sha256").update("hunter22").digest("hex"));
db.prepare("INSERT INTO identity_transactions (did, amount_cents, type, description, balance_after) VALUES (?, 100000, ?, ?, 100000)").run(id.did, "test_grant", "smoke");'
TOK=$(curl -s -X POST "$API/api/identity/auth-fingerprint" -H 'content-type: application/json' -d '{"username":"owner","password":"hunter22","scope":"transact","expires_in":"1h"}' | J token)
[ -n "$TOK" ] && [ "$TOK" != None ] || { echo "FAIL sign-in"; exit 1; }
STORE=$(python3 -c 'import json,sys; print(json.dumps({"name":"forge-token","value":sys.argv[1],"secret_type":"api_key"}))' "$SECRET")
curl -s -o /dev/null -X POST "$API/api/demipass/store" -H "Authorization: Bearer $TOK" -H 'content-type: application/json' -d "$STORE"
BAL(){ Q "SELECT balance_cents FROM identity_wallets WHERE username='owner'"; }

# use PATH [METHOD] [BODYFILE] → writes $S/out, sets CODE
use(){ local body; body=$(python3 -c 'import json,sys
b = {"name":"forge-token","action":"http_header","params":{"url":"https://repo.dustroot.com"+sys.argv[1],"method":sys.argv[2],"header_prefix":"token "}}
if len(sys.argv) > 3: b["params"]["body"] = {"text": open(sys.argv[3]).read()}
print(json.dumps(b))' "$1" "${2:-GET}" ${3:+"$3"})
  printf '%s' "$body" > "$S/req.json"
  CODE=$(curl -s -m 60 -o "$S/out" -w '%{http_code}' -X POST "$API/api/demipass/use" -H "Authorization: Bearer $TOK" -H 'content-type: application/json' --data-binary @"$S/req.json"); }

UNDER=$((LIMIT - 1))
use /bytes/$UNDER
WANT=$(curl -s -D - -o /dev/null "http://127.0.0.1:$UP_PORT/bytes/$UNDER" | tr -d '\r' | awk -F': ' 'tolower($1)=="x-sha256"{print $2}')
GOT=$(python3 -c 'import json,sys,hashlib; print(hashlib.sha256(json.load(open(sys.argv[1]))["result"]["body"].encode()).hexdigest())' "$S/out" 2>/dev/null)
[ "$CODE" = 200 ] && [ -n "$WANT" ] && [ "$GOT" = "$WANT" ] && ok "a $UNDER-byte upstream body (limit − 1) round-trips byte for byte" || fail "under: $CODE got=$GOT want=$WANT $(head -c 200 "$S/out")"

use /bytes/304587
[ "$CODE" = 200 ] && [ "$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))["result"]["body"].encode()))' "$S/out")" = 304587 ] && ok "a 304587-byte diff (the FLEETGATE size) goes through" || fail "300k: $CODE"

B0=$(BAL); use /bytes/$((LIMIT + 1))
[ "$CODE" = 413 ] && [ "$(J limit_bytes < "$S/out")" = "$LIMIT" ] && [ "$(J declared_bytes < "$S/out")" = $((LIMIT + 1)) ] && ok "over the limit with Content-Length → 413 naming the $LIMIT-byte limit" || fail "over CL: $CODE $(head -c 300 "$S/out")"
[ $((B0 - $(BAL))) = 1 ] && ok "the refused-but-made upstream call is charged 1 DD" || fail "charge: $B0 → $(BAL)"
use "/bytes/$((LIMIT + 1))?chunked"
[ "$CODE" = 413 ] && [ "$(J limit_bytes < "$S/out")" = "$LIMIT" ] && [ -n "$(J read_bytes < "$S/out")" ] && ok "over the limit, chunked (no Content-Length) → 413 too" || fail "over chunked: $CODE $(head -c 300 "$S/out")"
grep -q "Internal\|<html" "$S/out" && fail "an HTML/500 body leaked" || ok "the 413 is JSON, not an HTML page"

# Token mode: an over-limit upstream answer uses the token up (it was charged), so it cannot be replayed.
OVER="https://repo.dustroot.com/bytes/$((LIMIT + 1))"
UT=$(curl -s -X POST "$API/api/demipass/request-token" -H "Authorization: Bearer $TOK" -H 'content-type: application/json' \
  -d '{"name":"forge-token","action":"http_header","target_url":"'$OVER'"}' | J use_token)
[ -n "$UT" ] && [ "$UT" != None ] || fail "request-token for the over-limit URL"
uset(){ CODE=$(curl -s -o "$S/out" -w '%{http_code}' -X POST "$API/api/demipass/use" -H "Authorization: Bearer $TOK" -H 'content-type: application/json' -d '{"use_token":"'$UT'","header_prefix":"token "}'); }
UC0=$(Q "SELECT use_count FROM blindkey_secrets WHERE name='forge-token'")
uset; [ "$CODE" = 413 ] && ok "token mode: over-limit upstream → 413" || fail "token 413: $CODE $(head -c 200 "$S/out")"
[ "$(Q "SELECT status FROM blindkey_use_tokens ORDER BY id DESC LIMIT 1")" = used ] && [ "$(Q "SELECT use_count FROM blindkey_secrets WHERE name='forge-token'")" = $((UC0 + 1)) ] \
  && ok "…and the token is used up and the use counted" || fail "token not burned: $(Q "SELECT status FROM blindkey_use_tokens ORDER BY id DESC LIMIT 1")"
uset; [ "$CODE" != 200 ] && [ "$CODE" != 413 ] && ok "replaying that token is refused ($CODE)" || fail "token replayed: $CODE"

use /echo-secret
[ "$CODE" = 200 ] && [ "$(J result.body.seen < "$S/out")" = "token [REDACTED]" ] && ! grep -q "0123456789" "$S/out" && ok "the secret echoed by the upstream comes back [REDACTED]" || fail "redact: $CODE $(cat "$S/out")"

python3 -c 'print("r" * 900000)' > "$S/900k"
use /echo POST "$S/900k"
[ "$CODE" = 200 ] && [ "$(J result.body.received_bytes < "$S/out")" -ge 900000 ] && ok "a ~900 kB request body reaches the upstream whole" || fail "900k post: $CODE $(head -c 200 "$S/out")"

python3 -c 'print("r" * 1100000)' > "$S/1100k"
B0=$(BAL); use /echo POST "$S/1100k"
[ "$CODE" = 413 ] && [ "$(J limit_bytes < "$S/out")" = 1048576 ] && [ "$(J charged < "$S/out")" = False ] && ok "a 1.1 MB request body → 413 naming the 1048576-byte limit" || fail "big post: $CODE $(head -c 300 "$S/out")"
[ "$(BAL)" = "$B0" ] && ok "the refused request is not charged" || fail "big post charged: $B0 → $(BAL)"

# Redirects: the allow-list checks only the first URL, so a 30x must never carry the secret onward.
LEAKS(){ curl -s "http://127.0.0.1:$UP_PORT/leak-count"; }
use /bounce
[ "$CODE" = 502 ] && [ "$(J upstream < "$S/out")" = redirect ] && ok "direct mode: an upstream 302 → 502 naming the redirect" || fail "302: $CODE $(head -c 300 "$S/out")"
use /bounce307 POST "$S/900k"
[ "$CODE" = 502 ] && [ "$(J upstream < "$S/out")" = redirect ] && ok "direct mode: an upstream 307 on a POST → 502" || fail "307: $CODE $(head -c 300 "$S/out")"
UT=$(curl -s -X POST "$API/api/demipass/request-token" -H "Authorization: Bearer $TOK" -H 'content-type: application/json' \
  -d '{"name":"forge-token","action":"http_header","target_url":"https://repo.dustroot.com/bounce"}' | J use_token)
uset; [ "$CODE" = 502 ] && ok "token mode: an upstream 302 → 502" || fail "token 302: $CODE $(head -c 300 "$S/out")"
[ "$(LEAKS)" = 0 ] && ok "the redirect target never received a request (no secret forwarded)" || fail "redirect followed: /leak hit $(LEAKS) time(s)"

[ $fails -gt 0 ] && { echo "--- server.log"; grep -i -m5 "error" "$S/server.log"; }
echo "$fails failure(s)"; exit $(( fails > 0 ))
