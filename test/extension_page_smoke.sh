#!/bin/bash
# Smoke of the extension install page (public/extension.html) and its waitlist (extension_routes.js), on a throwaway DB.
#   - /extension serves the page; the release JSON in it names the .xpi and its SHA-256, and the served file matches;
#   - the .xpi is Mozilla-signed (META-INF/cose.sig) and served as application/x-xpinstall;
#   - the waitlist takes chrome/brave/edge + a valid email, answers the same for a repeat (one row), refuses a bad
#     email or browser (400), and rate-limits (429 after 10 in 15 min);
#   - the page has no install script, policy file or registry step.
# No network beyond 127.0.0.1.
set -u
W=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
S=$(mktemp -d /tmp/dustforge-extension-page-smoke.XXXXXX)
PORT=${PORT:-3797}; API=http://127.0.0.1:$PORT
[ -d "$W/node_modules" ] || export NODE_PATH=${NODE_PATH:-/home/flimflam/project/dustforge/node_modules}
export IDENTITY_MASTER_KEY=$(python3 -c 'import secrets;print(secrets.token_hex(32))') DB_PATH=$S/dustforge.db PORT \
  STALWART_HOST=127.0.0.1 STALWART_PORT=1 SMTP_RELAY_HOST= SMTP_HOST=127.0.0.1 SMTP_PORT=9
cd "$W"
node server.js >"$S/server.log" 2>&1 & SRV=$!
trap 'kill $SRV 2>/dev/null; rm -rf "$S"' EXIT
for i in $(seq 1 40); do curl -s -o /dev/null "$API/" && break; sleep 0.5; done
kill -0 $SRV 2>/dev/null || { echo "server died:"; tail -5 "$S/server.log"; exit 1; }
fails=0; ok(){ echo "ok   $*"; }; fail(){ echo "FAIL $*"; fails=$((fails+1)); }
Q(){ python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); r=c.execute(sys.argv[2]).fetchone(); print(r[0] if r else '')" "$DB_PATH" "$1"; }

CODE=$(curl -s -o "$S/page.html" -w '%{http_code}' "$API/extension")
[ "$CODE" = 200 ] && grep -q 'id="release"' "$S/page.html" && ok "/extension serves the install page" || fail "page: $CODE"
read -r XPI SHA < <(python3 -c 'import re,json,sys; t=open(sys.argv[1]).read(); r=json.loads(re.search(r"<script type=\"application/json\" id=\"release\">(.*?)</script>", t, re.S).group(1)); print(r["firefox"]["xpi"], r["firefox"]["sha256"])' "$S/page.html")
CT=$(curl -s -o "$S/dl.xpi" -D - "$API$XPI" | tr -d '\r' | awk -F': ' 'tolower($1)=="content-type"{print $2}')
[ "$CT" = application/x-xpinstall ] && ok "$XPI is served as application/x-xpinstall" || fail "content-type: '$CT'"
[ "$(sha256sum "$S/dl.xpi" | cut -d' ' -f1)" = "$SHA" ] && ok "the served .xpi matches the SHA-256 the page states" || fail "sha mismatch"
unzip -l "$S/dl.xpi" | grep -q 'META-INF/cose.sig' && unzip -p "$S/dl.xpi" manifest.json | grep -q '"demipass-browser@demipass.com"' \
  && ok "the .xpi is Mozilla-signed (cose.sig) and is demipass-browser@demipass.com" || fail "not signed / wrong id"

P(){ CODE=$(curl -s -o "$S/out" -w '%{http_code}' -X POST "$API/api/extension/waitlist" -H 'content-type: application/json' -d "$1"); }
P '{"email":"Person@Example.com","browser":"chrome"}'; [ "$CODE" = 200 ] && ok "waitlist: chrome + email → 200" || fail "wl: $CODE $(cat "$S/out")"
P '{"email":"person@example.com ","browser":"Chrome"}'; [ "$CODE" = 200 ] && [ "$(Q "SELECT COUNT(*) FROM extension_waitlist")" = 1 ] \
  && ok "a repeat (case, spaces) answers the same and adds no row" || fail "dup: $CODE rows=$(Q "SELECT COUNT(*) FROM extension_waitlist")"
P '{"email":"person@example.com","browser":"brave"}'; [ "$CODE" = 200 ] && [ "$(Q "SELECT COUNT(*) FROM extension_waitlist")" = 2 ] && ok "the same email for brave is its own row" || fail "brave: $CODE"
P '{"email":"not-an-email","browser":"edge"}'; [ "$CODE" = 400 ] && ok "a bad email → 400" || fail "bad email: $CODE"
P '{"email":"a@b.co","browser":"firefox"}'; [ "$CODE" = 400 ] && ok "a browser outside chrome/brave/edge/chromium → 400" || fail "bad browser: $CODE"
for i in $(seq 1 6); do P '{"email":"x'$i'@example.com","browser":"edge"}'; done
[ "$CODE" = 429 ] && ok "the 11th request in 15 minutes → 429" || fail "rate limit: $CODE"

if grep -i -E '\.(sh|ps1|bat|cmd|reg|mobileconfig)\b|policies\.json|ExtensionInstallForcelist|HKEY_|curl [^"]*\|' "$S/page.html" >/dev/null; then
  fail "the page mentions an install script, policy file or registry step"
else ok "no install script, policy file or registry step on the page"; fi

[ $fails -gt 0 ] && { echo "--- server.log"; grep -i -m5 "error" "$S/server.log"; }
echo "$fails failure(s)"; exit $(( fails > 0 ))
