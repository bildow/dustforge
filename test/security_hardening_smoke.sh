#!/bin/bash
# Smoke of the 2026-10-28 hardening: account passwords are kept only as salted scrypt hashes, and a secret that
# can never be served again loses its encrypted value. Boots server.js on a throwaway DB against a fake Stalwart
# admin API (a JSON file of principals; every request is logged to stalwart.log). Checks:
#   - sign-in for each stored form: unsalted sha256, sha256 wrapped in scrypt, readable Stalwart password,
#     hashed Stalwart password, current local hash (Stalwart never asked); a match upgrades the local hash and a
#     sign-in never writes to Stalwart; wrong passwords fail; auth-critical works from the local hash alone;
#   - scripts/migrate-password-hashes.js: the dry run writes nothing; --execute hashes every readable Stalwart
#     password (app passwords and hashed entries kept), Stalwart's password wins over a stale local sha256, and no
#     unsalted hash is left;
#   - deleting or revoking a secret empties its value; at start the sweep empties values of deleted rows, retires a
#     rotation whose grace ended earlier today (an ISO time) and drops abandoned or finished checkouts' sealed
#     passwords, while live rows keep theirs; afterwards the erased values are nowhere in the database file or WAL.
# No network.
set -u
W=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
S=$(mktemp -d /tmp/dustforge-harden-smoke.XXXXXX)
PORT=${PORT:-3791}; STW_PORT=${STW_PORT:-3793}; API=http://127.0.0.1:$PORT
[ -d "$W/node_modules" ] || export NODE_PATH=${NODE_PATH:-/home/flimflam/project/dustforge/node_modules}
export IDENTITY_MASTER_KEY=$(python3 -c 'import secrets;print(secrets.token_hex(32))') DB_PATH=$S/dustforge.db PORT \
  STALWART_HOST=127.0.0.1 STALWART_PORT=$STW_PORT STALWART_PASS=x SMTP_RELAY_HOST= SMTP_HOST=127.0.0.1 SMTP_PORT=9
cd "$W"
fails=0; ok(){ echo "ok   $*"; }; fail(){ echo "FAIL $*"; fails=$((fails+1)); }
Q(){ python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); r=c.execute(sys.argv[2]).fetchone(); print(r[0] if r else '')" "$DB_PATH" "$1"; }
J(){ node -e "$1" "${@:2}"; }

# Fake Stalwart: principals in stw.json; GET one / list, PATCH set secrets. Logs "METHOD name".
cat >"$S/stw.json" <<'EOF'
{}
EOF
node -e '
const http = require("http"), fs = require("fs"); const [port, dir] = process.argv.slice(1);
const load = () => JSON.parse(fs.readFileSync(dir + "/stw.json", "utf8")), save = (s) => fs.writeFileSync(dir + "/stw.json", JSON.stringify(s));
http.createServer((req, res) => { let b = ""; req.on("data", c => b += c); req.on("end", () => {
  const u = new URL(req.url, "http://x"), st = load(), send = (code, j) => { res.writeHead(code, { "content-type": "application/json" }); res.end(JSON.stringify(j)); };
  if (u.pathname === "/api/principal") { fs.appendFileSync(dir + "/stalwart.log", "LIST\n"); const items = Object.entries(st).map(([name, p]) => ({ name, ...p })); return send(200, { data: { items, total: items.length } }); }
  const name = decodeURIComponent(u.pathname.split("/").pop()); fs.appendFileSync(dir + "/stalwart.log", req.method + " " + name + "\n");
  if (!st[name]) return send(404, { error: "notFound" });
  if (req.method === "GET") return send(200, { data: { name, ...st[name] } });
  if (req.method === "PATCH") { for (const op of JSON.parse(b)) if (op.action === "set" && op.field === "secrets") st[name].secrets = op.value; save(st); return send(200, { data: null }); }
  send(405, {});
}); }).listen(Number(port), "127.0.0.1");
' "$STW_PORT" "$S" & FAKE=$!
SRV=
start(){ node server.js >>"$S/server.log" 2>&1 & SRV=$!; for i in $(seq 1 40); do curl -s -o /dev/null "$API/" && break; sleep 0.5; done; kill -0 $SRV 2>/dev/null || { echo "server died:"; tail -5 "$S/server.log"; exit 1; }; sleep 0.5; }
stop(){ kill $SRV 2>/dev/null; wait $SRV 2>/dev/null; }
trap 'kill $SRV $FAKE 2>/dev/null; [ -n "${KEEP:-}" ] || rm -rf "$S"' EXIT
start   # creates the schema
stop

# Seed wallets, Stalwart principals, secrets and checkouts.
J '
const identity = require("./identity"), pw = require("./passwords"), Database = require("better-sqlite3"), fs = require("fs"), crypto = require("crypto");
const db = new Database(process.env.DB_PATH), sha = (s) => crypto.createHash("sha256").update(s).digest("hex");
(async () => {
  const add = (u, h) => { const id = identity.createIdentity(); db.prepare("INSERT INTO identity_wallets (did, username, email, encrypted_private_key, balance_cents, password_hash) VALUES (?, ?, ?, ?, 1000, ?)").run(id.did, u, u + "@dustforge.com", id.encrypted_private_key || id.encryptedPrivateKey, h); return id.did; };
  const owner = add("legacy", sha("legacypass1"));
  add("wrapped", await pw.wrapLegacySha256(sha("wrappedpass1")));
  add("plain", null); add("hashed", null);
  add("current", await pw.hashPassword("currentpass1"));
  add("m1", sha("stale-old-pass")); add("m2", null); add("m3", sha("m3localpass"));
  const st = { plain: { type: "individual", secrets: ["plainpass1"] }, hashed: { type: "individual", secrets: [await pw.hashPassword("hashedpass1")] },
    current: { type: "individual", secrets: ["not-the-password"] }, m1: { type: "individual", secrets: ["m1stalwartpass"] },
    m2: { type: "individual", secrets: ["m2pass1", "$app$phone$keepme"] }, "dustforge.com": { type: "domain", secrets: [] } };
  fs.writeFileSync(process.argv[1] + "/stw.json", JSON.stringify(st));
  const iso = (min) => new Date(Date.now() + min * 60000).toISOString();
  const sec = db.prepare("INSERT INTO blindkey_secrets (did, name, encrypted_value, status, rotate_expires_at) VALUES (?, ?, ?, ?, ?)");
  sec.run(owner, "live1", "MARKERAAAA-live", "active", "");
  sec.run(owner, "del1", "MARKERBBBB-deleted", "deleted", "");
  sec.run(owner, "rot1", "MARKERCCCC-rotated-out", "rotating", iso(-1));
  sec.run(owner, "rotlive", "MARKERDDDD-in-grace", "rotating", iso(60));
  sec.run(owner, "todel", "MARKEREEEE-to-delete", "active", "");
  sec.run(owner, "torev", "MARKERFFFF-to-revoke", "active", "");
  const co = db.prepare("INSERT INTO identity_pending_checkouts (session_id, username, encrypted_password, status, created_at) VALUES (?, ?, ?, ?, ?)");
  co.run("cs_done", "x1", "MARKERGGGG-completed", "completed", new Date().toISOString().replace("T", " ").slice(0, 19));
  co.run("cs_old", "x2", "MARKERHHHH-abandoned", "pending", new Date(Date.now() - 10 * 864e5).toISOString().replace("T", " ").slice(0, 19));
  co.run("cs_new", "x3", "MARKERIIII-fresh", "pending", new Date().toISOString().replace("T", " ").slice(0, 19));
  db.close();
})();' "$S"
: >"$S/stalwart.log"
start

signin(){ curl -s -X POST "$API/api/identity/auth-fingerprint" -H 'Content-Type: application/json' -d "{\"username\":\"$1\",\"password\":\"$2\",\"scope\":\"transact\"}"; }
code(){ curl -s -o /dev/null -w '%{http_code}' -X POST "$API/api/identity/auth-fingerprint" -H 'Content-Type: application/json' -d "{\"username\":\"$1\",\"password\":\"$2\",\"scope\":\"transact\"}"; }
current(){ J 'require("./passwords").verifyPassword(process.argv[2], process.argv[1]).then(r => console.log(r.ok && !r.upgrade ? "yes" : "no"))' "$(Q "select password_hash from identity_wallets where username='$1'")" "$2"; }

# 1. Sign-in for every stored form.
for u in legacy:legacypass1 wrapped:wrappedpass1 plain:plainpass1 hashed:hashedpass1 current:currentpass1; do
  n=${u%%:*}; p=${u#*:}
  [ "$(code "$n" "wrong-$p")" = 401 ] && ok "$n: wrong password refused" || fail "$n: wrong password not refused"
  [ "$(code "$n" "$p")" = 200 ] && ok "$n: right password signs in" || fail "$n: right password refused ($(signin "$n" "$p"))"
  [ "$(current "$n" "$p")" = yes ] && ok "$n: local hash is now current scrypt" || fail "$n: local hash not upgraded"
done
grep -q '^GET current$' "$S/stalwart.log" && fail "Stalwart asked although a current local hash exists" || ok "current local hash: Stalwart not asked"
grep -q '^PATCH' "$S/stalwart.log" && fail "a sign-in wrote to Stalwart" || ok "sign-in never writes to Stalwart"
G0=$(grep -c '^GET plain$' "$S/stalwart.log")
[ "$(code plain plainpass1)" = 200 ] && [ "$(grep -c '^GET plain$' "$S/stalwart.log")" = "$G0" ] && ok "after the upgrade, plain signs in without asking Stalwart" || fail "plain still asks Stalwart"
CR=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$API/api/identity/auth-critical" -H 'Content-Type: application/json' -d '{"username":"legacy","password":"legacypass1","scope":"critical"}')
[ "$CR" != 503 ] && [ "$CR" != 401 ] && ok "auth-critical verifies from the local hash ($CR)" || fail "auth-critical: $CR"

# 2. Migration.
cp "$S/stw.json" "$S/stw.before"
OUT=$(node scripts/migrate-password-hashes.js 2>&1)
cmp -s "$S/stw.json" "$S/stw.before" && ok "dry run leaves Stalwart alone" || fail "dry run wrote to Stalwart"
echo "$OUT" | grep -q '"mode":"dry-run"' && ok "dry run reports" || fail "dry run output: $OUT"
OUT=$(node scripts/migrate-password-hashes.js --execute 2>&1); echo "$OUT" | tail -1 >"$S/migrate.json"
grep -q '"stalwart_failed":0' "$S/migrate.json" && grep -q '"unsalted_left":0' "$S/migrate.json" && ok "migration: no failures, no unsalted hash left" || fail "migration: $OUT"
J 'const s = require(process.argv[1] + "/stw.json"), pw = require("./passwords"); const bad = Object.entries(s).filter(([n, p]) => (p.secrets || []).some(pw.isPlaintextSecret)).map(([n]) => n); console.log(bad.join(",") || "none")' "$S" | grep -qx none \
  && ok "no readable password left in Stalwart" || fail "readable passwords left in Stalwart"
J 'const s = require(process.argv[1] + "/stw.json"); process.exit(s.m2.secrets[1] === "$app$phone$keepme" && s.m2.secrets.length === 2 ? 0 : 1)' "$S" && ok "app password kept as it was" || fail "app password changed"
J 'const s = require(process.argv[1] + "/stw.json"), pw = require("./passwords"); pw.verifyPassword("hashedpass1", s.hashed.secrets[0]).then(r => process.exit(r.ok ? 0 : 1))' "$S" && ok "already-hashed Stalwart entry kept" || fail "hashed entry broken"
[ "$(code m1 m1stalwartpass)" = 200 ] && [ "$(code m1 stale-old-pass)" = 401 ] && ok "m1: Stalwart's password wins over the stale local sha256" || fail "m1 sign-in wrong after migration"
[ "$(code m3 m3localpass)" = 200 ] && [ "$(current m3 m3localpass)" = yes ] && ok "m3: wrapped sha256 signs in and upgrades" || fail "m3 sign-in wrong after migration"
[ "$(code m2 m2pass1)" = 200 ] && ok "m2 signs in after migration" || fail "m2 sign-in failed"
[ "$(code current currentpass1)" = 200 ] && ok "current kept its local hash" || fail "current broken by migration"

# 3. Secret values.
TOKEN=$(signin legacy legacypass1 | python3 -c 'import json,sys; print(json.load(sys.stdin).get("token",""))')
v(){ Q "select length(encrypted_value) from blindkey_secrets where name='$1'"; }
[ "$(v del1)" = 0 ] && ok "sweep at start: deleted row emptied" || fail "deleted row still has a value"
[ "$(v rot1)" = 0 ] && [ "$(Q "select status from blindkey_secrets where name='rot1'")" = retired ] && ok "rotation whose grace ended earlier today: retired and emptied" || fail "expired rotation: $(Q "select status||' '||length(encrypted_value) from blindkey_secrets where name='rot1'")"
[ "$(v rotlive)" -gt 0 ] && [ "$(v live1)" -gt 0 ] && ok "live and in-grace rows keep their values" || fail "a live value was erased"
[ "$(Q "select length(encrypted_password) from identity_pending_checkouts where session_id='cs_done'")" = 0 ] && [ "$(Q "select length(encrypted_password) from identity_pending_checkouts where session_id='cs_old'")" = 0 ] \
  && [ "$(Q "select length(encrypted_password) from identity_pending_checkouts where session_id='cs_new'")" -gt 0 ] && ok "finished and abandoned checkouts lose the sealed password; a fresh one keeps it" || fail "checkout passwords wrong"
DEL=$(curl -s -o /dev/null -w '%{http_code}' -X DELETE "$API/api/blindkey/delete" -H 'Content-Type: application/json' -H "Authorization: Bearer $TOKEN" -d '{"name":"todel"}')
[ "$DEL" = 200 ] && [ "$(v todel)" = 0 ] && ok "delete empties the value" || fail "delete: $DEL, value length $(v todel)"
REV=$(curl -s -o /dev/null -w '%{http_code}' -X DELETE "$API/api/blindkey/revoke" -H 'Content-Type: application/json' -H "Authorization: Bearer $TOKEN" -d '{"name":"torev"}')
[ "$REV" = 200 ] && [ "$(v torev)" = 0 ] && ok "revoke empties the value" || fail "revoke: $REV, value length $(v torev)"
stop; start; stop   # the sweep checkpoints at start
files="$DB_PATH $DB_PATH-wal"
for m in BBBB CCCC EEEE FFFF GGGG HHHH; do
  cat $files 2>/dev/null | grep -aq "MARKER$m" && fail "erased value MARKER$m still in the database file" || ok "MARKER$m gone from the database file"
done
cat $files 2>/dev/null | grep -aq MARKERAAAA && ok "(a live value is still found, so the check can see)" || fail "the file check sees nothing"

echo; [ $fails = 0 ] && echo "security hardening smoke: all ok" || { echo "security hardening smoke: $fails failed"; exit 1; }
