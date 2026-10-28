#!/usr/bin/env node
'use strict';
// One-off (2026-10-28): stop keeping account passwords readable.
//
// Stalwart held every account password as given, and dustforge's local verifier (identity_wallets.password_hash)
// was an unsalted sha256. This script:
//   1. replaces each readable Stalwart secret with its salted scrypt hash (passwords.js; Stalwart verifies it for
//      mail logins): plain secrets, {PLAIN}/{CLEAR} ones, and the readable inner part of an app password
//      ($app$<name>$<inner>). Hashed entries, TOTP seeds (otpauth://) and domain principals are left alone. Each
//      principal is read again just before it is written and skipped if it changed since the listing;
//   2. gives each wallet whose Stalwart password it just hashed that same hash as its local verifier. Stalwart's
//      password was the one sign-in trusted, so it wins over a stale local sha256, and over a current local hash
//      that does not match it;
//   3. wraps every remaining unsalted sha256 in scrypt (passwords.wrapLegacySha256), so no unsalted hash is left;
//      the next sign-in replaces it with a plain scrypt hash.
// Run it after the server that reads these forms is deployed, at a quiet moment: a password reset in the same
// instant as an account's write is detected and reported (reset again), not prevented. Dry run by default; --execute writes. Prints counts
// and usernames only, never a password or a hash.
//
//   set -a; . /opt/dustforge/.env; set +a; node scripts/migrate-password-hashes.js [--execute]
const http = require('http');
const path = require('path');
const Database = require('better-sqlite3');
const passwords = require('../passwords');

const EXECUTE = process.argv.includes('--execute');
const DB_PATH = process.env.DB_PATH || path.join(__dirname, '..', 'data', 'dustforge.db');
const HOST = process.env.STALWART_HOST || '100.83.112.88';
const PORT = Number(process.env.STALWART_PORT || 8080);
const AUTH = 'Basic ' + Buffer.from('admin:' + (process.env.STALWART_PASS || '')).toString('base64');

function stalwart(method, p, body) {
  return new Promise((resolve, reject) => {
    const r = http.request({ hostname: HOST, port: PORT, path: p, method, headers: { Authorization: AUTH, 'Content-Type': 'application/json' } }, (res) => {
      let d = ''; res.on('data', (c) => d += c);
      res.on('end', () => { let j = null; try { j = JSON.parse(d); } catch (_) {} resolve({ status: res.statusCode, json: j }); });
    });
    r.on('error', reject);
    r.setTimeout(15000, () => r.destroy(new Error('stalwart timeout')));
    if (body) r.write(JSON.stringify(body));
    r.end();
  });
}

const asList = (s) => (Array.isArray(s) ? s : s ? [s] : []);

async function principals() {
  const out = [];
  for (let page = 1; page < 1000; page++) {
    const r = await stalwart('GET', `/api/principal?limit=100&page=${page}`);
    const items = r.json && r.json.data && r.json.data.items;
    if (r.status !== 200 || !Array.isArray(items)) throw new Error(`listing principals failed (HTTP ${r.status})`);
    out.push(...items);
    if (!items.length || out.length >= r.json.data.total) break;
  }
  return out;
}

(async () => {
  const db = new Database(DB_PATH);
  db.pragma('secure_delete = ON');   // the replaced unsalted hashes are zeroed, not left in free pages
  const wallets = new Map(db.prepare('SELECT did, username, password_hash FROM identity_wallets').all().map((w) => [w.username, w]));
  const tally = { principals: 0, stalwart_hashed: 0, stalwart_failed: 0, skipped_changed: 0, local_from_stalwart: 0, local_disagreed: 0,
    local_wrapped: 0, local_current: 0, raced_by_reset: 0 };
  const fromStalwart = new Set();
  const localNow = (did) => (db.prepare('SELECT password_hash FROM identity_wallets WHERE did = ?').get(did) || {}).password_hash || '';

  for (const listed of await principals()) {
    if (listed.type !== 'individual') continue;
    tally.principals++;
    if (!asList(listed.secrets).some(passwords.isPlaintextSecret)) continue;
    const name = listed.name, w = wallets.get(name);
    // Read the principal again right before deciding: hashing what the listing saw would undo a reset made since.
    const fresh = await stalwart('GET', `/api/principal/${encodeURIComponent(name)}`);
    const secrets = asList(fresh.json && fresh.json.data && fresh.json.data.secrets);
    if (fresh.status !== 200 || JSON.stringify(secrets) !== JSON.stringify(asList(listed.secrets))) {
      tally.skipped_changed++; console.error(`  skipped ${name}: changed since the listing; run the script again`); continue;
    }
    const hashed = [];
    for (const s of secrets) { const h = await passwords.hashStalwartSecret(s); hashed.push(h === null ? s : h); }
    // The local verifier follows Stalwart's account password, which is what sign-in trusted until now.
    const readable = passwords.readableSecret(secrets[0]);
    const before = w ? localNow(w.did) : '';
    let local = null, note = '';
    if (w && readable !== null) {
      if (!passwords.isCurrent(before)) local = hashed[0];
      else if ((await passwords.verifyPassword(readable, before)).ok !== true) {
        local = hashed[0]; tally.local_disagreed++; note = "; its local hash disagreed with Stalwart, Stalwart's password kept";
      }
    }
    console.log(`${EXECUTE ? 'hash' : 'would hash'} Stalwart password of ${name}${w ? '' : ' (no wallet)'}${note}`);
    if (!EXECUTE) { tally.stalwart_hashed++; if (local) { tally.local_from_stalwart++; fromStalwart.add(name); } continue; }
    const r = await stalwart('PATCH', `/api/principal/${encodeURIComponent(name)}`, [{ action: 'set', field: 'secrets', value: hashed }]);
    const check = await stalwart('GET', `/api/principal/${encodeURIComponent(name)}`);
    const now = asList(check.json && check.json.data && check.json.data.secrets);
    if (r.status >= 300 || now.length !== hashed.length || now.some(passwords.isPlaintextSecret)) {
      tally.stalwart_failed++; console.error(`  FAILED for ${name} (HTTP ${r.status}); left as it was found`); continue;
    }
    tally.stalwart_hashed++;
    // A reset lands in Stalwart first, then in the local hash: a local hash that moved while this ran means a
    // reset may have been overwritten in Stalwart by the old password's hash.
    if (w && localNow(w.did) !== before) {
      tally.raced_by_reset++; console.error(`  WARNING ${name}: the password was reset while this ran; reset it again`); continue;
    }
    if (local) {
      // Only over the hash read above: a sign-in or reset in between keeps what it wrote.
      const ch = db.prepare("UPDATE identity_wallets SET password_hash = ? WHERE did = ? AND COALESCE(password_hash, '') = ?").run(local, w.did, before).changes;
      if (ch) { tally.local_from_stalwart++; fromStalwart.add(name); }
    }
  }

  for (const w of wallets.values()) {
    if (fromStalwart.has(w.username)) continue;
    const h = localNow(w.did);
    if (passwords.isCurrent(h)) { tally.local_current++; continue; }
    if (!/^[0-9a-f]{64}$/.test(h)) continue;
    console.log(`${EXECUTE ? 'wrap' : 'would wrap'} the unsalted local hash of ${w.username}`);
    if (!EXECUTE) { tally.local_wrapped++; continue; }
    if (db.prepare('UPDATE identity_wallets SET password_hash = ? WHERE did = ? AND password_hash = ?').run(await passwords.wrapLegacySha256(h), w.did, h).changes) tally.local_wrapped++;
  }

  const left = db.prepare("SELECT count(*) n FROM identity_wallets WHERE length(password_hash) = 64 AND password_hash NOT LIKE '$%'").get().n;
  if (EXECUTE) { try { db.pragma('wal_checkpoint(TRUNCATE)'); } catch (_) {} }
  console.log(JSON.stringify({ mode: EXECUTE ? 'execute' : 'dry-run', ...tally, unsalted_left: left }));
  db.close();
  if (tally.stalwart_failed) process.exit(1);
})().catch((e) => { console.error(e.message); process.exit(1); });
