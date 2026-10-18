#!/usr/bin/env node
/**
 * Atomic token consumption — refresh tokens and device codes.
 *
 * Why this exists: single-use consumption used to be a SELECT followed later by an UPDATE, and the
 * successor refresh token was issued before the predecessor was revoked. That was only single-use
 * because the service is one synchronous Node process — a property stated nowhere. These tests pin
 * the invariant to the database: consumption is one guarded UPDATE, rotation/redemption is one
 * transaction, a failed mint burns nothing, and a consumed token presented again is logged as a reuse.
 *
 * Runs the real helper functions extracted from server.js against an in-memory SQLite database
 * created from the real CREATE TABLE statements. No network, no credentials.
 *
 *   NODE_PATH=/path/to/dustforge/node_modules node test/atomic-token-consumption.test.js
 */
const fs = require('fs');
const path = require('path');
const assert = require('assert');
const Database = require('better-sqlite3');

const src = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');

// ── extract the helper block verbatim from server.js ──
const start = src.indexOf('// ── Refresh-token helpers (OAuth-style)');
const end = src.indexOf("app.post('/api/identity/create'", start);
assert.ok(start > 0 && end > start, 'helper block not found in server.js');
const helperSrc = src.slice(start, end);
const schema = (name) => {
  const m = src.match(new RegExp(`CREATE TABLE IF NOT EXISTS ${name} \\([\\s\\S]*?\\)\``));
  assert.ok(m, `schema for ${name} not found`);
  return m[0].replace(/`$/, '');
};

function fresh() {
  const db = new Database(':memory:');
  db.exec(schema('refresh_tokens'));
  db.exec(schema('device_auth'));
  const h = new Function('db', 'require', helperSrc +
    '\nreturn { _refreshHash, issueRefreshToken, consumeRefreshToken, revokeRefreshToken, rotateRefreshToken, claimDeviceAuth, redeemDeviceCode };')(db, require);
  return { db, h };
}

let failures = 0, passes = 0;
const errs = [];
const realErr = console.error; console.error = (...a) => errs.push(a.join(' '));
function check(name, fn) {
  try { fn(); passes++; console.log(`  ok    ${name}`); }
  catch (e) { failures++; console.log(`  FAIL  ${name}\n        ${(e.stack || e.message).split('\n').slice(0, 3).join('\n        ')}`); }
}
const iso = (ms) => new Date(Date.now() + ms).toISOString();

console.log('\nrefresh-token consumption');
check('issue → consume once; row revoked; second consume null + reuse logged', () => {
  const { db, h } = fresh(); errs.length = 0;
  const { refresh_token } = h.issueRefreshToken('did:key:zA', 'transact');
  const rec = h.consumeRefreshToken(refresh_token);
  assert.ok(rec && rec.did === 'did:key:zA' && rec.scope === 'transact');
  assert.strictEqual(db.prepare('SELECT revoked FROM refresh_tokens WHERE id = ?').get(rec.id).revoked, 1);
  assert.strictEqual(h.consumeRefreshToken(refresh_token), null);
  assert.ok(errs.some((l) => l.includes('[refresh-reuse]') && l.includes('did:key:zA')), 'reuse must be logged');
});
check('expired token is not consumed and not logged as reuse', () => {
  const { db, h } = fresh(); errs.length = 0;
  const raw = 'dpr_expired';
  db.prepare('INSERT INTO refresh_tokens (did, token_hash, scope, expires_at) VALUES (?,?,?,?)').run('did:key:zA', h._refreshHash(raw), 'read', iso(-1000));
  assert.strictEqual(h.consumeRefreshToken(raw), null);
  assert.strictEqual(db.prepare('SELECT revoked FROM refresh_tokens WHERE token_hash = ?').get(h._refreshHash(raw)).revoked, 0);
  assert.strictEqual(errs.length, 0);
});
check('unknown / malformed input → null, no throw', () => {
  const { h } = fresh();
  assert.strictEqual(h.consumeRefreshToken('dpr_nope'), null);
  assert.strictEqual(h.consumeRefreshToken(''), null);
  assert.strictEqual(h.consumeRefreshToken(undefined), null);
  assert.strictEqual(h.consumeRefreshToken(42), null);
});
check('the consuming statement is the validating statement (source-level guard)', () => {
  const body = helperSrc.slice(helperSrc.indexOf('function consumeRefreshToken'), helperSrc.indexOf('function revokeRefreshToken'));
  const firstStmt = body.match(/db\.prepare\((['"`])([\s\S]*?)\1/)[2];
  assert.ok(/UPDATE refresh_tokens SET revoked = 1/.test(firstStmt), 'first statement must be the guarded UPDATE');
  assert.ok(/revoked = 0/.test(firstStmt) && /expires_at > \?/.test(firstStmt), 'guard must check revoked and expiry');
});

console.log('\nrotateRefreshToken (transaction)');
check('success: old revoked + linked to new hash, new row live, mint called once, result carries minted', () => {
  const { db, h } = fresh();
  const { refresh_token: old } = h.issueRefreshToken('did:key:zA', 'transact');
  let calls = 0;
  const out = h.rotateRefreshToken(old, (rec) => { calls++; return { token: 'jwt-for-' + rec.did }; });
  assert.strictEqual(calls, 1);
  assert.strictEqual(out.minted.token, 'jwt-for-did:key:zA');
  const oldRow = db.prepare('SELECT * FROM refresh_tokens WHERE id = ?').get(out.rec.id);
  assert.strictEqual(oldRow.revoked, 1);
  assert.strictEqual(oldRow.rotated_to, h._refreshHash(out.nrf.refresh_token));
  const newRow = db.prepare('SELECT * FROM refresh_tokens WHERE token_hash = ?').get(h._refreshHash(out.nrf.refresh_token));
  assert.ok(newRow && newRow.revoked === 0 && newRow.did === 'did:key:zA' && newRow.scope === 'transact');
  assert.strictEqual(db.prepare('SELECT COUNT(*) c FROM refresh_tokens').get().c, 2);
});
check('mint throws → consumption rolled back: old token still live, no successor, retry succeeds', () => {
  const { db, h } = fresh();
  const { refresh_token: old } = h.issueRefreshToken('did:key:zA', 'transact');
  assert.throws(() => h.rotateRefreshToken(old, () => { throw Object.assign(new Error('identity not found'), { status: 404 }); }), /identity not found/);
  assert.strictEqual(db.prepare('SELECT revoked FROM refresh_tokens WHERE token_hash = ?').get(h._refreshHash(old)).revoked, 0);
  assert.strictEqual(db.prepare('SELECT COUNT(*) c FROM refresh_tokens').get().c, 1);
  assert.ok(h.rotateRefreshToken(old, () => ({ token: 'ok' })), 'retry after rollback must succeed');
});
check('unknown or already-rotated token → null, mint never called', () => {
  const { h } = fresh();
  let calls = 0;
  assert.strictEqual(h.rotateRefreshToken('dpr_nope', () => { calls++; }), null);
  const { refresh_token: old } = h.issueRefreshToken('did:key:zA', 'read');
  h.rotateRefreshToken(old, () => ({}));
  assert.strictEqual(h.rotateRefreshToken(old, () => { calls++; }), null);
  assert.strictEqual(calls, 0);
});

console.log('\ndevice-code claim + redemption');
const seedDevice = (db, status, ttlMs = 60000) =>
  db.prepare('INSERT INTO device_auth (device_code, user_code, agent_label, scope, status, approved_did, expires_at) VALUES (?,?,?,?,?,?,?)')
    .run('dpd_' + status, 'ABCD-EFGH', 'agent@host', 'transact', status, status === 'pending' ? null : 'did:key:zOP', iso(ttlMs));
check('approved → claimed exactly once; second claim null', () => {
  const { db, h } = fresh(); seedDevice(db, 'approved');
  const row = h.claimDeviceAuth('dpd_approved');
  assert.ok(row && row.status === 'claimed' && row.approved_did === 'did:key:zOP');
  assert.strictEqual(h.claimDeviceAuth('dpd_approved'), null);
});
check('pending / denied / expired / unknown → null and status unchanged', () => {
  const { db, h } = fresh(); seedDevice(db, 'pending'); seedDevice(db, 'denied');
  db.prepare("INSERT INTO device_auth (device_code, user_code, scope, status, approved_did, expires_at) VALUES ('dpd_old','ZZZZ-ZZZZ','read','approved','did:key:zOP',?)").run(iso(-1000));
  for (const c of ['dpd_pending', 'dpd_denied', 'dpd_old', 'dpd_missing']) assert.strictEqual(h.claimDeviceAuth(c), null, c);
  assert.strictEqual(db.prepare("SELECT status FROM device_auth WHERE device_code = 'dpd_pending'").get().status, 'pending');
  assert.strictEqual(db.prepare("SELECT status FROM device_auth WHERE device_code = 'dpd_old'").get().status, 'approved');
});
check('redeem: claim + mint + refresh in one transaction; refresh issued for the approving DID', () => {
  const { db, h } = fresh(); seedDevice(db, 'approved');
  const out = h.redeemDeviceCode('dpd_approved', (r) => ({ token: 'jwt-' + r.approved_did }));
  assert.strictEqual(out.minted.token, 'jwt-did:key:zOP');
  assert.strictEqual(out.row.status, 'claimed');
  const rf = db.prepare('SELECT * FROM refresh_tokens WHERE token_hash = ?').get(h._refreshHash(out.rf.refresh_token));
  assert.ok(rf && rf.did === 'did:key:zOP' && rf.scope === 'transact');
  assert.strictEqual(h.redeemDeviceCode('dpd_approved', () => ({})), null);
});
check('redeem: mint throws → claim rolled back to approved, no refresh row, retry succeeds', () => {
  const { db, h } = fresh(); seedDevice(db, 'approved');
  assert.throws(() => h.redeemDeviceCode('dpd_approved', () => { throw new Error('mint failed'); }), /mint failed/);
  assert.strictEqual(db.prepare("SELECT status FROM device_auth WHERE device_code = 'dpd_approved'").get().status, 'approved');
  assert.strictEqual(db.prepare('SELECT COUNT(*) c FROM refresh_tokens').get().c, 0);
  assert.ok(h.redeemDeviceCode('dpd_approved', () => ({ token: 'ok' })));
});

console.log('\nhandlers use the transactional helpers (source-level)');
check('refresh handler → rotateRefreshToken; device handler → redeemDeviceCode; no bare claim UPDATE in handlers', () => {
  const refreshH = src.slice(src.indexOf("app.post('/api/identity/refresh',"), src.indexOf("app.post('/api/identity/refresh/revoke'"));
  assert.ok(refreshH.includes('rotateRefreshToken('), 'refresh handler must rotate transactionally');
  assert.ok(!refreshH.includes('issueRefreshToken('), 'refresh handler must not issue a successor outside the transaction');
  const deviceH = src.slice(src.indexOf("app.post('/api/identity/device/token',"), src.indexOf("app.get('/api/identity/device/pending'"));
  assert.ok(deviceH.includes('redeemDeviceCode('), 'device handler must redeem transactionally');
  assert.ok(!/UPDATE device_auth SET status = 'claimed' WHERE device_code = \?"\)/.test(deviceH), 'no unguarded claim UPDATE in the handler');
});

console.error = realErr;
console.log(`\n${passes} passed, ${failures} failed`);
process.exit(failures ? 1 : 0);
