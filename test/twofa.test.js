'use strict';
// node --test test/twofa.test.js
const test = require('node:test');
const assert = require('node:assert/strict');
const Database = require('better-sqlite3');
const tf = require('../twofa');

function mkdb() {
  const db = new Database(':memory:');
  db.exec(`CREATE TABLE identity_wallets (id INTEGER PRIMARY KEY AUTOINCREMENT, did TEXT UNIQUE, username TEXT, email TEXT, recovery_email TEXT DEFAULT '')`);
  db.exec(`CREATE TABLE identity_2fa_codes (id INTEGER PRIMARY KEY AUTOINCREMENT, did TEXT, code TEXT, expires_at TEXT, used INTEGER DEFAULT 0, created_at TEXT DEFAULT CURRENT_TIMESTAMP)`);
  tf.initSchema(db);
  db.prepare("INSERT INTO identity_wallets (did, username, email) VALUES ('did:key:a', 'aaron', 'aaron@dustforge.com')").run();
  return db;
}
const wallet = db => db.prepare("SELECT * FROM identity_wallets WHERE did = 'did:key:a'").get();

test('RFC 6238 vectors (SHA-1): the test secret produces the published codes', () => {
  const secret = tf.base32Encode(Buffer.from('12345678901234567890'));
  assert.equal(secret, 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ');
  assert.equal(tf.totp(secret, 59 * 1000), '287082');            // T=59  → 94287082
  assert.equal(tf.totp(secret, 1111111109 * 1000), '081804');    // T=1111111109 → 07081804
  assert.equal(tf.totp(secret, 1234567890 * 1000), '005924');    // T=1234567890 → 89005924
  assert.equal(tf.totp(secret, 20000000000 * 1000), '353130');   // T=20000000000 → 65353130
});

test('base32 round-trips and tolerates padding, spaces, dashes, lowercase', () => {
  for (const n of [1, 5, 10, 20, 33]) {
    const buf = require('crypto').randomBytes(n);
    assert.deepEqual(tf.base32Decode(tf.base32Encode(buf)), buf);
  }
  assert.deepEqual(tf.base32Decode('gezd gnbv-GY3TQOJQ=='), Buffer.from('1234567890'));
  assert.throws(() => tf.base32Decode('1!'), /invalid base32/);
});

test('verifyTotp: window of one step, replay refused, bad input refused', () => {
  const secret = tf.generateSecret();
  const now = 1_700_000_000_000;
  const step = tf.totpStep(now);
  const cur = tf.hotp(secret, step), prev = tf.hotp(secret, step - 1), next = tf.hotp(secret, step + 1), old = tf.hotp(secret, step - 2);
  assert.equal(tf.verifyTotp(secret, cur, { nowMs: now }).ok, true);
  assert.equal(tf.verifyTotp(secret, prev, { nowMs: now }).ok, true);
  assert.equal(tf.verifyTotp(secret, next, { nowMs: now }).ok, true);
  assert.equal(tf.verifyTotp(secret, old, { nowMs: now }).ok, false);
  assert.equal(tf.verifyTotp(secret, cur, { nowMs: now, lastStep: step }).ok, false, 'same step twice is a replay');
  assert.equal(tf.verifyTotp(secret, prev, { nowMs: now, lastStep: step }).ok, false, 'older step after a newer one is a replay');
  assert.equal(tf.verifyTotp(secret, next, { nowMs: now, lastStep: step }).ok, true);
  assert.equal(tf.verifyTotp(secret, '12 34', { nowMs: now }).ok, false);
  assert.equal(tf.verifyTotp(secret, 'abcdef', { nowMs: now }).ok, false);
});

test('otpauth uri carries issuer, account, secret, and standard parameters', () => {
  const u = tf.otpauthUri({ account: 'aaron', secret: 'ABCD' });
  assert.equal(u, 'otpauth://totp/DemiPass%3Aaaron?secret=ABCD&issuer=DemiPass&algorithm=SHA1&digits=6&period=30');
});

test('recovery codes: eight distinct codes, each usable once, hashes never store the code', () => {
  const { codes, hashes } = tf.generateRecoveryCodes();
  assert.equal(codes.length, 8); assert.equal(new Set(codes).size, 8);
  assert.ok(codes.every(c => /^[0-9a-f]{5}-[0-9a-f]{5}$/.test(c)));
  assert.ok(hashes.every(h => /^[0-9a-f]{64}$/.test(h) && !codes.includes(h)));
  const left = tf.consumeRecoveryCode(hashes, codes[2].toUpperCase().replace('-', ' '));
  assert.equal(left.length, 7);
  assert.equal(tf.consumeRecoveryCode(left, codes[2]), null, 'spent code is gone');
  assert.equal(tf.consumeRecoveryCode(left, 'nope-nope'), null);
});

test('gate: disabled → pass; enabled → requires a factor; each factor works; device token skips', () => {
  const db = mkdb();
  const decrypt = s => s;                                        // tests store the secret in the clear
  assert.deepEqual(tf.gate(db, wallet(db), {}), { ok: true, method: 'none' });
  const secret = tf.generateSecret();
  const { codes, hashes } = tf.generateRecoveryCodes();
  db.prepare('UPDATE identity_wallets SET twofa_enabled = 1, totp_secret = ?, recovery_codes = ? WHERE did = ?').run(secret, JSON.stringify(hashes), 'did:key:a');
  const r0 = tf.gate(db, wallet(db), {}, { decryptSecret: decrypt });
  assert.equal(r0.ok, false); assert.equal(r0.required, true); assert.deepEqual(r0.methods, ['totp', 'email', 'recovery']);
  const now = Date.now();
  const r1 = tf.gate(db, wallet(db), { otp: tf.totp(secret, now) }, { decryptSecret: decrypt, nowMs: now });
  assert.deepEqual(r1, { ok: true, method: 'totp' });
  const r1b = tf.gate(db, wallet(db), { otp: tf.totp(secret, now) }, { decryptSecret: decrypt, nowMs: now });
  assert.equal(r1b.ok, false, 'the same code cannot be used twice');
  const { code } = tf.issueEmailCode(db, 'did:key:a');
  assert.equal(tf.gate(db, wallet(db), { email_code: '000000' }, { decryptSecret: decrypt }).ok, code === '000000');
  assert.deepEqual(tf.gate(db, wallet(db), { email_code: code }, { decryptSecret: decrypt }), { ok: true, method: 'email' });
  assert.equal(tf.gate(db, wallet(db), { email_code: code }, { decryptSecret: decrypt }).ok, false, 'email code is single-use');
  const r3 = tf.gate(db, wallet(db), { recovery_code: codes[0] }, { decryptSecret: decrypt });
  assert.equal(r3.ok, true); assert.equal(r3.method, 'recovery'); assert.equal(r3.recovery_codes_left, 7);
  assert.equal(tf.gate(db, wallet(db), { recovery_code: codes[0] }, { decryptSecret: decrypt }).ok, false);
  const dev = tf.issueDeviceToken(db, 'did:key:a', 'phone');
  assert.match(dev.token, /^dpdev_/);
  assert.deepEqual(tf.gate(db, wallet(db), { device_token: dev.token }, { decryptSecret: decrypt }), { ok: true, method: 'device' });
  assert.equal(tf.listDevices(db, 'did:key:a').length, 1);
  assert.equal(tf.gate(db, wallet(db), { device_token: 'dpdev_bogus' }, { decryptSecret: decrypt }).ok, false);
  assert.equal(tf.revokeDevice(db, 'did:key:a', tf.listDevices(db, 'did:key:a')[0].id), true);
  assert.equal(tf.gate(db, wallet(db), { device_token: dev.token }, { decryptSecret: decrypt }).ok, false, 'revoked device no longer skips');
  db.prepare("UPDATE identity_trusted_devices SET revoked = 0, expires_at = '2000-01-01T00:00:00.000Z'").run();
  assert.equal(tf.gate(db, wallet(db), { device_token: dev.token }, { decryptSecret: decrypt }).ok, false, 'expired device no longer skips');
});
