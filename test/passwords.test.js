'use strict';
const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const pw = require('../passwords');

const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');

test('hashPassword: salted PHC scrypt, different every time, verifies', async () => {
  const a = await pw.hashPassword('correct horse'), b = await pw.hashPassword('correct horse');
  assert.match(a, /^\$scrypt\$ln=15,r=8,p=1\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+$/);
  assert.notStrictEqual(a, b);
  assert.deepStrictEqual(await pw.verifyPassword('correct horse', a), { ok: true, upgrade: false });
  assert.deepStrictEqual(await pw.verifyPassword('correct horsf', a), { ok: false, upgrade: false });
  assert.ok(pw.isCurrent(a));
});

test('legacy forms verify and ask for an upgrade', async () => {
  assert.deepStrictEqual(await pw.verifyPassword('old', sha('old')), { ok: true, upgrade: true });
  assert.deepStrictEqual(await pw.verifyPassword('new', sha('old')), { ok: false, upgrade: true });
  const wrapped = await pw.wrapLegacySha256(sha('old'));
  assert.ok(wrapped.startsWith('sha256+$scrypt$'));
  assert.ok(!pw.isCurrent(wrapped));
  assert.deepStrictEqual(await pw.verifyPassword('old', wrapped), { ok: true, upgrade: true });
  assert.deepStrictEqual(await pw.verifyPassword(sha('old'), wrapped), { ok: false, upgrade: true });   // the digest is not the password
  await assert.rejects(pw.wrapLegacySha256('not-hex'));
});

test('a weaker scrypt verifies but asks for an upgrade', async () => {
  const salt = crypto.randomBytes(16), key = crypto.scryptSync('pw', salt, 32, { N: 2 ** 10, r: 8, p: 1 });
  const weak = `$scrypt$ln=10,r=8,p=1$${salt.toString('base64').replace(/=+$/, '')}$${key.toString('base64').replace(/=+$/, '')}`;
  assert.deepStrictEqual(await pw.verifyPassword('pw', weak), { ok: true, upgrade: true });
});

test('Stalwart secrets: readable ones verify only in stalwart mode; other schemes give no verdict', async () => {
  const st = { stalwart: true };
  assert.deepStrictEqual(await pw.verifyPassword('hunter2', 'hunter2'), { ok: null, upgrade: false });
  assert.deepStrictEqual(await pw.verifyPassword('hunter2', 'hunter2', st), { ok: true, upgrade: true });
  assert.deepStrictEqual(await pw.verifyPassword('$weird{pw', '$weird{pw', st), { ok: true, upgrade: true });
  assert.deepStrictEqual(await pw.verifyPassword('pw', '{PLAIN}pw', st), { ok: true, upgrade: true });
  assert.deepStrictEqual(await pw.verifyPassword('pw', '{CLEAR}pw', st), { ok: true, upgrade: true });
  // A readable password that happens to be 64 hex characters is a password in Stalwart, not a sha256 digest.
  const hex = crypto.randomBytes(32).toString('hex');
  assert.deepStrictEqual(await pw.verifyPassword(hex, hex, st), { ok: true, upgrade: true });
  assert.deepStrictEqual(await pw.verifyPassword(hex, sha(hex)), { ok: true, upgrade: true });   // local mode: a digest
  for (const other of ['$argon2id$v=19$m=1,t=1,p=1$x$y', '$2b$10$abc', '$6$salt$hash', '$y$j9T$a$b', '$7$abc', '{SSHA}abc', '$app$phone$x', '$pbkdf2-sha256$i=1$x$y', 'otpauth://totp/a?secret=B'])
    assert.deepStrictEqual(await pw.verifyPassword('x', other, st), { ok: null, upgrade: false }, other);
  assert.strictEqual((await pw.verifyPassword('pw', await pw.hashPassword('pw'), st)).ok, true);
});

test('which Stalwart secrets the migration hashes, and how', async () => {
  for (const readable of ['hunter2', '$weird{pw', '{PLAIN}pw', '{CLEAR}pw', '$app$phone$plainapp']) assert.ok(pw.isPlaintextSecret(readable), readable);
  const h = await pw.hashPassword('a');
  for (const kept of [h, '$app$phone$' + h, 'otpauth://totp/a?secret=B', '{SSHA}x', '$2b$10$abc', '']) assert.ok(!pw.isPlaintextSecret(kept), kept);
  const plain = await pw.hashStalwartSecret('{PLAIN}pw');
  assert.ok(pw.isCurrent(plain) && (await pw.verifyPassword('pw', plain)).ok);
  const app = await pw.hashStalwartSecret('$app$phone$plainapp');
  assert.match(app, /^\$app\$phone\$\$scrypt\$/);
  assert.ok((await pw.verifyPassword('plainapp', app.slice('$app$phone$'.length))).ok);
  assert.strictEqual(await pw.hashStalwartSecret('$app$phone$' + h), null);
  assert.strictEqual(await pw.hashStalwartSecret('otpauth://totp/a?secret=B'), null);
  assert.strictEqual(await pw.hashStalwartSecret(h), null);
});

test('stored scrypt parameters above the caps are refused, not computed', async () => {
  const salt = crypto.randomBytes(16).toString('base64').replace(/=+$/, ''), hash = crypto.randomBytes(32).toString('base64').replace(/=+$/, '');
  for (const params of ['ln=17,r=8,p=1', 'ln=20,r=8,p=16', 'ln=15,r=9,p=1', 'ln=15,r=8,p=3']) {
    const t = Date.now();
    assert.strictEqual((await pw.verifyPassword('pw', `$scrypt$${params}$${salt}$${hash}`)).ok, null, params);
    assert.ok(Date.now() - t < 50, params);
  }
});

test('malformed or tampered hashes never verify', async () => {
  const good = await pw.hashPassword('pw');
  const [, , params, salt, hash] = good.split('$');
  const flipped = hash.slice(0, -2) + (hash.slice(-2) === 'AA' ? 'BB' : 'AA');
  assert.strictEqual((await pw.verifyPassword('pw', `$scrypt$${params}$${salt}$${flipped}`)).ok, false);
  for (const bad of ['$scrypt$ln=99,r=8,p=1$' + salt + '$' + hash, '$scrypt$ln=15,r=8,p=1$$' + hash, '$scrypt$garbage', 'sha256+$scrypt$nope'])
    assert.strictEqual((await pw.verifyPassword('pw', bad)).ok, null, bad);
  assert.strictEqual((await pw.verifyPassword('', good)).ok, null);
  assert.strictEqual((await pw.verifyPassword('pw', null)).ok, null);
  await assert.rejects(pw.hashPassword(''));
});
