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

test('readable Stalwart secrets only with allowPlaintext; other schemes give no verdict', async () => {
  assert.deepStrictEqual(await pw.verifyPassword('hunter2', 'hunter2'), { ok: null, upgrade: false });
  assert.deepStrictEqual(await pw.verifyPassword('hunter2', 'hunter2', { allowPlaintext: true }), { ok: true, upgrade: true });
  assert.deepStrictEqual(await pw.verifyPassword('$weird{pw', '$weird{pw', { allowPlaintext: true }), { ok: true, upgrade: true });
  for (const other of ['$argon2id$v=19$m=1,t=1,p=1$x$y', '$2b$10$abc', '$6$salt$hash', '{SSHA}abc', '$app$phone$x', '$pbkdf2-sha256$i=1$x$y'])
    assert.deepStrictEqual(await pw.verifyPassword('x', other, { allowPlaintext: true }), { ok: null, upgrade: false }, other);
  assert.ok(pw.isPlaintextSecret('hunter2') && pw.isPlaintextSecret('$weird{pw'));
  assert.ok(!pw.isPlaintextSecret('$app$phone$x') && !pw.isPlaintextSecret(await pw.hashPassword('a')) && !pw.isPlaintextSecret(''));
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
