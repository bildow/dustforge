'use strict';
// node --test test/pin_gate.test.js — the vault PIN helpers behind POST /api/identity/pin and gate 'pin'.
const test = require('node:test');
const assert = require('node:assert/strict');
const pg = require('../pin_gate');

test('validPin: 4 to 8 digits, strings only', () => {
  for (const ok of ['0000', '1234', '12345678']) assert.equal(pg.validPin(ok), true, ok);
  for (const bad of ['123', '123456789', '12a4', ' 1234', '1234\n', '', null, undefined, 1234]) assert.equal(pg.validPin(bad), false, String(bad));
});

test('hashPin/verifyPin: round trip, wrong PIN, salted, malformed store', () => {
  const h = pg.hashPin('4821');
  assert.match(h, /^scrypt\$16384\$[0-9a-f]{32}\$[0-9a-f]{64}$/);
  assert.equal(pg.verifyPin(h, '4821'), true);
  assert.equal(pg.verifyPin(h, '4822'), false);
  assert.equal(pg.verifyPin(h, '48210'), false);
  assert.notEqual(pg.hashPin('4821'), h, 'per-hash salt');
  for (const bad of [null, '', 'plain', 'scrypt$x$y', 'sha256$00$00', 'scrypt$16384$zz$zz']) assert.equal(pg.verifyPin(bad, '4821'), false, String(bad));
  assert.equal(pg.verifyPin(h, 'abcd'), false, 'non-digit input never verifies');
  assert.throws(() => pg.hashPin('12'), /4 to 8 digits/);
});

test('afterFailure: counts up, 5th miss locks for 15 min and resets the counter', () => {
  const now = Date.parse('2026-10-19T20:00:00Z');
  let w = { pin_failures: 0, pin_locked_until: null };
  const seen = [];
  for (let i = 0; i < 4; i++) { const n = pg.afterFailure(w, now); seen.push(n.attempts_left); assert.equal(n.locked, false); w = { ...w, ...n }; }
  assert.deepEqual(seen, [4, 3, 2, 1]);
  const fifth = pg.afterFailure(w, now);
  assert.equal(fifth.locked, true);
  assert.equal(fifth.attempts_left, 0);
  assert.equal(fifth.pin_failures, 0);
  assert.equal(fifth.pin_locked_until, '2026-10-19T20:15:00.000Z');
  assert.equal(pg.lockedFor({ ...w, ...fifth }, now), 900);
  assert.equal(pg.lockedFor({ ...w, ...fifth }, now + 899_000), 1);
  assert.equal(pg.lockedFor({ ...w, ...fifth }, now + 900_000), 0, 'lock expires');
});

test('lockedFor: tolerant of missing or garbage state', () => {
  assert.equal(pg.lockedFor(null), 0);
  assert.equal(pg.lockedFor({}), 0);
  assert.equal(pg.lockedFor({ pin_locked_until: 'not a date' }), 0);
  assert.equal(pg.lockedFor({ pin_locked_until: '2000-01-01T00:00:00Z' }), 0);
});

test('normalizeGates: legacy fingerprint becomes pin, deduplicated, order kept', () => {
  assert.deepEqual(pg.normalizeGates(['fingerprint']), ['pin']);
  assert.deepEqual(pg.normalizeGates(['fingerprint', 'twofa', 'pin', 'sms']), ['pin', 'twofa', 'sms']);
  assert.deepEqual(pg.normalizeGates([]), []);
  assert.deepEqual(pg.normalizeGates(undefined), []);
  assert.equal(pg.normalizeGate('password'), 'password');
});
