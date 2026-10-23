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

test('locks escalate: doubling within a day of the last lock, the third in a row is hard; a day later they start over', () => {
  const now = Date.parse('2026-10-22T10:00:00Z');
  const l1 = pg.afterFailure({ pin_failures: 4 }, now);
  assert.equal(l1.lock_seconds, 900); assert.equal(l1.pin_lock_count, 1); assert.equal(l1.hard, false);
  const l2 = pg.afterFailure({ pin_failures: 4, pin_locked_until: l1.pin_locked_until, pin_lock_count: 1 }, now + 3600e3);
  assert.equal(l2.lock_seconds, 1800); assert.equal(l2.pin_lock_count, 2); assert.equal(l2.hard, false);
  const l3 = pg.afterFailure({ pin_failures: 4, pin_locked_until: l2.pin_locked_until, pin_lock_count: 2 }, now + 7200e3);
  assert.equal(l3.hard, true); assert.equal(l3.pin_locked_until, pg.HARD_LOCK_UNTIL); assert.equal(pg.isHardLocked(l3), true);
  assert.ok(pg.lockedFor(l3, now + 365 * 86400e3) > 0, 'a hard lock does not expire');
  const later = pg.afterFailure({ pin_failures: 4, pin_locked_until: '2026-10-20T09:00:00.000Z', pin_lock_count: 2 }, now);
  assert.equal(later.lock_seconds, 900); assert.equal(later.pin_lock_count, 1, 'over a day since the last lock: start over');
  const miss = pg.afterFailure({ pin_failures: 1, pin_locked_until: l1.pin_locked_until, pin_lock_count: 1 }, now);
  assert.equal(miss.locked, false); assert.equal(miss.pin_locked_until, l1.pin_locked_until, 'a miss keeps the lock history'); assert.equal(miss.pin_lock_count, 1);
  assert.equal(pg.lockAfterMiss({ pin_failures: 5 }, now).pin_lock_count, 1, 'lockAfterMiss takes the already-counted state');
  assert.equal(pg.isHardLocked({ pin_locked_until: l1.pin_locked_until }), false);
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

test('weakenedGates: removing a gate demands every gate currently on that action; adding needs nothing', () => {
  const std = { reveal: ['pin'], rotate: [], delete: [], use: [] };
  const elev = { reveal: ['pin', 'twofa'], rotate: ['twofa'], delete: ['twofa'], use: [] };
  const crit = { reveal: ['pin', 'twofa', 'sms'], rotate: ['pin', 'twofa'], delete: ['pin', 'twofa', 'sms'], use: [] };
  assert.deepEqual(pg.weakenedGates(std, elev), { actions: [], prove: [] }, 'strengthening');
  assert.deepEqual(pg.weakenedGates(std, std), { actions: [], prove: [] }, 'no change');
  assert.deepEqual(pg.weakenedGates(elev, std), { actions: ['reveal', 'rotate', 'delete'], prove: ['pin', 'twofa'] });
  assert.deepEqual(pg.weakenedGates(crit, elev), { actions: ['reveal', 'rotate', 'delete'], prove: ['pin', 'twofa', 'sms'] });
  assert.deepEqual(pg.weakenedGates(std, { reveal: [], rotate: [], delete: [], use: [] }), { actions: ['reveal'], prove: ['pin'] });
  // legacy spelling counts as the same gate; reordering is not a weakening
  assert.deepEqual(pg.weakenedGates({ reveal: ['fingerprint', 'twofa'] }, { reveal: ['twofa', 'pin'] }), { actions: [], prove: [] });
  assert.deepEqual(pg.weakenedGates({ reveal: ['pin'] }, {}), { actions: ['reveal'], prove: ['pin'] }, 'missing action = empty list');
  assert.deepEqual(pg.weakenedGates(null, null), { actions: [], prove: [] });
});
