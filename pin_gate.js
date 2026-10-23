'use strict';
// Vault PIN — the human-presence factor behind `reveal` (and any other action a gate policy puts it on).
// A 4–8 digit code the owner types on the phone. Stored as scrypt(pin, per-user salt); never kept or logged in
// clear. Brute force is bounded by an escalating lockout (MAX_FAILURES wrong tries → LOCK_SECONDS, doubling while
// locks follow each other, and a lock only the account password clears after HARD_LOCK_AFTER of them) on top of
// the route's rate limit, so even a 4-digit PIN behind a password-authenticated session is not guessable.
// Pure helpers (no db) so they are unit-testable; server.js owns the rows.
const crypto = require('crypto');

const PIN_RE = /^\d{4,8}$/;
const MAX_FAILURES = 5;
const LOCK_SECONDS = 15 * 60;              // the first lock; each lock within LOCK_WINDOW_SECONDS of the last doubles
const LOCK_WINDOW_SECONDS = 24 * 60 * 60;
const HARD_LOCK_AFTER = 3;                 // the 3rd lock in a row never expires: only the password (a new PIN) clears it
const HARD_LOCK_UNTIL = '9999-12-31T23:59:59.000Z';
const SCRYPT = { N: 16384, r: 8, p: 1, keylen: 32 };

function validPin(pin) { return typeof pin === 'string' && PIN_RE.test(pin); }

function hashPin(pin) {
  if (!validPin(pin)) throw new Error('PIN must be 4 to 8 digits');
  const salt = crypto.randomBytes(16);
  const key = crypto.scryptSync(pin, salt, SCRYPT.keylen, { N: SCRYPT.N, r: SCRYPT.r, p: SCRYPT.p });
  return `scrypt$${SCRYPT.N}$${salt.toString('hex')}$${key.toString('hex')}`;
}

function verifyPin(stored, pin) {
  if (!stored || typeof stored !== 'string' || !validPin(pin)) return false;
  const parts = stored.split('$');
  if (parts.length !== 4 || parts[0] !== 'scrypt') return false;
  const N = Number(parts[1]);
  const salt = Buffer.from(parts[2], 'hex');
  const want = Buffer.from(parts[3], 'hex');
  if (!N || !salt.length || !want.length) return false;
  let got;
  try { got = crypto.scryptSync(pin, salt, want.length, { N, r: SCRYPT.r, p: SCRYPT.p }); } catch (_) { return false; }
  return crypto.timingSafeEqual(got, want);
}

// Lockout state lives on the wallet row (pin_failures, pin_locked_until as ISO text).
// Seconds the PIN stays locked from `now`, 0 when usable.
function lockedFor(wallet, now = Date.now()) {
  if (!wallet || !wallet.pin_locked_until) return 0;
  const until = Date.parse(wallet.pin_locked_until);
  if (Number.isNaN(until)) return 0;
  return Math.max(0, Math.ceil((until - now) / 1000));
}

function isHardLocked(wallet) { return Boolean(wallet && wallet.pin_locked_until === HARD_LOCK_UNTIL); }

// What a miss does once it has been counted (`wallet.pin_failures` already includes it). The MAX_FAILURES-th miss
// locks the PIN and resets the counter. Locks escalate: one that follows the previous lock within
// LOCK_WINDOW_SECONDS lasts twice as long, and the HARD_LOCK_AFTER-th in a row does not expire — only the account
// password (setting a new PIN) clears it. A right PIN resets the miss counter but never the lock history, so the
// owner's own use cannot hand someone who is guessing a fresh run.
function lockAfterMiss(wallet, now = Date.now()) {
  const failures = Number(wallet && wallet.pin_failures) || 0;
  const history = { pin_locked_until: (wallet && wallet.pin_locked_until) || null, pin_lock_count: Number(wallet && wallet.pin_lock_count) || 0 };
  if (failures < MAX_FAILURES) return { pin_failures: failures, ...history, locked: false, attempts_left: MAX_FAILURES - failures };
  const lastEnd = Date.parse(history.pin_locked_until || '');
  const level = !Number.isNaN(lastEnd) && now - lastEnd < LOCK_WINDOW_SECONDS * 1000 ? history.pin_lock_count + 1 : 1;
  if (level >= HARD_LOCK_AFTER) return { pin_failures: 0, pin_locked_until: HARD_LOCK_UNTIL, pin_lock_count: level, locked: true, hard: true, lock_seconds: null, attempts_left: 0 };
  const lock_seconds = LOCK_SECONDS * 2 ** (level - 1);
  return { pin_failures: 0, pin_locked_until: new Date(now + lock_seconds * 1000).toISOString(), pin_lock_count: level, locked: true, hard: false, lock_seconds, attempts_left: 0 };
}
// Count-and-decide in one step (the state before the miss).
function afterFailure(wallet, now = Date.now()) {
  return lockAfterMiss({ ...(wallet || {}), pin_failures: (Number(wallet && wallet.pin_failures) || 0) + 1 }, now);
}

// Gate names in stored policies: 'fingerprint' used to mean "re-enter the password on a fingerprint-authed
// token"; it is the PIN now. Legacy custom policies keep working without a migration.
function normalizeGate(g) { return g === 'fingerprint' ? 'pin' : g; }
function normalizeGates(list) {
  const out = [];
  for (const g of Array.isArray(list) ? list : []) { const n = normalizeGate(g); if (!out.includes(n)) out.push(n); }
  return out;
}

// What a policy change takes away. For every action whose protection the proposed policy weakens (any gate
// currently required but no longer), the caller must first open that lock: prove EVERY gate currently guarding
// the action. Adding factors weakens nothing and needs only the owner token. Both inputs are effective
// (resolved) policies: { action: [gates] }.
function weakenedGates(current, proposed) {
  const actions = [], prove = [];
  for (const action of Object.keys(current || {})) {
    const cur = normalizeGates(current[action]);
    const next = normalizeGates((proposed || {})[action]);
    if (!cur.some(g => !next.includes(g))) continue;
    actions.push(action);
    for (const g of cur) if (!prove.includes(g)) prove.push(g);
  }
  return { actions, prove };
}

module.exports = { PIN_RE, MAX_FAILURES, LOCK_SECONDS, LOCK_WINDOW_SECONDS, HARD_LOCK_AFTER, HARD_LOCK_UNTIL, validPin, hashPin, verifyPin, lockedFor, isHardLocked, lockAfterMiss, afterFailure, normalizeGate, normalizeGates, weakenedGates };
