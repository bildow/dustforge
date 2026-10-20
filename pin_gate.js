'use strict';
// Vault PIN — the human-presence factor behind `reveal` (and any other action a gate policy puts it on).
// A 4–8 digit code the owner types on the phone. Stored as scrypt(pin, per-user salt); never kept or logged in
// clear. Brute force is bounded by a lockout (MAX_FAILURES wrong tries → LOCK_SECONDS) on top of the route's
// rate limit, so even a 4-digit PIN behind a password-authenticated session is not guessable in practice.
// Pure helpers (no db) so they are unit-testable; server.js owns the rows.
const crypto = require('crypto');

const PIN_RE = /^\d{4,8}$/;
const MAX_FAILURES = 5;
const LOCK_SECONDS = 15 * 60;
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

// What a wrong PIN does to the counters. The MAX_FAILURES-th miss locks the PIN and resets the counter, so a
// fresh set of tries opens once the lock expires.
function afterFailure(wallet, now = Date.now()) {
  const failures = (Number(wallet && wallet.pin_failures) || 0) + 1;
  if (failures >= MAX_FAILURES) {
    return { pin_failures: 0, pin_locked_until: new Date(now + LOCK_SECONDS * 1000).toISOString(), locked: true, attempts_left: 0 };
  }
  return { pin_failures: failures, pin_locked_until: null, locked: false, attempts_left: MAX_FAILURES - failures };
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

module.exports = { PIN_RE, MAX_FAILURES, LOCK_SECONDS, validPin, hashPin, verifyPin, lockedFor, afterFailure, normalizeGate, normalizeGates, weakenedGates };
