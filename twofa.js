'use strict';
// ── Second factor for the vault (carbon) login.
//
// TOTP (RFC 6238, SHA-1, 6 digits, 30 s) with a ±1-step window and replay
// protection, email codes as the fallback factor, one-time recovery codes, and
// 30-day trusted-device tokens so a phone is not asked every day.
//
// Pure functions + a `gate()` that takes the db handle; no requires beyond crypto.

const crypto = require('crypto');

const STEP_SECONDS = 30;
const DIGITS = 6;
const WINDOW = 1;                         // accept the previous and next step too
const RECOVERY_CODES = 8;
const DEVICE_TTL_DAYS = 30;
const EMAIL_CODE_TTL_MIN = 10;
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

// ── base32 (RFC 4648, no padding on output; padding tolerated on input) ──────
function base32Encode(buf) {
  let bits = 0, value = 0, out = '';
  for (const byte of buf) {
    value = (value << 8) | byte; bits += 8;
    while (bits >= 5) { out += B32[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}
function base32Decode(str) {
  const clean = String(str || '').toUpperCase().replace(/[=\s-]/g, '');
  let bits = 0, value = 0; const out = [];
  for (const ch of clean) {
    const idx = B32.indexOf(ch);
    if (idx < 0) throw new Error('invalid base32');
    value = (value << 5) | idx; bits += 5;
    if (bits >= 8) { out.push((value >>> (bits - 8)) & 255); bits -= 8; }
  }
  return Buffer.from(out);
}

// ── TOTP ─────────────────────────────────────────────────────────────────────
function generateSecret(bytes = 20) { return base32Encode(crypto.randomBytes(bytes)); }

function hotp(secretB32, counter, digits = DIGITS) {
  const key = base32Decode(secretB32);
  const msg = Buffer.alloc(8);
  msg.writeUInt32BE(Math.floor(counter / 0x100000000), 0);
  msg.writeUInt32BE(counter >>> 0, 4);
  const h = crypto.createHmac('sha1', key).update(msg).digest();
  const off = h[h.length - 1] & 0x0f;
  const bin = ((h[off] & 0x7f) << 24) | ((h[off + 1] & 0xff) << 16) | ((h[off + 2] & 0xff) << 8) | (h[off + 3] & 0xff);
  return String(bin % 10 ** digits).padStart(digits, '0');
}
function totpStep(nowMs = Date.now()) { return Math.floor(nowMs / 1000 / STEP_SECONDS); }
function totp(secretB32, nowMs = Date.now()) { return hotp(secretB32, totpStep(nowMs)); }

// Returns { ok, step } — `lastStep` is the last step already accepted for this
// account; a code for that step or an earlier one is a replay and is refused.
function verifyTotp(secretB32, code, { nowMs = Date.now(), lastStep = 0, window = WINDOW } = {}) {
  const c = String(code || '').replace(/\s+/g, '');
  if (!/^\d{6}$/.test(c)) return { ok: false, error: 'code must be 6 digits' };
  const now = totpStep(nowMs);
  for (let d = -window; d <= window; d++) {
    const step = now + d;
    if (step <= (lastStep || 0)) continue;
    const expected = hotp(secretB32, step);
    if (expected.length === c.length && crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(c))) return { ok: true, step };
  }
  return { ok: false, error: 'invalid or already used code' };
}

function otpauthUri({ issuer = 'DemiPass', account, secret }) {
  const label = encodeURIComponent(`${issuer}:${account}`);
  return `otpauth://totp/${label}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=${DIGITS}&period=${STEP_SECONDS}`;
}

// ── Recovery codes ───────────────────────────────────────────────────────────
function hashCode(c) { return crypto.createHash('sha256').update(String(c).toLowerCase().replace(/[\s-]/g, '')).digest('hex'); }
function generateRecoveryCodes(n = RECOVERY_CODES) {
  const codes = [];
  for (let i = 0; i < n; i++) {
    const raw = crypto.randomBytes(5).toString('hex');            // 10 hex chars
    codes.push(raw.slice(0, 5) + '-' + raw.slice(5));
  }
  return { codes, hashes: codes.map(hashCode) };
}
// Returns the remaining hashes with the used one removed, or null if no match.
function consumeRecoveryCode(hashes, code) {
  const h = hashCode(code);
  const idx = (hashes || []).indexOf(h);
  if (idx < 0) return null;
  return hashes.filter((_, i) => i !== idx);
}

// ── Email codes (identity_2fa_codes) ─────────────────────────────────────────
function issueEmailCode(db, did) {
  const code = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
  const expiresAt = new Date(Date.now() + EMAIL_CODE_TTL_MIN * 60000).toISOString();
  db.prepare('INSERT INTO identity_2fa_codes (did, code, expires_at) VALUES (?, ?, ?)').run(did, code, expiresAt);
  return { code, expiresAt };
}
function consumeEmailCode(db, did, code) {
  const c = String(code || '').replace(/\s+/g, '');
  if (!/^\d{6}$/.test(c)) return false;
  const row = db.prepare(`SELECT id FROM identity_2fa_codes WHERE did = ? AND code = ? AND used = 0 AND expires_at > ? ORDER BY id DESC LIMIT 1`)
    .get(did, c, new Date().toISOString());
  if (!row) return false;
  db.prepare('UPDATE identity_2fa_codes SET used = 1 WHERE id = ?').run(row.id);
  return true;
}

// ── Trusted devices ──────────────────────────────────────────────────────────
function hashToken(t) { return crypto.createHash('sha256').update(String(t)).digest('hex'); }
function issueDeviceToken(db, did, label = '') {
  const raw = 'dpdev_' + crypto.randomBytes(24).toString('base64url');
  const expiresAt = new Date(Date.now() + DEVICE_TTL_DAYS * 86400000).toISOString();
  db.prepare('INSERT INTO identity_trusted_devices (did, token_hash, label, expires_at) VALUES (?, ?, ?, ?)')
    .run(did, hashToken(raw), String(label || '').slice(0, 120), expiresAt);
  return { token: raw, expires_at: expiresAt };
}
function checkDeviceToken(db, did, raw) {
  if (!raw) return false;
  const row = db.prepare('SELECT id, expires_at, revoked FROM identity_trusted_devices WHERE did = ? AND token_hash = ?').get(did, hashToken(raw));
  if (!row || row.revoked) return false;
  if (new Date(row.expires_at).getTime() < Date.now()) return false;
  db.prepare("UPDATE identity_trusted_devices SET last_used_at = datetime('now') WHERE id = ?").run(row.id);
  return true;
}
function listDevices(db, did) {
  return db.prepare(`SELECT id, label, created_at, expires_at, last_used_at FROM identity_trusted_devices
                     WHERE did = ? AND revoked = 0 AND expires_at > ? ORDER BY id DESC`).all(did, new Date().toISOString());
}
function revokeDevice(db, did, id) {
  return db.prepare('UPDATE identity_trusted_devices SET revoked = 1 WHERE did = ? AND id = ?').run(did, id).changes > 0;
}
function revokeAllDevices(db, did) {
  return db.prepare('UPDATE identity_trusted_devices SET revoked = 1 WHERE did = ?').run(did).changes;
}

// ── Login gate ───────────────────────────────────────────────────────────────
// `wallet` is the identity_wallets row (needs twofa_enabled, totp_secret, totp_last_step,
// recovery_codes, did); `decryptSecret` turns the stored secret into base32; `body` is the
// login request body. Returns { ok, method } or { ok: false, required: true, methods, error }.
function methodsFor(wallet) {
  const m = [];
  if (wallet.totp_secret) m.push('totp');
  m.push('email');
  if (wallet.recovery_codes && wallet.recovery_codes !== '[]') m.push('recovery');
  return m;
}
function gate(db, wallet, body, { decryptSecret, nowMs = Date.now() } = {}) {
  if (!wallet.twofa_enabled) return { ok: true, method: 'none' };
  const b = body || {};
  if (b.device_token && checkDeviceToken(db, wallet.did, b.device_token)) return { ok: true, method: 'device' };
  if (b.otp) {
    if (!wallet.totp_secret) return { ok: false, required: true, methods: methodsFor(wallet), error: 'authenticator not set up' };
    const secret = decryptSecret(wallet.totp_secret);
    const v = verifyTotp(secret, b.otp, { nowMs, lastStep: wallet.totp_last_step || 0 });
    if (!v.ok) return { ok: false, required: true, methods: methodsFor(wallet), error: v.error };
    db.prepare('UPDATE identity_wallets SET totp_last_step = ? WHERE did = ?').run(v.step, wallet.did);
    return { ok: true, method: 'totp' };
  }
  if (b.email_code) {
    if (!consumeEmailCode(db, wallet.did, b.email_code)) return { ok: false, required: true, methods: methodsFor(wallet), error: 'invalid or expired email code' };
    return { ok: true, method: 'email' };
  }
  if (b.recovery_code) {
    let hashes = [];
    try { hashes = JSON.parse(wallet.recovery_codes || '[]'); } catch (_) { hashes = []; }
    const left = consumeRecoveryCode(hashes, b.recovery_code);
    if (!left) return { ok: false, required: true, methods: methodsFor(wallet), error: 'invalid recovery code' };
    db.prepare('UPDATE identity_wallets SET recovery_codes = ? WHERE did = ?').run(JSON.stringify(left), wallet.did);
    return { ok: true, method: 'recovery', recovery_codes_left: left.length };
  }
  return { ok: false, required: true, methods: methodsFor(wallet), error: 'second factor required' };
}

function initSchema(db) {
  for (const col of [
    'twofa_enabled INTEGER DEFAULT 0', "totp_secret TEXT DEFAULT ''", 'totp_confirmed_at TEXT', 'totp_last_step INTEGER DEFAULT 0',
    "recovery_codes TEXT DEFAULT '[]'", 'twofa_enabled_at TEXT',
  ]) { try { db.exec(`ALTER TABLE identity_wallets ADD COLUMN ${col}`); } catch (_) {} }
  db.exec(`CREATE TABLE IF NOT EXISTS identity_trusted_devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    did TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    label TEXT DEFAULT '',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    expires_at TEXT NOT NULL,
    last_used_at TEXT,
    revoked INTEGER DEFAULT 0
  )`);
  db.exec('CREATE INDEX IF NOT EXISTS idx_itd_did ON identity_trusted_devices(did)');
}

module.exports = {
  initSchema, base32Encode, base32Decode, generateSecret, hotp, totp, totpStep, verifyTotp, otpauthUri,
  generateRecoveryCodes, consumeRecoveryCode, hashCode, issueEmailCode, consumeEmailCode,
  issueDeviceToken, checkDeviceToken, listDevices, revokeDevice, revokeAllDevices, methodsFor, gate,
  STEP_SECONDS, DIGITS, WINDOW, RECOVERY_CODES, DEVICE_TTL_DAYS, EMAIL_CODE_TTL_MIN,
};
