'use strict';
// Account passwords: salted scrypt in PHC string form, `$scrypt$ln=15,r=8,p=1$<salt>$<hash>` (unpadded base64).
// Stalwart verifies that same form for mail logins, so dustforge (identity_wallets.password_hash) and the mail
// server hold the same salted hash and neither keeps a readable password.
//
// Older forms still verify, so a caller can upgrade them on the next good sign-in (`upgrade: true`):
//   - a bare 64-hex sha256 (dustforge's local hash before 2026-10-28);
//   - `sha256+$scrypt$…`: that sha256 wrapped in scrypt, written by scripts/migrate-password-hashes.js where no
//     readable password existed to hash properly;
//   - a readable password, as Stalwart stored them before 2026-10-28 (only with { stalwart: true }).
const crypto = require('crypto');

const LN = 15, R = 8, P = 1, KEYLEN = 32, SALT_BYTES = 16;
// Stored parameters above these are refused, not computed: a planted ln=20,p=16 would cost seconds per check.
const MAX_LN = 16, MAX_R = 8, MAX_P = 2;
const MAXMEM = 128 * MAX_R * (2 ** MAX_LN) * MAX_P + (8 << 20);
const WRAP = 'sha256+';

const b64 = (buf) => buf.toString('base64').replace(/=+$/, '');
const unb64 = (s) => Buffer.from(s, 'base64');
const sha256hex = (s) => crypto.createHash('sha256').update(s).digest('hex');
// Hashed-secret schemes Stalwart reads. {PLAIN}/{CLEAR} mark a readable password; $app$<name>$<inner> is an app
// password whose inner part is itself readable or hashed; otpauth:// is a mail TOTP seed, not a password.
const HASH_SCHEME = /^(\$(scrypt|argon2(id|i|d)?|pbkdf2(-sha\d+)?|2[abxy]?|[1567]|y|gy|sha1|sha256|sha512|md5)\$|\{(S?SHA(1|256|512)?|S?MD5|CRYPT|SMD5)\})/i;
const PLAIN_PREFIX = /^\{(PLAIN|CLEAR)\}/i;
const APP = /^\$app\$([^$]*)\$(.*)$/s;
const OTP = /^otpauth:/i;

function scrypt(pw, salt, keylen, ln, r, p) {
  return new Promise((resolve, reject) =>
    crypto.scrypt(pw, salt, keylen, { N: 2 ** ln, r, p, maxmem: MAXMEM }, (e, k) => (e ? reject(e) : resolve(k))));
}

function sameBytes(a, b) {
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

// `$scrypt$ln=15,r=8,p=1$salt$hash` → { ln, r, p, salt, hash }, or null.
function parsePhc(s) {
  const m = /^\$scrypt\$ln=(\d{1,2}),r=(\d{1,2}),p=(\d{1,2})\$([A-Za-z0-9+/]+)\$([A-Za-z0-9+/]+)$/.exec(s);
  if (!m) return null;
  const ln = Number(m[1]), r = Number(m[2]), p = Number(m[3]);
  if (ln < 1 || ln > MAX_LN || r < 1 || r > MAX_R || p < 1 || p > MAX_P) return null;
  const salt = unb64(m[4]), hash = unb64(m[5]);
  if (salt.length < 8 || hash.length < 16 || hash.length > 64) return null;
  return { ln, r, p, salt, hash };
}

async function phcScrypt(pw) {
  const salt = crypto.randomBytes(SALT_BYTES);
  const key = await scrypt(pw, salt, KEYLEN, LN, R, P);
  return `$scrypt$ln=${LN},r=${R},p=${P}$${b64(salt)}$${b64(key)}`;
}

async function phcMatches(pw, phc) {
  const got = await scrypt(pw, phc.salt, phc.hash.length, phc.ln, phc.r, phc.p);
  return sameBytes(got, phc.hash);
}

function sameText(a, b) {
  return crypto.timingSafeEqual(crypto.createHash('sha256').update(a).digest(), crypto.createHash('sha256').update(b).digest());
}

// The stored form for a new or changed password.
async function hashPassword(password) {
  if (typeof password !== 'string' || !password) throw new Error('password required');
  return phcScrypt(password);
}

// A legacy unsalted sha256, wrapped so it is salted and slow until the next sign-in replaces it.
async function wrapLegacySha256(hex) {
  if (!/^[0-9a-f]{64}$/.test(hex)) throw new Error('not a sha256 hex digest');
  return WRAP + await phcScrypt(hex);
}

function isCurrent(stored) {
  const phc = typeof stored === 'string' && parsePhc(stored);
  return Boolean(phc && phc.ln >= LN && phc.r >= R && phc.hash.length >= KEYLEN);
}

// The readable password a Stalwart secret holds, or null when it holds none (hashed, app password, TOTP seed).
function readableSecret(secret) {
  if (typeof secret !== 'string' || !secret) return null;
  if (PLAIN_PREFIX.test(secret)) return secret.replace(PLAIN_PREFIX, '') || null;
  if (HASH_SCHEME.test(secret) || APP.test(secret) || OTP.test(secret)) return null;
  return secret;
}

// Checks `password` against a stored form. Returns { ok, upgrade }: ok is true/false, or null when the stored
// form is empty or one this module does not read (the caller then has no verdict from it). upgrade says the
// caller should store hashPassword(password) in its place after a match.
//   default: a dustforge local verifier (current or weaker scrypt, sha256+ wrapped, bare sha256 hex);
//   { stalwart: true }: a Stalwart account secret (scrypt, or a readable password, even one that looks like hex).
async function verifyPassword(password, stored, { stalwart = false } = {}) {
  if (typeof password !== 'string' || !password || typeof stored !== 'string' || !stored) return { ok: null, upgrade: false };
  if (stored.startsWith('$scrypt$')) {
    const phc = parsePhc(stored);
    if (!phc) return { ok: null, upgrade: false };
    return { ok: await phcMatches(password, phc), upgrade: !isCurrent(stored) };
  }
  if (stalwart) {
    const readable = readableSecret(stored);
    return readable === null ? { ok: null, upgrade: false } : { ok: sameText(password, readable), upgrade: true };
  }
  if (stored.startsWith(WRAP)) {
    const phc = parsePhc(stored.slice(WRAP.length));
    if (!phc) return { ok: null, upgrade: false };
    return { ok: await phcMatches(sha256hex(password), phc), upgrade: true };
  }
  if (/^[0-9a-f]{64}$/.test(stored)) return { ok: sameText(sha256hex(password), stored), upgrade: true };
  return { ok: null, upgrade: false };
}

// True when a Stalwart secret keeps a password readable: a plain secret, or an app password with a readable inner part.
function isPlaintextSecret(secret) {
  if (readableSecret(secret) !== null) return true;
  const app = typeof secret === 'string' && APP.exec(secret);
  return Boolean(app && readableSecret(app[2]) !== null);
}

// The hashed replacement for a Stalwart secret that keeps a password readable, or null to leave it as it is.
async function hashStalwartSecret(secret) {
  const readable = readableSecret(secret);
  if (readable !== null) return hashPassword(readable);
  const app = typeof secret === 'string' && APP.exec(secret);
  if (app && readableSecret(app[2]) !== null) return `$app$${app[1]}$${await hashPassword(readableSecret(app[2]))}`;
  return null;
}

module.exports = { hashPassword, verifyPassword, wrapLegacySha256, isCurrent, isPlaintextSecret, readableSecret, hashStalwartSecret, parsePhc };
