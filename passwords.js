'use strict';
// Account passwords: salted scrypt in PHC string form, `$scrypt$ln=15,r=8,p=1$<salt>$<hash>` (unpadded base64).
// Stalwart verifies that same form for mail logins, so dustforge (identity_wallets.password_hash) and the mail
// server hold the same salted hash and neither keeps a readable password.
//
// Older forms still verify, so a caller can upgrade them on the next good sign-in (`upgrade: true`):
//   - a bare 64-hex sha256 (dustforge's local hash before 2026-10-28);
//   - `sha256+$scrypt$…`: that sha256 wrapped in scrypt, written by scripts/migrate-password-hashes.js where no
//     readable password existed to hash properly;
//   - a readable password, as Stalwart stored them before 2026-10-28 (only with { allowPlaintext: true }).
const crypto = require('crypto');

const LN = 15, R = 8, P = 1, KEYLEN = 32, SALT_BYTES = 16;
const MAXMEM = 128 * R * (2 ** 20) + (8 << 20);   // ln up to 20 (scrypt needs 128·N·r bytes)
const WRAP = 'sha256+';

const b64 = (buf) => buf.toString('base64').replace(/=+$/, '');
const unb64 = (s) => Buffer.from(s, 'base64');
const sha256hex = (s) => crypto.createHash('sha256').update(s).digest('hex');
// Hashed-secret schemes Stalwart reads. Anything else in a Stalwart secret is a readable password, even one that
// happens to start with "$" or "{".
const HASH_SCHEME = /^(\$(scrypt|argon2(id|i|d)?|pbkdf2(-sha\d+)?|2[abxy]?|[156]|sha1|md5|app)\$|\{(S?SHA(256|512)?|S?MD5|CRYPT|PLAIN|SMD5)\})/i;

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
  if (ln < 1 || ln > 20 || r < 1 || p < 1 || p > 16) return null;
  const salt = unb64(m[4]), hash = unb64(m[5]);
  if (salt.length < 8 || hash.length < 16) return null;
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

// Checks `password` against a stored form. Returns { ok, upgrade }: ok is true/false, or null when the stored
// form is empty or one this module does not read (the caller then has no verdict from it). upgrade says the
// caller should store hashPassword(password) in its place after a match.
async function verifyPassword(password, stored, { allowPlaintext = false } = {}) {
  if (typeof password !== 'string' || !password || typeof stored !== 'string' || !stored) return { ok: null, upgrade: false };
  if (stored.startsWith('$scrypt$')) {
    const phc = parsePhc(stored);
    if (!phc) return { ok: null, upgrade: false };
    return { ok: await phcMatches(password, phc), upgrade: !isCurrent(stored) };
  }
  if (stored.startsWith(WRAP)) {
    const phc = parsePhc(stored.slice(WRAP.length));
    if (!phc) return { ok: null, upgrade: false };
    return { ok: await phcMatches(sha256hex(password), phc), upgrade: true };
  }
  if (/^[0-9a-f]{64}$/.test(stored)) {
    return { ok: sameBytes(Buffer.from(sha256hex(password)), Buffer.from(stored)), upgrade: true };
  }
  if (HASH_SCHEME.test(stored)) return { ok: null, upgrade: false };   // another scheme
  if (!allowPlaintext) return { ok: null, upgrade: false };
  const a = crypto.createHash('sha256').update(password).digest(), b = crypto.createHash('sha256').update(stored).digest();
  return { ok: crypto.timingSafeEqual(a, b), upgrade: true };
}

// True for a Stalwart secret still kept readable (anything not in a hashed scheme).
function isPlaintextSecret(secret) {
  return typeof secret === 'string' && secret !== '' && !HASH_SCHEME.test(secret);
}

module.exports = { hashPassword, verifyPassword, wrapLegacySha256, isCurrent, isPlaintextSecret, parsePhc };
