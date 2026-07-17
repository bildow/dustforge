/**
 * Civitasvox Identity Layer — DID:key + Token System
 *
 * Each silicon gets an Ed25519 keypair. The public key IS the identity (DID:key format).
 * Private keys are encrypted at rest. Tokens are JWTs signed with the private key.
 * Anyone can verify a token using only the DID (which contains the public key).
 *
 * SECURITY: Private keys never in git, never in logs, never in API responses.
 */

const crypto = require('crypto');

// Master encryption key from environment — NEVER hardcode
const MASTER_KEY = process.env.IDENTITY_MASTER_KEY;
if (!MASTER_KEY) {
  console.error('[FATAL] IDENTITY_MASTER_KEY environment variable is required. Refusing to start with random key — encrypted data would be unrecoverable after restart.');
  process.exit(1);
}
const ENCRYPTION_ALGO = 'aes-256-gcm';

// ── Key Generation ──

function generateKeypair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'der' },
    privateKeyEncoding: { type: 'pkcs8', format: 'der' },
  });
  return { publicKey, privateKey };
}

// Multibase-aware DID:key encoding. Default output is z-base58btc — the
// form every stock did:key resolver accepts. u-base64url is still accepted
// on input for compatibility with pre-2026-07-17 DIDs. Reencode any DID to
// a target form losslessly via reencodeDid().
function publicKeyToDID(publicKeyDer, form = 'z') {
  // DID:key = multicodec ed25519-pub (0xed01) + raw 32-byte pubkey
  const rawPubKey = publicKeyDer.slice(-32);
  const multicodec = Buffer.concat([Buffer.from([0xed, 0x01]), rawPubKey]);
  if (form === 'u') return `did:key:u${multicodec.toString('base64url')}`;
  if (form === 'z') return `did:key:z${base58Encode(multicodec)}`;
  throw new Error(`unknown DID multibase form: ${form}`);
}

function didToPublicKey(did) {
  if (!did.startsWith('did:key:')) throw new Error('invalid DID:key format');
  const prefix = did[8]; // multibase char after 'did:key:'
  const encoded = did.slice(9);
  let decoded;
  if (prefix === 'u') decoded = Buffer.from(encoded, 'base64url');
  else if (prefix === 'z') decoded = base58Decode(encoded);
  else throw new Error(`unsupported DID:key multibase prefix: ${prefix}`);
  if (decoded.length < 34 || decoded[0] !== 0xed || decoded[1] !== 0x01) throw new Error('not an ed25519 DID:key');
  const rawPubKey = decoded.slice(2);
  const spkiPrefix = Buffer.from('302a300506032b6570032100', 'hex');
  return Buffer.concat([spkiPrefix, rawPubKey]);
}

// Reencode a DID:key string to a target multibase form ('z' or 'u') without
// changing the underlying key. Use before publishing a DID to any surface a
// third-party resolver may consume (ARD/agent-cards/A2A/ai-catalog). The
// resulting DID resolves to the same key as the input.
function reencodeDid(did, form = 'z') {
  const pkSpki = didToPublicKey(did);
  return publicKeyToDID(pkSpki, form);
}

// ── Encryption (private keys at rest) ──

function encryptPrivateKey(privateKeyDer) {
  const key = Buffer.from(MASTER_KEY, 'hex').slice(0, 32);
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(ENCRYPTION_ALGO, key, iv);
  const encrypted = Buffer.concat([cipher.update(privateKeyDer), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return Buffer.concat([iv, authTag, encrypted]).toString('base64');
}

function decryptPrivateKey(encryptedBase64) {
  const key = Buffer.from(MASTER_KEY, 'hex').slice(0, 32);
  const data = Buffer.from(encryptedBase64, 'base64');
  const iv = data.slice(0, 16);
  const authTag = data.slice(16, 32);
  const encrypted = data.slice(32);
  const decipher = crypto.createDecipheriv(ENCRYPTION_ALGO, key, iv);
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(encrypted), decipher.final()]);
}

// ── Token System (custom JWT with Ed25519 — native crypto, no library EdDSA dependency) ──

// ── Scope registry (single source of truth) ──
// Ranked hierarchy: read < write < transact < admin < critical.
// 'full' is a legacy alias for admin — honored on existing tokens, still issuable.
// 'critical' is minted ONLY by the 5-minute re-auth gate, never by normal flows.
const SCOPE_RANK = { read: 0, write: 1, transact: 2, admin: 3, full: 3, critical: 4 };
const ISSUABLE_SCOPES = ['read', 'write', 'transact', 'admin', 'full'];
// Hard TTL ceiling per scope, in seconds. Issuance clamps to these — callers
// may ask for less, never more. (Pre-existing tokens are grandfathered; the
// revocation registry covers them.)
const SCOPE_MAX_TTL = {
  read: 90 * 86400,
  write: 90 * 86400,
  transact: 30 * 86400,
  admin: 30 * 86400,
  full: 30 * 86400,
  critical: 300,
};

function isKnownScope(scope) {
  return Object.prototype.hasOwnProperty.call(SCOPE_RANK, scope);
}

function scopeAtLeast(scope, min) {
  const r = SCOPE_RANK[scope];
  const m = SCOPE_RANK[min];
  return r !== undefined && m !== undefined && r >= m;
}

function parseExpiry(expiresIn) {
  const match = String(expiresIn).match(/^(\d+)(s|m|h|d)$/);
  if (!match) return 86400; // default 24h
  const num = parseInt(match[1]);
  const unit = match[2];
  return num * ({ s: 1, m: 60, h: 3600, d: 86400 }[unit] || 3600);
}

function base64url(buf) {
  return Buffer.from(buf).toString('base64url');
}

// Host app registers a persistence hook so every minted token lands in the
// issued_tokens registry (the revocation surface). identity.js stays db-free.
let tokenRecorder = null;
function setTokenRecorder(fn) { tokenRecorder = fn; }

function createToken(privateKeyDer, did, options = {}) {
  const {
    scope = 'read',
    expiresIn = '24h',
    metadata = {},
  } = options;

  // Scope must be canonical — unknown strings used to mint silently and rank
  // as nothing at enforcement time. Routes pre-validate; this is the backstop.
  if (!isKnownScope(scope)) {
    throw new Error(`unknown scope '${scope}' — valid scopes: ${ISSUABLE_SCOPES.join(', ')}`);
  }

  const privateKeyObj = crypto.createPrivateKey({
    key: privateKeyDer,
    format: 'der',
    type: 'pkcs8',
  });

  const header = { alg: 'EdDSA', typ: 'JWT' };
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    sub: did,
    scope,
    iss: 'civitasvox',
    iat: now,
    // TTL is clamped to the per-scope ceiling — elevated scopes stay short-lived.
    exp: now + Math.min(parseExpiry(expiresIn), SCOPE_MAX_TTL[scope] || 86400),
    jti: crypto.randomBytes(8).toString('hex'),
    ...metadata,
  };
  if (tokenRecorder) { try { tokenRecorder(payload); } catch (_) {} }

  const headerB64 = base64url(JSON.stringify(header));
  const payloadB64 = base64url(JSON.stringify(payload));
  const signingInput = `${headerB64}.${payloadB64}`;
  const signature = crypto.sign(null, Buffer.from(signingInput), privateKeyObj);

  return `${signingInput}.${base64url(signature)}`;
}

function verifyToken(token, did) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return { valid: false, error: 'malformed token' };

    const publicKeyDer = didToPublicKey(did);
    const publicKeyObj = crypto.createPublicKey({
      key: publicKeyDer,
      format: 'der',
      type: 'spki',
    });

    const signingInput = `${parts[0]}.${parts[1]}`;
    const signature = Buffer.from(parts[2], 'base64url');
    const valid = crypto.verify(null, Buffer.from(signingInput), publicKeyObj, signature);
    if (!valid) return { valid: false, error: 'signature invalid' };

    const decoded = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
    if (decoded.sub !== did) return { valid: false, error: 'DID mismatch' };
    if (decoded.exp && decoded.exp < Math.floor(Date.now() / 1000)) return { valid: false, error: 'token expired' };
    if (decoded.iss !== 'civitasvox') return { valid: false, error: 'wrong issuer' };

    return { valid: true, decoded };
  } catch (err) {
    return { valid: false, error: err.message };
  }
}

function verifyTokenStandalone(token) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return { valid: false, error: 'malformed token' };
    const decoded = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
    if (!decoded?.sub?.startsWith('did:key:')) return { valid: false, error: 'no DID in token' };
    return verifyToken(token, decoded.sub);
  } catch (err) {
    return { valid: false, error: err.message };
  }
}

// ── Base58 encoding (Bitcoin-style, for DID:key) ──

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function base58Encode(buffer) {
  if (buffer.length === 0) return '';
  const digits = [0];
  for (const byte of buffer) {
    let carry = byte;
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j] << 8;
      digits[j] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }
  let result = '';
  for (const byte of buffer) {
    if (byte !== 0) break;
    result += '1';
  }
  for (let i = digits.length - 1; i >= 0; i--) {
    result += BASE58_ALPHABET[digits[i]];
  }
  return result;
}

function base58Decode(str) {
  if (str.length === 0) return Buffer.alloc(0);
  const bytes = [0];
  for (const char of str) {
    const val = BASE58_ALPHABET.indexOf(char);
    if (val < 0) throw new Error(`invalid base58 character: ${char}`);
    let carry = val;
    for (let j = 0; j < bytes.length; j++) {
      carry += bytes[j] * 58;
      bytes[j] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }
  for (const char of str) {
    if (char !== '1') break;
    bytes.push(0);
  }
  return Buffer.from(bytes.reverse());
}

// ── Identity Creation (full flow) ──

function createIdentity() {
  const { publicKey, privateKey } = generateKeypair();
  const did = publicKeyToDID(publicKey);
  const encryptedPrivateKey = encryptPrivateKey(privateKey);

  return {
    did,                    // The Silicon SSN — public, shareable
    encrypted_private_key:  encryptedPrivateKey, // Store in DB, never expose
    // DO NOT return raw private key
  };
}

function createTokenForIdentity(encryptedPrivateKey, did, options) {
  const privateKeyDer = decryptPrivateKey(encryptedPrivateKey);
  return createToken(privateKeyDer, did, options);
}

module.exports = {
  createIdentity,
  createTokenForIdentity,
  setTokenRecorder,
  verifyToken,
  verifyTokenStandalone,
  publicKeyToDID,
  didToPublicKey,
  reencodeDid,
  encryptPrivateKey,
  decryptPrivateKey,
  // Scope registry — the ONLY place scope names/ranks are defined
  SCOPE_RANK,
  ISSUABLE_SCOPES,
  SCOPE_MAX_TTL,
  isKnownScope,
  scopeAtLeast,
  // MASTER_KEY removed from exports — never expose the encryption key
};
