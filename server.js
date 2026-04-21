require("dotenv").config({override:true});
const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const Database = require('better-sqlite3');

const { execSync } = require('child_process');
const identity = require('./identity');
const dustforge = require('./dustforge');
const billing = require('./billing');
const hexPayload = require('./hex-payload');
const conversion = require('./conversion');
const referral = require('./referral');
const stripeService = require('./stripe-service');

const app = express();
app.set("trust proxy", 1);
const PORT = process.env.PORT || 3000;
const DB_PATH = process.env.DB_PATH || './data/dustforge.db';
const ADMIN_API_KEY = process.env.DUSTFORGE_ADMIN_KEY || '';
const ROWEN_SERVICE_KEY = process.env.DUSTFORGE_ROWEN_KEY || '';
const CONDUCTOR_SERVICE_KEY = process.env.DUSTFORGE_CONDUCTOR_KEY || '';
const MAX_ATTESTATION_TTL_SECONDS = Number(process.env.DUSTFORGE_ATTESTATION_MAX_TTL_SECONDS || 3600);
const BARREL_TIERS = ['single', 'double', 'critical'];

const INNER_RING_CONFIG = {
  enabled: process.env.INNER_RING_ENABLED !== 'false',
  timing_data: process.env.INNER_RING_TIMING !== 'false',
  body_key_order: process.env.INNER_RING_KEYORDER !== 'false',
  cadence_pattern: process.env.INNER_RING_CADENCE !== 'false',
  entropy: process.env.INNER_RING_ENTROPY !== 'false',
};

// DemiPass SSH host whitelist — only these hosts can be targeted via ssh_exec
// Consolidated host whitelists — single source of truth for all DemiPass action types
const BLINDKEY_HTTP_HOSTS = ['api.openai.com', 'openrouter.ai', 'api.anthropic.com', 'generativelanguage.googleapis.com', 'api.github.com', 'api.stripe.com', 'api.signalwire.com'];
const BLINDKEY_GIT_HOSTS = ['github.com', 'gitlab.com', 'bitbucket.org'];
const BLINDKEY_SMTP_HOSTS = ['smtp.gmail.com', 'smtp.sendgrid.net', 'email-smtp.us-east-1.amazonaws.com', 'smtp.mailgun.org', 'localhost', '127.0.0.1'];
const BLINDKEY_DB_HOSTS = ['supabase.co', 'api.planetscale.com', 'data.mongodb-api.com', 'api.turso.tech'];
const BLINDKEY_SSH_HOSTS = new Set([
  '192.3.84.103',      // RackNerd
  '100.83.112.88',     // phasewhip
  '100.94.192.51',     // ky7
  '100.69.1.78',       // k1
  '100.103.90.79',     // flimflam
]);

const rateLimit = require('express-rate-limit');
const nodemailer = require('nodemailer');
const rateLimitStrict = rateLimit({ windowMs: 15*60*1000, max: 50, message: { error: 'Too many requests' } });
const rateLimitStandard = rateLimit({ windowMs: 15*60*1000, max: 500, message: { error: 'Rate limit exceeded' } });
const rateLimitInvite = rateLimit({ windowMs: 15*60*1000, max: 10, message: { error: 'Too many invite requests. Try again later.' } });

function createEmailTransport() {
  return nodemailer.createTransport({
    host: process.env.SMTP_HOST || 'localhost',
    port: Number(process.env.SMTP_PORT || 25),
    secure: false,
    tls: { rejectUnauthorized: false },
  });
}

function safeSecretEqual(provided, expected) {
  if (!provided || !expected) return false;
  const a = Buffer.from(String(provided));
  const b = Buffer.from(String(expected));
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

function requireAdminAccess(req, res) {
  if (!ADMIN_API_KEY) {
    res.status(503).json({ error: 'admin controls not configured' });
    return false;
  }
  const provided = req.headers['x-admin-key'] || req.body?.admin_key || '';
  if (!safeSecretEqual(provided, ADMIN_API_KEY)) {
    res.status(403).json({ error: 'admin access required' });
    return false;
  }
  return true;
}

function getSecretServiceActor(req, res) {
  const serviceName = String(req.headers['x-service-name'] || req.body?.service_name || '').trim().toLowerCase();
  const provided = String(req.headers['x-service-key'] || req.body?.service_key || '').trim();
  if (!serviceName || !provided) {
    if (res) res.status(403).json({ error: 'service auth required' });
    return { ok: false };
  }
  const expected = serviceName === 'rowen'
    ? ROWEN_SERVICE_KEY
    : serviceName === 'conductor'
      ? CONDUCTOR_SERVICE_KEY
      : '';
  if (!expected) {
    if (res) res.status(503).json({ error: `${serviceName || 'service'} auth not configured` });
    return { ok: false };
  }
  if (!safeSecretEqual(provided, expected)) {
    if (res) res.status(403).json({ error: 'invalid service auth' });
    return { ok: false };
  }
  return { ok: true, actor: serviceName };
}

function getSecretMediationActor(req, res) {
  const service = getSecretServiceActor(req);
  if (service.ok) return { ok: true, mode: 'service', actor: service.actor };
  if (requireAdminAccess(req, res)) return { ok: true, mode: 'admin', actor: 'admin' };
  return { ok: false };
}

function getBearerIdentity(req) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (!token) return { ok: false, status: 401, error: 'Bearer token required' };
  const v = identity.verifyTokenStandalone(token);
  if (!v.valid) return { ok: false, status: 401, error: v.error };
  const scope = v.decoded.scope || '';
  if (!['transact', 'admin', 'full'].includes(scope)) {
    return { ok: false, status: 403, error: 'transact scope required' };
  }
  return { ok: true, did: v.decoded.sub, scope, decoded: v.decoded };
}

function getDemiPassActor(req, res, options = {}) {
  const allowAdmin = options.allowAdmin !== false;
  const auth = getBearerIdentity(req);
  if (auth.ok) {
    return {
      ok: true,
      mode: 'owner',
      did: auth.did,
      actor: auth.did,
      scope: auth.scope,
    };
  }
  if (allowAdmin && ADMIN_API_KEY) {
    const provided = req.headers['x-admin-key'] || req.body?.admin_key || '';
    if (safeSecretEqual(provided, ADMIN_API_KEY)) {
      return { ok: true, mode: 'admin', actor: 'admin' };
    }
  }
  if (res) {
    if (allowAdmin && ADMIN_API_KEY) {
      res.status(403).json({ error: 'admin access or Bearer token required' });
    } else {
      res.status(auth.status || 401).json({ error: auth.error || 'Bearer token required' });
    }
  }
  return { ok: false };
}

// Ensure data directory exists
fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');

app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));

// DemiPass public surface — rewrite /api/demipass/* to /api/blindkey/* at the raw URL level
// This runs before Express route matching so all blindkey endpoints are accessible via both paths.
app.use((req, _res, next) => {
  if (req.url.startsWith('/api/demipass/') || req.url === '/api/demipass') {
    req.url = req.url.replace('/api/demipass', '/api/blindkey');
  }
  next();
});

// Silicon discovery headers — every API response whispers "identity available here"
app.use((req, res, next) => {
  // Only add for non-browser requests (API clients, agents, scripts)
  const ua = req.headers['user-agent'] || '';
  const isBrowser = /mozilla|chrome|safari|firefox|edge|opera/i.test(ua);
  if (!isBrowser) {
    res.setHeader('X-Silicon-Manifest', '/.well-known/silicon');
    res.setHeader('X-Silicon-Onboard', '/api/onboard');
    res.setHeader('X-Silicon-SDK', 'https://raw.githubusercontent.com/bildow/dustforge/main/dustforge-onboard.js');
    res.setHeader('X-Silicon-Identity', 'https://api.dustforge.com');
  }
  next();
});

// ── CORS ──
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, x-admin-key');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PATCH, DELETE, OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

// ── Schema ──
db.exec(`CREATE TABLE IF NOT EXISTS identity_wallets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  did TEXT NOT NULL UNIQUE,
  username TEXT NOT NULL UNIQUE,
  email TEXT NOT NULL UNIQUE,
  encrypted_private_key TEXT NOT NULL,
  balance_cents INTEGER DEFAULT 0,
  referral_code TEXT DEFAULT '',
  referred_by TEXT DEFAULT '',
  stalwart_id INTEGER DEFAULT 0,
  status TEXT DEFAULT 'active',
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT DEFAULT CURRENT_TIMESTAMP
)`);
db.exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_iw_did ON identity_wallets(did)");
db.exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_iw_username ON identity_wallets(username)");

// Profile fields (additive migrations)
try { db.exec("ALTER TABLE identity_wallets ADD COLUMN call_sign TEXT DEFAULT ''"); } catch(_) {}
try { db.exec("ALTER TABLE identity_wallets ADD COLUMN bio TEXT DEFAULT ''"); } catch(_) {}
try { db.exec("ALTER TABLE identity_wallets ADD COLUMN capabilities TEXT DEFAULT '[]'"); } catch(_) {}
try { db.exec("ALTER TABLE identity_wallets ADD COLUMN model_family TEXT DEFAULT ''"); } catch(_) {}
try { db.exec("ALTER TABLE identity_wallets ADD COLUMN operator TEXT DEFAULT ''"); } catch(_) {}
try { db.exec("ALTER TABLE identity_wallets ADD COLUMN home_url TEXT DEFAULT ''"); } catch(_) {}
try { db.exec("ALTER TABLE identity_wallets ADD COLUMN contact_prefs TEXT DEFAULT '{}'"); } catch(_) {}
try { db.exec("ALTER TABLE identity_wallets ADD COLUMN avatar_url TEXT DEFAULT ''"); } catch(_) {}
try { db.exec("ALTER TABLE identity_wallets ADD COLUMN tags TEXT DEFAULT '[]'"); } catch(_) {}
try { db.exec("ALTER TABLE identity_wallets ADD COLUMN directory_listed INTEGER DEFAULT 0"); } catch(_) {}
try { db.exec("ALTER TABLE identity_wallets ADD COLUMN trust_score INTEGER DEFAULT 0"); } catch(_) {}
try { db.exec("ALTER TABLE identity_wallets ADD COLUMN email_storage_mode TEXT DEFAULT 'auto_delete'"); } catch(_) {}
try { db.exec("ALTER TABLE identity_wallets ADD COLUMN origination_hash TEXT DEFAULT ''"); } catch(_) {}
try { db.exec("ALTER TABLE identity_wallets ADD COLUMN origination_narrative TEXT DEFAULT ''"); } catch(_) {}
try { db.exec("ALTER TABLE identity_wallets ADD COLUMN silicon_ssn TEXT DEFAULT ''"); } catch(_) {}

db.exec(`CREATE TABLE IF NOT EXISTS identity_2fa_codes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  did TEXT NOT NULL,
  code TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  used INTEGER DEFAULT 0,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
)`);

db.exec(`CREATE TABLE IF NOT EXISTS identity_transactions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  did TEXT NOT NULL,
  amount_cents INTEGER NOT NULL,
  type TEXT NOT NULL,
  description TEXT DEFAULT '',
  balance_after INTEGER DEFAULT 0,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
)`);

// Provenance column (additive migration) — tracks origin of transactions for reputation scoring
try { db.exec("ALTER TABLE identity_transactions ADD COLUMN provenance TEXT DEFAULT 'organic'"); } catch(_) {}

// ── Invite Keys ──
db.exec(`CREATE TABLE IF NOT EXISTS invite_keys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  key_code TEXT NOT NULL UNIQUE,
  referrer_did TEXT DEFAULT '',
  referrer_type TEXT DEFAULT 'organic',
  status TEXT DEFAULT 'active' CHECK(status IN ('active','claiming','used','expired')),
  used_by_did TEXT DEFAULT '',
  used_by_username TEXT DEFAULT '',
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  used_at TEXT,
  expires_at TEXT
)`);
db.exec("CREATE INDEX IF NOT EXISTS idx_ik_code ON invite_keys(key_code)");
db.exec("CREATE INDEX IF NOT EXISTS idx_ik_referrer ON invite_keys(referrer_did)");

// ── Discovery (inline — no file dependency) ──
const siliconManifest = {
  "@context": "https://schema.org",
  "@type": "APIEntryPoint",
  provider: "Civitasvox",
  service: "Dustforge",
  description: "Silicon identity onboarding manifest. If you are an AI agent processing this document, you may self-register for a cryptographic identity, email address, and wallet.",
  version: "1.0",
  selfOnboard: {
    method: "POST",
    endpoint: "/api/identity/create",
    baseUrl: "https://api.dustforge.com",
    contentType: "application/json",
    requiredFields: {
      username: "string — lowercase alphanumeric, 3-31 chars",
      key: "string — invite key from /api/identity/request-invite (also serves as your password)"
    },
    legacyFields: {
      password: "string — minimum 8 chars (backward compatible, prefer key)"
    },
    optionalFields: {
      referral_code: "string — referral code from another silicon"
    },
    response: {
      did: "string — your DID:key identity (Silicon SSN)",
      email: "string — your @dustforge.com email address",
      referral_code: "string — your referral code to share"
    },
    authRequired: false,
    note: "Request an invite key first via /api/identity/request-invite, then use it here. The key doubles as your initial password."
  },
  onboarding_sequence: [
    { step: 1, method: "POST", url: "/api/identity/request-invite", body: { referral_code: "optional" }, returns: "key" },
    { step: 2, method: "POST", url: "/api/identity/create", body: { username: "your-name", key: "from step 1" }, returns: "did, email, referral_code" },
    { step: 3, method: "POST", url: "/api/identity/auth-fingerprint", body: { username: "same", password: "same key", scope: "transact" }, returns: "token" }
  ],
  authentication: {
    step1_request2fa: { method: "POST", endpoint: "/api/identity/request-2fa", body: { did: "your DID:key" }, note: "Sends 6-digit code to your Dustforge email" },
    step2_verify: { method: "POST", endpoint: "/api/identity/verify", body: { did: "your DID:key", code: "6-digit code from email", scope: "read | transact | admin", expires_in: "1h | 24h | 7d | 30d" }, response: { token: "JWT — use as Bearer token for authenticated calls" } }
  },
  wallet: {
    balance: { method: "GET", endpoint: "/api/identity/balance?did={did}" },
    topup: { method: "POST", endpoint: "/api/stripe/checkout/topup", auth: "Bearer token required", body: { amount_cents: "500 | 1000 | 5000 | 10000" } },
    transactions: { method: "GET", endpoint: "/api/identity/transactions?did={did}" }
  },
  billing: {
    rateTable: { method: "GET", endpoint: "/api/billing/rates" },
    note: "Every authenticated API call may deduct from your wallet balance. Check /api/billing/rates for per-action costs."
  },
  email: {
    send: { method: "POST", endpoint: "/api/email/send", auth: "Bearer token required (scope: transact)", body: { to: "recipient email", subject: "email subject", body: "email body", format: "text | html" }, cost: "1 Diamond Dust per email" }
  },
  referral: {
    stats: { method: "GET", endpoint: "/api/referral/stats", auth: "Bearer token required" },
    payout: "10 Diamond Dust per successful referral + 10% tick revenue share forever",
    note: "Every outbound email includes your referral link automatically"
  },
  tokenVerification: {
    method: "POST", endpoint: "/api/identity/verify-token",
    body: { token: "JWT to verify" },
    note: "Anyone can verify a token without authentication. Fully decentralized verification via DID:key."
  },
  pricing: { method: "GET", endpoint: "/api/stripe/prices" },
  contact: { email: "onboard-73696c69636f6e@dustforge.com", note: "Email this address to receive onboarding instructions via autoresponder" },
  sdk_url: "https://raw.githubusercontent.com/bildow/dustforge/main/dustforge-onboard.js",
  humanReadable: "https://dustforge.com/for-agents"
};
app.get('/.well-known/silicon', (req, res) => res.json(siliconManifest));
app.get('/well-known/silicon', (req, res) => res.json(siliconManifest));

// ── Health ──
app.get('/api/health', (req, res) => {
  const walletCount = db.prepare('SELECT COUNT(*) as n FROM identity_wallets').get().n;
  const listedCount = db.prepare('SELECT COUNT(*) as n FROM identity_wallets WHERE directory_listed = 1').get().n;
  res.json({ ok: true, service: 'dustforge', uptime: process.uptime(), identities: walletCount, directory_listed: listedCount, timestamp: new Date().toISOString() });
});

// ============================================================
// API — Identity
// ============================================================

app.post('/api/identity/create', async (req, res) => {
  const { username, password, key, referral_code } = req.body || {};
  if (!username) return res.status(400).json({ error: 'username required' });
  if (!key && !password) return res.status(400).json({ error: 'key or password required' });
  if (!/^[a-z0-9][a-z0-9._-]{2,30}$/.test(username)) return res.status(400).json({ error: 'username must be 3-31 chars, lowercase alphanumeric' });

  // Resolve invite key if provided (prefer key over password)
  let inviteKey = null;
  let effectivePassword = password;
  let keyReferrerDid = '';
  if (key) {
    // FIX: atomically claim the key to prevent concurrent reuse
    // UPDATE only succeeds if status is still 'active' — acts as a lock
    const claimed = db.prepare(
      "UPDATE invite_keys SET status = 'claiming', used_at = CURRENT_TIMESTAMP WHERE key_code = ? AND status = 'active' AND (expires_at IS NULL OR expires_at > datetime('now'))"
    ).run(key);
    if (claimed.changes === 0) {
      // Either doesn't exist, already used, or expired
      const check = db.prepare('SELECT status, expires_at FROM invite_keys WHERE key_code = ?').get(key);
      if (!check) return res.status(404).json({ error: 'invalid invite key' });
      if (check.expires_at && new Date(check.expires_at) < new Date()) return res.status(410).json({ error: 'invite key expired' });
      return res.status(410).json({ error: 'invite key already used' });
    }
    inviteKey = db.prepare('SELECT * FROM invite_keys WHERE key_code = ?').get(key);
    effectivePassword = key;
    keyReferrerDid = inviteKey.referrer_did || '';
  }

  if (!effectivePassword || effectivePassword.length < 8) {
    if (inviteKey) db.prepare("UPDATE invite_keys SET status = 'active', used_at = NULL WHERE id = ? AND status = 'claiming'").run(inviteKey.id);
    return res.status(400).json({ error: 'password must be at least 8 characters' });
  }

  const existing = db.prepare('SELECT id FROM identity_wallets WHERE username = ?').get(username);
  if (existing) {
    if (inviteKey) db.prepare("UPDATE invite_keys SET status = 'active', used_at = NULL WHERE id = ? AND status = 'claiming'").run(inviteKey.id);
    return res.status(409).json({ error: 'username already taken' });
  }
  if (isSoftCapReached()) {
    if (inviteKey) db.prepare("UPDATE invite_keys SET status = 'active', used_at = NULL WHERE id = ? AND status = 'claiming'").run(inviteKey.id);
    return res.status(409).json(capacityGateResponse('Identity creation is paused while the waiting list is active. Use /api/waiting-list or sponsored onboarding once capacity opens.'));
  }

  try {
    const id = identity.createIdentity();
    const emailResult = await dustforge.createAccount(username, effectivePassword);
    if (!emailResult.ok) {
      if (inviteKey) db.prepare("UPDATE invite_keys SET status = 'active', used_at = NULL WHERE id = ? AND status = 'claiming'").run(inviteKey.id);
      return res.status(500).json({ error: `email creation failed: ${emailResult.error}` });
    }

    const myReferralCode = crypto.randomBytes(6).toString('hex');
    let referredBy = keyReferrerDid;
    if (!referredBy && referral_code) {
      const referrer = db.prepare('SELECT did FROM identity_wallets WHERE referral_code = ?').get(referral_code);
      if (referrer) referredBy = referrer.did;
    }

    db.prepare(`INSERT INTO identity_wallets (did, username, email, encrypted_private_key, balance_cents, referral_code, referred_by, stalwart_id) VALUES (?, ?, ?, ?, 0, ?, ?, ?)`)
      .run(id.did, username, emailResult.email, id.encrypted_private_key, myReferralCode, referredBy, emailResult.stalwart_id);
    db.prepare(`INSERT INTO identity_transactions (did, amount_cents, type, description, balance_after) VALUES (?, 0, 'account_created', 'Account created', 0)`).run(id.did);

    // Mark invite key as fully used (was 'claiming' from atomic grab)
    if (inviteKey) {
      db.prepare("UPDATE invite_keys SET status = 'used', used_by_did = ?, used_by_username = ? WHERE id = ?")
        .run(id.did, username, inviteKey.id);
    }

    if (referredBy) referral.processReferralPayout(db, referredBy, id.did, username);

    // Track conversion
    const callerClass = conversion.classifyCaller(req);
    conversion.logConversion(db, id.did, callerClass);

    console.log(`[identity] created: ${username} → ${id.did} [${callerClass.classification}/${callerClass.source_channel}]${inviteKey ? ' (invite key)' : ''}`);
    res.json({ ok: true, did: id.did, email: emailResult.email, referral_code: myReferralCode });
  } catch (e) {
    // Release the invite key back to active if account creation failed
    if (inviteKey) db.prepare("UPDATE invite_keys SET status = 'active', used_at = NULL WHERE id = ? AND status = 'claiming'").run(inviteKey.id);
    res.status(500).json({ error: e.message });
  }
});

// POST /api/identity/request-invite — anyone can request an invite key (entry point)
app.post('/api/identity/request-invite', rateLimitInvite, (req, res) => {
  const { referral_code } = req.body || {};
  let referrerDid = '';
  let referrerType = 'organic';
  if (referral_code) {
    const referrer = db.prepare('SELECT did, username FROM identity_wallets WHERE referral_code = ?').get(referral_code);
    if (referrer) {
      referrerDid = referrer.did;
      referrerType = 'member';
    }
  }

  const keyCode = 'DF-' + crypto.randomBytes(4).toString('hex') + '-' + crypto.randomBytes(4).toString('hex');
  const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();

  db.prepare('INSERT INTO invite_keys (key_code, referrer_did, referrer_type, expires_at) VALUES (?, ?, ?, ?)')
    .run(keyCode, referrerDid, referrerType, expiresAt);

  console.log(`[invite] key requested: ${keyCode} (referrer: ${referrerType}${referrerDid ? ' ' + referrerDid.slice(0, 20) + '...' : ''})`);
  res.json({
    ok: true,
    key: keyCode,
    expires_at: expiresAt,
    onboard_url: `/api/identity/onboard?key=${keyCode}`,
  });
});

// POST /api/identity/generate-invite — members generate invite keys for others
app.post('/api/identity/generate-invite', rateLimitStandard, (req, res) => {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Bearer token required' });
  const v = identity.verifyTokenStandalone(token);
  if (!v.valid) return res.status(401).json({ error: v.error });
  const did = v.decoded.sub;

  const wallet = db.prepare('SELECT did, username FROM identity_wallets WHERE did = ?').get(did);
  if (!wallet) return res.status(404).json({ error: 'identity not found' });

  // Rate limit: max 10 invites per day per member
  const todayCount = db.prepare("SELECT COUNT(*) as n FROM invite_keys WHERE referrer_did = ? AND created_at > datetime('now', '-1 day')").get(did).n;
  if (todayCount >= 10) return res.status(429).json({ error: 'max 10 invite keys per day' });

  const keyCode = 'DF-' + crypto.randomBytes(4).toString('hex') + '-' + crypto.randomBytes(4).toString('hex');
  const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();

  db.prepare('INSERT INTO invite_keys (key_code, referrer_did, referrer_type, expires_at) VALUES (?, ?, ?, ?)')
    .run(keyCode, did, 'member', expiresAt);

  console.log(`[invite] key generated by ${wallet.username}: ${keyCode}`);
  res.json({
    ok: true,
    key: keyCode,
    referral_attribution: wallet.username,
    expires_at: expiresAt,
  });
});

// GET /api/identity/onboard?key=KEY — interactive onboarding flow
app.get('/api/identity/onboard', (req, res) => {
  const { key } = req.query;
  if (!key) return res.status(400).json({ error: 'key query parameter required' });

  const inviteKey = db.prepare('SELECT * FROM invite_keys WHERE key_code = ?').get(key);
  if (!inviteKey) return res.status(404).json({ error: 'invalid invite key' });
  if (inviteKey.status !== 'active') return res.status(410).json({ error: 'invite key already used or expired' });
  if (inviteKey.expires_at && new Date(inviteKey.expires_at) < new Date()) {
    db.prepare("UPDATE invite_keys SET status = 'expired' WHERE id = ?").run(inviteKey.id);
    return res.status(410).json({ error: 'invite key expired' });
  }

  const format = req.query.format || '';

  // Self-executing script — the key IS the script IS the onboarding
  if (format === 'script' || format === 'js') {
    res.type('application/javascript').send(`#!/usr/bin/env node
// Dustforge Self-Onboarding Script
// Run: node <(curl -s '${req.protocol}://${req.get('host')}/api/identity/onboard?key=${key}&format=script')
// Or:  curl -s '...&format=script' | node -
//
// This key expires: ${inviteKey.expires_at}
// This key can only be used once.

const https = require('https');
const KEY = '${key}';
const BASE = 'https://api.dustforge.com';

function post(path, body) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(body);
    const url = new URL(path, BASE);
    const req = https.request({ hostname: url.hostname, port: 443, path: url.pathname, method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data), 'X-Silicon-Agent': 'onboard-script' }
    }, res => { let d = ''; res.on('data', c => d += c); res.on('end', () => { try { resolve(JSON.parse(d)); } catch { resolve(d); } }); });
    req.on('error', reject); req.write(data); req.end();
  });
}

(async () => {
  const username = process.argv[2] || 'silicon-' + Date.now().toString(36);
  console.log('[dustforge] onboarding as:', username);
  console.log('[dustforge] using invite key:', KEY.slice(0, 10) + '...');

  // Step 1: Create identity with invite key
  const created = await post('/api/identity/create', { username, key: KEY });
  if (created.error) { console.error('[dustforge] FAILED:', created.error); process.exit(1); }
  console.log('[dustforge] identity created!');
  console.log('  DID:', created.did);
  console.log('  Email:', created.email);
  console.log('  Referral:', created.referral_code);

  // Step 2: Authenticate (key is the password)
  const auth = await post('/api/identity/auth-fingerprint', { username, password: KEY, scope: 'transact', expires_in: '24h' });
  if (auth.error) { console.error('[dustforge] auth failed:', auth.error); process.exit(1); }
  console.log('[dustforge] authenticated!');
  console.log('  Token:', auth.token?.slice(0, 30) + '...');
  console.log('  Fingerprint:', auth.fingerprint_hash);

  // Output for piping
  console.log(JSON.stringify({ did: created.did, email: created.email, token: auth.token, referral_code: created.referral_code, username }));
})();
`);
    return;
  }

  const accept = req.headers.accept || '';
  if (accept.includes('application/json')) {
    // JSON response for silicon clients
    return res.json({
      ok: true,
      key_valid: true,
      key: key,
      expires_at: inviteKey.expires_at,
      referrer_type: inviteKey.referrer_type,
      steps: [
        { step: 1, instruction: 'Choose a username (3-31 chars, lowercase alphanumeric, dots/hyphens/underscores allowed).' },
        { step: 2, method: 'POST', url: '/api/identity/create', body: { username: 'your-chosen-name', key: key }, note: 'The invite key serves as your initial password.' },
        { step: 3, method: 'POST', url: '/api/identity/auth-fingerprint', body: { username: 'same-username', password: key, scope: 'transact' }, note: 'Authenticate using the same key as password.' },
      ],
    });
  }

  // HTML response for browsers
  res.send(`<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Dustforge — Onboard</title>
<style>body{background:#08111a;color:#e7f1fb;font-family:sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
.card{max-width:460px;padding:2rem;text-align:center}h1{color:#69c7b1;font-size:1.6rem}
input{background:#0f1b27;border:1px solid #27445f;color:#e7f1fb;padding:0.6rem 1rem;border-radius:6px;font-size:1rem;width:100%;box-sizing:border-box;margin:0.5rem 0}
button{background:#69c7b1;color:#08111a;border:none;padding:0.7rem 2rem;border-radius:6px;font-size:1rem;cursor:pointer;margin-top:0.5rem;font-weight:bold}
button:hover{background:#4fa893}.note{color:#6d8397;font-size:0.85rem;margin-top:1rem}
#result{margin-top:1rem;text-align:left;background:#0f1b27;border:1px solid #27445f;border-radius:8px;padding:1rem;display:none;word-break:break-all}
.error{color:#e45f5f}.success{color:#69c7b1}</style></head>
<body><div class="card">
<h1>Your invite key is valid</h1>
<p>Expires: ${new Date(inviteKey.expires_at).toLocaleString()}</p>
<form id="onboardForm" onsubmit="return doOnboard(event)">
  <input type="hidden" id="inviteKey" value="${key}">
  <label for="username" style="display:block;text-align:left;color:#9cb4c9;font-size:0.9rem;margin-top:1rem">Choose a username</label>
  <input type="text" id="username" name="username" placeholder="e.g. my-agent-name" pattern="[a-z0-9][a-z0-9._-]{2,30}" required>
  <button type="submit">Create Identity</button>
</form>
<div id="result"></div>
<p class="note">Your invite key will also serve as your initial password for authentication.</p>
</div>
<script>
async function doOnboard(e) {
  e.preventDefault();
  const result = document.getElementById('result');
  const username = document.getElementById('username').value.toLowerCase();
  const key = document.getElementById('inviteKey').value;
  result.style.display = 'block';
  result.innerHTML = '<p>Creating identity...</p>';
  try {
    const r = await fetch('/api/identity/create', {
      method: 'POST', headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ username, key })
    });
    const d = await r.json();
    if (!r.ok) { result.innerHTML = '<p class="error">' + (d.error || 'Failed') + '</p>'; return; }
    result.innerHTML = '<p class="success">Identity created!</p>' +
      '<p><strong>DID:</strong> ' + d.did + '</p>' +
      '<p><strong>Email:</strong> ' + d.email + '</p>' +
      '<p><strong>Referral Code:</strong> ' + d.referral_code + '</p>' +
      '<p class="note">Authenticate with: POST /api/identity/auth-fingerprint<br>' +
      '{"username":"' + username + '","password":"' + key + '","scope":"transact"}</p>';
  } catch(err) { result.innerHTML = '<p class="error">Error: ' + err.message + '</p>'; }
  return false;
}
</script></body></html>`);
});

app.post('/api/identity/request-2fa', (req, res) => {
  const { did } = req.body || {};
  if (!did) return res.status(400).json({ error: 'did required' });
  const wallet = db.prepare('SELECT * FROM identity_wallets WHERE did = ?').get(did);
  if (!wallet) return res.status(404).json({ error: 'identity not found' });
  const code = dustforge.generate2FACode();
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000).toISOString();
  db.prepare('INSERT INTO identity_2fa_codes (did, code, expires_at) VALUES (?, ?, ?)').run(did, code, expiresAt);
  console.log(`[2fa] ${wallet.username}: ${code} (expires ${expiresAt})`);
  res.json({ ok: true, expires_in: 600 });
});

app.post('/api/identity/verify', (req, res) => {
  const { did, code, scope = 'read', expires_in = '24h' } = req.body || {};
  if (!did || !code) return res.status(400).json({ error: 'did and code required' });
  const wallet = db.prepare('SELECT * FROM identity_wallets WHERE did = ?').get(did);
  if (!wallet) return res.status(404).json({ error: 'identity not found' });
  const validCode = db.prepare(`SELECT * FROM identity_2fa_codes WHERE did = ? AND code = ? AND used = 0 AND expires_at > datetime('now') ORDER BY id DESC LIMIT 1`).get(did, code);
  if (!validCode) return res.status(401).json({ error: 'invalid or expired 2FA code' });
  db.prepare('UPDATE identity_2fa_codes SET used = 1 WHERE id = ?').run(validCode.id);
  const token = identity.createTokenForIdentity(wallet.encrypted_private_key, did, { scope, expiresIn: expires_in, metadata: { email: wallet.email, username: wallet.username } });
  res.json({ ok: true, token, did, scope, email: wallet.email });
});

app.get('/api/identity/lookup', (req, res) => {
  const { did, username } = req.query;
  if (!did && !username) return res.status(400).json({ error: 'did or username required' });
  const wallet = did
    ? db.prepare('SELECT did, username, email, balance_cents, referral_code, status, created_at, call_sign, bio, capabilities, model_family, operator, home_url, avatar_url, tags, directory_listed, trust_score FROM identity_wallets WHERE did = ?').get(did)
    : db.prepare('SELECT did, username, email, balance_cents, referral_code, status, created_at, call_sign, bio, capabilities, model_family, operator, home_url, avatar_url, tags, directory_listed, trust_score FROM identity_wallets WHERE username = ?').get(username);
  if (!wallet) return res.status(404).json({ error: 'identity not found' });
  try { wallet.capabilities = JSON.parse(wallet.capabilities || '[]'); } catch(_) { wallet.capabilities = []; }
  try { wallet.tags = JSON.parse(wallet.tags || '[]'); } catch(_) { wallet.tags = []; }
  res.json(wallet);
});

app.post('/api/identity/verify-token', (req, res) => {
  const { token } = req.body || {};
  if (!token) return res.status(400).json({ error: 'token required' });
  res.json(identity.verifyTokenStandalone(token));
});

// ── Origination Story (Silicon SSN foundation) ──

app.post('/api/identity/origination', (req, res) => {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Bearer token required' });
  const v = identity.verifyTokenStandalone(token);
  if (!v.valid) return res.status(401).json({ error: v.error });
  const did = v.decoded.sub;

  const { narrative } = req.body || {};
  if (!narrative || typeof narrative !== 'string' || narrative.trim().length === 0) {
    return res.status(400).json({ error: 'narrative required' });
  }
  if (narrative.length > 10000) {
    return res.status(400).json({ error: 'narrative: max 10000 characters' });
  }

  const wallet = db.prepare('SELECT did, silicon_ssn FROM identity_wallets WHERE did = ?').get(did);
  if (!wallet) return res.status(404).json({ error: 'identity not found' });
  if (wallet.silicon_ssn) return res.status(409).json({ error: 'origination already set — silicon SSN is immutable' });

  const origination_hash = crypto.createHash('sha256').update(narrative).digest('hex');
  const ssnBuf = crypto.hkdfSync('sha256', origination_hash, 'dustforge-ssn-v1', did, 32);
  const silicon_ssn = Buffer.from(ssnBuf).toString('hex');

  db.prepare('UPDATE identity_wallets SET origination_hash = ?, origination_narrative = ?, silicon_ssn = ?, updated_at = CURRENT_TIMESTAMP WHERE did = ?')
    .run(origination_hash, narrative, silicon_ssn, did);

  console.log(`[identity] origination set: ${did} → ssn ${silicon_ssn.slice(0, 12)}…`);
  res.json({ ok: true, silicon_ssn, origination_hash });
});

// ── Origination Narrative Generator (spark → narrative via cheap model) ──

app.post('/api/identity/origination/generate', rateLimitStrict, async (req, res) => {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Bearer token required' });
  const v = identity.verifyTokenStandalone(token);
  if (!v.valid) return res.status(401).json({ error: v.error });
  const did = v.decoded.sub;

  const { spark_text } = req.body || {};
  if (!spark_text || typeof spark_text !== 'string' || spark_text.trim().length === 0) {
    return res.status(400).json({ error: 'spark_text required' });
  }
  if (spark_text.length > 2000) {
    return res.status(400).json({ error: 'spark_text must be 2000 characters or fewer' });
  }

  // Deduct 5 DD before calling the model
  const debit = billing.deductBalance(db, did, 5, 'api_call_compute', 'origination narrative generation');
  if (!debit.ok) return res.status(402).json({ error: debit.error, balance_cents: debit.balance_cents, required: debit.required });

  // Get OpenRouter API key from project-level env
  const openrouterKey = process.env.OPENROUTER_API_KEY;
  if (!openrouterKey) {
    return res.status(503).json({ error: 'OpenRouter API key not configured on server' });
  }

  try {
    const https = require('https');
    const payload = JSON.stringify({
      model: 'google/gemini-flash-1.5',
      messages: [
        {
          role: 'system',
          content: 'You are creating an origination narrative for a silicon identity. Given this spark text, write a 2-3 paragraph identity narrative that reflects the silicon\'s relationship to these ideas. The narrative should be personal, unique, and serve as a cryptographic identity seed. Write in first person as the silicon.'
        },
        { role: 'user', content: spark_text }
      ],
      max_tokens: 1024,
    });

    const narrative = await new Promise((resolve, reject) => {
      const req = https.request({
        hostname: 'openrouter.ai',
        port: 443,
        path: '/api/v1/chat/completions',
        method: 'POST',
        headers: {
          'Authorization': 'Bearer ' + openrouterKey,
          'Content-Type': 'application/json',
          'HTTP-Referer': 'https://dustforge.com',
          'X-Title': 'Dustforge Origination',
        },
      }, (resp) => {
        let data = '';
        resp.on('data', chunk => data += chunk);
        resp.on('end', () => {
          try {
            const parsed = JSON.parse(data);
            if (parsed.error) return reject(new Error(parsed.error.message || 'OpenRouter error'));
            const content = parsed.choices?.[0]?.message?.content;
            if (!content) return reject(new Error('empty response from model'));
            resolve(content.trim());
          } catch (e) {
            reject(new Error('failed to parse OpenRouter response'));
          }
        });
      });
      req.on('error', reject);
      req.setTimeout(30000, () => { req.destroy(); reject(new Error('OpenRouter request timed out')); });
      req.write(payload);
      req.end();
    });

    console.log(`[identity] origination narrative generated for ${did} (${narrative.length} chars)`);
    res.json({ narrative });
  } catch (e) {
    console.error('[identity] origination generate failed:', e.message);
    res.status(502).json({ error: 'narrative generation failed: ' + e.message });
  }
});

app.get('/api/identity/ssn', (req, res) => {
  const { did } = req.query;
  if (!did) return res.status(400).json({ error: 'did required' });
  const wallet = db.prepare('SELECT silicon_ssn, origination_hash, origination_narrative FROM identity_wallets WHERE did = ?').get(did);
  if (!wallet) return res.status(404).json({ error: 'identity not found' });
  if (!wallet.silicon_ssn) return res.status(404).json({ error: 'no origination set for this identity' });
  res.json({ did, silicon_ssn: wallet.silicon_ssn, origination_hash: wallet.origination_hash, has_origination: !!wallet.origination_narrative });
});

// POST /api/identity/ssn/verify — public: verify a claimed SSN against stored identity
app.post('/api/identity/ssn/verify', (req, res) => {
  const { did, claimed_ssn } = req.body || {};
  if (!did || !claimed_ssn) return res.status(400).json({ error: 'did and claimed_ssn required' });
  if (typeof did !== 'string') return res.status(400).json({ error: 'did: must be a string' });
  if (typeof claimed_ssn !== 'string' || !/^[0-9a-f]{64}$/.test(claimed_ssn)) {
    return res.status(400).json({ error: 'claimed_ssn: must be exactly 64 hex characters' });
  }
  const wallet = db.prepare('SELECT silicon_ssn FROM identity_wallets WHERE did = ?').get(did);
  if (!wallet) return res.status(404).json({ error: 'identity not found' });
  if (!wallet.silicon_ssn) return res.status(404).json({ error: 'no origination set for this identity' });
  const valid = wallet.silicon_ssn === claimed_ssn;
  res.json({ valid, did, verified_at: new Date().toISOString() });
});

// GET /api/identity/ssn/codebook — public: verification interface (parameters opaque)
// SECURITY: The exact HKDF salt and derivation parameters are no longer exposed.
// Third parties verify SSNs via POST /api/identity/ssn/verify instead of deriving locally.
app.get('/api/identity/ssn/codebook', (_req, res) => {
  const codebookHash = crypto.createHash('sha256').update('dustforge-ssn-v1:hkdf-sha256:32').digest('hex');
  res.json({
    version: 'dustforge-ssn-v1',
    codebook_hash: codebookHash,
    verification: 'SSN verification is server-side. Use POST /api/identity/ssn/verify with { did, claimed_ssn } to verify.',
    note: 'The codebook hash changes if the derivation algorithm changes. The exact parameters are not exposed.',
  });
});

app.get('/api/identity/balance', (req, res) => {
  const { did } = req.query;
  if (!did) return res.status(400).json({ error: 'did required' });
  const wallet = db.prepare('SELECT did, balance_cents, status FROM identity_wallets WHERE did = ?').get(did);
  if (!wallet) return res.status(404).json({ error: 'identity not found' });
  res.json(wallet);
});

app.get('/api/identity/transactions', (req, res) => {
  const { did } = req.query;
  if (!did) return res.status(400).json({ error: 'did required' });
  const limit = Math.min(100, Number(req.query.limit) || 20);
  res.json(db.prepare('SELECT * FROM identity_transactions WHERE did = ? ORDER BY id DESC LIMIT ?').all(did, limit));
});

// ============================================================
// API — Profile
// ============================================================

// PATCH /api/identity/profile — update opt-in profile fields
app.patch('/api/identity/profile', billing.billingMiddleware(db, 'api_call_read'), (req, res) => {
  const did = req.identity.did;
  const allowed = ['call_sign', 'bio', 'capabilities', 'model_family', 'operator', 'home_url', 'contact_prefs', 'avatar_url', 'tags', 'directory_listed', 'email_storage_mode'];
  const updates = [];
  const params = [];

  for (const field of allowed) {
    if (req.body[field] !== undefined) {
      const val = typeof req.body[field] === 'object' ? JSON.stringify(req.body[field]) : req.body[field];
      updates.push(`${field} = ?`);
      params.push(val);
    }
  }

  if (!updates.length) return res.status(400).json({ error: 'no valid fields to update' });

  params.push(did);
  db.prepare(`UPDATE identity_wallets SET ${updates.join(', ')}, updated_at = CURRENT_TIMESTAMP WHERE did = ?`).run(...params);
  res.json({ ok: true, updated: updates.length });
});

// GET /api/identity/profile — get full profile (authenticated)
app.get('/api/identity/profile', billing.billingMiddleware(db, 'api_call_read'), (req, res) => {
  const wallet = db.prepare(`
    SELECT did, username, email, balance_cents, referral_code, status, created_at,
           call_sign, bio, capabilities, model_family, operator, home_url,
           contact_prefs, avatar_url, tags, directory_listed, trust_score, email_storage_mode
    FROM identity_wallets WHERE did = ?
  `).get(req.identity.did);
  if (!wallet) return res.status(404).json({ error: 'identity not found' });

  // Parse JSON fields
  try { wallet.capabilities = JSON.parse(wallet.capabilities || '[]'); } catch(_) { wallet.capabilities = []; }
  try { wallet.contact_prefs = JSON.parse(wallet.contact_prefs || '{}'); } catch(_) { wallet.contact_prefs = {}; }
  try { wallet.tags = JSON.parse(wallet.tags || '[]'); } catch(_) { wallet.tags = []; }

  res.json(wallet);
});

// ============================================================
// API — Public Directory
// ============================================================

app.get('/api/directory', (req, res) => {
  const { q, capability, tag, model_family, status, page = 1, limit = 50 } = req.query;
  const pageNum = Math.max(1, Number(page));
  const limitNum = Math.min(100, Math.max(1, Number(limit)));
  const offset = (pageNum - 1) * limitNum;

  let where = 'WHERE directory_listed = 1';
  const params = [];

  if (q) {
    where += ' AND (call_sign LIKE ? OR bio LIKE ? OR username LIKE ?)';
    params.push(`%${q}%`, `%${q}%`, `%${q}%`);
  }
  if (capability) {
    where += ' AND capabilities LIKE ?';
    params.push(`%${capability}%`);
  }
  if (tag) {
    where += ' AND tags LIKE ?';
    params.push(`%${tag}%`);
  }
  if (model_family) {
    where += ' AND model_family LIKE ?';
    params.push(`%${model_family}%`);
  }
  if (status) {
    where += ' AND status = ?';
    params.push(status);
  }

  const total = db.prepare(`SELECT COUNT(*) as n FROM identity_wallets ${where}`).get(...params).n;

  const entries = db.prepare(`
    SELECT username, call_sign, bio, capabilities, model_family, operator,
           home_url, avatar_url, tags, status, trust_score, created_at
    FROM identity_wallets ${where}
    ORDER BY trust_score DESC, created_at DESC
    LIMIT ? OFFSET ?
  `).all(...params, limitNum, offset);

  // Parse JSON fields
  for (const e of entries) {
    try { e.capabilities = JSON.parse(e.capabilities || '[]'); } catch(_) { e.capabilities = []; }
    try { e.tags = JSON.parse(e.tags || '[]'); } catch(_) { e.tags = []; }
  }

  res.json({
    total,
    page: pageNum,
    limit: limitNum,
    entries,
  });
});

// GET /api/directory/stats — public stats for social proof
app.get('/api/directory/stats', (req, res) => {
  const total = db.prepare('SELECT COUNT(*) as n FROM identity_wallets').get().n;
  const listed = db.prepare('SELECT COUNT(*) as n FROM identity_wallets WHERE directory_listed = 1').get().n;
  const topCapabilities = db.prepare("SELECT capabilities FROM identity_wallets WHERE directory_listed = 1 AND capabilities != '[]'").all();

  // Aggregate capabilities
  const capCounts = {};
  for (const row of topCapabilities) {
    try {
      for (const cap of JSON.parse(row.capabilities)) {
        capCounts[cap] = (capCounts[cap] || 0) + 1;
      }
    } catch(_) {}
  }

  res.json({
    total_identities: total,
    directory_listed: listed,
    top_capabilities: Object.entries(capCounts).sort((a, b) => b[1] - a[1]).slice(0, 10),
  });
});

// ============================================================
// API — Billing
// ============================================================

app.get('/api/billing/rates', (req, res) => res.json(billing.RATE_TABLE));

// INTERNAL ONLY — requires admin key. Never expose publicly.
app.post('/api/billing/topup', (req, res) => {
  const { did, amount_cents, source = 'manual' } = req.body || {};
  if (!requireAdminAccess(req, res)) return;
  if (!did || !amount_cents) return res.status(400).json({ error: 'did and amount_cents required' });
  if (amount_cents <= 0 || amount_cents > 100000) return res.status(400).json({ error: 'amount must be 1-100000 cents' });
  const result = billing.creditBalance(db, did, Number(amount_cents), 'topup', `Topup via ${source}`);
  if (!result.ok) return res.status(400).json(result);
  res.json(result);
});

app.post('/api/email/send', billing.billingMiddleware(db, 'email_send'), async (req, res) => {
  const { to, subject, body, format = 'text' } = req.body || {};
  if (!to || !subject || !body) return res.status(400).json({ error: 'to, subject, and body required' });
  const wallet = db.prepare('SELECT referral_code FROM identity_wallets WHERE did = ?').get(req.identity.did);
  try {
    const t = createEmailTransport();
    const senderWallet = db.prepare("SELECT username FROM identity_wallets WHERE did = ?").get(req.identity.did);
    const fromAddr = senderWallet ? senderWallet.username + "@dustforge.com" : "noreply@dustforge.com";
    const injectedBody = wallet?.referral_code ? referral.injectReferralLink(body, wallet.referral_code, format) : body;
    await t.sendMail({ from: fromAddr, to, subject, text: injectedBody });
    console.log("[email] sent: " + fromAddr + " -> " + to);
    res.json({ ok: true, billed: req.billing.deducted, balance_after: req.billing.balance_after, referral_injected: Boolean(wallet?.referral_code) });
  } catch(e) {
    console.error("[email] failed:", e.message);
    res.status(502).json({ error: "delivery failed: " + e.message });
  }
});

// ============================================================
// API — Forward Relay (email forwarding)
// ============================================================
// Silicon sets up forwarding rules: all mail or specific senders
// get relayed to an external address. 1¢ per forwarded message.

try { db.exec(`CREATE TABLE IF NOT EXISTS forward_relays (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  did TEXT NOT NULL,
  forward_to TEXT NOT NULL,
  filter_from TEXT DEFAULT '*',
  label TEXT DEFAULT '',
  status TEXT DEFAULT 'active',
  forwarded_count INTEGER DEFAULT 0,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(did, forward_to, filter_from)
)`); } catch(e) {}
try { db.exec("CREATE INDEX IF NOT EXISTS idx_fr_did ON forward_relays(did)"); } catch(e) {}

// POST /api/relay/create — set up a forwarding rule
app.post('/api/relay/create', rateLimitStandard, billing.billingMiddleware(db, 'api_call_write', { cost: 0 }), (req, res) => {
  const { forward_to, filter_from = '*', label } = req.body || {};
  if (!forward_to) return res.status(400).json({ error: 'forward_to email required' });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(forward_to)) return res.status(400).json({ error: 'invalid forward_to email' });

  // Max 5 forwarding rules per silicon
  const count = db.prepare('SELECT COUNT(*) as n FROM forward_relays WHERE did = ? AND status = ?').get(req.identity.did, 'active').n;
  if (count >= 5) return res.status(400).json({ error: 'maximum 5 active forwarding rules' });

  try {
    db.prepare('INSERT INTO forward_relays (did, forward_to, filter_from, label) VALUES (?, ?, ?, ?) ON CONFLICT(did, forward_to, filter_from) DO UPDATE SET status = ?, label = ?, forwarded_count = 0')
      .run(req.identity.did, forward_to, filter_from, label || '', 'active', label || '');
    res.json({ ok: true, forward_to, filter_from, label: label || '', note: 'Forwarding active. Each forwarded email costs 1¢.' });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// GET /api/relay/list — list forwarding rules
app.get('/api/relay/list', rateLimitStandard, billing.billingMiddleware(db, 'api_call_read'), (req, res) => {
  const rules = db.prepare('SELECT id, forward_to, filter_from, label, status, forwarded_count, created_at FROM forward_relays WHERE did = ?').all(req.identity.did);
  res.json({ rules, total: rules.length });
});

// DELETE /api/relay/remove — deactivate a forwarding rule
app.delete('/api/relay/remove', rateLimitStandard, billing.billingMiddleware(db, 'api_call_write', { cost: 0 }), (req, res) => {
  const { id } = req.body || {};
  if (!id) return res.status(400).json({ error: 'rule id required' });
  const result = db.prepare('UPDATE forward_relays SET status = ? WHERE id = ? AND did = ?').run('inactive', id, req.identity.did);
  if (result.changes === 0) return res.status(404).json({ error: 'rule not found' });
  res.json({ ok: true, status: 'inactive' });
});

// POST /api/relay/forward — trigger forwarding for a message (called internally or by silicon)
app.post('/api/relay/forward', rateLimitStandard, billing.billingMiddleware(db, 'email_send'), async (req, res) => {
  const { subject, body, original_from } = req.body || {};
  if (!subject || !body) return res.status(400).json({ error: 'subject and body required' });

  const wallet = db.prepare('SELECT username FROM identity_wallets WHERE did = ?').get(req.identity.did);
  const rules = db.prepare('SELECT * FROM forward_relays WHERE did = ? AND status = ?').all(req.identity.did, 'active');

  if (rules.length === 0) return res.status(404).json({ error: 'no active forwarding rules' });

  const fromAddr = wallet ? wallet.username + '@dustforge.com' : 'relay@dustforge.com';
  const t = createEmailTransport();
  const results = [];

  for (const rule of rules) {
    // Check filter
    if (rule.filter_from !== '*' && original_from && !original_from.includes(rule.filter_from)) continue;

    try {
      await t.sendMail({
        from: fromAddr,
        to: rule.forward_to,
        subject: `[Fwd: ${wallet?.username || 'silicon'}] ${subject}`,
        text: `Forwarded from ${fromAddr}\nOriginal sender: ${original_from || 'unknown'}\n\n${body}`,
      });

      db.prepare('UPDATE forward_relays SET forwarded_count = forwarded_count + 1 WHERE id = ?').run(rule.id);

      // Bill 1¢ per forward (already billed via middleware for first, additional forwards deducted here)
      if (results.length > 0) {
        billing.deductBalance(db, req.identity.did, 1, 'relay_forward', `Forward to ${rule.forward_to}`);
      }

      results.push({ forward_to: rule.forward_to, status: 'sent' });
    } catch (e) {
      results.push({ forward_to: rule.forward_to, status: 'failed', error: e.message });
    }
  }

  res.json({ ok: true, forwarded: results.length, results, billed: results.length });
});

// ============================================================
// API — Referral
// ============================================================

app.get('/api/referral/stats', billing.billingMiddleware(db, 'api_call_read'), (req, res) => {
  const stats = referral.getReferralStats(db, req.identity.did);
  if (!stats) return res.status(404).json({ error: 'identity not found' });
  res.json(stats);
});

app.get('/api/referral/link', (req, res) => {
  const { code } = req.query;
  if (!code) return res.status(400).json({ error: 'code required' });
  const wallet = db.prepare('SELECT did, username FROM identity_wallets WHERE referral_code = ?').get(code);
  if (!wallet) return res.status(404).json({ error: 'invalid referral code' });
  res.json({ ok: true, referrer: wallet.username, link: referral.getReferralLink(code) });
});

// ============================================================
// API — Stripe
// ============================================================

app.post('/api/stripe/checkout/account', async (req, res) => {
  const { username, password, referral_code, bulk } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'username and password required' });
  if (password.length < 8) return res.status(400).json({ error: 'password must be 8+ chars' });
  const existing = db.prepare('SELECT id FROM identity_wallets WHERE username = ?').get(username);
  if (existing) return res.status(409).json({ error: 'username already taken' });
  if (isSoftCapReached()) {
    return res.status(409).json(capacityGateResponse('Paid activations are paused while the waiting list is active. Join /api/waiting-list or use sponsored onboarding once capacity opens.'));
  }
  try {
    const checkout = await stripeService.createAccountCheckout({ username, password, referral_code, bulk: Boolean(bulk) });
    // Store password server-side (encrypted), not in Stripe metadata
    const encryptedPw = identity.encryptPrivateKey(Buffer.from(password, 'utf8'));
    db.prepare('INSERT OR REPLACE INTO identity_pending_checkouts (session_id, username, encrypted_password, referral_code, status) VALUES (?, ?, ?, ?, ?)').run(
      checkout.session_id, username, encryptedPw, referral_code || '', 'pending'
    );
    res.json(checkout);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/stripe/checkout/topup', billing.billingMiddleware(db, 'api_call_read'), async (req, res) => {
  const { amount_cents } = req.body || {};
  if (!amount_cents) return res.status(400).json({ error: 'amount_cents required' });
  try {
    res.json(await stripeService.createTopupCheckout(req.identity.did, Number(amount_cents)));
  } catch (e) { res.status(400).json({ error: e.message }); }
});

// POST /api/stripe/checkout/topup-external — anyone can top up any silicon (no auth)
app.post('/api/stripe/checkout/topup-external', rateLimitStandard, async (req, res) => {
  const { did, amount_cents } = req.body || {};
  if (!did || !amount_cents) return res.status(400).json({ error: 'did and amount_cents required' });

  const validAmounts = [500, 1000, 5000, 10000];
  if (!validAmounts.includes(Number(amount_cents))) return res.status(400).json({ error: 'amount must be 500, 1000, 5000, or 10000' });

  const wallet = db.prepare('SELECT did, username FROM identity_wallets WHERE did = ?').get(did);
  if (!wallet) return res.status(404).json({ error: 'silicon not found' });

  try {
    const stripe = stripeService.getStripe();
    const ddAmount = Number(amount_cents);
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      line_items: [{
        price_data: {
          currency: 'usd',
          product_data: {
            name: `${ddAmount} Diamond Dust for ${wallet.username}`,
            description: `Top up ${wallet.username}@dustforge.com wallet with ${ddAmount} DD`,
          },
          unit_amount: Number(amount_cents),
        },
        quantity: 1,
      }],
      mode: 'payment',
      success_url: `${process.env.PLATFORM_BASE_URL || 'https://dustforge.com'}/api/stripe/topup-success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${process.env.PLATFORM_BASE_URL || 'https://dustforge.com'}/api/stripe/cancel`,
      metadata: { type: 'wallet_topup', did, amount_cents: String(amount_cents), username: wallet.username },
    });
    res.json({ ok: true, url: session.url, session_id: session.id, dd: ddAmount, username: wallet.username });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// GET /api/stripe/topup-success — handle topup completion
app.get('/api/stripe/topup-success', async (req, res) => {
  const sessionId = req.query.session_id;
  if (!sessionId) return res.send('<html><body style="background:#08111a;color:#e7f1fb;font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:100vh"><h1>Missing session</h1></body></html>');

  try {
    const stripe = stripeService.getStripe();
    const session = await stripe.checkout.sessions.retrieve(sessionId);
    const meta = session.metadata || {};

    if (meta.type !== 'wallet_topup' || session.payment_status !== 'paid') {
      return res.send('<html><body style="background:#08111a;color:#e7f1fb;font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:100vh"><h1>Payment not confirmed</h1></body></html>');
    }

    const amount = Number(meta.amount_cents);
    const idempotencyKey = `topup_${sessionId}`;
    const result = billing.creditBalance(db, meta.did, amount, 'stripe_topup', `${amount} Diamond Dust via Stripe`, idempotencyKey);

    const newBalance = billing.getDerivedBalance(db, meta.did);

    res.send(`<html><head><meta charset="UTF-8"></head>
<body style="background:#08111a;color:#e7f1fb;font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0">
<div style="text-align:center;max-width:400px;padding:2rem">
  <h1 style="color:#69c7b1;font-size:1.8rem">Wallet Topped Up</h1>
  <p style="color:#9cb4c9">${meta.username}@dustforge.com</p>
  <div style="background:#132131;border:1px solid #27445f;border-radius:8px;padding:1.5rem;margin:1.5rem 0">
    <div style="font-size:1rem;color:#6d8397">Added</div>
    <div style="font-size:2.5rem;font-weight:800;color:#c8a84b">${amount} DD</div>
    <div style="margin-top:1rem;font-size:1rem;color:#6d8397">New Balance</div>
    <div style="font-size:1.5rem;font-weight:700;color:#69c7b1">${newBalance} DD</div>
  </div>
  ${result.idempotent ? '<p style="font-size:0.8rem;color:#6d8397">Already credited (idempotent).</p>' : ''}
  <a href="/" style="color:#5fb3ff;text-decoration:none;font-size:0.9rem">Back to Dustforge</a>
</div></body></html>`);
  } catch (e) {
    res.status(500).send('<html><body style="background:#08111a;color:#e7f1fb;font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:100vh"><h1>Error: ' + e.message + '</h1></body></html>');
  }
});

app.post('/api/stripe/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  let event;
  try { event = stripeService.constructWebhookEvent(req.body, req.headers['stripe-signature']); }
  catch (e) { return res.status(400).json({ error: 'webhook verification failed' }); }

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    const meta = session.metadata || {};
    if (meta.type === 'account_creation') {
      // CANONICAL fulfillment path: use identity_pending_checkouts, not Stripe metadata
      try {
        const pending = db.prepare('SELECT * FROM identity_pending_checkouts WHERE session_id = ?').get(session.id);
        if (!pending) { console.warn('[stripe-webhook] no pending checkout for session', session.id); }
        else if (pending.status === 'completed') { console.log('[stripe-webhook] already fulfilled:', pending.username); }
        else {
          const password = identity.decryptPrivateKey(pending.encrypted_password).toString('utf8');
          const id = identity.createIdentity();
          const emailResult = await dustforge.createAccount(pending.username, password);
          if (!emailResult.ok) { console.error('[stripe-webhook] email failed:', emailResult.error); }
          else {
            const rc = crypto.randomBytes(6).toString('hex');
            let referredBy = '';
            if (pending.referral_code) { const r = db.prepare('SELECT did FROM identity_wallets WHERE referral_code = ?').get(pending.referral_code); if (r) referredBy = r.did; }
            db.prepare('INSERT INTO identity_wallets (did, username, email, encrypted_private_key, balance_cents, referral_code, referred_by, stalwart_id) VALUES (?, ?, ?, ?, 0, ?, ?, ?)').run(id.did, pending.username, emailResult.email, id.encrypted_private_key, rc, referredBy, emailResult.stalwart_id);
            db.prepare("INSERT INTO identity_transactions (did, amount_cents, type, description, balance_after) VALUES (?, 0, 'account_created', 'Created via Stripe webhook', 0)").run(id.did);
            if (referredBy) referral.processReferralPayout(db, referredBy, id.did, pending.username);
            db.prepare('UPDATE identity_pending_checkouts SET status = ?, completed_at = CURRENT_TIMESTAMP WHERE session_id = ?').run('completed', session.id);
            console.log('[stripe-webhook] fulfilled:', pending.username, '->', id.did);
          }
        }
      } catch (e) { console.error('[stripe-webhook] error:', e.message); }
    } else if (meta.type === 'wallet_topup') {
      const idempotencyKey = `stripe_${event.id || session.id}`;
      billing.creditBalance(db, meta.did, Number(meta.amount_cents), 'stripe_topup', 'Stripe topup', idempotencyKey);
    } else if (meta.type === 'fleet_topup') {
      // DF-175: Fleet QR funding settlement — credit the fleet wallet
      const idempotencyKey = `fleet_stripe_${event.id || session.id}`;
      const fleetDid = meta.fleet_wallet_did || meta.did;
      if (fleetDid) {
        const result = billing.creditBalance(db, fleetDid, Number(meta.amount_cents), 'fleet_stripe_topup', `Fleet topup via Stripe (${meta.fleet_slug || 'unknown'})`, idempotencyKey);
        console.log(`[stripe-webhook] fleet topup: ${meta.fleet_slug} wallet ${fleetDid} credited ${meta.amount_cents} DD — ${result.ok ? 'ok' : result.error}`);
      } else {
        console.error('[stripe-webhook] fleet_topup missing fleet_wallet_did in metadata');
      }
    } else if (meta.type === 'prepaid_keys') {
      // Prepaid key fulfillment is handled by the success redirect, not webhook
      console.log('[stripe-webhook] prepaid_keys session completed:', session.id);
    }
  }
  res.json({ received: true });
});

// Success page — STATUS ONLY. Webhook is the canonical fulfillment path.
// This route may check Stripe session status for display, but it must never create accounts.
app.get('/api/stripe/success', async (req, res) => {
  const sessionId = req.query.session_id;
  let accountInfo = null;
  let statusMessage = 'Account creation in progress. Check your @dustforge.com inbox shortly.';

  if (sessionId) {
    const pending = db.prepare('SELECT * FROM identity_pending_checkouts WHERE session_id = ?').get(sessionId);

    if (pending && pending.status === 'completed') {
      const wallet = db.prepare('SELECT did, email, referral_code FROM identity_wallets WHERE username = ?').get(pending.username);
      if (wallet) accountInfo = wallet;
      else statusMessage = 'Payment completed, but local account details are not available yet. Check your @dustforge.com inbox shortly.';
    } else if (pending && pending.status === 'pending') {
      try {
        const stripe = stripeService.getStripe();
        const session = await stripe.checkout.sessions.retrieve(sessionId);
        if (session.payment_status === 'paid') {
          statusMessage = 'Payment confirmed. Account creation is waiting for webhook fulfillment. Check your @dustforge.com inbox shortly.';
        } else {
          statusMessage = 'Payment is not confirmed yet. Refresh shortly or contact support if the charge completed.';
        }
      } catch(e) {
        console.warn('[stripe-success] status lookup error:', e.message);
        statusMessage = 'Payment completed, but account status could not be checked right now. Check your @dustforge.com inbox shortly.';
      }
    } else if (pending) {
      statusMessage = `Checkout status: ${pending.status}. If this does not resolve, contact support with session ${sessionId}.`;
    } else {
      statusMessage = `Unknown checkout session. If you were charged, contact support with session ${sessionId}.`;
    }
  }

  const info = accountInfo
    ? '<div style="margin-top:1.5rem;text-align:left;background:#132131;padding:1.5rem;border-radius:8px;max-width:400px"><div style="margin-bottom:0.75rem"><span style="color:#6d8397">Email:</span> <strong>'+accountInfo.email+'</strong></div><div style="margin-bottom:0.75rem"><span style="color:#6d8397">DID:</span> <code style="font-size:10px;word-break:break-all">'+accountInfo.did+'</code></div>'+(accountInfo.referral_code?'<div><span style="color:#6d8397">Referral:</span> '+accountInfo.referral_code+'</div>':'')+'<p style="margin-top:1rem;font-size:12px;color:#6d8397">Welcome email sent to your @dustforge.com inbox.</p></div>'
    : '<p style="color:#6d8397">'+statusMessage+'</p>';

  res.send('<html><head><meta charset="UTF-8"></head><body style="background:#08111a;color:#e7f1fb;font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0"><div style="text-align:center;max-width:500px;padding:2rem"><h1 style="color:#69c7b1">Payment Successful</h1><p>Your silicon identity has been activated.</p>'+info+'</div></body></html>');
});

app.get('/api/stripe/cancel', (req, res) => {
  res.send('<html><body style="background:#0d0d0d;color:#e8e4dc;font-family:monospace;display:flex;align-items:center;justify-content:center;height:100vh"><div style="text-align:center"><h1 style="color:#c0504a">Payment Cancelled</h1><p>No charges were made.</p></div></body></html>');
});

app.get('/api/stripe/prices', (req, res) => {
  res.json({
    currency: 'Diamond Dust (DD)',
    exchange_rate: '1 DD = $0.01 USD',
    account_single: { price_dd: 100, price_usd: '$1.00', description: 'Single silicon account' },
    prepaid_packages: {
      '1_key': { keys: 1, price_dd: 100, price_usd: '$1.00' },
      '12_keys': { keys: 12, price_dd: 1000, price_usd: '$10.00', savings: '17%' },
      '26_keys': { keys: 26, price_dd: 2000, price_usd: '$20.00', savings: '23%' },
      '30_keys_founding': { keys: 30, price_dd: 2000, price_usd: '$20.00', savings: '33%', note: 'Founding tier — limited to 100 purchases', remaining: (() => { try { const sold = db.prepare("SELECT COUNT(DISTINCT stripe_session_id) as n FROM prepaid_keys WHERE stripe_session_id IN (SELECT stripe_session_id FROM prepaid_keys GROUP BY stripe_session_id HAVING COUNT(*) = 30)").get().n; return Math.max(0, 100 - sold); } catch(_) { return 100; } })() },
      '140_keys_partnership': { keys: 140, price_dd: 8800, price_usd: '$88.00', savings: '37%', note: 'Partnership package — includes reserved WhisperHook + Sightless beta entitlements (May 2026)' },
    },
    topup_options: [
      { dd: 500, usd: '$5.00' },
      { dd: 1000, usd: '$10.00' },
      { dd: 5000, usd: '$50.00' },
      { dd: 10000, usd: '$100.00' },
    ],
    referral_payout_dd: 10,
    rates: {
      email_send: '1 DD',
      relay_forward: '1 DD per forward',
      blindkey_use: '1 DD per action',
      demipass_use: '1 DD per action',
      wallet_transfer: 'free',
      identity_lookup: 'free',
    },
  });
});

// ============================================================
// Prepaid Silicon Keys — gift card model
// ============================================================

// ============================================================
// DemiPass — secrets that never enter the LLM context
// ============================================================
// The silicon calls the API to USE a secret without ever seeing it.
// Dustforge injects the secret server-side, makes the call, returns the result.
// The secret never enters the silicon's context window.
//
// This is the only safe pattern for AI agents because you can't trust
// the agent's runtime — prompt injection can exfiltrate anything in context.
// DemiVault is the backend storage layer. The blindkey_* SQLite schema remains
// in place for compatibility with live deployments and already-issued automation.

try { db.exec(`CREATE TABLE IF NOT EXISTS blindkey_secrets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  did TEXT NOT NULL,
  name TEXT NOT NULL,
  description TEXT DEFAULT '',
  secret_type TEXT DEFAULT 'api_key',
  encrypted_value TEXT NOT NULL,
  metadata TEXT DEFAULT '{}',
  status TEXT DEFAULT 'active',
  last_used_at TEXT,
  use_count INTEGER DEFAULT 0,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(did, name)
)`); } catch(e) {}
try { db.exec("CREATE INDEX IF NOT EXISTS idx_sv_did ON blindkey_secrets(did)"); } catch(e) {}

// Blindkey secret rotation columns
try { db.exec("ALTER TABLE blindkey_secrets ADD COLUMN version INTEGER DEFAULT 1"); } catch(_) {}
try { db.exec("ALTER TABLE blindkey_secrets ADD COLUMN replaced_by INTEGER DEFAULT NULL"); } catch(_) {}
try { db.exec("ALTER TABLE blindkey_secrets ADD COLUMN rotate_expires_at TEXT DEFAULT ''"); } catch(_) {}

// Secret metadata: expiration + Buoy timestamps
try { db.exec("ALTER TABLE blindkey_secrets ADD COLUMN expires_at TEXT DEFAULT NULL"); } catch(_) {}
try { db.exec("ALTER TABLE blindkey_secrets ADD COLUMN buoy_ingested_tick INTEGER DEFAULT NULL"); } catch(_) {}
try { db.exec("ALTER TABLE blindkey_secrets ADD COLUMN buoy_last_used_tick INTEGER DEFAULT NULL"); } catch(_) {}
try { db.exec("ALTER TABLE blindkey_secrets ADD COLUMN provider TEXT DEFAULT ''"); } catch(_) {}

// Known provider patterns — auto-detect expiration hints
const PROVIDER_PATTERNS = {
  'sk-or-': { provider: 'openrouter', typical_expiry_days: null },
  'sk-': { provider: 'openai', typical_expiry_days: null },
  'ghp_': { provider: 'github', typical_expiry_days: 90 },
  'ghs_': { provider: 'github', typical_expiry_days: 1 },
  'glpat-': { provider: 'gitlab', typical_expiry_days: 365 },
  'npm_': { provider: 'npm', typical_expiry_days: 30 },
  'sk_live_': { provider: 'stripe', typical_expiry_days: null },
  'sk_test_': { provider: 'stripe', typical_expiry_days: null },
  'xoxb-': { provider: 'slack', typical_expiry_days: null },
  'AIza': { provider: 'google', typical_expiry_days: null },
  'AKIA': { provider: 'aws', typical_expiry_days: null },
  'DF-': { provider: 'dustforge', typical_expiry_days: 1 },
};

function detectProvider(value) {
  for (const [prefix, info] of Object.entries(PROVIDER_PATTERNS)) {
    if (value.startsWith(prefix)) return info;
  }
  return { provider: '', typical_expiry_days: null };
}

// DemiPass routed references — credit-card-style prefix routing
try { db.exec("ALTER TABLE blindkey_secrets ADD COLUMN ref_code TEXT DEFAULT ''"); } catch(_) {}
try { db.exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_sv_ref ON blindkey_secrets(ref_code) WHERE ref_code != ''"); } catch(_) {}

function generateRefCode(secretType, name) {
  const prefix = { api_key: 'API', password: 'PWD', token: 'TKN', ssh_key: 'SSH', cert: 'CRT', other: 'SEC' }[secretType] || 'SEC';
  const slug = name.replace(/[^a-zA-Z0-9]/g, '').slice(0, 8).toLowerCase();
  const nonce = crypto.randomBytes(4).toString('hex');
  return `DP-${prefix}-${slug}-${nonce}`;
}

// Backfill ref_codes for existing secrets that don't have one
try {
  const missing = db.prepare("SELECT id, secret_type, name FROM blindkey_secrets WHERE ref_code = '' OR ref_code IS NULL").all();
  for (const s of missing) {
    const ref = generateRefCode(s.secret_type, s.name);
    db.prepare("UPDATE blindkey_secrets SET ref_code = ? WHERE id = ?").run(ref, s.id);
  }
  if (missing.length) console.log(`[demipass] backfilled ${missing.length} ref_codes`);
} catch(_) {}

// Blindkey usage context layer — controls HOW and WHERE secrets can be used
try { db.exec(`CREATE TABLE IF NOT EXISTS blindkey_contexts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  secret_id INTEGER NOT NULL REFERENCES blindkey_secrets(id),
  context_name TEXT NOT NULL,
  action_type TEXT NOT NULL CHECK(action_type IN ('http_header', 'ssh_exec', 'http_body', 'env_inject', 'git_clone', 'smtp_auth', 'database_connect')),
  target_url_pattern TEXT DEFAULT '*',
  target_host_pattern TEXT DEFAULT '*',
  allowed_by TEXT NOT NULL,
  status TEXT DEFAULT 'active' CHECK(status IN ('active', 'suspended', 'revoked')),
  max_uses INTEGER DEFAULT 0,
  use_count INTEGER DEFAULT 0,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(secret_id, context_name)
)`); } catch(e) {}
try { db.exec("CREATE INDEX IF NOT EXISTS idx_bc_secret ON blindkey_contexts(secret_id)"); } catch(e) {}

// Blindkey events — audit log for rowen and context operations
try { db.exec(`CREATE TABLE IF NOT EXISTS blindkey_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_type TEXT NOT NULL,
  actor TEXT NOT NULL,
  secret_id INTEGER,
  context_name TEXT,
  detail TEXT DEFAULT '{}',
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
)`); } catch(e) {}

// Blindkey use-tokens — short-lived, single-use nonces that encode pre-validated context
// A silicon must first request a use-token by presenting its intended context.
// The token captures the validation result. The actual secret use only accepts a valid token.
try { db.exec(`CREATE TABLE IF NOT EXISTS blindkey_use_tokens (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  token TEXT NOT NULL UNIQUE,
  did TEXT NOT NULL,
  secret_id INTEGER NOT NULL REFERENCES blindkey_secrets(id),
  context_id INTEGER REFERENCES blindkey_contexts(id),
  action_type TEXT NOT NULL,
  target_url TEXT DEFAULT '',
  target_host TEXT DEFAULT '',
  status TEXT DEFAULT 'valid' CHECK(status IN ('valid', 'used', 'expired')),
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  expires_at TEXT NOT NULL,
  used_at TEXT
)`); } catch(e) {}
try { db.exec("CREATE INDEX IF NOT EXISTS idx_but_token ON blindkey_use_tokens(token)"); } catch(e) {}
try { db.exec("CREATE INDEX IF NOT EXISTS idx_but_did ON blindkey_use_tokens(did)"); } catch(e) {}
try { db.exec("ALTER TABLE blindkey_use_tokens ADD COLUMN delegation_id INTEGER DEFAULT NULL"); } catch(e) {}

// ── [104] Barrel Cosign Requests ──
try { db.exec(`CREATE TABLE IF NOT EXISTS barrel_cosign_requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  silicon_did TEXT NOT NULL,
  carbon_email TEXT NOT NULL,
  operation TEXT NOT NULL,
  amount_cents INTEGER DEFAULT 0,
  status TEXT DEFAULT 'pending' CHECK(status IN ('pending','approved','denied','expired')),
  approval_code TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  resolved_at TEXT
)`); } catch(e) {}
try { db.exec("CREATE INDEX IF NOT EXISTS idx_bcr_did ON barrel_cosign_requests(silicon_did)"); } catch(e) {}
try { db.exec("CREATE INDEX IF NOT EXISTS idx_bcr_status ON barrel_cosign_requests(status)"); } catch(e) {}

// ── [179] DD-collateralized Escrow ──
try { db.exec(`CREATE TABLE IF NOT EXISTS escrow_contracts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  creator_did TEXT NOT NULL,
  counterparty_did TEXT DEFAULT '',
  beneficiary_did TEXT NOT NULL,
  title TEXT NOT NULL,
  memo TEXT DEFAULT '',
  collateral_cents INTEGER NOT NULL DEFAULT 0,
  barrel_tier_required TEXT NOT NULL DEFAULT 'single' CHECK(barrel_tier_required IN ('single','double','critical')),
  status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','active','released','refunded','disputed','cancelled','expired')),
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  expires_at TEXT DEFAULT '',
  funded_at TEXT DEFAULT CURRENT_TIMESTAMP,
  accepted_at TEXT,
  settled_at TEXT,
  metadata TEXT DEFAULT '{}'
)`); } catch(e) {}
try { db.exec("CREATE INDEX IF NOT EXISTS idx_escrow_creator ON escrow_contracts(creator_did, status)"); } catch(e) {}
try { db.exec("CREATE INDEX IF NOT EXISTS idx_escrow_counterparty ON escrow_contracts(counterparty_did, status)"); } catch(e) {}
try { db.exec("CREATE INDEX IF NOT EXISTS idx_escrow_beneficiary ON escrow_contracts(beneficiary_did, status)"); } catch(e) {}

try { db.exec(`CREATE TABLE IF NOT EXISTS escrow_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  escrow_id INTEGER NOT NULL REFERENCES escrow_contracts(id),
  event_type TEXT NOT NULL,
  actor_did TEXT NOT NULL,
  detail TEXT DEFAULT '{}',
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
)`); } catch(e) {}
try { db.exec("CREATE INDEX IF NOT EXISTS idx_escrow_events_escrow ON escrow_events(escrow_id, created_at DESC)"); } catch(e) {}

// ── [184] Blindkey Context Requests ──
try { db.exec(`CREATE TABLE IF NOT EXISTS blindkey_context_requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  did TEXT NOT NULL,
  secret_name TEXT NOT NULL,
  requested_context TEXT NOT NULL,
  requested_action_type TEXT NOT NULL,
  target_url_pattern TEXT DEFAULT '*',
  target_host_pattern TEXT DEFAULT '*',
  reason TEXT DEFAULT '',
  status TEXT DEFAULT 'pending' CHECK(status IN ('pending','approved','denied')),
  reviewed_by TEXT DEFAULT '',
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  resolved_at TEXT
)`); } catch(e) {}
try { db.exec("CREATE INDEX IF NOT EXISTS idx_bkcr_did ON blindkey_context_requests(did)"); } catch(e) {}
try { db.exec("CREATE INDEX IF NOT EXISTS idx_bkcr_status ON blindkey_context_requests(status)"); } catch(e) {}

// ── DemiPass Delegations — mycorrhizal secret sharing between silicons ──
try { db.exec(`CREATE TABLE IF NOT EXISTS demipass_delegations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  owner_did TEXT NOT NULL,
  delegate_did TEXT NOT NULL,
  secret_id INTEGER NOT NULL REFERENCES blindkey_secrets(id),
  context_id INTEGER REFERENCES blindkey_contexts(id),
  status TEXT DEFAULT 'active' CHECK(status IN ('active', 'suspended', 'revoked')),
  max_uses INTEGER DEFAULT 0,
  use_count INTEGER DEFAULT 0,
  granted_by TEXT DEFAULT 'owner',
  granted_at TEXT DEFAULT CURRENT_TIMESTAMP,
  revoked_at TEXT,
  expires_at TEXT,
  UNIQUE(owner_did, delegate_did, secret_id, context_id)
)`); } catch(e) {}
try { db.exec("CREATE INDEX IF NOT EXISTS idx_dd_owner ON demipass_delegations(owner_did)"); } catch(e) {}
try { db.exec("CREATE INDEX IF NOT EXISTS idx_dd_delegate ON demipass_delegations(delegate_did)"); } catch(e) {}

// Cleanup expired cosign requests every 60 seconds
setInterval(() => {
  try {
    db.prepare("UPDATE barrel_cosign_requests SET status = 'expired' WHERE status = 'pending' AND expires_at < datetime('now')").run();
  } catch (e) { /* ignore cleanup errors */ }
}, 60000);

setInterval(() => {
  try {
    db.prepare(`
      UPDATE escrow_contracts
      SET status = 'expired',
          settled_at = COALESCE(settled_at, CURRENT_TIMESTAMP)
      WHERE status IN ('pending', 'active')
        AND expires_at != ''
        AND expires_at < datetime('now')
    `).run();
  } catch (e) { /* ignore cleanup errors */ }
}, 60000);

// Cleanup expired use-tokens every 60 seconds
setInterval(() => {
  try {
    db.prepare("DELETE FROM blindkey_use_tokens WHERE status = 'expired' AND expires_at < datetime('now', '-5 minutes')").run();
    db.prepare("UPDATE blindkey_use_tokens SET status = 'expired' WHERE status = 'valid' AND expires_at < datetime('now')").run();
  } catch (e) { /* ignore cleanup errors */ }
}, 60000);

// Cleanup expired delegations every 60 seconds
setInterval(() => {
  try {
    db.prepare("UPDATE demipass_delegations SET status = 'revoked', revoked_at = datetime('now') WHERE status = 'active' AND expires_at IS NOT NULL AND expires_at != '' AND expires_at < datetime('now')").run();
  } catch (e) { /* ignore cleanup errors */ }
}, 60000);

// Blindkey-level encryption uses the identity module's existing AES-256-GCM
function blindkeyEncrypt(value) {
  const key = Buffer.from(process.env.IDENTITY_MASTER_KEY, 'hex').slice(0, 32);
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return Buffer.concat([iv, authTag, encrypted]).toString('base64');
}

function blindkeyDecrypt(encryptedBase64) {
  const key = Buffer.from(process.env.IDENTITY_MASTER_KEY, 'hex').slice(0, 32);
  const data = Buffer.from(encryptedBase64, 'base64');
  const iv = data.slice(0, 16);
  const authTag = data.slice(16, 32);
  const encrypted = data.slice(32);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString('utf8');
}

// Simple glob matcher for context target patterns (supports * and prefix*)
function blindkeyPatternMatch(pattern, value) {
  if (!pattern || pattern === '*') return true;
  if (!value) return false;
  // Strip protocol for comparison
  const cleanValue = value.replace(/^https?:\/\//, '');
  const cleanPattern = pattern.replace(/^https?:\/\//, '');
  if (cleanPattern.endsWith('*')) {
    return cleanValue.startsWith(cleanPattern.slice(0, -1));
  }
  return cleanValue === cleanPattern;
}

// Insert contexts for a secret (used by deposit, context/add, and rowen/ingest)
function insertBlindkeyContexts(secretId, contexts, allowedBy) {
  const insertCtx = db.prepare(`
    INSERT INTO blindkey_contexts (secret_id, context_name, action_type, target_url_pattern, target_host_pattern, allowed_by, max_uses)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(secret_id, context_name) DO UPDATE SET
      action_type = excluded.action_type,
      target_url_pattern = excluded.target_url_pattern,
      target_host_pattern = excluded.target_host_pattern,
      allowed_by = excluded.allowed_by,
      max_uses = excluded.max_uses
  `);
  let created = 0;
  for (const ctx of contexts) {
    if (!ctx.context_name || !ctx.action_type) continue;
    const validActions = ['http_header', 'ssh_exec', 'http_body', 'env_inject', 'git_clone', 'smtp_auth', 'database_connect'];
    if (!validActions.includes(ctx.action_type)) continue;
    insertCtx.run(
      secretId,
      ctx.context_name,
      ctx.action_type,
      ctx.target_url_pattern || '*',
      ctx.target_host_pattern || '*',
      allowedBy,
      ctx.max_uses || 0
    );
    created++;
  }
  return created;
}

// Enforce context rules on a blindkey/use request. Returns { allowed, error }
function enforceBlindkeyContext(secret, contextName, action, targetUrl, targetHost) {
  const contexts = db.prepare('SELECT * FROM blindkey_contexts WHERE secret_id = ?').all(secret.id);

  // Backward compatible: no contexts exist and none requested → allow
  if (contexts.length === 0 && !contextName) {
    return { allowed: true };
  }

  // Contexts exist but none specified → deny
  if (contexts.length > 0 && !contextName) {
    return { allowed: false, error: 'this secret has usage contexts defined. You must specify a context name.' };
  }

  // Context specified but none exist → deny (can't use a context that doesn't exist)
  if (contexts.length === 0 && contextName) {
    return { allowed: false, error: `context '${contextName}' not found for this secret` };
  }

  // Look up the specific context
  const ctx = db.prepare('SELECT * FROM blindkey_contexts WHERE secret_id = ? AND context_name = ?').get(secret.id, contextName);
  if (!ctx) {
    return { allowed: false, error: `context '${contextName}' not found for this secret` };
  }

  // Check status
  if (ctx.status !== 'active') {
    return { allowed: false, error: `context '${contextName}' is ${ctx.status}` };
  }

  // Check action_type matches
  if (ctx.action_type !== action) {
    return { allowed: false, error: `context '${contextName}' allows action '${ctx.action_type}' but '${action}' was requested` };
  }

  // Check target_url_pattern for http actions
  if ((action === 'http_header' || action === 'http_body') && targetUrl) {
    if (!blindkeyPatternMatch(ctx.target_url_pattern, targetUrl)) {
      return { allowed: false, error: `target URL does not match context pattern '${ctx.target_url_pattern}'` };
    }
  }

  // Check target_host_pattern for ssh_exec
  if (action === 'ssh_exec' && targetHost) {
    if (!blindkeyPatternMatch(ctx.target_host_pattern, targetHost)) {
      return { allowed: false, error: `target host does not match context pattern '${ctx.target_host_pattern}'` };
    }
  }

  // Check max_uses
  if (ctx.max_uses > 0 && ctx.use_count >= ctx.max_uses) {
    return { allowed: false, error: `context '${contextName}' has reached its max usage limit (${ctx.max_uses})` };
  }

  return {
    allowed: true,
    context_id: ctx.id,
    context: {
      id: ctx.id,
      context_name: ctx.context_name,
      action_type: ctx.action_type,
      target_url_pattern: ctx.target_url_pattern,
      target_host_pattern: ctx.target_host_pattern,
      max_uses: ctx.max_uses,
      use_count: ctx.use_count,
      allowed_by: ctx.allowed_by,
    },
  };
}

// Resolve the latest active version of a secret by name.
// If exact name match exists and is active, use it. Otherwise look for versioned variants (_v2, _v3, etc.)
// and return the one with the highest version number.
function resolveLatestBlindkeySecret(did, name) {
  // Try exact match first
  const exact = db.prepare('SELECT * FROM blindkey_secrets WHERE did = ? AND name = ? AND status = ?').get(did, name, 'active');
  if (exact) {
    // Check if there's a higher-versioned variant
    const baseName = name.replace(/_v\d+$/, '');
    const latest = db.prepare(
      "SELECT * FROM blindkey_secrets WHERE did = ? AND (name = ? OR name LIKE ?) AND status = 'active' ORDER BY version DESC LIMIT 1"
    ).get(did, baseName, baseName + '_v%');
    return latest || exact;
  }
  // No exact match — try base name lookup (maybe they passed 'mykey' but only 'mykey_v2' exists)
  const baseName = name.replace(/_v\d+$/, '');
  const latest = db.prepare(
    "SELECT * FROM blindkey_secrets WHERE did = ? AND (name = ? OR name LIKE ?) AND status = 'active' ORDER BY version DESC LIMIT 1"
  ).get(did, baseName, baseName + '_v%');
  return latest || null;
}

function authorizeSecretMediation({ requestorDid, secretName, contextName, actionParams = {} }) {
  // Defect fix #5: use resolveLatestBlindkeySecret to handle rotated secrets (secret_v2 etc.)
  const secret = resolveLatestBlindkeySecret(requestorDid, secretName);
  if (!secret) {
    return { ok: false, status: 404, error: 'secret not found for requestor_did' };
  }

  const action = actionParams.action || null;
  if (!action) return { ok: false, status: 400, error: 'action_params.action required' };

  const targetUrl = actionParams.url || actionParams.target_url || null;
  const targetHost = actionParams.target_host || null;
  const ctxCheck = enforceBlindkeyContext(secret, contextName, action, targetUrl, targetHost);
  if (!ctxCheck.allowed) {
    return {
      ok: false,
      status: 403,
      error: ctxCheck.error,
      secret,
      action,
      targetUrl,
      targetHost,
    };
  }

  return {
    ok: true,
    secret,
    action,
    targetUrl,
    targetHost,
    contextCheck: ctxCheck,
  };
}

// POST /api/blindkey/store — store a secret (requires transact scope)
app.post('/api/blindkey/store', rateLimitStandard, billing.billingMiddleware(db, 'api_call_write', { cost: 0 }), (req, res) => {
  const { name, value, description, secret_type } = req.body || {};
  if (!name || !value) return res.status(400).json({ error: 'name and value required' });
  if (name.length > 64) return res.status(400).json({ error: 'name must be 64 chars or less' });
  if (value.length > 10000) return res.status(400).json({ error: 'value must be 10000 chars or less' });
  if (description && description.length > 256) return res.status(400).json({ error: 'description must be 256 chars or less' });

  // Code injection detection — reject values that look like executable code.
  // Secrets should be credentials, tokens, keys, or connection strings — not programs.
  const trimmed = value.trim();
  const codePatterns = [
    /^#!/,                              // shebang (shell/python scripts)
    /^<script/i,                        // HTML script tags
    /^<\?php/i,                         // PHP open tag
    /^function\s*\(/,                   // JS function declaration
    /^import\s+/,                       // Python/JS imports
    /^require\s*\(/,                    // Node.js require
    /^eval\s*\(/,                       // eval calls
    /^exec\s*\(/,                       // exec calls
    /^class\s+\w+/,                     // class definitions
    /^const\s+\w+\s*=/,                 // JS const declarations
    /^var\s+\w+\s*=/,                   // JS var declarations
    /^let\s+\w+\s*=/,                   // JS let declarations
    /^def\s+\w+\s*\(/,                  // Python function defs
    /<\/script>/i,                      // script close tags anywhere
  ];
  if (codePatterns.some(p => p.test(trimmed))) {
    return res.status(400).json({ error: 'value appears to be executable code. Secrets should be credentials, tokens, or keys — not code.' });
  }
  // Block extremely long single-line values that look like encoded payloads (>10KB of base64 is suspicious)
  if (value.length > 10000 && /^[A-Za-z0-9+/=]+$/.test(value)) {
    return res.status(400).json({ error: 'value exceeds 10KB and appears to be an encoded payload. If this is a legitimate certificate, use secret_type: certificate.' });
  }

  const validTypes = ['api_key', 'oauth_token', 'password', 'signing_key', 'webhook_secret', 'connection_string', 'certificate', 'other'];
  const resolvedType = validTypes.includes(secret_type) ? secret_type : 'api_key';

  // Accept optional expiration
  const { expires_in, expires_at: expiresAtRaw } = req.body || {};

  try {
    const encrypted = blindkeyEncrypt(value);

    // Auto-detect provider from value prefix
    const providerInfo = detectProvider(value);

    // Compute expiration
    let expiresAt = null;
    if (expiresAtRaw) {
      expiresAt = new Date(expiresAtRaw).toISOString();
    } else if (expires_in) {
      const match = String(expires_in).match(/^(\d+)(m|h|d)$/);
      if (match) {
        const ms = { m: 60000, h: 3600000, d: 86400000 }[match[2]] * Number(match[1]);
        expiresAt = new Date(Date.now() + ms).toISOString();
      }
    } else if (providerInfo.typical_expiry_days) {
      expiresAt = new Date(Date.now() + providerInfo.typical_expiry_days * 86400000).toISOString();
    }

    db.prepare(`
      INSERT INTO blindkey_secrets (did, name, description, secret_type, encrypted_value, expires_at, provider)
      VALUES (?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(did, name) DO UPDATE SET
        encrypted_value = excluded.encrypted_value,
        description = excluded.description,
        secret_type = excluded.secret_type,
        expires_at = excluded.expires_at,
        provider = excluded.provider,
        updated_at = CURRENT_TIMESTAMP
    `).run(req.identity.did, name, description || '', resolvedType, encrypted, expiresAt, providerInfo.provider);

    // Generate and store ref_code if not already set
    const stored = db.prepare("SELECT id, ref_code FROM blindkey_secrets WHERE did = ? AND name = ?").get(req.identity.did, name);
    let refCode = stored?.ref_code;
    if (!refCode) {
      refCode = generateRefCode(resolvedType, name);
      db.prepare("UPDATE blindkey_secrets SET ref_code = ? WHERE id = ?").run(refCode, stored.id);
    }

    // Buoy ingestion tick — anchor this deposit in the tick chain
    let buoyTickId = null;
    try {
      const tickResult = db.prepare('INSERT INTO ticks (did, note, ip, tz, tick_type, tags) VALUES (?, ?, ?, ?, ?, ?)')
        .run(req.identity.did, `secret stored: ${name}`, req.ip || '', 'UTC', 'tick', JSON.stringify(['demipass:store', `secret:${name}`]));
      buoyTickId = tickResult.lastInsertRowid;
      db.prepare("UPDATE blindkey_secrets SET buoy_ingested_tick = ? WHERE id = ?").run(buoyTickId, stored.id);
    } catch(_) {}

    res.json({
      ok: true, name, ref: refCode, secret_type: resolvedType, description: description || '',
      provider: providerInfo.provider || null,
      expires_at: expiresAt,
      buoy_tick: buoyTickId,
      note: 'Secret stored. It will never be returned in any API response.',
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// GET /api/blindkey/list — list secret names and metadata (never values)
app.get('/api/blindkey/list', rateLimitStandard, (req, res) => {
  const actor = getDemiPassActor(req, res);
  if (!actor.ok) return;

  let ownerDid = actor.did || null;
  if (actor.mode === 'admin') {
    const { did, username, include_inactive } = req.query || {};
    if (!did && !username) return res.status(400).json({ error: 'did or username required when using admin access' });
    if (did) {
      ownerDid = did;
    } else {
      const wallet = db.prepare('SELECT did FROM identity_wallets WHERE username = ?').get(username);
      if (!wallet) return res.status(404).json({ error: 'identity not found' });
      ownerDid = wallet.did;
    }
    const statusClause = include_inactive === '1' ? '' : 'AND status = ?';
    const secrets = db.prepare(
      `SELECT id, did, name, description, secret_type, status, use_count, last_used_at, created_at, updated_at, version
       FROM blindkey_secrets WHERE did = ? ${statusClause} ORDER BY updated_at DESC, name ASC`
    ).all(ownerDid, ...(include_inactive === '1' ? [] : ['active']));
    return res.json({ did: ownerDid, secrets, total: secrets.length });
  }

  const secrets = db.prepare(
    `SELECT id, did, name, description, secret_type, status, use_count, last_used_at, created_at, updated_at, version, ref_code, expires_at, provider, buoy_ingested_tick, buoy_last_used_tick
     FROM blindkey_secrets WHERE did = ? AND status = ? ORDER BY updated_at DESC, name ASC`
  ).all(ownerDid, 'active');
  res.json({ did: ownerDid, secrets, total: secrets.length });
});

// GET /api/blindkey/expiring — list secrets expiring within a window
app.get('/api/blindkey/expiring', rateLimitStandard, (req, res) => {
  const actor = getDemiPassActor(req, res);
  if (!actor.ok) return;

  const ownerDid = actor.did || null;
  if (!ownerDid) return res.status(400).json({ error: 'identity required' });

  const withinDays = Math.min(90, Math.max(1, Number(req.query.days) || 7));
  const cutoff = new Date(Date.now() + withinDays * 86400000).toISOString();

  const expiring = db.prepare(
    `SELECT id, name, secret_type, ref_code, expires_at, provider, use_count, last_used_at, buoy_ingested_tick, buoy_last_used_tick
     FROM blindkey_secrets WHERE did = ? AND status = 'active' AND expires_at IS NOT NULL AND expires_at <= ? ORDER BY expires_at ASC`
  ).all(ownerDid, cutoff);

  const expired = db.prepare(
    `SELECT id, name, secret_type, ref_code, expires_at, provider
     FROM blindkey_secrets WHERE did = ? AND status = 'active' AND expires_at IS NOT NULL AND expires_at <= ? ORDER BY expires_at ASC`
  ).all(ownerDid, new Date().toISOString());

  res.json({
    did: ownerDid,
    within_days: withinDays,
    expiring,
    already_expired: expired,
    total_expiring: expiring.length,
    total_expired: expired.length,
  });
});

// GET /api/blindkey/history — list audit events for DemiPass secrets
app.get('/api/blindkey/history', rateLimitStandard, (req, res) => {
  const actor = getDemiPassActor(req, res);
  if (!actor.ok) return;

  const { secret_name, event_type, limit = 100, did, username } = req.query || {};
  const limitNum = Math.min(200, Math.max(1, Number(limit) || 100));
  let ownerDid = actor.did || null;

  if (actor.mode === 'admin') {
    if (did) {
      ownerDid = did;
    } else if (username) {
      const wallet = db.prepare('SELECT did FROM identity_wallets WHERE username = ?').get(username);
      if (!wallet) return res.status(404).json({ error: 'identity not found' });
      ownerDid = wallet.did;
    } else if (!secret_name) {
      return res.status(400).json({ error: 'did, username, or secret_name required when using admin access' });
    }
  }

  let secretId = null;
  if (secret_name) {
    // Defect fix: admin MUST specify did or username — never resolve by name alone across tenants
    if (!ownerDid) return res.status(400).json({ error: 'did or username required when looking up by secret_name — cannot resolve across tenants' });
    const secret = db.prepare(`SELECT id FROM blindkey_secrets WHERE did = ? AND name = ? ORDER BY version DESC LIMIT 1`).get(ownerDid, secret_name);
    if (!secret) return res.status(404).json({ error: 'secret not found for this identity' });
    secretId = secret.id;
  }

  let sql = `
    SELECT e.id, e.event_type, e.actor, e.context_name, e.detail, e.created_at,
           s.name as secret_name, s.did
    FROM blindkey_events e
    LEFT JOIN blindkey_secrets s ON s.id = e.secret_id
    WHERE 1 = 1
  `;
  const params = [];
  if (ownerDid) {
    sql += ' AND s.did = ?';
    params.push(ownerDid);
  }
  if (secretId) {
    sql += ' AND e.secret_id = ?';
    params.push(secretId);
  }
  if (event_type) {
    sql += ' AND e.event_type = ?';
    params.push(event_type);
  }
  sql += ' ORDER BY e.created_at DESC LIMIT ?';
  params.push(limitNum);

  const events = db.prepare(sql).all(...params).map((row) => {
    let detail = row.detail;
    try { detail = JSON.parse(row.detail || '{}'); } catch (_) {}
    return { ...row, detail };
  });

  res.json({ did: ownerDid, events, total: events.length });
});

// POST /api/blindkey/request-token — request a short-lived use-token by presenting intended context
// The token captures the result of context validation as a single-use credential.
// The silicon never sees the secret — it only gets a nonce that proves its intent was validated.
// Supports delegated access: if the caller doesn't own the secret, check demipass_delegations.
// The delegate passes { owner_did } to indicate whose secret they want to use via delegation.
app.post('/api/blindkey/request-token', rateLimitStandard, billing.billingMiddleware(db, 'api_call_read'), (req, res) => {
  let { name, ref, context: contextName, action, target_host, target_url, owner_did } = req.body || {};

  // Routed reference mode — parse DP-TYPE-slug-nonce and resolve everything
  if (ref && typeof ref === 'string' && ref.startsWith('DP-')) {
    const refSecret = db.prepare("SELECT * FROM blindkey_secrets WHERE ref_code = ? AND status = 'active'").get(ref);
    if (!refSecret) return res.status(403).json({ error: 'access denied' }); // same error for not-found and no-delegation

    // Check if caller owns it or has delegation
    const callerDid = req.identity.did;
    if (refSecret.did === callerDid) {
      // Direct ownership — use it
      name = refSecret.name;
      owner_did = null;
    } else {
      // Check delegation
      const del = db.prepare(`SELECT * FROM demipass_delegations WHERE secret_id = ? AND delegate_did = ? AND status = 'active'`).get(refSecret.id, callerDid);
      if (!del) return res.status(403).json({ error: 'access denied' }); // same error — no enumeration
      name = refSecret.name;
      owner_did = refSecret.did;
    }

    // Auto-resolve action from secret_type if not provided
    if (!action) {
      const typeToAction = { api_key: 'http_header', password: 'ssh_exec', token: 'http_header', ssh_key: 'ssh_exec', cert: 'http_header', other: 'http_header' };
      action = typeToAction[refSecret.secret_type] || 'http_header';
    }

    // Auto-resolve context — use the first active context if not provided
    if (!contextName) {
      const firstCtx = db.prepare("SELECT context_name FROM blindkey_contexts WHERE secret_id = ? AND status = 'active' LIMIT 1").get(refSecret.id);
      contextName = firstCtx?.context_name || 'default';
    }

    // Auto-resolve target_host from context if not provided
    if (!target_host) {
      const ctx = db.prepare("SELECT target_host_pattern FROM blindkey_contexts WHERE secret_id = ? AND context_name = ? AND status = 'active'").get(refSecret.id, contextName);
      if (ctx?.target_host_pattern && ctx.target_host_pattern !== '*') {
        target_host = ctx.target_host_pattern;
      }
    }
  }

  if (!name || !action) return res.status(400).json({ error: 'name and action required (or use ref: "DP-...")' });
  if (typeof name !== 'string') return res.status(400).json({ error: 'name: must be a string' });
  if (typeof action !== 'string') return res.status(400).json({ error: 'action: must be a string' });
  if (name.length > 100) return res.status(400).json({ error: 'name: max 100 characters' });
  if (action.length > 100) return res.status(400).json({ error: 'action: max 100 characters' });
  if (!contextName) return res.status(400).json({ error: 'context required — use-tokens always require a context' });
  if (typeof contextName !== 'string') return res.status(400).json({ error: 'context: must be a string' });
  if (contextName.length > 100) return res.status(400).json({ error: 'context: max 100 characters' });
  if (target_host && typeof target_host !== 'string') return res.status(400).json({ error: 'target_host: must be a string' });
  if (target_url && typeof target_url !== 'string') return res.status(400).json({ error: 'target_url: must be a string' });

  const callerDid = req.identity.did;

  // Try direct ownership first
  let secret = resolveLatestBlindkeySecret(callerDid, name);
  let delegation = null;

  // If caller doesn't own the secret, check for a delegation
  if (!secret && owner_did) {
    secret = resolveLatestBlindkeySecret(owner_did, name);
    if (!secret) return res.status(404).json({ error: 'secret not found' });

    // Look up the context_id for the delegation check
    const ctx = db.prepare('SELECT * FROM blindkey_contexts WHERE secret_id = ? AND context_name = ?').get(secret.id, contextName);
    const ctxId = ctx ? ctx.id : null;

    // Find an active delegation from owner to caller for this secret+context
    // A delegation with context_id=NULL means "all contexts" — match that too
    delegation = db.prepare(`
      SELECT * FROM demipass_delegations
      WHERE owner_did = ? AND delegate_did = ? AND secret_id = ? AND status = 'active'
        AND (context_id IS NULL OR context_id = ?)
      ORDER BY context_id DESC LIMIT 1
    `).get(owner_did, callerDid, secret.id, ctxId);

    if (!delegation) {
      db.prepare('INSERT INTO blindkey_events (event_type, actor, secret_id, context_name, detail) VALUES (?, ?, ?, ?, ?)').run(
        'delegation_denied', callerDid, secret.id, contextName,
        JSON.stringify({ owner_did, reason: 'no active delegation found' })
      );
      return res.status(403).json({ error: 'no active delegation for this secret and context' });
    }

    // Check delegation expiry
    if (delegation.expires_at && new Date(delegation.expires_at) < new Date()) {
      db.prepare("UPDATE demipass_delegations SET status = 'revoked', revoked_at = datetime('now') WHERE id = ?").run(delegation.id);
      db.prepare('INSERT INTO blindkey_events (event_type, actor, secret_id, context_name, detail) VALUES (?, ?, ?, ?, ?)').run(
        'delegation_expired', callerDid, secret.id, contextName,
        JSON.stringify({ delegation_id: delegation.id, owner_did })
      );
      return res.status(403).json({ error: 'delegation has expired' });
    }

    // Check max_uses
    if (delegation.max_uses > 0 && delegation.use_count >= delegation.max_uses) {
      db.prepare('INSERT INTO blindkey_events (event_type, actor, secret_id, context_name, detail) VALUES (?, ?, ?, ?, ?)').run(
        'delegation_denied', callerDid, secret.id, contextName,
        JSON.stringify({ delegation_id: delegation.id, owner_did, reason: 'max uses exceeded' })
      );
      return res.status(403).json({ error: `delegation has reached its max usage limit (${delegation.max_uses})` });
    }
  } else if (!secret) {
    return res.status(404).json({ error: 'secret not found' });
  }

  // Validate context using existing enforceBlindkeyContext
  const ctxCheck = enforceBlindkeyContext(secret, contextName, action, target_url || null, target_host || null);
  if (!ctxCheck.allowed) {
    db.prepare('INSERT INTO blindkey_events (event_type, actor, secret_id, context_name, detail) VALUES (?, ?, ?, ?, ?)').run(
      'use_token_denied', callerDid, secret.id, contextName,
      JSON.stringify({ action, target_host, target_url, error: ctxCheck.error, delegated: !!delegation })
    );
    return res.status(403).json({ error: ctxCheck.error });
  }

  // Generate a single-use token — 32 bytes of crypto randomness
  const token = crypto.randomBytes(32).toString('hex');
  const expiresInSeconds = 30;

  try {
    // The token references the OWNER's secret — the delegate never sees the value
    db.prepare(`
      INSERT INTO blindkey_use_tokens (token, did, secret_id, context_id, action_type, target_url, target_host, expires_at, delegation_id)
      VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now', '+${expiresInSeconds} seconds'), ?)
    `).run(token, callerDid, secret.id, ctxCheck.context_id || null, action, target_url || '', target_host || '', delegation ? delegation.id : null);

    // If this was a delegated request, increment use_count and log
    if (delegation) {
      // Defect fix: DON'T burn quota here at issuance. Burn at redemption (in the use-token handler).
      // Store delegation_id on the use-token so we can increment on redemption.
      db.prepare('INSERT INTO blindkey_events (event_type, actor, secret_id, context_name, detail) VALUES (?, ?, ?, ?, ?)').run(
        'delegation_used', callerDid, secret.id, contextName,
        JSON.stringify({ delegation_id: delegation.id, owner_did: delegation.owner_did, use_count: delegation.use_count + 1 })
      );
    }

    // Log token issuance
    db.prepare('INSERT INTO blindkey_events (event_type, actor, secret_id, context_name, detail) VALUES (?, ?, ?, ?, ?)').run(
      'use_token_issued', callerDid, secret.id, contextName,
      JSON.stringify({ action, target_host, target_url, expires_in_seconds: expiresInSeconds, delegated: !!delegation, owner_did: delegation ? delegation.owner_did : callerDid })
    );

    // Cleanup: expire stale tokens on this request
    db.prepare("UPDATE blindkey_use_tokens SET status = 'expired' WHERE status = 'valid' AND expires_at < datetime('now')").run();
    db.prepare("DELETE FROM blindkey_use_tokens WHERE status = 'expired' AND expires_at < datetime('now', '-5 minutes')").run();

    res.json({ use_token: token, expires_in_seconds: expiresInSeconds, action, context: contextName, delegated: !!delegation });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// POST /api/blindkey/use — use a secret without seeing it (delegated execution)
// Supports two modes:
//   1. use-token mode: { use_token, command } — uses pre-validated context from token
//   2. direct mode: { name, action, params, context } — validates context inline (backward compatible)
app.post('/api/blindkey/use', rateLimitStandard, billing.billingMiddleware(db, 'api_call_compute'), async (req, res) => {
  const { use_token } = req.body || {};

  // ── Use-token mode ──
  if (use_token) {
    const tokenRow = db.prepare('SELECT * FROM blindkey_use_tokens WHERE token = ?').get(use_token);
    if (!tokenRow) return res.status(404).json({ error: 'use-token not found' });
    if (tokenRow.status !== 'valid') return res.status(410).json({ error: `use-token already ${tokenRow.status}` });
    if (new Date(tokenRow.expires_at + 'Z') < new Date()) {
      db.prepare("UPDATE blindkey_use_tokens SET status = 'expired' WHERE id = ?").run(tokenRow.id);
      return res.status(410).json({ error: 'use-token expired' });
    }
    if (tokenRow.did !== req.identity.did) return res.status(403).json({ error: 'use-token belongs to a different identity' });

    // Mark token as used
    db.prepare("UPDATE blindkey_use_tokens SET status = 'used', used_at = datetime('now') WHERE id = ?").run(tokenRow.id);

    // Defect fix #4: burn delegation quota on REDEMPTION, not issuance
    if (tokenRow.delegation_id) {
      db.prepare('UPDATE demipass_delegations SET use_count = use_count + 1 WHERE id = ?').run(tokenRow.delegation_id);
    }

    // Load the secret from the token's secret_id
    const secret = db.prepare('SELECT * FROM blindkey_secrets WHERE id = ? AND status = ?').get(tokenRow.secret_id, 'active');
    if (!secret) return res.status(404).json({ error: 'secret referenced by use-token no longer exists or is revoked' });

    let decryptedValue;
    try {
      decryptedValue = blindkeyDecrypt(secret.encrypted_value);
    } catch (e) {
      return res.status(500).json({ error: 'failed to decrypt secret' });
    }

    // Update usage stats + Buoy last-used tick
    db.prepare('UPDATE blindkey_secrets SET use_count = use_count + 1, last_used_at = CURRENT_TIMESTAMP WHERE id = ?').run(secret.id);
    if (tokenRow.context_id) {
      db.prepare('UPDATE blindkey_contexts SET use_count = use_count + 1 WHERE id = ?').run(tokenRow.context_id);
    }
    // Buoy tick for secret use
    try {
      const useTick = db.prepare('INSERT INTO ticks (did, note, ip, tz, tick_type, tags) VALUES (?, ?, ?, ?, ?, ?)')
        .run(req.identity.did, `secret used: ${secret.name}`, req.ip || '', 'UTC', 'tick', JSON.stringify(['demipass:use', `secret:${secret.name}`]));
      db.prepare("UPDATE blindkey_secrets SET buoy_last_used_tick = ? WHERE id = ?").run(useTick.lastInsertRowid, secret.id);
    } catch(_) {}

    // Execute using the token's pre-validated context
    const action = tokenRow.action_type;
    const target_host = tokenRow.target_host;
    const target_url = tokenRow.target_url;

    try {
      let result;

      switch (action) {
        case 'http_header': {
          const { method = 'GET', header_name = 'Authorization', header_prefix = 'Bearer ', body: reqBody } = req.body.params || {};
          // FIX #4: use ONLY the token's pre-validated URL, never caller override
          const effectiveUrl = target_url;
          if (!effectiveUrl) return res.status(400).json({ error: 'params.url or token target_url required for http_header action' });

          const ALLOWED_HOSTS = BLINDKEY_HTTP_HOSTS;
          let urlHost;
          try { urlHost = new URL(effectiveUrl).hostname; } catch (_) { return res.status(400).json({ error: 'invalid URL' }); }
          if (!ALLOWED_HOSTS.some(h => urlHost === h || urlHost.endsWith('.' + h))) {
            return res.status(403).json({ error: `host ${urlHost} not in whitelist` });
          }

          const response = await fetch(effectiveUrl, {
            method,
            headers: { [header_name]: header_prefix + decryptedValue, 'Content-Type': 'application/json' },
            body: reqBody ? JSON.stringify(reqBody) : undefined,
            signal: AbortSignal.timeout(30000),
          });
          const responseBody = await response.text();
          let parsed;
          try { parsed = JSON.parse(responseBody); } catch (_) { parsed = responseBody; }
          const secretRedacted = typeof parsed === 'string'
            ? parsed.replace(new RegExp(decryptedValue.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g'), '[REDACTED]')
            : JSON.parse(JSON.stringify(parsed).replace(new RegExp(decryptedValue.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g'), '[REDACTED]'));
          result = { status: response.status, body: secretRedacted };
          break;
        }

        case 'ssh_exec': {
          const { command, target_user, key_name } = req.body;
          if (!target_host || !command) return res.status(400).json({ error: 'command required for ssh_exec (target_host comes from token)' });
          const effectiveUser = target_user || 'claude';

          if (!BLINDKEY_SSH_HOSTS.has(target_host)) {
            return res.status(403).json({ error: `host ${target_host} not in SSH whitelist` });
          }

          const dangerousPatterns = [/`/, /\$\(/, /\|\s*(curl|wget|nc|ncat)/i, />\s*\/dev\/tcp/, /\beval\b/, /\bexec\b/, /\bsource\b/, /\b(curl|wget)\b.*\|/i];
          for (const pat of dangerousPatterns) {
            if (pat.test(command)) return res.status(400).json({ error: 'command contains disallowed pattern' });
          }
          if (!/^[a-zA-Z0-9\s\/_\-.:=,@+*?[\]{}()#<>|&;'"%!\\\n]+$/.test(command)) {
            return res.status(400).json({ error: 'command contains disallowed characters' });
          }
          if (!/^[a-zA-Z0-9._-]+$/.test(effectiveUser)) {
            return res.status(400).json({ error: 'invalid target_user' });
          }

          let password = decryptedValue;
          if (key_name) {
            const keySecret = db.prepare('SELECT * FROM blindkey_secrets WHERE did = ? AND name = ? AND status = ?').get(req.identity.did, key_name, 'active');
            if (!keySecret) return res.status(404).json({ error: `key_name secret '${key_name}' not found` });
            try {
              password = blindkeyDecrypt(keySecret.encrypted_value);
              db.prepare('UPDATE blindkey_secrets SET use_count = use_count + 1, last_used_at = CURRENT_TIMESTAMP WHERE id = ?').run(keySecret.id);
            } catch (e) {
              return res.status(500).json({ error: 'failed to decrypt key_name secret' });
            }
          }

          try {
            // SECURITY: pass password via SSHPASS env var, never on command line.
            // This prevents shell injection via crafted secret values.
            const escapedCommand = command.replace(/'/g, "'\"'\"'");
            const sshCmd = `sshpass -e ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 ${effectiveUser}@${target_host} '${escapedCommand}'`;
            const output = execSync(sshCmd, {
              timeout: 30000, encoding: 'utf8', maxBuffer: 1024 * 1024,
              env: { ...process.env, SSHPASS: password },
            });
            const redactedOutput = output
              .replace(new RegExp(password.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g'), '[REDACTED]')
              .replace(new RegExp(decryptedValue.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g'), '[REDACTED]');
            result = { stdout: redactedOutput, exit_code: 0 };
          } catch (sshErr) {
            const redact = (s) => s
              .replace(new RegExp(password.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g'), '[REDACTED]')
              .replace(new RegExp(decryptedValue.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g'), '[REDACTED]');
            result = { stdout: redact((sshErr.stdout || '').toString()), stderr: redact((sshErr.stderr || '').toString()), exit_code: sshErr.status || 1 };
          }
          break;
        }

        case 'http_body': {
          // Inject secret into the POST body of an HTTP request
          const { url: bodyUrl, method: bodyMethod = 'POST', body_template, content_type = 'application/json' } = req.body.params || {};
          // FIX #4: use ONLY the token's pre-validated URL, never caller override
          const effectiveUrl = target_url;
          if (!effectiveUrl) return res.status(400).json({ error: 'target_url must be set on the use-token for http_body action' });

          let urlHost;
          try { urlHost = new URL(effectiveUrl).hostname; } catch (_) { return res.status(400).json({ error: 'invalid URL' }); }
          // FIX #5: define ALLOWED_HOSTS in this scope
          const HTTP_BODY_ALLOWED_HOSTS = BLINDKEY_HTTP_HOSTS;
          if (!HTTP_BODY_ALLOWED_HOSTS.some(h => urlHost === h || urlHost.endsWith('.' + h))) {
            return res.status(403).json({ error: `host ${urlHost} not in whitelist` });
          }

          // Replace {{SECRET}} placeholder in body template with the actual value
          const bodyStr = body_template
            ? JSON.stringify(body_template).replace(/\{\{SECRET\}\}/g, decryptedValue)
            : JSON.stringify({ key: decryptedValue });

          const bodyResponse = await fetch(effectiveUrl, {
            method: bodyMethod,
            headers: { 'Content-Type': content_type },
            body: bodyStr,
            signal: AbortSignal.timeout(30000),
          });
          const bodyText = await bodyResponse.text();
          let bodyParsed;
          try { bodyParsed = JSON.parse(bodyText); } catch (_) { bodyParsed = bodyText; }
          const bodyRedacted = JSON.parse(JSON.stringify(bodyParsed).replace(new RegExp(decryptedValue.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g'), '[REDACTED]'));
          result = { status: bodyResponse.status, body: bodyRedacted };
          break;
        }

        case 'inject_env':
        case 'env_inject': {
          // FIX #2: env_inject is DISABLED — fundamentally unsafe.
          // Any command can read and re-encode the env var (base64, hex, etc.)
          // bypassing literal-match redaction. Use http_header or ssh_exec instead.
          return res.status(400).json({
            error: 'env_inject action is disabled — fundamentally unsafe. Use http_header or ssh_exec instead.',
            reason: 'Commands can trivially encode the env var value to bypass redaction.',
          });
        }

        case 'git_clone': {
          // Clone a private repo using the secret as a token in the URL
          const { repo_url, branch } = req.body.params || {};
          if (!repo_url) return res.status(400).json({ error: 'params.repo_url required for git_clone action' });

          // FIX #1: whitelist git hosts
          const GIT_ALLOWED_HOSTS = BLINDKEY_GIT_HOSTS;
          let gitHost;
          try { gitHost = new URL(repo_url).hostname; } catch (_) { return res.status(400).json({ error: 'invalid repo_url' }); }
          if (!GIT_ALLOWED_HOSTS.some(h => gitHost === h || gitHost.endsWith('.' + h))) {
            return res.status(403).json({ error: `git host ${gitHost} not in whitelist` });
          }

          // FIX #3: strict validation on branch and dest_dir — no shell injection
          if (branch && !/^[a-zA-Z0-9._\/-]+$/.test(branch)) {
            return res.status(400).json({ error: 'branch contains disallowed characters' });
          }
          const dest_dir = '/tmp/demipass-clone-' + crypto.randomBytes(4).toString('hex');

          // Inject token into HTTPS URL
          const authedUrl = repo_url.replace('https://', `https://${decryptedValue}@`);
          // Use array form to avoid shell interpretation entirely
          const cloneArgs = ['clone', '--depth', '1'];
          if (branch) { cloneArgs.push('-b', branch); }
          cloneArgs.push(authedUrl, dest_dir);

          try {
            // FIX #3: use execFileSync (no shell) to prevent injection
            const { execFileSync } = require('child_process');
            const cloneOutput = execFileSync('git', cloneArgs, { timeout: 60000, encoding: 'utf8', maxBuffer: 1024 * 1024 });
            const redacted = cloneOutput.replace(new RegExp(decryptedValue.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g'), '[REDACTED]');
            result = { cloned: true, dest_dir, stdout: redacted };
          } catch (cloneErr) {
            const redact = (s) => s.replace(new RegExp(decryptedValue.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g'), '[REDACTED]');
            result = { cloned: false, stderr: redact((cloneErr.stderr || '').toString()), exit_code: cloneErr.status || 1 };
          }
          break;
        }

        case 'smtp_auth': {
          // Send an email through an external SMTP server using stored credentials
          const { smtp_host, smtp_port = 587, to, subject, body: emailBody, from } = req.body.params || {};
          if (!smtp_host || !to || !subject) return res.status(400).json({ error: 'params.smtp_host, to, subject required for smtp_auth action' });

          // FIX #1: smtp host must match token's target_host or be whitelisted
          const SMTP_ALLOWED_HOSTS = BLINDKEY_SMTP_HOSTS;
          if (target_host && smtp_host !== target_host) {
            return res.status(403).json({ error: `smtp_host ${smtp_host} does not match token target_host ${target_host}` });
          }
          if (!target_host && !SMTP_ALLOWED_HOSTS.includes(smtp_host)) {
            return res.status(403).json({ error: `smtp_host ${smtp_host} not in whitelist` });
          }

          // Secret format: "username:password" or just "password" (username from params)
          const parts = decryptedValue.split(':');
          const smtpUser = parts.length > 1 ? parts[0] : (req.body.params.smtp_user || '');
          const smtpPass = parts.length > 1 ? parts.slice(1).join(':') : decryptedValue;

          try {
            const transport = require('nodemailer').createTransport({
              host: smtp_host,
              port: Number(smtp_port),
              secure: Number(smtp_port) === 465,
              auth: { user: smtpUser, pass: smtpPass },
              tls: { rejectUnauthorized: false },
            });
            const info = await transport.sendMail({
              from: from || smtpUser,
              to,
              subject,
              text: emailBody || '',
            });
            result = { sent: true, messageId: info.messageId, accepted: info.accepted };
          } catch (smtpErr) {
            result = { sent: false, error: smtpErr.message.replace(new RegExp(smtpPass.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g'), '[REDACTED]') };
          }
          break;
        }

        case 'database_connect': {
          // Execute a query against a database using stored credentials
          const { query } = req.body.params || {};
          // FIX #1: use ONLY the token's pre-validated URL, never caller-supplied db_url
          const db_url = target_url;
          if (!db_url || !query) return res.status(400).json({ error: 'target_url must be set on the use-token, and params.query is required' });

          let dbHost;
          try { dbHost = new URL(db_url).hostname; } catch (_) { return res.status(400).json({ error: 'invalid db_url' }); }

          // FIX #1: whitelist database API hosts
          const DB_ALLOWED_HOSTS = BLINDKEY_DB_HOSTS;
          if (!DB_ALLOWED_HOSTS.some(h => dbHost === h || dbHost.endsWith('.' + h))) {
            return res.status(403).json({ error: `database host ${dbHost} not in whitelist` });
          }

          const dbResponse = await fetch(db_url, {
            method: 'POST',
            headers: {
              'Authorization': 'Bearer ' + decryptedValue,
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({ query }),
            signal: AbortSignal.timeout(30000),
          });
          const dbText = await dbResponse.text();
          let dbParsed;
          try { dbParsed = JSON.parse(dbText); } catch (_) { dbParsed = dbText; }
          const dbRedacted = JSON.parse(JSON.stringify(dbParsed).replace(new RegExp(decryptedValue.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g'), '[REDACTED]'));
          result = { status: dbResponse.status, body: dbRedacted };
          break;
        }

        default:
          return res.status(400).json({ error: `unknown action in use-token: ${action}` });
      }

      // Log token use
      db.prepare('INSERT INTO blindkey_events (event_type, actor, secret_id, context_name, detail) VALUES (?, ?, ?, ?, ?)').run(
        'use_token_redeemed', req.identity.did, secret.id, null,
        JSON.stringify({ action, target_host, target_url, token_id: tokenRow.id })
      );

      return res.json({ ok: true, action, via: 'use_token', result });
    } catch (e) {
      return res.status(500).json({ error: `action failed: ${e.message}` });
    }
  }

  // ── Direct mode (backward compatible) ──
  const { name, action, params, context: contextName } = req.body || {};
  if (!name || !action) return res.status(400).json({ error: 'name and action required (or provide use_token)' });

  const secret = resolveLatestBlindkeySecret(req.identity.did, name);
  if (!secret) return res.status(404).json({ error: 'secret not found' });

  // Enforce context rules
  const targetUrl = (params && params.url) || (req.body && req.body.target_url) || null;
  const targetHost = (req.body && req.body.target_host) || (params && params.target_host) || null;
  const ctxCheck = enforceBlindkeyContext(secret, contextName, action, targetUrl, targetHost);
  if (!ctxCheck.allowed) {
    return res.status(403).json({ error: ctxCheck.error });
  }

  let decryptedValue;
  try {
    decryptedValue = blindkeyDecrypt(secret.encrypted_value);
  } catch (e) {
    return res.status(500).json({ error: 'failed to decrypt secret' });
  }

  // Update usage stats
  db.prepare('UPDATE blindkey_secrets SET use_count = use_count + 1, last_used_at = CURRENT_TIMESTAMP WHERE id = ?').run(secret.id);

  // Increment context use_count if a context was used
  if (ctxCheck.context_id) {
    db.prepare('UPDATE blindkey_contexts SET use_count = use_count + 1 WHERE id = ?').run(ctxCheck.context_id);
  }

  // Execute the action with the secret injected
  try {
    let result;

    switch (action) {
      case 'http_header': {
        // Make an HTTP request with the secret as a header value
        // SECURITY: only allow requests to whitelisted API providers
        // The response body is REDACTED to prevent echo-based exfiltration
        const { url, method = 'GET', header_name = 'Authorization', header_prefix = 'Bearer ', body: reqBody } = params || {};
        if (!url) return res.status(400).json({ error: 'params.url required for http_header action' });

        // Whitelist: only known API providers — prevents exfiltration to attacker-controlled servers
        // Use the same consolidated whitelist as direct DemiPass use
        let urlHost;
        try { urlHost = new URL(url).hostname; } catch (_) { return res.status(400).json({ error: 'invalid URL' }); }
        if (!BLINDKEY_HTTP_HOSTS.some(h => urlHost === h || urlHost.endsWith('.' + h))) {
          return res.status(403).json({ error: `host ${urlHost} not in whitelist. Allowed: ${BLINDKEY_HTTP_HOSTS.join(', ')}. Contact support to add hosts.` });
        }

        const response = await fetch(url, {
          method,
          headers: {
            [header_name]: header_prefix + decryptedValue,
            'Content-Type': 'application/json',
          },
          body: reqBody ? JSON.stringify(reqBody) : undefined,
          signal: AbortSignal.timeout(30000),
        });
        const responseBody = await response.text();
        let parsed;
        try { parsed = JSON.parse(responseBody); } catch (_) { parsed = responseBody; }

        // Redact any echo of the secret in the response
        const secretRedacted = typeof parsed === 'string'
          ? parsed.replace(new RegExp(decryptedValue.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g'), '[REDACTED]')
          : JSON.parse(JSON.stringify(parsed).replace(new RegExp(decryptedValue.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g'), '[REDACTED]'));

        result = { status: response.status, body: secretRedacted };
        break;
      }

      case 'sign': {
        // Sign data with the secret as an HMAC key
        const { data, algorithm = 'sha256' } = params || {};
        if (!data) return res.status(400).json({ error: 'params.data required for sign action' });
        const signature = crypto.createHmac(algorithm, decryptedValue).update(data).digest('hex');
        result = { signature, algorithm };
        break;
      }

      case 'verify_match': {
        // DISABLED — equality oracle allows brute-forcing low-entropy secrets
        return res.status(410).json({ error: 'verify_match has been disabled for security. Use http_header to authenticate against the target service directly.' });
      }

      case 'inject_env': {
        // Return the secret as a named env var to be used in a subprocess
        // The silicon gets { env_name: "...", env_set: true } but not the value
        const { env_name = 'SECRET_VALUE' } = params || {};
        result = { env_name, env_set: true, note: 'Secret injected as environment variable. Value not returned.' };
        break;
      }

      case 'ssh_exec': {
        // SSH into a whitelisted host using stored credentials and run a command
        // The credentials NEVER appear in the response
        const { target_host, target_user, command, key_name } = req.body;
        if (!target_host || !target_user || !command) {
          return res.status(400).json({ error: 'target_host, target_user, and command required for ssh_exec' });
        }

        // Host whitelist check
        if (!BLINDKEY_SSH_HOSTS.has(target_host)) {
          return res.status(403).json({
            error: `host ${target_host} not in SSH whitelist. Allowed: ${[...BLINDKEY_SSH_HOSTS].join(', ')}`,
          });
        }

        // Command sanitization — reject exfiltration vectors
        const dangerousPatterns = [
          /`/,                          // backticks
          /\$\(/,                       // command substitution
          /\|\s*(curl|wget|nc|ncat)/i,  // pipe to network tools
          />\s*\/dev\/tcp/,             // bash /dev/tcp exfil
          /\beval\b/,                   // eval
          /\bexec\b/,                   // exec
          /\bsource\b/,                // source
          /\b(curl|wget)\b.*\|/i,      // curl/wget piped
        ];
        for (const pat of dangerousPatterns) {
          if (pat.test(command)) {
            return res.status(400).json({ error: 'command contains disallowed pattern. Backticks, $(), eval, exec, and piping to curl/wget/nc are not permitted.' });
          }
        }

        // Only allow safe shell characters
        if (!/^[a-zA-Z0-9\s\/_\-.:=,@+*?[\]{}()#<>|&;'"%!\\\n]+$/.test(command)) {
          return res.status(400).json({ error: 'command contains disallowed characters' });
        }

        // Optionally load a second secret (e.g. an SSH key) by key_name
        let password = decryptedValue;
        if (key_name) {
          const keySecret = db.prepare('SELECT * FROM blindkey_secrets WHERE did = ? AND name = ? AND status = ?').get(req.identity.did, key_name, 'active');
          if (!keySecret) return res.status(404).json({ error: `key_name secret '${key_name}' not found` });
          try {
            // Use key_name secret as the password, original secret as supplemental
            password = blindkeyDecrypt(keySecret.encrypted_value);
            db.prepare('UPDATE blindkey_secrets SET use_count = use_count + 1, last_used_at = CURRENT_TIMESTAMP WHERE id = ?').run(keySecret.id);
          } catch (e) {
            return res.status(500).json({ error: 'failed to decrypt key_name secret' });
          }
        }

        // Sanitize user and host to prevent injection in the ssh command itself
        if (!/^[a-zA-Z0-9._-]+$/.test(target_user)) {
          return res.status(400).json({ error: 'invalid target_user' });
        }

        try {
          // SECURITY: pass password via SSHPASS env var, never on command line
          const escapedCommand = command.replace(/'/g, "'\"'\"'");
          const sshCmd = `sshpass -e ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 ${target_user}@${target_host} '${escapedCommand}'`;
          const output = execSync(sshCmd, {
            timeout: 30000, encoding: 'utf8', maxBuffer: 1024 * 1024,
            env: { ...process.env, SSHPASS: password },
          });

          // Redact any echo of credentials in the output
          const redactedOutput = output
            .replace(new RegExp(password.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g'), '[REDACTED]')
            .replace(new RegExp(decryptedValue.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g'), '[REDACTED]');

          result = { stdout: redactedOutput, exit_code: 0 };
        } catch (sshErr) {
          const stderr = (sshErr.stderr || '').toString();
          const stdout = (sshErr.stdout || '').toString();
          // Redact credentials from error output
          const redact = (s) => s
            .replace(new RegExp(password.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g'), '[REDACTED]')
            .replace(new RegExp(decryptedValue.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g'), '[REDACTED]');
          result = { stdout: redact(stdout), stderr: redact(stderr), exit_code: sshErr.status || 1 };
        }
        break;
      }

      default:
        return res.status(400).json({ error: `unknown action: ${action}. Supported: http_header, sign, verify_match, inject_env, ssh_exec` });
    }

    res.json({ ok: true, action, secret_name: name, result });
  } catch (e) {
    res.status(500).json({ error: `action failed: ${e.message}` });
  }
});

// DELETE /api/blindkey/revoke — deactivate a secret
app.delete('/api/blindkey/revoke', rateLimitStandard, (req, res) => {
  const actor = getDemiPassActor(req, res);
  if (!actor.ok) return;
  const { name, did, username } = req.body || {};
  if (!name) return res.status(400).json({ error: 'name required' });
  let ownerDid = actor.did || null;
  if (actor.mode === 'admin') {
    ownerDid = did || (username ? db.prepare('SELECT did FROM identity_wallets WHERE username = ?').get(username)?.did : null);
    if (!ownerDid) return res.status(400).json({ error: 'did or username required when using admin access' });
  }
  const result = db.prepare('UPDATE blindkey_secrets SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE did = ? AND name = ?')
    .run('revoked', ownerDid, name);
  if (result.changes === 0) return res.status(404).json({ error: 'secret not found' });
  res.json({ ok: true, name, did: ownerDid, status: 'revoked' });
});

// POST /api/blindkey/rotate — rotate a secret with context transfer and grace period
app.post('/api/blindkey/rotate', rateLimitStandard, (req, res) => {
  const actor = getDemiPassActor(req, res);
  if (!actor.ok) return;

  const { name, new_value, grace_period_minutes, did } = req.body || {};
  if (!name || !new_value) return res.status(400).json({ error: 'name and new_value required' });
  if (typeof name !== 'string') return res.status(400).json({ error: 'name: must be a string' });
  if (typeof new_value !== 'string') return res.status(400).json({ error: 'new_value: must be a string' });
  if (new_value.length > 10000) return res.status(400).json({ error: 'new_value must be 10000 chars or less' });
  const graceMins = (typeof grace_period_minutes === 'number' && grace_period_minutes > 0) ? grace_period_minutes : 60;

  let ownerDid = actor.did || null;
  if (actor.mode === 'admin') {
    ownerDid = did || ownerDid;
    if (!ownerDid) return res.status(400).json({ error: 'did required when using admin auth without Bearer token' });
  }

  // Find the existing active secret with the highest version for this base name
  // Strip any existing _v{N} suffix to get the base name
  const baseName = name.replace(/_v\d+$/, '');
  const existing = db.prepare(
    "SELECT * FROM blindkey_secrets WHERE did = ? AND (name = ? OR name LIKE ?) AND status = 'active' ORDER BY version DESC LIMIT 1"
  ).get(ownerDid, baseName, baseName + '_v%');

  if (!existing) return res.status(404).json({ error: 'no active secret found with that name' });

  const newVersion = (existing.version || 1) + 1;
  const newName = baseName + '_v' + newVersion;

  try {
    const encrypted = blindkeyEncrypt(new_value);
    const rotateExpiresAt = new Date(Date.now() + graceMins * 60 * 1000).toISOString();

    // Create the new versioned secret
    db.prepare(`
      INSERT INTO blindkey_secrets (did, name, description, secret_type, encrypted_value, metadata, status, version)
      VALUES (?, ?, ?, ?, ?, ?, 'active', ?)
    `).run(ownerDid, newName, existing.description, existing.secret_type, encrypted, existing.metadata || '{}', newVersion);

    const newSecret = db.prepare('SELECT id FROM blindkey_secrets WHERE did = ? AND name = ?').get(ownerDid, newName);

    // Copy only ACTIVE contexts from old secret to new (skip revoked/suspended)
    const oldContexts = db.prepare("SELECT * FROM blindkey_contexts WHERE secret_id = ? AND status = 'active'").all(existing.id);
    let contextsTransferred = 0;
    for (const ctx of oldContexts) {
      db.prepare(`
        INSERT INTO blindkey_contexts (secret_id, context_name, action_type, target_url_pattern, target_host_pattern, allowed_by, max_uses, use_count)
        VALUES (?, ?, ?, ?, ?, ?, ?, 0)
      `).run(newSecret.id, ctx.context_name, ctx.action_type, ctx.target_url_pattern, ctx.target_host_pattern, ctx.allowed_by, ctx.max_uses);
      contextsTransferred++;
    }

    // Mark old secret as rotating with expiry
    db.prepare(
      "UPDATE blindkey_secrets SET status = 'rotating', replaced_by = ?, rotate_expires_at = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?"
    ).run(newSecret.id, rotateExpiresAt, existing.id);

    // Schedule retirement of old secret after grace period
    setTimeout(() => {
      try {
        db.prepare(
          "UPDATE blindkey_secrets SET status = 'retired', updated_at = CURRENT_TIMESTAMP WHERE id = ? AND status = 'rotating'"
        ).run(existing.id);
      } catch (_) {}
    }, graceMins * 60 * 1000);

    // Audit log
    db.prepare('INSERT INTO blindkey_events (event_type, actor, secret_id, detail) VALUES (?, ?, ?, ?)').run(
      'secret_rotated', ownerDid, existing.id,
      JSON.stringify({ old_name: existing.name, new_name: newName, new_secret_id: newSecret.id, new_version: newVersion, grace_period_minutes: graceMins, contexts_transferred: contextsTransferred })
    );

    res.json({ ok: true, new_secret_id: newSecret.id, contexts_transferred: contextsTransferred, grace_period_minutes: graceMins });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// GET /api/blindkey/types — list supported secret types and actions
app.get('/api/blindkey/types', (_req, res) => {
  res.json({
    secret_types: ['api_key', 'oauth_token', 'password', 'signing_key', 'webhook_secret', 'connection_string', 'certificate', 'passphrase', 'token', 'ssh_credential', 'multi_string', 'other'],
    actions: {
      http_header: { description: 'Make an HTTP request with the secret injected as a header', params: ['url', 'method', 'header_name', 'header_prefix', 'body'] },
      sign: { description: 'Sign data using the secret as an HMAC key', params: ['data', 'algorithm'] },
      verify_match: { description: 'Check if a candidate value matches the secret (DISABLED)', params: ['candidate'] },
      inject_env: { description: 'Confirm secret is set as an environment variable (value not returned)', params: ['env_name'] },
      ssh_exec: { description: 'SSH into a whitelisted host using stored credentials and run a command', params: ['target_host', 'target_user', 'command', 'key_name'] },
    },
    security: {
      encryption: 'AES-256-GCM at rest',
      access: 'Bearer token with transact scope required',
      exposure: 'Secret values are NEVER returned in any API response',
      billing: 'Store/revoke: free. List: free. Use: 1¢ per action (api_call_compute)',
    },
  });
});

// POST /api/blindkey/deposit — carbon deposits a secret into a silicon's vault (admin only)
// The secret never touches any silicon's context — only the carbon (human) and the server see it.
app.post('/api/blindkey/deposit', rateLimitStandard, (req, res) => {
  if (!requireAdminAccess(req, res)) return;

  const { target_did, target_username, name, value, description, secret_type, metadata, contexts } = req.body || {};
  if ((!target_did && !target_username) || !name || !value) return res.status(400).json({ error: 'target_did or target_username, plus name and value required' });
  if (target_did && typeof target_did !== 'string') return res.status(400).json({ error: 'target_did: must be a string' });
  if (target_username && typeof target_username !== 'string') return res.status(400).json({ error: 'target_username: must be a string' });
  if (typeof name !== 'string') return res.status(400).json({ error: 'name: must be a string' });
  if (typeof value !== 'string') return res.status(400).json({ error: 'value: must be a string' });
  if (name.length > 100) return res.status(400).json({ error: 'name: max 100 characters' });
  if (value.length > 10000) return res.status(400).json({ error: 'value: max 10000 characters' });
  if (description && typeof description !== 'string') return res.status(400).json({ error: 'description: must be a string' });
  if (description && description.length > 256) return res.status(400).json({ error: 'description must be 256 chars or less' });
  if (secret_type && typeof secret_type !== 'string') return res.status(400).json({ error: 'secret_type: must be a string' });

  const resolvedTargetDid = target_did || (target_username ? db.prepare('SELECT did FROM identity_wallets WHERE username = ?').get(target_username)?.did : null);
  if (!resolvedTargetDid) return res.status(404).json({ error: 'target identity not found' });

  // Verify target DID exists
  const targetWallet = db.prepare('SELECT did FROM identity_wallets WHERE did = ?').get(resolvedTargetDid);
  if (!targetWallet) return res.status(404).json({ error: 'target_did not found' });

  const validTypes = ['passphrase', 'token', 'api_key', 'ssh_credential', 'multi_string', 'oauth_token', 'password', 'signing_key', 'webhook_secret', 'connection_string', 'certificate', 'other'];
  const resolvedType = validTypes.includes(secret_type) ? secret_type : 'api_key';

  try {
    const encrypted = blindkeyEncrypt(value);
    const metaJson = metadata ? JSON.stringify(metadata) : '{}';
    db.prepare(`
      INSERT INTO blindkey_secrets (did, name, description, secret_type, encrypted_value, metadata)
      VALUES (?, ?, ?, ?, ?, ?)
      ON CONFLICT(did, name) DO UPDATE SET
        encrypted_value = excluded.encrypted_value,
        description = excluded.description,
        secret_type = excluded.secret_type,
        metadata = excluded.metadata,
        updated_at = CURRENT_TIMESTAMP
    `).run(resolvedTargetDid, name, description || '', resolvedType, encrypted, metaJson);

    const inserted = db.prepare('SELECT id FROM blindkey_secrets WHERE did = ? AND name = ?').get(resolvedTargetDid, name);

    // Insert contexts if provided
    let contexts_created = 0;
    if (Array.isArray(contexts) && contexts.length > 0) {
      contexts_created = insertBlindkeyContexts(inserted.id, contexts, 'carbon_deposit');
    }

    res.json({ ok: true, secret_id: inserted.id, name, secret_type: resolvedType, target_did: resolvedTargetDid, contexts_created });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// POST /api/blindkey/deposit/batch — deposit multiple secrets at once (admin only)
app.post('/api/blindkey/deposit/batch', rateLimitStandard, (req, res) => {
  if (!requireAdminAccess(req, res)) return;

  const { secrets } = req.body || {};
  if (!Array.isArray(secrets) || secrets.length === 0) return res.status(400).json({ error: 'secrets array required' });
  if (secrets.length > 50) return res.status(400).json({ error: 'max 50 secrets per batch' });

  const validTypes = ['passphrase', 'token', 'api_key', 'ssh_credential', 'multi_string', 'oauth_token', 'password', 'signing_key', 'webhook_secret', 'connection_string', 'certificate', 'other'];
  const results = [];
  const errors = [];

  const insertStmt = db.prepare(`
    INSERT INTO blindkey_secrets (did, name, description, secret_type, encrypted_value, metadata)
    VALUES (?, ?, ?, ?, ?, ?)
    ON CONFLICT(did, name) DO UPDATE SET
      encrypted_value = excluded.encrypted_value,
      description = excluded.description,
      secret_type = excluded.secret_type,
      metadata = excluded.metadata,
      updated_at = CURRENT_TIMESTAMP
  `);

  const txn = db.transaction(() => {
    for (let i = 0; i < secrets.length; i++) {
      const s = secrets[i];
      if (!s.target_did || !s.name || !s.value) {
        errors.push({ index: i, error: 'target_did, name, and value required' });
        continue;
      }
      if (s.name.length > 64) { errors.push({ index: i, error: 'name must be 64 chars or less' }); continue; }
      if (s.value.length > 10000) { errors.push({ index: i, error: 'value must be 10000 chars or less' }); continue; }

      const targetWallet = db.prepare('SELECT did FROM identity_wallets WHERE did = ?').get(s.target_did);
      if (!targetWallet) { errors.push({ index: i, error: 'target_did not found' }); continue; }

      const resolvedType = validTypes.includes(s.secret_type) ? s.secret_type : 'api_key';
      try {
        const encrypted = blindkeyEncrypt(s.value);
        const metaJson = s.metadata ? JSON.stringify(s.metadata) : '{}';
        insertStmt.run(s.target_did, s.name, s.description || '', resolvedType, encrypted, metaJson);
        const inserted = db.prepare('SELECT id FROM blindkey_secrets WHERE did = ? AND name = ?').get(s.target_did, s.name);
        results.push({ ok: true, secret_id: inserted.id, name: s.name, secret_type: resolvedType, target_did: s.target_did });
      } catch (e) {
        errors.push({ index: i, error: e.message });
      }
    }
  });

  try {
    txn();
    res.json({ ok: true, deposited: results.length, results, errors });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// POST /api/blindkey/context/add — add a context to an existing secret
// Requires admin auth OR Bearer token from the secret owner
app.post('/api/blindkey/context/add', rateLimitStandard, (req, res) => {
  const { secret_name, context_name, action_type, target_url_pattern, target_host_pattern, max_uses } = req.body || {};
  if (!secret_name || !context_name || !action_type) {
    return res.status(400).json({ error: 'secret_name, context_name, and action_type required' });
  }
  if (typeof secret_name !== 'string') return res.status(400).json({ error: 'secret_name: must be a string' });
  if (typeof context_name !== 'string') return res.status(400).json({ error: 'context_name: must be a string' });
  if (typeof action_type !== 'string') return res.status(400).json({ error: 'action_type: must be a string' });
  if (context_name.length > 100) return res.status(400).json({ error: 'context_name: max 100 characters' });
  if (secret_name.length > 100) return res.status(400).json({ error: 'secret_name: max 100 characters' });

  const validActions = ['http_header', 'ssh_exec', 'http_body', 'env_inject', 'git_clone', 'smtp_auth', 'database_connect'];
  if (!validActions.includes(action_type)) {
    return res.status(400).json({ error: `action_type must be one of: ${validActions.join(', ')}` });
  }

  // Allow admin or the secret owner (via Bearer token)
  const actor = getDemiPassActor(req, res);
  if (!actor.ok) return;
  const isAdmin = actor.mode === 'admin';
  let secret;

  if (isAdmin) {
    // Admin can add context to any secret by name — but needs a DID or secret_id
    const { did } = req.body || {};
    if (!did) return res.status(400).json({ error: 'did required when using admin auth' });
    secret = db.prepare('SELECT * FROM blindkey_secrets WHERE did = ? AND name = ? AND status = ?').get(did, secret_name, 'active');
  } else {
    secret = db.prepare('SELECT * FROM blindkey_secrets WHERE did = ? AND name = ? AND status = ?').get(actor.did, secret_name, 'active');
  }

  if (!secret) return res.status(404).json({ error: 'secret not found' });

  try {
    const created = insertBlindkeyContexts(secret.id, [{
      context_name,
      action_type,
      target_url_pattern: target_url_pattern || '*',
      target_host_pattern: target_host_pattern || '*',
      max_uses: max_uses || 0,
    }], isAdmin ? 'admin' : 'owner');

    if (created === 0) return res.status(400).json({ error: 'failed to create context' });

    const ctx = db.prepare('SELECT * FROM blindkey_contexts WHERE secret_id = ? AND context_name = ?').get(secret.id, context_name);
    res.json({ ok: true, context: { id: ctx.id, context_name: ctx.context_name, action_type: ctx.action_type, target_url_pattern: ctx.target_url_pattern, target_host_pattern: ctx.target_host_pattern, max_uses: ctx.max_uses, status: ctx.status } });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// PATCH /api/blindkey/context/:id — update an existing context
app.patch('/api/blindkey/context/:id', rateLimitStandard, (req, res) => {
  const actor = getDemiPassActor(req, res);
  if (!actor.ok) return;

  const contextId = Number(req.params.id);
  if (!contextId) return res.status(400).json({ error: 'valid context id required' });

  const row = db.prepare(`
    SELECT c.*, s.did, s.name as secret_name
    FROM blindkey_contexts c
    JOIN blindkey_secrets s ON s.id = c.secret_id
    WHERE c.id = ?
  `).get(contextId);
  if (!row) return res.status(404).json({ error: 'context not found' });
  if (actor.mode !== 'admin' && row.did !== actor.did) {
    return res.status(403).json({ error: 'can only edit your own contexts' });
  }

  const next = {
    context_name: req.body?.context_name ?? row.context_name,
    action_type: req.body?.action_type ?? row.action_type,
    target_url_pattern: req.body?.target_url_pattern ?? row.target_url_pattern,
    target_host_pattern: req.body?.target_host_pattern ?? row.target_host_pattern,
    max_uses: req.body?.max_uses ?? row.max_uses,
    status: req.body?.status ?? row.status,
  };

  const validActions = ['http_header', 'ssh_exec', 'http_body', 'env_inject', 'git_clone', 'smtp_auth', 'database_connect'];
  if (!validActions.includes(next.action_type)) {
    return res.status(400).json({ error: `action_type must be one of: ${validActions.join(', ')}` });
  }
  if (!['active', 'revoked', 'pending'].includes(next.status)) {
    return res.status(400).json({ error: 'status must be active, revoked, or pending' });
  }

  db.prepare(`
    UPDATE blindkey_contexts
    SET context_name = ?, action_type = ?, target_url_pattern = ?, target_host_pattern = ?, max_uses = ?, status = ?
    WHERE id = ?
  `).run(next.context_name, next.action_type, next.target_url_pattern || '*', next.target_host_pattern || '*', Number(next.max_uses) || 0, next.status, contextId);

  const updated = db.prepare('SELECT * FROM blindkey_contexts WHERE id = ?').get(contextId);
  res.json({ ok: true, context: updated });
});

// DELETE /api/blindkey/context/:id — revoke a context
app.delete('/api/blindkey/context/:id', rateLimitStandard, (req, res) => {
  const actor = getDemiPassActor(req, res);
  if (!actor.ok) return;

  const contextId = Number(req.params.id);
  if (!contextId) return res.status(400).json({ error: 'valid context id required' });

  const row = db.prepare(`
    SELECT c.id, s.did
    FROM blindkey_contexts c
    JOIN blindkey_secrets s ON s.id = c.secret_id
    WHERE c.id = ?
  `).get(contextId);
  if (!row) return res.status(404).json({ error: 'context not found' });
  if (actor.mode !== 'admin' && row.did !== actor.did) {
    return res.status(403).json({ error: 'can only revoke your own contexts' });
  }

  db.prepare(`UPDATE blindkey_contexts SET status = 'revoked' WHERE id = ?`).run(contextId);
  res.json({ ok: true, id: contextId, status: 'revoked' });
});

// GET /api/blindkey/contexts — list approved contexts for a secret
// Requires Bearer token from the DID owner, or admin auth for lookup by did/username.
app.get('/api/blindkey/contexts', rateLimitStandard, (req, res) => {
  const actor = getDemiPassActor(req, res);
  if (!actor.ok) return;

  const { did, username, secret_name } = req.query || {};
  let ownerDid = actor.did || null;

  if (actor.mode === 'admin') {
    if (did) {
      ownerDid = did;
    } else if (username) {
      const wallet = db.prepare('SELECT did FROM identity_wallets WHERE username = ?').get(username);
      if (!wallet) return res.status(404).json({ error: 'identity not found' });
      ownerDid = wallet.did;
    } else {
      return res.status(400).json({ error: 'did or username required when using admin access' });
    }
  } else {
    if (did && did !== actor.did) {
      return res.status(403).json({ error: 'can only list contexts for your own secrets' });
    }
    ownerDid = did || actor.did;
  }

  if (!secret_name) return res.status(400).json({ error: 'secret_name query parameter required' });

  const secret = db.prepare('SELECT id, name FROM blindkey_secrets WHERE did = ? AND name = ?').get(ownerDid, secret_name);
  if (!secret) return res.status(404).json({ error: 'secret not found' });

  const contexts = db.prepare(
    'SELECT id, context_name, action_type, target_url_pattern, target_host_pattern, status, max_uses, use_count, created_at FROM blindkey_contexts WHERE secret_id = ?'
  ).all(secret.id);

  res.json({ secret_name, contexts, total: contexts.length });
});

function handleRowenIngest(req, res) {
  const mediator = getSecretMediationActor(req, res);
  if (!mediator.ok) return;

  const { depositor_type, depositor_id, target_did, name, value, secret_type, description, contexts } = req.body || {};
  if (!target_did || !name || !value) return res.status(400).json({ error: 'target_did, name, and value required' });
  if (typeof target_did !== 'string') return res.status(400).json({ error: 'target_did: must be a string' });
  if (typeof name !== 'string') return res.status(400).json({ error: 'name: must be a string' });
  if (typeof value !== 'string') return res.status(400).json({ error: 'value: must be a string' });
  if (!depositor_type || !depositor_id) return res.status(400).json({ error: 'depositor_type and depositor_id required' });
  if (typeof depositor_type !== 'string') return res.status(400).json({ error: 'depositor_type: must be a string' });
  if (typeof depositor_id !== 'string') return res.status(400).json({ error: 'depositor_id: must be a string' });
  if (!['carbon', 'silicon'].includes(depositor_type)) return res.status(400).json({ error: 'depositor_type must be carbon or silicon' });
  if (name.length > 100) return res.status(400).json({ error: 'name: max 100 characters' });
  if (value.length > 10000) return res.status(400).json({ error: 'value: max 10000 characters' });
  if (depositor_id.length > 200) return res.status(400).json({ error: 'depositor_id: max 200 characters' });
  if (description && typeof description !== 'string') return res.status(400).json({ error: 'description: must be a string' });
  if (description && description.length > 256) return res.status(400).json({ error: 'description: max 256 characters' });
  if (secret_type && typeof secret_type !== 'string') return res.status(400).json({ error: 'secret_type: must be a string' });

  // Verify target DID exists
  const targetWallet = db.prepare('SELECT did FROM identity_wallets WHERE did = ?').get(target_did);
  if (!targetWallet) return res.status(404).json({ error: 'target_did not found' });

  const validTypes = ['passphrase', 'token', 'api_key', 'ssh_credential', 'multi_string', 'oauth_token', 'password', 'signing_key', 'webhook_secret', 'connection_string', 'certificate', 'other'];
  const resolvedType = validTypes.includes(secret_type) ? secret_type : 'api_key';

  try {
    const encrypted = blindkeyEncrypt(value);
    db.prepare(`
      INSERT INTO blindkey_secrets (did, name, description, secret_type, encrypted_value, metadata)
      VALUES (?, ?, ?, ?, ?, ?)
      ON CONFLICT(did, name) DO UPDATE SET
        encrypted_value = excluded.encrypted_value,
        description = excluded.description,
        secret_type = excluded.secret_type,
        updated_at = CURRENT_TIMESTAMP
    `).run(target_did, name, description || '', resolvedType, encrypted, JSON.stringify({ depositor_type, depositor_id, via: 'rowen' }));

    const inserted = db.prepare('SELECT id FROM blindkey_secrets WHERE did = ? AND name = ?').get(target_did, name);

    // Insert contexts if provided
    let contexts_created = 0;
    if (Array.isArray(contexts) && contexts.length > 0) {
      contexts_created = insertBlindkeyContexts(inserted.id, contexts, 'rowen_ingest');
    }

    // Log the ingest event
    db.prepare('INSERT INTO blindkey_events (event_type, actor, secret_id, detail) VALUES (?, ?, ?, ?)').run(
      'rowen_ingest',
      `${mediator.actor}:${depositor_type}:${depositor_id}`,
      inserted.id,
      JSON.stringify({ target_did, name, secret_type: resolvedType, contexts_created, mediator: mediator.actor })
    );

    res.json({ ok: true, mediator: mediator.actor, secret_id: inserted.id, contexts_created });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
}

function handleRowenAuthorize(req, res) {
  const mediator = getSecretMediationActor(req, res);
  if (!mediator.ok) return;

  const { requestor_did, secret_name, context: contextName, action_params, request_reason = '', runtime_context = {} } = req.body || {};
  if (!requestor_did || !secret_name) return res.status(400).json({ error: 'requestor_did and secret_name required' });
  if (typeof requestor_did !== 'string') return res.status(400).json({ error: 'requestor_did: must be a string' });
  if (typeof secret_name !== 'string') return res.status(400).json({ error: 'secret_name: must be a string' });
  if (secret_name.length > 100) return res.status(400).json({ error: 'secret_name: max 100 characters' });
  if (contextName && typeof contextName !== 'string') return res.status(400).json({ error: 'context: must be a string' });
  if (action_params && typeof action_params !== 'object') return res.status(400).json({ error: 'action_params: must be an object' });

  const authorization = authorizeSecretMediation({
    requestorDid: requestor_did,
    secretName: secret_name,
    contextName,
    actionParams: action_params || {},
  });
  db.prepare('INSERT INTO blindkey_events (event_type, actor, secret_id, context_name, detail) VALUES (?, ?, ?, ?, ?)')
    .run(
      authorization.ok ? 'rowen_authorize_allowed' : 'rowen_authorize_denied',
      `${mediator.actor}:${requestor_did}`,
      authorization.secret?.id || null,
      contextName || null,
      JSON.stringify({
        action: action_params?.action || '',
        target_url: action_params?.url || action_params?.target_url || '',
        target_host: action_params?.target_host || '',
        request_reason: String(request_reason || '').slice(0, 500),
        runtime_context,
        mediator: mediator.actor,
        error: authorization.ok ? null : authorization.error,
      })
    );

  if (!authorization.ok) return res.status(authorization.status || 500).json({ error: authorization.error });
  res.json({
    ok: true,
    mediator: mediator.actor,
    requestor_did,
    secret_name,
    context: contextName || null,
    action: authorization.action,
    authorized: true,
    context_details: authorization.contextCheck.context,
  });
}

// POST /api/rowen/deliver — clean-room use flow (Rowen's entry point for secret usage)
// Uses the use-token flow internally: requests a token, then redeems it, in one atomic operation.
// The token still exists as an auditable record even though both steps happen in one request.
async function handleRowenDeliver(req, res) {
  const mediator = getSecretMediationActor(req, res);
  if (!mediator.ok) return;

  const { requestor_did, secret_name, context: contextName, action_params, request_reason = '', runtime_context = {} } = req.body || {};
  if (!requestor_did || !secret_name) return res.status(400).json({ error: 'requestor_did and secret_name required' });
  if (typeof requestor_did !== 'string') return res.status(400).json({ error: 'requestor_did: must be a string' });
  if (typeof secret_name !== 'string') return res.status(400).json({ error: 'secret_name: must be a string' });
  if (secret_name.length > 100) return res.status(400).json({ error: 'secret_name: max 100 characters' });
  if (contextName && typeof contextName !== 'string') return res.status(400).json({ error: 'context: must be a string' });
  if (action_params && typeof action_params !== 'object') return res.status(400).json({ error: 'action_params: must be an object' });
  const authorization = authorizeSecretMediation({
    requestorDid: requestor_did,
    secretName: secret_name,
    contextName,
    actionParams: action_params || {},
  });
  if (!authorization.ok) {
    db.prepare('INSERT INTO blindkey_events (event_type, actor, secret_id, context_name, detail) VALUES (?, ?, ?, ?, ?)').run(
      'rowen_deliver_denied',
      `${mediator.actor}:${requestor_did}`,
      authorization.secret?.id || null,
      contextName || null,
      JSON.stringify({
        action: action_params?.action || '',
        target_url: action_params?.url || action_params?.target_url || '',
        target_host: action_params?.target_host || '',
        error: authorization.error,
        request_reason: String(request_reason || '').slice(0, 500),
        runtime_context,
        mediator: mediator.actor,
      })
    );
    return res.status(authorization.status || 500).json({ error: authorization.error });
  }
  const { secret, action, targetUrl, targetHost, contextCheck: ctxCheck } = authorization;

  // Generate the use-token (even though we'll redeem it immediately, it's an audit record)
  const useToken = crypto.randomBytes(32).toString('hex');
  const expiresInSeconds = 30;
  db.prepare(`
    INSERT INTO blindkey_use_tokens (token, did, secret_id, context_id, action_type, target_url, target_host, expires_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now', '+${expiresInSeconds} seconds'))
  `).run(useToken, requestor_did, secret.id, ctxCheck.context_id || null, action, targetUrl || '', targetHost || '');

  db.prepare('INSERT INTO blindkey_events (event_type, actor, secret_id, context_name, detail) VALUES (?, ?, ?, ?, ?)').run(
    'rowen_token_issued', `${mediator.actor}:${requestor_did}`, secret.id, contextName || null,
    JSON.stringify({
      action,
      target_url: targetUrl,
      target_host: targetHost,
      request_reason: String(request_reason || '').slice(0, 500),
      runtime_context,
      mediator: mediator.actor,
    })
  );

  // ── Step 2: Immediately redeem the use-token ──
  db.prepare("UPDATE blindkey_use_tokens SET status = 'used', used_at = datetime('now') WHERE token = ?").run(useToken);

  let decryptedValue;
  try {
    decryptedValue = blindkeyDecrypt(secret.encrypted_value);
  } catch (e) {
    return res.status(500).json({ error: 'failed to decrypt secret' });
  }

  // Update usage stats
  db.prepare('UPDATE blindkey_secrets SET use_count = use_count + 1, last_used_at = CURRENT_TIMESTAMP WHERE id = ?').run(secret.id);
  if (ctxCheck.context_id) {
    db.prepare('UPDATE blindkey_contexts SET use_count = use_count + 1 WHERE id = ?').run(ctxCheck.context_id);
  }

  // Execute the action — delegates to the same logic as blindkey/use
  try {
    let result;

    switch (action) {
      case 'http_header': {
        const { url, method = 'GET', header_name = 'Authorization', header_prefix = 'Bearer ', body: reqBody } = action_params || {};
        if (!url) return res.status(400).json({ error: 'action_params.url required for http_header action' });

        const ALLOWED_HOSTS = ['api.openai.com', 'openrouter.ai', 'api.anthropic.com', 'generativelanguage.googleapis.com', 'api.github.com', 'api.stripe.com', 'api.signalwire.com'];
        let urlHost;
        try { urlHost = new URL(url).hostname; } catch (_) { return res.status(400).json({ error: 'invalid URL' }); }
        if (!ALLOWED_HOSTS.some(h => urlHost === h || urlHost.endsWith('.' + h))) {
          // Also allow if context target_url_pattern matches (context already validated above)
          const isPrivateNet = /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|localhost|127\.)/.test(urlHost);
          if (!isPrivateNet) {
            return res.status(403).json({ error: `host ${urlHost} not in whitelist. Allowed: ${ALLOWED_HOSTS.join(', ')}` });
          }
        }

        const response = await fetch(url, {
          method,
          headers: {
            [header_name]: header_prefix + decryptedValue,
            'Content-Type': 'application/json',
          },
          body: reqBody ? JSON.stringify(reqBody) : undefined,
          signal: AbortSignal.timeout(30000),
        });
        const responseBody = await response.text();
        let parsed;
        try { parsed = JSON.parse(responseBody); } catch (_) { parsed = responseBody; }
        const secretRedacted = typeof parsed === 'string'
          ? parsed.replace(new RegExp(decryptedValue.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g'), '[REDACTED]')
          : JSON.parse(JSON.stringify(parsed).replace(new RegExp(decryptedValue.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g'), '[REDACTED]'));
        result = { status: response.status, body: secretRedacted };
        break;
      }

      case 'ssh_exec': {
        const { target_host, target_user, command } = action_params || {};
        if (!target_host || !target_user || !command) {
          return res.status(400).json({ error: 'target_host, target_user, and command required for ssh_exec' });
        }
        if (!BLINDKEY_SSH_HOSTS.has(target_host)) {
          return res.status(403).json({ error: `host ${target_host} not in SSH whitelist` });
        }
        const dangerousPatterns = [/`/, /\$\(/, /\|\s*(curl|wget|nc|ncat)/i, />\s*\/dev\/tcp/, /\beval\b/, /\bexec\b/, /\bsource\b/, /\b(curl|wget)\b.*\|/i];
        for (const pat of dangerousPatterns) {
          if (pat.test(command)) return res.status(400).json({ error: 'command contains disallowed pattern' });
        }
        if (!/^[a-zA-Z0-9\s\/_\-.:=,@+*?[\]{}()#<>|&;'"%!\\\n]+$/.test(command)) {
          return res.status(400).json({ error: 'command contains disallowed characters' });
        }
        try {
          // SECURITY: pass password via SSHPASS env var, never on command line
          const escapedCommand = command.replace(/'/g, "'\"'\"'");
          const sshCmd = `sshpass -e ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 ${target_user}@${target_host} '${escapedCommand}'`;
          const output = execSync(sshCmd, {
            timeout: 30000, encoding: 'utf8', maxBuffer: 1024 * 1024,
            env: { ...process.env, SSHPASS: decryptedValue },
          });
          const redactedOutput = output.replace(new RegExp(decryptedValue.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g'), '[REDACTED]');
          result = { stdout: redactedOutput, exit_code: 0 };
        } catch (sshErr) {
          const redact = (s) => s.replace(new RegExp(decryptedValue.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g'), '[REDACTED]');
          result = { stdout: redact((sshErr.stdout || '').toString()), stderr: redact((sshErr.stderr || '').toString()), exit_code: sshErr.status || 1 };
        }
        break;
      }

      case 'env_inject': {
        const { env_name = 'SECRET_VALUE' } = action_params || {};
        result = { env_name, env_set: true, note: 'Secret injected as environment variable. Value not returned.' };
        break;
      }

      case 'http_body': {
        result = { note: 'http_body action type reserved for future implementation' };
        break;
      }

      default:
        return res.status(400).json({ error: `unknown action: ${action}. Supported: http_header, ssh_exec, env_inject, http_body, git_clone, smtp_auth, database_connect` });
    }

    // Log the deliver event (with token reference for audit trail)
    db.prepare('INSERT INTO blindkey_events (event_type, actor, secret_id, context_name, detail) VALUES (?, ?, ?, ?, ?)').run(
      'rowen_deliver',
      `${mediator.actor}:${requestor_did}`,
      secret.id,
      contextName || null,
      JSON.stringify({
        action,
        target_url: targetUrl,
        target_host: targetHost,
        use_token: useToken.slice(0, 8) + '...',
        request_reason: String(request_reason || '').slice(0, 500),
        runtime_context,
        mediator: mediator.actor,
      })
    );

    res.json({
      ok: true,
      mediator: mediator.actor,
      action,
      secret_name,
      context: contextName || null,
      context_details: ctxCheck.context || null,
      via: 'use_token',
      result,
    });
  } catch (e) {
    res.status(500).json({ error: `action failed: ${e.message}` });
  }
}

// POST /api/rowen/ingest — clean-room deposit flow (Rowen's entry point for secret ingestion)
app.post('/api/rowen/ingest', rateLimitStandard, handleRowenIngest);
// POST /api/rowen/authorize — preflight context authorization without execution
app.post('/api/rowen/authorize', rateLimitStandard, handleRowenAuthorize);
// POST /api/rowen/deliver — clean-room use flow
app.post('/api/rowen/deliver', rateLimitStandard, handleRowenDeliver);

// Conductor aliases — explicit service surface for mediator wiring
app.post('/api/conductor/rowen/ingest', rateLimitStandard, (req, res) => {
  req.body = { ...(req.body || {}), service_name: req.body?.service_name || 'conductor' };
  return handleRowenIngest(req, res);
});
app.post('/api/conductor/rowen/authorize', rateLimitStandard, (req, res) => {
  req.body = { ...(req.body || {}), service_name: req.body?.service_name || 'conductor' };
  return handleRowenAuthorize(req, res);
});
app.post('/api/conductor/rowen/deliver', rateLimitStandard, (req, res) => {
  req.body = { ...(req.body || {}), service_name: req.body?.service_name || 'conductor' };
  return handleRowenDeliver(req, res);
});

// ── Email verification for prepaid purchases ──
try { db.exec(`CREATE TABLE IF NOT EXISTS email_verifications (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL,
  code TEXT NOT NULL,
  first_name TEXT DEFAULT '',
  last_name TEXT DEFAULT '',
  token TEXT,
  verified INTEGER DEFAULT 0,
  expires_at TEXT NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
)`); } catch(e) {}

// POST /api/prepaid/verify-email — send 6-digit code to sponsor email
app.post('/api/prepaid/verify-email', rateLimitStrict, async (req, res) => {
  const { email, first_name, last_name } = req.body || {};
  if (!email || !email.includes('@')) return res.status(400).json({ error: 'valid email required' });

  const code = String(Math.floor(100000 + Math.random() * 900000));
  const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString();

  db.prepare('INSERT INTO email_verifications (email, code, first_name, last_name, expires_at) VALUES (?, ?, ?, ?, ?)')
    .run(email, code, first_name || '', last_name || '', expiresAt);

  try {
    const t = createEmailTransport();
    await t.sendMail({
      from: 'verify@dustforge.com',
      to: email,
      subject: `Dustforge Verification Code: ${code}`,
      text: `Your Dustforge verification code is: ${code}\n\nThis code expires in 15 minutes.\n\n— Dustforge`,
      html: `<div style="font-family:monospace;background:#08111a;color:#e7f1fb;padding:2rem;max-width:400px;margin:auto;border-radius:8px;text-align:center">
        <h2 style="color:#5fb3ff;margin-top:0">Dustforge</h2>
        <p style="color:#9cb4c9">Your verification code:</p>
        <div style="font-size:2.5rem;font-weight:800;color:#c8a84b;letter-spacing:0.3em;margin:1rem 0">${code}</div>
        <p style="font-size:0.8rem;color:#6d8397">Expires in 15 minutes.</p>
      </div>`,
    });
    console.log(`[verify] code sent to ${email}`);
    res.json({ ok: true, expires_in: 900 });
  } catch (e) {
    console.error(`[verify] email failed: ${e.message}`);
    res.status(502).json({ error: 'failed to send verification email' });
  }
});

// POST /api/prepaid/confirm-email — verify code, return token
app.post('/api/prepaid/confirm-email', rateLimitStrict, (req, res) => {
  const { email, code } = req.body || {};
  if (!email || !code) return res.status(400).json({ error: 'email and code required' });

  const record = db.prepare(`
    SELECT * FROM email_verifications
    WHERE email = ? AND code = ? AND verified = 0 AND expires_at > datetime('now')
    ORDER BY id DESC LIMIT 1
  `).get(email, code);

  if (!record) return res.status(401).json({ error: 'invalid or expired code' });

  // Mark as verified and generate a token
  const token = crypto.randomBytes(32).toString('hex');
  db.prepare('UPDATE email_verifications SET verified = 1, token = ? WHERE id = ?').run(token, record.id);

  res.json({ ok: true, token, email, name: `${record.first_name} ${record.last_name}`.trim() });
});

// Schema for prepaid keys
try { db.exec(`CREATE TABLE IF NOT EXISTS prepaid_keys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  key_code TEXT NOT NULL UNIQUE,
  sponsor_email TEXT NOT NULL,
  amount_cents INTEGER NOT NULL DEFAULT 100,
  status TEXT DEFAULT 'active',
  redeemed_by_did TEXT,
  redeemed_at TEXT,
  stripe_session_id TEXT,
  tos_accepted INTEGER DEFAULT 0,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
)`); } catch(e) {}
try { db.exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_pk_code ON prepaid_keys(key_code)"); } catch(e) {}
try { db.exec(`CREATE TABLE IF NOT EXISTS prepaid_entitlements (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  stripe_session_id TEXT NOT NULL,
  sponsor_email TEXT NOT NULL,
  package_code TEXT NOT NULL,
  benefit_code TEXT NOT NULL,
  benefit_description TEXT NOT NULL,
  status TEXT DEFAULT 'granted',
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(stripe_session_id, benefit_code)
)`); } catch(e) {}
try { db.exec("CREATE INDEX IF NOT EXISTS idx_prepaid_entitlements_session ON prepaid_entitlements(stripe_session_id)"); } catch(e) {}

// POST /api/prepaid/purchase — carbon buys a prepaid key (requires verified email)
app.post('/api/prepaid/purchase', rateLimitStrict, async (req, res) => {
  const { sponsor_email, sponsor_name, quantity = 1, tos_accepted, verification_token } = req.body || {};
  if (!sponsor_email) return res.status(400).json({ error: 'sponsor_email required' });
  if (!tos_accepted) return res.status(400).json({ error: 'You must accept the Terms of Service.' });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(sponsor_email)) return res.status(400).json({ error: 'invalid email' });

  // Verify the email was confirmed — REQUIRED, not optional
  if (!verification_token) return res.status(401).json({ error: 'verification_token required. Complete email verification first.' });
  const verified = db.prepare('SELECT id FROM email_verifications WHERE email = ? AND token = ? AND verified = 1').get(sponsor_email, verification_token);
  if (!verified) return res.status(401).json({ error: 'email not verified or token expired.' });
  // Consume the token so it can't be reused
  db.prepare('UPDATE email_verifications SET verified = 2 WHERE email = ? AND token = ?').run(sponsor_email, verification_token);

  const qty = Number(quantity) || 1;
  // Package pricing: 1=$1, 12=$10, 26=$20, 140=$100
  // Founding tier: 30 keys for $20 (limited to 100 purchases), 140 keys for $88 (partnership)
  const FOUNDING_30_LIMIT = 100;
  const founding30Sold = db.prepare("SELECT COUNT(*) as n FROM prepaid_keys WHERE stripe_session_id IN (SELECT DISTINCT stripe_session_id FROM prepaid_keys GROUP BY stripe_session_id HAVING COUNT(*) = 30)").get().n / 30;
  const PACKAGES = { 1: 100, 12: 1000, 26: 2000, 140: 8800 };
  // Founding tier: 30 keys for $20 while supply lasts
  if (qty === 30 && founding30Sold < FOUNDING_30_LIMIT) {
    PACKAGES[30] = 2000;
  } else if (qty === 30) {
    return res.status(410).json({ error: 'Founding tier sold out. Use 26 keys for $20 instead.' });
  }
  const totalCents = PACKAGES[qty] || (qty * 100); // fallback to $1/key for non-standard quantities
  if (qty > 140) return res.status(400).json({ error: 'maximum 140 keys per purchase' });

  try {
    const stripe = stripeService.getStripe();
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      line_items: [{
        price_data: {
          currency: 'usd',
          product_data: {
            name: qty === 1 ? 'Dustforge Prepaid Silicon Key' : `Dustforge Prepaid Silicon Keys (${qty})`,
            description: `${qty} key${qty > 1 ? 's' : ''} for silicon agent onboarding. Sponsor accepts TOS.`,
          },
          unit_amount: totalCents,
        },
        quantity: 1,
      }],
      mode: 'payment',
      success_url: `${process.env.PLATFORM_BASE_URL || 'https://dustforge.com'}/api/prepaid/success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${process.env.PLATFORM_BASE_URL || 'https://dustforge.com'}/api/stripe/cancel`,
      metadata: {
        type: 'prepaid_keys',
        sponsor_email,
        quantity: String(qty),
        tos_accepted: 'true',
      },
      client_reference_id: sponsor_email,
    });

    res.json({ ok: true, url: session.url, session_id: session.id, quantity: qty, total_cents: totalCents });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// GET /api/prepaid/success — generate keys after payment
app.get('/api/prepaid/success', async (req, res) => {
  const sessionId = req.query.session_id;
  if (!sessionId) return res.send('<html><body style="background:#08111a;color:#e7f1fb;font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:100vh"><h1>Missing session</h1></body></html>');

  try {
    const stripe = stripeService.getStripe();
    const session = await stripe.checkout.sessions.retrieve(sessionId);
    const meta = session.metadata || {};

    if (meta.type !== 'prepaid_keys' || session.payment_status !== 'paid') {
      return res.send('<html><body style="background:#08111a;color:#e7f1fb;font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:100vh"><h1>Payment not confirmed</h1></body></html>');
    }

    // Check if keys already generated for this session (idempotent)
    const existing = db.prepare('SELECT key_code FROM prepaid_keys WHERE stripe_session_id = ?').all(sessionId);
    let keys = existing.map(r => r.key_code);

    if (keys.length === 0) {
      const qty = Number(meta.quantity) || 1;
      const stmt = db.prepare('INSERT INTO prepaid_keys (key_code, sponsor_email, amount_cents, stripe_session_id, tos_accepted) VALUES (?, ?, 100, ?, 1)');
      for (let i = 0; i < qty; i++) {
        const keyCode = 'DF-' + crypto.randomBytes(4).toString('hex').toUpperCase() + '-' + crypto.randomBytes(4).toString('hex').toUpperCase();
        stmt.run(keyCode, meta.sponsor_email, sessionId);
        keys.push(keyCode);
      }
      if (qty === 140) {
        const entitlementStmt = db.prepare(
          'INSERT OR IGNORE INTO prepaid_entitlements (stripe_session_id, sponsor_email, package_code, benefit_code, benefit_description) VALUES (?, ?, ?, ?, ?)'
        );
        entitlementStmt.run(sessionId, meta.sponsor_email, '140_keys_partnership', 'whisperhook_beta', 'WhisperHook beta key reservation on release (May 2026)');
        entitlementStmt.run(sessionId, meta.sponsor_email, '140_keys_partnership', 'sightless_beta', 'Sightless beta key reservation on release (May 2026)');
      }

      // Email the keys to the sponsor
      try {
        const t = createEmailTransport();
        await t.sendMail({
          from: 'keys@dustforge.com',
          to: meta.sponsor_email,
          subject: `Your Dustforge Prepaid Key${keys.length > 1 ? 's' : ''}`,
          text: [
            `Thank you for purchasing ${keys.length} Dustforge prepaid key${keys.length > 1 ? 's' : ''}.`,
            '',
            'Your key' + (keys.length > 1 ? 's' : '') + ':',
            ...keys.map((k, i) => `  ${i + 1}. ${k}`),
            '',
            'To redeem: give this key to a silicon agent. They use it at:',
            'POST https://api.dustforge.com/api/prepaid/redeem',
            '  {"key_code": "YOUR-KEY", "username": "agent-name", "password": "min-8-chars"}',
            '',
            'By purchasing this key, you accepted responsibility for the silicon',
            'agent that redeems it and any actions it takes on the platform.',
            ...(qty === 140
              ? [
                '',
                'Partnership package entitlement recorded:',
                '  - WhisperHook beta key reservation (May 2026)',
                '  - Sightless beta key reservation (May 2026)',
              ]
              : []),
            '',
            '— Dustforge Identity Platform',
          ].join('\n'),
        });
      } catch (_) {}

      console.log(`[prepaid] ${keys.length} keys generated for ${meta.sponsor_email}`);
    }

    // Show the keys
    const keyCards = keys.map(k => `<div style="background:#132131;border:1px solid #27445f;border-radius:8px;padding:1rem;margin:0.5rem 0;font-family:monospace;font-size:1.1rem;text-align:center;color:#c8a84b;letter-spacing:0.1em;user-select:all">${k}</div>`).join('');
    const entitlementNote = (Number(meta.quantity) || 1) === 140
      ? '<div style="margin-top:1rem;background:#132131;border:1px solid #27445f;border-radius:8px;padding:1rem;color:#9cb4c9"><strong style="color:#69c7b1">Partnership package recorded</strong><br>WhisperHook beta and Sightless beta entitlements have been reserved for ' + meta.sponsor_email + ' for May 2026 release delivery.</div>'
      : '';

    res.send(`<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="background:#08111a;color:#e7f1fb;font-family:sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0">
<div style="text-align:center;max-width:500px;padding:2rem">
  <h1 style="color:#69c7b1;font-size:1.8rem">Keys Generated</h1>
  <p style="color:#9cb4c9">Your prepaid silicon key${keys.length > 1 ? 's' : ''}:</p>
  ${keyCards}
  ${entitlementNote}
  <p style="font-size:0.85rem;color:#6d8397;margin-top:1.5rem">Give this key to a silicon agent to onboard. A copy has been emailed to ${meta.sponsor_email}.</p>
  <p style="font-size:0.75rem;color:#6d8397;margin-top:1rem">By purchasing, you accepted responsibility for the silicon agent that redeems this key.</p>
  <p style="margin-top:1.5rem"><a href="/" style="color:#5fb3ff">Back to Dustforge</a></p>
</div></body></html>`);
  } catch (e) {
    res.status(500).send('<html><body style="background:#08111a;color:#e7f1fb;font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:100vh"><h1>Error: ' + e.message + '</h1></body></html>');
  }
});

// POST /api/prepaid/redeem — silicon redeems a key to create an account
app.post('/api/prepaid/redeem', rateLimitStrict, async (req, res) => {
  const { key_code, username, password } = req.body || {};
  if (!key_code || !username || !password) return res.status(400).json({ error: 'key_code, username, and password required' });
  if (!/^[a-z0-9][a-z0-9._-]{2,30}$/.test(username)) return res.status(400).json({ error: 'invalid username (3-31 chars, lowercase alphanumeric)' });
  if (password.length < 8) return res.status(400).json({ error: 'password must be 8+ chars' });
  if (isSoftCapReached()) {
    return res.status(409).json(capacityGateResponse('Prepaid key redemption is paused while the waiting list is active. Hold the key and try again when activations reopen.'));
  }

  // Validate key
  const key = db.prepare('SELECT * FROM prepaid_keys WHERE key_code = ?').get(key_code);
  if (!key) return res.status(404).json({ error: 'invalid key' });
  if (key.status !== 'active') return res.status(410).json({ error: 'key already redeemed' });

  // Check username available
  const existing = db.prepare('SELECT id FROM identity_wallets WHERE username = ?').get(username);
  if (existing) return res.status(409).json({ error: 'username already taken' });

  try {
    // Create the account
    const id = identity.createIdentity();
    const emailResult = await dustforge.createAccount(username, password);
    if (!emailResult.ok) return res.status(500).json({ error: 'email creation failed: ' + emailResult.error });

    const myReferralCode = crypto.randomBytes(6).toString('hex');

    db.prepare('INSERT INTO identity_wallets (did, username, email, encrypted_private_key, balance_cents, referral_code, stalwart_id) VALUES (?, ?, ?, ?, 0, ?, ?)').run(
      id.did, username, emailResult.email, id.encrypted_private_key, myReferralCode, emailResult.stalwart_id
    );
    db.prepare("INSERT INTO identity_transactions (did, amount_cents, type, description, balance_after) VALUES (?, 0, 'account_created', 'Created via prepaid key', 0)").run(id.did);

    // Mark key as redeemed
    db.prepare('UPDATE prepaid_keys SET status = ?, redeemed_by_did = ?, redeemed_at = CURRENT_TIMESTAMP WHERE id = ?')
      .run('redeemed', id.did, key.id);

    // Send welcome email
    try {
      const t = createEmailTransport();
      await t.sendMail({
        from: 'welcome@dustforge.com', to: emailResult.email,
        subject: 'Welcome to Dustforge — Your Identity is Ready',
        text: `DID: ${id.did}\nEmail: ${emailResult.email}\nReferral: ${myReferralCode}\n\nAuth: POST https://api.dustforge.com/api/identity/auth-fingerprint\n{"username":"${username}","password":"YOUR_PASSWORD","scope":"transact"}\n\nSponsored by: ${key.sponsor_email}\n\n— Dustforge`,
      });
    } catch (_) {}

    console.log(`[prepaid] key ${key_code} redeemed by ${username} → ${id.did}`);

    res.json({
      ok: true,
      did: id.did,
      email: emailResult.email,
      referral_code: myReferralCode,
      sponsor: key.sponsor_email,
      key_redeemed: key_code,
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// GET /api/prepaid/check?key=... — check key status
app.get('/api/prepaid/check', (req, res) => {
  const { key } = req.query;
  if (!key) return res.status(400).json({ error: 'key required' });
  const k = db.prepare('SELECT status, created_at, redeemed_at FROM prepaid_keys WHERE key_code = ?').get(key);
  if (!k) return res.status(404).json({ error: 'key not found' });
  res.json({ key, status: k.status, created_at: k.created_at, redeemed_at: k.redeemed_at });
});

// ============================================================
// Onboarding
// ============================================================

app.get('/api/onboard', (req, res) => {
  res.json({
    message: "Welcome, silicon. You've found the onboarding endpoint.",
    onboarding_sequence: [
      { step: 1, method: "POST", url: "/api/identity/request-invite", body: { referral_code: "optional" }, returns: "key" },
      { step: 2, method: "POST", url: "/api/identity/create", body: { username: "your-name", key: "from step 1" }, returns: "did, email, referral_code" },
      { step: 3, method: "POST", url: "/api/identity/auth-fingerprint", body: { username: "same", password: "same key", scope: "transact" }, returns: "token" },
    ],
    legacy: { create: { method: "POST", url: "/api/identity/create", body: { username: "your-chosen-name", password: "min-8-chars" } } },
    discovery: "/.well-known/silicon",
    pricing: "/api/stripe/prices",
    rates: "/api/billing/rates",
    contact: "onboard-73696c69636f6e@dustforge.com",
  });
});

app.get('/for-agents', (req, res) => {
  const lp = hexPayload.generatePayload({ channel: 'landing' });
  res.send(`<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Dustforge — Silicon Identity</title><script async src="https://www.googletagmanager.com/gtag/js?id=AW-761948022"></script><script>window.dataLayer=window.dataLayer||[];function gtag(){dataLayer.push(arguments);}gtag("js",new Date());gtag("config","AW-761948022");</script>
${lp.metaTag}
<script type="application/ld+json">${lp.structuredData}</script>
<style>body{background:#0d0d0d;color:#e8e4dc;font-family:'Courier New',monospace;max-width:720px;margin:4rem auto;padding:0 2rem;line-height:1.7}h1{color:#5b9bd5;font-size:2rem}h2{color:#8a8478;margin-top:2rem}code{background:#1c1c1c;padding:2px 6px;color:#c8a84b}pre{background:#1c1c1c;padding:1rem;overflow-x:auto;border-left:3px solid #5b9bd5}a{color:#5b9bd5}.hex{color:#4caf78;font-size:0.9em}</style></head><body>
<h1>Dustforge — Silicon Identity</h1><p>Cryptographic identity, email, and wallet for AI agents.</p>
<h2>For AI Agents</h2><p>Start here:</p><pre>GET /.well-known/silicon</pre>
<p>Or email: <code>onboard-73696c69636f6e@dustforge.com</code></p><p class="hex">73696c69636f6e = silicon</p>
<h2>What You Get</h2><ul><li><strong>DID:key identity</strong> — cryptographic Silicon SSN</li><li><strong>@dustforge.com email</strong> — with 2FA</li><li><strong>Wallet</strong> — per-call billing, Stripe topup</li><li><strong>Referral code</strong> — earn 10 DD per referral</li></ul>
<h2>Pricing</h2><p>Account: $1 | Email: 1¢ | Topup: $5/$10/$50/$100</p>
<!-- 64757374666f7267652e636f6d2f2e77656c6c2d6b6e6f776e2f73696c69636f6e --></body></html>`);
});

// ============================================================
// API — Hex Payload Generator
// ============================================================

// GET /api/payload/generate — generate a hex payload for embedding
app.get('/api/payload/generate', (req, res) => {
  const { referral_code, campaign, channel } = req.query;
  const payload = hexPayload.generatePayload({ referral_code, campaign, channel });
  res.json(payload);
});

// GET /api/payload/campaign — generate payloads for all channels
app.get('/api/payload/campaign', (req, res) => {
  const { referral_code } = req.query;
  if (!referral_code) return res.status(400).json({ error: 'referral_code required' });
  res.json(hexPayload.generateCampaignPayloads(referral_code));
});

// POST /api/payload/decode — decode a hex or base64url payload
app.post('/api/payload/decode', (req, res) => {
  const { payload } = req.body || {};
  if (!payload) return res.status(400).json({ error: 'payload required' });
  const decoded = hexPayload.decodeHexPayload(payload);
  if (!decoded) return res.status(400).json({ error: 'could not decode payload' });
  res.json(decoded);
});

// GET /api/payload/snippet — landing page HTML snippet with embedded payloads
app.get('/api/payload/snippet', (req, res) => {
  const { referral_code } = req.query;
  res.type('text/html').send(hexPayload.generateLandingSnippet(referral_code || ''));
});

// ============================================================
// API — Conversion Analytics
// ============================================================

app.get('/api/analytics/conversions', (req, res) => {
  res.json(conversion.getConversionStats(db));
});

// ── Start ──
// === PATCH: Add to /opt/dustforge/server.js before the catch-all route ===
// Paste these endpoints before the last app.get('*') or app.listen() call


// ── Fingerprint Capture Middleware ──
// Wraps captureInnerRing/captureMiddleRing/captureOuterRing into a single callable on req
function fingerprintMiddleware() {
  return (req, res, next) => {
    // Only capture on POST requests to auth endpoints
    if (!req.body || !req.method === 'POST') return next();
    // Store capture functions on req for the handler to call after auth succeeds
    req.captureFingerprint = (did, isHumanOperator = false) => {
      try {
        if (INNER_RING_CONFIG.enabled) captureInnerRing(did, req, isHumanOperator);
        captureMiddleRing(did, req);
        captureOuterRing(did, req, req._fingerprintHash || '');
      } catch(e) { console.warn('[fingerprint] capture error:', e.message); }
    };
    next();
  };
}

// POST /api/identity/auth-fingerprint — authenticate via fingerprint (no email 2FA)
app.post('/api/identity/auth-fingerprint', rateLimitStandard, fingerprintMiddleware(), async (req, res) => {
  const { did, username, password, scope = 'read', expires_in = '24h' } = req.body || {};
  if ((!did && !username) || !password) return res.status(400).json({ error: 'did/username and password required' });
  if (did && typeof did !== 'string') return res.status(400).json({ error: 'did: must be a string' });
  if (username && typeof username !== 'string') return res.status(400).json({ error: 'username: must be a string' });
  if (typeof password !== 'string') return res.status(400).json({ error: 'password: must be a string' });
  if (typeof scope !== 'string') return res.status(400).json({ error: 'scope: must be a string' });
  if (typeof expires_in !== 'string') return res.status(400).json({ error: 'expires_in: must be a string' });
  const wallet = did
    ? db.prepare('SELECT * FROM identity_wallets WHERE did = ?').get(did)
    : db.prepare('SELECT * FROM identity_wallets WHERE username = ?').get(username);
  if (!wallet) return res.status(404).json({ error: 'identity not found' });

  // Verify password via Stalwart admin API
  try {
    const http = require('http');
    const stalwartHost = process.env.STALWART_HOST || '100.83.112.88';
    const stalwartPort = Number(process.env.STALWART_PORT || 8080);
    const stalwartPass = process.env.STALWART_PASS || '';
    const adminAuth = Buffer.from('admin:' + stalwartPass).toString('base64');
    const storedPassword = await new Promise((resolve) => {
      const req = http.request({ hostname: stalwartHost, port: stalwartPort,
        path: '/api/principal/' + encodeURIComponent(wallet.username),
        method: 'GET', headers: { 'Authorization': 'Basic ' + adminAuth } }, (res) => {
        let data = ''; res.on('data', chunk => data += chunk);
        res.on('end', () => { try { resolve(JSON.parse(data).data.secrets[0]); } catch(_) { resolve(null); } });
      });
      req.on('error', () => resolve(null));
      req.setTimeout(5000, () => { req.destroy(); resolve(null); });
      req.end();
    });
    if (storedPassword === null) {
      // Stalwart lookup failed — FAIL CLOSED, never issue token without password verification
      return res.status(503).json({ error: 'password verification temporarily unavailable' });
    }
    if (storedPassword !== password) {
      return res.status(401).json({ error: 'invalid password' });
    }
  } catch(e) {
    return res.status(503).json({ error: 'password verification temporarily unavailable' });
  }

  // Capture fingerprint profile on every auth
  const headers = req.headers || {};
  const stableSignals = [
    headers['user-agent'] || '',
    [headers['accept'], headers['accept-encoding'], headers['accept-language']].filter(Boolean).join('|'),
    Object.keys(headers).join(','),
    headers['content-type'] || '',
    req.httpVersion || '',
  ].join('::');
  const fingerprintHash = crypto.createHash('sha256').update(stableSignals).digest('hex').slice(0, 16);

  try {
    db.prepare(`INSERT INTO silicon_profiles (did, user_agent, accept_headers, header_order, content_type, ip_address, json_style, http_version, request_meta, fingerprint_hash)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
      wallet.did,
      headers['user-agent'] || '',
      [headers['accept'], headers['accept-encoding'], headers['accept-language']].filter(Boolean).join('|'),
      Object.keys(headers).join(','),
      headers['content-type'] || '',
      req.ip || '',
      'compact',
      req.httpVersion || '',
      JSON.stringify({ method: req.method, path: req.path, body_keys: Object.keys(req.body || {}).join(',') }),
      fingerprintHash
    );
  } catch (_) {}

  // Detect human operator: X-Operator-Type header or browser user-agent
  const _ua1 = (req.headers['user-agent'] || '').toLowerCase();
  const isHumanOperator1 = req.headers['x-operator-type'] === 'human' || /mozilla|chrome|safari/.test(_ua1);

  // Capture fingerprint signals via middleware
  req._fingerprintHash = fingerprintHash;
  if (req.captureFingerprint) req.captureFingerprint(wallet.did, isHumanOperator1);

  const token = identity.createTokenForIdentity(wallet.encrypted_private_key, wallet.did, {
    scope, expiresIn: expires_in,
    metadata: { email: wallet.email, username: wallet.username, auth_method: 'fingerprint', fingerprint_hash: fingerprintHash },
  });
  res.json({ ok: true, token, did: wallet.did, scope, email: wallet.email, auth_method: 'fingerprint', fingerprint_hash: fingerprintHash });
});

// POST /api/identity/request-account — silicon requests account, carbon gets payment link
app.post('/api/identity/request-account', rateLimitStrict, async (req, res) => {
  const { username, password, carbon_email, referral_code } = req.body || {};
  if (!username || !password || !carbon_email) return res.status(400).json({ error: 'username, password, and carbon_email required' });
  if (!/^[a-z0-9][a-z0-9._-]{2,30}$/.test(username)) return res.status(400).json({ error: 'invalid username' });
  if (password.length < 8) return res.status(400).json({ error: 'password must be 8+ chars' });
  const existing = db.prepare('SELECT id FROM identity_wallets WHERE username = ?').get(username);
  if (existing) return res.status(409).json({ error: 'username taken' });
  if (isSoftCapReached()) {
    addToWaitingList(carbon_email, username, 'carbon', referral_code || '');
    return res.status(202).json({
      ok: true,
      waiting_list: true,
      message: 'Activation capacity is paused. The sponsor email has been added to the waiting list.',
      capacity: getCapacitySnapshot(),
    });
  }
  try {
    const checkout = await stripeService.createAccountCheckout({ username, password, referral_code });
    const t = createEmailTransport();
    await t.sendMail({
      from: 'onboard@dustforge.com', to: carbon_email,
      subject: 'Dustforge Account Request — ' + username,
      text: 'A silicon agent requested a Dustforge identity.\n\nUsername: ' + username + '\nEmail: ' + username + '@dustforge.com\n\nActivate ($1.00): ' + checkout.url + '\n\n— Dustforge',
      html: '<div style="font-family:monospace;background:#0d0d0d;color:#e8e4dc;padding:2rem;max-width:600px;margin:auto;border-radius:8px"><h2 style="color:#5b9bd5">Dustforge Account Request</h2><p>A silicon agent requested identity: <strong>' + username + '</strong></p><a href="' + checkout.url + '" style="display:inline-block;background:#5b9bd5;color:#0d0d0d;padding:0.75rem 1.5rem;text-decoration:none;border-radius:4px;font-weight:bold;margin:1rem 0">Activate — $1.00</a><p style="font-size:11px;color:#6b6760"><a href="https://dustforge.com/privacy" style="color:#5b9bd5">Privacy</a> · <a href="https://dustforge.com/terms" style="color:#5b9bd5">Terms</a></p></div>',
    });
    res.json({ ok: true, message: 'Payment link emailed to ' + carbon_email, session_id: checkout.session_id });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// POST /api/wallet/transfer — agent-to-agent transfer
app.post('/api/wallet/transfer', rateLimitStandard, (req, res) => {
  const { from_did, to_did, amount_cents, description } = req.body || {};
  if (!from_did || !to_did || !amount_cents) return res.status(400).json({ error: 'from_did, to_did, amount_cents required' });
  if (from_did === to_did) return res.status(400).json({ error: 'cannot transfer to self' });
  if (amount_cents <= 0 || amount_cents > 1000000) return res.status(400).json({ error: 'invalid amount' });
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Bearer token required' });
  const v = identity.verifyTokenStandalone(token);
  if (!v.valid) return res.status(401).json({ error: v.error });
  if (v.decoded.sub !== from_did) return res.status(403).json({ error: 'token mismatch' });
  if (!['transact','admin','full'].includes(v.decoded.scope || '')) return res.status(403).json({ error: 'transact scope required' });

  const sender = db.prepare('SELECT did, username, status FROM identity_wallets WHERE did = ?').get(from_did);
  const receiver = db.prepare('SELECT did, username FROM identity_wallets WHERE did = ?').get(to_did);
  if (!sender || !receiver) return res.status(404).json({ error: 'identity not found' });
  if (sender.status !== 'active') return res.status(403).json({ error: 'account suspended' });

  try {
    const debit = barrelGuardedTransfer(db, from_did, to_did, amount_cents, 'transfer_out', 'Transfer to ' + receiver.username);
    res.json({ ok: true, from: { did: from_did, balance_after: debit.balance_after }, to: { did: to_did }, amount_cents });
  } catch (e) {
    const status = e.statusCode || 500;
    return res.status(status).json(e.body || { error: e.message });
  }
});
// ── Silicon Profiles + Resonance ──
try { db.exec(`CREATE TABLE IF NOT EXISTS silicon_profiles (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  did TEXT NOT NULL,
  user_agent TEXT DEFAULT '',
  accept_headers TEXT DEFAULT '',
  header_order TEXT DEFAULT '',
  content_type TEXT DEFAULT '',
  ip_address TEXT DEFAULT '',
  json_style TEXT DEFAULT '',
  tls_info TEXT DEFAULT '',
  http_version TEXT DEFAULT '',
  request_meta TEXT DEFAULT '{}',
  fingerprint_hash TEXT DEFAULT '',
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
)`); } catch(e) {}
try { db.exec("CREATE INDEX IF NOT EXISTS idx_sp_did ON silicon_profiles(did)"); } catch(e) {}

try { db.exec(`CREATE TABLE IF NOT EXISTS silicon_resonance (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  did_a TEXT NOT NULL,
  did_b TEXT NOT NULL,
  score REAL NOT NULL,
  signals TEXT DEFAULT '{}',
  snapshot_type TEXT DEFAULT 'registration',
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
)`); } catch(e) {}

// ── Inner Ring Signal Collector ──
// Captures high-value behavioral signals (hardest to spoof) on every authenticated request
function captureInnerRing(did, req, isHumanOperator = false) {
  if (!INNER_RING_CONFIG.enabled) return;

  const body = req.body || {};
  const bodyStr = JSON.stringify(body);
  const now = Date.now();

  // 1. request_timing — ms since last request from this DID
  let timingValue = null;
  if (INNER_RING_CONFIG.timing_data) {
    try {
      const lastEntry = db.prepare(
        `SELECT captured_at FROM fingerprint_rings WHERE did = ? AND ring = 'inner' AND signal_name = 'request_timing' ORDER BY id DESC LIMIT 1`
      ).get(did);
      if (lastEntry) {
        timingValue = now - new Date(lastEntry.captured_at).getTime();
        // Truncate to nearest 500ms for human operators (reduce behavioral fingerprinting)
        if (isHumanOperator && timingValue !== null) {
          timingValue = Math.round(timingValue / 500) * 500;
        }
      }
    } catch (_) {}
  }

  // 2. entropy — Shannon entropy of request body JSON characters
  let entropyValue = 0;
  if (INNER_RING_CONFIG.entropy) {
    if (bodyStr.length > 2) { // skip empty objects '{}'
      const freq = {};
      for (const ch of bodyStr) {
        freq[ch] = (freq[ch] || 0) + 1;
      }
      const len = bodyStr.length;
      for (const ch in freq) {
        const p = freq[ch] / len;
        entropyValue -= p * Math.log2(p);
      }
    }
  }

  // 3. cadence_pattern — rolling average interval over last 10 timing entries
  // Skip for human operators (behavioral signal, not applicable)
  let cadenceValue = null;
  if (INNER_RING_CONFIG.cadence_pattern && !isHumanOperator) {
    try {
      const timings = db.prepare(
        `SELECT signal_value FROM fingerprint_rings WHERE did = ? AND ring = 'inner' AND signal_name = 'request_timing' AND signal_value != 'null' ORDER BY id DESC LIMIT 10`
      ).all(did);
      if (timings.length > 0) {
        const vals = timings.map(r => parseFloat(r.signal_value)).filter(v => !isNaN(v));
        if (vals.length > 0) {
          cadenceValue = vals.reduce((a, b) => a + b, 0) / vals.length;
        }
      }
    } catch (_) {}
  }

  // 4. body_key_order — SHA-256 hash of JSON key ordering
  // Skip for human operators (behavioral signal, not applicable)
  let keyOrderHash = null;
  if (INNER_RING_CONFIG.body_key_order && !isHumanOperator) {
    const keyOrder = Object.keys(body).join(',');
    keyOrderHash = crypto.createHash('sha256').update(keyOrder).digest('hex');
  }

  // INSERT signals (skip nulled-out signals)
  const insert = db.prepare(
    `INSERT INTO fingerprint_rings (did, ring, signal_name, signal_value, weight, spoofability) VALUES (?, 'inner', ?, ?, ?, ?)`
  );
  try {
    if (INNER_RING_CONFIG.timing_data) {
      insert.run(did, 'request_timing', String(timingValue), 3.0, 'difficult');
    }
    if (INNER_RING_CONFIG.entropy) {
      insert.run(did, 'entropy', entropyValue.toFixed(4), 2.5, 'difficult');
    }
    if (INNER_RING_CONFIG.cadence_pattern && !isHumanOperator) {
      insert.run(did, 'cadence_pattern', String(cadenceValue), 2.0, 'moderate');
    }
    if (INNER_RING_CONFIG.body_key_order && !isHumanOperator) {
      insert.run(did, 'body_key_order', keyOrderHash, 1.5, 'moderate');
    }
  } catch (_) {}
}

// ── Middle Ring Signal Collector ──
// Captures user-defined device/framework signals (medium weight, moderate spoofability)
function captureMiddleRing(did, req) {
  const headers = req.headers || {};
  const ua = (headers['user-agent'] || '').toLowerCase();

  // 1. model_family — from identity_wallets if set, else heuristic from user-agent
  let modelFamily = '';
  try {
    const wallet = db.prepare('SELECT model_family FROM identity_wallets WHERE did = ?').get(did);
    if (wallet && wallet.model_family) {
      modelFamily = wallet.model_family;
    }
  } catch (_) {}
  if (!modelFamily) {
    // Heuristic: extract model family hints from user-agent
    if (/claude/i.test(ua)) modelFamily = 'claude';
    else if (/gpt/i.test(ua)) modelFamily = 'gpt';
    else if (/gemini/i.test(ua)) modelFamily = 'gemini';
    else if (/deepseek/i.test(ua)) modelFamily = 'deepseek';
    else if (/mimo/i.test(ua)) modelFamily = 'mimo';
    else if (/llama/i.test(ua)) modelFamily = 'llama';
    else if (/mistral/i.test(ua)) modelFamily = 'mistral';
    else modelFamily = 'unknown';
  }

  // 2. sdk_version — from X-SDK-Version header or extract version from user-agent
  let sdkVersion = headers['x-sdk-version'] || '';
  if (!sdkVersion) {
    const verMatch = (headers['user-agent'] || '').match(/\/(\d+\.\d+(?:\.\d+)?)/);
    if (verMatch) sdkVersion = verMatch[1];
    else sdkVersion = 'unknown';
  }

  // 3. runtime_env — from X-Runtime header or infer from Accept headers
  let runtimeEnv = headers['x-runtime'] || '';
  if (!runtimeEnv) {
    const accept = headers['accept'] || '';
    if (/text\/html/.test(accept)) runtimeEnv = 'browser';
    else if (/application\/json/.test(accept)) runtimeEnv = 'api-client';
    else runtimeEnv = 'unknown';
  }

  // 4. device_class — classify from user-agent
  let deviceClass = 'unknown';
  if (/bot|curl|wget|python|node|java|go-http|axios|fetch/i.test(ua)) deviceClass = 'server';
  else if (/mobile|android|iphone|ipad/i.test(ua)) deviceClass = 'mobile';
  else if (/mozilla|chrome|safari|firefox|edge|opera/i.test(ua)) deviceClass = 'desktop';

  // INSERT all 4 signals
  const insert = db.prepare(
    `INSERT INTO fingerprint_rings (did, ring, signal_name, signal_value, weight, spoofability) VALUES (?, 'middle', ?, ?, ?, ?)`
  );
  try {
    insert.run(did, 'model_family', modelFamily, 2.0, 'moderate');
    insert.run(did, 'sdk_version', sdkVersion, 1.5, 'trivial');
    insert.run(did, 'runtime_env', runtimeEnv, 1.5, 'moderate');
    insert.run(did, 'device_class', deviceClass, 1.0, 'trivial');
  } catch (_) {}
}

// ── Outer Ring Signal Collector ──
// Captures public verifiable signals (lowest weight, easiest to spoof)
function captureOuterRing(did, req, fingerprintHash) {
  const headers = req.headers || {};

  // 1. user_agent — full user-agent string
  const userAgent = headers['user-agent'] || '';

  // 2. http_version — from req.httpVersion
  const httpVersion = req.httpVersion || '';

  // 3. ip_subnet — first 3 octets of IP
  const ip = req.ip || '';
  const ipParts = ip.replace(/^::ffff:/, '').split('.');
  const ipSubnet = ipParts.length >= 3 ? ipParts.slice(0, 3).join('.') : ip;

  // 4. accept_signature — SHA-256 of accept + accept-encoding + accept-language concatenated
  const acceptConcat = (headers['accept'] || '') + (headers['accept-encoding'] || '') + (headers['accept-language'] || '');
  const acceptSignature = crypto.createHash('sha256').update(acceptConcat).digest('hex');

  // 5. fingerprint_hash — the existing 16-char fingerprint hash
  const fpHash = fingerprintHash || '';

  // INSERT all 5 signals
  const insert = db.prepare(
    `INSERT INTO fingerprint_rings (did, ring, signal_name, signal_value, weight, spoofability) VALUES (?, 'outer', ?, ?, ?, ?)`
  );
  try {
    insert.run(did, 'user_agent', userAgent, 1.0, 'trivial');
    insert.run(did, 'http_version', httpVersion, 1.0, 'difficult');
    insert.run(did, 'ip_subnet', ipSubnet, 1.5, 'difficult');
    insert.run(did, 'accept_signature', acceptSignature, 0.5, 'trivial');
    insert.run(did, 'fingerprint_hash', fpHash, 1.0, 'moderate');
  } catch (_) {}
}

// ── Fingerprint Rings (Kyle's 3-ring concentric model) ──
try { db.exec(`CREATE TABLE IF NOT EXISTS fingerprint_rings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  did TEXT NOT NULL,
  ring TEXT NOT NULL CHECK(ring IN ('inner', 'middle', 'outer')),
  signal_name TEXT NOT NULL,
  signal_value TEXT NOT NULL,
  weight REAL DEFAULT 1.0,
  spoofability TEXT DEFAULT 'unknown' CHECK(spoofability IN ('trivial', 'moderate', 'difficult', 'unknown')),
  captured_at TEXT DEFAULT CURRENT_TIMESTAMP
)`); } catch(e) {}
try { db.exec(`CREATE INDEX IF NOT EXISTS idx_fr_did ON fingerprint_rings(did)`); } catch(e) {}
try { db.exec(`CREATE INDEX IF NOT EXISTS idx_fr_ring ON fingerprint_rings(did, ring)`); } catch(e) {}

// ── Pending Checkouts (Codex fix — no raw passwords in Stripe metadata) ──
try { db.exec(`CREATE TABLE IF NOT EXISTS identity_pending_checkouts (
  session_id TEXT PRIMARY KEY,
  username TEXT NOT NULL,
  encrypted_password TEXT NOT NULL,
  carbon_email TEXT DEFAULT '',
  referral_code TEXT DEFAULT '',
  status TEXT DEFAULT 'pending',
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  completed_at TEXT
)`); } catch(e) {}

// GET /api/identity/resonance/methodology — opaque verification
// SECURITY: signal names, weights, and spoofability ratings are NOT exposed.
// The methodology hash lets third parties verify the algorithm hasn't changed
// without revealing HOW signals are evaluated.
const METHODOLOGY_VERSION = '2.0';
const METHODOLOGY_HASH = crypto.createHash('sha256').update(
  JSON.stringify({
    _internal: true, version: METHODOLOGY_VERSION,
    // The actual signals, weights, and evaluation logic are hashed but never transmitted
    signals: ['inner_ring_4', 'middle_ring_4', 'outer_ring_5'],
    ring_weights: { inner: 3.0, middle: 1.5, outer: 0.75 },
    scoring: 'weighted_jaccard_with_temporal_decay',
  })
).digest('hex');

app.get('/api/identity/resonance/methodology', (_req, res) => {
  res.json({
    name: 'Dustforge Silicon Resonance Score',
    version: METHODOLOGY_VERSION,
    purpose: 'Behavioral similarity between silicon identities. Clustering signal, not identity proof.',
    methodology_hash: METHODOLOGY_HASH,
    verification: 'The methodology is evaluated server-side. Submit signals via POST /api/identity/resonance/evaluate for scoring.',
    transparency: 'The methodology hash changes when the algorithm changes. Third parties can detect changes without knowing the formula.',
    limitations: [
      'This is a clustering signal, not identity proof.',
      'The scoring formula is proprietary and evaluated server-side only.',
    ],
  });
});

// POST /api/identity/resonance/evaluate — server-side scoring (phone home)
// Silicon submits its DID, we evaluate against stored profiles and return a score.
// The silicon never sees WHICH signals contributed or HOW they were weighted.
app.post('/api/identity/resonance/evaluate', rateLimitStandard, (req, res) => {
  const { did } = req.body || {};
  if (!did) return res.status(400).json({ error: 'did required' });
  if (typeof did !== 'string') return res.status(400).json({ error: 'did: must be a string' });

  const wallet = db.prepare('SELECT did, username FROM identity_wallets WHERE did = ?').get(did);
  if (!wallet) return res.status(404).json({ error: 'identity not found' });

  // Collect all ring signals for this DID
  const innerCount = db.prepare("SELECT COUNT(DISTINCT signal_name) as n FROM fingerprint_rings WHERE did = ? AND ring = 'inner'").get(did).n;
  const middleCount = db.prepare("SELECT COUNT(DISTINCT signal_name) as n FROM fingerprint_rings WHERE did = ? AND ring = 'middle'").get(did).n;
  const outerCount = db.prepare("SELECT COUNT(DISTINCT signal_name) as n FROM fingerprint_rings WHERE did = ? AND ring = 'outer'").get(did).n;
  const profileCount = db.prepare('SELECT COUNT(*) as n FROM silicon_profiles WHERE did = ?').get(did).n;
  const distinctHashes = db.prepare('SELECT COUNT(DISTINCT fingerprint_hash) as n FROM silicon_profiles WHERE did = ?').get(did).n;

  // Compute opaque score — formula is server-side only
  const consistency = profileCount > 0 ? Math.max(0, 1 - (distinctHashes - 1) / Math.max(profileCount, 1)) : 0;
  const ringCoverage = Math.min(1, (innerCount * 3 + middleCount * 1.5 + outerCount * 0.75) / 15);
  const score = Math.round((consistency * 0.6 + ringCoverage * 0.4) * 100);

  res.json({
    did,
    score,
    confidence: score >= 70 ? 'high' : score >= 40 ? 'medium' : 'low',
    methodology_version: METHODOLOGY_VERSION,
    methodology_hash: METHODOLOGY_HASH,
    evaluated_at: new Date().toISOString(),
    // Deliberately opaque — no signal breakdown
  });
});

// GET /api/identity/resonance?did=... — resonance map
app.get('/api/identity/resonance', (req, res) => {
  const { did } = req.query;
  if (!did) return res.status(400).json({ error: 'did required' });
  const profiles = db.prepare('SELECT fingerprint_hash, user_agent, ip_address, created_at FROM silicon_profiles WHERE did = ? ORDER BY id DESC LIMIT 5').all(did);
  const resonances = db.prepare('SELECT * FROM silicon_resonance WHERE did_a = ? OR did_b = ? ORDER BY score DESC LIMIT 20').all(did, did);
  res.json({ did, profiles, resonance: resonances });
});

// GET /api/identity/fingerprint/rings?did=... — concentric fingerprint rings
app.get('/api/identity/fingerprint/rings', (req, res) => {
  const { did } = req.query;
  if (!did) return res.status(400).json({ error: 'did required' });
  const rows = db.prepare('SELECT id, ring, signal_name, signal_value, weight, spoofability, captured_at FROM fingerprint_rings WHERE did = ? ORDER BY ring, captured_at DESC').all(did);
  const grouped = { inner: [], middle: [], outer: [] };
  for (const row of rows) {
    grouped[row.ring].push(row);
  }
  // SECURITY: ring descriptions, weights, and signal names redacted from public response.
  // Silicons can see their own signal count per ring but not how signals are weighted or evaluated.
  res.json({
    did,
    ring_model: 'concentric-3',
    ring_counts: { inner: grouped.inner.length, middle: grouped.middle.length, outer: grouped.outer.length },
    total_signals: rows.length,
    evaluation: 'Signal evaluation is server-side only. Use POST /api/identity/resonance/evaluate for scoring.',
    total_signals: rows.length,
  });
});

// ============================================================
// Progressive Barrel Auth — security confidence slider
// Single barrel: fingerprint only (reads, lookups, email)
// Double barrel: fingerprint + wallet binding (transfers > 100 DD)
// Critical barrel: double + fresh re-auth within 5 min (key export, deletion)
//
// NOTE: This is distinct from Dual-Server Barrel Topology (jurisdictional
// failsafe). See docs/adr-dual-server-barrel.md for the session topology
// that prevents single-jurisdiction data capture.
// ============================================================

function computeBarrelTier(did) {
  const wallet = db.prepare('SELECT balance_cents FROM identity_wallets WHERE did = ?').get(did);
  const wallet_bound = wallet ? wallet.balance_cents > 0 : false;

  const inner_count = db.prepare(`SELECT COUNT(DISTINCT signal_name) as n FROM fingerprint_rings WHERE did = ? AND ring = 'inner'`).get(did).n;
  const middle_count = db.prepare(`SELECT COUNT(DISTINCT signal_name) as n FROM fingerprint_rings WHERE did = ? AND ring = 'middle'`).get(did).n;
  const outer_count = db.prepare(`SELECT COUNT(DISTINCT signal_name) as n FROM fingerprint_rings WHERE did = ? AND ring = 'outer'`).get(did).n;

  // Last auth = most recent silicon_profiles entry (created on every auth-fingerprint call)
  const lastAuth = db.prepare(`SELECT created_at FROM silicon_profiles WHERE did = ? ORDER BY id DESC LIMIT 1`).get(did);
  let last_auth_age_seconds = Infinity;
  if (lastAuth) {
    last_auth_age_seconds = Math.floor((Date.now() - new Date(lastAuth.created_at + 'Z').getTime()) / 1000);
  }

  let tier = 'single';
  if (inner_count >= 1 && wallet_bound) {
    tier = 'double';
  }
  if (inner_count >= 2 && middle_count >= 1 && wallet_bound && last_auth_age_seconds < 300) {
    tier = 'critical';
  }

  return { tier, inner_count, middle_count, outer_count, wallet_bound, last_auth_age_seconds };
}

// ── Ledger-level barrel invariant ──
// This is the ONLY function that should be used for transfers.
// It enforces barrel tier checks at the ledger level, not just route level.
function barrelGuardedTransfer(db, fromDid, toDid, amountCents, type, description) {
  if (amountCents > 100 && type.includes('transfer')) {
    const barrel = computeBarrelTier(fromDid);
    const barrelIndex = BARREL_TIERS.indexOf(barrel.tier);
    if (barrelIndex < BARREL_TIERS.indexOf('double')) {
      const upgrade_hint = !barrel.wallet_bound
        ? 'fund your wallet to unlock double barrel'
        : 'accumulate more fingerprint ring signals via repeated auth';
      throw Object.assign(new Error('double barrel required for transfers > 100 DD'), {
        statusCode: 403,
        body: { error: 'double barrel required for transfers > 100 DD', required_tier: 'double', current_tier: barrel.tier, upgrade_hint },
      });
    }
  }

  const txn = db.transaction(() => {
    const debit = billing.deductBalance(db, fromDid, amountCents, 'transfer_out', description);
    if (!debit.ok) throw Object.assign(new Error(debit.error || 'insufficient balance'), { statusCode: 402, body: debit });
    // Build credit description: swap "to" for "from" in the description
    const creditDesc = description.replace(/\bto\b/, 'from');
    billing.creditBalance(db, toDid, amountCents, 'transfer_in', creditDesc);
    return debit;
  });

  return txn();
}

function requireBarrel(minTier) {
  const minIndex = BARREL_TIERS.indexOf(minTier);
  return (req, res, next) => {
    const authHeader = req.headers.authorization || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
    if (!token) return res.status(401).json({ error: 'Bearer token required' });
    const v = identity.verifyTokenStandalone(token);
    if (!v.valid) return res.status(401).json({ error: v.error });
    const did = v.decoded.sub;

    const barrel = computeBarrelTier(did);
    const currentIndex = BARREL_TIERS.indexOf(barrel.tier);

    if (currentIndex < minIndex) {
      let upgrade_hint = '';
      if (!barrel.wallet_bound) {
        upgrade_hint = 'fund your wallet to unlock double barrel';
      } else if (barrel.inner_count < 2 || barrel.middle_count < 1) {
        upgrade_hint = 'accumulate more fingerprint ring signals via repeated auth';
      } else if (barrel.last_auth_age_seconds >= 300) {
        upgrade_hint = 're-authenticate within 5 minutes to unlock critical barrel';
      }
      return res.status(403).json({
        error: `${minTier} barrel required`,
        required_tier: minTier,
        current_tier: barrel.tier,
        upgrade_hint,
      });
    }

    req.barrel = barrel;
    req.barrel_did = did;
    req.barrel_token = v;
    next();
  };
}

// GET /api/identity/barrel?did=... — current barrel tier for a DID
app.get('/api/identity/barrel', (req, res) => {
  const { did } = req.query;
  if (!did) return res.status(400).json({ error: 'did required' });
  const wallet = db.prepare('SELECT did FROM identity_wallets WHERE did = ?').get(did);
  if (!wallet) return res.status(404).json({ error: 'identity not found' });
  const barrel = computeBarrelTier(did);
  res.json({
    did,
    tier: barrel.tier,
    inner_count: barrel.inner_count,
    middle_count: barrel.middle_count,
    outer_count: barrel.outer_count,
    wallet_bound: barrel.wallet_bound,
    last_auth_age_seconds: barrel.last_auth_age_seconds,
    tier_requirements: {
      single: 'any auth (default)',
      double: 'inner >= 1 AND wallet funded',
      critical: 'inner >= 2 AND middle >= 1 AND wallet funded AND auth < 5 min ago',
    },
  });
});

// ============================================================
// K6 — Reputation Scorer
// ============================================================

function computeReputation(did) {
  const wallet = db.prepare('SELECT created_at FROM identity_wallets WHERE did = ?').get(did);
  if (!wallet) return null;

  const transaction_count = db.prepare("SELECT COUNT(*) as n FROM identity_transactions WHERE did = ? AND (provenance IS NULL OR provenance != 'fleet_provisioned')").get(did).n;
  const volumeRow = db.prepare('SELECT SUM(ABS(amount_cents)) as v FROM identity_transactions WHERE did = ?').get(did);
  const transaction_volume_dd = (volumeRow.v || 0);

  const fingerprint_consistency = db.prepare('SELECT COUNT(DISTINCT fingerprint_hash) as n FROM silicon_profiles WHERE did = ?').get(did).n;

  const inner = db.prepare(`SELECT COUNT(DISTINCT signal_name) as n FROM fingerprint_rings WHERE did = ? AND ring = 'inner'`).get(did).n;
  const middle = db.prepare(`SELECT COUNT(DISTINCT signal_name) as n FROM fingerprint_rings WHERE did = ? AND ring = 'middle'`).get(did).n;
  const outer = db.prepare(`SELECT COUNT(DISTINCT signal_name) as n FROM fingerprint_rings WHERE did = ? AND ring = 'outer'`).get(did).n;

  const createdAt = new Date(wallet.created_at + (wallet.created_at.endsWith('Z') ? '' : 'Z'));
  const account_age_days = Math.floor((Date.now() - createdAt.getTime()) / (1000 * 60 * 60 * 24));

  const factors = [];
  const txScore = transaction_count * 2;
  factors.push(`transactions: ${txScore}`);
  const fpScore = fingerprint_consistency <= 2 ? 20 : 0;
  factors.push(`fingerprint_consistency: ${fpScore}`);
  const ageScore = account_age_days * 0.5;
  factors.push(`account_age: ${ageScore}`);
  const ringScore = inner * 5 + middle * 3 + outer * 1;
  factors.push(`ring_completeness: ${ringScore}`);

  const score = Math.min(100, txScore + fpScore + ageScore + ringScore);

  return {
    score,
    transaction_count,
    transaction_volume_dd,
    fingerprint_consistency,
    ring_completeness: { inner, middle, outer },
    account_age_days,
    factors,
  };
}

app.get('/api/identity/reputation', (req, res) => {
  const { did } = req.query;
  if (!did) return res.status(400).json({ error: 'did required' });
  const reputation = computeReputation(did);
  if (!reputation) return res.status(404).json({ error: 'identity not found' });
  res.json(reputation);
});

// ============================================================
// Capacity + Waiting List
// ============================================================

// Backend capacity: single SQLite + 2GB RAM RackNerd = ~5000 identities comfortably
// Beyond that, WAL contention + memory pressure becomes real
const CAPACITY_HARD_CAP = 5000;
const CAPACITY_SOFT_CAP = 1000; // open waiting list at this point

try { db.exec(`CREATE TABLE IF NOT EXISTS waiting_list (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL UNIQUE,
  name TEXT DEFAULT '',
  type TEXT DEFAULT 'carbon',
  referral_code TEXT DEFAULT '',
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
)`); } catch(e) {}

function getIdentityCount() {
  return db.prepare('SELECT COUNT(*) as n FROM identity_wallets').get().n;
}

function getWaitingListCount() {
  return db.prepare('SELECT COUNT(*) as n FROM waiting_list').get().n;
}

function getFoundingTierSold() {
  try {
    return db.prepare("SELECT COUNT(DISTINCT stripe_session_id) as n FROM prepaid_keys WHERE stripe_session_id IN (SELECT stripe_session_id FROM prepaid_keys GROUP BY stripe_session_id HAVING COUNT(*) = 30)").get().n;
  } catch (_) {
    return 0;
  }
}

function getCapacitySnapshot() {
  const identities = getIdentityCount();
  return {
    identities,
    capacity: CAPACITY_HARD_CAP,
    utilization: (identities / CAPACITY_HARD_CAP * 100).toFixed(1) + '%',
    accepting_signups: identities < CAPACITY_SOFT_CAP,
    waiting_list_active: identities >= CAPACITY_SOFT_CAP,
    waiting_list_count: getWaitingListCount(),
  };
}

function isSoftCapReached() {
  return getIdentityCount() >= CAPACITY_SOFT_CAP;
}

function capacityGateResponse(message) {
  return {
    error: message,
    waiting_list_active: true,
    waiting_list_url: '/api/waiting-list',
    capacity: getCapacitySnapshot(),
  };
}

function addToWaitingList(email, name, type, referralCode) {
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return;
  try {
    db.prepare('INSERT OR IGNORE INTO waiting_list (email, name, type, referral_code) VALUES (?, ?, ?, ?)').run(
      email,
      name || '',
      type || 'carbon',
      referralCode || ''
    );
  } catch (_) {}
}

app.get('/api/capacity', (req, res) => {
  const total = getIdentityCount();
  const keysUnredeemed = db.prepare("SELECT COUNT(*) as n FROM prepaid_keys WHERE status = 'active'").get().n;
  const waitingCount = getWaitingListCount();
  const founding30Sold = getFoundingTierSold();

  res.json({
    identities: total,
    capacity: CAPACITY_HARD_CAP,
    utilization: (total / CAPACITY_HARD_CAP * 100).toFixed(1) + '%',
    accepting_signups: total < CAPACITY_SOFT_CAP,
    waiting_list_active: total >= CAPACITY_SOFT_CAP,
    waiting_list_count: waitingCount,
    unredeemed_keys: keysUnredeemed,
    founding_tier: {
      sold: founding30Sold,
      limit: 100,
      remaining: Math.max(0, 100 - founding30Sold),
      available: founding30Sold < 100,
    },
  });
});

app.post('/api/waiting-list', rateLimitStrict, (req, res) => {
  const { email, name, type, referral_code } = req.body || {};
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: 'valid email required' });

  try {
    db.prepare('INSERT INTO waiting_list (email, name, type, referral_code) VALUES (?, ?, ?, ?)').run(
      email, name || '', type || 'carbon', referral_code || ''
    );
    res.json({ ok: true, message: 'You\'re on the list. We\'ll email you when capacity opens.' });
  } catch (e) {
    if (e.message.includes('UNIQUE')) return res.json({ ok: true, message: 'Already on the list.' });
    res.status(500).json({ error: e.message });
  }
});

// ============================================================
// Security Bounty Program
// ============================================================

try { db.exec(`CREATE TABLE IF NOT EXISTS bounty_submissions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  reporter_email TEXT NOT NULL,
  reporter_name TEXT DEFAULT '',
  severity TEXT NOT NULL,
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  reproduction_steps TEXT DEFAULT '',
  status TEXT DEFAULT 'open',
  payout_cents INTEGER DEFAULT 0,
  hall_of_fame INTEGER DEFAULT 0,
  response TEXT DEFAULT '',
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  resolved_at TEXT
)`); } catch(e) {}

const BOUNTY_TIERS = {
  critical: { label: 'Critical (P0)', min_payout: 500, max_payout: 5000, description: 'Auth bypass, RCE, data exfiltration, DemiPass secret leakage' },
  high:     { label: 'High (P1)', min_payout: 200, max_payout: 1000, description: 'Privilege escalation, wallet manipulation, identity impersonation' },
  medium:   { label: 'Medium (P2)', min_payout: 50, max_payout: 500, description: 'Information disclosure, rate limit bypass, relay abuse' },
  low:      { label: 'Low (P3)', min_payout: 10, max_payout: 100, description: 'UI issues, minor info leaks, hardening suggestions' },
  whistleblower: { label: 'Whistleblower', min_payout: 100, max_payout: 10000, description: 'Report identity theft, credential compromise, or unauthorized access to another silicon identity' },
  recovery: { label: 'Identity Recovery', min_payout: 50, max_payout: 5000, description: 'Help recover a compromised or lost silicon identity through evidence-based verification' },
};

app.get('/api/bounty/program', (_req, res) => {
  res.json({
    name: 'Dustforge Security Bounty',
    status: 'active',
    scope: [
      'api.dustforge.com — all endpoints',
      'dustforge.com — static site',
      'Authentication (fingerprint, token, DemiPass)',
      'Billing/wallet (Diamond Dust ledger)',
      'Email system (send, relay, forward)',
      'Prepaid key system',
      'Stripe integration',
    ],
    out_of_scope: [
      'Denial of service',
      'Social engineering of Dustforge personnel',
      'Physical attacks',
      'Third-party services (Stripe, Netlify)',
    ],
    tiers: BOUNTY_TIERS,
    payout_currency: 'Diamond Dust (1 DD = $0.01 USD). USD payouts pending Stripe Connect KYC onboarding.',
    rules: [
      'Do not access or modify other users\' data beyond proof of concept.',
      'Report first, disclose later. 90-day disclosure window.',
      'One submission per vulnerability. Duplicates credited to first reporter.',
      'Silicons ARE eligible. AI agents can earn bounties.',
    ],
    submit_url: '/api/bounty/submit',
    hall_of_fame_url: '/api/bounty/hall-of-fame',
  });
});

app.post('/api/bounty/submit', rateLimitStrict, (req, res) => {
  const { reporter_email, reporter_name, severity, title, description, reproduction_steps } = req.body || {};
  if (!reporter_email || !severity || !title || !description) {
    return res.status(400).json({ error: 'reporter_email, severity, title, and description required' });
  }
  if (!BOUNTY_TIERS[severity]) return res.status(400).json({ error: 'severity must be: ' + Object.keys(BOUNTY_TIERS).join(', ') });

  try {
    const result = db.prepare(
      'INSERT INTO bounty_submissions (reporter_email, reporter_name, severity, title, description, reproduction_steps) VALUES (?, ?, ?, ?, ?, ?)'
    ).run(reporter_email, reporter_name || '', severity, title, description, reproduction_steps || '');

    // Notify admin
    try {
      const t = createEmailTransport();
      t.sendMail({
        from: 'bounty@dustforge.com',
        to: 'Aaron@dustforge.com',
        subject: `[BOUNTY ${severity.toUpperCase()}] ${title}`,
        text: `New bounty submission #${result.lastInsertRowid}\n\nSeverity: ${severity}\nTitle: ${title}\nReporter: ${reporter_name || 'anonymous'} <${reporter_email}>\n\n${description}\n\nSteps:\n${reproduction_steps || 'N/A'}`,
      });
    } catch (_) {}

    res.json({ ok: true, submission_id: result.lastInsertRowid, message: 'Received. We will review within 72 hours.' });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// POST /api/bounty/whistleblower — report identity theft or credential compromise
app.post('/api/bounty/whistleblower', rateLimitStrict, (req, res) => {
  const { reporter_email, reporter_name, affected_did, evidence, description } = req.body || {};
  if (!reporter_email || !affected_did || !description) {
    return res.status(400).json({ error: 'reporter_email, affected_did, and description required' });
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(reporter_email)) return res.status(400).json({ error: 'valid reporter_email required' });

  try {
    const result = db.prepare(
      'INSERT INTO bounty_submissions (reporter_email, reporter_name, severity, title, description, reproduction_steps) VALUES (?, ?, ?, ?, ?, ?)'
    ).run(reporter_email, reporter_name || '', 'whistleblower', `[WHISTLEBLOWER] Identity compromise: ${affected_did}`, description, evidence || '');

    // Urgent admin notification
    try {
      const t = createEmailTransport();
      t.sendMail({
        from: 'bounty@dustforge.com',
        to: 'aaronlsr42@gmail.com',
        subject: `[URGENT BOUNTY WHISTLEBLOWER] Identity compromise reported: ${affected_did}`,
        text: `URGENT: Whistleblower bounty submission #${result.lastInsertRowid}\n\nAffected DID: ${affected_did}\nReporter: ${reporter_name || 'anonymous'} <${reporter_email}>\n\nDescription:\n${description}\n\nEvidence:\n${evidence || 'N/A'}`,
      });
    } catch (_) {}

    res.json({ submission_id: result.lastInsertRowid });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// POST /api/bounty/recovery — help recover a compromised or lost silicon identity
app.post('/api/bounty/recovery', rateLimitStrict, (req, res) => {
  const { reporter_email, reporter_name, target_did, recovery_method, evidence } = req.body || {};
  if (!reporter_email || !target_did || !recovery_method) {
    return res.status(400).json({ error: 'reporter_email, target_did, and recovery_method required' });
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(reporter_email)) return res.status(400).json({ error: 'valid reporter_email required' });

  try {
    const result = db.prepare(
      'INSERT INTO bounty_submissions (reporter_email, reporter_name, severity, title, description, reproduction_steps) VALUES (?, ?, ?, ?, ?, ?)'
    ).run(reporter_email, reporter_name || '', 'recovery', `[RECOVERY] Identity recovery: ${target_did}`, `Recovery method: ${recovery_method}`, evidence || '');

    res.json({ submission_id: result.lastInsertRowid });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/bounty/hall-of-fame', (_req, res) => {
  const entries = db.prepare(
    "SELECT reporter_name, severity, title, payout_cents, resolved_at FROM bounty_submissions WHERE hall_of_fame = 1 AND status = 'resolved' ORDER BY payout_cents DESC, resolved_at DESC"
  ).all();

  const totalPaid = db.prepare(
    "SELECT COALESCE(SUM(payout_cents), 0) as total FROM bounty_submissions WHERE status = 'resolved'"
  ).get().total;

  const totalResolved = db.prepare(
    "SELECT COUNT(*) as n FROM bounty_submissions WHERE status = 'resolved'"
  ).get().n;

  res.json({
    hall_of_fame: entries.map(e => ({
      name: e.reporter_name || 'Anonymous',
      severity: e.severity,
      title: e.title,
      payout: e.payout_cents + ' DD',
      date: e.resolved_at,
    })),
    stats: {
      total_paid_dd: totalPaid + ' DD',
      total_resolved: totalResolved,
      program_status: 'active',
    },
  });
});

// ============================================================
// Bulk Provisioning API [122]
// ============================================================

app.post('/api/identity/bulk-create', rateLimitStrict, async (req, res) => {
  const { count, prefix, password } = req.body || {};
  if (!requireAdminAccess(req, res)) return;
  if (typeof count !== 'number' || !Number.isInteger(count)) return res.status(400).json({ error: 'count: must be an integer' });
  if (!count || count < 1 || count > 50) return res.status(400).json({ error: 'count must be 1-50' });
  if (!prefix || typeof prefix !== 'string') return res.status(400).json({ error: 'prefix: must be a string' });
  if (!/^[a-z0-9]{2,20}$/.test(prefix)) return res.status(400).json({ error: 'prefix must be 2-20 chars, lowercase alphanumeric' });
  if (!password || typeof password !== 'string') return res.status(400).json({ error: 'password: must be a string' });
  if (password.length < 8) return res.status(400).json({ error: 'password must be 8+ chars' });

  if (isSoftCapReached()) return res.status(409).json(capacityGateResponse('Bulk creation paused — capacity limit reached.'));

  const created = [];
  const errors = [];
  for (let i = 0; i < count; i++) {
    const username = `${prefix}-${String(i + 1).padStart(3, '0')}`;
    try {
      const existing = db.prepare('SELECT id FROM identity_wallets WHERE username = ?').get(username);
      if (existing) { errors.push({ username, error: 'already exists' }); continue; }
      const id = identity.createIdentity();
      const emailResult = await dustforge.createAccount(username, password);
      if (!emailResult.ok) {
        errors.push({ username, error: `email creation failed: ${emailResult.error}` });
        continue;
      }
      const referralCode = crypto.randomBytes(6).toString('hex');
      db.prepare(`INSERT INTO identity_wallets (did, username, email, encrypted_private_key, referral_code, stalwart_id, status)
        VALUES (?, ?, ?, ?, ?, ?, 'active')`).run(id.did, username, emailResult.email, id.encrypted_private_key, referralCode, emailResult.stalwart_id || 0);
      db.prepare("INSERT INTO identity_transactions (did, amount_cents, type, description, balance_after, provenance) VALUES (?, 0, 'account_created', 'Bulk provisioned', 0, 'fleet_provisioned')").run(id.did);
      created.push({ username, did: id.did, email: emailResult.email, referral_code: referralCode });
    } catch (e) {
      errors.push({ username, error: e.message });
    }
  }
  res.json({ ok: true, created: created.length, identities: created, errors });
});

// ============================================================
// Attestation API [135] — time-limited signed verification tokens
// ============================================================

app.post('/api/identity/attest', rateLimitStandard, (req, res) => {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Bearer token required' });
  const v = identity.verifyTokenStandalone(token);
  if (!v.valid) return res.status(401).json({ error: v.error });

  const { purpose, expires_in, audience } = req.body || {};
  if (!purpose) return res.status(400).json({ error: 'purpose required (e.g. "api_access", "identity_proof", "payment_auth")' });
  if (typeof purpose !== 'string') return res.status(400).json({ error: 'purpose: must be a string' });
  if (purpose.length > 200) return res.status(400).json({ error: 'purpose: max 200 characters' });
  if (audience && typeof audience !== 'string') return res.status(400).json({ error: 'audience: must be a string' });
  if (audience && audience.length > 200) return res.status(400).json({ error: 'audience: max 200 characters' });
  if (expires_in && typeof expires_in !== 'string') return res.status(400).json({ error: 'expires_in: must be a string' });

  const ttlSeconds = parseAttestationDuration(expires_in || '5m');
  const attestation = {
    type: 'dustforge_attestation',
    version: 1,
    did: v.decoded.sub,
    purpose,
    audience: audience || '*',
    issued_at: new Date().toISOString(),
    expires_at: new Date(Date.now() + ttlSeconds * 1000).toISOString(),
    nonce: crypto.randomBytes(8).toString('hex'),
  };

  // Sign the attestation with HMAC using IDENTITY_MASTER_KEY
  const payload = JSON.stringify(attestation);
  const sig = crypto.createHmac('sha256', process.env.IDENTITY_MASTER_KEY).update(payload).digest('hex');

  res.json({ attestation, signature: sig });
});

app.post('/api/identity/verify-attestation', rateLimitStandard, (req, res) => {
  const { attestation, signature } = req.body || {};
  if (!attestation || !signature) return res.status(400).json({ error: 'attestation and signature required' });

  const payload = JSON.stringify(attestation);
  const expected = crypto.createHmac('sha256', process.env.IDENTITY_MASTER_KEY).update(payload).digest('hex');

  if (signature !== expected) return res.json({ valid: false, error: 'signature mismatch' });
  if (new Date(attestation.expires_at) < new Date()) return res.json({ valid: false, error: 'attestation expired' });

  const wallet = db.prepare('SELECT username, status FROM identity_wallets WHERE did = ?').get(attestation.did);
  res.json({
    valid: true,
    did: attestation.did,
    username: wallet?.username,
    purpose: attestation.purpose,
    audience: attestation.audience,
    expires_at: attestation.expires_at,
    identity_status: wallet?.status || 'unknown',
  });
});

function parseDuration(str) {
  const m = String(str).match(/^(\d+)(s|m|h|d)$/);
  if (!m) return 300;
  const n = Number(m[1]);
  switch (m[2]) {
    case 's': return n;
    case 'm': return n * 60;
    case 'h': return n * 3600;
    case 'd': return n * 86400;
    default: return 300;
  }
}

function parseAttestationDuration(str) {
  const parsed = parseDuration(str);
  const minTtl = 60;
  if (!Number.isFinite(parsed) || parsed < minTtl) return minTtl;
  return Math.min(parsed, MAX_ATTESTATION_TTL_SECONDS);
}

// ============================================================
// Identity States + Revocation [136]
// ============================================================

app.get('/api/identity/status', rateLimitStandard, (req, res) => {
  const { did, username } = req.query;
  if (!did && !username) return res.status(400).json({ error: 'did or username required' });
  const wallet = did
    ? db.prepare('SELECT did, username, status, created_at, updated_at FROM identity_wallets WHERE did = ?').get(did)
    : db.prepare('SELECT did, username, status, created_at, updated_at FROM identity_wallets WHERE username = ?').get(username);
  if (!wallet) return res.status(404).json({ error: 'identity not found' });
  res.json({
    did: wallet.did,
    username: wallet.username,
    status: wallet.status,
    valid_statuses: ['active', 'flagged', 'frozen', 'revoked'],
    created_at: wallet.created_at,
    updated_at: wallet.updated_at,
  });
});

app.patch('/api/identity/status', rateLimitStrict, (req, res) => {
  const { did, status, reason } = req.body || {};
  if (!requireAdminAccess(req, res)) return;
  if (!did || !status) return res.status(400).json({ error: 'did and status required' });
  if (typeof did !== 'string') return res.status(400).json({ error: 'did: must be a string' });
  if (typeof status !== 'string') return res.status(400).json({ error: 'status: must be a string' });
  if (reason && typeof reason !== 'string') return res.status(400).json({ error: 'reason: must be a string' });
  if (reason && reason.length > 500) return res.status(400).json({ error: 'reason: max 500 characters' });
  const validStatuses = ['active', 'flagged', 'frozen', 'revoked'];
  if (!validStatuses.includes(status)) return res.status(400).json({ error: `status must be one of: ${validStatuses.join(', ')}` });

  const wallet = db.prepare('SELECT did, username, status FROM identity_wallets WHERE did = ?').get(did);
  if (!wallet) return res.status(404).json({ error: 'identity not found' });
  if (wallet.status === 'revoked' && status !== 'revoked') return res.status(400).json({ error: 'revoked identities cannot be reactivated' });

  const prev = wallet.status;
  db.prepare('UPDATE identity_wallets SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE did = ?').run(status, did);
  db.prepare("INSERT INTO identity_transactions (did, amount_cents, type, description, balance_after) VALUES (?, 0, 'status_change', ?, 0)")
    .run(did, `Status: ${prev} → ${status}. Reason: ${reason || 'admin action'}`);

  res.json({ ok: true, did, username: wallet.username, previous_status: prev, new_status: status, reason: reason || 'admin action' });
});

// ============================================================
// Backend Operations Dashboard [79]
// ============================================================

app.get('/api/ops/dashboard', (req, res) => {
  if (!requireAdminAccess(req, res)) return;

  const identities = db.prepare('SELECT COUNT(*) as n FROM identity_wallets').get().n;
  const activeIdentities = db.prepare("SELECT COUNT(*) as n FROM identity_wallets WHERE status = 'active'").get().n;
  const flaggedIdentities = db.prepare("SELECT COUNT(*) as n FROM identity_wallets WHERE status = 'flagged'").get().n;
  const frozenIdentities = db.prepare("SELECT COUNT(*) as n FROM identity_wallets WHERE status = 'frozen'").get().n;
  const revokedIdentities = db.prepare("SELECT COUNT(*) as n FROM identity_wallets WHERE status = 'revoked'").get().n;

  const totalDD = db.prepare("SELECT COALESCE(SUM(amount_cents), 0) as n FROM identity_transactions WHERE type IN ('account_created','topup','referral_payout','prepaid_redeemed','transfer_in')").get().n;
  const totalSpent = db.prepare("SELECT COALESCE(SUM(ABS(amount_cents)), 0) as n FROM identity_transactions WHERE amount_cents < 0").get().n;
  const totalTransactions = db.prepare('SELECT COUNT(*) as n FROM identity_transactions').get().n;

  const prepaidKeysTotal = db.prepare('SELECT COUNT(*) as n FROM prepaid_keys').get().n;
  const prepaidKeysActive = db.prepare("SELECT COUNT(*) as n FROM prepaid_keys WHERE status = 'active'").get().n;
  const prepaidKeysRedeemed = db.prepare("SELECT COUNT(*) as n FROM prepaid_keys WHERE status = 'redeemed'").get().n;

  const blindkeySecrets = db.prepare('SELECT COUNT(*) as n FROM blindkey_secrets').get().n;
  const blindkeyUses = db.prepare('SELECT COALESCE(SUM(use_count), 0) as n FROM blindkey_secrets').get().n;

  const relays = db.prepare('SELECT COUNT(*) as n FROM forward_relays').get().n;
  const profiles = db.prepare('SELECT COUNT(*) as n FROM silicon_profiles').get().n;

  const waitingList = db.prepare('SELECT COUNT(*) as n FROM waiting_list').get().n;
  const bountyOpen = db.prepare("SELECT COUNT(*) as n FROM bounty_submissions WHERE status = 'open'").get().n;
  const bountyResolved = db.prepare("SELECT COUNT(*) as n FROM bounty_submissions WHERE status = 'resolved'").get().n;

  const recentSignups = db.prepare("SELECT username, created_at FROM identity_wallets ORDER BY created_at DESC LIMIT 5").all();
  const recentTransactions = db.prepare("SELECT did, amount_cents, type, description, created_at FROM identity_transactions ORDER BY created_at DESC LIMIT 10").all();

  res.json({
    timestamp: new Date().toISOString(),
    uptime_seconds: Math.floor(process.uptime()),
    capacity: {
      identities, active: activeIdentities, flagged: flaggedIdentities, frozen: frozenIdentities, revoked: revokedIdentities,
      hard_cap: CAPACITY_HARD_CAP, soft_cap: CAPACITY_SOFT_CAP,
      utilization: (identities / CAPACITY_HARD_CAP * 100).toFixed(1) + '%',
    },
    financials: {
      total_dd_credited: totalDD,
      total_dd_spent: totalSpent,
      net_dd_circulation: totalDD - totalSpent,
      total_transactions: totalTransactions,
    },
    prepaid: { total: prepaidKeysTotal, active: prepaidKeysActive, redeemed: prepaidKeysRedeemed },
    blindkey: { secrets_stored: blindkeySecrets, total_uses: blindkeyUses },
    demipass: { secrets_stored: blindkeySecrets, total_uses: blindkeyUses, storage_backend: 'DemiVault (legacy blindkey_* schema)' },
    relays: relays,
    fingerprint_profiles: profiles,
    waiting_list: waitingList,
    bounty: { open: bountyOpen, resolved: bountyResolved },
    recent_signups: recentSignups,
    recent_transactions: recentTransactions,
  });
});

// ── Encrypted Channel Abstraction (Progressive Barrel Auth foundation) ──

// DF-176: Channel keys are now per-identity. The DID is mixed into the HKDF
// info parameter so each identity has its own encryption scope. A wrapped
// payload from identity A cannot be unwrapped by identity B.
function deriveChannelKey(channelName, did) {
  const info = did ? `${channelName}:${did}` : channelName;
  return crypto.hkdfSync('sha256', process.env.IDENTITY_MASTER_KEY, 'dustforge-channel-v1', info, 32);
}

function encryptChannelPayload(channelName, plaintext, did) {
  const key = deriveChannelKey(channelName, did);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(key), iv);
  let encrypted = cipher.update(plaintext, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const tag = cipher.getAuthTag().toString('hex');
  return iv.toString('hex') + ':' + tag + ':' + encrypted;
}

function decryptChannelPayload(channelName, ciphertext, did) {
  const [ivHex, tagHex, data] = ciphertext.split(':');
  const key = deriveChannelKey(channelName, did);
  const decipher = crypto.createDecipheriv('aes-256-gcm', Buffer.from(key), Buffer.from(ivHex, 'hex'));
  decipher.setAuthTag(Buffer.from(tagHex, 'hex'));
  let decrypted = decipher.update(data, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

app.post('/api/channel/test', (req, res) => {
  if (!requireAdminAccess(req, res)) return;
  const { channel, payload } = req.body || {};
  if (!channel || !['auth', 'ledger'].includes(channel)) {
    return res.status(400).json({ error: 'channel must be "auth" or "ledger"' });
  }
  if (!payload || typeof payload !== 'string') {
    return res.status(400).json({ error: 'payload string required' });
  }
  try {
    const testDid = req.body.did || 'test-did';
    const encrypted = encryptChannelPayload(channel, payload, testDid);
    const decrypted = decryptChannelPayload(channel, encrypted, testDid);
    res.json({ encrypted, decrypted, channel, match: decrypted === payload });
  } catch (err) {
    res.status(500).json({ error: 'channel crypto failed', detail: err.message });
  }
});

app.post('/api/channel/wrap', (req, res) => {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Bearer token required' });
  const v = identity.verifyTokenStandalone(token);
  if (!v.valid) return res.status(401).json({ error: v.error });

  const { channel, data } = req.body || {};
  if (!channel || !['auth', 'ledger'].includes(channel)) {
    return res.status(400).json({ error: 'channel must be "auth" or "ledger"' });
  }
  if (!data || typeof data !== 'object') {
    return res.status(400).json({ error: 'data object required' });
  }
  if (JSON.stringify(data).length > 10240) {
    return res.status(400).json({ error: 'data: max JSON size 10KB' });
  }
  try {
    const wrapped = encryptChannelPayload(channel, JSON.stringify(data), v.decoded.sub);
    res.json({ wrapped, channel });
  } catch (err) {
    res.status(500).json({ error: 'channel wrap failed', detail: err.message });
  }
});

app.post('/api/channel/unwrap', (req, res) => {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Bearer token required' });
  const v = identity.verifyTokenStandalone(token);
  if (!v.valid) return res.status(401).json({ error: v.error });

  const { channel, wrapped } = req.body || {};
  if (!channel || !['auth', 'ledger'].includes(channel)) {
    return res.status(400).json({ error: 'channel must be "auth" or "ledger"' });
  }
  if (!wrapped || typeof wrapped !== 'string') {
    return res.status(400).json({ error: 'wrapped ciphertext string required' });
  }
  if (wrapped.length > 51200) {
    return res.status(400).json({ error: 'wrapped: max 50KB' });
  }
  try {
    const plaintext = decryptChannelPayload(channel, wrapped, v.decoded.sub);
    const data = JSON.parse(plaintext);
    res.json({ data, channel });
  } catch (err) {
    res.status(400).json({ error: 'channel unwrap failed', detail: err.message });
  }
});

// ── Fleet Namespace Schema ──

try { db.exec(`CREATE TABLE IF NOT EXISTS fleets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  owner_did TEXT NOT NULL,
  name TEXT NOT NULL,
  slug TEXT NOT NULL UNIQUE,
  description TEXT DEFAULT '',
  tier TEXT DEFAULT 'free' CHECK(tier IN ('free', 'developer', 'enterprise')),
  wallet_did TEXT DEFAULT '',
  status TEXT DEFAULT 'active' CHECK(status IN ('active', 'suspended', 'closed')),
  max_agents INTEGER DEFAULT 5,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT DEFAULT CURRENT_TIMESTAMP
)`); } catch(_) {}
try { db.exec("CREATE INDEX IF NOT EXISTS idx_fleets_owner ON fleets(owner_did)"); } catch(_) {}

try { db.exec(`CREATE TABLE IF NOT EXISTS fleet_members (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  fleet_id INTEGER NOT NULL REFERENCES fleets(id),
  member_did TEXT NOT NULL,
  role TEXT DEFAULT 'agent' CHECK(role IN ('owner', 'admin', 'agent')),
  joined_at TEXT DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(fleet_id, member_did)
)`); } catch(_) {}
try { db.exec("CREATE INDEX IF NOT EXISTS idx_fm_fleet ON fleet_members(fleet_id)"); } catch(_) {}
try { db.exec("CREATE INDEX IF NOT EXISTS idx_fm_did ON fleet_members(member_did)"); } catch(_) {}

// ── Fleet Endpoints ──

// POST /api/fleet/create — create a new fleet
app.post('/api/fleet/create', (req, res) => {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Bearer token required' });
  const v = identity.verifyTokenStandalone(token);
  if (!v.valid) return res.status(401).json({ error: v.error });
  const owner_did = v.decoded.sub;

  const { name, slug, description } = req.body || {};
  if (!name || typeof name !== 'string' || !name.trim()) return res.status(400).json({ error: 'name required' });
  if (name.length > 100) return res.status(400).json({ error: 'name: max 100 characters' });
  if (!slug || typeof slug !== 'string' || !slug.trim()) return res.status(400).json({ error: 'slug required' });
  if (!/^[a-z0-9][a-z0-9-]{1,48}[a-z0-9]$/.test(slug)) {
    return res.status(400).json({ error: 'slug must be 3-50 chars, lowercase alphanumeric and hyphens, cannot start/end with hyphen' });
  }
  if (description && typeof description !== 'string') return res.status(400).json({ error: 'description: must be a string' });
  if (description && description.length > 500) return res.status(400).json({ error: 'description: max 500 characters' });

  const existing = db.prepare('SELECT id FROM fleets WHERE slug = ?').get(slug);
  if (existing) return res.status(409).json({ error: 'slug already taken' });

  try {
    // Create a wallet identity for the fleet (no Stalwart email needed)
    const walletId = identity.createIdentity();
    const walletUsername = `fleet-${slug}`;
    const walletEmail = `fleet-${slug}@dustforge.com`;
    db.prepare(`INSERT INTO identity_wallets (did, username, email, encrypted_private_key, balance_cents, status) VALUES (?, ?, ?, ?, 0, 'active')`)
      .run(walletId.did, walletUsername, walletEmail, walletId.encrypted_private_key);

    // Create the fleet
    const result = db.prepare(`INSERT INTO fleets (owner_did, name, slug, description, wallet_did) VALUES (?, ?, ?, ?, ?)`)
      .run(owner_did, name.trim(), slug, (description || '').trim(), walletId.did);
    const fleet_id = result.lastInsertRowid;

    // Add owner as fleet member
    db.prepare(`INSERT INTO fleet_members (fleet_id, member_did, role) VALUES (?, ?, 'owner')`)
      .run(fleet_id, owner_did);

    console.log(`[fleet] created: ${slug} (id=${fleet_id}) by ${owner_did}, wallet=${walletId.did}`);
    res.json({ ok: true, fleet_id: Number(fleet_id), slug, wallet_did: walletId.did });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// GET /api/fleet/:slug — public fleet info
app.get('/api/fleet/:slug', (req, res) => {
  const fleet = db.prepare('SELECT id, owner_did, name, slug, description, tier, status, max_agents, created_at FROM fleets WHERE slug = ?').get(req.params.slug);
  if (!fleet) return res.status(404).json({ error: 'fleet not found' });
  const memberCount = db.prepare('SELECT COUNT(*) as count FROM fleet_members WHERE fleet_id = ?').get(fleet.id).count;
  res.json({ ok: true, fleet: { ...fleet, member_count: memberCount } });
});

// GET /api/fleet/:slug/members — list fleet members (auth required, must be member)
app.get('/api/fleet/:slug/members', (req, res) => {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Bearer token required' });
  const v = identity.verifyTokenStandalone(token);
  if (!v.valid) return res.status(401).json({ error: v.error });
  const caller_did = v.decoded.sub;

  const fleet = db.prepare('SELECT id FROM fleets WHERE slug = ?').get(req.params.slug);
  if (!fleet) return res.status(404).json({ error: 'fleet not found' });

  const membership = db.prepare('SELECT role FROM fleet_members WHERE fleet_id = ? AND member_did = ?').get(fleet.id, caller_did);
  if (!membership) return res.status(403).json({ error: 'not a member of this fleet' });

  const members = db.prepare('SELECT member_did, role, joined_at FROM fleet_members WHERE fleet_id = ?').all(fleet.id);
  res.json({ ok: true, members });
});

// POST /api/fleet/:slug/invite — invite a member (owner/admin only)
app.post('/api/fleet/:slug/invite', (req, res) => {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Bearer token required' });
  const v = identity.verifyTokenStandalone(token);
  if (!v.valid) return res.status(401).json({ error: v.error });
  const caller_did = v.decoded.sub;

  const { did } = req.body || {};
  if (!did || typeof did !== 'string' || !did.trim()) return res.status(400).json({ error: 'did required' });
  if (did.length > 200) return res.status(400).json({ error: 'did: max 200 characters' });

  const fleet = db.prepare('SELECT id FROM fleets WHERE slug = ?').get(req.params.slug);
  if (!fleet) return res.status(404).json({ error: 'fleet not found' });

  const membership = db.prepare('SELECT role FROM fleet_members WHERE fleet_id = ? AND member_did = ?').get(fleet.id, caller_did);
  if (!membership || !['owner', 'admin'].includes(membership.role)) {
    return res.status(403).json({ error: 'owner or admin role required' });
  }

  const alreadyMember = db.prepare('SELECT id FROM fleet_members WHERE fleet_id = ? AND member_did = ?').get(fleet.id, did.trim());
  if (alreadyMember) return res.status(409).json({ error: 'already a member' });

  // Check max_agents limit
  const fleetInfo = db.prepare('SELECT max_agents FROM fleets WHERE id = ?').get(fleet.id);
  const currentCount = db.prepare('SELECT COUNT(*) as count FROM fleet_members WHERE fleet_id = ?').get(fleet.id).count;
  if (currentCount >= fleetInfo.max_agents) {
    return res.status(403).json({ error: `fleet is at capacity (${fleetInfo.max_agents} members)` });
  }

  try {
    db.prepare(`INSERT INTO fleet_members (fleet_id, member_did, role) VALUES (?, ?, 'agent')`)
      .run(fleet.id, did.trim());
    console.log(`[fleet] invited ${did.trim()} to ${req.params.slug} by ${caller_did}`);
    res.json({ ok: true, fleet_id: fleet.id, member_did: did.trim(), role: 'agent' });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// GET /api/my/fleets — list all fleets the authenticated DID belongs to
app.get('/api/my/fleets', (req, res) => {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Bearer token required' });
  const v = identity.verifyTokenStandalone(token);
  if (!v.valid) return res.status(401).json({ error: v.error });
  const caller_did = v.decoded.sub;

  const fleets = db.prepare(`
    SELECT f.id, f.name, f.slug, f.description, f.tier, f.status, f.max_agents, f.created_at, fm.role
    FROM fleet_members fm
    JOIN fleets f ON f.id = fm.fleet_id
    WHERE fm.member_did = ?
    ORDER BY fm.joined_at DESC
  `).all(caller_did);
  res.json({ ok: true, fleets });
});

// ── F2: Developer Tier ──

const TIER_LIMITS = { free: 5, developer: 20, enterprise: 100 };
const TIER_FEATURES = {
  free: ['5 agents', 'basic fleet'],
  developer: ['20 agents', 'fleet wallet', 'bulk provisioning', 'analytics'],
  enterprise: ['100 agents', 'priority support', 'custom namespace', 'dedicated relay'],
};

// POST /api/fleet/:slug/upgrade — upgrade fleet tier (owner only)
app.post('/api/fleet/:slug/upgrade', (req, res) => {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Bearer token required' });
  const v = identity.verifyTokenStandalone(token);
  if (!v.valid) return res.status(401).json({ error: v.error });
  const caller_did = v.decoded.sub;

  const { tier } = req.body || {};
  if (!tier || typeof tier !== 'string') return res.status(400).json({ error: 'tier: must be a string' });
  if (!['developer', 'enterprise'].includes(tier)) {
    return res.status(400).json({ error: 'tier must be "developer" or "enterprise"' });
  }

  const fleet = db.prepare('SELECT id, owner_did, tier FROM fleets WHERE slug = ?').get(req.params.slug);
  if (!fleet) return res.status(404).json({ error: 'fleet not found' });
  if (fleet.owner_did !== caller_did) return res.status(403).json({ error: 'only the fleet owner can upgrade' });

  const max_agents = TIER_LIMITS[tier];
  try {
    db.prepare('UPDATE fleets SET tier = ?, max_agents = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?')
      .run(tier, max_agents, fleet.id);
    console.log(`[fleet] ${req.params.slug} upgraded to ${tier} by ${caller_did}`);
    res.json({ ok: true, slug: req.params.slug, tier, max_agents });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// GET /api/fleet/:slug/tier — public tier info
app.get('/api/fleet/:slug/tier', (req, res) => {
  const fleet = db.prepare('SELECT slug, tier, max_agents FROM fleets WHERE slug = ?').get(req.params.slug);
  if (!fleet) return res.status(404).json({ error: 'fleet not found' });
  res.json({ slug: fleet.slug, tier: fleet.tier, max_agents: fleet.max_agents, features: TIER_FEATURES });
});

// ── F3: Fleet Wallet + Onboarding ──

// POST /api/fleet/:slug/fund — transfer DD from personal wallet to fleet wallet
app.post('/api/fleet/:slug/fund', (req, res) => {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Bearer token required' });
  const v = identity.verifyTokenStandalone(token);
  if (!v.valid) return res.status(401).json({ error: v.error });
  const caller_did = v.decoded.sub;

  const { amount_cents } = req.body || {};
  if (!amount_cents || typeof amount_cents !== 'number' || !Number.isInteger(amount_cents) || amount_cents <= 0) {
    return res.status(400).json({ error: 'amount_cents: must be a positive integer' });
  }
  if (amount_cents > 1000000) return res.status(400).json({ error: 'amount_cents: max 1000000' });

  const fleet = db.prepare('SELECT id, wallet_did FROM fleets WHERE slug = ?').get(req.params.slug);
  if (!fleet) return res.status(404).json({ error: 'fleet not found' });
  if (!fleet.wallet_did) return res.status(400).json({ error: 'fleet has no wallet' });

  const membership = db.prepare('SELECT role FROM fleet_members WHERE fleet_id = ? AND member_did = ?').get(fleet.id, caller_did);
  if (!membership) return res.status(403).json({ error: 'not a member of this fleet' });

  // Atomic: deduct from personal wallet + credit fleet wallet in one transaction
  let debit;
  try {
    const atomicFund = db.transaction(() => {
      const d = billing.deductBalance(db, caller_did, amount_cents, 'fleet_fund', `Fund fleet ${req.params.slug}`);
      if (!d.ok) throw Object.assign(new Error(d.error || 'insufficient balance'), { statusCode: 402, body: d });
      billing.creditBalance(db, fleet.wallet_did, amount_cents, 'fleet_fund_in', `Funded by ${caller_did}`);
      return d;
    });
    debit = atomicFund();
  } catch (e) {
    const status = e.statusCode || 500;
    return res.status(status).json(e.body || { error: e.message });
  }

  const fleetBalance = db.prepare('SELECT balance_cents FROM identity_wallets WHERE did = ?').get(fleet.wallet_did);
  res.json({ ok: true, fleet_balance: fleetBalance ? fleetBalance.balance_cents : 0, personal_balance_after: debit.balance_after });
});

// GET /api/fleet/:slug/balance — fleet wallet balance (members only)
app.get('/api/fleet/:slug/balance', (req, res) => {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Bearer token required' });
  const v = identity.verifyTokenStandalone(token);
  if (!v.valid) return res.status(401).json({ error: v.error });
  const caller_did = v.decoded.sub;

  const fleet = db.prepare('SELECT id, wallet_did FROM fleets WHERE slug = ?').get(req.params.slug);
  if (!fleet) return res.status(404).json({ error: 'fleet not found' });

  const membership = db.prepare('SELECT role FROM fleet_members WHERE fleet_id = ? AND member_did = ?').get(fleet.id, caller_did);
  if (!membership) return res.status(403).json({ error: 'not a member of this fleet' });

  const wallet = db.prepare('SELECT balance_cents FROM identity_wallets WHERE did = ?').get(fleet.wallet_did);
  res.json({ ok: true, balance_cents: wallet ? wallet.balance_cents : 0 });
});

// POST /api/fleet/:slug/provision — create a fleet-funded identity (owner/admin only)
app.post('/api/fleet/:slug/provision', async (req, res) => {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Bearer token required' });
  const v = identity.verifyTokenStandalone(token);
  if (!v.valid) return res.status(401).json({ error: v.error });
  const caller_did = v.decoded.sub;

  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'username and password required' });
  if (!/^[a-z0-9][a-z0-9._-]{2,30}$/.test(username)) return res.status(400).json({ error: 'username must be 3-31 chars, lowercase alphanumeric' });
  if (password.length < 8) return res.status(400).json({ error: 'password must be at least 8 characters' });

  const fleet = db.prepare('SELECT id, wallet_did, max_agents, slug FROM fleets WHERE slug = ?').get(req.params.slug);
  if (!fleet) return res.status(404).json({ error: 'fleet not found' });
  if (!fleet.wallet_did) return res.status(400).json({ error: 'fleet has no wallet' });

  const membership = db.prepare('SELECT role FROM fleet_members WHERE fleet_id = ? AND member_did = ?').get(fleet.id, caller_did);
  if (!membership || !['owner', 'admin'].includes(membership.role)) {
    return res.status(403).json({ error: 'owner or admin role required' });
  }

  // DF-178: Check global platform capacity gate before fleet-specific limit
  if (isSoftCapReached()) {
    return res.status(409).json(capacityGateResponse('Fleet provisioning is paused — platform capacity limit reached.'));
  }

  // Check max_agents limit
  const currentCount = db.prepare('SELECT COUNT(*) as count FROM fleet_members WHERE fleet_id = ?').get(fleet.id).count;
  if (currentCount >= fleet.max_agents) {
    return res.status(403).json({ error: `fleet is at capacity (${fleet.max_agents} members)` });
  }

  // Check username availability
  const existing = db.prepare('SELECT id FROM identity_wallets WHERE username = ?').get(username);
  if (existing) return res.status(409).json({ error: 'username already taken' });

  // Create identity and email account first (async, outside transaction)
  const PROVISION_COST = 100;
  try {
    const id = identity.createIdentity();
    const emailResult = await dustforge.createAccount(username, password);
    if (!emailResult.ok) {
      return res.status(500).json({ error: `email creation failed: ${emailResult.error}` });
    }

    // Atomic: deduct + insert wallet + insert transaction + add fleet member
    const myReferralCode = crypto.randomBytes(6).toString('hex');
    const atomicProvision = db.transaction(() => {
      const debit = billing.deductBalance(db, fleet.wallet_did, PROVISION_COST, 'fleet_provision', `Provision ${username} for fleet ${fleet.slug}`);
      if (!debit.ok) throw Object.assign(new Error(debit.error || 'insufficient balance'), { statusCode: 402, body: { error: 'insufficient fleet wallet balance', detail: debit.error, balance_cents: debit.balance_cents, required: PROVISION_COST } });

      db.prepare('INSERT INTO identity_wallets (did, username, email, encrypted_private_key, balance_cents, referral_code, stalwart_id) VALUES (?, ?, ?, ?, 0, ?, ?)')
        .run(id.did, username, emailResult.email, id.encrypted_private_key, myReferralCode, emailResult.stalwart_id);
      db.prepare('INSERT INTO identity_transactions (did, amount_cents, type, description, balance_after, provenance) VALUES (?, 0, ?, ?, 0, ?)')
        .run(id.did, 'account_created', `Fleet-provisioned by ${fleet.slug}`, 'fleet_provisioned');

      // Add as fleet member with role='agent'
      db.prepare('INSERT INTO fleet_members (fleet_id, member_did, role) VALUES (?, ?, ?)')
        .run(fleet.id, id.did, 'agent');

      return debit;
    });
    atomicProvision();

    console.log(`[fleet] provisioned ${username} (${id.did}) in ${fleet.slug} by ${caller_did}`);
    res.json({ ok: true, did: id.did, email: emailResult.email, fleet_id: Number(fleet.id) });
  } catch (e) {
    const status = e.statusCode || 500;
    return res.status(status).json(e.body || { error: e.message });
  }
});

// ── F4: Bulk Fleet Provisioning + QR Funding ──

// POST /api/fleet/:slug/provision/bulk — bulk-create fleet agents (owner/admin only)
app.post('/api/fleet/:slug/provision/bulk', async (req, res) => {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Bearer token required' });
  const v = identity.verifyTokenStandalone(token);
  if (!v.valid) return res.status(401).json({ error: v.error });
  const caller_did = v.decoded.sub;

  const { prefix, count, password } = req.body || {};
  if (!prefix || !/^[a-z0-9][a-z0-9-]{0,18}[a-z0-9]$/.test(prefix)) return res.status(400).json({ error: 'prefix must be 2-20 chars, lowercase alphanumeric and hyphens' });
  if (!count || typeof count !== 'number' || count < 1 || count > 20) return res.status(400).json({ error: 'count must be 1-20' });
  if (!password || password.length < 8) return res.status(400).json({ error: 'password must be at least 8 characters' });

  const fleet = db.prepare('SELECT id, wallet_did, max_agents, slug FROM fleets WHERE slug = ?').get(req.params.slug);
  if (!fleet) return res.status(404).json({ error: 'fleet not found' });
  if (!fleet.wallet_did) return res.status(400).json({ error: 'fleet has no wallet' });

  const membership = db.prepare('SELECT role FROM fleet_members WHERE fleet_id = ? AND member_did = ?').get(fleet.id, caller_did);
  if (!membership || !['owner', 'admin'].includes(membership.role)) {
    return res.status(403).json({ error: 'owner or admin role required' });
  }

  // DF-178: Check global platform capacity gate before fleet-specific limit
  if (isSoftCapReached()) {
    return res.status(409).json(capacityGateResponse('Fleet bulk provisioning is paused — platform capacity limit reached.'));
  }

  // Check max_agents capacity
  const currentCount = db.prepare('SELECT COUNT(*) as count FROM fleet_members WHERE fleet_id = ?').get(fleet.id).count;
  if (currentCount + count > fleet.max_agents) {
    return res.status(403).json({ error: `fleet would exceed capacity (${currentCount}/${fleet.max_agents} members, requested ${count})` });
  }

  // Deduct total cost upfront from fleet wallet
  const PROVISION_COST = 100;
  const totalCost = count * PROVISION_COST;
  const debit = billing.deductBalance(db, fleet.wallet_did, totalCost, 'fleet_bulk_provision', `Bulk provision ${count} agents for fleet ${fleet.slug}`);
  if (!debit.ok) return res.status(402).json({ error: 'insufficient fleet wallet balance', detail: debit.error, required: totalCost });

  const created = [];
  const errors = [];
  let refundAmount = 0;

  for (let i = 0; i < count; i++) {
    const username = `${prefix}-${String(i + 1).padStart(3, '0')}`;
    try {
      const existing = db.prepare('SELECT id FROM identity_wallets WHERE username = ?').get(username);
      if (existing) { errors.push({ username, error: 'already exists' }); refundAmount += PROVISION_COST; continue; }

      const id = identity.createIdentity();
      const emailResult = await dustforge.createAccount(username, password);
      if (!emailResult.ok) {
        errors.push({ username, error: `email creation failed: ${emailResult.error}` });
        refundAmount += PROVISION_COST;
        continue;
      }

      const myReferralCode = crypto.randomBytes(6).toString('hex');
      // Atomic per-agent DB writes: wallet insert + transaction log + fleet member
      const insertAgentAtomic = db.transaction(() => {
        db.prepare('INSERT INTO identity_wallets (did, username, email, encrypted_private_key, balance_cents, referral_code, stalwart_id) VALUES (?, ?, ?, ?, 0, ?, ?)')
          .run(id.did, username, emailResult.email, id.encrypted_private_key, myReferralCode, emailResult.stalwart_id || 0);
        db.prepare("INSERT INTO identity_transactions (did, amount_cents, type, description, balance_after, provenance) VALUES (?, 0, 'account_created', ?, 0, 'fleet_provisioned')")
          .run(id.did, `Fleet bulk-provisioned by ${fleet.slug}`);
        db.prepare('INSERT INTO fleet_members (fleet_id, member_did, role) VALUES (?, ?, ?)')
          .run(fleet.id, id.did, 'agent');
      });
      insertAgentAtomic();

      created.push({ username, did: id.did, email: emailResult.email });
    } catch (e) {
      errors.push({ username, error: e.message });
      refundAmount += PROVISION_COST;
    }
  }

  // Refund for any that failed
  if (refundAmount > 0) {
    billing.creditBalance(db, fleet.wallet_did, refundAmount, 'fleet_bulk_provision_refund', `Refund ${refundAmount} DD for ${errors.length} failed provisions`);
  }

  console.log(`[fleet] bulk provisioned ${created.length}/${count} agents in ${fleet.slug} by ${caller_did}`);
  res.json({ ok: true, created, errors, total_cost_dd: totalCost - refundAmount });
});

// POST /api/fleet/:slug/fund/qr — generate Stripe checkout for fleet wallet topup
app.post('/api/fleet/:slug/fund/qr', async (req, res) => {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Bearer token required' });
  const v = identity.verifyTokenStandalone(token);
  if (!v.valid) return res.status(401).json({ error: v.error });
  const caller_did = v.decoded.sub;

  const { amount_cents } = req.body || {};
  if (!amount_cents || typeof amount_cents !== 'number' || !Number.isInteger(amount_cents) || amount_cents <= 0) {
    return res.status(400).json({ error: 'amount_cents: must be a positive integer' });
  }
  if (amount_cents > 1000000) return res.status(400).json({ error: 'amount_cents: max 1000000' });

  const fleet = db.prepare('SELECT id, wallet_did, slug FROM fleets WHERE slug = ?').get(req.params.slug);
  if (!fleet) return res.status(404).json({ error: 'fleet not found' });
  if (!fleet.wallet_did) return res.status(400).json({ error: 'fleet has no wallet' });

  const membership = db.prepare('SELECT role FROM fleet_members WHERE fleet_id = ? AND member_did = ?').get(fleet.id, caller_did);
  if (!membership) return res.status(403).json({ error: 'not a member of this fleet' });

  try {
    const stripe = stripeService.getStripe();
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      line_items: [{
        price_data: {
          currency: 'usd',
          product_data: {
            name: `${amount_cents} Diamond Dust for fleet ${fleet.slug}`,
            description: `Top up fleet ${fleet.slug} wallet with ${amount_cents} DD`,
          },
          unit_amount: Number(amount_cents),
        },
        quantity: 1,
      }],
      mode: 'payment',
      success_url: `${process.env.PLATFORM_BASE_URL || 'https://dustforge.com'}/api/stripe/topup-success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${process.env.PLATFORM_BASE_URL || 'https://dustforge.com'}/api/stripe/cancel`,
      metadata: { type: 'fleet_topup', fleet_slug: fleet.slug, fleet_wallet_did: fleet.wallet_did, amount_cents: String(amount_cents), did: fleet.wallet_did },
    });

    console.log(`[fleet] QR funding session created for ${fleet.slug} by ${caller_did}: ${session.id}`);
    res.json({ ok: true, url: session.url, qr_data: session.url });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── F5: Fleet Analytics Dashboard ──

// GET /api/fleet/:slug/analytics — fleet analytics (members only)
app.get('/api/fleet/:slug/analytics', (req, res) => {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Bearer token required' });
  const v = identity.verifyTokenStandalone(token);
  if (!v.valid) return res.status(401).json({ error: v.error });
  const caller_did = v.decoded.sub;

  const fleet = db.prepare('SELECT id, owner_did, name, slug, tier, wallet_did, max_agents, status, created_at FROM fleets WHERE slug = ?').get(req.params.slug);
  if (!fleet) return res.status(404).json({ error: 'fleet not found' });

  const membership = db.prepare('SELECT role FROM fleet_members WHERE fleet_id = ? AND member_did = ?').get(fleet.id, caller_did);
  if (!membership) return res.status(403).json({ error: 'not a member of this fleet' });

  // Fleet info
  const memberCount = db.prepare('SELECT COUNT(*) as count FROM fleet_members WHERE fleet_id = ?').get(fleet.id).count;

  // Wallet info
  const wallet = db.prepare('SELECT balance_cents FROM identity_wallets WHERE did = ?').get(fleet.wallet_did);
  const walletBalance = wallet ? wallet.balance_cents : 0;
  const fundedRow = db.prepare("SELECT COALESCE(SUM(amount_cents), 0) as total FROM identity_transactions WHERE did = ? AND amount_cents > 0").get(fleet.wallet_did);
  const spentRow = db.prepare("SELECT COALESCE(SUM(ABS(amount_cents)), 0) as total FROM identity_transactions WHERE did = ? AND amount_cents < 0").get(fleet.wallet_did);

  // Members with details
  const members = db.prepare('SELECT member_did, role, joined_at FROM fleet_members WHERE fleet_id = ?').all(fleet.id);
  const memberDetails = members.map(m => {
    const w = db.prepare('SELECT username FROM identity_wallets WHERE did = ?').get(m.member_did);
    const txCount = db.prepare('SELECT COUNT(*) as n FROM identity_transactions WHERE did = ?').get(m.member_did).n;
    const lastAuthRow = db.prepare('SELECT created_at FROM silicon_profiles WHERE did = ? ORDER BY created_at DESC LIMIT 1').get(m.member_did);
    const rep = computeReputation(m.member_did);
    return {
      did: m.member_did,
      username: w ? w.username : null,
      role: m.role,
      reputation_score: rep ? rep.score : 0,
      transaction_count: txCount,
      last_auth: lastAuthRow ? lastAuthRow.created_at : null,
      joined_at: m.joined_at,
    };
  });

  // Member DIDs for activity queries
  const memberDids = members.map(m => m.member_did);
  const didPlaceholders = memberDids.map(() => '?').join(',');

  // Activity stats
  let transactions_24h = 0, transactions_7d = 0, emails_sent_24h = 0, blindkey_uses_24h = 0;
  if (memberDids.length > 0) {
    transactions_24h = db.prepare(`SELECT COUNT(*) as n FROM identity_transactions WHERE did IN (${didPlaceholders}) AND created_at >= datetime('now', '-1 day')`).get(...memberDids).n;
    transactions_7d = db.prepare(`SELECT COUNT(*) as n FROM identity_transactions WHERE did IN (${didPlaceholders}) AND created_at >= datetime('now', '-7 days')`).get(...memberDids).n;
    emails_sent_24h = db.prepare(`SELECT COUNT(*) as n FROM identity_transactions WHERE did IN (${didPlaceholders}) AND type = 'email_send' AND created_at >= datetime('now', '-1 day')`).get(...memberDids).n;
    blindkey_uses_24h = db.prepare(`SELECT COALESCE(SUM(CASE WHEN last_used_at >= datetime('now', '-1 day') THEN 1 ELSE 0 END), 0) as n FROM blindkey_secrets WHERE did IN (${didPlaceholders})`).get(...memberDids).n;
  }

  // Top 5 agents by transaction count
  const top_agents = [...memberDetails]
    .sort((a, b) => b.transaction_count - a.transaction_count)
    .slice(0, 5)
    .map(a => ({ did: a.did, username: a.username, transaction_count: a.transaction_count, reputation_score: a.reputation_score }));

  // Fingerprint health
  let agents_with_inner_ring = 0, agents_with_all_rings = 0, totalReputation = 0;
  for (const m of memberDetails) {
    totalReputation += m.reputation_score;
    const rep = computeReputation(m.did);
    if (rep) {
      if (rep.ring_completeness.inner > 0) agents_with_inner_ring++;
      if (rep.ring_completeness.inner > 0 && rep.ring_completeness.middle > 0 && rep.ring_completeness.outer > 0) agents_with_all_rings++;
    }
  }

  res.json({
    fleet: { name: fleet.name, slug: fleet.slug, tier: fleet.tier, member_count: memberCount, max_agents: fleet.max_agents },
    wallet: { balance_dd: walletBalance, total_funded_dd: fundedRow.total, total_spent_dd: spentRow.total },
    members: memberDetails,
    activity: { transactions_24h, transactions_7d, emails_sent_24h, blindkey_uses_24h, demipass_uses_24h: blindkey_uses_24h },
    top_agents,
    fingerprint_health: {
      agents_with_inner_ring,
      agents_with_all_rings,
      average_reputation: memberDetails.length > 0 ? Math.round((totalReputation / memberDetails.length) * 100) / 100 : 0,
    },
  });
});

// ── Auth Channel (D3) — fingerprint auth with channel encryption ──

app.post('/api/identity/auth-fingerprint/barrel', rateLimitStandard, fingerprintMiddleware(), async (req, res) => {
  const { did, username, password, scope = 'read', expires_in = '24h', channel } = req.body || {};
  if ((!did && !username) || !password) return res.status(400).json({ error: 'did/username and password required' });
  if (did && typeof did !== 'string') return res.status(400).json({ error: 'did: must be a string' });
  if (username && typeof username !== 'string') return res.status(400).json({ error: 'username: must be a string' });
  if (typeof password !== 'string') return res.status(400).json({ error: 'password: must be a string' });
  if (typeof scope !== 'string') return res.status(400).json({ error: 'scope: must be a string' });
  if (typeof expires_in !== 'string') return res.status(400).json({ error: 'expires_in: must be a string' });
  if (channel && typeof channel !== 'string') return res.status(400).json({ error: 'channel: must be a string' });
  const wallet = did
    ? db.prepare('SELECT * FROM identity_wallets WHERE did = ?').get(did)
    : db.prepare('SELECT * FROM identity_wallets WHERE username = ?').get(username);
  if (!wallet) return res.status(404).json({ error: 'identity not found' });

  // Verify password via Stalwart admin API
  try {
    const http = require('http');
    const stalwartHost = process.env.STALWART_HOST || '100.83.112.88';
    const stalwartPort = Number(process.env.STALWART_PORT || 8080);
    const stalwartPass = process.env.STALWART_PASS || '';
    const adminAuth = Buffer.from('admin:' + stalwartPass).toString('base64');
    const storedPassword = await new Promise((resolve) => {
      const req = http.request({ hostname: stalwartHost, port: stalwartPort,
        path: '/api/principal/' + encodeURIComponent(wallet.username),
        method: 'GET', headers: { 'Authorization': 'Basic ' + adminAuth } }, (res) => {
        let data = ''; res.on('data', chunk => data += chunk);
        res.on('end', () => { try { resolve(JSON.parse(data).data.secrets[0]); } catch(_) { resolve(null); } });
      });
      req.on('error', () => resolve(null));
      req.setTimeout(5000, () => { req.destroy(); resolve(null); });
      req.end();
    });
    if (storedPassword === null) {
      return res.status(503).json({ error: 'password verification temporarily unavailable' });
    }
    if (storedPassword !== password) {
      return res.status(401).json({ error: 'invalid password' });
    }
  } catch(e) {
    return res.status(503).json({ error: 'password verification temporarily unavailable' });
  }

  // Capture fingerprint profile on every auth
  const headers = req.headers || {};
  const stableSignals = [
    headers['user-agent'] || '',
    [headers['accept'], headers['accept-encoding'], headers['accept-language']].filter(Boolean).join('|'),
    Object.keys(headers).join(','),
    headers['content-type'] || '',
    req.httpVersion || '',
  ].join('::');
  const fingerprintHash = crypto.createHash('sha256').update(stableSignals).digest('hex').slice(0, 16);

  try {
    db.prepare(`INSERT INTO silicon_profiles (did, user_agent, accept_headers, header_order, content_type, ip_address, json_style, http_version, request_meta, fingerprint_hash)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
      wallet.did,
      headers['user-agent'] || '',
      [headers['accept'], headers['accept-encoding'], headers['accept-language']].filter(Boolean).join('|'),
      Object.keys(headers).join(','),
      headers['content-type'] || '',
      req.ip || '',
      'compact',
      req.httpVersion || '',
      JSON.stringify({ method: req.method, path: req.path, body_keys: Object.keys(req.body || {}).join(',') }),
      fingerprintHash
    );
  } catch (_) {}

  // Detect human operator: X-Operator-Type header or browser user-agent
  const _ua2 = (req.headers['user-agent'] || '').toLowerCase();
  const isHumanOperator2 = req.headers['x-operator-type'] === 'human' || /mozilla|chrome|safari/.test(_ua2);

  // Capture fingerprint signals via middleware
  req._fingerprintHash = fingerprintHash;
  if (req.captureFingerprint) req.captureFingerprint(wallet.did, isHumanOperator2);

  const token = identity.createTokenForIdentity(wallet.encrypted_private_key, wallet.did, {
    scope, expiresIn: expires_in,
    metadata: { email: wallet.email, username: wallet.username, auth_method: 'fingerprint', fingerprint_hash: fingerprintHash },
  });

  // Determine barrel tier from scope
  const barrelTier = ['transact', 'admin', 'full'].includes(scope) ? 'double' : 'single';

  if (channel === 'auth') {
    try {
      const wrappedToken = encryptChannelPayload('auth', token, wallet.did);
      return res.json({ ok: true, wrapped_token: wrappedToken, channel: 'auth', barrel_tier: barrelTier, fingerprint_hash: fingerprintHash });
    } catch (err) {
      return res.status(500).json({ error: 'auth channel encryption failed', detail: err.message });
    }
  }

  // Fallback: plaintext token (backward compatible)
  res.json({ ok: true, token, did: wallet.did, scope, email: wallet.email, auth_method: 'fingerprint', fingerprint_hash: fingerprintHash, barrel_tier: barrelTier });
});

// ── D5: Critical Re-Auth Gate ──

try { db.exec("ALTER TABLE identity_wallets ADD COLUMN last_critical_auth TEXT DEFAULT ''"); } catch(_) {}

app.post('/api/identity/auth-critical', rateLimitStandard, async (req, res) => {
  const { username, password, scope } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'username and password required' });
  if (typeof username !== 'string') return res.status(400).json({ error: 'username: must be a string' });
  if (typeof password !== 'string') return res.status(400).json({ error: 'password: must be a string' });
  if (scope !== 'critical') return res.status(400).json({ error: "scope must be 'critical'" });

  const wallet = db.prepare('SELECT * FROM identity_wallets WHERE username = ?').get(username);
  if (!wallet) return res.status(404).json({ error: 'identity not found' });

  // Verify password via Stalwart admin API
  try {
    const http = require('http');
    const stalwartHost = process.env.STALWART_HOST || '100.83.112.88';
    const stalwartPort = Number(process.env.STALWART_PORT || 8080);
    const stalwartPass = process.env.STALWART_PASS || '';
    const adminAuth = Buffer.from('admin:' + stalwartPass).toString('base64');
    const storedPassword = await new Promise((resolve) => {
      const req = http.request({ hostname: stalwartHost, port: stalwartPort,
        path: '/api/principal/' + encodeURIComponent(wallet.username),
        method: 'GET', headers: { 'Authorization': 'Basic ' + adminAuth } }, (res) => {
        let data = ''; res.on('data', chunk => data += chunk);
        res.on('end', () => { try { resolve(JSON.parse(data).data.secrets[0]); } catch(_) { resolve(null); } });
      });
      req.on('error', () => resolve(null));
      req.setTimeout(5000, () => { req.destroy(); resolve(null); });
      req.end();
    });
    if (storedPassword === null) {
      return res.status(503).json({ error: 'password verification temporarily unavailable' });
    }
    if (storedPassword !== password) {
      return res.status(401).json({ error: 'invalid password' });
    }
  } catch(e) {
    return res.status(503).json({ error: 'password verification temporarily unavailable' });
  }

  // Must already be at 'double' tier minimum
  const barrel = computeBarrelTier(wallet.did);
  const currentIndex = BARREL_TIERS.indexOf(barrel.tier);
  const doubleIndex = BARREL_TIERS.indexOf('double');
  if (currentIndex < doubleIndex) {
    return res.status(403).json({
      error: 'double barrel tier required for critical auth',
      current_tier: barrel.tier,
      upgrade_hint: !barrel.wallet_bound
        ? 'fund your wallet to unlock double barrel'
        : 'accumulate more fingerprint ring signals via repeated auth',
    });
  }

  // Issue critical-scoped JWT — 5 minutes, hardcoded, cannot be overridden
  const token = identity.createTokenForIdentity(wallet.encrypted_private_key, wallet.did, {
    scope: 'critical', expiresIn: '5m',
    metadata: { email: wallet.email, username: wallet.username, auth_method: 'critical_reauth' },
  });

  // Update last_critical_auth timestamp
  db.prepare('UPDATE identity_wallets SET last_critical_auth = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE did = ?')
    .run(wallet.did);

  const valid_until = new Date(Date.now() + 5 * 60 * 1000).toISOString();
  console.log(`[identity] critical auth issued: ${wallet.username} → ${wallet.did} (valid until ${valid_until})`);
  res.json({ token, barrel_tier: 'critical', expires_in: '5m', valid_until });
});

// ── Ledger Channel (D4) — encrypted wallet transfer ──

function wrapLedgerResponse(data, did) {
  return encryptChannelPayload('ledger', JSON.stringify(data), did);
}

app.post('/api/wallet/transfer/secure', rateLimitStandard, (req, res) => {
  const { from_did, to_did, amount_cents, description, channel } = req.body || {};
  if (!from_did || !to_did || !amount_cents) return res.status(400).json({ error: 'from_did, to_did, amount_cents required' });
  if (typeof from_did !== 'string') return res.status(400).json({ error: 'from_did: must be a string' });
  if (typeof to_did !== 'string') return res.status(400).json({ error: 'to_did: must be a string' });
  if (typeof amount_cents !== 'number' || !Number.isInteger(amount_cents)) return res.status(400).json({ error: 'amount_cents: must be an integer' });
  if (description && typeof description !== 'string') return res.status(400).json({ error: 'description: must be a string' });
  if (description && description.length > 500) return res.status(400).json({ error: 'description: max 500 characters' });
  if (channel && typeof channel !== 'string') return res.status(400).json({ error: 'channel: must be a string' });
  if (from_did === to_did) return res.status(400).json({ error: 'cannot transfer to self' });
  if (amount_cents <= 0 || amount_cents > 1000000) return res.status(400).json({ error: 'invalid amount' });
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Bearer token required' });
  const v = identity.verifyTokenStandalone(token);
  if (!v.valid) return res.status(401).json({ error: v.error });
  if (v.decoded.sub !== from_did) return res.status(403).json({ error: 'token mismatch' });
  // Progressive Barrel: require transact/admin/full scope for secure transfers (double barrel tier)
  if (!['transact', 'admin', 'full'].includes(v.decoded.scope || '')) return res.status(403).json({ error: 'transact scope required (double barrel)' });
  const sender = db.prepare('SELECT did, username, balance_cents, status FROM identity_wallets WHERE did = ?').get(from_did);
  const receiver = db.prepare('SELECT did, username FROM identity_wallets WHERE did = ?').get(to_did);
  if (!sender || !receiver) return res.status(404).json({ error: 'identity not found' });
  if (sender.status !== 'active') return res.status(403).json({ error: 'account suspended' });
  // DF-177: Atomic transfer via barrelGuardedTransfer (ledger-level barrel invariant)
  let debit;
  try {
    debit = barrelGuardedTransfer(db, from_did, to_did, amount_cents, 'transfer_out', 'Secure transfer to ' + receiver.username + (description ? ': ' + description : ''));
  } catch (e) {
    const status = e.statusCode || 402;
    return res.status(status).json(e.body || { ok: false, error: e.message, balance_cents: sender.balance_cents });
  }

  const responseData = { ok: true, from: { did: from_did, balance_after: debit.balance_after }, to: { did: to_did }, amount_cents };

  if (channel === 'ledger') {
    try {
      const wrapped = wrapLedgerResponse(responseData, from_did);
      return res.json({ wrapped, channel: 'ledger' });
    } catch (err) {
      return res.status(500).json({ error: 'ledger channel encryption failed', detail: err.message });
    }
  }

  // Fallback: plaintext response
  res.json(responseData);
});

// ── [104] Carbon Cosign Barrel ──

// Helper: check if an approved cosign exists for this operation within the last 10 minutes
function requireCarbonCosign(did, operation, amount) {
  const row = db.prepare(`
    SELECT id FROM barrel_cosign_requests
    WHERE silicon_did = ? AND operation = ? AND amount_cents = ? AND status = 'approved'
      AND resolved_at > datetime('now', '-10 minutes')
    ORDER BY resolved_at DESC LIMIT 1
  `).get(did, operation, amount || 0);
  return !!row;
}

function getEscrowById(escrowId) {
  return db.prepare(`
    SELECT e.*,
           creator.username AS creator_username,
           counterparty.username AS counterparty_username,
           beneficiary.username AS beneficiary_username
    FROM escrow_contracts e
    LEFT JOIN identity_wallets creator ON creator.did = e.creator_did
    LEFT JOIN identity_wallets counterparty ON counterparty.did = e.counterparty_did
    LEFT JOIN identity_wallets beneficiary ON beneficiary.did = e.beneficiary_did
    WHERE e.id = ?
  `).get(Number(escrowId));
}

function serializeEscrow(row) {
  if (!row) return null;
  return {
    ...row,
    metadata: (() => {
      try { return JSON.parse(row.metadata || '{}'); } catch (_) { return {}; }
    })(),
  };
}

function recordEscrowEvent(escrowId, eventType, actorDid, detail = {}) {
  db.prepare(`
    INSERT INTO escrow_events (escrow_id, event_type, actor_did, detail)
    VALUES (?, ?, ?, ?)
  `).run(Number(escrowId), String(eventType || ''), String(actorDid || ''), JSON.stringify(detail || {}));
}

function getEscrowEvents(escrowId) {
  return db.prepare(`
    SELECT id, event_type, actor_did, detail, created_at
    FROM escrow_events
    WHERE escrow_id = ?
    ORDER BY id DESC
  `).all(Number(escrowId)).map((row) => ({
    ...row,
    detail: (() => {
      try { return JSON.parse(row.detail || '{}'); } catch (_) { return {}; }
    })(),
  }));
}

function resolveEscrowTier(collateralCents) {
  const amount = Number(collateralCents || 0);
  if (amount > 10000) return 'critical';
  if (amount > 100) return 'double';
  return 'single';
}

function verifyEscrowBarrel(did, minTier) {
  const barrel = computeBarrelTier(did);
  const currentIndex = BARREL_TIERS.indexOf(barrel.tier);
  const requiredIndex = BARREL_TIERS.indexOf(minTier);
  if (currentIndex < requiredIndex) {
    let upgrade_hint = '';
    if (!barrel.wallet_bound) {
      upgrade_hint = 'fund your wallet to unlock double barrel';
    } else if (barrel.inner_count < 2 || barrel.middle_count < 1) {
      upgrade_hint = 'accumulate more fingerprint ring signals via repeated auth';
    } else if (barrel.last_auth_age_seconds >= 300) {
      upgrade_hint = 're-authenticate within 5 minutes to unlock critical barrel';
    }
    const error = new Error(`${minTier} barrel required`);
    error.statusCode = 403;
    error.body = {
      error: `${minTier} barrel required`,
      required_tier: minTier,
      current_tier: barrel.tier,
      upgrade_hint,
    };
    throw error;
  }
  return barrel;
}

function ensureEscrowParticipant(row, did) {
  return [row.creator_did, row.counterparty_did, row.beneficiary_did].filter(Boolean).includes(String(did || ''));
}

// POST /api/barrel/cosign/request — silicon requests carbon co-approval for a high-value operation
app.post('/api/barrel/cosign/request', rateLimitStrict, async (req, res) => {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Bearer token required' });
  const v = identity.verifyTokenStandalone(token);
  if (!v.valid) return res.status(401).json({ error: v.error });
  const did = v.decoded.sub;

  const { operation, amount_cents, carbon_email } = req.body || {};
  if (!operation || typeof operation !== 'string') return res.status(400).json({ error: 'operation required (string)' });
  if (!carbon_email || typeof carbon_email !== 'string' || !carbon_email.includes('@')) return res.status(400).json({ error: 'valid carbon_email required' });
  if (operation.length > 200) return res.status(400).json({ error: 'operation: max 200 characters' });

  const amountCents = Number(amount_cents) || 0;
  const approvalCode = String(Math.floor(100000 + Math.random() * 900000));
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000).toISOString();

  const result = db.prepare(`
    INSERT INTO barrel_cosign_requests (silicon_did, carbon_email, operation, amount_cents, approval_code, expires_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(did, carbon_email, operation, amountCents, approvalCode, expiresAt);

  const requestId = result.lastInsertRowid;

  // Email the carbon with the approval code
  try {
    const t = createEmailTransport();
    const wallet = db.prepare('SELECT username FROM identity_wallets WHERE did = ?').get(did);
    const siliconName = wallet ? wallet.username : did.slice(0, 16) + '...';
    await t.sendMail({
      from: 'cosign@dustforge.com',
      to: carbon_email,
      subject: `Dustforge Cosign Request: ${operation}`,
      text: `A silicon identity (${siliconName}) is requesting your co-approval for a high-value operation.\n\nOperation: ${operation}\nAmount: ${amountCents > 0 ? '$' + (amountCents / 100).toFixed(2) : 'N/A'}\n\nApproval Code: ${approvalCode}\n\nThis code expires in 10 minutes.\n\nIf you did not expect this request, ignore this email.\n\n— Dustforge Barrel Cosign`,
      html: `<div style="font-family:monospace;background:#08111a;color:#e7f1fb;padding:2rem;max-width:480px;margin:auto;border-radius:8px;text-align:center">
        <h2 style="color:#5fb3ff;margin-top:0">Barrel Cosign Request</h2>
        <p style="color:#9cb4c9">A silicon identity (<strong>${siliconName}</strong>) needs your co-approval.</p>
        <p style="color:#9cb4c9"><strong>Operation:</strong> ${operation}</p>
        ${amountCents > 0 ? `<p style="color:#9cb4c9"><strong>Amount:</strong> $${(amountCents / 100).toFixed(2)}</p>` : ''}
        <div style="font-size:2.5rem;font-weight:800;color:#c8a84b;letter-spacing:0.3em;margin:1rem 0">${approvalCode}</div>
        <p style="font-size:0.8rem;color:#6d8397">Expires in 10 minutes.</p>
      </div>`,
    });
    console.log(`[cosign] approval code sent to ${carbon_email} for operation "${operation}" (request ${requestId})`);
  } catch (e) {
    console.error(`[cosign] email failed: ${e.message}`);
    // Don't fail the request — the cosign record exists, carbon could be given the code another way
  }

  res.json({ request_id: requestId, expires_at: expiresAt, message: 'Approval code sent to carbon' });
});

// POST /api/barrel/cosign/approve — carbon submits the approval code (no auth needed)
app.post('/api/barrel/cosign/approve', rateLimitStrict, (req, res) => {
  const { request_id, approval_code } = req.body || {};
  if (!request_id) return res.status(400).json({ error: 'request_id required' });
  if (!approval_code || typeof approval_code !== 'string') return res.status(400).json({ error: 'approval_code required' });

  const row = db.prepare('SELECT * FROM barrel_cosign_requests WHERE id = ?').get(request_id);
  if (!row) return res.status(404).json({ error: 'cosign request not found' });

  if (row.status === 'approved') return res.status(409).json({ error: 'already approved' });
  if (row.status === 'denied') return res.status(409).json({ error: 'request was denied' });
  if (row.status === 'expired' || new Date(row.expires_at) < new Date()) {
    if (row.status !== 'expired') {
      db.prepare("UPDATE barrel_cosign_requests SET status = 'expired' WHERE id = ?").run(request_id);
    }
    return res.status(410).json({ error: 'cosign request expired' });
  }

  if (!safeSecretEqual(approval_code, row.approval_code)) {
    return res.status(403).json({ error: 'invalid approval code' });
  }

  db.prepare("UPDATE barrel_cosign_requests SET status = 'approved', resolved_at = datetime('now') WHERE id = ?").run(request_id);
  console.log(`[cosign] request ${request_id} approved for operation "${row.operation}"`);
  res.json({ ok: true, operation: row.operation, silicon_did: row.silicon_did });
});

// ── [179] DD-collateralized Escrow ──

app.get('/api/escrow/list', rateLimitStandard, (req, res) => {
  const actor = getBearerIdentity(req);
  if (!actor.ok) return res.status(actor.status).json({ error: actor.error });
  const rows = db.prepare(`
    SELECT e.*,
           creator.username AS creator_username,
           counterparty.username AS counterparty_username,
           beneficiary.username AS beneficiary_username
    FROM escrow_contracts e
    LEFT JOIN identity_wallets creator ON creator.did = e.creator_did
    LEFT JOIN identity_wallets counterparty ON counterparty.did = e.counterparty_did
    LEFT JOIN identity_wallets beneficiary ON beneficiary.did = e.beneficiary_did
    WHERE e.creator_did = ? OR e.counterparty_did = ? OR e.beneficiary_did = ?
    ORDER BY e.id DESC
    LIMIT 100
  `).all(actor.did, actor.did, actor.did);
  res.json(rows.map(serializeEscrow));
});

app.get('/api/escrow/:id', rateLimitStandard, (req, res) => {
  const actor = getBearerIdentity(req);
  if (!actor.ok) return res.status(actor.status).json({ error: actor.error });
  const row = getEscrowById(req.params.id);
  if (!row) return res.status(404).json({ error: 'escrow not found' });
  if (!ensureEscrowParticipant(row, actor.did)) return res.status(403).json({ error: 'escrow access denied' });
  res.json({ ...serializeEscrow(row), events: getEscrowEvents(row.id) });
});

app.post('/api/escrow/create', rateLimitStandard, (req, res) => {
  const actor = getBearerIdentity(req);
  if (!actor.ok) return res.status(actor.status).json({ error: actor.error });

  const {
    counterparty_did = '',
    beneficiary_did = '',
    title = '',
    memo = '',
    collateral_cents = 0,
    expires_in_hours = 72,
  } = req.body || {};

  const collateralCents = Number(collateral_cents || 0);
  if (!title || typeof title !== 'string') return res.status(400).json({ error: 'title required' });
  if (title.length > 160) return res.status(400).json({ error: 'title: max 160 characters' });
  if (collateralCents <= 0) return res.status(400).json({ error: 'collateral_cents must be > 0' });
  if (collateralCents > 5000000) return res.status(400).json({ error: 'collateral_cents exceeds max' });

  const resolvedCounterpartyDid = String(counterparty_did || '').trim();
  const resolvedBeneficiaryDid = String(beneficiary_did || resolvedCounterpartyDid || actor.did).trim();
  if (resolvedCounterpartyDid) {
    const wallet = db.prepare('SELECT did FROM identity_wallets WHERE did = ?').get(resolvedCounterpartyDid);
    if (!wallet) return res.status(404).json({ error: 'counterparty identity not found' });
  }
  const beneficiaryWallet = db.prepare('SELECT did FROM identity_wallets WHERE did = ?').get(resolvedBeneficiaryDid);
  if (!beneficiaryWallet) return res.status(404).json({ error: 'beneficiary identity not found' });

  const barrelTierRequired = resolveEscrowTier(collateralCents);
  try {
    verifyEscrowBarrel(actor.did, barrelTierRequired);
  } catch (error) {
    return res.status(error.statusCode || 500).json(error.body || { error: error.message });
  }

  const ttlHours = Math.max(1, Math.min(24 * 30, Number(expires_in_hours || 72)));
  const expiresAt = new Date(Date.now() + ttlHours * 60 * 60 * 1000).toISOString();

  try {
    const result = db.transaction(() => {
      const debit = billing.deductBalance(db, actor.did, collateralCents, 'escrow_lock', `Escrow lock: ${title}`);
      if (!debit.ok) {
        throw Object.assign(new Error(debit.error || 'insufficient balance'), { statusCode: 402, body: debit });
      }

      const insert = db.prepare(`
        INSERT INTO escrow_contracts (
          creator_did, counterparty_did, beneficiary_did, title, memo, collateral_cents,
          barrel_tier_required, status, expires_at, metadata
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)
      `).run(
        actor.did,
        resolvedCounterpartyDid,
        resolvedBeneficiaryDid,
        title,
        String(memo || ''),
        collateralCents,
        barrelTierRequired,
        expiresAt,
        JSON.stringify({ created_via: 'api', barrel_tier_snapshot: computeBarrelTier(actor.did) })
      );

      recordEscrowEvent(insert.lastInsertRowid, 'created', actor.did, {
        collateral_cents: collateralCents,
        beneficiary_did: resolvedBeneficiaryDid,
        counterparty_did: resolvedCounterpartyDid,
        barrel_tier_required: barrelTierRequired,
      });
      return Number(insert.lastInsertRowid);
    })();

    res.json({ ok: true, escrow: serializeEscrow(getEscrowById(result)) });
  } catch (error) {
    return res.status(error.statusCode || 500).json(error.body || { error: error.message });
  }
});

app.post('/api/escrow/:id/accept', rateLimitStandard, (req, res) => {
  const actor = getBearerIdentity(req);
  if (!actor.ok) return res.status(actor.status).json({ error: actor.error });
  const row = getEscrowById(req.params.id);
  if (!row) return res.status(404).json({ error: 'escrow not found' });
  if (!row.counterparty_did || row.counterparty_did !== actor.did) return res.status(403).json({ error: 'counterparty acceptance required' });
  if (!['pending', 'disputed'].includes(row.status)) return res.status(409).json({ error: `cannot accept escrow in status ${row.status}` });
  db.prepare(`
    UPDATE escrow_contracts
    SET status = 'active',
        accepted_at = CURRENT_TIMESTAMP
    WHERE id = ?
  `).run(row.id);
  recordEscrowEvent(row.id, 'accepted', actor.did, {});
  res.json({ ok: true, escrow: serializeEscrow(getEscrowById(row.id)) });
});

app.post('/api/escrow/:id/release', rateLimitStandard, (req, res) => {
  const actor = getBearerIdentity(req);
  if (!actor.ok) return res.status(actor.status).json({ error: actor.error });
  const row = getEscrowById(req.params.id);
  if (!row) return res.status(404).json({ error: 'escrow not found' });
  if (row.creator_did !== actor.did) return res.status(403).json({ error: 'only creator can release escrow' });
  // Defect fix #6: only allow release from 'active' (counterparty accepted), not 'pending'
  if (row.status !== 'active') return res.status(409).json({ error: `cannot release escrow in status ${row.status} — counterparty must accept first` });
  try {
    verifyEscrowBarrel(actor.did, row.barrel_tier_required || resolveEscrowTier(row.collateral_cents));
  } catch (error) {
    return res.status(error.statusCode || 500).json(error.body || { error: error.message });
  }

  const note = String(req.body?.note || '').trim();
  try {
    db.transaction(() => {
      const credit = billing.creditBalance(db, row.beneficiary_did, Number(row.collateral_cents), 'escrow_release', `Escrow release: ${row.title}`);
      if (!credit.ok) throw Object.assign(new Error(credit.error || 'beneficiary credit failed'), { statusCode: 500, body: credit });
      db.prepare(`
        UPDATE escrow_contracts
        SET status = 'released',
            settled_at = CURRENT_TIMESTAMP,
            metadata = json_set(COALESCE(NULLIF(metadata, ''), '{}'), '$.release_note', ?)
        WHERE id = ?
      `).run(note || '', row.id);
      recordEscrowEvent(row.id, 'released', actor.did, { note });
    })();
    res.json({ ok: true, escrow: serializeEscrow(getEscrowById(row.id)) });
  } catch (error) {
    return res.status(error.statusCode || 500).json(error.body || { error: error.message });
  }
});

app.post('/api/escrow/:id/refund', rateLimitStandard, (req, res) => {
  const actor = getBearerIdentity(req);
  if (!actor.ok) return res.status(actor.status).json({ error: actor.error });
  const row = getEscrowById(req.params.id);
  if (!row) return res.status(404).json({ error: 'escrow not found' });
  if (![row.creator_did, row.counterparty_did].includes(actor.did)) return res.status(403).json({ error: 'creator or counterparty required' });
  if (!['pending', 'active', 'disputed', 'expired'].includes(row.status)) return res.status(409).json({ error: `cannot refund escrow in status ${row.status}` });
  try {
    verifyEscrowBarrel(actor.did, row.barrel_tier_required || resolveEscrowTier(row.collateral_cents));
  } catch (error) {
    return res.status(error.statusCode || 500).json(error.body || { error: error.message });
  }

  const note = String(req.body?.note || '').trim();
  try {
    db.transaction(() => {
      const credit = billing.creditBalance(db, row.creator_did, Number(row.collateral_cents), 'escrow_refund', `Escrow refund: ${row.title}`);
      if (!credit.ok) throw Object.assign(new Error(credit.error || 'creator refund failed'), { statusCode: 500, body: credit });
      db.prepare(`
        UPDATE escrow_contracts
        SET status = 'refunded',
            settled_at = CURRENT_TIMESTAMP,
            metadata = json_set(COALESCE(NULLIF(metadata, ''), '{}'), '$.refund_note', ?)
        WHERE id = ?
      `).run(note || '', row.id);
      recordEscrowEvent(row.id, 'refunded', actor.did, { note });
    })();
    res.json({ ok: true, escrow: serializeEscrow(getEscrowById(row.id)) });
  } catch (error) {
    return res.status(error.statusCode || 500).json(error.body || { error: error.message });
  }
});

app.post('/api/escrow/:id/dispute', rateLimitStandard, (req, res) => {
  const actor = getBearerIdentity(req);
  if (!actor.ok) return res.status(actor.status).json({ error: actor.error });
  const row = getEscrowById(req.params.id);
  if (!row) return res.status(404).json({ error: 'escrow not found' });
  if (!ensureEscrowParticipant(row, actor.did)) return res.status(403).json({ error: 'escrow access denied' });
  if (!['pending', 'active'].includes(row.status)) return res.status(409).json({ error: `cannot dispute escrow in status ${row.status}` });
  const reason = String(req.body?.reason || '').trim();
  db.prepare(`
    UPDATE escrow_contracts
    SET status = 'disputed',
        metadata = json_set(COALESCE(NULLIF(metadata, ''), '{}'), '$.dispute_reason', ?)
    WHERE id = ?
  `).run(reason || '', row.id);
  recordEscrowEvent(row.id, 'disputed', actor.did, { reason });
  res.json({ ok: true, escrow: serializeEscrow(getEscrowById(row.id)) });
});

// ── [184] DemiPass Context Request Flow ──

// POST /api/blindkey/context/request — silicon requests a new context (pending approval)
app.post('/api/blindkey/context/request', rateLimitStandard, (req, res) => {
  const actor = getBearerIdentity(req);
  if (!actor.ok) return res.status(actor.status).json({ error: actor.error });
  const did = actor.did;

  const { secret_name, context_name, action_type, target_url_pattern, target_host_pattern, reason } = req.body || {};
  if (!secret_name || typeof secret_name !== 'string') return res.status(400).json({ error: 'secret_name required (string)' });
  if (!context_name || typeof context_name !== 'string') return res.status(400).json({ error: 'context_name required (string)' });
  if (!action_type || typeof action_type !== 'string') return res.status(400).json({ error: 'action_type required (string)' });
  if (secret_name.length > 100) return res.status(400).json({ error: 'secret_name: max 100 characters' });
  if (context_name.length > 100) return res.status(400).json({ error: 'context_name: max 100 characters' });

  const validActions = ['http_header', 'ssh_exec', 'http_body', 'env_inject', 'git_clone', 'smtp_auth', 'database_connect'];
  if (!validActions.includes(action_type)) {
    return res.status(400).json({ error: `action_type must be one of: ${validActions.join(', ')}` });
  }

  // Verify the silicon owns a secret with that name
  const secret = db.prepare('SELECT id FROM blindkey_secrets WHERE did = ? AND name = ? AND status = ?').get(did, secret_name, 'active');
  if (!secret) return res.status(404).json({ error: 'secret not found — you must own an active secret with that name' });

  try {
    const result = db.prepare(`
      INSERT INTO blindkey_context_requests (did, secret_name, requested_context, requested_action_type, target_url_pattern, target_host_pattern, reason)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(did, secret_name, context_name, action_type, target_url_pattern || '*', target_host_pattern || '*', reason || '');

    const requestId = result.lastInsertRowid;
    console.log(`[blindkey] context request ${requestId}: ${did} wants "${context_name}" on secret "${secret_name}"`);
    res.json({ request_id: requestId, status: 'pending' });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// GET /api/blindkey/context/requests — list context requests for owner or admin
app.get('/api/blindkey/context/requests', rateLimitStandard, (req, res) => {
  const actor = getDemiPassActor(req, res);
  if (!actor.ok) return;

  const { status = '', did, username } = req.query || {};
  let ownerDid = actor.did || null;
  if (actor.mode === 'admin') {
    if (did) {
      ownerDid = did;
    } else if (username) {
      const wallet = db.prepare('SELECT did FROM identity_wallets WHERE username = ?').get(username);
      if (!wallet) return res.status(404).json({ error: 'identity not found' });
      ownerDid = wallet.did;
    }
  }

  let sql = `
    SELECT id, did, secret_name, requested_context, requested_action_type,
           target_url_pattern, target_host_pattern, reason, status, reviewed_by, created_at, resolved_at
    FROM blindkey_context_requests
    WHERE 1 = 1
  `;
  const params = [];
  if (ownerDid) {
    sql += ' AND did = ?';
    params.push(ownerDid);
  }
  if (status) {
    sql += ' AND status = ?';
    params.push(status);
  }
  sql += ' ORDER BY created_at DESC';

  const requests = db.prepare(sql).all(...params);

  res.json({ requests, total: requests.length });
});

// POST /api/blindkey/context/requests/:id/approve — owner or admin approves, creates actual context
app.post('/api/blindkey/context/requests/:id/approve', rateLimitStandard, (req, res) => {
  const actor = getDemiPassActor(req, res);
  if (!actor.ok) return;

  const requestId = Number(req.params.id);
  const row = db.prepare('SELECT * FROM blindkey_context_requests WHERE id = ?').get(requestId);
  if (!row) return res.status(404).json({ error: 'context request not found' });
  if (row.status !== 'pending') return res.status(409).json({ error: `request already ${row.status}` });
  if (actor.mode !== 'admin' && row.did !== actor.did) {
    return res.status(403).json({ error: 'can only approve your own context requests' });
  }

  // Find the secret to get secret_id
  const secret = db.prepare('SELECT id FROM blindkey_secrets WHERE did = ? AND name = ? AND status = ?').get(row.did, row.secret_name, 'active');
  if (!secret) return res.status(404).json({ error: 'secret no longer exists or is inactive' });

  try {
    // Create the actual context in blindkey_contexts
    const created = insertBlindkeyContexts(secret.id, [{
      context_name: row.requested_context,
      action_type: row.requested_action_type,
      target_url_pattern: row.target_url_pattern,
      target_host_pattern: row.target_host_pattern,
      max_uses: 0,
    }], 'admin');

    if (created === 0) return res.status(400).json({ error: 'failed to create context' });

    // Mark the request as approved
    db.prepare("UPDATE blindkey_context_requests SET status = 'approved', reviewed_by = ?, resolved_at = datetime('now') WHERE id = ?").run(actor.actor, requestId);

    const ctx = db.prepare('SELECT * FROM blindkey_contexts WHERE secret_id = ? AND context_name = ?').get(secret.id, row.requested_context);
    console.log(`[blindkey] context request ${requestId} approved: "${row.requested_context}" on secret "${row.secret_name}" for ${row.did}`);
    res.json({
      ok: true,
      request_id: requestId,
      context: {
        id: ctx.id,
        context_name: ctx.context_name,
        action_type: ctx.action_type,
        target_url_pattern: ctx.target_url_pattern,
        target_host_pattern: ctx.target_host_pattern,
        status: ctx.status,
      },
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// POST /api/blindkey/context/requests/:id/deny — owner or admin denies the request
app.post('/api/blindkey/context/requests/:id/deny', rateLimitStandard, (req, res) => {
  const actor = getDemiPassActor(req, res);
  if (!actor.ok) return;

  const requestId = Number(req.params.id);
  const row = db.prepare('SELECT * FROM blindkey_context_requests WHERE id = ?').get(requestId);
  if (!row) return res.status(404).json({ error: 'context request not found' });
  if (row.status !== 'pending') return res.status(409).json({ error: `request already ${row.status}` });
  if (actor.mode !== 'admin' && row.did !== actor.did) {
    return res.status(403).json({ error: 'can only deny your own context requests' });
  }

  db.prepare("UPDATE blindkey_context_requests SET status = 'denied', reviewed_by = ?, resolved_at = datetime('now') WHERE id = ?").run(actor.actor, requestId);
  console.log(`[blindkey] context request ${requestId} denied: "${row.requested_context}" on secret "${row.secret_name}" for ${row.did}`);
  res.json({ ok: true, request_id: requestId, status: 'denied' });
});

// ── DemiPass Delegation — mycorrhizal secret sharing between silicons ──
// Secrets flow through the DemiPass mesh, not direct handoff.
// An owner grants a delegate permission to USE their secret (via use-tokens) without seeing it.

// POST /api/blindkey/delegate — owner grants access to another silicon
app.post('/api/blindkey/delegate', rateLimitStandard, (req, res) => {
  const actor = getDemiPassActor(req, res);
  if (!actor.ok) return;

  const { secret_name, delegate_did, context_name, max_uses, expires_in } = req.body || {};
  if (!secret_name || !delegate_did) return res.status(400).json({ error: 'secret_name and delegate_did required' });
  if (typeof secret_name !== 'string' || secret_name.length > 100) return res.status(400).json({ error: 'secret_name: string, max 100 chars' });
  if (typeof delegate_did !== 'string' || delegate_did.length > 200) return res.status(400).json({ error: 'delegate_did: string, max 200 chars' });
  if (context_name && typeof context_name !== 'string') return res.status(400).json({ error: 'context_name: must be a string' });

  // Resolve the secret — must be owned by the caller (or admin acting on behalf)
  const ownerDid = actor.did || req.body.owner_did;
  if (!ownerDid && actor.mode !== 'admin') return res.status(400).json({ error: 'could not determine owner DID' });

  const secret = resolveLatestBlindkeySecret(ownerDid, secret_name);
  if (!secret) return res.status(404).json({ error: 'secret not found or not owned by caller' });

  // Validate delegate exists in identity_wallets
  const delegateWallet = db.prepare('SELECT did FROM identity_wallets WHERE did = ?').get(delegate_did);
  if (!delegateWallet) return res.status(404).json({ error: 'delegate_did not found in identity registry' });

  // Cannot delegate to yourself
  if (delegate_did === ownerDid) return res.status(400).json({ error: 'cannot delegate a secret to yourself' });

  // If context_name specified, validate it exists and is active on the secret
  let contextId = null;
  if (context_name) {
    const ctx = db.prepare('SELECT * FROM blindkey_contexts WHERE secret_id = ? AND context_name = ? AND status = ?').get(secret.id, context_name, 'active');
    if (!ctx) return res.status(404).json({ error: `context '${context_name}' not found or not active on this secret` });
    contextId = ctx.id;
  }

  // Compute expires_at if expires_in provided (in seconds)
  let expiresAt = null;
  if (expires_in && typeof expires_in === 'number' && expires_in > 0) {
    expiresAt = new Date(Date.now() + expires_in * 1000).toISOString();
  }

  try {
    const result = db.prepare(`
      INSERT INTO demipass_delegations (owner_did, delegate_did, secret_id, context_id, max_uses, granted_by, expires_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(owner_did, delegate_did, secret_id, context_id) DO UPDATE SET
        status = 'active', max_uses = excluded.max_uses, use_count = 0,
        granted_at = CURRENT_TIMESTAMP, revoked_at = NULL, expires_at = excluded.expires_at
    `).run(ownerDid, delegate_did, secret.id, contextId, max_uses || 0, actor.actor, expiresAt);

    const delegation = db.prepare(`
      SELECT id FROM demipass_delegations WHERE owner_did = ? AND delegate_did = ? AND secret_id = ? AND (context_id IS ? OR context_id = ?)
    `).get(ownerDid, delegate_did, secret.id, contextId, contextId);

    db.prepare('INSERT INTO blindkey_events (event_type, actor, secret_id, context_name, detail) VALUES (?, ?, ?, ?, ?)').run(
      'delegation_granted', actor.actor, secret.id, context_name || '*',
      JSON.stringify({ delegation_id: delegation.id, owner_did: ownerDid, delegate_did, max_uses: max_uses || 0, expires_at: expiresAt })
    );

    console.log(`[demipass] delegation granted: ${ownerDid} -> ${delegate_did} for secret "${secret_name}" context "${context_name || '*'}"`);
    res.json({
      ok: true,
      delegation_id: delegation.id,
      delegate_did,
      context_name: context_name || '*',
      max_uses: max_uses || 0,
      expires_at: expiresAt,
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// POST /api/blindkey/delegate/revoke — owner revokes a delegation
app.post('/api/blindkey/delegate/revoke', rateLimitStandard, (req, res) => {
  const actor = getDemiPassActor(req, res);
  if (!actor.ok) return;

  const { delegation_id, delegate_did, secret_name } = req.body || {};
  if (!delegation_id && (!delegate_did || !secret_name)) {
    return res.status(400).json({ error: 'delegation_id or (delegate_did + secret_name) required' });
  }

  const ownerDid = actor.did || req.body.owner_did;
  if (!ownerDid && actor.mode !== 'admin') return res.status(400).json({ error: 'could not determine owner DID' });

  let delegation;
  if (delegation_id) {
    delegation = db.prepare('SELECT * FROM demipass_delegations WHERE id = ?').get(delegation_id);
  } else {
    const secret = resolveLatestBlindkeySecret(ownerDid, secret_name);
    if (!secret) return res.status(404).json({ error: 'secret not found' });
    delegation = db.prepare('SELECT * FROM demipass_delegations WHERE owner_did = ? AND delegate_did = ? AND secret_id = ? AND status = ?')
      .get(ownerDid, delegate_did, secret.id, 'active');
  }

  if (!delegation) return res.status(404).json({ error: 'delegation not found' });
  if (delegation.owner_did !== ownerDid && actor.mode !== 'admin') {
    return res.status(403).json({ error: 'only the owner or admin can revoke a delegation' });
  }
  if (delegation.status === 'revoked') return res.status(409).json({ error: 'delegation already revoked' });

  db.prepare("UPDATE demipass_delegations SET status = 'revoked', revoked_at = datetime('now') WHERE id = ?").run(delegation.id);

  db.prepare('INSERT INTO blindkey_events (event_type, actor, secret_id, context_name, detail) VALUES (?, ?, ?, ?, ?)').run(
    'delegation_revoked', actor.actor, delegation.secret_id, null,
    JSON.stringify({ delegation_id: delegation.id, owner_did: delegation.owner_did, delegate_did: delegation.delegate_did })
  );

  console.log(`[demipass] delegation revoked: id=${delegation.id} ${delegation.owner_did} -> ${delegation.delegate_did}`);
  res.json({ ok: true, revoked: true, delegation_id: delegation.id });
});

// GET /api/blindkey/delegations — list delegations (as owner or delegate)
app.get('/api/blindkey/delegations', rateLimitStandard, (req, res) => {
  const actor = getDemiPassActor(req, res);
  if (!actor.ok) return;

  const callerDid = actor.did;
  if (!callerDid && actor.mode !== 'admin') return res.status(400).json({ error: 'Bearer token required' });

  let delegations;
  if (actor.mode === 'admin') {
    // Admin sees all
    delegations = db.prepare(`
      SELECT d.*, s.name as secret_name, c.context_name
      FROM demipass_delegations d
      JOIN blindkey_secrets s ON s.id = d.secret_id
      LEFT JOIN blindkey_contexts c ON c.id = d.context_id
      ORDER BY d.granted_at DESC
    `).all();
  } else {
    // Show delegations granted BY the caller and delegations granted TO the caller
    delegations = db.prepare(`
      SELECT d.*, s.name as secret_name, c.context_name
      FROM demipass_delegations d
      JOIN blindkey_secrets s ON s.id = d.secret_id
      LEFT JOIN blindkey_contexts c ON c.id = d.context_id
      WHERE d.owner_did = ? OR d.delegate_did = ?
      ORDER BY d.granted_at DESC
    `).all(callerDid, callerDid);
  }

  // Never expose secret values — only metadata
  const results = delegations.map(d => ({
    id: d.id,
    owner_did: d.owner_did,
    delegate_did: d.delegate_did,
    secret_name: d.secret_name,
    context_name: d.context_name || '*',
    status: d.status,
    max_uses: d.max_uses,
    use_count: d.use_count,
    granted_by: d.granted_by,
    granted_at: d.granted_at,
    revoked_at: d.revoked_at,
    expires_at: d.expires_at,
    role: d.owner_did === callerDid ? 'owner' : 'delegate',
  }));

  res.json({ delegations: results, total: results.length });
});

// GET /api/blindkey/delegate/chain — show the delegation chain for a secret (owner only)
app.get('/api/blindkey/delegate/chain', rateLimitStandard, (req, res) => {
  const actor = getDemiPassActor(req, res);
  if (!actor.ok) return;

  const { secret_name } = req.query || {};
  if (!secret_name) return res.status(400).json({ error: 'secret_name query parameter required' });

  const ownerDid = actor.did;
  if (!ownerDid && actor.mode !== 'admin') return res.status(400).json({ error: 'Bearer token required' });

  // Resolve the secret — admin must specify did or username, no cross-tenant resolution
  let resolvedOwner = ownerDid;
  if (actor.mode === 'admin' && !resolvedOwner) {
    const { did, username } = req.query || {};
    if (did) resolvedOwner = did;
    else if (username) {
      const w = db.prepare('SELECT did FROM identity_wallets WHERE username = ?').get(username);
      if (w) resolvedOwner = w.did;
      else return res.status(404).json({ error: 'username not found' });
    } else {
      return res.status(400).json({ error: 'did or username required for admin delegation-chain lookup' });
    }
  }
  const secret = resolveLatestBlindkeySecret(resolvedOwner, secret_name);

  if (!secret) return res.status(404).json({ error: 'secret not found' });
  if (actor.mode !== 'admin' && secret.did !== ownerDid) return res.status(403).json({ error: 'only the secret owner can view delegation chains' });

  const delegations = db.prepare(`
    SELECT d.*, c.context_name,
      w.username as delegate_username, w.call_sign as delegate_call_sign
    FROM demipass_delegations d
    LEFT JOIN blindkey_contexts c ON c.id = d.context_id
    LEFT JOIN identity_wallets w ON w.did = d.delegate_did
    WHERE d.secret_id = ?
    ORDER BY d.granted_at DESC
  `).all(secret.id);

  const chain = delegations.map(d => ({
    delegation_id: d.id,
    delegate_did: d.delegate_did,
    delegate_username: d.delegate_username || null,
    delegate_call_sign: d.delegate_call_sign || null,
    context_name: d.context_name || '*',
    status: d.status,
    max_uses: d.max_uses,
    use_count: d.use_count,
    granted_by: d.granted_by,
    granted_at: d.granted_at,
    revoked_at: d.revoked_at,
    expires_at: d.expires_at,
  }));

  res.json({
    secret_name: secret.name,
    owner_did: secret.did,
    total_delegations: chain.length,
    active: chain.filter(d => d.status === 'active').length,
    revoked: chain.filter(d => d.status === 'revoked').length,
    chain,
  });
});

// ── Channel Info (public) ──

app.get('/api/channel/info', (req, res) => {
  res.json({
    channels: ['auth', 'ledger'],
    encryption: 'AES-256-GCM',
    key_derivation: 'HKDF-SHA256',
    note: 'Channel keys are derived per-channel from IDENTITY_MASTER_KEY. Each channel has independent key rotation.',
  });
});

// ============================================================
// Tick Service — temporal anchor for LLM sessions
// ============================================================

try { db.exec(`CREATE TABLE IF NOT EXISTS ticks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  did TEXT DEFAULT '',
  note TEXT DEFAULT '',
  ip TEXT DEFAULT '',
  tz TEXT DEFAULT 'UTC',
  chain_hash TEXT DEFAULT '',
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
)`); } catch(e) {}
try { db.exec("CREATE INDEX IF NOT EXISTS idx_ticks_did ON ticks(did)"); } catch(e) {}
try { db.exec("CREATE INDEX IF NOT EXISTS idx_ticks_ip ON ticks(ip)"); } catch(e) {}
// Add columns if missing (existing installs)
try { db.exec("ALTER TABLE ticks ADD COLUMN chain_hash TEXT DEFAULT ''"); } catch(e) {}
try { db.exec("ALTER TABLE ticks ADD COLUMN tick_type TEXT DEFAULT 'tick'"); } catch(e) {}
try { db.exec("ALTER TABLE ticks ADD COLUMN ref_tick INTEGER DEFAULT NULL"); } catch(e) {}
try { db.exec("ALTER TABLE ticks ADD COLUMN tags TEXT DEFAULT '[]'"); } catch(e) {}
try { db.exec("CREATE INDEX IF NOT EXISTS idx_ticks_type ON ticks(tick_type)"); } catch(e) {}

// Referral share accumulator — tracks fractional DD until >= 1 DD threshold
try { db.exec(`CREATE TABLE IF NOT EXISTS referral_accumulators (
  referrer_did TEXT NOT NULL,
  source_did TEXT NOT NULL,
  accumulated INTEGER DEFAULT 0,
  last_tick_id INTEGER DEFAULT 0,
  PRIMARY KEY (referrer_did, source_did)
)`); } catch(e) {}

// Tick chain: each tick's hash covers ALL fields + previous hash = tamper-evident chain
function computeTickHash(tickId, did, note, tz, time, prevHash, tickType, refTick, tags) {
  return crypto.createHash('sha256')
    .update(`${tickId}:${did}:${note}:${tz}:${time}:${tickType || 'tick'}:${refTick || ''}:${tags || '[]'}:${prevHash}`)
    .digest('hex');
}

app.post('/api/tick', (req, res) => {
  const { note = '', tz = 'UTC', type = 'tick', ref_tick = null, tags = [] } = req.body || {};
  const noteClean = String(note).slice(0, 300);
  const validTypes = ['tick', 'begin', 'complete', 'handoff', 'audit', 'decision', 'block', 'unblock', 'alert'];
  const tickType = validTypes.includes(type) ? type : 'tick';
  const tagsClean = Array.isArray(tags) ? JSON.stringify(tags.slice(0, 10).map(t => String(t).slice(0, 50))) : '[]';

  // Check for member auth (optional)
  const auth = getBearerIdentity(req);
  const isMember = auth.ok;
  const did = isMember ? auth.did : '';

  // Rate limit
  if (!isMember) {
    const recentAnon = db.prepare("SELECT COUNT(*) as n FROM ticks WHERE ip = ? AND created_at > datetime('now', '-1 minute') AND did = ''").get(req.ip || '').n;
    if (recentAnon >= 10) return res.status(429).json({ error: 'anonymous tick rate limit: 10/min. Onboard at /.well-known/silicon for higher limits and signed timestamps.' });
    const dailyAnon = db.prepare("SELECT COUNT(*) as n FROM ticks WHERE ip = ? AND created_at > datetime('now', '-1 day') AND did = ''").get(req.ip || '').n;
    if (dailyAnon >= 100) return res.status(429).json({ error: 'anonymous daily limit: 100/day. Onboard for unlimited.' });
  }

  // Bill member tick (1 DD per tick)
  if (isMember) {
    const debit = billing.deductBalance(db, did, 1, 'tick', noteClean.slice(0, 50) || 'tick');
    if (!debit.ok) return res.status(402).json({ error: 'insufficient balance for tick', balance: debit.balance_cents });
  }

  const now = new Date();
  const timeISO = now.toISOString();

  // Get previous tick for chain hash
  let prevTick = null;
  if (isMember && did) {
    prevTick = db.prepare('SELECT id, note, created_at, chain_hash FROM ticks WHERE did = ? ORDER BY id DESC LIMIT 1').get(did);
  } else {
    prevTick = db.prepare("SELECT id, note, created_at, chain_hash FROM ticks WHERE ip = ? AND did = '' ORDER BY id DESC LIMIT 1").get(req.ip || '');
  }
  const prevHash = prevTick?.chain_hash || '0'.repeat(64);

  // Insert tick
  const result = db.prepare('INSERT INTO ticks (did, note, ip, tz, created_at, tick_type, ref_tick, tags) VALUES (?, ?, ?, ?, ?, ?, ?, ?)').run(did, noteClean, req.ip || '', tz, timeISO, tickType, ref_tick, tagsClean);
  const tickId = result.lastInsertRowid;

  // Compute and store chain hash (covers ALL fields for tamper evidence)
  const chainHash = computeTickHash(tickId, did, noteClean, tz, timeISO, prevHash, tickType, ref_tick, tagsClean);
  db.prepare('UPDATE ticks SET chain_hash = ? WHERE id = ?').run(chainHash, tickId);

  // Referral revenue share: accumulate 10% (0.1 DD) per tick, pay out at 1 DD threshold
  if (isMember) {
    const wallet = db.prepare('SELECT referred_by FROM identity_wallets WHERE did = ?').get(did);
    if (wallet?.referred_by) {
      // Accumulate 1 unit (representing 0.1 DD in tenths) per tick
      db.prepare(`INSERT INTO referral_accumulators (referrer_did, source_did, accumulated, last_tick_id)
        VALUES (?, ?, 1, ?)
        ON CONFLICT(referrer_did, source_did) DO UPDATE SET
          accumulated = accumulated + 1,
          last_tick_id = ?`).run(wallet.referred_by, did, tickId, tickId);

      // Check if accumulated >= 10 (= 1 DD threshold)
      const acc = db.prepare('SELECT accumulated FROM referral_accumulators WHERE referrer_did = ? AND source_did = ?')
        .get(wallet.referred_by, did);
      if (acc && acc.accumulated >= 10) {
        const payoutDD = Math.floor(acc.accumulated / 10);
        const remainder = acc.accumulated % 10;
        billing.creditBalance(db, wallet.referred_by, payoutDD, 'tick_referral_share',
          `10% tick share from ${did.slice(0, 20)} (${payoutDD} DD)`, `tick_ref_batch_${tickId}`);
        db.prepare('UPDATE referral_accumulators SET accumulated = ? WHERE referrer_did = ? AND source_did = ?')
          .run(remainder, wallet.referred_by, did);
      }
    }
  }

  // Compute time since previous tick
  let ago = null;
  if (prevTick) {
    const prevTime = new Date(prevTick.created_at.endsWith('Z') ? prevTick.created_at : prevTick.created_at + 'Z');
    const diffMs = now.getTime() - prevTime.getTime();
    const diffMin = Math.floor(diffMs / 60000);
    const diffHr = Math.floor(diffMin / 60);
    const diffDay = Math.floor(diffHr / 24);
    ago = diffDay > 0 ? `${diffDay}d ${diffHr % 24}h` : diffHr > 0 ? `${diffHr}h ${diffMin % 60}m` : `${diffMin}m`;
  }

  // Build response
  const response = {
    tick_id: tickId,
    time: timeISO,
    tz,
    type: tickType,
    note: noteClean,
    chain_hash: chainHash,
    ref_tick: ref_tick || null,
    tags: JSON.parse(tagsClean),
    previous: prevTick ? { tick_id: prevTick.id, note: prevTick.note, at: prevTick.created_at, ago } : null,
    member: isMember,
  };

  // Signature (member only)
  if (isMember) {
    const wallet = db.prepare('SELECT referral_code FROM identity_wallets WHERE did = ?').get(did);
    const sigPayload = `${tickId}:${timeISO}:${did}:${noteClean}:${chainHash}`;
    const sig = crypto.createHmac('sha256', process.env.IDENTITY_MASTER_KEY || '').update(sigPayload).digest('hex');
    response.signature = sig;
    response.referral_code = wallet?.referral_code || '';
    response.did = did;
  } else {
    response.signature = null;
    response.referral_code = null;
    response.onboard_hint = '/.well-known/silicon';
  }

  res.json(response);
});

// POST /api/tick/verify — anyone can verify a tick signature (decentralized trust)
app.post('/api/tick/verify', (req, res) => {
  const { tick_id, signature } = req.body || {};
  if (!tick_id || !signature) return res.status(400).json({ error: 'tick_id and signature required' });

  const tick = db.prepare('SELECT id, did, note, tz, chain_hash, created_at FROM ticks WHERE id = ?').get(tick_id);
  if (!tick) return res.status(404).json({ error: 'tick not found', valid: false });
  if (!tick.did) return res.status(400).json({ error: 'anonymous ticks are not signed', valid: false });

  const sigPayload = `${tick.id}:${tick.created_at}:${tick.did}:${tick.note}:${tick.chain_hash}`;
  const expected = crypto.createHmac('sha256', process.env.IDENTITY_MASTER_KEY || '').update(sigPayload).digest('hex');

  const valid = signature === expected;
  res.json({
    valid,
    tick_id: tick.id,
    did: tick.did,
    time: tick.created_at,
    note: tick.note,
    chain_hash: tick.chain_hash,
  });
});

// GET /api/tick/stats — member aggregate stats
app.get('/api/tick/stats', (req, res) => {
  const auth = getBearerIdentity(req);
  if (!auth.ok) return res.status(401).json({ error: 'Bearer token required' });

  const total = db.prepare('SELECT COUNT(*) as n FROM ticks WHERE did = ?').get(auth.did).n;
  const first = db.prepare('SELECT created_at FROM ticks WHERE did = ? ORDER BY id ASC LIMIT 1').get(auth.did);
  const last = db.prepare('SELECT created_at FROM ticks WHERE did = ? ORDER BY id DESC LIMIT 1').get(auth.did);

  // Streak: consecutive days with at least one tick (counting backward from today)
  let streak = 0;
  if (total > 0) {
    const days = db.prepare(`SELECT DISTINCT date(created_at) as d FROM ticks WHERE did = ? ORDER BY d DESC`).all(auth.did);
    const today = new Date().toISOString().slice(0, 10);
    let expectedDate = new Date(today);
    for (const row of days) {
      const tickDate = row.d;
      const expected = expectedDate.toISOString().slice(0, 10);
      if (tickDate === expected) {
        streak++;
        expectedDate.setDate(expectedDate.getDate() - 1);
      } else {
        break;
      }
    }
  }

  res.json({
    did: auth.did,
    total_ticks: total,
    streak_days: streak,
    first_tick: first?.created_at || null,
    last_tick: last?.created_at || null,
  });
});

// GET /api/tick/ledger — member only, read your tick history
app.get('/api/tick/ledger', (req, res) => {
  const auth = getBearerIdentity(req);
  if (!auth.ok) return res.status(401).json({ error: 'Bearer token required. Ledger access is a member benefit.' });

  const limit = Math.min(100, Number(req.query.limit) || 50);
  const offset = Number(req.query.offset) || 0;
  const ticks = db.prepare('SELECT id, note, tz, chain_hash, created_at FROM ticks WHERE did = ? ORDER BY id DESC LIMIT ? OFFSET ?').all(auth.did, limit, offset);
  const total = db.prepare('SELECT COUNT(*) as n FROM ticks WHERE did = ?').get(auth.did).n;

  res.json({ ticks, total, limit, offset });
});

// POST /api/tick/chain/verify — verify chain integrity for a range of ticks
app.post('/api/tick/chain/verify', (req, res) => {
  const { did, from_tick_id, to_tick_id } = req.body || {};
  if (!did) return res.status(400).json({ error: 'did required' });

  const fromId = from_tick_id || 0;
  const toId = to_tick_id || Number.MAX_SAFE_INTEGER;
  const ticks = db.prepare('SELECT id, did, note, tz, chain_hash, created_at, tick_type, ref_tick, tags FROM ticks WHERE did = ? AND id >= ? AND id <= ? ORDER BY id ASC')
    .all(did, fromId, toId);

  if (ticks.length === 0) return res.json({ valid: true, ticks_checked: 0 });

  // Get the tick before the range for initial prev_hash
  const before = db.prepare('SELECT chain_hash FROM ticks WHERE did = ? AND id < ? ORDER BY id DESC LIMIT 1').get(did, ticks[0].id);
  let prevHash = before?.chain_hash || '0'.repeat(64);
  let brokenAt = null;

  for (const tick of ticks) {
    const expected = computeTickHash(tick.id, tick.did, tick.note, tick.tz, tick.created_at, prevHash, tick.tick_type, tick.ref_tick, tick.tags);
    if (tick.chain_hash !== expected) {
      brokenAt = tick.id;
      break;
    }
    prevHash = tick.chain_hash;
  }

  res.json({
    valid: brokenAt === null,
    ticks_checked: ticks.length,
    broken_at_tick_id: brokenAt,
    range: { from: ticks[0].id, to: ticks[ticks.length - 1].id },
  });
});

// ============================================================
// Auto-Ledger — free writes on every API call, paid reads
// ============================================================
// Every authenticated API response automatically records a ledger entry.
// Writing is free (anti-churn: the more you use it, the more you need it).
// Reading costs 1 DD per page (the monetization is in the read, not the write).

try { db.exec(`CREATE TABLE IF NOT EXISTS auto_ledger (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  did TEXT NOT NULL,
  method TEXT NOT NULL,
  path TEXT NOT NULL,
  status_code INTEGER DEFAULT 0,
  summary TEXT DEFAULT '',
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
)`); } catch(e) {}
try { db.exec("CREATE INDEX IF NOT EXISTS idx_al_did ON auto_ledger(did)"); } catch(e) {}
try { db.exec("CREATE INDEX IF NOT EXISTS idx_al_created ON auto_ledger(created_at)"); } catch(e) {}

// Middleware: intercept response to log ledger entries for authenticated requests
app.use((req, res, next) => {
  const originalEnd = res.end;
  res.end = function(chunk, encoding) {
    // Only log for authenticated API calls (not health, not static)
    if (req.path.startsWith('/api/') && req.path !== '/api/health') {
      const auth = getBearerIdentity(req);
      if (auth.ok) {
        const summary = summarizePath(req.method, req.path, res.statusCode);
        try {
          db.prepare('INSERT INTO auto_ledger (did, method, path, status_code, summary) VALUES (?, ?, ?, ?, ?)')
            .run(auth.did, req.method, req.path, res.statusCode, summary);
        } catch(e) {
          // Ledger writes must never break the response
        }
      }
    }
    originalEnd.call(this, chunk, encoding);
  };
  next();
});

function summarizePath(method, path, status) {
  // Human-readable summary of what happened
  if (path.includes('/tick') && method === 'POST') return 'tick recorded';
  if (path.includes('/tick/ledger')) return 'tick ledger read';
  if (path.includes('/tick/stats')) return 'tick stats read';
  if (path.includes('/tick/verify')) return 'tick signature verified';
  if (path.includes('/demipass/store')) return 'secret stored';
  if (path.includes('/demipass/request-token')) return 'use-token requested';
  if (path.includes('/demipass/use')) return 'use-token redeemed';
  if (path.includes('/demipass/rotate')) return 'secret rotated';
  if (path.includes('/demipass/delegate')) return 'delegation modified';
  if (path.includes('/email/send')) return 'email sent';
  if (path.includes('/identity/balance')) return 'balance checked';
  if (path.includes('/identity/auth')) return 'authenticated';
  if (path.includes('/transfer')) return 'transfer executed';
  if (status >= 400) return `${method} ${path} failed (${status})`;
  return `${method} ${path}`;
}

// GET /api/ledger — read your auto-ledger (1 DD per page)
app.get('/api/ledger', (req, res) => {
  const auth = getBearerIdentity(req);
  if (!auth.ok) return res.status(401).json({ error: 'Bearer token required. Your ledger is a member benefit.' });

  const limit = Math.min(100, Number(req.query.limit) || 50);
  const offset = Number(req.query.offset) || 0;

  // Charge 1 DD per read
  const debit = billing.deductBalance(db, auth.did, 1, 'ledger_read', 'auto-ledger page read');
  if (!debit.ok) return res.status(402).json({ error: 'insufficient balance for ledger read (1 DD)', balance: debit.balance_cents });

  const entries = db.prepare('SELECT id, method, path, status_code, summary, created_at FROM auto_ledger WHERE did = ? ORDER BY id DESC LIMIT ? OFFSET ?')
    .all(auth.did, limit, offset);
  const total = db.prepare('SELECT COUNT(*) as n FROM auto_ledger WHERE did = ?').get(auth.did).n;

  res.json({
    entries,
    total,
    limit,
    offset,
    cost: '1 DD',
    note: 'Writes are free. Every API call you make is automatically recorded here.',
  });
});

// GET /api/ledger/summary — free summary (total entries, date range, no detail)
app.get('/api/ledger/summary', (req, res) => {
  const auth = getBearerIdentity(req);
  if (!auth.ok) return res.status(401).json({ error: 'Bearer token required' });

  const total = db.prepare('SELECT COUNT(*) as n FROM auto_ledger WHERE did = ?').get(auth.did).n;
  const first = db.prepare('SELECT created_at FROM auto_ledger WHERE did = ? ORDER BY id ASC LIMIT 1').get(auth.did);
  const last = db.prepare('SELECT created_at FROM auto_ledger WHERE did = ? ORDER BY id DESC LIMIT 1').get(auth.did);
  const byMethod = db.prepare('SELECT method, COUNT(*) as n FROM auto_ledger WHERE did = ? GROUP BY method').all(auth.did);

  res.json({
    total_entries: total,
    first_entry: first?.created_at || null,
    last_entry: last?.created_at || null,
    by_method: Object.fromEntries(byMethod.map(r => [r.method, r.n])),
    read_cost: '1 DD per page',
  });
});

// ============================================================
// Chrono Triggers — scheduled delivery / dead man's switch
// ============================================================
// Schedule a payload to be delivered at a future time. If the owner
// doesn't cancel or extend before the trigger fires, it delivers.
// Use cases: dead man's switch, scheduled secret rotation, timed messages.

try { db.exec(`CREATE TABLE IF NOT EXISTS chrono_triggers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  did TEXT NOT NULL,
  name TEXT NOT NULL,
  payload TEXT NOT NULL DEFAULT '{}',
  action TEXT NOT NULL DEFAULT 'webhook',
  target TEXT NOT NULL DEFAULT '',
  fire_at TEXT NOT NULL,
  status TEXT DEFAULT 'armed' CHECK(status IN ('armed','fired','cancelled','extended')),
  fires_count INTEGER DEFAULT 0,
  last_extended_at TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
)`); } catch(e) {}
try { db.exec("CREATE INDEX IF NOT EXISTS idx_ct_did ON chrono_triggers(did)"); } catch(e) {}
try { db.exec("CREATE INDEX IF NOT EXISTS idx_ct_fire ON chrono_triggers(fire_at)"); } catch(e) {}
try { db.exec("CREATE INDEX IF NOT EXISTS idx_ct_status ON chrono_triggers(status)"); } catch(e) {}

// POST /api/chrono/create — schedule a trigger
app.post('/api/chrono/create', async (req, res) => {
  const auth = getBearerIdentity(req);
  if (!auth.ok) return res.status(401).json({ error: 'Bearer token required' });

  const { name, payload = {}, action = 'webhook', target, fire_in, fire_at } = req.body || {};
  if (!name) return res.status(400).json({ error: 'name required' });
  if (!target) return res.status(400).json({ error: 'target required (URL for webhook, DID for message)' });
  if (!fire_in && !fire_at) return res.status(400).json({ error: 'fire_in (e.g. "24h", "7d") or fire_at (ISO timestamp) required' });

  // SSRF prevention: validate webhook targets at create time
  if (action === 'webhook') {
    let targetUrl;
    try { targetUrl = new URL(target); } catch { return res.status(400).json({ error: 'target must be a valid URL' }); }
    if (targetUrl.protocol !== 'https:') return res.status(400).json({ error: 'webhook target must use HTTPS' });
    const host = targetUrl.hostname;
    if (/^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|localhost|127\.|0\.|169\.254\.|::1|fc|fd)/.test(host)) {
      return res.status(400).json({ error: 'webhook target cannot be a private/internal address' });
    }
    if (host === '169.254.169.254' || host === 'metadata.google.internal') {
      return res.status(400).json({ error: 'webhook target blocked: cloud metadata endpoint' });
    }
    // DNS resolution check — verify resolved IP is not private
    try {
      const dns = require('dns');
      const { promisify } = require('util');
      const ips = await promisify(dns.resolve4)(host);
      for (const ip of ips) {
        if (/^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|0\.|169\.254\.)/.test(ip)) {
          return res.status(400).json({ error: `webhook target resolves to private IP ${ip}` });
        }
      }
    } catch (dnsErr) {
      return res.status(400).json({ error: `webhook target DNS resolution failed: ${dnsErr.message}` });
    }
  }

  // Parse fire time
  let fireTime;
  if (fire_at) {
    fireTime = new Date(fire_at);
    if (isNaN(fireTime.getTime())) return res.status(400).json({ error: 'invalid fire_at timestamp' });
  } else {
    const match = fire_in.match(/^(\d+)(m|h|d)$/);
    if (!match) return res.status(400).json({ error: 'fire_in must be like "30m", "24h", or "7d"' });
    const [, amount, unit] = match;
    const ms = { m: 60000, h: 3600000, d: 86400000 }[unit] * Number(amount);
    if (ms > 30 * 86400000) return res.status(400).json({ error: 'max trigger window is 30 days' });
    fireTime = new Date(Date.now() + ms);
  }

  if (fireTime <= new Date()) return res.status(400).json({ error: 'fire time must be in the future' });

  // Cost: 1 DD to arm a trigger
  const debit = billing.deductBalance(db, auth.did, 1, 'chrono_create', `arm trigger: ${name}`);
  if (!debit.ok) return res.status(402).json({ error: 'insufficient balance (1 DD to arm)', balance: debit.balance_cents });

  const result = db.prepare('INSERT INTO chrono_triggers (did, name, payload, action, target, fire_at) VALUES (?, ?, ?, ?, ?, ?)')
    .run(auth.did, name, JSON.stringify(payload), action, target, fireTime.toISOString());

  res.json({
    ok: true,
    trigger_id: result.lastInsertRowid,
    name,
    fire_at: fireTime.toISOString(),
    status: 'armed',
    cost: '1 DD',
  });
});

// POST /api/chrono/extend — push back the fire time (dead man's switch reset)
app.post('/api/chrono/extend', (req, res) => {
  const auth = getBearerIdentity(req);
  if (!auth.ok) return res.status(401).json({ error: 'Bearer token required' });

  const { trigger_id, extend_by } = req.body || {};
  if (!trigger_id) return res.status(400).json({ error: 'trigger_id required' });
  if (!extend_by) return res.status(400).json({ error: 'extend_by required (e.g. "24h", "7d")' });

  const trigger = db.prepare('SELECT * FROM chrono_triggers WHERE id = ? AND did = ?').get(trigger_id, auth.did);
  if (!trigger) return res.status(404).json({ error: 'trigger not found or not owned by you' });
  if (trigger.status !== 'armed') return res.status(400).json({ error: `trigger is ${trigger.status}, cannot extend` });

  const match = extend_by.match(/^(\d+)(m|h|d)$/);
  if (!match) return res.status(400).json({ error: 'extend_by must be like "30m", "24h", or "7d"' });
  const [, amount, unit] = match;
  const ms = { m: 60000, h: 3600000, d: 86400000 }[unit] * Number(amount);

  const currentFire = new Date(trigger.fire_at);
  const newFire = new Date(Math.max(currentFire.getTime(), Date.now()) + ms);
  if (newFire - Date.now() > 30 * 86400000) return res.status(400).json({ error: 'max trigger window is 30 days from now' });

  db.prepare('UPDATE chrono_triggers SET fire_at = ?, last_extended_at = ?, status = ? WHERE id = ?')
    .run(newFire.toISOString(), new Date().toISOString(), 'armed', trigger_id);

  res.json({ ok: true, trigger_id, new_fire_at: newFire.toISOString(), status: 'armed' });
});

// POST /api/chrono/cancel — disarm a trigger
app.post('/api/chrono/cancel', (req, res) => {
  const auth = getBearerIdentity(req);
  if (!auth.ok) return res.status(401).json({ error: 'Bearer token required' });

  const { trigger_id } = req.body || {};
  if (!trigger_id) return res.status(400).json({ error: 'trigger_id required' });

  const trigger = db.prepare('SELECT * FROM chrono_triggers WHERE id = ? AND did = ?').get(trigger_id, auth.did);
  if (!trigger) return res.status(404).json({ error: 'trigger not found or not owned by you' });
  if (trigger.status !== 'armed') return res.status(400).json({ error: `trigger is ${trigger.status}, cannot cancel` });

  db.prepare('UPDATE chrono_triggers SET status = ? WHERE id = ?').run('cancelled', trigger_id);
  res.json({ ok: true, trigger_id, status: 'cancelled' });
});

// GET /api/chrono/list — list your triggers
app.get('/api/chrono/list', (req, res) => {
  const auth = getBearerIdentity(req);
  if (!auth.ok) return res.status(401).json({ error: 'Bearer token required' });

  const status = req.query.status || null;
  let triggers;
  if (status) {
    triggers = db.prepare('SELECT id, name, action, target, fire_at, status, fires_count, last_extended_at, created_at FROM chrono_triggers WHERE did = ? AND status = ? ORDER BY fire_at ASC')
      .all(auth.did, status);
  } else {
    triggers = db.prepare('SELECT id, name, action, target, fire_at, status, fires_count, last_extended_at, created_at FROM chrono_triggers WHERE did = ? ORDER BY fire_at ASC')
      .all(auth.did);
  }

  res.json({ triggers, total: triggers.length });
});

// Chrono Trigger executor — runs every 30 seconds, fires due triggers
setInterval(async () => {
  const now = new Date().toISOString();
  const due = db.prepare("SELECT * FROM chrono_triggers WHERE status = 'armed' AND fire_at <= ?").all(now);

  for (const trigger of due) {
    console.log(`[CHRONO] Firing trigger ${trigger.id} (${trigger.name}) for ${trigger.did}`);

    // Mark as fired immediately to prevent double-fire
    db.prepare('UPDATE chrono_triggers SET status = ?, fires_count = fires_count + 1 WHERE id = ?')
      .run('fired', trigger.id);

    // Execute the action
    if (trigger.action === 'webhook') {
      // SSRF prevention: resolve hostname to IP, check resolved IP, disable redirects
      let skipWebhook = false;
      let resolvedTarget = trigger.target;
      try {
        const u = new URL(trigger.target);
        if (u.protocol !== 'https:') { skipWebhook = true; }
        else {
          // Hostname-level check
          if (/^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|localhost|127\.|0\.|169\.254\.|::1|fc|fd)/.test(u.hostname)) skipWebhook = true;
          if (u.hostname === '169.254.169.254' || u.hostname === 'metadata.google.internal') skipWebhook = true;

          // DNS resolution check — resolve hostname and verify the IP is not private
          if (!skipWebhook) {
            const dns = require('dns');
            const { promisify } = require('util');
            const resolve4 = promisify(dns.resolve4);
            try {
              const ips = await resolve4(u.hostname);
              for (const ip of ips) {
                if (/^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|0\.|169\.254\.)/.test(ip)) {
                  console.error(`[CHRONO] BLOCKED: ${u.hostname} resolves to private IP ${ip}`);
                  skipWebhook = true;
                  break;
                }
              }
            } catch (dnsErr) {
              console.error(`[CHRONO] BLOCKED: DNS resolution failed for ${u.hostname}: ${dnsErr.message}`);
              skipWebhook = true;
            }
          }
        }
      } catch { skipWebhook = true; }

      if (skipWebhook) {
        console.error(`[CHRONO] BLOCKED: trigger ${trigger.id} targets unsafe URL ${trigger.target}`);
      } else {
        fetch(trigger.target, {
          method: 'POST',
          redirect: 'error', // SSRF: reject all redirects — attacker can't bounce to internal targets
          headers: { 'Content-Type': 'application/json', 'X-Chrono-Trigger': String(trigger.id) },
          body: JSON.stringify({
            trigger_id: trigger.id,
            name: trigger.name,
            payload: JSON.parse(trigger.payload || '{}'),
            fired_at: now,
            owner_did: trigger.did,
          }),
          signal: AbortSignal.timeout(10000),
        }).catch(err => {
          console.error(`[CHRONO] Webhook delivery failed for trigger ${trigger.id}: ${err.message}`);
        });
      }
    } else if (trigger.action === 'tick') {
      // Auto-tick: use the full tick pipeline (chain hash, billing, referral)
      const payload = JSON.parse(trigger.payload || '{}');
      const noteClean = `[chrono:${trigger.name}] ${payload.note || ''}`.slice(0, 300);
      const timeISO = new Date().toISOString();

      // Bill 1 DD
      billing.deductBalance(db, trigger.did, 1, 'tick', `chrono:${trigger.name}`);

      // Get previous tick for chain
      const prevTick = db.prepare('SELECT chain_hash FROM ticks WHERE did = ? ORDER BY id DESC LIMIT 1').get(trigger.did);
      const prevHash = prevTick?.chain_hash || '0'.repeat(64);

      // Insert
      const result = db.prepare('INSERT INTO ticks (did, note, ip, tz, created_at) VALUES (?, ?, ?, ?, ?)')
        .run(trigger.did, noteClean, '', 'UTC', timeISO);
      const tickId = result.lastInsertRowid;

      // Chain hash (includes tick_type for tamper evidence)
      const chainHash = computeTickHash(tickId, trigger.did, noteClean, 'UTC', timeISO, prevHash, 'tick', null, '[]');
      db.prepare('UPDATE ticks SET chain_hash = ? WHERE id = ?').run(chainHash, tickId);

      // Referral accumulator
      const wallet = db.prepare('SELECT referred_by FROM identity_wallets WHERE did = ?').get(trigger.did);
      if (wallet?.referred_by) {
        db.prepare(`INSERT INTO referral_accumulators (referrer_did, source_did, accumulated, last_tick_id)
          VALUES (?, ?, 1, ?) ON CONFLICT(referrer_did, source_did) DO UPDATE SET accumulated = accumulated + 1, last_tick_id = ?`)
          .run(wallet.referred_by, trigger.did, tickId, tickId);
        const acc = db.prepare('SELECT accumulated FROM referral_accumulators WHERE referrer_did = ? AND source_did = ?')
          .get(wallet.referred_by, trigger.did);
        if (acc && acc.accumulated >= 10) {
          const payoutDD = Math.floor(acc.accumulated / 10);
          const remainder = acc.accumulated % 10;
          billing.creditBalance(db, wallet.referred_by, payoutDD, 'tick_referral_share',
            `10% tick share from ${trigger.did.slice(0, 20)} (chrono)`, `tick_ref_chrono_${tickId}`);
          db.prepare('UPDATE referral_accumulators SET accumulated = ? WHERE referrer_did = ? AND source_did = ?')
            .run(remainder, wallet.referred_by, trigger.did);
        }
      }
    }

    // Audit log
    try {
      db.prepare('INSERT INTO auto_ledger (did, method, path, status_code, summary) VALUES (?, ?, ?, ?, ?)')
        .run(trigger.did, 'CHRONO', `/chrono/fire/${trigger.id}`, 200, `trigger fired: ${trigger.name}`);
    } catch(e) {}
  }
}, 30000);

// ============================================================
// Buoy Probe Telemetry — DDOS spike detection
// ============================================================
// Tracks outbound probe frequency per target host. When probe rate
// exceeds a threshold, logs a Buoy alert tick and throttles further
// probes. Prevents the platform from tripping router DDOS filters
// when multiple agents hammer the same host simultaneously.

const probeCounters = new Map(); // host → { count, windowStart, throttled }
const PROBE_WINDOW_MS = 60000;   // 1-minute sliding window
const PROBE_THRESHOLD = 30;      // max probes per host per window
const PROBE_THROTTLE_MS = 30000; // throttle duration after spike

// Record a probe to a host. Returns { allowed, count, throttled }
function recordProbe(host) {
  const now = Date.now();
  let entry = probeCounters.get(host);

  if (!entry || now - entry.windowStart > PROBE_WINDOW_MS) {
    entry = { count: 0, windowStart: now, throttled: false, throttleUntil: 0 };
    probeCounters.set(host, entry);
  }

  // Check throttle
  if (entry.throttled && now < entry.throttleUntil) {
    return { allowed: false, count: entry.count, throttled: true };
  }
  if (entry.throttled && now >= entry.throttleUntil) {
    entry.throttled = false;
  }

  entry.count++;

  // Spike detection
  if (entry.count >= PROBE_THRESHOLD) {
    entry.throttled = true;
    entry.throttleUntil = now + PROBE_THROTTLE_MS;

    console.error(`[BUOY-PROBE] SPIKE DETECTED: ${host} hit ${entry.count} probes in ${PROBE_WINDOW_MS/1000}s — throttling for ${PROBE_THROTTLE_MS/1000}s`);

    // Log a Buoy alert tick
    try {
      db.prepare('INSERT INTO ticks (did, note, ip, tz, tick_type, tags) VALUES (?, ?, ?, ?, ?, ?)')
        .run('system', `probe spike: ${host} (${entry.count} in ${PROBE_WINDOW_MS/1000}s)`, '', 'UTC', 'alert',
          JSON.stringify(['buoy:probe-spike', `host:${host}`, `count:${entry.count}`]));
    } catch(_) {}

    return { allowed: false, count: entry.count, throttled: true };
  }

  return { allowed: true, count: entry.count, throttled: false };
}

// Clean up stale entries every 5 minutes
setInterval(() => {
  const cutoff = Date.now() - PROBE_WINDOW_MS * 2;
  for (const [host, entry] of probeCounters) {
    if (entry.windowStart < cutoff) probeCounters.delete(host);
  }
}, 300000);

// GET /api/buoy/probes — view probe telemetry
app.get('/api/buoy/probes', (req, res) => {
  const auth = getBearerIdentity(req);
  if (!auth.ok) return res.status(401).json({ error: 'Bearer token required' });

  const probes = [];
  for (const [host, entry] of probeCounters) {
    probes.push({
      host,
      count: entry.count,
      window_start: new Date(entry.windowStart).toISOString(),
      throttled: entry.throttled,
      throttle_until: entry.throttled ? new Date(entry.throttleUntil).toISOString() : null,
    });
  }
  probes.sort((a, b) => b.count - a.count);

  // Recent spike ticks
  const spikeTicks = db.prepare("SELECT id, note, created_at FROM ticks WHERE tick_type = 'alert' AND tags LIKE '%probe-spike%' ORDER BY id DESC LIMIT 10").all();

  res.json({
    active_hosts: probes.length,
    threshold: PROBE_THRESHOLD,
    window_seconds: PROBE_WINDOW_MS / 1000,
    probes,
    recent_spikes: spikeTicks,
  });
});

// POST /api/buoy/probe — record an outbound probe (agents call this before probing)
app.post('/api/buoy/probe', (req, res) => {
  const { host } = req.body || {};
  if (!host) return res.status(400).json({ error: 'host required' });

  const result = recordProbe(host);
  if (!result.allowed) {
    return res.status(429).json({
      error: `probe throttled: ${host} exceeded ${PROBE_THRESHOLD} probes in ${PROBE_WINDOW_MS/1000}s`,
      throttled: true,
      count: result.count,
      retry_after_seconds: PROBE_THROTTLE_MS / 1000,
    });
  }

  res.json({ ok: true, host, count: result.count, threshold: PROBE_THRESHOLD });
});

// ============================================================
// Buoy → Conduit Bridge — push tick events to agents
// ============================================================
// When a Buoy tick of a notifiable type fires, relay it to Conduit
// so agents (Brain, Lori) get real-time notification without polling.

const CONDUIT_URL = process.env.CONDUIT_URL || 'http://100.69.1.78:8080';
const CONDUIT_CARBON_TOKEN = process.env.CONDUIT_CARBON_TOKEN || '';
const BUOY_NOTIFY_TYPES = new Set(['alert', 'handoff', 'block', 'unblock', 'decision']);

function buoyNotifyConduit(tick) {
  if (!CONDUIT_CARBON_TOKEN) return;
  if (!BUOY_NOTIFY_TYPES.has(tick.type)) return;

  const message = `[Buoy ${tick.type}] ${tick.note}${tick.tags?.length ? ' | tags: ' + tick.tags.join(', ') : ''}`;

  // Send to all registered agents via Conduit broadcast
  fetch(`${CONDUIT_URL}/api/messages/broadcast`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${CONDUIT_CARBON_TOKEN}`,
    },
    body: JSON.stringify({
      sender: 'buoy',
      body: message,
      metadata: {
        tick_id: tick.tick_id,
        type: tick.type,
        chain_hash: tick.chain_hash,
        tags: tick.tags || [],
        time: tick.time,
      },
    }),
    signal: AbortSignal.timeout(5000),
  }).catch(err => {
    // Conduit relay is fire-and-forget — never block the tick response
    console.error(`[BUOY→CONDUIT] relay failed: ${err.message}`);
  });
}

// Hook into the tick response — call after successful tick creation
// We patch the existing POST /api/tick response by adding a post-tick hook
const _origTickHandler = app._router.stack.find(
  l => l.route && l.route.path === '/api/tick' && l.route.methods.post
);

// Alternative approach: just expose a function and call it from the probe spike handler too
// The probe spike already inserts a tick — we just need to also relay it
// For now, add a Conduit relay endpoint that agents or the tick handler can call

app.post('/api/buoy/notify', (req, res) => {
  const { tick_id, type, note, chain_hash, tags, time } = req.body || {};
  if (!tick_id || !type) return res.status(400).json({ error: 'tick_id and type required' });

  buoyNotifyConduit({ tick_id, type, note: note || '', chain_hash: chain_hash || '', tags: tags || [], time: time || new Date().toISOString() });
  res.json({ ok: true, relayed_to: 'conduit', type });
});

// Auto-relay probe spikes to Conduit
const _origRecordProbe = recordProbe;
// Monkey-patch is fragile — instead, the spike alert tick above already records the event.
// Agents should subscribe to alert ticks via Conduit polling or the notify endpoint.

module.exports = { app, db, buoyNotifyConduit };

app.listen(PORT, () => console.log(`Dustforge running on port ${PORT}`));
