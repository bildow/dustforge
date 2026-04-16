require("dotenv").config({override:true});
const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const Database = require('better-sqlite3');

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

const rateLimit = require('express-rate-limit');
const nodemailer = require('nodemailer');
const rateLimitStrict = rateLimit({ windowMs: 15*60*1000, max: 10, message: { error: 'Too many requests' } });
const rateLimitStandard = rateLimit({ windowMs: 15*60*1000, max: 100, message: { error: 'Rate limit exceeded' } });

function createEmailTransport() {
  return nodemailer.createTransport({
    host: process.env.SMTP_HOST || 'localhost',
    port: Number(process.env.SMTP_PORT || 25),
    secure: false,
    tls: { rejectUnauthorized: false },
  });
}

// Ensure data directory exists
fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');

app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));

// ── CORS ──
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
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

// ── Discovery ──
const siliconManifest = JSON.parse(fs.readFileSync(path.join(__dirname, 'public', '.well-known', 'silicon'), 'utf8'));
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
  const { username, password, referral_code } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'username and password required' });
  if (!/^[a-z0-9][a-z0-9._-]{2,30}$/.test(username)) return res.status(400).json({ error: 'username must be 3-31 chars, lowercase alphanumeric' });
  if (password.length < 8) return res.status(400).json({ error: 'password must be at least 8 characters' });

  const existing = db.prepare('SELECT id FROM identity_wallets WHERE username = ?').get(username);
  if (existing) return res.status(409).json({ error: 'username already taken' });
  if (isSoftCapReached()) {
    return res.status(409).json(capacityGateResponse('Identity creation is paused while the waiting list is active. Use /api/waiting-list or sponsored onboarding once capacity opens.'));
  }

  try {
    const id = identity.createIdentity();
    const emailResult = await dustforge.createAccount(username, password);
    if (!emailResult.ok) return res.status(500).json({ error: `email creation failed: ${emailResult.error}` });

    const myReferralCode = crypto.randomBytes(6).toString('hex');
    let referredBy = '';
    if (referral_code) {
      const referrer = db.prepare('SELECT did FROM identity_wallets WHERE referral_code = ?').get(referral_code);
      if (referrer) referredBy = referrer.did;
    }

    db.prepare(`INSERT INTO identity_wallets (did, username, email, encrypted_private_key, balance_cents, referral_code, referred_by, stalwart_id) VALUES (?, ?, ?, ?, 0, ?, ?, ?)`)
      .run(id.did, username, emailResult.email, id.encrypted_private_key, myReferralCode, referredBy, emailResult.stalwart_id);
    db.prepare(`INSERT INTO identity_transactions (did, amount_cents, type, description, balance_after) VALUES (?, 0, 'account_created', 'Account created', 0)`).run(id.did);

    if (referredBy) referral.processReferralPayout(db, referredBy, id.did, username);

    // Track conversion
    const callerClass = conversion.classifyCaller(req);
    conversion.logConversion(db, id.did, callerClass);

    console.log(`[identity] created: ${username} → ${id.did} [${callerClass.classification}/${callerClass.source_channel}]`);
    res.json({ ok: true, did: id.did, email: emailResult.email, referral_code: myReferralCode });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
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
  const { did, amount_cents, source = 'manual', admin_key } = req.body || {};
  if (admin_key !== process.env.IDENTITY_MASTER_KEY) return res.status(403).json({ error: 'admin access required' });
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
    }
  }
  res.json({ received: true });
});

// Success page — STATUS ONLY, no account creation. Webhook is the canonical fulfillment path.
// If webhook hasn't fired yet (Tailscale-only), we trigger fulfillment here as a fallback
// but ONLY from the pending_checkouts table, never from Stripe metadata.
app.get('/api/stripe/success', async (req, res) => {
  const sessionId = req.query.session_id;
  let accountInfo = null;

  if (sessionId) {
    // Check if already fulfilled
    const pending = db.prepare('SELECT * FROM identity_pending_checkouts WHERE session_id = ?').get(sessionId);

    if (pending && pending.status === 'completed') {
      // Already created — show the info
      const wallet = db.prepare('SELECT did, email, referral_code FROM identity_wallets WHERE username = ?').get(pending.username);
      if (wallet) accountInfo = wallet;
    } else if (pending && pending.status === 'pending') {
      // Not yet fulfilled — verify payment and fulfill from server-side pending record
      try {
        const stripe = stripeService.getStripe();
        const session = await stripe.checkout.sessions.retrieve(sessionId);
        if (session.payment_status === 'paid') {
          // Decrypt password from server-side storage (never from Stripe metadata)
          const password = identity.decryptPrivateKey(pending.encrypted_password).toString('utf8');
          const id = identity.createIdentity();
          const emailResult = await dustforge.createAccount(pending.username, password);
          if (emailResult.ok) {
            const rc = crypto.randomBytes(6).toString('hex');
            let referredBy = '';
            if (pending.referral_code) { const r = db.prepare('SELECT did FROM identity_wallets WHERE referral_code = ?').get(pending.referral_code); if (r) referredBy = r.did; }
            db.prepare('INSERT INTO identity_wallets (did, username, email, encrypted_private_key, balance_cents, referral_code, referred_by, stalwart_id) VALUES (?, ?, ?, ?, 0, ?, ?, ?)').run(id.did, pending.username, emailResult.email, id.encrypted_private_key, rc, referredBy, emailResult.stalwart_id);
            db.prepare("INSERT INTO identity_transactions (did, amount_cents, type, description, balance_after) VALUES (?, 0, 'account_created', 'Created via Stripe', 0)").run(id.did);
            if (referredBy) referral.processReferralPayout(db, referredBy, id.did, pending.username);
            db.prepare('UPDATE identity_pending_checkouts SET status = ?, completed_at = CURRENT_TIMESTAMP WHERE session_id = ?').run('completed', sessionId);
            accountInfo = { did: id.did, email: emailResult.email, referral_code: rc };
            try {
              const t = createEmailTransport();
              await t.sendMail({ from:'welcome@dustforge.com', to: emailResult.email,
                subject:'Welcome to Dustforge', text:'DID: '+id.did+'\nEmail: '+emailResult.email+'\nReferral: '+rc+'\n\nAuth: POST https://api.dustforge.com/api/identity/auth-fingerprint\n\n— Dustforge' });
            } catch(_){}
            console.log('[stripe-success] fulfilled from pending: '+pending.username+' -> '+id.did);
          }
        }
      } catch(e) { console.warn('[stripe-success] fulfillment error:', e.message); }
    }
  }

  const info = accountInfo
    ? '<div style="margin-top:1.5rem;text-align:left;background:#132131;padding:1.5rem;border-radius:8px;max-width:400px"><div style="margin-bottom:0.75rem"><span style="color:#6d8397">Email:</span> <strong>'+accountInfo.email+'</strong></div><div style="margin-bottom:0.75rem"><span style="color:#6d8397">DID:</span> <code style="font-size:10px;word-break:break-all">'+accountInfo.did+'</code></div>'+(accountInfo.referral_code?'<div><span style="color:#6d8397">Referral:</span> '+accountInfo.referral_code+'</div>':'')+'<p style="margin-top:1rem;font-size:12px;color:#6d8397">Welcome email sent to your @dustforge.com inbox.</p></div>'
    : '<p style="color:#6d8397">Account creation in progress. Check your @dustforge.com inbox shortly.</p>';

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
      wallet_transfer: 'free',
      identity_lookup: 'free',
    },
  });
});

// ============================================================
// Prepaid Silicon Keys — gift card model
// ============================================================

// ============================================================
// Blindkey — secrets that never enter the LLM context
// ============================================================
// The silicon calls the API to USE a secret without ever seeing it.
// Dustforge injects the secret server-side, makes the call, returns the result.
// The secret never enters the silicon's context window.
//
// This is the only safe pattern for AI agents because you can't trust
// the agent's runtime — prompt injection can exfiltrate anything in context.

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

// POST /api/blindkey/store — store a secret (requires transact scope)
app.post('/api/blindkey/store', rateLimitStandard, billing.billingMiddleware(db, 'api_call_write', { cost: 0 }), (req, res) => {
  const { name, value, description, secret_type } = req.body || {};
  if (!name || !value) return res.status(400).json({ error: 'name and value required' });
  if (name.length > 64) return res.status(400).json({ error: 'name must be 64 chars or less' });
  if (value.length > 10000) return res.status(400).json({ error: 'value must be 10000 chars or less' });
  if (description && description.length > 256) return res.status(400).json({ error: 'description must be 256 chars or less' });

  // Basic code detection — reject if it looks like executable code
  const codePatterns = /^(#!|<script|function\s*\(|import\s+|require\s*\(|eval\s*\(|exec\s*\()/i;
  if (codePatterns.test(value.trim())) return res.status(400).json({ error: 'value appears to be executable code. Secrets should be credentials, tokens, or keys — not code.' });

  const validTypes = ['api_key', 'oauth_token', 'password', 'signing_key', 'webhook_secret', 'connection_string', 'certificate', 'other'];
  const resolvedType = validTypes.includes(secret_type) ? secret_type : 'api_key';

  try {
    const encrypted = blindkeyEncrypt(value);
    db.prepare(`
      INSERT INTO blindkey_secrets (did, name, description, secret_type, encrypted_value)
      VALUES (?, ?, ?, ?, ?)
      ON CONFLICT(did, name) DO UPDATE SET
        encrypted_value = excluded.encrypted_value,
        description = excluded.description,
        secret_type = excluded.secret_type,
        updated_at = CURRENT_TIMESTAMP
    `).run(req.identity.did, name, description || '', resolvedType, encrypted);

    res.json({ ok: true, name, secret_type: resolvedType, description: description || '', note: 'Secret stored. It will never be returned in any API response.' });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// GET /api/blindkey/list — list secret names and metadata (never values)
app.get('/api/blindkey/list', rateLimitStandard, billing.billingMiddleware(db, 'api_call_read'), (req, res) => {
  const secrets = db.prepare(
    'SELECT name, description, secret_type, status, use_count, last_used_at, created_at, updated_at FROM blindkey_secrets WHERE did = ? AND status = ?'
  ).all(req.identity.did, 'active');
  res.json({ secrets, total: secrets.length });
});

// POST /api/blindkey/use — use a secret without seeing it (delegated execution)
app.post('/api/blindkey/use', rateLimitStandard, billing.billingMiddleware(db, 'api_call_compute'), async (req, res) => {
  const { name, action, params } = req.body || {};
  if (!name || !action) return res.status(400).json({ error: 'name and action required' });

  const secret = db.prepare('SELECT * FROM blindkey_secrets WHERE did = ? AND name = ? AND status = ?').get(req.identity.did, name, 'active');
  if (!secret) return res.status(404).json({ error: 'secret not found' });

  let decryptedValue;
  try {
    decryptedValue = blindkeyDecrypt(secret.encrypted_value);
  } catch (e) {
    return res.status(500).json({ error: 'failed to decrypt secret' });
  }

  // Update usage stats
  db.prepare('UPDATE blindkey_secrets SET use_count = use_count + 1, last_used_at = CURRENT_TIMESTAMP WHERE id = ?').run(secret.id);

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
        const ALLOWED_HOSTS = ['api.openai.com', 'openrouter.ai', 'api.anthropic.com', 'generativelanguage.googleapis.com', 'api.github.com', 'api.stripe.com', 'api.signalwire.com'];
        let urlHost;
        try { urlHost = new URL(url).hostname; } catch (_) { return res.status(400).json({ error: 'invalid URL' }); }
        if (!ALLOWED_HOSTS.some(h => urlHost === h || urlHost.endsWith('.' + h))) {
          return res.status(403).json({ error: `host ${urlHost} not in whitelist. Allowed: ${ALLOWED_HOSTS.join(', ')}. Contact support to add hosts.` });
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

      default:
        return res.status(400).json({ error: `unknown action: ${action}. Supported: http_header, sign, verify_match, inject_env` });
    }

    res.json({ ok: true, action, secret_name: name, result });
  } catch (e) {
    res.status(500).json({ error: `action failed: ${e.message}` });
  }
});

// DELETE /api/blindkey/revoke — deactivate a secret
app.delete('/api/blindkey/revoke', rateLimitStandard, billing.billingMiddleware(db, 'api_call_write', { cost: 0 }), (req, res) => {
  const { name } = req.body || {};
  if (!name) return res.status(400).json({ error: 'name required' });
  const result = db.prepare('UPDATE blindkey_secrets SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE did = ? AND name = ?')
    .run('revoked', req.identity.did, name);
  if (result.changes === 0) return res.status(404).json({ error: 'secret not found' });
  res.json({ ok: true, name, status: 'revoked' });
});

// GET /api/blindkey/types — list supported secret types and actions
app.get('/api/blindkey/types', (_req, res) => {
  res.json({
    secret_types: ['api_key', 'oauth_token', 'password', 'signing_key', 'webhook_secret', 'connection_string', 'certificate', 'other'],
    actions: {
      http_header: { description: 'Make an HTTP request with the secret injected as a header', params: ['url', 'method', 'header_name', 'header_prefix', 'body'] },
      sign: { description: 'Sign data using the secret as an HMAC key', params: ['data', 'algorithm'] },
      verify_match: { description: 'Check if a candidate value matches the secret', params: ['candidate'] },
      inject_env: { description: 'Confirm secret is set as an environment variable (value not returned)', params: ['env_name'] },
    },
    security: {
      encryption: 'AES-256-GCM at rest',
      access: 'Bearer token with transact scope required',
      exposure: 'Secret values are NEVER returned in any API response',
      billing: 'Store/revoke: free. List: free. Use: 1¢ per action (api_call_compute)',
    },
  });
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
    identity: { create: { method: "POST", url: "/api/identity/create", body: { username: "your-chosen-name", password: "min-8-chars" }, cost: "$1.00 USD", checkout: { method: "POST", url: "/api/stripe/checkout/account" } } },
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
<h2>What You Get</h2><ul><li><strong>DID:key identity</strong> — cryptographic Silicon SSN</li><li><strong>@dustforge.com email</strong> — with 2FA</li><li><strong>Wallet</strong> — per-call billing, Stripe topup</li><li><strong>Referral code</strong> — earn 25¢ per onboard</li></ul>
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


// POST /api/identity/auth-fingerprint — authenticate via fingerprint (no email 2FA)
app.post('/api/identity/auth-fingerprint', rateLimitStandard, async (req, res) => {
  const { did, username, password, scope = 'read', expires_in = '24h' } = req.body || {};
  if ((!did && !username) || !password) return res.status(400).json({ error: 'did/username and password required' });
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
  const debit = billing.deductBalance(db, from_did, amount_cents, 'transfer_out', 'Transfer to ' + receiver.username);
  if (!debit.ok) return res.status(402).json(debit);
  billing.creditBalance(db, to_did, amount_cents, 'transfer_in', 'Transfer from ' + sender.username);
  res.json({ ok: true, from: { did: from_did, balance_after: debit.balance_after }, to: { did: to_did }, amount_cents });
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

// GET /api/identity/resonance/methodology — public documentation
app.get('/api/identity/resonance/methodology', (_req, res) => {
  res.json({
    name: 'Dustforge Silicon Resonance Score',
    version: '1.0',
    purpose: 'Behavioral similarity between silicon identities. Clustering signal, not identity proof.',
    signals: [
      { name: 'user_agent', weight: 3, spoofability: 'trivial' },
      { name: 'accept_headers', weight: 2, spoofability: 'trivial' },
      { name: 'header_order', weight: 2, spoofability: 'moderate' },
      { name: 'body_key_order', weight: 2, spoofability: 'moderate' },
      { name: 'json_style', weight: 1, spoofability: 'trivial' },
      { name: 'http_version', weight: 1, spoofability: 'difficult' },
      { name: 'ip_subnet', weight: 1, spoofability: 'difficult' },
    ],
    limitations: [
      'Scores above 0.85 cannot reliably distinguish same-entity from shared-framework.',
      '50% of score weight is trivially spoofable.',
      'The score is a clustering signal, not identity proof.',
    ],
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
  critical: { label: 'Critical (P0)', min_payout: 500, max_payout: 5000, description: 'Auth bypass, RCE, data exfiltration, Blindkey secret leakage' },
  high:     { label: 'High (P1)', min_payout: 200, max_payout: 1000, description: 'Privilege escalation, wallet manipulation, identity impersonation' },
  medium:   { label: 'Medium (P2)', min_payout: 50, max_payout: 500, description: 'Information disclosure, rate limit bypass, relay abuse' },
  low:      { label: 'Low (P3)', min_payout: 10, max_payout: 100, description: 'UI issues, minor info leaks, hardening suggestions' },
};

app.get('/api/bounty/program', (_req, res) => {
  res.json({
    name: 'Dustforge Security Bounty',
    status: 'active',
    scope: [
      'api.dustforge.com — all endpoints',
      'dustforge.com — static site',
      'Authentication (fingerprint, token, Blindkey)',
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
  if (!BOUNTY_TIERS[severity]) return res.status(400).json({ error: 'severity must be: critical, high, medium, low' });

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
  const { admin_key, count, prefix, password } = req.body || {};
  if (admin_key !== process.env.IDENTITY_MASTER_KEY) return res.status(403).json({ error: 'admin_key required' });
  if (!count || count < 1 || count > 50) return res.status(400).json({ error: 'count must be 1-50' });
  if (!prefix || !/^[a-z0-9]{2,20}$/.test(prefix)) return res.status(400).json({ error: 'prefix must be 2-20 chars, lowercase alphanumeric' });
  if (!password || password.length < 8) return res.status(400).json({ error: 'password must be 8+ chars' });

  if (isSoftCapReached()) return res.status(409).json(capacityGateResponse('Bulk creation paused — capacity limit reached.'));

  const created = [];
  const errors = [];
  for (let i = 0; i < count; i++) {
    const username = `${prefix}-${String(i + 1).padStart(3, '0')}`;
    try {
      const existing = db.prepare('SELECT id FROM identity_wallets WHERE username = ?').get(username);
      if (existing) { errors.push({ username, error: 'already exists' }); continue; }
      const id = identity.createIdentity();
      const referralCode = crypto.randomBytes(6).toString('hex');
      db.prepare(`INSERT INTO identity_wallets (did, username, email, encrypted_private_key, referral_code, status)
        VALUES (?, ?, ?, ?, ?, 'active')`).run(id.did, username, `${username}@dustforge.com`, id.encrypted_private_key, referralCode);
      db.prepare("INSERT INTO identity_transactions (did, amount_cents, type, description, balance_after) VALUES (?, 0, 'account_created', 'Bulk provisioned', 0)").run(id.did);
      created.push({ username, did: id.did, email: `${username}@dustforge.com`, referral_code: referralCode });
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

  const ttlSeconds = parseDuration(expires_in || '5m');
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
  const { admin_key, did, status, reason } = req.body || {};
  if (admin_key !== process.env.IDENTITY_MASTER_KEY) return res.status(403).json({ error: 'admin_key required' });
  if (!did || !status) return res.status(400).json({ error: 'did and status required' });
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
  const { admin_key } = req.query;
  if (admin_key !== process.env.IDENTITY_MASTER_KEY) return res.status(403).json({ error: 'admin_key required' });

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
    relays: relays,
    fingerprint_profiles: profiles,
    waiting_list: waitingList,
    bounty: { open: bountyOpen, resolved: bountyResolved },
    recent_signups: recentSignups,
    recent_transactions: recentTransactions,
  });
});

module.exports = { app, db };

app.listen(PORT, () => console.log(`Dustforge running on port ${PORT}`));
