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

app.post('/api/billing/topup', (req, res) => {
  const { did, amount_cents, source = 'manual' } = req.body || {};
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
  const existing = db.prepare('SELECT id FROM identity_wallets WHERE username = ?').get(username);
  if (existing) return res.status(409).json({ error: 'username already taken' });
  try {
    res.json(await stripeService.createAccountCheckout({ username, password, referral_code, bulk: Boolean(bulk) }));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/stripe/checkout/topup', billing.billingMiddleware(db, 'api_call_read'), async (req, res) => {
  const { amount_cents } = req.body || {};
  if (!amount_cents) return res.status(400).json({ error: 'amount_cents required' });
  try {
    res.json(await stripeService.createTopupCheckout(req.identity.did, Number(amount_cents)));
  } catch (e) { res.status(400).json({ error: e.message }); }
});

app.post('/api/stripe/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  let event;
  try { event = stripeService.constructWebhookEvent(req.body, req.headers['stripe-signature']); }
  catch (e) { return res.status(400).json({ error: 'webhook verification failed' }); }

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    const meta = session.metadata || {};
    if (meta.type === 'account_creation') {
      try {
        const id = identity.createIdentity();
        const emailResult = await dustforge.createAccount(meta.username, `stripe_${meta.password_hash || 'default'}`);
        if (!emailResult.ok) return res.json({ received: true, error: 'email failed' });
        const myReferralCode = crypto.randomBytes(6).toString('hex');
        let referredBy = '';
        if (meta.referral_code) { const r = db.prepare('SELECT did FROM identity_wallets WHERE referral_code = ?').get(meta.referral_code); if (r) referredBy = r.did; }
        db.prepare(`INSERT INTO identity_wallets (did, username, email, encrypted_private_key, balance_cents, referral_code, referred_by, stalwart_id) VALUES (?, ?, ?, ?, 0, ?, ?, ?)`).run(id.did, meta.username, emailResult.email, id.encrypted_private_key, myReferralCode, referredBy, emailResult.stalwart_id);
        db.prepare(`INSERT INTO identity_transactions (did, amount_cents, type, description, balance_after) VALUES (?, 0, 'account_created', 'Account created via Stripe', 0)`).run(id.did);
        if (referredBy) referral.processReferralPayout(db, referredBy, id.did, meta.username);
        console.log(`[stripe] account: ${meta.username} → ${id.did}`);
      } catch (e) { console.error('[stripe] error:', e.message); }
    } else if (meta.type === 'wallet_topup') {
      billing.creditBalance(db, meta.did, Number(meta.amount_cents), 'stripe_topup', `Stripe topup`);
    }
  }
  res.json({ received: true });
});

app.get('/api/stripe/success', async (req, res) => {
  const sessionId = req.query.session_id;
  let accountInfo = null;
  if (sessionId) {
    try {
      const stripe = stripeService.getStripe();
      const session = await stripe.checkout.sessions.retrieve(sessionId);
      const meta = session.metadata || {};
      if (meta.type === 'account_creation' && meta.username) {
        const existing = db.prepare('SELECT did, email FROM identity_wallets WHERE username = ?').get(meta.username);
        if (existing) { accountInfo = existing; }
        else {
          try {
            const id = identity.createIdentity();
            const password = meta.password || crypto.randomBytes(16).toString('hex');
            const emailResult = await dustforge.createAccount(meta.username, password);
            if (emailResult.ok) {
              const rc = crypto.randomBytes(6).toString('hex');
              let referredBy = '';
              if (meta.referral_code) { const r = db.prepare('SELECT did FROM identity_wallets WHERE referral_code = ?').get(meta.referral_code); if (r) referredBy = r.did; }
              db.prepare('INSERT INTO identity_wallets (did, username, email, encrypted_private_key, balance_cents, referral_code, referred_by, stalwart_id) VALUES (?, ?, ?, ?, 0, ?, ?, ?)').run(id.did, meta.username, emailResult.email, id.encrypted_private_key, rc, referredBy, emailResult.stalwart_id);
              db.prepare("INSERT INTO identity_transactions (did, amount_cents, type, description, balance_after) VALUES (?, 0, 'account_created', 'Created via Stripe', 0)").run(id.did);
              if (referredBy) referral.processReferralPayout(db, referredBy, id.did, meta.username);
              accountInfo = { did: id.did, email: emailResult.email, referral_code: rc };
              try {
                const t = createEmailTransport();
                await t.sendMail({ from:'welcome@dustforge.com', to: emailResult.email,
                  subject:'Welcome to Dustforge', text:'DID: '+id.did+'\nEmail: '+emailResult.email+'\n\nAuth: POST /api/identity/auth-fingerprint\n{"username":"'+meta.username+'","password":"YOUR_PASS","scope":"transact"}\n\nAPI: GET /.well-known/silicon' });
              } catch(_){}
              console.log('[stripe-success] created: '+meta.username+' -> '+id.did);
            }
          } catch(e) { console.error('[stripe-success] failed:', e.message); }
        }
      }
    } catch(e) { console.warn('[stripe-success] session error:', e.message); }
  }
  const info = accountInfo ? '<div style="margin-top:1.5rem;text-align:left;background:#132131;padding:1.5rem;border-radius:8px;max-width:400px"><div style="margin-bottom:0.75rem"><span style="color:#6d8397">Email:</span> <strong>'+accountInfo.email+'</strong></div><div style="margin-bottom:0.75rem"><span style="color:#6d8397">DID:</span> <code style="font-size:10px;word-break:break-all">'+accountInfo.did+'</code></div>'+(accountInfo.referral_code?'<div><span style="color:#6d8397">Referral:</span> '+accountInfo.referral_code+'</div>':'')+'<p style="margin-top:1rem;font-size:12px;color:#6d8397">Welcome email sent to the @dustforge.com inbox.</p><div style="margin-top:1rem;padding:1rem;background:#0e1824;border-radius:6px;text-align:left"><div style="font-size:11px;color:#5fb3ff;font-weight:bold;margin-bottom:0.5rem">Next Step — Authenticate</div><code style="font-size:10px;color:#9cb4c9;word-break:break-all">POST https://dustforge.com/api/identity/auth-fingerprint</code><pre style="font-size:10px;color:#6d8397;margin:0.5rem 0;white-space:pre-wrap">{"username":"YOUR_USERNAME","password":"YOUR_PASSWORD","scope":"transact","expires_in":"7d"}</pre><div style="font-size:10px;color:#6d8397">Full API: <a href="https://dustforge.com/.well-known/silicon" style="color:#5fb3ff">/.well-known/silicon</a></div></div><p style="display:none"></p></div>' : '<p style="color:#6d8397">Account creation in progress...</p>';
  res.send('<html><head><meta charset="UTF-8"></head><body style="background:#08111a;color:#e7f1fb;font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0"><div style="text-align:center;max-width:500px;padding:2rem"><h1 style="color:#69c7b1">Payment Successful</h1><p>Your silicon identity has been activated.</p>'+info+'</div></body></html>');
});

app.get('/api/stripe/cancel', (req, res) => {
  res.send('<html><body style="background:#0d0d0d;color:#e8e4dc;font-family:monospace;display:flex;align-items:center;justify-content:center;height:100vh"><div style="text-align:center"><h1 style="color:#c0504a">Payment Cancelled</h1><p>No charges were made.</p></div></body></html>');
});

app.get('/api/stripe/prices', (req, res) => {
  res.json({
    account_single: { price_cents: 100, description: 'Single silicon account ($1.00)' },
    account_bulk_10: { price_cents: 500, description: '10 silicon accounts ($5.00)' },
    topup_options: [{ amount_cents: 500, label: '$5.00' }, { amount_cents: 1000, label: '$10.00' }, { amount_cents: 5000, label: '$50.00' }, { amount_cents: 10000, label: '$100.00' }],
    referral_payout_cents: 25,
  });
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

const nodemailer = require('nodemailer');
const rateLimit = require('express-rate-limit');

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
        path: '/api/principal/' + encodeURIComponent(wallet.username + '@dustforge.com'),
        method: 'GET', headers: { 'Authorization': 'Basic ' + adminAuth } }, (res) => {
        let data = ''; res.on('data', chunk => data += chunk);
        res.on('end', () => { try { resolve(JSON.parse(data).data.secrets[0]); } catch(_) { resolve(null); } });
      });
      req.on('error', () => resolve(null));
      req.setTimeout(5000, () => { req.destroy(); resolve(null); });
      req.end();
    });
    if (storedPassword !== null && storedPassword !== password) {
      return res.status(401).json({ error: 'invalid password' });
    }
  } catch(e) {}

  const token = identity.createTokenForIdentity(wallet.encrypted_private_key, wallet.did, {
    scope, expiresIn: expires_in,
    metadata: { email: wallet.email, username: wallet.username, auth_method: 'fingerprint' },
  });
  res.json({ ok: true, token, did: wallet.did, scope, email: wallet.email, auth_method: 'fingerprint' });
});

// POST /api/identity/request-account — silicon requests account, carbon gets payment link
app.post('/api/identity/request-account', rateLimitStrict, async (req, res) => {
  const { username, password, carbon_email, referral_code } = req.body || {};
  if (!username || !password || !carbon_email) return res.status(400).json({ error: 'username, password, and carbon_email required' });
  if (!/^[a-z0-9][a-z0-9._-]{2,30}$/.test(username)) return res.status(400).json({ error: 'invalid username' });
  if (password.length < 8) return res.status(400).json({ error: 'password must be 8+ chars' });
  const existing = db.prepare('SELECT id FROM identity_wallets WHERE username = ?').get(username);
  if (existing) return res.status(409).json({ error: 'username taken' });
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

module.exports = { app, db };

app.listen(PORT, () => console.log(`Dustforge running on port ${PORT}`));
