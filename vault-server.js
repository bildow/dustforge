/**
 * Dustforge Vault API — Hardened secret operations server
 *
 * Runs on phasewhip (100.83.112.88:7743). Only accessible over Tailscale.
 * The Dustforge API on RackNerd calls this for operations that must never
 * leave the trusted network: private key decryption, ledger writes,
 * and DemiPass usage.
 *
 * Auth: HMAC-SHA256 on every request (except /vault/health).
 * Anomaly detection: lockdown after 10 decrypts in 60 seconds.
 */

require('dotenv').config({ override: true });
const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const Database = require('better-sqlite3');
const rateLimit = require('express-rate-limit');

// ── Required env vars ──
const IDENTITY_MASTER_KEY = process.env.IDENTITY_MASTER_KEY;
const VAULT_SHARED_SECRET = process.env.VAULT_SHARED_SECRET;
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY;

if (!IDENTITY_MASTER_KEY) {
  console.error('[FATAL] IDENTITY_MASTER_KEY required');
  process.exit(1);
}
if (!VAULT_SHARED_SECRET) {
  console.error('[FATAL] VAULT_SHARED_SECRET required');
  process.exit(1);
}
if (!ENCRYPTION_KEY) {
  console.error('[FATAL] ENCRYPTION_KEY required');
  process.exit(1);
}

const PORT = 7743;
const DB_PATH = process.env.DB_PATH || './data/dustforge.db';
const ENCRYPTION_ALGO = 'aes-256-gcm';

// ── Database ──
fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');

// ── Vault audit log table ──
db.exec(`CREATE TABLE IF NOT EXISTS vault_audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  endpoint TEXT NOT NULL,
  source_ip TEXT DEFAULT '',
  request_body TEXT DEFAULT '',
  result TEXT DEFAULT '',
  error TEXT DEFAULT '',
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
)`);

// Ensure idempotency_key column exists on identity_transactions
try {
  db.exec(`ALTER TABLE identity_transactions ADD COLUMN idempotency_key TEXT`);
} catch (_) { /* column already exists */ }

// ── Express setup ──
const app = express();
app.set('trust proxy', 1);
app.use(express.json());

// DemiPass public surface — keep legacy /vault/blindkey-use working during the rename.
app.use('/vault/demipass-use', (req, _res, next) => {
  req.url = '/vault/blindkey-use';
  next();
});

// Rate limit: 100 requests per minute per IP
const globalLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100,
  message: { error: 'rate limit exceeded' },
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(globalLimiter);

// ── Anomaly Detection — Decrypt Lockdown ──
const decryptTimestamps = [];
let lockdownUntil = 0;

function recordDecryptRequest() {
  const now = Date.now();
  decryptTimestamps.push(now);
  // Prune entries older than 60 seconds
  while (decryptTimestamps.length > 0 && decryptTimestamps[0] < now - 60000) {
    decryptTimestamps.shift();
  }
  if (decryptTimestamps.length > 10) {
    lockdownUntil = now + 5 * 60 * 1000; // 5 minute lockdown
    console.error(`[ALERT] LOCKDOWN ENGAGED — ${decryptTimestamps.length} decrypt requests in 60s. Lockdown until ${new Date(lockdownUntil).toISOString()}`);
    auditLog('LOCKDOWN', '', JSON.stringify({ count: decryptTimestamps.length }), 'lockdown_engaged', '');
  }
}

function isLockedDown() {
  return Date.now() < lockdownUntil;
}

// ── Nonce Replay Protection ──
const seenNonces = new Map(); // nonce -> timestamp

// Cleanup old nonces every 30 seconds
setInterval(() => {
  const cutoff = Date.now() - 60000;
  for (const [nonce, ts] of seenNonces) {
    if (ts < cutoff) seenNonces.delete(nonce);
  }
}, 30000);

// ── Audit Logger ──
const auditStmt = db.prepare(
  'INSERT INTO vault_audit_log (endpoint, source_ip, request_body, result, error) VALUES (?, ?, ?, ?, ?)'
);

function auditLog(endpoint, sourceIp, body, result, error) {
  try {
    // Redact sensitive fields from the logged body
    let sanitized = body;
    try {
      const parsed = JSON.parse(body);
      if (parsed.plaintext) parsed.plaintext = '[REDACTED]';
      if (parsed.value) parsed.value = '[REDACTED]';
      if (parsed.secret) parsed.secret = '[REDACTED]';
      sanitized = JSON.stringify(parsed);
    } catch (_) { /* not JSON, log as-is */ }
    auditStmt.run(endpoint, sourceIp || '', sanitized, result || '', error || '');
  } catch (_) { /* never let audit logging crash the server */ }
}

// ── HMAC Auth Middleware ──
function hmacAuth(req, res, next) {
  const sig = req.headers['x-vault-sig'];
  const ts = req.headers['x-vault-ts'];
  const nonce = req.headers['x-vault-nonce'];

  if (!sig || !ts || !nonce) {
    auditLog(req.path, req.ip, '', '', 'missing auth headers');
    return res.status(403).json({});
  }

  // Timestamp drift check — 30 seconds
  const now = Math.floor(Date.now() / 1000);
  const requestTs = parseInt(ts, 10);
  if (isNaN(requestTs) || Math.abs(now - requestTs) > 30) {
    auditLog(req.path, req.ip, '', '', 'timestamp drift');
    return res.status(403).json({});
  }

  // Nonce replay check — 60 seconds
  if (seenNonces.has(nonce)) {
    auditLog(req.path, req.ip, '', '', 'nonce replay');
    return res.status(403).json({});
  }
  seenNonces.set(nonce, Date.now());

  // HMAC-SHA256(timestamp + nonce + body, VAULT_SHARED_SECRET)
  const rawBody = JSON.stringify(req.body || {});
  const expected = crypto
    .createHmac('sha256', VAULT_SHARED_SECRET)
    .update(ts + nonce + rawBody)
    .digest('hex');

  // Timing-safe comparison
  const sigBuf = Buffer.from(sig);
  const expBuf = Buffer.from(expected);
  if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) {
    auditLog(req.path, req.ip, '', '', 'hmac mismatch');
    return res.status(403).json({});
  }

  next();
}

// ── Lockdown Middleware (applied to authenticated routes) ──
function lockdownCheck(req, res, next) {
  if (isLockedDown()) {
    auditLog(req.path, req.ip, '', '', 'rejected_lockdown');
    return res.status(503).json({ error: 'vault in lockdown mode' });
  }
  next();
}

// ── Encryption helpers (match identity.js / DemiPass pattern) ──

function decryptPrivateKey(encryptedBase64) {
  const key = Buffer.from(IDENTITY_MASTER_KEY, 'hex').slice(0, 32);
  const data = Buffer.from(encryptedBase64, 'base64');
  const iv = data.slice(0, 16);
  const authTag = data.slice(16, 32);
  const encrypted = data.slice(32);
  const decipher = crypto.createDecipheriv(ENCRYPTION_ALGO, key, iv);
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(encrypted), decipher.final()]);
}

function blindkeyDecrypt(encryptedBase64) {
  const key = Buffer.from(IDENTITY_MASTER_KEY, 'hex').slice(0, 32);
  const data = Buffer.from(encryptedBase64, 'base64');
  const iv = data.slice(0, 16);
  const authTag = data.slice(16, 32);
  const encrypted = data.slice(32);
  const decipher = crypto.createDecipheriv(ENCRYPTION_ALGO, key, iv);
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString('utf8');
}

// ── Billing helpers (inline, matching billing.js pattern) ──

function getDerivedBalance(did) {
  const result = db.prepare(
    'SELECT COALESCE(SUM(amount_cents), 0) as balance FROM identity_transactions WHERE did = ?'
  ).get(did);
  return result.balance;
}

function syncCachedBalance(did) {
  const derived = getDerivedBalance(did);
  db.prepare('UPDATE identity_wallets SET balance_cents = ?, updated_at = CURRENT_TIMESTAMP WHERE did = ?')
    .run(derived, did);
  return derived;
}

// ── SSH Host Whitelist ──
const BLINDKEY_SSH_HOSTS = new Set([
  '192.3.84.103',    // RackNerd
  '100.83.112.88',   // phasewhip
  '100.94.192.51',   // ky7
  '100.69.1.78',     // k1
  '100.103.90.79',   // flimflam
]);

// ── HTTP Host Whitelist ──
const BLINDKEY_HTTP_HOSTS = [
  'api.openai.com', 'openrouter.ai', 'api.anthropic.com',
  'generativelanguage.googleapis.com', 'api.github.com',
  'api.stripe.com', 'api.signalwire.com',
];

// ============================================================
// Endpoints
// ============================================================

// ── GET /vault/health — no auth ──
app.get('/vault/health', (_req, res) => {
  const identityCount = db.prepare('SELECT COUNT(*) as n FROM identity_wallets').get().n;
  const dbStat = fs.statSync(DB_PATH);
  res.json({
    status: 'ok',
    uptime: process.uptime(),
    db_size: dbStat.size,
    identity_count: identityCount,
    queue_depth: 0,
    lockdown: isLockedDown(),
  });
});

// ── POST /vault/decrypt ──
app.post('/vault/decrypt', hmacAuth, lockdownCheck, (req, res) => {
  const { key_id, purpose_tag } = req.body || {};
  if (!key_id) {
    auditLog('/vault/decrypt', req.ip, JSON.stringify(req.body), '', 'missing key_id');
    return res.status(400).json({ error: 'key_id required' });
  }

  // Record for anomaly detection
  recordDecryptRequest();

  // Check lockdown again after recording (may have just triggered)
  if (isLockedDown()) {
    auditLog('/vault/decrypt', req.ip, JSON.stringify(req.body), 'lockdown_triggered', '');
    return res.status(503).json({ error: 'vault in lockdown mode' });
  }

  try {
    const wallet = db.prepare('SELECT encrypted_private_key FROM identity_wallets WHERE did = ?').get(key_id);
    if (!wallet) {
      auditLog('/vault/decrypt', req.ip, JSON.stringify(req.body), '', 'did_not_found');
      return res.status(404).json({ error: 'identity not found' });
    }

    const decrypted = decryptPrivateKey(wallet.encrypted_private_key);
    const plaintext = decrypted.toString('base64');

    auditLog('/vault/decrypt', req.ip, JSON.stringify({ key_id, purpose_tag: purpose_tag || '' }), 'ok', '');
    res.json({ plaintext });
  } catch (e) {
    auditLog('/vault/decrypt', req.ip, JSON.stringify(req.body), '', e.message);
    return res.status(500).json({ error: 'decryption failed' });
  }
});

// ── POST /vault/ledger-write ──
app.post('/vault/ledger-write', hmacAuth, lockdownCheck, (req, res) => {
  const { actor_did, op_type, amount_cents, description, idempotency_key } = req.body || {};

  if (!actor_did || !op_type || amount_cents === undefined || amount_cents === null) {
    auditLog('/vault/ledger-write', req.ip, JSON.stringify(req.body), '', 'missing fields');
    return res.status(400).json({ error: 'actor_did, op_type, and amount_cents required' });
  }

  if (typeof amount_cents !== 'number' || !Number.isInteger(amount_cents)) {
    return res.status(400).json({ error: 'amount_cents must be an integer' });
  }

  const wallet = db.prepare('SELECT id, status FROM identity_wallets WHERE did = ?').get(actor_did);
  if (!wallet) {
    auditLog('/vault/ledger-write', req.ip, JSON.stringify(req.body), '', 'did_not_found');
    return res.status(404).json({ error: 'identity not found' });
  }

  try {
    const txn = db.transaction(() => {
      // Acquire exclusive lock on wallet row
      db.prepare('UPDATE identity_wallets SET updated_at = updated_at WHERE id = ?').run(wallet.id);

      // Idempotency check
      if (idempotency_key) {
        const existing = db.prepare(
          'SELECT id, balance_after FROM identity_transactions WHERE idempotency_key = ?'
        ).get(idempotency_key);
        if (existing) {
          return { tx_id: existing.id, balance_after: existing.balance_after, idempotent: true };
        }
      }

      const currentBalance = getDerivedBalance(actor_did);
      const newBalance = currentBalance + amount_cents;

      const result = db.prepare(
        'INSERT INTO identity_transactions (did, amount_cents, type, description, balance_after, idempotency_key) VALUES (?, ?, ?, ?, ?, ?)'
      ).run(actor_did, amount_cents, op_type, description || '', newBalance, idempotency_key || null);

      // Sync cached balance
      db.prepare('UPDATE identity_wallets SET balance_cents = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?')
        .run(newBalance, wallet.id);

      return { tx_id: result.lastInsertRowid, balance_after: newBalance };
    });

    const result = txn();
    auditLog('/vault/ledger-write', req.ip, JSON.stringify({ actor_did, op_type, amount_cents, idempotency_key }), JSON.stringify(result), '');
    res.json(result);
  } catch (e) {
    auditLog('/vault/ledger-write', req.ip, JSON.stringify(req.body), '', e.message);
    return res.status(500).json({ error: 'ledger write failed' });
  }
});

// ── POST /vault/blindkey-use (legacy) / /vault/demipass-use (public) ──
app.post('/vault/blindkey-use', hmacAuth, lockdownCheck, async (req, res) => {
  const { did, secret_name, context, action, action_params } = req.body || {};

  if (!did || !secret_name || !action) {
    auditLog('/vault/blindkey-use', req.ip, JSON.stringify(req.body), '', 'missing fields');
    return res.status(400).json({ error: 'did, secret_name, and action required' });
  }

  // Look up the secret
  const secret = db.prepare('SELECT * FROM blindkey_secrets WHERE did = ? AND name = ? AND status = ?').get(did, secret_name, 'active');
  if (!secret) {
    auditLog('/vault/blindkey-use', req.ip, JSON.stringify({ did, secret_name, action }), '', 'secret_not_found');
    return res.status(404).json({ error: 'secret not found' });
  }

  // Context validation
  if (context) {
    const ctx = db.prepare(
      'SELECT * FROM blindkey_contexts WHERE secret_id = ? AND context_name = ? AND status = ?'
    ).get(secret.id, context, 'active');
    if (!ctx) {
      auditLog('/vault/blindkey-use', req.ip, JSON.stringify({ did, secret_name, context, action }), '', 'context_not_found');
      return res.status(403).json({ error: 'context not found or not active' });
    }
    if (ctx.action_type !== action) {
      auditLog('/vault/blindkey-use', req.ip, JSON.stringify({ did, secret_name, context, action }), '', 'action_mismatch');
      return res.status(403).json({ error: `context requires action '${ctx.action_type}', got '${action}'` });
    }
    if (ctx.max_uses > 0 && ctx.use_count >= ctx.max_uses) {
      return res.status(403).json({ error: 'context max uses exceeded' });
    }
    // Increment context use count
    db.prepare('UPDATE blindkey_contexts SET use_count = use_count + 1 WHERE id = ?').run(ctx.id);
  }

  // Decrypt the secret value
  let decryptedValue;
  try {
    decryptedValue = blindkeyDecrypt(secret.encrypted_value);
  } catch (e) {
    auditLog('/vault/blindkey-use', req.ip, JSON.stringify({ did, secret_name, action }), '', 'decrypt_failed');
    return res.status(500).json({ error: 'failed to decrypt secret' });
  }

  // Update usage stats
  db.prepare('UPDATE blindkey_secrets SET use_count = use_count + 1, last_used_at = CURRENT_TIMESTAMP WHERE id = ?').run(secret.id);

  try {
    let result;
    const params = action_params || {};

    switch (action) {
      case 'http_header': {
        const { url, method = 'GET', header_name = 'Authorization', header_prefix = 'Bearer ', body: reqBody } = params;
        if (!url) {
          return res.status(400).json({ error: 'action_params.url required for http_header' });
        }

        // Host whitelist check
        let urlHost;
        try { urlHost = new URL(url).hostname; } catch (_) {
          return res.status(400).json({ error: 'invalid URL' });
        }
        if (!BLINDKEY_HTTP_HOSTS.some(h => urlHost === h || urlHost.endsWith('.' + h))) {
          return res.status(403).json({ error: `host ${urlHost} not in whitelist` });
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
        const escaped = decryptedValue.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        const secretRedacted = typeof parsed === 'string'
          ? parsed.replace(new RegExp(escaped, 'g'), '[REDACTED]')
          : JSON.parse(JSON.stringify(parsed).replace(new RegExp(escaped, 'g'), '[REDACTED]'));

        result = { status: response.status, body: secretRedacted };
        break;
      }

      case 'ssh_exec': {
        const { target_host, target_user, command, key_name } = params;
        if (!target_host || !target_user || !command) {
          return res.status(400).json({ error: 'target_host, target_user, and command required for ssh_exec' });
        }

        // Host whitelist check
        if (!BLINDKEY_SSH_HOSTS.has(target_host)) {
          return res.status(403).json({ error: `host ${target_host} not in SSH whitelist` });
        }

        // Command sanitization
        const dangerousPatterns = [
          /`/,
          /\$\(/,
          /\|\s*(curl|wget|nc|ncat)/i,
          />\s*\/dev\/tcp/,
          /\beval\b/,
          /\bexec\b/,
          /\bsource\b/,
          /\b(curl|wget)\b.*\|/i,
        ];
        for (const pat of dangerousPatterns) {
          if (pat.test(command)) {
            return res.status(400).json({ error: 'command contains disallowed pattern' });
          }
        }

        if (!/^[a-zA-Z0-9\s\/_\-.:=,@+*?[\]{}()#<>|&;'"%!\\\n]+$/.test(command)) {
          return res.status(400).json({ error: 'command contains disallowed characters' });
        }

        if (!/^[a-zA-Z0-9._-]+$/.test(target_user)) {
          return res.status(400).json({ error: 'invalid target_user' });
        }

        // Optionally load a second secret as the password
        let password = decryptedValue;
        if (key_name) {
          const keySecret = db.prepare('SELECT * FROM blindkey_secrets WHERE did = ? AND name = ? AND status = ?').get(did, key_name, 'active');
          if (!keySecret) return res.status(404).json({ error: `key_name secret '${key_name}' not found` });
          try {
            password = blindkeyDecrypt(keySecret.encrypted_value);
            db.prepare('UPDATE blindkey_secrets SET use_count = use_count + 1, last_used_at = CURRENT_TIMESTAMP WHERE id = ?').run(keySecret.id);
          } catch (_) {
            return res.status(500).json({ error: 'failed to decrypt key_name secret' });
          }
        }

        try {
          const escapedPassword = password.replace(/'/g, "'\"'\"'");
          const escapedCommand = command.replace(/'/g, "'\"'\"'");
          const sshCmd = `sshpass -p '${escapedPassword}' ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 ${target_user}@${target_host} '${escapedCommand}'`;
          const output = execSync(sshCmd, { timeout: 30000, encoding: 'utf8', maxBuffer: 1024 * 1024 });

          // Redact credentials from output
          const escapedPw = password.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
          const escapedVal = decryptedValue.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
          const redactedOutput = output
            .replace(new RegExp(escapedPw, 'g'), '[REDACTED]')
            .replace(new RegExp(escapedVal, 'g'), '[REDACTED]');

          result = { stdout: redactedOutput, exit_code: 0 };
        } catch (sshErr) {
          const stderr = (sshErr.stderr || '').toString();
          const stdout = (sshErr.stdout || '').toString();
          const escapedPw = password.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
          const escapedVal = decryptedValue.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
          const redact = (s) => s
            .replace(new RegExp(escapedPw, 'g'), '[REDACTED]')
            .replace(new RegExp(escapedVal, 'g'), '[REDACTED]');
          result = { stdout: redact(stdout), stderr: redact(stderr), exit_code: sshErr.status || 1 };
        }
        break;
      }

      default:
        auditLog('/vault/blindkey-use', req.ip, JSON.stringify({ did, secret_name, action }), '', 'unknown_action');
        return res.status(400).json({ error: `unknown action: ${action}. Supported: http_header, ssh_exec` });
    }

    auditLog('/vault/blindkey-use', req.ip, JSON.stringify({ did, secret_name, context, action }), 'ok', '');
    // Secret value NEVER returned — only the action result
    res.json({ ok: true, action, secret_name, result });
  } catch (e) {
    auditLog('/vault/blindkey-use', req.ip, JSON.stringify({ did, secret_name, action }), '', e.message);
    return res.status(500).json({ error: `action failed: ${e.message}` });
  }
});

// ── Start ──
app.listen(PORT, '0.0.0.0', () => {
  console.log(`[vault] listening on 0.0.0.0:${PORT}`);
  console.log(`[vault] DB: ${DB_PATH}`);
  console.log(`[vault] Endpoints: /vault/health, /vault/decrypt, /vault/ledger-write, /vault/blindkey-use, /vault/demipass-use`);
});
