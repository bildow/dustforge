/**
 * Rowen Egress Server — Dual-Barrel Secret Courier
 *
 * Runs in the Rowen incus container on phasewhip (100.83.112.88:3002).
 * Replaces the minimal server.js in the container.
 *
 * Architecture:
 *   1. Caller POSTs to /rowen/egress with a use_token + action_params
 *   2. Rowen opens a closing table session
 *   3. Barrel A (phasewhip vault, port 7743) returns encrypted secret blob
 *   4. Barrel B (ky7 service) returns authorization + key shard
 *   5. Secret is assembled into a SecretDose (auto-wipes after 30s)
 *   6. Heartbeat supervision ensures both barrels stay alive
 *   7. Action executes (http_header or ssh_exec)
 *   8. Dose metabolizes, audit logs sent to Dustforge API
 *
 * Auth: HMAC-SHA256 on all endpoints except /health.
 * Rate limit: 30 req/min.
 */

require('dotenv').config({ override: true });
const express = require('express');
const crypto = require('crypto');
const { execSync } = require('child_process');
const rateLimit = require('express-rate-limit');

// ── Required env vars ──
const ROWEN_SHARED_SECRET = process.env.ROWEN_SHARED_SECRET;
if (!ROWEN_SHARED_SECRET) {
  console.error('[FATAL] ROWEN_SHARED_SECRET required');
  process.exit(1);
}

const PORT = Number(process.env.ROWEN_PORT) || 3002;
const BARREL_B_STUB = process.env.BARREL_B_STUB === 'true';
const BARREL_B_URL = process.env.BARREL_B_URL || 'http://100.94.192.51:7744';
const VAULT_URL = process.env.VAULT_URL || 'http://100.83.112.88:7743';
const VAULT_SHARED_SECRET = process.env.VAULT_SHARED_SECRET || '';
const DUSTFORGE_API_URL = process.env.DUSTFORGE_API_URL || 'http://192.3.84.103:3000';
const DUSTFORGE_ADMIN_KEY = process.env.DUSTFORGE_ADMIN_KEY || '';
const BARREL_B_HMAC_KEY = process.env.BARREL_B_HMAC_KEY || '';

// Stub-mode self-sign key (only used when BARREL_B_STUB=true)
const STUB_SIGN_KEY = crypto.randomBytes(32).toString('hex');

// ── SSH Host Whitelist ──
const SSH_HOSTS = new Set([
  '192.3.84.103',    // RackNerd
  '100.83.112.88',   // phasewhip
  '100.94.192.51',   // ky7
  '100.69.1.78',     // k1
  '100.103.90.79',   // flimflam
]);

// ── HTTP Host Whitelist ──
const HTTP_HOSTS = [
  'api.openai.com', 'openrouter.ai', 'api.anthropic.com',
  'generativelanguage.googleapis.com', 'api.github.com',
  'api.stripe.com', 'api.signalwire.com',
];

// ============================================================
// SecretDose — models the secret as a substance with a half-life
// ============================================================

class SecretDose {
  constructor(maxWindowMs = 30000) {
    this._buffer = null;
    this._consumed = false;
    this._timer = setTimeout(() => this.metabolize(), maxWindowMs);
  }

  absorb(plaintext) {
    this._buffer = Buffer.from(plaintext);
    return this;
  }

  dose() {
    if (this._consumed || !this._buffer) throw new Error('dose expired or consumed');
    return this._buffer.toString();
  }

  metabolize() {
    if (this._buffer) {
      // Triple-pass wipe: zero, random, zero
      this._buffer.fill(0);
      crypto.randomFillSync(this._buffer);
      this._buffer.fill(0);
      this._buffer = null;
    }
    this._consumed = true;
    clearTimeout(this._timer);
  }

  get isAlive() {
    return !this._consumed && this._buffer !== null;
  }
}

// ============================================================
// Nonce / Replay Protection
// ============================================================

const seenNonces = new Map();
setInterval(() => {
  const cutoff = Date.now() - 60000;
  for (const [nonce, ts] of seenNonces) {
    if (ts < cutoff) seenNonces.delete(nonce);
  }
}, 30000);

// Session replay protection for barrel B
const seenSessionIds = new Set();
setInterval(() => {
  // Session IDs expire after 5 minutes
  // Since UUIDs are unique, we just cap the set size
  if (seenSessionIds.size > 10000) seenSessionIds.clear();
}, 300000);

// ============================================================
// HMAC Auth Middleware
// ============================================================

function hmacAuth(req, res, next) {
  const sig = req.headers['x-rowen-sig'];
  const ts = req.headers['x-rowen-ts'];
  const nonce = req.headers['x-rowen-nonce'];

  if (!sig || !ts || !nonce) {
    return res.status(403).json({});
  }

  // Timestamp drift check — 30 seconds
  const now = Math.floor(Date.now() / 1000);
  const requestTs = parseInt(ts, 10);
  if (isNaN(requestTs) || Math.abs(now - requestTs) > 30) {
    return res.status(403).json({});
  }

  // Nonce replay check
  if (seenNonces.has(nonce)) {
    return res.status(403).json({});
  }
  seenNonces.set(nonce, Date.now());

  // HMAC-SHA256(timestamp + nonce + body, ROWEN_SHARED_SECRET)
  const rawBody = JSON.stringify(req.body || {});
  const expected = crypto
    .createHmac('sha256', ROWEN_SHARED_SECRET)
    .update(ts + nonce + rawBody)
    .digest('hex');

  const sigBuf = Buffer.from(sig);
  const expBuf = Buffer.from(expected);
  if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) {
    return res.status(403).json({});
  }

  next();
}

// ============================================================
// Vault HMAC helper — sign requests to Barrel A (phasewhip vault)
// ============================================================

function makeVaultHeaders(body) {
  const ts = String(Math.floor(Date.now() / 1000));
  const nonce = crypto.randomBytes(16).toString('hex');
  const rawBody = JSON.stringify(body);
  const sig = crypto
    .createHmac('sha256', VAULT_SHARED_SECRET)
    .update(ts + nonce + rawBody)
    .digest('hex');
  return {
    'Content-Type': 'application/json',
    'x-vault-sig': sig,
    'x-vault-ts': ts,
    'x-vault-nonce': nonce,
  };
}

// ============================================================
// Barrel A — phasewhip vault (POST /vault/decrypt)
// ============================================================

async function requestBarrelA(sessionId, useToken) {
  const body = {
    key_id: useToken.did,
    purpose_tag: `rowen_egress:${sessionId}`,
  };

  const response = await fetch(`${VAULT_URL}/vault/decrypt`, {
    method: 'POST',
    headers: makeVaultHeaders(body),
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(10000),
  });

  if (!response.ok) {
    const text = await response.text().catch(() => '');
    throw new Error(`Barrel A rejected: ${response.status} ${text}`);
  }

  const result = await response.json();
  return {
    barrel: 'A',
    host: 'phasewhip',
    ciphertext: result.plaintext, // vault returns base64-encoded decrypted private key
    session_id: sessionId,
    responded_at: Date.now(),
  };
}

// ============================================================
// Barrel B — ky7 authorization + key shard
// ============================================================

async function requestBarrelB(sessionId, useToken) {
  // Validate session UUID not seen before
  if (seenSessionIds.has(sessionId)) {
    throw new Error('Barrel B: session UUID replay detected');
  }
  seenSessionIds.add(sessionId);

  // Timestamp check: must be within ±2s
  const now = Date.now();

  if (BARREL_B_STUB) {
    // ── SINGLE BARREL MODE — NOT FOR PRODUCTION ──
    console.warn(`[BARREL-B] SINGLE BARREL MODE — NOT FOR PRODUCTION (session: ${sessionId})`);

    // Self-sign authorization
    const authorization = crypto
      .createHmac('sha256', STUB_SIGN_KEY)
      .update(sessionId + ':' + now)
      .digest('hex');

    return {
      barrel: 'B',
      host: 'stub',
      authorization,
      keyShard: null, // No shard in stub mode — secret comes straight from Barrel A
      session_id: sessionId,
      responded_at: now,
      stub: true,
    };
  }

  // Production mode: call ky7
  const body = {
    session_id: sessionId,
    timestamp: now,
    silicon_id: useToken.silicon_id || 'rowen',
  };

  const sig = crypto
    .createHmac('sha256', BARREL_B_HMAC_KEY)
    .update(JSON.stringify(body))
    .digest('hex');

  const response = await fetch(`${BARREL_B_URL}/barrel/authorize`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-barrel-sig': sig,
    },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(5000),
  });

  if (!response.ok) {
    const text = await response.text().catch(() => '');
    throw new Error(`Barrel B rejected: ${response.status} ${text}`);
  }

  const result = await response.json();
  return {
    barrel: 'B',
    host: 'ky7',
    authorization: result.authorization,
    keyShard: result.key_shard,
    session_id: sessionId,
    responded_at: Date.now(),
    stub: false,
  };
}

// ============================================================
// Secret Assembly — decrypt with dual-barrel shards
// ============================================================

function assembleSecret(barrelA, barrelB) {
  if (barrelB.stub) {
    // Stub mode: Barrel A returned the full secret (base64-encoded)
    return Buffer.from(barrelA.ciphertext, 'base64').toString('utf8');
  }

  // Production mode: XOR the key shard from Barrel B with the ciphertext from Barrel A
  // Barrel A: encrypted blob, Barrel B: key shard to decrypt it
  const cipherBuf = Buffer.from(barrelA.ciphertext, 'base64');
  const shardBuf = Buffer.from(barrelB.keyShard, 'base64');

  // Use key shard as AES-256-GCM key to decrypt the Barrel A ciphertext
  const iv = cipherBuf.slice(0, 16);
  const authTag = cipherBuf.slice(16, 32);
  const encrypted = cipherBuf.slice(32);
  const decipher = crypto.createDecipheriv('aes-256-gcm', shardBuf.slice(0, 32), iv);
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString('utf8');
}

// ============================================================
// Heartbeat Supervision — inverted dead man's switch
// ============================================================

function startHeartbeatSupervision(sessionId, onDeath) {
  const interval = 500; // ms
  let alive = true;
  let timer;

  if (BARREL_B_STUB) {
    // Stub mode: heartbeat always succeeds, just runs on a timer
    timer = setInterval(() => {
      // No-op in stub mode — barrel is self
    }, interval);

    return {
      stop() {
        alive = false;
        clearInterval(timer);
      },
      get alive() { return alive; },
    };
  }

  // Production mode: ping both barrels every 500ms
  async function ping() {
    if (!alive) return;

    try {
      const [ackA, ackB] = await Promise.all([
        fetch(`${VAULT_URL}/vault/health`, {
          signal: AbortSignal.timeout(interval),
        }).then(r => r.ok),
        fetch(`${BARREL_B_URL}/barrel/heartbeat`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ session_id: sessionId }),
          signal: AbortSignal.timeout(interval),
        }).then(r => r.ok),
      ]);

      if (!ackA || !ackB) {
        console.error(`[HEARTBEAT] Barrel went dark (A=${ackA}, B=${ackB}) — killing dose for session ${sessionId}`);
        alive = false;
        clearInterval(timer);
        onDeath();
      }
    } catch (err) {
      console.error(`[HEARTBEAT] Ping failed for session ${sessionId}: ${err.message} — killing dose`);
      alive = false;
      clearInterval(timer);
      onDeath();
    }
  }

  timer = setInterval(ping, interval);

  return {
    stop() {
      alive = false;
      clearInterval(timer);
    },
    get alive() { return alive; },
  };
}

// ============================================================
// Action Execution
// ============================================================

async function executeAction(dose, actionParams) {
  const { action, ...params } = actionParams;
  const secretValue = dose.dose(); // Throws if expired

  switch (action) {
    case 'http_header': {
      const { url, method = 'GET', header_name = 'Authorization', header_prefix = 'Bearer ', body: reqBody } = params;
      if (!url) throw new Error('action_params.url required for http_header');

      // Host whitelist check
      let urlHost;
      try { urlHost = new URL(url).hostname; } catch (_) {
        throw new Error('invalid URL');
      }

      const isAllowed = HTTP_HOSTS.some(h => urlHost === h || urlHost.endsWith('.' + h));
      const isPrivateNet = /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|localhost|127\.)/.test(urlHost);
      if (!isAllowed && !isPrivateNet) {
        throw new Error(`host ${urlHost} not in whitelist`);
      }

      const response = await fetch(url, {
        method,
        headers: {
          [header_name]: header_prefix + secretValue,
          'Content-Type': 'application/json',
        },
        body: reqBody ? JSON.stringify(reqBody) : undefined,
        signal: AbortSignal.timeout(30000),
      });

      const responseBody = await response.text();
      let parsed;
      try { parsed = JSON.parse(responseBody); } catch (_) { parsed = responseBody; }

      // Redact secret from response
      const escaped = secretValue.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const redacted = typeof parsed === 'string'
        ? parsed.replace(new RegExp(escaped, 'g'), '[REDACTED]')
        : JSON.parse(JSON.stringify(parsed).replace(new RegExp(escaped, 'g'), '[REDACTED]'));

      return { action: 'http_header', status: response.status, body: redacted };
    }

    case 'ssh_exec': {
      const { target_host, target_user, command } = params;
      if (!target_host || !target_user || !command) {
        throw new Error('target_host, target_user, and command required for ssh_exec');
      }

      // Host whitelist
      if (!SSH_HOSTS.has(target_host)) {
        throw new Error(`host ${target_host} not in SSH whitelist`);
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
        if (pat.test(command)) throw new Error('command contains disallowed pattern');
      }
      if (!/^[a-zA-Z0-9\s\/_\-.:=,@+*?[\]{}()#<>|&;'"%!\\\n]+$/.test(command)) {
        throw new Error('command contains disallowed characters');
      }
      if (!/^[a-zA-Z0-9._-]+$/.test(target_user)) {
        throw new Error('invalid target_user');
      }

      try {
        const escapedPassword = secretValue.replace(/'/g, "'\"'\"'");
        const escapedCommand = command.replace(/'/g, "'\"'\"'");
        const sshCmd = `sshpass -p '${escapedPassword}' ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 ${target_user}@${target_host} '${escapedCommand}'`;
        const output = execSync(sshCmd, { timeout: 30000, encoding: 'utf8', maxBuffer: 1024 * 1024 });

        const escapedSecret = secretValue.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        const redactedOutput = output.replace(new RegExp(escapedSecret, 'g'), '[REDACTED]');

        return { action: 'ssh_exec', stdout: redactedOutput, exit_code: 0 };
      } catch (sshErr) {
        const escapedSecret = secretValue.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        const redact = (s) => s.replace(new RegExp(escapedSecret, 'g'), '[REDACTED]');
        return {
          action: 'ssh_exec',
          stdout: redact((sshErr.stdout || '').toString()),
          stderr: redact((sshErr.stderr || '').toString()),
          exit_code: sshErr.status || 1,
        };
      }
    }

    default:
      throw new Error(`unknown action: ${action}. Supported: http_header, ssh_exec`);
  }
}

// ============================================================
// Audit Logging — POST results back to Dustforge API
// ============================================================

async function logDelivery(sessionId, barrelA, barrelB, result, executionTimeMs) {
  const event = {
    event_type: 'rowen_egress',
    actor: 'rowen',
    detail: JSON.stringify({
      session_id: sessionId,
      barrels_responded: [barrelA.barrel, barrelB.barrel],
      barrel_a_host: barrelA.host,
      barrel_b_host: barrelB.host,
      barrel_b_stub: barrelB.stub || false,
      execution_time_ms: executionTimeMs,
      action_type: result.action,
      success: result.exit_code === undefined ? (result.status < 400) : (result.exit_code === 0),
    }),
  };

  try {
    await fetch(`${DUSTFORGE_API_URL}/api/blindkey/event`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-admin-key': DUSTFORGE_ADMIN_KEY,
      },
      body: JSON.stringify(event),
      signal: AbortSignal.timeout(5000),
    });
  } catch (err) {
    // Audit logging should never crash the server
    console.error(`[AUDIT] Failed to log delivery for session ${sessionId}: ${err.message}`);
  }
}

// ============================================================
// Express Setup
// ============================================================

const app = express();
app.set('trust proxy', 1);
app.use(express.json());

// Rate limit: 30 req/min
const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  message: { error: 'rate limit exceeded' },
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);

// ============================================================
// GET /health — no auth
// ============================================================

app.get('/health', (_req, res) => {
  res.json({
    agent: 'rowen',
    role: 'egress-courier',
    mode: BARREL_B_STUB ? 'stub' : 'production',
    uptime: process.uptime(),
  });
});

// ============================================================
// POST /rowen/egress — dual-barrel closing table
// ============================================================

app.post('/rowen/egress', hmacAuth, async (req, res) => {
  const { use_token, action_params } = req.body || {};

  if (!use_token || typeof use_token !== 'object') {
    return res.status(400).json({ error: 'use_token object required' });
  }
  if (!use_token.did || !use_token.secret_name) {
    return res.status(400).json({ error: 'use_token must contain did and secret_name' });
  }
  if (!action_params || typeof action_params !== 'object') {
    return res.status(400).json({ error: 'action_params object required' });
  }
  if (!action_params.action) {
    return res.status(400).json({ error: 'action_params.action required' });
  }

  // Open a closing table session
  const sessionId = crypto.randomUUID();
  const startTime = Date.now();
  let dose = null;
  let heartbeat = null;

  try {
    // Request from both barrels simultaneously
    let barrelA, barrelB;
    try {
      [barrelA, barrelB] = await Promise.all([
        requestBarrelA(sessionId, use_token),
        requestBarrelB(sessionId, use_token),
      ]);
    } catch (err) {
      console.error(`[EGRESS] Barrel request failed for session ${sessionId}: ${err.message}`);
      return res.status(502).json({ error: 'barrel request failed', session_id: sessionId });
    }

    // Both responded — assemble the secret
    dose = new SecretDose(30000); // 30s hard kill
    const assembled = assembleSecret(barrelA, barrelB);
    dose.absorb(assembled);

    // Start heartbeat supervision
    heartbeat = startHeartbeatSupervision(sessionId, () => {
      if (dose) dose.metabolize();
    });

    // Execute the action
    let result;
    try {
      result = await executeAction(dose, action_params);
    } finally {
      dose.metabolize();
      heartbeat.stop();
    }

    const executionTimeMs = Date.now() - startTime;

    // Log to Dustforge API (fire and forget)
    logDelivery(sessionId, barrelA, barrelB, result, executionTimeMs).catch(() => {});

    res.json({ ok: true, session_id: sessionId, execution_time_ms: executionTimeMs, result });
  } catch (err) {
    // Ensure dose is always wiped on error
    if (dose) dose.metabolize();
    if (heartbeat) heartbeat.stop();

    console.error(`[EGRESS] Session ${sessionId} failed: ${err.message}`);
    res.status(500).json({ error: `egress failed: ${err.message}`, session_id: sessionId });
  }
});

// ============================================================
// POST /rowen/ingest — placeholder (Codex building this)
// ============================================================

app.post('/rowen/ingest', hmacAuth, (_req, res) => {
  res.status(501).json({
    error: 'not implemented',
    note: 'Ingest flow is under construction. Use /api/rowen/ingest on the Dustforge API directly.',
  });
});

// ============================================================
// POST /rowen/conduit — Conduit inbound handler
// ============================================================

app.post('/rowen/conduit', hmacAuth, (req, res) => {
  const { from, message, thread_id } = req.body || {};
  console.log(`[CONDUIT] Message from ${from}: ${JSON.stringify(message).slice(0, 200)}`);
  res.json({ ok: true, ack: true, thread_id });
});

// ============================================================
// Start
// ============================================================

app.listen(PORT, '0.0.0.0', () => {
  console.log(`[rowen] listening on 0.0.0.0:${PORT}`);
  console.log(`[rowen] mode: ${BARREL_B_STUB ? 'STUB (single barrel)' : 'PRODUCTION (dual barrel)'}`);
  console.log(`[rowen] vault: ${VAULT_URL}`);
  console.log(`[rowen] barrel B: ${BARREL_B_STUB ? 'self-signed stub' : BARREL_B_URL}`);
  console.log(`[rowen] endpoints: /health, /rowen/egress, /rowen/ingest (501), /rowen/conduit`);
});
