/**
 * Dustforge API Wrapper — programmatic email account management via Stalwart
 *
 * Wraps Stalwart's REST API for account CRUD, email sending, and quota management.
 * SECURITY: Admin credentials from env, never hardcoded.
 */

const http = require('http');

const STALWART_HOST = process.env.STALWART_HOST || '10.225.75.76';
const STALWART_PORT = Number(process.env.STALWART_PORT || 8080);
const STALWART_USER = process.env.STALWART_USER || 'admin';
const STALWART_PASS = process.env.STALWART_PASS || '';

function stalwartRequest(method, path, body = null) {
  return new Promise((resolve, reject) => {
    const auth = Buffer.from(`${STALWART_USER}:${STALWART_PASS}`).toString('base64');
    const opts = {
      hostname: STALWART_HOST,
      port: STALWART_PORT,
      path,
      method,
      headers: {
        'Authorization': `Basic ${auth}`,
        'Content-Type': 'application/json',
      },
    };
    const req = http.request(opts, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch (_) { resolve({ raw: data }); }
      });
    });
    req.on('error', reject);
    req.setTimeout(10000, () => { req.destroy(); reject(new Error('stalwart timeout')); });
    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

// ── Account Management ──

async function createAccount(username, password, options = {}) {
  const {
    quota = 1073741824, // 1GB default
    displayName = username,
  } = options;
  const email = `${username}@dustforge.com`;

  const result = await stalwartRequest('POST', '/api/principal', {
    type: 'individual',
    name: username,
    emails: [email],
    secrets: [password],
    quota,
    roles: ['user'],
    description: displayName,
  });

  if (result.data) {
    return { ok: true, stalwart_id: result.data, email, username };
  }
  return { ok: false, error: result.detail || result.title || 'account creation failed' };
}

async function deleteAccount(username) {
  const result = await stalwartRequest('DELETE', `/api/principal/${encodeURIComponent(username)}`);
  return { ok: true, result };
}

async function getAccount(username) {
  const result = await stalwartRequest('GET', `/api/principal/${encodeURIComponent(username)}`);
  if (result.data) {
    return { ok: true, account: result.data };
  }
  return { ok: false, error: result.detail || 'not found' };
}

async function listAccounts(limit = 50) {
  const result = await stalwartRequest('GET', `/api/principal?limit=${limit}`);
  if (result.data) {
    return {
      ok: true,
      accounts: result.data.items.filter(a => a.type === 'individual'),
      total: result.data.total,
    };
  }
  return { ok: false, error: result.detail || 'list failed' };
}

async function changePassword(username, newPassword) {
  const result = await stalwartRequest('PATCH', `/api/principal/${encodeURIComponent(username)}`, {
    secrets: [newPassword],
  });
  return { ok: !result.status || result.status < 400 };
}

// ── 2FA Code Generation ──

function generate2FACode() {
  const crypto = require('crypto');
  return crypto.randomInt(100000, 999999).toString();
}

module.exports = {
  createAccount,
  deleteAccount,
  getAccount,
  listAccounts,
  changePassword,
  generate2FACode,
  stalwartRequest,
};
