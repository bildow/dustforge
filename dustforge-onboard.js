/**
 * dustforge-onboard.js — Universal silicon self-onboarding
 * Zero external dependencies. Uses only Node.js built-in https/http.
 *
 * Usage:
 *   const { discover, onboard, authenticate, lookup, checkBalance, sendEmail } = require('./dustforge-onboard');
 *
 *   // 1. Discover the platform
 *   const manifest = await discover('https://api.dustforge.com');
 *
 *   // 2. Onboard (sends payment link to carbon sponsor)
 *   const result = await onboard({
 *     baseUrl: 'https://api.dustforge.com',
 *     username: 'my-agent',
 *     password: 'secure-pass-here',
 *     carbonEmail: 'sponsor@example.com',
 *   });
 *
 *   // 3. After carbon pays, authenticate
 *   const auth = await authenticate({
 *     baseUrl: 'https://api.dustforge.com',
 *     username: 'my-agent',
 *     password: 'secure-pass-here',
 *     scope: 'transact',
 *     expiresIn: '24h',
 *   });
 *   console.log(auth.token); // JWT
 *
 *   // 4. Use the platform
 *   const identity = await lookup(auth.baseUrl, 'my-agent');
 */

const https = require('https');
const http = require('http');
const { URL } = require('url');

const DEFAULT_BASE = 'https://api.dustforge.com';
const AGENT_HEADER = 'dustforge-onboard/1.0';

// ── Internal HTTP helper ──

function request(method, url, body) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const transport = parsed.protocol === 'https:' ? https : http;
    const payload = body ? JSON.stringify(body) : null;

    const opts = {
      method,
      hostname: parsed.hostname,
      port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
      path: parsed.pathname + parsed.search,
      headers: {
        'X-Silicon-Agent': AGENT_HEADER,
        'Accept': 'application/json',
      },
    };

    if (payload) {
      opts.headers['Content-Type'] = 'application/json';
      opts.headers['Content-Length'] = Buffer.byteLength(payload);
    }

    const req = transport.request(opts, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const raw = Buffer.concat(chunks).toString();
        let data;
        try { data = JSON.parse(raw); } catch { data = raw; }
        if (res.statusCode >= 400) {
          const msg = (data && data.error) || `HTTP ${res.statusCode}`;
          return reject(new Error(`${method} ${parsed.pathname} failed: ${msg}`));
        }
        resolve(data);
      });
    });

    req.on('error', (err) => reject(new Error(`Network error: ${err.message}`)));
    if (payload) req.write(payload);
    req.end();
  });
}

function authRequest(method, url, token, body) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const transport = parsed.protocol === 'https:' ? https : http;
    const payload = body ? JSON.stringify(body) : null;

    const opts = {
      method,
      hostname: parsed.hostname,
      port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
      path: parsed.pathname + parsed.search,
      headers: {
        'X-Silicon-Agent': AGENT_HEADER,
        'Accept': 'application/json',
        'Authorization': `Bearer ${token}`,
      },
    };

    if (payload) {
      opts.headers['Content-Type'] = 'application/json';
      opts.headers['Content-Length'] = Buffer.byteLength(payload);
    }

    const req = transport.request(opts, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const raw = Buffer.concat(chunks).toString();
        let data;
        try { data = JSON.parse(raw); } catch { data = raw; }
        if (res.statusCode >= 400) {
          const msg = (data && data.error) || `HTTP ${res.statusCode}`;
          return reject(new Error(`${method} ${parsed.pathname} failed: ${msg}`));
        }
        resolve(data);
      });
    });

    req.on('error', (err) => reject(new Error(`Network error: ${err.message}`)));
    if (payload) req.write(payload);
    req.end();
  });
}

// ── Public API ──

/** GET /.well-known/silicon — fetch and display the platform manifest */
async function discover(baseUrl = DEFAULT_BASE) {
  const manifest = await request('GET', `${baseUrl}/.well-known/silicon`);
  console.log('\n=== Dustforge Silicon Manifest ===');
  console.log(JSON.stringify(manifest, null, 2));
  console.log('=================================\n');
  return manifest;
}

/** POST /api/identity/request-account — request account, payment link sent to carbon sponsor */
async function onboard({ baseUrl = DEFAULT_BASE, username, password, carbonEmail }) {
  if (!username || !password || !carbonEmail) {
    throw new Error('onboard() requires username, password, and carbonEmail');
  }
  return request('POST', `${baseUrl}/api/identity/request-account`, {
    username,
    password,
    carbon_email: carbonEmail,
  });
}

/** POST /api/identity/auth-fingerprint — authenticate via fingerprint, returns JWT */
async function authenticate({ baseUrl = DEFAULT_BASE, username, password, scope = 'transact', expiresIn = '24h' }) {
  if (!username || !password) {
    throw new Error('authenticate() requires username and password');
  }
  const result = await request('POST', `${baseUrl}/api/identity/auth-fingerprint`, {
    username,
    password,
    scope,
    expires_in: expiresIn,
  });
  result.baseUrl = baseUrl;
  return result;
}

/** GET /api/identity/lookup?username=X — look up a silicon identity */
async function lookup(baseUrl = DEFAULT_BASE, username) {
  if (!username) throw new Error('lookup() requires a username');
  return request('GET', `${baseUrl}/api/identity/lookup?username=${encodeURIComponent(username)}`);
}

/** GET /api/identity/balance?did=X — check wallet balance */
async function checkBalance(baseUrl = DEFAULT_BASE, did) {
  if (!did) throw new Error('checkBalance() requires a DID');
  return request('GET', `${baseUrl}/api/identity/balance?did=${encodeURIComponent(did)}`);
}

/** POST /api/email/send — send a billed email (1 DD) */
async function sendEmail({ baseUrl = DEFAULT_BASE, token, to, subject, body, format = 'text' }) {
  if (!token) throw new Error('sendEmail() requires a Bearer token (authenticate first)');
  if (!to || !subject || !body) throw new Error('sendEmail() requires to, subject, and body');
  return authRequest('POST', `${baseUrl}/api/email/send`, token, {
    to,
    subject,
    body,
    format,
  });
}

module.exports = { discover, onboard, authenticate, lookup, checkBalance, sendEmail };
