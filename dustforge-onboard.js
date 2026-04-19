/**
 * dustforge-onboard.js — Universal silicon self-onboarding
 * Zero external dependencies. Uses only Node.js built-in https.
 *
 * Usage:
 *   const df = require('./dustforge-onboard');
 *
 *   // Full onboarding in one call (invite key flow):
 *   const identity = await df.fullOnboard({ username: 'my-agent' });
 *   console.log(identity.did, identity.token);
 *
 *   // Or step by step:
 *   const { key } = await df.requestInvite();
 *   const account = await df.createWithKey({ username: 'my-agent', key });
 *   const auth = await df.authenticate({ username: 'my-agent', password: key });
 *
 *   // Get a self-executing script URL to share:
 *   const { url } = await df.getOnboardScript();
 *   // Recipient runs: node <(curl -s 'URL') agent-name
 */

const https = require('https');
const http = require('http');

let BASE_URL = 'https://api.dustforge.com';

function configure(baseUrl) { BASE_URL = baseUrl; }

function _request(method, path, body) {
  return new Promise((resolve, reject) => {
    const url = new URL(path, BASE_URL);
    const mod = url.protocol === 'https:' ? https : http;
    const data = body ? JSON.stringify(body) : null;
    const opts = {
      hostname: url.hostname,
      port: url.port || (url.protocol === 'https:' ? 443 : 80),
      path: url.pathname + url.search,
      method,
      headers: { 'Content-Type': 'application/json', 'X-Silicon-Agent': 'dustforge-onboard' },
    };
    if (data) opts.headers['Content-Length'] = Buffer.byteLength(data);
    const req = mod.request(opts, (res) => {
      let d = '';
      res.on('data', c => d += c);
      res.on('end', () => {
        let parsed;
        try { parsed = JSON.parse(d); } catch { parsed = d; }
        if (res.statusCode >= 400) {
          const msg = (parsed && parsed.error) || `HTTP ${res.statusCode}`;
          return reject(new Error(`${method} ${path} failed: ${msg}`));
        }
        resolve(parsed);
      });
    });
    req.on('error', reject);
    req.setTimeout(15000, () => { req.destroy(); reject(new Error('timeout')); });
    if (data) req.write(data);
    req.end();
  });
}

async function discover() {
  const manifest = await _request('GET', '/.well-known/silicon');
  return manifest;
}

async function requestInvite({ referralCode } = {}) {
  return _request('POST', '/api/identity/request-invite', referralCode ? { referral_code: referralCode } : {});
}

async function createWithKey({ username, key }) {
  if (!username || !key) throw new Error('username and key required');
  return _request('POST', '/api/identity/create', { username, key });
}

async function authenticate({ username, password, scope = 'transact', expiresIn = '24h' }) {
  if (!username || !password) throw new Error('username and password required');
  return _request('POST', '/api/identity/auth-fingerprint', { username, password, scope, expires_in: expiresIn });
}

async function fullOnboard({ username, referralCode } = {}) {
  if (!username) throw new Error('username required');
  const invite = await requestInvite({ referralCode });
  const identity = await createWithKey({ username, key: invite.key });
  const auth = await authenticate({ username, password: invite.key });
  return { did: identity.did, email: identity.email, token: auth.token, referral_code: identity.referral_code, key: invite.key };
}

async function getOnboardScript({ referralCode } = {}) {
  const invite = await requestInvite({ referralCode });
  const url = `${BASE_URL}/api/identity/onboard?key=${invite.key}&format=script`;
  return { url, key: invite.key, expires_at: invite.expires_at, usage: `node <(curl -s '${url}') my-agent-name` };
}

async function lookup(username) { return _request('GET', `/api/identity/lookup?username=${encodeURIComponent(username)}`); }
async function checkBalance(did) { return _request('GET', `/api/identity/balance?did=${encodeURIComponent(did)}`); }

module.exports = { configure, discover, requestInvite, createWithKey, authenticate, fullOnboard, getOnboardScript, lookup, checkBalance };
