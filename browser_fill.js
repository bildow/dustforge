// Browser fill: the rules for which page may receive a stored login. A secret is filled only into a page whose
// origin is bound to it; the extension (a person) or the agent fill tool (a silicon) asks, the server decides.
// Pure helpers — the routes live in server.js. Contract: docs/browser-fill-api.md.
const crypto = require('crypto');

const MAX_ORIGINS = 10;
const MAX_LOGIN = 256;
const REQUEST_TTL_SEC = 120;   // a fill request is approved and redeemed within two minutes or dies
const LOCAL_HOSTS = new Set(['localhost', '127.0.0.1']);

// `https://host[:port]` for anything URL-shaped, or null. Plain http only for localhost/127.0.0.1: a password
// filled over http travels in the clear. Exact origins only — no wildcards, no "same site" — so a lookalike
// subdomain never matches by accident.
function normalizeOrigin(raw) {
  if (typeof raw !== 'string' || raw.length === 0 || raw.length > 2048) return null;
  let u;
  try { u = new URL(raw.trim()); } catch (_) { return null; }
  if (u.username || u.password) return null;
  if (u.protocol === 'https:') return u.origin;
  if (u.protocol === 'http:' && LOCAL_HOSTS.has(u.hostname)) return u.origin;
  return null;
}

// A list of origins from a request body → { origins } (deduped, normalized) or { error }.
function parseOrigins(list) {
  if (!Array.isArray(list)) return { error: 'origins must be an array of URLs' };
  const out = [];
  for (const raw of list) {
    const o = normalizeOrigin(raw);
    if (!o) return { error: `origin '${String(raw).slice(0, 80)}' is not https (http only for localhost)` };
    if (!out.includes(o)) out.push(o);
  }
  if (out.length > MAX_ORIGINS) return { error: `at most ${MAX_ORIGINS} origins per secret` };
  return { origins: out };
}

// The stored column → array. A corrupt column binds nothing (fails closed).
function storedOrigins(column) {
  if (!column) return [];
  try {
    const v = JSON.parse(column);
    return Array.isArray(v) ? v.filter(o => typeof o === 'string') : [];
  } catch (_) { return []; }
}

// The account name a website login belongs to: an email or username. Display data, not a secret, but it is
// echoed into a wallet card and a page field, so no control characters.
function validLogin(s) {
  return typeof s === 'string' && s.length <= MAX_LOGIN && !/[\u0000-\u001f\u007f]/.test(s);
}

function newRequestCode() {
  return 'dpf_' + crypto.randomBytes(24).toString('base64url');
}

module.exports = { MAX_ORIGINS, MAX_LOGIN, REQUEST_TTL_SEC, normalizeOrigin, parseOrigins, storedOrigins, validLogin, newRequestCode };
