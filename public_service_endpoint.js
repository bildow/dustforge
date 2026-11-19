'use strict';
// Network membership must never be an MCP/API onboarding prerequisite.
// Registered service endpoints are public HTTPS; even loopback is not a public registry address.
const net = require('net');

function hostOf(value) { return String(value).toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, ''); }
function loopback(host) {
  host = hostOf(host);
  return host === 'localhost' || host === '::1' || /^127\./.test(host) && net.isIP(host) === 4;
}
function privateAddress(host) {
  host = hostOf(host);
  if (host.startsWith('::ffff:')) {
    const rest = host.slice(7);
    if (net.isIP(rest) === 4) return privateAddress(rest);
    const m = /^([a-f0-9]{1,4}):([a-f0-9]{1,4})$/.exec(rest);
    if (m) { const a = parseInt(m[1],16), b = parseInt(m[2],16); return privateAddress(`${a>>8}.${a&255}.${b>>8}.${b&255}`); }
  }
  if (net.isIP(host) === 4) {
    const [a,b] = host.split('.').map(Number);
    return a === 0 || a === 10 || a === 127 || a === 169 && b === 254 ||
      a === 172 && b >= 16 && b <= 31 || a === 192 && b === 168 ||
      a === 100 && b >= 64 && b <= 127 || a >= 224;
  }
  return net.isIP(host) === 6 && (host === '::' || host === '::1' || /^(fc|fd|fe[89ab]|ff)/i.test(host));
}
function failure() { return Object.assign(new Error('Public HTTPS service endpoint required; private/tailnet routes are not permitted for MCP, API calls or onboarding'), { code: 'PRIVATE_SERVICE_ROUTE' }); }
function assertPublicRoute(value) {
  const u = value instanceof URL ? value : new URL(value);
  const host = hostOf(u.hostname);
  if (u.username || u.password || !['http:', 'https:'].includes(u.protocol)) throw failure();
  if (loopback(host)) throw failure();
  if (u.protocol !== 'https:' || host === 'ts.net' || host.endsWith('.ts.net') ||
      host === 'tailscale.com' || host.endsWith('.tailscale.com') ||
      !host.includes('.') && !net.isIP(host) || privateAddress(host)) throw failure();
  return u;
}
module.exports = { assertPublicRoute };
