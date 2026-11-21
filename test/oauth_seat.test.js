'use strict';
// node --test test/oauth_seat.test.js
// The OAuth 2.1 front for web seats (oauth_seat.js) against an in-memory DB and stand-ins for the password and PIN
// checks. The real service_tenants wiring (verify() answering auth_method/seat/resource) is covered by
// test/oauth_seat_smoke.sh against server.js.
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const express = require('express');
const Database = require('better-sqlite3');
process.env.IDENTITY_MASTER_KEY = process.env.IDENTITY_MASTER_KEY || 'c'.repeat(64);
process.env.PUBLIC_API_URL = 'https://api.example.test';
const identity = require('../identity');
const registerOauthSeat = require('../oauth_seat');

const RESOURCE = 'https://conduit.dustroot.com/mcp';
const CB = 'https://claude.ai/api/mcp/auth_callback';
const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');
const b64 = (b) => Buffer.from(b).toString('base64url');
const pkce = () => { const verifier = crypto.randomBytes(48).toString('base64url'); return { verifier, challenge: crypto.createHash('sha256').update(verifier).digest('base64url') }; };
const decode = (jwt) => JSON.parse(Buffer.from(jwt.split('.')[1], 'base64url').toString('utf8'));

// The pre-existing tables the module reads, as main has them (a legacy fixture: rows made before the module existed).
function mkdb() {
  const db = new Database(':memory:');
  db.exec(`CREATE TABLE identity_wallets (id INTEGER PRIMARY KEY AUTOINCREMENT, did TEXT UNIQUE, username TEXT, email TEXT, encrypted_private_key TEXT DEFAULT '',
             status TEXT DEFAULT 'active', password_hash TEXT, pin_hash TEXT, pin_set_at TEXT, pin_failures INTEGER DEFAULT 0, pin_locked_until TEXT, pin_lock_count INTEGER DEFAULT 0)`);
  db.exec(`CREATE TABLE fleets (id INTEGER PRIMARY KEY AUTOINCREMENT, owner_did TEXT NOT NULL, name TEXT, slug TEXT UNIQUE, status TEXT DEFAULT 'active')`);
  db.exec(`CREATE TABLE fleet_silicons (id INTEGER PRIMARY KEY AUTOINCREMENT, fleet_id INTEGER, member_did TEXT, handle TEXT, status TEXT DEFAULT 'active', created_by_fleet INTEGER DEFAULT 0, joined_via TEXT)`);
  db.exec(`CREATE TABLE service_tenants (id INTEGER PRIMARY KEY AUTOINCREMENT, slug TEXT UNIQUE, name TEXT, service_did TEXT, owner_did TEXT, status TEXT DEFAULT 'active', created_by TEXT, created_at TEXT)`);
  db.exec(`CREATE TABLE service_actions (id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id INTEGER, action TEXT, scope TEXT, measured_cost_dd INTEGER, max_cost_dd INTEGER, depth TEXT DEFAULT 'standard', open INTEGER DEFAULT 1, status TEXT DEFAULT 'active', updated_at TEXT)`);
  db.exec(`CREATE TABLE service_delegations (id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id INTEGER, scope TEXT, owner_did TEXT, delegate_did TEXT, status TEXT DEFAULT 'active', granted_at TEXT, expires_at TEXT, revoked_at TEXT)`);
  db.exec(`CREATE TABLE service_consents (id INTEGER PRIMARY KEY AUTOINCREMENT, payer_did TEXT, tenant_id INTEGER, daily_cap_dd INTEGER, approved_by TEXT, approval_id INTEGER, status TEXT DEFAULT 'active', created_at TEXT, revoked_at TEXT, on_request_cap_dd INTEGER)`);
  db.exec(`CREATE TABLE issued_tokens (jti TEXT PRIMARY KEY, did TEXT, scope TEXT, issued_at INTEGER, expires_at INTEGER, revoked INTEGER DEFAULT 0, revoked_at TEXT, sid TEXT)`);
  db.exec(`CREATE TABLE blindkey_events (id INTEGER PRIMARY KEY AUTOINCREMENT, event_type TEXT, actor TEXT, secret_id INTEGER, context_name TEXT, detail TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP)`);
  return db;
}

async function world() {
  const db = mkdb();
  identity.setTokenRecorder((p) => { if (p.jti) db.prepare('INSERT OR IGNORE INTO issued_tokens (jti, did, scope, issued_at, expires_at, sid) VALUES (?, ?, ?, ?, ?, ?)').run(p.jti, p.sub, p.scope || '', p.iat || null, p.exp || null, p.sid || null); });
  const mk = (username, extra = {}) => { const id = identity.createIdentity(); db.prepare('INSERT INTO identity_wallets (did, username, email, encrypted_private_key, status, pin_hash, pin_set_at) VALUES (?, ?, ?, ?, ?, ?, ?)')
    .run(id.did, username, username + '@x', id.encrypted_private_key, 'active', extra.pin === false ? null : 'scrypt$x', extra.pin === false ? null : '2026-01-01 00:00:00.000'); return id.did; };
  const owner = mk('owner-a'), seat = mk('seat-fable'), other = mk('seat-other'), agent = mk('agent-b'), nopin = mk('owner-nopin', { pin: false }), tenantDid = mk('conduit-svc');
  const fleetId = Number(db.prepare("INSERT INTO fleets (owner_did, name, slug) VALUES (?, 'A', 'a-fleet')").run(owner).lastInsertRowid);
  db.prepare("INSERT INTO fleet_silicons (fleet_id, member_did, handle, created_by_fleet, joined_via) VALUES (?, ?, 'seat-fable', 1, 'owner')").run(fleetId, seat);
  db.prepare("INSERT INTO fleet_silicons (fleet_id, member_did, handle, created_by_fleet, joined_via) VALUES (?, ?, 'seat-other', 1, 'owner')").run(fleetId, other);
  db.prepare("INSERT INTO fleet_silicons (fleet_id, member_did, handle, created_by_fleet, joined_via) VALUES (?, ?, 'agent-b', 1, 'owner')").run(fleetId, agent);
  const tenantId = Number(db.prepare("INSERT INTO service_tenants (slug, name, service_did, owner_did, created_by, created_at) VALUES ('conduit', 'Conduit', ?, ?, 'test', '2026-01-01')").run(tenantDid, owner).lastInsertRowid);
  for (const a of ['read', 'post', 'ack', 'forward']) db.prepare("INSERT INTO service_actions (tenant_id, action, scope, measured_cost_dd, max_cost_dd, updated_at) VALUES (?, ?, ?, 1, 100, '2026-01-01')").run(tenantId, a, a);
  // A legacy delegation and consent made before the module existed: they must stay as they are after the module loads.
  db.prepare("INSERT INTO service_delegations (tenant_id, scope, owner_did, delegate_did, granted_at) VALUES (?, 'read', ?, ?, '2026-01-01')").run(tenantId, owner, agent);
  db.prepare("INSERT INTO service_consents (payer_did, tenant_id, daily_cap_dd, approved_by, created_at) VALUES (?, ?, 300, ?, '2026-01-01')").run(seat, tenantId, owner);
  const creators = { [seat]: owner, [other]: owner, [agent]: owner };
  const personFor = (did) => creators[did] || did;
  const tenantBySlug = (s) => db.prepare("SELECT * FROM service_tenants WHERE slug = ? AND status = 'active'").get(s);
  const consentOf = (did, t) => db.prepare("SELECT * FROM service_consents WHERE payer_did = ? AND tenant_id = ? AND status = 'active' ORDER BY id DESC LIMIT 1").get(did, t.id);
  const liveConsent = (did, t) => { const c = consentOf(did, t); return c && c.approved_by === personFor(did) ? c : null; };
  const getBearerIdentity = (req) => {
    const h = String(req.headers.authorization || ''); if (!h.startsWith('Bearer ')) return { ok: false, status: 401, error: 'Bearer token required' };
    const v = identity.verifyTokenStandalone(h.slice(7)); if (!v.valid) return { ok: false, status: 401, error: v.error };
    return { ok: true, did: v.decoded.sub, scope: v.decoded.scope, decoded: v.decoded, silicon: false };
  };
  const pinTries = {};
  const app = express();
  const noLimit = (req, res, next) => next();
  const oauth = registerOauthSeat({ app, db, identity, express, rateLimitStandard: noLimit, rateLimitStrict: noLimit, rateLimitLogin: noLimit, getBearerIdentity,
    logSecurityEvent: () => {}, services: { tenantBySlug, liveConsent, consentOf, personFor },
    checkPassword: async (w, pw) => pw === 'pw-' + w.username, pinLocked: () => 0,
    checkPin: (did, pin) => { if (pin === '1234') return { ok: true }; pinTries[did] = (pinTries[did] || 0) + 1; return { status: 403, body: { error: 'incorrect PIN', attempts_left: 5 - pinTries[did] } }; } });
  const server = app.listen(0, "127.0.0.1"); await new Promise((r) => server.once("listening", r));
  const base = () => `http://127.0.0.1:${server.address().port}`;
  const call = async (method, path, { body, headers = {}, form = false, redirect = 'manual' } = {}) => {
    const r = await fetch(base() + path, { method, redirect, headers: { ...(body === undefined ? {} : { 'content-type': form ? 'application/x-www-form-urlencoded' : 'application/json' }), ...headers },
      body: body === undefined ? undefined : form ? new URLSearchParams(body).toString() : JSON.stringify(body) });
    const text = await r.text(); let json = null; try { json = JSON.parse(text); } catch (_) {}
    return { status: r.status, headers: r.headers, text, json };
  };
  const ownerToken = (did) => { const w = db.prepare('SELECT * FROM identity_wallets WHERE did = ?').get(did); return identity.createTokenForIdentity(w.encrypted_private_key, did, { scope: 'transact', expiresIn: '1h', metadata: { auth_method: 'fingerprint', sid: 's1' } }); };
  const close = () => new Promise((r) => server.close(r));
  return { db, app, oauth, call, owner, seat, other, agent, nopin, tenantId, ownerToken, close };
}

async function registerClient(w, extra = {}) {
  const r = await w.call('POST', '/oauth/register', { body: { client_name: 'Claude', redirect_uris: [CB], ...extra } });
  assert.equal(r.status, 201, r.text);
  return r.json;
}
// Walk the browser flow to a code. Returns {code, state, client, verifier, requestId}.
async function authorizeToCode(w, client, { scope = 'read post ack', chooseScopes, seat = 'seat-fable', username = 'owner-a' } = {}) {
  const { verifier, challenge } = pkce();
  const state = 'st-' + crypto.randomBytes(4).toString('hex');
  const q = new URLSearchParams({ response_type: 'code', client_id: client.client_id, redirect_uri: CB, state, code_challenge: challenge, code_challenge_method: 'S256', resource: RESOURCE, scope });
  const page = await w.call('GET', '/oauth/authorize?' + q.toString());
  assert.equal(page.status, 200, page.text);
  const requestId = /dpa_[A-Za-z0-9_-]+/.exec(page.text)[0];
  const l = await w.call('POST', '/oauth/authorize/login', { body: { request_id: requestId, username, password: 'pw-' + username } });
  assert.equal(l.status, 200, l.text);
  const p = await w.call('POST', '/oauth/authorize/pin', { body: { request_id: requestId, pin: '1234' } });
  assert.equal(p.status, 200, p.text);
  const d = await w.call('POST', '/oauth/authorize/decide', { body: { request_id: requestId, approve: true, seat, ...(chooseScopes ? { scopes: chooseScopes } : {}) } });
  assert.equal(d.status, 200, d.text);
  const u = new URL(d.json.redirect);
  assert.equal(u.origin + u.pathname, CB);
  assert.equal(u.searchParams.get('state'), state);
  assert.equal(u.searchParams.get('iss'), 'https://api.example.test');
  return { code: u.searchParams.get('code'), state, client, verifier, requestId, pinReply: p.json };
}
const basic = (c) => ({ authorization: 'Basic ' + Buffer.from(`${c.client_id}:${c.client_secret}`).toString('base64') });
async function exchange(w, { code, client, verifier }, extra = {}) {
  return w.call('POST', '/oauth/token', { form: true, headers: basic(client), body: { grant_type: 'authorization_code', code, redirect_uri: CB, code_verifier: verifier, resource: RESOURCE, ...extra } });
}

test('metadata names this issuer, S256 only, the code and refresh grants, registration and the one resource', async () => {
  const w = await world();
  try {
    const r = await w.call('GET', '/.well-known/oauth-authorization-server');
    assert.equal(r.status, 200);
    assert.equal(r.json.issuer, 'https://api.example.test');
    assert.equal(r.json.authorization_endpoint, 'https://api.example.test/oauth/authorize');
    assert.equal(r.json.token_endpoint, 'https://api.example.test/oauth/token');
    assert.equal(r.json.registration_endpoint, 'https://api.example.test/oauth/register');
    assert.deepEqual(r.json.code_challenge_methods_supported, ['S256']);
    assert.deepEqual(r.json.grant_types_supported, ['authorization_code', 'refresh_token']);
    assert.deepEqual(r.json.response_types_supported, ['code']);
    assert.deepEqual(r.json.scopes_supported.sort(), ['ack', 'forward', 'post', 'read']);
    assert.deepEqual(r.json.resources_supported, [RESOURCE]);
    // Legacy rows untouched by the module's schema work.
    assert.equal(w.db.prepare("SELECT COUNT(*) AS n FROM service_delegations WHERE status = 'active'").get().n, 1);
    assert.equal(w.db.prepare("SELECT daily_cap_dd FROM service_consents WHERE payer_did = ?").get(w.seat).daily_cap_dd, 300);
  } finally { await w.close(); }
});

test('registration: only the Claude callbacks; a confidential client gets a secret once; a public client none', async () => {
  const w = await world();
  try {
    const bad = await w.call('POST', '/oauth/register', { body: { redirect_uris: ['https://evil.example/cb'] } });
    assert.equal(bad.status, 400); assert.equal(bad.json.error, 'invalid_redirect_uri');
    const mixed = await w.call('POST', '/oauth/register', { body: { redirect_uris: [CB, 'https://claude.ai/other'] } });
    assert.equal(mixed.status, 400);
    const c = await registerClient(w);
    assert.match(c.client_id, /^dpc_/); assert.match(c.client_secret, /^dps_/); assert.equal(c.token_endpoint_auth_method, 'client_secret_basic');
    assert.equal(w.db.prepare('SELECT secret_hash FROM oauth_clients WHERE client_id = ?').get(c.client_id).secret_hash, sha(c.client_secret));
    const pub = await registerClient(w, { token_endpoint_auth_method: 'none' });
    assert.equal(pub.client_secret, undefined);
    const badGrant = await w.call('POST', '/oauth/register', { body: { redirect_uris: [CB], grant_types: ['implicit'] } });
    assert.equal(badGrant.status, 400);
  } finally { await w.close(); }
});

test('authorize: an unknown client or unregistered redirect gets a page, never a redirect; other faults go back with state', async () => {
  const w = await world();
  try {
    const c = await registerClient(w);
    const unknown = await w.call('GET', `/oauth/authorize?response_type=code&client_id=dpc_nope&redirect_uri=${encodeURIComponent(CB)}`);
    assert.equal(unknown.status, 400); assert.match(unknown.text, /Unknown client/); assert.equal(unknown.headers.get('location'), null);
    const badUri = await w.call('GET', `/oauth/authorize?response_type=code&client_id=${c.client_id}&redirect_uri=${encodeURIComponent('https://claude.ai/elsewhere')}`);
    assert.equal(badUri.status, 400); assert.match(badUri.text, /Redirect not registered/);
    const noPkce = await w.call('GET', `/oauth/authorize?response_type=code&client_id=${c.client_id}&redirect_uri=${encodeURIComponent(CB)}&state=s1`);
    assert.equal(noPkce.status, 302);
    const u = new URL(noPkce.headers.get('location'));
    assert.equal(u.origin + u.pathname, CB); assert.equal(u.searchParams.get('error'), 'invalid_request'); assert.equal(u.searchParams.get('state'), 's1');
    const { challenge } = pkce();
    const plain = await w.call('GET', `/oauth/authorize?response_type=code&client_id=${c.client_id}&redirect_uri=${encodeURIComponent(CB)}&code_challenge=${challenge}&code_challenge_method=plain`);
    assert.equal(new URL(plain.headers.get('location')).searchParams.get('error'), 'invalid_request');
    const wrongRes = await w.call('GET', `/oauth/authorize?response_type=code&client_id=${c.client_id}&redirect_uri=${encodeURIComponent(CB)}&code_challenge=${challenge}&resource=${encodeURIComponent('https://fleetgate.example/mcp')}`);
    assert.equal(new URL(wrongRes.headers.get('location')).searchParams.get('error'), 'invalid_target');
    const badScope = await w.call('GET', `/oauth/authorize?response_type=code&client_id=${c.client_id}&redirect_uri=${encodeURIComponent(CB)}&code_challenge=${challenge}&scope=admin`);
    assert.equal(new URL(badScope.headers.get('location')).searchParams.get('error'), 'invalid_scope');
    const ok = await w.call('GET', `/oauth/authorize?response_type=code&client_id=${c.client_id}&redirect_uri=${encodeURIComponent(CB)}&code_challenge=${challenge}&resource=${encodeURIComponent(RESOURCE)}`);
    assert.equal(ok.status, 200); assert.match(ok.text, /dpa_/); assert.match(ok.headers.get('content-security-policy'), /script-src 'nonce-/); assert.equal(ok.headers.get('cache-control'), 'no-store');
    // Default scopes when none asked.
    const id = /dpa_[A-Za-z0-9_-]+/.exec(ok.text)[0];
    assert.deepEqual(JSON.parse(w.db.prepare('SELECT scopes FROM oauth_authz WHERE request_id = ?').get(id).scopes), ['read', 'post', 'ack']);
  } finally { await w.close(); }
});

test('login step: wrong passwords are counted and end the request; an agent cannot sign in; a PIN must exist', async () => {
  const w = await world();
  try {
    const c = await registerClient(w);
    const { challenge } = pkce();
    const start = async () => { const r = await w.call('GET', `/oauth/authorize?response_type=code&client_id=${c.client_id}&redirect_uri=${encodeURIComponent(CB)}&code_challenge=${challenge}`); return /dpa_[A-Za-z0-9_-]+/.exec(r.text)[0]; };
    let id = await start();
    for (let i = 0; i < 5; i++) { const r = await w.call('POST', '/oauth/authorize/login', { body: { request_id: id, username: 'owner-a', password: 'nope' } }); assert.equal(r.status, 401); assert.equal(r.json.tries_left, 4 - i); }
    const sixth = await w.call('POST', '/oauth/authorize/login', { body: { request_id: id, username: 'owner-a', password: 'pw-owner-a' } });
    assert.equal(sixth.status, 429);
    assert.equal(w.db.prepare('SELECT 1 FROM oauth_authz WHERE request_id = ?').get(id), undefined);
    id = await start();
    const agent = await w.call('POST', '/oauth/authorize/login', { body: { request_id: id, username: 'agent-b', password: 'pw-agent-b' } });
    assert.equal(agent.status, 403); assert.equal(agent.json.error, 'not_a_person');
    const nopin = await w.call('POST', '/oauth/authorize/login', { body: { request_id: id, username: 'owner-nopin', password: 'pw-owner-nopin' } });
    assert.equal(nopin.status, 403); assert.equal(nopin.json.error, 'pin_required');
    // The PIN step is refused before login, and a wrong PIN is refused with the gate's own answer.
    const early = await w.call('POST', '/oauth/authorize/pin', { body: { request_id: id, pin: '1234' } });
    assert.equal(early.status, 409);
    const ok = await w.call('POST', '/oauth/authorize/login', { body: { request_id: id, username: 'owner-a', password: 'pw-owner-a' } });
    assert.equal(ok.status, 200); assert.equal(ok.json.next, 'pin');
    const wrong = await w.call('POST', '/oauth/authorize/pin', { body: { request_id: id, pin: '0000' } });
    assert.equal(wrong.status, 403); assert.equal(wrong.json.error, 'wrong_pin');
    const right = await w.call('POST', '/oauth/authorize/pin', { body: { request_id: id, pin: '1234' } });
    assert.equal(right.status, 200);
    assert.deepEqual(right.json.seats.map(s => [s.handle, s.consent_ok]), [['seat-fable', true], ['seat-other', false]]);
  } finally { await w.close(); }
});

test('decide: a seat without consent is refused; approving grants the delegations and a one-time code', async () => {
  const w = await world();
  try {
    const c = await registerClient(w);
    await assert.rejects(authorizeToCode(w, c, { seat: 'seat-other' }), /consent_required/);
    await assert.rejects(authorizeToCode(w, c, { seat: 'agent-b' }), /invalid_request/);
    const a = await authorizeToCode(w, c, { chooseScopes: ['read', 'post'] });
    assert.match(a.code, /^dpz_/);
    const dels = w.db.prepare("SELECT scope FROM service_delegations WHERE delegate_did = ? AND status = 'active' ORDER BY scope").all(w.seat).map(r => r.scope);
    assert.deepEqual(dels, ['post', 'read']);
    const g = w.db.prepare('SELECT * FROM oauth_grants WHERE seat_did = ?').get(w.seat);
    assert.deepEqual(JSON.parse(g.scopes), ['read', 'post']); assert.equal(g.resource, RESOURCE); assert.equal(g.owner_did, w.owner);
    // A scope outside what was asked is refused at decide.
    await assert.rejects(authorizeToCode(w, c, { chooseScopes: ['forward'] }), /invalid_scope/);
    // Deny goes back with access_denied and the state.
    const { challenge } = pkce();
    const r = await w.call('GET', `/oauth/authorize?response_type=code&client_id=${c.client_id}&redirect_uri=${encodeURIComponent(CB)}&code_challenge=${challenge}&state=zz`);
    const id = /dpa_[A-Za-z0-9_-]+/.exec(r.text)[0];
    await w.call('POST', '/oauth/authorize/login', { body: { request_id: id, username: 'owner-a', password: 'pw-owner-a' } });
    await w.call('POST', '/oauth/authorize/pin', { body: { request_id: id, pin: '1234' } });
    const deny = await w.call('POST', '/oauth/authorize/decide', { body: { request_id: id, approve: false } });
    const u = new URL(deny.json.redirect);
    assert.equal(u.searchParams.get('error'), 'access_denied'); assert.equal(u.searchParams.get('state'), 'zz');
  } finally { await w.close(); }
});

test('token: PKCE and client secret are checked; the access token is the seat\'s Conduit service token; a replayed code kills the grant', async () => {
  const w = await world();
  try {
    const c = await registerClient(w);
    const a = await authorizeToCode(w, c);
    const noSecret = await w.call('POST', '/oauth/token', { form: true, body: { grant_type: 'authorization_code', code: a.code, client_id: c.client_id, code_verifier: a.verifier } });
    assert.equal(noSecret.status, 401); assert.equal(noSecret.json.error, 'invalid_client'); assert.match(noSecret.headers.get('www-authenticate'), /Basic/);
    const badVerifier = await exchange(w, a, { code_verifier: crypto.randomBytes(48).toString('base64url') });
    assert.equal(badVerifier.status, 400); assert.equal(badVerifier.json.error, 'invalid_grant');
    const otherResource = await exchange(w, a, { resource: 'https://other.example/mcp' });
    assert.equal(otherResource.status, 400); assert.equal(otherResource.json.error, 'invalid_target');
    const ok = await exchange(w, a);
    assert.equal(ok.status, 200, ok.text);
    assert.equal(ok.headers.get('cache-control'), 'no-store');
    assert.equal(ok.json.token_type, 'Bearer'); assert.ok(ok.json.expires_in > 3500 && ok.json.expires_in <= 3600);
    assert.equal(ok.json.scope, 'read post ack'); assert.match(ok.json.refresh_token, /^dpo_/); assert.equal(ok.json.seat, 'seat-fable');
    const d = decode(ok.json.access_token);
    assert.equal(d.iss, 'demipass-svc'); assert.equal(d.aud, 'svc:conduit'); assert.equal(d.sub, w.seat); assert.equal(d.scope, 'transact');
    assert.deepEqual(d.svc_scopes, ['read', 'post', 'ack']); assert.equal(d.auth_method, 'oauth_seat'); assert.equal(d.seat, 'seat-fable'); assert.equal(d.resource, RESOURCE);
    assert.equal(d.cap_dd, 300); assert.equal(d.fleet, 'a-fleet'); assert.ok(d.exp - d.iat <= 3600);
    assert.equal(identity.verifyTokenStandalone(ok.json.access_token).valid, false, 'a service token opens nothing at DemiPass (iss is not civitasvox)');
    assert.equal(w.db.prepare('SELECT revoked FROM issued_tokens WHERE jti = ?').get(d.jti).revoked, 0);
    // Replay of the same code: the grant and the access token die.
    const again = await exchange(w, a);
    assert.equal(again.status, 400); assert.match(again.json.error_description, /revoked/);
    assert.equal(w.db.prepare('SELECT status FROM oauth_grants WHERE seat_did = ?').get(w.seat).status, 'revoked');
    assert.equal(w.db.prepare('SELECT revoked FROM issued_tokens WHERE jti = ?').get(d.jti).revoked, 1);
    const refreshAfter = await w.call('POST', '/oauth/token', { form: true, headers: basic(c), body: { grant_type: 'refresh_token', refresh_token: ok.json.refresh_token } });
    assert.equal(refreshAfter.status, 400);
  } finally { await w.close(); }
});

test('refresh: rotates, re-checks consent and delegation, and a replayed refresh token ends the grant', async () => {
  const w = await world();
  try {
    const c = await registerClient(w);
    const first = await exchange(w, await authorizeToCode(w, c));
    assert.equal(first.status, 200);
    const r1 = await w.call('POST', '/oauth/token', { form: true, headers: basic(c), body: { grant_type: 'refresh_token', refresh_token: first.json.refresh_token } });
    assert.equal(r1.status, 200, r1.text);
    assert.notEqual(r1.json.refresh_token, first.json.refresh_token);
    assert.equal(decode(r1.json.access_token).seat, 'seat-fable');
    const narrower = await w.call('POST', '/oauth/token', { form: true, headers: basic(c), body: { grant_type: 'refresh_token', refresh_token: r1.json.refresh_token, scope: 'read admin' } });
    assert.equal(narrower.status, 400); assert.equal(narrower.json.error, 'invalid_scope');
    // Another client cannot use this refresh token.
    const c2 = await registerClient(w);
    const stolen = await w.call('POST', '/oauth/token', { form: true, headers: basic(c2), body: { grant_type: 'refresh_token', refresh_token: r1.json.refresh_token } });
    assert.equal(stolen.status, 400);
    // The owner revokes the delegation of 'post' in the app: the grant (which carries post) ends at once.
    const d = w.db.prepare("SELECT * FROM service_delegations WHERE delegate_did = ? AND scope = 'post' AND status = 'active'").get(w.seat);
    w.db.prepare("UPDATE service_delegations SET status = 'revoked' WHERE id = ?").run(d.id);
    assert.equal(w.oauth.revokeForDelegation(d), 1);
    const g = w.db.prepare('SELECT * FROM oauth_grants WHERE seat_did = ?').get(w.seat);
    assert.equal(g.status, 'revoked'); assert.match(g.revoked_why, /delegation of 'post'/);
    assert.equal(w.db.prepare('SELECT COUNT(*) AS n FROM oauth_access a JOIN issued_tokens i ON i.jti = a.jti WHERE a.grant_id = ? AND i.revoked = 0').get(g.id).n, 0);
    const r2 = await w.call('POST', '/oauth/token', { form: true, headers: basic(c), body: { grant_type: 'refresh_token', refresh_token: r1.json.refresh_token } });
    assert.equal(r2.status, 400); assert.equal(r2.json.error, 'invalid_grant');
    // New grant; a used refresh token presented again revokes it.
    const second = await exchange(w, await authorizeToCode(w, c));
    const r3 = await w.call('POST', '/oauth/token', { form: true, headers: basic(c), body: { grant_type: 'refresh_token', refresh_token: second.json.refresh_token } });
    assert.equal(r3.status, 200);
    const replay = await w.call('POST', '/oauth/token', { form: true, headers: basic(c), body: { grant_type: 'refresh_token', refresh_token: second.json.refresh_token } });
    assert.equal(replay.status, 400); assert.match(replay.json.error_description, /revoked/);
    const r4 = await w.call('POST', '/oauth/token', { form: true, headers: basic(c), body: { grant_type: 'refresh_token', refresh_token: r3.json.refresh_token } });
    assert.equal(r4.status, 400, 'the successor dies with the grant');
    // Consent revoked (or re-approved by someone else) → the next refresh fails and the grant is closed.
    const third = await exchange(w, await authorizeToCode(w, c));
    w.db.prepare("UPDATE service_consents SET status = 'revoked' WHERE payer_did = ?").run(w.seat);
    const r5 = await w.call('POST', '/oauth/token', { form: true, headers: basic(c), body: { grant_type: 'refresh_token', refresh_token: third.json.refresh_token } });
    assert.equal(r5.status, 400); assert.match(r5.json.error_description, /consent/);
    assert.equal(w.db.prepare('SELECT status FROM oauth_grants WHERE id = (SELECT MAX(id) FROM oauth_grants)').get().status, 'revoked');
  } finally { await w.close(); }
});

test('a seat that stops being a fleet-created agent, or an owner wallet that is closed, cannot mint again', async () => {
  const w = await world();
  try {
    const c = await registerClient(w);
    const t = await exchange(w, await authorizeToCode(w, c));
    w.db.prepare("UPDATE fleet_silicons SET status = 'removed' WHERE member_did = ?").run(w.seat);
    const r = await w.call('POST', '/oauth/token', { form: true, headers: basic(c), body: { grant_type: 'refresh_token', refresh_token: t.json.refresh_token } });
    assert.equal(r.status, 400); assert.match(r.json.error_description, /no longer a seat/);
    w.db.prepare("UPDATE fleet_silicons SET status = 'active' WHERE member_did = ?").run(w.seat);
    const t2 = await exchange(w, await authorizeToCode(w, c));
    w.db.prepare("UPDATE identity_wallets SET status = 'suspended' WHERE did = ?").run(w.owner);
    const r2 = await w.call('POST', '/oauth/token', { form: true, headers: basic(c), body: { grant_type: 'refresh_token', refresh_token: t2.json.refresh_token } });
    assert.equal(r2.status, 400); assert.match(r2.json.error_description, /owner wallet/);
  } finally { await w.close(); }
});

test('the owner sees and ends grants from their own session; an agent or seat token cannot; RFC 7009 revoke works for the client', async () => {
  const w = await world();
  try {
    const c = await registerClient(w);
    const t = await exchange(w, await authorizeToCode(w, c));
    const list = await w.call('GET', '/api/oauth/grants', { headers: { authorization: 'Bearer ' + w.ownerToken(w.owner) } });
    assert.equal(list.status, 200); assert.equal(list.json.grants.length, 1); assert.equal(list.json.grants[0].seat, 'seat-fable'); assert.equal(list.json.grants[0].live_access_tokens, 1);
    const asSeat = await w.call('GET', '/api/oauth/grants', { headers: { authorization: 'Bearer ' + t.json.access_token } });
    assert.equal(asSeat.status, 401, 'a service token is not a DemiPass session');
    const other = await w.call('POST', `/api/oauth/grants/${list.json.grants[0].id}/revoke`, { headers: { authorization: 'Bearer ' + w.ownerToken(w.agent) } });
    assert.equal(other.status, 404);
    const rfc = await w.call('POST', '/oauth/revoke', { form: true, headers: basic(c), body: { token: t.json.refresh_token } });
    assert.equal(rfc.status, 200);
    assert.equal(w.db.prepare('SELECT status FROM oauth_grants WHERE seat_did = ?').get(w.seat).status, 'revoked');
    const t2 = await exchange(w, await authorizeToCode(w, c));
    const id = w.db.prepare('SELECT id FROM oauth_grants WHERE status = ?').get('active').id;
    const rv = await w.call('POST', `/api/oauth/grants/${id}/revoke`, { headers: { authorization: 'Bearer ' + w.ownerToken(w.owner) } });
    assert.equal(rv.status, 200); assert.equal(rv.json.grant.status, 'revoked'); assert.equal(rv.json.grant.live_access_tokens, 0);
    assert.equal(w.db.prepare('SELECT revoked FROM issued_tokens WHERE jti = ?').get(decode(t2.json.access_token).jti).revoked, 1);
  } finally { await w.close(); }
});

test('a public client (auth none) exchanges with PKCE alone and is refused if it sends a secret', async () => {
  const w = await world();
  try {
    const c = await registerClient(w, { token_endpoint_auth_method: 'none' });
    const a = await authorizeToCode(w, c);
    const withSecret = await w.call('POST', '/oauth/token', { form: true, body: { grant_type: 'authorization_code', code: a.code, client_id: c.client_id, client_secret: 'x', code_verifier: a.verifier } });
    assert.equal(withSecret.status, 401);
    const ok = await w.call('POST', '/oauth/token', { form: true, body: { grant_type: 'authorization_code', code: a.code, client_id: c.client_id, code_verifier: a.verifier, redirect_uri: CB } });
    assert.equal(ok.status, 200, ok.text);
    assert.equal(decode(ok.json.access_token).seat, 'seat-fable');
  } finally { await w.close(); }
});
