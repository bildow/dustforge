'use strict';
// ── OAuth 2.1 front for human web seats (Claude.ai custom connectors) ─────────────────────────────────────────────────
// Aaron 2026-11-21: "Add the OAuth 2.1 front that Claude.ai's custom-connector flow needs, on top of DemiPass's existing
// app JWT, so a human web seat can authorize a Conduit connector once in the browser."
//
// What Claude.ai requires (support.claude.com "Getting started with custom connectors using remote MCP", read 2026-11-21,
// and the MCP authorization spec 2025-06-18): the MCP server answers 401 with WWW-Authenticate naming its protected-
// resource metadata (RFC 9728), that document names this authorization server, this server publishes RFC 8414 metadata
// at /.well-known/oauth-authorization-server, the client registers dynamically (RFC 7591) or is given a client id,
// authorization code + PKCE S256, `resource` (RFC 8707) on both legs, the resource server checks the audience, refresh
// tokens rotate, every endpoint is HTTPS. Claude.ai's callback is https://claude.ai/api/mcp/auth_callback.
//
// How it maps onto DemiPass:
//   • A SEAT is a fleet-created agent of the owner's fleet whose handle starts with `seat-` (first: seat-fable). It is a
//     wallet of its own: charges land on it; it is removed, funded and watched like any agent. The owner is personFor().
//   • The access token IS the seat's Conduit service token (service_tenants.js: iss demipass-svc, aud svc:conduit,
//     EdDSA by the seat's own key), with svc_scopes = the granted subset, auth_method 'oauth_seat', the seat handle and
//     the resource. Conduit verifies it exactly as any service token (POST /api/services/verify); the aud test is the
//     audience check the MCP spec demands; the token opens nothing at DemiPass and nothing at another tenant.
//   • The authorize screen is the owner's DemiPass login + PIN in the browser (Aaron's spec), then a consent naming the
//     seat and the Conduit scopes. Approving also grants the owner's use-only delegation of each scope to the seat
//     (service_delegations), standard depth. The seat's consent to pay Conduit (daily cap = the per-day hop cap) must
//     already stand: that is an elevated approval on the owner's phone, never a browser click.
//   • Every mint (code exchange and each refresh) re-checks: seat still an active fleet-created agent of the owner,
//     owner and seat wallets active, live consent approved by the owner, live delegation of every scope. Revoking the
//     delegation or the consent in the app revokes the grant and every unexpired access token at once.
//   • The connector holds only OAuth tokens. No vault value is involved anywhere here.
//
// Endpoints
//   GET  /.well-known/oauth-authorization-server
//   POST /oauth/register                           RFC 7591; redirect URIs restricted to the Claude callbacks
//   GET  /oauth/authorize                          the browser page (validates the request first; never redirects an
//                                                  invalid client/redirect_uri)
//   POST /oauth/authorize/login|pin|decide         the page's three steps (JSON)
//   POST /oauth/token                              authorization_code | refresh_token (form-encoded or JSON)
//   POST /oauth/revoke                             RFC 7009
//   GET  /api/oauth/grants, POST /api/oauth/grants/:id/revoke   the owner's view (own session)

const crypto = require('crypto');

const ACCESS_TTL_SEC = 3600;                 // short-lived; a refresh re-checks everything
const REFRESH_TTL_SEC = 30 * 86400;
const CODE_TTL_SEC = 300;
const AUTHZ_TTL_SEC = 600;                   // a browser has ten minutes to log in, type the PIN and decide
const DELEGATION_TTL_SEC = REFRESH_TTL_SEC;  // the owner's delegation to the seat lasts as long as the grant can
const LOGIN_TRIES_PER_REQUEST = 5;
const MAX_CLIENTS = 200;
const DEFAULT_SCOPES = ['read', 'post', 'ack'];
const SEAT_PREFIX = 'seat-';
const CONDUIT_SLUG = 'conduit';
const HEX64 = /^[0-9a-f]{64}$/;
const B64URL_43_128 = /^[A-Za-z0-9._~-]{43,128}$/;   // PKCE verifier / challenge alphabet and length (RFC 7636)
const DEFAULT_REDIRECTS = ['https://claude.ai/api/mcp/auth_callback', 'https://claude.com/api/mcp/auth_callback'];

module.exports = function registerOauthSeat(deps) {
  const { app, db, identity, express, rateLimitStandard, rateLimitStrict, rateLimitLogin, getBearerIdentity, logSecurityEvent } = deps;
  const svc = deps.services;                       // service_tenants' return value (lazy getter or object)
  const S = () => (typeof svc === 'function' ? svc() : svc);
  const checkPassword = deps.checkPassword;        // async (wallet, password) → true | false | null (unavailable)
  const checkPin = deps.checkPin;                  // (did, pin, req, context) → {ok} | {status, body}   (counts misses, locks)
  const pinLocked = deps.pinLocked || (() => 0);   // (wallet) → seconds locked, 0 when usable
  const log = deps.log || ((...a) => console.log('[oauth]', ...a));
  const BASE = String(deps.publicApi || process.env.PUBLIC_API_URL || 'https://api.dustforge.com').replace(/\/+$/, '');
  const RESOURCE = String(process.env.OAUTH_CONDUIT_RESOURCE || 'https://conduit.dustroot.com/mcp').replace(/\/+$/, '');
  const REDIRECT_ALLOWLIST = new Set((process.env.OAUTH_REDIRECT_ALLOWLIST || DEFAULT_REDIRECTS.join(',')).split(',').map(s => s.trim()).filter(Boolean));
  const formOrJson = express.urlencoded({ extended: false, limit: '16kb' });

  // ── schema (new tables only; every statement is idempotent) ────────────────────────────────────────────────────
  db.exec(`CREATE TABLE IF NOT EXISTS oauth_clients (
    client_id TEXT PRIMARY KEY,
    secret_hash TEXT,                         -- NULL: a public client (token_endpoint_auth_method none)
    client_name TEXT NOT NULL DEFAULT '',
    redirect_uris TEXT NOT NULL,              -- JSON list, each in the allowlist
    auth_method TEXT NOT NULL,                -- none | client_secret_basic | client_secret_post
    created_at TEXT NOT NULL,
    created_ip TEXT,
    last_used_at TEXT
  )`);
  db.exec(`CREATE TABLE IF NOT EXISTS oauth_authz (
    request_id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    scopes TEXT NOT NULL,                     -- JSON list requested
    state TEXT,
    code_challenge TEXT NOT NULL,
    resource TEXT NOT NULL,
    step TEXT NOT NULL DEFAULT 'login',       -- login | pin | decide | done
    owner_did TEXT,
    login_tries INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    ip TEXT
  )`);
  db.exec(`CREATE TABLE IF NOT EXISTS oauth_grants (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id TEXT NOT NULL,
    owner_did TEXT NOT NULL,
    seat_did TEXT NOT NULL,
    seat_handle TEXT NOT NULL,
    fleet_slug TEXT NOT NULL,
    scopes TEXT NOT NULL,                     -- JSON list granted
    resource TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',    -- active | revoked
    created_at TEXT NOT NULL,
    last_used_at TEXT,
    revoked_at TEXT,
    revoked_why TEXT
  )`);
  db.exec('CREATE INDEX IF NOT EXISTS idx_oauth_grants_seat ON oauth_grants(seat_did, status)');
  db.exec(`CREATE TABLE IF NOT EXISTS oauth_codes (
    code_hash TEXT PRIMARY KEY,
    grant_id INTEGER NOT NULL,
    client_id TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    code_challenge TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used_at TEXT
  )`);
  db.exec(`CREATE TABLE IF NOT EXISTS oauth_refresh (
    token_hash TEXT PRIMARY KEY,
    grant_id INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used_at TEXT,
    rotated_to TEXT                           -- hash of the successor, once used
  )`);
  db.exec('CREATE INDEX IF NOT EXISTS idx_oauth_refresh_grant ON oauth_refresh(grant_id)');
  db.exec(`CREATE TABLE IF NOT EXISTS oauth_access (
    jti TEXT PRIMARY KEY,
    grant_id INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
  )`);
  db.exec('CREATE INDEX IF NOT EXISTS idx_oauth_access_grant ON oauth_access(grant_id)');

  // ── helpers ──────────────────────────────────────────────────────────────────────────────────────────────────
  const nowIso = () => new Date().toISOString();
  const nowSec = () => Math.floor(Date.now() / 1000);
  const later = (sec) => new Date(Date.now() + sec * 1000).toISOString();
  const sha = (s) => crypto.createHash('sha256').update(String(s)).digest('hex');
  const rand = (n = 32) => crypto.randomBytes(n).toString('base64url');
  const jsonList = (s) => { try { const v = JSON.parse(s || '[]'); return Array.isArray(v) ? v : []; } catch (_) { return []; } };
  const safeEq = (a, b) => { const x = Buffer.from(String(a || '')), y = Buffer.from(String(b || '')); return x.length === y.length && x.length > 0 && crypto.timingSafeEqual(x, y); };
  const noStore = (res) => { res.set('Cache-Control', 'no-store'); res.set('Pragma', 'no-cache'); };
  const oauthError = (res, status, error, description, extra = {}) => { noStore(res); return res.status(status).json({ error, error_description: description, ...extra }); };
  const event = (type, actor, detail) => { try { db.prepare('INSERT INTO blindkey_events (event_type, actor, secret_id, context_name, detail) VALUES (?, ?, ?, ?, ?)').run(type, actor, null, 'oauth', JSON.stringify(detail)); } catch (_) {} };
  const sec = (type, severity, detail) => { try { if (logSecurityEvent) logSecurityEvent(type, severity, detail); } catch (_) {} };
  const tenant = () => S().tenantBySlug(CONDUIT_SLUG);
  const tenantScopes = (t) => db.prepare("SELECT DISTINCT scope FROM service_actions WHERE tenant_id = ? AND status = 'active'").all(t.id).map(r => r.scope);
  const isSeatHandle = (h) => typeof h === 'string' && h.startsWith(SEAT_PREFIX) && /^[a-z0-9][a-z0-9_-]{1,40}$/.test(h);

  // Scope strings: a space-separated list; each one a Conduit scope. Nothing requested → the default set (∩ what the
  // tenant has). Unknown scope → invalid_scope, never a silent narrowing.
  function parseScopes(raw, t) {
    const known = tenantScopes(t);
    const asked = String(raw || '').split(/[\s,]+/).filter(Boolean);
    if (!asked.length) return { ok: true, scopes: DEFAULT_SCOPES.filter(s => known.includes(s)) };
    if (asked.length > 10 || asked.some(s => !known.includes(s))) return { ok: false, error: `scope: a space-separated list from ${known.join(' ')}` };
    return { ok: true, scopes: [...new Set(asked)] };
  }

  // The seats an owner may bind: fleet-created agents of a fleet they own, handle `seat-…`, active, not network-joined.
  function seatsOf(ownerDid) {
    return db.prepare(`SELECT s.handle, s.member_did, f.slug AS fleet_slug FROM fleet_silicons s JOIN fleets f ON f.id = s.fleet_id
      WHERE f.owner_did = ? AND f.status = 'active' AND s.status = 'active' AND s.created_by_fleet = 1
        AND COALESCE(s.joined_via, 'owner') != 'network' AND s.handle LIKE 'seat-%' ORDER BY s.handle`).all(ownerDid)
      .filter(s => isSeatHandle(s.handle));
  }
  function seatRow(ownerDid, handle) { return seatsOf(ownerDid).find(s => s.handle === handle) || null; }
  const walletActive = (did) => { const w = db.prepare('SELECT did, username, status, encrypted_private_key FROM identity_wallets WHERE did = ?').get(did); return w && w.status === 'active' && w.encrypted_private_key ? w : null; };
  // The seat's standing consent to pay Conduit, approved by the person who answers for it (the owner) — liveConsent().
  function seatConsent(seatDid, ownerDid, t) {
    const c = S().liveConsent ? S().liveConsent(seatDid, t) : null;
    return c && c.approved_by === ownerDid ? c : null;
  }
  const liveDelegation = (t, scope, ownerDid, seatDid) => db.prepare(`SELECT * FROM service_delegations WHERE tenant_id = ? AND scope = ? AND owner_did = ? AND delegate_did = ?
      AND status = 'active' AND (expires_at IS NULL OR expires_at > ?) ORDER BY id DESC LIMIT 1`).get(t.id, scope, ownerDid, seatDid, nowIso());

  // Everything a mint needs to be true, now. Returns {ok, seat, consent, cap} or {ok:false, error, code}.
  function grantStillGood(g) {
    const t = tenant();
    if (!t) return { ok: false, error: 'Conduit is not a registered service here', code: 'invalid_grant' };
    if (g.status !== 'active') return { ok: false, error: 'this grant was revoked', code: 'invalid_grant' };
    if (!walletActive(g.owner_did)) return { ok: false, error: 'the owner wallet is not active', code: 'invalid_grant' };
    const seat = seatRow(g.owner_did, g.seat_handle);
    if (!seat || seat.member_did !== g.seat_did) return { ok: false, error: `@${g.seat_handle} is no longer a seat of this owner's fleet`, code: 'invalid_grant' };
    const w = walletActive(g.seat_did);
    if (!w) return { ok: false, error: 'the seat wallet is not active', code: 'invalid_grant' };
    const consent = seatConsent(g.seat_did, g.owner_did, t);
    if (!consent) return { ok: false, error: `@${g.seat_handle} has no live consent to pay Conduit approved by its owner`, code: 'invalid_grant' };
    for (const scope of jsonList(g.scopes)) {
      if (!liveDelegation(t, scope, g.owner_did, g.seat_did)) return { ok: false, error: `the owner's delegation of '${scope}' to @${g.seat_handle} is gone`, code: 'invalid_grant' };
    }
    return { ok: true, t, seat, wallet: w, consent, cap: Math.min(500, consent.daily_cap_dd) };
  }

  // The access token: the seat's Conduit service token (service_tenants.js mints the same shape for a caller's own
  // session; here the OAuth front mints it for the seat after the owner's browser approval). Recorded for revocation.
  function mintAccess(g, good) {
    const scopes = jsonList(g.scopes);
    const meta = { iss: require('./service_tenants').SVC_ISS, aud: 'svc:' + good.t.slug, auth_method: 'oauth_seat', src_auth: 'oauth_seat',
      cap_dd: good.cap, svc_scopes: scopes, seat: g.seat_handle, resource: g.resource, grant: g.id, fleet: g.fleet_slug, username: good.wallet.username || undefined };
    const token = identity.createTokenForIdentity(good.wallet.encrypted_private_key, g.seat_did, { scope: 'transact', expiresIn: `${ACCESS_TTL_SEC}s`, metadata: meta });
    const d = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8'));
    db.prepare('INSERT OR IGNORE INTO oauth_access (jti, grant_id, expires_at) VALUES (?, ?, ?)').run(d.jti, g.id, d.exp);
    db.prepare('UPDATE oauth_grants SET last_used_at = ? WHERE id = ?').run(nowIso(), g.id);
    return { token, jti: d.jti, exp: d.exp, scopes };
  }
  function mintRefresh(gId) {
    const raw = 'dpo_' + rand(32);
    db.prepare('INSERT INTO oauth_refresh (token_hash, grant_id, created_at, expires_at) VALUES (?, ?, ?, ?)').run(sha(raw), gId, nowIso(), later(REFRESH_TTL_SEC));
    return raw;
  }
  // Revoke a grant and everything it issued: unexpired access tokens (issued_tokens.revoked, which every verify reads),
  // its refresh chain, its unused codes. Idempotent.
  function revokeGrant(gId, why) {
    const g = db.prepare('SELECT * FROM oauth_grants WHERE id = ?').get(gId);
    if (!g) return false;
    db.transaction(() => {
      if (g.status === 'active') db.prepare("UPDATE oauth_grants SET status = 'revoked', revoked_at = ?, revoked_why = ? WHERE id = ?").run(nowIso(), String(why || '').slice(0, 200), gId);
      for (const a of db.prepare('SELECT jti FROM oauth_access WHERE grant_id = ? AND expires_at > ?').all(gId, nowSec())) {
        db.prepare("UPDATE issued_tokens SET revoked = 1, revoked_at = datetime('now') WHERE jti = ? AND revoked = 0").run(a.jti);
      }
      db.prepare('DELETE FROM oauth_refresh WHERE grant_id = ?').run(gId);
      db.prepare('DELETE FROM oauth_codes WHERE grant_id = ? AND used_at IS NULL').run(gId);
    })();
    event('oauth_grant_revoked', g.owner_did, { grant_id: gId, seat: g.seat_handle, client_id: g.client_id, why });
    return true;
  }
  // Hooks for service_tenants: the owner revoked a delegation or a consent in the app → the seat's grants end now.
  function revokeForDelegation(d) {
    const t = tenant(); if (!t || !d || d.tenant_id !== t.id) return 0;
    let n = 0;
    for (const g of db.prepare("SELECT * FROM oauth_grants WHERE status = 'active' AND owner_did = ? AND seat_did = ?").all(d.owner_did, d.delegate_did)) {
      if (jsonList(g.scopes).includes(d.scope) && revokeGrant(g.id, `delegation of '${d.scope}' revoked`)) n++;
    }
    return n;
  }
  function revokeForConsent(c) {
    const t = tenant(); if (!t || !c || c.tenant_id !== t.id) return 0;
    let n = 0;
    for (const g of db.prepare("SELECT * FROM oauth_grants WHERE status = 'active' AND seat_did = ?").all(c.payer_did)) if (revokeGrant(g.id, 'consent to pay Conduit revoked')) n++;
    return n;
  }
  function sweep() {
    const t = nowIso();
    try {
      db.prepare('DELETE FROM oauth_authz WHERE expires_at <= ?').run(t);
      db.prepare('DELETE FROM oauth_codes WHERE expires_at <= ?').run(t);
      db.prepare('DELETE FROM oauth_refresh WHERE expires_at <= ?').run(t);
      db.prepare('DELETE FROM oauth_access WHERE expires_at <= ?').run(nowSec());
    } catch (_) {}
  }
  const sweeper = setInterval(sweep, 60000); if (sweeper.unref) sweeper.unref();

  // ── metadata ─────────────────────────────────────────────────────────────────────────────────────────────────
  const metadata = () => ({
    issuer: BASE,
    authorization_endpoint: `${BASE}/oauth/authorize`,
    token_endpoint: `${BASE}/oauth/token`,
    registration_endpoint: `${BASE}/oauth/register`,
    revocation_endpoint: `${BASE}/oauth/revoke`,
    response_types_supported: ['code'],
    response_modes_supported: ['query'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    code_challenge_methods_supported: ['S256'],
    token_endpoint_auth_methods_supported: ['none', 'client_secret_basic', 'client_secret_post'],
    revocation_endpoint_auth_methods_supported: ['none', 'client_secret_basic', 'client_secret_post'],
    scopes_supported: (() => { const t = tenant(); return t ? tenantScopes(t) : DEFAULT_SCOPES; })(),
    service_documentation: 'https://demipass.com/mcp-agents',
    ui_locales_supported: ['en'],
    // What this server issues tokens FOR (RFC 8707): one resource, Conduit's MCP endpoint. Informational.
    resources_supported: [RESOURCE],
  });
  app.get('/.well-known/oauth-authorization-server', rateLimitStandard, (req, res) => { res.set('Cache-Control', 'public, max-age=300'); res.json(metadata()); });

  // ── dynamic client registration (RFC 7591) ───────────────────────────────────────────────────────────────────
  // Open to anyone, as the spec intends, but a client can only ever send a user back to a Claude callback: the
  // redirect URIs are checked against the allowlist, exactly. A public client (auth none) is accepted because PKCE
  // is mandatory on every code; a confidential one gets a secret shown once.
  app.post('/oauth/register', rateLimitStrict, express.json({ limit: '16kb' }), (req, res) => {
    noStore(res);
    const b = req.body || {};
    const uris = Array.isArray(b.redirect_uris) ? b.redirect_uris.map(String) : [];
    if (!uris.length || uris.length > 5) return oauthError(res, 400, 'invalid_redirect_uri', 'redirect_uris: 1-5 https URIs');
    for (const u of uris) if (!REDIRECT_ALLOWLIST.has(u)) return oauthError(res, 400, 'invalid_redirect_uri', `redirect_uri not allowed here: ${u.slice(0, 120)}`);
    const grants = Array.isArray(b.grant_types) && b.grant_types.length ? b.grant_types.map(String) : ['authorization_code'];
    if (grants.some(g => !['authorization_code', 'refresh_token'].includes(g))) return oauthError(res, 400, 'invalid_client_metadata', 'grant_types: authorization_code, refresh_token');
    const rts = Array.isArray(b.response_types) && b.response_types.length ? b.response_types.map(String) : ['code'];
    if (rts.some(r => r !== 'code')) return oauthError(res, 400, 'invalid_client_metadata', 'response_types: code');
    const method = b.token_endpoint_auth_method === undefined ? 'client_secret_basic' : String(b.token_endpoint_auth_method);
    if (!['none', 'client_secret_basic', 'client_secret_post'].includes(method)) return oauthError(res, 400, 'invalid_client_metadata', 'token_endpoint_auth_method: none, client_secret_basic or client_secret_post');
    if (db.prepare('SELECT COUNT(*) AS n FROM oauth_clients').get().n >= MAX_CLIENTS) {
      // Room is made from clients that never came back: registered over a day ago, never used.
      db.prepare('DELETE FROM oauth_clients WHERE last_used_at IS NULL AND created_at < ?').run(new Date(Date.now() - 86400000).toISOString());
      if (db.prepare('SELECT COUNT(*) AS n FROM oauth_clients').get().n >= MAX_CLIENTS) return oauthError(res, 429, 'temporarily_unavailable', 'too many registered clients; try later');
    }
    const clientId = 'dpc_' + rand(16);
    const secret = method === 'none' ? null : 'dps_' + rand(32);
    const name = String(b.client_name || '').replace(/[\u0000-\u001f\u007f]/g, '').trim().slice(0, 80);
    db.prepare('INSERT INTO oauth_clients (client_id, secret_hash, client_name, redirect_uris, auth_method, created_at, created_ip) VALUES (?, ?, ?, ?, ?, ?, ?)')
      .run(clientId, secret ? sha(secret) : null, name, JSON.stringify(uris), method, nowIso(), String(req.ip || ''));
    event('oauth_client_registered', null, { client_id: clientId, name, method, ip: req.ip });
    res.status(201).json({
      client_id: clientId, ...(secret ? { client_secret: secret, client_secret_expires_at: 0 } : {}), client_id_issued_at: nowSec(),
      client_name: name, redirect_uris: uris, grant_types: ['authorization_code', 'refresh_token'], response_types: ['code'],
      token_endpoint_auth_method: method, scope: DEFAULT_SCOPES.join(' '),
    });
  });

  // ── authorize ────────────────────────────────────────────────────────────────────────────────────────────────
  // The request is validated before anything is shown. A bad client or redirect_uri gets an error PAGE (never a
  // redirect: RFC 6749 §4.1.2.1); everything else wrong is sent back to the registered redirect_uri as an error.
  function clientOf(id) { return id ? db.prepare('SELECT * FROM oauth_clients WHERE client_id = ?').get(String(id)) : null; }
  function redirectWith(res, uri, params) {
    const u = new URL(uri);
    for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== null && v !== '') u.searchParams.set(k, String(v));
    noStore(res);
    res.redirect(302, u.toString());
  }
  app.get('/oauth/authorize', rateLimitStandard, (req, res) => {
    noStore(res);
    const q = req.query || {};
    const client = clientOf(q.client_id);
    if (!client) return errorPage(res, 400, 'Unknown client', 'This connector is not registered here. Remove it in Claude and add it again.');
    const uris = jsonList(client.redirect_uris);
    const redirect = q.redirect_uri === undefined ? (uris.length === 1 ? uris[0] : null) : String(q.redirect_uri);
    if (!redirect || !uris.includes(redirect) || !REDIRECT_ALLOWLIST.has(redirect)) return errorPage(res, 400, 'Redirect not registered', 'The connector asked to send you to an address it did not register. Nothing was done.');
    const state = q.state === undefined ? null : String(q.state).slice(0, 512);
    const back = (error, description) => redirectWith(res, redirect, { error, error_description: description, state });
    if (String(q.response_type || '') !== 'code') return back('unsupported_response_type', 'response_type must be code');
    if (q.code_challenge_method !== undefined && String(q.code_challenge_method) !== 'S256') return back('invalid_request', 'code_challenge_method must be S256');
    const challenge = String(q.code_challenge || '');
    if (!B64URL_43_128.test(challenge)) return back('invalid_request', 'code_challenge (S256) is required');
    const resource = q.resource === undefined ? RESOURCE : String(q.resource).replace(/\/+$/, '');
    if (resource !== RESOURCE) return back('invalid_target', `this server issues tokens for ${RESOURCE} only`);
    const t = tenant();
    if (!t) return back('temporarily_unavailable', 'Conduit is not registered here');
    const sc = parseScopes(q.scope, t);
    if (!sc.ok) return back('invalid_scope', sc.error);
    const requestId = 'dpa_' + rand(24);
    db.prepare('INSERT INTO oauth_authz (request_id, client_id, redirect_uri, scopes, state, code_challenge, resource, created_at, expires_at, ip) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)')
      .run(requestId, client.client_id, redirect, JSON.stringify(sc.scopes), state, challenge, resource, nowIso(), later(AUTHZ_TTL_SEC), String(req.ip || ''));
    db.prepare('UPDATE oauth_clients SET last_used_at = ? WHERE client_id = ?').run(nowIso(), client.client_id);
    res.set('Content-Type', 'text/html; charset=utf-8');
    res.send(authorizePage({ requestId, clientName: client.client_name || 'a connector', scopes: sc.scopes, resource, nonce: rand(16) }, res));
  });

  function authzOf(req, res, step) {
    const id = String((req.body || {}).request_id || '');
    const a = /^dpa_[A-Za-z0-9_-]{20,}$/.test(id) ? db.prepare('SELECT * FROM oauth_authz WHERE request_id = ?').get(id) : null;
    if (!a || a.expires_at <= nowIso()) { res.status(410).json({ error: 'expired', error_description: 'this sign-in request has expired; start again from Claude' }); return null; }
    if (a.step !== step) { res.status(409).json({ error: 'wrong_step', error_description: `this request is at step '${a.step}'` }); return null; }
    return a;
  }
  // Step 1: the owner's DemiPass login (username + password). Rate limited by IP like every login; five tries per request.
  app.post('/oauth/authorize/login', rateLimitLogin || rateLimitStrict, express.json({ limit: '8kb' }), async (req, res) => {
    noStore(res);
    const a = authzOf(req, res, 'login'); if (!a) return;
    const { username, password } = req.body || {};
    if (typeof username !== 'string' || typeof password !== 'string' || !username || !password) return res.status(400).json({ error: 'invalid_request', error_description: 'username and password' });
    if (a.login_tries >= LOGIN_TRIES_PER_REQUEST) { db.prepare('DELETE FROM oauth_authz WHERE request_id = ?').run(a.request_id); return res.status(429).json({ error: 'too_many_tries', error_description: 'too many wrong sign-ins; start again from Claude' }); }
    db.prepare('UPDATE oauth_authz SET login_tries = login_tries + 1 WHERE request_id = ?').run(a.request_id);
    const wallet = db.prepare('SELECT * FROM identity_wallets WHERE username = ?').get(username.toLowerCase().trim());
    const okPw = wallet ? await checkPassword(wallet, password) : false;
    if (okPw === null) return res.status(503).json({ error: 'temporarily_unavailable', error_description: 'password check unavailable; try again' });
    if (!okPw || wallet.status !== 'active') {
      sec('oauth_login_failed', 'warn', { ip: req.ip, username: username.slice(0, 40), request_id: a.request_id });
      return res.status(401).json({ error: 'invalid_login', error_description: 'wrong username or password', tries_left: LOGIN_TRIES_PER_REQUEST - a.login_tries - 1 });
    }
    // An agent wallet (one a fleet created or that joined one) is not a person: the seat's owner signs in, never a seat.
    if (S().personFor(wallet.did) !== wallet.did) return res.status(403).json({ error: 'not_a_person', error_description: 'sign in with the account that owns the fleet, not with an agent' });
    if (!wallet.pin_hash) return res.status(403).json({ error: 'pin_required', error_description: 'set a vault PIN in the DemiPass app first; the connector approval takes your PIN' });
    db.prepare("UPDATE oauth_authz SET owner_did = ?, step = 'pin' WHERE request_id = ?").run(wallet.did, a.request_id);
    res.json({ ok: true, next: 'pin', username: wallet.username });
  });
  // Step 2: the PIN. tryPin counts every miss on the wallet (lockout after 5, doubling, hard lock), so the browser
  // cannot guess a PIN any faster than the app could.
  app.post('/oauth/authorize/pin', rateLimitStrict, express.json({ limit: '8kb' }), (req, res) => {
    noStore(res);
    const a = authzOf(req, res, 'pin'); if (!a) return;
    const pin = String((req.body || {}).pin ?? '');
    if (!/^\d{4,8}$/.test(pin)) return res.status(400).json({ error: 'invalid_request', error_description: 'pin: 4 to 8 digits' });
    const wallet = db.prepare('SELECT * FROM identity_wallets WHERE did = ?').get(a.owner_did);
    if (!wallet || wallet.status !== 'active') return res.status(410).json({ error: 'expired', error_description: 'start again from Claude' });
    const locked = pinLocked(wallet);
    if (locked > 0) return res.status(429).json({ error: 'pin_locked', error_description: `PIN locked; try again in ${Math.ceil(locked / 60)} min`, locked_for_seconds: locked });
    const r = checkPin(wallet.did, pin, req, 'oauth-seat');
    if (!r.ok) return res.status(r.status || 403).json({ ...(r.body || {}), error: 'wrong_pin', error_description: (r.body && r.body.error) || 'incorrect PIN' });
    db.prepare("UPDATE oauth_authz SET step = 'decide' WHERE request_id = ?").run(a.request_id);
    const t = tenant();
    const seats = seatsOf(wallet.did).map(s => {
      const consent = t ? seatConsent(s.member_did, wallet.did, t) : null;
      return { handle: s.handle, fleet: s.fleet_slug, consent_ok: Boolean(consent), daily_cap_dd: consent ? consent.daily_cap_dd : null,
        delegated: t ? jsonList(a.scopes).filter(sc => liveDelegation(t, sc, wallet.did, s.member_did)) : [] };
    });
    res.json({ ok: true, next: 'decide', seats, scopes: jsonList(a.scopes),
      ...(seats.length ? {} : { note: `no seat yet: create a fleet agent whose handle starts with "${SEAT_PREFIX}" (Fleet → agents), then approve its consent to pay Conduit on your phone` }) });
  });
  // Step 3: approve (seat + scopes) or deny. Approving grants the owner's use-only delegations and issues the code.
  app.post('/oauth/authorize/decide', rateLimitStrict, express.json({ limit: '8kb' }), (req, res) => {
    noStore(res);
    const a = authzOf(req, res, 'decide'); if (!a) return;
    const b = req.body || {};
    const finish = (params) => { db.prepare("UPDATE oauth_authz SET step = 'done' WHERE request_id = ?").run(a.request_id); const u = new URL(a.redirect_uri); for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== null && v !== '') u.searchParams.set(k, String(v)); res.json({ ok: true, redirect: u.toString() }); };
    if (b.approve !== true) { event('oauth_denied', a.owner_did, { client_id: a.client_id }); return finish({ error: 'access_denied', error_description: 'the owner declined', state: a.state }); }
    const owner = walletActive(a.owner_did);
    if (!owner) return res.status(410).json({ error: 'expired', error_description: 'start again from Claude' });
    const t = tenant();
    if (!t) return res.status(503).json({ error: 'temporarily_unavailable', error_description: 'Conduit is not registered here' });
    const handle = String(b.seat || '').toLowerCase();
    const seat = isSeatHandle(handle) ? seatRow(owner.did, handle) : null;
    if (!seat) return res.status(400).json({ error: 'invalid_request', error_description: `seat: one of your fleet's seat-… agents` });
    if (!walletActive(seat.member_did)) return res.status(409).json({ error: 'seat_inactive', error_description: `@${handle} is not an active wallet` });
    const asked = jsonList(a.scopes);
    const chosen = Array.isArray(b.scopes) ? b.scopes.map(String) : asked;
    if (!chosen.length || chosen.some(s => !asked.includes(s))) return res.status(400).json({ error: 'invalid_scope', error_description: `scopes: a non-empty subset of ${asked.join(' ')}` });
    const consent = seatConsent(seat.member_did, owner.did, t);
    if (!consent) return res.status(409).json({ error: 'consent_required', error_description: `@${handle} has no live consent to pay Conduit approved by you. It is filed by the seat (POST /api/services/consent {service:"conduit", daily_cap_dd:500}) and approved on your phone; then come back.` });
    const grantId = db.transaction(() => {
      // The owner's use-only delegation of each granted scope to the seat (what POST /api/services/delegate does from
      // the owner's session): standard depth, renewed to the grant's horizon, the previous active row replaced.
      for (const scope of chosen) {
        const cur = liveDelegation(t, scope, owner.did, seat.member_did);
        if (cur && cur.expires_at && new Date(cur.expires_at).getTime() > Date.now() + DELEGATION_TTL_SEC * 1000 / 2) continue;
        db.prepare("UPDATE service_delegations SET status = 'revoked', revoked_at = ? WHERE tenant_id = ? AND scope = ? AND owner_did = ? AND delegate_did = ? AND status = 'active'").run(nowIso(), t.id, scope, owner.did, seat.member_did);
        db.prepare('INSERT INTO service_delegations (tenant_id, scope, owner_did, delegate_did, granted_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)').run(t.id, scope, owner.did, seat.member_did, nowIso(), later(DELEGATION_TTL_SEC));
      }
      // One live grant per (client, seat): a re-authorization replaces the old one and ends its tokens.
      for (const old of db.prepare("SELECT id FROM oauth_grants WHERE status = 'active' AND client_id = ? AND seat_did = ?").all(a.client_id, seat.member_did)) revokeGrant(old.id, 're-authorized');
      return Number(db.prepare('INSERT INTO oauth_grants (client_id, owner_did, seat_did, seat_handle, fleet_slug, scopes, resource, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
        .run(a.client_id, owner.did, seat.member_did, handle, seat.fleet_slug, JSON.stringify(chosen), a.resource, nowIso()).lastInsertRowid);
    })();
    const code = 'dpz_' + rand(32);
    db.prepare('INSERT INTO oauth_codes (code_hash, grant_id, client_id, redirect_uri, code_challenge, expires_at) VALUES (?, ?, ?, ?, ?, ?)').run(sha(code), grantId, a.client_id, a.redirect_uri, a.code_challenge, later(CODE_TTL_SEC));
    event('oauth_granted', owner.did, { grant_id: grantId, client_id: a.client_id, seat: handle, scopes: chosen, resource: a.resource, ip: req.ip });
    sec('oauth_seat_granted', 'warn', { caller_did: owner.did, ip: req.ip, context: { seat: handle, scopes: chosen, client_id: a.client_id } });
    finish({ code, state: a.state, iss: BASE });
  });

  // ── token ────────────────────────────────────────────────────────────────────────────────────────────────────
  // Client authentication: Basic, body (client_secret_post) or none for a public client. A wrong secret is
  // invalid_client (401 + WWW-Authenticate: Basic); a confidential client without its secret too.
  function authenticateClient(req) {
    let id = null, secret = null;
    const h = String(req.headers.authorization || '');
    if (/^Basic\s+/i.test(h)) {
      try { const [u, ...p] = Buffer.from(h.replace(/^Basic\s+/i, ''), 'base64').toString('utf8').split(':'); id = decodeURIComponent(u); secret = decodeURIComponent(p.join(':')); } catch (_) { return { ok: false }; }
    } else { id = (req.body || {}).client_id; secret = (req.body || {}).client_secret; }
    const c = clientOf(id);
    if (!c) return { ok: false };
    if (c.auth_method === 'none') { if (secret) return { ok: false }; return { ok: true, client: c }; }
    if (!secret || !c.secret_hash || !safeEq(sha(secret), c.secret_hash)) return { ok: false };
    return { ok: true, client: c };
  }
  const tokenReply = (res, g, good) => {
    const acc = mintAccess(g, good);
    const refresh = mintRefresh(g.id);
    noStore(res);
    res.json({ access_token: acc.token, token_type: 'Bearer', expires_in: Math.max(1, acc.exp - nowSec()), refresh_token: refresh, scope: acc.scopes.join(' '),
      seat: g.seat_handle, resource: g.resource });
  };
  app.post('/oauth/token', rateLimitStrict, formOrJson, express.json({ limit: '16kb' }), (req, res) => {
    noStore(res);
    const b = req.body || {};
    const auth = authenticateClient(req);
    if (!auth.ok) { res.set('WWW-Authenticate', 'Basic realm="oauth"'); return oauthError(res, 401, 'invalid_client', 'client authentication failed'); }
    const client = auth.client;
    db.prepare('UPDATE oauth_clients SET last_used_at = ? WHERE client_id = ?').run(nowIso(), client.client_id);
    const grantType = String(b.grant_type || '');
    if (b.resource !== undefined && String(b.resource).replace(/\/+$/, '') !== RESOURCE) return oauthError(res, 400, 'invalid_target', `tokens here are for ${RESOURCE}`);

    if (grantType === 'authorization_code') {
      const code = String(b.code || '');
      const row = /^dpz_[A-Za-z0-9_-]{20,}$/.test(code) ? db.prepare('SELECT * FROM oauth_codes WHERE code_hash = ?').get(sha(code)) : null;
      if (!row || row.client_id !== client.client_id) return oauthError(res, 400, 'invalid_grant', 'unknown code');
      if (row.used_at) {
        // A code presented twice: someone else may hold it. Everything the first exchange issued dies (OAuth 2.1 §4.1.2).
        revokeGrant(row.grant_id, 'authorization code replayed');
        sec('oauth_code_replay', 'alert', { ip: req.ip, client_id: client.client_id, grant_id: row.grant_id });
        return oauthError(res, 400, 'invalid_grant', 'code already used; the grant was revoked');
      }
      if (row.expires_at <= nowIso()) return oauthError(res, 400, 'invalid_grant', 'code expired');
      if (b.redirect_uri !== undefined && String(b.redirect_uri) !== row.redirect_uri) return oauthError(res, 400, 'invalid_grant', 'redirect_uri does not match');
      const verifier = String(b.code_verifier || '');
      if (!B64URL_43_128.test(verifier) || !safeEq(crypto.createHash('sha256').update(verifier).digest('base64url'), row.code_challenge)) return oauthError(res, 400, 'invalid_grant', 'PKCE verification failed');
      db.prepare('UPDATE oauth_codes SET used_at = ? WHERE code_hash = ?').run(nowIso(), row.code_hash);
      const g = db.prepare('SELECT * FROM oauth_grants WHERE id = ?').get(row.grant_id);
      const good = g ? grantStillGood(g) : { ok: false, error: 'no grant', code: 'invalid_grant' };
      if (!good.ok) return oauthError(res, 400, good.code, good.error);
      event('oauth_token_issued', g.owner_did, { grant_id: g.id, seat: g.seat_handle, via: 'code', client_id: client.client_id });
      return tokenReply(res, g, good);
    }
    if (grantType === 'refresh_token') {
      const raw = String(b.refresh_token || '');
      const row = /^dpo_[A-Za-z0-9_-]{20,}$/.test(raw) ? db.prepare('SELECT * FROM oauth_refresh WHERE token_hash = ?').get(sha(raw)) : null;
      if (!row) return oauthError(res, 400, 'invalid_grant', 'unknown refresh token');
      const g = db.prepare('SELECT * FROM oauth_grants WHERE id = ?').get(row.grant_id);
      if (!g || g.client_id !== client.client_id) return oauthError(res, 400, 'invalid_grant', 'refresh token is not this client\'s');
      if (row.used_at) {
        // Rotation: a used refresh token presented again means a copy exists. The whole grant ends (OAuth 2.1 §4.3.1).
        revokeGrant(g.id, 'refresh token replayed');
        sec('oauth_refresh_replay', 'alert', { ip: req.ip, client_id: client.client_id, grant_id: g.id });
        return oauthError(res, 400, 'invalid_grant', 'refresh token already used; the grant was revoked');
      }
      if (row.expires_at <= nowIso()) return oauthError(res, 400, 'invalid_grant', 'refresh token expired');
      if (b.scope !== undefined) {
        const want = String(b.scope).split(/[\s,]+/).filter(Boolean), have = jsonList(g.scopes);
        if (!want.length || want.some(s => !have.includes(s))) return oauthError(res, 400, 'invalid_scope', 'scope: a subset of what was granted');
      }
      const good = grantStillGood(g);
      if (!good.ok) { revokeGrant(g.id, good.error); return oauthError(res, 400, good.code, good.error); }
      const acc = mintAccess(g, good);
      const next = mintRefresh(g.id);
      db.prepare('UPDATE oauth_refresh SET used_at = ?, rotated_to = ? WHERE token_hash = ?').run(nowIso(), sha(next), row.token_hash);
      event('oauth_token_issued', g.owner_did, { grant_id: g.id, seat: g.seat_handle, via: 'refresh', client_id: client.client_id });
      return res.json({ access_token: acc.token, token_type: 'Bearer', expires_in: Math.max(1, acc.exp - nowSec()), refresh_token: next, scope: acc.scopes.join(' '), seat: g.seat_handle, resource: g.resource });
    }
    return oauthError(res, 400, 'unsupported_grant_type', 'grant_type: authorization_code or refresh_token');
  });

  // RFC 7009: revoke a refresh token (the grant and its access tokens go with it) or an access token (its grant too:
  // a connector that revokes is disconnecting). Always 200 for a token this client does not hold — nothing is learned.
  app.post('/oauth/revoke', rateLimitStrict, formOrJson, express.json({ limit: '16kb' }), (req, res) => {
    noStore(res);
    const auth = authenticateClient(req);
    if (!auth.ok) { res.set('WWW-Authenticate', 'Basic realm="oauth"'); return oauthError(res, 401, 'invalid_client', 'client authentication failed'); }
    const raw = String((req.body || {}).token || '');
    let gId = null;
    if (/^dpo_/.test(raw)) { const r = db.prepare('SELECT grant_id FROM oauth_refresh WHERE token_hash = ?').get(sha(raw)); gId = r ? r.grant_id : null; }
    else if (raw.split('.').length === 3) { try { const d = JSON.parse(Buffer.from(raw.split('.')[1], 'base64url').toString('utf8')); const r = d.jti ? db.prepare('SELECT grant_id FROM oauth_access WHERE jti = ?').get(d.jti) : null; gId = r ? r.grant_id : null; } catch (_) {} }
    if (gId) { const g = db.prepare('SELECT client_id FROM oauth_grants WHERE id = ?').get(gId); if (g && g.client_id === auth.client.client_id) revokeGrant(gId, 'revoked by the connector'); }
    res.status(200).json({ ok: true });
  });

  // ── the owner's view (own session): what seats are connected where, and the kill switch ──────────────────────
  function ownerAuth(req, res) {
    const a = getBearerIdentity(req);
    if (!a.ok) { res.status(a.status || 401).json({ error: a.error, ...(a.code ? { code: a.code } : {}) }); return null; }
    if (a.silicon || (a.decoded && (a.decoded.wrk || a.decoded.auth_method === 'fleet_owner_mint' || a.decoded.auth_method === 'oauth_seat'))) { res.status(403).json({ error: 'the owner\'s own session' }); return null; }
    return a;
  }
  const grantView = (g) => ({ id: g.id, seat: g.seat_handle, fleet: g.fleet_slug, scopes: jsonList(g.scopes), resource: g.resource, status: g.status,
    client: (db.prepare('SELECT client_name FROM oauth_clients WHERE client_id = ?').get(g.client_id) || {}).client_name || g.client_id,
    created_at: g.created_at, last_used_at: g.last_used_at, revoked_at: g.revoked_at, revoked_why: g.revoked_why,
    live_access_tokens: db.prepare('SELECT COUNT(*) AS n FROM oauth_access a JOIN issued_tokens i ON i.jti = a.jti WHERE a.grant_id = ? AND a.expires_at > ? AND i.revoked = 0').get(g.id, nowSec()).n });
  app.get('/api/oauth/grants', rateLimitStandard, (req, res) => {
    const a = ownerAuth(req, res); if (!a) return;
    res.json({ ok: true, grants: db.prepare('SELECT * FROM oauth_grants WHERE owner_did = ? ORDER BY id DESC LIMIT 100').all(a.did).map(grantView), resource: RESOURCE, issuer: BASE });
  });
  app.post('/api/oauth/grants/:id/revoke', rateLimitStandard, (req, res) => {
    const a = ownerAuth(req, res); if (!a) return;
    const id = Number(req.params.id);
    const g = Number.isInteger(id) && id > 0 ? db.prepare('SELECT * FROM oauth_grants WHERE id = ? AND owner_did = ?').get(id, a.did) : null;
    if (!g) return res.status(404).json({ error: 'no grant of yours with that id' });
    if (g.status !== 'active') return res.status(409).json({ error: `already ${g.status}` });
    revokeGrant(id, 'revoked by the owner');
    res.json({ ok: true, revoked: true, grant: grantView(db.prepare('SELECT * FROM oauth_grants WHERE id = ?').get(id)) });
  });

  // ── pages ────────────────────────────────────────────────────────────────────────────────────────────────────
  const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  function errorPage(res, status, title, text) {
    noStore(res);
    res.set('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'");
    res.status(status).set('Content-Type', 'text/html; charset=utf-8').send(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>DemiPass</title>${STYLE}</head><body><main class="card"><h1>${esc(title)}</h1><p>${esc(text)}</p></main></body></html>`);
  }
  const STYLE = `<style>:root{color-scheme:light dark;--bg:#0d0d0d;--fg:#e8e4dc;--mut:#8a857c;--acc:#5b9bd5;--bad:#d9534f;--card:#17171a;--bd:#2a2a2e}@media (prefers-color-scheme: light){:root{--bg:#f6f4ef;--fg:#1a1a1a;--mut:#5c5853;--card:#fff;--bd:#dcd8d0}}
body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.45 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;display:flex;min-height:100vh;align-items:center;justify-content:center;padding:16px;box-sizing:border-box}
.card{background:var(--card);border:1px solid var(--bd);border-radius:12px;padding:24px;width:100%;max-width:440px}h1{font-size:20px;margin:0 0 6px}p{margin:8px 0;color:var(--mut)}label{display:block;margin:12px 0 4px;font-size:14px}
input,select{width:100%;box-sizing:border-box;padding:10px;border:1px solid var(--bd);border-radius:8px;background:transparent;color:var(--fg);font:inherit}button{margin-top:16px;width:100%;padding:11px;border:0;border-radius:8px;background:var(--acc);color:#0d0d0d;font:inherit;font-weight:600;cursor:pointer}
button.ghost{background:transparent;color:var(--mut);border:1px solid var(--bd)}.err{color:var(--bad);min-height:1.2em;font-size:14px}.hid{display:none}ul{padding-left:18px}li{margin:4px 0}code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:14px}.ok{color:var(--acc)}</style>`;
  function authorizePage({ requestId, clientName, scopes, resource, nonce }, res) {
    res.set('Content-Security-Policy', `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`);
    res.set('Referrer-Policy', 'no-referrer');
    res.set('X-Frame-Options', 'DENY');
    const data = JSON.stringify({ requestId, clientName, scopes, resource });
    return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Connect a seat — DemiPass</title>${STYLE}</head><body>
<main class="card">
  <h1>Connect ${esc(clientName)} to Conduit</h1>
  <p>Sign in to DemiPass as the fleet owner. You will then pick which seat the connector acts as and what it may do. The connector receives only tokens for <code>${esc(resource)}</code>; nothing from your vault.</p>
  <section id="s-login">
    <form id="f-login" autocomplete="on">
      <label for="u">DemiPass username</label><input id="u" name="username" autocomplete="username" required>
      <label for="p">Password</label><input id="p" name="password" type="password" autocomplete="current-password" required>
      <div class="err" id="e-login"></div>
      <button type="submit">Sign in</button>
    </form>
  </section>
  <section id="s-pin" class="hid">
    <form id="f-pin">
      <p>Signed in as <strong id="who"></strong>.</p>
      <label for="pin">Vault PIN</label><input id="pin" name="pin" type="password" inputmode="numeric" pattern="[0-9]{4,8}" autocomplete="one-time-code" required>
      <div class="err" id="e-pin"></div>
      <button type="submit">Continue</button>
    </form>
  </section>
  <section id="s-decide" class="hid">
    <form id="f-decide">
      <label for="seat">Seat (the identity this connector acts as)</label><select id="seat" name="seat" required></select>
      <p id="seatnote"></p>
      <p>Allow on Conduit:</p><ul id="scopes"></ul>
      <div class="err" id="e-decide"></div>
      <button type="submit" id="approve">Approve</button>
      <button type="button" class="ghost" id="deny">Deny</button>
    </form>
  </section>
  <section id="s-done" class="hid"><p id="donetext">Returning to the connector…</p></section>
</main>
<script nonce="${nonce}">
(function(){
  var D=${data};var $=function(id){return document.getElementById(id)};var show=function(id){['s-login','s-pin','s-decide','s-done'].forEach(function(s){$(s).className=s===id?'':'hid'})};
  var seats=[];
  function post(path,body){return fetch(path,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(Object.assign({request_id:D.requestId},body))}).then(function(r){return r.json().then(function(j){return {status:r.status,body:j}})})}
  function finish(url,text){show('s-done');if(text)$('donetext').textContent=text;if(url)location.replace(url)}
  $('f-login').addEventListener('submit',function(ev){ev.preventDefault();$('e-login').textContent='';post('/oauth/authorize/login',{username:$('u').value,password:$('p').value}).then(function(r){
    $('p').value='';if(r.status!==200){$('e-login').textContent=r.body.error_description||r.body.error||'sign-in failed';if(r.status===410||r.status===429)finish(null,r.body.error_description);return}
    $('who').textContent=r.body.username;show('s-pin');$('pin').focus()})});
  $('f-pin').addEventListener('submit',function(ev){ev.preventDefault();$('e-pin').textContent='';post('/oauth/authorize/pin',{pin:$('pin').value}).then(function(r){
    $('pin').value='';if(r.status!==200){$('e-pin').textContent=r.body.error_description||r.body.error||'PIN refused';if(r.status===410)finish(null,r.body.error_description);return}
    seats=r.body.seats||[];var sel=$('seat');sel.innerHTML='';seats.forEach(function(s){var o=document.createElement('option');o.value=s.handle;o.textContent='@'+s.handle+(s.consent_ok?'':' (no Conduit consent yet)');sel.appendChild(o)});
    if(!seats.length){$('seatnote').textContent=r.body.note||'no seat available';$('approve').disabled=true}
    var ul=$('scopes');ul.innerHTML='';(r.body.scopes||[]).forEach(function(sc){var li=document.createElement('li');var cb=document.createElement('input');cb.type='checkbox';cb.checked=true;cb.value=sc;cb.id='sc-'+sc;var lb=document.createElement('label');lb.htmlFor=cb.id;lb.style.display='inline';lb.textContent=' '+sc+(sc==='read'?' (read the seat\\'s inbox, 1 DD each)':sc==='post'?' (post messages, 1 DD per recipient)':sc==='ack'?' (acknowledge messages, 1 DD)':'');li.appendChild(cb);li.appendChild(lb);ul.appendChild(li)});
    sel.addEventListener('change',note);note();show('s-decide')})});
  function note(){var s=seats.filter(function(x){return x.handle===$('seat').value})[0];if(!s)return;$('seatnote').textContent=s.consent_ok?('Consent to pay Conduit: up to '+s.daily_cap_dd+' DD a day (the hop cap). Charges land on @'+s.handle+'.'):('@'+s.handle+' has not been allowed to pay Conduit yet: approve its consent card on your phone first.');$('approve').disabled=!s.consent_ok}
  $('f-decide').addEventListener('submit',function(ev){ev.preventDefault();$('e-decide').textContent='';var sc=[].slice.call(document.querySelectorAll('#scopes input:checked')).map(function(c){return c.value});
    post('/oauth/authorize/decide',{approve:true,seat:$('seat').value,scopes:sc}).then(function(r){if(r.status!==200){$('e-decide').textContent=r.body.error_description||r.body.error||'refused';return}finish(r.body.redirect,'Approved. Returning to the connector…')})});
  $('deny').addEventListener('click',function(){post('/oauth/authorize/decide',{approve:false}).then(function(r){finish(r.body&&r.body.redirect,'Declined. Returning to the connector…')})});
})();
</script></body></html>`;
  }

  sweep();
  return { revokeGrant, revokeForDelegation, revokeForConsent, grantStillGood, seatsOf, metadata, RESOURCE, BASE, ACCESS_TTL_SEC, REFRESH_TTL_SEC };
};
module.exports.ACCESS_TTL_SEC = ACCESS_TTL_SEC;
module.exports.REFRESH_TTL_SEC = REFRESH_TTL_SEC;
module.exports.DEFAULT_REDIRECTS = DEFAULT_REDIRECTS;
