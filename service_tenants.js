'use strict';
// ── Service tenants: DemiPass as the identity and metering layer for agent services (docs/service-tenants.md) ────────
// A tenant is a service (FLEETGATE, Conduit, …) with its own DemiPass wallet. Callers reach it with SERVICE TOKENS:
// ordinary DemiPass tokens locked to the caller's wallet and to one tenant (`aud: svc:<slug>`, `iss: demipass-svc`).
// Every other DemiPass route checks `iss: civitasvox` (identity.verifyToken), so a service token a tenant receives opens
// nothing at DemiPass itself: the tenant can verify it and charge against it, never spend it as the caller.
//
//   tenant side (Bearer = the tenant wallet's own token)
//     POST /api/services/verify   {token, action, call?, approval_id?, approval_code?}
//          → {wallet, token_id, scope, depth, via, principal?, price, cap_dd, spent_dd, expires_at}
//            Never the human: no username, email or owner DID. A delegated call carries a pairwise principal id
//            (stable per tenant, different at every tenant). Elevated actions answer 202 approval_pending first.
//     POST /api/services/charge   {action, cost_dd, token_id, idempotency_key}
//          → debits the caller, credits the tenant, atomically; 402 when the caller cannot cover it (pass it on).
//     PUT  /api/services/:slug/actions  {actions:[{action, scope, measured_cost_dd, max_cost_dd?, depth?, open?}]}
//   caller side (Bearer = the caller's own token)
//     POST /api/services/token    {service, ttl?, scopes?, cap_dd?}  → a service token for that tenant
//     POST /api/services/token/revoke {token_id}
//     POST /api/services/delegate {service, scope, delegate_did, expires_in?}   use-only, agents only
//     POST /api/services/delegations/:id/revoke
//     GET  /api/services/delegations, GET /api/services/charges
//   public
//     GET  /api/services, GET /api/services/:slug  (actions with cost, margin, price)
//     POST /api/services/receipts/verify {receipt, sig}
//   registration
//     POST /api/services/register {slug, name, service_did?}
//
// Price: the tenant declares each action's measured cost; DemiPass adds the platform margin (SERVICE_MARGIN_PCT, in
// code so a change is a reviewed PR). A charge posts this call's cost (≤ the action's max_cost_dd) and bills
// cost + margin. Every charge row carries the caller's token id, like mail and /use do.
// Depth: an action is standard, elevated or critical, set by the tenant. Elevated and critical actions take an
// approval on the phone of the person whose authority is used (the delegating owner, or the caller itself when it
// acts on its own account), through the same approval requests elevated secrets use (use_approvals.js). Lowering an
// action's depth takes the tenant owner, in their own session, with the PIN.

const crypto = require('crypto');

// Platform margin over a tenant's measured cost. Aaron's order left the number blank; 20 is a placeholder pending
// his figure — change it here (one line, reviewed PR). Charges record the margin they used.
const SERVICE_MARGIN_PCT = 20;
const SVC_ISS = 'demipass-svc';
const SLUG_RE = /^[a-z][a-z0-9-]{1,30}$/;
const ACTION_RE = /^[a-z][a-z0-9_.-]{0,40}$/;
const IDEM_RE = /^[A-Za-z0-9._:-]{8,100}$/;
const DEPTHS = ['standard', 'elevated', 'critical'];
const MAX_COST_DD = 100000;            // one call, before margin ($100)
const TOKEN_TTL_DEFAULT_SEC = 3600;
const TOKEN_TTL_MAX_SEC = 24 * 3600;
const TOKEN_CAP_DEFAULT_DD = 500;
const TOKEN_CAP_MAX_DD = 1000000;
const RECEIPT_VERSION = 1;

const priceOf = (costDd, marginPct = SERVICE_MARGIN_PCT) => costDd + Math.ceil(costDd * marginPct / 100);

module.exports = function registerServiceTenants(deps) {
  const { app, db, identity, billing, getBearerIdentity, gateFresh, gateMissing, spendSingleUse, gateSession,
          logSecurityEvent, rateLimitStandard, approvals, masterKey } = deps;
  const ledger = deps.ledger || (() => { try { return require('./dd_ledger'); } catch (_) { return null; } })();

  // ── schema ─────────────────────────────────────────────────────────────────────────────────────────────────────
  db.exec(`CREATE TABLE IF NOT EXISTS service_tenants (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    slug TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    service_did TEXT NOT NULL UNIQUE,     -- the tenant's wallet: authenticates its calls, receives its charges
    owner_did TEXT NOT NULL,              -- the person who controls it (holds its closed scopes; lowers depth)
    status TEXT NOT NULL DEFAULT 'active',
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL
  )`);
  db.exec(`CREATE TABLE IF NOT EXISTS service_actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id INTEGER NOT NULL,
    action TEXT NOT NULL,
    scope TEXT NOT NULL,
    measured_cost_dd INTEGER NOT NULL,
    max_cost_dd INTEGER NOT NULL,
    depth TEXT NOT NULL DEFAULT 'standard',
    open INTEGER NOT NULL DEFAULT 1,      -- 1: any wallet on its own account; 0: the owner and its delegates only
    status TEXT NOT NULL DEFAULT 'active',
    updated_at TEXT NOT NULL,
    UNIQUE (tenant_id, action)
  )`);
  // A tenant may charge only a token it has verified (and only while that token lives): no charging wallets that never
  // called it. One row per (tenant, token).
  db.exec(`CREATE TABLE IF NOT EXISTS service_verifications (
    tenant_id INTEGER NOT NULL,
    token_jti TEXT NOT NULL,
    did TEXT NOT NULL,
    iat INTEGER, exp INTEGER NOT NULL,
    auth_method TEXT, fleet TEXT,
    cap_dd INTEGER NOT NULL,
    delegation_id INTEGER,
    first_at TEXT NOT NULL, last_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, token_jti)
  )`);
  db.exec(`CREATE TABLE IF NOT EXISTS service_charges (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    charge_id TEXT NOT NULL UNIQUE,
    tenant_id INTEGER NOT NULL,
    payer_did TEXT NOT NULL,
    payee_did TEXT NOT NULL,
    action TEXT NOT NULL,
    cost_dd INTEGER NOT NULL,
    margin_pct INTEGER NOT NULL,
    dd INTEGER NOT NULL,
    token_jti TEXT NOT NULL,
    delegation_id INTEGER,
    idempotency_key TEXT NOT NULL,
    receipt TEXT NOT NULL,
    sig TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE (tenant_id, idempotency_key)
  )`);
  db.exec('CREATE INDEX IF NOT EXISTS idx_svc_charges_payer ON service_charges(payer_did, id)');
  db.exec('CREATE INDEX IF NOT EXISTS idx_svc_charges_token ON service_charges(token_jti)');
  db.exec(`CREATE TABLE IF NOT EXISTS service_delegations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id INTEGER NOT NULL,
    scope TEXT NOT NULL,
    owner_did TEXT NOT NULL,
    delegate_did TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    granted_at TEXT NOT NULL,
    expires_at TEXT,
    revoked_at TEXT
  )`);
  db.exec('CREATE INDEX IF NOT EXISTS idx_svc_deleg_delegate ON service_delegations(delegate_did, tenant_id, scope, status)');

  // ── keys ───────────────────────────────────────────────────────────────────────────────────────────────────────
  // Receipts are signed by the meter's key (same issuer did:key as /api/meter receipts), pairwise principals by an
  // HMAC key of their own. Both derive from IDENTITY_MASTER_KEY; without it nothing is signed or charged (503).
  const meterKey = require('./meter').deriveSigningKey(masterKey);
  const issuer = meterKey ? identity.publicKeyToDID(meterKey.publicKeyDer) : null;
  const pairwiseKey = masterKey ? Buffer.from(crypto.hkdfSync('sha256', Buffer.from(String(masterKey)), Buffer.from('dustforge-services'),
    Buffer.from('pairwise-principal-v1'), 32)) : null;
  const principalId = (tenant, did) => pairwiseKey
    ? 'pp_' + crypto.createHmac('sha256', pairwiseKey).update(`${tenant.slug}\n${did}`).digest('base64url').slice(0, 22) : null;

  // ── helpers ────────────────────────────────────────────────────────────────────────────────────────────────────
  const nowIso = () => new Date().toISOString();
  const nowSec = () => Math.floor(Date.now() / 1000);
  const isAgentToken = (auth) => Boolean(auth.silicon || (auth.decoded && (auth.decoded.wrk || auth.decoded.auth_method === 'fleet_owner_mint')));
  const tenantBySlug = (slug) => db.prepare("SELECT * FROM service_tenants WHERE slug = ? AND status = 'active'").get(String(slug || ''));
  const tenantByDid = (did) => db.prepare("SELECT * FROM service_tenants WHERE service_did = ? AND status = 'active'").get(did);
  const actionOf = (tenant, action) => db.prepare("SELECT * FROM service_actions WHERE tenant_id = ? AND action = ? AND status = 'active'").get(tenant.id, String(action || ''));
  const scopesOf = (tenant) => db.prepare("SELECT DISTINCT scope FROM service_actions WHERE tenant_id = ? AND status = 'active'").all(tenant.id).map(r => r.scope);
  const isAgentWallet = (did) => Boolean(db.prepare("SELECT 1 FROM fleet_silicons WHERE member_did = ? AND status = 'active'").get(did));
  // A silicon the owner's own fleet created (consented, owned outright): same test as /api/blindkey/delegate.
  const ownAgent = (ownerDid, did) => Boolean(db.prepare(`SELECT 1 FROM fleets f JOIN fleet_silicons s ON s.fleet_id = f.id
      WHERE f.owner_did = ? AND f.status = 'active' AND s.member_did = ? AND s.status = 'active' AND s.created_by_fleet = 1
      AND COALESCE(s.joined_via, 'owner') != 'network'`).get(ownerDid, did));
  const fleetOwnerOf = (did) => (db.prepare(`SELECT f.owner_did FROM fleets f JOIN fleet_silicons s ON s.fleet_id = f.id
      WHERE s.member_did = ? AND s.status = 'active' AND s.created_by_fleet = 1 AND f.status = 'active' LIMIT 1`).get(did) || {}).owner_did || null;
  function actionView(a) {
    return { action: a.action, scope: a.scope, depth: a.depth, open: Boolean(a.open), measured_cost_dd: a.measured_cost_dd,
      max_cost_dd: a.max_cost_dd, margin_pct: SERVICE_MARGIN_PCT, price_dd: priceOf(a.measured_cost_dd), max_price_dd: priceOf(a.max_cost_dd) };
  }
  function tenantView(t) {
    const actions = db.prepare("SELECT * FROM service_actions WHERE tenant_id = ? AND status = 'active' ORDER BY action").all(t.id);
    return { slug: t.slug, name: t.name, service_did: t.service_did, audience: 'svc:' + t.slug, margin_pct: SERVICE_MARGIN_PCT,
      actions: actions.map(actionView) };
  }
  function event(type, actor, detail) {
    try { db.prepare('INSERT INTO blindkey_events (event_type, actor, secret_id, context_name, detail) VALUES (?, ?, ?, ?, ?)').run(type, actor, null, 'service', JSON.stringify(detail)); } catch (_) {}
  }

  // The bearer as a wallet's OWN token (standard civitasvox JWT). Old `silicon:` tokens act as their carbon and worker
  // tokens share their parent's DID, so neither is locked to the wallet that would pay: refused here.
  function walletAuth(req, res, { minScope = 'transact' } = {}) {
    const auth = getBearerIdentity(req);
    if (!auth.ok) { res.status(auth.status || 401).json({ error: auth.error }); return null; }
    if (auth.silicon || (auth.decoded && (auth.decoded.wrk || auth.decoded.auth_method === 'worker'))) {
      res.status(403).json({ error: "a service call takes a wallet's own token (silicon: and worker tokens act for another wallet)" }); return null;
    }
    if (!identity.scopeAtLeast(auth.scope, minScope)) { res.status(403).json({ error: `${minScope} scope required` }); return null; }
    return auth;
  }
  function tenantAuth(req, res) {
    const auth = walletAuth(req, res); if (!auth) return null;
    const tenant = tenantByDid(auth.did);
    if (!tenant) { res.status(403).json({ error: 'this token is not a registered service tenant\'s wallet' }); return null; }
    return { auth, tenant };
  }

  // ── service tokens ─────────────────────────────────────────────────────────────────────────────────────────────
  // Same Ed25519 signature as every DemiPass token (the wallet's key), different issuer and an audience. Checked here
  // only; identity.verifyToken refuses the issuer everywhere else.
  function verifyServiceToken(token, tenant) {
    if (typeof token !== 'string' || token.length > 4096) return { ok: false, status: 400, error: 'token: the caller\'s service token (string)' };
    const parts = token.split('.');
    if (parts.length !== 3) return { ok: false, status: 401, error: 'malformed token' };
    let decoded;
    try { decoded = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8')); } catch (_) { return { ok: false, status: 401, error: 'malformed token' }; }
    if (!decoded || typeof decoded.sub !== 'string' || !decoded.sub.startsWith('did:key:')) return { ok: false, status: 401, error: 'no wallet in token' };
    let good = false;
    try {
      const pub = crypto.createPublicKey({ key: identity.didToPublicKey(decoded.sub), format: 'der', type: 'spki' });
      good = crypto.verify(null, Buffer.from(`${parts[0]}.${parts[1]}`), pub, Buffer.from(parts[2], 'base64url'));
    } catch (_) { good = false; }
    if (!good) return { ok: false, status: 401, error: 'signature invalid' };
    if (decoded.iss !== SVC_ISS) return { ok: false, status: 401, error: 'not a service token (mint one: POST /api/services/token)' };
    if (decoded.aud !== 'svc:' + tenant.slug) return { ok: false, status: 401, error: 'this token is for another service' };
    if (!Number.isInteger(decoded.exp) || decoded.exp <= nowSec()) return { ok: false, status: 401, error: 'token expired' };
    if (!decoded.jti) return { ok: false, status: 401, error: 'token has no id' };
    const dead = billing.checkTokenRevocation(db, decoded);
    if (dead.revoked) return { ok: false, status: 401, error: dead.reason };
    const w = db.prepare('SELECT status FROM identity_wallets WHERE did = ?').get(decoded.sub);
    if (!w || w.status !== 'active') return { ok: false, status: 403, error: 'wallet not active' };
    return { ok: true, decoded };
  }

  // ── authority: own account, or a delegation of the action's scope ──────────────────────────────────────────────
  function authority(tenant, action, did, svcScopes) {
    if (Array.isArray(svcScopes) && !svcScopes.includes(action.scope)) return { ok: false, error: `this token does not carry the '${action.scope}' scope` };
    const d = db.prepare(`SELECT * FROM service_delegations WHERE tenant_id = ? AND scope = ? AND delegate_did = ? AND status = 'active'
        AND (expires_at IS NULL OR expires_at > ?) ORDER BY id DESC LIMIT 1`).get(tenant.id, action.scope, did, nowIso());
    // A delegation counts only while its owner still holds the scope (a closed scope: still the tenant owner).
    if (d && (action.open || d.owner_did === tenant.owner_did)) return { ok: true, via: 'delegation', delegation: d, approver: d.owner_did };
    if (action.open || did === tenant.owner_did) return { ok: true, via: 'own', delegation: null, approver: did };
    return { ok: false, error: `the '${action.scope}' scope at ${tenant.slug} is held by its owner; ask them to delegate it` };
  }

  // ── verify ─────────────────────────────────────────────────────────────────────────────────────────────────────
  function verify(tenant, body) {
    const b = body || {};
    const t = verifyServiceToken(b.token, tenant);
    if (!t.ok) return { status: t.status, body: { ok: false, error: t.error } };
    const d = t.decoded;
    const action = actionOf(tenant, b.action);
    if (!action) return { status: 404, body: { ok: false, error: `no action '${String(b.action || '')}' at ${tenant.slug}` } };
    if (d.sub === tenant.service_did) return { status: 400, body: { ok: false, error: 'a tenant does not call itself' } };
    const scope = d.scope || 'read';
    if (!identity.scopeAtLeast(scope, 'transact')) return { status: 403, body: { ok: false, error: 'a service token needs transact scope to pay' } };
    const who = authority(tenant, action, d.sub, d.svc_scopes);
    if (!who.ok) return { status: 403, body: { ok: false, error: who.error } };
    let approval = null;
    if (action.depth !== 'standard') {
      // The approval is a person's: an agent acting on its own account has nobody to approve for it.
      if (who.via === 'own' && isAgentWallet(d.sub)) {
        return { status: 403, body: { ok: false, error: `'${action.action}' is ${action.depth}: an agent needs a person's delegation of '${action.scope}' (POST /api/services/delegate), whose phone approves each call`, depth: action.depth } };
      }
      const call = b.call && typeof b.call === 'object' && !Array.isArray(b.call) ? b.call : {};
      const g = approvals.gateService({
        key: `svc:${tenant.slug}:${action.action}`, name: `${tenant.slug} · ${action.action}`, approverDid: who.approver, depth: action.depth,
      }, { did: d.sub, label: d.agent_label || d.username || '' }, { action: action.action, targetHost: tenant.slug, params: call,
        delegationId: who.delegation ? who.delegation.id : null }, b);
      if (!g.ok) return { status: g.status, body: { ...g.body, depth: action.depth } };
      approval = g.approval_id;
    }
    const cap = Number.isInteger(d.cap_dd) && d.cap_dd > 0 ? Math.min(d.cap_dd, TOKEN_CAP_MAX_DD) : TOKEN_CAP_DEFAULT_DD;
    const at = nowIso();
    db.prepare(`INSERT INTO service_verifications (tenant_id, token_jti, did, iat, exp, auth_method, fleet, cap_dd, delegation_id, first_at, last_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(tenant_id, token_jti) DO UPDATE SET last_at = excluded.last_at, delegation_id = excluded.delegation_id`)
      .run(tenant.id, d.jti, d.sub, d.iat || null, d.exp, d.auth_method || null, d.fleet ? String(d.fleet) : null, cap,
           who.delegation ? who.delegation.id : null, at, at);
    const spent = db.prepare('SELECT COALESCE(SUM(dd), 0) AS s FROM service_charges WHERE token_jti = ? AND tenant_id = ?').get(d.jti, tenant.id).s;
    return { status: 200, body: {
      ok: true, wallet: d.sub, token_id: d.jti, scope, service_scopes: Array.isArray(d.svc_scopes) ? d.svc_scopes : null,
      action: action.action, action_scope: action.scope, depth: action.depth, via: who.via,
      ...(who.delegation ? { delegation_id: who.delegation.id, principal: principalId(tenant, who.delegation.owner_did) } : {}),
      ...(approval ? { approval_id: approval } : {}),
      price: actionView(action), cap_dd: cap, spent_dd: spent, expires_at: new Date(d.exp * 1000).toISOString(),
    } };
  }

  // ── charge ─────────────────────────────────────────────────────────────────────────────────────────────────────
  function charge(tenant, body, tenantJti) {
    if (!meterKey) return { status: 503, body: { error: 'signing key unavailable' } };
    const b = body || {};
    if (b.service !== undefined && b.service !== tenant.slug) return { status: 403, body: { error: `this token is ${tenant.slug}'s; it charges only for ${tenant.slug}` } };
    const action = actionOf(tenant, b.action);
    if (!action) return { status: 404, body: { error: `no action '${String(b.action || '')}' at ${tenant.slug}` } };
    const cost = b.cost_dd === undefined ? action.measured_cost_dd : b.cost_dd;
    if (!Number.isInteger(cost) || cost < 1 || cost > action.max_cost_dd) return { status: 400, body: { error: `cost_dd: an integer from 1 to ${action.max_cost_dd} (this action's max_cost_dd)` } };
    if (typeof b.idempotency_key !== 'string' || !IDEM_RE.test(b.idempotency_key)) return { status: 400, body: { error: 'idempotency_key: 8-100 of [A-Za-z0-9._:-] (one per billed call; a retry sends the same key)' } };
    if (typeof b.token_id !== 'string' || !/^[0-9a-f]{8,64}$/.test(b.token_id)) return { status: 400, body: { error: 'token_id: from your verify of the caller\'s token' } };
    const dd = priceOf(cost);

    const prior = db.prepare('SELECT * FROM service_charges WHERE tenant_id = ? AND idempotency_key = ?').get(tenant.id, b.idempotency_key);
    if (prior) {
      if (prior.token_jti !== b.token_id || prior.action !== action.action || prior.cost_dd !== cost) {
        return { status: 409, body: { error: 'this idempotency_key was already used for a different charge', charge_id: prior.charge_id } };
      }
      return { status: 200, body: chargeView(prior, true) };
    }
    const v = db.prepare('SELECT * FROM service_verifications WHERE tenant_id = ? AND token_jti = ?').get(tenant.id, b.token_id);
    if (!v) return { status: 403, body: { error: 'verify this token first (POST /api/services/verify): a tenant charges only callers it verified' } };
    if (v.exp <= nowSec()) return { status: 401, body: { error: 'the caller\'s token has expired; charge within its life' } };
    const dead = billing.checkTokenRevocation(db, { jti: v.token_jti, sub: v.did, iat: v.iat, auth_method: v.auth_method, fleet: v.fleet });
    if (dead.revoked) return { status: 401, body: { error: dead.reason } };
    if (v.did === tenant.service_did) return { status: 400, body: { error: 'a tenant does not charge itself' } };

    const run = db.transaction(() => {
      const spent = db.prepare('SELECT COALESCE(SUM(dd), 0) AS s FROM service_charges WHERE token_jti = ? AND tenant_id = ?').get(v.token_jti, tenant.id).s;
      if (spent + dd > v.cap_dd) { const e = new Error('cap'); e.cap = { spent, cap: v.cap_dd }; throw e; }
      const charge_id = 'sc_' + crypto.randomBytes(12).toString('hex');
      const at = nowIso();
      const what = `service ${tenant.slug}/${action.action} cost ${cost} + ${SERVICE_MARGIN_PCT}% ${charge_id}`;
      // Both rows carry the caller's token (the one that made the charge). Typed as transfers: DD moves between
      // wallets, so its lineage follows (dd_ledger.recordTransfer below), not a spend.
      const debit = billing.deductBalance(db, v.did, dd, 'service_transfer_out', what, { tokenJti: v.token_jti });
      if (!debit.ok) { const e = new Error('debit'); e.debit = debit; throw e; }
      const credit = billing.creditBalance(db, tenant.service_did, dd, 'service_transfer_in', what, null, { tokenJti: v.token_jti });
      if (!credit.ok) throw new Error('credit to the tenant wallet failed: ' + credit.error);
      const receipt = JSON.stringify({ v: RECEIPT_VERSION, type: 'dustforge_service_charge', charge_id, issuer, service: tenant.slug,
        payer: v.did, payee: tenant.service_did, action: action.action, cost_dd: cost, margin_pct: SERVICE_MARGIN_PCT, dd,
        token_id: v.token_jti, idempotency_key: b.idempotency_key, at });
      const sig = crypto.sign(null, Buffer.from(receipt, 'utf8'), meterKey.privateKey).toString('base64url');
      db.prepare(`INSERT INTO service_charges (charge_id, tenant_id, payer_did, payee_did, action, cost_dd, margin_pct, dd, token_jti, delegation_id,
                  idempotency_key, receipt, sig, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
        .run(charge_id, tenant.id, v.did, tenant.service_did, action.action, cost, SERVICE_MARGIN_PCT, dd, v.token_jti, v.delegation_id,
             b.idempotency_key, receipt, sig, at);
      return { row: db.prepare('SELECT * FROM service_charges WHERE charge_id = ?').get(charge_id), balance_after: debit.balance_after };
    });
    let out;
    try { out = run.immediate(); }
    catch (e) {
      if (e.cap) return { status: 402, body: { error: `this charge would pass the caller token's spend cap (${e.cap.spent} + ${dd} > ${e.cap.cap} DD); the caller mints a token with a higher cap_dd`, required_dd: dd, cap_dd: e.cap.cap, spent_dd: e.cap.spent, cap_exceeded: true } };
      if (e.debit) {
        const insufficient = /insufficient/.test(e.debit.error || '');
        return { status: insufficient ? 402 : 403, body: { error: insufficient ? 'the caller\'s wallet cannot cover this call' : e.debit.error, required_dd: dd,
          ...(insufficient ? { balance_dd: e.debit.balance_cents, top_up: 'https://demipass.com/app' } : {}) } };
      }
      throw e;
    }
    try { if (ledger) ledger.recordTransfer(db, v.did, tenant.service_did, dd); } catch (_) {}
    event('service_charge', tenant.service_did, { charge_id: out.row.charge_id, service: tenant.slug, action: action.action, dd, token_id: v.token_jti });
    return { status: 201, body: { ...chargeView(out.row, false), payer_balance_after: out.balance_after } };
  }
  function chargeView(r, replayed) {
    return { ok: true, replayed, charge_id: r.charge_id, action: r.action, cost_dd: r.cost_dd, margin_pct: r.margin_pct, dd: r.dd,
      token_id: r.token_jti, at: r.created_at, receipt: r.receipt, sig: r.sig, issuer };
  }

  // ── routes ─────────────────────────────────────────────────────────────────────────────────────────────────────
  const lim = rateLimitStandard || ((req, res, next) => next());

  app.get('/api/services', lim, (req, res) => {
    res.json({ margin_pct: SERVICE_MARGIN_PCT, issuer, tenants: db.prepare("SELECT * FROM service_tenants WHERE status = 'active' ORDER BY slug").all().map(tenantView) });
  });
  app.get('/api/services/charges', lim, (req, res) => {
    const auth = walletAuth(req, res, { minScope: 'read' }); if (!auth) return;
    const n = Math.min(Math.max(Number(req.query.limit) || 50, 1), 200);
    const cols = 'c.charge_id, t.slug AS service, c.action, c.cost_dd, c.margin_pct, c.dd, c.token_jti AS token_id, c.delegation_id, c.created_at';
    const paid = db.prepare(`SELECT ${cols} FROM service_charges c JOIN service_tenants t ON t.id = c.tenant_id WHERE c.payer_did = ? ORDER BY c.id DESC LIMIT ?`).all(auth.did, n);
    const tenant = tenantByDid(auth.did);
    // A tenant sees what it was paid and by which token, never who holds the wallet beyond its DID.
    const received = tenant ? db.prepare(`SELECT ${cols}, c.payer_did AS payer FROM service_charges c JOIN service_tenants t ON t.id = c.tenant_id WHERE c.tenant_id = ? ORDER BY c.id DESC LIMIT ?`).all(tenant.id, n) : [];
    res.json({ ok: true, paid, ...(tenant ? { received } : {}) });
  });
  app.get('/api/services/delegations', lim, (req, res) => {
    const auth = walletAuth(req, res, { minScope: 'read' }); if (!auth) return;
    const q = `SELECT d.id, t.slug AS service, d.scope, d.owner_did, d.delegate_did, d.status, d.granted_at, d.expires_at, d.revoked_at
               FROM service_delegations d JOIN service_tenants t ON t.id = d.tenant_id`;
    res.json({ ok: true, granted: db.prepare(q + ' WHERE d.owner_did = ? ORDER BY d.id DESC LIMIT 200').all(auth.did),
      held: db.prepare(q + " WHERE d.delegate_did = ? AND d.status = 'active' ORDER BY d.id DESC LIMIT 200").all(auth.did) });
  });
  app.get('/api/services/:slug', lim, (req, res) => {
    const t = tenantBySlug(req.params.slug);
    if (!t) return res.status(404).json({ error: 'no such service' });
    res.json(tenantView(t));
  });

  // Registration. The service wallet itself (it then belongs to its fleet's owner, or to itself when it is nobody's
  // silicon), or a person naming one of their own fleet's silicons. One tenant per wallet.
  app.post('/api/services/register', lim, (req, res) => {
    const auth = walletAuth(req, res); if (!auth) return;
    const b = req.body || {};
    const slug = String(b.slug || '').trim().toLowerCase();
    if (!SLUG_RE.test(slug)) return res.status(400).json({ error: 'slug: 2-31 of [a-z0-9-], starting with a letter' });
    const name = String(b.name || slug).replace(/[\u0000-\u001f\u007f]/g, '').slice(0, 80);
    const serviceDid = b.service_did ? String(b.service_did) : auth.did;
    let ownerDid;
    if (serviceDid === auth.did) {
      ownerDid = fleetOwnerOf(auth.did) || auth.did;
    } else {
      if (isAgentToken(auth)) return res.status(403).json({ error: 'a person registers one of their silicons from their own session' });
      if (!ownAgent(auth.did, serviceDid)) return res.status(403).json({ error: 'service_did must be you or a silicon your own fleet created' });
      ownerDid = auth.did;
    }
    if (!db.prepare('SELECT 1 FROM identity_wallets WHERE did = ?').get(serviceDid)) return res.status(404).json({ error: 'service_did: no such wallet' });
    if (db.prepare('SELECT 1 FROM service_tenants WHERE slug = ?').get(slug)) return res.status(409).json({ error: 'that slug is taken' });
    if (db.prepare('SELECT 1 FROM service_tenants WHERE service_did = ?').get(serviceDid)) return res.status(409).json({ error: 'that wallet is already a tenant' });
    db.prepare('INSERT INTO service_tenants (slug, name, service_did, owner_did, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?)')
      .run(slug, name, serviceDid, ownerDid, auth.did, nowIso());
    event('service_registered', auth.did, { slug, service_did: serviceDid, owner_did: ownerDid });
    logSecurityEvent('service_registered', 'info', { caller_did: auth.did, capability: 'service-register', target: slug, context: { service_did: serviceDid } });
    res.status(201).json({ ok: true, ...tenantView(tenantBySlug(slug)), owner_is_you: ownerDid === auth.did });
  });

  // The tenant's price list. The tenant wallet or its owner. Lowering a depth (elevated → standard, say) removes a
  // person's approval from every call: the owner, in their own session, with the PIN.
  app.put('/api/services/:slug/actions', lim, (req, res) => {
    const auth = walletAuth(req, res); if (!auth) return;
    const t = tenantBySlug(req.params.slug);
    if (!t) return res.status(404).json({ error: 'no such service' });
    const asOwner = auth.did === t.owner_did && !isAgentToken(auth);
    if (auth.did !== t.service_did && !asOwner) return res.status(403).json({ error: 'the tenant wallet or its owner sets prices' });
    const list = (req.body || {}).actions;
    if (!Array.isArray(list) || !list.length || list.length > 50) return res.status(400).json({ error: 'actions: 1-50 entries' });
    const rows = [];
    for (const a of list) {
      if (!a || typeof a !== 'object') return res.status(400).json({ error: 'each action is an object' });
      const action = String(a.action || ''), scope = String(a.scope || a.action || '');
      if (!ACTION_RE.test(action) || !ACTION_RE.test(scope)) return res.status(400).json({ error: `action/scope '${action}': 1-41 of [a-z0-9_.-]` });
      if (a.retired === true) { rows.push({ action, retired: true }); continue; }
      const cost = a.measured_cost_dd, max = a.max_cost_dd === undefined ? cost : a.max_cost_dd;
      if (!Number.isInteger(cost) || cost < 1 || cost > MAX_COST_DD) return res.status(400).json({ error: `${action}: measured_cost_dd 1-${MAX_COST_DD}` });
      if (!Number.isInteger(max) || max < cost || max > MAX_COST_DD) return res.status(400).json({ error: `${action}: max_cost_dd from measured_cost_dd to ${MAX_COST_DD}` });
      const depth = a.depth === undefined ? null : String(a.depth);
      if (depth !== null && !DEPTHS.includes(depth)) return res.status(400).json({ error: `${action}: depth is one of ${DEPTHS.join(', ')}` });
      rows.push({ action, scope, cost, max, depth, open: a.open === undefined ? null : Boolean(a.open) });
    }
    // Anything that weakens a gate: a lower depth, or a closed action opened to every wallet.
    const weakens = rows.filter(r => {
      const cur = actionOf(t, r.action); if (!cur || r.retired) return false;
      return (r.depth !== null && DEPTHS.indexOf(r.depth) < DEPTHS.indexOf(cur.depth)) || (r.open === true && !cur.open) || (r.scope !== cur.scope && cur.depth !== 'standard');
    });
    if (weakens.length) {
      if (!asOwner) return res.status(403).json({ error: `lowering a depth or opening a closed action (${weakens.map(r => r.action).join(', ')}) takes the owner, in their own session, with the PIN` });
      const intent = `svc-depth:${t.id}`;
      if (!gateFresh(auth.did, 'pin', auth, intent)) return res.status(403).json(gateMissing('svc-depth', ['pin'], ['pin'], intent));
      const refused = spendSingleUse(auth.did, 'svc-depth', ['pin'], auth, intent);
      if (refused) return res.status(refused.status || 403).json(refused);
    }
    const at = nowIso();
    db.transaction(() => {
      for (const r of rows) {
        if (r.retired) { db.prepare("UPDATE service_actions SET status = 'retired', updated_at = ? WHERE tenant_id = ? AND action = ?").run(at, t.id, r.action); continue; }
        const cur = db.prepare('SELECT * FROM service_actions WHERE tenant_id = ? AND action = ?').get(t.id, r.action);
        const depth = r.depth !== null ? r.depth : (cur ? cur.depth : 'standard');
        const open = r.open !== null ? (r.open ? 1 : 0) : (cur ? cur.open : 1);
        db.prepare(`INSERT INTO service_actions (tenant_id, action, scope, measured_cost_dd, max_cost_dd, depth, open, status, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, 'active', ?)
                    ON CONFLICT(tenant_id, action) DO UPDATE SET scope = excluded.scope, measured_cost_dd = excluded.measured_cost_dd,
                      max_cost_dd = excluded.max_cost_dd, depth = excluded.depth, open = excluded.open, status = 'active', updated_at = excluded.updated_at`)
          .run(t.id, r.action, r.scope, r.cost, r.max, depth, open, at);
      }
    })();
    event('service_actions_set', auth.did, { service: t.slug, actions: rows.map(r => r.action), weakened: weakens.map(r => r.action) });
    res.json({ ok: true, ...tenantView(t) });
  });

  // A caller mints a token for one tenant. Its own token (agents' fleet-minted ones included: that is how a silicon
  // signs in), transact scope. The new token lives at most as long as the one minting it.
  app.post('/api/services/token', lim, (req, res) => {
    const auth = walletAuth(req, res); if (!auth) return;
    const b = req.body || {};
    const t = tenantBySlug(b.service);
    if (!t) return res.status(404).json({ error: 'service: no such service (GET /api/services)' });
    if (auth.did === t.service_did) return res.status(400).json({ error: 'a tenant does not call itself' });
    const m = /^(\d+)(m|h)$/.exec(String(b.ttl || '1h'));
    if (!m) return res.status(400).json({ error: 'ttl: e.g. 15m, 1h, 24h' });
    let ttl = Number(m[1]) * (m[2] === 'h' ? 3600 : 60);
    ttl = Math.min(ttl, TOKEN_TTL_MAX_SEC, Math.max(0, ((auth.decoded && auth.decoded.exp) || 0) - nowSec()));
    if (ttl < 60) return res.status(400).json({ error: 'your token expires within a minute; sign in again' });
    const scopes = b.scopes === undefined ? null : b.scopes;
    if (scopes !== null) {
      const known = scopesOf(t);
      if (!Array.isArray(scopes) || !scopes.length || scopes.length > 20 || scopes.some(s => !known.includes(s))) return res.status(400).json({ error: `scopes: a list from ${known.join(', ') || '(none yet)'}` });
    }
    const cap = b.cap_dd === undefined ? TOKEN_CAP_DEFAULT_DD : b.cap_dd;
    if (!Number.isInteger(cap) || cap < 1 || cap > TOKEN_CAP_MAX_DD) return res.status(400).json({ error: `cap_dd: 1-${TOKEN_CAP_MAX_DD} (the most this token can be charged)` });
    const w = db.prepare('SELECT encrypted_private_key, did, status FROM identity_wallets WHERE did = ?').get(auth.did);
    if (!w || w.status !== 'active' || !w.encrypted_private_key) return res.status(403).json({ error: 'wallet not active' });
    const meta = { iss: SVC_ISS, aud: 'svc:' + t.slug, auth_method: 'service_token', cap_dd: cap, minted_by_jti: (auth.decoded && auth.decoded.jti) || null,
      ...(scopes ? { svc_scopes: scopes } : {}), ...(auth.decoded && auth.decoded.fleet ? { fleet: auth.decoded.fleet, src_auth: auth.decoded.auth_method } : {}) };
    let token;
    try { token = identity.createTokenForIdentity(w.encrypted_private_key, w.did, { scope: 'transact', expiresIn: `${ttl}s`, metadata: meta }); }
    catch (e) { return res.status(500).json({ error: 'token mint failed' }); }
    const d = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8'));
    event('service_token_minted', auth.did, { service: t.slug, token_id: d.jti, cap_dd: cap, exp: d.exp });
    res.status(201).json({ ok: true, token, token_id: d.jti, service: t.slug, audience: d.aud, scope: d.scope, cap_dd: cap,
      ...(scopes ? { scopes } : {}), expires_at: new Date(d.exp * 1000).toISOString(),
      use: `send it to ${t.name} as Authorization: Bearer <token>; it opens nothing at DemiPass itself` });
  });

  // Revoke one of my service tokens (or a fleet owner revokes it for their silicon: use the silicon's revoke-all).
  app.post('/api/services/token/revoke', lim, (req, res) => {
    const auth = walletAuth(req, res, { minScope: 'read' }); if (!auth) return;
    const id = String((req.body || {}).token_id || '');
    if (!/^[0-9a-f]{8,64}$/.test(id)) return res.status(400).json({ error: 'token_id' });
    const r = db.prepare("UPDATE issued_tokens SET revoked = 1, revoked_at = datetime('now') WHERE jti = ? AND did = ? AND revoked = 0").run(id, auth.did);
    if (!r.changes) return res.status(404).json({ error: 'no live token of yours with that id' });
    event('service_token_revoked', auth.did, { token_id: id });
    res.json({ ok: true, revoked: true, token_id: id });
  });

  // Delegation of a service scope, use-only: the delegate calls the tenant's actions in that scope with ITS OWN service
  // token (and pays from its own wallet); the tenant sees the delegation and a pairwise principal, never the owner.
  // Same rules as secret delegation (/api/blindkey/delegate): a person's own session, never an agent token (so agents
  // never hand a scope on); delegates are agents; an agent the owner's fleet did not create takes the PIN. Depth comes
  // with the scope: the delegate's elevated calls wait on the owner's approval.
  app.post('/api/services/delegate', lim, (req, res) => {
    const auth = walletAuth(req, res); if (!auth) return;
    if (isAgentToken(auth)) {
      logSecurityEvent('service_delegate_denied', 'warning', { caller_did: auth.did, capability: 'service-delegate', ip: req.ip, error: 'agent token' });
      return res.status(403).json({ error: 'agents do not hand on a service scope; the owner delegates from their own session' });
    }
    const b = req.body || {};
    const t = tenantBySlug(b.service);
    if (!t) return res.status(404).json({ error: 'service: no such service' });
    const scope = String(b.scope || '');
    const acts = db.prepare("SELECT * FROM service_actions WHERE tenant_id = ? AND scope = ? AND status = 'active'").all(t.id, scope);
    if (!acts.length) return res.status(404).json({ error: `no scope '${scope}' at ${t.slug} (${scopesOf(t).join(', ')})` });
    // A closed scope (any of its actions closed) is the tenant owner's to hand on; an open one, anybody's.
    if (acts.some(a => !a.open) && auth.did !== t.owner_did) return res.status(403).json({ error: `'${scope}' at ${t.slug} is held by its owner only` });
    const delegate = String(b.delegate_did || '');
    if (!db.prepare('SELECT 1 FROM identity_wallets WHERE did = ?').get(delegate)) return res.status(404).json({ error: 'delegate_did: no such wallet' });
    if (delegate === auth.did) return res.status(400).json({ error: 'you hold it already' });
    if (delegate === t.service_did) return res.status(400).json({ error: 'not to the tenant itself' });
    if (!isAgentWallet(delegate)) return res.status(403).json({ error: 'a service scope goes to an agent (a silicon in a fleet)' });
    if (!ownAgent(auth.did, delegate)) {
      const intent = `svc-delegate:${t.id}`;
      if (!gateFresh(auth.did, 'pin', auth, intent)) return res.status(403).json(gateMissing('svc-delegate', ['pin'], ['pin'], intent));
      const refused = spendSingleUse(auth.did, 'svc-delegate', ['pin'], auth, intent);
      if (refused) return res.status(refused.status || 403).json(refused);
    }
    const expiresAt = Number.isInteger(b.expires_in) && b.expires_in > 0 ? new Date(Date.now() + Math.min(b.expires_in, 365 * 86400) * 1000).toISOString() : null;
    const at = nowIso();
    const id = db.transaction(() => {
      db.prepare("UPDATE service_delegations SET status = 'revoked', revoked_at = ? WHERE tenant_id = ? AND scope = ? AND owner_did = ? AND delegate_did = ? AND status = 'active'")
        .run(at, t.id, scope, auth.did, delegate);
      return Number(db.prepare('INSERT INTO service_delegations (tenant_id, scope, owner_did, delegate_did, granted_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)')
        .run(t.id, scope, auth.did, delegate, at, expiresAt).lastInsertRowid);
    })();
    event('service_delegated', auth.did, { delegation_id: id, service: t.slug, scope, delegate_did: delegate, expires_at: expiresAt });
    res.status(201).json({ ok: true, delegation_id: id, service: t.slug, scope, delegate_did: delegate, use_only: true, expires_at: expiresAt,
      depth: Object.fromEntries(acts.map(a => [a.action, a.depth])) });
  });

  // Revoke a delegation: its owner (any token of theirs, agents included: taking access away is always allowed).
  app.post('/api/services/delegations/:id/revoke', lim, (req, res) => {
    const auth = walletAuth(req, res, { minScope: 'read' }); if (!auth) return;
    const id = Number(req.params.id);
    const d = Number.isInteger(id) && id > 0 ? db.prepare('SELECT * FROM service_delegations WHERE id = ? AND owner_did = ?').get(id, auth.did) : null;
    if (!d) return res.status(404).json({ error: 'no delegation of yours with that id' });
    if (d.status !== 'active') return res.status(409).json({ error: `already ${d.status}` });
    db.prepare("UPDATE service_delegations SET status = 'revoked', revoked_at = ? WHERE id = ? AND status = 'active'").run(nowIso(), id);
    event('service_delegation_revoked', auth.did, { delegation_id: id });
    res.json({ ok: true, revoked: true, delegation_id: id });
  });

  app.post('/api/services/verify', lim, (req, res) => {
    const a = tenantAuth(req, res); if (!a) return;
    const r = verify(a.tenant, req.body);
    res.status(r.status).json(r.body);
  });
  app.post('/api/services/charge', lim, (req, res) => {
    const a = tenantAuth(req, res); if (!a) return;
    const r = charge(a.tenant, req.body, a.auth.decoded && a.auth.decoded.jti);
    res.status(r.status).json(r.body);
  });

  app.post('/api/services/receipts/verify', lim, (req, res) => {
    const { receipt, sig } = req.body || {};
    if (!meterKey) return res.status(503).json({ error: 'signing key unavailable' });
    if (typeof receipt !== 'string' || typeof sig !== 'string' || receipt.length > 4096 || sig.length > 200) return res.status(400).json({ error: 'receipt (string) and sig' });
    let ok = false;
    try { ok = crypto.verify(null, Buffer.from(receipt, 'utf8'), crypto.createPublicKey({ key: meterKey.publicKeyDer, format: 'der', type: 'spki' }), Buffer.from(sig, 'base64url')); } catch (_) {}
    if (!ok) return res.json({ valid: false, error: 'signature does not verify against this server\'s key' });
    let p; try { p = JSON.parse(receipt); } catch (_) { return res.json({ valid: false, error: 'not JSON' }); }
    const row = db.prepare('SELECT receipt FROM service_charges WHERE charge_id = ?').get(p.charge_id);
    res.json({ valid: true, on_record: !!row && row.receipt === receipt, charge: p });
  });

  return { verify, charge, verifyServiceToken, priceOf, tenantBySlug, SERVICE_MARGIN_PCT, issuer };
};

module.exports.SERVICE_MARGIN_PCT = SERVICE_MARGIN_PCT;
module.exports.priceOf = priceOf;
module.exports.SVC_ISS = SVC_ISS;
