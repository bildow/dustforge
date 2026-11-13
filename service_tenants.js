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
//     POST /api/services/charge   {action, cost_dd, token_id, idempotency_key}   (an action this token was verified for)
//     PUT  /api/services/:slug/actions  {actions:[…]}   weakening a gate waits on the tenant owner's approval
//     POST /api/services/charge-on-request {action, cost_dd, idempotency_key, request_charge_id, message_sha256,
//          request_nonce, dry_run?}   work a wallet asked for by a Conduit message, with no service token (below)
//   caller side (Bearer = the caller's own token)
//     POST /api/services/consent  {service, daily_cap_dd}   paying a service at all: approved on a phone (below)
//     POST /api/services/token    {service, ttl?, scopes?, cap_dd?}  → a service token for that tenant
//     POST /api/services/token/revoke {token_id}
//     POST /api/services/delegate {service, scope, delegate_did, expires_in?}   use-only, to your own fleet's agents
//     POST /api/services/delegations/:id/revoke, POST /api/services/consents/:id/revoke
//     GET  /api/services/delegations, /consents, /charges
//   public: GET /api/services, GET /api/services/:slug, POST /api/services/receipts/verify
//   registration: POST /api/services/register {slug, name, service_did?}   approved on the owner's phone
//
// Money (#68 review H1): a charge moves DD out of the caller's wallet, so paying a tenant needs a standing CONSENT for
// that tenant with a daily cap, approved like an elevated secret's use (the request waits in the DemiPass app; PIN to
// open; the linked phone signs the decision). A person approves their own; a fleet-created agent's consent is its fleet
// owner's to approve. A token alone (stolen, or an agent holding its owner's device login) can ask, never grant.
// Charges are bounded by the token's cap_dd, the consent's daily cap, the action's max_cost_dd + margin, and the
// barrel tier for amounts over 1000 DD (transferBarrelRefusal, as for transfers).
// Depth: an action is standard, elevated or critical. Elevated and critical actions take an approval on the phone of
// the person whose authority the call uses, bound to that authority (approver + delegation) and to the exact call.

const crypto = require('crypto');

// Margin over a tenant's measured cost, credited to the tenant with the cost (the tenant's price = cost + margin).
// Aaron's order left the figure blank; 20 is a placeholder pending his number — change it here (one line, reviewed
// PR). Charges record the margin they used.
const SERVICE_MARGIN_PCT = 20;          // the default; a tenant's owner sets its own (PUT /api/services/:slug/margin)
const MAX_MARGIN_PCT = 33;              // Aaron 2026-11-10: "33% seems like the top we will charge"
// Metered follow-ups (2026-11-10): work a caller started (a door submission) keeps billing after its token expired —
// later review rounds, in portions of at most MAX_PORTION_DD (25¢) — only when the caller opted in: the token carries a
// follow-up budget (claim fu_dd, chosen at mint, no more than the daily consent). Only an action the tenant's owner
// approved as starting work (its `follow_ups` list) is an origin, and only the actions listed there, as they stood at
// the origin charge, are follow-ups of it; at the origin's margin or lower; for FOLLOW_UP_DAYS (#88 review H1/H2/M1/M3).
const FOLLOW_UP_DAYS = 14;
const MAX_PORTION_DD = 250;
// Charging on a Conduit request (FleetEngine F1b; tome decisions/2026-11-12-DECISION-fleetengine-and-shadow-engine-
// redefinition.md). A wallet may ask a tenant for work by posting it a Conduit message instead of sending a service
// token. Conduit's own charge for that post is the proof: Conduit verified the payer's service token for it, and its
// idempotency key is requestKey(recipient wallet, sha256 of the message body, nonce), which Conduit computes for a post
// addressed to one agent. The tenant shows the message hash and nonce it received; this server recomputes the key with
// the CALLING tenant's own wallet DID, so a charge for a message to someone else, or for other bytes, never matches.
// The recipient is bound by wallet DID, not by Conduit name: DemiPass has no view of Conduit's name registry, so a
// name could be claimed by any tenant; Conduit already binds each name to the wallet that registered it.
// Only a consent that opted in (on_request_cap_dd, approved on the phone with the consent) can be charged this way, at
// most that much per request (origin + follow-ups); each Conduit charge authorizes one origin charge, within 10 min.
const CONDUIT_SLUG = 'conduit';
const REQUEST_KEY_DOMAIN = 'conduit-request:v1\n';
const REQUEST_MAX_AGE_MS = 10 * 60 * 1000;
const NONCE_MAX = 128;
const SVC_ISS = 'demipass-svc';
const RECEIPT_DOMAIN = 'dustforge-service-charge:v1\n';   // signed bytes = domain + receipt: never valid as a meter receipt
const SLUG_RE = /^[a-z][a-z0-9-]{1,30}$/;
const ACTION_RE = /^[a-z][a-z0-9_.-]{0,40}$/;
const IDEM_RE = /^[A-Za-z0-9._:-]{8,100}$/;
const DEPTHS = ['standard', 'elevated', 'critical'];
const RESERVED_SLUGS = new Set(['demipass', 'dustforge', 'admin', 'meter', 'services', 'api', 'charges', 'delegations', 'consents', 'consent', 'token', 'verify', 'charge', 'register', 'receipts', 'delegate', 'charge-on-request']);
const MAX_COST_DD = 100000;            // one call, before margin ($100)
const TOKEN_TTL_MAX_SEC = 24 * 3600;
const TOKEN_CAP_DEFAULT_DD = 500;
const CONSENT_CAP_MAX_DD = 100000;     // a day, per tenant ($100)
const RECEIPT_VERSION = 1;

const priceOf = (costDd, marginPct = SERVICE_MARGIN_PCT) => costDd + Math.ceil(costDd * marginPct / 100);
// The idempotency key Conduit gives the post charge of a message to one agent (see CONDUIT_SLUG above). The fields are
// fixed-format except the nonce, which comes last, so the hashed string parses one way only.
const requestKey = (recipientDid, messageSha256, nonce) => 'cr1:' + crypto.createHash('sha256')
  .update(REQUEST_KEY_DOMAIN + recipientDid + '\n' + messageSha256 + '\n' + nonce, 'utf8').digest('hex');

module.exports = function registerServiceTenants(deps) {
  const { app, db, identity, billing, getBearerIdentity, logSecurityEvent, rateLimitStandard, approvals, masterKey } = deps;
  const barrelRefusal = deps.transferBarrelRefusal || (() => null);
  const ledger = deps.ledger || (() => { try { return require('./dd_ledger'); } catch (_) { return null; } })();

  // ── schema ─────────────────────────────────────────────────────────────────────────────────────────────────────
  db.exec(`CREATE TABLE IF NOT EXISTS service_tenants (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    slug TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    service_did TEXT NOT NULL UNIQUE,     -- the tenant's wallet: authenticates its calls, receives its charges
    owner_did TEXT NOT NULL,              -- the person who controls it (holds its closed scopes, approves weakening)
    status TEXT NOT NULL DEFAULT 'active',
    created_by TEXT NOT NULL,
    approval_id INTEGER,
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
  // Where callers reach the tenant, and which MCP server a caller's agent attaches to it with (2026-11-10, Aaron: "a
  // systemic tool to onboard to the MCP service seamlessly"). Kept in the registry so no client hard-codes a URL that
  // goes stale (Conduit moved from k1 to phasewhip; panes kept the dead address). Set by PUT /api/services/:slug/connect.
  try { db.exec("ALTER TABLE service_tenants ADD COLUMN endpoint TEXT NOT NULL DEFAULT ''"); } catch (_) {}
  try { db.exec("ALTER TABLE service_tenants ADD COLUMN mcp_server TEXT NOT NULL DEFAULT ''"); } catch (_) {}
  // The tenant's own margin (NULL: the default). Raised or lowered by its owner, approved in the app, 0..MAX_MARGIN_PCT.
  try { db.exec('ALTER TABLE service_tenants ADD COLUMN margin_pct INTEGER'); } catch (_) {}
  // An action that starts work names the actions that may bill as its follow-ups (JSON list; NULL: none).
  try { db.exec('ALTER TABLE service_actions ADD COLUMN follow_ups TEXT'); } catch (_) {}
  // A tenant may charge only a token it verified, only for an action it verified, while that token lives.
  db.exec(`CREATE TABLE IF NOT EXISTS service_verifications (
    tenant_id INTEGER NOT NULL,
    token_jti TEXT NOT NULL,
    did TEXT NOT NULL,
    iat INTEGER, exp INTEGER NOT NULL,
    src_auth TEXT, fleet TEXT, parent_jti TEXT,
    svc_scopes TEXT,                      -- JSON list, or NULL (all)
    actions TEXT NOT NULL DEFAULT '[]',   -- JSON list of actions verified on this token
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
  db.exec('CREATE INDEX IF NOT EXISTS idx_svc_charges_payer ON service_charges(payer_did, tenant_id, created_at)');
  // A metered follow-up names the charge that started the work (NULL: an ordinary charge on a live token).
  try { db.exec('ALTER TABLE service_charges ADD COLUMN follows_charge_id TEXT'); } catch (_) {}
  // On an origin charge: the follow-up actions it allows, as they stood when it was made (JSON list; NULL: none).
  try { db.exec('ALTER TABLE service_charges ADD COLUMN follow_ups TEXT'); } catch (_) {}
  // The follow-up budget the caller's token carried (claim fu_dd; 0: no follow-ups).
  try { db.exec('ALTER TABLE service_verifications ADD COLUMN follow_up_dd INTEGER NOT NULL DEFAULT 0'); } catch (_) {}
  try { db.exec('CREATE INDEX IF NOT EXISTS idx_svc_charges_follows ON service_charges(follows_charge_id)'); } catch (_) {}
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
  db.exec(`CREATE TABLE IF NOT EXISTS service_consents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    payer_did TEXT NOT NULL,
    tenant_id INTEGER NOT NULL,
    daily_cap_dd INTEGER NOT NULL,
    approved_by TEXT NOT NULL,
    approval_id INTEGER,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TEXT NOT NULL,
    revoked_at TEXT
  )`);
  db.exec('CREATE INDEX IF NOT EXISTS idx_svc_consent ON service_consents(payer_did, tenant_id, status)');
  // A consent may also cover work the wallet asks for by a Conduit message (charge-on-request): the most one request
  // may run up, origin + follow-ups. NULL: not allowed (every consent made before this, and any that did not opt in).
  try { db.exec('ALTER TABLE service_consents ADD COLUMN on_request_cap_dd INTEGER'); } catch (_) {}
  // The Conduit post charge an origin charge was made on (NULL: an ordinary charge). Each authorizes at most one.
  try { db.exec('ALTER TABLE service_charges ADD COLUMN request_charge_id TEXT'); } catch (_) {}
  db.exec('CREATE UNIQUE INDEX IF NOT EXISTS idx_svc_charges_request ON service_charges(request_charge_id) WHERE request_charge_id IS NOT NULL');

  // ── keys ───────────────────────────────────────────────────────────────────────────────────────────────────────
  // Receipts are signed by the meter's key (same issuer did:key), over RECEIPT_DOMAIN + receipt, so neither kind
  // verifies as the other. Pairwise principals use an HMAC key of their own. Without the master key: 503.
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
  const anyActionOf = (tenant, action) => db.prepare('SELECT * FROM service_actions WHERE tenant_id = ? AND action = ?').get(tenant.id, String(action || ''));
  const scopesOf = (tenant) => db.prepare("SELECT DISTINCT scope FROM service_actions WHERE tenant_id = ? AND status = 'active'").all(tenant.id).map(r => r.scope);
  const isAgentWallet = (did) => Boolean(db.prepare("SELECT 1 FROM fleet_silicons WHERE member_did = ? AND status = 'active'").get(did));
  // A silicon the owner's own fleet created (consented, owned outright): same test as /api/blindkey/delegate.
  const ownAgent = (ownerDid, did) => Boolean(db.prepare(`SELECT 1 FROM fleets f JOIN fleet_silicons s ON s.fleet_id = f.id
      WHERE f.owner_did = ? AND f.status = 'active' AND s.member_did = ? AND s.status = 'active' AND s.created_by_fleet = 1
      AND COALESCE(s.joined_via, 'owner') != 'network'`).get(ownerDid, did));
  const fleetOwnerOf = (did) => (db.prepare(`SELECT f.owner_did FROM fleets f JOIN fleet_silicons s ON s.fleet_id = f.id
      WHERE s.member_did = ? AND s.status = 'active' AND s.created_by_fleet = 1 AND COALESCE(s.joined_via, 'owner') != 'network'
      AND f.status = 'active' LIMIT 1`).get(did) || {}).owner_did || null;
  // The person who answers for a wallet: for a wallet a fleet created, that fleet's owner WHATEVER its row's status now
  // (a created agent that left or was removed is still not a person: #68 re-review N1, the fleetExitRefusal rule); an
  // agent no fleet created has nobody → null (refused); anyone else answers for themselves.
  // fleet_billing.creatorOf reads wallet_creators, which survives the row deletion when a wallet joins another fleet.
  const creatorOf = (did) => (require('./fleet_billing').creatorOf(db, did) || {}).owner_did || null;
  const personFor = (did) => creatorOf(did) || (isAgentWallet(did) ? null : did);
  // A consent counts only while the person who approved it still answers for the wallet.
  const liveConsent = (did, tenant) => { const c = consentOf(did, tenant); return c && c.approved_by === personFor(did) ? c : null; };
  const jsonList = (s) => { try { const v = JSON.parse(s || '[]'); return Array.isArray(v) ? v : []; } catch (_) { return []; } };
  const marginOf = (t) => Math.min(MAX_MARGIN_PCT, t && Number.isInteger(t.margin_pct) && t.margin_pct >= 0 ? t.margin_pct : SERVICE_MARGIN_PCT);
  function actionView(a, m = SERVICE_MARGIN_PCT) {
    return { action: a.action, scope: a.scope, depth: a.depth, open: Boolean(a.open), measured_cost_dd: a.measured_cost_dd,
      max_cost_dd: a.max_cost_dd, margin_pct: m, price_dd: priceOf(a.measured_cost_dd, m), max_price_dd: priceOf(a.max_cost_dd, m),
      ...(jsonList(a.follow_ups).length ? { follow_ups: jsonList(a.follow_ups) } : {}) };
  }
  function tenantView(t) {
    const actions = db.prepare("SELECT * FROM service_actions WHERE tenant_id = ? AND status = 'active' ORDER BY action").all(t.id);
    const m = marginOf(t);
    return { slug: t.slug, name: t.name, service_did: t.service_did, audience: 'svc:' + t.slug, margin_pct: m,
      endpoint: t.endpoint || null, mcp_server: t.mcp_server || null, actions: actions.map(a => actionView(a, m)),
      follow_ups: { days: FOLLOW_UP_DAYS, max_portion_dd: MAX_PORTION_DD, budget: 'the caller\'s token (follow_up_dd at mint)' } };
  }
  function event(type, actor, detail) {
    try { db.prepare('INSERT INTO blindkey_events (event_type, actor, secret_id, context_name, detail) VALUES (?, ?, ?, ?, ?)').run(type, actor, null, 'service', JSON.stringify(detail)); } catch (_) {}
  }

  // A person's approval through use_approvals (the DemiPass app's approvals list; PIN to open; the phone signs).
  // The reply a caller (or a tenant) sees never names the approver (#68 review M1).
  function personApproval(key, name, approverDid, depth, caller, action, target, params, body, delegationId) {
    const g = approvals.gateService({ key, name, approverDid, depth }, caller, { action, targetHost: target, params, delegationId }, body || {});
    if (g.ok) return { ok: true, approval_id: g.approval_id };
    const b = { ...(g.body || {}) };
    delete b.owner;
    if (g.status === 202) {
      b.next = 'Park this call. The person whose authority it uses approves it in their DemiPass app; then make the same call once more with approval_id. Do not retry in a loop.';
    }
    return { ok: false, status: g.status, body: b };
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
  const consentOf = (did, tenant) => db.prepare("SELECT * FROM service_consents WHERE payer_did = ? AND tenant_id = ? AND status = 'active' ORDER BY id DESC LIMIT 1").get(did, tenant.id);
  const spentToday = (did, tenant) => db.prepare("SELECT COALESCE(SUM(dd), 0) AS s FROM service_charges WHERE payer_did = ? AND tenant_id = ? AND created_at > ?")
    .get(did, tenant.id, new Date(Date.now() - 86400000).toISOString()).s;
  // A live consent that opted in to charges on Conduit requests.
  const onRequestConsent = (did, tenant) => { const c = liveConsent(did, tenant); return c && Number.isInteger(c.on_request_cap_dd) && c.on_request_cap_dd > 0 ? c : null; };
  // Work started on a Conduit request stops when the Conduit token that posted it is revoked by any route (its own flag,
  // the token that minted it, the wallet's session or time cutoff, a fleet cut). → reason, or null.
  function requestStopped(originRow) {
    if (!originRow || !originRow.request_charge_id) return null;
    const ct = tenantBySlug(CONDUIT_SLUG);
    const rc = ct && db.prepare('SELECT * FROM service_charges WHERE charge_id = ? AND tenant_id = ?').get(originRow.request_charge_id, ct.id);
    const cv = rc && db.prepare('SELECT * FROM service_verifications WHERE tenant_id = ? AND token_jti = ?').get(ct.id, rc.token_jti);
    if (!cv) return 'the Conduit request this work started from is no longer on record';
    return revoked({ jti: cv.token_jti, sub: cv.did, iat: cv.iat, src_auth: cv.src_auth, fleet: cv.fleet, parent_jti: cv.parent_jti });
  }

  // ── service tokens ─────────────────────────────────────────────────────────────────────────────────────────────
  // Same Ed25519 signature as every DemiPass token (the wallet's key), another issuer and an audience. Checked here
  // only. It dies with the token that minted it, with its session (sid), and with a fleet cut (#68 review M4).
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
    const dead = revoked({ jti: decoded.jti, sub: decoded.sub, iat: decoded.iat, src_auth: decoded.src_auth, fleet: decoded.fleet, parent_jti: decoded.minted_by_jti });
    if (dead) return { ok: false, status: 401, error: dead };
    const w = db.prepare('SELECT status FROM identity_wallets WHERE did = ?').get(decoded.sub);
    if (!w || w.status !== 'active') return { ok: false, status: 403, error: 'wallet not active' };
    return { ok: true, decoded };
  }
  function revoked({ jti, sub, iat, src_auth, fleet, parent_jti }) {
    const r = billing.checkTokenRevocation(db, { jti, sub, iat, auth_method: src_auth || 'service_token', ...(fleet ? { fleet } : {}) });
    if (r.revoked) return r.reason;
    if (parent_jti) {
      const p = db.prepare('SELECT revoked FROM issued_tokens WHERE jti = ?').get(parent_jti);
      if (p && p.revoked) return 'token revoked: the token that minted it was revoked';
    }
    return null;
  }

  // ── authority: own account, or a live delegation of the action's scope ────────────────────────────────────────
  // A delegation counts only while its owner still holds the scope and the delegate is still an agent the owner's
  // fleet created (#68 review H2, M4: a stranger cannot push one onto someone else's agent; removal ends it).
  function authority(tenant, action, did, svcScopes) {
    if (Array.isArray(svcScopes) && !svcScopes.includes(action.scope)) return { ok: false, error: `this token does not carry the '${action.scope}' scope` };
    const ds = db.prepare(`SELECT * FROM service_delegations WHERE tenant_id = ? AND scope = ? AND delegate_did = ? AND status = 'active'
        AND (expires_at IS NULL OR expires_at > ?) ORDER BY id DESC`).all(tenant.id, action.scope, did, nowIso());
    const d = ds.find(x => ownAgent(x.owner_did, did) && (action.open || x.owner_did === tenant.owner_did));
    if (d) return { ok: true, via: 'delegation', delegation: d, approver: d.owner_did };
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
      if (who.via === 'own' && personFor(d.sub) !== d.sub) {
        return { status: 403, body: { ok: false, error: `'${action.action}' is ${action.depth}: an agent needs its fleet owner's delegation of '${action.scope}' (POST /api/services/delegate), whose phone approves each call`, depth: action.depth } };
      }
      const call = b.call && typeof b.call === 'object' && !Array.isArray(b.call) ? b.call : {};
      // The approval binds the exact call AND the authority it was given under (approver + delegation; #68 review H2).
      const g = personApproval(`svc:${tenant.slug}:${action.action}`, `${tenant.slug} · ${action.action}`, who.approver, action.depth,
        { did: d.sub, label: d.username || '' }, action.action, tenant.slug,
        { ...call, authority: { approver_principal: principalId(tenant, who.approver), delegation_id: who.delegation ? who.delegation.id : null } },
        b, who.delegation ? who.delegation.id : null);
      if (!g.ok) return { status: g.status, body: { ...g.body, depth: action.depth } };
      approval = g.approval_id;
    }
    const cap = Number.isInteger(d.cap_dd) && d.cap_dd > 0 ? d.cap_dd : TOKEN_CAP_DEFAULT_DD;
    const at = nowIso();
    const prior = db.prepare('SELECT actions FROM service_verifications WHERE tenant_id = ? AND token_jti = ?').get(tenant.id, d.jti);
    const actions = [...new Set([...jsonList(prior && prior.actions), action.action])];
    const fuDd = Number.isInteger(d.fu_dd) && d.fu_dd > 0 ? d.fu_dd : 0;
    db.prepare(`INSERT INTO service_verifications (tenant_id, token_jti, did, iat, exp, src_auth, fleet, parent_jti, svc_scopes, actions, cap_dd, delegation_id, first_at, last_at, follow_up_dd)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(tenant_id, token_jti) DO UPDATE SET last_at = excluded.last_at, actions = excluded.actions, delegation_id = excluded.delegation_id`)
      .run(tenant.id, d.jti, d.sub, d.iat || null, d.exp, d.src_auth || null, d.fleet ? String(d.fleet) : null, d.minted_by_jti || null,
           Array.isArray(d.svc_scopes) ? JSON.stringify(d.svc_scopes) : null, JSON.stringify(actions), cap, who.delegation ? who.delegation.id : null, at, at, fuDd);
    const spent = db.prepare('SELECT COALESCE(SUM(dd), 0) AS s FROM service_charges WHERE token_jti = ? AND tenant_id = ?').get(d.jti, tenant.id).s;
    return { status: 200, body: {
      ok: true, wallet: d.sub, token_id: d.jti, scope, service_scopes: Array.isArray(d.svc_scopes) ? d.svc_scopes : null,
      action: action.action, action_scope: action.scope, depth: action.depth, via: who.via,
      ...(who.delegation ? { delegation_id: who.delegation.id, principal: principalId(tenant, who.delegation.owner_did) } : {}),
      ...(approval ? { approval_id: approval } : {}),
      price: actionView(action, marginOf(tenant)), cap_dd: cap, spent_dd: spent, follow_up_dd: fuDd, expires_at: new Date(d.exp * 1000).toISOString(),
    } };
  }

  // ── charge ─────────────────────────────────────────────────────────────────────────────────────────────────────
  function charge(tenant, body) {
    if (!meterKey) return { status: 503, body: { error: 'signing key unavailable' } };
    const b = body || {};
    if (b.service !== undefined && b.service !== tenant.slug) return { status: 403, body: { error: `this token is ${tenant.slug}'s; it charges only for ${tenant.slug}` } };
    const action = actionOf(tenant, b.action);
    if (!action) return { status: 404, body: { error: `no action '${String(b.action || '')}' at ${tenant.slug}` } };
    const cost = b.cost_dd === undefined ? action.measured_cost_dd : b.cost_dd;
    // A follow-up's dry run sizes a whole step (billed later in portions), bounded by the follow-up budget, not by one
    // charge's max_cost_dd.
    const wholeStep = b.dry_run === true && b.follow_up_of !== undefined;
    const costMax = wholeStep ? CONSENT_CAP_MAX_DD : action.max_cost_dd;
    if (!Number.isInteger(cost) || cost < 1 || cost > costMax) return { status: 400, body: { error: wholeStep ? `cost_dd: an integer from 1 to ${costMax} (a whole step)` : `cost_dd: an integer from 1 to ${costMax} (this action's max_cost_dd)` } };
    const dry = b.dry_run === true;
    const followUp = b.follow_up_of !== undefined;
    if (!dry && (typeof b.idempotency_key !== 'string' || !IDEM_RE.test(b.idempotency_key))) return { status: 400, body: { error: 'idempotency_key: 8-100 of [A-Za-z0-9._:-] (one per billed call; a retry sends the same key)' } };
    if (followUp && (typeof b.follow_up_of !== 'string' || !/^sc_[0-9a-f]{24}$/.test(b.follow_up_of))) return { status: 400, body: { error: 'follow_up_of: the charge_id that started this work' } };
    if (!followUp && (typeof b.token_id !== 'string' || !/^[0-9a-f]{8,64}$/.test(b.token_id))) return { status: 400, body: { error: 'token_id: from your verify of the caller\'s token' } };
    let margin = marginOf(tenant);
    let dd = priceOf(cost, margin);

    // A metered follow-up: the authority is the charge that started the work and the follow-up budget its token
    // carried, not a live token (it has expired by the time a later review round runs). See FOLLOW_UP_DAYS above.
    let origin = null;
    if (followUp) {
      origin = db.prepare('SELECT * FROM service_charges WHERE charge_id = ? AND tenant_id = ?').get(b.follow_up_of, tenant.id);
      if (!origin) return { status: 404, body: { error: 'follow_up_of: no charge of this service with that id' } };
      if (origin.follows_charge_id) return { status: 400, body: { error: 'follow_up_of: name the charge that started the work, not another follow-up', origin: origin.follows_charge_id } };
      if (!jsonList(origin.follow_ups).includes(action.action)) return { status: 403, body: { error: `'${action.action}' is not a follow-up the charge ${origin.charge_id} allowed when it was made` } };
      if (Date.parse(origin.created_at) < Date.now() - FOLLOW_UP_DAYS * 86400000) return { status: 403, body: { error: `follow-ups end ${FOLLOW_UP_DAYS} days after the charge that started the work` } };
      if (!dry && cost > MAX_PORTION_DD) return { status: 400, body: { error: `a follow-up is billed in portions of at most ${MAX_PORTION_DD} DD (cost); split it` } };
    }
    // A follow-up pays the margin of the charge that started the work, or the tenant's current one if lower (M1).
    if (followUp) { margin = Math.min(origin.margin_pct, margin); dd = priceOf(cost, margin); }
    const chargeMargin = margin, chargeDd = dd;

    const prior = dry ? null : db.prepare('SELECT * FROM service_charges WHERE tenant_id = ? AND idempotency_key = ?').get(tenant.id, b.idempotency_key);
    if (prior && followUp) {
      if (prior.follows_charge_id !== b.follow_up_of || prior.action !== action.action || prior.cost_dd !== cost) return { status: 409, body: { error: 'this idempotency_key was already used for a different charge', charge_id: prior.charge_id } };
      // A replay is a go-ahead for the work: only while the origin token is unrevoked and the consent live.
      const ov = db.prepare('SELECT * FROM service_verifications WHERE tenant_id = ? AND token_jti = ?').get(tenant.id, origin.token_jti);
      const ow = ov ? authority(tenant, action, ov.did, ov.svc_scopes ? jsonList(ov.svc_scopes) : null) : null;
      if (!ov || revoked({ jti: ov.token_jti, sub: ov.did, iat: ov.iat, src_auth: ov.src_auth, fleet: ov.fleet, parent_jti: ov.parent_jti }) || !liveConsent(ov.did, tenant)
          || !ow.ok || (ov.delegation_id && !(ow.delegation && ow.delegation.id === ov.delegation_id))
          || (origin.request_charge_id && (requestStopped(origin) || !onRequestConsent(ov.did, tenant)))) {
        return { status: 409, body: { error: 'this follow-up was charged, but its token or consent has since been withdrawn: stop the work', charge_id: prior.charge_id } };
      }
      return { status: 200, body: chargeView(prior, true) };
    }

    if (prior) {
      // A retry may come with a new token of the same wallet (the first expired, or the caller's process restarted
      // after it was charged): that is still the same charge, so it replays. Another wallet's token never does
      // (demipass #17 review M1). A replay moves no DD.
      // The token retrying (the first one or another of the same wallet) must still be good, with the same checks a
      // charge runs: verified for this action and its scope, unexpired, not revoked by any route (its own flag, the
      // wallet, a session or time cutoff, a fleet cut, its parent), its consent live (#87 review L/L1: a token or
      // consent withdrawn never gets a "go ahead").
      const nv = db.prepare('SELECT * FROM service_verifications WHERE tenant_id = ? AND token_jti = ?').get(tenant.id, b.token_id);
      const nvScopes = nv && nv.svc_scopes ? jsonList(nv.svc_scopes) : null;
      const samePayer = Boolean(!prior.follows_charge_id && nv && nv.did === prior.payer_did && nv.exp > nowSec() && jsonList(nv.actions).includes(action.action)
        && (!nvScopes || nvScopes.includes(action.scope))
        && !revoked({ jti: nv.token_jti, sub: nv.did, iat: nv.iat, src_auth: nv.src_auth, fleet: nv.fleet, parent_jti: nv.parent_jti })
        && liveConsent(nv.did, tenant));
      if (!samePayer || prior.action !== action.action || prior.cost_dd !== cost) {
        return { status: 409, body: { error: 'this idempotency_key was already used for a different charge', charge_id: prior.charge_id } };
      }
      return { status: 200, body: chargeView(prior, true) };
    }
    const v = db.prepare('SELECT * FROM service_verifications WHERE tenant_id = ? AND token_jti = ?').get(tenant.id, followUp ? origin.token_jti : b.token_id);
    if (!v) return { status: 403, body: { error: 'verify this token first (POST /api/services/verify): a tenant charges only callers it verified' } };
    const scopes = v.svc_scopes ? jsonList(v.svc_scopes) : null;
    if (followUp) {
      if (!(v.follow_up_dd > 0)) return { status: 403, body: { error: 'the token that started this work allowed no follow-ups (follow_up_dd at mint)' } };
      if (action.depth !== 'standard') return { status: 403, body: { error: 'an elevated action is never a follow-up: it needs its own verified token' } };
      // The caller's authority now, not only when the work started: a delegation withdrawn ends the follow-ups (M2).
      const who = authority(tenant, action, v.did, scopes);
      if (!who.ok) return { status: 403, body: { error: who.error } };
      if (v.delegation_id && !(who.delegation && who.delegation.id === v.delegation_id)) return { status: 403, body: { error: 'the delegation this work started under has ended' } };
    } else {
      // Only for an action this token was verified for (an elevated one: only after its approval passed), within the
      // token's scopes (#68 review M2).
      if (!jsonList(v.actions).includes(action.action)) return { status: 403, body: { error: `this token was not verified for '${action.action}'; verify it for that action first` } };
      if (scopes && !scopes.includes(action.scope)) return { status: 403, body: { error: `this token does not carry the '${action.scope}' scope` } };
      if (v.exp <= nowSec()) return { status: 401, body: { error: 'the caller\'s token has expired; charge within its life' } };
    }
    const dead = revoked({ jti: v.token_jti, sub: v.did, iat: v.iat, src_auth: v.src_auth, fleet: v.fleet, parent_jti: v.parent_jti });
    if (dead) return { status: 401, body: { error: dead } };
    if (followUp && origin.request_charge_id) { const why = requestStopped(origin); if (why) return { status: 401, body: { error: why } }; }
    if (v.did === tenant.service_did) return { status: 400, body: { error: 'a tenant does not charge itself' } };
    const consent = liveConsent(v.did, tenant);
    if (!consent) return { status: 402, body: { error: `the caller has no standing consent to pay ${tenant.slug}`, consent_required: true } };
    if (followUp && origin.request_charge_id && !onRequestConsent(v.did, tenant)) return { status: 402, body: { error: `the caller's consent no longer covers ${tenant.slug} charging for Conduit requests`, consent_required: true, on_request_required: true } };
    const barrel = barrelRefusal(v.did, dd);
    if (barrel) return { status: barrel.statusCode || 403, body: barrel.body || { error: barrel.message } };
    // Follow-ups draw on the token's follow-up budget, apart from its cap for ordinary charges.
    const followed = () => db.prepare('SELECT COALESCE(SUM(dd), 0) AS s FROM service_charges WHERE token_jti = ? AND tenant_id = ? AND follows_charge_id IS NOT NULL').get(v.token_jti, tenant.id).s;
    const ordinary = () => db.prepare('SELECT COALESCE(SUM(dd), 0) AS s FROM service_charges WHERE token_jti = ? AND tenant_id = ? AND follows_charge_id IS NULL').get(v.token_jti, tenant.id).s;

    // A dry run ("survey the wallet" before a portion of work): every check a charge makes, nothing written.
    if (dry) {
      // A follow-up's dry run may ask about a whole step before it runs (the meter surveys one model call, which it then
      // bills in ≤250 DD portions), up to what the token's follow-up budget could ever pay; an ordinary one, one portion.
      // (#57 review: surveying only one portion let a 250 DD wallet start a 1,000 DD call.)
      if (!followUp && cost > MAX_PORTION_DD) return { status: 400, body: { error: `a dry run asks about one portion: at most ${MAX_PORTION_DD} DD (cost)` } };
      if (followUp && dd > v.follow_up_dd) return { status: 402, body: { ok: false, dry_run: true, would_charge_dd: dd, margin_pct: margin, refused: 'follow_up_budget' } };
      const w = db.prepare('SELECT status FROM identity_wallets WHERE did = ?').get(v.did);
      const today = spentToday(v.did, tenant);
      const bal = billing.getDerivedBalance(db, v.did);
      const why = (!w || w.status !== 'active') ? 'wallet_inactive' : (!followUp && ordinary() + chargeDd > v.cap_dd) ? 'token_cap'
        : (today + chargeDd > consent.daily_cap_dd) ? 'daily_cap' : (followUp && followed() + chargeDd > v.follow_up_dd) ? 'follow_up_budget'
        : (bal < chargeDd) ? 'insufficient' : null;
      return { status: why ? 402 : 200, body: { ok: !why, dry_run: true, would_charge_dd: chargeDd, margin_pct: chargeMargin, ...(why ? { refused: why } : {}) } };
    }

    const run = db.transaction(() => {
      if (!followUp) { const spent = ordinary(); if (spent + dd > v.cap_dd) { const e = new Error('cap'); e.cap = { kind: 'token', spent, cap: v.cap_dd }; throw e; } }
      if (followUp) { const f = followed(); if (f + chargeDd > v.follow_up_dd) { const e = new Error('cap'); e.cap = { kind: 'follow_up', spent: f, cap: v.follow_up_dd }; throw e; } }
      const today = spentToday(v.did, tenant);
      if (today + dd > consent.daily_cap_dd) { const e = new Error('cap'); e.cap = { kind: 'daily', spent: today, cap: consent.daily_cap_dd }; throw e; }
      const charge_id = 'sc_' + crypto.randomBytes(12).toString('hex');
      const at = nowIso();
      const what = `service ${tenant.slug}/${action.action} cost ${cost} + ${margin}% ${charge_id}${followUp ? ' (follows ' + origin.charge_id + ')' : ''}`;
      // Both rows carry the caller's token (the one that made the charge). Typed as transfers: DD moves between
      // wallets, so its lineage follows (dd_ledger.recordTransfer below), not a spend.
      const debit = billing.deductBalance(db, v.did, dd, 'service_transfer_out', what, { tokenJti: v.token_jti });
      if (!debit.ok) { const e = new Error('debit'); e.debit = debit; throw e; }
      const credit = billing.creditBalance(db, tenant.service_did, dd, 'service_transfer_in', what, null, { tokenJti: v.token_jti });
      if (!credit.ok) throw new Error('credit to the tenant wallet failed: ' + credit.error);
      const receipt = JSON.stringify({ v: RECEIPT_VERSION, type: 'dustforge_service_charge', charge_id, issuer, service: tenant.slug,
        payer: v.did, payee: tenant.service_did, action: action.action, cost_dd: cost, margin_pct: margin, dd,
        token_id: v.token_jti, idempotency_key: b.idempotency_key, ...(followUp ? { follows: origin.charge_id } : {}), at });
      const sig = crypto.sign(null, Buffer.from(RECEIPT_DOMAIN + receipt, 'utf8'), meterKey.privateKey).toString('base64url');
      db.prepare(`INSERT INTO service_charges (charge_id, tenant_id, payer_did, payee_did, action, cost_dd, margin_pct, dd, token_jti, delegation_id,
                  idempotency_key, receipt, sig, created_at, follows_charge_id, follow_ups) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
        .run(charge_id, tenant.id, v.did, tenant.service_did, action.action, cost, margin, dd, v.token_jti, v.delegation_id,
             b.idempotency_key, receipt, sig, at, followUp ? origin.charge_id : null,
             !followUp && v.follow_up_dd > 0 && jsonList(action.follow_ups).length ? JSON.stringify(jsonList(action.follow_ups)) : null);
      return { row: db.prepare('SELECT * FROM service_charges WHERE charge_id = ?').get(charge_id), balance_after: debit.balance_after };
    });
    let out;
    try { out = run.immediate(); }
    catch (e) {
      if (e.cap && e.cap.kind === 'token') return { status: 402, body: { error: `this charge would pass the caller token's spend cap (${e.cap.spent} + ${dd} > ${e.cap.cap} DD); the caller mints a token with a higher cap_dd`, required_dd: dd, cap_dd: e.cap.cap, spent_dd: e.cap.spent, cap_exceeded: true } };
      if (e.cap && e.cap.kind === 'follow_up') return { status: 402, body: { error: `this would pass the follow-up budget the caller's token carried (${e.cap.spent} + ${dd} > ${e.cap.cap} DD)`, follow_up_budget_exceeded: true, spent_dd: e.cap.spent, follow_up_dd: e.cap.cap } };
      if (e.cap) return { status: 402, body: { error: `this charge would pass the caller's daily consent for ${tenant.slug} (${e.cap.spent} + ${dd} > ${e.cap.cap} DD in 24 h)`, required_dd: dd, daily_cap_dd: e.cap.cap, spent_today_dd: e.cap.spent, daily_cap_exceeded: true } };
      if (e.debit) {
        const insufficient = /insufficient/.test(e.debit.error || '');
        return { status: insufficient ? 402 : 403, body: { error: insufficient ? 'the caller\'s wallet cannot cover this call' : e.debit.error, required_dd: dd,
          ...(insufficient ? { balance_dd: e.debit.balance_cents, top_up: 'https://demipass.com/app' } : {}) } };
      }
      if (/UNIQUE/.test(e.message || '')) return { status: 409, body: { error: 'a concurrent charge used this idempotency_key; retry to get it' } };
      throw e;
    }
    try { if (ledger) ledger.recordTransfer(db, v.did, tenant.service_did, dd); } catch (_) {}
    event('service_charge', tenant.service_did, { charge_id: out.row.charge_id, service: tenant.slug, action: action.action, dd, token_id: v.token_jti });
    return { status: 201, body: { ...chargeView(out.row, false), payer_balance_after: out.balance_after } };
  }
  // ── charge on a Conduit request (see CONDUIT_SLUG above) ──────────────────────────────────────────────────────
  // The origin charge of work a wallet asked for by a Conduit message. Its later portions bill as ordinary follow-ups
  // (POST /api/services/charge {follow_up_of}) against a per-request verification row: actions [] (no ordinary charge
  // can use it), cap and follow-up budget from the consent's on_request_cap_dd, parent = the Conduit token, so revoking
  // that token, the wallet's sessions or the consent (or its opt-in) stops the work.
  function chargeOnRequest(tenant, body) {
    if (!meterKey) return { status: 503, body: { error: 'signing key unavailable' } };
    const b = body || {};
    const conduit = tenantBySlug(CONDUIT_SLUG);
    if (!conduit) return { status: 503, body: { error: 'no Conduit tenant is registered' } };
    if (conduit.id === tenant.id) return { status: 400, body: { error: 'Conduit does not charge on its own requests' } };
    const action = actionOf(tenant, b.action);
    if (!action) return { status: 404, body: { error: `no action '${String(b.action || '')}' at ${tenant.slug}` } };
    if (action.depth !== 'standard') return { status: 403, body: { error: `'${action.action}' is ${action.depth}: it needs a verified service token and a person's approval, never a Conduit request` } };
    const cost = b.cost_dd === undefined ? action.measured_cost_dd : b.cost_dd;
    if (!Number.isInteger(cost) || cost < 1 || cost > action.max_cost_dd) return { status: 400, body: { error: `cost_dd: an integer from 1 to ${action.max_cost_dd} (this action's max_cost_dd)` } };
    const dry = b.dry_run === true;
    if (!dry && (typeof b.idempotency_key !== 'string' || !IDEM_RE.test(b.idempotency_key))) return { status: 400, body: { error: 'idempotency_key: 8-100 of [A-Za-z0-9._:-] (a retry sends the same key)' } };
    if (typeof b.request_charge_id !== 'string' || !/^sc_[0-9a-f]{24}$/.test(b.request_charge_id)) return { status: 400, body: { error: 'request_charge_id: the charge_id of the Conduit post that asked for this work' } };
    if (typeof b.message_sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(b.message_sha256)) return { status: 400, body: { error: 'message_sha256: lowercase hex sha256 of the message body (UTF-8) as Conduit delivered it' } };
    if (typeof b.request_nonce !== 'string' || !b.request_nonce.length || b.request_nonce.length > NONCE_MAX) return { status: 400, body: { error: `request_nonce: the nonce Conduit delivered with the message (1-${NONCE_MAX} characters)` } };

    // (1) A Conduit post charge, on record and signed by this server's meter key, for THIS message to THIS tenant.
    const rc = db.prepare('SELECT * FROM service_charges WHERE charge_id = ? AND tenant_id = ?').get(b.request_charge_id, conduit.id);
    if (!rc) return { status: 404, body: { error: 'request_charge_id: no Conduit charge with that id' } };
    let receipt = null; try { receipt = JSON.parse(rc.receipt); } catch (_) {}
    let signed = false;
    try { signed = crypto.verify(null, Buffer.from(RECEIPT_DOMAIN + rc.receipt, 'utf8'), crypto.createPublicKey({ key: meterKey.publicKeyDer, format: 'der', type: 'spki' }), Buffer.from(rc.sig, 'base64url')); } catch (_) {}
    if (!signed || !receipt || receipt.charge_id !== rc.charge_id || receipt.service !== CONDUIT_SLUG || receipt.payer !== rc.payer_did
        || receipt.action !== rc.action || receipt.idempotency_key !== rc.idempotency_key || receipt.token_id !== rc.token_jti) {
      return { status: 403, body: { error: 'that Conduit charge\'s receipt does not verify against this server\'s key' } };
    }
    if (rc.action !== 'post' || rc.follows_charge_id || rc.request_charge_id) return { status: 403, body: { error: 'request_charge_id: name the charge for a Conduit post' } };
    if (rc.idempotency_key !== requestKey(tenant.service_did, b.message_sha256, b.request_nonce)) {
      return { status: 403, body: { error: 'that Conduit charge is not for this message to this tenant (the recipient wallet, message_sha256 and request_nonce must be the ones Conduit charged for)' } };
    }
    const payer = rc.payer_did;
    if (payer === tenant.service_did) return { status: 400, body: { error: 'a tenant does not charge itself' } };
    // The Conduit token that posted it must still be good (any revocation route).
    const cv = db.prepare('SELECT * FROM service_verifications WHERE tenant_id = ? AND token_jti = ?').get(conduit.id, rc.token_jti);
    if (!cv || cv.did !== payer) return { status: 403, body: { error: 'the Conduit token that posted the request is not on record' } };
    const dead = revoked({ jti: cv.token_jti, sub: cv.did, iat: cv.iat, src_auth: cv.src_auth, fleet: cv.fleet, parent_jti: cv.parent_jti });
    if (dead) return { status: 401, body: { error: `the Conduit token that posted the request: ${dead}` } };

    // A retry (same key): replays while the request still stands, whatever its age; anything else on that key → 409.
    const prior = dry ? null : db.prepare('SELECT * FROM service_charges WHERE tenant_id = ? AND idempotency_key = ?').get(tenant.id, b.idempotency_key);
    if (prior) {
      if (prior.request_charge_id !== rc.charge_id || prior.action !== action.action || prior.cost_dd !== cost) return { status: 409, body: { error: 'this idempotency_key was already used for a different charge', charge_id: prior.charge_id } };
      if (!onRequestConsent(payer, tenant)) return { status: 409, body: { error: 'this request was charged, but the payer has since withdrawn its consent: stop the work', charge_id: prior.charge_id } };
      return { status: 200, body: { ...chargeView(prior, true), payer } };
    }
    // (3) Fresh: within REQUEST_MAX_AGE_MS of Conduit's charge. (4) One origin charge per Conduit charge.
    if (!(Date.parse(rc.created_at) > Date.now() - REQUEST_MAX_AGE_MS)) return { status: 403, body: { error: `that Conduit request is older than ${REQUEST_MAX_AGE_MS / 60000} minutes; the caller asks again` } };
    const used = db.prepare('SELECT charge_id FROM service_charges WHERE request_charge_id = ?').get(rc.charge_id);
    if (used) return { status: 409, body: { error: 'that Conduit request already authorized a charge', charge_id: used.charge_id } };

    // (2) A live consent that opted in, within its per-request and daily caps.
    const consent = liveConsent(payer, tenant);
    if (!consent) return { status: 402, body: { error: `the payer has no standing consent to pay ${tenant.slug}`, consent_required: true } };
    if (!(Number.isInteger(consent.on_request_cap_dd) && consent.on_request_cap_dd > 0)) {
      return { status: 402, body: { error: `the payer's consent to ${tenant.slug} does not cover Conduit requests (POST /api/services/consent with on_request_cap_dd)`, consent_required: true, on_request_required: true } };
    }
    const who = authority(tenant, action, payer, null);
    if (!who.ok) return { status: 403, body: { error: who.error } };
    const margin = marginOf(tenant);
    const dd = priceOf(cost, margin);
    if (dd > consent.on_request_cap_dd) return { status: 402, body: { error: `this charge (${dd} DD) is over what the payer allows one Conduit request (${consent.on_request_cap_dd} DD)`, required_dd: dd, on_request_cap_dd: consent.on_request_cap_dd, on_request_cap_exceeded: true } };
    const barrel = barrelRefusal(payer, dd);
    if (barrel) return { status: barrel.statusCode || 403, body: barrel.body || { error: barrel.message } };
    const followUps = jsonList(action.follow_ups);
    const fuDd = followUps.length ? consent.on_request_cap_dd - dd : 0;   // origin + follow-ups ≤ on_request_cap_dd

    if (dry) {
      const w = db.prepare('SELECT status FROM identity_wallets WHERE did = ?').get(payer);
      const today = spentToday(payer, tenant);
      const bal = billing.getDerivedBalance(db, payer);
      const why = (!w || w.status !== 'active') ? 'wallet_inactive' : (today + dd > consent.daily_cap_dd) ? 'daily_cap' : (bal < dd) ? 'insufficient' : null;
      return { status: why ? 402 : 200, body: { ok: !why, dry_run: true, would_charge_dd: dd, margin_pct: margin, payer, follow_up_dd: fuDd, ...(why ? { refused: why } : {}) } };
    }

    // The per-request verification row the follow-ups bill against: its own id (one per request), parent = the
    // Conduit token, the wallet's iat/session/fleet claims, no ordinary actions.
    const jti = crypto.createHash('sha256').update('conduit-request-origin:' + rc.charge_id).digest('hex');
    const run = db.transaction(() => {
      const today = spentToday(payer, tenant);
      if (today + dd > consent.daily_cap_dd) { const e = new Error('cap'); e.cap = { spent: today, cap: consent.daily_cap_dd }; throw e; }
      const at = nowIso();
      db.prepare(`INSERT INTO service_verifications (tenant_id, token_jti, did, iat, exp, src_auth, fleet, parent_jti, svc_scopes, actions, cap_dd, delegation_id, first_at, last_at, follow_up_dd)
                  VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, '[]', ?, ?, ?, ?, ?)`)
        .run(tenant.id, jti, payer, cv.iat, cv.exp, cv.src_auth, cv.fleet, cv.token_jti, consent.on_request_cap_dd, who.delegation ? who.delegation.id : null, at, at, fuDd);
      const charge_id = 'sc_' + crypto.randomBytes(12).toString('hex');
      const what = `service ${tenant.slug}/${action.action} cost ${cost} + ${margin}% ${charge_id} (requested by conduit ${rc.charge_id})`;
      const debit = billing.deductBalance(db, payer, dd, 'service_transfer_out', what, { tokenJti: jti });
      if (!debit.ok) { const e = new Error('debit'); e.debit = debit; throw e; }
      const credit = billing.creditBalance(db, tenant.service_did, dd, 'service_transfer_in', what, null, { tokenJti: jti });
      if (!credit.ok) throw new Error('credit to the tenant wallet failed: ' + credit.error);
      const rcpt = JSON.stringify({ v: RECEIPT_VERSION, type: 'dustforge_service_charge', charge_id, issuer, service: tenant.slug,
        payer, payee: tenant.service_did, action: action.action, cost_dd: cost, margin_pct: margin, dd,
        token_id: jti, idempotency_key: b.idempotency_key, requested_by: rc.charge_id, message_sha256: b.message_sha256, at });
      const sig = crypto.sign(null, Buffer.from(RECEIPT_DOMAIN + rcpt, 'utf8'), meterKey.privateKey).toString('base64url');
      db.prepare(`INSERT INTO service_charges (charge_id, tenant_id, payer_did, payee_did, action, cost_dd, margin_pct, dd, token_jti, delegation_id,
                  idempotency_key, receipt, sig, created_at, follows_charge_id, follow_ups, request_charge_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?)`)
        .run(charge_id, tenant.id, payer, tenant.service_did, action.action, cost, margin, dd, jti, who.delegation ? who.delegation.id : null,
             b.idempotency_key, rcpt, sig, at, fuDd > 0 ? JSON.stringify(followUps) : null, rc.charge_id);
      return { row: db.prepare('SELECT * FROM service_charges WHERE charge_id = ?').get(charge_id), balance_after: debit.balance_after };
    });
    let out;
    try { out = run.immediate(); }
    catch (e) {
      if (e.cap) return { status: 402, body: { error: `this charge would pass the payer's daily consent for ${tenant.slug} (${e.cap.spent} + ${dd} > ${e.cap.cap} DD in 24 h)`, required_dd: dd, daily_cap_dd: e.cap.cap, spent_today_dd: e.cap.spent, daily_cap_exceeded: true } };
      if (e.debit) {
        const insufficient = /insufficient/.test(e.debit.error || '');
        return { status: insufficient ? 402 : 403, body: { error: insufficient ? 'the payer\'s wallet cannot cover this call' : e.debit.error, required_dd: dd } };
      }
      if (/UNIQUE/.test(e.message || '')) return { status: 409, body: { error: 'a concurrent charge used this idempotency_key or this Conduit request; retry to get it' } };
      throw e;
    }
    try { if (ledger) ledger.recordTransfer(db, payer, tenant.service_did, dd); } catch (_) {}
    event('service_charge_on_request', tenant.service_did, { charge_id: out.row.charge_id, service: tenant.slug, action: action.action, dd, request_charge_id: rc.charge_id });
    return { status: 201, body: { ...chargeView(out.row, false), payer, follow_up_dd: fuDd, payer_balance_after: out.balance_after } };
  }

  function chargeView(r, replayed) {
    return { ok: true, replayed, charge_id: r.charge_id, action: r.action, cost_dd: r.cost_dd, margin_pct: r.margin_pct, dd: r.dd,
      ...(r.follows_charge_id ? { follows: r.follows_charge_id } : {}),
      ...(r.request_charge_id ? { requested_by: r.request_charge_id } : {}),
      token_id: r.token_jti, at: r.created_at, receipt: r.receipt, sig: r.sig, signed: 'Ed25519 over "' + RECEIPT_DOMAIN.trim() + '\\n" + receipt', issuer };
  }

  // ── routes ─────────────────────────────────────────────────────────────────────────────────────────────────────
  const lim = rateLimitStandard || ((req, res, next) => next());

  app.get('/api/services', lim, (req, res) => {
    res.json({ margin_pct: SERVICE_MARGIN_PCT, max_margin_pct: MAX_MARGIN_PCT, issuer, tenants: db.prepare("SELECT * FROM service_tenants WHERE status = 'active' ORDER BY slug").all().map(tenantView) });
  });
  app.get('/api/services/charges', lim, (req, res) => {
    const auth = walletAuth(req, res, { minScope: 'read' }); if (!auth) return;
    const n = Math.min(Math.max(Number(req.query.limit) || 50, 1), 200);
    const cols = 'c.charge_id, t.slug AS service, c.action, c.cost_dd, c.margin_pct, c.dd, c.token_jti AS token_id, c.delegation_id, c.created_at, c.follows_charge_id AS follows';
    const paid = db.prepare(`SELECT ${cols} FROM service_charges c JOIN service_tenants t ON t.id = c.tenant_id WHERE c.payer_did = ? ORDER BY c.id DESC LIMIT ?`).all(auth.did, n);
    const tenant = tenantByDid(auth.did);
    // A tenant finds one of its own charges by the idempotency key it chose (the FLEETGATE meter: a PR's door branch
    // names the submit charge's key, so later review rounds bill as follow-ups of it). Its own charges only.
    const key = typeof req.query.idempotency_key === 'string' ? req.query.idempotency_key : null;
    if (key !== null && (!tenant || !IDEM_RE.test(key))) return res.status(tenant ? 400 : 403).json({ error: tenant ? 'idempotency_key: 8-100 of [A-Za-z0-9._:-]' : 'only a tenant looks up its charges by key' });
    const received = !tenant ? [] : key !== null
      ? db.prepare(`SELECT ${cols}, c.payer_did AS payer FROM service_charges c JOIN service_tenants t ON t.id = c.tenant_id WHERE c.tenant_id = ? AND c.idempotency_key = ?`).all(tenant.id, key)
      : db.prepare(`SELECT ${cols}, c.payer_did AS payer FROM service_charges c JOIN service_tenants t ON t.id = c.tenant_id WHERE c.tenant_id = ? ORDER BY c.id DESC LIMIT ?`).all(tenant.id, n);
    res.json({ ok: true, paid, ...(tenant ? { received } : {}) });
  });
  app.get('/api/services/delegations', lim, (req, res) => {
    const auth = walletAuth(req, res, { minScope: 'read' }); if (!auth) return;
    const q = `SELECT d.id, t.slug AS service, d.scope, d.owner_did, d.delegate_did, d.status, d.granted_at, d.expires_at, d.revoked_at
               FROM service_delegations d JOIN service_tenants t ON t.id = d.tenant_id`;
    res.json({ ok: true, granted: db.prepare(q + ' WHERE d.owner_did = ? ORDER BY d.id DESC LIMIT 200').all(auth.did),
      held: db.prepare(q + " WHERE d.delegate_did = ? AND d.status = 'active' ORDER BY d.id DESC LIMIT 200").all(auth.did) });
  });
  app.get('/api/services/consents', lim, (req, res) => {
    const auth = walletAuth(req, res, { minScope: 'read' }); if (!auth) return;
    const q = `SELECT c.id, t.slug AS service, c.payer_did, c.daily_cap_dd, c.on_request_cap_dd, c.status, c.created_at, c.revoked_at FROM service_consents c JOIN service_tenants t ON t.id = c.tenant_id`;
    res.json({ ok: true, mine: db.prepare(q + ' WHERE c.payer_did = ? ORDER BY c.id DESC LIMIT 100').all(auth.did),
      approved_by_me: db.prepare(q + ' WHERE c.approved_by = ? AND c.payer_did != ? ORDER BY c.id DESC LIMIT 100').all(auth.did, auth.did) });
  });
  app.get('/api/services/:slug', lim, (req, res) => {
    const t = tenantBySlug(req.params.slug);
    if (!t) return res.status(404).json({ error: 'no such service' });
    res.json(tenantView(t));
  });

  // Registration (#68 review H1): approved on the owner's phone. The service wallet itself asks (its fleet owner
  // approves), or a person names themselves or a silicon their own fleet created (they approve). One tenant per wallet.
  app.post('/api/services/register', lim, (req, res) => {
    const auth = walletAuth(req, res); if (!auth) return;
    const b = req.body || {};
    const slug = String(b.slug || '').trim().toLowerCase();
    if (!SLUG_RE.test(slug) || RESERVED_SLUGS.has(slug)) return res.status(400).json({ error: 'slug: 2-31 of [a-z0-9-], starting with a letter, not reserved' });
    const name = String(b.name || slug).replace(/[\u0000-\u001f\u007f]/g, '').slice(0, 80);
    const serviceDid = b.service_did ? String(b.service_did) : auth.did;
    let ownerDid;
    if (serviceDid === auth.did) {
      ownerDid = personFor(auth.did);
      if (!ownerDid) return res.status(403).json({ error: 'an agent no fleet created has no person to approve it as a service' });
    } else {
      if (isAgentToken(auth)) return res.status(403).json({ error: 'a person registers one of their silicons from their own session' });
      if (!ownAgent(auth.did, serviceDid)) return res.status(403).json({ error: 'service_did must be you or a silicon your own fleet created' });
      ownerDid = auth.did;
    }
    if (!db.prepare('SELECT 1 FROM identity_wallets WHERE did = ?').get(serviceDid)) return res.status(404).json({ error: 'service_did: no such wallet' });
    if (db.prepare('SELECT 1 FROM service_tenants WHERE slug = ?').get(slug)) return res.status(409).json({ error: 'that slug is taken' });
    if (db.prepare('SELECT 1 FROM service_tenants WHERE service_did = ?').get(serviceDid)) return res.status(409).json({ error: 'that wallet is already a tenant' });
    const g = personApproval('svc:demipass:register', `register service ${slug}`, ownerDid, 'elevated', { did: auth.did, label: name }, 'register', 'demipass',
      { slug, name, service_did: serviceDid, owner: 'you' }, b, null);
    if (!g.ok) return res.status(g.status).json(g.body);
    try {
      db.prepare('INSERT INTO service_tenants (slug, name, service_did, owner_did, created_by, approval_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)')
        .run(slug, name, serviceDid, ownerDid, auth.did, g.approval_id, nowIso());
    } catch (e) { return res.status(409).json({ error: 'that slug or wallet was registered meanwhile' }); }
    event('service_registered', auth.did, { slug, service_did: serviceDid, owner_did: ownerDid, approval_id: g.approval_id });
    logSecurityEvent('service_registered', 'info', { caller_did: auth.did, capability: 'service-register', target: slug, context: { service_did: serviceDid } });
    res.status(201).json({ ok: true, ...tenantView(tenantBySlug(slug)), owner_is_you: ownerDid === auth.did });
  });

  // Where callers connect, and the MCP server agents attach with: {endpoint, mcp_server}. The tenant wallet or its owner
  // asks; every change waits on the tenant owner's approval in the app (svc:demipass:connect), because the endpoint is
  // where callers send their service tokens. endpoint: an https URL (http only on a tailnet *.ts.net host), no
  // credentials, query or fragment. mcp_server: "<npm package>#<bin>", e.g. "demipass#fleetgate-mcp". '' clears either.
  const MCP_SERVER_RE = /^(@[a-z0-9][a-z0-9._-]{0,60}\/)?[a-z0-9][a-z0-9._-]{0,80}#[a-z0-9][a-z0-9._-]{0,60}$/;
  // Returns { endpoint } (normalized, the form stored and shown) or { error }. Only plain printable ASCII, and the
  // input must already be in normalized form: parsers disagree on backslashes and odd characters (#87 review M1:
  // "http://x.ts.net\\@evil.com" is x.ts.net to Node and evil.com to Python).
  function normalizeEndpoint(v) {
    if (v === '') return { endpoint: '' };
    if (v.length > 200) return { error: 'endpoint: at most 200 characters' };
    if (!/^[\x21-\x7e]+$/.test(v) || /[\\"<>^`{|}]/.test(v)) return { error: 'endpoint: plain ASCII, no spaces or backslashes' };
    let u; try { u = new URL(v); } catch (_) { return { error: 'endpoint: a URL' }; }
    if (u.username || u.password || u.search || u.hash || /[?#@]/.test(v)) return { error: 'endpoint: no credentials, query or fragment' };
    const norm = u.href.replace(/\/+$/, '');
    if (norm !== v) return { error: `endpoint: give it in normal form (${norm})` };
    if (u.protocol === 'https:') return { endpoint: norm };
    if (u.protocol === 'http:' && /^[a-z0-9-]+(\.[a-z0-9-]+)*\.ts\.net$/.test(u.hostname)) return { endpoint: norm };
    return { error: 'endpoint: https (http only on a tailnet *.ts.net host)' };
  }
  // Which MCP server callers' machines run for a tenant is code on their machines, run with their DemiPass session
  // nearby: first-party only (the demipass package's own servers) until there is a trust model for others (#87 M2).
  const MCP_FIRST_PARTY_SERVERS = new Set(['demipass#demipass-mcp', 'demipass#fleetgate-mcp']);   // the MCP servers the demipass package ships
  const MCP_FIRST_PARTY = { test: (v) => MCP_FIRST_PARTY_SERVERS.has(v) };
  app.put('/api/services/:slug/connect', lim, (req, res) => {
    const auth = walletAuth(req, res); if (!auth) return;
    const t = tenantBySlug(req.params.slug);
    if (!t) return res.status(404).json({ error: 'no such service' });
    if (auth.did !== t.service_did && auth.did !== t.owner_did) return res.status(403).json({ error: 'the tenant wallet or its owner sets where callers connect' });
    const b = req.body || {};
    const endpoint = b.endpoint === undefined ? (t.endpoint || '') : String(b.endpoint).trim().replace(/\/+$/, '');
    const mcp = b.mcp_server === undefined ? (t.mcp_server || '') : String(b.mcp_server).trim();
    const ne = normalizeEndpoint(endpoint);
    if (ne.error) return res.status(400).json({ error: ne.error });
    if (mcp !== '' && !MCP_SERVER_RE.test(mcp)) return res.status(400).json({ error: 'mcp_server: "<npm package>#<bin>", e.g. demipass#fleetgate-mcp' });
    if (mcp !== '' && !MCP_FIRST_PARTY.test(mcp)) return res.status(403).json({ error: `mcp_server: only first-party servers for now (${[...MCP_FIRST_PARTY_SERVERS].join(', ')})` });
    if (endpoint === (t.endpoint || '') && mcp === (t.mcp_server || '')) return res.json({ ok: true, unchanged: true, ...tenantView(t) });
    const g = personApproval('svc:demipass:connect', `point callers of ${t.slug} at ${endpoint || '(nothing)'}; their agents run ${mcp || '(no MCP server)'}`, t.owner_did, 'elevated',
      { did: auth.did, label: t.slug }, 'connect', t.slug, { service: t.slug, endpoint, mcp_server: mcp, was: { endpoint: t.endpoint || '', mcp_server: t.mcp_server || '' } }, b, null);
    if (!g.ok) return res.status(g.status).json(g.body);
    db.prepare('UPDATE service_tenants SET endpoint = ?, mcp_server = ? WHERE id = ?').run(endpoint, mcp, t.id);
    event('service_connect_set', auth.did, { service: t.slug, endpoint, mcp_server: mcp, approval_id: g.approval_id });
    logSecurityEvent('service_connect_set', 'info', { caller_did: auth.did, capability: 'service-connect', target: t.slug, context: { endpoint, mcp_server: mcp } });
    res.json({ ok: true, ...tenantView(tenantBySlug(t.slug)) });
  });

  // The tenant's margin over its measured cost (what callers pay above it): {margin_pct} 0..MAX_MARGIN_PCT. Only the
  // tenant's owner asks, from their own session, and approves it in the app (svc:demipass:margin): it changes what every
  // caller pays. Charges already made keep the margin in their row and receipt.
  app.put('/api/services/:slug/margin', lim, (req, res) => {
    const auth = walletAuth(req, res); if (!auth) return;
    const t = tenantBySlug(req.params.slug);
    if (!t) return res.status(404).json({ error: 'no such service' });
    if (auth.did !== t.owner_did || isAgentToken(auth)) return res.status(403).json({ error: 'the tenant\'s owner sets its margin, from their own session' });
    const b = req.body || {};
    const m = b.margin_pct;
    if (!Number.isInteger(m) || m < 0 || m > MAX_MARGIN_PCT) return res.status(400).json({ error: `margin_pct: a whole number 0..${MAX_MARGIN_PCT}` });
    if (m === marginOf(t)) return res.json({ ok: true, unchanged: true, ...tenantView(t) });
    const g = personApproval('svc:demipass:margin', `${t.slug}: margin ${marginOf(t)}% → ${m}%`, t.owner_did, 'elevated', { did: auth.did, label: t.slug }, 'margin', t.slug,
      { service: t.slug, margin_pct: m, was: marginOf(t) }, b, null);
    if (!g.ok) return res.status(g.status).json(g.body);
    db.prepare('UPDATE service_tenants SET margin_pct = ? WHERE id = ?').run(m, t.id);
    event('service_margin_set', auth.did, { service: t.slug, margin_pct: m, approval_id: g.approval_id });
    logSecurityEvent('service_margin_set', 'info', { caller_did: auth.did, capability: 'service-margin', target: t.slug, context: { margin_pct: m, was: marginOf(t) } });
    res.json({ ok: true, ...tenantView(tenantBySlug(t.slug)) });
  });

  // The tenant's price list. The tenant wallet or its owner. Anything that weakens a gate — a lower depth, a closed
  // action opened, a gated action moved to another scope, an action added to (or moved into) a scope someone holds by
  // delegation — waits on the tenant owner's approval of exactly that change (#68 review M3).
  app.put('/api/services/:slug/actions', lim, (req, res) => {
    const auth = walletAuth(req, res); if (!auth) return;
    const t = tenantBySlug(req.params.slug);
    if (!t) return res.status(404).json({ error: 'no such service' });
    if (auth.did !== t.service_did && auth.did !== t.owner_did) return res.status(403).json({ error: 'the tenant wallet or its owner sets prices' });
    const body = req.body || {};
    const list = body.actions;
    if (!Array.isArray(list) || !list.length || list.length > 50) return res.status(400).json({ error: 'actions: 1-50 entries' });
    const rows = [];
    for (const a of list) {
      if (!a || typeof a !== 'object') return res.status(400).json({ error: 'each action is an object' });
      const action = String(a.action || '');
      if (!ACTION_RE.test(action)) return res.status(400).json({ error: `action '${action}': 1-41 of [a-z0-9_.-]` });
      const cur = anyActionOf(t, action);
      const scope = a.scope !== undefined ? String(a.scope) : (cur ? cur.scope : action);   // omitted: keep the current scope
      if (!ACTION_RE.test(scope)) return res.status(400).json({ error: `scope '${scope}': 1-41 of [a-z0-9_.-]` });
      if (a.retired === true) { rows.push({ action, retired: true }); continue; }
      // Omitted on an existing action: keep its costs (e.g. a change to follow_ups alone).
      const cost = a.measured_cost_dd === undefined && cur ? cur.measured_cost_dd : a.measured_cost_dd;
      const max = a.max_cost_dd === undefined ? (a.measured_cost_dd === undefined && cur ? cur.max_cost_dd : cost) : a.max_cost_dd;
      if (!Number.isInteger(cost) || cost < 1 || cost > MAX_COST_DD) return res.status(400).json({ error: `${action}: measured_cost_dd 1-${MAX_COST_DD}` });
      if (!Number.isInteger(max) || max < cost || max > MAX_COST_DD) return res.status(400).json({ error: `${action}: max_cost_dd from measured_cost_dd to ${MAX_COST_DD}` });
      const depth = a.depth === undefined ? (cur ? cur.depth : 'standard') : String(a.depth);
      if (!DEPTHS.includes(depth)) return res.status(400).json({ error: `${action}: depth is one of ${DEPTHS.join(', ')}` });
      const open = a.open === undefined ? (cur ? cur.open : 1) : (a.open ? 1 : 0);
      // follow_ups: the actions that may bill as follow-ups of this one (it starts work). Omitted: keep the current list.
      let fus = a.follow_ups === undefined ? jsonList(cur && cur.follow_ups) : a.follow_ups;
      if (!Array.isArray(fus) || fus.length > 10 || fus.some(x => typeof x !== 'string' || !ACTION_RE.test(x))) return res.status(400).json({ error: `${action}: follow_ups is a list of up to 10 action names` });
      fus = [...new Set(fus)];
      rows.push({ action, scope, cost, max, depth, open, follow_ups: fus });
    }
    // A follow-up must already be a priced, active, standard action (in this call or before it): an approved list can
    // never name an action the tenant creates later, wherever it puts it (#88 re-review L1).
    for (const r of rows) {
      for (const f of (r.follow_ups || [])) {
        const inCall = rows.find(x => x.action === f && !x.retired);
        const live = inCall || actionOf(t, f);
        if (!live || (inCall ? inCall.depth : live.depth) !== 'standard') return res.status(400).json({ error: `${r.action}: follow-up '${f}' must be an existing standard action` });
      }
    }
    const delegated = (scope) => Boolean(db.prepare("SELECT 1 FROM service_delegations WHERE tenant_id = ? AND scope = ? AND status = 'active' LIMIT 1").get(t.id, scope));
    // Compared with the row whatever its status: retiring and re-adding is no way around this.
    const weakens = rows.filter(r => {
      if (r.retired) return false;
      const cur = anyActionOf(t, r.action);
      if (!cur) return delegated(r.scope);
      // Letting an action start billable follow-up work, or adding to what may follow it, is weakening too (#88 H1/H2).
      const addsFollowUps = (r.follow_ups || []).some(x => !jsonList(cur.follow_ups).includes(x));
      return addsFollowUps || DEPTHS.indexOf(r.depth) < DEPTHS.indexOf(cur.depth) || (r.open && !cur.open)
        || (r.scope !== cur.scope && (cur.depth !== 'standard' || !cur.open || delegated(r.scope)));
    }).concat(rows.filter(r => !r.retired && !anyActionOf(t, r.action) && !delegated(r.scope) && ((r.follow_ups || []).length
      || db.prepare("SELECT 1 FROM service_actions WHERE tenant_id = ? AND follow_ups LIKE ? LIMIT 1").get(t.id, '%"' + r.action + '"%'))));
    if (weakens.length) {
      const g = personApproval(`svc:demipass:weaken`, `weaken ${t.slug} actions`, t.owner_did, 'elevated', { did: auth.did, label: t.slug }, 'weaken', t.slug,
        { service: t.slug, changes: weakens.map(r => ({ action: r.action, scope: r.scope, depth: r.depth, open: Boolean(r.open), ...((r.follow_ups || []).length ? { follow_ups: r.follow_ups } : {}) })) }, body, null);
      if (!g.ok) return res.status(g.status).json({ ...g.body, weakens: weakens.map(r => r.action) });
    }
    const at = nowIso();
    db.transaction(() => {
      for (const r of rows) {
        if (r.retired) { db.prepare("UPDATE service_actions SET status = 'retired', updated_at = ? WHERE tenant_id = ? AND action = ?").run(at, t.id, r.action); continue; }
        db.prepare(`INSERT INTO service_actions (tenant_id, action, scope, measured_cost_dd, max_cost_dd, depth, open, status, updated_at, follow_ups)
                    VALUES (?, ?, ?, ?, ?, ?, ?, 'active', ?, ?)
                    ON CONFLICT(tenant_id, action) DO UPDATE SET scope = excluded.scope, measured_cost_dd = excluded.measured_cost_dd,
                      max_cost_dd = excluded.max_cost_dd, depth = excluded.depth, open = excluded.open, status = 'active', updated_at = excluded.updated_at,
                      follow_ups = excluded.follow_ups`)
          .run(t.id, r.action, r.scope, r.cost, r.max, r.depth, r.open, at, r.follow_ups && r.follow_ups.length ? JSON.stringify(r.follow_ups) : null);
      }
    })();
    event('service_actions_set', auth.did, { service: t.slug, actions: rows.map(r => r.action), weakened: weakens.map(r => r.action) });
    res.json({ ok: true, ...tenantView(t) });
  });

  // Consent to pay a service (#68 review H1): {service, daily_cap_dd}. The person who answers for the wallet approves
  // it in their app (themselves; an agent's fleet owner). Repeat the call with approval_id once approved. A new consent
  // replaces the old one; the payer or the approver revokes it.
  app.post('/api/services/consent', lim, (req, res) => {
    const auth = walletAuth(req, res); if (!auth) return;
    const b = req.body || {};
    const t = tenantBySlug(b.service);
    if (!t) return res.status(404).json({ error: 'service: no such service' });
    if (auth.did === t.service_did) return res.status(400).json({ error: 'a tenant does not pay itself' });
    const cap = b.daily_cap_dd;
    if (!Number.isInteger(cap) || cap < 1 || cap > CONSENT_CAP_MAX_DD) return res.status(400).json({ error: `daily_cap_dd: 1-${CONSENT_CAP_MAX_DD} (the most ${t.slug} can charge this wallet in 24 h)` });
    // Opt-in: let this tenant also charge for work this wallet asks for by a Conduit message, at most this much per
    // request (origin + follow-ups). Part of what the person approves (it is in the approval's bound parameters).
    const orc = b.on_request_cap_dd === undefined || b.on_request_cap_dd === null ? null : b.on_request_cap_dd;
    if (orc !== null && (!Number.isInteger(orc) || orc < 1 || orc > cap)) return res.status(400).json({ error: `on_request_cap_dd: 1-${cap} (the most one Conduit request may run up; at most the daily cap)` });
    const approver = personFor(auth.did);
    if (!approver) return res.status(403).json({ error: 'an agent no fleet created has no person to consent for it' });
    // A wallet consenting for itself: the barrel tier applies to what the consent lets out in a day, not only per
    // charge (re-review L). An agent's consent is its creator's to approve, with the creator's PIN and phone.
    const barrel = approver === auth.did ? barrelRefusal(auth.did, cap) : null;
    if (barrel) return res.status(barrel.statusCode || 403).json(barrel.body || { error: barrel.message });
    const g = personApproval('svc:demipass:consent', `let a wallet pay ${t.slug}`, approver, 'elevated', { did: auth.did, label: '' }, 'consent', 'demipass',
      { service: t.slug, wallet: auth.did, daily_cap_dd: cap, ...(orc !== null ? { on_request_cap_dd: orc } : {}) }, b, null);
    if (!g.ok) return res.status(g.status).json(g.body);
    const at = nowIso();
    const id = db.transaction(() => {
      db.prepare("UPDATE service_consents SET status = 'replaced', revoked_at = ? WHERE payer_did = ? AND tenant_id = ? AND status = 'active'").run(at, auth.did, t.id);
      return Number(db.prepare('INSERT INTO service_consents (payer_did, tenant_id, daily_cap_dd, approved_by, approval_id, created_at, on_request_cap_dd) VALUES (?, ?, ?, ?, ?, ?, ?)')
        .run(auth.did, t.id, cap, approver, g.approval_id, at, orc).lastInsertRowid);
    })();
    event('service_consent', auth.did, { consent_id: id, service: t.slug, daily_cap_dd: cap, on_request_cap_dd: orc, approval_id: g.approval_id });
    res.status(201).json({ ok: true, consent_id: id, service: t.slug, daily_cap_dd: cap, on_request_cap_dd: orc });
  });
  app.post('/api/services/consents/:id/revoke', lim, (req, res) => {
    const auth = walletAuth(req, res, { minScope: 'read' }); if (!auth) return;
    const id = Number(req.params.id);
    const c = Number.isInteger(id) && id > 0 ? db.prepare("SELECT * FROM service_consents WHERE id = ? AND (payer_did = ? OR approved_by = ?)").get(id, auth.did, auth.did) : null;
    if (!c) return res.status(404).json({ error: 'no consent of yours with that id' });
    if (c.status !== 'active') return res.status(409).json({ error: `already ${c.status}` });
    db.prepare("UPDATE service_consents SET status = 'revoked', revoked_at = ? WHERE id = ? AND status = 'active'").run(nowIso(), id);
    event('service_consent_revoked', auth.did, { consent_id: id });
    res.json({ ok: true, revoked: true, consent_id: id });
  });

  // A caller mints a token for one tenant it has consent to pay. Its own token (agents' fleet-minted ones included),
  // transact scope. The new token lives at most as long as the one minting it, and dies with it.
  app.post('/api/services/token', lim, (req, res) => {
    const auth = walletAuth(req, res); if (!auth) return;
    const b = req.body || {};
    const t = tenantBySlug(b.service);
    if (!t) return res.status(404).json({ error: 'service: no such service (GET /api/services)' });
    if (auth.did === t.service_did) return res.status(400).json({ error: 'a tenant does not call itself' });
    const consent = liveConsent(auth.did, t);
    if (!consent) return res.status(403).json({ error: `consent to pay ${t.slug} first: POST /api/services/consent {service, daily_cap_dd} (approved in the DemiPass app)`, consent_required: true });
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
    const cap = b.cap_dd === undefined ? Math.min(TOKEN_CAP_DEFAULT_DD, consent.daily_cap_dd) : b.cap_dd;
    // The follow-up budget: what work this token starts may keep billing after it expires (review rounds). Opt-in,
    // never above the daily consent (which still caps every day).
    const fuDd = b.follow_up_dd === undefined ? 0 : b.follow_up_dd;
    if (!Number.isInteger(fuDd) || fuDd < 0 || fuDd > consent.daily_cap_dd) return res.status(400).json({ error: `follow_up_dd: 0-${consent.daily_cap_dd} (your daily consent for ${t.slug})` });
    if (!Number.isInteger(cap) || cap < 1 || cap > consent.daily_cap_dd) return res.status(400).json({ error: `cap_dd: 1-${consent.daily_cap_dd} (your daily consent for ${t.slug})` });
    const w = db.prepare('SELECT encrypted_private_key, did, status FROM identity_wallets WHERE did = ?').get(auth.did);
    if (!w || w.status !== 'active' || !w.encrypted_private_key) return res.status(403).json({ error: 'wallet not active' });
    const dec = auth.decoded || {};
    const meta = { iss: SVC_ISS, aud: 'svc:' + t.slug, auth_method: 'service_token', cap_dd: cap, ...(fuDd ? { fu_dd: fuDd } : {}), minted_by_jti: dec.jti || null,
      ...(dec.sid ? { sid: dec.sid } : {}), ...(dec.auth_method ? { src_auth: dec.auth_method } : {}), ...(dec.fleet ? { fleet: dec.fleet } : {}),
      ...(scopes ? { svc_scopes: scopes } : {}) };
    let token;
    try { token = identity.createTokenForIdentity(w.encrypted_private_key, w.did, { scope: 'transact', expiresIn: `${ttl}s`, metadata: meta }); }
    catch (e) { return res.status(500).json({ error: 'token mint failed' }); }
    const d = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8'));
    event('service_token_minted', auth.did, { service: t.slug, token_id: d.jti, cap_dd: cap, exp: d.exp });
    res.status(201).json({ ok: true, token, token_id: d.jti, service: t.slug, audience: d.aud, scope: d.scope, cap_dd: cap, follow_up_dd: fuDd,
      ...(scopes ? { scopes } : {}), expires_at: new Date(d.exp * 1000).toISOString(),
      use: `send it to ${t.name} as Authorization: Bearer <token>; it opens nothing at DemiPass itself` });
  });

  app.post('/api/services/token/revoke', lim, (req, res) => {
    const auth = walletAuth(req, res, { minScope: 'read' }); if (!auth) return;
    const id = String((req.body || {}).token_id || '');
    if (!/^[0-9a-f]{8,64}$/.test(id)) return res.status(400).json({ error: 'token_id' });
    const r = db.prepare("UPDATE issued_tokens SET revoked = 1, revoked_at = datetime('now') WHERE jti = ? AND did = ? AND revoked = 0").run(id, auth.did);
    if (!r.changes) return res.status(404).json({ error: 'no live token of yours with that id' });
    event('service_token_revoked', auth.did, { token_id: id });
    res.json({ ok: true, revoked: true, token_id: id });
  });

  // Delegation of a service scope, use-only, to an agent the person's own fleet created (#68 review H2: nobody pushes a
  // scope onto someone else's agent). A person's own session, never an agent token, so agents never hand a scope on.
  // The delegate calls with its own service token and pays from its own wallet; depth comes with the scope.
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
    if (acts.some(a => !a.open) && auth.did !== t.owner_did) return res.status(403).json({ error: `'${scope}' at ${t.slug} is held by its owner only` });
    const delegate = String(b.delegate_did || '');
    if (!db.prepare('SELECT 1 FROM identity_wallets WHERE did = ?').get(delegate)) return res.status(404).json({ error: 'delegate_did: no such wallet' });
    if (delegate === t.service_did) return res.status(400).json({ error: 'not to the tenant itself' });
    if (!ownAgent(auth.did, delegate)) return res.status(403).json({ error: 'a service scope goes to an agent your own fleet created' });
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
    const r = charge(a.tenant, req.body);
    res.status(r.status).json(r.body);
  });

  app.post('/api/services/charge-on-request', lim, (req, res) => {
    const a = tenantAuth(req, res); if (!a) return;
    const r = chargeOnRequest(a.tenant, req.body);
    res.status(r.status).json(r.body);
  });

  app.post('/api/services/receipts/verify', lim, (req, res) => {
    const { receipt, sig } = req.body || {};
    if (!meterKey) return res.status(503).json({ error: 'signing key unavailable' });
    if (typeof receipt !== 'string' || typeof sig !== 'string' || receipt.length > 4096 || sig.length > 200) return res.status(400).json({ error: 'receipt (string) and sig' });
    let ok = false;
    try { ok = crypto.verify(null, Buffer.from(RECEIPT_DOMAIN + receipt, 'utf8'), crypto.createPublicKey({ key: meterKey.publicKeyDer, format: 'der', type: 'spki' }), Buffer.from(sig, 'base64url')); } catch (_) {}
    if (!ok) return res.json({ valid: false, error: 'signature does not verify against this server\'s key' });
    let p; try { p = JSON.parse(receipt); } catch (_) { return res.json({ valid: false, error: 'not JSON' }); }
    const row = db.prepare('SELECT receipt FROM service_charges WHERE charge_id = ?').get(p.charge_id);
    res.json({ valid: true, on_record: !!row && row.receipt === receipt, charge: p });
  });

  return { verify, charge, chargeOnRequest, verifyServiceToken, priceOf, tenantBySlug, SERVICE_MARGIN_PCT, issuer };
};

module.exports.SERVICE_MARGIN_PCT = SERVICE_MARGIN_PCT;
module.exports.priceOf = priceOf;
module.exports.SVC_ISS = SVC_ISS;
module.exports.RECEIPT_DOMAIN = RECEIPT_DOMAIN;
module.exports.requestKey = requestKey;
module.exports.REQUEST_MAX_AGE_MS = REQUEST_MAX_AGE_MS;
