'use strict';
// ── Agent (fleet silicon) token requests: asked for by whoever acts in the fleet, approved in the owner's app ───────
// Aaron 2026-11-08: "Request Conduit's tenant token through the normal path: file it as a DemiPass request … so it lands
// in my app for approval, same as the scanner tokens did. Don't wait on my session to mint it."
// The shape is the leak scanner's (leak_scan.js): a request, the owner's approval with the PIN (and the linked phone),
// and a one-time claim by whoever holds the claim secret. The token is shown to nobody else, ever.
//
//   POST /api/fleet/:slug/silicons/:handle/token-requests {scope?, expires_in?, label?, claim_secret_hash?}
//        any member of the fleet (the owner, an admin or another agent) → 202 {request_id, claim_secret?}
//        claim_secret_hash (sha256 hex of a secret the requester keeps, e.g. inside a container) means the filer never
//        sees the secret; without it, a claim_secret is generated and returned here, once.
//   GET  /api/silicon-token-requests                  the owner's waiting requests (the app)
//   POST /api/silicon-token-requests/:id/approve      the fleet owner, own session, PIN (silicon-token:<id>) + linked phone
//   POST /api/silicon-token-requests/:id/deny         the fleet owner
//   POST /api/silicon-token-requests/:id/claim {claim_secret}   no session: the secret is the proof; 202 while pending
//        (also at POST /api/fleet/:slug/silicons/:handle/token-requests/:id/claim)
// Creating an agent by request (Aaron 2026-11-09: "File 'create an agent' as a dustforge app request … the provisioner
// is fleet-created like Conduit"): the same call for a handle the fleet does not have yet, with `create`:
//   POST /api/fleet/:slug/silicons/:handle/token-requests {create: {display_name?, username?}, scope?, expires_in?, …}
// On the owner's approval (PIN + phone, the phone's text starting "create ") the fleet creates the agent exactly as the
// owner's own POST /api/fleet/:slug/silicons {create} does (fleet_routes.js createFleetSilicon: mailbox + wallet,
// charged like /provision, created_by_fleet = 1) and mints its first token; the claim hands over the token, the DID and
// the mailbox password, once.
// A request waits REQUEST_TTL_SEC for the owner; an approved token waits CLAIM_TTL_SEC to be claimed, then it is
// revoked (nobody holds it). The minted token is what POST …/silicons/:handle/token makes (auth_method
// fleet_owner_mint: it acts as the agent's wallet but never runs a fleet), capped at transact.

const REQUEST_TTL_SEC = 24 * 60 * 60;   // the owner may be away: a day to decide
const CLAIM_TTL_SEC = 60 * 60;
const MAX_PENDING_PER_SILICON = 3;
const MAX_PENDING_PER_FLEET = 20;
const TOKEN_SCOPE_CAP = 'transact';
const HEX64 = /^[0-9a-f]{64}$/;

module.exports = function registerSiliconTokenRequests(deps) {
  const { app, db, identity, crypto, fleetBilling: fb, rateLimitStandard, getBearerIdentity, gateSession, gateFresh, gateMissing,
          spendSingleUse, blindkeyEncrypt, blindkeyDecrypt, logSecurityEvent } = deps;
  const devices = deps.devices || (() => null);
  const sendMail = deps.sendMail || (() => Promise.resolve(false));

  db.exec(`CREATE TABLE IF NOT EXISTS silicon_token_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fleet_id INTEGER NOT NULL,
    fleet_slug TEXT NOT NULL,
    silicon_row INTEGER NOT NULL,           -- fleet_silicons.id
    handle TEXT NOT NULL,
    member_did TEXT NOT NULL,               -- the agent's wallet the token is for
    owner_did TEXT NOT NULL,                -- the fleet owner, who decides
    requested_by_did TEXT NOT NULL,
    says_it_is TEXT DEFAULT '',             -- the requester's own label, shown as its claim, never as fact
    scope TEXT NOT NULL,
    expires_in TEXT NOT NULL,
    claim_hash TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending', -- pending | approved | claimed | denied | expired
    sealed TEXT DEFAULT NULL,               -- the minted token, encrypted, between approval and claim only
    token_jti TEXT DEFAULT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    decided_at TEXT DEFAULT NULL,
    claimed_at TEXT DEFAULT NULL
  )`);
  try { db.exec("ALTER TABLE silicon_token_requests ADD COLUMN requester_role TEXT DEFAULT ''"); } catch (_) {}
  // Agent creation requests: the agent does not exist when asked for (silicon_row 0, member_did '' until approval).
  for (const col of ["creates INTEGER DEFAULT 0", "display_name TEXT DEFAULT ''", "username TEXT DEFAULT ''"]) {
    try { db.exec(`ALTER TABLE silicon_token_requests ADD COLUMN ${col}`); } catch (_) {}
  }
  db.exec('CREATE INDEX IF NOT EXISTS idx_str_owner ON silicon_token_requests(owner_did, status)');

  const sha = (t) => crypto.createHash('sha256').update(String(t)).digest('hex');
  const nowIso = () => new Date().toISOString();
  const later = (sec) => new Date(Date.now() + sec * 1000).toISOString();
  const clean = (s, n) => String(s == null ? '' : s).replace(/[\u0000-\u001f\u007f​-‏‪-‮⁦-⁩﻿]/g, '').trim().slice(0, n);
  const mailOwner = (did, subject, text) => {
    const w = db.prepare('SELECT email FROM identity_wallets WHERE did = ?').get(did);
    try { if (w && w.email) Promise.resolve(sendMail({ to: w.email, subject, text })).catch(() => {}); } catch (_) {}
  };

  // Requests past their time end; tokens approved but never claimed are revoked (nobody holds them).
  function expireRequests() {
    const t = nowIso();
    for (const r of db.prepare("SELECT id, token_jti FROM silicon_token_requests WHERE status = 'approved' AND expires_at <= ?").all(t)) {
      if (r.token_jti) db.prepare("UPDATE issued_tokens SET revoked = 1, revoked_at = datetime('now') WHERE jti = ?").run(r.token_jti);
    }
    db.prepare("UPDATE silicon_token_requests SET status = 'expired', sealed = NULL, decided_at = COALESCE(decided_at, ?) WHERE status IN ('pending','approved') AND expires_at <= ?").run(t, t);
  }
  const sweeper = setInterval(() => { try { expireRequests(); } catch (_) {} }, 60000); if (sweeper.unref) sweeper.unref();

  // The fleet owner deciding, in their own session (a person's wallet token that can hold a PIN proof).
  function ownerAuth(req, res) {
    const auth = getBearerIdentity(req);
    if (!auth.ok) { res.status(auth.status || 401).json({ error: auth.error }); return null; }
    if (auth.silicon || (auth.decoded && (auth.decoded.wrk || auth.decoded.auth_method === 'fleet_owner_mint'))) { res.status(403).json({ error: 'agent tokens are approved by the fleet owner in their own session' }); return null; }
    if (gateSession && !gateSession(auth)) { res.status(403).json({ error: 'sign in again' }); return null; }
    return auth;
  }
  const view = (r) => ({ id: r.id, fleet: r.fleet_slug, handle: r.handle, scope: r.scope, expires_in: r.expires_in, says_it_is: r.says_it_is,
    requested_by: (db.prepare('SELECT username FROM identity_wallets WHERE did = ?').get(r.requested_by_did) || {}).username || null,
    requester_role: r.requester_role || '', status: r.status, created_at: r.created_at, expires_at: r.expires_at, intent: `silicon-token:${r.id}`,
    creates: Boolean(r.creates), ...(r.creates ? { display_name: r.display_name, username: r.username, cost_dd: fleetCreate().PROVISION_COST || null } : {}) });
  const requesterName = (r) => (db.prepare('SELECT username FROM identity_wallets WHERE did = ?').get(r.requested_by_did) || {}).username || '?';
  // What the phone signs: a creation says so first, so a token for an existing agent and a new agent never share a text.
  const bindFor = (r) => `${r.creates ? 'create ' : ''}${r.fleet_slug}/${r.handle}:${r.scope}:${r.expires_in} asked by ${requesterName(r)}`;
  const fleetCreate = deps.fleetCreate || (() => ({}));

  // ── file a request ──────────────────────────────────────────────────────────────────────────────────────────────
  app.post('/api/fleet/:slug/silicons/:handle/token-requests', rateLimitStandard, (req, res) => {
    const auth = getBearerIdentity(req);
    if (!auth.ok) return res.status(auth.status || 401).json({ error: auth.error });
    // A fleet-minted token acts as its agent but never reaches the agent's other fleets or its siblings through that
    // fleet's owner (fleet_routes.js fleetAuth; leak_scan.js does the same) — #78 review M.
    if (auth.silicon || (auth.decoded && (auth.decoded.wrk || auth.decoded.auth_method === 'fleet_owner_mint'))) return res.status(403).json({ error: 'ask with a fleet member\'s own wallet token (not a fleet-minted or worker token)' });
    expireRequests();
    const fleet = db.prepare("SELECT * FROM fleets WHERE slug = ? AND COALESCE(status,'active') = 'active'").get(req.params.slug);
    if (!fleet) return res.status(404).json({ error: 'fleet not found' });
    // Membership by consent only: an active fleet_silicons row (created by the fleet, linked with the wallet's own
    // token, or joined through the network). A bare fleet_members row can be written by POST /api/fleet/:slug/invite
    // without asking the wallet (threat model item 17), so it files nothing (#77 review note on #78).
    const member = fleet.owner_did === auth.did || db.prepare("SELECT 1 FROM fleet_silicons WHERE fleet_id = ? AND member_did = ? AND status = 'active'").get(fleet.id, auth.did);
    if (!member) return res.status(403).json({ error: 'fleet membership required' });
    const b = req.body || {};
    const handle = String(req.params.handle || '').toLowerCase();
    const found = fb.getSilicon(db, fleet.id, handle);
    const creates = b.create !== undefined;
    let s, username = '', displayName = '';
    if (creates) {
      // A new agent: nothing by this handle in the fleet yet; checked now and again when the owner approves.
      if (!b.create || typeof b.create !== 'object' || Array.isArray(b.create)) return res.status(400).json({ error: 'create: an object {display_name?, username?}' });
      if (found && found.status !== 'removed') return res.status(409).json({ error: `@${handle} already exists in this fleet: ask for its token without create` });
      const fc = fleetCreate();
      if (!fc.createCheck) return res.status(501).json({ error: 'agent creation is not available here' });
      username = String(b.create.username || handle).toLowerCase();
      displayName = clean(b.create.display_name || handle, 100);
      try { fc.createCheck(fleet, handle, username); } catch (e) { return res.status(e.statusCode || 400).json(e.body || { error: e.message }); }
      if (db.prepare("SELECT 1 FROM silicon_token_requests WHERE fleet_id = ? AND creates = 1 AND status IN ('pending','creating') AND (handle = ? OR username = ?)").get(fleet.id, handle, username)) {
        return res.status(409).json({ error: `a request to create @${handle} is already waiting` });
      }
      s = { id: 0, handle, member_did: '' };
    } else {
      s = found;
      if (!s || s.status !== 'active') return res.status(404).json({ error: 'silicon not found in this fleet' });
      if (s.joined_via === 'network') return res.status(403).json({ error: `@${s.handle} joined through the network and keeps its own key: it signs in itself` });
    }
    const scope = b.scope === undefined ? TOKEN_SCOPE_CAP : String(b.scope);
    if (!identity.ISSUABLE_SCOPES.includes(scope) || identity.scopeAtLeast(scope, 'admin')) return res.status(400).json({ error: `scope must be read, write or ${TOKEN_SCOPE_CAP}` });
    // The lifetime on the owner's card is the one minted: capped here by the scope's ceiling (identity.js), at least 1 h.
    const asked = b.expires_in === undefined ? '30d' : String(b.expires_in);
    const m = /^(\d{1,5})([smhd])$/.exec(asked);
    if (!m) return res.status(400).json({ error: 'expires_in: e.g. 24h, 7d, 30d' });
    const secs = Number(m[1]) * { s: 1, m: 60, h: 3600, d: 86400 }[m[2]];
    if (secs < 3600) return res.status(400).json({ error: 'expires_in: at least 1h' });
    const capSecs = Math.min(secs, (identity.SCOPE_MAX_TTL && identity.SCOPE_MAX_TTL[scope]) || 30 * 86400);
    const expiresIn = capSecs % 86400 === 0 ? `${capSecs / 86400}d` : capSecs % 3600 === 0 ? `${capSecs / 3600}h` : `${capSecs}s`;
    let claimHash, claimSecret = null;
    if (b.claim_secret_hash !== undefined) {
      claimHash = String(b.claim_secret_hash).toLowerCase();
      if (!HEX64.test(claimHash)) return res.status(400).json({ error: 'claim_secret_hash: the sha256 (64 hex) of a secret you keep' });
    } else { claimSecret = crypto.randomBytes(24).toString('base64url'); claimHash = sha(claimSecret); }
    if ((!creates && db.prepare("SELECT COUNT(*) AS n FROM silicon_token_requests WHERE silicon_row = ? AND status = 'pending'").get(s.id).n >= MAX_PENDING_PER_SILICON)
      || db.prepare("SELECT COUNT(*) AS n FROM silicon_token_requests WHERE fleet_id = ? AND status = 'pending'").get(fleet.id).n >= MAX_PENDING_PER_FLEET) {
      return res.status(429).json({ error: 'too many token requests waiting for the owner' });
    }
    const says = clean(b.label || (auth.decoded && (auth.decoded.agent_name || auth.decoded.label)) || '', 80);
    // Who is asking, as the owner's card says it: the owner, the agent itself, or ANOTHER agent of the fleet.
    const role = auth.did === fleet.owner_did ? 'owner' : (!creates && auth.did === s.member_did) ? 'self'
      : (db.prepare('SELECT role FROM fleet_members WHERE fleet_id = ? AND member_did = ?').get(fleet.id, auth.did) || {}).role === 'admin' ? 'admin'
      // A member the fleet did not create (joined through the network or linked) is someone else's wallet: say so (#79 review).
      : db.prepare("SELECT 1 FROM fleet_silicons WHERE fleet_id = ? AND member_did = ? AND status = 'active' AND created_by_fleet = 1 AND COALESCE(joined_via, 'owner') != 'network'").get(fleet.id, auth.did) ? 'other_agent' : 'outside_agent';
    const id = Number(db.prepare(`INSERT INTO silicon_token_requests (fleet_id, fleet_slug, silicon_row, handle, member_did, owner_did, requested_by_did,
        says_it_is, requester_role, scope, expires_in, claim_hash, created_at, expires_at, creates, display_name, username) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .run(fleet.id, fleet.slug, s.id, s.handle, s.member_did, fleet.owner_did, auth.did, says, role, scope, expiresIn, claimHash, nowIso(), later(REQUEST_TTL_SEC),
        creates ? 1 : 0, displayName, username).lastInsertRowid);
    const who = role === 'outside_agent' ? 'A WALLET YOUR FLEET DID NOT CREATE, in' : role === 'other_agent' ? 'ANOTHER AGENT of' : 'Someone in';
    if (creates) {
      mailOwner(fleet.owner_did, `DemiPass: a new agent @${s.handle} is asked for`,
        `${who} your fleet ${fleet.slug} asks you to CREATE a new agent @${s.handle} (wallet and mailbox ${username}@dustforge.com, charged like a provision) and give it a ${scope} token (lasting ${expiresIn})${says ? `, saying it is for "${says}"` : ''}. If you approve, the wallet that asked receives that token and the new mailbox's password, and can act as @${s.handle}.\nApprove or deny it in the DemiPass app (Settings → Agent token requests). It waits ${REQUEST_TTL_SEC / 3600} hours.\n`);
    } else {
      mailOwner(fleet.owner_did, `DemiPass: a token for @${s.handle} is asked for`,
        `${who} your fleet ${fleet.slug} asks for a ${scope} token for @${s.handle} (lasting ${expiresIn})${says ? `, saying it is for "${says}"` : ''}.${role === 'other_agent' || role === 'outside_agent' ? ' If you approve, the wallet that asked can act as @' + s.handle + '.' : ''}\nApprove or deny it in the DemiPass app (Settings → Agent token requests). It waits ${REQUEST_TTL_SEC / 3600} hours.\n`);
    }
    res.status(202).json({ ok: true, request_id: id, ...(claimSecret ? { claim_secret: claimSecret } : {}), expires_at: later(REQUEST_TTL_SEC),
      next: `the fleet owner approves it in the DemiPass app; then POST /api/silicon-token-requests/${id}/claim {claim_secret} once` });
  });

  // ── the owner's side ────────────────────────────────────────────────────────────────────────────────────────────
  app.get('/api/silicon-token-requests', rateLimitStandard, (req, res) => {
    const auth = ownerAuth(req, res); if (!auth) return;
    expireRequests();
    const rows = db.prepare("SELECT * FROM silicon_token_requests WHERE owner_did = ? AND status = 'pending' ORDER BY id DESC").all(auth.did);
    res.json({ ok: true, requests: rows.map(view) });
  });

  app.post('/api/silicon-token-requests/:id/approve', rateLimitStandard, async (req, res) => {
    const auth = ownerAuth(req, res); if (!auth) return;
    expireRequests();
    const r = db.prepare('SELECT * FROM silicon_token_requests WHERE id = ? AND owner_did = ?').get(Number(req.params.id), auth.did);
    if (!r) return res.status(404).json({ error: 'token request not found' });
    if (r.status !== 'pending') return res.status(409).json({ error: `this request is ${r.status}` });
    // The fleet is still this owner's and the agent still in it, as it was asked for.
    const fleet = db.prepare('SELECT * FROM fleets WHERE id = ?').get(r.fleet_id);
    if (!fleet || fleet.owner_did !== auth.did || (fleet.status && fleet.status !== 'active')) {
      return res.status(409).json({ error: 'the fleet changed since this was asked for: ask again' });
    }
    if (r.creates) {
      // The handle and username must still be free, and the fleet able to take and pay for one more agent.
      const fc = fleetCreate();
      if (!fc.createCheck) return res.status(501).json({ error: 'agent creation is not available here' });
      try { fc.createCheck(fleet, r.handle, r.username); } catch (e) { return res.status(409).json({ error: `cannot create @${r.handle} now: ${(e.body && e.body.error) || e.message}` }); }
    } else {
      const s = fb.getSilicon(db, r.fleet_id, r.handle);
      if (!s || s.status !== 'active' || s.id !== r.silicon_row || s.joined_via === 'network') {
        return res.status(409).json({ error: 'the agent or the fleet changed since this was asked for: ask again' });
      }
    }
    // Whoever filed it must still be the owner or a consented member: a filer that left or was removed, or a request
    // filed before #79 by a bare fleet_members row, cannot be approved (#79 review).
    if (r.requested_by_did !== fleet.owner_did && !db.prepare("SELECT 1 FROM fleet_silicons WHERE fleet_id = ? AND member_did = ? AND status = 'active'").get(r.fleet_id, r.requested_by_did)) {
      return res.status(409).json({ error: 'whoever asked for this is no longer in your fleet: it cannot be approved' });
    }
    const intent = `silicon-token:${r.id}`;
    if (!gateFresh(auth.did, 'pin', auth, intent)) return res.status(403).json({ ...gateMissing('silicon-token', ['pin'], ['pin'], intent), error: `a token for @${r.handle} needs your PIN` });
    const dk = devices();
    const refused = dk ? dk.approvalRefusal(auth, 'silicon-token', r.id, bindFor(r), req.body) : null;
    if (refused) return res.status(refused.status).json(refused.body);
    if (r.creates) return approveCreate(req, res, auth, r, fleet, intent);
    const wallet = db.prepare('SELECT * FROM identity_wallets WHERE did = ?').get(r.member_did);
    if (!wallet) return res.status(404).json({ error: 'identity not found' });
    try {
      db.transaction(() => {
        const spent = spendSingleUse(auth.did, 'silicon-token', ['pin'], auth, intent);
        if (spent) throw Object.assign(new Error(spent.error), { statusCode: spent.status || 403, body: spent });
        const token = identity.createTokenForIdentity(wallet.encrypted_private_key, wallet.did, {
          scope: r.scope, expiresIn: r.expires_in,
          metadata: { email: wallet.email, username: wallet.username, auth_method: 'fleet_owner_mint', fleet: r.fleet_slug, minted_by: auth.did, token_request: r.id },
        });
        const jti = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString()).jti || null;
        const n = db.prepare("UPDATE silicon_token_requests SET status = 'approved', sealed = ?, token_jti = ?, decided_at = ?, expires_at = ? WHERE id = ? AND status = 'pending'")
          .run(blindkeyEncrypt(token), jti, nowIso(), later(CLAIM_TTL_SEC), r.id).changes;
        if (n !== 1) throw Object.assign(new Error('this request changed meanwhile'), { statusCode: 409 });
      }).immediate();
    } catch (e) { return res.status(e.statusCode || 500).json(e.body || { error: e.message }); }
    if (logSecurityEvent) logSecurityEvent('silicon_token_minted', 'warn', { caller_did: auth.did, ip: req.ip, target: r.handle, context: { request_id: r.id, fleet: r.fleet_slug, scope: r.scope } });
    res.json({ ok: true, approved: { handle: r.handle, scope: r.scope, expires_in: r.expires_in }, claim_within_seconds: CLAIM_TTL_SEC });
  });

  // An approved creation: the PIN is spent and the request taken ('creating') in one step, so a second approval cannot
  // make a second agent; then the fleet creates the agent and its first token is minted and sealed for the claim.
  async function approveCreate(req, res, auth, r, fleet, intent) {
    try {
      db.transaction(() => {
        const spent = spendSingleUse(auth.did, 'silicon-token', ['pin'], auth, intent);
        if (spent) throw Object.assign(new Error(spent.error), { statusCode: spent.status || 403, body: spent });
        if (db.prepare("UPDATE silicon_token_requests SET status = 'creating' WHERE id = ? AND status = 'pending'").run(r.id).changes !== 1) {
          throw Object.assign(new Error('this request changed meanwhile'), { statusCode: 409 });
        }
      }).immediate();
    } catch (e) { return res.status(e.statusCode || 500).json(e.body || { error: e.message }); }
    const password = crypto.randomBytes(18).toString('base64url');
    let made;
    try {
      made = await fleetCreate().createFleetSilicon(fleet, { handle: r.handle, displayName: r.display_name || r.handle, username: r.username, password, by: auth.did });
    } catch (e) {
      // Nothing was made: the request waits again for a fresh approval.
      db.prepare("UPDATE silicon_token_requests SET status = 'pending' WHERE id = ? AND status = 'creating'").run(r.id);
      return res.status(e.statusCode && e.statusCode !== 500 ? 409 : 500).json({ error: `@${r.handle} was not created: ${(e.body && e.body.error) || e.message}` });
    }
    try {
      const wallet = db.prepare('SELECT * FROM identity_wallets WHERE did = ?').get(made.did);
      const token = identity.createTokenForIdentity(wallet.encrypted_private_key, wallet.did, {
        scope: r.scope, expiresIn: r.expires_in,
        metadata: { email: wallet.email, username: wallet.username, auth_method: 'fleet_owner_mint', fleet: r.fleet_slug, minted_by: auth.did, token_request: r.id },
      });
      const jti = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString()).jti || null;
      db.prepare(`UPDATE silicon_token_requests SET status = 'approved', member_did = ?, silicon_row = ?, sealed = ?, token_jti = ?, decided_at = ?, expires_at = ?
                  WHERE id = ? AND status = 'creating'`)
        .run(made.did, made.silicon.id, blindkeyEncrypt(JSON.stringify({ token, password })), jti, nowIso(), later(CLAIM_TTL_SEC), r.id);
    } catch (e) {
      // The agent exists (the owner approved it); only its first token failed. It stays in the fleet; ask for a token.
      db.prepare("UPDATE silicon_token_requests SET status = 'denied', decided_at = ? WHERE id = ? AND status = 'creating'").run(nowIso(), r.id);
      return res.status(500).json({ error: `@${r.handle} was created, but its token could not be minted: ask for a token for @${r.handle}` });
    }
    if (logSecurityEvent) logSecurityEvent('silicon_created_by_request', 'warn', { caller_did: auth.did, ip: req.ip, target: r.handle, context: { request_id: r.id, fleet: r.fleet_slug, did: made.did, scope: r.scope } });
    res.json({ ok: true, created: { handle: r.handle, did: made.did, email: made.email }, approved: { handle: r.handle, scope: r.scope, expires_in: r.expires_in }, claim_within_seconds: CLAIM_TTL_SEC });
  }

  app.post('/api/silicon-token-requests/:id/deny', rateLimitStandard, (req, res) => {
    const auth = ownerAuth(req, res); if (!auth) return;
    const n = db.prepare("UPDATE silicon_token_requests SET status = 'denied', decided_at = ? WHERE id = ? AND owner_did = ? AND status = 'pending'").run(nowIso(), Number(req.params.id), auth.did).changes;
    res.status(n ? 200 : 404).json(n ? { ok: true } : { error: 'no waiting request by that id' });
  });

  // ── the claim: no session, the secret is the proof; the token comes out once ────────────────────────────────────
  function claim(req, res) {
    expireRequests();
    const r = db.prepare('SELECT * FROM silicon_token_requests WHERE id = ?').get(Number(req.params.id));
    const presented = Buffer.from(sha(String((req.body || {}).claim_secret || '')), 'hex');
    const stored = r ? Buffer.from(r.claim_hash, 'hex') : Buffer.alloc(32);
    if (!r || !crypto.timingSafeEqual(presented, stored)) return res.status(404).json({ error: 'no such request' });
    if (req.params.slug && (req.params.slug !== r.fleet_slug || String(req.params.handle || '').toLowerCase() !== r.handle)) return res.status(404).json({ error: 'no such request' });
    if (r.status === 'pending') return res.status(202).json({ ok: false, status: 'pending', next: 'waiting for the fleet owner to approve in the app' });
    if (r.status !== 'approved') return res.status(410).json({ error: `this request is ${r.status}`, status: r.status });
    const n = db.prepare("UPDATE silicon_token_requests SET status = 'claimed', sealed = NULL, claimed_at = ? WHERE id = ? AND status = 'approved'").run(nowIso(), r.id).changes;
    if (n !== 1) return res.status(410).json({ error: 'already claimed', status: 'claimed' });
    let token, password = null;
    try {
      token = blindkeyDecrypt(r.sealed);
      if (r.creates) ({ token, password } = JSON.parse(token));
    } catch (_) {
      // Marked claimed already: nobody will ever hold this token, so it must not stay valid (#78 review).
      if (r.token_jti) db.prepare("UPDATE issued_tokens SET revoked = 1, revoked_at = datetime('now') WHERE jti = ?").run(r.token_jti);
      return res.status(500).json({ error: 'could not open the approved token; it was revoked: ask again' });
    }
    if (r.creates) {
      const w = db.prepare('SELECT email, username FROM identity_wallets WHERE did = ?').get(r.member_did) || {};
      return res.json({ ok: true, created: true, handle: r.handle, did: r.member_did, email: w.email, username: w.username, scope: r.scope, token,
                        password_once: password, note: 'shown once: store the token and the mailbox password in 0600 files' });
    }
    res.json({ ok: true, handle: r.handle, did: r.member_did, scope: r.scope, token, note: 'shown once: store it in a 0600 file' });
  }
  app.post('/api/silicon-token-requests/:id/claim', rateLimitStandard, claim);
  app.post('/api/fleet/:slug/silicons/:handle/token-requests/:id/claim', rateLimitStandard, claim);

  return { expireRequests, REQUEST_TTL_SEC, CLAIM_TTL_SEC };
};
