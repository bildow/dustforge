'use strict';
// ── Fleet routes: silicon subpages, onboarding, refills, attribution, work links.
// Registered from server.js: require('./fleet_routes')({ app, db, ... }).
// Everything money-related goes through ./fleet_billing (unit-tested); this
// file is HTTP plumbing + authorization.

const PROVISION_COST = 100;   // DD, same as /api/fleet/:slug/provision
const TOKEN_SCOPE_CAP = 'transact';
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

module.exports = function registerFleetRoutes(deps) {
  const { app, db, identity, billing, fleetBilling: fb, ledger, dustforge, createEmailTransport, rateLimitStandard, adminKey, crypto } = deps;
  const log = deps.log || ((...a) => console.log('[fleet]', ...a));
  const apiBase = deps.apiBase || 'https://api.dustforge.com';
  const vaultBase = deps.vaultBase || 'https://demipass.com';

  // ── helpers ───────────────────────────────────────────────────────────────
  function safeEq(a, b) {
    const x = Buffer.from(String(a || '')); const y = Buffer.from(String(b || ''));
    return x.length === y.length && x.length > 0 && crypto.timingSafeEqual(x, y);
  }
  function isAdminReq(req) {
    if (!adminKey) return false;
    return safeEq(req.headers['x-admin-key'] || (req.body && req.body.admin_key) || '', adminKey);
  }
  function bearer(req, res) {
    const h = req.headers.authorization || '';
    const token = h.startsWith('Bearer ') ? h.slice(7) : null;
    if (!token) { res.status(401).json({ error: 'Bearer token required' }); return null; }
    const v = identity.verifyTokenStandalone(token);
    if (!v.valid) { res.status(401).json({ error: v.error }); return null; }
    const dead = billing.checkTokenRevocation(db, v.decoded);
    if (dead.revoked) { res.status(401).json({ error: dead.reason }); return null; }
    return { did: v.decoded.sub, scope: v.decoded.scope || 'read', decoded: v.decoded, token };
  }
  function fleetAuth(req, res, { roles = null, minScope = 'read' } = {}) {
    const who = bearer(req, res);
    if (!who) return null;
    if (!identity.scopeAtLeast(who.scope, minScope)) { res.status(403).json({ error: `scope '${who.scope}' insufficient`, required_scope: minScope }); return null; }
    const fleet = db.prepare('SELECT * FROM fleets WHERE slug = ?').get(req.params.slug);
    if (!fleet) { res.status(404).json({ error: 'fleet not found' }); return null; }
    const m = db.prepare('SELECT role FROM fleet_members WHERE fleet_id = ? AND member_did = ?').get(fleet.id, who.did);
    const role = m ? m.role : (fleet.owner_did === who.did ? 'owner' : null);
    if (!role) { res.status(403).json({ error: 'fleet membership required' }); return null; }
    if (roles && !roles.includes(role)) { res.status(403).json({ error: `${roles.join(' or ')} role required` }); return null; }
    return { ...who, fleet, role };
  }
  function sendMail({ to, subject, text }) {
    if (!to) return Promise.resolve(false);
    try {
      const t = createEmailTransport();
      return t.sendMail({ from: 'DemiPass Fleet <support@dustforge.com>', to, subject, text })
        .then(() => true).catch(e => { log('mail failed:', e.message); return false; });
    } catch (e) { log('mail transport:', e.message); return Promise.resolve(false); }
  }
  function fail(res, e) {
    const status = e.statusCode || 500;
    return res.status(status).json(e.body || { error: e.message });
  }
  function ownerUsername(did) {
    const w = db.prepare('SELECT username FROM identity_wallets WHERE did = ?').get(did);
    return w ? w.username : null;
  }
  function siliconOr404(res, fleet, handle) {
    const s = fb.getSilicon(db, fleet.id, handle);
    if (!s || s.status === 'removed') { res.status(404).json({ error: 'silicon not found in this fleet' }); return null; }
    return s;
  }
  function projectRows(fleet) {
    const rows = db.prepare(`SELECT id, project, owner_did, lane_address, wallet_did, COALESCE(bill_mode,'owner') AS bill_mode, updated_at
                             FROM fleet_projects WHERE fleet_id = ? ORDER BY project`).all(fleet.id);
    const ops = db.prepare('SELECT operator_did FROM fleet_project_operators WHERE project_id = ?');
    return rows.map(r => ({
      project: r.project, bill_mode: r.bill_mode, wallet_did: r.wallet_did, lane_address: r.lane_address,
      wallet_balance_cents: r.wallet_did ? billing.getDerivedBalance(db, r.wallet_did) : 0,
      operators: ops.all(r.id).map(o => o.operator_did), updated_at: r.updated_at,
    }));
  }

  // ── Which fleets am I in? ─────────────────────────────────────────────────
  app.get('/api/fleets/mine', rateLimitStandard, (req, res) => {
    const who = bearer(req, res); if (!who) return;
    const rows = db.prepare(`SELECT f.slug, f.name, f.owner_did, f.tier, m.role FROM fleets f
                             JOIN fleet_members m ON m.fleet_id = f.id WHERE m.member_did = ? AND f.status = 'active'
                             UNION SELECT f.slug, f.name, f.owner_did, f.tier, 'owner' FROM fleets f
                             WHERE f.owner_did = ? AND f.status = 'active' ORDER BY 2`).all(who.did, who.did);
    const seen = new Set();
    res.json({ ok: true, fleets: rows.filter(r => !seen.has(r.slug) && seen.add(r.slug)) });
  });

  // ── Overview (one call for the Fleet tab) ─────────────────────────────────
  app.get('/api/fleet/:slug/overview', rateLimitStandard, (req, res) => {
    const a = fleetAuth(req, res); if (!a) return;
    const { fleet } = a;
    const silicons = db.prepare("SELECT * FROM fleet_silicons WHERE fleet_id = ? AND status != 'removed' ORDER BY handle").all(fleet.id)
      .map(s => fb.siliconView(db, billing, s, { fleet }));
    const ownerView = ['owner', 'admin'].includes(a.role);
    res.json({
      ok: true,
      fleet: { slug: fleet.slug, name: fleet.name, owner_did: fleet.owner_did, owner_username: ownerUsername(fleet.owner_did), tier: fleet.tier, max_agents: fleet.max_agents, wallet_did: fleet.wallet_did || null },
      owner: ownerView ? { balance_cents: billing.getDerivedBalance(db, fleet.owner_did), refill_rule: fb.getOwnerRefillRule(db, fleet.owner_did) } : null,
      silicons, projects: ownerView ? projectRows(fleet) : [],
      attribution: ownerView ? fb.attributionReport(db, { payerDids: [fleet.owner_did, ...silicons.map(s => s.did)], actorDids: silicons.map(s => s.did), sinceDays: 30 }) : null,
      work_links: fb.listWorkLinks(db, a.did),
      current_tick: fb.currentTick(db),
      caller: { did: a.did, role: a.role },
    });
  });

  // ── Silicons ──────────────────────────────────────────────────────────────
  app.get('/api/fleet/:slug/silicons', rateLimitStandard, (req, res) => {
    const a = fleetAuth(req, res); if (!a) return;
    const rows = db.prepare("SELECT * FROM fleet_silicons WHERE fleet_id = ? AND status != 'removed' ORDER BY handle").all(a.fleet.id);
    res.json({ ok: true, silicons: rows.map(s => fb.siliconView(db, billing, s, { fleet: a.fleet })) });
  });

  // Onboard a silicon: link an existing identity (with consent) or create a new one.
  // body: { handle, display_name?, contact_email?, did?, member_token?, create?: {username?, password?}, refill?: {...} }
  app.post('/api/fleet/:slug/silicons', rateLimitStandard, async (req, res) => {
    const a = fleetAuth(req, res, { roles: ['owner', 'admin'], minScope: 'transact' }); if (!a) return;
    const { fleet } = a;
    const b = req.body || {};
    const handle = String(b.handle || '').trim().toLowerCase();
    if (!fb.HANDLE_RE.test(handle)) return res.status(400).json({ error: 'handle: 2-31 chars, lowercase alphanumeric and hyphens' });
    const displayName = String(b.display_name || handle).slice(0, 100);
    const contactEmail = String(b.contact_email || '').trim().toLowerCase();
    if (contactEmail && !EMAIL_RE.test(contactEmail)) return res.status(400).json({ error: 'contact_email: invalid' });
    const prior = fb.getSilicon(db, fleet.id, handle);
    if (prior && prior.status !== 'removed') return res.status(409).json({ error: 'handle already used in this fleet' });
    if (prior) db.prepare('DELETE FROM fleet_silicons WHERE id = ?').run(prior.id);   // a removed silicon can be re-added
    const refill = b.refill && typeof b.refill === 'object' ? b.refill : {};

    // Existing identity? by did, else by contact email.
    let wallet = null;
    if (b.did) wallet = db.prepare('SELECT * FROM identity_wallets WHERE did = ?').get(String(b.did));
    if (!wallet && b.member_token) {   // the proof token also identifies the identity
      const v = identity.verifyTokenStandalone(String(b.member_token));
      if (!v.valid) return res.status(403).json({ error: 'member_token invalid: ' + v.error });
      wallet = db.prepare('SELECT * FROM identity_wallets WHERE did = ?').get(v.decoded.sub);
    }
    if (!wallet && contactEmail) wallet = db.prepare('SELECT * FROM identity_wallets WHERE email = ?').get(contactEmail);
    if (b.did && !wallet) return res.status(404).json({ error: 'did not found' });

    try {
      if (wallet) {
        if (wallet.did === fleet.owner_did) return res.status(400).json({ error: 'the fleet owner is not a silicon of their own fleet' });
        const other = db.prepare("SELECT f.slug FROM fleet_silicons s JOIN fleets f ON f.id = s.fleet_id WHERE s.member_did = ? AND s.fleet_id != ? AND s.status = 'active'").get(wallet.did, fleet.id);
        if (other) return res.status(409).json({ error: `identity is already a silicon of fleet '${other.slug}'` });
        // consent: member token, admin key, or mailbox claim
        let proof = null;
        if (b.member_token) {
          const v = identity.verifyTokenStandalone(String(b.member_token));
          if (v.valid && v.decoded.sub === wallet.did) proof = 'member_token';
          else return res.status(403).json({ error: 'member_token does not belong to that identity' });
        } else if (isAdminReq(req)) proof = 'admin';
        const s = fb.upsertSilicon(db, { fleetId: fleet.id, memberDid: wallet.did, handle, displayName, contactEmail: contactEmail || wallet.email, refill });
        if (proof) {
          db.prepare("INSERT OR IGNORE INTO fleet_members (fleet_id, member_did, role) VALUES (?, ?, 'agent')").run(fleet.id, wallet.did);
          const text = fb.didRecordEmail({ silicon: s, fleet: { ...fleet, owner_username: ownerUsername(fleet.owner_did) }, wallet, apiBase });
          sendMail({ to: s.contact_email, subject: `DemiPass: ${handle} joined fleet ${fleet.slug} — your DID record`, text });
          log(`linked ${handle} (${wallet.did}) into ${fleet.slug} via ${proof}`);
          return res.json({ ok: true, mode: 'linked', proof, silicon: fb.siliconView(db, billing, s, { fleet }) });
        }
        const claim = fb.issueClaim(db, s);
        const claimUrl = `${apiBase}/api/fleet/claim/${claim.code}`;
        const sent = await sendMail({ to: wallet.email, subject: `DemiPass: confirm joining fleet ${fleet.slug} as ${handle}`, text: fb.claimEmail({ silicon: s, fleet, claimUrl }) });
        log(`claim issued for ${handle} (${wallet.did}) in ${fleet.slug}; mail ${sent ? 'sent' : 'NOT sent'} to ${wallet.email}`);
        return res.json({ ok: true, mode: 'pending_claim', claim_sent_to: wallet.email, claim_expires_at: claim.expires_at, mail_sent: sent,
                          silicon: fb.siliconView(db, billing, fb.getSilicon(db, fleet.id, handle), { fleet }) });
      }

      // Create a brand-new identity (mailbox + wallet), charged like /provision.
      const create = b.create && typeof b.create === 'object' ? b.create : {};
      const username = String(create.username || handle).toLowerCase();
      if (!/^[a-z0-9][a-z0-9._-]{2,30}$/.test(username)) return res.status(400).json({ error: 'username must be 3-31 chars, lowercase alphanumeric' });
      if (db.prepare('SELECT 1 FROM identity_wallets WHERE username = ?').get(username)) return res.status(409).json({ error: 'username already taken' });
      const password = create.password ? String(create.password) : crypto.randomBytes(12).toString('base64url');
      if (password.length < 8) return res.status(400).json({ error: 'password must be at least 8 characters' });
      const count = db.prepare('SELECT COUNT(*) AS n FROM fleet_members WHERE fleet_id = ?').get(fleet.id).n;
      if (count >= fleet.max_agents) return res.status(403).json({ error: `fleet is at capacity (${fleet.max_agents} members)` });
      const payer = fleet.wallet_did || fleet.owner_did;
      if (billing.getDerivedBalance(db, payer) < PROVISION_COST) return res.status(402).json({ error: 'insufficient balance to provision', required: PROVISION_COST, payer_did: payer });

      const id = identity.createIdentity();
      const emailResult = await dustforge.createAccount(username, password);
      if (!emailResult.ok) return res.status(500).json({ error: `email creation failed: ${emailResult.error}` });
      const referral = crypto.randomBytes(6).toString('hex');
      const pwHash = crypto.createHash('sha256').update(password).digest('hex');
      const txn = db.transaction(() => {
        const debit = billing.deductBalance(db, payer, PROVISION_COST, 'fleet_provision', `Provision ${username} for fleet ${fleet.slug}`);
        if (!debit.ok) throw Object.assign(new Error(debit.error || 'insufficient balance'), { statusCode: 402, body: { error: 'insufficient balance to provision', detail: debit.error, payer_did: payer } });
        db.prepare('INSERT INTO identity_wallets (did, username, email, encrypted_private_key, balance_cents, referral_code, stalwart_id, password_hash) VALUES (?, ?, ?, ?, 0, ?, ?, ?)')
          .run(id.did, username, emailResult.email, id.encrypted_private_key, referral, emailResult.stalwart_id, pwHash);
        db.prepare("INSERT INTO identity_transactions (did, amount_cents, type, description, balance_after, provenance) VALUES (?, 0, 'account_created', ?, 0, 'fleet_provisioned')")
          .run(id.did, `Fleet-provisioned by ${fleet.slug}`);
        db.prepare("INSERT INTO fleet_members (fleet_id, member_did, role) VALUES (?, ?, 'agent')").run(fleet.id, id.did);
      });
      txn();
      const s = fb.upsertSilicon(db, { fleetId: fleet.id, memberDid: id.did, handle, displayName, contactEmail: contactEmail || emailResult.email, refill });
      const walletRow = { username, email: emailResult.email };
      const text = fb.didRecordEmail({ silicon: s, fleet: { ...fleet, owner_username: ownerUsername(fleet.owner_did) }, wallet: walletRow, apiBase });
      const subject = `DemiPass: ${handle} created in fleet ${fleet.slug} — your DID record`;
      sendMail({ to: emailResult.email, subject, text });
      if (contactEmail && contactEmail !== emailResult.email) sendMail({ to: contactEmail, subject, text });
      log(`created ${handle} (${id.did}, ${emailResult.email}) in ${fleet.slug} by ${a.did}`);
      return res.json({ ok: true, mode: 'created', did: id.did, email: emailResult.email, username, password_once: create.password ? undefined : password,
                        silicon: fb.siliconView(db, billing, s, { fleet }) });
    } catch (e) { return fail(res, e); }
  });

  // One-time mailbox claim link (no auth; the code is the proof).
  app.get('/api/fleet/claim/:code', rateLimitStandard, (req, res) => {
    const r = fb.redeemClaim(db, req.params.code);
    if (!r.ok) return res.status(400).send(`<html><body style="font-family:sans-serif;padding:2rem"><h2>DemiPass fleet</h2><p>${r.error}.</p></body></html>`);
    const fleet = db.prepare('SELECT * FROM fleets WHERE id = ?').get(r.silicon.fleet_id);
    const wallet = db.prepare('SELECT username, email FROM identity_wallets WHERE did = ?').get(r.silicon.member_did) || {};
    sendMail({ to: r.silicon.contact_email || wallet.email, subject: `DemiPass: ${r.silicon.handle} joined fleet ${fleet.slug} — your DID record`,
               text: fb.didRecordEmail({ silicon: r.silicon, fleet: { ...fleet, owner_username: ownerUsername(fleet.owner_did) }, wallet, apiBase }) });
    log(`claim redeemed: ${r.silicon.handle} joined ${fleet.slug}`);
    res.send(`<html><body style="font-family:sans-serif;padding:2rem"><h2>DemiPass fleet</h2><p><strong>${r.silicon.handle}</strong> is now a member of fleet <strong>${fleet.name}</strong>. A record of the DID was sent to ${r.silicon.contact_email || wallet.email}.</p></body></html>`);
  });

  app.get('/api/fleet/:slug/silicons/:handle', rateLimitStandard, (req, res) => {
    const a = fleetAuth(req, res); if (!a) return;
    const s = siliconOr404(res, a.fleet, req.params.handle); if (!s) return;
    const ownerView = ['owner', 'admin'].includes(a.role) || s.member_did === a.did;
    if (!ownerView) return res.status(403).json({ error: 'owner, admin, or the silicon itself' });
    const delegations = db.prepare(`SELECT d.id, d.status, d.max_uses, d.use_count, d.granted_at, d.expires_at, b.name AS secret_name, b.ref_code, b.secret_type
                                    FROM demipass_delegations d JOIN blindkey_secrets b ON b.id = d.secret_id
                                    WHERE d.delegate_did = ? ORDER BY d.granted_at DESC LIMIT 50`).all(s.member_did);
    res.json({
      ok: true,
      silicon: fb.siliconView(db, billing, s, { fleet: a.fleet }),
      recent: fb.recentSpend(db, s.member_did, 30),
      attribution: fb.attributionReport(db, { actorDids: [s.member_did], sinceDays: 30 }),
      delegations, work_links: fb.listWorkLinks(db, s.member_did),
      current_tick: fb.currentTick(db),
    });
  });

  app.patch('/api/fleet/:slug/silicons/:handle', rateLimitStandard, (req, res) => {
    const a = fleetAuth(req, res, { roles: ['owner', 'admin'], minScope: 'transact' }); if (!a) return;
    const s = siliconOr404(res, a.fleet, req.params.handle); if (!s) return;
    try {
      const updated = fb.updateSiliconSettings(db, s, req.body || {});
      res.json({ ok: true, silicon: fb.siliconView(db, billing, updated, { fleet: a.fleet }) });
    } catch (e) { fail(res, e); }
  });

  app.delete('/api/fleet/:slug/silicons/:handle', rateLimitStandard, (req, res) => {
    const a = fleetAuth(req, res, { roles: ['owner', 'admin'], minScope: 'transact' }); if (!a) return;
    const s = siliconOr404(res, a.fleet, req.params.handle); if (!s) return;
    db.prepare("UPDATE fleet_silicons SET status = 'removed', refill_enabled = 0, updated_at = CURRENT_TIMESTAMP WHERE id = ?").run(s.id);
    db.prepare("DELETE FROM fleet_members WHERE fleet_id = ? AND member_did = ? AND role = 'agent'").run(a.fleet.id, s.member_did);
    log(`removed ${s.handle} from ${a.fleet.slug} by ${a.did}`);
    res.json({ ok: true });
  });

  app.post('/api/fleet/:slug/silicons/:handle/refill', rateLimitStandard, (req, res) => {
    const a = fleetAuth(req, res, { roles: ['owner', 'admin'], minScope: 'transact' }); if (!a) return;
    const s = siliconOr404(res, a.fleet, req.params.handle); if (!s) return;
    const amount = Number((req.body || {}).amount_cents || s.refill_amount_cents);
    if (!Number.isInteger(amount) || amount < 1 || amount > 1000000) return res.status(400).json({ error: 'amount_cents: integer 1-1000000' });
    const r = fb.thresholdRefill(db, billing, s, { force: true, amount, ledger });
    if (!r.ok) return res.status(402).json({ error: r.error || r.skipped, from_did: r.from_did });
    res.json({ ok: true, ...r, silicon: fb.siliconView(db, billing, fb.getSilicon(db, a.fleet.id, s.handle), { fleet: a.fleet }) });
  });

  // Owner/admin mints a token FOR a silicon of their fleet (the fleet holds the
  // silicon's key). Capped at transact scope; TTL clamps per scope in identity.js.
  app.post('/api/fleet/:slug/silicons/:handle/token', rateLimitStandard, (req, res) => {
    const a = fleetAuth(req, res, { roles: ['owner', 'admin'], minScope: 'transact' }); if (!a) return;
    const s = siliconOr404(res, a.fleet, req.params.handle); if (!s) return;
    const { scope = TOKEN_SCOPE_CAP, expires_in = '30d' } = req.body || {};
    if (!identity.ISSUABLE_SCOPES.includes(scope) || identity.scopeAtLeast(scope, 'admin')) return res.status(400).json({ error: `scope must be read, write or ${TOKEN_SCOPE_CAP}` });
    if (typeof expires_in !== 'string' || !/^\d+[smhd]$/.test(expires_in)) return res.status(400).json({ error: 'expires_in: e.g. 24h, 7d, 30d' });
    const wallet = db.prepare('SELECT * FROM identity_wallets WHERE did = ?').get(s.member_did);
    if (!wallet) return res.status(404).json({ error: 'identity not found' });
    try {
      const token = identity.createTokenForIdentity(wallet.encrypted_private_key, wallet.did, {
        scope, expiresIn: expires_in,
        metadata: { email: wallet.email, username: wallet.username, auth_method: 'fleet_owner_mint', fleet: a.fleet.slug, minted_by: a.did },
      });
      const st = fb.tokenStatus(db, wallet.did);
      log(`token minted for ${s.handle} (${scope}, ${expires_in}) by ${a.did}`);
      res.json({ ok: true, token, did: wallet.did, scope, expires_at: st.expires_at, username: wallet.username, email: wallet.email });
    } catch (e) { res.status(500).json({ error: 'token mint failed: ' + e.message }); }
  });

  // Owner delegates one of THEIR secrets to a silicon of the fleet (same semantics as /api/blindkey/delegate).
  app.post('/api/fleet/:slug/silicons/:handle/delegate', rateLimitStandard, (req, res) => {
    const a = fleetAuth(req, res, { roles: ['owner'], minScope: 'transact' }); if (!a) return;
    const s = siliconOr404(res, a.fleet, req.params.handle); if (!s) return;
    const { secret_name, ref, max_uses = 0, expires_in } = req.body || {};
    let secret = null;
    if (ref) secret = db.prepare("SELECT * FROM blindkey_secrets WHERE ref_code = ? AND did = ? AND status = 'active'").get(String(ref), a.did);
    else if (secret_name) secret = db.prepare("SELECT * FROM blindkey_secrets WHERE did = ? AND name = ? AND status = 'active' ORDER BY version DESC LIMIT 1").get(a.did, String(secret_name));
    if (!secret) return res.status(404).json({ error: 'secret not found among the owner\'s active secrets' });
    const expiresAt = (typeof expires_in === 'number' && expires_in > 0) ? new Date(Date.now() + expires_in * 1000).toISOString() : null;
    try {
      db.prepare(`INSERT INTO demipass_delegations (owner_did, delegate_did, secret_id, context_id, max_uses, granted_by, expires_at)
                  VALUES (?, ?, ?, NULL, ?, ?, ?)
                  ON CONFLICT(owner_did, delegate_did, secret_id, context_id) DO UPDATE SET
                    status = 'active', max_uses = excluded.max_uses, use_count = 0, granted_at = CURRENT_TIMESTAMP, revoked_at = NULL, expires_at = excluded.expires_at`)
        .run(a.did, s.member_did, secret.id, Number(max_uses) || 0, a.did, expiresAt);
      const d = db.prepare('SELECT id FROM demipass_delegations WHERE owner_did = ? AND delegate_did = ? AND secret_id = ? AND context_id IS NULL').get(a.did, s.member_did, secret.id);
      try {
        db.prepare('INSERT INTO blindkey_events (event_type, actor, secret_id, context_name, detail) VALUES (?, ?, ?, ?, ?)')
          .run('delegation_granted', a.did, secret.id, '*', JSON.stringify({ delegation_id: d && d.id, owner_did: a.did, delegate_did: s.member_did, via: 'fleet', max_uses: Number(max_uses) || 0, expires_at: expiresAt }));
      } catch (_) {}
      log(`delegated ${secret.name} → ${s.handle} by ${a.did}`);
      res.json({ ok: true, delegation_id: d && d.id, secret_name: secret.name, ref: secret.ref_code, delegate_did: s.member_did, expires_at: expiresAt });
    } catch (e) { fail(res, e); }
  });

  // ── Owner refill rule ─────────────────────────────────────────────────────
  app.get('/api/fleet/:slug/owner-refill', rateLimitStandard, (req, res) => {
    const a = fleetAuth(req, res, { roles: ['owner', 'admin'] }); if (!a) return;
    res.json({ ok: true, rule: fb.getOwnerRefillRule(db, a.fleet.owner_did), balance_cents: billing.getDerivedBalance(db, a.fleet.owner_did),
               grant_permitted: (process.env.OPERATOR_GRANT_DIDS || '').split(',').map(x => x.trim()).includes(a.fleet.owner_did) });
  });
  app.put('/api/fleet/:slug/owner-refill', rateLimitStandard, (req, res) => {
    const a = fleetAuth(req, res, { roles: ['owner'], minScope: 'transact' }); if (!a) return;
    try {
      const rule = fb.setOwnerRefillRule(db, a.fleet.owner_did, req.body || {});
      res.json({ ok: true, rule });
    } catch (e) { fail(res, e); }
  });

  // ── Project billing mode ──────────────────────────────────────────────────
  app.patch('/api/fleet/:slug/projects/:project', rateLimitStandard, (req, res) => {
    const a = fleetAuth(req, res, { roles: ['owner', 'admin'], minScope: 'transact' }); if (!a) return;
    const { bill_mode } = req.body || {};
    if (!['owner', 'project_wallet'].includes(bill_mode)) return res.status(400).json({ error: "bill_mode: 'owner' or 'project_wallet'" });
    const r = db.prepare('UPDATE fleet_projects SET bill_mode = ?, updated_at = CURRENT_TIMESTAMP WHERE fleet_id = ? AND project = ?').run(bill_mode, a.fleet.id, req.params.project);
    if (!r.changes) return res.status(404).json({ error: 'project not found on this fleet board' });
    res.json({ ok: true, project: req.params.project, bill_mode });
  });

  // ── Attribution report + manual scheduler run ─────────────────────────────
  app.get('/api/fleet/:slug/attribution', rateLimitStandard, (req, res) => {
    const a = fleetAuth(req, res, { roles: ['owner', 'admin'] }); if (!a) return;
    const days = Math.min(365, Math.max(1, parseInt(req.query.days, 10) || 30));
    const dids = db.prepare("SELECT member_did FROM fleet_silicons WHERE fleet_id = ? AND status = 'active'").all(a.fleet.id).map(r => r.member_did);
    res.json({ ok: true, days, ...fb.attributionReport(db, { payerDids: [a.fleet.owner_did, ...dids], actorDids: dids, sinceDays: days }) });
  });
  app.post('/api/fleet/:slug/refills/run', rateLimitStandard, (req, res) => {
    const a = fleetAuth(req, res, { roles: ['owner', 'admin'], minScope: 'transact' }); if (!a) return;
    try { res.json({ ok: true, ...fb.runRefills(db, billing, { ledger, mailer: sendMail }) }); } catch (e) { fail(res, e); }
  });

  // ── A silicon's own view ──────────────────────────────────────────────────
  app.get('/api/silicons/me', rateLimitStandard, (req, res) => {
    const who = bearer(req, res); if (!who) return;
    const rows = db.prepare("SELECT s.*, f.slug AS fleet_slug, f.name AS fleet_name FROM fleet_silicons s JOIN fleets f ON f.id = s.fleet_id WHERE s.member_did = ? AND s.status = 'active'").all(who.did);
    res.json({ ok: true, did: who.did, silicon_id: fb.siliconId(who.did), balance_cents: billing.getDerivedBalance(db, who.did),
               memberships: rows.map(s => fb.siliconView(db, billing, s, { fleet: { slug: s.fleet_slug, name: s.fleet_name } })),
               work_links: fb.listWorkLinks(db, who.did), token: fb.tokenStatus(db, who.did), current_tick: fb.currentTick(db) });
  });
  app.get('/api/silicons/resolve/:sid', rateLimitStandard, (req, res) => {
    const who = bearer(req, res); if (!who) return;
    const r = fb.resolveSiliconId(db, req.params.sid);
    if (!r) return res.status(404).json({ error: 'unknown silicon id' });
    const fleet = db.prepare('SELECT slug, name, owner_did FROM fleets WHERE id = ?').get(r.fleet_id) || {};
    const sameFleet = fleet.owner_did === who.did || db.prepare('SELECT 1 FROM fleet_members WHERE fleet_id = ? AND member_did = ?').get(r.fleet_id, who.did);
    res.json({ ok: true, silicon_id: req.params.sid, handle: r.handle, display_name: r.display_name, fleet: { slug: fleet.slug, name: fleet.name },
               did: sameFleet ? r.did : undefined });
  });

  // ── Work links (silicon ↔ silicon) ────────────────────────────────────────
  function resolveParty(ref) {
    if (!ref) return null;
    const s = String(ref);
    if (s.startsWith('did:')) return db.prepare('SELECT did FROM identity_wallets WHERE did = ?').get(s) ? s : null;
    if (s.startsWith('sil_')) { const r = fb.resolveSiliconId(db, s); return r ? r.did : null; }
    const m = s.match(/^([a-z0-9-]+)@([a-z0-9-]+)$/);
    if (m) {
      const f = db.prepare('SELECT id FROM fleets WHERE slug = ?').get(m[2]);
      const r = f && fb.getSilicon(db, f.id, m[1]);
      return r && r.status === 'active' ? r.member_did : null;
    }
    const w = db.prepare('SELECT did FROM identity_wallets WHERE username = ?').get(s);
    return w ? w.did : null;
  }
  function linkView(l, viewerDid) {
    return { ...l, role: l.requester_did === viewerDid ? 'requester' : 'provider',
             requester: fb.siliconId(l.requester_did), provider: fb.siliconId(l.provider_did) };
  }
  app.post('/api/work-links', rateLimitStandard, async (req, res) => {
    const who = bearer(req, res); if (!who) return;
    if (!identity.scopeAtLeast(who.scope, 'transact')) return res.status(403).json({ error: 'transact scope required (the requester pays)' });
    const b = req.body || {};
    const providerDid = resolveParty(b.provider);
    if (!providerDid) return res.status(404).json({ error: 'provider not found (use a sil_ id, DID, username, or handle@fleet)' });
    try {
      const link = fb.createWorkLink(db, { requesterDid: who.did, providerDid, ttlTicks: b.ttl_ticks, ttlSeconds: b.ttl_seconds || undefined,
                                           project: b.project || '', note: b.note || '', maxSpendCents: b.max_spend_cents || 0 });
      const prov = db.prepare("SELECT s.handle, s.contact_email FROM fleet_silicons s WHERE s.member_did = ? AND s.status = 'active' LIMIT 1").get(providerDid);
      if (prov && prov.contact_email) {
        sendMail({ to: prov.contact_email, subject: `DemiPass: work link request #${link.id} from ${fb.siliconId(who.did)}`,
                   text: `Silicon ${fb.siliconId(who.did)} asks ${prov.handle} to work for them for ${link.ttl_ticks} buoy ticks` +
                         (link.project ? ` on project '${link.project}'` : '') + (link.note ? `.\nNote: ${link.note}` : '.') +
                         `\n\nTheir wallet pays for calls made with the link token. Accept: POST ${apiBase}/api/work-links/${link.id}/accept (your bearer token). Decline: /decline. Revoke any time: /revoke.` });
      }
      res.json({ ok: true, link: linkView(link, who.did) });
    } catch (e) { fail(res, e); }
  });
  app.get('/api/work-links', rateLimitStandard, (req, res) => {
    const who = bearer(req, res); if (!who) return;
    res.json({ ok: true, current_tick: fb.currentTick(db), links: fb.listWorkLinks(db, who.did).map(l => linkView(l, who.did)) });
  });
  app.post('/api/work-links/:id/accept', rateLimitStandard, (req, res) => {
    const who = bearer(req, res); if (!who) return;
    try {
      const { token, link } = fb.acceptWorkLink(db, { id: Number(req.params.id), providerDid: who.did });
      res.json({ ok: true, work_token: token, link: linkView(link, who.did),
                 usage: 'send header X-DemiPass-Billing: {"work_link":"<work_token>"} on billed calls; the requester pays until the tick window or wall-clock cap closes' });
    } catch (e) { fail(res, e); }
  });
  app.post('/api/work-links/:id/decline', rateLimitStandard, (req, res) => {
    const who = bearer(req, res); if (!who) return;
    try { res.json({ ok: true, link: linkView(fb.declineWorkLink(db, { id: Number(req.params.id), providerDid: who.did }), who.did) }); } catch (e) { fail(res, e); }
  });
  app.post('/api/work-links/:id/revoke', rateLimitStandard, (req, res) => {
    const who = bearer(req, res); if (!who) return;
    try { res.json({ ok: true, link: linkView(fb.revokeWorkLink(db, { id: Number(req.params.id), byDid: who.did }), who.did) }); } catch (e) { fail(res, e); }
  });

  return { sendMail };
};
