'use strict';
// ── Person-to-person secret sharing and ownership transfer ────────────────────────────────────────────────────
// Registered from server.js: require('./secret_sharing')({ app, db, ... }). Contract: docs/sharing.md.
//
// A share is a delegation (demipass_delegations) from one person to another, the same row an agent delegation
// is, with delegate_kind 'person':
//   - Only between two people who are connected in the wallet network (network_peers). Being connected, or
//     being in the same fleet, grants nothing by itself: a secret is reachable only through a share.
//   - The owner offers it with the vault PIN (intent share:<secret id>). It waits, inert (status 'suspended',
//     offer_state 'offered'), until the other person accepts it in the app. Accepting is their only step.
//   - Use-only: the person, and the agents that act as them, reach the secret through /use; DemiPass injects it
//     and the value never leaves the server. Scoped (all contexts or one), expiring (always), revocable by either
//     side, logged in blindkey_events and demipass_security_events.
//   - Reveal is the emergency door only, a separate permission: the owner grants N reveals for a window (default
//     an hour, at most a day) with the PIN (intent reveal-grant:<share id>); the person spends one with their own PIN
//     (intent share-reveal:<share id>). Every reveal is a critical security event on both sides, and the share's
//     audit (GET /shares/:id/audit) shows who revealed what and when. The design rule everywhere else is that a
//     person never reads or types a value: a flow that needs a reveal is a defect to name, not a use of this door.
// A transfer moves a secret to another person's vault (PIN, intent transfer:<secret id>). The ref stays the same;
// the old owner keeps a use-only share unless they choose not to; every other delegation of it ends, so the new
// owner starts with a vault entry nobody else reaches but the one share they can see and revoke.

const SHARE_DEFAULT_DAYS = 90;
const SHARE_MAX_DAYS = 365;
const KEEP_DEFAULT_DAYS = 365;
const MAX_REVEALS_PER_GRANT = 5;
const REVEAL_DEFAULT_MINUTES = 60;      // a reveal grant is the emergency door: time-boxed, default one hour
const REVEAL_MAX_MINUTES = 24 * 60;
const MAX_LIST = 100;

module.exports = function registerSecretSharing(deps) {
  const { app, db, rateLimitStandard, rateLimitFill, getBearerIdentity, gateSession, gateFresh, gateMissing, spendSingleUse,
          logSecurityEvent, blindkeyDecrypt, cleanLabel, REDEEMABLE_STATUS_SQL, resolveLatestBlindkeySecret, resolveGatePolicy } = deps;
  // Decisions that give access away are signed by the owner's enrolled phone once there is one (red team item 4b).
  function deviceRefusal(me, kind, id, bind, req, res) {
    const dk = deps.devices && deps.devices();
    const r = dk ? dk.approvalRefusal(me.auth, kind, id, bind, req.body) : null;
    if (r) { res.status(r.status).json(r.body); return true; }
    return false;
  }
  const limiter = rateLimitFill || rateLimitStandard;

  const nowIso = () => new Date().toISOString();
  const expired = (row) => Boolean(row.expires_at) && new Date(row.expires_at) <= new Date();
  const event = (type, actor, secretId, detail) => db.prepare('INSERT INTO blindkey_events (event_type, actor, secret_id, context_name, detail) VALUES (?, ?, ?, ?, ?)')
    .run(type, actor, secretId, '*', JSON.stringify(detail));
  const tick = (did, note, tags) => { try {
    db.prepare('INSERT INTO ticks (did, note, ip, tz, tick_type, tags) VALUES (?, ?, ?, ?, ?, ?)').run(did, note, '', 'UTC', 'alert', JSON.stringify(tags));
  } catch (_) {} };

  // ── who ─────────────────────────────────────────────────────────────────────────────────────────────────────
  // An agent wallet: an active silicon of some fleet (fleet_silicons rows are made with the agent's consent: it was
  // created by its owner or accepted the join). fleet_members is not used: a fleet owner can add any DID there
  // without asking, so it would let anyone turn a person into "an agent".
  function isAgentWallet(did) {
    return Boolean(db.prepare("SELECT 1 FROM fleet_silicons WHERE member_did = ? AND status = 'active'").get(did));
  }
  function isPeer(x, y) {
    const [a, b] = x < y ? [x, y] : [y, x];
    return Boolean(db.prepare("SELECT 1 FROM network_peers WHERE did_a = ? AND did_b = ? AND status = 'active'").get(a, b));
  }
  // A contact confirmed in person: paired by QR with both screens' codes compared (pairing.js; red team item 6). Name
  // lookup alone is phishable, so shares and transfers need this — a contact made by request carries no share rights.
  function isConfirmedPeer(x, y) {
    const [a, b] = x < y ? [x, y] : [y, x];
    try { return Boolean(db.prepare("SELECT 1 FROM network_peers WHERE did_a = ? AND did_b = ? AND status = 'active' AND verified_via IS NOT NULL").get(a, b)); }
    catch (_) { return false; }   // no verified_via column yet: nobody is confirmed
  }
  const PAIR_HINT = 'meet them and pair in person: Fleet → Pair in person (QR) — you compare a 6-digit code on both screens';
  // `did` is a person `owner` may share with: a connection in the network that is not an agent.
  function isPersonPeer(owner, did) {
    return owner !== did && isPeer(owner, did) && !isAgentWallet(did);
  }
  function findWallet(q) {
    const s = String(q || '').trim();
    if (!s || s.length > 200) return null;
    const v = s.toLowerCase();
    return db.prepare('SELECT did, username, status FROM identity_wallets WHERE did = ? OR username = ? OR email = ?').get(s, v, v)
      || (v.includes('@') ? null : db.prepare('SELECT did, username, status FROM identity_wallets WHERE email = ?').get(v + '@dustforge.com'));
  }
  const usernameOf = (did) => (db.prepare('SELECT username FROM identity_wallets WHERE did = ?').get(did) || {}).username || null;

  // The caller, as a person acting in their own session: no silicon token, no worker token, no token a fleet owner
  // minted for an agent, and a session a PIN proof can be bound to.
  function personAuth(req, res) {
    const auth = getBearerIdentity(req);
    if (!auth.ok) { res.status(auth.status || 401).json({ error: auth.error }); return null; }
    if (auth.silicon || (auth.decoded && (auth.decoded.wrk || auth.decoded.auth_method === 'fleet_owner_mint'))) {
      res.status(403).json({ error: "sharing between people is done by the people themselves, in their own session — an agent token cannot share, accept, transfer or reveal" });
      return null;
    }
    if (!gateSession(auth)) { res.status(403).json({ error: 'this token cannot hold a PIN proof — sign in again' }); return null; }
    const w = db.prepare('SELECT did, username, status FROM identity_wallets WHERE did = ?').get(auth.did);
    if (!w || w.status !== 'active') { res.status(403).json({ error: 'account not active' }); return null; }
    return { auth, did: auth.did, username: w.username };
  }
  // Every gate in `required` (the PIN at least) fresh for `intent`, single-use proofs spent once. Returns true when
  // proven; otherwise it has already answered.
  // Factors checked first, then (once a phone is linked) its device signature over this decision, then the factors
  // spent — so a 428 for the signature never costs the PIN proof, and a signature never meets a missing PIN (#47 M2).
  function requireGates(me, required, intent, action, res, device = null) {
    const missing = required.filter(g => !gateFresh(me.did, g, me.auth, intent));
    if (missing.length) { res.status(403).json(gateMissing(action, required, missing, intent)); return false; }
    if (device && deviceRefusal(me, device.kind, device.id, device.bind, device.req, res)) return false;
    const refused = spendSingleUse(me.did, action, required, me.auth, intent);
    if (refused) { res.status(refused.status || 403).json(refused); return false; }
    return true;
  }
  const requirePin = (me, intent, action, res, device = null) => requireGates(me, ['pin'], intent, action, res, device);
  // What the owner proves to open a reveal for someone else: the secret's own reveal policy (PIN, plus email/SMS
  // codes at higher depths) — never less than what revealing it to themselves would take.
  function ownerRevealGates(secret) {
    let g = ['pin'];
    try { const r = resolveGatePolicy(secret).reveal; if (Array.isArray(r) && r.length) g = r; } catch (_) {}
    return g.includes('pin') ? g : ['pin', ...g];
  }

  // ── what ────────────────────────────────────────────────────────────────────────────────────────────────────
  // The caller's own live secret, by ref or by name: the active version (never a 'rotating' one on its way out).
  // A name resolves the way /use resolves it (latest active version of the base name).
  function ownSecret(did, pick) {
    if (!pick || typeof pick !== 'string' || pick.length > 100) return null;
    if (pick.startsWith('DP-')) return db.prepare("SELECT * FROM blindkey_secrets WHERE ref_code = ? AND did = ? AND status = 'active'").get(pick, did) || null;
    return resolveLatestBlindkeySecret(did, pick) || null;
  }
  const baseName = (n) => String(n).replace(/_v\d+$/, '');
  // Any row of this name family (base or base_vN) the vault holds, in any status: UNIQUE(did, name) and version
  // lookups both see them.
  const nameFamilyTaken = (did, name) => Boolean(db.prepare('SELECT 1 FROM blindkey_secrets WHERE did = ? AND (name = ? OR name LIKE ?)').get(did, baseName(name), baseName(name) + '_v%'));
  function stateOf(row) {
    if (row.status === 'revoked') return ['declined', 'dropped'].includes(row.offer_state) ? row.offer_state : 'revoked';
    if (expired(row)) return 'expired';
    if (row.status === 'suspended' && row.offer_state === 'offered') return 'offered';
    if (row.status === 'active') return 'active';
    return row.status;
  }
  const revealOpen = (row) => Boolean(row.reveal_allowed) && (row.reveals_used || 0) < (row.max_reveals || 0)
    && Boolean(row.reveal_until) && new Date(row.reveal_until) > new Date();
  function view(row, me) {
    const s = db.prepare('SELECT name, ref_code, secret_type, note, account_username FROM blindkey_secrets WHERE id = ?').get(row.secret_id) || {};
    const ctx = row.context_id ? db.prepare('SELECT context_name, action_type FROM blindkey_contexts WHERE id = ?').get(row.context_id) : null;
    const state = stateOf(row);
    return {
      id: row.id, state, role: row.owner_did === me ? 'owner' : 'recipient',
      owner: usernameOf(row.owner_did), recipient: usernameOf(row.delegate_did),
      secret: { name: s.name || null, ref: s.ref_code || null, type: s.secret_type || null, ...(s.note ? { note: s.note } : {}),
                ...(s.account_username ? { username: s.account_username } : {}) },
      scope: ctx ? { context: ctx.context_name, action: ctx.action_type } : { context: '*' },
      use_only: !revealOpen(row),
      reveals_left: revealOpen(row) ? Math.max(0, (row.max_reveals || 0) - (row.reveals_used || 0)) : 0,
      ...(revealOpen(row) ? { reveal_until: row.reveal_until } : {}),
      max_uses: row.max_uses || 0, use_count: row.use_count || 0,
      expires_at: row.expires_at || null, offered_at: row.granted_at, accepted_at: row.accepted_at || null,
      revoked_at: row.revoked_at || null, via: row.via || 'share', ...(row.note ? { note: row.note } : {}),
    };
  }
  function shareRow(id) {
    const n = Number(id);
    if (!Number.isInteger(n) || n < 1) return null;
    return db.prepare("SELECT * FROM demipass_delegations WHERE id = ? AND delegate_kind = 'person'").get(n) || null;
  }
  function parseDays(v, def, max, field, res) {
    if (v === undefined || v === null || v === '') return def;
    if (!Number.isInteger(v) || v < 1 || v > max) { res.status(400).json({ error: `${field}: whole days, 1 to ${max} (a share always expires)` }); return null; }
    return v;
  }
  const daysFromNow = (d) => new Date(Date.now() + d * 86400000).toISOString();

  // ── POST /api/blindkey/shares — offer a person use of one of your secrets ─────────────────────────────────────
  // { secret: name or ref, to: username / email / DID, expires_in_days?: 1–365 (90), context?: one context name,
  //   max_uses?: 0 = no cap, note?: shown to them }. Needs the PIN (intent share:<secret id>).
  app.post('/api/blindkey/shares', limiter, (req, res) => {
    const me = personAuth(req, res); if (!me) return;
    const { secret: pick, to, expires_in_days, context, max_uses, note } = req.body || {};
    const secret = ownSecret(me.did, pick);
    if (!secret) return res.status(404).json({ error: 'secret: name or ref of one of your active secrets' });
    const target = findWallet(to);
    if (!target) return res.status(404).json({ error: 'to: no wallet with that username, email or DID' });
    if (target.did === me.did) return res.status(400).json({ error: 'that is you' });
    if (target.status !== 'active') return res.status(403).json({ error: `${target.username} is not active` });
    if (isAgentWallet(target.did)) return res.status(409).json({ error: `${target.username} is an agent — give an agent a secret with POST /api/demipass/delegate` });
    if (!isPeer(me.did, target.did)) {
      return res.status(403).json({ error: `you can share only with people you are connected to — add ${target.username} as a person in your network first (Fleet → +, "A person")` });
    }
    if (!isConfirmedPeer(me.did, target.did)) {
      return res.status(403).json({ error: `you can share only with contacts confirmed in person — ${PAIR_HINT}`, pair_required: true });
    }
    const days = parseDays(expires_in_days, SHARE_DEFAULT_DAYS, SHARE_MAX_DAYS, 'expires_in_days', res); if (days === null) return;
    if (max_uses !== undefined && max_uses !== null && (!Number.isInteger(max_uses) || max_uses < 0 || max_uses > 1000000)) return res.status(400).json({ error: 'max_uses: 0 (no cap) to 1000000' });
    if (note !== undefined && note !== null && (typeof note !== 'string' || note.length > 300)) return res.status(400).json({ error: 'note: at most 300 characters' });
    let contextId = null;
    if (context !== undefined && context !== null && context !== '' && context !== '*') {
      if (typeof context !== 'string') return res.status(400).json({ error: 'context: a context name' });
      const c = db.prepare("SELECT id FROM blindkey_contexts WHERE secret_id = ? AND context_name = ? AND status = 'active'").get(secret.id, context);
      if (!c) return res.status(404).json({ error: `context '${cleanLabel(context, 100)}' is not an active context of ${secret.name}` });
      contextId = c.id;
    }
    const prior = db.prepare(`SELECT * FROM demipass_delegations WHERE owner_did = ? AND delegate_did = ? AND secret_id = ? AND context_id IS ? ORDER BY id DESC LIMIT 1`)
      .get(me.did, target.did, secret.id, contextId);
    if (prior && ['active', 'offered'].includes(stateOf(prior))) {
      return res.status(409).json({ error: `${target.username} already has ${stateOf(prior) === 'active' ? 'this share' : 'this offer waiting'}`, share: view(prior, me.did) });
    }
    if (!requirePin(me, `share:${secret.id}`, 'share', res,
      { kind: 'share', id: secret.id, bind: [to, context || '', max_uses || 0, expires_in_days || ''].join('|'), req })) return;
    const expiresAt = daysFromNow(days);
    const cleanNote = note ? cleanLabel(note, 300).trim() : '';
    let id;
    db.transaction(() => {
      if (prior) {
        db.prepare(`UPDATE demipass_delegations SET status = 'suspended', delegate_kind = 'person', offer_state = 'offered', accepted_at = NULL,
                    max_uses = ?, use_count = 0, granted_by = ?, granted_at = CURRENT_TIMESTAMP, revoked_at = NULL, expires_at = ?,
                    reveal_allowed = 0, max_reveals = 0, reveals_used = 0, reveal_granted_at = NULL, note = ?, via = 'share' WHERE id = ?`)
          .run(max_uses || 0, me.did, expiresAt, cleanNote, prior.id);
        id = prior.id;
      } else {
        id = Number(db.prepare(`INSERT INTO demipass_delegations (owner_did, delegate_did, secret_id, context_id, status, max_uses, granted_by, expires_at,
                                delegate_kind, offer_state, note, via) VALUES (?, ?, ?, ?, 'suspended', ?, ?, ?, 'person', 'offered', ?, 'share')`)
          .run(me.did, target.did, secret.id, contextId, max_uses || 0, me.did, expiresAt, cleanNote).lastInsertRowid);
      }
      event('share_offered', me.did, secret.id, { delegation_id: id, owner_did: me.did, delegate_did: target.did, context_id: contextId, expires_at: expiresAt, use_only: true });
    })();
    logSecurityEvent('share_offered', 'warn', { caller_did: me.did, capability: 'share', target: secret.name, ip: req.ip, context: { share_id: id, to: target.username, expires_at: expiresAt } });
    res.status(201).json({ ok: true, share: view(shareRow(id), me.did),
      next: `${target.username} accepts it in the DemiPass app; until then it opens nothing` });
  });

  // ── GET /api/blindkey/shares — shares you gave and shares given to you ──────────────────────────────────────
  app.get('/api/blindkey/shares', rateLimitStandard, (req, res) => {
    const auth = getBearerIdentity(req);
    if (!auth.ok) return res.status(auth.status || 401).json({ error: auth.error });
    const given = db.prepare(`SELECT * FROM demipass_delegations WHERE owner_did = ? AND delegate_kind = 'person' ORDER BY id DESC LIMIT ?`).all(auth.did, MAX_LIST);
    const received = db.prepare(`SELECT * FROM demipass_delegations WHERE delegate_did = ? AND delegate_kind = 'person' ORDER BY id DESC LIMIT ?`).all(auth.did, MAX_LIST);
    const g = given.map(r => view(r, auth.did)), r = received.map(x => view(x, auth.did));
    res.json({ ok: true, given: g, received: r, waiting_for_you: r.filter(x => x.state === 'offered').length });
  });

  // ── POST /api/blindkey/shares/:id/accept — the recipient's one step ─────────────────────────────────────────
  app.post('/api/blindkey/shares/:id/accept', limiter, (req, res) => {
    const me = personAuth(req, res); if (!me) return;
    const row = shareRow(req.params.id);
    if (!row || row.delegate_did !== me.did) return res.status(404).json({ error: 'share not found' });
    const state = stateOf(row);
    if (state !== 'offered') return res.status(409).json({ error: `this share is ${state}`, share: view(row, me.did) });
    const secret = db.prepare(`SELECT id FROM blindkey_secrets WHERE id = ? AND did = ? AND ${REDEEMABLE_STATUS_SQL}`).get(row.secret_id, row.owner_did);
    if (!secret) return res.status(410).json({ error: 'the owner no longer has this secret' });
    // An offer made before pairing existed (or to a contact since removed) is taken only between confirmed contacts.
    if (!isConfirmedPeer(row.owner_did, me.did)) return res.status(403).json({ error: `this share can be taken only between contacts confirmed in person — ${PAIR_HINT}`, pair_required: true });
    // The recipient's PIN: an agent signed in as them (device login) cannot take on a share for them.
    if (!requirePin(me, `share-accept:${row.id}`, 'share-accept', res, { kind: 'share-accept', id: row.id, bind: String(row.secret_id), req })) return;
    const done = db.prepare(`UPDATE demipass_delegations SET status = 'active', offer_state = 'accepted', accepted_at = CURRENT_TIMESTAMP
                             WHERE id = ? AND status = 'suspended' AND offer_state = 'offered'`).run(row.id).changes;
    if (done !== 1) return res.status(409).json({ error: 'this share changed meanwhile; reload' });
    event('share_accepted', me.did, row.secret_id, { delegation_id: row.id, owner_did: row.owner_did, delegate_did: me.did });
    logSecurityEvent('share_accepted', 'info', { caller_did: me.did, capability: 'share', ip: req.ip, context: { share_id: row.id, owner: usernameOf(row.owner_did) } });
    res.json({ ok: true, share: view(shareRow(row.id), me.did),
      how_to_use: 'your agents (signed in as you) call POST /api/demipass/use with this ref; DemiPass injects the secret and they never see it' });
  });

  // ── POST /api/blindkey/shares/:id/decline — the recipient says no, or drops a share they hold ──────────────
  app.post('/api/blindkey/shares/:id/decline', limiter, (req, res) => {
    const me = personAuth(req, res); if (!me) return;
    const row = shareRow(req.params.id);
    if (!row || row.delegate_did !== me.did) return res.status(404).json({ error: 'share not found' });
    const state = stateOf(row);
    if (!['offered', 'active'].includes(state)) return res.status(409).json({ error: `this share is already ${state}` });
    const how = state === 'offered' ? 'declined' : 'dropped';
    db.prepare("UPDATE demipass_delegations SET status = 'revoked', offer_state = ?, revoked_at = datetime('now') WHERE id = ?").run(how, row.id);
    event(`share_${how}`, me.did, row.secret_id, { delegation_id: row.id, owner_did: row.owner_did, delegate_did: me.did });
    res.json({ ok: true, share: view(shareRow(row.id), me.did) });
  });

  // ── POST /api/blindkey/shares/:id/revoke — the owner ends it (an offer or a live share) ─────────────────────
  app.post('/api/blindkey/shares/:id/revoke', limiter, (req, res) => {
    const me = personAuth(req, res); if (!me) return;
    const row = shareRow(req.params.id);
    if (!row || row.owner_did !== me.did) return res.status(404).json({ error: 'share not found' });
    if (row.status === 'revoked') return res.status(409).json({ error: `this share is already ${stateOf(row)}` });
    db.prepare("UPDATE demipass_delegations SET status = 'revoked', revoked_at = datetime('now'), reveal_allowed = 0 WHERE id = ?").run(row.id);
    event('delegation_revoked', me.did, row.secret_id, { delegation_id: row.id, owner_did: me.did, delegate_did: row.delegate_did, via: 'share' });
    logSecurityEvent('share_revoked', 'info', { caller_did: me.did, capability: 'share', ip: req.ip, context: { share_id: row.id, recipient: usernameOf(row.delegate_did) } });
    res.json({ ok: true, share: view(shareRow(row.id), me.did) });
  });

  // ── POST /api/blindkey/shares/:id/reveal-grant — { allow: true, reveals?: 1–5, minutes?: 1–1440 (60) } with the PIN,
  //    or { allow: false } to close the door early ─
  app.post('/api/blindkey/shares/:id/reveal-grant', limiter, (req, res) => {
    const me = personAuth(req, res); if (!me) return;
    const row = shareRow(req.params.id);
    if (!row || row.owner_did !== me.did) return res.status(404).json({ error: 'share not found' });
    const state = stateOf(row);
    if (!['offered', 'active'].includes(state)) return res.status(409).json({ error: `this share is ${state}` });
    const { allow, reveals, minutes } = req.body || {};
    if (allow === false) {
      db.prepare('UPDATE demipass_delegations SET reveal_allowed = 0 WHERE id = ?').run(row.id);
      event('share_reveal_withdrawn', me.did, row.secret_id, { delegation_id: row.id, delegate_did: row.delegate_did });
      return res.json({ ok: true, share: view(shareRow(row.id), me.did) });
    }
    if (allow !== true) return res.status(400).json({ error: 'allow: true (with the PIN) or false' });
    const n = reveals === undefined || reveals === null ? 1 : reveals;
    if (!Number.isInteger(n) || n < 1 || n > MAX_REVEALS_PER_GRANT) return res.status(400).json({ error: `reveals: 1 to ${MAX_REVEALS_PER_GRANT}` });
    const mins = minutes === undefined || minutes === null ? REVEAL_DEFAULT_MINUTES : minutes;
    if (!Number.isInteger(mins) || mins < 1 || mins > REVEAL_MAX_MINUTES) return res.status(400).json({ error: `minutes: 1 to ${REVEAL_MAX_MINUTES} (a reveal grant is always time-boxed)` });
    const gsecret = db.prepare('SELECT * FROM blindkey_secrets WHERE id = ?').get(row.secret_id);
    if (!gsecret || gsecret.did !== me.did) return res.status(410).json({ error: 'you no longer own this secret' });
    // Letting someone SEE the value: signed by the phone too (#47 review H3).
    if (!requireGates(me, ownerRevealGates(gsecret), `reveal-grant:${row.id}`, 'reveal-grant', res,
      { kind: 'reveal-grant', id: row.id, bind: [n, mins].join('|'), req })) return;
    const until = new Date(Date.now() + mins * 60000).toISOString();
    db.prepare('UPDATE demipass_delegations SET reveal_allowed = 1, max_reveals = ?, reveals_used = 0, reveal_granted_at = CURRENT_TIMESTAMP, reveal_until = ? WHERE id = ?').run(n, until, row.id);
    event('share_reveal_granted', me.did, row.secret_id, { delegation_id: row.id, delegate_did: row.delegate_did, reveals: n, until });
    logSecurityEvent('share_reveal_granted', 'alert', { caller_did: me.did, capability: 'reveal-grant', ip: req.ip, context: { share_id: row.id, recipient: usernameOf(row.delegate_did), reveals: n, until } });
    res.json({ ok: true, share: view(shareRow(row.id), me.did) });
  });

  // ── POST /api/blindkey/shares/:id/reveal — the recipient sees the value, once per granted reveal, with their PIN ─
  app.post('/api/blindkey/shares/:id/reveal', limiter, (req, res) => {
    const me = personAuth(req, res); if (!me) return;
    const row = shareRow(req.params.id);
    if (!row || row.delegate_did !== me.did) return res.status(404).json({ error: 'share not found' });
    const state = stateOf(row);
    if (state !== 'active') return res.status(409).json({ error: state === 'offered' ? 'accept the share first' : `this share is ${state}` });
    if (!revealOpen(row)) {
      const lapsed = row.reveal_allowed && row.reveal_until && new Date(row.reveal_until) <= new Date();
      return res.status(403).json({ error: lapsed ? `the reveal window ${usernameOf(row.owner_did)} opened has closed` : `this share is use-only — ${usernameOf(row.owner_did)} has to allow a reveal first`, use_only: true });
    }
    const secret = db.prepare(`SELECT * FROM blindkey_secrets WHERE id = ? AND did = ? AND ${REDEEMABLE_STATUS_SQL}`).get(row.secret_id, row.owner_did);
    if (!secret) return res.status(410).json({ error: 'the owner no longer has this secret' });
    if (secret.frozen) return res.status(423).json({ error: 'the owner froze this secret', frozen: true });
    // Critical: a reveal also takes the owner's approval of this recipient's request (checked, then the PIN, then spent).
    const approvals = deps.approvals && deps.approvals();
    const critical = approvals && approvals.depthOf(secret) === 'critical';
    if (critical) {
      const g = approvals.gate(secret, { did: me.did, label: 'share reveal' }, { kind: 'reveal' }, req.body || {}, { peek: true });
      if (!g.ok) return res.status(g.status).json(g.body);
    }
    if (!requirePin(me, `share-reveal:${row.id}`, 'share-reveal', res)) return;
    if (critical) {
      const g = approvals.gate(secret, { did: me.did, label: 'share reveal' }, { kind: 'reveal' }, req.body || {});
      if (!g.ok) return res.status(g.status).json(g.body);
    }
    // Spend the reveal before decrypting: a reveal that cannot be counted is not given.
    const spent = db.prepare(`UPDATE demipass_delegations SET reveals_used = reveals_used + 1,
                              reveal_allowed = CASE WHEN reveals_used + 1 >= max_reveals THEN 0 ELSE 1 END
                              WHERE id = ? AND status = 'active' AND reveal_allowed = 1 AND reveals_used < max_reveals AND reveal_until > ?`).run(row.id, nowIso()).changes;
    if (spent !== 1) return res.status(409).json({ error: 'no reveal left on this share' });
    let value;
    try { value = blindkeyDecrypt(secret.encrypted_value); } catch (_) { return res.status(500).json({ error: 'decryption failed' }); }
    event('share_revealed', me.did, secret.id, { delegation_id: row.id, owner_did: row.owner_did, delegate_did: me.did });
    logSecurityEvent('secret_revealed', 'critical', { caller_did: me.did, capability: 'share-reveal', target: secret.name, ip: req.ip,
      context: { ref: secret.ref_code, owner_did: row.owner_did, share_id: row.id, fingerprint: me.auth.fingerprint_hash } });
    tick(me.did, `shared secret REVEALED: ${secret.name} (owner ${usernameOf(row.owner_did)})`, ['demipass:share-reveal', `secret:${secret.name}`]);
    tick(row.owner_did, `your secret ${secret.name} was REVEALED to ${me.username} (share ${row.id})`, ['demipass:share-reveal', `secret:${secret.name}`]);
    const after = shareRow(row.id);
    res.json({ ok: true, name: secret.name, value, revealed_at: nowIso(), reveals_left: Math.max(0, after.max_reveals - after.reveals_used),
      warning: `Shown to you once, logged as a CRITICAL event on your account and on ${usernameOf(row.owner_did)}'s.` });
  });

  // ── GET /api/blindkey/shares/:id/audit — who did what with this share, and when (owner or recipient) ──────────
  // Offer, accept, decline, every use, every reveal grant and every reveal, from blindkey_events. Never a value.
  app.get('/api/blindkey/shares/:id/audit', rateLimitStandard, (req, res) => {
    const auth = getBearerIdentity(req);
    if (!auth.ok) return res.status(auth.status || 401).json({ error: auth.error });
    const row = shareRow(req.params.id);
    if (!row || (row.owner_did !== auth.did && row.delegate_did !== auth.did)) return res.status(404).json({ error: 'share not found' });
    const rows = db.prepare(`SELECT event_type, actor, detail, created_at FROM blindkey_events
                             WHERE secret_id = ? AND json_valid(detail) AND json_extract(detail, '$.delegation_id') = ? ORDER BY id`).all(row.secret_id, row.id);
    const who = (a) => (typeof a === 'string' && a.startsWith('did:') ? usernameOf(a) : null) || (typeof a === 'string' ? a.split(':').slice(0, 2).join(':') : a);
    res.json({ ok: true, share: view(row, auth.did), events: rows.map(e => {
      let d = {}; try { d = JSON.parse(e.detail); } catch (_) {}
      return { at: e.created_at, event: e.event_type, by: who(e.actor), ...(d.reveals ? { reveals: d.reveals } : {}), ...(d.until ? { until: d.until } : {}) };
    }) });
  });

  // ── POST /api/blindkey/transfer — move one of your secrets to another person's vault ────────────────────────
  // { secret: name or ref, to: username / email / DID, keep?: 'use' (default) | 'none', keep_days?: 1–365 (365),
  //   new_name?: when they already have a secret with that name }. Needs the PIN (intent transfer:<secret id>).
  app.post('/api/blindkey/transfer', limiter, (req, res) => {
    const me = personAuth(req, res); if (!me) return;
    const { secret: pick, to, keep = 'use', keep_days, new_name } = req.body || {};
    const secret = ownSecret(me.did, pick);
    if (!secret) return res.status(404).json({ error: 'secret: name or ref of one of your active secrets' });
    if (secret.frozen) return res.status(423).json({ error: 'unfreeze the secret before transferring it', frozen: true });
    const target = findWallet(to);
    if (!target) return res.status(404).json({ error: 'to: no wallet with that username, email or DID' });
    if (target.did === me.did) return res.status(400).json({ error: 'that is you' });
    if (target.status !== 'active') return res.status(403).json({ error: `${target.username} is not active` });
    if (isAgentWallet(target.did)) return res.status(409).json({ error: `${target.username} is an agent — deposit into an agent's vault with POST /api/demipass/deposit` });
    if (!isPeer(me.did, target.did)) return res.status(403).json({ error: `you can transfer only to people you are connected to — add ${target.username} as a person in your network first` });
    if (!isConfirmedPeer(me.did, target.did)) return res.status(403).json({ error: `you can transfer only to contacts confirmed in person — ${PAIR_HINT}`, pair_required: true });
    if (!['use', 'none'].includes(keep)) return res.status(400).json({ error: "keep: 'use' (you keep use-only access) or 'none'" });
    const days = parseDays(keep_days, KEEP_DEFAULT_DAYS, SHARE_MAX_DAYS, 'keep_days', res); if (days === null) return;
    // Mid-rotation the old value is still live for its grace period: finish (or cancel) the rotation first.
    if (db.prepare("SELECT 1 FROM blindkey_secrets WHERE did = ? AND (name = ? OR name LIKE ?) AND status = 'rotating'").get(me.did, baseName(secret.name), baseName(secret.name) + '_v%')) {
      return res.status(409).json({ error: `${secret.name} is being rotated — finish the rotation before transferring it` });
    }
    // It lands as version 1 under a plain name (no _vN): a version suffix would let it take over a same-named
    // secret of theirs through /use's latest-version lookup.
    let finalName = baseName(secret.name);
    if (new_name !== undefined && new_name !== null && new_name !== '') {
      if (typeof new_name !== 'string' || new_name.length > 64 || /[\u0000-\u001f\u007f]/.test(new_name)) return res.status(400).json({ error: 'new_name: at most 64 characters' });
      finalName = new_name.trim();
      if (!finalName || /_v\d+$/.test(finalName)) return res.status(400).json({ error: 'new_name: a plain name, not ending in _v<number>' });
    }
    if (!requirePin(me, `transfer:${secret.id}`, 'transfer', res, { kind: 'transfer', id: secret.id, bind: [to, keep, new_name || ''].join('|'), req })) return;
    // Checked after the PIN, so whether a name exists in their vault is never answered for free.
    if (nameFamilyTaken(target.did, finalName)) {
      return res.status(409).json({ error: `${target.username} already uses the name '${finalName}' — send new_name (the PIN is asked again)`, name_taken: true });
    }
    let keptId = null, ended = [];
    try {
      db.transaction(() => {
        const moved = db.prepare(`UPDATE blindkey_secrets SET did = ?, name = ?, version = 1, replaced_by = NULL, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND did = ? AND status = 'active'`)
          .run(target.did, finalName, secret.id, me.did).changes;
        if (moved !== 1) throw Object.assign(new Error('the secret changed meanwhile; reload'), { status: 409 });
        let meta = {}; try { meta = JSON.parse(secret.metadata || '{}') || {}; } catch (_) {}
        meta.transfers = [...(Array.isArray(meta.transfers) ? meta.transfers : []), { from: me.username, to: target.username, at: nowIso() }].slice(-20);
        db.prepare('UPDATE blindkey_secrets SET metadata = ? WHERE id = ?').run(JSON.stringify(meta), secret.id);
        // Every access the old owner gave ends: the new owner starts from nothing they did not choose.
        ended = db.prepare("SELECT id, delegate_did FROM demipass_delegations WHERE secret_id = ? AND status IN ('active', 'suspended')").all(secret.id);
        db.prepare("UPDATE demipass_delegations SET status = 'revoked', revoked_at = datetime('now'), reveal_allowed = 0 WHERE secret_id = ? AND status IN ('active', 'suspended')").run(secret.id);
        db.prepare("UPDATE blindkey_use_tokens SET status = 'expired' WHERE secret_id = ? AND status = 'valid'").run(secret.id);
        if (keep === 'use') {
          keptId = Number(db.prepare(`INSERT INTO demipass_delegations (owner_did, delegate_did, secret_id, context_id, status, max_uses, granted_by, granted_at,
                                      expires_at, delegate_kind, offer_state, accepted_at, note, via)
                                      VALUES (?, ?, ?, NULL, 'active', 0, ?, CURRENT_TIMESTAMP, ?, 'person', 'accepted', CURRENT_TIMESTAMP, ?, 'transfer')`)
            .run(target.did, me.did, secret.id, me.did, daysFromNow(days), `kept by ${me.username} when they transferred it to you`).lastInsertRowid);
        }
        event('secret_transferred', me.did, secret.id, { from_did: me.did, to_did: target.did, name: finalName, ref: secret.ref_code, kept_delegation_id: keptId,
          ended_delegations: ended.map(d => d.id) });
      })();
    } catch (e) {
      return res.status(e.status || 500).json({ error: e.status ? e.message : 'could not transfer the secret; nothing changed' });
    }
    logSecurityEvent('secret_transferred', 'warn', { caller_did: me.did, capability: 'transfer', target: secret.name, ip: req.ip,
      context: { ref: secret.ref_code, to: target.username, kept_delegation_id: keptId, ended_delegations: ended.length } });
    tick(target.did, `secret received from ${me.username}: ${finalName}`, ['demipass:transfer-in', `secret:${finalName}`]);
    res.json({ ok: true, ref: secret.ref_code, name: finalName, owner: target.username, ended_delegations: ended.length,
      ...(keptId ? { kept: view(shareRow(keptId), me.did) } : {}),
      note: keptId ? `${target.username} owns it now; you keep use-only access through share ${keptId}, which they can see and revoke` : `${target.username} owns it now; you have no access to it` });
  });

  return { isPersonPeer, isAgentWallet, isPeer, isConfirmedPeer };
};
