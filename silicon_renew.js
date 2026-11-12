'use strict';
// ── Silicon token renewal: the owner renews an agent's token from the app; the token goes sealed to the agent's key ──
// Aaron 2026-11-12: "@claude's access token expired and the silicon didn't re-sign itself; the app shows 'token expired'
// with no action. Owner override on every silicon card: 'Renew token' with PIN that issues a fresh token to the
// silicon's own key, plus an expiry warning 24 h before lapse. No value ever shown."
//
// The server holds each fleet-created agent's wallet key, so it can mint for it; what was missing is a way to hand the
// token to the agent and to nobody else. The agent registers a DELIVERY KEY (X25519) with its own session; the owner's
// renewal mints the token and seals it to that key; the agent picks the sealed blob up and opens it (bin/token-pickup.js).
// The owner, the app, the server's answers and its logs never carry the token.
//
//   POST /api/identity/delivery-key {public_key}
//        the wallet's own session (transact). Not a worker, silicon: or agent device-login token, and not a token whose
//        value was shown in clear (the owner's "Mint a token" button: fleet_owner_mint without token_request/renewed).
//        X25519 public key, raw 32 bytes, base64url. The FIRST key is pinned at once (201 set). A different key later
//        is a PENDING change (202): the fleet owner approves it with the PIN and the phone in the app, or it lapses.
//        PR #100 review H1: otherwise any copy of an agent token silently redirects every later renewal.
//   POST /api/fleet/:slug/silicons/:handle/delivery-key/:change/approve | /deny
//        the fleet owner's own session; approve takes the PIN (silicon-key:<fleet_silicons id>) + the phone (bind
//        "key <fleet>/<handle> to <fingerprint>").
//   POST /api/fleet/:slug/silicons/:handle/renew-token {scope?, expires_in?}
//        the fleet owner's own person session, PIN (silicon-renew:<fleet_silicons id>) + linked phone
//        → {ok, delivery_id (random), expires_at}; 409 with no delivery key, or within KEY_COOLDOWN_SEC of a key change
//   GET  /api/identity/token-deliveries?did=…
//        no session (only the key holder can open a blob): the newest few unexpired, unrevoked, unacknowledged
//        deliveries as {id, epk, iv, tag, ciphertext} only — scope and expiry are inside the sealed payload (review M3)
//   POST /api/identity/token-deliveries/ack {used?}      Bearer = the delivered token itself (it proves it was opened)
//        used (default true): the agent holds it now — the card stops saying "awaiting pickup" and the expiry notices
//        start over. used: false — the agent kept a newer token; the delivered one is revoked (nobody holds it).
//        A renewed token's first use on any route acknowledges it too (noteUse, called from server.js).
//
// Sealing: an ephemeral X25519 key per delivery; ECDH with the agent's delivery key; HKDF-SHA256 (salt = ephemeral
// public ‖ recipient public, info = "demipass-token-delivery-v1:" + DID + ":" + delivery id) → a 32-byte key;
// AES-256-GCM, 12-byte IV, 16-byte tag, associated data DID + ":" + delivery id. The plaintext is JSON
// {v, did, delivery_id, token, scope, expires_at}. Stored: ephemeral public key, IV, tag, ciphertext — all base64url.

const TOKEN_SCOPE_CAP = 'transact';          // what an agent's token may be (silicon_token_requests.js, fleet_routes.js)
const DEFAULT_EXPIRES_IN = '30d';
const LIST_LIMIT = 3;                        // the pickup sees only the newest few
const KEEP_PER_DID = 10;                     // older deliveries of one DID are dropped
const KEY_CHANGE_TTL_SEC = 24 * 60 * 60;     // a key change waits a day for the owner
const KEY_COOLDOWN_SEC = 6 * 60 * 60;        // no renewal to a key changed less than this ago
const ALG = 'X25519-HKDF-SHA256-A256GCM';
const INFO_PREFIX = 'demipass-token-delivery-v1:';

// A token whose value some screen or answer showed in clear: the owner's own mint (fleet_routes.js POST …/token) — a
// fleet_owner_mint that is neither a claimed token request nor a sealed renewal. `shown` marks new ones explicitly.
function shownInClear(decoded) {
  const d = decoded || {};
  return d.auth_method === 'fleet_owner_mint' && (Boolean(d.shown) || (!d.token_request && !d.renewed));
}
// Tokens that are some agent acting, not the fleet owner deciding (fleet_routes.js member_token consent, #70 round-2).
function agentToken(auth) {
  const d = (auth && auth.decoded) || {};
  return Boolean(auth && auth.silicon) || Boolean(d.wrk) || d.auth_method === 'fleet_owner_mint' || d.auth_method === 'worker'
    || d.auth_method === 'device' || Boolean(d.agent_label) || Boolean(d.agent_name);
}

module.exports = function registerSiliconRenew(deps) {
  const { app, db, identity, crypto, fleetBilling: fb, rateLimitStandard, getBearerIdentity, gateSession, gateFresh, gateMissing,
          spendSingleUse, logSecurityEvent, billing } = deps;
  const devices = deps.devices || (() => null);
  const sendMail = deps.sendMail || (() => Promise.resolve(false));
  // The pickup is unauthenticated: per address AND DID (an agent polling never starves another), with a looser cap per
  // address so one client cannot sweep many DIDs (review L3).
  const erl = require('express-rate-limit');
  const ipKey = (req) => (erl.ipKeyGenerator ? erl.ipKeyGenerator(req.ip || '') : String(req.ip || ''));
  const pickupLimits = deps.pickupLimits || [
    erl({ windowMs: 15 * 60 * 1000, max: 60, keyGenerator: (req) => ipKey(req) + '|' + String(req.query.did || '').slice(0, 200), message: { error: 'Rate limit exceeded' } }),
    erl({ windowMs: 15 * 60 * 1000, max: 600, keyGenerator: ipKey, message: { error: 'Rate limit exceeded' } }),
  ];

  // Legacy-safe: a database made before this branch gets the columns and the tables on start.
  for (const col of ['delivery_public_key TEXT', 'delivery_key_set_at TEXT', 'delivery_key_changed_at TEXT']) {
    try { db.exec(`ALTER TABLE identity_wallets ADD COLUMN ${col}`); } catch (_) {}
  }
  db.exec(`CREATE TABLE IF NOT EXISTS delivery_key_changes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    did TEXT NOT NULL,
    public_key TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending', -- pending | approved | denied | expired | superseded
    auth_method TEXT DEFAULT '',            -- of the session that asked
    ip TEXT DEFAULT '',
    requested_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    decided_at TEXT DEFAULT NULL,
    decided_by TEXT DEFAULT NULL
  )`);
  db.exec('CREATE INDEX IF NOT EXISTS idx_dkc_did ON delivery_key_changes(did, status)');
  db.exec(`CREATE TABLE IF NOT EXISTS token_deliveries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pub_id TEXT NOT NULL UNIQUE,            -- the id anyone sees: random
    did TEXT NOT NULL,                      -- the agent the token is for (and whose delivery key sealed it)
    fleet_id INTEGER NOT NULL,
    silicon_row INTEGER NOT NULL,           -- fleet_silicons.id
    owner_did TEXT NOT NULL,                -- who renewed
    scope TEXT NOT NULL,
    token_jti TEXT NOT NULL,
    iat INTEGER NOT NULL,                   -- the token's issue time: the revoke-all cut needs no other row (review L6)
    key_fingerprint TEXT NOT NULL,          -- of the delivery key it was sealed to
    epk TEXT NOT NULL, iv TEXT NOT NULL, tag TEXT NOT NULL, ciphertext TEXT NOT NULL,   -- emptied once acknowledged
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,               -- the token's own expiry: the delivery ends with it
    acked_at TEXT DEFAULT NULL,
    ack TEXT DEFAULT NULL                   -- used | declined
  )`);
  db.exec('CREATE INDEX IF NOT EXISTS idx_td_did ON token_deliveries(did, id)');
  db.exec('CREATE INDEX IF NOT EXISTS idx_td_jti ON token_deliveries(token_jti)');

  const nowIso = () => new Date().toISOString();
  const later = (sec) => new Date(Date.now() + sec * 1000).toISOString();
  const fingerprint = (raw) => fb.deliveryKeyFingerprint(raw);   // the card shows the same one
  const x25519Public = (raw) => crypto.createPublicKey({ key: { kty: 'OKP', crv: 'X25519', x: Buffer.from(raw).toString('base64url') }, format: 'jwk' });
  const ownersOf = (did) => db.prepare(`SELECT f.id AS fleet_id, f.slug, f.owner_did, s.id AS silicon_row, s.handle, w.email AS owner_email
                                          FROM fleet_silicons s JOIN fleets f ON f.id = s.fleet_id LEFT JOIN identity_wallets w ON w.did = f.owner_did
                                         WHERE s.member_did = ? AND s.status = 'active' AND COALESCE(s.joined_via, 'owner') != 'network'
                                           AND COALESCE(f.status, 'active') = 'active'`).all(did);
  const mail = (to, subject, text) => { try { if (to) Promise.resolve(sendMail({ to, subject, text })).catch(() => {}); } catch (_) {} };

  // A public key the server can seal to: 32 bytes of base64url, and a working (not low-order) X25519 point.
  function parseDeliveryKey(s) {
    const str = String(s == null ? '' : s).trim();
    if (!/^[A-Za-z0-9_-]{43}$/.test(str)) return null;
    const raw = Buffer.from(str, 'base64url');
    if (raw.length !== 32) return null;
    try {
      const probe = crypto.generateKeyPairSync('x25519').privateKey;
      const shared = crypto.diffieHellman({ privateKey: probe, publicKey: x25519Public(raw) });
      if (shared.every(b => b === 0)) return null;
      shared.fill(0);
    } catch (_) { return null; }
    return raw;
  }

  function seal(payload, recipientRaw, did, pubId) {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519');
    const epk = Buffer.from(publicKey.export({ format: 'jwk' }).x, 'base64url');
    const shared = crypto.diffieHellman({ privateKey, publicKey: x25519Public(recipientRaw) });
    const key = Buffer.from(crypto.hkdfSync('sha256', shared, Buffer.concat([epk, recipientRaw]), Buffer.from(`${INFO_PREFIX}${did}:${pubId}`), 32));
    shared.fill(0);
    const iv = crypto.randomBytes(12);
    const c = crypto.createCipheriv('aes-256-gcm', key, iv, { authTagLength: 16 });
    c.setAAD(Buffer.from(`${did}:${pubId}`));
    const pt = Buffer.from(JSON.stringify(payload), 'utf8');
    const ct = Buffer.concat([c.update(pt), c.final()]);
    pt.fill(0); key.fill(0);
    return { epk: epk.toString('base64url'), iv: iv.toString('base64url'), tag: c.getAuthTag().toString('base64url'), ciphertext: ct.toString('base64url') };
  }

  function sweep() {
    const t = nowIso();
    db.prepare('DELETE FROM token_deliveries WHERE expires_at <= ?').run(t);
    db.prepare("UPDATE delivery_key_changes SET status = 'expired', decided_at = ? WHERE status = 'pending' AND expires_at <= ?").run(t, t);
  }
  const sweeper = setInterval(() => { try { sweep(); } catch (_) {} }, 10 * 60 * 1000); if (sweeper.unref) sweeper.unref();

  // The agent holds the delivered token now (or has refused it): the card counts it, the notices start over.
  function acknowledge(jti, did, used) {
    const d = db.prepare('SELECT id, silicon_row FROM token_deliveries WHERE token_jti = ? AND did = ? AND acked_at IS NULL').get(jti, did);
    if (!d) return false;
    db.transaction(() => {
      db.prepare("UPDATE token_deliveries SET acked_at = ?, ack = ?, epk = '', iv = '', tag = '', ciphertext = '' WHERE id = ?").run(nowIso(), used ? 'used' : 'declined', d.id);
      if (used) db.prepare('UPDATE fleet_silicons SET token_warned_at = NULL, token_owner_warned_jti = NULL WHERE id = ?').run(d.silicon_row);
      else db.prepare("UPDATE issued_tokens SET revoked = 1, revoked_at = datetime('now') WHERE jti = ?").run(jti);
    })();
    return true;
  }
  // server.js: a request authenticated by a renewed token is its use. Cheap: only tokens that carry `renewed`.
  function noteUse(decoded) {
    if (!decoded || !decoded.renewed || !decoded.jti) return;
    try { acknowledge(decoded.jti, decoded.sub, true); } catch (_) {}
  }

  // ── 1. the agent registers its delivery key, with its own session ───────────────────────────────────────────────
  app.post('/api/identity/delivery-key', rateLimitStandard, (req, res) => {
    const auth = getBearerIdentity(req);
    if (!auth.ok) return res.status(auth.status || 401).json({ error: auth.error });
    const d = auth.decoded || {};
    // A silicon: token acts for its carbon owner, a worker token for a sub-agent, a device login for an agent signed in
    // as a person: none is the wallet itself.
    if (auth.silicon || d.wrk || d.auth_method === 'worker' || d.auth_method === 'device' || d.agent_label || d.agent_name) {
      return res.status(403).json({ error: 'register the delivery key with the wallet\'s own token (not a worker, silicon: or device-login token)' });
    }
    if (shownInClear(d)) {
      return res.status(403).json({ shown_in_clear: true, error: 'this token\'s value was shown in clear when it was minted, so it cannot choose where renewals go. Use the agent\'s own sign-in, or a token from an agent token request (claimed by the agent), or a renewed token.' });
    }
    const raw = parseDeliveryKey((req.body || {}).public_key);
    if (!raw) return res.status(400).json({ error: 'public_key: an X25519 public key, 32 bytes, base64url' });
    const w = db.prepare('SELECT delivery_public_key FROM identity_wallets WHERE did = ?').get(auth.did);
    if (!w) return res.status(404).json({ error: 'identity not found' });
    const fp = fingerprint(raw), b64 = raw.toString('base64url');
    sweep();
    if (!w.delivery_public_key) {
      // The first key is pinned. Concurrent firsts: only one wins (the row still has none).
      const n = db.prepare('UPDATE identity_wallets SET delivery_public_key = ?, delivery_key_set_at = ?, delivery_key_changed_at = NULL WHERE did = ? AND delivery_public_key IS NULL').run(b64, nowIso(), auth.did).changes;
      if (n === 1) {
        if (logSecurityEvent) logSecurityEvent('delivery_key_set', 'info', { caller_did: auth.did, ip: req.ip, target: auth.did, context: { fingerprint: fp, auth_method: d.auth_method || null } });
        return res.status(201).json({ ok: true, status: 'set', did: auth.did, fingerprint: fp });
      }
    }
    const cur = db.prepare('SELECT delivery_public_key FROM identity_wallets WHERE did = ?').get(auth.did);
    if (cur.delivery_public_key === b64) return res.json({ ok: true, status: 'set', unchanged: true, did: auth.did, fingerprint: fp });
    // A different key: the fleet owner decides. One pending change per wallet; a newer ask replaces an older one.
    const id = db.transaction(() => {
      db.prepare("UPDATE delivery_key_changes SET status = 'superseded', decided_at = ? WHERE did = ? AND status = 'pending'").run(nowIso(), auth.did);
      return Number(db.prepare('INSERT INTO delivery_key_changes (did, public_key, fingerprint, auth_method, ip, requested_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)')
        .run(auth.did, b64, fp, String(d.auth_method || ''), String(req.ip || ''), nowIso(), later(KEY_CHANGE_TTL_SEC)).lastInsertRowid);
    }).immediate();
    if (logSecurityEvent) logSecurityEvent('delivery_key_change_asked', 'warn', { caller_did: auth.did, ip: req.ip, target: auth.did,
      context: { change_id: id, fingerprint: fp, current: fingerprint(Buffer.from(cur.delivery_public_key, 'base64url')), auth_method: d.auth_method || null } });
    for (const o of ownersOf(auth.did)) {
      mail(o.owner_email, `DemiPass: @${o.handle} asks to change its delivery key`,
        `Someone holding a live token of your agent @${o.handle} (fleet ${o.slug}) asks to change the key its renewed tokens are sealed to, to ${fp}.\n` +
        `Until you approve it, renewals keep going to the current key. If you did not set this agent up again yourself, deny it and revoke the agent's tokens: a copy of one may have leaked.\n` +
        `Approve or deny it in the DemiPass app (Fleet → @${o.handle}). It waits ${KEY_CHANGE_TTL_SEC / 3600} hours.\n`);
    }
    res.status(202).json({ ok: true, status: 'pending', change_id: id, did: auth.did, fingerprint: fp,
      next: 'the fleet owner approves the new key in the DemiPass app; until then renewals are sealed to the current key' });
  });

  // ── the owner's side ────────────────────────────────────────────────────────────────────────────────────────────
  function ownerAuth(req, res) {
    const auth = getBearerIdentity(req);
    if (!auth.ok) { res.status(auth.status || 401).json({ error: auth.error }); return null; }
    if (agentToken(auth)) { res.status(403).json({ error: 'an agent\'s token is renewed by the fleet owner in their own session (not an agent, worker, fleet-minted or device-login token)' }); return null; }
    if (gateSession && !gateSession(auth)) { res.status(403).json({ error: 'sign in again' }); return null; }
    return auth;
  }
  // The fleet (owned by the caller; anything else is 404) and its active, fleet-held agent.
  function ownedSilicon(req, res, auth) {
    const fleet = db.prepare("SELECT * FROM fleets WHERE slug = ? AND COALESCE(status,'active') = 'active'").get(req.params.slug);
    if (!fleet || fleet.owner_did !== auth.did) { res.status(404).json({ error: 'fleet not found' }); return null; }
    const s = fb.getSilicon(db, fleet.id, String(req.params.handle || '').toLowerCase());
    if (!s || s.status !== 'active') { res.status(404).json({ error: 'silicon not found in this fleet' }); return null; }
    if (s.joined_via === 'network') { res.status(403).json({ error: `@${s.handle} joined through the network and keeps its own key: it signs in itself` }); return null; }
    return { fleet, s };
  }

  app.post('/api/fleet/:slug/silicons/:handle/delivery-key/:change/approve', rateLimitStandard, (req, res) => {
    const auth = ownerAuth(req, res); if (!auth) return;
    const o = ownedSilicon(req, res, auth); if (!o) return;
    const { fleet, s } = o;
    sweep();
    const ch = db.prepare("SELECT * FROM delivery_key_changes WHERE id = ? AND did = ?").get(Number(req.params.change), s.member_did);
    if (!ch) return res.status(404).json({ error: 'no such key change' });
    if (ch.status !== 'pending') return res.status(409).json({ error: `this key change is ${ch.status}` });
    const intent = `silicon-key:${s.id}`;
    if (!gateFresh(auth.did, 'pin', auth, intent)) return res.status(403).json({ ...gateMissing('silicon-key', ['pin'], ['pin'], intent), error: `a new delivery key for @${s.handle} needs your PIN` });
    const bind = `key ${fleet.slug}/${s.handle} to ${ch.fingerprint}`;
    const dk = devices();
    const refused = dk ? dk.approvalRefusal(auth, 'silicon-key', s.id, bind, req.body) : null;
    if (refused) return res.status(refused.status).json(refused.body);
    try {
      db.transaction(() => {
        const spent = spendSingleUse(auth.did, 'silicon-key', ['pin'], auth, intent);
        if (spent) throw Object.assign(new Error(spent.error), { statusCode: spent.status || 403, body: spent });
        if (db.prepare("UPDATE delivery_key_changes SET status = 'approved', decided_at = ?, decided_by = ? WHERE id = ? AND status = 'pending'").run(nowIso(), auth.did, ch.id).changes !== 1) {
          throw Object.assign(new Error('this key change changed meanwhile'), { statusCode: 409 });
        }
        db.prepare('UPDATE identity_wallets SET delivery_public_key = ?, delivery_key_changed_at = ? WHERE did = ?').run(ch.public_key, nowIso(), s.member_did);
      }).immediate();
    } catch (e) { return res.status(e.statusCode || 500).json(e.body || { error: e.message }); }
    if (logSecurityEvent) logSecurityEvent('delivery_key_changed', 'warn', { caller_did: auth.did, ip: req.ip, target: s.handle, context: { fleet: fleet.slug, did: s.member_did, change_id: ch.id, fingerprint: ch.fingerprint } });
    res.json({ ok: true, handle: s.handle, fingerprint: ch.fingerprint, renew_after: later(KEY_COOLDOWN_SEC) });
  });

  app.post('/api/fleet/:slug/silicons/:handle/delivery-key/:change/deny', rateLimitStandard, (req, res) => {
    const auth = ownerAuth(req, res); if (!auth) return;
    const o = ownedSilicon(req, res, auth); if (!o) return;
    const n = db.prepare("UPDATE delivery_key_changes SET status = 'denied', decided_at = ?, decided_by = ? WHERE id = ? AND did = ? AND status = 'pending'")
      .run(nowIso(), auth.did, Number(req.params.change), o.s.member_did).changes;
    if (n && logSecurityEvent) logSecurityEvent('delivery_key_change_denied', 'warn', { caller_did: auth.did, ip: req.ip, target: o.s.handle, context: { change_id: Number(req.params.change) } });
    res.status(n ? 200 : 404).json(n ? { ok: true } : { error: 'no waiting key change by that id' });
  });

  // ── 2. the owner renews ─────────────────────────────────────────────────────────────────────────────────────────
  app.post('/api/fleet/:slug/silicons/:handle/renew-token', rateLimitStandard, (req, res) => {
    const auth = ownerAuth(req, res); if (!auth) return;
    const o = ownedSilicon(req, res, auth); if (!o) return;
    const { fleet, s } = o;
    const b = req.body || {};
    const scope = b.scope === undefined ? TOKEN_SCOPE_CAP : String(b.scope);
    if (!identity.ISSUABLE_SCOPES.includes(scope) || identity.scopeAtLeast(scope, 'admin')) return res.status(400).json({ error: `scope must be read, write or ${TOKEN_SCOPE_CAP}` });
    const asked = b.expires_in === undefined ? DEFAULT_EXPIRES_IN : String(b.expires_in);
    const m = /^(\d{1,5})([smhd])$/.exec(asked);
    if (!m) return res.status(400).json({ error: 'expires_in: e.g. 24h, 7d, 30d' });
    const secs = Number(m[1]) * { s: 1, m: 60, h: 3600, d: 86400 }[m[2]];
    if (secs < 3600) return res.status(400).json({ error: 'expires_in: at least 1h' });
    // Within the scope's ceiling (identity.js clamps too; the phone and the answer say the lifetime actually minted).
    const capSecs = Math.min(secs, (identity.SCOPE_MAX_TTL && identity.SCOPE_MAX_TTL[scope]) || 30 * 86400);
    const expiresIn = capSecs % 86400 === 0 ? `${capSecs / 86400}d` : capSecs % 3600 === 0 ? `${capSecs / 3600}h` : `${capSecs}s`;
    const wallet = db.prepare('SELECT * FROM identity_wallets WHERE did = ?').get(s.member_did);
    if (!wallet) return res.status(404).json({ error: 'identity not found' });
    // Nowhere to send it: said before the PIN is asked for.
    const recipient = wallet.delivery_public_key ? parseDeliveryKey(wallet.delivery_public_key) : null;
    if (!recipient) {
      return res.status(409).json({ no_delivery_key: true,
        error: `@${s.handle} has no delivery key, so a renewed token could reach nobody but you. On the agent, run "node bin/token-pickup.js --init <dir>" with its own sign-in token (DEMIPASS_TOKEN), then renew again. If its token has already lapsed, ask for one through an agent token request instead.` });
    }
    // A key that changed just now: wait, so a change the owner did not mean to approve can still be undone first.
    const changedAt = wallet.delivery_key_changed_at ? Date.parse(wallet.delivery_key_changed_at) : 0;
    if (changedAt && Date.now() - changedAt < KEY_COOLDOWN_SEC * 1000) {
      const after = new Date(changedAt + KEY_COOLDOWN_SEC * 1000).toISOString();
      return res.status(409).json({ key_cooldown: true, renew_after: after,
        error: `@${s.handle}'s delivery key changed at ${wallet.delivery_key_changed_at}: renewals to it start ${KEY_COOLDOWN_SEC / 3600} hours after a change (${after}).` });
    }
    const fp = fingerprint(recipient);
    const intent = `silicon-renew:${s.id}`;
    if (!gateFresh(auth.did, 'pin', auth, intent)) return res.status(403).json({ ...gateMissing('silicon-renew', ['pin'], ['pin'], intent), error: `renewing @${s.handle}'s token needs your PIN` });
    // What the linked phone signs: this agent, this scope and lifetime, sealed to this key.
    const bind = `renew ${fleet.slug}/${s.handle}:${scope}:${expiresIn} to key ${fp}`;
    const dk = devices();
    const refused = dk ? dk.approvalRefusal(auth, 'silicon-renew', s.id, bind, req.body) : null;
    if (refused) return res.status(refused.status).json(refused.body);
    let out;
    try {
      out = db.transaction(() => {
        const spent = spendSingleUse(auth.did, 'silicon-renew', ['pin'], auth, intent);
        if (spent) throw Object.assign(new Error(spent.error), { statusCode: spent.status || 403, body: spent });
        // Minted like the owner's own mint for an agent (fleet_routes.js POST …/token): it acts as the agent's wallet
        // and never runs a fleet. The token recorder (server.js) puts it in issued_tokens, the revocation surface.
        const token = identity.createTokenForIdentity(wallet.encrypted_private_key, wallet.did, {
          scope, expiresIn,
          metadata: { email: wallet.email, username: wallet.username, auth_method: 'fleet_owner_mint', fleet: fleet.slug, minted_by: auth.did, renewed: true },
        });
        const claims = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString());
        const pubId = crypto.randomBytes(12).toString('base64url');
        const expiresAt = new Date(claims.exp * 1000).toISOString();
        const sealed = seal({ v: 1, did: wallet.did, delivery_id: pubId, token, scope, expires_at: expiresAt }, recipient, wallet.did, pubId);
        db.prepare(`INSERT INTO token_deliveries (pub_id, did, fleet_id, silicon_row, owner_did, scope, token_jti, iat, key_fingerprint, epk, iv, tag, ciphertext, created_at, expires_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
          .run(pubId, wallet.did, fleet.id, s.id, auth.did, scope, claims.jti, claims.iat, fp, sealed.epk, sealed.iv, sealed.tag, sealed.ciphertext, nowIso(), expiresAt);
        db.prepare('DELETE FROM token_deliveries WHERE did = ? AND id NOT IN (SELECT id FROM token_deliveries WHERE did = ? ORDER BY id DESC LIMIT ?)').run(wallet.did, wallet.did, KEEP_PER_DID);
        return { pubId, expiresAt };
      }).immediate();
    } catch (e) {
      if (!e.statusCode) console.error('[renew] mint failed for', s.handle, '-', e.message);   // no token exists on this path
      return res.status(e.statusCode || 500).json(e.body || { error: e.statusCode ? e.message : 'the token could not be renewed' });
    }
    if (logSecurityEvent) logSecurityEvent('silicon_token_renewed', 'warn', { caller_did: auth.did, ip: req.ip, target: s.handle,
      context: { fleet: fleet.slug, did: wallet.did, delivery_id: out.pubId, scope, expires_in: expiresIn, key_fingerprint: fp } });
    res.json({ ok: true, delivery_id: out.pubId, expires_at: out.expiresAt, handle: s.handle, scope, expires_in: expiresIn, key_fingerprint: fp });
  });

  // ── 3. the agent picks it up: no session, non-consuming, the newest few, nothing but the sealed blob ────────────
  app.get('/api/identity/token-deliveries', ...pickupLimits, (req, res) => {
    const did = String(req.query.did || '');
    if (!/^did:[a-z0-9]+:[A-Za-z0-9._:%-]{1,200}$/.test(did)) return res.status(400).json({ error: 'did required' });
    sweep();
    // A token revoked since (its jti, sign-out everywhere, the agent leaving that fleet) is not handed out: the same
    // check a request carrying it would meet (billing.checkTokenRevocation), on the iat kept with the delivery.
    const rows = db.prepare(`SELECT d.pub_id, d.did, d.token_jti, d.iat, d.epk, d.iv, d.tag, d.ciphertext, f.slug AS fleet_slug
                               FROM token_deliveries d LEFT JOIN issued_tokens t ON t.jti = d.token_jti LEFT JOIN fleets f ON f.id = d.fleet_id
                              WHERE d.did = ? AND d.expires_at > ? AND d.acked_at IS NULL AND COALESCE(t.revoked, 0) = 0
                              ORDER BY d.id DESC LIMIT ?`).all(did, nowIso(), LIST_LIMIT)
      .filter(r => !(billing && billing.checkTokenRevocation(db, { jti: r.token_jti, sub: r.did, iat: r.iat, auth_method: 'fleet_owner_mint', fleet: r.fleet_slug }).revoked));
    res.json({ ok: true, alg: ALG, deliveries: rows.map(r => ({ id: r.pub_id, epk: r.epk, iv: r.iv, tag: r.tag, ciphertext: r.ciphertext })) });
  });

  // The agent says it holds the delivered token (or keeps a newer one). The token itself is the proof.
  app.post('/api/identity/token-deliveries/ack', rateLimitStandard, (req, res) => {
    const h = req.headers.authorization || '';
    const v = h.startsWith('Bearer ') ? identity.verifyTokenStandalone(h.slice(7)) : { valid: false, error: 'Bearer token required' };
    if (!v.valid) return res.status(401).json({ error: v.error });
    if (billing && billing.checkTokenRevocation(db, v.decoded).revoked) return res.status(401).json({ error: 'token revoked' });
    const used = (req.body || {}).used !== false;
    if (!acknowledge(v.decoded.jti, v.decoded.sub, used)) return res.status(404).json({ error: 'no delivery waiting for this token' });
    res.json({ ok: true, ack: used ? 'used' : 'declined' });
  });

  return { sweep, noteUse, shownInClear, ALG, INFO_PREFIX, KEY_COOLDOWN_SEC };
};
module.exports.ALG = ALG;
module.exports.INFO_PREFIX = INFO_PREFIX;
module.exports.shownInClear = shownInClear;
