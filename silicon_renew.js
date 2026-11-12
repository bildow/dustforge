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
//   POST /api/identity/delivery-key {public_key}          the wallet's own session (transact; not a worker or silicon:
//        token): X25519 public key, raw 32 bytes, base64url → {ok, did, fingerprint}
//   POST /api/fleet/:slug/silicons/:handle/renew-token {scope?, expires_in?}
//        the fleet owner's own person session, PIN (silicon-renew:<fleet_silicons id>) + linked phone
//        → {ok, delivery_id, expires_at}; 409 when the agent has no delivery key
//   GET  /api/identity/token-deliveries?did=…              no session (only the key holder can open a blob):
//        the newest few unexpired, unrevoked sealed deliveries; reading consumes nothing
//
// Sealing: an ephemeral X25519 key per delivery; ECDH with the agent's delivery key; HKDF-SHA256 (salt = ephemeral
// public ‖ recipient public, info = "demipass-token-delivery-v1:" + DID) → a 32-byte key; AES-256-GCM with a 12-byte
// IV and the DID as associated data. Stored: ephemeral public key, IV, tag, ciphertext — all base64url.

const TOKEN_SCOPE_CAP = 'transact';          // what an agent's token may be (silicon_token_requests.js, fleet_routes.js)
const DEFAULT_EXPIRES_IN = '30d';
const LIST_LIMIT = 3;                        // the pickup sees only the newest few
const KEEP_PER_DID = 10;                     // older deliveries of one DID are dropped
const ALG = 'X25519-HKDF-SHA256-A256GCM';
const INFO_PREFIX = 'demipass-token-delivery-v1:';

module.exports = function registerSiliconRenew(deps) {
  const { app, db, identity, crypto, fleetBilling: fb, rateLimitStandard, getBearerIdentity, gateSession, gateFresh, gateMissing,
          spendSingleUse, logSecurityEvent, billing } = deps;
  const devices = deps.devices || (() => null);
  // The pickup is unauthenticated: its own budget per address, apart from the shared limiters.
  const rateLimitPickup = deps.rateLimitPickup || require('express-rate-limit')({ windowMs: 15 * 60 * 1000, max: 60, message: { error: 'Rate limit exceeded' } });

  // Legacy-safe: a database made before this branch gets the columns and the table on start.
  for (const col of ['delivery_public_key TEXT', 'delivery_key_set_at TEXT']) {
    try { db.exec(`ALTER TABLE identity_wallets ADD COLUMN ${col}`); } catch (_) {}
  }
  db.exec(`CREATE TABLE IF NOT EXISTS token_deliveries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    did TEXT NOT NULL,                      -- the agent the token is for (and whose delivery key sealed it)
    fleet_id INTEGER NOT NULL,
    silicon_row INTEGER NOT NULL,           -- fleet_silicons.id
    owner_did TEXT NOT NULL,                -- who renewed
    scope TEXT NOT NULL,
    token_jti TEXT NOT NULL,
    key_fingerprint TEXT NOT NULL,          -- of the delivery key it was sealed to
    epk TEXT NOT NULL, iv TEXT NOT NULL, tag TEXT NOT NULL, ciphertext TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL                -- the token's own expiry: the delivery ends with it
  )`);
  db.exec('CREATE INDEX IF NOT EXISTS idx_td_did ON token_deliveries(did, id)');

  const nowIso = () => new Date().toISOString();
  const fingerprint = (raw) => fb.deliveryKeyFingerprint(raw);   // the card shows the same one
  const x25519Public = (raw) => crypto.createPublicKey({ key: { kty: 'OKP', crv: 'X25519', x: Buffer.from(raw).toString('base64url') }, format: 'jwk' });

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

  function seal(plaintext, recipientRaw, did) {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519');
    const epk = Buffer.from(publicKey.export({ format: 'jwk' }).x, 'base64url');
    const shared = crypto.diffieHellman({ privateKey, publicKey: x25519Public(recipientRaw) });
    const key = Buffer.from(crypto.hkdfSync('sha256', shared, Buffer.concat([epk, recipientRaw]), Buffer.from(INFO_PREFIX + did), 32));
    shared.fill(0);
    const iv = crypto.randomBytes(12);
    const c = crypto.createCipheriv('aes-256-gcm', key, iv);
    c.setAAD(Buffer.from(did));
    const ct = Buffer.concat([c.update(Buffer.from(plaintext, 'utf8')), c.final()]);
    const tag = c.getAuthTag();
    key.fill(0);
    return { epk: epk.toString('base64url'), iv: iv.toString('base64url'), tag: tag.toString('base64url'), ciphertext: ct.toString('base64url') };
  }

  function purgeExpired() {
    db.prepare('DELETE FROM token_deliveries WHERE expires_at <= ?').run(nowIso());
  }
  const sweeper = setInterval(() => { try { purgeExpired(); } catch (_) {} }, 10 * 60 * 1000); if (sweeper.unref) sweeper.unref();

  // ── 1. the agent registers its delivery key, with its own session ───────────────────────────────────────────────
  app.post('/api/identity/delivery-key', rateLimitStandard, (req, res) => {
    const auth = getBearerIdentity(req);
    if (!auth.ok) return res.status(auth.status || 401).json({ error: auth.error });
    // A silicon: token acts for its carbon owner, a worker token for a sub-agent: neither is the wallet itself.
    if (auth.silicon || (auth.decoded && auth.decoded.wrk)) return res.status(403).json({ error: 'register the delivery key with the wallet\'s own token (not a worker or silicon: token)' });
    const raw = parseDeliveryKey((req.body || {}).public_key);
    if (!raw) return res.status(400).json({ error: 'public_key: an X25519 public key, 32 bytes, base64url' });
    const before = db.prepare('SELECT delivery_public_key FROM identity_wallets WHERE did = ?').get(auth.did);
    if (!before) return res.status(404).json({ error: 'identity not found' });
    const fp = fingerprint(raw);
    db.prepare('UPDATE identity_wallets SET delivery_public_key = ?, delivery_key_set_at = ? WHERE did = ?').run(raw.toString('base64url'), nowIso(), auth.did);
    if (logSecurityEvent) logSecurityEvent('delivery_key_set', before.delivery_public_key ? 'warn' : 'info', { caller_did: auth.did, ip: req.ip, target: auth.did,
      context: { fingerprint: fp, replaced: Boolean(before.delivery_public_key), auth_method: (auth.decoded && auth.decoded.auth_method) || null } });
    res.json({ ok: true, did: auth.did, fingerprint: fp });
  });

  // ── 2. the owner renews ─────────────────────────────────────────────────────────────────────────────────────────
  function ownerAuth(req, res) {
    const auth = getBearerIdentity(req);
    if (!auth.ok) { res.status(auth.status || 401).json({ error: auth.error }); return null; }
    if (auth.silicon || (auth.decoded && (auth.decoded.wrk || auth.decoded.auth_method === 'fleet_owner_mint'))) { res.status(403).json({ error: 'an agent\'s token is renewed by the fleet owner in their own session' }); return null; }
    if (gateSession && !gateSession(auth)) { res.status(403).json({ error: 'sign in again' }); return null; }
    return auth;
  }

  app.post('/api/fleet/:slug/silicons/:handle/renew-token', rateLimitStandard, (req, res) => {
    const auth = ownerAuth(req, res); if (!auth) return;
    const fleet = db.prepare("SELECT * FROM fleets WHERE slug = ? AND COALESCE(status,'active') = 'active'").get(req.params.slug);
    // Someone else's fleet looks like no fleet at all.
    if (!fleet || fleet.owner_did !== auth.did) return res.status(404).json({ error: 'fleet not found' });
    const s = fb.getSilicon(db, fleet.id, String(req.params.handle || '').toLowerCase());
    if (!s || s.status !== 'active') return res.status(404).json({ error: 'silicon not found in this fleet' });
    if (s.joined_via === 'network') return res.status(403).json({ error: `@${s.handle} joined through the network and keeps its own key: it signs in itself` });
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
        error: `@${s.handle} has no delivery key, so a renewed token could reach nobody but you. On the agent, run "node bin/token-pickup.js --init <dir>" with its current token (DEMIPASS_TOKEN), then renew again. If its token has already lapsed, ask for one through an agent token request instead.` });
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
        const sealed = seal(token, recipient, wallet.did);
        const expiresAt = new Date(claims.exp * 1000).toISOString();
        const id = Number(db.prepare(`INSERT INTO token_deliveries (did, fleet_id, silicon_row, owner_did, scope, token_jti, key_fingerprint, epk, iv, tag, ciphertext, created_at, expires_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
          .run(wallet.did, fleet.id, s.id, auth.did, scope, claims.jti, fp, sealed.epk, sealed.iv, sealed.tag, sealed.ciphertext, nowIso(), expiresAt).lastInsertRowid);
        db.prepare('DELETE FROM token_deliveries WHERE did = ? AND id NOT IN (SELECT id FROM token_deliveries WHERE did = ? ORDER BY id DESC LIMIT ?)').run(wallet.did, wallet.did, KEEP_PER_DID);
        // A renewed token restarts the expiry notices.
        db.prepare('UPDATE fleet_silicons SET token_warned_at = NULL WHERE id = ?').run(s.id);
        return { id, expiresAt, jti: claims.jti };
      }).immediate();
    } catch (e) {
      if (!e.statusCode) console.error('[renew] mint failed for', s.handle, '-', e.message);   // no token exists on this path
      // Never e.message of a mint that went wrong past the token (there is none: errors come before or without it).
      return res.status(e.statusCode || 500).json(e.body || { error: e.statusCode ? e.message : 'the token could not be renewed' });
    }
    if (logSecurityEvent) logSecurityEvent('silicon_token_renewed', 'warn', { caller_did: auth.did, ip: req.ip, target: s.handle,
      context: { fleet: fleet.slug, did: wallet.did, delivery_id: out.id, scope, expires_in: expiresIn, key_fingerprint: fp } });
    res.json({ ok: true, delivery_id: out.id, expires_at: out.expiresAt, handle: s.handle, scope, expires_in: expiresIn, key_fingerprint: fp });
  });

  // ── 3. the agent picks it up: no session, non-consuming, the newest few ─────────────────────────────────────────
  app.get('/api/identity/token-deliveries', rateLimitPickup, (req, res) => {
    const did = String(req.query.did || '');
    if (!/^did:[a-z0-9]+:[A-Za-z0-9._:%-]{1,200}$/.test(did)) return res.status(400).json({ error: 'did required' });
    purgeExpired();
    // A token revoked since (its jti, sign-out everywhere, the agent leaving that fleet) is not handed out: the same
    // check a request carrying it would meet (billing.checkTokenRevocation).
    const rows = db.prepare(`SELECT d.id, d.did, d.scope, d.key_fingerprint, d.epk, d.iv, d.tag, d.ciphertext, d.created_at, d.expires_at,
                                    d.token_jti, t.issued_at, t.revoked, f.slug AS fleet_slug
                               FROM token_deliveries d LEFT JOIN issued_tokens t ON t.jti = d.token_jti LEFT JOIN fleets f ON f.id = d.fleet_id
                              WHERE d.did = ? AND d.expires_at > ? AND COALESCE(t.revoked, 0) = 0
                              ORDER BY d.id DESC LIMIT ?`).all(did, nowIso(), LIST_LIMIT)
      .filter(r => !(billing && billing.checkTokenRevocation(db, { jti: r.token_jti, sub: r.did, iat: r.issued_at, auth_method: 'fleet_owner_mint', fleet: r.fleet_slug }).revoked));
    res.json({ ok: true, did, deliveries: rows.map(r => ({ id: r.id, scope: r.scope, created_at: r.created_at, expires_at: r.expires_at, key_fingerprint: r.key_fingerprint,
      sealed: { alg: ALG, epk: r.epk, iv: r.iv, tag: r.tag, ciphertext: r.ciphertext } })) });
  });

  return { purgeExpired, ALG, INFO_PREFIX };
};
module.exports.ALG = ALG;
module.exports.INFO_PREFIX = INFO_PREFIX;
