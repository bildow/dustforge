'use strict';
// ── Silicon token renewal: the owner renews an agent's token from the app; the token goes sealed to the agent's key ──
// Aaron 2026-11-12: "@claude's access token expired and the silicon didn't re-sign itself; the app shows 'token expired'
// with no action. Owner override on every silicon card: 'Renew token' with PIN that issues a fresh token to the
// silicon's own key, plus an expiry warning 24 h before lapse. No value ever shown."
//
// The server holds each fleet-created agent's wallet key, so it can mint for it; what was missing is a way to hand the
// token to the agent and to nobody else. The agent registers a DELIVERY KEY (X25519); the owner's renewal mints the
// token and seals it to that key; the agent picks the sealed blob up and opens it (bin/token-pickup.js). The owner, the
// app, the server's answers and its logs never carry the token.
//
// Which key renewals go to is the owner's decision (PR #100 review rounds 2-3): any live copy of an agent token could
// otherwise choose it.
//   POST /api/identity/delivery-key {public_key}
//        X25519 public key, raw 32 bytes, base64url, asked for with a token of the wallet. Refused: worker, silicon:,
//        device-login tokens, and tokens whose value someone other than the agent saw (a fleet_owner_mint that is not
//        `agent_own` and not a sealed renewal: the owner's "Mint a token", a request filed or claimed by another member).
//        → 202 pending: the fleet owner approves it in the app (PIN silicon-key:<fleet_silicons id> + phone, bind
//          "key <fleet>/<handle> to <fingerprint>") — the FIRST key too. One waiting ask per wallet: another while one
//          waits is 429 (it names the waiting fingerprint); the owner is mailed at most once per MAIL_GAP_SEC per wallet.
//        No key is ever set on an ask alone (round-4 review H1: a leaked sign-in could file a request "for itself").
//        The other way a key is set: it travels IN an agent token request (delivery_key), the owner's phone signs
//        "… key <fingerprint>" with the request, and the key is set when the request is claimed (setKeyFromRequest).
//        A waiting ask ends when its token is revoked (revoke-all, a fleet cut, its jti) — checked again at approval;
//        an ask a claimed request's key replaces is ended loudly (logged, the owner mailed), never silently.
//   POST /api/fleet/:slug/silicons/:handle/delivery-key/:change/approve | /deny
//        deny also signs out the token that asked (and its session): it cannot ask again at once (round-4 M1).
//   POST /api/fleet/:slug/silicons/:handle/delivery-key/revert
//        within REVERT_WINDOW_SEC of an approved change: back to the previous key (PIN silicon-key-revert:<id> + phone);
//        every token sealed to the reverted key is revoked, and so is the token (and session) that asked for it.
//        An ask after a deny or a revert always mails the owner (the 3 h mail cap does not hide it).
//   POST /api/fleet/:slug/silicons/:handle/renew-token {scope?, expires_in?}
//        the fleet owner's own person session, PIN (silicon-renew:<fleet_silicons id>) + linked phone
//        → {ok, delivery_id (random), expires_at}; 409 while no key is approved
//   GET  /api/identity/token-deliveries?did=…
//        no session (only the key holder can open a blob): the newest few unexpired, unrevoked, unacknowledged
//        deliveries as {id, epk, iv, tag, ciphertext} only — scope and expiry are inside the sealed payload
//   POST /api/identity/token-deliveries/ack {used?}      Bearer = the delivered token itself (it proves it was opened)
//        used (default true): the agent holds it now — the card stops saying "awaiting pickup" and the expiry notices
//        start over. used: false — the agent keeps another token; the delivered one is revoked (nobody holds it).
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
const KEY_CHANGE_TTL_SEC = 24 * 60 * 60;     // a key ask waits a day for the owner
const REVERT_WINDOW_SEC = 6 * 60 * 60;       // an approved change can be undone this long
const MAIL_GAP_SEC = 3 * 60 * 60;            // key-ask mails: at most one per wallet per this
const ALG = 'X25519-HKDF-SHA256-A256GCM';
const INFO_PREFIX = 'demipass-token-delivery-v1:';
// The way in for an agent whose tokens were all seen by someone else (review round 3, L3).
const OWN_TOKEN_HOWTO = 'The way in: an agent token request that carries the agent\'s key — on the agent, "node bin/token-pickup.js --material <dir>" prints ' +
  'its delivery_key and a claim_secret_hash; the fleet owner files POST /api/fleet/<fleet>/silicons/<handle>/token-requests {"claim_secret_hash", "delivery_key"} ' +
  'and approves it in the app (the phone shows the key\'s fingerprint); the agent runs "node bin/token-pickup.js --claim <dir> <request id>": its token, and the key set. ' +
  'With the agent\'s own sign-in, "node bin/token-pickup.js --request <dir> <fleet> <handle>" files that request itself.';

// A public key the server can seal to: 32 bytes of base64url, and a working (not low-order) X25519 point. → raw or null.
function parseDeliveryKey(s) {
  const crypto = require('crypto');
  const str = String(s == null ? '' : s).trim();
  if (!/^[A-Za-z0-9_-]{43}$/.test(str)) return null;
  const raw = Buffer.from(str, 'base64url');
  if (raw.length !== 32) return null;
  try {
    const probe = crypto.generateKeyPairSync('x25519').privateKey;
    const shared = crypto.diffieHellman({ privateKey: probe, publicKey: crypto.createPublicKey({ key: { kty: 'OKP', crv: 'X25519', x: str }, format: 'jwk' }) });
    if (shared.every(b => b === 0)) return null;
    shared.fill(0);
  } catch (_) { return null; }
  return raw;
}

// A token whose value someone other than the agent may have seen: a fleet-minted token that is neither the agent's
// own request (`agent_own`, set at mint by silicon_token_requests.js) nor a sealed renewal.
function shownInClear(decoded) {
  const d = decoded || {};
  return d.auth_method === 'fleet_owner_mint' && !d.agent_own && !d.renewed;
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
  // address so one client cannot sweep many DIDs.
  const erl = require('express-rate-limit');
  const ipKey = (req) => (erl.ipKeyGenerator ? erl.ipKeyGenerator(req.ip || '') : String(req.ip || ''));
  const pickupLimits = deps.pickupLimits || [
    erl({ windowMs: 15 * 60 * 1000, max: 60, keyGenerator: (req) => ipKey(req) + '|' + String(req.query.did || '').slice(0, 200), message: { error: 'Rate limit exceeded' } }),
    erl({ windowMs: 15 * 60 * 1000, max: 600, keyGenerator: ipKey, message: { error: 'Rate limit exceeded' } }),
  ];

  // Legacy-safe: a database made before this branch (or by an earlier round of it) gets the columns and tables on start.
  for (const col of ['delivery_public_key TEXT', 'delivery_key_set_at TEXT', 'delivery_key_changed_at TEXT', 'delivery_key_previous TEXT', 'delivery_key_previous_until TEXT']) {
    try { db.exec(`ALTER TABLE identity_wallets ADD COLUMN ${col}`); } catch (_) {}
  }
  db.exec(`CREATE TABLE IF NOT EXISTS delivery_key_changes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    did TEXT NOT NULL,
    public_key TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending', -- pending | approved | denied | expired | superseded | revoked | reverted
    auth_method TEXT DEFAULT '',            -- of the token that asked
    ip TEXT DEFAULT '',
    requested_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    decided_at TEXT DEFAULT NULL,
    decided_by TEXT DEFAULT NULL
  )`);
  // request_id / claimed_jti: a key set by a claimed token request (setKeyFromRequest) is recorded as an approved change too,
  // so an undo finds who filed it and the token it handed out (round-5 M1).
  for (const col of ["ask_jti TEXT DEFAULT ''", 'ask_iat INTEGER DEFAULT 0', "ask_fleet TEXT DEFAULT ''", "ask_sid TEXT DEFAULT ''", 'first_key INTEGER DEFAULT 0', 'mailed_at TEXT DEFAULT NULL',
                     'request_id INTEGER DEFAULT NULL', "claimed_jti TEXT DEFAULT ''", "asker_did TEXT DEFAULT ''"]) {
    try { db.exec(`ALTER TABLE delivery_key_changes ADD COLUMN ${col}`); } catch (_) {}
  }
  db.exec('CREATE INDEX IF NOT EXISTS idx_dkc_did ON delivery_key_changes(did, status)');
  db.exec(`CREATE TABLE IF NOT EXISTS token_deliveries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pub_id TEXT,                            -- the id anyone sees: random (unique index below)
    did TEXT NOT NULL,                      -- the agent the token is for (and whose delivery key sealed it)
    fleet_id INTEGER NOT NULL,
    silicon_row INTEGER NOT NULL,           -- fleet_silicons.id
    owner_did TEXT NOT NULL,                -- who renewed
    scope TEXT NOT NULL,
    token_jti TEXT NOT NULL,
    iat INTEGER DEFAULT 0,                  -- the token's issue time: the revoke-all cut needs no other row
    key_fingerprint TEXT NOT NULL,          -- of the delivery key it was sealed to
    epk TEXT NOT NULL, iv TEXT NOT NULL, tag TEXT NOT NULL, ciphertext TEXT NOT NULL,   -- emptied once acknowledged
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,               -- the token's own expiry: the delivery ends with it
    acked_at TEXT DEFAULT NULL,
    ack TEXT DEFAULT NULL                   -- used | declined
  )`);
  // A token_deliveries made by round 1 of this branch (no pub_id/iat/acked_at/ack): add them; old rows get a random id
  // and the iat of their issued_tokens row (round-3 review L4).
  for (const col of ['pub_id TEXT', 'iat INTEGER DEFAULT 0', 'acked_at TEXT DEFAULT NULL', 'ack TEXT DEFAULT NULL']) {
    try { db.exec(`ALTER TABLE token_deliveries ADD COLUMN ${col}`); } catch (_) {}
  }
  for (const r of db.prepare("SELECT id FROM token_deliveries WHERE pub_id IS NULL OR pub_id = ''").all()) {
    db.prepare('UPDATE token_deliveries SET pub_id = ? WHERE id = ?').run(crypto.randomBytes(12).toString('base64url'), r.id);
  }
  try { db.exec('UPDATE token_deliveries SET iat = COALESCE((SELECT issued_at FROM issued_tokens t WHERE t.jti = token_deliveries.token_jti), 0) WHERE COALESCE(iat, 0) = 0'); } catch (_) {}
  db.exec('CREATE UNIQUE INDEX IF NOT EXISTS idx_td_pub ON token_deliveries(pub_id)');
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
  // {revoked, lookup_failed}: a lookup that could not run refuses (G2) but is never written down as a revocation.
  const askState = (c) => (billing && billing.checkTokenRevocation(db, { jti: c.ask_jti || undefined, sub: c.did, iat: c.ask_iat || 0,
    auth_method: c.auth_method, fleet: c.ask_fleet || undefined })) || { revoked: false };
  const askRevoked = (c) => Boolean(askState(c).revoked);   // display only (the owner's card hides it); never persisted

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

  // The token that asked for a key, and the session behind it (every token refreshed from that sign-in, its refresh
  // chain): signed out when the owner denies the ask or undoes the change it got approved (round-4 review M1).
  // A request filed by the fleet owner is the owner's own session: an undo does not sign the owner out (only what the
  // request handed out is revoked). Note: a renewed token has no session, so denying an ask the agent made with its
  // only (renewed) token leaves it without one — the owner renews again once it has a key (documented; round-5 L3).
  function endAsker(c) {
    let n = 0;
    const who = c.asker_did || c.did;
    if (c.request_id && who !== c.did) return 0;
    try {
      if (c.ask_jti) n += db.prepare("UPDATE issued_tokens SET revoked = 1, revoked_at = datetime('now') WHERE did = ? AND revoked = 0 AND jti = ?").run(who, c.ask_jti).changes;
      if (c.ask_sid) n += db.prepare("UPDATE issued_tokens SET revoked = 1, revoked_at = datetime('now') WHERE did = ? AND revoked = 0 AND sid = ?").run(who, c.ask_sid).changes;
      try { db.prepare('UPDATE refresh_tokens SET revoked = 1, rotated_to = NULL WHERE did = ? AND revoked = 0 AND ((session_id = ? AND ? != \'\') OR (access_jti = ? AND ? != \'\'))').run(who, c.ask_sid || '', c.ask_sid || '', c.ask_jti || '', c.ask_jti || ''); } catch (_) {}
    } catch (_) {}
    return n;
  }
  // The owner hears of an ask at most once per MAIL_GAP_SEC — except the first ask after a deny or an undo, which is
  // always mailed (the deny loop: round-4 review M1).
  function shouldMail(did) {
    const last = db.prepare('SELECT MAX(mailed_at) AS t FROM delivery_key_changes WHERE did = ? AND mailed_at IS NOT NULL').get(did).t;
    if (!last || Date.now() - Date.parse(last) >= MAIL_GAP_SEC * 1000) return true;
    return Boolean(db.prepare("SELECT 1 FROM delivery_key_changes WHERE did = ? AND status IN ('denied','reverted') AND decided_at >= ?").get(did, last));
  }
  // The card hides an ask whose token was revoked, by the same check the routes use.
  if (fb.setAskRevokedCheck) fb.setAskRevokedCheck(askRevoked);

  // Expired deliveries go; key asks past their day expire; an ask whose token was revoked since (revoke-all, a fleet
  // cut, its jti) ends — whoever held it is not trusted to choose a key any more (round-3 review L1).
  function sweep() {
    const t = nowIso();
    db.prepare('DELETE FROM token_deliveries WHERE expires_at <= ?').run(t);
    db.prepare("UPDATE delivery_key_changes SET status = 'expired', decided_at = ? WHERE status = 'pending' AND expires_at <= ?").run(t, t);
    for (const c of db.prepare("SELECT * FROM delivery_key_changes WHERE status = 'pending'").all()) {
      const r = askState(c);
      if (r.lookup_failed) continue;   // a database fault is not a revocation: leave the ask pending (G2 review M1)
      if (r.revoked) db.prepare("UPDATE delivery_key_changes SET status = 'revoked', decided_at = ? WHERE id = ? AND status = 'pending'").run(t, c.id);
    }
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

  // ── 1. the agent asks for its delivery key ──────────────────────────────────────────────────────────────────────
  app.post('/api/identity/delivery-key', rateLimitStandard, (req, res) => {
    const auth = getBearerIdentity(req);
    if (!auth.ok) return res.status(auth.status || 401).json({ error: auth.error, ...(auth.code ? { code: auth.code } : {}) });
    const d = auth.decoded || {};
    // A silicon: token acts for its carbon owner, a worker token for a sub-agent, a device login for an agent signed in
    // as a person: none is the wallet itself.
    if (auth.silicon || d.wrk || d.auth_method === 'worker' || d.auth_method === 'device' || d.agent_label || d.agent_name) {
      return res.status(403).json({ error: 'register the delivery key with the wallet\'s own token (not a worker, silicon: or device-login token)' });
    }
    if (shownInClear(d)) {
      return res.status(403).json({ shown_in_clear: true, error: `this token was handed to someone other than the agent (its value was shown, or another member asked for it), so it cannot choose where renewals go. ${OWN_TOKEN_HOWTO}` });
    }
    const raw = parseDeliveryKey((req.body || {}).public_key);
    if (!raw) return res.status(400).json({ error: 'public_key: an X25519 public key, 32 bytes, base64url' });
    const w = db.prepare('SELECT delivery_public_key FROM identity_wallets WHERE did = ?').get(auth.did);
    if (!w) return res.status(404).json({ error: 'identity not found' });
    const fp = fingerprint(raw), b64 = raw.toString('base64url');
    sweep();
    if (w.delivery_public_key === b64) return res.json({ ok: true, status: 'set', unchanged: true, did: auth.did, fingerprint: fp });
    // Every ask waits for the fleet owner — one at a time per wallet. (A key is set without an ask only when it came
    // inside an agent token request the owner approved with its fingerprint on the phone: setKeyFromRequest.)
    const waiting = db.prepare("SELECT * FROM delivery_key_changes WHERE did = ? AND status = 'pending' ORDER BY id DESC LIMIT 1").get(auth.did);
    if (waiting) {
      if (waiting.public_key === b64) return res.status(202).json({ ok: true, status: 'pending', change_id: waiting.id, did: auth.did, fingerprint: fp, already_asked: true });
      return res.status(429).json({ key_ask_waiting: true, waiting: { fingerprint: waiting.fingerprint, requested_at: waiting.requested_at, expires_at: waiting.expires_at },
        error: `a delivery key ${waiting.fingerprint} is already waiting for the fleet owner (asked ${waiting.requested_at}). If it is not this agent's, tell the owner to deny it; then ask again.` });
    }
    const first = !w.delivery_public_key;
    const mailNow = shouldMail(auth.did);
    const id = Number(db.prepare(`INSERT INTO delivery_key_changes (did, public_key, fingerprint, auth_method, ip, requested_at, expires_at, ask_jti, ask_iat, ask_fleet, ask_sid, first_key)
                                  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .run(auth.did, b64, fp, String(d.auth_method || ''), String(req.ip || ''), nowIso(), later(KEY_CHANGE_TTL_SEC), String(d.jti || ''), Number(d.iat || 0),
        String(d.fleet || ''), String(d.sid || ''), first ? 1 : 0).lastInsertRowid);
    if (logSecurityEvent) logSecurityEvent('delivery_key_change_asked', 'warn', { caller_did: auth.did, ip: req.ip, target: auth.did,
      context: { change_id: id, fingerprint: fp, first_key: first, current: first ? null : fingerprint(Buffer.from(w.delivery_public_key, 'base64url')), auth_method: d.auth_method || null } });
    // One mail per wallet per MAIL_GAP_SEC (a flood of asks is one notice, and only one ask waits anyway) — but always
    // the first ask after a deny or an undo.
    if (mailNow) {
      db.prepare('UPDATE delivery_key_changes SET mailed_at = ? WHERE id = ?').run(nowIso(), id);
      for (const o of ownersOf(auth.did)) {
        mail(o.owner_email, `DemiPass: @${o.handle} asks to ${first ? 'set' : 'change'} its delivery key`,
          `A token of your agent @${o.handle} (fleet ${o.slug}; ${d.auth_method || 'sign-in'} from ${req.ip || '?'}) asks to ${first ? 'set' : 'change'} the key its renewed tokens are sealed to${first ? '' : ' (they go to the current key until you decide)'}: ${fp}.\n` +
          `Approve it only if you set @${o.handle} up yourself just now and its setup printed this fingerprint. Otherwise deny it and revoke the agent's tokens: a copy of one may have leaked.\n` +
          `Approve or deny it in the DemiPass app (Fleet → @${o.handle}). It waits ${KEY_CHANGE_TTL_SEC / 3600} hours.\n`);
      }
    }
    res.status(202).json({ ok: true, status: 'pending', change_id: id, did: auth.did, fingerprint: fp, first_key: first,
      next: `the fleet owner approves key ${fp} in the DemiPass app${first ? '' : '; until then renewals are sealed to the current key'}` });
  });

  // ── the owner's side ────────────────────────────────────────────────────────────────────────────────────────────
  function ownerAuth(req, res) {
    const auth = getBearerIdentity(req);
    if (!auth.ok) { res.status(auth.status || 401).json({ error: auth.error, ...(auth.code ? { code: auth.code } : {}) }); return null; }
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
    if (!gateFresh(auth.did, 'pin', auth, intent)) return res.status(403).json({ ...gateMissing('silicon-key', ['pin'], ['pin'], intent), error: `a delivery key for @${s.handle} needs your PIN` });
    const curW = db.prepare('SELECT delivery_public_key FROM identity_wallets WHERE did = ?').get(s.member_did);
    const curFp = curW && curW.delivery_public_key ? fingerprint(Buffer.from(curW.delivery_public_key, 'base64url')) : null;
    const bind = `key ${fleet.slug}/${s.handle} to ${ch.fingerprint}${curFp ? ` replaces ${curFp}` : ''}`;   // round-5 L1
    const dk = devices();
    const refused = dk ? dk.approvalRefusal(auth, 'silicon-key', s.id, bind, req.body) : null;
    if (refused) return res.status(refused.status).json(refused.body);
    // The token that asked may have been revoked since the sweep (revoke-all, a fleet cut): checked once more, now.
    const askNow = askState(ch);
    if (askNow.lookup_failed) return res.status(503).json({ error: 'token status could not be checked; try again', code: 'unavailable' });
    if (askNow.revoked) {
      db.prepare("UPDATE delivery_key_changes SET status = 'revoked', decided_at = ? WHERE id = ? AND status = 'pending'").run(nowIso(), ch.id);
      return res.status(409).json({ error: 'the token that asked for this key has been revoked since: it can no longer be approved' });
    }
    let prev = null;
    try {
      db.transaction(() => {
        const spent = spendSingleUse(auth.did, 'silicon-key', ['pin'], auth, intent);
        if (spent) throw Object.assign(new Error(spent.error), { statusCode: spent.status || 403, body: spent });
        if (db.prepare("UPDATE delivery_key_changes SET status = 'approved', decided_at = ?, decided_by = ? WHERE id = ? AND status = 'pending'").run(nowIso(), auth.did, ch.id).changes !== 1) {
          throw Object.assign(new Error('this key change changed meanwhile'), { statusCode: 409 });
        }
        const w = db.prepare('SELECT delivery_public_key FROM identity_wallets WHERE did = ?').get(s.member_did);
        prev = w && w.delivery_public_key;
        if (prev) {
          // Kept REVERT_WINDOW_SEC so the owner can undo it (round-3 review L2).
          db.prepare('UPDATE identity_wallets SET delivery_public_key = ?, delivery_key_changed_at = ?, delivery_key_previous = ?, delivery_key_previous_until = ? WHERE did = ?')
            .run(ch.public_key, nowIso(), prev, later(REVERT_WINDOW_SEC), s.member_did);
        } else {
          db.prepare('UPDATE identity_wallets SET delivery_public_key = ?, delivery_key_set_at = ?, delivery_key_changed_at = NULL, delivery_key_previous = NULL, delivery_key_previous_until = NULL WHERE did = ?')
            .run(ch.public_key, nowIso(), s.member_did);
        }
      }).immediate();
    } catch (e) { return res.status(e.statusCode || 500).json(e.body || { error: e.message }); }
    if (logSecurityEvent) logSecurityEvent(prev ? 'delivery_key_changed' : 'delivery_key_set', 'warn', { caller_did: auth.did, ip: req.ip, target: s.handle,
      context: { fleet: fleet.slug, did: s.member_did, change_id: ch.id, fingerprint: ch.fingerprint, approved: true } });
    res.json({ ok: true, handle: s.handle, fingerprint: ch.fingerprint, first_key: !prev, ...(prev ? { revert_until: later(REVERT_WINDOW_SEC) } : {}) });
  });

  app.post('/api/fleet/:slug/silicons/:handle/delivery-key/:change/deny', rateLimitStandard, (req, res) => {
    const auth = ownerAuth(req, res); if (!auth) return;
    const o = ownedSilicon(req, res, auth); if (!o) return;
    const ch = db.prepare("SELECT * FROM delivery_key_changes WHERE id = ? AND did = ? AND status = 'pending'").get(Number(req.params.change), o.s.member_did);
    if (!ch) return res.status(404).json({ error: 'no waiting key change by that id' });
    let signedOut = 0;
    db.transaction(() => {
      db.prepare("UPDATE delivery_key_changes SET status = 'denied', decided_at = ?, decided_by = ? WHERE id = ? AND status = 'pending'").run(nowIso(), auth.did, ch.id);
      signedOut = endAsker(ch);   // "deny and sign out this token": it cannot just ask again
    })();
    try { sweep(); } catch (_) {}   // asks made with the tokens just signed out end now, not at the next sweep
    if (logSecurityEvent) logSecurityEvent('delivery_key_change_denied', 'warn', { caller_did: auth.did, ip: req.ip, target: o.s.handle, context: { change_id: ch.id, fingerprint: ch.fingerprint, tokens_signed_out: signedOut } });
    res.json({ ok: true, tokens_signed_out: signedOut });
  });

  // Undo an approved change while the previous key is kept: back to it, and every token sealed to the key being
  // dropped is revoked — whoever holds that key keeps nothing it got through it.
  app.post('/api/fleet/:slug/silicons/:handle/delivery-key/revert', rateLimitStandard, (req, res) => {
    const auth = ownerAuth(req, res); if (!auth) return;
    const o = ownedSilicon(req, res, auth); if (!o) return;
    const { fleet, s } = o;
    const w = db.prepare('SELECT delivery_public_key, delivery_key_previous, delivery_key_previous_until FROM identity_wallets WHERE did = ?').get(s.member_did);
    if (!w || !w.delivery_key_previous || !w.delivery_key_previous_until || Date.parse(w.delivery_key_previous_until) <= Date.now()) {
      return res.status(409).json({ error: `no key change of @${s.handle} to undo (it can be undone for ${REVERT_WINDOW_SEC / 3600} hours after it was approved)` });
    }
    const prevFp = fingerprint(Buffer.from(w.delivery_key_previous, 'base64url')), dropFp = fingerprint(Buffer.from(w.delivery_public_key, 'base64url'));
    const intent = `silicon-key-revert:${s.id}`;
    if (!gateFresh(auth.did, 'pin', auth, intent)) return res.status(403).json({ ...gateMissing('silicon-key-revert', ['pin'], ['pin'], intent), error: `undoing @${s.handle}'s key change needs your PIN` });
    const bind = `revert key ${fleet.slug}/${s.handle} to ${prevFp}`;
    const dk = devices();
    const refused = dk ? dk.approvalRefusal(auth, 'silicon-key-revert', s.id, bind, req.body) : null;
    if (refused) return res.status(refused.status).json(refused.body);
    let revoked = 0;
    try {
      db.transaction(() => {
        const spent = spendSingleUse(auth.did, 'silicon-key-revert', ['pin'], auth, intent);
        if (spent) throw Object.assign(new Error(spent.error), { statusCode: spent.status || 403, body: spent });
        if (db.prepare('UPDATE identity_wallets SET delivery_public_key = delivery_key_previous, delivery_key_changed_at = ?, delivery_key_previous = NULL, delivery_key_previous_until = NULL WHERE did = ? AND delivery_public_key = ?')
          .run(nowIso(), s.member_did, w.delivery_public_key).changes !== 1) throw Object.assign(new Error('the key changed meanwhile'), { statusCode: 409 });
        for (const r of db.prepare('SELECT token_jti FROM token_deliveries WHERE did = ? AND key_fingerprint = ?').all(s.member_did, dropFp)) {
          revoked += db.prepare("UPDATE issued_tokens SET revoked = 1, revoked_at = datetime('now') WHERE jti = ? AND revoked = 0").run(r.token_jti).changes;
        }
        db.prepare("UPDATE token_deliveries SET acked_at = COALESCE(acked_at, ?), ack = COALESCE(ack, 'declined'), epk = '', iv = '', tag = '', ciphertext = '' WHERE did = ? AND key_fingerprint = ?").run(nowIso(), s.member_did, dropFp);
        // Whoever asked for the dropped key is signed out too, and the change is marked undone.
        const asked = db.prepare("SELECT * FROM delivery_key_changes WHERE did = ? AND public_key = ? AND status = 'approved' ORDER BY id DESC LIMIT 1").get(s.member_did, w.delivery_public_key);
        if (asked) {
          revoked += endAsker(asked);
          db.prepare("UPDATE delivery_key_changes SET status = 'reverted', decided_at = ? WHERE id = ?").run(nowIso(), asked.id);
          if (asked.request_id) {
            // The key came in a token request: the token it handed out goes too, and the request is marked undone.
            if (asked.claimed_jti) revoked += db.prepare("UPDATE issued_tokens SET revoked = 1, revoked_at = datetime('now') WHERE jti = ? AND revoked = 0").run(asked.claimed_jti).changes;
            try { db.prepare("UPDATE silicon_token_requests SET status = 'undone' WHERE id = ?").run(asked.request_id); } catch (_) {}
          }
        }
      }).immediate();
    } catch (e) { return res.status(e.statusCode || 500).json(e.body || { error: e.message }); }
    try { sweep(); } catch (_) {}   // e.g. an ask made with a token the dropped key received: ended now
    if (logSecurityEvent) logSecurityEvent('delivery_key_reverted', 'warn', { caller_did: auth.did, ip: req.ip, target: s.handle, context: { fleet: fleet.slug, did: s.member_did, to: prevFp, dropped: dropFp, tokens_revoked: revoked } });
    res.json({ ok: true, handle: s.handle, fingerprint: prevFp, tokens_revoked: revoked });
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
      const waiting = db.prepare("SELECT fingerprint FROM delivery_key_changes WHERE did = ? AND status = 'pending' AND expires_at > ? ORDER BY id DESC LIMIT 1").get(s.member_did, nowIso());
      return res.status(409).json({ no_delivery_key: true, ...(waiting ? { key_waiting: waiting.fingerprint } : {}),
        error: waiting
          ? `@${s.handle} has no approved delivery key yet: key ${waiting.fingerprint} is waiting for you on @${s.handle}'s page. Approve it (if it is the one its setup printed), then renew.`
          : `@${s.handle} has no delivery key, so a renewed token could reach nobody but you. On the agent, run "node bin/token-pickup.js --init <dir>" with its own token, then approve the key on @${s.handle}'s page and renew. If its token has already lapsed: ${OWN_TOKEN_HOWTO}` });
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
        // The key the phone signed for must still be the key (an undo or an approval may have landed meanwhile).
        const now = db.prepare('SELECT delivery_public_key FROM identity_wallets WHERE did = ?').get(wallet.did);
        if (!now || now.delivery_public_key !== wallet.delivery_public_key) throw Object.assign(new Error(`@${s.handle}'s delivery key changed meanwhile: renew again`), { statusCode: 409 });
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
    { const dead = billing ? billing.checkTokenRevocation(db, v.decoded) : { revoked: false }; if (dead.revoked) return res.status(billing.revokedStatus(dead)).json({ error: dead.lookup_failed ? dead.reason : 'token revoked', ...billing.revokedCode(dead) }); }
    const used = (req.body || {}).used !== false;
    if (!acknowledge(v.decoded.jti, v.decoded.sub, used)) return res.status(404).json({ error: 'no delivery waiting for this token' });
    res.json({ ok: true, ack: used ? 'used' : 'declined' });
  });

  // A key that travelled inside an agent token request the owner approved (its fingerprint was on the phone), set when
  // the request is claimed (silicon_token_requests.js). A different key replaces the current one like an approved
  // change (the previous kept REVERT_WINDOW_SEC); a waiting ask it overtakes is ended loudly: logged, owner mailed.
  function setKeyFromRequest(did, b64, { requestId, ownerDid, ip, claimedJti, filer } = {}) {
    const raw = parseDeliveryKey(b64);
    if (!raw) return { ok: false, error: 'the request\'s delivery key is not a usable X25519 key' };
    const fp = fingerprint(raw);
    let superseded = [], prev = null;
    db.transaction(() => {
      const w = db.prepare('SELECT delivery_public_key FROM identity_wallets WHERE did = ?').get(did);
      prev = w && w.delivery_public_key;
      if (prev === b64) return;
      if (prev) db.prepare('UPDATE identity_wallets SET delivery_public_key = ?, delivery_key_changed_at = ?, delivery_key_previous = ?, delivery_key_previous_until = ? WHERE did = ?').run(b64, nowIso(), prev, later(REVERT_WINDOW_SEC), did);
      else db.prepare('UPDATE identity_wallets SET delivery_public_key = ?, delivery_key_set_at = ?, delivery_key_changed_at = NULL WHERE did = ?').run(b64, nowIso(), did);
      superseded = db.prepare("SELECT * FROM delivery_key_changes WHERE did = ? AND status = 'pending'").all(did);
      db.prepare("UPDATE delivery_key_changes SET status = 'superseded', decided_at = ? WHERE did = ? AND status = 'pending'").run(nowIso(), did);
      // Recorded as an approved change (the owner approved the request with this fingerprint): an undo finds it.
      const f = filer || {};
      db.prepare(`INSERT INTO delivery_key_changes (did, public_key, fingerprint, status, auth_method, ip, requested_at, expires_at, decided_at, decided_by,
                    ask_jti, ask_iat, ask_fleet, ask_sid, first_key, request_id, claimed_jti, asker_did) VALUES (?, ?, ?, 'approved', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
        .run(did, b64, fp, String(f.auth_method || ''), String(ip || ''), nowIso(), nowIso(), nowIso(), ownerDid || null, String(f.jti || ''), Number(f.iat || 0),
          String(f.fleet || ''), String(f.sid || ''), prev ? 0 : 1, requestId || null, String(claimedJti || ''), String(f.did || ''));
    })();
    if (prev === b64) return { ok: true, fingerprint: fp, unchanged: true };
    if (logSecurityEvent) logSecurityEvent(prev ? 'delivery_key_changed' : 'delivery_key_set', 'warn', { caller_did: ownerDid || null, ip, target: did,
      context: { via: 'token_request', request_id: requestId || null, fingerprint: fp, superseded: superseded.map(c => ({ id: c.id, fingerprint: c.fingerprint })) } });
    if (superseded.length || prev) {
      for (const o of ownersOf(did)) {
        mail(o.owner_email, `DemiPass: @${o.handle}'s delivery key was set by token request #${requestId}`,
          `The agent token request #${requestId} you approved for @${o.handle} (fleet ${o.slug}) carried delivery key ${fp}; it was claimed and that key is now set.` +
          (superseded.length ? `\nIt replaced ${superseded.length === 1 ? 'a waiting key ask' : superseded.length + ' waiting key asks'} (${superseded.map(c => c.fingerprint).join(', ')}).` : '') +
          (prev ? `\nYou can undo it for ${REVERT_WINDOW_SEC / 3600} hours on @${o.handle}'s page.` : '') + `\nIf you did not expect this, undo it and revoke @${o.handle}'s tokens.\n`);
      }
    }
    return { ok: true, fingerprint: fp, replaced: Boolean(prev), superseded: superseded.length };
  }

  return { sweep, noteUse, shownInClear, setKeyFromRequest, parseDeliveryKey, fingerprint, ALG, INFO_PREFIX, REVERT_WINDOW_SEC };
};
module.exports.ALG = ALG;
module.exports.INFO_PREFIX = INFO_PREFIX;
module.exports.shownInClear = shownInClear;
module.exports.OWN_TOKEN_HOWTO = OWN_TOKEN_HOWTO;
module.exports.parseDeliveryKey = parseDeliveryKey;
