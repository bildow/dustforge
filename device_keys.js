'use strict';
// ── Device keys, dormancy lock, biometric PIN-equivalent (red team items 4b and 8, one feature) ─────────────────────
// Build spec: tome decisions/2026-11-05-THREAT-MODEL-demipass-red-team-v0.1.md § "Build spec v1".
//
// An enrolled phone holds two non-exportable Keystore keys (P-256):
//   D  device key   — no user authentication. Proves *this phone*: every approval carries D's signature once the owner
//                     has a device enrolled, so a session token copied off the phone (or an agent's device login)
//                     approves nothing.
//   P  presence key — user authentication on every use (biometric or device credential). Its signature over a gate
//                     challenge is a PIN-equivalent: it mints the same single-use PIN proof the PIN does, so every
//                     PIN prompt accepts biometric with no change to the route behind it.
// Challenges are one-use, 60 s, bound to (wallet, session, purpose, intent); what is signed is a plain text line, so the
// phone can show the owner what it signs.
//
// Dormancy: the wallet's lock_after_sec (default 300, 60–3600; raising it takes the PIN). An unlock (PIN or P) is kept
// per session with the time of last activity; while it is fresh, an elevated approval opens without another PIN.

const crypto = require('crypto');

const CHALLENGE_TTL_SEC = 60;
const MAX_DEVICES = 3;
const LOCK_DEFAULT = 300, LOCK_MIN = 60, LOCK_MAX = 3600;
const PURPOSES = new Set(['enrol', 'gate', 'approve']);

module.exports = function registerDeviceKeys(deps) {
  const { app, db, rateLimitStandard, getBearerIdentity, gateSession, gateFresh, gateMissing, spendSingleUse,
          logSecurityEvent, cleanLabel, sendMail, recordGate, pinIntentOk } = deps;

  db.exec(`CREATE TABLE IF NOT EXISTS device_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    did TEXT NOT NULL,
    device_id TEXT NOT NULL,
    kind TEXT NOT NULL CHECK(kind IN ('D', 'P')),
    public_key TEXT NOT NULL,
    label TEXT DEFAULT '',
    enrolled_at TEXT NOT NULL,
    last_used_at TEXT,
    revoked_at TEXT,
    UNIQUE(device_id, kind)
  )`);
  db.exec(`CREATE TABLE IF NOT EXISTS device_challenges (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    did TEXT NOT NULL,
    session TEXT NOT NULL,
    purpose TEXT NOT NULL,
    intent TEXT NOT NULL,
    nonce TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used_at TEXT
  )`);
  db.exec(`CREATE TABLE IF NOT EXISTS session_unlocks (
    session TEXT PRIMARY KEY,
    did TEXT NOT NULL,
    unlocked_at TEXT NOT NULL,
    last_active_at TEXT NOT NULL,
    via TEXT NOT NULL
  )`);
  try { db.exec(`ALTER TABLE identity_wallets ADD COLUMN lock_after_sec INTEGER DEFAULT ${LOCK_DEFAULT}`); } catch (_) {}

  const nowIso = () => new Date().toISOString();
  const isAgent = (auth) => !auth || !auth.ok || auth.silicon || (auth.decoded && (auth.decoded.wrk || auth.decoded.auth_method === 'fleet_owner_mint'));

  function personAuth(req, res) {
    const auth = getBearerIdentity(req);
    if (!auth.ok) { res.status(auth.status || 401).json({ error: auth.error }); return null; }
    if (isAgent(auth)) { res.status(403).json({ error: 'device keys belong to the owner\'s phone, not to an agent token' }); return null; }
    if (!gateSession(auth)) { res.status(403).json({ error: 'sign in again' }); return null; }
    return auth;
  }

  // ── keys and signatures ────────────────────────────────────────────────────────────────────────────────────────
  function parsePublicKey(b64) {
    if (typeof b64 !== 'string' || b64.length > 400) return null;
    try {
      const k = crypto.createPublicKey({ key: Buffer.from(b64, 'base64'), format: 'der', type: 'spki' });
      if (k.asymmetricKeyType !== 'ec' || (k.asymmetricKeyDetails && k.asymmetricKeyDetails.namedCurve !== 'prime256v1')) return null;
      return k;
    } catch (_) { return null; }
  }
  function verifySig(publicKeyB64, message, sigB64) {
    const k = parsePublicKey(publicKeyB64);
    if (!k || typeof sigB64 !== 'string' || sigB64.length > 200) return false;
    try { return crypto.verify('sha256', Buffer.from(message, 'utf8'), k, Buffer.from(sigB64, 'base64')); } catch (_) { return false; }
  }
  const activeKeys = (did, kind) => db.prepare('SELECT * FROM device_keys WHERE did = ? AND kind = ? AND revoked_at IS NULL').all(did, kind);
  const hasDevice = (did) => activeKeys(did, 'D').length > 0;

  // The text a key signs. Plain and readable on purpose: the phone shows it.
  function messageFor(ch, extra = '') {
    return `demipass:${ch.purpose}:${ch.did}:${ch.session}:${ch.intent}:${ch.nonce}${extra ? ':' + extra : ''}`;
  }
  function newChallenge(did, session, purpose, intent) {
    const nonce = crypto.randomBytes(24).toString('base64url');
    const created = nowIso(), expires = new Date(Date.now() + CHALLENGE_TTL_SEC * 1000).toISOString();
    db.prepare("DELETE FROM device_challenges WHERE expires_at < ?").run(new Date(Date.now() - 3600 * 1000).toISOString());
    const id = Number(db.prepare('INSERT INTO device_challenges (did, session, purpose, intent, nonce, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)')
      .run(did, session, purpose, intent, nonce, created, expires).lastInsertRowid);
    return { id, did, session, purpose, intent, nonce, expires_at: expires };
  }
  // Take a challenge for this wallet/session/purpose/intent and mark it used — whatever the signature turns out to be,
  // a challenge is tried once. Returns the row or null.
  function takeChallenge(did, session, id, purpose, intent) {
    const ch = db.prepare('SELECT * FROM device_challenges WHERE id = ?').get(Number(id) || 0);
    if (!ch || ch.did !== did || ch.session !== session || ch.purpose !== purpose || ch.intent !== intent) return null;
    if (ch.used_at || Date.parse(ch.expires_at) < Date.now()) return null;
    if (db.prepare('UPDATE device_challenges SET used_at = ? WHERE id = ? AND used_at IS NULL').run(nowIso(), ch.id).changes !== 1) return null;
    return ch;
  }
  // Which active key of `kind` signed `message`? Returns the key row or null; marks it used.
  function signer(did, kind, message, sigB64) {
    for (const k of activeKeys(did, kind)) {
      if (verifySig(k.public_key, message, sigB64)) {
        db.prepare('UPDATE device_keys SET last_used_at = ? WHERE id = ?').run(nowIso(), k.id);
        return k;
      }
    }
    return null;
  }

  // ── approvals bound to the device (item 4b) ────────────────────────────────────────────────────────────────────
  // Called by every approve route. Once the owner has a device enrolled, the call must carry D's signature over the
  // approval challenge for this exact decision; before that the old session rule stands (migration), and the answer
  // says so. `bind` is what the decision is about (the request's binding hash, a fill's origin…). Returns null when
  // the approval may proceed, else { status, body }.
  function approvalRefusal(auth, kind, id, bind, body) {
    if (!hasDevice(auth.did)) return null;
    const intent = `${kind}:${id}`;
    const b = body || {};
    if (!b.device_challenge_id || !b.device_signature) {
      return { status: 428, body: { error: 'approve from your enrolled phone: this approval needs its device signature', device_required: true, challenge: { purpose: 'approve', intent } } };
    }
    const ch = takeChallenge(auth.did, gateSession(auth), b.device_challenge_id, 'approve', intent);
    if (!ch) return { status: 403, body: { error: 'device challenge missing, used, expired or for another approval — ask for a new one' } };
    const k = signer(auth.did, 'D', messageFor(ch, String(bind || '')), b.device_signature);
    if (!k) {
      logSecurityEvent('device_signature_refused', 'critical', { caller_did: auth.did, capability: 'approve', target: intent, context: { kind } });
      return { status: 403, body: { error: 'this approval is not signed by an enrolled device of yours' } };
    }
    return null;
  }

  // ── unlock state (dormancy) ────────────────────────────────────────────────────────────────────────────────────
  function lockAfter(did) {
    const w = db.prepare('SELECT lock_after_sec FROM identity_wallets WHERE did = ?').get(did);
    const v = Number(w && w.lock_after_sec);
    return v >= LOCK_MIN && v <= LOCK_MAX ? v : LOCK_DEFAULT;
  }
  function markUnlocked(did, session, via) {
    const t = nowIso();
    db.prepare(`INSERT INTO session_unlocks (session, did, unlocked_at, last_active_at, via) VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(session) DO UPDATE SET did = excluded.did, unlocked_at = excluded.unlocked_at, last_active_at = excluded.last_active_at, via = excluded.via`)
      .run(session, did, t, t, via);
  }
  // Fresh: unlocked in this session and active within the owner's lock time.
  function unlockFresh(auth) {
    if (isAgent(auth)) return false;
    const session = gateSession(auth);
    if (!session) return false;
    const row = db.prepare('SELECT * FROM session_unlocks WHERE session = ? AND did = ?').get(session, auth.did);
    if (!row) return false;
    return Date.now() - Date.parse(row.last_active_at) <= lockAfter(auth.did) * 1000;
  }

  // ── gate/verify {gate:'device'} — the biometric PIN-equivalent ─────────────────────────────────────────────────
  // P's signature over a 'gate' challenge for `intent` records a PIN proof for that intent in this session (same
  // single-use, same lifetime, same PIN generation as one the PIN made). intent unlock:0 also unlocks the session.
  function verifyDeviceGate(req, res, auth) {
    if (isAgent(auth)) return res.status(403).json({ error: 'agents have no device key' });
    const { challenge_id, signature, intent } = req.body || {};
    if (typeof intent !== 'string' || !pinIntentOk(intent)) return res.status(400).json({ error: 'intent required (as named in the 403 that asked for it)' });
    const session = gateSession(auth);
    if (!session) return res.status(403).json({ error: 'sign in again' });
    const w = db.prepare('SELECT pin_hash, pin_set_at, pin_locked_until FROM identity_wallets WHERE did = ?').get(auth.did);
    if (!w || !w.pin_hash) return res.status(409).json({ error: 'set a PIN first — biometric stands in for it, it does not replace it', pin_set: false });
    if (w.pin_locked_until && Date.parse(w.pin_locked_until) > Date.now()) return res.status(429).json({ error: 'the PIN is locked; biometric does not open a locked PIN' });
    const ch = takeChallenge(auth.did, session, challenge_id, 'gate', intent);
    if (!ch) return res.status(403).json({ error: 'device challenge missing, used, expired or for another intent' });
    const k = signer(auth.did, 'P', messageFor(ch), signature);
    if (!k) {
      logSecurityEvent('device_signature_refused', 'alert', { caller_did: auth.did, capability: 'gate', target: intent, ip: req.ip });
      return res.status(403).json({ error: 'not signed by an enrolled device of yours' });
    }
    if (!recordGate(auth.did, 'pin', session, intent, w.pin_set_at, null)) return res.status(503).json({ error: 'could not record the verification; try again', retry: true });
    if (intent === 'unlock:0') markUnlocked(auth.did, session, 'device');
    return res.json({ ok: true, gate: 'device', single_use: true, intent, via: 'biometric' });
  }

  // ── routes ─────────────────────────────────────────────────────────────────────────────────────────────────────
  // POST /api/identity/device/challenge {purpose: 'enrol'|'gate'|'approve', intent}
  app.post('/api/identity/device/challenge', rateLimitStandard, (req, res) => {
    const auth = personAuth(req, res); if (!auth) return;
    const { purpose, intent } = req.body || {};
    if (!PURPOSES.has(purpose)) return res.status(400).json({ error: "purpose: 'enrol', 'gate' or 'approve'" });
    if (typeof intent !== 'string' || intent.length > 80 || !/^[a-z-]+:[0-9]{1,12}$/.test(intent)) return res.status(400).json({ error: 'intent: <action>:<id>' });
    if (purpose === 'gate' && !pinIntentOk(intent)) return res.status(400).json({ error: 'not a PIN intent' });
    if (purpose === 'enrol' && intent !== 'device-enrol:0') return res.status(400).json({ error: 'enrol intent is device-enrol:0' });
    const ch = newChallenge(auth.did, gateSession(auth), purpose, intent);
    res.json({ ok: true, challenge_id: ch.id, message: messageFor(ch), expires_at: ch.expires_at,
      ...(purpose === 'approve' ? { note: 'sign message + ":" + the decision\'s binding with the device key (D)' } : {}) });
  });

  // POST /api/identity/device/enrol {challenge_id, device_id, label, key_d, key_p, sig_d, sig_p} — PIN (device-enrol:0)
  app.post('/api/identity/device/enrol', rateLimitStandard, (req, res) => {
    const auth = personAuth(req, res); if (!auth) return;
    const { challenge_id, device_id, label, key_d, key_p, sig_d, sig_p } = req.body || {};
    if (typeof device_id !== 'string' || !/^[A-Za-z0-9_-]{8,64}$/.test(device_id)) return res.status(400).json({ error: 'device_id: 8–64 of A-Z a-z 0-9 _ -' });
    if (!parsePublicKey(key_d) || !parsePublicKey(key_p) || key_d === key_p) return res.status(400).json({ error: 'key_d and key_p: two different P-256 public keys (SPKI, base64)' });
    const intent = 'device-enrol:0';
    if (!gateFresh(auth.did, 'pin', auth, intent)) return res.status(403).json(gateMissing('device-enrol', ['pin'], ['pin'], intent));
    const live = db.prepare('SELECT COUNT(DISTINCT device_id) AS n FROM device_keys WHERE did = ? AND revoked_at IS NULL').get(auth.did).n;
    const existing = db.prepare('SELECT did FROM device_keys WHERE device_id = ? LIMIT 1').get(device_id);
    if (existing && existing.did !== auth.did) return res.status(409).json({ error: 'that device id is taken' });
    if (!existing && live >= MAX_DEVICES) return res.status(409).json({ error: `at most ${MAX_DEVICES} devices — remove one first` });
    const ch = takeChallenge(auth.did, gateSession(auth), challenge_id, 'enrol', intent);
    if (!ch) return res.status(403).json({ error: 'enrol challenge missing, used or expired' });
    const msg = messageFor(ch, device_id);
    if (!verifySig(key_d, msg, sig_d) || !verifySig(key_p, msg, sig_p)) return res.status(403).json({ error: 'each key must sign the enrol challenge (message + ":" + device_id)' });
    const refused = spendSingleUse(auth.did, 'device-enrol', ['pin'], auth, intent);
    if (refused) return res.status(refused.status || 403).json(refused);
    const t = nowIso(), lbl = cleanLabel(label || 'phone', 60);
    db.transaction(() => {
      db.prepare('UPDATE device_keys SET revoked_at = ? WHERE device_id = ? AND revoked_at IS NULL').run(t, device_id);   // re-enrol replaces
      db.prepare('DELETE FROM device_keys WHERE device_id = ?').run(device_id);
      const ins = db.prepare('INSERT INTO device_keys (did, device_id, kind, public_key, label, enrolled_at) VALUES (?, ?, ?, ?, ?, ?)');
      ins.run(auth.did, device_id, 'D', key_d, lbl, t); ins.run(auth.did, device_id, 'P', key_p, lbl, t);
    })();
    logSecurityEvent('device_enrolled', 'warn', { caller_did: auth.did, capability: 'device', target: lbl, ip: req.ip, context: { device_id } });
    notifyOwner(auth.did, `A device was added to your DemiPass wallet: ${lbl}`);
    res.status(201).json({ ok: true, device_id, label: lbl, note: 'approvals now need this phone (or another enrolled one)' });
  });

  // GET /api/identity/devices
  app.get('/api/identity/devices', rateLimitStandard, (req, res) => {
    const auth = getBearerIdentity(req); if (!auth.ok) return res.status(auth.status || 401).json({ error: auth.error });
    const rows = db.prepare("SELECT device_id, label, MIN(enrolled_at) AS enrolled_at, MAX(last_used_at) AS last_used_at FROM device_keys WHERE did = ? AND revoked_at IS NULL GROUP BY device_id, label ORDER BY enrolled_at").all(auth.did);
    res.json({ ok: true, devices: rows, lock_after_sec: lockAfter(auth.did), approvals_need_device: rows.length > 0 });
  });

  // DELETE /api/identity/devices/:device_id — PIN (device-revoke:0). Refused for agent tokens.
  app.delete('/api/identity/devices/:device_id', rateLimitStandard, (req, res) => {
    const auth = personAuth(req, res); if (!auth) return;
    const intent = 'device-revoke:0';
    if (!gateFresh(auth.did, 'pin', auth, intent)) return res.status(403).json(gateMissing('device-revoke', ['pin'], ['pin'], intent));
    const refused = spendSingleUse(auth.did, 'device-revoke', ['pin'], auth, intent);
    if (refused) return res.status(refused.status || 403).json(refused);
    const n = db.prepare('UPDATE device_keys SET revoked_at = ? WHERE did = ? AND device_id = ? AND revoked_at IS NULL').run(nowIso(), auth.did, String(req.params.device_id)).changes;
    if (!n) return res.status(404).json({ error: 'device not found' });
    logSecurityEvent('device_revoked', 'warn', { caller_did: auth.did, capability: 'device', target: String(req.params.device_id), ip: req.ip });
    notifyOwner(auth.did, 'A device was removed from your DemiPass wallet.');
    res.json({ ok: true, revoked: true });
  });

  // GET/PUT /api/identity/lock — the dormancy setting. Shortening is free; lengthening takes the PIN (lock-setting:0).
  app.get('/api/identity/lock', rateLimitStandard, (req, res) => {
    const auth = getBearerIdentity(req); if (!auth.ok) return res.status(auth.status || 401).json({ error: auth.error });
    res.json({ ok: true, lock_after_sec: lockAfter(auth.did), min: LOCK_MIN, max: LOCK_MAX, unlocked: unlockFresh(auth) });
  });
  app.put('/api/identity/lock', rateLimitStandard, (req, res) => {
    const auth = personAuth(req, res); if (!auth) return;
    const v = Number((req.body || {}).lock_after_sec);
    if (!Number.isInteger(v) || v < LOCK_MIN || v > LOCK_MAX) return res.status(400).json({ error: `lock_after_sec: ${LOCK_MIN}–${LOCK_MAX}` });
    if (v > lockAfter(auth.did)) {
      const intent = 'lock-setting:0';
      if (!gateFresh(auth.did, 'pin', auth, intent)) return res.status(403).json(gateMissing('lock-setting', ['pin'], ['pin'], intent));
      const refused = spendSingleUse(auth.did, 'lock-setting', ['pin'], auth, intent);
      if (refused) return res.status(refused.status || 403).json(refused);
    }
    db.prepare('UPDATE identity_wallets SET lock_after_sec = ? WHERE did = ?').run(v, auth.did);
    res.json({ ok: true, lock_after_sec: v });
  });
  // POST /api/identity/lock/ping — the app reports activity; keeps a fresh unlock fresh. Never revives a stale one.
  app.post('/api/identity/lock/ping', rateLimitStandard, (req, res) => {
    const auth = personAuth(req, res); if (!auth) return;
    const fresh = unlockFresh(auth);
    if (fresh) db.prepare('UPDATE session_unlocks SET last_active_at = ? WHERE session = ?').run(nowIso(), gateSession(auth));
    res.json({ ok: true, unlocked: fresh, lock_after_sec: lockAfter(auth.did) });
  });
  // POST /api/identity/lock/now — lock this session at once (the app's lock button, or idle timeout).
  app.post('/api/identity/lock/now', rateLimitStandard, (req, res) => {
    const auth = getBearerIdentity(req); if (!auth.ok) return res.status(auth.status || 401).json({ error: auth.error });
    db.prepare('DELETE FROM session_unlocks WHERE session = ?').run(gateSession(auth) || '');
    res.json({ ok: true, unlocked: false });
  });

  function notifyOwner(did, text) {
    try {
      const w = db.prepare('SELECT email FROM identity_wallets WHERE did = ?').get(did);
      if (w && w.email && sendMail) Promise.resolve(sendMail({ to: w.email, subject: 'DemiPass: device change', text: text + '\n\nIf this was not you, remove it in the DemiPass app and change your PIN.\n' })).catch(() => {});
    } catch (_) {}
  }

  return { approvalRefusal, unlockFresh, markUnlocked, verifyDeviceGate, hasDevice, lockAfter, messageFor,
           LOCK_DEFAULT, LOCK_MIN, LOCK_MAX };
};
