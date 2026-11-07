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
    bind TEXT NOT NULL DEFAULT '',
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
  // When an unlock stops being fresh, fixed when it was made or pinged: lengthening the lock time later never revives
  // a stale unlock (#47 review L2).
  try { db.exec('ALTER TABLE session_unlocks ADD COLUMN fresh_until TEXT'); } catch (_) {}
  // A biometric (presence key) made in this session for an intent — what removing a phone can rest on besides the
  // password. Kept 120 s, one use.
  db.exec(`CREATE TABLE IF NOT EXISTS device_gate_proofs (id INTEGER PRIMARY KEY AUTOINCREMENT, did TEXT NOT NULL, session TEXT NOT NULL,
    intent TEXT NOT NULL, at TEXT NOT NULL, used INTEGER NOT NULL DEFAULT 0)`);
  try { db.exec(`ALTER TABLE identity_wallets ADD COLUMN lock_after_sec INTEGER DEFAULT ${LOCK_DEFAULT}`); } catch (_) {}
  // Item 9: how a phone was removed ('device' = with a phone's presence signature: no grace for cancels; 'password';
  // or the reset that removed every phone), and which phone made a biometric proof (a young phone removes nothing).
  try { db.exec('ALTER TABLE device_keys ADD COLUMN revoked_via TEXT'); } catch (_) {}
  try { db.exec('ALTER TABLE device_gate_proofs ADD COLUMN device_id TEXT'); } catch (_) {}
  const holds = () => deps.holds && deps.holds();

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

  // The text a key signs. Plain and readable on purpose: the phone shows it. For an approval it ends with what is being
  // decided (the request's binding, a fill's origin, a share's recipient…), named when the challenge was asked for.
  function messageFor(ch, extra = '') {
    const tail = [ch.bind || '', extra || ''].filter(Boolean).join(':');
    return `demipass:${ch.purpose}:${ch.did}:${ch.session}:${ch.intent}:${ch.nonce}${tail ? ':' + tail : ''}`;
  }
  function newChallenge(did, session, purpose, intent, bind = '') {
    const nonce = crypto.randomBytes(24).toString('base64url');
    const created = nowIso(), expires = new Date(Date.now() + CHALLENGE_TTL_SEC * 1000).toISOString();
    db.prepare("DELETE FROM device_challenges WHERE expires_at < ?").run(new Date(Date.now() - 3600 * 1000).toISOString());
    const id = Number(db.prepare('INSERT INTO device_challenges (did, session, purpose, intent, bind, nonce, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
      .run(did, session, purpose, intent, bind, nonce, created, expires).lastInsertRowid);
    return { id, did, session, purpose, intent, bind, nonce, expires_at: expires };
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
    // The device key signs without a prompt: the phone must be unlocked (PIN or biometric within the lock time) for its
    // signature to count — a locked phone approves nothing (#47 review H2). Checked before any challenge is spent.
    if (!unlockFresh(auth)) return { status: 423, body: { error: 'unlock DemiPass on your phone first', locked: true } };
    if (!b.device_challenge_id || !b.device_signature) {
      return { status: 428, body: { error: 'approve from your enrolled phone: this approval needs its device signature', device_required: true, challenge: { purpose: 'approve', intent, bind: String(bind || '') } } };
    }
    const ch = takeChallenge(auth.did, gateSession(auth), b.device_challenge_id, 'approve', intent);
    if (!ch) return { status: 403, body: { error: 'device challenge missing, used, expired or for another approval — ask for a new one' } };
    // The challenge named what the phone was shown; it must be what is actually being decided.
    if (String(ch.bind || '') !== String(bind || '')) return { status: 409, body: { error: 'the signed approval was for something else than this decision — ask for a new challenge', expected_bind: String(bind || '') } };
    const k = signer(auth.did, 'D', messageFor(ch), b.device_signature);
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
    const t = nowIso(), until = new Date(Date.now() + lockAfter(did) * 1000).toISOString();
    db.prepare(`INSERT INTO session_unlocks (session, did, unlocked_at, last_active_at, via, fresh_until) VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(session) DO UPDATE SET did = excluded.did, unlocked_at = excluded.unlocked_at, last_active_at = excluded.last_active_at, via = excluded.via, fresh_until = excluded.fresh_until`)
      .run(session, did, t, t, via, until);
  }
  // Fresh: unlocked in this session, and still inside the window fixed at the last unlock or activity ping.
  function unlockFresh(auth) {
    if (isAgent(auth)) return false;
    const session = gateSession(auth);
    if (!session) return false;
    const row = db.prepare('SELECT * FROM session_unlocks WHERE session = ? AND did = ?').get(session, auth.did);
    if (!row) return false;
    const until = Date.parse(row.fresh_until || '') || (Date.parse(row.last_active_at) + lockAfter(auth.did) * 1000);
    return Date.now() <= until && Date.now() - Date.parse(row.last_active_at) <= lockAfter(auth.did) * 1000;
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
    db.prepare('INSERT INTO device_gate_proofs (did, session, intent, at, device_id) VALUES (?, ?, ?, ?, ?)').run(auth.did, session, intent, nowIso(), k.device_id);
    if (intent === 'unlock:0') markUnlocked(auth.did, session, 'device');
    return res.json({ ok: true, gate: 'device', single_use: true, intent, via: 'biometric' });
  }

  // ── routes ─────────────────────────────────────────────────────────────────────────────────────────────────────
  // POST /api/identity/device/challenge {purpose: 'enrol'|'gate'|'approve', intent}
  app.post('/api/identity/device/challenge', rateLimitStandard, (req, res) => {
    const auth = personAuth(req, res); if (!auth) return;
    const { purpose, intent } = req.body || {};
    const bind = String((req.body || {}).bind ?? '');
    if (bind.length > 300 || /[\u0000-\u001f]/.test(bind)) return res.status(400).json({ error: 'bind: up to 300 printable characters' });
    if (!PURPOSES.has(purpose)) return res.status(400).json({ error: "purpose: 'enrol', 'gate' or 'approve'" });
    if (typeof intent !== 'string' || intent.length > 80 || !/^[a-z-]+:[0-9]{1,12}$/.test(intent)) return res.status(400).json({ error: 'intent: <action>:<id>' });
    if (purpose === 'gate' && !pinIntentOk(intent)) return res.status(400).json({ error: 'not a PIN intent' });
    if (purpose === 'enrol' && intent !== 'device-enrol:0') return res.status(400).json({ error: 'enrol intent is device-enrol:0' });
    const ch = newChallenge(auth.did, gateSession(auth), purpose, intent, purpose === 'approve' ? bind : '');
    res.json({ ok: true, challenge_id: ch.id, message: messageFor(ch), expires_at: ch.expires_at,
      sign_with: purpose === 'gate' ? 'P' : purpose === 'approve' ? 'D' : 'D and P' });
  });

  // POST /api/identity/device/enrol {challenge_id, device_id, label, key_d, key_p, sig_d, sig_p} — PIN (device-enrol:0)
  app.post('/api/identity/device/enrol', rateLimitStandard, (req, res) => {
    const auth = personAuth(req, res); if (!auth) return;
    const { challenge_id, device_id, label, key_d, key_p, sig_d, sig_p } = req.body || {};
    // The PIN and a second factor: knowing the PIN once must not plant a device (#47 review H1). The second factor is the
    // account password OR an emailed code (to the wallet's own mailbox, which only the password opens), so an owner who
    // never types a vault value links a phone from the phone alone. Each stays fresh 5 minutes in this session.
    const intent = 'device-enrol:0';
    // A mail-forwarding rule that became active in the last 48 hours may have carried the code to someone else (a
    // session token alone can make one): then only the password counts (#63 review H1). Active or not — removing the
    // rule after the code went out must not clear it (#63 re-review H1).
    let newRelay = false;
    try { newRelay = !!db.prepare("SELECT 1 FROM forward_relays WHERE did = ? AND julianday(COALESCE(activated_at, created_at)) > julianday('now', '-2 days') LIMIT 1").get(auth.did); } catch (_) {}
    const secondOk = gateFresh(auth.did, 'password', auth) || (!newRelay && gateFresh(auth.did, 'twofa', auth));
    const second = newRelay ? 'password' : 'twofa';
    const missing = [...(secondOk ? [] : [second]), ...(gateFresh(auth.did, 'pin', auth, intent) ? [] : ['pin'])];
    if (missing.length) return res.status(403).json({ ...gateMissing('device-enrol', [second, 'pin'], missing, intent),
      ...(newRelay ? { note: 'a mail-forwarding rule was made or turned on in the last 48 hours, so an emailed code does not count: the account password, then the PIN' }
                   : { or: { twofa: 'password' }, note: 'an emailed code (or the account password), then the PIN' }) });
    // {check:true}: the factors are fresh and nothing in the way — the app makes its keys and links within the PIN's
    // minute. Nothing is spent.
    if ((req.body || {}).check === true) {
      const n = db.prepare('SELECT COUNT(DISTINCT device_id) AS n FROM device_keys WHERE did = ? AND revoked_at IS NULL').get(auth.did).n;
      if (n >= MAX_DEVICES) return res.status(409).json({ error: `at most ${MAX_DEVICES} devices — remove one first` });
      const Hc = holds();
      if (Hc && hasDevice(auth.did)) { const stop = Hc.startRefusal(auth.did, 'enrol'); if (stop) return res.status(stop.status).json(stop.body); }
      return res.json({ ok: true, ready: true });
    }
    if (typeof device_id !== 'string' || !/^[A-Za-z0-9_-]{8,64}$/.test(device_id)) return res.status(400).json({ error: 'device_id: 8–64 of A-Z a-z 0-9 _ -' });
    if (!parsePublicKey(key_d) || !parsePublicKey(key_p) || key_d === key_p) return res.status(400).json({ error: 'key_d and key_p: two different P-256 public keys (SPKI, base64)' });
    const live = db.prepare('SELECT COUNT(DISTINCT device_id) AS n FROM device_keys WHERE did = ? AND revoked_at IS NULL').get(auth.did).n;
    if (db.prepare('SELECT 1 FROM device_keys WHERE device_id = ? LIMIT 1').get(device_id)) return res.status(409).json({ error: 'that device id is already known — the app makes a new one for each link' });
    if (live >= MAX_DEVICES) return res.status(409).json({ error: `at most ${MAX_DEVICES} devices — remove one first` });
    const ch = takeChallenge(auth.did, gateSession(auth), challenge_id, 'enrol', intent);
    if (!ch) return res.status(403).json({ error: 'enrol challenge missing, used or expired' });
    const msg = messageFor(ch, device_id);
    if (!verifySig(key_d, msg, sig_d) || !verifySig(key_p, msg, sig_p)) return res.status(403).json({ error: 'each key must sign the enrol challenge (message + ":" + device_id)' });
    const H = holds();
    const pendingSame = H && H.openHolds(auth.did, 'enrol').some(h => { try { return JSON.parse(h.payload).device_id === device_id; } catch (_) { return false; } });
    if (pendingSame) return res.status(409).json({ error: 'that phone is already waiting to be linked' });
    const refused = spendSingleUse(auth.did, 'device-enrol', ['pin'], auth, intent);
    if (refused) return res.status(refused.status || 403).json(refused);
    const lbl = cleanLabel(label || 'phone', 60);
    // E1 (item 9): while a phone is linked, a new one waits 48 hours — cancelable from any linked phone — unless an
    // established phone (linked ≥ 48 h) approves it with its presence key. Otherwise password + PIN alone would make an
    // attacker's phone count at once: it could remove the owner's phones and cancel the owner's recoveries.
    if (H && hasDevice(auth.did)) {
      const stop = H.startRefusal(auth.did, 'enrol');
      if (stop) return res.status(stop.status).json(stop.body);
      const h = H.createHold(auth.did, 'enrol', { device_id, label: lbl, key_d, key_p }, { why: lbl });
      logSecurityEvent('device_enrol_pending', 'warn', { caller_did: auth.did, capability: 'device', target: lbl, ip: req.ip, context: { device_id, hold_id: h.id } });
      return res.status(202).json({ ok: true, pending: true, device_id, label: lbl, hold_id: h.id, active_at: h.ready_at, fingerprint: H.view(h).fingerprint,
        note: 'this phone is linked in 48 hours unless it is canceled — or at once if you approve it on a phone already linked for 48 hours or more (DemiPass → Settings)' });
    }
    const r = activateEnrolment(auth.did, { device_id, label: lbl, key_d, key_p });
    if (!r.ok) return res.status(409).json({ error: r.error });
    logSecurityEvent('device_enrolled', 'warn', { caller_did: auth.did, capability: 'device', target: lbl, ip: req.ip, context: { device_id } });
    res.status(201).json({ ok: true, device_id, label: lbl, note: 'approvals now need this phone (or another enrolled one)' });
  });

  // Link a phone's two keys now (first phone, an approved or a due pending one). Re-checks the limits.
  function activateEnrolment(did, p) {
    if (!p || !/^[A-Za-z0-9_-]{8,64}$/.test(String(p.device_id || '')) || !parsePublicKey(p.key_d) || !parsePublicKey(p.key_p)) return { ok: false, error: 'bad enrolment' };
    if (db.prepare('SELECT 1 FROM device_keys WHERE device_id = ? LIMIT 1').get(p.device_id)) return { ok: false, error: 'that device id is already known' };
    const live = db.prepare('SELECT COUNT(DISTINCT device_id) AS n FROM device_keys WHERE did = ? AND revoked_at IS NULL').get(did).n;
    if (live >= MAX_DEVICES) return { ok: false, error: `at most ${MAX_DEVICES} devices — remove one first` };
    const t = nowIso(), lbl = cleanLabel(p.label || 'phone', 60);
    db.transaction(() => {
      const ins = db.prepare('INSERT INTO device_keys (did, device_id, kind, public_key, label, enrolled_at) VALUES (?, ?, ?, ?, ?, ?)');
      ins.run(did, p.device_id, 'D', p.key_d, lbl, t); ins.run(did, p.device_id, 'P', p.key_p, lbl, t);
    })();
    notifyOwner(did, `A device was added to your DemiPass wallet: ${lbl}`);
    return { ok: true };
  }

  // GET /api/identity/devices — linked phones, and phones waiting to be linked (E1).
  app.get('/api/identity/devices', rateLimitStandard, (req, res) => {
    const auth = getBearerIdentity(req); if (!auth.ok) return res.status(auth.status || 401).json({ error: auth.error });
    const rows = db.prepare("SELECT device_id, label, MIN(enrolled_at) AS enrolled_at, MAX(last_used_at) AS last_used_at FROM device_keys WHERE did = ? AND revoked_at IS NULL GROUP BY device_id, label ORDER BY enrolled_at").all(auth.did);
    const H = holds();
    const pending = H && !auth.silicon ? H.openHolds(auth.did, 'enrol').map(h => { let p = {}; try { p = JSON.parse(h.payload); } catch (_) {} return { device_id: p.device_id, label: p.label, hold_id: h.id, active_at: h.ready_at }; }) : [];
    res.json({ ok: true, devices: rows, pending, lock_after_sec: lockAfter(auth.did), approvals_need_device: rows.length > 0 });
  });

  // DELETE /api/identity/devices/:device_id — PIN (device-revoke:0). Refused for agent tokens.
  app.delete('/api/identity/devices/:device_id', rateLimitStandard, (req, res) => {
    const auth = personAuth(req, res); if (!auth) return;
    // The PIN, plus the account password or a biometric from a linked phone in this session: knowing the PIN alone must
    // not remove the owner's phone so that another can be linked (#47 review H1).
    const intent = 'device-revoke:0';
    const session = gateSession(auth);
    const bio = db.prepare("SELECT id, device_id FROM device_gate_proofs WHERE did = ? AND session = ? AND intent = ? AND used = 0 AND at > ? ORDER BY id DESC LIMIT 1")
      .get(auth.did, session, intent, new Date(Date.now() - 120000).toISOString());
    const pwOk = gateFresh(auth.did, 'password', auth);
    if (!gateFresh(auth.did, 'pin', auth, intent) || (!bio && !pwOk)) {
      const missing = [...(gateFresh(auth.did, 'pin', auth, intent) ? [] : ['pin']), ...(bio || pwOk ? [] : ['password'])];
      return res.status(403).json({ ...gateMissing('device-revoke', ['pin', 'password'], missing, intent), note: 'a biometric from a linked phone stands in for both' });
    }
    const target = String(req.params.device_id);
    // Item 9: a phone linked less than 48 hours ago removes no other phone (E1/H3), and while guardians are set the last
    // phone stays (remove the guardians first, through their 48-hour change) — so no one can strip the owner's phones
    // and then run a recovery or a reset nobody can cancel.
    if (bio && bio.device_id && bio.device_id !== target) {
      const prover = db.prepare("SELECT MIN(enrolled_at) AS at FROM device_keys WHERE did = ? AND device_id = ? AND revoked_at IS NULL").get(auth.did, bio.device_id);
      if (!prover || !prover.at || Date.parse(prover.at) > Date.now() - 48 * 3600 * 1000) return res.status(403).json({ error: 'a phone linked less than 48 hours ago cannot remove another phone' });
    }
    const H = holds();
    if (H && H.guardiansActive(auth.did)) {
      const others = db.prepare('SELECT COUNT(DISTINCT device_id) AS n FROM device_keys WHERE did = ? AND revoked_at IS NULL AND device_id != ?').get(auth.did, target).n;
      if (!others) return res.status(409).json({ error: 'this is your last linked phone and you have recovery guardians: remove the guardians first (it takes 48 hours), or link another phone' });
    }
    if (!db.prepare('SELECT 1 FROM device_keys WHERE did = ? AND device_id = ? AND revoked_at IS NULL').get(auth.did, target)) return res.status(404).json({ error: 'device not found' });
    // #59 review H1: at once only with a presence signature from the phone itself or from a phone linked ≥ 48 hours.
    // With the password (and PIN) alone it waits 48 hours, cancelable from any linked phone — otherwise password + PIN
    // would strip every phone, and then R0, E1 and E2 would all act at once.
    const bySelf = bio && bio.device_id === target;
    const byEstablished = bio && bio.device_id && db.prepare('SELECT 1 FROM device_keys WHERE did = ? AND device_id = ? AND revoked_at IS NULL AND enrolled_at <= ?')
      .get(auth.did, bio.device_id, new Date(Date.now() - 48 * 3600 * 1000).toISOString());
    if (H && !bySelf && !byEstablished) {
      const stop = H.startRefusal(auth.did, 'unlink');
      if (stop) return res.status(stop.status).json(stop.body);
      if (H.openHolds(auth.did, 'unlink').some(h => { try { return JSON.parse(h.payload).device_id === target; } catch (_) { return false; } })) return res.status(409).json({ error: 'that phone is already being removed' });
      const refusedP = spendSingleUse(auth.did, 'device-revoke', ['pin'], auth, intent);
      if (refusedP) return res.status(refusedP.status || 403).json(refusedP);
      const lbl = (db.prepare('SELECT label FROM device_keys WHERE did = ? AND device_id = ? LIMIT 1').get(auth.did, target) || {}).label || '';
      const h = H.createHold(auth.did, 'unlink', { device_id: target, label: lbl }, { why: lbl });
      return res.status(202).json({ ok: true, pending: true, hold_id: h.id, ready_at: h.ready_at,
        note: 'removed in 48 hours unless canceled from a linked phone — or remove it at once by confirming on the phone itself or on a phone linked for 48 hours or more' });
    }
    const refused = spendSingleUse(auth.did, 'device-revoke', ['pin'], auth, intent);
    if (refused) return res.status(refused.status || 403).json(refused);
    if (bio) db.prepare('UPDATE device_gate_proofs SET used = 1 WHERE id = ?').run(bio.id);
    const r = revokeOne(auth.did, target, bio ? 'device' : 'password');
    if (!r.ok) return res.status(r.status || 404).json({ error: r.error });
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
    if (fresh) db.prepare('UPDATE session_unlocks SET last_active_at = ?, fresh_until = ? WHERE session = ?').run(nowIso(), new Date(Date.now() + lockAfter(auth.did) * 1000).toISOString(), gateSession(auth));
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

  // A PIN reset with the account password (recovery) unlinks every phone: whoever reset it starts clean.
  // One phone removed (the DELETE route, or a due 'unlink' hold). The last phone stays while guardians are set.
  function revokeOne(did, deviceId, via) {
    const H = holds();
    if (H && H.guardiansActive(did) && !db.prepare('SELECT 1 FROM device_keys WHERE did = ? AND revoked_at IS NULL AND device_id != ? LIMIT 1').get(did, deviceId)) {
      return { ok: false, status: 409, error: 'the last linked phone stays while recovery guardians are set' };
    }
    const n = db.prepare('UPDATE device_keys SET revoked_at = ?, revoked_via = ? WHERE did = ? AND device_id = ? AND revoked_at IS NULL').run(nowIso(), via, did, String(deviceId)).changes;
    return n ? { ok: true } : { ok: false, status: 404, error: 'device not found' };
  }
  function revokeAll(did, why, via = 'reset') {
    const n = db.prepare('UPDATE device_keys SET revoked_at = ?, revoked_via = ? WHERE did = ? AND revoked_at IS NULL').run(nowIso(), via, did).changes;
    const H = holds(); if (H) H.dropDeviceHolds(did, why);
    db.prepare('DELETE FROM session_unlocks WHERE did = ?').run(did);
    if (n) { logSecurityEvent('devices_revoked', 'warn', { caller_did: did, capability: 'device', context: { why } }); notifyOwner(did, 'Every phone was removed from your DemiPass wallet (' + why + '). Link yours again in Settings.'); }
    return n;
  }
  // A presence-key (P) signature, in this session, over a 'gate' challenge for `intent`, by an active phone of the
  // caller — linked at least `minAgeSec` ago. Works while the PIN is locked (it proves the phone, not the PIN).
  // Returns the key row or null; the challenge is spent either way.
  function verifyPresence(auth, challengeId, signature, intent, minAgeSec = 0) {
    if (isAgent(auth)) return null;
    const ch = takeChallenge(auth.did, gateSession(auth), challengeId, 'gate', intent);
    if (!ch) return null;
    const k = signer(auth.did, 'P', messageFor(ch), signature);
    if (!k) return null;
    if (minAgeSec && Date.parse(k.enrolled_at) > Date.now() - minAgeSec * 1000) return null;
    return k;
  }
  return { approvalRefusal, unlockFresh, markUnlocked, verifyDeviceGate, hasDevice, lockAfter, messageFor, revokeAll,
           verifySig, verifyPresence, activateEnrolment, revokeOne,
           LOCK_DEFAULT, LOCK_MIN, LOCK_MAX };
};
