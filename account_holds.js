'use strict';
// ── Account holds: delayed, cancelable account changes (red team item 9, step 1) ─────────────────────────────────
// Design: tome decisions/2026-11-07-demipass-item9-social-recovery-design.md (v1.1).
//
// While an account has a linked phone, the ways back into it without that phone wait 48 hours and can be canceled
// from any eligible phone:
//   pin-reset  R0  a PIN reset with the account password (it unlinks every phone when it applies)
//   enrol      E1  a new phone linked with password + PIN (immediate instead when an established phone approves)
//   email      E2  a recovery-email change (immediate instead with an established phone's presence signature)
//   recovery   guardian recovery (step 3) — the cancel path is here and tested first
//   guardians  a change of the guardian set (step 2)
//   unlink     a phone removed without an established phone's presence (password + PIN) — #59 review H1
//
// Eligible phone (one rule for every cancel and for alerts): enrolled to the account and active at some moment from
// (hold start − 7 days) until now; a phone removed with a phone's presence signature (revoked_via = 'device') gets no
// grace. A cancel is signed by the phone's PRESENCE key P (biometric/device credential) and needs no session: whoever
// is taking the account may already have ended the owner's sessions. Alerts are signed by the device key D.

const crypto = require('crypto');

const HOLD_DELAY_SEC = 48 * 3600;
const GRACE_SEC = 7 * 24 * 3600;           // a phone removed this long before a hold started may still cancel it
const ESTABLISHED_SEC = 48 * 3600;         // a phone this old may approve a new one / change the recovery email at once
const CHALLENGE_TTL_SEC = 60;
const PIN_RESET_PER_WEEK = 3;
const KINDS = new Set(['pin-reset', 'enrol', 'email', 'recovery', 'guardians', 'unlink']);
const ENROL_OPEN_MAX = 3;                  // phones waiting to be linked at once (#59 review L3)
const PURPOSES = { cancel: 'P', alerts: 'D', 'enrol-approve': 'P' };

module.exports = function registerAccountHolds(deps) {
  const { app, db, rateLimitStrict, logSecurityEvent, sendMail, cleanLabel } = deps;
  // Late-bound (registered after this module): the device-key module, and server.js helpers.
  const devices = () => deps.devices();

  db.exec(`CREATE TABLE IF NOT EXISTS account_holds (
    id TEXT PRIMARY KEY,
    did TEXT NOT NULL,
    kind TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',   -- pending | quorum | canceled | completed | expired | failed
    created_at TEXT NOT NULL,
    ready_at TEXT,
    expires_at TEXT,
    payload TEXT NOT NULL DEFAULT '{}',
    canceled_by TEXT,
    canceled_at TEXT,
    completed_at TEXT,
    note TEXT
  )`);
  db.exec('CREATE INDEX IF NOT EXISTS idx_account_holds_did ON account_holds(did, status)');
  db.exec(`CREATE TABLE IF NOT EXISTS hold_challenges (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    did TEXT NOT NULL,
    device_id TEXT NOT NULL,
    purpose TEXT NOT NULL,
    hold_id TEXT NOT NULL DEFAULT '',
    nonce TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used_at TEXT
  )`);
  db.exec('CREATE UNIQUE INDEX IF NOT EXISTS idx_hold_challenges_nonce ON hold_challenges(nonce)');
  // Guardians (step 2 fills it); here only for the last-phone guard.
  db.exec(`CREATE TABLE IF NOT EXISTS recovery_guardians (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_did TEXT NOT NULL,
    guardian_did TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'invited',
    invited_at TEXT NOT NULL,
    accepted_at TEXT,
    removed_at TEXT,
    why TEXT
  )`);
  // Every recovery address an account had, so alerts also reach one changed in the last 7 days (design H1).
  db.exec(`CREATE TABLE IF NOT EXISTS recovery_email_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT, did TEXT NOT NULL, email TEXT NOT NULL, replaced_at TEXT NOT NULL)`);
  try { db.exec('ALTER TABLE identity_wallets ADD COLUMN password_must_change INTEGER DEFAULT 0'); } catch (_) {}

  const nowIso = () => new Date().toISOString();
  const isoIn = (sec) => new Date(Date.now() + sec * 1000).toISOString();
  const isoAgo = (sec, from = Date.now()) => new Date(from - sec * 1000).toISOString();
  const newHoldId = () => {
    for (;;) { const id = String(crypto.randomInt(1e11, 1e12)); if (!db.prepare('SELECT 1 FROM account_holds WHERE id = ?').get(id)) return id; }
  };
  const parse = (s) => { try { return JSON.parse(s || '{}'); } catch (_) { return {}; } };

  // ── who hears about a hold ─────────────────────────────────────────────────────────────────────────────────────
  function addresses(did) {
    const w = db.prepare('SELECT email, recovery_email FROM identity_wallets WHERE did = ?').get(did) || {};
    const past = db.prepare('SELECT email FROM recovery_email_history WHERE did = ? AND replaced_at > ?').all(did, isoAgo(GRACE_SEC)).map(r => r.email);
    const seen = new Set(), out = [];
    for (const a of [w.email, w.recovery_email, ...past]) { const k = String(a || '').trim().toLowerCase(); if (k && !seen.has(k)) { seen.add(k); out.push(String(a).trim()); } }
    return out;
  }
  function tell(did, subject, text) {
    if (!sendMail) return;
    for (const to of addresses(did)) { try { Promise.resolve(sendMail({ to, subject: 'DemiPass: ' + subject, text })).catch(() => {}); } catch (_) {} }
  }
  const WHAT = {
    'pin-reset': 'a PIN reset with your account password (it removes every linked phone when it applies)',
    enrol: 'a new phone being linked to your wallet',
    email: 'a change of your recovery email',
    recovery: 'a recovery of your wallet onto a new phone, by your guardians',
    guardians: 'a change of your recovery guardians',
    unlink: 'a phone being removed from your wallet with the account password',
  };

  // Things the phone should show that are not holds (item 6b): mail forwarding rules turned on in the last 48 hours —
  // the window in which codes and reset links do not go through them, and the one to notice a stranger's rule in.
  function notices(did) {
    try {
      return db.prepare(`SELECT id, forward_to, filter_from, COALESCE(activated_at, created_at) AS since FROM forward_relays
          WHERE did = ? AND status = 'active' AND julianday(COALESCE(activated_at, created_at)) > julianday('now', '-2 days') ORDER BY id DESC LIMIT 10`).all(did)
        .map(r => ({ kind: 'forward', rule_id: r.id, forward_to: r.forward_to, filter_from: r.filter_from, since: r.since,
          text: `Mail forwarding to ${r.forward_to} was turned on. If this was not you, remove it in the Dustforge tab.` }));
    } catch (_) { return []; }
  }

  // ── eligibility ────────────────────────────────────────────────────────────────────────────────────────────────
  // The key row (`kind` D or P) of a phone of `did` that was active at some moment from `since` until now.
  function eligibleKey(did, deviceId, kind, since) {
    return db.prepare(`SELECT * FROM device_keys WHERE did = ? AND device_id = ? AND kind = ?
                       AND (revoked_at IS NULL OR (revoked_at >= ? AND COALESCE(revoked_via, '') != 'device'))`).get(did, String(deviceId || ''), kind, since) || null;
  }
  const holdSince = (h) => isoAgo(GRACE_SEC, Date.parse(h.created_at));
  // Established: active (not removed) and linked at least ESTABLISHED_SEC ago.
  function establishedKey(did, deviceId, kind) {
    return db.prepare('SELECT * FROM device_keys WHERE did = ? AND device_id = ? AND kind = ? AND revoked_at IS NULL AND enrolled_at <= ?')
      .get(did, String(deviceId || ''), kind, isoAgo(ESTABLISHED_SEC)) || null;
  }
  const verify = (key, msg, sig) => devices().verifySig(key.public_key, msg, sig);

  // ── holds ──────────────────────────────────────────────────────────────────────────────────────────────────────
  const OPEN = "status IN ('pending', 'quorum')";
  function openHolds(did, kind) {
    return db.prepare(`SELECT * FROM account_holds WHERE did = ? AND ${OPEN}${kind ? ' AND kind = ?' : ''} ORDER BY created_at`).all(...(kind ? [did, kind] : [did]));
  }
  function createHold(did, kind, payload, { delaySec = HOLD_DELAY_SEC, readyAt, expiresAt, why = '', quiet = false } = {}) {
    if (!KINDS.has(kind)) throw new Error('unknown hold kind');
    const id = newHoldId(), t = nowIso();
    const ready = readyAt === undefined ? isoIn(delaySec) : readyAt;
    db.prepare('INSERT INTO account_holds (id, did, kind, status, created_at, ready_at, expires_at, payload) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
      .run(id, did, kind, 'pending', t, ready, expiresAt || null, JSON.stringify(payload || {}));
    logSecurityEvent('account_hold_started', 'critical', { caller_did: did, capability: kind, context: { hold_id: id, ready_at: ready, why } });
    if (!quiet) tell(did, `${kind === 'recovery' ? 'someone is recovering your wallet' : 'a change to your account is waiting'} — cancel it from your phone if it was not you`,
      `Started ${t}: ${WHAT[kind]}${why ? ` (${why})` : ''}.\n` +
      (ready ? `It takes effect at ${ready} unless it is canceled.\n` : '') +
      `If this was not you, open DemiPass on one of your phones and cancel it there (your fingerprint or screen lock confirms).\n`);
    return db.prepare('SELECT * FROM account_holds WHERE id = ?').get(id);
  }
  const view = (h) => {
    const p = parse(h.payload);
    return { id: h.id, kind: h.kind, status: h.status, created_at: h.created_at, ready_at: h.ready_at, expires_at: h.expires_at,
             what: WHAT[h.kind], ...(h.kind === 'enrol' ? { label: p.label, fingerprint: keyPrint(p.key_d) } : {}),
             ...(h.kind === 'email' ? { recovery_email: p.recovery_email } : {}), ...(h.kind === 'unlink' ? { device_id: p.device_id, label: p.label } : {}) };
  };

  // The first 8 hex of sha256(the new phone's device key): shown on the new phone and in the approval, so the owner
  // approves the phone in their hand and not another one with the same name (#59 review M4).
  // 16 hex (64 bits): a look-alike phone would take ~2^64 key generations (#59 re-review L2). The new phone computes it
  // from its own key (the page hashes key_d the same way) — it does not take the server's word for it.
  const keyPrint = (k) => k ? crypto.createHash('sha256').update(String(k)).digest('hex').slice(0, 16) : '';
  // A label for a signed message: whole code points (an emoji is never cut in half), no lone surrogates, no ':' or
  // controls — Node and Java must turn it into the same bytes (#59 re-review L3).
  const msgLabel = (l) => Array.from(String(l || '')).slice(0, 60).join('')
    .replace(/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/g, '').replace(/[:\u0000-\u001f\u007f]/g, ' ');

  // ── session-less challenges ────────────────────────────────────────────────────────────────────────────────────
  function messageFor(ch) {
    if (ch.purpose === 'cancel') {
      const h = db.prepare('SELECT kind FROM account_holds WHERE id = ?').get(ch.hold_id) || {};
      return `demipass:recovery-cancel:${ch.did}:${h.kind || ''}:${ch.hold_id}:${ch.nonce}`;
    }
    if (ch.purpose === 'enrol-approve') {
      const h = db.prepare('SELECT payload FROM account_holds WHERE id = ?').get(ch.hold_id) || {};
      const p = parse(h.payload);
      return `demipass:enrol-approve:${ch.did}:${ch.hold_id}:${keyPrint(p.key_d)}:${msgLabel(p.label)}:${ch.nonce}`;
    }
    return `demipass:alerts:${ch.did}:${ch.device_id}:${ch.nonce}`;
  }
  const NOT_HERE = { status: 404, body: { error: 'not available from this phone' } };   // one answer for every refusal (L1)
  // A challenge is found by its nonce (random, given only to the asker) — never by a counter someone could walk — and
  // spent only once its signature verifies (spendChallenge): junk posts cannot burn the owner's cancel (#59 review H2).
  function findChallenge(nonce, purpose, deviceId, holdId) {
    if (typeof nonce !== 'string' || !/^[A-Za-z0-9_-]{32}$/.test(nonce)) return null;
    const ch = db.prepare('SELECT * FROM hold_challenges WHERE nonce = ?').get(nonce);
    if (!ch || ch.purpose !== purpose || ch.device_id !== String(deviceId || '') || ch.hold_id !== String(holdId || '')) return null;
    if (ch.used_at || Date.parse(ch.expires_at) < Date.now()) return null;
    return ch;
  }
  const spendChallenge = (ch) => db.prepare('UPDATE hold_challenges SET used_at = ? WHERE id = ? AND used_at IS NULL').run(nowIso(), ch.id).changes === 1;

  // POST /api/identity/holds/challenge {purpose: 'cancel'|'alerts'|'enrol-approve', device_id, hold_id?}
  app.post('/api/identity/holds/challenge', rateLimitStrict, (req, res) => {
    const { purpose, device_id } = req.body || {};
    const holdId = String((req.body || {}).hold_id || '');
    if (!PURPOSES[purpose] || typeof device_id !== 'string' || !/^[A-Za-z0-9_-]{8,64}$/.test(device_id)) return res.status(400).json({ error: "purpose ('cancel', 'alerts' or 'enrol-approve') and device_id required" });
    const key = db.prepare('SELECT did FROM device_keys WHERE device_id = ? LIMIT 1').get(device_id);
    if (!key) return res.status(NOT_HERE.status).json(NOT_HERE.body);
    if (purpose !== 'alerts') {
      const h = db.prepare(`SELECT * FROM account_holds WHERE id = ? AND did = ? AND ${OPEN}`).get(holdId, key.did);
      if (!h || (purpose === 'enrol-approve' && h.kind !== 'enrol')) return res.status(NOT_HERE.status).json(NOT_HERE.body);
    }
    db.prepare('DELETE FROM hold_challenges WHERE expires_at < ?').run(isoAgo(3600));
    const nonce = crypto.randomBytes(24).toString('base64url');
    const id = Number(db.prepare('INSERT INTO hold_challenges (did, device_id, purpose, hold_id, nonce, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)')
      .run(key.did, device_id, purpose, purpose === 'alerts' ? '' : holdId, nonce, nowIso(), isoIn(CHALLENGE_TTL_SEC)).lastInsertRowid);
    const ch = db.prepare('SELECT * FROM hold_challenges WHERE id = ?').get(id);
    res.json({ ok: true, challenge: nonce, message: messageFor(ch), sign_with: PURPOSES[purpose], expires_at: ch.expires_at });
  });

  // POST /api/identity/holds/alerts {device_id, challenge_id, signature} — D. What is waiting on this phone's account.
  app.post('/api/identity/holds/alerts', rateLimitStrict, (req, res) => {
    const { device_id, challenge, signature } = req.body || {};
    const ch = findChallenge(challenge, 'alerts', device_id, '');
    if (!ch) return res.status(NOT_HERE.status).json(NOT_HERE.body);
    const key = eligibleKey(ch.did, device_id, 'D', isoAgo(GRACE_SEC));
    if (!key || !verify(key, messageFor(ch), signature) || !spendChallenge(ch)) return res.status(NOT_HERE.status).json(NOT_HERE.body);
    sweep();
    const holds = openHolds(ch.did).filter(h => eligibleKey(ch.did, device_id, 'P', holdSince(h)));
    res.json({ ok: true, holds: holds.map(view), notices: notices(ch.did) });
  });

  // POST /api/identity/holds/:id/cancel {device_id, challenge_id, signature} — P of an eligible phone. No session.
  app.post('/api/identity/holds/:id/cancel', rateLimitStrict, (req, res) => {
    const holdId = String(req.params.id);
    const { device_id, challenge, signature } = req.body || {};
    const ch = findChallenge(challenge, 'cancel', device_id, holdId);
    if (!ch) return res.status(NOT_HERE.status).json(NOT_HERE.body);
    let done = null;
    db.transaction(() => {
      const h = db.prepare(`SELECT * FROM account_holds WHERE id = ? AND did = ? AND ${OPEN}`).get(holdId, ch.did);
      if (!h) return;
      const key = eligibleKey(h.did, device_id, 'P', holdSince(h));
      if (!key || !verify(key, messageFor(ch), signature) || !spendChallenge(ch)) return;
      if (db.prepare(`UPDATE account_holds SET status = 'canceled', canceled_by = ?, canceled_at = ?, payload = '{}' WHERE id = ? AND ${OPEN}`)
        .run(device_id, nowIso(), h.id).changes === 1) done = h;
    }).immediate();
    if (!done) {
      logSecurityEvent('hold_cancel_refused', 'alert', { caller_did: ch.did, capability: 'hold-cancel', ip: req.ip, context: { hold_id: holdId, device_id: String(device_id || '').slice(0, 64) } });
      return res.status(NOT_HERE.status).json(NOT_HERE.body);
    }
    afterCancel(done, device_id);
    res.json({ ok: true, canceled: view({ ...done, status: 'canceled' }) });
  });

  function afterCancel(h, deviceId) {
    logSecurityEvent('account_hold_canceled', 'critical', { caller_did: h.did, capability: h.kind, context: { hold_id: h.id, by_device: deviceId } });
    // Whoever started a PIN reset holds the password: end every session and make the owner change it (design M3).
    if (h.kind === 'pin-reset') {
      try { deps.cutSessions(h.did); } catch (_) {}
      db.prepare('UPDATE identity_wallets SET password_must_change = 1 WHERE did = ?').run(h.did);
    }
    tell(h.did, `canceled: ${h.kind === 'recovery' ? 'the recovery of your wallet' : WHAT[h.kind]}`,
      `It was canceled from one of your phones at ${nowIso()}. Nothing changed.\n` +
      (h.kind === 'pin-reset' ? 'Whoever started it knows your account password: every session was signed out, and you must choose a new password at your next sign-in.\n' : ''));
    if (h.kind === 'recovery' && deps.recovery) { try { deps.recovery().onCanceled(h); } catch (_) {} }
    if (h.kind === 'guardians' && deps.guardians) { try { deps.guardians().dropChange(h); } catch (_) {} }
  }

  // POST /api/identity/holds/:id/approve-enrol {device_id, challenge_id, signature} — P of an established phone
  // (linked ≥ 48 h, not removed) of the same account: the waiting phone is linked now (E1).
  app.post('/api/identity/holds/:id/approve-enrol', rateLimitStrict, (req, res) => {
    const holdId = String(req.params.id);
    const { device_id, challenge, signature } = req.body || {};
    const ch = findChallenge(challenge, 'enrol-approve', device_id, holdId);
    if (!ch) return res.status(NOT_HERE.status).json(NOT_HERE.body);
    const key = establishedKey(ch.did, device_id, 'P');
    if (!key || !verify(key, messageFor(ch), signature) || !spendChallenge(ch)) return res.status(NOT_HERE.status).json(NOT_HERE.body);
    const h = db.prepare(`SELECT * FROM account_holds WHERE id = ? AND did = ? AND kind = 'enrol' AND ${OPEN}`).get(holdId, ch.did);
    if (!h) return res.status(NOT_HERE.status).json(NOT_HERE.body);
    const r = applyHold(h, `approved by phone ${device_id}`);
    if (!r.ok) return res.status(409).json({ error: r.error });
    res.json({ ok: true, linked: parse(h.payload).device_id });
  });

  // GET /api/identity/holds — the signed-in owner's open holds (the app's cards). Agents see none.
  app.get('/api/identity/holds', deps.rateLimitStandard, (req, res) => {
    const auth = deps.getBearerIdentity(req); if (!auth.ok) return res.status(auth.status || 401).json({ error: auth.error });
    if (auth.silicon) return res.json({ ok: true, holds: [] });
    sweep();
    res.json({ ok: true, holds: openHolds(auth.did).map(view), notices: notices(auth.did) });
  });

  // ── applying a due hold ────────────────────────────────────────────────────────────────────────────────────────
  // Every check is re-run when it applies. Returns {ok} or {ok:false, error}; the hold ends completed or failed.
  function applyHold(h, how) {
    const p = parse(h.payload);
    let result = { ok: false, error: 'not applicable' };
    try {
      db.transaction(() => {
        const cur = db.prepare(`SELECT * FROM account_holds WHERE id = ? AND ${OPEN}`).get(h.id);
        if (!cur) { result = { ok: false, error: 'no longer waiting' }; return; }
        if (h.kind === 'pin-reset') {
          const r = deps.applyPinReset(h.did, p.pin_hash, 'PIN reset with the account password (after 48 h)');
          if (!r || !r.ok) throw new Error('the PIN could not be set');
        } else if (h.kind === 'enrol') {
          const r = devices().activateEnrolment(h.did, p);
          if (!r.ok) throw Object.assign(new Error(r.error), { soft: true });
        } else if (h.kind === 'unlink') {
          const r = devices().revokeOne(h.did, p.device_id, 'password');
          if (!r.ok) throw Object.assign(new Error(r.error), { soft: true });
        } else if (h.kind === 'guardians') {
          deps.guardians().applyChange(h, p);
        } else if (h.kind === 'email') {
          const w = db.prepare('SELECT recovery_email FROM identity_wallets WHERE did = ?').get(h.did);
          setRecoveryEmail(h.did, w && w.recovery_email, p.recovery_email);
        } else { result = { ok: false, error: 'applied by its own flow' }; return; }
        db.prepare("UPDATE account_holds SET status = 'completed', completed_at = ?, payload = '{}', note = ? WHERE id = ?").run(nowIso(), how, h.id);
        result = { ok: true };
      }).immediate();
    } catch (e) {
      db.prepare("UPDATE account_holds SET status = 'failed', note = ?, payload = '{}' WHERE id = ? AND status IN ('pending', 'quorum')").run(String(e.message).slice(0, 200), h.id);
      if (h.kind === 'guardians') { try { deps.guardians().dropChange(h); } catch (_) {} }
      result = { ok: false, error: e.message };
      tell(h.did, `not done: ${WHAT[h.kind]}`, `It did not take effect: ${e.message}. Nothing changed.\n`);
    }
    if (result.ok) {
      logSecurityEvent('account_hold_applied', 'critical', { caller_did: h.did, capability: h.kind, context: { hold_id: h.id, how } });
      tell(h.did, `done: ${WHAT[h.kind]}`, `It took effect at ${nowIso()} (${how}).\nIf this was not you, your account is no longer only yours: act now.\n`);
    }
    return result;
  }
  function setRecoveryEmail(did, previous, next) {
    if (previous && String(previous).toLowerCase() !== String(next || '').toLowerCase()) db.prepare('INSERT INTO recovery_email_history (did, email, replaced_at) VALUES (?, ?, ?)').run(did, previous, nowIso());
    db.prepare('UPDATE identity_wallets SET recovery_email = ?, updated_at = CURRENT_TIMESTAMP WHERE did = ?').run(next, did);
  }
  function sweep() {
    const t = nowIso();
    for (const h of db.prepare(`SELECT * FROM account_holds WHERE status = 'pending' AND kind IN ('pin-reset', 'enrol', 'email', 'unlink', 'guardians') AND ready_at IS NOT NULL AND ready_at <= ?`).all(t)) applyHold(h, 'after 48 h, not canceled');
    db.prepare(`UPDATE account_holds SET status = 'expired', payload = '{}' WHERE ${OPEN} AND expires_at IS NOT NULL AND expires_at <= ?`).run(t);
  }
  const timer = setInterval(() => { try { sweep(); } catch (e) { console.error('[holds] sweep:', e.message); } }, Number(process.env.HOLD_SWEEP_MS) || 30000);
  if (timer.unref) timer.unref();

  // ── what the other routes ask ──────────────────────────────────────────────────────────────────────────────────
  // R0: may a PIN reset with the password start now? {ok} or {status, body}.
  function pinResetRefusal(did) {
    const open = openHolds(did, 'pin-reset')[0];
    if (open) return { status: 409, body: { error: 'a PIN reset is already waiting', hold: view(open) } };
    const n = db.prepare("SELECT COUNT(*) AS n FROM account_holds WHERE did = ? AND kind = 'pin-reset' AND created_at > ?").get(did, isoAgo(7 * 86400)).n;
    if (n >= PIN_RESET_PER_WEEK) return { status: 429, body: { error: `at most ${PIN_RESET_PER_WEEK} PIN resets a week` } };
    return null;
  }
  // Refusal for starting a waiting change: after a canceled PIN reset the password is known to someone else, so until
  // it is changed nothing more starts from it (#59 review M1); and a few waiting phones at most (L3).
  function startRefusal(did, kind) {
    const w = db.prepare('SELECT password_must_change FROM identity_wallets WHERE did = ?').get(did);
    if (w && w.password_must_change) return { status: 403, body: { error: 'change your account password first (Forgot password → the link in your mail): a PIN reset you canceled was started with it', password_must_change: true } };
    if (kind === 'enrol' && openHolds(did, 'enrol').length >= ENROL_OPEN_MAX) return { status: 429, body: { error: `at most ${ENROL_OPEN_MAX} phones can wait to be linked at once` } };
    if (kind === 'unlink' && openHolds(did, 'unlink').length >= 3) return { status: 429, body: { error: 'too many phone removals waiting' } };
    return null;
  }
  // When every phone is unlinked (a reset, a recovery), phones waiting to be linked and removals waiting go too (#59 M3).
  function dropDeviceHolds(did, why) {
    db.prepare(`UPDATE account_holds SET status = 'canceled', canceled_by = ?, canceled_at = ?, payload = '{}' WHERE did = ? AND kind IN ('enrol', 'unlink') AND ${OPEN}`).run(String(why).slice(0, 60), nowIso(), did);
  }
  // A waiting change of this kind made moot by one applied now (with the phone): it must never apply later.
  function closeOpen(did, kind, why) {
    db.prepare(`UPDATE account_holds SET status = 'canceled', canceled_by = ?, canceled_at = ?, payload = '{}' WHERE did = ? AND kind = ? AND ${OPEN}`).run(String(why).slice(0, 60), nowIso(), did, kind);
  }
  const guardiansActive = (did) => db.prepare("SELECT COUNT(*) AS n FROM recovery_guardians WHERE owner_did = ? AND status = 'active'").get(did).n > 0;

  return { createHold, openHolds, view, sweep, pinResetRefusal, guardiansActive, startRefusal, dropDeviceHolds, closeOpen, tellOwner: tell, establishedKey, eligibleKey, setRecoveryEmail,
           HOLD_DELAY_SEC, ESTABLISHED_SEC, GRACE_SEC };
};
