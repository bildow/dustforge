'use strict';
// ── Guardian recovery (red team item 9, step 3) ─────────────────────────────────────────────────────────────────────
// Design: tome decisions/2026-11-07-demipass-item9-social-recovery-design.md (v1.1) § Recovery request, § Guardian
// approval, § Completion. A recovery is an account hold of kind 'recovery' (account_holds.js): every eligible phone of
// the owner is alerted and can cancel it, without a session, at any point before it completes.
//
//   start      no session. A fresh install makes D/P keys and signs the start challenge with both. Unknown account →
//              404 (names are public anyway); a known one always 202 {request_id, code}, guardians or not. The code
//              (6 digits, server-random, hashed) is shown only on the new phone; the owner tells it to each guardian.
//   approve    a guardian of the snapshot taken at start, still eligible: PIN (recovery-approve:<id>) + their phone's
//              device signature bound to "<id>|<new phone's key code>|<code>". Refused when the guardian's own account
//              linked a phone in the last 7 days or after the start, or had a password reset / recovery-email change
//              in the last 7 days (design M2). 3 wrong codes, across guardians, cancel the request.
//   quorum     the 2nd valid approval: ready_at = now + 48 h (the delay starts here), everyone told again.
//   decline    a guardian cancels it, in any phase.   withdraw: a guardian takes an approval back (below 2 → no clock).
//   complete   from the new phone, signed by the request's own D and P, at/after ready_at, ≥ 2 approvals still valid:
//              the mailbox password first (fail closed), then everything else in one transaction (design H5).

const crypto = require('crypto');

const QUORUM = 2;
const DELAY_SEC = 48 * 3600;
const PENDING_TTL_SEC = 72 * 3600;          // approvals must reach quorum within this
const COMPLETE_WINDOW_SEC = 7 * 24 * 3600;  // after ready_at
const MAX_CODE_MISSES = 3;
const OPEN_PER_ACCOUNT = 5;
const APPROVED_STARTS_PER_WEEK = 3;
const GLOBAL_STARTS_PER_DAY = 500;
const CHALLENGE_TTL_SEC = 120;

module.exports = function registerRecovery(deps) {
  const { app, db, rateLimitStrict, rateLimitStandard, getBearerIdentity, gateFresh, gateMissing, spendSingleUse, logSecurityEvent, sendMail } = deps;
  const devices = () => deps.devices(), holds = () => deps.holds(), guardians = () => deps.guardians(), cryptoDepth = () => deps.cryptoDepth();

  db.exec(`CREATE TABLE IF NOT EXISTS recovery_challenges (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nonce TEXT NOT NULL UNIQUE,
    purpose TEXT NOT NULL,              -- start | complete
    account TEXT NOT NULL DEFAULT '',
    hold_id TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used_at TEXT
  )`);

  const nowIso = () => new Date().toISOString();
  const isoIn = (sec) => new Date(Date.now() + sec * 1000).toISOString();
  const isoAgo = (sec) => new Date(Date.now() - sec * 1000).toISOString();
  const sqlAgo = (sec) => isoAgo(sec).replace('T', ' ').slice(0, 19);
  const parse = (s) => { try { return JSON.parse(s || '{}'); } catch (_) { return {}; } };
  const nameOf = (did) => { const w = db.prepare('SELECT username FROM identity_wallets WHERE did = ?').get(did); return w ? w.username : null; };
  const keyPrint = (k) => crypto.createHash('sha256').update(String(k)).digest('hex').slice(0, 16);
  const codeHash = (id, code) => crypto.createHash('sha256').update(`${id}:${code}`).digest('hex');
  const OPEN = "status IN ('pending', 'quorum')";
  function tellDid(did, subject, text) {
    try { const w = db.prepare('SELECT email FROM identity_wallets WHERE did = ?').get(did); if (w && w.email && sendMail) Promise.resolve(sendMail({ to: w.email, subject: 'DemiPass: ' + subject, text })).catch(() => {}); } catch (_) {}
  }
  const getReq = (id) => db.prepare(`SELECT * FROM account_holds WHERE id = ? AND kind = 'recovery'`).get(String(id || ''));
  const savePayload = (id, p) => db.prepare('UPDATE account_holds SET payload = ? WHERE id = ?').run(JSON.stringify(p), id);

  // ── challenges (no session) ────────────────────────────────────────────────────────────────────────────────────
  function newChallenge(purpose, account, holdId) {
    db.prepare('DELETE FROM recovery_challenges WHERE expires_at < ?').run(isoAgo(3600));
    const nonce = crypto.randomBytes(24).toString('base64url');
    db.prepare('INSERT INTO recovery_challenges (nonce, purpose, account, hold_id, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)')
      .run(nonce, purpose, account || '', holdId || '', nowIso(), isoIn(CHALLENGE_TTL_SEC));
    return nonce;
  }
  function findChallenge(nonce, purpose) {
    if (typeof nonce !== 'string' || !/^[A-Za-z0-9_-]{32}$/.test(nonce)) return null;
    const c = db.prepare('SELECT * FROM recovery_challenges WHERE nonce = ? AND purpose = ?').get(nonce, purpose);
    if (!c || c.used_at || Date.parse(c.expires_at) < Date.now()) return null;
    return c;
  }
  const spend = (c) => db.prepare('UPDATE recovery_challenges SET used_at = ? WHERE id = ? AND used_at IS NULL').run(nowIso(), c.id).changes === 1;
  const normAccount = (a) => String(a || '').trim().toLowerCase().replace(/^@/, '').replace(/@dustforge\.com$/i, '');
  const startMessage = (account, nonce) => `demipass:recovery-start:${account}:${nonce}`;
  const completeMessage = (did, id, nonce) => `demipass:recovery-complete:${did}:${id}:${nonce}`;

  // POST /api/identity/recovery/challenge {account} → {challenge, message}; the new phone signs message + ":" + device_id
  // with both its new keys.
  app.post('/api/identity/recovery/challenge', rateLimitStrict, (req, res) => {
    const account = normAccount((req.body || {}).account);
    if (!/^[a-z0-9._-]{1,64}$/.test(account)) return res.status(400).json({ error: 'account: your DemiPass username' });
    const nonce = newChallenge('start', account, '');
    res.json({ ok: true, challenge: nonce, message: startMessage(account, nonce) });
  });

  // POST /api/identity/recovery/start {account, challenge, device_id, label, key_d, key_p, sig_d, sig_p}
  app.post('/api/identity/recovery/start', rateLimitStrict, (req, res) => {
    const b = req.body || {};
    const account = normAccount(b.account);
    const c = findChallenge(b.challenge, 'start');
    if (!c || c.account !== account) return res.status(403).json({ error: 'start challenge missing, used or expired — ask for a new one' });
    if (typeof b.device_id !== 'string' || !/^[A-Za-z0-9_-]{8,64}$/.test(b.device_id)) return res.status(400).json({ error: 'device_id: 8–64 of A-Z a-z 0-9 _ -' });
    const D = devices();
    if (!D.verifySig(b.key_d, startMessage(account, c.nonce) + ':' + b.device_id, b.sig_d) || !D.verifySig(b.key_p, startMessage(account, c.nonce) + ':' + b.device_id, b.sig_p) || b.key_d === b.key_p) {
      return res.status(403).json({ error: 'each new key must sign the start challenge (message + ":" + device_id)' });
    }
    const w = db.prepare('SELECT did, username, status FROM identity_wallets WHERE lower(username) = ?').get(account);
    if (!w || w.status !== 'active') return res.status(404).json({ error: 'no such account' });
    if (db.prepare('SELECT 1 FROM device_keys WHERE device_id = ? LIMIT 1').get(b.device_id)) return res.status(409).json({ error: 'that device id is already known — the app makes a new one each time' });
    if (!spend(c)) return res.status(403).json({ error: 'start challenge already used' });
    // Limits (design H4): several open at once (each bound to its own key and code), so junk starts never block a
    // real one; only starts a guardian approved count toward the weekly limit; and a global daily cap.
    const open = db.prepare(`SELECT COUNT(*) AS n FROM account_holds WHERE did = ? AND kind = 'recovery' AND ${OPEN}`).get(w.did).n;
    if (open >= OPEN_PER_ACCOUNT) return res.status(429).json({ error: 'too many recoveries are waiting for this account' });
    const approvedWeek = db.prepare("SELECT payload, status, note FROM account_holds WHERE did = ? AND kind = 'recovery' AND created_at > ?").all(w.did, isoAgo(7 * 86400))
      .filter(h => h.note === 'approved' || Object.keys(parse(h.payload).approvals || {}).length).length;
    if (approvedWeek >= APPROVED_STARTS_PER_WEEK) return res.status(429).json({ error: 'too many recoveries this week for this account' });
    if (db.prepare("SELECT COUNT(*) AS n FROM account_holds WHERE kind = 'recovery' AND created_at > ?").get(isoAgo(86400)).n >= GLOBAL_STARTS_PER_DAY) return res.status(429).json({ error: 'try again later' });
    const G = guardians();
    const snapshot = G.activeSet(w.did).map(r => r.guardian_did).filter(d => G.isActiveGuardian(w.did, d));
    const code = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
    const label = String(b.label || 'new phone').replace(/[\u0000-\u001f\u007f]/g, ' ').slice(0, 60);
    const h = holds().createHold(w.did, 'recovery', {}, { readyAt: null, expiresAt: isoIn(PENDING_TTL_SEC), why: `onto a new phone "${label}"` });
    savePayload(h.id, { device_id: b.device_id, label, key_d: b.key_d, key_p: b.key_p, code_hash: codeHash(h.id, code), misses: 0, guardians: snapshot, approvals: {}, start_ip: String(req.ip || '').slice(0, 64) });
    for (const g of snapshot) tellDid(g, `${w.username} asks you to help recover their wallet`, `${w.username} asks to get back into their DemiPass wallet on a new phone.\nApprove ONLY if ${w.username} told you the code themselves — in person, or on a call you started to a number you already had. Open the DemiPass app (Settings → Guardians).\nIf you did not hear from them, decline: it stops the recovery.\n`);
    logSecurityEvent('recovery_started', 'critical', { caller_did: w.did, capability: 'recovery', ip: req.ip, context: { hold_id: h.id, guardians: snapshot.length } });
    // The same answer whether or not the account has guardians (L1): the starter cannot tell.
    res.status(202).json({ ok: true, request_id: h.id, code, fingerprint: keyPrint(b.key_d), expires_at: h.expires_at,
      note: 'tell this code to each of your guardians yourself — in person or by voice. Two of them must approve; then 48 hours later you can finish here, unless one of your phones cancels it.' });
  });

  // GET /api/identity/recovery/status?id=&challenge-free — the new phone polls its request (no session; the id is a
  // 12-digit random). Says only the state and when it can finish — never who the guardians are.
  app.get('/api/identity/recovery/status', rateLimitStandard, (req, res) => {
    const h = getReq(req.query.id);
    if (!h) return res.status(404).json({ error: 'no such request' });
    const p = parse(h.payload);
    res.json({ ok: true, status: h.status, approvals: Object.keys(p.approvals || {}).length, needed: QUORUM, ready_at: h.ready_at, expires_at: h.expires_at });
  });

  // ── guardians ──────────────────────────────────────────────────────────────────────────────────────────────────
  function guardianAuth(req, res) {
    const auth = getBearerIdentity(req);
    if (!auth.ok) { res.status(auth.status || 401).json({ error: auth.error }); return null; }
    if (auth.silicon || (auth.decoded && (auth.decoded.wrk || auth.decoded.auth_method === 'fleet_owner_mint'))) { res.status(403).json({ error: 'guardians decide in the app, not with an agent token' }); return null; }
    return auth;
  }
  // The guardian may act on this request: in its snapshot and still an eligible guardian of the owner.
  function mineToDecide(h, did) {
    const p = parse(h.payload);
    return (p.guardians || []).includes(did) && guardians().isActiveGuardian(h.did, did);
  }
  // Design M2: a guardian's own account recently changed is not the shortcut to someone else's wallet.
  function guardianTooFresh(did, startedAt) {
    const newest = db.prepare('SELECT MAX(enrolled_at) AS at FROM device_keys WHERE did = ? AND revoked_at IS NULL').get(did);
    if (newest && newest.at && (Date.parse(newest.at) > Date.now() - 7 * 86400 * 1000 || Date.parse(newest.at) > Date.parse(startedAt))) return 'a phone was linked to your wallet in the last 7 days';
    const ev = db.prepare("SELECT event_type FROM demipass_security_events WHERE caller_did = ? AND event_type IN ('password_reset', 'recovery_email_changed', 'devices_revoked', 'device_enrolled') AND created_at > ? LIMIT 1").get(did, sqlAgo(7 * 86400));
    if (ev) return 'your own account changed in the last 7 days (' + ev.event_type.replace(/_/g, ' ') + ')';
    return null;
  }
  const validApprovals = (h) => Object.keys(parse(h.payload).approvals || {}).filter(g => mineToDecide(h, g));
  // Recount after a change: quorum starts the clock; falling below it stops the clock.
  function recount(h) {
    const cur = getReq(h.id); if (!cur || !['pending', 'quorum'].includes(cur.status)) return cur;
    const n = validApprovals(cur).length;
    if (n >= QUORUM && cur.status === 'pending') {
      const ready = isoIn(DELAY_SEC);
      db.prepare("UPDATE account_holds SET status = 'quorum', ready_at = ?, expires_at = ?, note = 'approved' WHERE id = ? AND status = 'pending'").run(ready, new Date(Date.parse(ready) + COMPLETE_WINDOW_SEC * 1000).toISOString(), cur.id);
      logSecurityEvent('recovery_quorum', 'critical', { caller_did: cur.did, capability: 'recovery', context: { hold_id: cur.id, ready_at: ready } });
      holds().tellOwner(cur.did, 'two guardians approved a recovery of your wallet — cancel it from your phone if it was not you',
        `Two of your guardians approved a recovery of your wallet onto a new phone. It can complete at ${ready} unless one of your phones cancels it.\nIf this was not you: open DemiPass on a linked phone now and cancel it.\n`);
    } else if (n < QUORUM && cur.status === 'quorum') {
      db.prepare("UPDATE account_holds SET status = 'pending', ready_at = NULL, expires_at = ? WHERE id = ? AND status = 'quorum'").run(new Date(Date.parse(cur.created_at) + PENDING_TTL_SEC * 1000).toISOString(), cur.id);
    }
    return getReq(h.id);
  }

  // GET /api/identity/recovery/asks — requests the signed-in guardian may decide on. Owner name and times only.
  app.get('/api/identity/recovery/asks', rateLimitStandard, (req, res) => {
    const auth = guardianAuth(req, res); if (!auth) return;
    const rows = db.prepare(`SELECT * FROM account_holds WHERE kind = 'recovery' AND ${OPEN} AND payload LIKE ?`).all(`%${auth.did}%`)
      .filter(h => mineToDecide(h, auth.did));
    res.json({ ok: true, asks: rows.map(h => { const p = parse(h.payload); return {
      id: h.id, owner: nameOf(h.did), status: h.status, started_at: h.created_at, ready_at: h.ready_at, new_phone: { label: p.label, code: keyPrint(p.key_d) },
      i_approved: Boolean((p.approvals || {})[auth.did]), intent: `recovery-approve:${h.id}` }; }) });
  });

  // POST /api/identity/recovery/:id/approve {code} — PIN (recovery-approve:<id>) + the guardian's phone (D).
  app.post('/api/identity/recovery/:id/approve', rateLimitStandard, (req, res) => {
    const auth = guardianAuth(req, res); if (!auth) return;
    const h = getReq(req.params.id);
    if (!h || !['pending', 'quorum'].includes(h.status) || !mineToDecide(h, auth.did)) return res.status(404).json({ error: 'no recovery for you to decide by that id' });
    const p = parse(h.payload);
    if ((p.approvals || {})[auth.did]) return res.status(409).json({ error: 'you already approved it' });
    const fresh = guardianTooFresh(auth.did, h.created_at);
    if (fresh) return res.status(403).json({ error: `you cannot approve a recovery right now: ${fresh}` });
    const code = String((req.body || {}).code || '').trim();
    if (!/^\d{6}$/.test(code)) return res.status(400).json({ error: 'code: the 6 digits the owner told you' });
    const intent = `recovery-approve:${h.id}`;
    if (!gateFresh(auth.did, 'pin', auth, intent)) return res.status(403).json({ ...gateMissing('recovery-approve', ['pin'], ['pin'], intent), error: 'approving a recovery needs your PIN' });
    // The code is checked before the phone signs (a wrong code must count even without a signature).
    const right = crypto.timingSafeEqual(Buffer.from(codeHash(h.id, code), 'hex'), Buffer.from(p.code_hash, 'hex'));
    if (!right) {
      let canceled = false;
      db.transaction(() => {
        const cur = getReq(h.id); if (!cur || !['pending', 'quorum'].includes(cur.status)) return;
        const q = parse(cur.payload); q.misses = (q.misses || 0) + 1; savePayload(cur.id, q);
        if (q.misses >= MAX_CODE_MISSES) {
          db.prepare(`UPDATE account_holds SET status = 'canceled', canceled_by = 'wrong codes', canceled_at = ?, payload = '{}' WHERE id = ? AND ${OPEN}`).run(nowIso(), cur.id);
          canceled = true;
        }
      }).immediate();
      logSecurityEvent('recovery_code_mismatch', 'alert', { caller_did: h.did, capability: 'recovery', ip: req.ip, context: { hold_id: h.id, guardian: nameOf(auth.did) } });
      if (canceled) {
        holds().tellOwner(h.did, 'a recovery of your wallet was stopped', 'Your guardians entered 3 wrong codes for a recovery of your wallet, so it was canceled. Nothing changed.\n');
        return res.status(403).json({ error: 'that is not the code — 3 wrong codes: the recovery is canceled', canceled: true });
      }
      return res.status(403).json({ error: 'that is not the code the owner has on their new phone' });
    }
    const refused = devices().approvalRefusal(auth, 'recovery-approve', h.id, `${h.id}|${keyPrint(p.key_d)}|${code}`, req.body);
    if (refused) return res.status(refused.status).json(refused.body);
    try {
      db.transaction(() => {
        const spent = spendSingleUse(auth.did, 'recovery-approve', ['pin'], auth, intent);
        if (spent) throw Object.assign(new Error(spent.error), { statusCode: spent.status || 403, body: spent });
        const cur = getReq(h.id);
        if (!cur || !['pending', 'quorum'].includes(cur.status)) throw Object.assign(new Error('this recovery ended meanwhile'), { statusCode: 409 });
        const q = parse(cur.payload); q.approvals = q.approvals || {}; q.approvals[auth.did] = { at: nowIso() }; savePayload(cur.id, q);
      }).immediate();
    } catch (e) { return res.status(e.statusCode || 500).json(e.body || { error: e.message }); }
    logSecurityEvent('recovery_approved_by_guardian', 'critical', { caller_did: h.did, capability: 'recovery', ip: req.ip, context: { hold_id: h.id, guardian: nameOf(auth.did) } });
    holds().tellOwner(h.did, `${nameOf(auth.did)} approved a recovery of your wallet`, `${nameOf(auth.did)}, one of your guardians, approved a recovery of your wallet onto a new phone. If this was not you, cancel it from one of your phones now.\n`);
    const now = recount(h);
    res.json({ ok: true, approved: true, status: now.status, ready_at: now.ready_at });
  });

  // POST /api/identity/recovery/:id/decline — a guardian stops it, in any phase (design L2). Their PIN.
  app.post('/api/identity/recovery/:id/decline', rateLimitStandard, (req, res) => {
    const auth = guardianAuth(req, res); if (!auth) return;
    const h = getReq(req.params.id);
    if (!h || !['pending', 'quorum'].includes(h.status) || !mineToDecide(h, auth.did)) return res.status(404).json({ error: 'no recovery for you to decide by that id' });
    const intent = `recovery-approve:${h.id}`;
    if (!gateFresh(auth.did, 'pin', auth, intent)) return res.status(403).json({ ...gateMissing('recovery-approve', ['pin'], ['pin'], intent), error: 'declining needs your PIN' });
    const spent = spendSingleUse(auth.did, 'recovery-approve', ['pin'], auth, intent);
    if (spent) return res.status(spent.status || 403).json(spent);
    const n = db.prepare(`UPDATE account_holds SET status = 'canceled', canceled_by = ?, canceled_at = ?, payload = '{}' WHERE id = ? AND ${OPEN}`).run('guardian ' + nameOf(auth.did), nowIso(), h.id).changes;
    if (!n) return res.status(409).json({ error: 'this recovery ended meanwhile' });
    logSecurityEvent('recovery_declined', 'critical', { caller_did: h.did, capability: 'recovery', context: { hold_id: h.id, guardian: nameOf(auth.did) } });
    holds().tellOwner(h.did, 'a guardian stopped a recovery of your wallet', `${nameOf(auth.did)} declined a recovery of your wallet, so it was canceled. Nothing changed.\n`);
    res.json({ ok: true, declined: true });
  });

  // POST /api/identity/recovery/:id/withdraw — a guardian takes back their approval.
  app.post('/api/identity/recovery/:id/withdraw', rateLimitStandard, (req, res) => {
    const auth = guardianAuth(req, res); if (!auth) return;
    const h = getReq(req.params.id);
    if (!h || !['pending', 'quorum'].includes(h.status) || !(parse(h.payload).approvals || {})[auth.did]) return res.status(404).json({ error: 'nothing of yours to withdraw' });
    withdrawApproval(h.did, auth.did, h.id);
    const now = getReq(h.id);
    res.json({ ok: true, withdrawn: true, status: now.status, ready_at: now.ready_at });
  });
  function withdrawApproval(owner, guardian, onlyId) {
    for (const h of db.prepare(`SELECT * FROM account_holds WHERE did = ? AND kind = 'recovery' AND ${OPEN}`).all(owner)) {
      if (onlyId && h.id !== onlyId) continue;
      const p = parse(h.payload);
      if (!(p.approvals || {})[guardian]) continue;
      delete p.approvals[guardian]; savePayload(h.id, p);
      recount(h);
    }
  }

  // ── completion (the new phone) ─────────────────────────────────────────────────────────────────────────────────
  app.post('/api/identity/recovery/:id/complete-challenge', rateLimitStrict, (req, res) => {
    const h = getReq(req.params.id);
    if (!h || h.status !== 'quorum' || parse(h.payload).device_id !== String((req.body || {}).device_id || '')) return res.status(404).json({ error: 'not ready to complete from this phone' });
    const nonce = newChallenge('complete', '', h.id);
    res.json({ ok: true, challenge: nonce, message: completeMessage(h.did, h.id, nonce), ready_at: h.ready_at });
  });

  app.post('/api/identity/recovery/:id/complete', rateLimitStrict, async (req, res) => {
    const b = req.body || {};
    const h = getReq(req.params.id);
    const c = findChallenge(b.challenge, 'complete');
    if (!h || !c || c.hold_id !== h.id) return res.status(404).json({ error: 'not ready to complete from this phone' });
    const p = parse(h.payload);
    const msg = completeMessage(h.did, h.id, c.nonce);
    if (p.device_id !== String(b.device_id || '') || !devices().verifySig(p.key_d, msg, b.sig_d) || !devices().verifySig(p.key_p, msg, b.sig_p)) {
      return res.status(403).json({ error: 'not signed by the new phone of this recovery' });
    }
    if (typeof b.new_password !== 'string' || b.new_password.length < 8 || b.new_password.length > 128) return res.status(400).json({ error: 'new_password: 8–128 characters' });
    if (h.status !== 'quorum' || !h.ready_at) return res.status(409).json({ error: 'two guardians have not approved it' });
    if (Date.parse(h.ready_at) > Date.now()) return res.status(409).json({ error: 'the 48 hours are not over', ready_at: h.ready_at });
    if (validApprovals(h).length < QUORUM) { recount(h); return res.status(409).json({ error: 'fewer than two guardians still stand behind it' }); }
    if (!spend(c)) return res.status(404).json({ error: 'not ready to complete from this phone' });
    // Claimed for completion: from here no cancel can land (the 48 hours are over), so the mailbox password is never
    // changed for a recovery that then gets canceled.
    if (db.prepare("UPDATE account_holds SET status = 'completing' WHERE id = ? AND status = 'quorum'").run(h.id).changes !== 1) return res.status(409).json({ error: 'this recovery ended meanwhile' });
    let newHash;
    try { newHash = await deps.hashPassword(b.new_password); } catch (_) { newHash = null; }
    const mail = newHash ? await deps.setMailboxPassword(h.did, newHash).catch(() => 'unknown') : 'unreached';
    if (mail !== 'ok') {
      db.prepare("UPDATE account_holds SET status = 'quorum' WHERE id = ? AND status = 'completing'").run(h.id);
      if (mail === 'unknown') { try { db.prepare('UPDATE identity_wallets SET password_hash = NULL WHERE did = ?').run(h.did); } catch (_) {} }
      return res.status(503).json({ error: 'the mail password could not be set — nothing else changed; try again', retry: true });
    }
    let report;
    try { report = finish(h, p, newHash); }
    catch (e) {
      console.error('[recovery] completion failed after the mailbox password changed:', e.message);
      db.prepare("UPDATE account_holds SET status = 'failed', note = ? WHERE id = ? AND status = 'completing'").run(String(e.message).slice(0, 200), h.id);
      return res.status(500).json({ error: 'the recovery could not finish — contact support' });
    }
    res.json({ ok: true, completed: true, device_id: p.device_id, next: 'set a new PIN (with the new password); your wallet is on this phone now', ...report });
  });

  // Design H5: everything in one transaction, after the mailbox password changed.
  function finish(h, p, newHash) {
    const did = h.did, t = nowIso(), D = devices(), H = holds(), CD = cryptoDepth();
    const out = {};
    db.transaction(() => {
      const cur = getReq(h.id);
      if (!cur || cur.status !== 'completing') throw new Error('state changed');
      // 1. every earlier phone and its wraps; phones waiting to be linked or removed
      D.revokeAll(did, 'social recovery', 'recovery');
      // 2. every session, refresh chain, device-flow code
      deps.cutSessions(did);
      // 3. agents registered in the last 30 days are cut (as a password reset does); the rest listed
      out.agents_cut = db.prepare("SELECT agent_name FROM silicon_agents WHERE carbon_did = ? AND status = 'active' AND created_at > datetime('now', '-30 days')").all(did).map(r => r.agent_name);
      db.prepare("UPDATE silicon_agents SET status = 'revoked' WHERE carbon_did = ? AND status = 'active' AND created_at > datetime('now', '-30 days')").run(did);
      // 4. delegations and scopes granted in the last 30 days are suspended (the owner re-enables them one by one)
      out.delegations_suspended = db.prepare("UPDATE demipass_delegations SET status = 'suspended' WHERE owner_did = ? AND status = 'active' AND COALESCE(offer_state, '') = '' AND granted_at > datetime('now', '-30 days')").run(did).changes;
      out.scopes_suspended = db.prepare("UPDATE blindkey_contexts SET status = 'suspended' WHERE status = 'active' AND created_at > datetime('now', '-30 days') AND secret_id IN (SELECT id FROM blindkey_secrets WHERE did = ?)").run(did).changes;
      // 5. everything waiting: approvals, transfers, share offers, other holds; unwrap sessions
      db.prepare("UPDATE use_approvals SET status = 'cancelled', decided_at = ?, unwrap_blob = NULL WHERE owner_did = ? AND status IN ('pending', 'approved')").run(t, did);
      try { db.prepare("UPDATE secret_transfers SET status = 'cancelled' WHERE (from_did = ? OR to_did = ?) AND status = 'pending'").run(did, did); } catch (_) {}
      db.prepare("UPDATE demipass_delegations SET status = 'revoked' WHERE owner_did = ? AND offer_state = 'offered' AND status = 'suspended'").run(did);
      for (const k of ['pin-reset', 'enrol', 'email', 'unlink', 'guardians']) H.closeOpen(did, k, 'social recovery completed');
      db.prepare(`UPDATE account_holds SET status = 'canceled', canceled_by = 'another recovery completed', canceled_at = ?, payload = '{}' WHERE did = ? AND kind = 'recovery' AND id != ? AND ${OPEN}`).run(t, did, h.id);
      if (CD && CD.dropOwnerSessions) CD.dropOwnerSessions(did);
      // 6. a recovery email changed in the last 30 days goes back to the one before
      const firstChange = db.prepare('SELECT email FROM recovery_email_history WHERE did = ? AND replaced_at > ? ORDER BY replaced_at ASC LIMIT 1').get(did, isoAgo(30 * 86400));
      if (firstChange) { db.prepare('UPDATE identity_wallets SET recovery_email = ? WHERE did = ?').run(firstChange.email, did); out.recovery_email_restored = true; }
      // 7–8. the lock time, the password (the mailbox has it already), the PIN cleared (the app sets a new one)
      db.prepare("UPDATE identity_wallets SET lock_after_sec = ?, password_hash = ?, password_must_change = 0, pin_hash = NULL, pin_failures = 0, pin_locked_until = NULL, pin_lock_count = 0, updated_at = CURRENT_TIMESTAMP WHERE did = ?")
        .run(D.LOCK_DEFAULT, newHash, did);
      // 9. the new phone
      const r = D.activateEnrolment(did, { device_id: p.device_id, label: p.label, key_d: p.key_d, key_p: p.key_p });
      if (!r.ok) throw new Error(r.error);
      db.prepare("UPDATE account_holds SET status = 'completed', completed_at = ?, payload = '{}', note = 'completed' WHERE id = ?").run(t, h.id);
    }).immediate();
    // 10. the wrapped secrets that cannot be opened any more (names only), and everyone told
    const lost = db.prepare("SELECT name FROM blindkey_secrets WHERE did = ? AND status = 'active' AND encrypted_value = ?").all(did, (cryptoDepth() || {}).MARKER || 'dpwrap:v1').map(r => r.name);
    out.wrapped_lost = lost;
    logSecurityEvent('recovery_completed', 'critical', { caller_did: did, capability: 'recovery', context: { hold_id: h.id, approvals: validApprovals({ ...h, payload: JSON.stringify(p) }).length } });
    const contacts = db.prepare("SELECT did_a, did_b FROM network_peers WHERE (did_a = ? OR did_b = ?) AND status = 'active' AND verified_via = 'qr' AND verified_at > ?").all(did, did, isoAgo(30 * 86400)).map(r => nameOf(r.did_a === did ? r.did_b : r.did_a));
    holds().tellOwner(did, 'your wallet was recovered onto a new phone',
      `Your wallet was recovered onto a new phone ("${p.label}") with the approval of two of your guardians. Every earlier phone and session was signed out.\n` +
      (out.agents_cut.length ? `Agents registered in the last 30 days were cut: ${out.agents_cut.join(', ')}.\n` : '') +
      (out.delegations_suspended || out.scopes_suspended ? `${out.delegations_suspended} delegation(s) and ${out.scopes_suspended} scope(s) granted in the last 30 days are suspended until you re-enable them.\n` : '') +
      (contacts.length ? `People paired with you in person in the last 30 days: ${contacts.join(', ')} — check you know them.\n` : '') +
      (lost.length ? `These elevated/critical secrets were locked to your old phones and can no longer be opened: ${lost.join(', ')}. Rotate each at its source, then store the new value.\n` : '') +
      'If this was not you, contact DemiPass support now.\n');
    for (const g of parse(h.payload).guardians || []) tellDid(g, `${nameOf(did)}'s wallet was recovered`, `The recovery of ${nameOf(did)}'s wallet that you were asked about has completed.\n`);
    return out;
  }

  // A recovery canceled from the owner's phone: guardians who were asked are told it is over.
  function onCanceled(h) {
    const p = parse(h.payload);
    for (const g of p.guardians || []) tellDid(g, `the recovery of ${nameOf(h.did)}'s wallet was canceled`, 'Nothing to do.\n');
  }
  return { withdrawApproval, onCanceled, QUORUM };
};
