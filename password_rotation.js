'use strict';
// ── Account password: one lock per account, and the blind rotation (POST /api/identity/password/rotate-blind) ────────
// The lock: rotate-blind, reset-password and guardian-recovery completion each change the account hash AND the
// Stalwart mailbox secret. Two at once could leave them split (#69 review M1), so each takes the account's lock (a
// claim row with an expiry) before reading the mailbox, and releases it when done.
//
// The rotation: a random password nobody sees becomes the account password and the mailbox password.
//   1. Plan (before anything changes): which vault entries hold the OLD account or OLD mailbox password, by value. Only
//      entries clearly tied to THIS account move (#69 review H1): fill origin demipass.com / dustforge.com, fill
//      username = this username or address, provider demipass / dustforge / stalwart, a name starting dustforge- /
//      demipass- / stalwart- / account-password-. Any other entry with the same value is a reused password for some other
//      service: it is named back as a candidate and never touched. Wrapped / elevated / frozen copies are named.
//   2. A pending row is written BEFORE the mailbox changes (#69 review M2): the new password (blindkey-encrypted), the
//      prior mailbox secret, the new hash, the plan. A crash, a timeout or a late answer from the mail server can then
//      never lose the new password or leave the two split: the sweep (at start and every 5 minutes) re-reads the
//      mailbox and settles the row.
//   3. PATCH the mailbox; settle: the mailbox holds the new hash → account hash + vault entries in one transaction (each
//      entry re-selected by id, still active with the same ciphertext); it holds the prior → nothing changed; neither or
//      unreachable → left pending for the sweep (never reported as "nothing changed").
// Moved entries keep the old value for ROTATE_GRACE_MIN (days, not a minute: a reused value somewhere may need it back).
const crypto = require('crypto');

const LOCK_TTL_SEC = 180;
const ROTATE_GRACE_MIN = 3 * 24 * 60;
// A pending row is the sweep's only once it is older than any request the mail server could still be working on: the
// PATCH times out at 10 s (setMailboxPasswordHash), so never before 15 s (#69 round-2 P3), whatever a test asks for.
// Test knobs are read only under NODE_ENV=test: in production a stray .env line can neither stall the scan nor make every
// pending row abandon on its first sweep (#69 round-3 review).
const TEST_ENV = process.env.NODE_ENV === 'test' ? process.env : {};
const SWEEP_AFTER_SEC = Math.max(15, Number(TEST_ENV.PW_ROTATE_SWEEP_AFTER_SEC || 120));
const MAX_ATTEMPTS = Math.max(1, Number(TEST_ENV.PW_ROTATE_MAX_ATTEMPTS || 288));    // ≈ 24 h of 5-minute sweeps
const MAX_PENDING_SEC = Number(TEST_ENV.PW_ROTATE_MAX_PENDING_SEC || 2 * 86400);
const SWEEP_EVERY_MS = Number(TEST_ENV.PW_ROTATE_SWEEP_MS || 5 * 60 * 1000);   // tests shorten both
// Exactly the hosts where THIS account's password is typed (#69 round-2 L-a): not every subdomain — repo.dustroot.com is
// Forgejo, with accounts of its own.
const TIED_HOSTS = new Set(['demipass.com', 'www.demipass.com', 'dustforge.com', 'www.dustforge.com', 'api.dustforge.com', 'mail.dustforge.com']);
const TIED_PROVIDERS = new Set(['demipass', 'dustforge', 'stalwart']);
const TIED_NAME = /^(dustforge|demipass|stalwart|account-password)-/i;

module.exports = function registerPasswordRotation(deps) {
  const { app, db, rateLimitStrict, getBearerIdentity, gateSession, gateFresh, gateMissing, spendSingleUse, logSecurityEvent,
          passwords, fetchStalwartSecret, setMailboxPasswordHash, blindkeyDecrypt, blindkeyEncrypt, rotateSecretValue,
          rotatingSecrets, generateRefCode, cutSessions, devices, sendMail, storedOrigins } = deps;
  const nowIso = () => new Date().toISOString();
  const sha = (s) => crypto.createHash('sha256').update(String(s || '')).digest('hex');

  db.exec(`CREATE TABLE IF NOT EXISTS account_password_locks (
    did TEXT PRIMARY KEY, holder TEXT NOT NULL, claimed_at TEXT NOT NULL, expires_at TEXT NOT NULL)`);
  db.exec(`CREATE TABLE IF NOT EXISTS account_password_rotations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    did TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',   -- pending | done | failed
    fresh_enc TEXT,                           -- the new password, blindkey-encrypted; wiped when settled
    prior TEXT,                               -- the mailbox secret before (NULL: no mailbox)
    new_hash TEXT NOT NULL,
    old_hash TEXT,                            -- identity_wallets.password_hash before
    plan TEXT NOT NULL,
    report TEXT,
    attempts INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    settled_at TEXT
  )`);
  db.exec("CREATE INDEX IF NOT EXISTS idx_apr_pending ON account_password_rotations(status, did)");

  // ── the lock ───────────────────────────────────────────────────────────────────────────────────────────────────
  function claim(did, holder, ttlSec = LOCK_TTL_SEC) {
    return db.transaction(() => {
      db.prepare('DELETE FROM account_password_locks WHERE did = ? AND expires_at < ?').run(did, nowIso());
      const r = db.prepare('INSERT OR IGNORE INTO account_password_locks (did, holder, claimed_at, expires_at) VALUES (?, ?, ?, ?)')
        .run(did, holder, nowIso(), new Date(Date.now() + ttlSec * 1000).toISOString());
      return r.changes === 1;
    }).immediate();
  }
  function release(did, holder) { try { db.prepare('DELETE FROM account_password_locks WHERE did = ? AND holder = ?').run(did, holder); } catch (_) {} }
  // A rotation still pending blocks other password changes too: its new password may already be the mailbox's.
  function pendingFor(did) { return db.prepare("SELECT id FROM account_password_rotations WHERE did = ? AND status = 'pending' LIMIT 1").get(did); }
  // Rotation and reset also wait while a guardian recovery is part-way through completing: it may still put its prior
  // mailbox secret back, which would undo either (#69 round-2 L-e).
  function blockedFor(did) {
    if (pendingFor(did)) return true;
    try { return Boolean(db.prepare("SELECT 1 FROM account_holds WHERE did = ? AND kind = 'recovery' AND status = 'completing' LIMIT 1").get(did)); } catch (_) { return false; }
  }
  // Keep holding the lock through a long step; false when it was lost (expired and taken) — the caller stops (L-b).
  function renew(did, holder, ttlSec = LOCK_TTL_SEC) {
    return db.prepare('UPDATE account_password_locks SET expires_at = ? WHERE did = ? AND holder = ?')
      .run(new Date(Date.now() + ttlSec * 1000).toISOString(), did, holder).changes === 1;
  }
  const BUSY = { error: 'a password change on this account is still settling — try again in a few minutes', busy: true };

  // ── what counts as this account's own entry ───────────────────────────────────────────────────────────────────
  function tie(s, wallet) {
    let origins = []; try { origins = storedOrigins ? storedOrigins(s.fill_origins) : JSON.parse(s.fill_origins || '[]'); } catch (_) { origins = []; }
    const hostOf = (o) => { try { return new URL(o).hostname; } catch (_) { return ''; } };
    if (origins.length && origins.every(o => TIED_HOSTS.has(hostOf(o).toLowerCase()))) return 'fill origin';
    // A fill username alone ties nothing (the same username exists on other services): only with one of the rules here.
    if (!origins.length && TIED_PROVIDERS.has(String(s.provider || '').toLowerCase())) return 'provider';
    if (!origins.length && TIED_NAME.test(String(s.name || '').replace(/_v\d+$/, ''))) return 'name';
    return null;
  }

  // ── settling a rotation row (inline and from the sweep) ───────────────────────────────────────────────────────
  // `mailbox` = what the mail server holds now ({state, secret}). Returns {status:'done'|'failed'|'pending', report?}.
  async function settle(row, mailbox, { fromSweep = false } = {}) {
    const plan = JSON.parse(row.plan || '{}');
    const fail = (why) => {
      db.prepare("UPDATE account_password_rotations SET status = 'failed', fresh_enc = NULL, settled_at = ?, report = ? WHERE id = ? AND status = 'pending'")
        .run(nowIso(), JSON.stringify({ why }), row.id);
      return { status: 'failed', why };
    };
    if (row.prior !== null && row.prior !== undefined) {
      if (mailbox.state === 'absent') { /* the principal is gone: nothing left to split — the account follows */ }
      else if (mailbox.state !== 'ok') { bump(row); return { status: 'pending' }; }
      else if (mailbox.secret === row.prior) {
        // The old secret is showing. Inline that proves nothing (a timed-out PATCH may still land): stay pending. The
        // sweep, past every timeout, writes the old secret back once — so a PATCH arriving even later is overwritten
        // in order, not after the decision — and only then calls it failed (#69 round-2 P3).
        if (!fromSweep) { bump(row); return { status: 'pending' }; }
        const put = await setMailboxPasswordHash(row.did, row.prior).catch(() => 'unknown');
        if (put !== 'ok') { bump(row); return { status: 'pending' }; }
        const again = await fetchStalwartSecret(plan.username).catch(() => ({ state: 'unreachable' }));
        if (again.state !== 'ok' || again.secret !== row.prior) { bump(row); return { status: 'pending' }; }
        return fail('the mail server kept the old password');
      }
      if (mailbox.state === 'ok' && mailbox.secret !== row.new_hash) {
        // Someone else changed the mailbox meanwhile (should not happen under the lock). DemiPass follows the account:
        // the mailbox gets the account's current hash, and this rotation ends.
        const cur = db.prepare('SELECT password_hash FROM identity_wallets WHERE did = ?').get(row.did) || {};
        if (cur.password_hash) await setMailboxPasswordHash(row.did, cur.password_hash).catch(() => 'unknown');
        logSecurityEvent('password_rotate_mailbox_foreign', 'critical', { caller_did: row.did, capability: 'pw-rotate', context: { rotation: row.id } });
        return fail('the mailbox changed under the rotation; it was set back to the account password');
      }
    }
    // The mailbox holds the new password (or there is none): the account and the vault follow, together.
    let fresh; try { fresh = blindkeyDecrypt(row.fresh_enc); } catch (_) { fresh = null; }
    if (!fresh) return fail('the pending password could not be read');
    const report = { secrets_moved: [], not_moved: [], stored_as: null };
    const taken = [];
    try {
      db.transaction(() => {
        const w = db.prepare('SELECT password_hash, username FROM identity_wallets WHERE did = ?').get(row.did) || {};
        if ((w.password_hash || '') !== (row.old_hash || '') && w.password_hash !== row.new_hash) throw Object.assign(new Error('the account password changed meanwhile'), { changed: true });
        db.prepare('UPDATE identity_wallets SET password_hash = ?, password_must_change = 0 WHERE did = ?').run(row.new_hash, row.did);
        for (const m of plan.moved || []) {
          // Re-selected by id: still active, still the same ciphertext as when it was planned (#69 review L2).
          const s = db.prepare("SELECT * FROM blindkey_secrets WHERE id = ? AND did = ? AND status = 'active'").get(m.id, row.did);
          if (!s || sha(s.encrypted_value) !== m.ct || rotatingSecrets.has(s.id)) { report.not_moved.push({ name: m.name, why: 'changed since the rotation began' }); continue; }
          rotatingSecrets.add(s.id); taken.push(s.id);
          const r = rotateSecretValue(row.did, s, fresh, ROTATE_GRACE_MIN, null);
          if (r.status !== 200) throw new Error(`could not rotate ${s.name}: ${r.body.error}`);
          report.secrets_moved.push({ name: s.name, new_name: r.body.new_name, ref: s.ref_code || null, matched: m.matched, tie: m.tie });
        }
        if (!report.secrets_moved.length) {
          const base = `account-password-${w.username || 'wallet'}`.slice(0, 80);
          const name = db.prepare('SELECT 1 FROM blindkey_secrets WHERE did = ? AND name = ?').get(row.did, base) ? `${base}-${Date.now()}` : base;
          const ref = generateRefCode('password', name);
          db.prepare(`INSERT INTO blindkey_secrets (did, name, description, secret_type, encrypted_value, metadata, status, version, ref_code, category, provider)
                      VALUES (?, ?, ?, 'password', ?, '{}', 'active', 1, ?, 'account', 'demipass')`)
            .run(row.did, name, 'Account + mailbox password, set by a blind rotation', blindkeyEncrypt(fresh), ref);
          report.stored_as = { name, ref };
        }
        // Exactly this pending row becomes done, or nothing happened (two sweeps, or a sweep and the route) (L-d).
        if (db.prepare("UPDATE account_password_rotations SET status = 'done', fresh_enc = NULL, settled_at = ?, report = ? WHERE id = ? AND status = 'pending'")
          .run(nowIso(), JSON.stringify(report), row.id).changes !== 1) throw Object.assign(new Error('settled elsewhere'), { already: true });
      }).immediate();
    } catch (e) {
      if (e.already) return { status: 'done-elsewhere' };
      // Nothing in DemiPass changed. Put the mailbox back — only if it still holds OUR new hash; if the account's
      // password changed meanwhile, the mailbox gets that one instead (#69 review M1).
      const now = row.prior === null ? { state: 'absent' } : await fetchStalwartSecret(plan.username).catch(() => ({ state: 'unreachable' }));
      const cur = db.prepare('SELECT password_hash FROM identity_wallets WHERE did = ?').get(row.did) || {};
      let back = row.prior === null;
      if (now.state === 'ok' && now.secret === row.new_hash) {
        const target = e.changed && cur.password_hash ? cur.password_hash : row.prior;
        back = (await setMailboxPasswordHash(row.did, target).catch(() => 'unknown')) === 'ok';
      } else if (now.state === 'ok') back = true;   // it no longer holds ours: nothing of this rotation is left there
      if (back) { fail(e.message); return { status: 'failed', why: e.message }; }
      bump(row);
      logSecurityEvent('password_rotate_unsettled', 'critical', { caller_did: row.did, capability: 'pw-rotate', context: { rotation: row.id, error: String(e.message).slice(0, 120) } });
      return { status: 'pending', why: e.message };
    } finally { for (const id of taken) rotatingSecrets.delete(id); fresh = null; }
    return { status: 'done', report };
  }
  // A row that never settles (the mail server gone for days) must not block every password change for ever (L-c). Its
  // new password may be the mailbox's now, so it is not thrown away: it goes into the owner's vault, named for what it
  // is, and the owner and the operator are told.
  function abandon(row, plan) {
    let fresh = null; try { fresh = blindkeyDecrypt(row.fresh_enc); } catch (_) {}
    db.transaction(() => {
      if (fresh) {
        const name = `account-password-unconfirmed-${plan.username || 'wallet'}-${row.id}`.slice(0, 100);
        db.prepare(`INSERT INTO blindkey_secrets (did, name, description, secret_type, encrypted_value, metadata, status, version, ref_code, category, provider)
                    VALUES (?, ?, ?, 'password', ?, '{}', 'active', 1, ?, 'account', 'demipass')`)
          .run(row.did, name, 'A blind rotation could not confirm whether the mail server took this password: it may be your mail password now', blindkeyEncrypt(fresh), generateRefCode('password', name));
      }
      db.prepare("UPDATE account_password_rotations SET status = 'abandoned', fresh_enc = NULL, settled_at = ?, report = ? WHERE id = ? AND status = 'pending'")
        .run(nowIso(), JSON.stringify({ why: 'never settled', attempts: row.attempts }), row.id);
    })();
    fresh = null;
    logSecurityEvent('password_rotate_abandoned', 'critical', { caller_did: row.did, capability: 'pw-rotate', context: { rotation: row.id, attempts: row.attempts } });
    try {
      const w = db.prepare('SELECT email, recovery_email FROM identity_wallets WHERE did = ?').get(row.did) || {};
      const to = w.recovery_email || w.email;
      if (to && sendMail) Promise.resolve(sendMail({ to, subject: 'DemiPass: a password rotation could not be confirmed',
        text: 'A blind rotation of your account password could not be confirmed with the mail server. Your account password is unchanged; your mail password may be the new one, which is in your vault as account-password-unconfirmed-…\nContact DemiPass support if mail sign-in fails.\n' })).catch(() => {});
    } catch (_) {}
  }
  function bump(row) { try { db.prepare('UPDATE account_password_rotations SET attempts = attempts + 1 WHERE id = ?').run(row.id); } catch (_) {} }

  // The sweep: every pending row not being worked on right now is settled from what the mailbox holds.
  async function sweep() {
    const rows = db.prepare("SELECT * FROM account_password_rotations WHERE status = 'pending' AND created_at < ?").all(new Date(Date.now() - SWEEP_AFTER_SEC * 1000).toISOString());
    for (const row of rows) {
      const holder = 'sweep:' + row.id;
      if (!claim(row.did, holder)) continue;
      try {
        const cur = db.prepare("SELECT * FROM account_password_rotations WHERE id = ? AND status = 'pending'").get(row.id);   // re-read under the lock (L-d)
        if (!cur) continue;
        const plan = JSON.parse(cur.plan || '{}');
        if (cur.attempts >= MAX_ATTEMPTS || Date.parse(cur.created_at) < Date.now() - MAX_PENDING_SEC * 1000) { abandon(cur, plan); continue; }
        const mb = cur.prior === null ? { state: 'absent' } : await fetchStalwartSecret(plan.username).catch(() => ({ state: 'unreachable' }));
        const r = await settle(cur, mb, { fromSweep: true });
        if (r.status !== 'pending') logSecurityEvent('password_rotate_settled_by_sweep', 'alert', { caller_did: row.did, capability: 'pw-rotate', context: { rotation: row.id, status: r.status } });
      } catch (e) { console.error('[pw-rotate] sweep:', e.message); }
      finally { release(row.did, holder); }
    }
  }
  const t0 = setTimeout(() => sweep().catch(() => {}), Math.min(20 * 1000, SWEEP_EVERY_MS)); if (t0.unref) t0.unref();
  const t = setInterval(() => sweep().catch(() => {}), SWEEP_EVERY_MS); if (t.unref) t.unref();

  // ── the route ──────────────────────────────────────────────────────────────────────────────────────────────────
  app.post('/api/identity/password/rotate-blind', rateLimitStrict, async (req, res) => {
    const auth = getBearerIdentity(req);
    if (!auth.ok) return res.status(auth.status || 401).json({ error: auth.error });
    const d = auth.decoded || {};
    // The owner's own sign-in only: no agent token of any kind — fleet-minted, worker, silicon, an agent's device login
    // or anything carrying an agent label (#69 review L1).
    if (auth.silicon || d.wrk || ['fleet_owner_mint', 'worker', 'device'].includes(d.auth_method) || d.agent_label || d.agent_name) {
      logSecurityEvent('password_rotate_denied', 'critical', { caller_did: auth.did, capability: 'pw-rotate', ip: req.ip, error: 'agent token' });
      return res.status(403).json({ error: 'only the owner, in their own session, rotates the account password' });
    }
    if (auth.scope !== 'transact' && auth.scope !== 'admin' && auth.scope !== 'full') return res.status(403).json({ error: 'transact scope required' });
    if (!gateSession(auth)) return res.status(403).json({ error: 'sign in again' });
    const did = auth.did, intent = 'pw-rotate:0';
    if (!gateFresh(did, 'pin', auth, intent)) return res.status(403).json(gateMissing('pw-rotate', ['pin'], ['pin'], intent));
    const dk = devices();
    if (dk) { const r = dk.approvalRefusal(auth, 'pw-rotate', 0, 'account-password', req.body); if (r) return res.status(r.status).json(r.body); }
    if (blockedFor(did)) return res.status(409).json(BUSY);
    const holder = 'rotate:' + crypto.randomBytes(6).toString('hex');
    if (!claim(did, holder)) return res.status(409).json(BUSY);
    let rowId = null;
    try {
      const refused = spendSingleUse(did, 'pw-rotate', ['pin'], auth, intent);
      if (refused) return res.status(refused.status || 403).json(refused);
      const wallet = db.prepare('SELECT * FROM identity_wallets WHERE did = ?').get(did);
      if (!wallet) return res.status(404).json({ error: 'identity not found' });
      const m = wallet.username ? await fetchStalwartSecret(wallet.username) : { state: 'absent' };
      if (m.state === 'unreachable') return res.status(503).json({ error: 'the mail server cannot be reached — nothing changed; try again', retry: true });
      const prior = m.state === 'ok' ? m.secret : null;
      // An app password ($app$…) in the mailbox is a different credential: never matched against the vault (H1).
      const priorComparable = prior && !String(prior).startsWith('$app$') ? prior : null;

      // 1. the plan
      const rows = db.prepare(`SELECT * FROM blindkey_secrets WHERE did = ? AND status = 'active'
        AND (ref_code LIKE 'DP-PWD-%' OR secret_type IN ('password', 'passphrase'))`).all(did);
      const plan = { username: wallet.username, moved: [], candidates: [], skipped: [] };
      for (const s of rows) {
        const depth = s.security_depth === 'elevated' || s.security_depth === 'critical' ? s.security_depth : 'standard';
        if (s.wrap_state === 'device') { plan.skipped.push({ name: s.name, ref: s.ref_code || null, why: 'wrapped to your phone: the server cannot read it to compare' }); continue; }
        let v; try { v = blindkeyDecrypt(s.encrypted_value); } catch (_) { continue; }
        if (typeof v !== 'string' || !v || v.length > 512) continue;
        const acct = wallet.password_hash ? (await passwords.verifyPassword(v, wallet.password_hash)).ok === true : false;
        const mail = priorComparable ? (await passwords.verifyPassword(v, priorComparable, { stalwart: true })).ok === true : false;
        v = null;
        if (!acct && !mail) continue;
        const matched = acct && mail ? 'account+mailbox' : acct ? 'account' : 'mailbox';
        if (s.frozen) { plan.skipped.push({ name: s.name, ref: s.ref_code || null, why: 'frozen' }); continue; }
        if (depth !== 'standard') { plan.skipped.push({ name: s.name, ref: s.ref_code || null, why: `${depth}: rotated only through its own approval` }); continue; }
        const why = tie(s, wallet);
        if (!why) { plan.candidates.push({ name: s.name, ref: s.ref_code || null }); continue; }
        plan.moved.push({ id: s.id, ct: sha(s.encrypted_value), name: s.name, ref: s.ref_code || null, matched, tie: why });
      }

      // (tests only: stretch the scan, to show a lock lost meanwhile stops the rotation)
      if (Number(TEST_ENV.PW_ROTATE_SCAN_PAUSE_MS) > 0) await new Promise(r => setTimeout(r, Number(TEST_ENV.PW_ROTATE_SCAN_PAUSE_MS)));
      // 2. the pending row, before anything outside DemiPass changes — still holding the lock (the scan can be long)
      const fresh = crypto.randomBytes(24).toString('base64url');
      const newHash = await passwords.hashPassword(fresh);
      if (!renew(did, holder) || blockedFor(did)) return res.status(409).json({ ...BUSY, error: 'the rotation lost its lock while comparing your vault — nothing changed; try again' });
      rowId = Number(db.prepare(`INSERT INTO account_password_rotations (did, status, fresh_enc, prior, new_hash, old_hash, plan, created_at)
                                 VALUES (?, 'pending', ?, ?, ?, ?, ?, ?)`).run(did, blindkeyEncrypt(fresh), prior, newHash, wallet.password_hash || null, JSON.stringify(plan), nowIso()).lastInsertRowid);

      // 3. the mailbox, then settle from what it holds
      let mb = { state: 'absent' };
      if (prior !== null) {
        const st = await setMailboxPasswordHash(did, newHash).catch(() => 'unknown');
        if (st === 'unreached') {
          // Never connected: the mail server received nothing. Safe to end here.
          db.prepare("UPDATE account_password_rotations SET status = 'failed', fresh_enc = NULL, settled_at = ?, report = ? WHERE id = ? AND status = 'pending'")
            .run(nowIso(), JSON.stringify({ why: 'mail server unreachable' }), rowId);
          return res.status(503).json({ error: 'the mail server cannot be reached — nothing changed; try again', retry: true });
        }
        mb = st === 'ok' ? { state: 'ok', secret: newHash } : await fetchStalwartSecret(wallet.username).catch(() => ({ state: 'unreachable' }));
        renew(did, holder);
      }
      const row = db.prepare('SELECT * FROM account_password_rotations WHERE id = ?').get(rowId);
      const r = await settle(row, mb);
      if (r.status === 'done-elsewhere') return res.status(202).json({ ok: false, pending: false, rotation_id: rowId, error: 'this rotation was settled by the background check; see your vault' });
      if (r.status === 'failed') return res.status(503).json({ error: `not rotated: ${r.why} — nothing changed; try again`, retry: true });
      if (r.status === 'pending') {
        return res.status(202).json({ ok: false, pending: true, rotation_id: rowId,
          error: 'the mail server did not answer clearly. The new password is held (encrypted) and the change settles within minutes, one way or the other — nothing is lost, and the account and mailbox end on the same password.' });
      }
      const rep = r.report;
      logSecurityEvent('account_password_rotated', 'info', { caller_did: did, capability: 'pw-rotate', ip: req.ip, context: { rotation: rowId, moved: rep.secrets_moved.map(x => x.name), candidates: plan.candidates.length } });
      try { db.prepare('INSERT INTO blindkey_events (event_type, actor, secret_id, detail) VALUES (?, ?, ?, ?)').run('account_password_rotated', did, null,
        JSON.stringify({ rotation: rowId, moved: rep.secrets_moved.map(x => x.ref || x.name), stored_as: rep.stored_as && rep.stored_as.ref })); } catch (_) {}
      const cut = (req.body || {}).cut_sessions === true;
      if (cut) { try { cutSessions(did); } catch (_) {} }
      const to = wallet.recovery_email || wallet.email;
      if (to && sendMail) try { Promise.resolve(sendMail({ to, subject: 'DemiPass: your account password was rotated',
        text: 'Your DemiPass account password (and mail password) was just replaced with a new random one that nobody has seen. It is in your vault' +
          (rep.secrets_moved.length ? ': ' + rep.secrets_moved.map(x => x.name).join(', ') : rep.stored_as ? ': ' + rep.stored_as.name : '') +
          '.\nSign in with an emailed code or your phone. If this was not you, contact DemiPass support now.\n' })).catch(() => {}); } catch (_) {}
      const stillOld = [...plan.candidates, ...plan.skipped.filter(x => !/wrapped/.test(x.why))].map(x => x.name);
      res.json({ ok: true, rotated: true, rotation_id: rowId, mailbox: prior === null ? 'no mailbox' : 'changed',
        secrets_moved: rep.secrets_moved, ...(rep.stored_as ? { stored_as: rep.stored_as } : {}), not_moved: rep.not_moved,
        candidates: plan.candidates.map(x => x.name), skipped: plan.skipped,
        still_hold_old_password: stillOld,
        note_candidates: plan.candidates.length ? 'these hold the same value but look like other services (a reused password): left unchanged — change them there' : undefined,
        sessions: cut ? 'cut: every session was signed out, this one too' : 'kept: you and your agents stay signed in (send cut_sessions:true to sign out everywhere)',
        old_value_kept_days: ROTATE_GRACE_MIN / 1440,
        sign_in: 'with an emailed code, or your linked phone; the password itself is only in your vault' });
    } catch (e) {
      console.error('[pw-rotate]', e.message);
      if (!res.headersSent) res.status(500).json({ error: 'the rotation failed: ' + e.message + (rowId ? ' — it is held pending and settles within minutes' : ' — nothing changed') });
    } finally { release(did, holder); }
  });

  return { claim, release, renew, pendingFor, blockedFor, sweep, BUSY, tie };
};
