'use strict';
// ── Recovery guardians (red team item 9, step 2) ─────────────────────────────────────────────────────────────────────
// Design: tome decisions/2026-11-07-demipass-item9-social-recovery-design.md (v1.1) § Setup — guardians.
//
// An owner with a linked phone names exactly 3 guardians: person wallets (never agents), paired with the owner IN
// PERSON by QR (verified_via = 'qr' — a vouch is not enough: a guardian is the one link that can hand over the whole
// wallet), each with a linked phone of their own. Naming takes the owner's PIN and phone; each guardian accepts with
// their PIN and phone. The set is active only when all 3 have accepted.
//
// Changing (or removing) an active set is an account hold of kind 'guardians' (account_holds.js): 48 hours,
// cancelable from any eligible phone of the owner, told to the owner and to old and new guardians. The new guardians
// are invited when the change starts and must all have accepted by the time it applies; it is re-checked then.
// A guardian may leave at once (the safe direction: recovery only gets harder); the owner is told.
// A guardian learns the owner's name and that they are a guardian — never secrets, balances or the other guardians.

const SET_SIZE = 3;

module.exports = function registerGuardians(deps) {
  const { app, db, rateLimitStandard, getBearerIdentity, gateFresh, gateMissing, spendSingleUse, logSecurityEvent, sendMail } = deps;
  const devices = () => deps.devices();
  const holds = () => deps.holds();

  // recovery_guardians is created by account_holds.js (the last-phone guard reads it); step 2 adds the change link.
  try { db.exec('ALTER TABLE recovery_guardians ADD COLUMN change_id TEXT'); } catch (_) {}
  db.exec('CREATE INDEX IF NOT EXISTS idx_recovery_guardians_owner ON recovery_guardians(owner_did, status)');
  db.exec('CREATE INDEX IF NOT EXISTS idx_recovery_guardians_guardian ON recovery_guardians(guardian_did, status)');

  const nowIso = () => new Date().toISOString();
  const nameOf = (did) => { const w = db.prepare('SELECT username FROM identity_wallets WHERE did = ?').get(did); return w ? w.username : null; };
  const isAgentWallet = (did) => Boolean(db.prepare("SELECT 1 FROM fleet_silicons WHERE member_did = ? AND status = 'active'").get(did));
  const pairedInPerson = (x, y) => { const [a, b] = x < y ? [x, y] : [y, x];
    return Boolean(db.prepare("SELECT 1 FROM network_peers WHERE did_a = ? AND did_b = ? AND status = 'active' AND verified_via = 'qr'").get(a, b)); };
  function tell(did, subject, text) {
    try { const w = db.prepare('SELECT email FROM identity_wallets WHERE did = ?').get(did); if (w && w.email && sendMail) Promise.resolve(sendMail({ to: w.email, subject: 'DemiPass: ' + subject, text })).catch(() => {}); } catch (_) {}
  }

  // The owner's or guardian's own sign-in (not an agent), a PIN set. Returns auth or null (answer sent).
  function personAuth(req, res) {
    const auth = getBearerIdentity(req);
    if (!auth.ok) { res.status(auth.status || 401).json({ error: auth.error }); return null; }
    if (auth.silicon || (auth.decoded && (auth.decoded.wrk || auth.decoded.auth_method === 'fleet_owner_mint')) || isAgentWallet(auth.did)) {
      res.status(403).json({ error: 'guardians are set and accepted by the person, in the app' }); return null;
    }
    const w = db.prepare('SELECT status, pin_hash FROM identity_wallets WHERE did = ?').get(auth.did);
    if (!w || w.status !== 'active') { res.status(403).json({ error: 'no active wallet for this token' }); return null; }
    if (!w.pin_hash) { res.status(403).json({ error: 'set your vault PIN first', pin_required: true }); return null; }
    return auth;
  }
  // Why `did` cannot guard `owner`, or null.
  const NOT_PAIRED = 'a guardian must be someone you paired with in person (Fleet → Pair in person); an introduction is not enough';
  // Pairing is checked first and every "no" before it is the same answer, so this route does not tell who exists or
  // who is an agent (#60 review L3). Specific reasons only about people the owner paired with.
  function ineligible(owner, did) {
    if (did && did === owner) return 'you cannot be your own guardian';
    if (!did || !pairedInPerson(owner, did)) return NOT_PAIRED;
    const w = db.prepare('SELECT status FROM identity_wallets WHERE did = ?').get(did);
    if (!w || w.status !== 'active' || isAgentWallet(did)) return NOT_PAIRED;
    if (!devices().hasDevice(did)) return 'a guardian needs a phone linked in their DemiPass app';
    return null;
  }
  function resolve(owner, who) {
    const s = String(who || '').trim();
    if (!s) return null;
    const w = s.startsWith('did:') ? db.prepare('SELECT did FROM identity_wallets WHERE did = ?').get(s)
      : db.prepare('SELECT did FROM identity_wallets WHERE username = ?').get(s.replace(/^@/, '').replace(/@dustforge\.com$/i, ''));
    return w ? w.did : null;
  }
  const activeSet = (owner) => db.prepare("SELECT * FROM recovery_guardians WHERE owner_did = ? AND status = 'active' AND change_id IS NULL ORDER BY id").all(owner);
  const invitedFor = (owner, changeId) => db.prepare(`SELECT * FROM recovery_guardians WHERE owner_did = ? AND status IN ('invited', 'accepted') AND ${changeId ? 'change_id = ?' : 'change_id IS NULL'} ORDER BY id`).all(...(changeId ? [owner, changeId] : [owner]));
  // Activate the first set once all 3 have accepted.
  function maybeActivate(owner) {
    const rows = invitedFor(owner, null);
    if (rows.length === SET_SIZE && rows.every(r => r.status === 'accepted') && !activeSet(owner).length && rows.every(r => !ineligible(owner, r.guardian_did))) {
      db.prepare("UPDATE recovery_guardians SET status = 'active' WHERE owner_did = ? AND status = 'accepted' AND change_id IS NULL").run(owner);
      logSecurityEvent('guardians_active', 'warn', { caller_did: owner, capability: 'guardians' });
      tell(owner, 'your recovery guardians are set', `All three accepted: ${rows.map(r => nameOf(r.guardian_did)).join(', ')}.\nIf you lose every phone, two of them together can let you back in after 48 hours — and any of your phones can stop it.\n`);
      return true;
    }
    return false;
  }

  // GET /api/identity/guardians — mine (names and states) and the people I guard (owner names only).
  app.get('/api/identity/guardians', rateLimitStandard, (req, res) => {
    const auth = getBearerIdentity(req); if (!auth.ok) return res.status(auth.status || 401).json({ error: auth.error });
    if (auth.silicon) return res.json({ ok: true, guardians: [], guarding: [] });
    const mine = db.prepare("SELECT id, guardian_did, status, change_id, invited_at, accepted_at FROM recovery_guardians WHERE owner_did = ? AND status IN ('invited', 'accepted', 'active') ORDER BY id").all(auth.did);
    const theirs = db.prepare("SELECT id, owner_did, status, change_id, invited_at FROM recovery_guardians WHERE guardian_did = ? AND status IN ('invited', 'accepted', 'active') ORDER BY id").all(auth.did);
    const change = holds().openHolds(auth.did, 'guardians')[0];
    // "active" means recovery would work now: three active guardians, each still eligible (paired, a person, a phone).
    const set = activeSet(auth.did);
    res.json({ ok: true, active: set.length === SET_SIZE && set.every(r => !ineligible(auth.did, r.guardian_did)),
      guardians: mine.map(r => ({ id: r.id, name: nameOf(r.guardian_did), status: r.status, pending_change: Boolean(r.change_id), invited_at: r.invited_at, accepted_at: r.accepted_at,
        ...(r.status === 'active' ? { eligible: !ineligible(auth.did, r.guardian_did) } : {}) })),
      change: change ? holds().view(change) : null,
      guarding: theirs.map(r => ({ id: r.id, owner: nameOf(r.owner_did), status: r.status, intent: `guardian-accept:${r.id}` })) });
  });

  // POST /api/identity/guardians {guardians: [3 names or DIDs]} — the owner's PIN (guardian-set:0) + phone.
  // No set yet: invites them. An active set: starts the 48-hour change. {guardians: []} removes the set (48 h).
  app.post('/api/identity/guardians', rateLimitStandard, (req, res) => {
    const auth = personAuth(req, res); if (!auth) return;
    const owner = auth.did;
    const list = (req.body || {}).guardians;
    if (!Array.isArray(list) || (list.length !== SET_SIZE && list.length !== 0)) return res.status(400).json({ error: `guardians: exactly ${SET_SIZE} people (or [] to remove them)` });
    if (!devices().hasDevice(owner)) return res.status(409).json({ error: 'link your phone first: guardians are set from it, and any of your phones can stop a recovery' });
    const dids = list.map(x => resolve(owner, x));
    const known = dids.filter(Boolean);   // unknown names fall through to the one "not paired" answer (#60 re-review L3)
    if (new Set(known).size !== known.length) return res.status(400).json({ error: 'three different people' });
    for (let i = 0; i < dids.length; i++) { const why = ineligible(owner, dids[i]); if (why) return res.status(409).json({ error: `${String(list[i]).slice(0, 60)}: ${why}` }); }
    const active = activeSet(owner);
    if (!active.length && !dids.length) return res.status(409).json({ error: 'you have no guardians to remove' });
    const H = holds();
    const stop = H.startRefusal(owner, 'guardians');
    if (stop) return res.status(stop.status).json(stop.body);
    if (H.openHolds(owner, 'guardians').length) return res.status(409).json({ error: 'a change of your guardians is already waiting' });
    const intent = 'guardian-set:0';
    if (!gateFresh(owner, 'pin', auth, intent)) return res.status(403).json({ ...gateMissing('guardian-set', ['pin'], ['pin'], intent), error: 'setting guardians needs your PIN' });
    const bind = [...dids].sort().map(d => `${nameOf(d)}=${d}`).join(',');
    const refused = devices().approvalRefusal(auth, 'guardian-set', 0, bind, req.body);
    if (refused) return res.status(refused.status).json(refused.body);
    const spent = spendSingleUse(owner, 'guardian-set', ['pin'], auth, intent);
    if (spent) return res.status(spent.status || 403).json(spent);
    const t = nowIso();
    // A first set (nothing active): invite at once; an invitation not yet complete is replaced.
    if (!active.length) {
      const dropped = invitedFor(owner, null).filter(r => !dids.includes(r.guardian_did));
      db.transaction(() => {
        db.prepare("UPDATE recovery_guardians SET status = 'removed', removed_at = ?, why = 'replaced before it was complete' WHERE owner_did = ? AND status IN ('invited', 'accepted') AND change_id IS NULL").run(t, owner);
        for (const d of dids) db.prepare("INSERT INTO recovery_guardians (owner_did, guardian_did, status, invited_at) VALUES (?, ?, 'invited', ?)").run(owner, d, t);
      })();
      for (const d of dids) tell(d, `${nameOf(owner)} asks you to be a recovery guardian`, `${nameOf(owner)} named you one of three people who can help them back into their DemiPass wallet if they lose every phone.\nAccept or decline in the DemiPass app (Settings → Guardians). You will never see their secrets or balance.\n`);
      for (const r of dropped) tell(r.guardian_did, `${nameOf(owner)} withdrew their guardian invitation`, 'You are not one of their recovery guardians. Nothing to do.\n');
      tell(owner, 'you named recovery guardians', `You asked ${dids.map(nameOf).join(', ')} to be your recovery guardians. They become active when all three accept.\nIf this was not you, someone has your PIN and phone: act now.\n`);
      logSecurityEvent('guardians_invited', 'warn', { caller_did: owner, capability: 'guardians', ip: req.ip });
      return res.status(201).json({ ok: true, invited: dids.map(nameOf), note: 'active when all three accept' });
    }
    // An active set: the change waits 48 hours (cancelable from any phone of the owner).
    const h = H.createHold(owner, 'guardians', { guardians: dids }, { why: dids.length ? 'new guardians: ' + dids.map(nameOf).join(', ') : 'remove your guardians' });
    // Guardians who stay are carried over as accepted; only people new to the set have to accept.
    db.transaction(() => { for (const d of dids) {
      const stays = active.some(r => r.guardian_did === d);
      db.prepare("INSERT INTO recovery_guardians (owner_did, guardian_did, status, invited_at, accepted_at, change_id) VALUES (?, ?, ?, ?, ?, ?)").run(owner, d, stays ? 'accepted' : 'invited', t, stays ? t : null, h.id);
    } })();
    for (const r of active) tell(r.guardian_did, `${nameOf(owner)} is changing their recovery guardians`, `In 48 hours you ${dids.includes(r.guardian_did) ? 'stay' : 'stop being'} one of ${nameOf(owner)}'s recovery guardians, unless they cancel it.\n`);
    for (const d of dids) if (!active.some(r => r.guardian_did === d)) tell(d, `${nameOf(owner)} asks you to be a recovery guardian`, `Accept or decline in the DemiPass app (Settings → Guardians). It takes effect in 48 hours.\n`);
    return res.status(202).json({ ok: true, pending: true, hold_id: h.id, ready_at: h.ready_at, note: 'your guardians change in 48 hours, once all new ones have accepted — any of your phones can cancel it' });
  });

  // POST /api/identity/guardians/:id/accept — the guardian's PIN (guardian-accept:<id>) + phone.
  app.post('/api/identity/guardians/:id/accept', rateLimitStandard, (req, res) => {
    const auth = personAuth(req, res); if (!auth) return;
    const r = db.prepare("SELECT * FROM recovery_guardians WHERE id = ? AND guardian_did = ? AND status = 'invited'").get(Number(req.params.id), auth.did);
    if (!r) return res.status(404).json({ error: 'no invitation by that id' });
    if (!devices().hasDevice(auth.did)) return res.status(409).json({ error: 'link your phone first: a guardian approves from it' });
    if (!pairedInPerson(r.owner_did, auth.did)) return res.status(409).json({ error: 'you are no longer paired in person with them' });
    const intent = `guardian-accept:${r.id}`;
    if (!gateFresh(auth.did, 'pin', auth, intent)) return res.status(403).json({ ...gateMissing('guardian-accept', ['pin'], ['pin'], intent), error: 'accepting needs your PIN' });
    const refused = devices().approvalRefusal(auth, 'guardian-accept', r.id, nameOf(r.owner_did), req.body);
    if (refused) return res.status(refused.status).json(refused.body);
    const spent = spendSingleUse(auth.did, 'guardian-accept', ['pin'], auth, intent);
    if (spent) return res.status(spent.status || 403).json(spent);
    if (db.prepare("UPDATE recovery_guardians SET status = 'accepted', accepted_at = ? WHERE id = ? AND status = 'invited'").run(nowIso(), r.id).changes !== 1) return res.status(409).json({ error: 'this invitation changed meanwhile' });
    tell(r.owner_did, `${nameOf(auth.did)} accepted to be your recovery guardian`, `${nameOf(auth.did)} is now ${r.change_id ? 'ready to become' : 'one of'} your recovery guardians.\n`);
    const active = r.change_id ? false : maybeActivate(r.owner_did);
    res.json({ ok: true, accepted: true, set_active: active });
  });

  // POST /api/identity/guardians/:id/decline — an invitation turned down (the owner is told).
  app.post('/api/identity/guardians/:id/decline', rateLimitStandard, (req, res) => {
    const auth = personAuth(req, res); if (!auth) return;
    const r = db.prepare("SELECT * FROM recovery_guardians WHERE id = ? AND guardian_did = ? AND status IN ('invited', 'accepted')").get(Number(req.params.id), auth.did);
    if (!r) return res.status(404).json({ error: 'no invitation by that id' });
    db.prepare("UPDATE recovery_guardians SET status = 'removed', removed_at = ?, why = 'declined' WHERE id = ?").run(nowIso(), r.id);
    tell(r.owner_did, `${nameOf(auth.did)} declined to be your recovery guardian`, 'Choose someone else in Settings → Guardians.\n');
    res.json({ ok: true, declined: true });
  });

  // POST /api/identity/guardians/:id/leave — a guardian steps down at once (the safe direction). The owner is told;
  // below three, recovery is unavailable until a replacement is in (through the 48-hour change).
  app.post('/api/identity/guardians/:id/leave', rateLimitStandard, (req, res) => {
    const auth = personAuth(req, res); if (!auth) return;
    const r = db.prepare("SELECT * FROM recovery_guardians WHERE id = ? AND guardian_did = ? AND status = 'active'").get(Number(req.params.id), auth.did);
    if (!r) return res.status(404).json({ error: 'you are not their guardian' });
    leave(r.owner_did, auth.did, 'left');
    res.json({ ok: true, left: true });
  });
  // A guardian leaves: every row of theirs for that owner goes, a pending change's too — so a change applying later
  // cannot put them back without their consent (#60 review M1; that change then fails: not all accepted).
  function leave(owner, guardian, why) {
    const n = db.prepare("UPDATE recovery_guardians SET status = 'removed', removed_at = ?, why = ? WHERE owner_did = ? AND guardian_did = ? AND status IN ('invited', 'accepted', 'active')").run(nowIso(), why, owner, guardian).changes;
    if (!n) return 0;
    logSecurityEvent('guardian_left', 'warn', { caller_did: owner, capability: 'guardians', context: { guardian: nameOf(guardian), why } });
    if (deps.onGuardianLeft) { try { deps.onGuardianLeft(owner, guardian); } catch (_) {} }
    tell(owner, `${nameOf(guardian)} is no longer your recovery guardian`, 'Recovery by guardians is unavailable until you name a replacement (Settings → Guardians; it takes 48 hours).\n');
    return n;
  }
  // Removing a contact (network_routes.js), #60 review M2: the owner cannot drop a guardian that way (it would switch
  // recovery off at once, skipping the 48 h) — change the guardians first; a guardian removing the owner leaves.
  function contactRemoval(me, other) {
    if (db.prepare("SELECT 1 FROM recovery_guardians WHERE owner_did = ? AND guardian_did = ? AND status IN ('invited', 'accepted', 'active') LIMIT 1").get(me, other)) {
      return { status: 409, body: { error: 'they are one of your recovery guardians: change your guardians first (Settings → Guardians; it takes 48 hours)' } };
    }
    leave(other, me, 'removed the contact');
    return null;
  }

  // Applying a due 'guardians' hold (account_holds.js calls this). Re-checks everything: every new guardian accepted
  // and still eligible. Throws to fail the hold.
  function applyChange(h, payload) {
    const owner = h.did, dids = Array.isArray(payload.guardians) ? payload.guardians : [];
    const rows = db.prepare("SELECT * FROM recovery_guardians WHERE owner_did = ? AND change_id = ? AND status IN ('invited', 'accepted')").all(owner, h.id);
    if (dids.length) {
      if (rows.length !== SET_SIZE || rows.some(r => r.status !== 'accepted')) throw new Error('not every new guardian accepted in time');
      for (const r of rows) { const why = ineligible(owner, r.guardian_did); if (why) throw new Error(`${nameOf(r.guardian_did)}: ${why}`); }
    }
    const t = nowIso();
    db.prepare("UPDATE recovery_guardians SET status = 'removed', removed_at = ?, why = 'replaced' WHERE owner_did = ? AND status = 'active'").run(t, owner);
    if (dids.length) db.prepare("UPDATE recovery_guardians SET status = 'active', change_id = NULL WHERE owner_did = ? AND change_id = ? AND status = 'accepted'").run(owner, h.id);
  }
  // A 'guardians' hold that ended without applying: its invitations go.
  function dropChange(h) {
    db.prepare("UPDATE recovery_guardians SET status = 'removed', removed_at = ?, why = 'change not applied' WHERE owner_did = ? AND change_id = ? AND status IN ('invited', 'accepted')").run(nowIso(), h.did, h.id);
  }

  // For step 3: the active set (exactly 3), and who may still approve.
  // An active guardian who is still eligible (paired in person, a person wallet, a phone) — what step 3 asks.
  const isActiveGuardian = (owner, did) => Boolean(db.prepare("SELECT 1 FROM recovery_guardians WHERE owner_did = ? AND guardian_did = ? AND status = 'active'").get(owner, did)) && !ineligible(owner, did);
  return { activeSet, ineligible, isActiveGuardian, applyChange, dropChange, contactRemoval, SET_SIZE };
};
