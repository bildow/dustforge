'use strict';

// Operator-authorized independent allowance. This is a public identity, NOT a
// credential. Match the authenticated account, never sender/body/username input.
const BRAIN_DID = 'did:key:u7QHYCTlNRSP7ifl6V_ZZOtL-QqyTaLsoKfD4srVnD9UjkQ';
const DAILY_LIMIT = 36;

function ensureTable(db) {
  db.exec(`CREATE TABLE IF NOT EXISTS email_identity_daily (
    day TEXT NOT NULL, did TEXT NOT NULL, sent INTEGER NOT NULL CHECK(sent >= 0),
    PRIMARY KEY(day, did)
  )`);
}

// What is left of Brain's allowance today (for the X-Mail-Remaining header).
function brainRemaining(db, now = Date.now()) {
  const day = new Date(now).toISOString().slice(0, 10);
  try {
    ensureTable(db);
    const row = db.prepare('SELECT sent FROM email_identity_daily WHERE day = ? AND did = ?').get(day, BRAIN_DID);
    return { scope: 'identity', day, limit: DAILY_LIMIT, remaining: Math.max(0, DAILY_LIMIT - (row ? row.sent : 0)) };
  } catch (_) { return { scope: 'identity', day, limit: DAILY_LIMIT, remaining: null }; }
}

// Reserve one of Brain's daily slots. { ok, release } or { ok: false, status, body }. release() gives it back once.
function reserveBrainSlot(db, now = Date.now()) {
  const day = new Date(now).toISOString().slice(0, 10);
  try {
    ensureTable(db);
    const reserved = db.transaction(() => {
      db.prepare('INSERT INTO email_identity_daily(day, did, sent) VALUES (?, ?, 0) ON CONFLICT(day, did) DO NOTHING').run(day, BRAIN_DID);
      return db.prepare('UPDATE email_identity_daily SET sent = sent + 1 WHERE day = ? AND did = ? AND sent < ?').run(day, BRAIN_DID, DAILY_LIMIT).changes === 1;
    })();
    if (!reserved) return { ok: false, status: 429, body: { error: 'daily identity mail cap reached', day, limit: DAILY_LIMIT, remaining: 0 } };
    let released = false;
    return { ok: true, release() {
      if (released) return; released = true;
      try { db.prepare('UPDATE email_identity_daily SET sent = MAX(0, sent - 1) WHERE day = ? AND did = ?').run(day, BRAIN_DID); }
      catch (error) { console.error('[email] identity reservation release failed:', error.message); }
    } };
  } catch (error) {
    console.error('[email] identity quota unavailable:', error.message);
    return { ok: false, status: 503, body: { error: 'identity mail quota unavailable' } };
  }
}

// Return true when this request belongs to Brain (including refusals); false
// leaves the pre-existing communal warmup guard in control. Authentication,
// scope/revocation checks AND request validation must precede this guard (a
// malformed call takes no slot); paid billing follows it.
function brainMailQuota(db, req, res, next, now = Date.now()) {
  if (req.identity?.did !== BRAIN_DID) return false;
  const slot = reserveBrainSlot(db, now);
  if (!slot.ok) { res.status(slot.status).json(slot.body); return true; }
  // A failed answer gives the slot back — before the answer is written (mailHeaders, so the header is exact) and on
  // 'finish' as a fallback. A crash/disconnect without a response keeps it conservatively.
  req.mailSlot = slot;
  res.once('finish', () => { if (res.statusCode >= 400) slot.release(); });
  next();
  return true;
}

module.exports = { brainMailQuota, reserveBrainSlot, brainRemaining, BRAIN_DID, DAILY_LIMIT };
