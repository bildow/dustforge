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

// Return true when this request belongs to Brain (including refusals); false
// leaves the pre-existing communal warmup guard in control. Authentication,
// scope/revocation checks AND request validation must precede this guard (a
// malformed call takes no slot); paid billing follows it.
function brainMailQuota(db, req, res, next, now = Date.now()) {
  if (req.identity?.did !== BRAIN_DID) return false;
  const day = new Date(now).toISOString().slice(0, 10);
  try {
    ensureTable(db);
    const reserved = db.transaction(() => {
      db.prepare('INSERT INTO email_identity_daily(day, did, sent) VALUES (?, ?, 0) ON CONFLICT(day, did) DO NOTHING').run(day, BRAIN_DID);
      return db.prepare('UPDATE email_identity_daily SET sent = sent + 1 WHERE day = ? AND did = ? AND sent < ?').run(day, BRAIN_DID, DAILY_LIMIT).changes === 1;
    })();
    if (!reserved) {
      res.status(429).json({ error: 'daily identity mail cap reached', day, limit: DAILY_LIMIT, remaining: 0 });
      return true;
    }
    // A failed answer gives the slot back — released before the answer is written (so the remaining count in its
    // header is exact), and on 'finish' as a fallback. A crash/disconnect without a response keeps it conservatively.
    let released = false;
    req.mailSlot = {
      release() {
        if (released) return; released = true;
        try { db.prepare('UPDATE email_identity_daily SET sent = MAX(0, sent - 1) WHERE day = ? AND did = ?').run(day, BRAIN_DID); }
        catch (error) { console.error('[email] identity reservation release failed:', error.message); }
      },
    };
    res.once('finish', () => { if (res.statusCode >= 400) req.mailSlot.release(); });
  } catch (error) {
    console.error('[email] identity quota unavailable:', error.message);
    res.status(503).json({ error: 'identity mail quota unavailable' });
    return true;
  }
  next();
  return true;
}

module.exports = { brainMailQuota, brainRemaining, BRAIN_DID, DAILY_LIMIT };
