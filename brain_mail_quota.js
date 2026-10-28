'use strict';

// Operator-authorized independent allowance. This is a public identity, NOT a
// credential. Match the authenticated account, never sender/body/username input.
const BRAIN_DID = 'did:key:u7QHYCTlNRSP7ifl6V_ZZOtL-QqyTaLsoKfD4srVnD9UjkQ';
const DAILY_LIMIT = 36;

// Return true when this request belongs to Brain (including refusals); false
// leaves the pre-existing communal warmup guard in control. Authentication and
// scope/revocation checks must precede this guard; paid billing follows it.
function brainMailQuota(db, req, res, next, now = Date.now()) {
  if (req.identity?.did !== BRAIN_DID) return false;
  const day = new Date(now).toISOString().slice(0, 10);
  try {
    db.exec(`CREATE TABLE IF NOT EXISTS email_identity_daily (
      day TEXT NOT NULL, did TEXT NOT NULL, sent INTEGER NOT NULL CHECK(sent >= 0),
      PRIMARY KEY(day, did)
    )`);
    const reserved = db.transaction(() => {
      db.prepare('INSERT INTO email_identity_daily(day, did, sent) VALUES (?, ?, 0) ON CONFLICT(day, did) DO NOTHING').run(day, BRAIN_DID);
      return db.prepare('UPDATE email_identity_daily SET sent = sent + 1 WHERE day = ? AND did = ? AND sent < ?').run(day, BRAIN_DID, DAILY_LIMIT).changes === 1;
    })();
    if (!reserved) {
      res.status(429).json({ error: 'daily identity mail cap reached', day, limit: DAILY_LIMIT });
      return true;
    }
    // Preserve existing warmup semantics: definitive failed responses release a
    // slot. A crash/disconnect without a response retains it conservatively.
    res.once('finish', () => {
      if (res.statusCode >= 400) {
        try {
          db.prepare('UPDATE email_identity_daily SET sent = MAX(0, sent - 1) WHERE day = ? AND did = ?').run(day, BRAIN_DID);
        } catch (error) {
          console.error('[email] identity reservation release failed:', error.message);
        }
      }
    });
  } catch (error) {
    console.error('[email] identity quota unavailable:', error.message);
    res.status(503).json({ error: 'identity mail quota unavailable' });
    return true;
  }
  next();
  return true;
}

module.exports = { brainMailQuota, BRAIN_DID, DAILY_LIMIT };
