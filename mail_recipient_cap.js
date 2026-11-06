'use strict';
// Per-recipient daily bound (Aaron 2026-11-06): no identity sends more than 5 messages to a single recipient per UTC
// day, unless the send goes through an elevated (or critical) secret on an approved request. "35 to one inbox is a
// loop, not correspondence."
//
// Covered: mail the identity originates — POST /api/email/send, POST /api/relay/forward, DemiPass /use smtp_auth on a
// standard-depth secret. Not covered: DemiPass's own notices (noreply@, verify@, …) and the inbound MTA hook forwarding
// third-party mail that arrived in the mailbox (the identity did not write those).
//
// A recipient is counted by its mailbox, not its spelling: lower-cased, display name and +tag dropped, and for Gmail
// the dots too (aaron.x+1@googlemail.com and AaronX@gmail.com are one inbox).

const LIMIT = 5;

function ensureTable(db) {
  db.exec(`CREATE TABLE IF NOT EXISTS email_recipient_daily (
    day TEXT NOT NULL, did TEXT NOT NULL, rcpt TEXT NOT NULL, sent INTEGER NOT NULL CHECK(sent >= 0),
    PRIMARY KEY(day, did, rcpt)
  )`);
}

function canonicalRecipient(addr) {
  let a = String(addr || '').trim();
  const angle = a.match(/<([^<>]+)>\s*$/);
  if (angle) a = angle[1];
  a = a.trim().toLowerCase();
  const at = a.lastIndexOf('@');
  if (at < 1) return a;
  let local = a.slice(0, at), domain = a.slice(at + 1).replace(/\.$/, '');
  local = local.split('+')[0];
  if (domain === 'googlemail.com') domain = 'gmail.com';
  if (domain === 'gmail.com') local = local.replace(/\./g, '');
  return local + '@' + domain;
}

// "a@x, b@y" | ["a@x", "b@y"] → unique canonical recipients.
function recipientList(to) {
  const raw = Array.isArray(to) ? to : String(to || '').split(',');
  return [...new Set(raw.map(x => String(x).trim()).filter(Boolean).map(canonicalRecipient))];
}

const today = (now) => new Date(now).toISOString().slice(0, 10);

// Reserve one send to each recipient, all or none. { ok, release(), remaining } or { ok:false, status, body }.
// remaining = the fewest sends left today among these recipients after this one. release() gives them back once.
function reserveRecipients(db, did, to, now = Date.now()) {
  const rcpts = recipientList(to);
  const day = today(now);
  if (!rcpts.length) return { ok: true, remaining: null, release() {} };
  try {
    ensureTable(db);
    const outcome = db.transaction(() => {
      const get = db.prepare('SELECT sent FROM email_recipient_daily WHERE day = ? AND did = ? AND rcpt = ?');
      let fewest = LIMIT;
      for (const r of rcpts) {
        const row = get.get(day, did, r);
        const sent = row ? row.sent : 0;
        if (sent >= LIMIT) return { full: r };
        fewest = Math.min(fewest, LIMIT - sent - 1);
      }
      const bump = db.prepare('INSERT INTO email_recipient_daily (day, did, rcpt, sent) VALUES (?, ?, ?, 1) ON CONFLICT(day, did, rcpt) DO UPDATE SET sent = sent + 1');
      for (const r of rcpts) bump.run(day, did, r);
      return { fewest };
    })();
    if (outcome.full) {
      return { ok: false, status: 429, body: { error: `daily per-recipient cap reached: ${outcome.full} has had ${LIMIT} messages from this identity today`,
        recipient: outcome.full, day, limit: LIMIT, remaining: 0,
        hint: 'more than 5 a day to one recipient goes through an elevated secret on an approved request (DemiPass /use smtp_auth)' } };
    }
    let released = false;
    return { ok: true, remaining: outcome.fewest, release() {
      if (released) return; released = true;
      try {
        const down = db.prepare('UPDATE email_recipient_daily SET sent = MAX(0, sent - 1) WHERE day = ? AND did = ? AND rcpt = ?');
        db.transaction(() => { for (const r of rcpts) down.run(day, did, r); })();
      } catch (error) { console.error('[email] recipient reservation release failed:', error.message); }
    } };
  } catch (error) {
    console.error('[email] recipient cap unavailable:', error.message);
    return { ok: false, status: 503, body: { error: 'recipient mail cap unavailable' } };
  }
}

// Express guard for routes whose recipients are req.body.to (after validation, before billing). The reservation is
// given back on any failed answer (mailHeaders releases req.rcptSlot before writing; 'finish' is the fallback).
function recipientCapGuard(db) {
  return function (req, res, next) {
    const slot = reserveRecipients(db, req.identity.did, (req.body || {}).to);
    res.setHeader('X-Mail-Recipient-Limit', String(LIMIT));
    if (!slot.ok) {
      if (slot.status === 429) res.setHeader('X-Mail-Recipient-Remaining', '0');
      return res.status(slot.status).json(slot.body);
    }
    req.rcptSlot = slot;
    if (slot.remaining !== null) res.setHeader('X-Mail-Recipient-Remaining', String(slot.remaining));
    res.once('finish', () => { if (res.statusCode >= 400) slot.release(); });
    next();
  };
}

module.exports = { LIMIT, canonicalRecipient, recipientList, reserveRecipients, recipientCapGuard };
