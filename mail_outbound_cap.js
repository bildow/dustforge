'use strict';
// ── Outbound recipients per wallet per UTC day (SPEC 2026-11-16 pane mailboxes v0.2, decision 6 / review 16) ──────────
// A wallet in its first 7 days sends to at most 50 recipients a day; after that, 500. Every recipient of every mail the
// wallet originates counts (POST /api/email/send, POST /api/mail/send, POST /api/relay/forward), whichever pane or
// session sent it. The owner can raise it for a while with a limit lift (limiter `mail_out`, #128): the lift's extra
// recipients are added to today's limit while it is active.
// Reserved before the charge, all or none; given back when the send fails.

const NEW_WALLET_DAYS = 7;
const NEW_WALLET_LIMIT = 50;
const WALLET_LIMIT = 500;

function ensureTable(db) {
  db.exec(`CREATE TABLE IF NOT EXISTS mail_outbound_daily (
    day TEXT NOT NULL, did TEXT NOT NULL, recipients INTEGER NOT NULL CHECK(recipients >= 0),
    PRIMARY KEY(day, did)
  )`);
}

const today = (now) => new Date(now).toISOString().slice(0, 10);

// The wallet's base limit today: 50 while it is under 7 days old (or its age cannot be read), else 500.
function baseLimit(db, did, now = Date.now()) {
  let created = NaN;
  try {
    const w = db.prepare('SELECT created_at FROM identity_wallets WHERE did = ?').get(did);
    if (w && w.created_at) created = Date.parse(/[zZ]|[+-]\d\d:?\d\d$/.test(w.created_at) ? w.created_at : String(w.created_at).replace(' ', 'T') + 'Z');
  } catch (_) { created = NaN; }
  if (!Number.isFinite(created) || now - created < NEW_WALLET_DAYS * 86400000) return { limit: NEW_WALLET_LIMIT, tier: 'new' };
  return { limit: WALLET_LIMIT, tier: 'established' };
}

function sentToday(db, did, now = Date.now()) {
  try { ensureTable(db); const r = db.prepare('SELECT recipients FROM mail_outbound_daily WHERE day = ? AND did = ?').get(today(now), did); return r ? r.recipients : 0; }
  catch (_) { return 0; }
}

// Reserve n recipients for did today. liftExtra: recipients an active `mail_out` lift adds. { ok, release(), limit,
// remaining } or { ok:false, status, body }. Fails closed (503) when the count cannot be kept.
function reserve(db, did, n, { liftExtra = 0, now = Date.now() } = {}) {
  const count = Math.max(0, Math.floor(Number(n) || 0));
  const { limit: base, tier } = baseLimit(db, did, now);
  const limit = base + Math.max(0, Number(liftExtra) || 0);
  const day = today(now);
  if (!count) return { ok: true, limit, remaining: null, release() {} };
  try {
    ensureTable(db);
    const outcome = db.transaction(() => {
      db.prepare('INSERT INTO mail_outbound_daily (day, did, recipients) VALUES (?, ?, 0) ON CONFLICT(day, did) DO NOTHING').run(day, did);
      const sent = db.prepare('SELECT recipients FROM mail_outbound_daily WHERE day = ? AND did = ?').get(day, did).recipients;
      if (sent + count > limit) return { full: true, sent };
      db.prepare('UPDATE mail_outbound_daily SET recipients = recipients + ? WHERE day = ? AND did = ?').run(count, day, did);
      return { sent: sent + count };
    })();
    if (outcome.full) {
      return { ok: false, status: 429, body: {
        error: `daily outbound cap reached: this wallet has sent to ${outcome.sent} of ${limit} recipients today${tier === 'new' ? ` (a wallet's first ${NEW_WALLET_DAYS} days: ${NEW_WALLET_LIMIT} a day)` : ''}; this mail has ${count}`,
        limiter: 'mail_out', day, limit, sent: outcome.sent, remaining: Math.max(0, limit - outcome.sent),
        lift: { limiter: 'mail_out', request: 'POST /api/identity/limits/lift', note: 'extra = recipients added to today\'s limit while the lift is active' } } };
    }
    let released = false;
    return { ok: true, limit, remaining: limit - outcome.sent, release() {
      if (released) return; released = true;
      try { db.prepare('UPDATE mail_outbound_daily SET recipients = MAX(0, recipients - ?) WHERE day = ? AND did = ?').run(count, day, did); }
      catch (e) { console.error('[email] outbound cap release failed:', e.message); }
    } };
  } catch (e) {
    console.error('[email] outbound cap unavailable:', e.message);
    return { ok: false, status: 503, body: { error: 'outbound mail cap unavailable' } };
  }
}

module.exports = { NEW_WALLET_DAYS, NEW_WALLET_LIMIT, WALLET_LIMIT, ensureTable, baseLimit, sentToday, reserve };
