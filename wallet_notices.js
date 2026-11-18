'use strict';
// ── Wallet notices: things about a wallet's DD the owner should hear about (Aaron 2026-11-15) ───────────────────────
// A refill rule that cannot run tells the wallet that pays for it: a card on the app's home, the phone's alerts poll
// (account_holds.js /api/identity/holds/alerts → `notices`, which AlertJob turns into a notification), and an email
// to the wallet's addresses. One notice per (wallet, key) while it is open: the scheduler retries every 5 minutes and
// must not repeat itself. A notice closes when the owner dismisses it, or when the condition clears (a refill of the
// same rule runs, or the wallet is funded again).
//
// kinds
//   refill_failed    a refill rule could not run; when the paying wallet is short, `deposit` says how much it needs
//   refill_capped    a silicon's automatic refills reached their daily cap
//   deposit_due      a card-funded scheduled refill is due: the owner pays it with a deposit (no stored card yet)

const KINDS = new Set(['refill_failed', 'refill_capped', 'deposit_due']);
const OPEN_DAYS = 7;          // an open notice older than this is no longer shown (the scheduler raises it again if it still applies)
const LIST_MAX = 10;

function init(db) {
  db.exec(`CREATE TABLE IF NOT EXISTS wallet_notices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    did TEXT NOT NULL,
    kind TEXT NOT NULL,
    nkey TEXT NOT NULL,
    title TEXT NOT NULL,
    text TEXT NOT NULL,
    data TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    closed_at TEXT,
    closed_why TEXT
  )`);
  db.exec('CREATE INDEX IF NOT EXISTS idx_wallet_notices_open ON wallet_notices(did, closed_at)');
}

const nowIso = (now = Date.now()) => new Date(now).toISOString();
const cutoff = (now = Date.now()) => new Date(now - OPEN_DAYS * 86400000).toISOString();

const DISMISS_QUIET_MS = 24 * 3600 * 1000;   // a dismissed notice stays quiet this long while its condition lasts

// → the new notice row, or null when one with this key is already open, or was dismissed in the last 24 hours (the
// scheduler retries every 5 minutes; a Dismiss must not come back on the next pass — #126 review M3).
function raise(db, did, { kind, key, title, text, data = {} }, { now = Date.now(), mailer = null } = {}) {
  if (!did || !KINDS.has(kind) || !key) return null;
  const open = db.prepare('SELECT id FROM wallet_notices WHERE did = ? AND nkey = ? AND closed_at IS NULL AND created_at > ?').get(did, key, cutoff(now));
  if (open) return null;
  const quiet = db.prepare("SELECT id FROM wallet_notices WHERE did = ? AND nkey = ? AND closed_why = 'dismissed' AND closed_at > ?").get(did, key, nowIso(now - DISMISS_QUIET_MS));
  if (quiet) return null;
  // An open one past the 7-day window is replaced, not left open forever (#126 review L4).
  db.prepare("UPDATE wallet_notices SET closed_at = ?, closed_why = 'superseded' WHERE did = ? AND nkey = ? AND closed_at IS NULL").run(nowIso(now), did, key);
  const id = Number(db.prepare('INSERT INTO wallet_notices (did, kind, nkey, title, text, data, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)')
    .run(did, kind, String(key).slice(0, 200), String(title).slice(0, 120), String(text).slice(0, 1000), JSON.stringify(data || {}), nowIso(now)).lastInsertRowid);
  if (mailer) {
    for (const to of addresses(db, did)) {
      try { Promise.resolve(mailer({ to, subject: 'DemiPass: ' + title, text: text + '\n\nOpen the DemiPass app to deposit DD or change the rule.\n' })).catch(() => {}); } catch (_) {}
    }
  }
  return db.prepare('SELECT * FROM wallet_notices WHERE id = ?').get(id);
}

// The wallet's own mailbox (it follows the owner's forwarding rules) and its recovery address.
function addresses(db, did) {
  const w = db.prepare('SELECT email, recovery_email FROM identity_wallets WHERE did = ?').get(did) || {};
  const seen = new Set(), out = [];
  for (const a of [w.email, w.recovery_email]) { const k = String(a || '').trim().toLowerCase(); if (k && !seen.has(k)) { seen.add(k); out.push(String(a).trim()); } }
  return out;
}

// Close the open notices of this wallet whose key starts with `prefix` (the condition cleared).
function clear(db, did, prefix, why = 'resolved', { now = Date.now() } = {}) {
  if (!did || !prefix) return 0;
  return db.prepare("UPDATE wallet_notices SET closed_at = ?, closed_why = ? WHERE did = ? AND closed_at IS NULL AND substr(nkey, 1, ?) = ?")
    .run(nowIso(now), why, did, prefix.length, prefix).changes;
}

function dismiss(db, did, id, { now = Date.now() } = {}) {
  return db.prepare("UPDATE wallet_notices SET closed_at = ?, closed_why = 'dismissed' WHERE id = ? AND did = ? AND closed_at IS NULL")
    .run(nowIso(now), Number(id), did).changes === 1;
}

function view(r) {
  let data = {}; try { data = JSON.parse(r.data || '{}'); } catch (_) {}
  return { kind: r.kind, notice_id: r.id, title: r.title, text: r.text, since: r.created_at, ...(data.deposit ? { deposit: data.deposit } : {}) };
}

function list(db, did, { now = Date.now() } = {}) {
  try {
    return db.prepare('SELECT * FROM wallet_notices WHERE did = ? AND closed_at IS NULL AND created_at > ? ORDER BY id DESC LIMIT ?').all(did, cutoff(now), LIST_MAX).map(view);
  } catch (_) { return []; }
}

module.exports = { init, raise, clear, dismiss, list, addresses, KINDS };
