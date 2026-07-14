/**
 * Dustforge onboarding helpers — single-use prepaid links + referral invite hashes
 * + the account-less "lightweight" referral identity.
 *
 * Invite hash: a keyed HMAC of the sponsor's email (IDENTITY_MASTER_KEY). Opaque
 * to outsiders; the platform resolves it by recomputing over its records. It is
 * the referral token in the invite link (?ref=<hash>) and the claim token the
 * sponsor uses when they mint their own account (?claim=<hash>).
 *
 * Lightweight referral identity: a sponsor with no Dustforge account still earns
 * 10 DD when someone they invited FUNDS ($1). It's held (capped at 10 DD total —
 * one referral's worth) against their email hash and deposited one-time when the
 * sponsor mints their own account. Each earning is tied to the invitee's funding
 * event so a chargeback claws it back through the ledger.
 */

const crypto = require('crypto');
const KEY = process.env.IDENTITY_MASTER_KEY || '';

const REFERRAL_EARN_CENTS = 10;       // per completed referral
const LIGHTWEIGHT_CAP_CENTS = 10;     // lightweight (account-less) ID earns at most this, total

function inviteHash(email) {
  return crypto.createHmac('sha256', KEY).update('invite-v1:' + String(email || '').toLowerCase().trim()).digest('hex').slice(0, 24);
}
function newToken(prefix) { return (prefix || '') + crypto.randomBytes(18).toString('base64url'); }

function initSchema(db) {
  db.exec(`CREATE TABLE IF NOT EXISTS prepaid_links (
    token TEXT PRIMARY KEY,
    key_code TEXT NOT NULL,
    status TEXT DEFAULT 'active',       -- active | used
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    used_at TEXT
  )`);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_plinks_key ON prepaid_links(key_code)`);
  db.exec(`CREATE TABLE IF NOT EXISTS referral_credits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email_hash TEXT NOT NULL,           -- inviteHash(sponsor email)
    earned_cents INTEGER NOT NULL DEFAULT 0,
    origin_event_id TEXT,               -- the invitee's funding event (clawback anchor)
    invitee_did TEXT,
    status TEXT DEFAULT 'pending',      -- pending | deposited
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    deposited_at TEXT,
    UNIQUE(email_hash, invitee_did)     -- one earning per (sponsor, invitee): idempotent + anti-farm
  )`);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_refcred_hash ON referral_credits(email_hash, status)`);
}

// ── single-use prepaid links ────────────────────────────────────────────────
function createPrepaidLink(db, key_code) {
  const token = newToken('pk_');
  db.prepare('INSERT INTO prepaid_links (token, key_code) VALUES (?,?)').run(token, key_code);
  return token;
}
function resolvePrepaidLink(db, token) {
  return db.prepare('SELECT token, key_code, status FROM prepaid_links WHERE token = ?').get(token) || null;
}
function consumePrepaidLink(db, token) {
  const r = db.prepare("UPDATE prepaid_links SET status='used', used_at=CURRENT_TIMESTAMP WHERE token=? AND status='active'").run(token);
  return r.changes > 0;
}

// ── referral resolution ─────────────────────────────────────────────────────
// Does this invite hash belong to an EXISTING account? (recompute over wallets)
function resolveInviteToAccount(db, hash) {
  if (!hash) return null;
  for (const w of db.prepare('SELECT did, email FROM identity_wallets').all()) {
    if (w.email && inviteHash(w.email) === hash) return w.did;
  }
  return null;
}

// Record a lightweight (account-less) referral earning. Capped at 10 DD per
// sponsor hash, idempotent per (sponsor, invitee). origin = invitee funding event.
function recordLightweightReferral(db, hash, invitee_did, origin_event_id) {
  if (!hash || !invitee_did) return { ok: false };
  const earned = db.prepare('SELECT COALESCE(SUM(earned_cents),0) n FROM referral_credits WHERE email_hash=?').get(hash).n;
  if (earned >= LIGHTWEIGHT_CAP_CENTS) return { ok: true, capped: true, earned: 0 };
  const grant = Math.min(REFERRAL_EARN_CENTS, LIGHTWEIGHT_CAP_CENTS - earned);
  try {
    db.prepare('INSERT INTO referral_credits (email_hash, earned_cents, origin_event_id, invitee_did) VALUES (?,?,?,?)')
      .run(hash, grant, origin_event_id || '', invitee_did);
    return { ok: true, earned: grant };
  } catch (_) { return { ok: true, earned: 0, duplicate: true }; }
}

// Deposit any pending lightweight earnings for `claimHash` into a newly-minted
// account (one-time). Ties each to its origin funding event for clawback. Returns
// total cents deposited.
function depositLightweightReferral(db, claimHash, newDid, billing, ledger) {
  if (!claimHash) return 0;
  const pending = db.prepare("SELECT * FROM referral_credits WHERE email_hash=? AND status='pending'").all(claimHash);
  let total = 0;
  for (const c of pending) {
    const r = billing.creditBalance(db, newDid, c.earned_cents, 'referral_deposit', 'Referral reward — deposited on account creation', 'refdep_' + c.id);
    if (r && r.ok && r.credited > 0) {
      try { ledger.recordCredit(db, { did: newDid, amount_cents: c.earned_cents, source: 'referral_payout', origin_event_id: c.origin_event_id || ('refcred_' + c.id), chargebackable: 1 }); } catch (_) {}
      total += c.earned_cents;
    }
    db.prepare("UPDATE referral_credits SET status='deposited', deposited_at=CURRENT_TIMESTAMP WHERE id=?").run(c.id);
  }
  return total;
}

module.exports = {
  inviteHash, initSchema,
  createPrepaidLink, resolvePrepaidLink, consumePrepaidLink,
  resolveInviteToAccount, recordLightweightReferral, depositLightweightReferral,
  REFERRAL_EARN_CENTS, LIGHTWEIGHT_CAP_CENTS,
};
