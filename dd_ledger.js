/**
 * Dustforge Diamond Dust Provenance Ledger
 *
 * A lineage layer over the existing balance system (identity_transactions is the
 * money truth; this records WHERE each DD lot came from so fraud can be traced
 * and clawed back). Privacy: every row references a KEYED HASH of the holder's
 * DID (HMAC with a server-held key) — never a raw DID/email/username. An outsider
 * holding a DID cannot compute its ledger id. Only the platform, holding the key,
 * can resolve a hash back to an account (by recomputing the HMAC over its wallet
 * list) — which clawback requires.
 *
 * Model: a LOT is a parcel of DD that entered a holder from one origin event.
 *   - amount_cents      : what entered this lot
 *   - spent_cents       : consumed by deductBalance
 *   - transferred_cents : moved out to child lots (handled by those children)
 *   - a holder's responsibility for a lot = amount - transferred (= remaining + spent)
 * Clawback of a reversed funding event charges (amount - transferred) back to each
 * holder in the lineage — reversing their net gain and driving the balance NEGATIVE
 * if they already spent it (negative-balance debt). Children carry the same
 * origin_event_id, so following the transfer graph is a single indexed query.
 *
 * "Tainted-first": chargebackable dust (funded signup / referral payout) is
 * consumed FIRST on spends and transfers, so clean dust can't sit in front of
 * fraud dust and shield it, and fraud dust is the first to leave (best clawback
 * reach into fleet wallets).
 */

const crypto = require('crypto');

const LEDGER_KEY = process.env.IDENTITY_MASTER_KEY || '';
const NS = 'dd-ledger-id-v1:';

// Keyed HMAC of a DID -> opaque ledger identity. Not computable without the key.
function didHash(did) {
  return crypto.createHmac('sha256', LEDGER_KEY).update(NS + String(did)).digest('hex').slice(0, 40);
}

function newLotId() { return 'lot_' + crypto.randomBytes(12).toString('hex'); }

function initSchema(db) {
  db.exec(`CREATE TABLE IF NOT EXISTS dd_ledger (
    lot_id           TEXT PRIMARY KEY,
    holder_hash      TEXT NOT NULL,
    origin_event_id  TEXT NOT NULL,
    source           TEXT NOT NULL,
    parent_lot_id    TEXT,
    chargebackable   INTEGER NOT NULL DEFAULT 0,
    amount_cents     INTEGER NOT NULL,
    spent_cents      INTEGER NOT NULL DEFAULT 0,
    transferred_cents INTEGER NOT NULL DEFAULT 0,
    evaporated       INTEGER NOT NULL DEFAULT 0,
    created_at       TEXT DEFAULT CURRENT_TIMESTAMP,
    metadata         TEXT DEFAULT '{}'
  )`);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_ddl_holder ON dd_ledger(holder_hash, evaporated)`);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_ddl_origin ON dd_ledger(origin_event_id, evaporated)`);
}

// A root credit lot (funded signup, referral payout, operator grant).
// chargebackable: 1 if this DD derives from a reversible payment.
function recordCredit(db, { did, amount_cents, source, origin_event_id, chargebackable = 0, parent_lot_id = null, metadata = {} }) {
  if (!did || !amount_cents || amount_cents <= 0 || !origin_event_id) return null;
  const lot_id = newLotId();
  db.prepare(`INSERT INTO dd_ledger (lot_id, holder_hash, origin_event_id, source, parent_lot_id, chargebackable, amount_cents, metadata)
              VALUES (?,?,?,?,?,?,?,?)`)
    .run(lot_id, didHash(did), origin_event_id, source, parent_lot_id, chargebackable ? 1 : 0, amount_cents, JSON.stringify(metadata));
  return lot_id;
}

// Live lots for a holder, tainted-first: chargebackable dust before clean, then oldest.
function liveLots(db, holderHash) {
  return db.prepare(`SELECT lot_id, origin_event_id, chargebackable, amount_cents, spent_cents, transferred_cents
                     FROM dd_ledger WHERE holder_hash=? AND evaporated=0
                     ORDER BY chargebackable DESC, created_at ASC, rowid ASC`).all(holderHash);
}

// Spend: attribute `amount_cents` of a deduction to the holder's live lots
// (tainted-first). Best-effort — untracked legacy DD just isn't attributed.
function recordSpend(db, did, amount_cents) {
  if (!did || !amount_cents || amount_cents <= 0) return;
  const h = didHash(did);
  let need = amount_cents;
  for (const lot of liveLots(db, h)) {
    if (need <= 0) break;
    const remaining = lot.amount_cents - lot.spent_cents - lot.transferred_cents;
    if (remaining <= 0) continue;
    const take = Math.min(remaining, need);
    db.prepare(`UPDATE dd_ledger SET spent_cents = spent_cents + ? WHERE lot_id=?`).run(take, lot.lot_id);
    need -= take;
  }
}

// Transfer A->B: consume `amount_cents` from A's live lots (tainted-first) and
// create child lots at B, each inheriting its parent's origin + chargeback flag,
// so the lineage (and any future clawback) follows the dust into fleet wallets.
function recordTransfer(db, fromDid, toDid, amount_cents) {
  if (!fromDid || !toDid || !amount_cents || amount_cents <= 0) return;
  const h = didHash(fromDid);
  let need = amount_cents;
  for (const lot of liveLots(db, h)) {
    if (need <= 0) break;
    const remaining = lot.amount_cents - lot.spent_cents - lot.transferred_cents;
    if (remaining <= 0) continue;
    const take = Math.min(remaining, need);
    db.prepare(`UPDATE dd_ledger SET transferred_cents = transferred_cents + ? WHERE lot_id=?`).run(take, lot.lot_id);
    recordCredit(db, { did: toDid, amount_cents: take, source: 'transfer', origin_event_id: lot.origin_event_id,
                       chargebackable: lot.chargebackable, parent_lot_id: lot.lot_id });
    need -= take;
  }
}

// Resolve the holder_hashes present in a lot set back to DIDs by recomputing the
// keyed hash over the wallet list. Only possible with the server key.
function resolveHolders(db, lots) {
  const wanted = new Set(lots.map(l => l.holder_hash));
  const map = {};
  for (const w of db.prepare('SELECT did FROM identity_wallets').all()) {
    const h = didHash(w.did);
    if (wanted.has(h)) map[h] = w.did;
  }
  return map;
}

// Clawback a reversed funding event ("evaporation"). Charges (amount-transferred)
// back to each holder in the lineage via billing.evaporate (a floor-less debit
// that can drive the balance negative). Idempotent per lot. Fully audited.
function clawback(db, origin_event_id, billing) {
  const lots = db.prepare(`SELECT * FROM dd_ledger WHERE origin_event_id=? AND evaporated=0`).all(origin_event_id);
  if (!lots.length) return { ok: true, evaporated_lots: 0, total_charged_cents: 0, note: 'no live lots for this event' };
  const holderDid = resolveHolders(db, lots);
  let charged = 0, count = 0;
  const audit = [];
  const run = db.transaction(() => {
    for (const lot of lots) {
      const charge = lot.amount_cents - lot.transferred_cents; // remaining + spent
      const did = holderDid[lot.holder_hash];
      if (did && charge > 0) {
        const r = billing.evaporate(db, did, charge, `clawback: funding ${origin_event_id} reversed`, `clawback_${lot.lot_id}`);
        if (r && r.ok) { charged += charge; count++; audit.push({ lot: lot.lot_id, holder: lot.holder_hash, charged: charge, balance_after: r.balance_after }); }
      }
      db.prepare('UPDATE dd_ledger SET evaporated=1 WHERE lot_id=?').run(lot.lot_id);
    }
  });
  run();
  return { ok: true, origin_event_id, evaporated_lots: count, total_charged_cents: charged, audit };
}

module.exports = { didHash, initSchema, recordCredit, recordSpend, recordTransfer, clawback, resolveHolders };
