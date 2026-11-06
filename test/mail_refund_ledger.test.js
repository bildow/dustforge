// node --test test/mail_refund_ledger.test.js — #50 review: (1) the token_jti column is never "remembered" after an
// ALTER that rolled back; (2) a refund gives back the DD lots the charge was spent from (chargeback lineage).
const test = require('node:test'); const assert = require('node:assert');
const Database = require('better-sqlite3');
const billing = require('../billing'); const ddl = require('../dd_ledger');
function fresh() {
  const db = new Database(':memory:');
  db.exec(`CREATE TABLE identity_wallets (id INTEGER PRIMARY KEY, did TEXT, status TEXT DEFAULT 'active', balance_cents INTEGER DEFAULT 0, updated_at TEXT);
           CREATE TABLE identity_transactions (id INTEGER PRIMARY KEY AUTOINCREMENT, did TEXT, amount_cents INTEGER, type TEXT, description TEXT,
             balance_after INTEGER, provenance TEXT, idempotency_key TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP);`);
  db.prepare("INSERT INTO identity_wallets (did, balance_cents) VALUES ('did:x', 0)").run();
  ddl.initSchema(db);
  return db;
}
test('an ALTER inside a rolled-back transaction is not cached: later charges still work and carry the token id', () => {
  const db = fresh();
  billing.creditBalance(db, 'did:x', 100, 'topup', 'seed');
  try { db.transaction(() => { billing.deductBalance(db, 'did:x', 10, 'email_send', 'x', { tokenJti: 'j1' }); throw new Error('rolled back'); })(); } catch (_) {}
  const r = billing.deductBalance(db, 'did:x', 10, 'email_send', 'x', { tokenJti: 'j2' });
  assert.equal(r.ok, true);
  const row = db.prepare("SELECT token_jti FROM identity_transactions WHERE type='email_send' ORDER BY id DESC LIMIT 1").get();
  assert.equal(row && row.token_jti, 'j2');
});
test('refundCharge restores the tainted lots the charge spent, so a later transfer carries the taint', () => {
  const db = fresh();
  billing.creditBalance(db, 'did:x', 100, 'topup', 'seed');
  ddl.recordCredit(db, { did: 'did:x', amount_cents: 100, source: 'stripe', origin_event_id: 'evt1', chargebackable: 1 });
  billing.deductBalance(db, 'did:x', 10, 'email_send', 'send', { tokenJti: 'j' });
  let lot = db.prepare('SELECT spent_cents FROM dd_ledger').get();
  assert.equal(lot.spent_cents, 10);
  billing.refundCharge(db, 'did:x', 10, 'email_send_refund', 'refund', { tokenJti: 'j' });
  lot = db.prepare('SELECT spent_cents FROM dd_ledger').get();
  assert.equal(lot.spent_cents, 0, 'the refunded spend is off the tainted lot again');
  assert.equal(db.prepare("SELECT token_jti FROM identity_transactions WHERE type='email_send_refund'").get().token_jti, 'j');
});
