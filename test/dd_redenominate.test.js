'use strict';
// Diamond Dust redenomination: 1 DD = $0.001, $1 deposit = 950 DD, stored DD ×10 once.
const test = require('node:test');
const assert = require('node:assert/strict');
const Database = require('better-sqlite3');
const billing = require('../billing');
const units = require('../dd_units');
const { migrate } = require('../dd_redenominate');

test('deposits buy 950 DD per dollar; prices are the old prices ×10', () => {
  assert.equal(units.ddForUsdCents(100), 950);
  assert.equal(units.ddForUsdCents(500), 4750);
  assert.equal(units.ddForUsdCents(10000), 95000);
  assert.equal(units.ddForUsdCents('1000'), 9500);           // Stripe metadata is a string
  assert.equal(units.usdLabel(10), '$0.010');
  assert.equal(billing.RATE_TABLE.api_call_compute, 10);      // DemiPass /use: still 1¢
  assert.equal(billing.RATE_TABLE.email_send, 10);
  assert.equal(billing.RATE_TABLE.identity_create, 1000);
  assert.equal(require('../referral').REFERRAL_PAYOUT_CENTS, 100);
});

// A database as production had it before the change: old-unit DD everywhere.
function legacyDb() {
  const db = new Database(':memory:');
  db.exec(`
    CREATE TABLE identity_wallets (id INTEGER PRIMARY KEY, did TEXT UNIQUE, username TEXT, balance_cents INTEGER DEFAULT 0, status TEXT DEFAULT 'active');
    CREATE TABLE identity_transactions (id INTEGER PRIMARY KEY, did TEXT, amount_cents INTEGER NOT NULL, type TEXT, description TEXT, balance_after INTEGER DEFAULT 0, idempotency_key TEXT, provenance TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE dd_ledger (lot_id TEXT, amount_cents INTEGER NOT NULL, spent_cents INTEGER NOT NULL DEFAULT 0, transferred_cents INTEGER NOT NULL DEFAULT 0);
    CREATE TABLE fleet_silicons (id INTEGER PRIMARY KEY, refill_threshold_cents INTEGER DEFAULT 0, refill_amount_cents INTEGER DEFAULT 0, refill_daily_cap_cents INTEGER DEFAULT 0);
    CREATE TABLE wallet_refill_rules (id INTEGER PRIMARY KEY, amount_cents INTEGER NOT NULL DEFAULT 0);
    CREATE TABLE escrow_contracts (id INTEGER PRIMARY KEY, collateral_cents INTEGER NOT NULL DEFAULT 0);
    CREATE TABLE prepaid_keys (id INTEGER PRIMARY KEY, amount_cents INTEGER NOT NULL DEFAULT 100);
    CREATE TABLE tick_billing (did TEXT PRIMARY KEY, pending INTEGER DEFAULT 0);
    CREATE TABLE referral_accumulators (referrer_did TEXT, source_did TEXT, accumulated INTEGER DEFAULT 0);
  `);
  const tx = db.prepare('INSERT INTO identity_transactions (did, amount_cents, type, balance_after) VALUES (?, ?, ?, ?)');
  db.prepare("INSERT INTO identity_wallets (did, username, balance_cents) VALUES ('did:a', 'a', 87), ('did:b', 'b', 0), ('did:c', 'c', 1)").run();
  tx.run('did:a', 0, 'account_created', 0);
  tx.run('did:a', 90, 'onboarding_grant', 90);
  tx.run('did:a', -3, 'api_call_compute', 87);
  tx.run('did:c', 1, 'topup', 1);
  db.prepare('INSERT INTO dd_ledger VALUES (?, ?, ?, ?)').run('lot1', 90, 3, 0);
  db.prepare('INSERT INTO fleet_silicons (refill_threshold_cents, refill_amount_cents, refill_daily_cap_cents) VALUES (20, 50, 50)').run();
  db.prepare('INSERT INTO wallet_refill_rules (amount_cents) VALUES (1000)').run();
  db.prepare('INSERT INTO escrow_contracts (collateral_cents) VALUES (1)').run();
  db.prepare('INSERT INTO prepaid_keys (amount_cents) VALUES (100)').run();
  db.prepare("INSERT INTO tick_billing VALUES ('did:a', 42)").run();
  db.prepare("INSERT INTO referral_accumulators VALUES ('did:a', 'did:c', 7)").run();
  return db;
}

test('redenomination multiplies stored DD by 10 and leaves dollars, ticks and accumulators alone', () => {
  const db = legacyDb();
  const r = migrate(db);
  assert.equal(r.applied, true);
  assert.equal(r.report.wallet_total_before, 88);
  assert.equal(r.report.wallet_total_after, 880);
  assert.deepEqual(db.prepare('SELECT username, balance_cents FROM identity_wallets ORDER BY username').all().map(w => [w.username, w.balance_cents]),
    [['a', 870], ['b', 0], ['c', 10]]);
  assert.deepEqual(db.prepare('SELECT amount_cents a, balance_after b FROM identity_transactions ORDER BY id').all().map(t => [t.a, t.b]),
    [[0, 0], [900, 900], [-30, 870], [10, 10]]);
  // The cached balance still equals the derived one, so reconcile finds nothing.
  for (const w of db.prepare('SELECT did, balance_cents FROM identity_wallets').all()) {
    assert.equal(billing.getDerivedBalance(db, w.did), w.balance_cents);
  }
  assert.deepEqual(db.prepare('SELECT amount_cents, spent_cents, transferred_cents FROM dd_ledger').get(), { amount_cents: 900, spent_cents: 30, transferred_cents: 0 });
  assert.deepEqual(db.prepare('SELECT refill_threshold_cents t, refill_amount_cents a, refill_daily_cap_cents c FROM fleet_silicons').get(), { t: 200, a: 500, c: 500 });
  assert.equal(db.prepare('SELECT amount_cents FROM wallet_refill_rules').get().amount_cents, 10000);
  assert.equal(db.prepare('SELECT collateral_cents FROM escrow_contracts').get().collateral_cents, 10);
  // US cents, ticks and the per-tick referral counter keep their values.
  assert.equal(db.prepare('SELECT amount_cents FROM prepaid_keys').get().amount_cents, 100);
  assert.equal(db.prepare('SELECT pending FROM tick_billing').get().pending, 42);
  assert.equal(db.prepare('SELECT accumulated FROM referral_accumulators').get().accumulated, 7);
});

test('redenomination runs once: a second start changes nothing', () => {
  const db = legacyDb();
  migrate(db);
  const again = migrate(db);
  assert.equal(again.applied, false);
  assert.ok(again.already.applied_at);
  assert.equal(db.prepare("SELECT balance_cents FROM identity_wallets WHERE did = 'did:a'").get().balance_cents, 870);
});

test('a dry run reports the change and rolls it back', () => {
  const db = legacyDb();
  const r = migrate(db, { dryRun: true });
  assert.equal(r.dryRun, true);
  assert.equal(r.report.wallet_total_after, 880);
  assert.equal(db.prepare("SELECT balance_cents FROM identity_wallets WHERE did = 'did:a'").get().balance_cents, 87);
  assert.equal(db.prepare('SELECT COUNT(*) n FROM dd_redenomination').get().n, 0);
  assert.equal(migrate(db).applied, true);   // the real run still happens afterwards
});

test('a fresh database (no wallets yet) just records the marker', () => {
  const db = new Database(':memory:');
  db.exec('CREATE TABLE identity_wallets (did TEXT, balance_cents INTEGER DEFAULT 0); CREATE TABLE identity_transactions (did TEXT, amount_cents INTEGER, balance_after INTEGER)');
  assert.equal(migrate(db).applied, true);
  assert.equal(migrate(db).applied, false);
});
