/**
 * One-time Diamond Dust redenomination: 1 old DD ($0.01) = 10 new DD ($0.001).
 *
 * Multiplies every stored DD amount by 10 in one transaction, so every balance
 * buys exactly what it bought before under the ×10 prices (see dd_units.js).
 * Runs at server start, before the server listens, so new prices never meet
 * old balances. A marker row makes it run once; a second call is a no-op.
 *
 * Not multiplied, on purpose:
 *   - prepaid_keys.amount_cents: the US cents a key was bought for.
 *   - tick_billing.pending: a count of ticks, not DD.
 *
 * referral_accumulators.accumulated changes unit too: one old unit was 0.1 old DD
 * (= 1 new DD); one new unit is 0.01 DD, so it is multiplied by 100.
 */
const { REDENOMINATION_FACTOR } = require('./dd_units');

// table → DD-denominated columns
const DD_COLUMNS = {
  identity_wallets: ['balance_cents'],
  identity_transactions: ['amount_cents', 'balance_after'],
  dd_ledger: ['amount_cents', 'spent_cents', 'transferred_cents'],
  billing_attributions: ['cost_cents'],
  bounty_submissions: ['payout_cents'],
  barrel_cosign_requests: ['amount_cents'],
  escrow_contracts: ['collateral_cents'],
  cruise_sessions: ['max_dd', 'spent_dd'],
  cruise_cycle_log: ['dd_cost'],
  referral_credits: ['earned_cents'],
  fleet_silicons: ['refill_threshold_cents', 'refill_amount_cents', 'refill_daily_cap_cents'],
  wallet_refill_rules: ['amount_cents'],
  fleet_work_links: ['spent_cents', 'max_spend_cents'],
  fleet_workers: ['max_spend_cents', 'spent_cents'],
  network_transfers: ['amount_cents'],
  network_topups: ['amount_cents', 'sent_cents'],
};
// table → { column: factor } where the factor is not REDENOMINATION_FACTOR
const OTHER_FACTORS = {
  referral_accumulators: { accumulated: 100 },
};

function columnsOf(db, table) {
  return new Set(db.prepare(`SELECT name FROM pragma_table_info(?)`).all(table).map(r => r.name));
}

function walletTotals(db) {
  return {
    wallets: db.prepare('SELECT COUNT(*) n, COALESCE(SUM(balance_cents),0) s FROM identity_wallets').get(),
    ledger: db.prepare('SELECT COUNT(*) n, COALESCE(SUM(amount_cents),0) s FROM identity_transactions').get(),
  };
}

// Returns { applied: false, ... } when it already ran, else what it changed.
// dryRun: do everything inside the transaction, then roll it back.
function migrate(db, { dryRun = false, log = () => {} } = {}) {
  db.exec(`CREATE TABLE IF NOT EXISTS dd_redenomination (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    factor INTEGER NOT NULL,
    applied_at TEXT NOT NULL,
    report TEXT NOT NULL
  )`);
  const done = db.prepare('SELECT * FROM dd_redenomination WHERE id = 1').get();
  if (done) return { applied: false, already: done };

  const f = REDENOMINATION_FACTOR;
  const before = walletTotals(db);
  const changed = {};
  const ROLLBACK = new Error('dry run');
  let report;
  try {
    db.transaction(() => {
      for (const [table, cols] of Object.entries(DD_COLUMNS)) {
        const have = columnsOf(db, table);
        const present = cols.filter(c => have.has(c));
        if (!present.length) continue;
        const set = present.map(c => `${c} = ${c} * ${f}`).join(', ');
        const where = present.map(c => `${c} != 0`).join(' OR ');
        changed[table] = db.prepare(`UPDATE ${table} SET ${set} WHERE ${where}`).run().changes;
      }
      for (const [table, cols] of Object.entries(OTHER_FACTORS)) {
        const have = columnsOf(db, table);
        for (const [c, k] of Object.entries(cols)) {
          if (have.has(c)) changed[`${table}.${c}`] = db.prepare(`UPDATE ${table} SET ${c} = ${c} * ${k} WHERE ${c} != 0`).run().changes;
        }
      }
      const after = walletTotals(db);
      if (after.wallets.s !== before.wallets.s * f || after.ledger.s !== before.ledger.s * f) {
        throw new Error(`redenomination check failed: wallets ${before.wallets.s}→${after.wallets.s}, ledger ${before.ledger.s}→${after.ledger.s}`);
      }
      report = { factor: f, rows_changed: changed, wallet_total_before: before.wallets.s, wallet_total_after: after.wallets.s,
                 ledger_total_before: before.ledger.s, ledger_total_after: after.ledger.s };
      db.prepare('INSERT INTO dd_redenomination (id, factor, applied_at, report) VALUES (1, ?, ?, ?)')
        .run(f, new Date().toISOString(), JSON.stringify(report));
      if (dryRun) throw ROLLBACK;
    })();
  } catch (e) {
    if (e !== ROLLBACK) throw e;
    log(`[dd] dry run, rolled back: ${JSON.stringify(report)}`);
    return { applied: false, dryRun: true, report };
  }
  log(`[dd] redenominated ×${f}: ${JSON.stringify(report)}`);
  return { applied: true, report };
}

module.exports = { migrate, DD_COLUMNS };
