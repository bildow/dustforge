/**
 * Civitasvox Per-Call Billing — Double-Entry Ledger
 *
 * ARCHITECTURE:
 * - Balance is ALWAYS derived from SUM(transactions), never stored directly
 * - identity_wallets.balance_cents is a CACHE updated after each transaction
 *   for read performance, but the transaction table is the source of truth
 * - Every mutation is wrapped in a SQLite transaction for atomicity
 * - Idempotency keys prevent duplicate credits (Stripe webhook replay)
 * - Reconciliation function detects cache/ledger divergence
 *
 * Returns 402 Payment Required when balance is insufficient.
 */

const crypto = require('crypto');

// ── Rate Table (Diamond Dust — 1 DD = 1¢ = $0.01) ──
const RATE_TABLE = {
  // Identity actions
  'identity_create':      100,  // 100 DD ($1.00) — account creation fee
  'identity_verify':        0,  // free — 2FA verification
  'identity_lookup':        0,  // free — public lookup
  'identity_token':         0,  // free — token verification

  // Email actions (via Dustforge)
  'email_send':             1,  // 1 DD per email sent
  'email_send_bulk':        1,  // 1 DD per email in bulk (per-email)

  // API calls (per-call billing)
  'api_call_read':          0,  // free — read operations
  'api_call_write':         0,  // $0.001 — write operations (future)
  'api_call_compute':       1,  // $0.01 — compute-heavy operations

  // Platform actions
  'round_dispatch':        10,  // $0.10 — dispatching a round (covers model costs)
  'round_collaboration':   25,  // $0.25 — collaboration round (multi-pass)
};

/**
 * Get the true balance by summing transactions (source of truth).
 */
function getDerivedBalance(db, did) {
  const result = db.prepare(
    'SELECT COALESCE(SUM(amount_cents), 0) as balance FROM identity_transactions WHERE did = ?'
  ).get(did);
  return result.balance;
}

/**
 * Sync the cached balance_cents on identity_wallets to match the derived balance.
 * Returns the derived balance.
 */
function syncCachedBalance(db, did) {
  const derived = getDerivedBalance(db, did);
  db.prepare('UPDATE identity_wallets SET balance_cents = ?, updated_at = CURRENT_TIMESTAMP WHERE did = ?')
    .run(derived, did);
  return derived;
}

/**
 * Deduct from wallet. Atomic: checks derived balance, inserts transaction, updates cache.
 * Returns { ok, balance_after } or { ok: false, error }.
 */
function deductBalance(db, did, amount_cents, type, description = '') {
  const wallet = db.prepare('SELECT id, status FROM identity_wallets WHERE did = ?').get(did);
  if (!wallet) return { ok: false, error: 'identity not found' };
  if (wallet.status !== 'active') return { ok: false, error: 'account suspended' };

  // IMMEDIATE transaction: acquires a write lock BEFORE any reads,
  // preventing concurrent transactions from reading stale balances.
  // In SQLite, BEGIN IMMEDIATE ensures no other writer can interleave
  // between our SELECT SUM and INSERT.
  const txn = db.transaction(() => {
    // Touch the wallet row first to acquire exclusive lock on it
    db.prepare('UPDATE identity_wallets SET updated_at = updated_at WHERE id = ?').run(wallet.id);

    const currentBalance = getDerivedBalance(db, did);
    if (currentBalance < amount_cents) {
      return { ok: false, error: 'insufficient balance', balance_cents: currentBalance, required: amount_cents };
    }

    const newBalance = currentBalance - amount_cents;
    db.prepare(
      'INSERT INTO identity_transactions (did, amount_cents, type, description, balance_after) VALUES (?, ?, ?, ?, ?)'
    ).run(did, -amount_cents, type, description, newBalance);

    // Update cache
    db.prepare('UPDATE identity_wallets SET balance_cents = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?')
      .run(newBalance, wallet.id);

    return { ok: true, balance_after: newBalance, deducted: amount_cents };
  });

  return txn();
}

/**
 * Credit wallet. Atomic: inserts transaction, updates cache.
 * Supports idempotency_key to prevent duplicate credits (Stripe webhook replay).
 */
function creditBalance(db, did, amount_cents, type, description = '', idempotency_key = null) {
  const wallet = db.prepare('SELECT id FROM identity_wallets WHERE did = ?').get(did);
  if (!wallet) return { ok: false, error: 'identity not found' };

  const txn = db.transaction(() => {
    // Acquire exclusive lock on wallet row before any reads
    db.prepare('UPDATE identity_wallets SET updated_at = updated_at WHERE id = ?').run(wallet.id);

    // Check idempotency key if provided
    if (idempotency_key) {
      const existing = db.prepare(
        'SELECT id FROM identity_transactions WHERE idempotency_key = ?'
      ).get(idempotency_key);
      if (existing) {
        // Already processed — return success without double-credit
        const currentBalance = getDerivedBalance(db, did);
        return { ok: true, balance_after: currentBalance, credited: 0, idempotent: true };
      }
    }

    const currentBalance = getDerivedBalance(db, did);
    const newBalance = currentBalance + amount_cents;

    db.prepare(
      'INSERT INTO identity_transactions (did, amount_cents, type, description, balance_after, idempotency_key) VALUES (?, ?, ?, ?, ?, ?)'
    ).run(did, amount_cents, type, description, newBalance, idempotency_key || null);

    // Update cache
    db.prepare('UPDATE identity_wallets SET balance_cents = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?')
      .run(newBalance, wallet.id);

    return { ok: true, balance_after: newBalance, credited: amount_cents };
  });

  return txn();
}

/**
 * Reconcile all wallets: compare cached balance_cents against derived SUM(transactions).
 * Returns list of divergent accounts.
 */
function reconcile(db) {
  const divergent = db.prepare(`
    SELECT w.did, w.username, w.balance_cents as cached,
           COALESCE(SUM(t.amount_cents), 0) as derived,
           w.balance_cents - COALESCE(SUM(t.amount_cents), 0) as divergence
    FROM identity_wallets w
    LEFT JOIN identity_transactions t ON w.did = t.did
    GROUP BY w.did
    HAVING w.balance_cents != COALESCE(SUM(t.amount_cents), 0)
  `).all();

  // Auto-fix divergent caches
  if (divergent.length > 0) {
    const fix = db.prepare('UPDATE identity_wallets SET balance_cents = ?, updated_at = CURRENT_TIMESTAMP WHERE did = ?');
    for (const d of divergent) {
      fix.run(d.derived, d.did);
    }
  }

  return {
    total_wallets: db.prepare('SELECT COUNT(*) as n FROM identity_wallets').get().n,
    divergent_count: divergent.length,
    divergent,
    auto_fixed: divergent.length > 0,
  };
}

/**
 * Express middleware — authenticate via Bearer token, deduct per-call cost.
 * Usage: app.post('/api/something', billingMiddleware(db, 'api_call_compute'), handler)
 */
function billingMiddleware(db, actionType, options = {}) {
  const identity = require('./identity');
  const cost = options.cost ?? RATE_TABLE[actionType] ?? 0;

  return (req, res, next) => {
    const authHeader = req.headers.authorization || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;

    if (!token) {
      return res.status(401).json({ error: 'Bearer token required', action: actionType });
    }

    const result = identity.verifyTokenStandalone(token);
    if (!result.valid) {
      return res.status(401).json({ error: `token invalid: ${result.error}`, action: actionType });
    }

    const did = result.decoded.sub;
    const scope = result.decoded.scope || 'read';

    const writeScopes = new Set(['write', 'transact', 'admin', 'full']);
    const isWrite = ['email_send', 'email_send_bulk', 'round_dispatch', 'round_collaboration', 'api_call_write', 'api_call_compute'].includes(actionType);
    if (isWrite && !writeScopes.has(scope)) {
      return res.status(403).json({ error: `scope '${scope}' cannot perform '${actionType}'`, required_scope: 'transact' });
    }

    if (cost > 0) {
      const deduction = deductBalance(db, did, cost, actionType, `API call: ${actionType}`);
      if (!deduction.ok) {
        return res.status(402).json({
          error: 'payment required',
          detail: deduction.error,
          balance_cents: deduction.balance_cents,
          required_cents: deduction.required || cost,
          action: actionType,
        });
      }
      req.billing = { did, deducted: cost, balance_after: deduction.balance_after };
    } else {
      req.billing = { did, deducted: 0, balance_after: null };
    }

    req.identity = { did, scope, decoded: result.decoded };
    next();
  };
}

module.exports = {
  RATE_TABLE,
  deductBalance,
  creditBalance,
  getDerivedBalance,
  syncCachedBalance,
  reconcile,
  billingMiddleware,
};
