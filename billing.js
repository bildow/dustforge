/**
 * Civitasvox Per-Call Billing Middleware
 *
 * Every authenticated API call deducts from wallet balance.
 * Like OpenRouter pricing — each action has a cost.
 * Returns 402 Payment Required when balance is insufficient.
 */

// ── Rate Table (cents) ──
const RATE_TABLE = {
  // Identity actions
  'identity_create':      100,  // $1.00 — account creation fee
  'identity_verify':        0,  // free — 2FA verification
  'identity_lookup':        0,  // free — public lookup
  'identity_token':         0,  // free — token verification

  // Email actions (via Dustforge)
  'email_send':             1,  // $0.01 per email sent
  'email_send_bulk':        1,  // $0.01 per email in bulk (per-email)

  // API calls (per-call billing)
  'api_call_read':          0,  // free — read operations
  'api_call_write':         0,  // $0.001 — write operations (future)
  'api_call_compute':       1,  // $0.01 — compute-heavy operations

  // Platform actions
  'round_dispatch':        10,  // $0.10 — dispatching a round (covers model costs)
  'round_collaboration':   25,  // $0.25 — collaboration round (multi-pass)
};

/**
 * Deduct from wallet. Returns { ok, balance_after } or { ok: false, error }.
 */
function deductBalance(db, did, amount_cents, type, description = '') {
  const wallet = db.prepare('SELECT id, balance_cents, status FROM identity_wallets WHERE did = ?').get(did);
  if (!wallet) return { ok: false, error: 'identity not found' };
  if (wallet.status !== 'active') return { ok: false, error: 'account suspended' };
  if (wallet.balance_cents < amount_cents) {
    return { ok: false, error: 'insufficient balance', balance_cents: wallet.balance_cents, required: amount_cents };
  }

  const newBalance = wallet.balance_cents - amount_cents;
  db.prepare('UPDATE identity_wallets SET balance_cents = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?')
    .run(newBalance, wallet.id);

  db.prepare(`
    INSERT INTO identity_transactions (did, amount_cents, type, description, balance_after)
    VALUES (?, ?, ?, ?, ?)
  `).run(did, -amount_cents, type, description, newBalance);

  return { ok: true, balance_after: newBalance, deducted: amount_cents };
}

/**
 * Credit wallet (for referral payouts, topups, etc.)
 */
function creditBalance(db, did, amount_cents, type, description = '') {
  const wallet = db.prepare('SELECT id, balance_cents FROM identity_wallets WHERE did = ?').get(did);
  if (!wallet) return { ok: false, error: 'identity not found' };

  const newBalance = wallet.balance_cents + amount_cents;
  db.prepare('UPDATE identity_wallets SET balance_cents = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?')
    .run(newBalance, wallet.id);

  db.prepare(`
    INSERT INTO identity_transactions (did, amount_cents, type, description, balance_after)
    VALUES (?, ?, ?, ?, ?)
  `).run(did, amount_cents, type, description, newBalance);

  return { ok: true, balance_after: newBalance, credited: amount_cents };
}

/**
 * Express middleware — authenticate via Bearer token, deduct per-call cost.
 * Usage: app.post('/api/something', billingMiddleware(db, 'api_call_compute'), handler)
 */
function billingMiddleware(db, actionType, options = {}) {
  const identity = require('./identity');
  const cost = options.cost ?? RATE_TABLE[actionType] ?? 0;

  return (req, res, next) => {
    // Extract token from Authorization header
    const authHeader = req.headers.authorization || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;

    if (!token) {
      return res.status(401).json({ error: 'Bearer token required', action: actionType });
    }

    // Verify token
    const result = identity.verifyTokenStandalone(token);
    if (!result.valid) {
      return res.status(401).json({ error: `token invalid: ${result.error}`, action: actionType });
    }

    const did = result.decoded.sub;
    const scope = result.decoded.scope || 'read';

    // Check scope permissions
    const writeScopes = new Set(['write', 'transact', 'admin', 'full']);
    const readScopes = new Set(['read', 'write', 'transact', 'admin', 'full']);
    const isWrite = ['email_send', 'email_send_bulk', 'round_dispatch', 'round_collaboration', 'api_call_write', 'api_call_compute'].includes(actionType);
    if (isWrite && !writeScopes.has(scope)) {
      return res.status(403).json({ error: `scope '${scope}' cannot perform '${actionType}'`, required_scope: 'transact' });
    }

    // Deduct if cost > 0
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

    // Attach identity to request
    req.identity = { did, scope, decoded: result.decoded };
    next();
  };
}

module.exports = {
  RATE_TABLE,
  deductBalance,
  creditBalance,
  billingMiddleware,
};
