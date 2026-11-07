'use strict';
// ── DemiPass meter: a priced, signed charge for a service call that is not a /use. ──────────────────────────────────
// Asked for by the BRN-GD-1 eval rig (tome eval/rig/2026-11-07-BRN-GD-1-eval-rig-design.md §4, "third tenant"): Aaron's
// order makes provisioning and scoring DemiPass-metered calls, and /use was the only priced action.
//
//   POST /api/meter/charge {tenant, sku, units, receipt_sha256}   (Bearer, transact scope)
//     Bills the caller's own wallet units × the rate-table price and answers {charge_id, dd, at, balance_after, receipt,
//     sig, issuer}. The same (caller, tenant, sku, receipt_sha256) again bills nothing and answers the first charge with
//     replayed: true, so a retry after a dropped reply never charges twice.
//   GET  /api/meter/rates        public rate table
//   GET  /api/meter/key          the meter's signing identity (did:key, Ed25519)
//   POST /api/meter/verify       {receipt, sig}: checks the signature and that the charge is on this server's books
//   GET  /api/meter/charges      the caller's own charges (?tenant=&limit=), free
//
// The receipt is the exact JSON string that was signed (no canonicalisation needed to check it). Anyone can verify it
// offline: Ed25519 over the UTF-8 bytes of `receipt`, public key from the issuer did:key (identity.didToPublicKey).
// The signing key is derived (HKDF) from IDENTITY_MASTER_KEY with its own label, so it needs no new secret on the host
// and is stable across restarts; it changes only if the master key does. Without the master key the meter refuses
// (503) rather than issuing unsigned receipts.
//
// Prices live here, in code, so a change is a reviewed PR. Units are capped per call.

const crypto = require('crypto');

const RECEIPT_VERSION = 1;
const MAX_UNITS = 100;
const SHA256_RE = /^[0-9a-f]{64}$/;

// DD per unit (1 DD = $0.001). 10 DD matches one /use (api_call_compute).
const METER_RATES = Object.freeze({
  'eval-rig': Object.freeze({
    provision: 10,   // one subject container provisioned from a packed artifact
    teardown: 10,    // one subject torn down
    score: 10,       // one scoring pass recorded against the run (rater model calls stay /use, billed separately)
  }),
});

function deriveSigningKey(masterKey) {
  if (!masterKey) return null;
  const seed = Buffer.from(crypto.hkdfSync('sha256', Buffer.from(String(masterKey)), Buffer.from('dustforge-meter'),
    Buffer.from('receipt-signing-ed25519-v1'), 32));
  // PKCS#8 wrapper for a raw 32-byte Ed25519 seed (RFC 8410).
  const der = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]);
  const privateKey = crypto.createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
  const publicKey = crypto.createPublicKey(privateKey);
  return { privateKey, publicKeyDer: publicKey.export({ type: 'spki', format: 'der' }) };
}

function initSchema(db) {
  db.exec(`CREATE TABLE IF NOT EXISTS meter_charges (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    charge_id TEXT NOT NULL UNIQUE,
    did TEXT NOT NULL,
    tenant TEXT NOT NULL,
    sku TEXT NOT NULL,
    units INTEGER NOT NULL,
    dd INTEGER NOT NULL,
    receipt_sha256 TEXT NOT NULL,
    receipt TEXT NOT NULL,
    sig TEXT NOT NULL,
    token_jti TEXT,
    created_at TEXT NOT NULL,
    UNIQUE (did, tenant, sku, receipt_sha256)
  )`);
  db.exec('CREATE INDEX IF NOT EXISTS idx_meter_charges_did ON meter_charges(did, id)');
}

function createMeter({ db, billing, identity, masterKey }) {
  initSchema(db);
  const key = deriveSigningKey(masterKey);
  const issuer = key ? identity.publicKeyToDID(key.publicKeyDer) : null;

  function publicInfo() {
    return key
      ? { issuer, alg: 'Ed25519', public_key_spki: key.publicKeyDer.toString('base64url'), receipt_version: RECEIPT_VERSION }
      : null;
  }

  function validate({ tenant, sku, units, receipt_sha256 }) {
    if (typeof tenant !== 'string' || !Object.prototype.hasOwnProperty.call(METER_RATES, tenant)) {
      return `tenant must be one of: ${Object.keys(METER_RATES).join(', ')}`;
    }
    const skus = METER_RATES[tenant];
    if (typeof sku !== 'string' || !Object.prototype.hasOwnProperty.call(skus, sku)) {
      return `sku for ${tenant} must be one of: ${Object.keys(skus).join(', ')}`;
    }
    if (!Number.isInteger(units) || units < 1 || units > MAX_UNITS) return `units must be an integer from 1 to ${MAX_UNITS}`;
    if (typeof receipt_sha256 !== 'string' || !SHA256_RE.test(receipt_sha256)) return 'receipt_sha256 must be 64 lowercase hex characters';
    return null;
  }

  function answer(row, replayed) {
    return { ok: true, replayed, charge_id: row.charge_id, dd: row.dd, at: row.created_at, receipt: row.receipt, sig: row.sig, issuer };
  }

  // → {ok:true, ...} | {ok:false, status, error, ...}
  function charge({ did, tokenJti = null, tenant, sku, units, receipt_sha256 }) {
    if (!key) return { ok: false, status: 503, error: 'meter signing key unavailable' };
    const bad = validate({ tenant, sku, units, receipt_sha256 });
    if (bad) return { ok: false, status: 400, error: bad };
    const dd = METER_RATES[tenant][sku] * units;

    const find = db.prepare('SELECT * FROM meter_charges WHERE did = ? AND tenant = ? AND sku = ? AND receipt_sha256 = ?');
    const run = db.transaction(() => {
      const prior = find.get(did, tenant, sku, receipt_sha256);
      if (prior) {
        // A different units value under the same receipt hash is a conflicting request, not a retry.
        if (prior.units !== units) return { ok: false, status: 409, error: 'this receipt_sha256 was already charged with different units', charge_id: prior.charge_id };
        return answer(prior, true);
      }
      const charge_id = 'mc_' + crypto.randomBytes(12).toString('hex');
      const at = new Date().toISOString();
      const debit = billing.deductBalance(db, did, dd, 'meter_charge', `meter ${tenant}/${sku} x${units} ${charge_id}`, { tokenJti });
      if (!debit.ok) {
        // Throwing rolls the transaction back; nothing is recorded for a refused charge.
        const e = new Error('debit refused'); e.debit = debit; throw e;
      }
      const receipt = JSON.stringify({ v: RECEIPT_VERSION, type: 'dustforge_meter_charge', charge_id, issuer, did, tenant, sku,
        units, dd, receipt_sha256, at });
      const sig = crypto.sign(null, Buffer.from(receipt, 'utf8'), key.privateKey).toString('base64url');
      db.prepare(`INSERT INTO meter_charges (charge_id, did, tenant, sku, units, dd, receipt_sha256, receipt, sig, token_jti, created_at)
                  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
        .run(charge_id, did, tenant, sku, units, dd, receipt_sha256, receipt, sig, tokenJti, at);
      return { ...answer({ charge_id, dd, created_at: at, receipt, sig }, false), balance_after: debit.balance_after };
    });
    try {
      return run.immediate();
    } catch (e) {
      if (e.debit) {
        const insufficient = /insufficient/.test(e.debit.error || '');
        return { ok: false, status: insufficient ? 402 : 403, error: e.debit.error, required_dd: dd,
          ...(insufficient ? { balance_dd: e.debit.balance_cents } : {}) };
      }
      throw e;
    }
  }

  // Offline check plus "is it on our books". Never trusts fields outside the signed string.
  function verify({ receipt, sig }) {
    if (!key) return { ok: false, status: 503, error: 'meter signing key unavailable' };
    if (typeof receipt !== 'string' || typeof sig !== 'string' || receipt.length > 4096 || sig.length > 200) {
      return { ok: false, status: 400, error: 'receipt (string) and sig (base64url) are required' };
    }
    let signatureValid = false;
    try { signatureValid = crypto.verify(null, Buffer.from(receipt, 'utf8'), crypto.createPublicKey({ key: key.publicKeyDer, format: 'der', type: 'spki' }), Buffer.from(sig, 'base64url')); }
    catch (_) { signatureValid = false; }
    if (!signatureValid) return { ok: true, valid: false, error: 'signature does not verify against this meter key' };
    let parsed; try { parsed = JSON.parse(receipt); } catch (_) { return { ok: true, valid: false, error: 'receipt is not JSON' }; }
    const row = db.prepare('SELECT receipt FROM meter_charges WHERE charge_id = ?').get(parsed.charge_id);
    return { ok: true, valid: true, on_record: !!row && row.receipt === receipt, charge: parsed };
  }

  function list(did, { tenant, limit } = {}) {
    const n = Math.min(Math.max(Number(limit) || 50, 1), 200);
    const rows = tenant
      ? db.prepare('SELECT charge_id, tenant, sku, units, dd, receipt_sha256, created_at FROM meter_charges WHERE did = ? AND tenant = ? ORDER BY id DESC LIMIT ?').all(did, String(tenant), n)
      : db.prepare('SELECT charge_id, tenant, sku, units, dd, receipt_sha256, created_at FROM meter_charges WHERE did = ? ORDER BY id DESC LIMIT ?').all(did, n);
    return rows;
  }

  return { charge, verify, list, publicInfo, issuer };
}

// Routes. Registered from server.js: require('./meter').registerRoutes({ app, db, billing, identity, getBearerIdentity }).
function registerRoutes({ app, db, billing, identity, getBearerIdentity, masterKey = process.env.IDENTITY_MASTER_KEY }) {
  const rateLimit = require('express-rate-limit');
  const meter = createMeter({ db, billing, identity, masterKey });
  const limit = rateLimit({ windowMs: 60 * 1000, max: 120, standardHeaders: true, legacyHeaders: false,
    message: { error: 'Too many meter requests. Try again in a minute.' } });

  app.get('/api/meter/rates', (req, res) => res.json({ unit: 'DD', dd_usd: 0.001, max_units_per_call: MAX_UNITS, rates: METER_RATES }));

  app.get('/api/meter/key', (req, res) => {
    const info = meter.publicInfo();
    if (!info) return res.status(503).json({ error: 'meter signing key unavailable' });
    res.json({ ...info, verify: 'Ed25519 over the UTF-8 bytes of `receipt`; public key = did:key issuer (or public_key_spki, DER, base64url)' });
  });

  app.post('/api/meter/charge', limit, (req, res) => {
    const auth = getBearerIdentity(req);
    if (!auth.ok) return res.status(auth.status || 401).json({ error: auth.error });
    const b = req.body || {};
    const r = meter.charge({ did: auth.did, tokenJti: (auth.decoded && auth.decoded.jti) || null,
      tenant: b.tenant, sku: b.sku, units: b.units === undefined ? 1 : b.units, receipt_sha256: b.receipt_sha256 });
    if (!r.ok) { const { ok, status, ...rest } = r; return res.status(status).json(rest); }
    const { ok, ...rest } = r;
    return res.status(r.replayed ? 200 : 201).json(rest);
  });

  app.post('/api/meter/verify', limit, (req, res) => {
    const r = meter.verify(req.body || {});
    if (!r.ok) return res.status(r.status).json({ error: r.error });
    const { ok, ...rest } = r;
    res.json(rest);
  });

  app.get('/api/meter/charges', limit, (req, res) => {
    const auth = getBearerIdentity(req);
    if (!auth.ok) return res.status(auth.status || 401).json({ error: auth.error });
    res.json({ charges: meter.list(auth.did, { tenant: req.query.tenant, limit: req.query.limit }) });
  });

  return meter;
}

module.exports = { METER_RATES, MAX_UNITS, RECEIPT_VERSION, deriveSigningKey, initSchema, createMeter, registerRoutes };
