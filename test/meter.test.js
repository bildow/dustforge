'use strict';
// node --test test/meter.test.js
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const Database = require('better-sqlite3');
const billing = require('../billing');
process.env.IDENTITY_MASTER_KEY = process.env.IDENTITY_MASTER_KEY || 'c'.repeat(64);   // identity.js refuses to load without it
const identity = require('../identity');
const meterMod = require('../meter');

const BENCH = 'did:key:bench';
const POOR = 'did:key:poor';
const MASTER = 'a'.repeat(64);
const H = (s) => crypto.createHash('sha256').update(s).digest('hex');

// Legacy shape on purpose: identity_transactions without token_jti (the column is added at startup on the live DB; a
// fresh handle here must still charge).
function mkdb() {
  const db = new Database(':memory:');
  db.exec(`CREATE TABLE identity_wallets (id INTEGER PRIMARY KEY AUTOINCREMENT, did TEXT UNIQUE, username TEXT, email TEXT,
             encrypted_private_key TEXT DEFAULT '', balance_cents INTEGER DEFAULT 0, status TEXT DEFAULT 'active',
             updated_at TEXT DEFAULT CURRENT_TIMESTAMP)`);
  db.exec(`CREATE TABLE identity_transactions (id INTEGER PRIMARY KEY AUTOINCREMENT, did TEXT, amount_cents INTEGER, type TEXT,
             description TEXT DEFAULT '', balance_after INTEGER DEFAULT 0, created_at TEXT DEFAULT CURRENT_TIMESTAMP,
             idempotency_key TEXT, provenance TEXT DEFAULT 'organic')`);
  for (const [did, bal] of [[BENCH, 500], [POOR, 5]]) {
    db.prepare('INSERT INTO identity_wallets (did, username, email, balance_cents) VALUES (?, ?, ?, ?)').run(did, did, did + '@x', bal);
    db.prepare("INSERT INTO identity_transactions (did, amount_cents, type, balance_after) VALUES (?, ?, 'grant', ?)").run(did, bal, bal);
  }
  return db;
}
const mk = (db = mkdb(), masterKey = MASTER) => ({ db, meter: meterMod.createMeter({ db, billing, identity, masterKey }) });

test('a charge bills units × rate, records one transaction, and signs a receipt anyone can check offline', () => {
  const { db, meter } = mk();
  const r = meter.charge({ did: BENCH, tokenJti: 'jti1', tenant: 'eval-rig', sku: 'provision', units: 4, receipt_sha256: H('r1') });
  assert.equal(r.ok, true);
  assert.equal(r.replayed, false);
  assert.equal(r.dd, 40);
  assert.equal(r.balance_after, 460);
  assert.match(r.charge_id, /^mc_[0-9a-f]{24}$/);
  assert.equal(billing.getDerivedBalance(db, BENCH), 460);
  const tx = db.prepare("SELECT * FROM identity_transactions WHERE type = 'meter_charge'").all();
  assert.equal(tx.length, 1);
  assert.equal(tx[0].amount_cents, -40);
  assert.match(tx[0].description, new RegExp(r.charge_id));

  // Offline: only the issuer did:key and the signed string.
  const pub = crypto.createPublicKey({ key: identity.didToPublicKey(r.issuer), format: 'der', type: 'spki' });
  assert.equal(crypto.verify(null, Buffer.from(r.receipt, 'utf8'), pub, Buffer.from(r.sig, 'base64url')), true);
  const body = JSON.parse(r.receipt);
  assert.deepEqual(
    { v: body.v, type: body.type, charge_id: body.charge_id, issuer: body.issuer, did: body.did, tenant: body.tenant, sku: body.sku, units: body.units, dd: body.dd, receipt_sha256: body.receipt_sha256, at: body.at },
    { v: 1, type: 'dustforge_meter_charge', charge_id: r.charge_id, issuer: r.issuer, did: BENCH, tenant: 'eval-rig', sku: 'provision', units: 4, dd: 40, receipt_sha256: H('r1'), at: r.at });
  assert.match(r.issuer, /^did:key:z6Mk/);
});

test('the same receipt again bills nothing and returns the first charge; different units is a 409', () => {
  const { db, meter } = mk();
  const a = meter.charge({ did: BENCH, tenant: 'eval-rig', sku: 'teardown', units: 1, receipt_sha256: H('t') });
  const b = meter.charge({ did: BENCH, tenant: 'eval-rig', sku: 'teardown', units: 1, receipt_sha256: H('t') });
  assert.equal(b.ok, true);
  assert.equal(b.replayed, true);
  assert.equal(b.charge_id, a.charge_id);
  assert.equal(b.receipt, a.receipt);
  assert.equal(billing.getDerivedBalance(db, BENCH), 490);
  const c = meter.charge({ did: BENCH, tenant: 'eval-rig', sku: 'teardown', units: 2, receipt_sha256: H('t') });
  assert.equal(c.ok, false);
  assert.equal(c.status, 409);
  assert.equal(c.charge_id, a.charge_id);
  // Same hash under another SKU is a separate charge.
  const d = meter.charge({ did: BENCH, tenant: 'eval-rig', sku: 'provision', units: 1, receipt_sha256: H('t') });
  assert.equal(d.replayed, false);
  assert.equal(billing.getDerivedBalance(db, BENCH), 480);
});

test('an insufficient balance is a 402 and leaves nothing behind', () => {
  const { db, meter } = mk();
  const r = meter.charge({ did: POOR, tenant: 'eval-rig', sku: 'score', units: 1, receipt_sha256: H('p') });
  assert.equal(r.ok, false);
  assert.equal(r.status, 402);
  assert.equal(r.required_dd, 10);
  assert.equal(r.balance_dd, 5);
  assert.equal(billing.getDerivedBalance(db, POOR), 5);
  assert.equal(db.prepare('SELECT COUNT(*) n FROM meter_charges').get().n, 0);
  assert.equal(db.prepare("SELECT COUNT(*) n FROM identity_transactions WHERE type = 'meter_charge'").get().n, 0);
});

test('a suspended or unknown wallet is refused without a record', () => {
  const { db, meter } = mk();
  db.prepare("UPDATE identity_wallets SET status = 'suspended' WHERE did = ?").run(BENCH);
  const r = meter.charge({ did: BENCH, tenant: 'eval-rig', sku: 'score', units: 1, receipt_sha256: H('s') });
  assert.equal(r.status, 403);
  const u = meter.charge({ did: 'did:key:nobody', tenant: 'eval-rig', sku: 'score', units: 1, receipt_sha256: H('s') });
  assert.equal(u.status, 403);
  assert.equal(db.prepare('SELECT COUNT(*) n FROM meter_charges').get().n, 0);
});

test('input is validated against the rate table', () => {
  const { meter } = mk();
  const base = { did: BENCH, tenant: 'eval-rig', sku: 'provision', units: 1, receipt_sha256: H('v') };
  for (const bad of [
    { tenant: 'other' }, { tenant: '__proto__' }, { sku: 'constructor' }, { sku: 'nope' },
    { units: 0 }, { units: 101 }, { units: 1.5 }, { units: '2' },
    { receipt_sha256: 'abc' }, { receipt_sha256: H('v').toUpperCase() }, { receipt_sha256: undefined },
  ]) {
    const r = meter.charge({ ...base, ...bad });
    assert.equal(r.status, 400, JSON.stringify(bad));
  }
});

test('verify: a good receipt is valid and on record; any edit or a foreign key fails', () => {
  const { meter } = mk();
  const r = meter.charge({ did: BENCH, tenant: 'eval-rig', sku: 'provision', units: 1, receipt_sha256: H('x') });
  const ok = meter.verify({ receipt: r.receipt, sig: r.sig });
  assert.equal(ok.valid, true);
  assert.equal(ok.on_record, true);
  assert.equal(ok.charge.charge_id, r.charge_id);
  const edited = meter.verify({ receipt: r.receipt.replace('"units":1', '"units":9'), sig: r.sig });
  assert.equal(edited.valid, false);
  // A receipt signed by another deployment's key does not verify here.
  const other = mk(mkdb(), 'b'.repeat(64)).meter;
  const foreign = other.charge({ did: BENCH, tenant: 'eval-rig', sku: 'provision', units: 1, receipt_sha256: H('x') });
  assert.notEqual(foreign.issuer, r.issuer);
  assert.equal(meter.verify({ receipt: foreign.receipt, sig: foreign.sig }).valid, false);
  assert.equal(meter.verify({ receipt: 1, sig: 'x' }).status, 400);
});

test('the signing key is stable for one master key (restart) and absent without one (503, no charge)', () => {
  const db = mkdb();
  const a = meterMod.createMeter({ db, billing, identity, masterKey: MASTER });
  const b = meterMod.createMeter({ db, billing, identity, masterKey: MASTER });
  assert.equal(a.issuer, b.issuer);
  const none = meterMod.createMeter({ db, billing, identity, masterKey: '' });
  assert.equal(none.publicInfo(), null);
  const r = none.charge({ did: BENCH, tenant: 'eval-rig', sku: 'provision', units: 1, receipt_sha256: H('n') });
  assert.equal(r.status, 503);
  assert.equal(billing.getDerivedBalance(db, BENCH), 500);
});

test('list returns only the caller\'s charges', () => {
  const { meter } = mk();
  meter.charge({ did: BENCH, tenant: 'eval-rig', sku: 'provision', units: 1, receipt_sha256: H('l1') });
  meter.charge({ did: BENCH, tenant: 'eval-rig', sku: 'teardown', units: 1, receipt_sha256: H('l2') });
  meter.charge({ did: POOR, tenant: 'eval-rig', sku: 'teardown', units: 1, receipt_sha256: H('l3') }); // 402, not listed
  const rows = meter.list(BENCH, { tenant: 'eval-rig' });
  assert.deepEqual(rows.map((x) => x.sku), ['teardown', 'provision']);
  assert.equal(meter.list(POOR).length, 0);
});
