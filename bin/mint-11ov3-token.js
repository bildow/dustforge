#!/usr/bin/env node
// Mint a long-lived transact-scope token for project-11ov3 + seed its wallet.
require('dotenv').config({ path: '/opt/dustforge/.env' });
process.chdir('/opt/dustforge');
const Database = require('better-sqlite3');
const identity = require('/opt/dustforge/identity');
const billing = require('/opt/dustforge/billing');

const DB_PATH = process.env.DB_PATH || './data/dustforge.db';
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');

const w = db.prepare('SELECT did, encrypted_private_key, balance_cents, username FROM identity_wallets WHERE username = ?').get('project-11ov3');
if (!w) { console.error('project-11ov3 not found'); process.exit(1); }
console.log('did:', w.did);
console.log('balance_before:', w.balance_cents);

// Seed 500 DD (500 cents) for buoy ticks. 1 DD per 100 ticks -> 50,000 ticks headroom.
const SEED = 500;
const already = db.prepare("SELECT SUM(amount_cents) as s FROM identity_transactions WHERE did = ? AND provenance = 'admin_seed_11ov3'").get(w.did);
if (!already || !already.s) {
  const result = billing.creditBalance(db, w.did, SEED, 'admin_seed', 'Seed for 11ov3 lane buoy ticks (per-lane billing wire-up)', 'admin_seed_11ov3_v1');
  console.log('seed result:', result);
} else {
  console.log('seed already applied (idempotency guard) — skipping');
}

const after = db.prepare('SELECT balance_cents FROM identity_wallets WHERE did = ?').get(w.did);
console.log('balance_after:', after.balance_cents);

const token = identity.createTokenForIdentity(w.encrypted_private_key, w.did, {
  scope: 'transact',
  expiresIn: '365d',
  metadata: { username: w.username, purpose: '11ov3-buoy-anchor' }
});
console.log('\ntoken:', token);
