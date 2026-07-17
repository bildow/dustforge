#!/usr/bin/env node
require('dotenv').config({ path: '/opt/dustforge/.env' });
process.chdir('/opt/dustforge');
const Database = require('better-sqlite3');
const identity = require('/opt/dustforge/identity');

const DB_PATH = process.env.DB_PATH || './data/dustforge.db';
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');

const FLEET_SLUG = 'aaron-agents';
const PROJECTS = ['dustforge', 'demipass', 'kodiak', 'brain', '11ov3', 'ops'];
const OPERATOR_DID = 'did:key:u7QF8gmIMlzgt6BAdDHUJ5AOpO0RvwtJL_IDhB31eKpZU0A';

const fleet = db.prepare('SELECT id, owner_did FROM fleets WHERE slug = ?').get(FLEET_SLUG);
if (!fleet) { console.error('fleet not found:', FLEET_SLUG); process.exit(1); }
console.log('fleet', FLEET_SLUG, 'id', fleet.id, 'owner', fleet.owner_did);

const upsertWallet = db.prepare("INSERT INTO identity_wallets (did, username, email, encrypted_private_key, balance_cents, status) VALUES (?, ?, ?, ?, 0, 'active')");
const findWalletByUsername = db.prepare('SELECT did FROM identity_wallets WHERE username = ?');
const insertMember = db.prepare("INSERT OR IGNORE INTO fleet_members (fleet_id, member_did, role) VALUES (?, ?, 'agent')");
const findProject = db.prepare('SELECT id, owner_did, wallet_did FROM fleet_projects WHERE fleet_id = ? AND project = ?');
const insertProject = db.prepare('INSERT INTO fleet_projects (fleet_id, project, owner_did, lane_address, wallet_did) VALUES (?, ?, ?, ?, ?)');
const insertOperator = db.prepare('INSERT OR IGNORE INTO fleet_project_operators (project_id, operator_did) VALUES (?, ?)');

for (const project of PROJECTS) {
  const existing = findProject.get(fleet.id, project);
  if (existing) {
    console.log('[skip]', project, '->', existing.owner_did.slice(0, 32) + '...', '(exists)');
    insertOperator.run(existing.id, OPERATOR_DID);
    continue;
  }
  const walletUsername = 'project-' + project;
  const walletEmail = 'project-' + project + '@dustforge.com';
  let did;
  const preExisting = findWalletByUsername.get(walletUsername);
  if (preExisting) {
    did = preExisting.did;
    console.log('[reuse]', walletUsername, '->', did.slice(0, 32) + '...');
  } else {
    const id = identity.createIdentity();
    upsertWallet.run(id.did, walletUsername, walletEmail, id.encrypted_private_key);
    did = id.did;
    console.log('[mint]', walletUsername, '->', did.slice(0, 32) + '...');
  }
  insertMember.run(fleet.id, did);
  const laneAddress = project + '.claude@dustforge.com';
  const result = insertProject.run(fleet.id, project, did, laneAddress, did);
  const projectId = result.lastInsertRowid;
  insertOperator.run(projectId, OPERATOR_DID);
  console.log('  board row', projectId, 'lane', laneAddress);
}

console.log('\n=== BOARD ===');
const board = db.prepare(`SELECT p.id, p.project, p.owner_did, p.lane_address, p.wallet_did, w.balance_cents
                          FROM fleet_projects p LEFT JOIN identity_wallets w ON w.did = p.wallet_did
                          WHERE p.fleet_id = ? ORDER BY p.project`).all(fleet.id);
for (const b of board) {
  const ops = db.prepare('SELECT operator_did FROM fleet_project_operators WHERE project_id = ?').all(b.id);
  console.log(b.project.padEnd(10), b.owner_did.slice(0, 40) + '...', b.lane_address.padEnd(35), 'bal=' + b.balance_cents, 'ops=' + ops.length);
}
