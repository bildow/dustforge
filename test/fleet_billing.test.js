'use strict';
// node --test test/fleet_billing.test.js
const test = require('node:test');
const assert = require('node:assert/strict');
const Database = require('better-sqlite3');
const billing = require('../billing');
const fb = require('../fleet_billing');

const OWNER = 'did:key:owner';
const BRAIN = 'did:key:brain';
const OTHER = 'did:key:other';
const PROJ_WALLET = 'did:key:project-brain';

function mkdb() {
  const db = new Database(':memory:');
  db.exec(`CREATE TABLE identity_wallets (id INTEGER PRIMARY KEY AUTOINCREMENT, did TEXT UNIQUE, username TEXT, email TEXT,
             encrypted_private_key TEXT DEFAULT '', balance_cents INTEGER DEFAULT 0, status TEXT DEFAULT 'active',
             recovery_email TEXT DEFAULT '', updated_at TEXT DEFAULT CURRENT_TIMESTAMP)`);
  db.exec(`CREATE TABLE identity_transactions (id INTEGER PRIMARY KEY AUTOINCREMENT, did TEXT, amount_cents INTEGER, type TEXT,
             description TEXT DEFAULT '', balance_after INTEGER DEFAULT 0, created_at TEXT DEFAULT CURRENT_TIMESTAMP,
             idempotency_key TEXT, provenance TEXT DEFAULT 'organic')`);
  db.exec(`CREATE TABLE fleets (id INTEGER PRIMARY KEY AUTOINCREMENT, owner_did TEXT, name TEXT, slug TEXT UNIQUE, wallet_did TEXT DEFAULT '', status TEXT DEFAULT 'active', max_agents INTEGER DEFAULT 5)`);
  db.exec(`CREATE TABLE fleet_members (id INTEGER PRIMARY KEY AUTOINCREMENT, fleet_id INTEGER, member_did TEXT, role TEXT DEFAULT 'agent', UNIQUE(fleet_id, member_did))`);
  db.exec(`CREATE TABLE fleet_projects (id INTEGER PRIMARY KEY AUTOINCREMENT, fleet_id INTEGER, project TEXT, owner_did TEXT, lane_address TEXT DEFAULT '', wallet_did TEXT, UNIQUE(fleet_id, project))`);
  db.exec(`CREATE TABLE fleet_project_operators (project_id INTEGER, operator_did TEXT, UNIQUE(project_id, operator_did))`);
  db.exec(`CREATE TABLE ticks (id INTEGER PRIMARY KEY AUTOINCREMENT, did TEXT DEFAULT '', created_at TEXT DEFAULT CURRENT_TIMESTAMP)`);
  db.exec(`CREATE TABLE issued_tokens (jti TEXT PRIMARY KEY, did TEXT, scope TEXT, issued_at INTEGER, expires_at INTEGER, revoked INTEGER DEFAULT 0)`);
  fb.initSchema(db);
  const w = db.prepare('INSERT INTO identity_wallets (did, username, email) VALUES (?, ?, ?)');
  w.run(OWNER, 'aaron', 'aaron@dustforge.com');
  w.run(BRAIN, 'brain', 'brain@dustforge.com');
  w.run(OTHER, 'other', 'other@dustforge.com');
  w.run(PROJ_WALLET, 'project-brain', 'project-brain@dustforge.com');
  db.prepare('INSERT INTO fleets (owner_did, name, slug) VALUES (?, ?, ?)').run(OWNER, 'Aaron Agents', 'aaron-agents');
  db.prepare('INSERT INTO fleet_members (fleet_id, member_did, role) VALUES (1, ?, ?)').run(OWNER, 'owner');
  db.prepare('INSERT INTO fleet_members (fleet_id, member_did, role) VALUES (1, ?, ?)').run(BRAIN, 'agent');
  db.prepare('INSERT INTO fleet_projects (fleet_id, project, owner_did, wallet_did) VALUES (1, ?, ?, ?)').run('brain', PROJ_WALLET, PROJ_WALLET);
  db.prepare('INSERT INTO fleet_projects (fleet_id, project, owner_did, wallet_did) VALUES (1, ?, ?, ?)').run('kodiak', OWNER, OWNER);
  db.prepare('INSERT INTO fleet_project_operators (project_id, operator_did) VALUES (1, ?)').run(BRAIN);
  return db;
}
function fund(db, did, cents) { return billing.creditBalance(db, did, cents, 'topup', 'test'); }
function bal(db, did) { return billing.getDerivedBalance(db, did); }

test('parseAttribution: header, body fallback, validation', () => {
  const h = fb.parseAttribution({ headers: { 'x-demipass-billing': '{"project":"brain","initiator":"operator"}', 'x-demipass-agent': 'brain-dyadic-handler/1.0' }, body: {} });
  assert.deepEqual(h, { project: 'brain', initiator: 'operator', work_link: '', agent: 'brain-dyadic-handler/1.0' });
  const b = fb.parseAttribution({ headers: {}, body: { billing: { project: 'Kodiak!', initiator: 'nope', work_link: 'dpw_x' } } });
  assert.equal(b.project, '');
  assert.equal(b.initiator, '');
  assert.equal(b.work_link, 'dpw_x');
  assert.deepEqual(fb.parseAttribution(null), { project: '', initiator: '', work_link: '', agent: '' });
});

test('resolvePayer: self / operator / autonomous / unauthorized', () => {
  const db = mkdb();
  const self = fb.resolvePayer(db, billing, { callerDid: BRAIN, attribution: {}, cost: 1 });
  assert.equal(self.payer_did, BRAIN); assert.equal(self.initiator, 'self');
  const op = fb.resolvePayer(db, billing, { callerDid: BRAIN, attribution: { project: 'brain', initiator: 'operator' }, cost: 1 });
  assert.equal(op.payer_did, OWNER); assert.equal(op.initiator, 'operator'); assert.equal(op.project, 'brain'); assert.equal(op.fleet_id, 1);
  const auto = fb.resolvePayer(db, billing, { callerDid: BRAIN, attribution: { project: 'brain', initiator: 'autonomous' }, cost: 1 });
  assert.equal(auto.payer_did, BRAIN); assert.equal(auto.initiator, 'autonomous'); assert.equal(auto.project, 'brain');
  const noInit = fb.resolvePayer(db, billing, { callerDid: BRAIN, attribution: { project: 'brain' }, cost: 1 });
  assert.equal(noInit.payer_did, BRAIN, 'project without initiator never bills the owner');
  const denied = fb.resolvePayer(db, billing, { callerDid: BRAIN, attribution: { project: 'kodiak', initiator: 'operator' }, cost: 1 });
  assert.equal(denied.ok, false); assert.equal(denied.status, 403);
  const stranger = fb.resolvePayer(db, billing, { callerDid: OTHER, attribution: { project: 'brain', initiator: 'operator' }, cost: 1 });
  assert.equal(stranger.ok, false);
  const ownerSelf = fb.resolvePayer(db, billing, { callerDid: OWNER, attribution: { project: 'kodiak', initiator: 'operator' }, cost: 1 });
  assert.equal(ownerSelf.payer_did, OWNER); assert.equal(ownerSelf.project, 'kodiak');
});

test('resolvePayer: project_wallet mode pays from the project wallet, overflows to owner when short', () => {
  const db = mkdb();
  db.prepare("UPDATE fleet_projects SET bill_mode = 'project_wallet' WHERE project = 'brain'").run();
  fund(db, PROJ_WALLET, 5);
  const a = fb.resolvePayer(db, billing, { callerDid: BRAIN, attribution: { project: 'brain', initiator: 'operator' }, cost: 1 });
  assert.equal(a.payer_did, PROJ_WALLET);
  const b = fb.resolvePayer(db, billing, { callerDid: BRAIN, attribution: { project: 'brain', initiator: 'operator' }, cost: 50 });
  assert.equal(b.payer_did, OWNER); assert.match(b.reason, /overflow/);
});

test('chargeAttributed: deducts from the resolved payer and records the attribution', () => {
  const db = mkdb();
  fund(db, OWNER, 100);
  const r = fb.chargeAttributed(db, billing, { callerDid: BRAIN, cost: 3, actionType: 'api_call_compute',
    attribution: { project: 'brain', initiator: 'operator', agent: 'brain/1.0' } });
  assert.equal(r.ok, true); assert.equal(r.payer_did, OWNER); assert.equal(r.balance_after, 97);
  assert.equal(bal(db, OWNER), 97); assert.equal(bal(db, BRAIN), 0);
  const a = db.prepare('SELECT * FROM billing_attributions WHERE id = ?').get(r.attribution_id);
  assert.equal(a.payer_did, OWNER); assert.equal(a.actor_did, BRAIN); assert.equal(a.project, 'brain');
  assert.equal(a.initiator, 'operator'); assert.equal(a.agent, 'brain/1.0'); assert.equal(a.cost_cents, 3);
  const tx = db.prepare('SELECT * FROM identity_transactions WHERE id = ?').get(a.tx_id);
  assert.equal(tx.did, OWNER); assert.equal(tx.amount_cents, -3);
  // insufficient: failure names the payer so the caller knows which wallet is empty
  const fail = fb.chargeAttributed(db, billing, { callerDid: BRAIN, cost: 1, actionType: 'api_call_compute', attribution: {} });
  assert.equal(fail.ok, false); assert.equal(fail.payer_did, BRAIN); assert.equal(fail.error, 'insufficient balance');
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM billing_attributions').get().n, 1, 'failed charges record nothing');
  // zero-cost actions resolve but write nothing
  const free = fb.chargeAttributed(db, billing, { callerDid: BRAIN, cost: 0, actionType: 'api_call_read', attribution: {} });
  assert.equal(free.ok, true); assert.equal(free.deducted, 0);
});

test('threshold refill: moves DD owner→silicon below threshold, honours cooldown and amount', () => {
  const db = mkdb();
  fund(db, OWNER, 2000);
  fund(db, BRAIN, 60);
  const s = fb.upsertSilicon(db, { fleetId: 1, memberDid: BRAIN, handle: 'brain', displayName: 'Brain', contactEmail: 'brain@dustforge.com',
    refill: { enabled: true, threshold_cents: 50, amount_cents: 500 } });
  assert.equal(s.silicon_id, fb.siliconId(BRAIN));
  assert.equal(fb.thresholdRefill(db, billing, s).skipped, 'above threshold');
  // spend down to 40 via an attributed charge → inline refill fires
  const r = fb.chargeAttributed(db, billing, { callerDid: BRAIN, cost: 20, actionType: 'api_call_compute', attribution: {} });
  assert.equal(r.ok, true);
  assert.equal(bal(db, BRAIN), 540, 'refilled inline right after dropping below threshold');
  assert.equal(bal(db, OWNER), 1500);
  const types = db.prepare('SELECT type FROM identity_transactions WHERE did = ? ORDER BY id').all(OWNER).map(x => x.type);
  assert.deepEqual(types, ['topup', 'fleet_transfer_refill_out']);
  // cooldown: another drop within 10 minutes does not refill again
  billing.deductBalance(db, BRAIN, 520, 'api_call_compute', 'burn');
  const again = fb.thresholdRefill(db, billing, fb.getSilicon(db, 1, 'brain'));
  assert.equal(again.skipped, 'cooldown');
  // force refill with explicit amount (manual "Refill now")
  const forced = fb.thresholdRefill(db, billing, fb.getSilicon(db, 1, 'brain'), { force: true, amount: 100 });
  assert.equal(forced.ok, true); assert.equal(bal(db, BRAIN), 120);
  // owner short: error is recorded on the silicon, nothing moves
  billing.deductBalance(db, OWNER, 1390, 'api_call_compute', 'drain');
  const short = fb.thresholdRefill(db, billing, fb.getSilicon(db, 1, 'brain'), { force: true, amount: 500 });
  assert.equal(short.ok, false); assert.match(short.error, /insufficient/);
  assert.match(fb.getSilicon(db, 1, 'brain').last_refill_error, /insufficient/);
  assert.equal(bal(db, BRAIN), 120);
});

test('owner weekly refill: operator grant with idempotency, schedule advance, permission gate', () => {
  const db = mkdb();
  const rule = fb.setOwnerRefillRule(db, OWNER, { cadence: 'weekly', amount_cents: 1000, enabled: true, next_run_at: '2026-10-01T00:00:00.000Z' });
  assert.equal(rule.enabled, 1);
  const t = Date.parse('2026-10-03T12:00:00Z');
  const denied = fb.runOwnerRefills(db, billing, { now: t, grantDids: [] });
  assert.equal(denied[0].ok, false); assert.equal(bal(db, OWNER), 0);
  assert.match(fb.getOwnerRefillRule(db, OWNER).last_error, /not permitted/);
  const ran = fb.runOwnerRefills(db, billing, { now: t, grantDids: [OWNER] });
  assert.equal(ran[0].ok, true); assert.equal(bal(db, OWNER), 1000);
  const after = fb.getOwnerRefillRule(db, OWNER);
  assert.equal(after.next_run_at, '2026-10-08T00:00:00.000Z', 'advances from the scheduled time, not from now');
  assert.equal(after.last_error, '');
  // not due again
  assert.equal(fb.runOwnerRefills(db, billing, { now: t, grantDids: [OWNER] }).length, 0);
  // idempotency: same period cannot credit twice even if forced due
  db.prepare("UPDATE wallet_refill_rules SET next_run_at = '2026-10-01T00:00:00.000Z' WHERE did = ?").run(OWNER);
  const dup = fb.runOwnerRefills(db, billing, { now: t, grantDids: [OWNER] });
  assert.equal(dup[0].credited, 0); assert.equal(bal(db, OWNER), 1000);
  // stripe funding is explicit about not existing yet
  fb.setOwnerRefillRule(db, OTHER, { cadence: 'weekly', amount_cents: 500, funding: 'stripe', enabled: true, next_run_at: '2026-10-01T00:00:00.000Z' });
  const st = fb.runOwnerRefills(db, billing, { now: t, grantDids: [OTHER] });
  assert.match(st[0].error, /stripe/);
});

test('nextRunAfter skips forward past now', () => {
  const now = Date.parse('2026-10-20T00:00:00Z');
  assert.equal(fb.nextRunAfter('weekly', '2026-10-01T00:00:00.000Z', now), '2026-10-22T00:00:00.000Z');
  assert.equal(fb.nextRunAfter('daily', '2026-10-19T06:00:00.000Z', now), '2026-10-20T06:00:00.000Z');
});

test('work links: accept → token; charges bill the requester; tick window and revoke close it', () => {
  const db = mkdb();
  fund(db, OTHER, 100);
  const link = fb.createWorkLink(db, { requesterDid: OTHER, providerDid: BRAIN, ttlTicks: 3, project: 'kodiak', note: 'summarize', maxSpendCents: 5 });
  assert.equal(link.status, 'pending');
  assert.throws(() => fb.acceptWorkLink(db, { id: link.id, providerDid: OTHER }), /only the provider/);
  db.prepare("INSERT INTO ticks (did) VALUES ('x')").run(); // tick 1
  const { token, link: active } = fb.acceptWorkLink(db, { id: link.id, providerDid: BRAIN });
  assert.match(token, /^dpw_/); assert.equal(active.status, 'active'); assert.equal(active.start_tick, 1); assert.equal(active.end_tick, 4);
  // provider charges through the link → requester pays
  const r = fb.chargeAttributed(db, billing, { callerDid: BRAIN, cost: 2, actionType: 'api_call_compute', attribution: { work_link: token } });
  assert.equal(r.ok, true); assert.equal(r.payer_did, OTHER); assert.equal(r.initiator, 'work_link'); assert.equal(r.project, 'kodiak');
  assert.equal(bal(db, OTHER), 98);
  let row = db.prepare('SELECT * FROM fleet_work_links WHERE id = ?').get(link.id);
  assert.equal(row.use_count, 1); assert.equal(row.spent_cents, 2);
  // someone else cannot use the token
  const wrong = fb.resolvePayer(db, billing, { callerDid: OTHER, attribution: { work_link: token }, cost: 1 });
  assert.equal(wrong.ok, false); assert.match(wrong.error, /another provider/);
  // spend cap
  const cap = fb.resolvePayer(db, billing, { callerDid: BRAIN, attribution: { work_link: token }, cost: 4 });
  assert.equal(cap.ok, false); assert.equal(cap.status, 402);
  // tick window closes
  for (let i = 0; i < 4; i++) db.prepare("INSERT INTO ticks (did) VALUES ('x')").run(); // tick 5 > end 4
  const closed = fb.resolvePayer(db, billing, { callerDid: BRAIN, attribution: { work_link: token }, cost: 1 });
  assert.equal(closed.ok, false); assert.match(closed.error, /tick window/);
  assert.equal(db.prepare('SELECT status FROM fleet_work_links WHERE id = ?').get(link.id).status, 'expired');
  // revoke by either party on a fresh link
  const l2 = fb.createWorkLink(db, { requesterDid: OTHER, providerDid: BRAIN, ttlTicks: 100 });
  fb.acceptWorkLink(db, { id: l2.id, providerDid: BRAIN });
  assert.throws(() => fb.revokeWorkLink(db, { id: l2.id, byDid: OWNER }), /not a party/);
  assert.equal(fb.revokeWorkLink(db, { id: l2.id, byDid: OTHER }).status, 'revoked');
  // wall-clock cap
  const l3 = fb.createWorkLink(db, { requesterDid: OTHER, providerDid: BRAIN, ttlTicks: 100, ttlSeconds: 60 });
  const acc3 = fb.acceptWorkLink(db, { id: l3.id, providerDid: BRAIN, now: Date.now() - 120000 });
  const late = fb.validateWorkLink(db, acc3.token, BRAIN);
  assert.equal(late.ok, false); assert.match(late.error, /wall-clock/);
  assert.equal(fb.listWorkLinks(db, BRAIN).length, 3);
  assert.throws(() => fb.createWorkLink(db, { requesterDid: BRAIN, providerDid: BRAIN, ttlTicks: 1 }), /itself/);
});

test('silicon ids are stable, distinct, resolvable, and not the DID', () => {
  const db = mkdb();
  const a = fb.siliconId(BRAIN, 'k'); const b = fb.siliconId(BRAIN, 'k'); const c = fb.siliconId(OTHER, 'k');
  assert.equal(a, b); assert.notEqual(a, c); assert.match(a, /^sil_[0-9a-f]{16}$/);
  assert.ok(!a.includes('brain'));
  const s = fb.upsertSilicon(db, { fleetId: 1, memberDid: BRAIN, handle: 'brain' });
  assert.equal(fb.resolveSiliconId(db, s.silicon_id).did, BRAIN);
  assert.equal(fb.resolveSiliconId(db, 'sil_nope'), null);
  assert.throws(() => fb.upsertSilicon(db, { fleetId: 1, memberDid: OTHER, handle: 'Bad Handle' }), /handle/);
});

test('token status and expiry warnings', () => {
  const db = mkdb();
  const now = Date.parse('2026-10-03T00:00:00Z');
  fb.upsertSilicon(db, { fleetId: 1, memberDid: BRAIN, handle: 'brain', contactEmail: 'brain@dustforge.com' });
  assert.equal(fb.tokenStatus(db, BRAIN, now).status, 'none');
  db.prepare('INSERT INTO issued_tokens (jti, did, scope, issued_at, expires_at) VALUES (?, ?, ?, ?, ?)').run('old', BRAIN, 'transact', 0, Math.floor(now / 1000) - 10);
  assert.equal(fb.tokenStatus(db, BRAIN, now).status, 'expired');
  db.prepare('INSERT INTO issued_tokens (jti, did, scope, issued_at, expires_at) VALUES (?, ?, ?, ?, ?)').run('soon', BRAIN, 'transact', 0, Math.floor(now / 1000) + 3 * 86400);
  const t = fb.tokenStatus(db, BRAIN, now);
  assert.equal(t.status, 'expiring'); assert.equal(t.days_left, 3);
  const sent = [];
  const w1 = fb.runTokenWarnings(db, { now, mailer: m => sent.push(m) });
  assert.equal(w1.length, 1); assert.equal(sent[0].to, 'brain@dustforge.com'); assert.match(sent[0].text, /3 days left/);
  assert.equal(fb.runTokenWarnings(db, { now: now + 3600000, mailer: m => sent.push(m) }).length, 0, 'once per day');
  db.prepare('INSERT INTO issued_tokens (jti, did, scope, issued_at, expires_at) VALUES (?, ?, ?, ?, ?)').run('fresh', BRAIN, 'transact', 0, Math.floor(now / 1000) + 30 * 86400);
  assert.equal(fb.tokenStatus(db, BRAIN, now).status, 'valid');
});

test('runRefills runs every engine and attributionReport/recentSpend read back', () => {
  const db = mkdb();
  fund(db, OWNER, 1000);
  fb.upsertSilicon(db, { fleetId: 1, memberDid: BRAIN, handle: 'brain', refill: { enabled: true, threshold_cents: 50, amount_cents: 500 } });
  const out = fb.runRefills(db, billing, { now: Date.now(), grantDids: [] });
  assert.equal(out.silicons[0].ok, true); assert.equal(bal(db, BRAIN), 500);
  fb.chargeAttributed(db, billing, { callerDid: BRAIN, cost: 7, actionType: 'api_call_compute', attribution: { project: 'brain', initiator: 'operator' } });
  fb.chargeAttributed(db, billing, { callerDid: BRAIN, cost: 2, actionType: 'api_call_compute', attribution: { project: 'brain', initiator: 'autonomous' } });
  const rep = fb.attributionReport(db, { payerDids: [OWNER], actorDids: [BRAIN] });
  const byInit = Object.fromEntries(rep.rows.map(r => [r.initiator, r.cents]));
  assert.equal(byInit.operator, 7); assert.equal(byInit.autonomous, 2);
  const spend = fb.recentSpend(db, BRAIN, 5);
  assert.equal(spend[0].project, 'brain'); assert.equal(spend[0].initiator, 'autonomous');
  const view = fb.siliconView(db, billing, fb.getSilicon(db, 1, 'brain'), { fleet: { slug: 'aaron-agents', name: 'Aaron Agents' } });
  assert.equal(view.balance_cents, 498); assert.equal(view.refill.threshold_cents, 50); assert.equal(view.token.status, 'none');
  assert.match(fb.didRecordEmail({ silicon: fb.getSilicon(db, 1, 'brain'), fleet: { name: 'Aaron Agents', slug: 'aaron-agents', owner_did: OWNER }, wallet: { username: 'brain', email: 'brain@dustforge.com' } }), /Silicon id:\s+sil_/);
});
