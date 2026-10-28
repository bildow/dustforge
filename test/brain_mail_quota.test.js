'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const Database = require('better-sqlite3');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { brainMailQuota, BRAIN_DID } = require('../brain_mail_quota');
const today = Date.parse('2026-10-28T23:59:59Z');
function attempt(db, did = BRAIN_DID, now = today, extra = {}) {
  const res = new EventEmitter();
  res.statusCode = 200;
  res.status = code => { res.statusCode = code; return res; };
  res.json = body => { res.body = body; res.emit('finish'); return res; };
  let next = 0;
  const handled = brainMailQuota(db, { identity: { did }, ...extra }, res, () => next++, now);
  return { handled, next, res };
}
test('36 accepted, 37 refused; pending reservations count and UTC midnight renews', () => {
  const db = new Database(':memory:');
  for (let i = 0; i < 36; i++) assert.equal(attempt(db).next, 1);
  const last = attempt(db);
  assert.equal(last.next, 0);
  assert.equal(last.res.statusCode, 429);
  assert.equal(last.res.body.limit, 36);
  assert.equal(attempt(db, BRAIN_DID, today + 1000).next, 1);
  db.close();
});
test('Brain does not touch exhausted communal pool; body and sender spoof cannot qualify', () => {
  const db = new Database(':memory:');
  db.exec("CREATE TABLE email_warmup_daily(day TEXT PRIMARY KEY,sent INTEGER); INSERT INTO email_warmup_daily VALUES('2026-10-28',80)");
  assert.equal(attempt(db).next, 1);
  for (const did of ['other', undefined]) {
    const r = attempt(db, did === undefined ? null : did, today, { body: { did: BRAIN_DID, from: 'brain@dustforge.com', username: 'brain' } });
    assert.equal(r.handled, false);
    assert.equal(r.next, 0);
  }
  assert.equal(db.prepare('SELECT sent FROM email_warmup_daily').get().sent, 80);
  for (let i = 1; i < 36; i++) attempt(db);
  assert.equal(attempt(db).res.statusCode, 429);
  assert.equal(attempt(db, 'other').handled, false, 'other accounts retain communal path');
  db.close();
});
test('definitive failure releases once; success and disconnected requests retain slot', () => {
  const db = new Database(':memory:');
  const a = attempt(db); a.res.statusCode = 502; a.res.emit('finish'); a.res.emit('finish');
  assert.equal(db.prepare('SELECT sent FROM email_identity_daily').get().sent, 0);
  const b = attempt(db); b.res.emit('finish');
  const c = attempt(db); c.res.emit('close');
  assert.equal(db.prepare('SELECT sent FROM email_identity_daily').get().sent, 2);
  db.close();
});
test('counter survives reopening and multiple connections cannot exceed cap', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'brain-mail-quota-'));
  const file = path.join(dir, 'quota.db');
  try {
    let a = new Database(file); attempt(a); a.close();
    a = new Database(file); const b = new Database(file);
    let accepted = 1;
    for (let i = 0; i < 80; i++) accepted += attempt(i % 2 ? a : b).next;
    assert.equal(accepted, 36); a.close(); b.close();
  } finally { fs.rmSync(dir, { recursive: true }); }
});
test('database failure refuses without calling downstream', () => {
  const db = new Database(':memory:'); db.close();
  const r = attempt(db);
  assert.equal(r.res.statusCode, 503); assert.equal(r.next, 0); assert.equal(r.handled, true);
});
test('real route authenticates with scope/revocation before quota, charges only after quota', () => {
  const source = fs.readFileSync(path.join(__dirname, '../server.js'), 'utf8');
  assert.match(source, /app\.post\('\/api\/email\/send', billing\.billingMiddleware\(db, 'email_send', \{ cost: 0 \}\), emailWarmupGuard, billing\.billingMiddleware\(db, 'email_send'\)/);
});

test('real communal guard remains independent: Brain passes at 80, other caller refuses; at 79 other passes', () => {
  const vm = require('node:vm');
  const source = fs.readFileSync(path.join(__dirname, '../server.js'), 'utf8');
  const body = source.slice(source.indexOf('function emailWarmupGuard('), source.indexOf('\nfunction safeSecretEqual('));
  const db = new Database(':memory:');
  db.exec("CREATE TABLE email_warmup_daily(day TEXT PRIMARY KEY,sent INTEGER); INSERT INTO email_warmup_daily VALUES('2026-10-28',80)");
  class Clock extends Date { static now() { return today; } }
  const guard = vm.runInNewContext(body + '\nemailWarmupGuard', {
    db, require: () => ({ brainMailQuota }), Date: Clock, console,
    process: { env: { MAIL_WARMUP_START_UTC: '2026-10-07', MAIL_WARMUP_INITIAL_DAILY_LIMIT: '10', MAIL_WARMUP_MAX_DAILY_LIMIT: '100' } },
  });
  const run = did => {
    const res = new EventEmitter(); res.statusCode = 200;
    res.status = code => { res.statusCode = code; return res; };
    res.json = body => { res.body = body; res.emit('finish'); };
    let next = 0;
    guard({ identity: { did } }, res, () => next++);
    return { res, next };
  };
  assert.equal(run(BRAIN_DID).next, 1);
  assert.equal(run('other').res.statusCode, 429);
  db.exec('UPDATE email_warmup_daily SET sent = 79');
  assert.equal(run('other').next, 1);
  assert.equal(db.prepare('SELECT sent FROM email_warmup_daily').get().sent, 80);
  assert.equal(db.prepare('SELECT sent FROM email_identity_daily').get().sent, 1);
  db.close();
});
