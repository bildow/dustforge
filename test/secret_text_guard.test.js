'use strict';
// node --test test/secret_text_guard.test.js
const test = require('node:test');
const assert = require('node:assert/strict');
const Database = require('better-sqlite3');
const g = require('../secret_text_guard');

test('valueInText: raw and JSON-escaped forms; short values and empty texts never match', () => {
  assert.equal(g.valueInText('hunter2222', 'Unified to hunter2222 on 07-07'), true);
  assert.equal(g.valueInText('pa"ss\\word', 'json: pa\\"ss\\\\word'), true);   // as it appears inside a JSON string
  assert.equal(g.valueInText('hunter2222', 'nothing here', '', null, undefined), false);
  assert.equal(g.valueInText('12345', 'pin 12345'), false);                  // under MIN_OWN: PINs and codes pass
  assert.equal(g.valueInText('', 'x'), false);
  assert.equal(g.valueInText(undefined, 'x'), false);
  assert.equal(g.valueInText('hunter2222', null, 'note: hunter2222'), true);  // any of the texts
});

function mkdb() {
  // Legacy-shaped row set: one value that does not decrypt (kept, never matched), one deleted secret (ignored).
  const db = new Database(':memory:');
  db.exec(`CREATE TABLE blindkey_secrets (id INTEGER PRIMARY KEY AUTOINCREMENT, did TEXT, name TEXT, ref_code TEXT DEFAULT '',
             description TEXT DEFAULT '', encrypted_value TEXT, status TEXT DEFAULT 'active')`);
  const ins = db.prepare('INSERT INTO blindkey_secrets (did, name, ref_code, description, encrypted_value, status) VALUES (?, ?, ?, ?, ?, ?)');
  ins.run('A', 'shared', 'DP-1', 'the shared login', 'enc:sharedpassword1', 'active');
  ins.run('A', 'longer', 'DP-2', 'x', 'enc:sharedpassword1-and-more', 'active');
  ins.run('A', 'imap', 'DP-3', 'Unified to sharedpassword1-and-more 07-07 (was sharedpassword1)', 'enc:imapvalue99', 'active');
  ins.run('A', 'broken', 'DP-4', 'mentions sharedpassword1', '!!not-decryptable', 'active');
  ins.run('A', 'gone', 'DP-5', 'whatever', 'enc:deletedvalue77', 'deleted');
  ins.run('B', 'other', 'DP-6', 'B quotes sharedpassword1', 'enc:bvalue123456', 'active');
  return db;
}
const decrypt = (e) => { if (!String(e).startsWith('enc:')) throw new Error('bad'); return e.slice(4); };

test('sweepDescriptions: names who holds what, longest value cut whole, only the owner, only with redact', () => {
  const db = mkdb();
  const found = g.sweepDescriptions(db, decrypt, 'A');
  const byName = Object.fromEntries(found.map(f => [f.name, f.holds.sort()]));
  assert.deepEqual(byName, { imap: ['longer', 'shared'], broken: ['shared'] });
  assert.match(db.prepare("SELECT description FROM blindkey_secrets WHERE name = 'imap'").get().description, /sharedpassword1/);   // check only

  g.sweepDescriptions(db, decrypt, 'A', { redact: true });
  assert.equal(db.prepare("SELECT description FROM blindkey_secrets WHERE name = 'imap'").get().description,
    `Unified to ${g.REDACTED} 07-07 (was ${g.REDACTED})`);
  assert.equal(db.prepare("SELECT description FROM blindkey_secrets WHERE name = 'broken'").get().description, `mentions ${g.REDACTED}`);
  assert.equal(db.prepare("SELECT description FROM blindkey_secrets WHERE name = 'other'").get().description, 'B quotes sharedpassword1');   // B's row untouched
  assert.deepEqual(g.sweepDescriptions(db, decrypt, 'A'), []);
});
