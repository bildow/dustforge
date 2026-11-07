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
  // Legacy-shaped rows: one value that does not decrypt (wrapped: counted unchecked), one deleted secret (ignored).
  const db = new Database(':memory:');
  db.exec(`CREATE TABLE blindkey_secrets (id INTEGER PRIMARY KEY AUTOINCREMENT, did TEXT, name TEXT, ref_code TEXT DEFAULT '',
             description TEXT DEFAULT '', note TEXT, encrypted_value TEXT, status TEXT DEFAULT 'active', updated_at TEXT)`);
  const ins = db.prepare('INSERT INTO blindkey_secrets (did, name, ref_code, description, note, encrypted_value, status, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)');
  const old = '2026-07-07 10:00:00';
  ins.run('A', 'shared', 'DP-1', 'the shared login', null, 'enc:sharedpassword1', 'active', old);
  ins.run('A', 'longer', 'DP-2', 'x', null, 'enc:sharedpassword1-and-more', 'active', old);
  ins.run('A', 'imap', 'DP-3', 'Unified to sharedpassword1-and-more 07-07', null, 'enc:imapvalue99', 'active', old);
  ins.run('A', 'noted', 'DP-7', 'fine', 'old pw sharedpassword1', 'enc:notedvalue88', 'active', old);
  ins.run('A', 'planted', 'DP-8', 'guesses: sharedpassword1 imapvalue99 nope1234', null, 'enc:plantedvalue1', 'active', '2026-11-07 11:00:00');
  ins.run('A', 'wrapped', 'DP-4', 'mentions sharedpassword1', null, 'dpwrap:v1:xyz', 'active', old);
  ins.run('A', 'gone', 'DP-5', 'whatever', null, 'enc:deletedvalue77', 'deleted', old);
  ins.run('B', 'other', 'DP-6', 'B quotes sharedpassword1', null, 'enc:bvalue123456', 'active', old);
  return db;
}
const decrypt = (e) => { if (!String(e).startsWith('enc:')) throw new Error('wrapped'); return e.slice(4); };
const NOW = Date.parse('2026-11-08T00:00:00Z');
const desc = (db, n, f = 'description') => db.prepare(`SELECT ${f} AS v FROM blindkey_secrets WHERE name = ?`).get(n).v;

test('sweep: names what holds which values (descriptions and notes), counts unreadable ones, flags planted-looking rows', () => {
  const db = mkdb();
  const { found, unchecked } = g.sweepDescriptions(db, decrypt, 'A', { now: NOW });
  const by = Object.fromEntries(found.map(f => [f.name, f]));
  assert.deepEqual(Object.keys(by).sort(), ['imap', 'noted', 'planted', 'wrapped']);
  assert.deepEqual(by.imap.holds.sort(), ['longer', 'shared']);
  assert.deepEqual(by.noted.fields, ['note']);
  assert.equal(by.planted.flagged, true);          // changed within 7 days and holds two secrets' values
  assert.equal(by.imap.flagged, true);             // holds two (the longer value contains the shorter)
  assert.equal(by.noted.flagged, false);
  assert.equal(unchecked, 1);                      // the wrapped one: never claimed clean
  assert.match(desc(db, 'imap'), /sharedpassword1/);   // a check changes nothing
});

test('sweep with redactIds: only the picked rows, longest value cut whole, notes too, other owners untouched', () => {
  const db = mkdb();
  const ids = g.sweepDescriptions(db, decrypt, 'A', { now: NOW }).found.filter(f => ['imap', 'noted'].includes(f.name)).map(f => f.id);
  g.sweepDescriptions(db, decrypt, 'A', { redactIds: ids, now: NOW });
  assert.equal(desc(db, 'imap'), `Unified to ${g.REDACTED} 07-07`);
  assert.equal(desc(db, 'noted', 'note'), `old pw ${g.REDACTED}`);
  assert.match(desc(db, 'planted'), /sharedpassword1 imapvalue99/);   // not picked: left as it was (no oracle)
  assert.equal(desc(db, 'other'), 'B quotes sharedpassword1');
  assert.deepEqual(g.sweepDescriptions(db, decrypt, 'A', { now: NOW }).found.map(f => f.name).sort(), ['planted', 'wrapped']);
});

test('cutValue (rotation copies) and a trailing newline on the stored value', () => {
  assert.equal(g.cutValue('Unified to hunter2222 (rotated)', 'hunter2222'), `Unified to ${g.REDACTED} (rotated)`);
  assert.equal(g.cutValue('short pin 1234', '1234'), 'short pin 1234');
  assert.equal(g.valueInText('hunter2222\n', 'Unified to hunter2222'), true);
});
