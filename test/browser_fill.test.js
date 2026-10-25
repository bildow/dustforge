'use strict';
// node --test test/browser_fill.test.js — which origins a stored login may be bound to and filled into.
const test = require('node:test');
const assert = require('node:assert/strict');
const bf = require('../browser_fill');

test('normalizeOrigin keeps scheme, host and port; drops path, query and fragment', () => {
  assert.equal(bf.normalizeOrigin('https://Login.Example.com/signin?next=/a#x'), 'https://login.example.com');
  assert.equal(bf.normalizeOrigin('https://example.com:8443/'), 'https://example.com:8443');
  assert.equal(bf.normalizeOrigin('https://example.com:443'), 'https://example.com');
  assert.equal(bf.normalizeOrigin('https://bücher.example'), 'https://xn--bcher-kva.example', 'IDN compares as punycode');
});

test('normalizeOrigin refuses anything a password should not travel over', () => {
  for (const bad of ['http://example.com', 'javascript:alert(1)', 'data:text/html,x', 'ftp://example.com', 'file:///etc/passwd',
    'https://user:pw@example.com', 'example.com', '', null, 42, 'https://' + 'a'.repeat(2100)]) {
    assert.equal(bf.normalizeOrigin(bad), null, String(bad).slice(0, 40));
  }
});

test('plain http only for localhost and 127.0.0.1', () => {
  assert.equal(bf.normalizeOrigin('http://localhost:3000/x'), 'http://localhost:3000');
  assert.equal(bf.normalizeOrigin('http://127.0.0.1'), 'http://127.0.0.1');
  assert.equal(bf.normalizeOrigin('http://localhost.example.com'), null);
  assert.equal(bf.normalizeOrigin('http://10.0.0.1'), null);
});

test('parseOrigins dedupes after normalizing, names the bad one, caps the count', () => {
  assert.deepEqual(bf.parseOrigins(['https://a.example/x', 'https://a.example/y']), { origins: ['https://a.example'] });
  assert.match(bf.parseOrigins(['https://a.example', 'http://b.example']).error, /http:\/\/b\.example/);
  assert.match(bf.parseOrigins('https://a.example').error, /array/);
  const eleven = Array.from({ length: 11 }, (_, i) => `https://h${i}.example`);
  assert.match(bf.parseOrigins(eleven).error, /at most 10/);
  assert.deepEqual(bf.parseOrigins([]), { origins: [] });
});

test('storedOrigins fails closed on a corrupt column', () => {
  assert.deepEqual(bf.storedOrigins(null), []);
  assert.deepEqual(bf.storedOrigins('{not json'), []);
  assert.deepEqual(bf.storedOrigins('{"a":1}'), []);
  assert.deepEqual(bf.storedOrigins('["https://a.example", 5]'), ['https://a.example']);
});

test('validLogin: emails and names, no control characters, bounded', () => {
  assert.ok(bf.validLogin('me+tag@example.com'));
  assert.ok(bf.validLogin(''));
  assert.ok(!bf.validLogin('a\nb'));
  assert.ok(!bf.validLogin('x'.repeat(257)));
  assert.ok(!bf.validLogin(7));
});

test('request codes are unguessable and distinct', () => {
  const a = bf.newRequestCode(), b = bf.newRequestCode();
  assert.match(a, /^dpf_[A-Za-z0-9_-]{32}$/);
  assert.notEqual(a, b);
});
