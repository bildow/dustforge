'use strict';
const test = require('node:test');
const assert = require('node:assert');
const t = require('../secret_types');

test('every type the menu advertises is a vault type', () => {
  for (const name of ['ssh_credential', 'passphrase', 'token', 'multi_string', 'api_key', 'password', 'oauth_token', 'signing_key', 'webhook_secret', 'connection_string', 'certificate', 'other']) {
    assert.strictEqual(t.canonicalType(name), name, name);
  }
});

test('old names map; unknown names are refused, never relabelled', () => {
  assert.strictEqual(t.canonicalType('ssh_key'), 'ssh_credential');
  assert.strictEqual(t.canonicalType('SSH-Key'), 'ssh_credential');
  assert.strictEqual(t.canonicalType('cert'), 'certificate');
  assert.strictEqual(t.canonicalType('nope'), null);
  const r = t.resolveType('nope', 'x');
  assert.ok(r.error && r.valid_types.includes('ssh_credential'));
  assert.ok(t.resolveType(42, 'x').error);
});

test('inference from the value when no type is named', () => {
  const cases = [
    ['-----BEGIN OPENSSH PRIVATE KEY-----\nAAA\n-----END OPENSSH PRIVATE KEY-----', 'ssh_credential'],
    ['-----BEGIN RSA PRIVATE KEY-----\nAAA', 'ssh_credential'],
    ['-----BEGIN PGP PRIVATE KEY BLOCK-----\nAAA', 'signing_key'],
    ['-----BEGIN CERTIFICATE-----\nAAA', 'certificate'],
    ['postgres://u:p@db.example.com:5432/app', 'connection_string'],
    ['whsec_abcdefgh12345678', 'webhook_secret'],
    ['eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.sig', 'token'],
    ['ghp_0123456789abcdefghij', 'token'],
    ['sk-or-v1-0123', 'api_key'],
    ['plain-value', 'api_key'],
  ];
  for (const [v, want] of cases) assert.strictEqual(t.resolveType(undefined, v).type, want, v.slice(0, 20));
  assert.strictEqual(t.resolveType('', 'plain', { username: 'root' }).type, 'password');
  assert.strictEqual(t.resolveType(undefined, 'x').inferred, true);
  assert.strictEqual(t.resolveType('token', 'x').inferred, false);
});

test('ref prefixes and default actions, including stored aliases', () => {
  assert.strictEqual(t.refPrefix('ssh_credential'), 'SSH');
  assert.strictEqual(t.refPrefix('ssh_key'), 'SSH');
  assert.strictEqual(t.refPrefix('password'), 'PWD');
  assert.strictEqual(t.refPrefix('api_key'), 'API');
  assert.strictEqual(t.refPrefix('whatever'), 'SEC');
  // The types live secrets carry keep the actions they had.
  assert.strictEqual(t.defaultAction('api_key'), 'http_header');
  assert.strictEqual(t.defaultAction('password'), 'ssh_exec');
  assert.strictEqual(t.defaultAction('oauth_token'), 'http_header');
  assert.strictEqual(t.defaultAction('other'), 'http_header');
  assert.strictEqual(t.defaultAction('ssh_credential'), 'ssh_exec');   // was http_header (no entry)
  assert.strictEqual(t.defaultAction('cert'), 'http_header');
});
