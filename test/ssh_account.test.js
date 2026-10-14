'use strict';
// node --test test/ssh_account.test.js
// Ported from test/resolve-ssh-target-user.test.js on fix/account-binding-on-secrets (PR #1):
// explicit → secret.username → context.target_user_default → HARD ERROR; no 'claude' fallback.
const test = require('node:test');
const assert = require('node:assert/strict');
const { resolveSshTargetUser: resolve, validUsername } = require('../ssh_account');

test('validUsername: SSH-safe grammar, 1–128 chars', () => {
  for (const ok of ['flimflam', 'claude', 'root', 'kyle.m', 'svc_user-1', 'a'.repeat(128)]) assert.equal(validUsername(ok), true, ok);
  for (const bad of ['', 'admin@example.com', 'user+role', 'nobody; rm -rf /', ' claude', 'a'.repeat(129), null, undefined, 42]) assert.equal(validUsername(bad), false, String(bad));
});

test('bound secret + no explicit → bound username, attribution=bound', () => {
  const r = resolve({ secret: { username: 'flimflam' }, context: null });
  assert.equal(r.ok, true); assert.equal(r.effective_user, 'flimflam'); assert.equal(r.override, null); assert.equal(r.attribution, 'bound');
});

test('bound secret + matching explicit → no override, attribution=bound', () => {
  const r = resolve({ explicit: 'flimflam', secret: { username: 'flimflam' }, context: null });
  assert.equal(r.ok, true); assert.equal(r.effective_user, 'flimflam'); assert.equal(r.override, null); assert.equal(r.attribution, 'bound');
});

test('bound secret + different explicit + no reason → hard error asking for override_reason', () => {
  const r = resolve({ explicit: 'root', secret: { username: 'flimflam' }, context: null });
  assert.equal(r.ok, false); assert.equal(r.status, 400); assert.match(r.error, /override_reason/);
});

test('bound secret + different explicit + reason → allowed, override recorded, attribution=override', () => {
  const r = resolve({ explicit: 'root', secret: { username: 'flimflam' }, context: null, override_reason: 'need to fix sudoers as root' });
  assert.equal(r.ok, true); assert.equal(r.effective_user, 'root'); assert.equal(r.attribution, 'override');
  assert.deepEqual(r.override, { bound_username: 'flimflam', explicit: 'root', reason: 'need to fix sudoers as root' });
});

test('unbound (legacy) secret + explicit → explicit, attribution=legacy', () => {
  const r = resolve({ explicit: 'flimflam', secret: { username: '' }, context: null });
  assert.equal(r.ok, true); assert.equal(r.effective_user, 'flimflam'); assert.equal(r.attribution, 'legacy');
});

test('unbound secret + no explicit + no context default → hard error, never claude', () => {
  const r = resolve({ secret: { username: '' }, context: null });
  assert.equal(r.ok, false); assert.equal(r.status, 400); assert.match(r.error, /unresolved/);
  assert.notEqual(r.effective_user, 'claude');
  const r2 = resolve({ secret: {}, context: {} });
  assert.equal(r2.ok, false);
  const r3 = resolve({});
  assert.equal(r3.ok, false);
});

test('unbound secret + no explicit + context default → context default, attribution=legacy', () => {
  const r = resolve({ secret: { username: '' }, context: { target_user_default: 'apple' } });
  assert.equal(r.ok, true); assert.equal(r.effective_user, 'apple'); assert.equal(r.attribution, 'legacy');
});

test('binding beats the context default', () => {
  const r = resolve({ secret: { username: 'flimflam' }, context: { target_user_default: 'root' } });
  assert.equal(r.ok, true); assert.equal(r.effective_user, 'flimflam'); assert.equal(r.attribution, 'bound');
});

test('a bound username outside the grammar (pre-fix rows) is refused, not used', () => {
  for (const u of ['admin@example.com', 'user+role']) {
    const r = resolve({ secret: { username: u }, context: null });
    assert.equal(r.ok, false); assert.match(r.error, /invalid bound username/);
  }
});

test('shape-invalid explicit target_user → hard error', () => {
  const r = resolve({ explicit: 'nobody; rm -rf /', secret: { username: '' }, context: null });
  assert.equal(r.ok, false); assert.equal(r.status, 400); assert.match(r.error, /invalid target_user/);
});

test('override_reason too long or with control characters → hard error', () => {
  for (const reason of ['x'.repeat(129), 'sneaky\x00null']) {
    const r = resolve({ explicit: 'root', secret: { username: 'flimflam' }, context: null, override_reason: reason });
    assert.equal(r.ok, false); assert.match(r.error, /override_reason/);
  }
});

test('TERMINATION: flimflam-sudo bound to flimflam + no explicit ⇒ flimflam, not claude', () => {
  const r = resolve({ secret: { username: 'flimflam' }, context: null });
  assert.equal(r.ok, true); assert.equal(r.effective_user, 'flimflam');
});

test('K1 fixture: shared-kyle-ssh bound to claude + Codex passes nothing ⇒ claude', () => {
  const r = resolve({ secret: { username: 'claude' }, context: { target_user_default: '' } });
  assert.equal(r.ok, true); assert.equal(r.effective_user, 'claude'); assert.equal(r.attribution, 'bound');
});
