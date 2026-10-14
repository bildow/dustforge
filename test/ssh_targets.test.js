'use strict';
// node --test test/ssh_targets.test.js
const test = require('node:test');
const assert = require('node:assert/strict');
const t = require('../ssh_targets');

// Verbatim copy of server.js blindkeyPatternMatch — chooseContext takes it as a parameter.
function patternMatch(pattern, value) {
  if (!pattern || pattern === '*') return true;
  if (!value) return false;
  const cleanValue = value.replace(/^https?:\/\//, '');
  const cleanPattern = pattern.replace(/^https?:\/\//, '');
  if (cleanPattern.endsWith('*')) return cleanValue.startsWith(cleanPattern.slice(0, -1));
  return cleanValue === cleanPattern;
}

test('resolveSshTarget: IP, tailnet name, OS hostname and MagicDNS FQDN all canonicalise to the whitelisted IP', () => {
  assert.equal(t.resolveSshTarget('100.69.1.78').ip, '100.69.1.78');
  assert.equal(t.resolveSshTarget('k1').ip, '100.69.1.78');
  assert.equal(t.resolveSshTarget('K1').ip, '100.69.1.78');
  assert.equal(t.resolveSshTarget('k1.taildb5a42.ts.net.').ip, '100.69.1.78');
  assert.equal(t.resolveSshTarget('flimflam-All-Series').ip, '100.103.90.79'); // what Codex sent on 2026-10-13
  assert.equal(t.resolveSshTarget('flimflam-all-series.taildb5a42.ts.net').ip, '100.103.90.79');
  assert.equal(t.resolveSshTarget(' flimflam ').ip, '100.103.90.79');
  assert.equal(t.resolveSshTarget('phasewhip').ip, '100.83.112.88');
  assert.equal(t.resolveSshTarget('racknerd').ip, '192.3.84.103');
  assert.equal(t.resolveSshTarget('ky7').name, 'ky7');
  assert.equal(t.resolveSshTarget('flimflam-All-Series').input, 'flimflam-All-Series');
});

test('resolveSshTarget: anything that is not an allowed host is refused', () => {
  for (const bad of ['8.8.8.8', '100.73.251.12', 'forge', 'brain', 'flimflam-All-Series; id', 'k 1', '', '.', null, undefined, 42, {}]) {
    assert.equal(t.resolveSshTarget(bad), null, `expected null for ${JSON.stringify(bad)}`);
  }
});

test('whitelist error and listing name every allowed host', () => {
  const msg = t.sshWhitelistError('forge');
  assert.match(msg, /^host forge not in SSH whitelist\. Allowed: /);
  assert.match(msg, /k1 \(100\.69\.1\.78\)/);
  assert.match(msg, /flimflam \(100\.103\.90\.79\)/);
  assert.deepEqual(t.listSshTargets().map(x => x.ip), [...t.BLINDKEY_SSH_HOSTS]);
  assert.equal(t.BLINDKEY_SSH_HOSTS.size, 6);
});

test('canonicalHostPattern: names become IPs for ssh_exec; wildcards, unknown hosts and other actions untouched', () => {
  assert.equal(t.canonicalHostPattern('ssh_exec', 'flimflam-All-Series'), '100.103.90.79');
  assert.equal(t.canonicalHostPattern('ssh_exec', '100.69.1.78'), '100.69.1.78');
  assert.equal(t.canonicalHostPattern('ssh_exec', '*'), '*');
  assert.equal(t.canonicalHostPattern('ssh_exec', '100.83.*'), '100.83.*');
  assert.equal(t.canonicalHostPattern('ssh_exec', 'forge'), 'forge');
  assert.equal(t.canonicalHostPattern('http_header', 'flimflam'), 'flimflam');
  assert.equal(t.canonicalHostPattern('ssh_exec', undefined), undefined);
});

// blindkey_contexts rows of shared-kyle-ssh (secret 131) on prod, 2026-10-13: table order is phasewhip first.
const KYLE = [
  { id: 9,  secret_id: 131, context_name: 'ssh_exec-100.83.112.88', action_type: 'ssh_exec', target_url_pattern: '*', target_host_pattern: '100.83.112.88', status: 'active' },
  { id: 19, secret_id: 131, context_name: 'k1-ssh',                 action_type: 'ssh_exec', target_url_pattern: '*', target_host_pattern: '100.69.1.78',   status: 'active' },
];

test('chooseContext: the context that covers the requested host wins, not the first row (K1 regression)', () => {
  assert.equal(t.chooseContext(KYLE, { action: 'ssh_exec', targetHost: '100.69.1.78', patternMatch }).context.context_name, 'k1-ssh');
  assert.equal(t.chooseContext(KYLE, { action: 'ssh_exec', targetHost: '100.83.112.88', patternMatch }).context.context_name, 'ssh_exec-100.83.112.88');
});

test('chooseContext: a pattern stored as a name still matches when the agent typed that name', () => {
  const rows = [{ id: 1, context_name: 'ssh_exec-flimflam', action_type: 'ssh_exec', target_host_pattern: 'flimflam-All-Series', target_url_pattern: '*', status: 'active' }];
  const r = t.chooseContext(rows, { action: 'ssh_exec', targetHost: ['100.103.90.79', 'flimflam-All-Series'], patternMatch });
  assert.equal(r.context.context_name, 'ssh_exec-flimflam');
});

test('chooseContext: no context covers the host → null, with the candidates listed for the error message', () => {
  const r = t.chooseContext(KYLE, { action: 'ssh_exec', targetHost: '100.94.192.51', patternMatch });
  assert.equal(r.context, null);
  assert.equal(r.matched, false);
  assert.deepEqual(r.candidates.map(c => c.context_name), ['ssh_exec-100.83.112.88', 'k1-ssh']);
});

test('chooseContext: most specific pattern wins; inactive and other-action contexts are ignored', () => {
  const rows = [
    { id: 1, context_name: 'any',       action_type: 'ssh_exec',    target_host_pattern: '*',             status: 'active' },
    { id: 2, context_name: 'tailnet',   action_type: 'ssh_exec',    target_host_pattern: '100.*',         status: 'active' },
    { id: 3, context_name: 'k1-exact',  action_type: 'ssh_exec',    target_host_pattern: '100.69.1.78',   status: 'active' },
    { id: 4, context_name: 'k1-old',    action_type: 'ssh_exec',    target_host_pattern: '100.69.1.78',   status: 'revoked' },
    { id: 5, context_name: 'api',       action_type: 'http_header', target_url_pattern: '*', target_host_pattern: '*', status: 'active' },
  ];
  assert.equal(t.chooseContext(rows, { action: 'ssh_exec', targetHost: '100.69.1.78', patternMatch }).context.context_name, 'k1-exact');
  assert.equal(t.chooseContext(rows, { action: 'ssh_exec', targetHost: '100.83.112.88', patternMatch }).context.context_name, 'tailnet');
  assert.equal(t.chooseContext(rows, { action: 'ssh_exec', targetHost: '192.3.84.103', patternMatch }).context.context_name, 'any');
  assert.equal(t.chooseContext(rows, { action: 'http_header', targetUrl: 'https://api.github.com/x', patternMatch }).context.context_name, 'api');
});

test('chooseContext: http actions choose by URL pattern', () => {
  const rows = [
    { id: 1, context_name: 'github', action_type: 'http_header', target_url_pattern: 'https://api.github.com/*', target_host_pattern: '*', status: 'active' },
    { id: 2, context_name: 'stripe', action_type: 'http_header', target_url_pattern: 'https://api.stripe.com/*', target_host_pattern: '*', status: 'active' },
  ];
  assert.equal(t.chooseContext(rows, { action: 'http_header', targetUrl: 'https://api.stripe.com/v1/charges', patternMatch }).context.context_name, 'stripe');
  assert.equal(t.chooseContext(rows, { action: 'http_header', targetUrl: 'https://api.openai.com/v1', patternMatch }).context, null);
});

test('chooseContext: no target given → first active context of that action (old behaviour kept)', () => {
  assert.equal(t.chooseContext(KYLE, { action: 'ssh_exec', patternMatch }).context.context_name, 'ssh_exec-100.83.112.88');
});

test('chooseContext: no context for that action → first active context, so the enforcer reports the mismatch', () => {
  const r = t.chooseContext(KYLE, { action: 'http_header', targetUrl: 'https://api.github.com', patternMatch });
  assert.equal(r.context.context_name, 'ssh_exec-100.83.112.88');
  assert.equal(r.matched, false);
  assert.deepEqual(r.candidates, []);
  assert.equal(t.chooseContext([], { action: 'ssh_exec', targetHost: '100.69.1.78', patternMatch }).context, null);
});
