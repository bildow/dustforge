'use strict';
// node --test test/hostops.test.js — the pure core of DemiPass host operations (hostops.js).
const test = require('node:test');
const assert = require('node:assert/strict');
const { execFileSync } = require('child_process');
const h = require('../hostops');

const FLIGHT = {
  name: 'flight', mode: 'job', sudo: true, max_seconds: 10800,
  argv: ['/usr/local/sbin/agent-ssd-flight.sh', { slot: 'container', enum: ['brain2', 'soul2', 'triadic2'] },
    { slot: 'stamp', match: '^[0-9]{8}T[0-9]{4}Z$' }, { literal: 'precopy', optional: true }],
};
const POOL = {
  name: 'pool-create', sudo: true, max_seconds: 60,
  argv: ['incus', 'storage', 'create', { slot: 'pool', type: 'word' }, 'dir', { slot: 'src', type: 'path', prefix: 'source=', under: ['/srv/agent-ssd/'] }],
};
const shape = s => { const v = h.validateShape(s); assert.equal(v.ok, true, v.error); return v.shape; };

test('validateShape: a well-formed job and run shape are accepted and normalised', () => {
  const f = shape(FLIGHT);
  assert.equal(f.mode, 'job'); assert.equal(f.sudo, true); assert.equal(f.max_seconds, 10800);
  assert.deepEqual(f.argv[0], { literal: '/usr/local/sbin/agent-ssd-flight.sh' });
  assert.equal(f.argv[3].optional, true);
  const p = shape(POOL);
  assert.equal(p.mode, 'run'); assert.equal(p.argv[5].prefix, 'source=');
  assert.equal(shape({ name: 'ls', argv: ['incus', 'list'] }).max_seconds, 60, 'run default');
});

test('validateShape: refusals say why', () => {
  const bad = [
    [{ ...FLIGHT, sudo: false }, /needs sudo/],
    [{ ...FLIGHT, max_seconds: 999999 }, /max_seconds/],
    [{ name: 'x', argv: [{ slot: 'cmd', type: 'word' }] }, /argv\[0\] must be a required literal/],
    [{ name: 'x', argv: [{ literal: 'incus', optional: true }] }, /argv\[0\]/],
    [{ name: 'x', argv: ['incus', { slot: 'Bad', type: 'word' }] }, /slot name/],
    [{ name: 'x', argv: ['incus', { slot: 'a', enum: ['ok', 'two words'] }] }, /enum/],
    [{ name: 'x', argv: ['incus', { slot: 'a', enum: ['-f'] }] }, /enum/],
    [{ name: 'x', argv: ['incus', { slot: 'a', match: 'brain.*' }] }, /anchored/],
    [{ name: 'x', argv: ['incus', { slot: 'a', type: 'path' }] }, /under/],
    [{ name: 'x', argv: ['incus', { slot: 'a', type: 'path', under: ['/srv/../etc/'] }] }, /under/],
    [{ name: 'x', argv: ['incus', { slot: 'a', type: 'word', enum: ['b'] }] }, /exactly one/],
    [{ name: 'x', argv: ['incus', { slot: 'a', type: 'word' }, { slot: 'a', type: 'int' }] }, /used twice/],
    [{ name: 'x', argv: ['two words'] }, /literal/],
    [{ name: '', argv: ['incus'] }, /shape name/],
  ];
  for (const [s, re] of bad) { const v = h.validateShape(s); assert.equal(v.ok, false, JSON.stringify(s)); assert.match(v.error, re); }
  assert.match(h.validateShapes([FLIGHT, FLIGHT]).error, /used twice/);
  assert.match(h.validateShapes([]).error, /1 to/);
});

test('matchShape: covered argv, optional elements, typed slots', () => {
  const f = shape(FLIGHT);
  assert.deepEqual(h.matchShape(f, ['/usr/local/sbin/agent-ssd-flight.sh', 'brain2', '20261023T0620Z']).values, { container: 'brain2', stamp: '20261023T0620Z' });
  assert.equal(h.matchShape(f, ['/usr/local/sbin/agent-ssd-flight.sh', 'soul2', '20261023T0620Z', 'precopy']).ok, true);
  const p = shape(POOL);
  assert.deepEqual(h.matchShape(p, ['incus', 'storage', 'create', 'agent-ssd', 'dir', 'source=/srv/agent-ssd/incus']).values, { pool: 'agent-ssd', src: '/srv/agent-ssd/incus' });
});

test('matchShape: a mismatch names the first argument that does not fit', () => {
  const f = shape(FLIGHT), p = shape(POOL);
  const cases = [
    [f, ['/usr/local/sbin/agent-ssd-flight.sh', 'brain3', '20261023T0620Z'], /argument 2 "brain3" is not one of brain2\|soul2\|triadic2/],
    [f, ['/usr/local/sbin/agent-ssd-flight.sh', 'brain2', 'today'], /argument 3 "today" does not match/],
    [f, ['/usr/local/sbin/agent-ssd-flight.sh', 'brain2', '20261023T0620Z', 'precopy', 'extra'], /one too many/],
    [f, ['/usr/local/sbin/agent-ssd-flight.sh', 'brain2'], /missing argument 3/],
    [f, ['/usr/local/bin/other.sh', 'brain2', '20261023T0620Z'], /argument 1 .* should be/],
    [p, ['incus', 'storage', 'create', '--force', 'dir', 'source=/srv/agent-ssd/x'], /starts with -/],
    [p, ['incus', 'storage', 'create', 'pool', 'dir', 'source=/srv/agent-ssd/../x'], /normalised absolute path/],
    [p, ['incus', 'storage', 'create', 'pool', 'dir', 'source=/srv/hitachi/x'], /is not under \/srv\/agent-ssd\//],
    [p, ['incus', 'storage', 'create', 'pool', 'dir', '/srv/agent-ssd/x'], /should start with "source="/],
    [p, ['incus', 'storage', 'create', 'po ol', 'dir', 'source=/srv/agent-ssd/x'], /has characters outside/],
  ];
  for (const [s, argv, re] of cases) { const m = h.matchShape(s, argv); assert.equal(m.ok, false, argv.join(' ')); assert.match(m.reason, re); }
});

test('findCover / explainRefusal: first fit wins; a refusal reports the nearest shape and why', () => {
  const windows = [{ id: 7, label: 'migration', closes_at: '2026-10-26T00:00:00Z', shapes: [shape(POOL), shape(FLIGHT)] }];
  const hit = h.findCover(windows, ['/usr/local/sbin/agent-ssd-flight.sh', 'triadic2', '20261023T0620Z']);
  assert.equal(hit.window.id, 7); assert.equal(hit.shape.name, 'flight');
  assert.equal(h.findCover(windows, ['incus', 'delete', 'brain']), null);
  const ex = h.explainRefusal(windows, ['/usr/local/sbin/agent-ssd-flight.sh', 'brain3', '20261023T0620Z']);
  assert.equal(ex.covered, false);
  assert.deepEqual(ex.open_windows, [{ id: 7, label: 'migration', closes_at: '2026-10-26T00:00:00Z', shapes: ['pool-create', 'flight'] }]);
  assert.equal(ex.nearest.shape, 'flight'); assert.match(ex.nearest.reason, /brain3/);
  assert.deepEqual(h.explainRefusal([], ['incus', 'list']), { covered: false, open_windows: [], nearest: null });
});

test('validateArgv / literalShape: words only; a one-time approval is the exact argv', () => {
  assert.equal(h.validateArgv(['incus', 'list']), null);
  assert.match(h.validateArgv([]), /1 to/);
  assert.match(h.validateArgv(['incus', 'two words']), /argv\[1\]/);
  assert.match(h.validateArgv(['incus', '']), /argv\[1\]/);
  assert.match(h.validateArgv(['incus', 42]), /argv\[1\]/);
  const once = h.literalShape(['incus', 'delete', 'brain-agentssd-failed-20261023T0105Z'], { sudo: true });
  assert.equal(once.ok, true);
  assert.equal(h.matchShape(once.shape, ['incus', 'delete', 'brain-agentssd-failed-20261023T0105Z']).ok, true);
  assert.equal(h.matchShape(once.shape, ['incus', 'delete', 'brain']).ok, false);
});

test('quote: the remote shell reads back exactly the word that was quoted', () => {
  for (const w of ['plain', "it's", 'a b', "x'y'z", '/srv/agent-ssd/incus', 'source=/srv/x']) {
    const back = execFileSync('/bin/sh', ['-c', 'printf "%s" ' + h.quote(w)], { encoding: 'utf8' });
    assert.equal(back, w);
  }
  assert.equal(h.quote("it's"), "'it'\\''s'");
});

test('renderRemote: run with and without sudo; a job becomes a capped transient unit', () => {
  const p = shape(POOL), f = shape(FLIGHT);
  assert.equal(h.renderRemote(p, ['incus', 'storage', 'create', 'agent-ssd', 'dir', 'source=/srv/agent-ssd/incus']),
    "sudo -n -- 'incus' 'storage' 'create' 'agent-ssd' 'dir' 'source=/srv/agent-ssd/incus'");
  assert.equal(h.renderRemote(shape({ name: 'ls', argv: ['incus', 'list'] }), ['incus', 'list']), "'incus' 'list'");
  assert.equal(h.renderRemote(f, ['/usr/local/sbin/agent-ssd-flight.sh', 'brain2', '20261023T0620Z'], { unit: 'dp-hostop-12' }),
    "sudo -n systemd-run --unit=dp-hostop-12 --remain-after-exit --quiet --property=RuntimeMaxSec=10800 -- '/usr/local/sbin/agent-ssd-flight.sh' 'brain2' '20261023T0620Z'");
  assert.throws(() => h.renderRemote(f, ['/usr/local/sbin/agent-ssd-flight.sh', 'brain2', '20261023T0620Z'], { unit: 'other' }), /unit/);
  assert.equal(h.jobProbe('dp-hostop-12').startsWith('sudo -n systemctl show dp-hostop-12 '), true);
  assert.throws(() => h.jobProbe('dp-hostop-x'), /bad unit/);
  assert.equal(h.jobStop('dp-hostop-12'), 'sudo -n systemctl stop dp-hostop-12');
});

test('parseJobProbe: running, succeeded, failed, timed out, lost', () => {
  const probe = (props, journal = 'line 1\nline 2') => Object.entries(props).map(([k, v]) => `${k}=${v}`).join('\n') + '\n---journal---\n' + journal + '\n';
  assert.equal(h.parseJobProbe(probe({ LoadState: 'loaded', ActiveState: 'active', SubState: 'running', Result: 'success', ExecMainStatus: '0' })).status, 'running');
  const ok = h.parseJobProbe(probe({ LoadState: 'loaded', ActiveState: 'active', SubState: 'exited', Result: 'success', ExecMainStatus: '0' }));
  assert.deepEqual([ok.status, ok.exit_code, ok.journal], ['succeeded', 0, 'line 1\nline 2']);
  const bad = h.parseJobProbe(probe({ LoadState: 'loaded', ActiveState: 'failed', SubState: 'failed', Result: 'exit-code', ExecMainStatus: '3' }));
  assert.deepEqual([bad.status, bad.exit_code], ['failed', 3]);
  assert.equal(h.parseJobProbe(probe({ LoadState: 'loaded', ActiveState: 'failed', SubState: 'failed', Result: 'timeout', ExecMainStatus: '0' })).status, 'timed_out');
  assert.equal(h.parseJobProbe(probe({ LoadState: 'not-found', ActiveState: 'inactive', SubState: 'dead', Result: 'success', ExecMainStatus: '0' })).status, 'lost');
});

test('parseKeyscan: known_hosts lines and the preferred key fingerprint', () => {
  const blob = Buffer.from('fixture-ed25519-key').toString('base64');
  const rsa = Buffer.from('fixture-rsa-key').toString('base64');
  const k = h.parseKeyscan(`# 100.83.112.88:22 SSH-2.0-OpenSSH\n100.83.112.88 ssh-rsa ${rsa}\n100.83.112.88 ssh-ed25519 ${blob}\n`, '100.83.112.88');
  assert.equal(k.key_type, 'ssh-ed25519');
  assert.equal(k.fingerprint, 'SHA256:' + require('crypto').createHash('sha256').update(Buffer.from(blob, 'base64')).digest('base64').replace(/=+$/, ''));
  assert.match(k.known_hosts, /^100\.83\.112\.88 ssh-ed25519 /);
  assert.match(h.parseKeyscan(`h ssh-ed25519 ${blob}\n`, 'h', 2222).known_hosts, /^\[h\]:2222 ssh-ed25519 /);
  assert.equal(h.parseKeyscan('garbage\n', 'h'), null);
});

test('hosts and output helpers', () => {
  for (const a of ['100.83.112.88', 'phasewhip', 'api.example.com']) assert.equal(h.validAddress(a), true, a);
  for (const a of ['', 'a b', '-x', 'host_name', 'x'.repeat(300)]) assert.equal(h.validAddress(a), false, a);
  assert.equal(h.validLogin('apple'), true); assert.equal(h.validLogin('Root!'), false);
  assert.equal(h.validPort(22), true); assert.equal(h.validPort(0), false);
  assert.equal(h.redact('pw=hunter2 and hunter2', ['hunter2']), 'pw=[REDACTED] and [REDACTED]');
  assert.equal(h.tail('abcdef', 3), '…def');
  assert.equal(h.normalPath('/srv/agent-ssd/incus'), '/srv/agent-ssd/incus');
  for (const p of ['/srv//x', '/srv/./x', '/srv/../etc', 'srv/x', '/srv/x y']) assert.equal(h.normalPath(p), null, p);
});

test('server-audit fixes: memoised matching, blocked addresses, no backslash words, longest rendering capped', () => {
  const many = shape({ name: 'opt', argv: ['tool', ...Array.from({ length: 30 }, (_, i) => ({ literal: 'o' + (i % 2), optional: true }))] });
  const t0 = Date.now();
  assert.equal(h.matchShape(many, ['tool', ...Array(30).fill('o0'), 'nope']).ok, false);
  assert.ok(Date.now() - t0 < 200, 'a non-matching argv against many optionals stays fast');
  for (const a of ['localhost', '127.0.0.1', '127.1.2.3', '169.254.169.254', '0.0.0.0', 'metadata.google.internal', '2130706433', '0x7f000001']) assert.equal(h.validAddress(a), false, a);
  assert.equal(h.validAddress('100.83.112.88'), true);
  assert.match(h.validateArgv(['echo', 'a\\b']), /argv\[1\]/, 'no backslash in argv words');
  assert.equal(h.validateShape({ name: 'x', argv: ['echo', 'a\\b'] }).ok, false, 'no backslash in literals');
  const wide = h.validateShape({ name: 'wide', mode: 'job', sudo: true, argv: ['/bin/x', ...Array.from({ length: 9 }, (_, i) => ({ slot: 'p' + i, type: 'path', under: ['/srv/'] }))] });
  assert.equal(wide.ok, false); assert.match(wide.error, /renders past 4096/);
});
