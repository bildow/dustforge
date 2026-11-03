'use strict';
// /use size limits and redaction (use_limits.js).
const test = require('node:test');
const assert = require('node:assert/strict');
const L = require('../use_limits');

const LIMIT = L.USE_MAX_RESPONSE_BYTES;
function streamOf(buf, chunk = 65536) {
  let i = 0;
  return new ReadableStream({ pull(c) { if (i >= buf.length) return c.close(); c.enqueue(buf.subarray(i, i += chunk)); } });
}

test('the documented limits', () => {
  assert.equal(L.USE_MAX_REQUEST_BYTES, 1048576);
  assert.equal(L.USE_MAX_RESPONSE_BYTES, 2097152);
});

test('a body at the limit is read whole, byte for byte, multi-byte characters included', async () => {
  const unit = Buffer.from('é"\\\n{x}ü✓ ');
  const buf = Buffer.alloc(LIMIT);
  for (let i = 0; i + unit.length <= LIMIT; i += unit.length) unit.copy(buf, i);
  buf.fill(0x61, LIMIT - (LIMIT % unit.length));
  const text = await L.readCapped(new Response(streamOf(buf, 7777)));   // chunks split characters
  assert.equal(Buffer.byteLength(text), LIMIT);
  assert.ok(Buffer.from(text).equals(buf));
});

test('over the limit with Content-Length: refused before reading, as a 413 naming the limit', async () => {
  let pulled = 0;
  const body = new ReadableStream({ pull(c) { pulled++; c.enqueue(new Uint8Array(1024)); } });
  const res = new Response(body, { headers: { 'content-length': String(LIMIT + 1) } });
  await assert.rejects(L.readCapped(res), (e) => e.code === 'upstream_too_large' && e.statusCode === 413
    && e.body.limit_bytes === LIMIT && e.body.declared_bytes === LIMIT + 1 && /2097152-byte \(2 MiB\) limit/.test(e.body.error) && e.body.charged === true);
  assert.ok(pulled <= 1, `read ${pulled} chunks of a body it should refuse unread`);
});

test('over the limit without Content-Length (chunked): reading stops just past the limit', async () => {
  let sent = 0;
  const body = new ReadableStream({ pull(c) { sent += 65536; c.enqueue(new Uint8Array(65536)); } });   // endless
  await assert.rejects(L.readCapped(new Response(body)), (e) => e.code === 'upstream_too_large' && e.body.read_bytes > LIMIT);
  assert.ok(sent <= LIMIT + 2 * 65536, `pulled ${sent} bytes`);
});

test('redaction: the secret, and its JSON-escaped form, become [REDACTED]; parse happens after', () => {
  const secret = 'tok"en\\42';
  const upstream = JSON.stringify({ echoed: secret, nested: { h: `token ${secret}` } });
  assert.ok(!upstream.includes(secret));                       // in JSON it appears only escaped
  const out = L.redactedBody(upstream, secret);
  assert.deepEqual(out, { echoed: '[REDACTED]', nested: { h: 'token [REDACTED]' } });
  assert.equal(L.redactedBody(`plain ${secret} text`, secret), 'plain [REDACTED] text');
  assert.equal(L.redactSecret('nothing to hide', ''), 'nothing to hide');   // an empty secret matches nothing
});

test('redaction is linear: 2 MiB of near-misses and 2 MiB of hits each take well under a second', () => {
  const secret = 'a'.repeat(63) + 'b';
  const nearMiss = 'a'.repeat(LIMIT);
  const hits = (secret + 'x').repeat(Math.floor(LIMIT / 65));
  for (const text of [nearMiss, hits]) {
    const t0 = process.hrtime.bigint();
    const out = L.redactSecret(text, secret);
    const ms = Number(process.hrtime.bigint() - t0) / 1e6;
    assert.ok(ms < 1000, `${ms} ms`);
    assert.ok(!out.includes(secret));
  }
});

test('redaction survives every way an upstream may escape the secret in JSON (review of #35)', () => {
  const cases = [
    ['abc/def+ghi==', '{"echo":"abc\\/def+ghi=="}'],                         // PHP escapes /
    ['tok&en<x>', '{"echo":"tok\\u0026en\\u003cx\\u003e"}'],                // Go, Rails: & < >
    ['pässwörd', '{"echo":"p\\u00e4ssw\\u00f6rd"}'],                         // Python: non-ASCII
    ['hunter2', '{"echo":"hunt\\u0065r2"}'],                                 // any letter as \uXXXX
    ['tok"en', '{"echo":"tok\\"en"}'],                                       // the case #35 first fixed
    ['hunter2', '{"hunt\\u0065r2":["x",{"deep":["hunter2 again"]}]}'],       // keys and nesting
  ];
  for (const [secret, upstream] of cases) {
    const out = JSON.stringify(L.redactedBody(upstream, secret));
    assert.ok(!out.includes(secret) && !JSON.stringify(JSON.parse(out)).includes(secret), `${secret} leaked: ${out}`);
    assert.match(out, /\[REDACTED\]/);
  }
});

test('a "__proto__" key from the upstream stays data, and a BOM-prefixed JSON body still parses', async () => {
  const out = L.redactedBody('{"__proto__":{"polluted":true},"a":"s3cret"}', 's3cret');
  assert.equal(Object.getPrototypeOf(out), Object.prototype);
  assert.deepEqual(Object.keys(out), ['__proto__', 'a']);
  assert.equal(out.a, '[REDACTED]');
  const bom = await L.readCapped(new Response(Buffer.from('﻿{"ok":true}')));
  assert.deepEqual(L.redactedBody(bom, 'x'), { ok: true });
});

test('no body (HEAD, 204, 304) is never refused for its Content-Length', async () => {
  for (const status of [204, 304]) {
    assert.equal(await L.readCapped(new Response(null, { status, headers: { 'content-length': String(LIMIT * 4) } })), '');
  }
});

test('a numeric secret echoed in another number form is redacted (1e3 for 1000)', () => {
  assert.deepEqual(L.redactedBody('{"pin":1e3,"n":[1000.0, 7]}', '1000'), { pin: '[REDACTED]', n: ['[REDACTED]', 7] });
  assert.equal(L.redactedBody('1e3', '1000'), '[REDACTED]');
  assert.deepEqual(L.redactedBody('{"pin":42}', '1000'), { pin: 42 });
});

test('review gaps of #35: escaped forms the raw pass would break, a secret split across key and value', () => {
  const leaks = (o, s) => (typeof o === 'string' ? o : JSON.stringify(o)).includes(s);
  for (const [secret, upstream] of [['tok"', '{"tok":1,"b":"tok\\u0022"}'], ['ab":"cd', '{"a\\u0062":"cd"}'], ['1000', '{"n":1000.0}']]) {
    const out = L.redactedBody(upstream, secret);
    assert.ok(!leaks(out, secret), `${secret} leaked from ${upstream}: ${JSON.stringify(out)}`);
  }
});

test('a long numeric secret echoed as a bare JSON number is redacted, not rounded into view', () => {
  const secret = '12345678901234567890';
  assert.deepEqual(L.redactedBody(`{"acct":${secret},"n":[98765432109876543210123]}`, secret), { acct: '[REDACTED]', n: [98765432109876543210123] });
  assert.equal(L.redactedBody('98765432109876543210123', '98765432109876543210123'), '[REDACTED]');
});
