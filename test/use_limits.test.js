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
