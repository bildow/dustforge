'use strict';
// secretFetch (use_limits.js): a call carrying a secret never follows a redirect.
// fetch() follows 30x by default and re-sends custom headers (X-Api-Key, Authorization) to the
// Location's origin, and on 307/308 the body too; /use's host allow-list checks only the first URL.
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const L = require('../use_limits');

const SECRET = 'sk-test-0123456789';
function listen(handler) {
  return new Promise(resolve => {
    const server = http.createServer(handler);
    server.listen(0, '127.0.0.1', () => resolve({ server, url: `http://127.0.0.1:${server.address().port}` }));
  });
}

test('every redirect status is refused before a second request, and the secret never reaches the target', async () => {
  const seen = [];
  const target = await listen((req, res) => {
    let body = ''; req.on('data', c => (body += c));
    req.on('end', () => { seen.push({ key: req.headers['x-api-key'], body }); res.end('{}'); });
  });
  const origin = await listen((req, res) => {
    const status = Number(new URL(req.url, 'http://x').pathname.slice(1));
    req.resume(); res.writeHead(status, { location: target.url + '/leak' }); res.end();
  });
  try {
    for (const status of [301, 302, 303, 307, 308]) {
      await assert.rejects(
        L.secretFetch(`${origin.url}/${status}`, { method: 'POST', headers: { 'X-Api-Key': SECRET }, body: JSON.stringify({ key: SECRET }) }),
        e => e.code === 'upstream_redirect' && e.body.upstream === 'redirect' && !JSON.stringify(e.body).includes(SECRET),
        `status ${status}`);
    }
    assert.equal(seen.length, 0, `redirect target was hit ${seen.length} time(s)`);
  } finally { origin.server.close(); target.server.close(); }
});

test('a plain 200 is returned as is', async () => {
  const up = await listen((req, res) => { res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify({ got: req.headers['x-api-key'] })); });
  try {
    const r = await L.secretFetch(up.url + '/ok', { headers: { 'X-Api-Key': SECRET } });
    assert.equal(r.status, 200);
    assert.equal((await r.json()).got, SECRET);
  } finally { up.server.close(); }
});

test('other network errors pass through unchanged (not reported as a redirect)', async () => {
  const up = await listen(() => {}); const url = up.url; up.server.close();
  await assert.rejects(L.secretFetch(url + '/gone', {}), e => e.code !== 'upstream_redirect');
});

test('the fetch is made with redirect: error whatever the caller passes', async () => {
  const real = global.fetch; let opts;
  global.fetch = async (_u, o) => { opts = o; return new Response('{}'); };
  try { await L.secretFetch('https://example.invalid/', { redirect: 'follow' }); } finally { global.fetch = real; }
  assert.equal(opts.redirect, 'error');
});
