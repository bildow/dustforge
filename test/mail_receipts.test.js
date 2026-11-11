'use strict';
// mail_receipts: sends name Resend's id (idempotent on the send id), receipts are the sender's own, Resend's events
// arrive Svix-signed and only move a receipt forward, ?refresh asks Resend, and the webhook is registered by the
// operator through an approval with the signing secret kept server-side. Mock Resend + in-memory DB only.
const test = require('node:test');
const assert = require('node:assert');
const http = require('http');
const crypto = require('crypto');
const express = require('express');
const Database = require('better-sqlite3');

const WH_KEY = crypto.randomBytes(24);
const WH_SECRET = 'whsec_' + WH_KEY.toString('base64');
const rs = { sent: [], refuse: false, lastEvent: 'complained', webhooks: [] };
const resendSrv = http.createServer((req, res) => {
  let b = ''; req.on('data', c => { b += c; }); req.on('end', () => {
    const j = (s, o) => { res.writeHead(s, { 'content-type': 'application/json' }); res.end(JSON.stringify(o)); };
    if (req.headers.authorization !== 'Bearer re_testkey') return j(401, { message: 'bad key' });
    if (req.method === 'POST' && req.url === '/emails') {
      if (rs.refuse) return j(422, { name: 'validation_error', message: 'domain not verified' });
      const body = JSON.parse(b); rs.sent.push({ body, idem: req.headers['idempotency-key'] });
      return j(200, { id: 're_' + String(rs.sent.length).padStart(8, '0') });
    }
    if (req.method === 'GET' && req.url.startsWith('/emails/')) return j(200, { id: req.url.split('/')[2], last_event: rs.lastEvent, created_at: '2026-11-10T12:00:00Z' });
    if (req.method === 'POST' && req.url === '/webhooks') { rs.webhooks.push(JSON.parse(b)); return j(201, { object: 'webhook', id: 'wh_1', signing_secret: WH_SECRET }); }
    j(404, { message: 'no route' });
  });
});

let api, base, mr, smtpSent = [];
const OPERATOR = 'did:key:zOperator', ALICE = 'did:key:zAlice', BOB = 'did:key:zBob';
const call = async (method, path, { as, body, headers = {}, raw } = {}) => {
  const r = await fetch(base + path, { method, headers: { ...(as ? { authorization: 'Bearer ' + as } : {}), ...(body || raw ? { 'content-type': 'application/json' } : {}), ...headers },
    body: raw !== undefined ? raw : (body ? JSON.stringify(body) : undefined) });
  return { status: r.status, body: await r.json().catch(() => ({})) };
};
const sign = (raw, { id = 'msg_' + crypto.randomBytes(6).toString('hex'), ts = Math.floor(Date.now() / 1000), key = WH_KEY } = {}) =>
  ({ 'svix-id': id, 'svix-timestamp': String(ts), 'svix-signature': 'v1,' + crypto.createHmac('sha256', key).update(`${id}.${ts}.${raw}`).digest('base64') });

test.before(async () => {
  await new Promise(ok => resendSrv.listen(0, '127.0.0.1', ok));
  process.env.RESEND_API_URL = `http://127.0.0.1:${resendSrv.address().port}`;
  process.env.IDENTITY_MASTER_KEY = crypto.randomBytes(32).toString('hex');
  delete process.env.RESEND_WEBHOOK_SECRET;
  const app = express();
  const raw = new Set(['/api/email/webhooks/resend']);
  app.use((req, res, next) => (raw.has(req.path) ? next() : express.json()(req, res, next)));
  const db = new Database(':memory:');
  mr = require('../mail_receipts')({ app, db, getBearerIdentity: (req) => { const t = (req.headers.authorization || '').slice(7); return t ? { ok: true, did: t, decoded: {} } : { ok: false, status: 401, error: 'sign in' }; },
    logSecurityEvent: () => {}, approvals: () => ({ gateService: (k, c, call, body) => (body.approval_id === 7 ? { ok: true, approval_id: 7 } : { ok: false, status: 202, body: { status: 'approval_pending', approval_id: 7 } }) }),
    createEmailTransport: () => ({ sendMail: async (m) => { smtpSent.push(m); return { messageId: m.messageId, response: '250 2.0.0 Ok: queued as ABC123' }; } }),
    operatorAllowed: (did) => did === OPERATOR, publicApi: 'https://api.example' });
  api = http.createServer(app); await new Promise(ok => api.listen(0, '127.0.0.1', ok)); base = `http://127.0.0.1:${api.address().port}`;
});
test.after(() => { resendSrv.close(); api.close(); });

let first;
test('a send through Resend: its email id comes back, idempotent on the send id; the receipt is the sender\'s', async () => {
  process.env.RESEND_API_KEY = 're_testkey';
  first = await mr.send({ did: ALICE, tokenJti: 'jti1', from: 'alice@dustforge.com', to: 'kyle@example.com', subject: 'hi', text: 'hello' });
  assert.strictEqual(first.provider, 'resend'); assert.strictEqual(first.provider_id, 're_00000001'); assert.match(first.send_id, /^es_[0-9a-f]{24}$/);
  assert.strictEqual(rs.sent[0].idem, first.send_id); assert.strictEqual(rs.sent[0].body.headers['X-Dustforge-Send'], first.send_id);
  const byOurs = await call('GET', `/api/email/sends/${first.send_id}`, { as: ALICE });
  const byResend = await call('GET', '/api/email/sends/re_00000001', { as: ALICE });
  assert.strictEqual(byOurs.body.status, 'accepted'); assert.strictEqual(byResend.body.send_id, first.send_id);
  assert.strictEqual((await call('GET', `/api/email/sends/${first.send_id}`, { as: BOB })).status, 404, 'never someone else\'s receipt');
  assert.strictEqual((await call('GET', '/api/email/sends')).status, 401);
});

test('Resend refusing the message throws (the route refunds); no receipt is written', async () => {
  rs.refuse = true;
  await assert.rejects(mr.send({ did: ALICE, from: 'alice@dustforge.com', to: 'x@example.com', subject: 's', text: 't' }), /Resend refused the message: HTTP 422/);
  rs.refuse = false;
  assert.strictEqual((await call('GET', '/api/email/sends', { as: ALICE })).body.sends.length, 1);
});

test('without a Resend key: the SMTP relay, with a receipt that says it has no delivery events', async () => {
  delete process.env.RESEND_API_KEY; process.env.SMTP_RELAY_HOST = 'smtp.other.example';
  const s = await mr.send({ did: ALICE, from: 'alice@dustforge.com', to: 'y@example.com', subject: 's', text: 't' });
  assert.strictEqual(s.provider, 'smtp'); assert.strictEqual(s.provider_id, null); assert.strictEqual(smtpSent[0].messageId, `<${s.send_id}@dustforge.com>`);
  const r = await call('GET', `/api/email/sends/${s.send_id}`, { as: ALICE }); assert.match(r.body.note, /no delivery events/);
  process.env.SMTP_RELAY_HOST = 'smtp.resend.com'; process.env.SMTP_RELAY_PASSWORD = 're_testkey';
  const s2 = await mr.send({ did: ALICE, from: 'alice@dustforge.com', to: 'z@example.com', subject: 's', text: 't' });
  assert.strictEqual(s2.provider, 'resend', 'the relay\'s own key is used when the relay is Resend');
});

test('the webhook: refused until registered; registering is the operator\'s, through an approval; the secret never leaves', async () => {
  const ev = JSON.stringify({ type: 'email.delivered', created_at: '2026-11-10T12:01:00Z', data: { email_id: 're_00000001' } });
  assert.strictEqual((await call('POST', '/api/email/webhooks/resend', { raw: ev, headers: sign(ev) })).status, 503);
  assert.strictEqual((await call('POST', '/api/email/webhooks/resend/register', { as: ALICE, body: {} })).status, 403);
  const ask = await call('POST', '/api/email/webhooks/resend/register', { as: OPERATOR, body: {} });
  assert.strictEqual(ask.status, 202); assert.strictEqual(rs.webhooks.length, 0, 'nothing registered before approval');
  const ok = await call('POST', '/api/email/webhooks/resend/register', { as: OPERATOR, body: { approval_id: 7 } });
  assert.strictEqual(ok.status, 200); assert.strictEqual(ok.body.webhook_id, 'wh_1');
  assert.ok(!JSON.stringify(ok.body).includes(WH_SECRET.slice(6, 20)), 'the answer never carries the secret');
  assert.deepStrictEqual(rs.webhooks[0].events.includes('email.bounced'), true); assert.strictEqual(rs.webhooks[0].endpoint, 'https://api.example/api/email/webhooks/resend');
});

test('signed events move the receipt forward only; bad, stale and replayed deliveries are refused or ignored', async () => {
  const post = (type, at, extra = {}, opts) => { const raw = JSON.stringify({ type, created_at: at, data: { email_id: 're_00000001', ...extra } }); return call('POST', '/api/email/webhooks/resend', { raw, headers: sign(raw, opts) }); };
  assert.strictEqual((await post('email.delivered', '2026-11-10T12:01:00Z')).status, 200);
  let r = await call('GET', `/api/email/sends/${first.send_id}`, { as: ALICE }); assert.strictEqual(r.body.status, 'delivered');
  await post('email.sent', '2026-11-10T12:00:30Z');   // late and out of order
  r = await call('GET', `/api/email/sends/${first.send_id}`, { as: ALICE }); assert.strictEqual(r.body.status, 'delivered', 'a late "sent" never moves it back');
  assert.deepStrictEqual(r.body.events.map(e => e.type), ['accepted', 'delivered', 'sent']);
  await post('email.bounced', '2026-11-10T12:02:00Z', { bounce: { type: 'Permanent', subType: 'General', message: 'mailbox unavailable' } });
  r = await call('GET', `/api/email/sends/${first.send_id}`, { as: ALICE }); assert.strictEqual(r.body.status, 'bounced'); assert.strictEqual(r.body.events.at(-1).detail.bounce.type, 'Permanent');
  const raw = JSON.stringify({ type: 'email.complained', data: { email_id: 're_00000001' } });
  assert.strictEqual((await call('POST', '/api/email/webhooks/resend', { raw, headers: sign(raw, { key: crypto.randomBytes(24) }) })).status, 401, 'a bad signature');
  assert.strictEqual((await call('POST', '/api/email/webhooks/resend', { raw, headers: sign(raw, { ts: Math.floor(Date.now() / 1000) - 900 }) })).status, 401, 'a stale timestamp');
  const h = sign(raw, { id: 'msg_fixed' });
  await call('POST', '/api/email/webhooks/resend', { raw, headers: h });
  assert.strictEqual((await call('POST', '/api/email/webhooks/resend', { raw, headers: h })).body.duplicate, true, 'a replayed delivery is ignored');
  const other = JSON.stringify({ type: 'email.delivered', data: { email_id: 're_notours' } });
  assert.strictEqual((await call('POST', '/api/email/webhooks/resend', { raw: other, headers: sign(other) })).body.unknown_email, true);
});

test('?refresh=1 asks Resend for its last event', async () => {
  process.env.RESEND_API_KEY = 're_testkey';
  const s = await mr.send({ did: BOB, from: 'bob@dustforge.com', to: 'k@example.com', subject: 's', text: 't' });
  rs.lastEvent = 'delivered';
  const r = await call('GET', `/api/email/sends/${s.provider_id}?refresh=1`, { as: BOB });
  assert.strictEqual(r.body.refresh.last_event, 'delivered'); assert.strictEqual(r.body.status, 'delivered');
});
