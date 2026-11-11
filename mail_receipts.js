'use strict';
// Mail receipts (Aaron 2026-11-10): every POST /api/email/send leaves a receipt that names the provider's own message id,
// returned to the caller; Resend's delivery events (delivered, bounced, complained, delayed) come back through a signed
// webhook, so a sender can ask what happened to a message by that id. Before this, a send was "ok" once the relay
// accepted it and nothing anywhere recorded what became of it (Brain held two sends as unverified).
//
//   send({ did, tokenJti, from, to, subject, text })  → { send_id, provider, provider_id, message_id }
//       Resend's API when a Resend key is configured (RESEND_API_KEY, or the relay's own key when SMTP_RELAY_HOST is
//       Resend's): its answer carries the email id. Otherwise the SMTP transport, recording its Message-ID and reply.
//   GET  /api/email/sends            the caller's receipts (newest first)
//   GET  /api/email/sends/:id        one receipt, by send_id or provider id; ?refresh=1 asks Resend for its last event
//   POST /api/email/webhooks/resend  Resend's events, Svix-signed; unknown ids and bad signatures are refused
//   POST /api/email/webhooks/resend/register   the operator registers the webhook with Resend, as a request approved
//       in the app; the server creates it with its own key and keeps the signing secret (encrypted) — no person or
//       agent ever sees it.
const crypto = require('crypto');

const RESEND_API = (process.env.RESEND_API_URL || 'https://api.resend.com').replace(/\/$/, '');   // override: tests only
const EVENTS = ['email.sent', 'email.delivered', 'email.delivery_delayed', 'email.bounced', 'email.complained', 'email.failed'];
// Later events never move a receipt back: a late "sent" after "delivered" is kept in the history only.
const RANK = { accepted: 0, sent: 1, delivery_delayed: 2, delivered: 3, failed: 4, bounced: 4, complained: 5 };
const SIG_TOLERANCE_SEC = 300;

module.exports = function mailReceipts({ app, db, rateLimitStandard, getBearerIdentity, logSecurityEvent, approvals, createEmailTransport, operatorAllowed, publicApi }) {
  db.exec(`CREATE TABLE IF NOT EXISTS email_receipts (
    send_id TEXT PRIMARY KEY,
    did TEXT NOT NULL,
    token_jti TEXT,
    from_addr TEXT NOT NULL,
    to_addr TEXT NOT NULL,
    subject_sha256 TEXT NOT NULL,
    provider TEXT NOT NULL,              -- 'resend' | 'smtp'
    provider_id TEXT,                    -- Resend's email id (smtp: the relay's reply, if any)
    message_id TEXT,                     -- the Message-ID header, when known
    status TEXT NOT NULL DEFAULT 'accepted',
    last_event_at TEXT,
    events TEXT NOT NULL DEFAULT '[]',   -- [{type, at, detail?}]
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
  )`);
  db.exec('CREATE INDEX IF NOT EXISTS idx_email_receipts_provider ON email_receipts(provider_id)');
  db.exec('CREATE INDEX IF NOT EXISTS idx_email_receipts_did ON email_receipts(did, created_at)');
  db.exec('CREATE TABLE IF NOT EXISTS mail_provider_state (k TEXT PRIMARY KEY, v TEXT NOT NULL, updated_at TEXT NOT NULL)');
  db.exec('CREATE TABLE IF NOT EXISTS mail_webhook_seen (svix_id TEXT PRIMARY KEY, at TEXT NOT NULL)');

  const now = () => new Date().toISOString();
  const resendKey = () => process.env.RESEND_API_KEY
    || (/(^|\.)resend\.com$/i.test(process.env.SMTP_RELAY_HOST || '') ? process.env.SMTP_RELAY_PASSWORD || '' : '');

  async function resend(method, path, body, extraHeaders = {}) {
    const key = resendKey();
    if (!key) throw Object.assign(new Error('no Resend key configured'), { status: 503 });
    const r = await fetch(RESEND_API + path, { method, headers: { 'content-type': 'application/json', authorization: 'Bearer ' + key, ...extraHeaders },
      body: body === undefined ? undefined : JSON.stringify(body), redirect: 'error', signal: AbortSignal.timeout(20000) });
    const d = await r.json().catch(() => ({}));
    return { status: r.status, data: d };
  }

  // ── sending ──────────────────────────────────────────────────────────────────────────────────────────────────
  async function send({ did, tokenJti, from, to, subject, text }) {
    const sendId = 'es_' + crypto.randomBytes(12).toString('hex');
    const messageId = `<${sendId}@dustforge.com>`;
    let provider, providerId = null, mid = messageId;
    if (resendKey()) {
      // The send id is the idempotency key: a retried request never becomes a second message.
      const r = await resend('POST', '/emails', { from, to: [to], subject, text, headers: { 'X-Dustforge-Send': sendId } }, { 'Idempotency-Key': sendId });
      if (r.status !== 200 || !r.data || !r.data.id) throw new Error(`Resend refused the message: HTTP ${r.status} ${(r.data && (r.data.message || r.data.name)) || ''}`.trim());
      provider = 'resend'; providerId = String(r.data.id); mid = null;   // Resend sets the Message-ID; its email id is the handle
    } else {
      const info = await createEmailTransport().sendMail({ from, to, subject, text, messageId });
      provider = 'smtp'; providerId = (info && info.response) ? String(info.response).slice(0, 200) : null; mid = (info && info.messageId) || messageId;
    }
    const at = now();
    db.prepare(`INSERT INTO email_receipts (send_id, did, token_jti, from_addr, to_addr, subject_sha256, provider, provider_id, message_id, status, events, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'accepted', ?, ?, ?)`)
      .run(sendId, did, tokenJti || null, from, to, crypto.createHash('sha256').update(String(subject || '')).digest('hex'), provider, providerId, mid,
           JSON.stringify([{ type: 'accepted', at, by: provider }]), at, at);
    return { send_id: sendId, provider, provider_id: provider === 'resend' ? providerId : null, message_id: mid };
  }

  function view(r) {
    return { send_id: r.send_id, provider: r.provider, provider_id: r.provider === 'resend' ? r.provider_id : null, message_id: r.message_id,
      from: r.from_addr, to: r.to_addr, status: r.status, last_event_at: r.last_event_at, events: JSON.parse(r.events || '[]'), created_at: r.created_at,
      ...(r.provider === 'smtp' ? { note: 'sent through the SMTP relay: no provider id, so no delivery events (only Resend sends report them)' } : {}) };
  }

  function applyEvent(r, type, at, detail) {
    const s = type.replace(/^email\./, '');
    const evs = JSON.parse(r.events || '[]');
    if (evs.some(e => e.type === s && e.at === at)) return false;   // the same event twice
    evs.push({ type: s, at, ...(detail ? { detail } : {}) });
    const status = (RANK[s] !== undefined && RANK[s] >= (RANK[r.status] || 0)) ? s : r.status;
    db.prepare('UPDATE email_receipts SET status = ?, last_event_at = ?, events = ?, updated_at = ? WHERE send_id = ?')
      .run(status, at, JSON.stringify(evs.slice(-50)), now(), r.send_id);
    return true;
  }

  // ── reading ──────────────────────────────────────────────────────────────────────────────────────────────────
  const lim = rateLimitStandard || ((req, res, next) => next());
  function who(req, res) {
    const a = getBearerIdentity(req);
    if (!a || !a.ok) { res.status((a && a.status) || 401).json({ error: (a && a.error) || 'sign in' }); return null; }
    return a;
  }
  app.get('/api/email/sends', lim, (req, res) => {
    const a = who(req, res); if (!a) return;
    const n = Math.min(Math.max(Number(req.query.limit) || 20, 1), 100);
    res.json({ ok: true, sends: db.prepare('SELECT * FROM email_receipts WHERE did = ? ORDER BY created_at DESC LIMIT ?').all(a.did, n).map(view) });
  });
  app.get('/api/email/sends/:id', lim, async (req, res) => {
    const a = who(req, res); if (!a) return;
    const id = String(req.params.id || '');
    if (!/^[A-Za-z0-9_-]{8,80}$/.test(id)) return res.status(400).json({ error: 'id: a send_id (es_…) or the provider id' });
    let r = db.prepare('SELECT * FROM email_receipts WHERE (send_id = ? OR (provider = ? AND provider_id = ?)) AND did = ?').get(id, 'resend', id, a.did);
    if (!r) return res.status(404).json({ error: 'no send of yours with that id' });
    let refresh = null;
    if (req.query.refresh === '1' && r.provider === 'resend') {
      // Resend's own record, for when an event was missed (or before the webhook is registered).
      try {
        const g = await resend('GET', `/emails/${encodeURIComponent(r.provider_id)}`);
        if (g.status === 200 && g.data && g.data.last_event) { applyEvent(r, 'email.' + g.data.last_event, g.data.last_event_at || g.data.created_at || now(), { source: 'refresh' }); refresh = { ok: true, last_event: g.data.last_event }; }
        else refresh = { ok: false, http_status: g.status, error: (g.data && (g.data.message || g.data.name)) || 'no last_event' };
      } catch (e) { refresh = { ok: false, error: e.message }; }
      r = db.prepare('SELECT * FROM email_receipts WHERE send_id = ?').get(r.send_id);
    }
    res.json({ ok: true, ...view(r), ...(refresh ? { refresh } : {}) });
  });

  // ── Resend's events ──────────────────────────────────────────────────────────────────────────────────────────
  const KEY_ENC = () => crypto.createHash('sha256').update('mail-webhook-secret:v1:' + (process.env.IDENTITY_MASTER_KEY || '')).digest();
  function storeSecret(secret) {
    const iv = crypto.randomBytes(12), c = crypto.createCipheriv('aes-256-gcm', KEY_ENC(), iv);
    const enc = Buffer.concat([c.update(secret, 'utf8'), c.final()]);
    db.prepare('INSERT INTO mail_provider_state (k, v, updated_at) VALUES (?, ?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v, updated_at = excluded.updated_at')
      .run('resend_webhook_secret', [iv, c.getAuthTag(), enc].map(b => b.toString('base64')).join('.'), now());
  }
  function loadSecret() {
    if (process.env.RESEND_WEBHOOK_SECRET) return process.env.RESEND_WEBHOOK_SECRET;
    const row = db.prepare("SELECT v FROM mail_provider_state WHERE k = 'resend_webhook_secret'").get();
    if (!row) return null;
    try {
      const [iv, tag, enc] = row.v.split('.').map(x => Buffer.from(x, 'base64'));
      const d = crypto.createDecipheriv('aes-256-gcm', KEY_ENC(), iv); d.setAuthTag(tag);
      return Buffer.concat([d.update(enc), d.final()]).toString('utf8');
    } catch (_) { return null; }
  }
  // Svix: HMAC-SHA256 over "id.timestamp.body" with the base64 key after "whsec_"; header "v1,<sig> v1,<sig>".
  function verifySvix(secret, headers, raw) {
    const id = headers['svix-id'], ts = headers['svix-timestamp'], sig = headers['svix-signature'];
    if (!id || !ts || !sig || !/^\d{1,12}$/.test(ts)) return 'missing signature headers';
    if (Math.abs(Date.now() / 1000 - Number(ts)) > SIG_TOLERANCE_SEC) return 'timestamp outside 5 minutes';
    const key = Buffer.from(String(secret).replace(/^whsec_/, ''), 'base64');
    const want = crypto.createHmac('sha256', key).update(`${id}.${ts}.${raw}`).digest();
    const ok = String(sig).split(' ').some(p => { const [v, s] = p.split(','); if (v !== 'v1' || !s) return false; const got = Buffer.from(s, 'base64'); return got.length === want.length && crypto.timingSafeEqual(got, want); });
    return ok ? null : 'bad signature';
  }
  app.post('/api/email/webhooks/resend', require('express').raw({ type: '*/*', limit: '256kb' }), (req, res) => {
    const secret = loadSecret();
    if (!secret) return res.status(503).json({ error: 'webhook not registered' });
    const raw = Buffer.isBuffer(req.body) ? req.body.toString('utf8') : '';
    const bad = verifySvix(secret, req.headers, raw);
    if (bad) { try { logSecurityEvent('mail_webhook_refused', 'warn', { capability: 'mail-webhook', context: { reason: bad } }); } catch (_) {} return res.status(401).json({ error: bad }); }
    const svixId = String(req.headers['svix-id']);
    if (db.prepare('SELECT 1 FROM mail_webhook_seen WHERE svix_id = ?').get(svixId)) return res.json({ ok: true, duplicate: true });
    let ev; try { ev = JSON.parse(raw); } catch (_) { return res.status(400).json({ error: 'not JSON' }); }
    db.prepare('INSERT OR IGNORE INTO mail_webhook_seen (svix_id, at) VALUES (?, ?)').run(svixId, now());
    db.prepare("DELETE FROM mail_webhook_seen WHERE at < ?").run(new Date(Date.now() - 7 * 86400000).toISOString());
    const type = String(ev.type || ''), data = ev.data || {};
    if (!EVENTS.includes(type) || !data.email_id) return res.json({ ok: true, ignored: type || 'unknown' });
    const r = db.prepare("SELECT * FROM email_receipts WHERE provider = 'resend' AND provider_id = ?").get(String(data.email_id));
    if (!r) return res.json({ ok: true, unknown_email: true });   // sent by another client of the same Resend account
    const detail = data.bounce ? { bounce: { type: data.bounce.type, sub_type: data.bounce.subType || data.bounce.sub_type, message: String(data.bounce.message || '').slice(0, 300) } } : null;
    applyEvent(r, type, String(ev.created_at || data.created_at || now()), detail);
    res.json({ ok: true });
  });

  // The operator registers the webhook with Resend: a request approved in the app (critical: the PIN, the phone). The
  // server makes it with its own key and stores the signing secret encrypted; the answer never carries it.
  app.post('/api/email/webhooks/resend/register', lim, async (req, res) => {
    const a = who(req, res); if (!a) return;
    if (!operatorAllowed(a.did) || a.silicon || (a.decoded && (a.decoded.wrk || a.decoded.auth_method === 'fleet_owner_mint'))) return res.status(403).json({ error: 'only the operator, from their own session' });
    if (!resendKey()) return res.status(503).json({ error: 'no Resend key configured on this server' });
    const A = approvals && approvals();
    if (!A || !A.gateService) return res.status(503).json({ error: 'approvals unavailable' });
    const endpoint = `${publicApi}/api/email/webhooks/resend`;
    const g = A.gateService({ key: 'svc:demipass:mail-webhook', name: `register Resend delivery events → ${endpoint}`, approverDid: a.did, depth: 'critical' },
      { did: a.did, label: 'mail receipts' }, { action: 'mail-webhook', targetHost: 'api.resend.com', params: { endpoint, events: EVENTS } }, req.body || {});
    if (!g.ok) { const b = { ...(g.body || {}) }; delete b.owner; return res.status(g.status).json(b); }
    const r = await resend('POST', '/webhooks', { endpoint, events: EVENTS }).catch(e => ({ status: 0, data: { message: e.message } }));
    const secret = r.data && (r.data.signing_secret || r.data.secret);
    if ((r.status !== 200 && r.status !== 201) || !secret) {
      return res.status(502).json({ error: `Resend did not create the webhook: HTTP ${r.status} ${(r.data && (r.data.message || r.data.name)) || ''}`.trim(),
        ...(r.status === 401 || r.status === 403 ? { hint: 'the relay key may be sending-only; a full-access key (RESEND_API_KEY) is needed to register webhooks' } : {}) });
    }
    storeSecret(String(secret));
    db.prepare('INSERT INTO mail_provider_state (k, v, updated_at) VALUES (?, ?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v, updated_at = excluded.updated_at').run('resend_webhook_id', String(r.data.id || ''), now());
    try { logSecurityEvent('mail_webhook_registered', 'info', { caller_did: a.did, capability: 'mail-webhook', context: { webhook_id: r.data.id, endpoint } }); } catch (_) {}
    res.json({ ok: true, webhook_id: r.data.id || null, endpoint, events: EVENTS });
  });

  return { send, verifySvix, applyEvent };
};
