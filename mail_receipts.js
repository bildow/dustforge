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
// Later events never move a receipt back: a late "sent" after "delivered" is kept in the history only. Opened/clicked
// (tracking) imply delivered. The status covers the whole email: with several recipients, "delivered" means Resend
// reported a delivery, and each event (with its recipients) is in the history.
const RANK = { accepted: 0, queued: 0, scheduled: 0, sent: 1, delivery_delayed: 2, delivered: 3, opened: 3, clicked: 3, failed: 4, bounced: 4, suppressed: 4, complained: 5 };
const AS_STATUS = { opened: 'delivered', clicked: 'delivered', queued: 'accepted', scheduled: 'accepted' };
const TERMINAL = new Set(['bounced', 'failed', 'suppressed', 'complained']);
const REFRESH_COOLDOWN_MS = 60 * 1000, REFRESH_PER_DID_HOUR = 30;
const SIG_TOLERANCE_SEC = 300;

module.exports = function mailReceipts({ app, db, rateLimitStandard, getBearerIdentity, getReadIdentity, logSecurityEvent, approvals, createEmailTransport, operatorAllowed, publicApi }) {
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
  db.exec('CREATE INDEX IF NOT EXISTS idx_mail_webhook_seen_at ON mail_webhook_seen(at)');
  try { db.exec('ALTER TABLE email_receipts ADD COLUMN refreshed_at TEXT'); } catch (_) {}
  try { db.exec('ALTER TABLE email_receipts ADD COLUMN client_key TEXT'); } catch (_) {}
  db.exec('CREATE UNIQUE INDEX IF NOT EXISTS idx_email_receipts_client_key ON email_receipts(did, client_key) WHERE client_key IS NOT NULL');

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
  // A caller's own idempotency key (header Idempotency-Key on /api/email/send): the same key again returns the first
  // send's receipt instead of mailing twice (#90 review L1).
  function byClientKey(did, key) { return key ? db.prepare('SELECT * FROM email_receipts WHERE did = ? AND client_key = ?').get(did, key) : null; }
  async function send({ did, tokenJti, from, to, subject, text, clientKey }) {
    const sendId = clientKey ? 'es_' + crypto.createHash('sha256').update(`${did}\n${clientKey}`).digest('hex').slice(0, 24) : 'es_' + crypto.randomBytes(12).toString('hex');
    // `to` is the validated list ("a@x, b@y", up to 10): Resend takes an array of addresses (#90 review H1).
    const toList = String(to).split(',').map(x => x.trim()).filter(Boolean);
    const subjectSha = crypto.createHash('sha256').update(String(subject || '')).digest('hex');
    // A client key is claimed before anything is sent: a second request with the same key at the same moment finds the
    // claim (409) instead of sending again (#90 re-review).
    if (clientKey) {
      try {
        db.prepare(`INSERT INTO email_receipts (send_id, did, token_jti, from_addr, to_addr, subject_sha256, provider, status, events, created_at, updated_at, client_key)
                    VALUES (?, ?, ?, ?, ?, ?, 'pending', 'sending', '[]', ?, ?, ?)`).run(sendId, did, tokenJti || null, from, toList.join(', '), subjectSha, now(), now(), clientKey);
      } catch (e) { throw Object.assign(new Error('a send with this Idempotency-Key is already in progress or done'), { status: 409 }); }
    }
    try { return await deliver(); }
    catch (e) { if (clientKey) db.prepare("DELETE FROM email_receipts WHERE send_id = ? AND status = 'sending'").run(sendId); throw e; }
    async function deliver() {
    const messageId = `<${sendId}@dustforge.com>`;
    let provider, providerId = null, mid = messageId;
    if (resendKey()) {
      // The send id is the idempotency key: a retried request never becomes a second message.
      const r = await resend('POST', '/emails', { from, to: toList, subject, text, headers: { 'X-Dustforge-Send': sendId } }, { 'Idempotency-Key': sendId });
      if (r.status !== 200 || !r.data || !r.data.id) throw new Error(`Resend refused the message: HTTP ${r.status} ${(r.data && (r.data.message || r.data.name)) || ''}`.trim());
      provider = 'resend'; providerId = String(r.data.id); mid = null;   // Resend sets the Message-ID; its email id is the handle
    } else {
      const info = await createEmailTransport().sendMail({ from, to, subject, text, messageId });
      provider = 'smtp'; providerId = (info && info.response) ? String(info.response).slice(0, 200) : null; mid = (info && info.messageId) || messageId;
    }
    const at = now();
    // The mail has left: a receipt that fails to write must not turn into a refund and a retry (a second message).
    try {
      db.prepare(`INSERT INTO email_receipts (send_id, did, token_jti, from_addr, to_addr, subject_sha256, provider, provider_id, message_id, status, events, created_at, updated_at, client_key)
                  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'accepted', ?, ?, ?, ?)
                  ON CONFLICT(send_id) DO UPDATE SET provider = excluded.provider, provider_id = excluded.provider_id, message_id = excluded.message_id,
                    status = 'accepted', events = excluded.events, updated_at = excluded.updated_at`)
        .run(sendId, did, tokenJti || null, from, toList.join(', '), subjectSha, provider, providerId, mid,
             JSON.stringify([{ type: 'accepted', at, by: provider }]), at, at, clientKey || null);
    } catch (e) { console.error(`[mail-receipts] sent ${sendId} (${provider} ${providerId || '-'}) but the receipt did not write: ${e.message}`); }
    return { send_id: sendId, provider, provider_id: provider === 'resend' ? providerId : null, message_id: mid };
    }
  }

  // Express middleware for /api/email/send, mounted before every cap, reservation and charge: a request repeating an
  // earlier Idempotency-Key gets that send's receipt and reserves, charges and sends nothing (#90 re-review H). The same
  // key with a different message is refused (422); a send still in flight is 409.
  function replayGuard(getIdentity) {
    return (req, res, next) => {
      const key = req.headers['idempotency-key'];
      if (typeof key !== 'string') return next();
      if (!/^[A-Za-z0-9._:-]{8,100}$/.test(key)) return res.status(400).json({ error: 'Idempotency-Key: 8-100 of [A-Za-z0-9._:-]' });
      const a = getIdentity(req);
      if (!a || !a.ok) return next();                         // the auth middleware answers this
      const r = byClientKey(a.did, key);
      if (!r) return next();
      const b = req.body || {};
      const sameTo = String(b.to || '').split(',').map(x => x.trim()).filter(Boolean).join(', ') === r.to_addr;
      const sameSubject = crypto.createHash('sha256').update(String(b.subject || '')).digest('hex') === r.subject_sha256;
      if (!sameTo || !sameSubject) return res.status(422).json({ error: 'this Idempotency-Key was used for a different message', send_id: r.send_id });
      if (r.status === 'sending') return res.status(409).json({ error: 'a send with this Idempotency-Key is still in progress; ask again shortly', send_id: r.send_id });
      return res.json({ ok: true, replayed: true, billed: 0, send_id: r.send_id, provider: r.provider, resend_id: r.provider === 'resend' ? r.provider_id : null,
        message_id: r.message_id, status: r.status, status_url: `/api/email/sends/${r.send_id}` });
    };
  }

  function view(r) {
    return { send_id: r.send_id, provider: r.provider, provider_id: r.provider === 'resend' ? r.provider_id : null, message_id: r.message_id,
      from: r.from_addr, to: r.to_addr, status: r.status, last_event_at: r.last_event_at, events: JSON.parse(r.events || '[]'), created_at: r.created_at,
      ...(r.provider === 'smtp' ? { note: 'sent through the SMTP relay: no provider id, so no delivery events (only Resend sends report them)' } : {}) };
  }

  // Re-read inside one transaction, so an event landing meanwhile (webhook vs refresh) is never overwritten (M3).
  const applyEvent = db.transaction((sendId, type, at, detail) => {
    const r = db.prepare('SELECT * FROM email_receipts WHERE send_id = ?').get(sendId);
    if (!r) return false;
    const s = String(type).replace(/^email\./, '');
    const evs = JSON.parse(r.events || '[]');
    if (evs.some(e => e.type === s && e.at === at)) return false;   // the same event twice
    evs.push({ type: s, at, ...(detail ? { detail } : {}) });
    const as = AS_STATUS[s] || s;
    const status = (RANK[as] !== undefined && RANK[as] > (RANK[r.status] || 0)) ? as : r.status;
    const last = !r.last_event_at || at > r.last_event_at ? at : r.last_event_at;
    db.prepare('UPDATE email_receipts SET status = ?, last_event_at = ?, events = ?, updated_at = ? WHERE send_id = ?')
      .run(status, last, JSON.stringify(evs.slice(-50)), now(), sendId);
    return true;
  });

  // ── reading ──────────────────────────────────────────────────────────────────────────────────────────────────
  const lim = rateLimitStandard || ((req, res, next) => next());
  const refreshLog = new Map();   // did → refresh times in the last hour
  // Reads take any live token of the wallet (read scope is enough: a token that can send can read its receipts, M1).
  function who(req, res, { write = false } = {}) {
    const a = write ? getBearerIdentity(req) : (getReadIdentity || getBearerIdentity)(req);
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
      // Resend's own record, for when an event was missed (or before the webhook is registered). Every refresh spends
      // the team's Resend rate limit, which sending shares: once a minute per receipt, 30 an hour per wallet, never
      // after a final status (M2).
      const recent = refreshLog.get(a.did) || []; const cut = Date.now() - 3600000;
      const mine = recent.filter(t => t > cut); if (!mine.length) refreshLog.delete(a.did);
      if (TERMINAL.has(r.status)) refresh = { ok: false, skipped: `final status (${r.status})` };
      else if (r.refreshed_at && Date.now() - Date.parse(r.refreshed_at) < REFRESH_COOLDOWN_MS) refresh = { ok: false, skipped: 'refreshed less than a minute ago' };
      else if (mine.length >= REFRESH_PER_DID_HOUR) refresh = { ok: false, skipped: `at most ${REFRESH_PER_DID_HOUR} refreshes an hour` };
      else {
        mine.push(Date.now()); refreshLog.set(a.did, mine);
        db.prepare('UPDATE email_receipts SET refreshed_at = ? WHERE send_id = ?').run(now(), r.send_id);
        try {
          const g = await resend('GET', `/emails/${encodeURIComponent(r.provider_id)}`);
          if (g.status === 200 && g.data && g.data.last_event) { applyEvent(r.send_id, 'email.' + g.data.last_event, now(), { source: 'refresh' }); refresh = { ok: true, last_event: g.data.last_event }; }
          else refresh = { ok: false, http_status: g.status, error: (g.data && (g.data.message || g.data.name)) || 'no last_event' };
        } catch (e) { refresh = { ok: false, error: e.message }; }
      }
      r = db.prepare('SELECT * FROM email_receipts WHERE send_id = ?').get(r.send_id);
    }
    res.json({ ok: true, ...view(r), ...(refresh ? { refresh } : {}) });
  });

  // ── Resend's events ──────────────────────────────────────────────────────────────────────────────────────────
  // HKDF from the master key; with no master key nothing is stored (it would be plaintext in effect, L4).
  const KEY_ENC = () => {
    if (!process.env.IDENTITY_MASTER_KEY) throw new Error('IDENTITY_MASTER_KEY is not set');
    return Buffer.from(crypto.hkdfSync('sha256', Buffer.from(process.env.IDENTITY_MASTER_KEY, 'utf8'), Buffer.alloc(0), Buffer.from('dustforge mail-webhook-secret v1'), 32));
  };
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
  // Refusals are counted per address in memory and logged at most once a minute each (an unauthenticated route must not
  // grow the database, M4); an address with 30 refusals in 10 minutes is turned away before any work.
  const refused = new Map();
  function refusedLately(ip) { const t = (refused.get(ip) || []).filter(x => x > Date.now() - 600000); if (t.length) refused.set(ip, t); else refused.delete(ip); return t; }
  const record = db.transaction((svixId, sendId, type, at, detail) => {
    if (db.prepare('SELECT 1 FROM mail_webhook_seen WHERE svix_id = ?').get(svixId)) return 'duplicate';
    db.prepare('INSERT INTO mail_webhook_seen (svix_id, at) VALUES (?, ?)').run(svixId, now());
    if (sendId) applyEvent(sendId, type, at, detail);
    return 'ok';
  });
  let lastPrune = 0;
  app.post('/api/email/webhooks/resend', require('express').raw({ type: '*/*', limit: '256kb' }), (req, res) => {
    const ip = req.ip || 'unknown';
    if (refusedLately(ip).length >= 30) return res.status(429).json({ error: 'too many refused deliveries' });
    const secret = loadSecret();
    if (!secret) return res.status(503).json({ error: 'webhook not registered' });
    const raw = Buffer.isBuffer(req.body) ? req.body.toString('utf8') : '';
    const bad = verifySvix(secret, req.headers, raw);
    if (bad) {
      const t = refusedLately(ip); t.push(Date.now()); refused.set(ip, t);
      if (t.length === 1 || t.length % 30 === 0) { try { logSecurityEvent('mail_webhook_refused', 'warn', { capability: 'mail-webhook', context: { reason: bad, refusals_10min: t.length } }); } catch (_) {} }
      return res.status(401).json({ error: bad });
    }
    let ev; try { ev = JSON.parse(raw); } catch (_) { ev = null; }
    if (!ev || typeof ev !== 'object' || Array.isArray(ev)) return res.status(400).json({ error: 'not a JSON object' });
    if (Date.now() - lastPrune > 3600000) { lastPrune = Date.now(); db.prepare('DELETE FROM mail_webhook_seen WHERE at < ?').run(new Date(Date.now() - 7 * 86400000).toISOString()); }
    const type = String(ev.type || ''), data = (ev.data && typeof ev.data === 'object') ? ev.data : {};
    const known = EVENTS.includes(type) && data.email_id;
    const r = known ? db.prepare("SELECT send_id FROM email_receipts WHERE provider = 'resend' AND provider_id = ?").get(String(data.email_id)) : null;
    const detail = data.bounce ? { bounce: { type: data.bounce.type, sub_type: data.bounce.subType || data.bounce.sub_type, message: String(data.bounce.message || '').slice(0, 300) } } : null;
    const out = record(String(req.headers['svix-id']), r ? r.send_id : null, type, String(ev.created_at || data.created_at || now()), detail);
    if (out === 'duplicate') return res.json({ ok: true, duplicate: true });
    if (!known) return res.json({ ok: true, ignored: type || 'unknown' });
    if (!r) return res.json({ ok: true, unknown_email: true });   // sent by another client of the same Resend account
    res.json({ ok: true });
  });

  // The operator registers the webhook with Resend: a request approved in the app (critical: the PIN, the phone). The
  // server makes it with its own key and stores the signing secret encrypted; the answer never carries it.
  app.post('/api/email/webhooks/resend/register', lim, async (req, res) => {
    const a = who(req, res, { write: true }); if (!a) return;
    if (!operatorAllowed(a.did) || a.silicon || (a.decoded && (a.decoded.wrk || a.decoded.auth_method === 'fleet_owner_mint'))) return res.status(403).json({ error: 'only the operator, from their own session' });
    if (!resendKey()) return res.status(503).json({ error: 'no Resend key configured on this server' });
    if (process.env.RESEND_WEBHOOK_SECRET) return res.status(409).json({ error: 'RESEND_WEBHOOK_SECRET is set in the environment and overrides a registered secret; remove it first' });
    if (!process.env.IDENTITY_MASTER_KEY) return res.status(503).json({ error: 'IDENTITY_MASTER_KEY is not set: the signing secret would not be stored safely' });
    const A = approvals && approvals();
    if (!A || !A.gateService) return res.status(503).json({ error: 'approvals unavailable' });
    const endpoint = `${publicApi}/api/email/webhooks/resend`;
    const g = A.gateService({ key: 'svc:demipass:mail-webhook', name: `register Resend delivery events → ${endpoint}`, approverDid: a.did, depth: 'critical' },
      { did: a.did, label: 'mail receipts' }, { action: 'mail-webhook', targetHost: 'api.resend.com', params: { endpoint, events: EVENTS } }, req.body || {});
    if (!g.ok) { const b = { ...(g.body || {}) }; delete b.owner; return res.status(g.status).json(b); }
    // A re-registration replaces the old webhook rather than leaving it to fail against a secret we no longer hold (L2).
    const prev = db.prepare("SELECT v FROM mail_provider_state WHERE k = 'resend_webhook_id'").get();
    const r = await resend('POST', '/webhooks', { endpoint, events: EVENTS }).catch(e => ({ status: 0, data: { message: e.message } }));
    const secret = r.data && (r.data.signing_secret || r.data.secret);
    if ((r.status !== 200 && r.status !== 201) || !secret) {
      return res.status(502).json({ error: `Resend did not create the webhook: HTTP ${r.status} ${(r.data && (r.data.message || r.data.name)) || ''}`.trim(),
        ...(r.status === 401 || r.status === 403 ? { hint: 'the relay key may be sending-only; a full-access key (RESEND_API_KEY) is needed to register webhooks' } : {}) });
    }
    storeSecret(String(secret));
    db.prepare('INSERT INTO mail_provider_state (k, v, updated_at) VALUES (?, ?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v, updated_at = excluded.updated_at').run('resend_webhook_id', String(r.data.id || ''), now());
    // Only now that the new one exists: the old webhook goes (created first, so events never stop).
    if (prev && prev.v && prev.v !== String(r.data.id || '')) await resend('DELETE', `/webhooks/${encodeURIComponent(prev.v)}`).catch(() => null);
    try { logSecurityEvent('mail_webhook_registered', 'info', { caller_did: a.did, capability: 'mail-webhook', context: { webhook_id: r.data.id, endpoint } }); } catch (_) {}
    res.json({ ok: true, webhook_id: r.data.id || null, endpoint, events: EVENTS });
  });

  return { send, byClientKey, replayGuard, verifySvix, applyEvent };
};
