'use strict';
// ── Security depth on use: per-use human approval (docs/approvals.md) ─────────────────────────────────────────────
// A secret's owner sets its depth (standard / elevated / critical, the existing security_depth). It is a property of
// the secret, so every share and delegation inherits it and no recipient can lower it (only the owner sets depth).
//   standard  — a delegation is enough, as before.
//   elevated  — every /use needs the owner's approval of THAT use. The call that finds none creates a pending request
//               (id, requester, secret ref, purpose, the exact action/target/params it binds, TTL 5 min), the owner is
//               notified, and the caller gets 202 approval_pending with the request id: it parks the task, no retry
//               loop. Opening the request screen starts a 6-digit code bound to that request id, rotating every 30 s
//               until approved or expired. Either the owner taps Approve (the app sends the code server-side; nobody
//               types it) or reads the code to the agent in another channel and the agent sends it with its /use.
//               One use per approval. Three wrong codes cancel the request (critical event).
//   critical  — the same, plus the owner's PIN to open the request screen at all; reveal also takes PIN + code.
//
// The code binding is channel-independent: code = HMAC(code_key of the request, "dp-approval:<id>:<30 s step>").
// A channel only DELIVERS it — today the app screen (`open`); later SMS via Riley — so adding a channel changes
// nothing about what a code proves: this request, this 30-second window, nothing else. A code seen in a transcript
// opens no other request, and is dead within a minute.

const crypto = require('crypto');

const TTL_SEC = 5 * 60;           // pending request, and an approved one waiting to be used
const STEP_SEC = 30;              // code rotation
const MAX_WRONG = 3;
const MAX_PENDING_PER_OWNER = 30;
const MAIL_PER_OWNER_PER_HOUR = 20;
const DEPTHS = new Set(['elevated', 'critical']);
// Keys that steer the approval itself, never part of what it binds.
// The raw request body is bound as sent (top level and `params` both, never a merged view — /use paths read from
// either), minus only the per-call token and these steering fields.
const META_KEYS = new Set(['use_token', 'approval_id', 'approval_code', 'purpose', 'admin_key']);
const MAX_BOUND_JSON = 4096;      // a call the owner cannot read in full is not offered for approval
const MAX_PENDING_PER_REQUESTER = 5;
const DENY_COOLDOWN_SEC = 10 * 60;  // after the owner denies a requester, it may not ask that owner again for 10 minutes

module.exports = function registerUseApprovals(deps) {
  const { app, db, rateLimitStandard, rateLimitFill, getBearerIdentity, gateSession, gateFresh, gateMissing, spendSingleUse,
          logSecurityEvent, cleanLabel, billing, sendMail } = deps;
  const limiter = rateLimitFill || rateLimitStandard;

  db.exec(`CREATE TABLE IF NOT EXISTS use_approvals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL DEFAULT 'use',            -- 'use' | 'reveal'
    secret_id INTEGER NOT NULL,
    owner_did TEXT NOT NULL,
    requester_did TEXT NOT NULL,
    requester_label TEXT DEFAULT '',
    delegation_id INTEGER,
    depth TEXT NOT NULL,
    purpose TEXT DEFAULT '',
    summary TEXT DEFAULT '',
    binding TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',      -- pending | approved | used | denied | expired | cancelled
    code_key TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    opened_at TEXT, opened_session TEXT, opened_via TEXT,
    approved_at TEXT, approved_via TEXT,
    used_at TEXT, decided_at TEXT,
    wrong_codes INTEGER DEFAULT 0,
    notified_at TEXT,
    bound_call TEXT DEFAULT ''
  )`);
  try { db.exec("ALTER TABLE use_approvals ADD COLUMN bound_call TEXT DEFAULT ''"); } catch (_) {}
  db.exec('CREATE INDEX IF NOT EXISTS idx_ua_owner ON use_approvals(owner_did, status)');
  db.exec('CREATE INDEX IF NOT EXISTS idx_ua_requester ON use_approvals(requester_did, status)');

  const nowIso = () => new Date().toISOString();
  const later = (sec) => new Date(Date.now() + sec * 1000).toISOString();
  const isPast = (iso) => !iso || Date.parse(iso) <= Date.now();
  const usernameOf = (did) => (db.prepare('SELECT username FROM identity_wallets WHERE did = ?').get(did) || {}).username || null;
  const event = (type, actor, secretId, detail) => db.prepare('INSERT INTO blindkey_events (event_type, actor, secret_id, context_name, detail) VALUES (?, ?, ?, ?, ?)')
    .run(type, actor, secretId, '*', JSON.stringify(detail));

  // ── depth and binding ──────────────────────────────────────────────────────────────────────────────────────────
  function depthOf(secret) {
    const d = secret && secret.security_depth;
    return DEPTHS.has(d) ? d : 'standard';
  }
  const BAD_KEYS = new Set(['__proto__', 'constructor', 'prototype']);
  function canonical(v) {
    if (Array.isArray(v)) return v.map(canonical);
    if (v && typeof v === 'object') { const o = Object.create(null); for (const k of Object.keys(v).sort()) o[k] = canonical(v[k]); return o; }
    return v;
  }
  // A call the owner could misread is refused before it is offered: the same key at the top level and inside
  // `params` with different values (paths read one or the other), or keys that do not survive as plain data.
  function ambiguity(body) {
    const walk = (v) => { if (v && typeof v === 'object') { for (const k of Object.keys(v)) { if (BAD_KEYS.has(k)) return k; const r = walk(v[k]); if (r) return r; } } return null; };
    const bad = walk(body);
    if (bad) return `the call carries a '${bad}' key — not accepted on an elevated/critical secret`;
    const p = body && body.params;
    if (p && typeof p === 'object' && !Array.isArray(p)) {
      for (const k of Object.keys(p)) if (Object.prototype.hasOwnProperty.call(body, k) && k !== 'params' && JSON.stringify(canonical(body[k])) !== JSON.stringify(canonical(p[k]))) {
        return `ambiguous call: '${k}' differs between the top level and params — send it once (or the same in both)`;
      }
    }
    return null;
  }
  // What an approval binds: this secret, this action, this target, these exact parameters (the command, the body).
  function boundCall({ kind = 'use', action = '', targetHost = '', targetUrl = '', params = {} }) {
    const p = {};
    for (const [k, v] of Object.entries(params || {})) if (!META_KEYS.has(k)) p[k] = v;
    return canonical({ kind, action, target_host: targetHost || '', target_url: targetUrl || '', body: p });
  }
  function bindingOf({ secretId, ...use }) {
    return crypto.createHash('sha256').update(JSON.stringify({ secretId, call: boundCall(use) })).digest('hex');
  }
  // A one-line headline for the card. The owner approves the full bound call (`call`, shown as JSON), never this alone.
  function summaryOf({ kind, action, targetHost, targetUrl, params }) {
    if (kind === 'reveal') return 'reveal the value';
    const p = params || {};
    const cmd = (p.params && p.params.command) || p.command || '';
    const what = action === 'ssh_exec' ? `ssh ${targetHost || ''}: ${JSON.stringify(String(cmd)).slice(1, -1)}` : `${action} ${targetUrl || targetHost || ''}`;
    return cleanLabel(what, 120) + (what.length > 120 ? ' …(see the full call)' : '');
  }

  // ── codes ──────────────────────────────────────────────────────────────────────────────────────────────────────
  const stepNow = () => Math.floor(Date.now() / 1000 / STEP_SEC);
  function codeAt(row, step) {
    // Bound to the request id, its secret and its requester (red team item 4c), and the 30-s step.
    const mac = crypto.createHmac('sha256', Buffer.from(row.code_key, 'hex')).update(`dp-approval:${row.id}:${row.secret_id}:${row.requester_did}:${step}`).digest();
    return String(mac.readUInt32BE(0) % 1000000).padStart(6, '0');
  }
  // The current code or the one just before it (a code read aloud may cross a 30-s boundary). Constant-time compare.
  function codeMatches(row, code) {
    if (typeof code !== 'string' || !/^\d{6}$/.test(code) || !row.opened_at) return false;
    const s = stepNow();
    return [s, s - 1].some(st => crypto.timingSafeEqual(Buffer.from(codeAt(row, st)), Buffer.from(code)));
  }

  // ── lifecycle ──────────────────────────────────────────────────────────────────────────────────────────────────
  function expireOld() {
    db.prepare("UPDATE use_approvals SET status = 'expired', decided_at = ? WHERE status IN ('pending', 'approved') AND expires_at <= ?").run(nowIso(), nowIso());
  }
  function view(row, me) {
    const owner = row.owner_did === me;
    const s = db.prepare('SELECT name, ref_code FROM blindkey_secrets WHERE id = ?').get(row.secret_id) || {};
    return {
      id: row.id, kind: row.kind, status: row.status, depth: row.depth,
      secret: { name: s.name || null, ref: s.ref_code || null },
      owner: usernameOf(row.owner_did), requester: usernameOf(row.requester_did), requester_label: row.requester_label || null,
      purpose: row.purpose || '', summary: row.summary || '',
      ...(owner ? { call: row.bound_call ? JSON.parse(row.bound_call) : null } : {}),
      created_at: row.created_at, expires_at: row.expires_at,
      ...(owner ? { opened: Boolean(row.opened_at), needs_pin_to_open: true } : {}),
      ...(row.approved_at ? { approved_at: row.approved_at, approved_via: row.approved_via } : {}),
      ...(row.used_at ? { used_at: row.used_at } : {}), ...(row.wrong_codes ? { wrong_codes: row.wrong_codes } : {}),
    };
  }
  // The owner's notice: that an approval is pending, nothing else (it may show on a locked phone).
  function notifyOwner(row) {
    if (!sendMail) return;
    try {
      const sent = db.prepare("SELECT COUNT(*) AS n FROM use_approvals WHERE owner_did = ? AND notified_at > ?").get(row.owner_did, new Date(Date.now() - 3600000).toISOString()).n;
      if (sent >= MAIL_PER_OWNER_PER_HOUR) return;
      const w = db.prepare('SELECT email, recovery_email FROM identity_wallets WHERE did = ?').get(row.owner_did) || {};
      const to = w.recovery_email || w.email;
      if (!to) return;
      db.prepare('UPDATE use_approvals SET notified_at = ? WHERE id = ?').run(nowIso(), row.id);
      Promise.resolve(sendMail({ to, subject: 'DemiPass: an approval is pending',
        text: 'An approval is pending in your DemiPass app.\n\nhttps://demipass.com/app\n' })).catch(() => {});
    } catch (_) {}
  }
  function createRequest({ secret, kind, requesterDid, label, delegationId, purpose, binding, summary, call }) {
    const callJson = JSON.stringify(call);
    if (Buffer.byteLength(callJson) > MAX_BOUND_JSON) return { error: `this call is too large to show the owner in full for approval (${Buffer.byteLength(callJson)} bytes > ${MAX_BOUND_JSON}); send a smaller one`, status: 413 };
    // An owner's own agents all request as the owner's DID: split by agent label only then. Anyone else gets 5 per DID,
    // whatever labels it signs in under (labels are self-chosen).
    const own = requesterDid === secret.did;
    const mine = own
      ? db.prepare("SELECT COUNT(*) AS n FROM use_approvals WHERE requester_did = ? AND owner_did = ? AND requester_label = ? AND status = 'pending'").get(requesterDid, secret.did, cleanLabel(label || '', 80)).n
      : db.prepare("SELECT COUNT(*) AS n FROM use_approvals WHERE requester_did = ? AND owner_did = ? AND status = 'pending'").get(requesterDid, secret.did).n;
    if (mine >= MAX_PENDING_PER_REQUESTER) return { error: `you already have ${mine} requests waiting on this owner; wait for them`, status: 429 };
    // A denial is an answer (red team item 4a): the requester waits before asking this owner again.
    const denied = db.prepare("SELECT decided_at FROM use_approvals WHERE requester_did = ? AND owner_did = ? AND status = 'denied' AND decided_at > ? ORDER BY decided_at DESC LIMIT 1")
      .get(requesterDid, secret.did, new Date(Date.now() - DENY_COOLDOWN_SEC * 1000).toISOString());
    if (denied) {
      const until = new Date(Date.parse(denied.decided_at) + DENY_COOLDOWN_SEC * 1000).toISOString();
      return { error: `the owner denied your last request — you can ask again after ${until}`, status: 429, extra: { cooldown_until: until } };
    }
    const pending = db.prepare("SELECT COUNT(*) AS n FROM use_approvals WHERE owner_did = ? AND status = 'pending'").get(secret.did).n;
    if (pending >= MAX_PENDING_PER_OWNER) return { error: 'too many approvals are waiting on this owner; try again later', status: 429 };
    const id = Number(db.prepare(`INSERT INTO use_approvals (kind, secret_id, owner_did, requester_did, requester_label, delegation_id, depth, purpose, summary,
                                  binding, code_key, created_at, expires_at, bound_call) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .run(kind, secret.id, secret.did, requesterDid, cleanLabel(label || '', 80), delegationId || null, depthOf(secret), cleanLabel(purpose || '', 200).trim(),
           summary, binding, crypto.randomBytes(32).toString('hex'), nowIso(), later(TTL_SEC), callJson).lastInsertRowid);
    const row = db.prepare('SELECT * FROM use_approvals WHERE id = ?').get(id);
    event('approval_requested', requesterDid, secret.id, { approval_id: id, kind, owner_did: secret.did, depth: row.depth, summary });
    logSecurityEvent('approval_requested', 'info', { caller_did: requesterDid, capability: kind, target: secret.name, context: { approval_id: id, owner_did: secret.did } });
    notifyOwner(row);
    return { row };
  }
  function pendingReply(row, me, extra = {}) {
    return { ok: false, status: 'approval_pending', approval_id: row.id, expires_at: row.expires_at, owner: usernameOf(row.owner_did), depth: row.depth,
      ...extra,
      next: `Park this task. ${usernameOf(row.owner_did)} approves it in the DemiPass app. Then make the same call once more with approval_id ${row.id} — or, if they read you the 6-digit code, with approval_id and approval_code. Do not retry in a loop: check GET /api/demipass/approvals/${row.id} when you resume.` };
  }

  // The gate /use calls before it acts with a secret. Returns { ok:true } to proceed, or { status, body } to answer.
  // `caller` = { did, label }, `use` = { kind, action, targetHost, targetUrl, params, delegationId }.
  // `peek`: report whether an approved request is there without spending it (reveal checks the PIN in between).
  function gate(secret, caller, use, body = {}, { peek = false } = {}) {
    if (depthOf(secret) === 'standard') return { ok: true };
    const amb = ambiguity(use.params);
    if (amb) return { status: 400, body: { error: amb } };
    expireOld();
    const kind = use.kind || 'use';
    const binding = bindingOf({ secretId: secret.id, kind, action: use.action, targetHost: use.targetHost, targetUrl: use.targetUrl, params: use.params });
    const aid = body.approval_id;
    if (aid !== undefined && aid !== null && aid !== '') {
      const id = Number(aid);
      const row = Number.isInteger(id) && id > 0 ? db.prepare('SELECT * FROM use_approvals WHERE id = ?').get(id) : null;
      // The same refusal for a missing, foreign or differently-bound request: nothing about other requests leaks.
      if (!row || row.requester_did !== caller.did || row.secret_id !== secret.id || row.kind !== kind) return { status: 404, body: { error: 'approval request not found for this caller and secret' } };
      if (row.binding !== binding) return { status: 409, body: { error: 'this approval was for a different call (action, target or parameters); make the approved call exactly, or ask anew without approval_id', approval_id: row.id } };
      if (row.status === 'approved') {
        if (peek) return { ok: true, approval_id: row.id, peeked: true };
        const took = db.prepare("UPDATE use_approvals SET status = 'used', used_at = ? WHERE id = ? AND status = 'approved'").run(nowIso(), row.id).changes;
        if (took !== 1) return { status: 410, body: { error: 'this approval was already used' } };
        event('approval_used', caller.did, secret.id, { approval_id: row.id, via: row.approved_via });
        return { ok: true, approval_id: row.id };
      }
      if (row.status === 'pending') {
        const code = body.approval_code;
        if (code === undefined || code === null || code === '') return { status: 202, body: pendingReply(row, caller.did, { already_pending: true }) };
        if (!row.opened_at) return { status: 409, body: { error: 'the owner has not opened this request yet — no code exists for it', approval_id: row.id } };
        if (codeMatches(row, String(code))) {
          if (peek) return { ok: true, approval_id: row.id, peeked: true };
          const took = db.prepare("UPDATE use_approvals SET status = 'used', approved_at = ?, approved_via = 'code', used_at = ?, decided_at = ? WHERE id = ? AND status = 'pending'")
            .run(nowIso(), nowIso(), nowIso(), row.id).changes;
          if (took !== 1) return { status: 410, body: { error: 'this request was decided meanwhile' } };
          event('approval_used', caller.did, secret.id, { approval_id: row.id, via: 'code' });
          logSecurityEvent('approval_code_accepted', 'info', { caller_did: caller.did, capability: kind, target: secret.name, context: { approval_id: row.id, owner_did: row.owner_did } });
          return { ok: true, approval_id: row.id };
        }
        const wrong = db.prepare('UPDATE use_approvals SET wrong_codes = wrong_codes + 1 WHERE id = ? RETURNING wrong_codes').get(row.id).wrong_codes;
        event('approval_code_wrong', caller.did, secret.id, { approval_id: row.id, wrong_codes: wrong });
        if (wrong >= MAX_WRONG) {
          db.prepare("UPDATE use_approvals SET status = 'cancelled', decided_at = ? WHERE id = ? AND status = 'pending'").run(nowIso(), row.id);
          logSecurityEvent('approval_cancelled_wrong_codes', 'critical', { caller_did: caller.did, capability: kind, target: secret.name, context: { approval_id: row.id, owner_did: row.owner_did, wrong_codes: wrong } });
          event('approval_cancelled', caller.did, secret.id, { approval_id: row.id, reason: 'wrong codes', wrong_codes: wrong });
          return { status: 403, body: { error: `wrong code — ${MAX_WRONG} wrong codes cancelled this request`, cancelled: true } };
        }
        return { status: 403, body: { error: 'wrong or expired code', attempts_left: MAX_WRONG - wrong, approval_id: row.id } };
      }
      return { status: 410, body: { error: `this approval request is ${row.status}`, approval_id: row.id } };
    }
    // No approval named: the same caller asking for the same call while one waits gets that one back, not a new one.
    const same = db.prepare("SELECT * FROM use_approvals WHERE requester_did = ? AND secret_id = ? AND binding = ? AND status IN ('pending', 'approved') ORDER BY id DESC LIMIT 1")
      .get(caller.did, secret.id, binding);
    if (same) return { status: 202, body: pendingReply(same, caller.did, { already_pending: true, ...(same.status === 'approved' ? { approved: true } : {}) }) };
    const made = createRequest({ secret, kind, requesterDid: caller.did, label: caller.label, delegationId: use.delegationId, purpose: body.purpose,
      binding, call: boundCall({ kind, action: use.action, targetHost: use.targetHost, targetUrl: use.targetUrl, params: use.params }),
      summary: summaryOf({ kind, action: use.action, targetHost: use.targetHost, targetUrl: use.targetUrl, params: use.params }) });
    if (made.error) return { status: made.status, body: { error: made.error, ...(made.extra || {}) } };
    return { status: 202, body: pendingReply(made.row, caller.did) };
  }

  // ── routes ─────────────────────────────────────────────────────────────────────────────────────────────────────
  // The owner, acting as a person in their own session (not an agent token).
  function ownerAuth(req, res) {
    const auth = getBearerIdentity(req);
    if (!auth.ok) { res.status(auth.status || 401).json({ error: auth.error }); return null; }
    if (auth.silicon || (auth.decoded && (auth.decoded.wrk || auth.decoded.auth_method === 'fleet_owner_mint'))) { res.status(403).json({ error: 'approvals are decided by the owner in their own session, not by an agent token' }); return null; }
    if (!gateSession(auth)) { res.status(403).json({ error: 'this token cannot hold a session — sign in again' }); return null; }
    return auth;
  }
  function ownRow(req, res, auth) {
    const id = Number(req.params.id);
    const row = Number.isInteger(id) && id > 0 ? db.prepare('SELECT * FROM use_approvals WHERE id = ? AND owner_did = ?').get(id, auth.did) : null;
    if (!row) { res.status(404).json({ error: 'approval request not found' }); return null; }
    return row;
  }

  // GET /api/blindkey/approvals — incoming (waiting on you), outgoing (yours), recent (decided, both sides): the audit.
  app.get('/api/blindkey/approvals', rateLimitFill || rateLimitStandard, (req, res) => {
    const auth = getBearerIdentity(req);
    if (!auth.ok) return res.status(auth.status || 401).json({ error: auth.error });
    expireOld();
    const incoming = db.prepare("SELECT * FROM use_approvals WHERE owner_did = ? AND status = 'pending' ORDER BY id DESC LIMIT 50").all(auth.did);
    const outgoing = db.prepare("SELECT * FROM use_approvals WHERE requester_did = ? ORDER BY id DESC LIMIT 20").all(auth.did);
    const recent = db.prepare("SELECT * FROM use_approvals WHERE owner_did = ? AND status != 'pending' ORDER BY id DESC LIMIT 20").all(auth.did);
    res.json({ ok: true, incoming: auth.silicon ? [] : incoming.map(r => view(r, auth.did)), outgoing: outgoing.map(r => view(r, auth.did)), recent: recent.map(r => view(r, auth.did)) });
  });

  // GET /api/blindkey/approvals/:id — status for the owner or the requester (never a code).
  app.get('/api/blindkey/approvals/:id', rateLimitStandard, (req, res) => {
    const auth = getBearerIdentity(req);
    if (!auth.ok) return res.status(auth.status || 401).json({ error: auth.error });
    expireOld();
    const id = Number(req.params.id);
    const row = Number.isInteger(id) && id > 0 ? db.prepare('SELECT * FROM use_approvals WHERE id = ?').get(id) : null;
    if (!row || (row.owner_did !== auth.did && row.requester_did !== auth.did)) return res.status(404).json({ error: 'approval request not found' });
    res.json({ ok: true, approval: view(row, auth.did) });
  });

  // POST /api/blindkey/approvals/:id/open — the request screen. Starts (and then returns) the current code.
  // Critical: the owner's PIN (intent approval-open:<id>) the first time each session opens it.
  app.post('/api/blindkey/approvals/:id/open', limiter, (req, res) => {
    const auth = ownerAuth(req, res); if (!auth) return;
    expireOld();
    const row = ownRow(req, res, auth); if (!row) return;
    if (row.status !== 'pending') return res.status(409).json({ error: `this request is ${row.status}`, approval: view(row, auth.did) });
    const session = gateSession(auth);
    // The PIN opens every request screen, at every depth: it is the one factor an agent signed in as the owner
    // (device login, refreshed token) never holds, so it is what makes the approval a person's. (When the app's
    // dormancy lock lands, its unlock can stand in for elevated; critical keeps asking.)
    if (row.opened_session !== session) {
      const intent = `approval-open:${row.id}`;
      if (!gateFresh(auth.did, 'pin', auth, intent)) return res.status(403).json(gateMissing('approval-open', ['pin'], ['pin'], intent));
      const refused = spendSingleUse(auth.did, 'approval-open', ['pin'], auth, intent);
      if (refused) return res.status(refused.status || 403).json(refused);
    }
    if (!row.opened_at || row.opened_session !== session) {
      db.prepare("UPDATE use_approvals SET opened_at = COALESCE(opened_at, ?), opened_session = ?, opened_via = 'app' WHERE id = ?").run(nowIso(), session, row.id);
      event('approval_opened', auth.did, row.secret_id, { approval_id: row.id, via: 'app' });
    }
    const fresh = db.prepare('SELECT * FROM use_approvals WHERE id = ?').get(row.id);
    const s = stepNow();
    res.json({ ok: true, approval: view(fresh, auth.did), code: codeAt(fresh, s), code_valid_until: new Date((s + 1) * STEP_SEC * 1000).toISOString(), step_seconds: STEP_SEC,
      note: 'Approve sends this code for you. Read it to the agent only if it is waiting in another channel.' });
  });

  // POST /api/blindkey/approvals/:id/approve — the screen's button. The app sends the code it shows; nobody types it.
  app.post('/api/blindkey/approvals/:id/approve', limiter, (req, res) => {
    const auth = ownerAuth(req, res); if (!auth) return;
    expireOld();
    const row = ownRow(req, res, auth); if (!row) return;
    if (row.status !== 'pending') return res.status(409).json({ error: `this request is ${row.status}` });
    if (!row.opened_at) return res.status(409).json({ error: 'open the request first' });
    // Approved only from the session that opened it with the PIN.
    if (row.opened_session !== gateSession(auth)) return res.status(403).json({ error: 'open this request with your PIN in this session first' });
    if (!codeMatches(row, String((req.body || {}).code || ''))) return res.status(409).json({ error: 'the code on the screen has rotated; try again' });
    const took = db.prepare("UPDATE use_approvals SET status = 'approved', approved_at = ?, approved_via = 'app', decided_at = ?, expires_at = ? WHERE id = ? AND status = 'pending'")
      .run(nowIso(), nowIso(), later(TTL_SEC), row.id).changes;
    if (took !== 1) return res.status(409).json({ error: 'this request was decided meanwhile' });
    event('approval_approved', auth.did, row.secret_id, { approval_id: row.id, requester_did: row.requester_did, via: 'app' });
    logSecurityEvent('approval_approved', 'info', { caller_did: auth.did, capability: row.kind, context: { approval_id: row.id, requester_did: row.requester_did } });
    res.json({ ok: true, approval: view(db.prepare('SELECT * FROM use_approvals WHERE id = ?').get(row.id), auth.did) });
  });

  // POST /api/blindkey/approvals/:id/deny
  app.post('/api/blindkey/approvals/:id/deny', limiter, (req, res) => {
    const auth = ownerAuth(req, res); if (!auth) return;
    const row = ownRow(req, res, auth); if (!row) return;
    if (!['pending', 'approved'].includes(row.status)) return res.status(409).json({ error: `this request is ${row.status}` });
    db.prepare("UPDATE use_approvals SET status = 'denied', decided_at = ? WHERE id = ? AND status IN ('pending', 'approved')").run(nowIso(), row.id);
    event('approval_denied', auth.did, row.secret_id, { approval_id: row.id, requester_did: row.requester_did });
    logSecurityEvent('approval_denied', 'info', { caller_did: auth.did, capability: row.kind, context: { approval_id: row.id, requester_did: row.requester_did } });
    res.json({ ok: true, approval: view(db.prepare('SELECT * FROM use_approvals WHERE id = ?').get(row.id), auth.did) });
  });

  return { gate, depthOf, bindingOf, _codeAt: codeAt, STEP_SEC, TTL_SEC };
};
