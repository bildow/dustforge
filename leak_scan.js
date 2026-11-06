'use strict';
// ── Leak scanner (red team item 5, tome decisions/2026-11-05-THREAT-MODEL-demipass-red-team-v0.1.md) ────────────────
// "Is any of my vault values in this text?" — answered here, where the values are, so the scanner never holds or
// prints one. A client (bin/leak-scan.js: pane start, the deploy gate, CI) sends text in chunks it labels (file:lines);
// the answer is, per chunk, the refs and names of the owner's secrets found in it and how often. Never a value.
//
// A scan is an oracle for the owner's values ("is password123 one of them?"), and panes are agents, so:
//   - Only a scan token scans — never a session token (an agent holding the owner's SDK session gets no oracle).
//   - The scanner is told one bit per request: leak or clean. Which secret and where (refs, names, file:lines) go only
//     to the owner — mail, and the app (#45 review H1: per-chunk answers let 12 chunks of a 3000-word dictionary
//     recover a value exactly from one positive scan).
//   - The first hit revokes the token that found it (stop the line), mails the owner and is a critical event.
//   - A token makes at most DAILY_REQUESTS scans and DAILY_BYTES a day, so testing guesses one by one is slow, and the
//     single positive it can get ends it. Values shorter than MIN_LEN are not matched; every scan is logged.
// Tokens: the owner mints one in their own session with the PIN; or anyone acting for the owner (a pane, CI set-up)
// REQUESTS tokens (POST /leak-scan/token-requests {labels}) and the owner approves in the app (PIN intent
// scan-approve:<id>, and the linked phone). The requester claims them once with the claim secret it got at request
// time — so no PIN is ever typed into an agent session and a token is never shown to anyone but the one who asked.

const crypto = require('crypto');

const MIN_LEN = 8;
const MAX_REQUEST_BYTES = 2 * 1024 * 1024;
const DAILY_BYTES = 64 * 1024 * 1024;
const MAX_CHUNKS = 200;
const DAILY_REQUESTS = 150;
const REQUEST_TTL_SEC = 15 * 60;     // a token request waits this long for the owner
const CLAIM_TTL_SEC = 60 * 60;       // approved tokens wait this long to be claimed (then they are dropped, unclaimed)
const MAX_LABELS = 8;
const MAX_PENDING_REQUESTS = 5;

module.exports = function registerLeakScan(deps) {
  const { app, db, express, rateLimitStandard, getBearerIdentity, gateSession, gateFresh, gateMissing, spendSingleUse,
          logSecurityEvent, blindkeyDecrypt, blindkeyEncrypt, cleanLabel } = deps;

  db.exec(`CREATE TABLE IF NOT EXISTS leak_scan_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_did TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    label TEXT DEFAULT '',
    created_at TEXT NOT NULL,
    revoked_at TEXT,
    last_used_at TEXT,
    day TEXT DEFAULT '',
    bytes_today INTEGER DEFAULT 0
  )`);
  for (const c of ['revoked_reason TEXT DEFAULT NULL', 'request_id INTEGER DEFAULT NULL', 'requests_today INTEGER DEFAULT 0']) { try { db.exec('ALTER TABLE leak_scan_tokens ADD COLUMN ' + c); } catch (_) {} }
  // What a hit found, for the owner only (the app's Settings → leak scanner, and the mail).
  db.exec(`CREATE TABLE IF NOT EXISTS leak_scan_hits (
    id INTEGER PRIMARY KEY AUTOINCREMENT, owner_did TEXT NOT NULL, token_id INTEGER, token_label TEXT DEFAULT '',
    found TEXT NOT NULL, created_at TEXT NOT NULL)`);
  db.exec(`CREATE TABLE IF NOT EXISTS leak_scan_token_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_did TEXT NOT NULL,
    labels TEXT NOT NULL,                   -- JSON array
    requested_by TEXT DEFAULT '',           -- agent label / user agent, for the owner's card
    claim_hash TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending', -- pending | approved | claimed | denied | expired
    sealed TEXT DEFAULT NULL,               -- the minted tokens, encrypted, between approval and claim only
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    decided_at TEXT DEFAULT NULL,
    claimed_at TEXT DEFAULT NULL
  )`);
  const sha = (t) => crypto.createHash('sha256').update(String(t)).digest('hex');
  const nowIso = () => new Date().toISOString();
  const later = (sec) => new Date(Date.now() + sec * 1000).toISOString();
  const parser = express.json({ limit: MAX_REQUEST_BYTES });
  const mailOwner = (did, subject, text) => {
    const w = db.prepare('SELECT email FROM identity_wallets WHERE did = ?').get(did);
    try { if (w && w.email && deps.sendMail) Promise.resolve(deps.sendMail({ to: w.email, subject, text })).catch(() => {}); } catch (_) {}
  };
  const newToken = () => 'dpscan_' + crypto.randomBytes(24).toString('base64url');
  function mint(ownerDid, label, requestId) {
    const token = newToken();
    const id = Number(db.prepare('INSERT INTO leak_scan_tokens (owner_did, token_hash, label, created_at, request_id) VALUES (?, ?, ?, ?, ?)')
      .run(ownerDid, sha(token), cleanLabel(label || '', 80), nowIso(), requestId || null).lastInsertRowid);
    return { id, token };
  }
  // Requests past their time end; tokens approved but never claimed are revoked (nobody holds them) (#45 review L1).
  function expireRequests() {
    const t = nowIso();
    const lapsed = db.prepare("SELECT id FROM leak_scan_token_requests WHERE status = 'approved' AND expires_at <= ?").all(t);
    for (const r of lapsed) db.prepare("UPDATE leak_scan_tokens SET revoked_at = ?, revoked_reason = 'unclaimed' WHERE request_id = ? AND revoked_at IS NULL").run(t, r.id);
    db.prepare("UPDATE leak_scan_token_requests SET status = 'expired', sealed = NULL, decided_at = COALESCE(decided_at, ?) WHERE status IN ('pending','approved') AND expires_at <= ?").run(t, t);
  }
  const sweeper = setInterval(() => { try { expireRequests(); } catch (_) {} }, 60000); if (sweeper.unref) sweeper.unref();

  // The owner, in their own session (a person's wallet token that can hold a PIN proof).
  function personAuth(req, res) {
    const auth = getBearerIdentity(req);
    if (!auth.ok) { res.status(auth.status || 401).json({ error: auth.error }); return null; }
    if (auth.silicon || (auth.decoded && (auth.decoded.wrk || auth.decoded.auth_method === 'fleet_owner_mint'))) { res.status(403).json({ error: 'scan tokens are approved by the owner in their own session' }); return null; }
    if (!gateSession(auth)) { res.status(403).json({ error: 'sign in again' }); return null; }
    return auth;
  }
  // Who is scanning: only a scan token (Authorization: Scan <token>).
  function scanCaller(req, res) {
    const h = String(req.headers.authorization || '');
    if (!h.startsWith('Scan ')) { res.status(403).json({ error: 'scanning takes a scan token (Authorization: Scan <token>) — a session token is never a scan oracle; request one with POST /api/demipass/leak-scan/token-requests' }); return null; }
    const row = db.prepare('SELECT * FROM leak_scan_tokens WHERE token_hash = ?').get(sha(h.slice(5).trim()));
    if (!row) { res.status(401).json({ error: 'invalid scan token' }); return null; }
    if (row.revoked_at) { res.status(401).json({ error: row.revoked_reason === 'hit' ? 'this scan token found a leak and was revoked — fix the leak, then have a new token approved' : 'this scan token is revoked', revoked: row.revoked_reason || 'revoked' }); return null; }
    return { did: row.owner_did, tokenRow: row };
  }

  // POST /api/blindkey/leak-scan/tokens {label} — the owner mints one in their own session (PIN, intent scan-token:0).
  app.post('/api/blindkey/leak-scan/tokens', rateLimitStandard, (req, res) => {
    const auth = personAuth(req, res); if (!auth) return;
    const intent = 'scan-token:0';
    if (!gateFresh(auth.did, 'pin', auth, intent)) return res.status(403).json(gateMissing('scan-token', ['pin'], ['pin'], intent));
    const dk = deps.devices && deps.devices();
    const refused = dk ? dk.approvalRefusal(auth, 'scan-token', 0, cleanLabel((req.body || {}).label || '', 80), req.body) : null;
    if (refused) return res.status(refused.status).json(refused.body);
    const spent = spendSingleUse(auth.did, 'scan-token', ['pin'], auth, intent);
    if (spent) return res.status(spent.status || 403).json(spent);
    const t = mint(auth.did, (req.body || {}).label);
    logSecurityEvent('scan_token_minted', 'warn', { caller_did: auth.did, ip: req.ip, context: { token_id: t.id } });
    res.status(201).json({ ok: true, id: t.id, token: t.token, note: 'shown once: put it in the vault or a CI secret, never in a file a pane reads' });
  });
  // GET /api/blindkey/leak-scan/tokens — the owner's scan tokens (never the token).
  app.get('/api/blindkey/leak-scan/tokens', rateLimitStandard, (req, res) => {
    const auth = getBearerIdentity(req); if (!auth.ok) return res.status(auth.status || 401).json({ error: auth.error });
    // The hits (what was found where) only to a person's own session — an agent of the owner sees the tokens, not them.
    const person = !(auth.silicon || (auth.decoded && (auth.decoded.wrk || auth.decoded.auth_method === 'fleet_owner_mint'))) && gateSession(auth);
    res.json({ ok: true, tokens: db.prepare('SELECT id, label, created_at, revoked_at, revoked_reason, last_used_at, bytes_today, requests_today, day FROM leak_scan_tokens WHERE owner_did = ? ORDER BY id DESC').all(auth.did),
      ...(person ? { hits: db.prepare('SELECT token_id, token_label, found, created_at FROM leak_scan_hits WHERE owner_did = ? ORDER BY id DESC LIMIT 20').all(auth.did).map(h => ({ ...h, found: JSON.parse(h.found) })) } : {}) });
  });
  // DELETE /api/blindkey/leak-scan/tokens/:id — revoke.
  // Revoking and denying are the owner's, in their own session (#45 review L3: an agent could revoke the deploy gate's
  // token and stop every deploy).
  // An agent signed in as the owner looks like the owner's session, so revoking takes the PIN (intent scan-token:<id>).
  app.delete('/api/blindkey/leak-scan/tokens/:id', rateLimitStandard, (req, res) => {
    const auth = personAuth(req, res); if (!auth) return;
    const intent = `scan-token:${Number(req.params.id) || 0}`;
    if (!gateFresh(auth.did, 'pin', auth, intent)) return res.status(403).json(gateMissing('scan-token', ['pin'], ['pin'], intent));
    const spent = spendSingleUse(auth.did, 'scan-token', ['pin'], auth, intent);
    if (spent) return res.status(spent.status || 403).json(spent);
    const n = db.prepare("UPDATE leak_scan_tokens SET revoked_at = ?, revoked_reason = 'owner' WHERE id = ? AND owner_did = ? AND revoked_at IS NULL").run(nowIso(), Number(req.params.id), auth.did).changes;
    res.status(n ? 200 : 404).json(n ? { ok: true } : { error: 'scan token not found' });
  });

  // ── token requests: asked for by whoever acts for the owner, approved in the owner's app ─────────────────────────
  // POST /api/blindkey/leak-scan/token-requests {labels: [..1–8]} → {request_id, claim_secret} (the secret only here).
  app.post('/api/blindkey/leak-scan/token-requests', rateLimitStandard, (req, res) => {
    const auth = getBearerIdentity(req); if (!auth.ok) return res.status(auth.status || 401).json({ error: auth.error });
    if (auth.silicon || (auth.decoded && (auth.decoded.wrk || auth.decoded.auth_method === 'fleet_owner_mint'))) return res.status(403).json({ error: 'ask with a token of the wallet whose values are scanned' });
    expireRequests();
    let labels = (req.body || {}).labels;
    if (labels === undefined && (req.body || {}).label !== undefined) labels = [req.body.label];
    if (!Array.isArray(labels) || !labels.length || labels.length > MAX_LABELS || labels.some(l => typeof l !== 'string' || !l.trim() || l.length > 80)) {
      return res.status(400).json({ error: `labels: 1–${MAX_LABELS} names, what each token is for (e.g. "ci-dustforge")` });
    }
    if (db.prepare("SELECT COUNT(*) AS n FROM leak_scan_token_requests WHERE owner_did = ? AND status = 'pending'").get(auth.did).n >= MAX_PENDING_REQUESTS) {
      return res.status(429).json({ error: 'too many token requests waiting for the owner' });
    }
    const claim = crypto.randomBytes(24).toString('base64url');
    // What the asker says it is — shown to the owner as its own claim, never as fact (#45 review L2).
    const by = cleanLabel((auth.decoded && (auth.decoded.agent_name || auth.decoded.label)) || String(req.headers['user-agent'] || '').slice(0, 60), 80);
    const id = Number(db.prepare('INSERT INTO leak_scan_token_requests (owner_did, labels, requested_by, claim_hash, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)')
      .run(auth.did, JSON.stringify(labels.map(l => cleanLabel(l, 80))), by, sha(claim), nowIso(), later(REQUEST_TTL_SEC)).lastInsertRowid);
    mailOwner(auth.did, 'DemiPass: a leak scanner asks for scan tokens', `Something acting for you asks for ${labels.length} leak-scan token(s): ${labels.join(', ')}.\nApprove or deny it in the DemiPass app (Settings → Leak scanner). It expires in ${REQUEST_TTL_SEC / 60} minutes.\n`);
    res.status(202).json({ ok: true, request_id: id, claim_secret: claim, expires_at: later(REQUEST_TTL_SEC),
      next: 'the owner approves it in the DemiPass app; then POST /api/demipass/leak-scan/token-requests/' + id + '/claim {claim_secret} once' });
  });
  // GET /api/blindkey/leak-scan/token-requests — the owner's waiting requests (for the app).
  app.get('/api/blindkey/leak-scan/token-requests', rateLimitStandard, (req, res) => {
    const auth = getBearerIdentity(req); if (!auth.ok) return res.status(auth.status || 401).json({ error: auth.error });
    expireRequests();
    const rows = db.prepare("SELECT id, labels, requested_by, status, created_at, expires_at FROM leak_scan_token_requests WHERE owner_did = ? AND status = 'pending' ORDER BY id DESC").all(auth.did);
    res.json({ ok: true, requests: rows.map(r => ({ ...r, says_it_is: r.requested_by, labels: JSON.parse(r.labels), intent: `scan-approve:${r.id}` })) });
  });
  // POST /api/blindkey/leak-scan/token-requests/:id/approve — the owner, PIN (scan-approve:<id>) + the linked phone.
  app.post('/api/blindkey/leak-scan/token-requests/:id/approve', rateLimitStandard, (req, res) => {
    const auth = personAuth(req, res); if (!auth) return;
    expireRequests();
    const r = db.prepare('SELECT * FROM leak_scan_token_requests WHERE id = ? AND owner_did = ?').get(Number(req.params.id), auth.did);
    if (!r) return res.status(404).json({ error: 'token request not found' });
    if (r.status !== 'pending') return res.status(409).json({ error: `this request is ${r.status}` });
    const intent = `scan-approve:${r.id}`;
    if (!gateFresh(auth.did, 'pin', auth, intent)) return res.status(403).json({ ...gateMissing('scan-approve', ['pin'], ['pin'], intent), error: 'approving scan tokens needs your PIN' });
    const dk = deps.devices && deps.devices();
    const refused = dk ? dk.approvalRefusal(auth, 'scan-approve', r.id, JSON.parse(r.labels).join(','), req.body) : null;
    if (refused) return res.status(refused.status).json(refused.body);
    try {
      db.transaction(() => {
        const spent = spendSingleUse(auth.did, 'scan-approve', ['pin'], auth, intent);
        if (spent) throw Object.assign(new Error(spent.error), { statusCode: spent.status || 403, body: spent });
        const minted = JSON.parse(r.labels).map(l => ({ label: l, ...mint(auth.did, l, r.id) }));
        // Approved tokens wait an hour to be claimed (e.g. by the operator's root call placing the deploy gate's token).
        const n = db.prepare("UPDATE leak_scan_token_requests SET status = 'approved', sealed = ?, decided_at = ?, expires_at = ? WHERE id = ? AND status = 'pending'")
          .run(blindkeyEncrypt(JSON.stringify(minted)), nowIso(), later(CLAIM_TTL_SEC), r.id).changes;
        if (n !== 1) throw Object.assign(new Error('this request changed meanwhile'), { statusCode: 409 });
      }).immediate();
    } catch (e) { return res.status(e.statusCode || 500).json(e.body || { error: e.message }); }
    logSecurityEvent('scan_token_minted', 'warn', { caller_did: auth.did, ip: req.ip, context: { request_id: r.id, count: JSON.parse(r.labels).length } });
    res.json({ ok: true, approved: JSON.parse(r.labels) });
  });
  app.post('/api/blindkey/leak-scan/token-requests/:id/deny', rateLimitStandard, (req, res) => {
    const auth = personAuth(req, res); if (!auth) return;
    const n = db.prepare("UPDATE leak_scan_token_requests SET status = 'denied', decided_at = ? WHERE id = ? AND owner_did = ? AND status = 'pending'").run(nowIso(), Number(req.params.id), auth.did).changes;
    res.status(n ? 200 : 404).json(n ? { ok: true } : { error: 'no waiting request by that id' });
  });
  // POST /api/blindkey/leak-scan/token-requests/:id/claim {claim_secret} — the requester takes the tokens, once.
  // No session needed: the claim secret (given only to the requester) is the proof. 202 while the owner has not decided.
  app.post('/api/blindkey/leak-scan/token-requests/:id/claim', rateLimitStandard, (req, res) => {
    expireRequests();
    const r = db.prepare('SELECT * FROM leak_scan_token_requests WHERE id = ?').get(Number(req.params.id));
    const presented = Buffer.from(sha(String((req.body || {}).claim_secret || '')), 'hex');
    const stored = r ? Buffer.from(r.claim_hash, 'hex') : Buffer.alloc(32);
    if (!r || !crypto.timingSafeEqual(presented, stored)) return res.status(404).json({ error: 'no such request' });
    if (r.status === 'pending') return res.status(202).json({ ok: false, status: 'pending', next: 'waiting for the owner to approve in the app' });
    if (r.status !== 'approved') return res.status(410).json({ error: `this request is ${r.status}`, status: r.status });
    const n = db.prepare("UPDATE leak_scan_token_requests SET status = 'claimed', sealed = NULL, claimed_at = ? WHERE id = ? AND status = 'approved'").run(nowIso(), r.id).changes;
    if (n !== 1) return res.status(410).json({ error: 'already claimed', status: 'claimed' });
    let tokens = [];
    try { tokens = JSON.parse(blindkeyDecrypt(r.sealed)); } catch (_) { return res.status(500).json({ error: 'could not open the approved tokens' }); }
    res.json({ ok: true, tokens: tokens.map(t => ({ id: t.id, label: t.label, token: t.token })), note: 'shown once: store each in a 0600 file or a CI secret' });
  });

  // POST /api/blindkey/leak-scan {chunks:[{id, text}]} → {hits:[{chunk, ref, name, count}], scanned_bytes}
  app.post('/api/blindkey/leak-scan', parser, rateLimitStandard, (req, res) => {
    const caller = scanCaller(req, res); if (!caller) return;
    const chunks = (req.body || {}).chunks;
    if (!Array.isArray(chunks) || !chunks.length || chunks.length > MAX_CHUNKS || chunks.some(c => !c || typeof c.text !== 'string' || (c.id !== undefined && typeof c.id !== 'string'))) {
      return res.status(400).json({ error: `chunks: 1–${MAX_CHUNKS} of {id: string, text: string}` });
    }
    const bytes = chunks.reduce((n, c) => n + Buffer.byteLength(c.text), 0);
    const day = nowIso().slice(0, 10);
    const used = caller.tokenRow.day === day ? caller.tokenRow.bytes_today : 0;
    const reqs = caller.tokenRow.day === day ? (caller.tokenRow.requests_today || 0) : 0;
    if (reqs + 1 > DAILY_REQUESTS) return res.status(429).json({ error: `this scan token's daily limit (${DAILY_REQUESTS} scans) is used up` });
    if (used + bytes > DAILY_BYTES) return res.status(429).json({ error: `this scan token's daily budget (${DAILY_BYTES} bytes) is used up` });
    db.prepare('UPDATE leak_scan_tokens SET day = ?, bytes_today = ?, requests_today = ?, last_used_at = ? WHERE id = ?').run(day, used + bytes, reqs + 1, nowIso(), caller.tokenRow.id);
    // The owner's values (every status but deleted: a rotated-away value that leaks still leaks), decrypted for this
    // request only, plus their JSON-escaped forms (transcripts and logs are JSON).
    const rows = db.prepare("SELECT id, name, ref_code, encrypted_value FROM blindkey_secrets WHERE did = ? AND status != 'deleted'").all(caller.did);
    const hits = [];
    let needles = [];
    try {
      for (const r of rows) {
        let v; try { v = blindkeyDecrypt(r.encrypted_value); } catch (_) { continue; }
        if (typeof v !== 'string' || v.length < MIN_LEN) continue;
        const forms = new Set([v, JSON.stringify(v).slice(1, -1)]);
        needles.push({ r, forms: [...forms] });
      }
      for (const c of chunks) {
        for (const { r, forms } of needles) {
          let count = 0;
          for (const f of forms) { let i = 0; while ((i = c.text.indexOf(f, i)) !== -1) { count++; i += f.length; } }
          if (count) hits.push({ chunk: cleanLabel(c.id || '', 300), ref: r.ref_code, name: r.name, count });
        }
      }
    } finally { needles = null; }
    let revoked = false;
    if (hits.length) {
      db.prepare('INSERT INTO leak_scan_hits (owner_did, token_id, token_label, found, created_at) VALUES (?, ?, ?, ?, ?)')
        .run(caller.did, caller.tokenRow.id, caller.tokenRow.label || '', JSON.stringify(hits.slice(0, 200)), nowIso());
      // Stop the line: this token is done (one positive answer, ever, per token).
      revoked = db.prepare("UPDATE leak_scan_tokens SET revoked_at = ?, revoked_reason = 'hit' WHERE id = ? AND revoked_at IS NULL").run(nowIso(), caller.tokenRow.id).changes === 1;
      const names = [...new Set(hits.map(h => h.name))];
      mailOwner(caller.did, `DemiPass: a vault value was found by the leak scanner (${caller.tokenRow.label || 'scan token ' + caller.tokenRow.id})`,
        `The leak scanner "${caller.tokenRow.label || caller.tokenRow.id}" found ${hits.length} place(s) holding a value of: ${names.join(', ')}.\nWhere: ${hits.slice(0, 20).map(h => h.chunk).join('; ')}\n\nRotate those secrets and remove the copies. The scan token was revoked; approve a new one when it is clean.\n`);
    }
    db.prepare('INSERT INTO blindkey_events (event_type, actor, secret_id, context_name, detail) VALUES (?, ?, ?, ?, ?)')
      .run('leak_scan', caller.did, null, null, JSON.stringify({ bytes, chunks: chunks.length, hits: hits.length, token_id: caller.tokenRow.id, revoked }));
    for (const h of hits) logSecurityEvent('leak_scan_hit', 'critical', { caller_did: caller.did, capability: 'leak-scan', target: h.name, context: { ref: h.ref, chunk: h.chunk, count: h.count, token_id: caller.tokenRow.id } });
    // One bit to the scanner: what and where go to the owner only (mail and the app).
    res.json({ ok: true, scanned_bytes: bytes, leak: hits.length > 0,
      ...(hits.length ? { token_revoked: revoked, note: 'a vault value was found: what and where were sent to the owner (DemiPass app → Settings → Leak scanner, and mail); this scan token is revoked' } : {}) });
  });

  return { MIN_LEN };
};
