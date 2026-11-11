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
// A token request waits a day for the owner's tap; the scanner that asked claims it on its next run (the daily timer, a
// pane start), so nobody has to be watching a terminal when the owner approves (Aaron 2026-11-11).
const REQUEST_TTL_SEC = 24 * 3600;
const CLAIM_TTL_SEC = 48 * 3600;     // approved tokens wait this long to be claimed (then they are dropped, unclaimed)
// After its first hit a token keeps scanning the rest of that run for DRAIN_SEC: every further hit is recorded for the
// owner ("where?"), and the scanner hears the same answer whatever it sends (no oracle: one positive bit per token,
// ever). One run then locates every copy instead of one per approved token (Aaron 2026-11-11).
const DRAIN_SEC = 30 * 60;
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
  // Copies found during a token's drain: shown only behind the PIN with the first hit ("where?"), never in the token
  // listing an agent session can read (#92 review H1: a per-request row there was a guessing oracle), at most 50 a token.
  db.exec(`CREATE TABLE IF NOT EXISTS leak_scan_drain_finds (id INTEGER PRIMARY KEY AUTOINCREMENT, token_id INTEGER NOT NULL, owner_did TEXT NOT NULL, found TEXT NOT NULL, created_at TEXT NOT NULL)`);
  db.exec('CREATE INDEX IF NOT EXISTS idx_lsdf_token ON leak_scan_drain_finds(token_id)');
  for (const c of ['revoked_reason TEXT DEFAULT NULL', 'request_id INTEGER DEFAULT NULL', 'requests_today INTEGER DEFAULT 0', 'drain_until TEXT DEFAULT NULL']) { try { db.exec('ALTER TABLE leak_scan_tokens ADD COLUMN ' + c); } catch (_) {} }
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
  // Where a leak report may be mailed (Aaron 2026-11-11: "a check box to forward the report via email to your forwarding
  // address"). Never the @dustforge.com mailbox: an agent signed in as the owner can read it, and file:lines must not reach
  // it (#45 re-review). First the owner's oldest catch-all forwarding address that has been active for 48 hours (a
  // younger rule may not be the owner's yet: forwardFresh in server.js), else the recovery email. None: no mail.
  function reportDestination(did) {
    let to = null, kind = null;
    try {
      const f = db.prepare("SELECT forward_to FROM forward_relays WHERE did = ? AND status = 'active' AND COALESCE(filter_from,'*') = '*' AND julianday(COALESCE(activated_at, created_at)) <= julianday('now', '-2 days') ORDER BY julianday(COALESCE(activated_at, created_at)) ASC LIMIT 1").get(did);
      if (f && f.forward_to) { to = f.forward_to; kind = 'forwarding'; }
    } catch (_) {}
    if (!to) {
      const w = db.prepare('SELECT recovery_email FROM identity_wallets WHERE did = ?').get(did) || {};
      const r = String(w.recovery_email || '').trim();
      if (r && !/@dustforge\.com$/i.test(r)) { to = r; kind = 'recovery'; }
    }
    return to ? { to, kind, masked: maskEmail(to) } : null;
  }
  const maskEmail = (e) => { const [u, d] = String(e).split('@'); return (u ? u[0] + '***' : '***') + '@' + (d || ''); };
  function hitsReport(did, days) {
    const rows = db.prepare("SELECT id, token_label, token_id, found, created_at FROM leak_scan_hits WHERE owner_did = ? AND created_at >= ? ORDER BY id DESC LIMIT 50")
      .all(did, new Date(Date.now() - days * 86400000).toISOString());
    const hits = rows.map(h => ({ id: h.id, created_at: h.created_at, token: h.token_label || ('token ' + h.token_id),
      found: JSON.parse(h.found).map(f => ({ name: f.name, ref: f.ref, where: f.chunk })) }));
    const lines = [`DemiPass leak scan: where values were found (last ${days} days, ${hits.length} hit${hits.length === 1 ? '' : 's'})`, ''];
    for (const h of hits) {
      lines.push(`#${h.id}  ${String(h.created_at).slice(0, 16).replace('T', ' ')} UTC  by scan token "${h.token}"`);
      for (const f of h.found) lines.push(`  - ${f.name} (${f.ref || 'no ref'}) in ${f.where || '(no location given)'}`);
      lines.push('');
    }
    lines.push('No values are in this report: names, refs and where they were found only.');
    lines.push('Next: remove each copy at that place, rotate those secrets, then approve a new scan token.');
    return { hits, text: lines.join('\n') };
  }
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
    const draining = row.revoked_reason === 'hit' && row.drain_until && row.drain_until > nowIso();
    if (row.revoked_at && !draining) { res.status(401).json({ error: row.revoked_reason === 'hit' ? 'this scan token found a leak and was revoked — fix the leak, then have a new token approved' : 'this scan token is revoked', revoked: row.revoked_reason || 'revoked' }); return null; }
    return { did: row.owner_did, tokenRow: row, draining };
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
    // Which secrets a token found, by name — never where or how often: an agent signed in as the owner reads this too,
    // and chunk labels or counts would rebuild the oracle the one-bit answer closed (#45 re-review). Where: with the PIN.
    res.json({ ok: true, tokens: db.prepare('SELECT id, label, created_at, revoked_at, revoked_reason, last_used_at, bytes_today, requests_today, day FROM leak_scan_tokens WHERE owner_did = ? ORDER BY id DESC').all(auth.did),
      ...(person ? { hits: db.prepare('SELECT id, token_id, token_label, found, created_at FROM leak_scan_hits WHERE owner_did = ? ORDER BY id DESC LIMIT 20').all(auth.did)
        .map(h => ({ id: h.id, token_id: h.token_id, token_label: h.token_label, created_at: h.created_at, secrets: [...new Set(JSON.parse(h.found).map(f => f.name))] })),
        report_to: (() => { const d = reportDestination(auth.did); return d ? { masked: d.masked, kind: d.kind } : null; })() } : {}) });
  });
  // POST /api/blindkey/leak-scan/hits-report {days?, mail?} — where EVERY hit of the last `days` (default 30, ≤ 90) was
  // found, behind one approval: the PIN or the linked phone's biometric (intent scan-hits:0, "all"). With mail: true the
  // same plain-text report goes to the owner's forwarding (or recovery) address — never the @dustforge.com mailbox.
  // Aaron 2026-11-11: no more one unlock per hit, screenshots, and a relay through Matrix to a pane.
  app.post('/api/blindkey/leak-scan/hits-report', rateLimitStandard, async (req, res) => {
    const auth = personAuth(req, res); if (!auth) return;
    const b = req.body || {};
    const days = b.days === undefined ? 30 : Number(b.days);
    if (!Number.isInteger(days) || days < 1 || days > 90) return res.status(400).json({ error: 'days: 1-90' });
    const intent = 'scan-hits:0';
    if (!gateFresh(auth.did, 'pin', auth, intent)) return res.status(403).json({ ...gateMissing('scan-hits', ['pin'], ['pin'], intent), error: 'where the leaks were found: your PIN or phone shows it' });
    const spent = spendSingleUse(auth.did, 'scan-hits', ['pin'], auth, intent);
    if (spent) return res.status(spent.status || 403).json(spent);
    const report = hitsReport(auth.did, days);
    let mailed = null;
    if (b.mail === true) {
      const d = reportDestination(auth.did);
      if (!d) mailed = { sent: false, error: 'no forwarding address (active 48 hours) or recovery email on file' };
      else if (!report.hits.length) mailed = { sent: false, to: d.masked, error: 'nothing to report' };
      else {
        let ok = false;
        try { ok = deps.sendMail ? Boolean(await deps.sendMail({ to: d.to, subject: `DemiPass: where the leak scanner found values (${report.hits.length} hit${report.hits.length === 1 ? '' : 's'})`, text: report.text })) : false; } catch (_) { ok = false; }
        mailed = { sent: ok, to: d.masked, kind: d.kind, ...(ok ? {} : { error: 'the mail could not be sent: try again' }) };
      }
    }
    db.prepare('INSERT INTO blindkey_events (event_type, actor, secret_id, context_name, detail) VALUES (?, ?, ?, ?, ?)')
      .run('leak_report', auth.did, null, null, JSON.stringify({ days, hits: report.hits.length, mailed: mailed ? { sent: mailed.sent, kind: mailed.kind || null } : null }));
    res.json({ ok: true, days, hits: report.hits, text: report.text, mailed });
  });
  // POST /api/blindkey/leak-scan/hits/:id — where a hit was found (file:lines), for the owner with the PIN
  // (intent scan-hits:<id>).
  app.post('/api/blindkey/leak-scan/hits/:id', rateLimitStandard, (req, res) => {
    const auth = personAuth(req, res); if (!auth) return;
    const id = Number(req.params.id);
    const h = Number.isInteger(id) && id > 0 ? db.prepare('SELECT * FROM leak_scan_hits WHERE id = ? AND owner_did = ?').get(id, auth.did) : null;
    if (!h) return res.status(404).json({ error: 'no such hit' });
    const intent = `scan-hits:${id}`;
    if (!gateFresh(auth.did, 'pin', auth, intent)) return res.status(403).json(gateMissing('scan-hits', ['pin'], ['pin'], intent));
    const spent = spendSingleUse(auth.did, 'scan-hits', ['pin'], auth, intent);
    if (spent) return res.status(spent.status || 403).json(spent);
    // Copies the same token found during its drain come with the first hit; their places were named by the scanner.
    const rows = h.token_id ? db.prepare('SELECT found, created_at FROM leak_scan_drain_finds WHERE token_id = ? AND owner_did = ? ORDER BY id').all(h.token_id, auth.did) : [];
    const truncated = rows.some(d => d.found === '"truncated"'), drained = rows.filter(d => d.found !== '"truncated"');
    res.json({ ok: true, id, token_label: h.token_label, created_at: h.created_at, found: JSON.parse(h.found).map(f => ({ name: f.name, ref: f.ref, where: f.chunk })),
      ...(drained.length ? { found_later_in_the_run: drained.flatMap(d => JSON.parse(d.found).map(f => ({ name: f.name, ref: f.ref, where: f.chunk, at: d.created_at }))),
        note: 'places after the first are as the scanner named them' } : {}),
      ...(truncated ? { found_later_truncated: true, truncated_note: 'more copies were found than are kept (50): rescan after cleaning these' } : {}) });
  });
  // POST /api/blindkey/leak-scan/descriptions {redact_ids?} — which of my descriptions and notes hold one of my vault
  // values (by name, never the value), and with redact_ids (rows picked from a check), cut the values out of those. The owner's own session with the PIN
  // (intent scan-descriptions:<0|1>): an oracle over the owner's values, like the scan itself (secret_text_guard.js).
  app.post('/api/blindkey/leak-scan/descriptions', rateLimitStandard, (req, res) => {
    const auth = personAuth(req, res); if (!auth) return;
    // Redact only the rows the owner picked from a check (#71 review M1): never "everything found".
    const ids = (req.body || {}).redact_ids;
    const redact = Array.isArray(ids) && ids.length > 0;
    if (ids !== undefined && (!Array.isArray(ids) || ids.length > 500 || !ids.every(x => Number.isInteger(x) && x > 0))) return res.status(400).json({ error: 'redact_ids: up to 500 secret ids from a check' });
    const intent = `scan-descriptions:${redact ? 1 : 0}`;
    if (!gateFresh(auth.did, 'pin', auth, intent)) return res.status(403).json(gateMissing('scan-descriptions', ['pin'], ['pin'], intent));
    const spent = spendSingleUse(auth.did, 'scan-descriptions', ['pin'], auth, intent);
    if (spent) return res.status(spent.status || 403).json(spent);
    const { found, unchecked } = require('./secret_text_guard').sweepDescriptions(db, blindkeyDecrypt, auth.did, { redactIds: redact ? ids : null });
    const done = redact ? found.filter(f => ids.includes(f.id)) : [];
    db.prepare('INSERT INTO blindkey_events (event_type, actor, secret_id, context_name, detail) VALUES (?, ?, ?, ?, ?)')
      .run(redact ? 'description_redact' : 'description_check', auth.did, null, null, JSON.stringify({ found: found.length, redacted: done.map(f => f.name), unchecked }));
    res.json({ ok: true, unchecked, redacted: done.map(f => f.name),
      found: found.map(f => ({ id: f.id, name: f.name, ref: f.ref_code, fields: f.fields, holds_value_of: f.holds, updated_at: f.updated_at, own: f.own, flagged: f.flagged })) });
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
    // A draining token (revoked by its hit, still recording) is stopped too (#92 review M1).
    const n = db.prepare("UPDATE leak_scan_tokens SET revoked_at = COALESCE(revoked_at, ?), revoked_reason = 'owner', drain_until = NULL WHERE id = ? AND owner_did = ? AND (revoked_at IS NULL OR (revoked_reason = 'hit' AND drain_until > ?))").run(nowIso(), Number(req.params.id), auth.did, nowIso()).changes;
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
    mailOwner(auth.did, 'DemiPass: a leak scanner asks for scan tokens', `Something acting for you asks for ${labels.length} leak-scan token(s): ${labels.join(', ')}.\nApprove or deny it in the DemiPass app (Settings → Leak scanner). It waits for you for ${REQUEST_TTL_SEC / 3600} hours; the scanner picks the tokens up on its next run.\n`);
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
    if (caller.draining) {
      // The rest of a run after its first hit: found copies go to the owner; the answer never varies with what was sent.
      // Written after the answer has gone (setImmediate): a hit costs the request no more time than a miss (#92 L).
      const found = hits.length ? JSON.stringify(hits.slice(0, 200).map(h => ({ name: h.name, ref: h.ref, chunk: h.chunk }))) : null, tokId = caller.tokenRow.id, owner = caller.did;
      if (found) setImmediate(() => { try {
        const kept = db.prepare('SELECT COUNT(*) AS n FROM leak_scan_drain_finds WHERE token_id = ?').get(tokId).n;
        if (kept < 51) db.prepare('INSERT INTO leak_scan_drain_finds (token_id, owner_did, found, created_at) VALUES (?, ?, ?, ?)').run(tokId, owner, kept < 50 ? found : '"truncated"', nowIso());
      } catch (_) {} });
      db.prepare('INSERT INTO blindkey_events (event_type, actor, secret_id, context_name, detail) VALUES (?, ?, ?, ?, ?)')
        .run('leak_scan', caller.did, null, null, JSON.stringify({ bytes, chunks: chunks.length, hits: hits.length, token_id: caller.tokenRow.id, draining: true }));
      return res.json({ ok: true, scanned_bytes: bytes, leak: true, token_revoked: true, draining: true, already_found: true,
        note: 'this token already found a leak: the rest of the run is recorded for the owner (DemiPass app → Settings → Leak scanner → "where?")' });
    }
    if (hits.length) {
      db.prepare('INSERT INTO leak_scan_hits (owner_did, token_id, token_label, found, created_at) VALUES (?, ?, ?, ?, ?)')
        .run(caller.did, caller.tokenRow.id, caller.tokenRow.label || '', JSON.stringify(hits.slice(0, 200).map(h => ({ name: h.name, ref: h.ref, chunk: h.chunk }))), nowIso());
      // Stop the line: this token is done (one positive answer, ever, per token).
      revoked = db.prepare("UPDATE leak_scan_tokens SET revoked_at = ?, revoked_reason = 'hit', drain_until = ? WHERE id = ? AND revoked_at IS NULL").run(nowIso(), later(DRAIN_SEC), caller.tokenRow.id).changes === 1;
      const names = [...new Set(hits.map(h => h.name))];
      // Names only — where it was found is in the app behind the PIN: an owner mailbox a pane can read must not become
      // the chunk channel (#45 re-review, low).
      mailOwner(caller.did, `DemiPass: a vault value was found by the leak scanner (${caller.tokenRow.label || 'scan token ' + caller.tokenRow.id})`,
        `The leak scanner "${caller.tokenRow.label || caller.tokenRow.id}" found a value of: ${names.join(', ')}.\n\nWhere it was found: DemiPass app → Settings → Leak scanner → "where?" (your PIN). Rotate those secrets and remove the copies. The scan token was revoked; it records the rest of this run's copies for you, then stops. Approve a new one when it is clean.\n`);
    }
    db.prepare('INSERT INTO blindkey_events (event_type, actor, secret_id, context_name, detail) VALUES (?, ?, ?, ?, ?)')
      .run('leak_scan', caller.did, null, null, JSON.stringify({ bytes, chunks: chunks.length, hits: hits.length, token_id: caller.tokenRow.id, revoked }));
    // One critical event per secret found, naming the token — no chunk labels, no counts (readable by an owner session).
    for (const name of [...new Set(hits.map(h => h.name))]) logSecurityEvent('leak_scan_hit', 'critical', { caller_did: caller.did, capability: 'leak-scan', target: name, context: { ref: (hits.find(h => h.name === name) || {}).ref, token_id: caller.tokenRow.id } });
    // One bit to the scanner: what and where go to the owner only (mail and the app).
    res.json({ ok: true, scanned_bytes: bytes, leak: hits.length > 0,
      ...(hits.length ? { token_revoked: revoked, draining: revoked, note: 'a vault value was found: what and where were sent to the owner (DemiPass app → Settings → Leak scanner, and mail); this scan token is revoked, and records the rest of this run for the owner' } : {}) });
  });

  return { MIN_LEN };
};
