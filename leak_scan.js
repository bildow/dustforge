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
// Scrub ("contain" a leaked value without rotating it, Aaron 2026-11-11: "keep the leak value for now but search all logs
// for it and scrub it from all memory and logs — an in-between state between rotate and keep"). A scrub token is asked
// for one entry (scrub_ref) and approved by the owner like a scan token. It answers, per chunk, WHERE that one entry's
// value sits (byte offsets), so the scrubber can overwrite those bytes in place. That is the value's location in text the
// scrubber already holds — in effect the value — which is why it covers one entry, is the owner's explicit approval,
// expires, and is good for nothing else (never a scan, never another entry).
const SCRUB_TTL_SEC = 72 * 3600;
const DAILY_SCRUB_BYTES = 16 * 1024 * 1024 * 1024;
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
  for (const c of ['revoked_reason TEXT DEFAULT NULL', 'request_id INTEGER DEFAULT NULL', 'requests_today INTEGER DEFAULT 0', 'drain_until TEXT DEFAULT NULL', 'scrub_secret_id INTEGER DEFAULT NULL', 'expires_at TEXT DEFAULT NULL']) { try { db.exec('ALTER TABLE leak_scan_tokens ADD COLUMN ' + c); } catch (_) {} }
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
  try { db.exec('ALTER TABLE leak_scan_token_requests ADD COLUMN scrub_secret_id INTEGER DEFAULT NULL'); } catch (_) {}
  // The rate limit every other call from the same address shares (500 per 15 min) would starve while a scrub reads
  // gigabytes of logs: scrubbing has its own.
  const scrubLimit = require('express-rate-limit')({ windowMs: 15 * 60 * 1000, max: 3000, message: { error: 'Rate limit exceeded' } });
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
  // Item 6b (forward rules need the PIN) was merged 2026-11-07 21:03Z: a rule activated before that could have been made by anything
  // holding the session token, so only later ones count (#95 review M2).
  const PIN_GATED_FORWARD_SINCE = '2026-11-08T00:00:00Z';   // item 6b (#70) merged 2026-11-07T21:03Z: the next whole day, so no rule made before its deploy counts (#95 re-review)
  const internalMailbox = (e) => /@dustforge\.com$/.test(String(e || '').trim().toLowerCase().replace(/\.+$/, ''));
  function reportDestination(did) {
    try {
      const rules = db.prepare(`SELECT id, forward_to FROM forward_relays WHERE did = ? AND status = 'active' AND COALESCE(filter_from,'*') = '*'
          AND activated_at IS NOT NULL AND julianday(activated_at) >= julianday(?) AND julianday(activated_at) <= julianday('now', '-2 days')
          ORDER BY julianday(activated_at) ASC`).all(did, PIN_GATED_FORWARD_SINCE);
      const f = rules.find(r => r.forward_to && !internalMailbox(r.forward_to));
      if (f) return { to: f.forward_to, kind: 'forwarding', rule_id: f.id, masked: maskEmail(f.forward_to) };
    } catch (_) {}
    const w = db.prepare('SELECT recovery_email FROM identity_wallets WHERE did = ?').get(did) || {};
    const r = String(w.recovery_email || '').trim();
    if (!r || internalMailbox(r)) return null;
    // A recovery address set in the last 48 hours may not be the owner's (#95 review): not a destination yet.
    try { if (db.prepare("SELECT 1 FROM recovery_email_history WHERE did = ? AND julianday(replaced_at) > julianday('now', '-2 days') LIMIT 1").get(did)) return null; } catch (_) {}
    return { to: r, kind: 'recovery', rule_id: null, masked: maskEmail(r) };
  }
  const maskEmail = (e) => { const [u, d] = String(e).split('@'); return (u ? u[0] + '***' : '***') + '@' + (d || ''); };
  // A location as the scanner named it, reduced to path-like characters for the report and the mail: a scan token chooses
  // these labels, and the mail goes to an outside inbox under DemiPass's name (#95 review: no planted links).
  const place = (w) => String(w || '').replace(/[^\w./:@#+,=~-]/g, '_').replace(/:\/\//g, ':_/').slice(0, 200) || '(no location given)';
  const MAX_HITS = 50;
  function hitsReport(did, days) {
    const rows = db.prepare("SELECT id, token_label, token_id, found, created_at FROM leak_scan_hits WHERE owner_did = ? AND created_at >= ? ORDER BY id DESC LIMIT ?")
      .all(did, new Date(Date.now() - days * 86400000).toISOString(), MAX_HITS + 1);
    const truncated = rows.length > MAX_HITS;
    let laterTruncated = false;
    const hits = rows.slice(0, MAX_HITS).map(h => {
      const found = JSON.parse(h.found).map(f => ({ name: f.name, ref: f.ref, where: place(f.chunk) }));
      // The rest of that run (#95 review M1): the copies found after the first, as the per-hit route shows them.
      const later = [];
      if (h.token_id) for (const d of db.prepare('SELECT found FROM leak_scan_drain_finds WHERE token_id = ? AND owner_did = ? ORDER BY id').all(h.token_id, did)) {
        let v; try { v = JSON.parse(d.found); } catch (_) { continue; }
        if (v === 'truncated') { laterTruncated = true; continue; }
        if (Array.isArray(v)) for (const f of v) later.push({ name: f.name, ref: f.ref, where: place(f.chunk) });
      }
      return { id: h.id, created_at: h.created_at, token: h.token_label || ('token ' + h.token_id), found, found_later_in_the_run: later };
    });
    const copies = hits.reduce((n, h) => n + h.found.length + h.found_later_in_the_run.length, 0);
    const lines = [`DemiPass leak scan: where values were found (last ${days} days, ${hits.length} hit${hits.length === 1 ? '' : 's'}, ${copies} cop${copies === 1 ? 'y' : 'ies'})`, ''];
    for (const h of hits) {
      lines.push(`#${h.id}  ${String(h.created_at).slice(0, 16).replace('T', ' ')} UTC  by scan token "${place(h.token)}"`);
      for (const f of h.found) lines.push(`  - ${f.name} (${f.ref || 'no ref'}) in ${f.where}`);
      for (const f of h.found_later_in_the_run) lines.push(`  - ${f.name} (${f.ref || 'no ref'}) in ${f.where}   (later in the same run)`);
      lines.push('');
    }
    if (truncated) lines.push(`More than ${MAX_HITS} hits in this window: only the latest ${MAX_HITS} are listed. Clean these, then look again.`);
    if (laterTruncated) lines.push('More copies were found in a run than are kept (50): rescan after cleaning these.');
    lines.push('No values are in this report: names, refs and where they were found only.');
    lines.push('Next: remove each copy at that place, rotate those secrets, then approve a new scan token.');
    return { hits, truncated, later_truncated: laterTruncated, text: lines.join('\n') };
  }
  const newToken = () => 'dpscan_' + crypto.randomBytes(24).toString('base64url');
  function mint(ownerDid, label, requestId, { scrubSecretId = null } = {}) {
    const token = newToken();
    const id = Number(db.prepare('INSERT INTO leak_scan_tokens (owner_did, token_hash, label, created_at, request_id, scrub_secret_id, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)')
      .run(ownerDid, sha(token), cleanLabel(label || '', 80), nowIso(), requestId || null, scrubSecretId || null, scrubSecretId ? later(SCRUB_TTL_SEC) : null).lastInsertRowid);
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
  // Who is scanning: only a scan token (Authorization: Scan <token>). A scrub token scrubs and does nothing else; a scan
  // token never scrubs.
  function scanCaller(req, res, { scrub = false } = {}) {
    const h = String(req.headers.authorization || '');
    if (!h.startsWith('Scan ')) { res.status(403).json({ error: 'scanning takes a scan token (Authorization: Scan <token>) — a session token is never a scan oracle; request one with POST /api/demipass/leak-scan/token-requests' }); return null; }
    const row = db.prepare('SELECT * FROM leak_scan_tokens WHERE token_hash = ?').get(sha(h.slice(5).trim()));
    if (!row) { res.status(401).json({ error: 'invalid scan token' }); return null; }
    const draining = row.revoked_reason === 'hit' && row.drain_until && row.drain_until > nowIso();
    if (Boolean(row.scrub_secret_id) !== scrub) { res.status(403).json({ error: scrub ? 'this is a scan token: scrubbing takes a scrub token for one entry (token-requests {scrub_ref})' : 'this is a scrub token: it only scrubs its one entry (POST /leak-scan/scrub)' }); return null; }
    if (scrub && (row.revoked_at || !row.expires_at || row.expires_at <= nowIso())) { res.status(401).json({ error: row.revoked_at ? 'this scrub token is used up or revoked' : 'this scrub token has expired' }); return null; }
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
        report_to: (() => { const d = reportDestination(auth.did); return d ? { masked: d.masked, address: d.to, kind: d.kind } : null; })() } : {}) });
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
        mailed = { sent: ok, to: d.masked, kind: d.kind, rule_id: d.rule_id, ...(ok ? {} : { error: 'the mail could not be sent: try again' }) };
      }
    }
    db.prepare('INSERT INTO blindkey_events (event_type, actor, secret_id, context_name, detail) VALUES (?, ?, ?, ?, ?)')
      .run('leak_report', auth.did, null, null, JSON.stringify({ days, hits: report.hits.length, truncated: report.truncated,
        mailed: mailed ? { sent: mailed.sent, to: mailed.to || null, kind: mailed.kind || null, rule_id: mailed.rule_id || null } : null }));
    if (mailed) delete mailed.rule_id;
    res.json({ ok: true, days, hits: report.hits, truncated: report.truncated, later_truncated: report.later_truncated, text: report.text, mailed });
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
    // A scrub token for one entry: the label is made here, so the owner's card names the entry (not the asker's words).
    let scrub = null;
    const scrubRef = (req.body || {}).scrub_ref;
    if (scrubRef !== undefined) {
      if (typeof scrubRef !== 'string' || !/^[A-Za-z0-9-]{4,80}$/.test(scrubRef) || labels !== undefined) return res.status(400).json({ error: 'scrub_ref: the ref of one of your entries (and no labels)' });
      scrub = db.prepare("SELECT id, name, ref_code, encrypted_value FROM blindkey_secrets WHERE did = ? AND ref_code = ? AND status != 'deleted' ORDER BY id DESC LIMIT 1").get(auth.did, scrubRef);
      if (!scrub) return res.status(404).json({ error: 'no entry of yours with that ref' });
      let v = null; try { v = blindkeyDecrypt(scrub.encrypted_value); } catch (_) { v = null; }
      if (typeof v !== 'string') return res.status(409).json({ error: 'this value is not readable here (wrapped to your phone): it cannot be looked for' });
      if (v.length < MIN_LEN) return res.status(409).json({ error: `values shorter than ${MIN_LEN} characters are not looked for (too many false matches)` });
      v = null;
      labels = ['scrub-' + scrub.ref_code];
    }
    if (!Array.isArray(labels) || !labels.length || labels.length > MAX_LABELS || labels.some(l => typeof l !== 'string' || !l.trim() || l.length > 80)) {
      return res.status(400).json({ error: `labels: 1–${MAX_LABELS} names, what each token is for (e.g. "ci-dustforge")` });
    }
    if (db.prepare("SELECT COUNT(*) AS n FROM leak_scan_token_requests WHERE owner_did = ? AND status = 'pending'").get(auth.did).n >= MAX_PENDING_REQUESTS) {
      return res.status(429).json({ error: 'too many token requests waiting for the owner' });
    }
    const claim = crypto.randomBytes(24).toString('base64url');
    // What the asker says it is — shown to the owner as its own claim, never as fact (#45 review L2).
    const by = cleanLabel((auth.decoded && (auth.decoded.agent_name || auth.decoded.label)) || String(req.headers['user-agent'] || '').slice(0, 60), 80);
    const id = Number(db.prepare('INSERT INTO leak_scan_token_requests (owner_did, labels, requested_by, claim_hash, created_at, expires_at, scrub_secret_id) VALUES (?, ?, ?, ?, ?, ?, ?)')
      .run(auth.did, JSON.stringify(labels.map(l => cleanLabel(l, 80))), by, sha(claim), nowIso(), later(REQUEST_TTL_SEC), scrub ? scrub.id : null).lastInsertRowid);
    if (scrub) mailOwner(auth.did, `DemiPass: a scrubber asks to remove ${scrub.name} from your files`, `Something acting for you asks for a scrub token for ${scrub.name} (${scrub.ref_code}): it would look for that value in the files it reads and overwrite each copy in place. The scrubber learns where the value sits in those files — in effect, the value — so approve it only if you started it.\nThe value is not rotated: once the scrub finishes, the entry shows as contained. Copies in backups and anywhere the scrubber cannot reach stay.\nApprove or deny it in the DemiPass app (Settings → Leak scanner). It waits for you for ${REQUEST_TTL_SEC / 3600} hours; the token works for ${SCRUB_TTL_SEC / 3600} hours after you approve.\n`);
    else mailOwner(auth.did, 'DemiPass: a leak scanner asks for scan tokens', `Something acting for you asks for ${labels.length} leak-scan token(s): ${labels.join(', ')}.\nApprove or deny it in the DemiPass app (Settings → Leak scanner). It waits for you for ${REQUEST_TTL_SEC / 3600} hours; the scanner picks the tokens up on its next run.\n`);
    res.status(202).json({ ok: true, request_id: id, claim_secret: claim, expires_at: later(REQUEST_TTL_SEC),
      next: 'the owner approves it in the DemiPass app; then POST /api/demipass/leak-scan/token-requests/' + id + '/claim {claim_secret} once' });
  });
  // GET /api/blindkey/leak-scan/token-requests — the owner's waiting requests (for the app).
  app.get('/api/blindkey/leak-scan/token-requests', rateLimitStandard, (req, res) => {
    const auth = getBearerIdentity(req); if (!auth.ok) return res.status(auth.status || 401).json({ error: auth.error });
    expireRequests();
    const rows = db.prepare("SELECT id, labels, requested_by, status, created_at, expires_at, scrub_secret_id FROM leak_scan_token_requests WHERE owner_did = ? AND status = 'pending' ORDER BY id DESC").all(auth.did);
    const entry = (sid) => { const e = sid ? db.prepare('SELECT name, ref_code FROM blindkey_secrets WHERE id = ? AND did = ?').get(sid, auth.did) : null; return e ? { name: e.name, ref: e.ref_code } : null; };
    res.json({ ok: true, requests: rows.map(({ scrub_secret_id, ...r }) => ({ ...r, says_it_is: r.requested_by, labels: JSON.parse(r.labels), intent: `scan-approve:${r.id}`,
      ...(scrub_secret_id ? { scrub: entry(scrub_secret_id), note: 'a scrub token: it finds this one value in the files it reads and overwrites each copy; the scrubber learns where the value is' } : {}) })) });
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
        const minted = JSON.parse(r.labels).map(l => ({ label: l, ...mint(auth.did, l, r.id, { scrubSecretId: r.scrub_secret_id }) }));
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
        uncontain(owner, hits);
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
      uncontain(caller.did, hits);
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

  // A value found again is no longer contained (whatever a scrub reported before).
  function uncontain(did, hits) {
    const refs = [...new Set(hits.map(h => h.ref).filter(Boolean))];
    for (const ref of refs) { try { db.prepare("UPDATE blindkey_secrets SET leak_contained_at = NULL, leak_contained_note = NULL WHERE did = ? AND ref_code = ? AND leak_contained_at IS NOT NULL").run(did, ref); } catch (_) {} }
  }
  // Every form a value takes in text: as it is, JSON-escaped once and twice (a tool call's JSON inside a transcript's
  // JSON), and with non-ASCII as \uXXXX (Python's json.dumps) — each once or twice escaped.
  function valueForms(v) {
    const esc = (t) => JSON.stringify(t).slice(1, -1);
    const ascii = (t) => esc(t).replace(/[\u0080-￿]/g, ch => '\\u' + ch.charCodeAt(0).toString(16).padStart(4, '0'));
    return [...new Set([v, esc(v), esc(esc(v)), ascii(v), esc(ascii(v))])].filter(f => f.length >= MIN_LEN);
  }
  // The entry a scrub token was approved for: its value now and every earlier version kept under the same ref.
  function scrubValues(caller) {
    const e = db.prepare("SELECT ref_code FROM blindkey_secrets WHERE id = ? AND did = ?").get(caller.tokenRow.scrub_secret_id, caller.did);
    if (!e) return null;
    const rows = db.prepare("SELECT id, encrypted_value FROM blindkey_secrets WHERE did = ? AND ref_code = ? AND status != 'deleted'").all(caller.did, e.ref_code);
    const out = [];
    for (const r of rows) { let v; try { v = blindkeyDecrypt(r.encrypted_value); } catch (_) { continue; } if (typeof v === 'string' && v.length >= MIN_LEN) out.push(v); }
    return { ref: e.ref_code, values: out };
  }

  // POST /api/blindkey/leak-scan/scrub {chunks:[{id, text}]} (a scrub token) → {matches:[{chunk, at:[[byte_offset, byte_length]]}]}
  // Where the token's one entry sits in each chunk, in UTF-8 bytes of the text as sent. Never the value; never another entry.
  app.post('/api/blindkey/leak-scan/scrub', parser, scrubLimit, (req, res) => {
    const caller = scanCaller(req, res, { scrub: true }); if (!caller) return;
    const chunks = (req.body || {}).chunks;
    if (!Array.isArray(chunks) || !chunks.length || chunks.length > MAX_CHUNKS || chunks.some(c => !c || typeof c.text !== 'string' || typeof c.id !== 'string' || c.id.length > 300)) {
      return res.status(400).json({ error: `chunks: 1–${MAX_CHUNKS} of {id: string, text: string}` });
    }
    const bytes = chunks.reduce((n, c) => n + Buffer.byteLength(c.text), 0);
    const day = nowIso().slice(0, 10);
    const used = caller.tokenRow.day === day ? caller.tokenRow.bytes_today : 0;
    const reqs = caller.tokenRow.day === day ? (caller.tokenRow.requests_today || 0) : 0;
    if (used + bytes > DAILY_SCRUB_BYTES) return res.status(429).json({ error: `this scrub token's daily budget (${DAILY_SCRUB_BYTES} bytes) is used up` });
    db.prepare('UPDATE leak_scan_tokens SET day = ?, bytes_today = ?, requests_today = ?, last_used_at = ? WHERE id = ?').run(day, used + bytes, reqs + 1, nowIso(), caller.tokenRow.id);
    let sv = scrubValues(caller);
    if (!sv) return res.status(410).json({ error: 'the entry this token was approved for is gone' });
    let forms = [];
    try { for (const v of sv.values) forms.push(...valueForms(v)); } finally { sv.values = null; }
    forms = [...new Set(forms)];
    const matches = [];
    let total = 0;
    try {
      for (const c of chunks) {
        const spans = [];
        for (const f of forms) { let i = 0; while ((i = c.text.indexOf(f, i)) !== -1) { spans.push([i, i + f.length]); i += 1; } }
        if (!spans.length) continue;
        spans.sort((a, b) => a[0] - b[0] || b[1] - a[1]);
        const merged = [];
        for (const sp of spans) { const last = merged[merged.length - 1]; if (last && sp[0] <= last[1]) last[1] = Math.max(last[1], sp[1]); else merged.push(sp.slice()); }
        // UTF-16 indices → UTF-8 byte offsets, walking forward once.
        const at = []; let ci = 0, cb = 0;
        for (const [a, b] of merged) { cb += Buffer.byteLength(c.text.slice(ci, a)); const len = Buffer.byteLength(c.text.slice(a, b)); at.push([cb, len]); cb += len; ci = b; }
        matches.push({ chunk: c.id, at }); total += at.length;
      }
    } finally { forms = null; }
    db.prepare('INSERT INTO blindkey_events (event_type, actor, secret_id, context_name, detail) VALUES (?, ?, ?, ?, ?)')
      .run('leak_scrub', caller.did, caller.tokenRow.scrub_secret_id, null, JSON.stringify({ bytes, chunks: chunks.length, matches: total, token_id: caller.tokenRow.id }));
    res.json({ ok: true, scanned_bytes: bytes, matches });
  });
  // POST /api/blindkey/leak-scan/scrub/finish {files_read, files_changed, copies_masked, copies_left} (a scrub token) — the
  // scrubber's report. The entry is marked contained (with the report, as the scrubber's own claim) unless it says it left
  // copies; the token is spent either way. A later scan that finds the value clears the mark.
  app.post('/api/blindkey/leak-scan/scrub/finish', rateLimitStandard, (req, res) => {
    const caller = scanCaller(req, res, { scrub: true }); if (!caller) return;
    const b = req.body || {};
    const num = (x) => (Number.isInteger(x) && x >= 0 && x < 1e12 ? x : null);
    const report = { files_read: num(b.files_read), files_changed: num(b.files_changed), copies_masked: num(b.copies_masked), copies_left: num(b.copies_left) };
    if (Object.values(report).some(v => v === null)) return res.status(400).json({ error: 'files_read, files_changed, copies_masked, copies_left: whole numbers' });
    const e = db.prepare("SELECT name, ref_code FROM blindkey_secrets WHERE id = ? AND did = ?").get(caller.tokenRow.scrub_secret_id, caller.did);
    const spent = db.prepare("UPDATE leak_scan_tokens SET revoked_at = ?, revoked_reason = 'scrubbed' WHERE id = ? AND revoked_at IS NULL").run(nowIso(), caller.tokenRow.id).changes === 1;
    if (!spent) return res.status(409).json({ error: 'this scrub token already finished' });
    const contained = Boolean(e) && report.copies_left === 0;
    const note = JSON.stringify({ ...report, token: caller.tokenRow.label || caller.tokenRow.id, at: nowIso() });
    if (contained) db.prepare("UPDATE blindkey_secrets SET leak_contained_at = ?, leak_contained_note = ? WHERE did = ? AND ref_code = ? AND status != 'deleted'").run(nowIso(), note, caller.did, e.ref_code);
    db.prepare('INSERT INTO blindkey_events (event_type, actor, secret_id, context_name, detail) VALUES (?, ?, ?, ?, ?)')
      .run('leak_contained', caller.did, caller.tokenRow.scrub_secret_id, null, JSON.stringify({ ...report, contained, token_id: caller.tokenRow.id }));
    logSecurityEvent('leak_scrubbed', 'warn', { caller_did: caller.did, capability: 'leak-scan', target: e ? e.name : String(caller.tokenRow.scrub_secret_id), context: { ...report, contained } });
    if (e) mailOwner(caller.did, `DemiPass: ${e.name} ${contained ? 'is contained' : 'was scrubbed, with copies left'}`,
      `The scrubber for ${e.name} (${e.ref_code}) reports: ${report.copies_masked} copies overwritten in ${report.files_changed} of ${report.files_read} files read; ${report.copies_left} left.\n` +
      (contained ? 'The entry now shows as contained: not rotated, but no copy is left where the scrubber looked. ' : 'Copies were left (files that changed while it worked, or files it would not write): the entry is not marked contained. ') +
      'Copies in backups, and anywhere the scrubber could not read, are still there; rotating is the only full fix. A later scan that finds the value clears the mark.\n');
    res.json({ ok: true, contained, entry: e ? { name: e.name, ref: e.ref_code } : null });
  });

  return { MIN_LEN };
};
