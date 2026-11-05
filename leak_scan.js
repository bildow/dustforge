'use strict';
// ── Leak scanner (red team item 5, tome decisions/2026-11-05-THREAT-MODEL-demipass-red-team-v0.1.md) ────────────────
// "Is any of my vault values in this text?" — answered here, where the values are, so the scanner never holds or
// prints one. A client (bin/leak-scan.js: pane start, deploy gate, CI) sends text in chunks it labels (file:lines);
// the answer is, per chunk, the refs and names of the owner's secrets found in it and how often. Never a value.
//
// Caller: the owner in their own session, or a scan token the owner minted (opaque, hashed at rest, good only here).
// A scan is an oracle for the owner's own values, so it is bounded: values shorter than MIN_LEN are not matched, a token
// scans at most DAILY_BYTES a day, every scan is logged (bytes, hits), and every hit is a critical security event.

const crypto = require('crypto');

const MIN_LEN = 8;
const MAX_REQUEST_BYTES = 2 * 1024 * 1024;
const DAILY_BYTES = 256 * 1024 * 1024;
const MAX_CHUNKS = 200;

module.exports = function registerLeakScan(deps) {
  const { app, db, express, rateLimitStandard, getBearerIdentity, gateSession, gateFresh, gateMissing, spendSingleUse,
          logSecurityEvent, blindkeyDecrypt, cleanLabel } = deps;

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
  const sha = (t) => crypto.createHash('sha256').update(String(t)).digest('hex');
  const nowIso = () => new Date().toISOString();
  const parser = express.json({ limit: MAX_REQUEST_BYTES });

  function personAuth(req, res) {
    const auth = getBearerIdentity(req);
    if (!auth.ok) { res.status(auth.status || 401).json({ error: auth.error }); return null; }
    if (auth.silicon || (auth.decoded && (auth.decoded.wrk || auth.decoded.auth_method === 'fleet_owner_mint'))) { res.status(403).json({ error: 'scan tokens are minted by the owner in their own session' }); return null; }
    if (!gateSession(auth)) { res.status(403).json({ error: 'sign in again' }); return null; }
    return auth;
  }
  // Who is scanning: a scan token (Authorization: Scan <token>) or the owner's own bearer session.
  function scanCaller(req, res) {
    const h = String(req.headers.authorization || '');
    if (h.startsWith('Scan ')) {
      const row = db.prepare('SELECT * FROM leak_scan_tokens WHERE token_hash = ? AND revoked_at IS NULL').get(sha(h.slice(5).trim()));
      if (!row) { res.status(401).json({ error: 'invalid scan token' }); return null; }
      return { did: row.owner_did, tokenRow: row };
    }
    const auth = getBearerIdentity(req);
    if (!auth.ok) { res.status(auth.status || 401).json({ error: auth.error }); return null; }
    if (auth.silicon || (auth.decoded && auth.decoded.wrk)) { res.status(403).json({ error: 'use a scan token' }); return null; }
    return { did: auth.did, tokenRow: null };
  }

  // POST /api/blindkey/leak-scan/tokens {label} — mint a scan token (PIN, intent scan-token:0). Shown once.
  app.post('/api/blindkey/leak-scan/tokens', rateLimitStandard, (req, res) => {
    const auth = personAuth(req, res); if (!auth) return;
    const intent = 'scan-token:0';
    if (!gateFresh(auth.did, 'pin', auth, intent)) return res.status(403).json(gateMissing('scan-token', ['pin'], ['pin'], intent));
    const refused = spendSingleUse(auth.did, 'scan-token', ['pin'], auth, intent);
    if (refused) return res.status(refused.status || 403).json(refused);
    const token = 'dpscan_' + crypto.randomBytes(24).toString('base64url');
    const id = Number(db.prepare('INSERT INTO leak_scan_tokens (owner_did, token_hash, label, created_at) VALUES (?, ?, ?, ?)')
      .run(auth.did, sha(token), cleanLabel((req.body || {}).label || '', 80), nowIso()).lastInsertRowid);
    logSecurityEvent('scan_token_minted', 'warn', { caller_did: auth.did, ip: req.ip, context: { token_id: id } });
    res.status(201).json({ ok: true, id, token, note: 'shown once: put it in the vault or a CI secret, never in a file a pane reads' });
  });
  // GET /api/blindkey/leak-scan/tokens — the owner's scan tokens (never the token).
  app.get('/api/blindkey/leak-scan/tokens', rateLimitStandard, (req, res) => {
    const auth = getBearerIdentity(req); if (!auth.ok) return res.status(auth.status || 401).json({ error: auth.error });
    res.json({ ok: true, tokens: db.prepare('SELECT id, label, created_at, revoked_at, last_used_at, bytes_today, day FROM leak_scan_tokens WHERE owner_did = ? ORDER BY id DESC').all(auth.did) });
  });
  // DELETE /api/blindkey/leak-scan/tokens/:id — revoke.
  app.delete('/api/blindkey/leak-scan/tokens/:id', rateLimitStandard, (req, res) => {
    const auth = getBearerIdentity(req); if (!auth.ok) return res.status(auth.status || 401).json({ error: auth.error });
    const n = db.prepare('UPDATE leak_scan_tokens SET revoked_at = ? WHERE id = ? AND owner_did = ? AND revoked_at IS NULL').run(nowIso(), Number(req.params.id), auth.did).changes;
    res.status(n ? 200 : 404).json(n ? { ok: true } : { error: 'scan token not found' });
  });

  // POST /api/blindkey/leak-scan {chunks:[{id, text}]} → {hits:[{chunk, ref, name, count}], scanned_bytes}
  app.post('/api/blindkey/leak-scan', parser, rateLimitStandard, (req, res) => {
    const caller = scanCaller(req, res); if (!caller) return;
    const chunks = (req.body || {}).chunks;
    if (!Array.isArray(chunks) || !chunks.length || chunks.length > MAX_CHUNKS || chunks.some(c => !c || typeof c.text !== 'string' || (c.id !== undefined && typeof c.id !== 'string'))) {
      return res.status(400).json({ error: `chunks: 1–${MAX_CHUNKS} of {id: string, text: string}` });
    }
    const bytes = chunks.reduce((n, c) => n + Buffer.byteLength(c.text), 0);
    if (caller.tokenRow) {
      const day = nowIso().slice(0, 10);
      const used = caller.tokenRow.day === day ? caller.tokenRow.bytes_today : 0;
      if (used + bytes > DAILY_BYTES) return res.status(429).json({ error: `this scan token's daily budget (${DAILY_BYTES} bytes) is used up` });
      db.prepare('UPDATE leak_scan_tokens SET day = ?, bytes_today = ?, last_used_at = ? WHERE id = ?').run(day, used + bytes, nowIso(), caller.tokenRow.id);
    }
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
    db.prepare('INSERT INTO blindkey_events (event_type, actor, secret_id, context_name, detail) VALUES (?, ?, ?, ?, ?)')
      .run('leak_scan', caller.did, null, null, JSON.stringify({ bytes, chunks: chunks.length, hits: hits.length, token_id: caller.tokenRow ? caller.tokenRow.id : null }));
    for (const h of hits) logSecurityEvent('leak_scan_hit', 'critical', { caller_did: caller.did, capability: 'leak-scan', target: h.name, context: { ref: h.ref, chunk: h.chunk, count: h.count } });
    res.json({ ok: true, scanned_bytes: bytes, hits });
  });

  return { MIN_LEN };
};
