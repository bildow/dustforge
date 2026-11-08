'use strict';
// ── QR pairing: contacts confirmed in person (red team item 6, queue item 4) ───────────────────────────────────────
// Name lookup alone is phishable (someone registers "kyle" first). A confirmed contact is made face to face:
//   1. A shows a QR (POST /api/network/pair/start): https://demipass.com/pair#<id>.<secret>. The secret is 128 random
//      bits; the server keeps only its hash. The fragment never reaches a server log.
//   2. B scans it in the app (POST /api/network/pair/join {token}). Each screen shows the other's name. Only A's screen
//      shows the 6-digit code: random, drawn by the server at join, stored on this pairing (between these two wallets)
//      and derived from nothing in the QR. B never receives it: B types what A's screen shows (Aaron 2026-11-06: a
//      forwarded QR alone no longer pairs — whoever scanned it must also read A's screen).
//   3. Each side confirms (POST /pair/:id/confirm) with the PIN (intent pair:<id>; biometric stands in for it) and,
//      once a phone is linked, the phone's device key over "<other name>|<code>". B's confirm carries {code}; it is
//      checked before anything else, so no answer to B ever contains the code. 3 wrong codes cancel the pairing (only
//      B, a party to it, can type). Either side can cancel (POST /pair/:id/cancel).
//   4. Both confirmed → the two wallets are contacts with verified_via = 'qr'. Shares and secret transfers go only to
//      such contacts (secret_sharing.js); contacts made by name request still exist for DD, but carry no share rights.
// People only: agents (fleet silicons), silicon/worker tokens and fleet-minted tokens cannot pair, and a wallet pairs
// only after it has set a PIN. One QR is good for one join, 5 minutes. Pairing ids are random 12-digit numbers (the PIN
// intent is pair:<id>); a wallet presenting 10 wrong codes in an hour is refused for the rest of it.

const crypto = require('crypto');

const TTL_SEC = 300;            // an open QR, and a joined pairing waiting for both confirmations
const MAX_OPEN = 3;             // open or joined pairings one wallet may have started
const MAX_WRONG_PER_HOUR = 10; // wrong pairing codes one wallet may present in an hour (per caller: nobody can cancel
                                // someone else's pairing by guessing at it — #52 review)
const TOKEN_RE = /^(\d{1,12})\.([A-Za-z0-9_-]{22})$/;
const MAX_CODE_TRIES = 3;       // wrong codes the scanner may type into one pairing before it is cancelled

module.exports = function registerPairing(deps) {
  const { app, db, rateLimitStandard, getBearerIdentity, gateFresh, gateMissing, spendSingleUse, logSecurityEvent } = deps;
  const log = deps.log || ((...a) => console.log('[pairing]', ...a));

  db.exec(`CREATE TABLE IF NOT EXISTS contact_pairings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    initiator_did TEXT NOT NULL,
    secret_hash TEXT NOT NULL,
    joiner_did TEXT DEFAULT NULL,
    code TEXT DEFAULT NULL,
    status TEXT NOT NULL DEFAULT 'open',          -- open | joined | confirmed | cancelled | expired
    initiator_confirmed_at TEXT DEFAULT NULL,
    joiner_confirmed_at TEXT DEFAULT NULL,
    wrong_joins INTEGER NOT NULL DEFAULT 0,       -- wrong codes typed by the scanner (3 cancel the pairing)
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    joined_at TEXT DEFAULT NULL,
    decided_at TEXT DEFAULT NULL,
    cancelled_by TEXT DEFAULT NULL
  )`);
  db.exec('CREATE INDEX IF NOT EXISTS idx_cp_initiator ON contact_pairings(initiator_did, status)');
  db.exec(`CREATE TABLE IF NOT EXISTS contact_pairing_misses (did TEXT NOT NULL, at TEXT NOT NULL)`);
  db.exec('CREATE INDEX IF NOT EXISTS idx_cpm_did ON contact_pairing_misses(did, at)');
  // network_peers is network_routes.js's table (registered first). A pair confirmed in person is marked on it.
  for (const c of ['verified_via TEXT DEFAULT NULL', 'verified_at TEXT DEFAULT NULL']) {
    try { db.exec('ALTER TABLE network_peers ADD COLUMN ' + c); } catch (_) {}
  }

  const nowIso = () => new Date().toISOString();
  const later = (sec) => new Date(Date.now() + sec * 1000).toISOString();
  const pairDids = (x, y) => (x < y ? [x, y] : [y, x]);
  const sha = (s) => crypto.createHash('sha256').update(String(s)).digest('hex');
  const name = (did) => { const w = db.prepare('SELECT username FROM identity_wallets WHERE did = ?').get(did); return w ? w.username : null; };
  // The code is drawn at join, server-side, from nothing in the QR: the scanner holds the QR's secret and both DIDs, so
  // a code derived from them (as in #52) could be computed without ever seeing the shower's screen.
  const newCode = () => String(crypto.randomInt(0, 1000000)).padStart(6, '0');
  function expireOld() {
    db.prepare("UPDATE contact_pairings SET status = 'expired', decided_at = ?, code = NULL WHERE status IN ('open','joined') AND expires_at <= ?").run(nowIso(), nowIso());
  }

  // A person's own wallet token, with a PIN set. Returns { auth, wallet } or null (answer sent).
  function personAuth(req, res) {
    const auth = getBearerIdentity(req);
    if (!auth.ok) { res.status(auth.status || 401).json({ error: auth.error }); return null; }
    if (auth.silicon || (auth.decoded && (auth.decoded.wrk || auth.decoded.auth_method === 'fleet_owner_mint'))) {
      res.status(403).json({ error: "pairing in person needs the wallet's own sign-in" }); return null;
    }
    const wallet = db.prepare('SELECT did, username, status, pin_hash FROM identity_wallets WHERE did = ?').get(auth.did);
    if (!wallet) { res.status(404).json({ error: 'no wallet for this token' }); return null; }
    if (wallet.status !== 'active') { res.status(403).json({ error: 'account suspended' }); return null; }
    if (db.prepare("SELECT 1 FROM fleet_silicons WHERE member_did = ? AND status = 'active'").get(wallet.did)) {
      res.status(403).json({ error: 'an agent wallet cannot pair in person; its fleet owner gives it secrets' }); return null;
    }
    if (!wallet.pin_hash) { res.status(403).json({ error: 'set your vault PIN first: confirming a contact takes it', pin_required: true }); return null; }
    return { auth, wallet };
  }
  function rowFor(req, res, me) {
    const id = Number(req.params.id);
    const row = Number.isInteger(id) && id > 0 ? db.prepare('SELECT * FROM contact_pairings WHERE id = ?').get(id) : null;
    if (!row || (row.initiator_did !== me && row.joiner_did !== me)) { res.status(404).json({ error: 'pairing not found' }); return null; }
    return row;
  }
  function view(row, me) {
    const role = row.initiator_did === me ? 'shown' : 'scanned';
    const other = role === 'shown' ? row.joiner_did : row.initiator_did;
    const mine = role === 'shown' ? row.initiator_confirmed_at : row.joiner_confirmed_at;
    const theirs = role === 'shown' ? row.joiner_confirmed_at : row.initiator_confirmed_at;
    const joined = row.status === 'joined' || row.status === 'confirmed';
    // The code goes only to the one who showed the QR; the scanner types it from that screen.
    const shown = role === 'shown';
    return {
      pair_id: row.id, status: row.status, role,
      other: other ? name(other) : null, other_did: other || null,
      code: joined && shown ? row.code : null,
      type_code: joined && !shown && !mine,
      code_tries_left: !shown ? Math.max(0, MAX_CODE_TRIES - (row.wrong_joins || 0)) : null,
      you_confirmed: Boolean(mine), they_confirmed: Boolean(theirs),
      intent: `pair:${row.id}`, bind: joined && other && shown ? `${name(other)}|${row.code}` : null,
      bind_prefix: joined && other ? `${name(other)}|` : null,
      expires_at: row.expires_at,
    };
  }

  // ── start: show a QR ────────────────────────────────────────────────────────────────────────────────────────────
  app.post('/api/network/pair/start', rateLimitStandard, (req, res) => {
    const p = personAuth(req, res); if (!p) return;
    expireOld();
    const open = db.prepare("SELECT COUNT(*) AS n FROM contact_pairings WHERE initiator_did = ? AND status IN ('open','joined')").get(p.wallet.did).n;
    if (open >= MAX_OPEN) return res.status(429).json({ error: `at most ${MAX_OPEN} pairings open at once — finish or cancel one` });
    const secret = crypto.randomBytes(16).toString('base64url');
    // A random 12-digit id: not enumerable, and still a valid PIN intent (pair:<digits>).
    let id = 0;
    for (let i = 0; i < 8 && !id; i++) {
      const cand = 100000000000 + crypto.randomInt(0, 899999999999);
      try { db.prepare('INSERT INTO contact_pairings (id, initiator_did, secret_hash, created_at, expires_at) VALUES (?, ?, ?, ?, ?)').run(cand, p.wallet.did, sha(secret), nowIso(), later(TTL_SEC)); id = cand; }
      catch (e) { if (!/UNIQUE|PRIMARY/.test(e.message)) throw e; }
    }
    if (!id) return res.status(503).json({ error: 'could not start a pairing; try again' });
    const token = `${id}.${secret}`;
    res.json({ ok: true, pair_id: id, token, qr: `https://demipass.com/pair#${token}`, expires_at: later(TTL_SEC),
               next: 'the other person scans this in their DemiPass app; then you both compare the 6-digit code and confirm' });
  });

  // ── join: the other person scanned it ───────────────────────────────────────────────────────────────────────────
  app.post('/api/network/pair/join', rateLimitStandard, (req, res) => {
    const p = personAuth(req, res); if (!p) return;
    let raw = String((req.body || {}).token || '').trim();
    const hash = raw.indexOf('#'); if (hash >= 0) raw = raw.slice(hash + 1);       // the whole scanned URL works too
    const m = raw.match(TOKEN_RE);
    if (!m) return res.status(400).json({ error: 'token: the code from the other person\'s DemiPass pairing QR' });
    expireOld();
    // Wrong codes count against the one presenting them, never against the pairing (#52 review).
    const hourAgo = new Date(Date.now() - 3600000).toISOString();
    db.prepare('DELETE FROM contact_pairing_misses WHERE at < ?').run(hourAgo);
    const misses = db.prepare('SELECT COUNT(*) AS n FROM contact_pairing_misses WHERE did = ? AND at >= ?').get(p.wallet.did, hourAgo).n;
    if (misses >= MAX_WRONG_PER_HOUR) return res.status(429).json({ error: 'too many wrong pairing codes from this wallet — try again in an hour' });
    const row = db.prepare('SELECT * FROM contact_pairings WHERE id = ?').get(Number(m[1]));
    const presented = Buffer.from(sha(m[2]), 'hex'), stored = row ? Buffer.from(row.secret_hash, 'hex') : Buffer.alloc(0);
    if (!row || presented.length !== stored.length || !crypto.timingSafeEqual(presented, stored)) {
      db.prepare('INSERT INTO contact_pairing_misses (did, at) VALUES (?, ?)').run(p.wallet.did, nowIso());
      if (misses + 1 >= MAX_WRONG_PER_HOUR) logSecurityEvent('pairing_guessed', 'alert', { caller_did: p.wallet.did, capability: 'pair', target: String(m[1]), ip: req.ip });
      return res.status(row ? 403 : 404).json({ error: row ? 'that code does not match this pairing' : 'no such pairing — ask them to show a new code' });
    }
    if (row.initiator_did === p.wallet.did) return res.status(400).json({ error: 'that is your own pairing code' });
    if (row.status !== 'open') return res.status(409).json({ error: row.status === 'joined' ? 'someone has already scanned this code — ask them to cancel it and show a new one' : `this pairing is ${row.status}` });
    const code = newCode();
    const took = db.prepare("UPDATE contact_pairings SET joiner_did = ?, code = ?, status = 'joined', joined_at = ?, expires_at = ? WHERE id = ? AND status = 'open'")
      .run(p.wallet.did, code, nowIso(), later(TTL_SEC), row.id).changes;
    if (took !== 1) return res.status(409).json({ error: 'someone has already scanned this code — ask them to show a new one' });
    log(`pairing ${row.id}: ${name(row.initiator_did)} ← ${p.wallet.username} joined`);
    res.json({ ok: true, ...view(db.prepare('SELECT * FROM contact_pairings WHERE id = ?').get(row.id), p.wallet.did),
               next: `type the 6-digit code shown on ${name(row.initiator_did)}'s screen, then confirm with your PIN` });
  });

  // ── state, for either side (the screen polls it) ────────────────────────────────────────────────────────────────
  app.get('/api/network/pair/:id', rateLimitStandard, (req, res) => {
    const auth = getBearerIdentity(req);
    if (!auth.ok) return res.status(auth.status || 401).json({ error: auth.error });
    expireOld();
    const row = rowFor(req, res, auth.did); if (!row) return;
    res.json({ ok: true, ...view(row, auth.did) });
  });

  // ── confirm: "the codes match" — PIN (or biometric), and the linked phone's signature ──────────────────────────
  app.post('/api/network/pair/:id/confirm', rateLimitStandard, (req, res) => {
    const p = personAuth(req, res); if (!p) return;
    expireOld();
    const me = p.wallet.did;
    const row = rowFor(req, res, me); if (!row) return;
    if (row.status !== 'joined') return res.status(409).json({ error: row.status === 'open' ? 'nobody has scanned this code yet' : `this pairing is ${row.status}`, ...view(row, me) });
    const v = view(row, me);
    if (v.you_confirmed) return res.json({ ok: true, ...v });
    // The scanner proves it reads the shower's screen: the typed code, checked first (before the PIN and the phone,
    // whose answers would otherwise name the code).
    if (row.joiner_did === me) {
      const typed = String((req.body || {}).code || '').replace(/\s+/g, '');
      if (!/^\d{6}$/.test(typed)) return res.status(400).json({ error: `type the 6-digit code shown on ${v.other}'s screen`, type_code: true });
      const a = Buffer.from(typed), b = Buffer.from(String(row.code));
      if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
        const tries = db.prepare('UPDATE contact_pairings SET wrong_joins = wrong_joins + 1 WHERE id = ? RETURNING wrong_joins').get(row.id).wrong_joins;
        if (tries >= MAX_CODE_TRIES) {
          db.prepare("UPDATE contact_pairings SET status = 'cancelled', decided_at = ?, cancelled_by = 'wrong-code', code = NULL WHERE id = ? AND status = 'joined'").run(nowIso(), row.id);
          logSecurityEvent('pairing_code_mismatch', 'alert', { caller_did: me, capability: 'pair', target: String(row.id), ip: req.ip, error: 'wrong code typed 3 times' });
          return res.status(403).json({ error: `that is not the code on ${v.other}'s screen — the pairing is cancelled; start again face to face`, status: 'cancelled' });
        }
        return res.status(403).json({ error: `that is not the code on ${v.other}'s screen`, code_tries_left: MAX_CODE_TRIES - tries });
      }
    }
    const intent = `pair:${row.id}`;
    if (!gateFresh(me, 'pin', p.auth, intent)) {
      return res.status(403).json({ ...gateMissing('pair', ['pin'], ['pin'], intent), error: 'confirming a contact needs your PIN' });
    }
    const dk = deps.devices && deps.devices();
    const refused = dk ? dk.approvalRefusal(p.auth, 'pair', row.id, `${v.other}|${row.code}`, req.body) : null;
    if (refused) return res.status(refused.status).json(refused.body);
    const col = row.initiator_did === me ? 'initiator_confirmed_at' : 'joiner_confirmed_at';
    try {
      let done = false;
      db.transaction(() => {
        const spent = spendSingleUse(me, 'pair', ['pin'], p.auth, intent);
        if (spent) throw Object.assign(new Error(spent.error), { statusCode: spent.status || 403, body: spent });
        const n = db.prepare(`UPDATE contact_pairings SET ${col} = ? WHERE id = ? AND status = 'joined' AND ${col} IS NULL AND expires_at > ?`).run(nowIso(), row.id, nowIso()).changes;
        if (n !== 1) throw Object.assign(new Error('this pairing changed meanwhile'), { statusCode: 409 });
        const cur = db.prepare('SELECT * FROM contact_pairings WHERE id = ?').get(row.id);
        if (cur.initiator_confirmed_at && cur.joiner_confirmed_at) {
          db.prepare("UPDATE contact_pairings SET status = 'confirmed', decided_at = ?, code = NULL WHERE id = ? AND status = 'joined'").run(nowIso(), row.id);
          const [a, b] = pairDids(cur.initiator_did, cur.joiner_did);
          db.prepare(`INSERT INTO network_peers (did_a, did_b, request_id, verified_via, verified_at) VALUES (?, ?, NULL, 'qr', ?)
                      ON CONFLICT(did_a, did_b) DO UPDATE SET status = 'active', removed_at = NULL, verified_via = 'qr', verified_at = excluded.verified_at, vouched_by = NULL`)
            .run(a, b, nowIso());
          // They met in person: any introduction of these two that is still waiting is moot.
          try { db.prepare("UPDATE contact_vouches SET status = 'withdrawn', decided_at = ?, decided_by = 'paired-in-person' WHERE did_a = ? AND did_b = ? AND status = 'pending'").run(nowIso(), a, b); } catch (_) {}
          done = true;
        }
      }).immediate();
      const now = db.prepare('SELECT * FROM contact_pairings WHERE id = ?').get(row.id);
      if (done) log(`pairing ${row.id}: ${name(now.initiator_did)} ⇄ ${name(now.joiner_did)} confirmed in person`);
      res.json({ ok: true, ...view(now, me), connected: done,
                 next: done ? 'you are confirmed contacts: you can share secrets with each other' : 'waiting for them to confirm on their screen' });
    } catch (e) { res.status(e.statusCode || 500).json(e.body || { error: e.message }); }
  });

  // ── cancel: either side, any time before both confirmed (the codes differ, wrong person, changed mind) ──────────
  app.post('/api/network/pair/:id/cancel', rateLimitStandard, (req, res) => {
    const auth = getBearerIdentity(req);
    if (!auth.ok) return res.status(auth.status || 401).json({ error: auth.error });
    const row = rowFor(req, res, auth.did); if (!row) return;
    const n = db.prepare("UPDATE contact_pairings SET status = 'cancelled', decided_at = ?, cancelled_by = ?, code = NULL WHERE id = ? AND status IN ('open','joined')")
      .run(nowIso(), auth.did, row.id).changes;
    if (n !== 1) return res.status(409).json({ error: `this pairing is ${db.prepare('SELECT status FROM contact_pairings WHERE id = ?').get(row.id).status}` });
    if ((req.body || {}).mismatch) logSecurityEvent('pairing_code_mismatch', 'alert', { caller_did: auth.did, capability: 'pair', target: String(row.id), ip: req.ip });
    res.json({ ok: true, ...view(db.prepare('SELECT * FROM contact_pairings WHERE id = ?').get(row.id), auth.did) });
  });

  // ── vouching: a contact both people met in person introduces them (red team item 6) ─────────────────────────────
  // C, confirmed in person (QR) with both A and B, vouches that A and B should be confirmed contacts. A and B each
  // accept with their PIN (intent vouch:<id>) and, once a phone is linked, its signature over "<voucher>|<other>".
  // Both accepted → a confirmed contact, verified_via = 'vouch', vouched_by = C. Only first-hand (QR) links vouch: a
  // contact confirmed by a vouch cannot vouch for anyone (no chains). The voucher states it with its own PIN
  // (vouch:0) and phone. 7 days to accept; a voucher has at most 10 open; either side declines; mail to both.
  const VOUCH_TTL_DAYS = 7, VOUCH_MAX_OPEN = 10;
  db.exec(`CREATE TABLE IF NOT EXISTS contact_vouches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    voucher_did TEXT NOT NULL,
    did_a TEXT NOT NULL,
    did_b TEXT NOT NULL,
    note TEXT DEFAULT '',
    status TEXT NOT NULL DEFAULT 'pending',      -- pending | confirmed | declined | expired | withdrawn
    a_accepted_at TEXT DEFAULT NULL,
    b_accepted_at TEXT DEFAULT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    decided_at TEXT DEFAULT NULL,
    decided_by TEXT DEFAULT NULL
  )`);
  db.exec('CREATE INDEX IF NOT EXISTS idx_cv_a ON contact_vouches(did_a, status)');
  db.exec('CREATE INDEX IF NOT EXISTS idx_cv_b ON contact_vouches(did_b, status)');
  db.exec('CREATE INDEX IF NOT EXISTS idx_cv_v ON contact_vouches(voucher_did, status)');
  try { db.exec('ALTER TABLE network_peers ADD COLUMN vouched_by TEXT DEFAULT NULL'); } catch (_) {}
  const peerRow = (x, y) => { const [a, b] = pairDids(x, y); return db.prepare("SELECT * FROM network_peers WHERE did_a = ? AND did_b = ? AND status = 'active'").get(a, b) || null; };
  const metInPerson = (x, y) => { const r = peerRow(x, y); return Boolean(r && r.verified_via === 'qr'); };
  const walletBy = (q) => {
    const v = String(q || '').trim().toLowerCase();
    if (!v || v.length > 200) return null;
    return db.prepare('SELECT did, username, email, status, pin_hash FROM identity_wallets WHERE did = ? OR username = ?').get(String(q).trim(), v) || null;
  };
  const mailTo = (did, subject, text) => {
    const w = db.prepare('SELECT email FROM identity_wallets WHERE did = ?').get(did);
    try { if (w && w.email && deps.sendMail) Promise.resolve(deps.sendMail({ to: w.email, subject, text })).catch(() => {}); } catch (_) {}
  };
  function expireVouches() {
    db.prepare("UPDATE contact_vouches SET status = 'expired', decided_at = ? WHERE status = 'pending' AND expires_at <= ?").run(nowIso(), nowIso());
  }
  function vouchView(v, me) {
    const side = me === v.did_a ? 'a' : me === v.did_b ? 'b' : 'voucher';
    const other = side === 'a' ? v.did_b : side === 'b' ? v.did_a : null;
    return { id: v.id, role: side === 'voucher' ? 'voucher' : 'introduced', voucher: name(v.voucher_did),
             a: name(v.did_a), b: name(v.did_b), other: other ? name(other) : null, note: v.note || '', status: v.status,
             you_accepted: side === 'a' ? Boolean(v.a_accepted_at) : side === 'b' ? Boolean(v.b_accepted_at) : null,
             a_accepted: Boolean(v.a_accepted_at), b_accepted: Boolean(v.b_accepted_at),
             intent: `vouch:${v.id}`, bind: other ? `${name(v.voucher_did)}|${name(other)}` : null,
             created_at: v.created_at, expires_at: v.expires_at };
  }
  function vouchFor(req, res, me) {
    const id = Number(req.params.id);
    const v = Number.isInteger(id) && id > 0 ? db.prepare('SELECT * FROM contact_vouches WHERE id = ?').get(id) : null;
    if (!v || ![v.voucher_did, v.did_a, v.did_b].includes(me)) { res.status(404).json({ error: 'introduction not found' }); return null; }
    return v;
  }

  // POST /api/network/vouch {a, b, note?} — C introduces two people C has met in person.
  app.post('/api/network/vouch', rateLimitStandard, (req, res) => {
    const p = personAuth(req, res); if (!p) return;
    expireVouches();
    const me = p.wallet.did;
    const { a, b, note } = req.body || {};
    const wa = walletBy(a), wb = walletBy(b);
    if (!wa || !wb) return res.status(404).json({ error: 'a and b: the usernames of two people you met in person' });
    if (wa.did === wb.did || wa.did === me || wb.did === me) return res.status(400).json({ error: 'introduce two other people to each other' });
    if (!metInPerson(me, wa.did) || !metInPerson(me, wb.did)) {
      return res.status(403).json({ error: 'you can vouch only for people you paired with in person (QR) — both of them', pair_required: true });
    }
    for (const w of [wa, wb]) {
      if (w.status !== 'active') return res.status(403).json({ error: `${w.username} is not active` });
      if (db.prepare("SELECT 1 FROM fleet_silicons WHERE member_did = ? AND status = 'active'").get(w.did)) return res.status(409).json({ error: `${w.username} is an agent` });
      if (!w.pin_hash) return res.status(409).json({ error: `${w.username} has no PIN yet, so they could not accept` });
    }
    const existing = peerRow(wa.did, wb.did);
    // An email-code pair (email_pairing.js) may be raised to a vouch: it carries no share rights until then.
    if (existing && existing.verified_via && existing.verified_via !== 'email-code') return res.status(409).json({ error: `${wa.username} and ${wb.username} are already confirmed contacts` });
    const [da, dbb] = pairDids(wa.did, wb.did);
    if (db.prepare("SELECT 1 FROM contact_vouches WHERE did_a = ? AND did_b = ? AND status = 'pending'").get(da, dbb)) return res.status(409).json({ error: 'an introduction of these two is already waiting' });
    if (db.prepare("SELECT COUNT(*) AS n FROM contact_vouches WHERE voucher_did = ? AND status = 'pending'").get(me).n >= VOUCH_MAX_OPEN) {
      return res.status(429).json({ error: `at most ${VOUCH_MAX_OPEN} introductions waiting at once` });
    }
    const cleanNote = String(note == null ? '' : note).replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, 200);
    // The voucher's word is a decision too: PIN, and the linked phone signs who is introduced to whom.
    const intent = 'vouch:0';
    if (!gateFresh(me, 'pin', p.auth, intent)) return res.status(403).json({ ...gateMissing('vouch', ['pin'], ['pin'], intent), error: 'vouching needs your PIN' });
    const dk = deps.devices && deps.devices();
    const refused = dk ? dk.approvalRefusal(p.auth, 'vouch', 0, `${name(da)}|${name(dbb)}`, req.body) : null;
    if (refused) return res.status(refused.status).json(refused.body);
    const spent = spendSingleUse(me, 'vouch', ['pin'], p.auth, intent);
    if (spent) return res.status(spent.status || 403).json(spent);
    const id = Number(db.prepare('INSERT INTO contact_vouches (voucher_did, did_a, did_b, note, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)')
      .run(me, da, dbb, cleanNote, nowIso(), later(VOUCH_TTL_DAYS * 86400)).lastInsertRowid);
    for (const [x, y] of [[da, dbb], [dbb, da]]) {
      mailTo(x, `DemiPass: ${p.wallet.username} introduces ${name(y)} to you`,
        `${p.wallet.username}, whom you met in person, vouches for ${name(y)}.${cleanNote ? `\n\n"${cleanNote}"` : ''}\n\nIf you both accept in the DemiPass app (Fleet), you become confirmed contacts and can share secrets. Accept only if you know who ${name(y)} is. Nothing happens otherwise; the introduction expires in ${VOUCH_TTL_DAYS} days.\n`);
    }
    log(`vouch ${id}: ${p.wallet.username} introduces ${name(da)} and ${name(dbb)}`);
    res.json({ ok: true, vouch: vouchView(db.prepare('SELECT * FROM contact_vouches WHERE id = ?').get(id), me) });
  });

  // GET /api/network/vouches — introductions you made or that name you.
  app.get('/api/network/vouches', rateLimitStandard, (req, res) => {
    const auth = getBearerIdentity(req);
    if (!auth.ok) return res.status(auth.status || 401).json({ error: auth.error });
    expireVouches();
    const rows = db.prepare('SELECT * FROM contact_vouches WHERE voucher_did = ? OR did_a = ? OR did_b = ? ORDER BY id DESC LIMIT 100').all(auth.did, auth.did, auth.did);
    const v = rows.map(r => vouchView(r, auth.did));
    res.json({ ok: true, vouches: v, waiting_for_you: v.filter(x => x.role === 'introduced' && x.status === 'pending' && !x.you_accepted).length });
  });

  // POST /api/network/vouches/:id/accept — one of the two introduced; PIN (vouch:<id>) and the linked phone.
  app.post('/api/network/vouches/:id/accept', rateLimitStandard, (req, res) => {
    const p = personAuth(req, res); if (!p) return;
    expireVouches();
    const me = p.wallet.did;
    const v = vouchFor(req, res, me); if (!v) return;
    if (me !== v.did_a && me !== v.did_b) return res.status(403).json({ error: 'only the two people introduced accept it' });
    if (v.status !== 'pending') return res.status(409).json({ error: `this introduction is ${v.status}`, vouch: vouchView(v, me) });
    const view0 = vouchView(v, me);
    if (view0.you_accepted) return res.json({ ok: true, vouch: view0 });
    // The voucher must still have met both in person: an introduction does not outlive the voucher's own links.
    if (!metInPerson(v.voucher_did, v.did_a) || !metInPerson(v.voucher_did, v.did_b)) {
      db.prepare("UPDATE contact_vouches SET status = 'withdrawn', decided_at = ?, decided_by = 'voucher-link-ended' WHERE id = ? AND status = 'pending'").run(nowIso(), v.id);
      return res.status(409).json({ error: `${name(v.voucher_did)} is no longer a confirmed contact of both of you; this introduction lapsed` });
    }
    const intent = `vouch:${v.id}`;
    if (!gateFresh(me, 'pin', p.auth, intent)) return res.status(403).json({ ...gateMissing('vouch', ['pin'], ['pin'], intent), error: 'accepting an introduction needs your PIN' });
    const dk = deps.devices && deps.devices();
    const refused = dk ? dk.approvalRefusal(p.auth, 'vouch', v.id, view0.bind, req.body) : null;
    if (refused) return res.status(refused.status).json(refused.body);
    const col = me === v.did_a ? 'a_accepted_at' : 'b_accepted_at';
    try {
      let done = false;
      db.transaction(() => {
        const spent = spendSingleUse(me, 'vouch', ['pin'], p.auth, intent);
        if (spent) throw Object.assign(new Error(spent.error), { statusCode: spent.status || 403, body: spent });
        if (db.prepare(`UPDATE contact_vouches SET ${col} = ? WHERE id = ? AND status = 'pending' AND ${col} IS NULL AND expires_at > ?`).run(nowIso(), v.id, nowIso()).changes !== 1) {
          throw Object.assign(new Error('this introduction changed meanwhile'), { statusCode: 409 });
        }
        const cur = db.prepare('SELECT * FROM contact_vouches WHERE id = ?').get(v.id);
        if (cur.a_accepted_at && cur.b_accepted_at) {
          db.prepare("UPDATE contact_vouches SET status = 'confirmed', decided_at = ? WHERE id = ? AND status = 'pending'").run(nowIso(), v.id);
          // A first-hand (QR) link they made meanwhile stays first-hand: a vouch never downgrades it (#55 review).
          db.prepare(`INSERT INTO network_peers (did_a, did_b, request_id, verified_via, verified_at, vouched_by) VALUES (?, ?, NULL, 'vouch', ?, ?)
                      ON CONFLICT(did_a, did_b) DO UPDATE SET
                        verified_via = CASE WHEN network_peers.status = 'active' AND network_peers.verified_via = 'qr' THEN 'qr' ELSE 'vouch' END,
                        vouched_by = CASE WHEN network_peers.status = 'active' AND network_peers.verified_via = 'qr' THEN NULL ELSE excluded.vouched_by END,
                        verified_at = CASE WHEN network_peers.status = 'active' AND network_peers.verified_via = 'qr' THEN network_peers.verified_at ELSE excluded.verified_at END,
                        status = 'active', removed_at = NULL`)
            .run(cur.did_a, cur.did_b, nowIso(), cur.voucher_did);
          done = true;
        }
      }).immediate();
      const now = db.prepare('SELECT * FROM contact_vouches WHERE id = ?').get(v.id);
      if (done) {
        log(`vouch ${v.id}: ${name(now.did_a)} ⇄ ${name(now.did_b)} confirmed (vouched by ${name(now.voucher_did)})`);
        mailTo(now.voucher_did, `DemiPass: ${name(now.did_a)} and ${name(now.did_b)} accepted your introduction`, `${name(now.did_a)} and ${name(now.did_b)} are now confirmed contacts on your word.\n`);
      }
      res.json({ ok: true, vouch: vouchView(now, me), connected: done });
    } catch (e) { res.status(e.statusCode || 500).json(e.body || { error: e.message }); }
  });

  // POST /api/network/vouches/:id/decline — either introduced person declines; the voucher withdraws. No PIN.
  app.post('/api/network/vouches/:id/decline', rateLimitStandard, (req, res) => {
    const auth = getBearerIdentity(req);
    if (!auth.ok) return res.status(auth.status || 401).json({ error: auth.error });
    const v = vouchFor(req, res, auth.did); if (!v) return;
    const st = auth.did === v.voucher_did ? 'withdrawn' : 'declined';
    const n = db.prepare("UPDATE contact_vouches SET status = ?, decided_at = ?, decided_by = ? WHERE id = ? AND status = 'pending'").run(st, nowIso(), auth.did, v.id).changes;
    if (n !== 1) return res.status(409).json({ error: `this introduction is ${db.prepare('SELECT status FROM contact_vouches WHERE id = ?').get(v.id).status}` });
    res.json({ ok: true, vouch: vouchView(db.prepare('SELECT * FROM contact_vouches WHERE id = ?').get(v.id), auth.did) });
  });

  // A confirmed contact for shares: active, and verified in person by QR or by the vouch of someone both met in person.
  // An email-code pair is a contact for DD only (email_pairing.js; threat model item 6 ruling 2026-11-07).
  function isConfirmedPeer(x, y) {
    const [a, b] = pairDids(x, y);
    return Boolean(db.prepare("SELECT 1 FROM network_peers WHERE did_a = ? AND did_b = ? AND status = 'active' AND verified_via IN ('qr','vouch')").get(a, b));
  }
  return { isConfirmedPeer, TTL_SEC, MAX_OPEN };
};
