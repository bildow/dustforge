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
                      ON CONFLICT(did_a, did_b) DO UPDATE SET status = 'active', removed_at = NULL, verified_via = 'qr', verified_at = excluded.verified_at`)
            .run(a, b, nowIso());
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

  // A confirmed (in-person) contact: active, and verified by QR.
  function isConfirmedPeer(x, y) {
    const [a, b] = pairDids(x, y);
    return Boolean(db.prepare("SELECT 1 FROM network_peers WHERE did_a = ? AND did_b = ? AND status = 'active' AND verified_via IS NOT NULL").get(a, b));
  }
  return { isConfirmedPeer, TTL_SEC, MAX_OPEN };
};
