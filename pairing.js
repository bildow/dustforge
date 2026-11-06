'use strict';
// ── QR pairing: contacts confirmed in person (red team item 6, queue item 4) ───────────────────────────────────────
// Name lookup alone is phishable (someone registers "kyle" first). A confirmed contact is made face to face:
//   1. A shows a QR (POST /api/network/pair/start): https://demipass.com/pair#<id>.<secret>. The secret is 128 random
//      bits; the server keeps only its hash. The fragment never reaches a server log.
//   2. B scans it in the app (POST /api/network/pair/join {token}). Both screens now show the other's name and the same
//      6-digit code = HMAC(secret, "dp-pair:<id>:<A did>:<B did>"), so it names this pairing AND these two wallets.
//   3. Each side compares the codes on the two screens and confirms (POST /pair/:id/confirm) with the PIN (intent
//      pair:<id>; biometric stands in for it) and, once a phone is linked, the phone's device key over
//      "<other name>|<code>". A mismatch is a cancel (POST /pair/:id/cancel), never a retry on the same pairing.
//   4. Both confirmed → the two wallets are contacts with verified_via = 'qr'. Shares and secret transfers go only to
//      such contacts (secret_sharing.js); contacts made by name request still exist for DD, but carry no share rights.
// People only: agents (fleet silicons), silicon/worker tokens and fleet-minted tokens cannot pair, and a wallet pairs
// only after it has set a PIN. One QR is good for one join, 5 minutes; 5 wrong secrets for an id cancel it.

const crypto = require('crypto');

const TTL_SEC = 300;            // an open QR, and a joined pairing waiting for both confirmations
const MAX_OPEN = 3;             // open or joined pairings one wallet may have started
const MAX_WRONG = 5;            // wrong secrets presented for one pairing id before it is cancelled
const TOKEN_RE = /^(\d{1,12})\.([A-Za-z0-9_-]{22})$/;

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
    wrong_joins INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    joined_at TEXT DEFAULT NULL,
    decided_at TEXT DEFAULT NULL,
    cancelled_by TEXT DEFAULT NULL
  )`);
  db.exec('CREATE INDEX IF NOT EXISTS idx_cp_initiator ON contact_pairings(initiator_did, status)');
  // network_peers is network_routes.js's table (registered first). A pair confirmed in person is marked on it.
  for (const c of ['verified_via TEXT DEFAULT NULL', 'verified_at TEXT DEFAULT NULL']) {
    try { db.exec('ALTER TABLE network_peers ADD COLUMN ' + c); } catch (_) {}
  }

  const nowIso = () => new Date().toISOString();
  const later = (sec) => new Date(Date.now() + sec * 1000).toISOString();
  const pairDids = (x, y) => (x < y ? [x, y] : [y, x]);
  const sha = (s) => crypto.createHash('sha256').update(String(s)).digest('hex');
  const name = (did) => { const w = db.prepare('SELECT username FROM identity_wallets WHERE did = ?').get(did); return w ? w.username : null; };
  const codeFor = (secret, id, a, b) => {
    const mac = crypto.createHmac('sha256', String(secret)).update(`dp-pair:${id}:${a}:${b}`).digest();
    return String(mac.readUInt32BE(0) % 1000000).padStart(6, '0');
  };
  function expireOld() {
    db.prepare("UPDATE contact_pairings SET status = 'expired', decided_at = ? WHERE status IN ('open','joined') AND expires_at <= ?").run(nowIso(), nowIso());
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
    return {
      pair_id: row.id, status: row.status, role,
      other: other ? name(other) : null, other_did: other || null,
      code: joined ? row.code : null,
      you_confirmed: Boolean(mine), they_confirmed: Boolean(theirs),
      intent: `pair:${row.id}`, bind: joined && other ? `${name(other)}|${row.code}` : null,
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
    const id = db.prepare('INSERT INTO contact_pairings (initiator_did, secret_hash, created_at, expires_at) VALUES (?, ?, ?, ?)')
      .run(p.wallet.did, sha(secret), nowIso(), later(TTL_SEC)).lastInsertRowid;
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
    const row = db.prepare('SELECT * FROM contact_pairings WHERE id = ?').get(Number(m[1]));
    if (!row) return res.status(404).json({ error: 'no such pairing — ask them to show a new code' });
    const presented = Buffer.from(sha(m[2]), 'hex'), stored = Buffer.from(row.secret_hash, 'hex');
    if (presented.length !== stored.length || !crypto.timingSafeEqual(presented, stored)) {
      const wrong = db.prepare('UPDATE contact_pairings SET wrong_joins = wrong_joins + 1 WHERE id = ? RETURNING wrong_joins').get(row.id).wrong_joins;
      if (wrong >= MAX_WRONG && ['open', 'joined'].includes(row.status)) {
        db.prepare("UPDATE contact_pairings SET status = 'cancelled', decided_at = ?, cancelled_by = 'wrong-secrets' WHERE id = ? AND status IN ('open','joined')").run(nowIso(), row.id);
        logSecurityEvent('pairing_guessed', 'critical', { caller_did: p.wallet.did, capability: 'pair', target: String(row.id), ip: req.ip });
      }
      return res.status(403).json({ error: 'that code does not match this pairing' });
    }
    if (row.initiator_did === p.wallet.did) return res.status(400).json({ error: 'that is your own pairing code' });
    if (row.status !== 'open') return res.status(409).json({ error: row.status === 'joined' ? 'someone has already scanned this code — ask them to cancel it and show a new one' : `this pairing is ${row.status}` });
    const code = codeFor(m[2], row.id, row.initiator_did, p.wallet.did);
    const took = db.prepare("UPDATE contact_pairings SET joiner_did = ?, code = ?, status = 'joined', joined_at = ?, expires_at = ? WHERE id = ? AND status = 'open'")
      .run(p.wallet.did, code, nowIso(), later(TTL_SEC), row.id).changes;
    if (took !== 1) return res.status(409).json({ error: 'someone has already scanned this code — ask them to show a new one' });
    log(`pairing ${row.id}: ${name(row.initiator_did)} ← ${p.wallet.username} joined`);
    res.json({ ok: true, ...view(db.prepare('SELECT * FROM contact_pairings WHERE id = ?').get(row.id), p.wallet.did),
               next: 'compare this code with the one on their screen; confirm only if they are the same' });
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
    const intent = `pair:${row.id}`;
    if (!gateFresh(me, 'pin', p.auth, intent)) {
      return res.status(403).json({ ...gateMissing('pair', ['pin'], ['pin'], intent), error: 'confirming a contact needs your PIN' });
    }
    const dk = deps.devices && deps.devices();
    const refused = dk ? dk.approvalRefusal(p.auth, 'pair', row.id, v.bind, req.body) : null;
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
          db.prepare("UPDATE contact_pairings SET status = 'confirmed', decided_at = ? WHERE id = ? AND status = 'joined'").run(nowIso(), row.id);
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
    const n = db.prepare("UPDATE contact_pairings SET status = 'cancelled', decided_at = ?, cancelled_by = ? WHERE id = ? AND status IN ('open','joined')")
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
