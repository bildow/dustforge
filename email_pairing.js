'use strict';
// ── Email-code pairing: a remote way to confirm a contact (Aaron's ruling 2026-11-07, threat model item 6) ───────────
// QR pairing (pairing.js) needs both people in one place. This is the remote path:
//   1. A (the inviter) asks for a link to an email address, or to a username (its wallet's address):
//      POST /api/network/pair/email {to}. The server mails a one-use link https://demipass.com/vault-mobile.html#epair=
//      <id>.<secret> (128-bit secret, only its hash kept; 30 min; one join). The reply to A never holds the link.
//   2. B opens it SIGNED IN to B's own wallet and confirms with B's PIN (intent pair:<id>):
//      POST /api/network/pair/email/join {token}. The server binds the invite to B's DID and draws a 6-digit code at
//      random — from nothing in the email — that only B's screen shows.
//   3. B tells A the code out of band (a call, in person). A types it: POST /api/network/pair/email/:id/confirm {code}.
//      The code is checked first (3 wrong codes cancel; no answer to A ever contains it), then A's PIN (pair:<id>) and,
//      once A has a phone linked, its device signature over "<B's name>|<code>".
//   4. Confirmed: A and B become contacts (one is made if none exists) with verified_via = 'email-code'; a contact
//      already confirmed by QR or a vouch keeps that. Both are mailed.
// What 'email-code' counts for: DD and contacts. Not shares, guardians or vouching (those need 'qr', or 'vouch' for
// shares) until Aaron rules otherwise — the residual risk: a forwarded email opened by the wrong person, who then reads
// A the code; A must recognise who is speaking. People only: agents, silicon/worker/fleet-minted tokens cannot pair.

const crypto = require('crypto');

const TTL_SEC = 30 * 60;          // an unopened link
const JOINED_TTL_SEC = 30 * 60;   // after B opened it, for A to type the code
const MAX_OPEN = 3;               // open links one inviter may have
const MAX_PER_ADDRESS_DAY = 5;    // links to one mailbox in 24 h, from anyone (canonical: +tags, Gmail dots, case) — the standing 5/day/recipient mail rule
const MAX_PER_PAIR_DAY = 3;       // from one inviter to one mailbox in 24 h: one wallet cannot use up a person's whole day (#75 re-review)
const MAX_PER_SENDER_DAY = 10;    // links one inviter may send in 24 h, cancelled and expired ones included
const MAX_CODE_TRIES = 3;
const MAX_WRONG_PER_HOUR = 10;    // wrong link tokens one wallet may present in an hour
const TOKEN_RE = /^(\d{1,12})\.([A-Za-z0-9_-]{22})$/;
const EMAIL_RE = /^[^\s@<>",;:()\[\]\\]{1,64}@[^\s@<>",;:()\[\]\\]{1,190}\.[^\s@<>",;:()\[\]\\]{2,}$/;
const cap = require('./mail_recipient_cap');
const addressparser = require('nodemailer/lib/addressparser');
// Exactly one bare mailbox, as nodemailer would read it: no display name, no group, no list, nothing around it (#75
// review: "x1<victim@gmail.com>" passed the old check and nodemailer delivered it). → the bare address, lower-cased, or null.
function bareMailbox(raw) {
  const t = String(raw || '').trim();
  if (!EMAIL_RE.test(t)) return null;
  let parsed; try { parsed = addressparser(t); } catch (_) { return null; }
  if (!Array.isArray(parsed) || parsed.length !== 1 || parsed[0].group || parsed[0].name || !parsed[0].address) return null;
  if (parsed[0].address.toLowerCase() !== t.toLowerCase()) return null;
  if (cap.recipientList(t).length !== 1) return null;
  return t.toLowerCase();
}

module.exports = function registerEmailPairing(deps) {
  const { app, db, rateLimitStandard, getBearerIdentity, gateFresh, gateMissing, spendSingleUse, logSecurityEvent } = deps;
  const log = deps.log || ((...a) => console.log('[email-pairing]', ...a));
  const base = deps.publicBase || 'https://demipass.com';

  db.exec(`CREATE TABLE IF NOT EXISTS email_pairings (
    id INTEGER PRIMARY KEY,
    inviter_did TEXT NOT NULL,
    to_email TEXT NOT NULL,
    to_canon TEXT NOT NULL,                     -- the mailbox it counts against (mail_recipient_cap.canonicalAddress)
    target_did TEXT DEFAULT NULL,               -- an invite by username: only that wallet may open it
    opener_matches INTEGER DEFAULT NULL,        -- an invite by address: did the opener's own address(es) match it
    secret_hash TEXT NOT NULL,
    joiner_did TEXT DEFAULT NULL,
    code TEXT DEFAULT NULL,
    status TEXT NOT NULL DEFAULT 'sent',        -- sent | joined | confirmed | cancelled | expired
    wrong_codes INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    joined_at TEXT DEFAULT NULL,
    decided_at TEXT DEFAULT NULL,
    cancelled_by TEXT DEFAULT NULL
  )`);
  db.exec('CREATE INDEX IF NOT EXISTS idx_ep_inviter ON email_pairings(inviter_did, status)');
  db.exec('CREATE INDEX IF NOT EXISTS idx_ep_to ON email_pairings(to_canon, created_at)');
  db.exec(`CREATE TABLE IF NOT EXISTS contact_pairing_misses (did TEXT NOT NULL, at TEXT NOT NULL)`);   // pairing.js's, shared

  const nowIso = () => new Date().toISOString();
  const later = (sec) => new Date(Date.now() + sec * 1000).toISOString();
  const sha = (s) => crypto.createHash('sha256').update(String(s)).digest('hex');
  const pairDids = (x, y) => (x < y ? [x, y] : [y, x]);
  const name = (did) => { const w = db.prepare('SELECT username FROM identity_wallets WHERE did = ?').get(did); return w ? w.username : null; };
  const mask = (e) => { const [u, d] = String(e).split('@'); return (u.length <= 2 ? u[0] + '…' : u.slice(0, 2) + '…') + '@' + d; };
  const isAgent = (did) => Boolean(db.prepare("SELECT 1 FROM fleet_silicons WHERE member_did = ? AND status = 'active'").get(did));
  const mail = (to, subject, text) => { try { if (to && deps.sendMail) Promise.resolve(deps.sendMail({ to, subject, text })).catch(() => {}); } catch (_) {} };
  const mailDid = (did, subject, text) => { const w = db.prepare('SELECT email FROM identity_wallets WHERE did = ?').get(did); if (w) mail(w.email, subject, text); };
  function expireOld() {
    db.prepare("UPDATE email_pairings SET status = 'expired', decided_at = ?, code = NULL WHERE status IN ('sent','joined') AND expires_at <= ?").run(nowIso(), nowIso());
  }

  // A person's own sign-in with a PIN set (as pairing.js). → { auth, wallet } or null (answered).
  function personAuth(req, res) {
    const auth = getBearerIdentity(req);
    if (!auth.ok) { res.status(auth.status || 401).json({ error: auth.error, ...(auth.code ? { code: auth.code } : {}) }); return null; }
    if (auth.silicon || (auth.decoded && (auth.decoded.wrk || auth.decoded.auth_method === 'fleet_owner_mint' || auth.decoded.auth_method === 'worker'))) {
      res.status(403).json({ error: "pairing needs the wallet's own sign-in" }); return null;
    }
    const wallet = db.prepare('SELECT did, username, email, recovery_email, status, pin_hash FROM identity_wallets WHERE did = ?').get(auth.did);
    if (!wallet) { res.status(404).json({ error: 'no wallet for this token' }); return null; }
    if (wallet.status !== 'active') { res.status(403).json({ error: 'account suspended' }); return null; }
    if (isAgent(wallet.did)) { res.status(403).json({ error: 'an agent wallet does not pair; its fleet owner gives it secrets' }); return null; }
    if (!wallet.pin_hash) { res.status(403).json({ error: 'set your vault PIN first: confirming a contact takes it', pin_required: true }); return null; }
    return { auth, wallet };
  }
  function viewFor(row, me) {
    const inviter = row.inviter_did === me;
    return {
      pair_id: row.id, kind: 'email-code', status: row.status, role: inviter ? 'inviter' : 'joiner',
      to: inviter ? mask(row.to_email) : null,
      other: inviter ? (row.joiner_did ? name(row.joiner_did) : null) : name(row.inviter_did),
      // Who A meant, and whether the wallet that opened it is that one (#75 review): by username it must be; by address
      // A is told whether the opener's own address(es) are the one the link went to.
      ...(inviter ? { sent_to_user: row.target_did ? name(row.target_did) : null,
        opener_matches_address: row.joiner_did && !row.target_did ? Boolean(row.opener_matches) : null } : {}),
      // Only B's screen shows the code; A types it.
      code: !inviter && row.status === 'joined' ? row.code : null,
      type_code: inviter && row.status === 'joined',
      code_tries_left: inviter ? Math.max(0, MAX_CODE_TRIES - (row.wrong_codes || 0)) : null,
      intent: `pair:${row.id}`, bind_prefix: inviter && row.joiner_did ? `${name(row.joiner_did)}|` : null,
      expires_at: row.expires_at,
    };
  }
  function rowFor(req, res, me) {
    const id = Number(req.params.id);
    const row = Number.isInteger(id) && id > 0 ? db.prepare('SELECT * FROM email_pairings WHERE id = ?').get(id) : null;
    if (!row || (row.inviter_did !== me && row.joiner_did !== me)) { res.status(404).json({ error: 'pairing not found' }); return null; }
    return row;
  }

  // ── A: send a link ─────────────────────────────────────────────────────────────────────────────────────────────
  app.post('/api/network/pair/email', rateLimitStandard, (req, res) => {
    const p = personAuth(req, res); if (!p) return;
    expireOld();
    const raw = String((req.body || {}).to || '').trim();
    if (!raw || raw.length > 254) return res.status(400).json({ error: 'to: an email address, or the username of a contact' });
    let to = null, target = null;
    if (raw.includes('@') || /[<>,;"]/.test(raw)) {
      to = bareMailbox(raw);
      if (!to) return res.status(400).json({ error: 'to: one plain email address (no name, no list), or the username of a person' });
    } else {
      target = db.prepare('SELECT did, username, email, status FROM identity_wallets WHERE username = ?').get(raw.toLowerCase());
      if (!target || target.status !== 'active' || !target.email) return res.status(404).json({ error: 'no wallet by that name with an address to send to — give an email address instead' });
      if (isAgent(target.did)) return res.status(403).json({ error: 'that is an agent wallet: people only' });
      to = bareMailbox(target.email);
      if (!to) return res.status(409).json({ error: 'that wallet has no plain address to send to — give an email address instead' });
    }
    const canon = cap.canonicalAddress(to);
    const mine = [p.wallet.email, p.wallet.recovery_email].filter(Boolean).map(e => cap.canonicalAddress(e));
    if ((target && target.did === p.wallet.did) || mine.includes(canon)) return res.status(400).json({ error: 'that is your own address' });
    const dayAgo = new Date(Date.now() - 86400000).toISOString();
    if (db.prepare('SELECT COUNT(*) AS n FROM email_pairings WHERE inviter_did = ? AND created_at > ?').get(p.wallet.did, dayAgo).n >= MAX_PER_SENDER_DAY) {
      return res.status(429).json({ error: `at most ${MAX_PER_SENDER_DAY} pairing links a day` });
    }
    const open = db.prepare("SELECT COUNT(*) AS n FROM email_pairings WHERE inviter_did = ? AND status IN ('sent','joined')").get(p.wallet.did).n;
    if (open >= MAX_OPEN) return res.status(429).json({ error: `at most ${MAX_OPEN} links open at once — finish or cancel one` });
    const recent = db.prepare('SELECT COUNT(*) AS n FROM email_pairings WHERE to_canon = ? AND created_at > ?').get(canon, dayAgo).n;
    if (recent >= MAX_PER_ADDRESS_DAY) return res.status(429).json({ error: 'that address has had enough pairing links today' });
    if (db.prepare('SELECT COUNT(*) AS n FROM email_pairings WHERE to_canon = ? AND inviter_did = ? AND created_at > ?').get(canon, p.wallet.did, dayAgo).n >= MAX_PER_PAIR_DAY) {
      return res.status(429).json({ error: `at most ${MAX_PER_PAIR_DAY} pairing links a day to one address` });
    }
    const secret = crypto.randomBytes(16).toString('base64url');
    let id = 0;
    for (let i = 0; i < 8 && !id; i++) {
      const cand = 100000000000 + crypto.randomInt(0, 899999999999);
      // The PIN intent is pair:<id>, shared with QR pairings: never reuse an id either kind holds.
      if (db.prepare('SELECT 1 FROM contact_pairings WHERE id = ?').get(cand)) continue;
      try { db.prepare('INSERT INTO email_pairings (id, inviter_did, to_email, to_canon, target_did, secret_hash, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)').run(cand, p.wallet.did, to, canon, target ? target.did : null, sha(secret), nowIso(), later(TTL_SEC)); id = cand; }
      catch (e) { if (!/UNIQUE|PRIMARY/.test(e.message)) throw e; }
    }
    if (!id) return res.status(503).json({ error: 'could not start a pairing; try again' });
    const link = `${base}/vault-mobile.html#epair=${id}.${secret}`;
    mail(to, `DemiPass: ${p.wallet.username} wants to confirm you as a contact`,
      `${p.wallet.username} asked DemiPass to confirm you as a contact.\n\n` +
      `1. Open this link signed in to YOUR OWN DemiPass wallet (it works once, for 30 minutes):\n${link}\n\n` +
      `2. It shows you a 6-digit code. Tell it to ${p.wallet.username} yourself — by phone or in person, never by email or chat.\n` +
      `3. ${p.wallet.username} types it in their app, and you are confirmed contacts.\n\n` +
      `If you do not know ${p.wallet.username}, or did not expect this, ignore it: nothing happens unless you open the link and give them the code.\n`);
    log(`email pairing ${id}: ${p.wallet.username} → ${mask(to)}`);
    res.status(201).json({ ok: true, ...viewFor(db.prepare('SELECT * FROM email_pairings WHERE id = ?').get(id), p.wallet.did),
      next: `a link is on its way to ${mask(to)}. When they open it, they see a 6-digit code: they tell it to you, and you type it here.` });
  });

  // ── B: open the link (signed in, with B's PIN) → B's screen shows the code ─────────────────────────────────────
  app.post('/api/network/pair/email/join', rateLimitStandard, (req, res) => {
    const p = personAuth(req, res); if (!p) return;
    let raw = String((req.body || {}).token || '').trim();
    const at = raw.indexOf('epair='); if (at >= 0) raw = raw.slice(at + 6);
    const m = raw.match(TOKEN_RE);
    if (!m) return res.status(400).json({ error: 'token: the code from the pairing link' });
    expireOld();
    const hourAgo = new Date(Date.now() - 3600000).toISOString();
    db.prepare('DELETE FROM contact_pairing_misses WHERE at < ?').run(hourAgo);
    const misses = db.prepare('SELECT COUNT(*) AS n FROM contact_pairing_misses WHERE did = ? AND at >= ?').get(p.wallet.did, hourAgo).n;
    if (misses >= MAX_WRONG_PER_HOUR) return res.status(429).json({ error: 'too many wrong pairing links from this wallet — try again in an hour' });
    const row = db.prepare('SELECT * FROM email_pairings WHERE id = ?').get(Number(m[1]));
    const presented = Buffer.from(sha(m[2]), 'hex'), stored = row ? Buffer.from(row.secret_hash, 'hex') : Buffer.alloc(0);
    if (!row || presented.length !== stored.length || !crypto.timingSafeEqual(presented, stored)) {
      db.prepare('INSERT INTO contact_pairing_misses (did, at) VALUES (?, ?)').run(p.wallet.did, nowIso());
      return res.status(404).json({ error: 'this pairing link is not valid — ask them to send a new one' });
    }
    if (row.inviter_did === p.wallet.did) return res.status(400).json({ error: 'that is your own pairing link' });
    if (row.status === 'joined' && row.joiner_did === p.wallet.did) return res.json({ ok: true, ...viewFor(row, p.wallet.did) });   // reopened: same code
    if (row.status !== 'sent') return res.status(409).json({ error: row.status === 'joined' ? 'this link was already opened by another wallet — ask them to cancel it and send a new one' : `this link is ${row.status}` });
    // Sent to a username: only that wallet opens it (#75 review — a forwarded link is no way in for anyone else).
    if (row.target_did && row.target_did !== p.wallet.did) return res.status(409).json({ error: `this link is for ${name(row.target_did)}'s wallet: sign in as ${name(row.target_did)} to open it` });
    // B's own PIN binds B's wallet: a session token alone (a stolen one) cannot pair B to anyone.
    const intent = `pair:${row.id}`;
    if (!gateFresh(p.wallet.did, 'pin', p.auth, intent)) return res.status(403).json({ ...gateMissing('pair', ['pin'], ['pin'], intent), error: `confirming ${name(row.inviter_did)} as a contact needs your PIN` });
    let joined = null;
    try {
      db.transaction(() => {
        const spent = spendSingleUse(p.wallet.did, 'pair', ['pin'], p.auth, intent);
        if (spent) throw Object.assign(new Error(spent.error), { statusCode: spent.status || 403, body: spent });
        const code = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
        // Only the address DemiPass issued: a recovery email is set unverified, so it would let a forwarded-link holder
        // switch A's mismatch warning off (#75 re-review).
        const own = [p.wallet.email].filter(Boolean).map(e => cap.canonicalAddress(e));
        const n = db.prepare("UPDATE email_pairings SET joiner_did = ?, code = ?, status = 'joined', joined_at = ?, expires_at = ?, opener_matches = ? WHERE id = ? AND status = 'sent' AND expires_at > ?")
          .run(p.wallet.did, code, nowIso(), later(JOINED_TTL_SEC), own.includes(row.to_canon) ? 1 : 0, row.id, nowIso()).changes;
        if (n !== 1) throw Object.assign(new Error('this link was opened meanwhile, or expired'), { statusCode: 409 });
        joined = db.prepare('SELECT * FROM email_pairings WHERE id = ?').get(row.id);
      }).immediate();
    } catch (e) { return res.status(e.statusCode || 500).json(e.body || { error: e.message }); }
    log(`email pairing ${row.id}: opened by ${p.wallet.username}`);
    res.json({ ok: true, ...viewFor(joined, p.wallet.did),
      next: `tell ${name(row.inviter_did)} this code yourself (a call, in person), never by email or chat; they type it in their app` });
  });

  // ── either side: list / state ──────────────────────────────────────────────────────────────────────────────────
  app.get('/api/network/pair/email', rateLimitStandard, (req, res) => {
    const auth = getBearerIdentity(req);
    if (!auth.ok) return res.status(auth.status || 401).json({ error: auth.error, ...(auth.code ? { code: auth.code } : {}) });
    expireOld();
    const rows = db.prepare("SELECT * FROM email_pairings WHERE (inviter_did = ? OR joiner_did = ?) AND status IN ('sent','joined') ORDER BY created_at DESC LIMIT 20").all(auth.did, auth.did);
    res.json({ ok: true, pairings: rows.map(r => viewFor(r, auth.did)) });
  });
  app.get('/api/network/pair/email/:id', rateLimitStandard, (req, res) => {
    const auth = getBearerIdentity(req);
    if (!auth.ok) return res.status(auth.status || 401).json({ error: auth.error, ...(auth.code ? { code: auth.code } : {}) });
    expireOld();
    const row = rowFor(req, res, auth.did); if (!row) return;
    res.json({ ok: true, ...viewFor(row, auth.did) });
  });

  // ── A: type the code B read out ────────────────────────────────────────────────────────────────────────────────
  app.post('/api/network/pair/email/:id/confirm', rateLimitStandard, (req, res) => {
    const p = personAuth(req, res); if (!p) return;
    expireOld();
    const me = p.wallet.did;
    const row = rowFor(req, res, me); if (!row) return;
    if (row.inviter_did !== me) return res.status(403).json({ error: 'the person who sent the link types the code' });
    if (row.status !== 'joined') return res.status(409).json({ error: row.status === 'sent' ? 'they have not opened the link yet' : `this pairing is ${row.status}`, ...viewFor(row, me) });
    const other = name(row.joiner_did);
    // The code first: no later answer (PIN, phone) may name it.
    const typed = String((req.body || {}).code || '').replace(/\s+/g, '');
    if (!/^\d{6}$/.test(typed)) return res.status(400).json({ error: `type the 6-digit code ${other} reads to you`, type_code: true });
    const a = Buffer.from(typed), b = Buffer.from(String(row.code));
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
      const tries = db.prepare('UPDATE email_pairings SET wrong_codes = wrong_codes + 1 WHERE id = ? RETURNING wrong_codes').get(row.id).wrong_codes;
      if (tries >= MAX_CODE_TRIES) {
        db.prepare("UPDATE email_pairings SET status = 'cancelled', decided_at = ?, cancelled_by = 'wrong-code', code = NULL WHERE id = ? AND status = 'joined'").run(nowIso(), row.id);
        logSecurityEvent('pairing_code_mismatch', 'alert', { caller_did: me, capability: 'pair-email', target: String(row.id), ip: req.ip, error: 'wrong code typed 3 times' });
        return res.status(403).json({ error: `that is not the code ${other}'s screen shows — the pairing is cancelled; send a new link`, status: 'cancelled' });
      }
      return res.status(403).json({ error: `that is not the code ${other}'s screen shows`, code_tries_left: MAX_CODE_TRIES - tries });
    }
    const intent = `pair:${row.id}`;
    if (!gateFresh(me, 'pin', p.auth, intent)) return res.status(403).json({ ...gateMissing('pair', ['pin'], ['pin'], intent), error: 'confirming a contact needs your PIN' });
    const dk = deps.devices && deps.devices();
    const refused = dk ? dk.approvalRefusal(p.auth, 'pair', row.id, `${other}|${row.code}`, req.body) : null;
    if (refused) return res.status(refused.status).json(refused.body);
    try {
      db.transaction(() => {
        const spent = spendSingleUse(me, 'pair', ['pin'], p.auth, intent);
        if (spent) throw Object.assign(new Error(spent.error), { statusCode: spent.status || 403, body: spent });
        const jb = db.prepare('SELECT status FROM identity_wallets WHERE did = ?').get(row.joiner_did);
        if (!jb || jb.status !== 'active' || isAgent(row.joiner_did)) throw Object.assign(new Error(`${other} can no longer be paired (not an active person)`), { statusCode: 409 });
        const n = db.prepare("UPDATE email_pairings SET status = 'confirmed', decided_at = ?, code = NULL WHERE id = ? AND status = 'joined' AND expires_at > ?").run(nowIso(), row.id, nowIso()).changes;
        if (n !== 1) throw Object.assign(new Error('this pairing changed meanwhile'), { statusCode: 409 });
        const [x, y] = pairDids(row.inviter_did, row.joiner_did);
        // A contact (made now if there is none). A link already confirmed in person or by a vouch keeps that stronger mark.
        db.prepare(`INSERT INTO network_peers (did_a, did_b, request_id, verified_via, verified_at) VALUES (?, ?, NULL, 'email-code', ?)
                    ON CONFLICT(did_a, did_b) DO UPDATE SET status = 'active', removed_at = NULL,
                      verified_via = CASE WHEN network_peers.status = 'active' AND network_peers.verified_via IN ('qr','vouch') THEN network_peers.verified_via ELSE 'email-code' END,
                      verified_at = CASE WHEN network_peers.status = 'active' AND network_peers.verified_via IN ('qr','vouch') THEN network_peers.verified_at ELSE excluded.verified_at END,
                      vouched_by = CASE WHEN network_peers.status = 'active' AND network_peers.verified_via = 'vouch' THEN network_peers.vouched_by ELSE NULL END`)
          .run(x, y, nowIso());
      }).immediate();
    } catch (e) { return res.status(e.statusCode || 500).json(e.body || { error: e.message }); }
    const done = db.prepare('SELECT * FROM email_pairings WHERE id = ?').get(row.id);
    const me_name = p.wallet.username;
    mailDid(row.inviter_did, `DemiPass: ${other} is now a confirmed contact`, `You confirmed ${other} as a contact by email code. You can send each other DD.\nIf this was not you, remove ${other} in DemiPass → Fleet → People and change your PIN.\n`);
    mailDid(row.joiner_did, `DemiPass: ${me_name} is now a confirmed contact`, `${me_name} typed the code you gave them: you are confirmed contacts and can send each other DD.\nIf you did not give anyone a code, remove ${me_name} in DemiPass → Fleet → People.\n`);
    logSecurityEvent('pairing_email_confirmed', 'info', { caller_did: me, capability: 'pair-email', target: String(row.id), context: { other_did: row.joiner_did } });
    log(`email pairing ${row.id}: ${me_name} ⇄ ${other} confirmed`);
    res.json({ ok: true, ...viewFor(done, me), connected: true, next: `${other} is a confirmed contact (by email code): DD and contacts; shares still need pairing in person` });
  });

  // ── either side: cancel ────────────────────────────────────────────────────────────────────────────────────────
  app.post('/api/network/pair/email/:id/cancel', rateLimitStandard, (req, res) => {
    const auth = getBearerIdentity(req);
    if (!auth.ok) return res.status(auth.status || 401).json({ error: auth.error, ...(auth.code ? { code: auth.code } : {}) });
    const row = rowFor(req, res, auth.did); if (!row) return;
    const n = db.prepare("UPDATE email_pairings SET status = 'cancelled', decided_at = ?, cancelled_by = ?, code = NULL WHERE id = ? AND status IN ('sent','joined')").run(nowIso(), auth.did, row.id).changes;
    if (n !== 1) return res.status(409).json({ error: `this pairing is ${db.prepare('SELECT status FROM email_pairings WHERE id = ?').get(row.id).status}` });
    res.json({ ok: true, ...viewFor(db.prepare('SELECT * FROM email_pairings WHERE id = ?').get(row.id), auth.did) });
  });
};
