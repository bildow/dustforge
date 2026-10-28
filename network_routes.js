'use strict';
// ── Network: connect wallets, bring agents into a fleet, send DD to connections.
// Registered from server.js: require('./network_routes')({ app, db, ... }). Contract: docs/network.md.
//
// Any wallet can ask any other wallet to connect, by username, email or DID. Three kinds of request:
//   person  — a peer contact (two people, or any two wallets). Either side can send the other DD.
//   agent   — "join my fleet": the target becomes a silicon in the requester's fleet.
//   join    — "let me join your fleet": the requester becomes a silicon in the target's fleet.
// Only the target decides. Joining a fleet hands its owner the fleet powers over the member (mint its tokens,
// refill it, delegate secrets to it), so a member who has a vault PIN accepts an `agent` request with the PIN.
// Sending DD is two steps: create the transfer (amount + recipient fixed), then confirm it with the PIN
// (intent send:<id>). A wallet with no PIN (an agent) confirms without one, like /api/wallet/transfer.
// An agent short of DD asks its fleet owner for a top-up (amount + why). The owner answers by sending DD (any
// confirmed send from the owner to the agent closes the ask) or declines it.

const REQUEST_TTL_DAYS = 14;
const TRANSFER_TTL_SEC = 300;
const MAX_OUTGOING = 20;          // pending requests one wallet may have out
const MAX_INCOMING = 50;          // pending requests one wallet may be sent
const MAX_PENDING_TRANSFERS = 10;
const MAX_TRANSFER = 1000000;     // same cap as /api/wallet/transfer
const NEW_FLEET_MAX_AGENTS = 25;
const KINDS = new Set(['person', 'agent', 'join']);
const REASK_COOLDOWN_HOURS = 24;  // after a decline or withdraw, the same wallet asks the same wallet again only after this
const TOPUP_TTL_DAYS = 7;
const TOPUP_DECLINE_COOLDOWN_HOURS = 1;  // after the owner declines, the agent asks again only after this
const TOPUP_MAX_PER_DAY = 5;             // asks per agent per 24 h (each one mails the owner)

module.exports = function registerNetworkRoutes(deps) {
  const { app, db, billing, fleetBilling: fb, rateLimitStandard, getBearerIdentity, gateSession, gateFresh, gateMissing,
          spendSingleUse, barrelGuardedTransfer, transferRefusal, sendMail } = deps;
  const log = deps.log || ((...a) => console.log('[network]', ...a));

  db.exec(`CREATE TABLE IF NOT EXISTS network_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL CHECK(kind IN ('person','agent','join')),
    requester_did TEXT NOT NULL,
    target_did TEXT NOT NULL,
    handle TEXT DEFAULT '',
    note TEXT DEFAULT '',
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    expires_at TEXT NOT NULL,
    decided_at TEXT DEFAULT NULL
  )`);
  db.exec('CREATE INDEX IF NOT EXISTS idx_nr_target ON network_requests(target_did, status)');
  db.exec('CREATE INDEX IF NOT EXISTS idx_nr_requester ON network_requests(requester_did, status)');
  // Peer contacts. A pair is stored once, did_a < did_b. Fleet links are not stored here: they are fleet_silicons.
  db.exec(`CREATE TABLE IF NOT EXISTS network_peers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    did_a TEXT NOT NULL,
    did_b TEXT NOT NULL,
    request_id INTEGER,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    removed_at TEXT DEFAULT NULL,
    UNIQUE(did_a, did_b)
  )`);
  db.exec(`CREATE TABLE IF NOT EXISTS network_transfers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    from_did TEXT NOT NULL,
    to_did TEXT NOT NULL,
    amount_cents INTEGER NOT NULL,
    note TEXT DEFAULT '',
    session TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    expires_at TEXT NOT NULL,
    decided_at TEXT DEFAULT NULL,
    error TEXT DEFAULT ''
  )`);
  db.exec('CREATE INDEX IF NOT EXISTS idx_nt_from ON network_transfers(from_did, status)');
  db.exec(`CREATE TABLE IF NOT EXISTS network_topups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_did TEXT NOT NULL,
    owner_did TEXT NOT NULL,
    amount_cents INTEGER NOT NULL,
    note TEXT DEFAULT '',
    status TEXT NOT NULL DEFAULT 'pending',
    sent_cents INTEGER DEFAULT NULL,
    transfer_id INTEGER DEFAULT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    expires_at TEXT NOT NULL,
    decided_at TEXT DEFAULT NULL
  )`);
  db.exec('CREATE INDEX IF NOT EXISTS idx_ntu_owner ON network_topups(owner_did, status)');
  db.exec('CREATE INDEX IF NOT EXISTS idx_ntu_agent ON network_topups(agent_did, status)');

  // ── helpers ───────────────────────────────────────────────────────────────
  const nowIso = () => new Date().toISOString();
  const later = sec => new Date(Date.now() + sec * 1000).toISOString();
  const expired = row => !row.expires_at || Date.parse(row.expires_at) <= Date.now();
  const pair = (x, y) => (x < y ? [x, y] : [y, x]);
  const cleanText = (s, n) => String(s == null ? '' : s).replace(/[\u0000-\u001f\u007f​-‏‪-‮⁦-⁩﻿]/g, '').trim().slice(0, n);

  // The caller: a person's or an agent's own wallet token. Silicon tokens (silicon:… act for their carbon) and
  // worker tokens cannot connect wallets, move DD or decide requests.
  function walletAuth(req, res) {
    const auth = getBearerIdentity(req);
    if (!auth.ok) { res.status(auth.status || 401).json({ error: auth.error }); return null; }
    if (auth.silicon || (auth.decoded && auth.decoded.wrk)) { res.status(403).json({ error: "only a wallet's own token can use the network" }); return null; }
    const wallet = db.prepare('SELECT did, username, email, status, pin_hash FROM identity_wallets WHERE did = ?').get(auth.did);
    if (!wallet) { res.status(404).json({ error: 'no wallet for this token' }); return null; }
    if (wallet.status !== 'active') { res.status(403).json({ error: 'account suspended' }); return null; }
    // A token a fleet owner minted for this wallet acts as the wallet, but does not decide fleet membership for it.
    const minted = Boolean(auth.decoded && auth.decoded.auth_method === 'fleet_owner_mint');
    return { auth, wallet, minted };
  }
  function findWallet(q) {
    const s = String(q || '').trim();
    if (!s) return null;
    const v = s.toLowerCase();
    return db.prepare("SELECT did, username, email, status FROM identity_wallets WHERE did = ? OR username = ? OR email = ?").get(s, v, v)
      || (v.includes('@') ? null : db.prepare('SELECT did, username, email, status FROM identity_wallets WHERE email = ?').get(v + '@dustforge.com'));
  }
  function walletName(did) {
    const w = db.prepare('SELECT username FROM identity_wallets WHERE did = ?').get(did);
    return w ? w.username : null;
  }
  function ownedFleet(did) {
    return db.prepare("SELECT * FROM fleets WHERE owner_did = ? AND status = 'active' ORDER BY id LIMIT 1").get(did);
  }
  // The fleet a wallet is an active silicon of, if any (a wallet is a silicon of at most one fleet).
  function memberFleet(did) {
    return db.prepare(`SELECT f.*, s.handle FROM fleet_silicons s JOIN fleets f ON f.id = s.fleet_id
                       WHERE s.member_did = ? AND s.status = 'active' AND f.status = 'active'`).get(did);
  }
  function isPeer(x, y) {
    const [a, b] = pair(x, y);
    return Boolean(db.prepare("SELECT 1 FROM network_peers WHERE did_a = ? AND did_b = ? AND status = 'active'").get(a, b));
  }
  // Is `y` one of `x`'s connections: a peer, an agent in x's fleet, or the owner of the fleet x is in?
  function connected(x, y) {
    if (isPeer(x, y)) return 'person';
    const mf = memberFleet(y);
    if (mf && mf.owner_did === x) return 'agent';
    const myFleet = memberFleet(x);
    if (myFleet && myFleet.owner_did === y) return 'fleet_owner';
    return null;
  }
  function defaultHandle(username) {
    const h = String(username || '').toLowerCase().replace(/[^a-z0-9-]/g, '-').replace(/^-+/, '').slice(0, 31);
    return fb.HANDLE_RE.test(h) ? h : 'agent';
  }
  // A handle no other silicon row of the fleet holds (removed rows keep theirs: handles are unique per fleet).
  function freeHandle(fleetId, wanted, memberDid) {
    const taken = h => db.prepare('SELECT 1 FROM fleet_silicons WHERE fleet_id = ? AND handle = ? AND member_did != ?').get(fleetId, h, memberDid);
    if (!taken(wanted)) return wanted;
    for (let i = 2; i < 100; i++) {
      const h = wanted.slice(0, 31 - String(i).length - 1) + '-' + i;
      if (!taken(h)) return h;
    }
    throw Object.assign(new Error('no free handle in that fleet'), { statusCode: 409 });
  }
  // The owner's fleet, created on the first agent that joins it.
  function ensureFleet(ownerDid) {
    const f = ownedFleet(ownerDid);
    if (f) {
      db.prepare("INSERT OR IGNORE INTO fleet_members (fleet_id, member_did, role) VALUES (?, ?, 'owner')").run(f.id, ownerDid);
      return f;
    }
    const username = walletName(ownerDid) || 'wallet';
    let slug = username.replace(/[^a-z0-9-]/g, '-').replace(/^-+|-+$/g, '').slice(0, 40);
    if (slug.length < 3) slug = (slug + '-fleet').replace(/^-+/, '');
    for (let i = 1; db.prepare('SELECT 1 FROM fleets WHERE slug = ?').get(slug); i++) slug = slug.replace(/-\d+$/, '') + '-' + (i + 1);
    const id = db.prepare('INSERT INTO fleets (owner_did, name, slug, max_agents) VALUES (?, ?, ?, ?)')
      .run(ownerDid, `${username}'s fleet`, slug, NEW_FLEET_MAX_AGENTS).lastInsertRowid;
    db.prepare("INSERT OR IGNORE INTO fleet_members (fleet_id, member_did, role) VALUES (?, ?, 'owner')").run(id, ownerDid);
    log(`created fleet ${slug} for ${username}`);
    return db.prepare('SELECT * FROM fleets WHERE id = ?').get(id);
  }
  // Who owns the fleet and who joins it, for a fleet request.
  function fleetSides(r) {
    if (r.kind === 'agent') return { owner: r.requester_did, member: r.target_did };
    if (r.kind === 'join') return { owner: r.target_did, member: r.requester_did };
    return null;
  }
  // Why this pair cannot make or take this request now, or null.
  function blocker(kind, requesterDid, targetDid) {
    if (kind === 'person') return isPeer(requesterDid, targetDid) ? 'you are already connected' : null;
    const { owner, member } = fleetSides({ kind, requester_did: requesterDid, target_did: targetDid });
    const mf = memberFleet(member);
    if (mf && mf.owner_did === owner) return 'already in that fleet';
    if (mf) return 'that wallet is already an agent in another fleet; it has to leave it first';
    if (memberFleet(owner)) return 'a wallet that is an agent in a fleet cannot take agents';
    if (fb.ownsFleetWithAgents(db, member)) return 'a wallet that runs its own fleet of agents cannot join one';
    return null;
  }
  function requestView(r, me) {
    const other = r.requester_did === me ? r.target_did : r.requester_did;
    const sides = fleetSides(r);
    return {
      id: r.id, kind: r.kind, direction: r.requester_did === me ? 'outgoing' : 'incoming',
      from: walletName(r.requester_did), from_did: r.requester_did, to: walletName(r.target_did), to_did: r.target_did,
      other: walletName(other), other_did: other,
      // What accepting means for the one who decides, in plain words.
      effect: r.kind === 'person' ? 'You become contacts and can send each other DD.'
        : (sides.member === me
          ? `You join ${walletName(sides.owner)}'s fleet as an agent. ${walletName(sides.owner)} can then see this wallet's balance and spend, refill it, give it secrets to use, and you can send each other DD. Your wallet keeps its own key.`
          : `${walletName(sides.member)} joins your fleet as an agent. You can then see its balance and spend, refill it, give it secrets to use, and send each other DD. It keeps its own key: it signs in itself.`),
      needs_pin: r.kind !== 'person' && sides.member === r.target_did && r.target_did === me && Boolean(db.prepare('SELECT pin_hash FROM identity_wallets WHERE did = ?').get(me)?.pin_hash),
      intent: `join:${r.id}`,
      handle: r.handle || '', note: r.note || '', status: r.status, created_at: r.created_at, expires_at: r.expires_at,
    };
  }
  function expireOld() {
    db.prepare("UPDATE network_requests SET status = 'expired', decided_at = CURRENT_TIMESTAMP WHERE status = 'pending' AND expires_at <= ?").run(nowIso());
    db.prepare("UPDATE network_transfers SET status = 'expired', decided_at = CURRENT_TIMESTAMP WHERE status = 'pending' AND expires_at <= ?").run(nowIso());
    db.prepare("UPDATE network_topups SET status = 'expired', decided_at = CURRENT_TIMESTAMP WHERE status = 'pending' AND expires_at <= ?").run(nowIso());
    // An ask outlives no membership: the agent left or was removed, or the fleet closed.
    db.prepare(`UPDATE network_topups SET status = 'cancelled', decided_at = CURRENT_TIMESTAMP WHERE status = 'pending' AND NOT EXISTS
                (SELECT 1 FROM fleet_silicons s JOIN fleets f ON f.id = s.fleet_id WHERE s.member_did = network_topups.agent_did
                 AND s.status = 'active' AND f.status = 'active' AND f.owner_did = network_topups.owner_did)`).run();
  }
  function topupView(t, me) {
    return { id: t.id, direction: t.agent_did === me ? 'outgoing' : 'incoming',
             agent: walletName(t.agent_did), agent_did: t.agent_did, owner: walletName(t.owner_did), owner_did: t.owner_did,
             handle: (db.prepare("SELECT handle FROM fleet_silicons WHERE member_did = ? AND status = 'active'").get(t.agent_did) || {}).handle || null,
             amount_cents: t.amount_cents, note: t.note || '', status: t.status, sent_cents: t.sent_cents,
             agent_balance_cents: billing.getDerivedBalance(db, t.agent_did), created_at: t.created_at, expires_at: t.expires_at };
  }
  function fail(res, e) {
    return res.status(e.statusCode || 500).json(e.body || { error: e.message });
  }

  // ── Overview: connections, requests, my fleet role ────────────────────────
  app.get('/api/network', rateLimitStandard, (req, res) => {
    const w = walletAuth(req, res); if (!w) return;
    const me = w.wallet.did;
    expireOld();
    const peers = db.prepare("SELECT * FROM network_peers WHERE (did_a = ? OR did_b = ?) AND status = 'active' ORDER BY id").all(me, me)
      .map(p => { const did = p.did_a === me ? p.did_b : p.did_a; return { kind: 'person', did, username: walletName(did), since: p.created_at }; });
    const fleet = ownedFleet(me);
    const agents = fleet ? db.prepare("SELECT * FROM fleet_silicons WHERE fleet_id = ? AND status = 'active' ORDER BY handle").all(fleet.id)
      .map(s => ({ kind: 'agent', did: s.member_did, username: walletName(s.member_did), handle: s.handle, display_name: s.display_name,
                   balance_cents: billing.getDerivedBalance(db, s.member_did), since: s.created_at })) : [];
    const mf = memberFleet(me);
    const requests = db.prepare("SELECT * FROM network_requests WHERE (target_did = ? OR requester_did = ?) AND status = 'pending' ORDER BY id DESC").all(me, me)
      .map(r => requestView(r, me));
    res.json({
      ok: true,
      me: { did: me, username: w.wallet.username, pin_set: Boolean(w.wallet.pin_hash), balance_cents: billing.getDerivedBalance(db, me) },
      fleet: fleet ? { slug: fleet.slug, name: fleet.name } : null,
      member_of: mf ? { slug: mf.slug, name: mf.name, owner: walletName(mf.owner_did), owner_did: mf.owner_did, handle: mf.handle } : null,
      people: peers, agents,
      incoming: requests.filter(r => r.direction === 'incoming'),
      outgoing: requests.filter(r => r.direction === 'outgoing'),
      // Top-up asks: from my agents (incoming), and mine to my fleet owner (outgoing).
      topups: {
        incoming: db.prepare("SELECT * FROM network_topups WHERE owner_did = ? AND status = 'pending' ORDER BY id DESC").all(me).map(t => topupView(t, me)),
        outgoing: db.prepare("SELECT * FROM network_topups WHERE agent_did = ? AND status = 'pending' ORDER BY id DESC").all(me).map(t => topupView(t, me)),
      },
    });
  });

  // ── Ask to connect ────────────────────────────────────────────────────────
  // body: { to: username | email | did, as: 'person' | 'agent' | 'join', handle?, note? }
  app.post('/api/network/requests', rateLimitStandard, (req, res) => {
    const w = walletAuth(req, res); if (!w) return;
    const me = w.wallet.did;
    const b = req.body || {};
    const kind = String(b.as || '');
    if (!KINDS.has(kind)) return res.status(400).json({ error: "as: 'person' (a contact), 'agent' (join my fleet) or 'join' (let me join your fleet)" });
    const target = findWallet(b.to);
    if (!target || target.status !== 'active') return res.status(404).json({ error: 'no wallet by that name' });
    if (target.did === me) return res.status(400).json({ error: 'that is your own wallet' });
    if (kind !== 'person' && w.minted) return res.status(403).json({ error: 'a fleet-minted token cannot change fleet membership; sign in as this wallet' });
    // A `join` request hands the asker to the target's fleet with no step on the asker's side after this one, so
    // it is for wallets with no PIN (agents). A wallet with a PIN asks the owner to invite it and accepts with the PIN.
    if (kind === 'join' && w.wallet.pin_hash) {
      return res.status(403).json({ error: 'this wallet has a PIN: ask the fleet owner to add you as an agent, then accept with your PIN' });
    }
    const note = cleanText(b.note, 200);
    let handle = '';
    if (kind !== 'person') {
      const memberName = kind === 'agent' ? target.username : w.wallet.username;
      handle = b.handle ? String(b.handle).trim().toLowerCase() : defaultHandle(memberName);
      if (!fb.HANDLE_RE.test(handle)) return res.status(400).json({ error: 'handle: 2-31 chars, lowercase letters, digits and hyphens' });
    }
    expireOld();
    const why = blocker(kind, me, target.did);
    if (why) return res.status(409).json({ error: why });
    // One open request per pair at a time, whichever way it points (the other side's request can just be accepted).
    const open = db.prepare(`SELECT * FROM network_requests WHERE status = 'pending' AND
                             ((requester_did = ? AND target_did = ?) OR (requester_did = ? AND target_did = ?))`).get(me, target.did, target.did, me);
    if (open) {
      return res.status(409).json({ error: open.requester_did === me ? 'you already asked; it is waiting for them' : `${target.username} already asked you; accept their request instead`,
                                    request: requestView(open, me) });
    }
    const recent = db.prepare(`SELECT decided_at FROM network_requests WHERE requester_did = ? AND target_did = ? AND status IN ('declined', 'withdrawn')
                               AND decided_at > datetime('now', ?) ORDER BY id DESC LIMIT 1`).get(me, target.did, `-${REASK_COOLDOWN_HOURS} hours`);
    if (recent) return res.status(429).json({ error: `you asked this wallet recently; ask again after ${REASK_COOLDOWN_HOURS} hours` });
    if (db.prepare("SELECT COUNT(*) AS n FROM network_requests WHERE requester_did = ? AND status = 'pending'").get(me).n >= MAX_OUTGOING) {
      return res.status(429).json({ error: `at most ${MAX_OUTGOING} requests can wait at once; withdraw one first` });
    }
    if (db.prepare("SELECT COUNT(*) AS n FROM network_requests WHERE target_did = ? AND status = 'pending'").get(target.did).n >= MAX_INCOMING) {
      return res.status(429).json({ error: `${target.username} has too many requests waiting` });
    }
    const id = db.prepare('INSERT INTO network_requests (kind, requester_did, target_did, handle, note, expires_at) VALUES (?, ?, ?, ?, ?, ?)')
      .run(kind, me, target.did, handle, note, later(REQUEST_TTL_DAYS * 86400)).lastInsertRowid;
    const row = db.prepare('SELECT * FROM network_requests WHERE id = ?').get(id);
    const ask = kind === 'person' ? 'wants to connect with you'
      : kind === 'agent' ? 'invites your wallet to join their fleet as an agent' : 'asks to join your fleet as an agent';
    // The mail only says a request waits; the note and the decision stay in the wallet (no free text from strangers
    // in a mail from DemiPass, and no ready-made accept command for an agent that reads its mailbox).
    if (sendMail) {
      sendMail({ to: target.email, subject: `DemiPass: ${w.wallet.username} ${ask}`,
        text: `${w.wallet.username} ${ask}.\n\n${requestView(row, target.did).effect}\n\n`
          + `Open your wallet at https://demipass.com/vault-mobile.html, tab Fleet, to see it and decide. If you do not know `
          + `${w.wallet.username}, decline it or let it expire (${REQUEST_TTL_DAYS} days).` });
    }
    log(`request ${id}: ${w.wallet.username} → ${target.username} (${kind})`);
    res.status(201).json({ ok: true, request: requestView(row, me) });
  });

  function requestFor(req, res, me) {
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id < 1) { res.status(400).json({ error: 'invalid request id' }); return null; }
    const r = db.prepare('SELECT * FROM network_requests WHERE id = ? AND (target_did = ? OR requester_did = ?)').get(id, me, me);
    if (!r) { res.status(404).json({ error: 'request not found' }); return null; }
    if (r.status === 'pending' && expired(r)) {
      db.prepare("UPDATE network_requests SET status = 'expired', decided_at = CURRENT_TIMESTAMP WHERE id = ? AND status = 'pending'").run(r.id);
      res.status(410).json({ error: 'this request expired' }); return null;
    }
    if (r.status !== 'pending') { res.status(409).json({ error: `this request is already ${r.status}` }); return null; }
    return r;
  }

  // ── Accept (the target only) ──────────────────────────────────────────────
  app.post('/api/network/requests/:id/accept', rateLimitStandard, (req, res) => {
    const w = walletAuth(req, res); if (!w) return;
    const me = w.wallet.did;
    const r = requestFor(req, res, me); if (!r) return;
    if (r.target_did !== me) return res.status(403).json({ error: 'only the wallet that was asked can accept' });
    if (r.kind !== 'person' && w.minted) return res.status(403).json({ error: 'a fleet-minted token cannot change fleet membership; sign in as this wallet' });
    const requester = db.prepare('SELECT status FROM identity_wallets WHERE did = ?').get(r.requester_did);
    if (!requester || requester.status !== 'active') return res.status(409).json({ error: 'the wallet that asked is no longer active' });
    const why = blocker(r.kind, r.requester_did, r.target_did);
    if (why) return res.status(409).json({ error: why });
    const sides = fleetSides(r);
    // Joining someone's fleet gives them power over this wallet: a wallet with a PIN says yes with it.
    const intent = `join:${r.id}`;
    const pinNeeded = sides && sides.member === me && Boolean(w.wallet.pin_hash);
    if (pinNeeded) {
      if (!gateFresh(me, 'pin', w.auth, intent)) {
        return res.status(403).json({ ...gateMissing('join', ['pin'], ['pin'], intent), error: 'joining a fleet needs your PIN' });
      }
    }
    try {
      let result;
      db.transaction(() => {
        if (pinNeeded) {
          const refused = spendSingleUse(me, 'join', ['pin'], w.auth, intent);
          if (refused) throw Object.assign(new Error(refused.error), { statusCode: refused.status || 403, body: refused });
        }
        const changed = db.prepare("UPDATE network_requests SET status = 'accepted', decided_at = CURRENT_TIMESTAMP WHERE id = ? AND status = 'pending'").run(r.id).changes;
        if (changed !== 1) throw Object.assign(new Error('this request was decided meanwhile'), { statusCode: 409 });
        if (r.kind === 'person') {
          const [a, b] = pair(r.requester_did, r.target_did);
          db.prepare(`INSERT INTO network_peers (did_a, did_b, request_id) VALUES (?, ?, ?)
                      ON CONFLICT(did_a, did_b) DO UPDATE SET status = 'active', request_id = excluded.request_id, created_at = CURRENT_TIMESTAMP, removed_at = NULL`)
            .run(a, b, r.id);
          result = { kind: 'person', with: walletName(r.requester_did) };
          return;
        }
        const fleet = ensureFleet(sides.owner);
        const count = db.prepare("SELECT COUNT(*) AS n FROM fleet_silicons WHERE fleet_id = ? AND status = 'active'").get(fleet.id).n;
        if (count >= fleet.max_agents) throw Object.assign(new Error(`that fleet is full (${fleet.max_agents} agents)`), { statusCode: 409 });
        const member = db.prepare('SELECT username, email FROM identity_wallets WHERE did = ?').get(sides.member);
        // The silicon id is one per wallet: rows it left behind in other fleets (removed, or a mailbox claim never
        // opened) give way. An active row elsewhere was refused above.
        const why2 = fb.joinBlocker(db, fleet, sides.member);
        if (why2) throw Object.assign(new Error(why2), { statusCode: 409 });
        fb.clearStaleSiliconRows(db, sides.member, fleet.id, { withPending: true });
        const handle = freeHandle(fleet.id, r.handle || defaultHandle(member.username), sides.member);
        const s = fb.upsertSilicon(db, { fleetId: fleet.id, memberDid: sides.member, handle, displayName: member.username, contactEmail: member.email });
        db.prepare("INSERT OR IGNORE INTO fleet_members (fleet_id, member_did, role) VALUES (?, ?, 'agent')").run(fleet.id, sides.member);
        db.prepare("UPDATE fleet_silicons SET joined_via = 'network' WHERE id = ?").run(s.id);   // keeps its own key
        result = { kind: 'agent', fleet: fleet.slug, handle: s.handle, member: member.username, owner: walletName(sides.owner) };
      }).immediate();
      log(`request ${r.id} accepted: ${JSON.stringify(result)}`);
      res.json({ ok: true, ...result });
    } catch (e) { fail(res, e); }
  });

  app.post('/api/network/requests/:id/decline', rateLimitStandard, (req, res) => {
    const w = walletAuth(req, res); if (!w) return;
    const r = requestFor(req, res, w.wallet.did); if (!r) return;
    if (r.target_did !== w.wallet.did) return res.status(403).json({ error: 'only the wallet that was asked can decline; withdraw your own request instead' });
    db.prepare("UPDATE network_requests SET status = 'declined', decided_at = CURRENT_TIMESTAMP WHERE id = ? AND status = 'pending'").run(r.id);
    res.json({ ok: true, id: r.id, status: 'declined' });
  });

  app.post('/api/network/requests/:id/withdraw', rateLimitStandard, (req, res) => {
    const w = walletAuth(req, res); if (!w) return;
    const r = requestFor(req, res, w.wallet.did); if (!r) return;
    if (r.requester_did !== w.wallet.did) return res.status(403).json({ error: 'only the wallet that asked can withdraw' });
    db.prepare("UPDATE network_requests SET status = 'withdrawn', decided_at = CURRENT_TIMESTAMP WHERE id = ? AND status = 'pending'").run(r.id);
    res.json({ ok: true, id: r.id, status: 'withdrawn' });
  });

  // ── Disconnect ────────────────────────────────────────────────────────────
  // A person: either side removes the contact.
  app.post('/api/network/people/remove', rateLimitStandard, (req, res) => {
    const w = walletAuth(req, res); if (!w) return;
    const other = findWallet((req.body || {}).did || (req.body || {}).username);
    if (!other) return res.status(404).json({ error: 'no wallet by that name' });
    const [a, b] = pair(w.wallet.did, other.did);
    const n = db.prepare("UPDATE network_peers SET status = 'removed', removed_at = CURRENT_TIMESTAMP WHERE did_a = ? AND did_b = ? AND status = 'active'").run(a, b).changes;
    if (!n) return res.status(404).json({ error: 'not a contact' });
    res.json({ ok: true });
  });
  // An agent leaves the fleet it is in (its owner removes it with DELETE /api/fleet/:slug/silicons/:handle).
  app.post('/api/network/leave-fleet', rateLimitStandard, (req, res) => {
    const w = walletAuth(req, res); if (!w) return;
    if (w.minted) return res.status(403).json({ error: 'a fleet-minted token cannot change fleet membership; sign in as this wallet' });
    const mf = memberFleet(w.wallet.did);
    if (!mf) return res.status(404).json({ error: 'this wallet is not an agent in a fleet' });
    const ownerHeldKey = (db.prepare('SELECT joined_via FROM fleet_silicons WHERE fleet_id = ? AND member_did = ?').get(mf.id, w.wallet.did) || {}).joined_via !== 'network';
    db.transaction(() => {
      db.prepare("UPDATE fleet_silicons SET status = 'removed', refill_enabled = 0, updated_at = CURRENT_TIMESTAMP WHERE fleet_id = ? AND member_did = ?").run(mf.id, w.wallet.did);
      db.prepare("DELETE FROM fleet_members WHERE fleet_id = ? AND member_did = ? AND role = 'agent'").run(mf.id, w.wallet.did);
      fb.cutFleetTokens(db, w.wallet.did, mf.slug);
      fb.revokeOwnerWorkers(db, w.wallet.did, mf.owner_did);
      // An owner that held this wallet's key (it created or linked it) could act as it: its sessions, refresh
      // tokens, workers and registered agents end, this session too. A wallet that joined through the network
      // kept its key; only the membership ends.
      if (ownerHeldKey) fb.signOutEverywhere(db, w.wallet.did);
    })();
    log(`${w.wallet.username} left fleet ${mf.slug}${ownerHeldKey ? ' (signed out everywhere)' : ''}`);
    res.json({ ok: true, left: mf.slug, signed_out: ownerHeldKey,
               note: ownerHeldKey ? 'the fleet owner held this wallet\'s key: every token of it was revoked, this one too — sign in again, and check the recovery email and registered agents' : undefined });
  });

  // ── Send DD to a connection ───────────────────────────────────────────────
  // Step 1: { to, amount_cents, note? } → 201 { transfer: { id, intent:'send:<id>', ... } }. Nothing moves yet.
  app.post('/api/network/transfers', rateLimitStandard, (req, res) => {
    const w = walletAuth(req, res); if (!w) return;
    const me = w.wallet.did;
    const b = req.body || {};
    const amount = Number(b.amount_cents);
    if (!Number.isInteger(amount) || amount < 1 || amount > MAX_TRANSFER) return res.status(400).json({ error: `amount_cents: a whole number of DD, 1 to ${MAX_TRANSFER}` });
    const to = findWallet(b.to);
    if (!to || to.status !== 'active') return res.status(404).json({ error: 'no wallet by that name' });
    if (to.did === me) return res.status(400).json({ error: 'that is your own wallet' });
    if (!connected(me, to.did)) return res.status(403).json({ error: `connect with ${to.username} first (Add wallet), then send` });
    const session = gateSession(w.auth);
    if (!session) return res.status(403).json({ error: 'this token cannot send DD — sign in again' });
    expireOld();
    if (db.prepare("SELECT COUNT(*) AS n FROM network_transfers WHERE from_did = ? AND status = 'pending'").get(me).n >= MAX_PENDING_TRANSFERS) {
      return res.status(429).json({ error: 'too many transfers waiting for confirmation' });
    }
    const id = db.prepare('INSERT INTO network_transfers (from_did, to_did, amount_cents, note, session, expires_at) VALUES (?, ?, ?, ?, ?, ?)')
      .run(me, to.did, amount, cleanText(b.note, 140), session, later(TRANSFER_TTL_SEC)).lastInsertRowid;
    res.status(201).json({ ok: true, transfer: { id: Number(id), intent: `send:${id}`, to: to.username, to_did: to.did, amount_cents: amount,
                                                  needs_pin: Boolean(w.wallet.pin_hash), expires_in: TRANSFER_TTL_SEC } });
  });

  // Step 2: confirm. A wallet with a PIN proves it for intent send:<id> first (403 + missing tells it so).
  app.post('/api/network/transfers/:id/confirm', rateLimitStandard, (req, res) => {
    const w = walletAuth(req, res); if (!w) return;
    const me = w.wallet.did;
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id < 1) return res.status(400).json({ error: 'invalid transfer id' });
    const t = db.prepare('SELECT * FROM network_transfers WHERE id = ? AND from_did = ?').get(id, me);
    if (!t || t.session !== gateSession(w.auth)) return res.status(404).json({ error: 'transfer not found' });
    if (t.status !== 'pending') return res.status(409).json({ error: `this transfer is already ${t.status}` });
    if (expired(t)) {
      db.prepare("UPDATE network_transfers SET status = 'expired', decided_at = CURRENT_TIMESTAMP WHERE id = ? AND status = 'pending'").run(t.id);
      return res.status(410).json({ error: 'this transfer expired; start it again' });
    }
    if (!connected(me, t.to_did)) return res.status(403).json({ error: 'no longer connected to that wallet' });
    const to = db.prepare('SELECT username, status FROM identity_wallets WHERE did = ?').get(t.to_did);
    if (!to || to.status !== 'active') return res.status(409).json({ error: 'that wallet is no longer active' });
    const intent = `send:${t.id}`;
    const barrel = transferRefusal ? transferRefusal(me, t.amount_cents) : null;   // say so before asking for a PIN
    if (barrel) return res.status(barrel.statusCode || 403).json(barrel.body || { error: barrel.message });
    const required = w.wallet.pin_hash ? ['pin'] : [];
    if (required.length && !gateFresh(me, 'pin', w.auth, intent)) {
      return res.status(403).json({ ...gateMissing('send', required, required, intent), error: `sending ${t.amount_cents} DD to ${to.username} needs your PIN` });
    }
    try {
      let debit;
      db.transaction(() => {
        if (required.length) {
          const refused = spendSingleUse(me, 'send', required, w.auth, intent);
          if (refused) throw Object.assign(new Error(refused.error), { statusCode: refused.status || 403, body: refused });
        }
        const changed = db.prepare("UPDATE network_transfers SET status = 'sent', decided_at = CURRENT_TIMESTAMP WHERE id = ? AND status = 'pending'").run(t.id).changes;
        if (changed !== 1) throw Object.assign(new Error('this transfer was decided meanwhile'), { statusCode: 409 });
        const note = t.note ? ': ' + t.note : '';
        debit = barrelGuardedTransfer(db, me, t.to_did, t.amount_cents, 'transfer_out', 'Transfer to ' + to.username + note, 'Transfer from ' + w.wallet.username + note);
        // A send from the owner to its agent answers the agent's open top-up ask, whatever the amount.
        db.prepare(`UPDATE network_topups SET status = 'sent', sent_cents = ?, transfer_id = ?, decided_at = CURRENT_TIMESTAMP
                    WHERE agent_did = ? AND owner_did = ? AND status = 'pending'`).run(t.amount_cents, t.id, t.to_did, me);
      }).immediate();
      log(`transfer ${t.id}: ${w.wallet.username} → ${to.username} ${t.amount_cents} DD`);
      res.json({ ok: true, id: t.id, status: 'sent', to: to.username, amount_cents: t.amount_cents, balance_after: debit.balance_after });
    } catch (e) {
      // Refused (balance, barrel, PIN race): the transfer stays pending until it expires, so a retry can confirm it.
      fail(res, e);
    }
  });

  app.post('/api/network/transfers/:id/cancel', rateLimitStandard, (req, res) => {
    const w = walletAuth(req, res); if (!w) return;
    const id = Number(req.params.id);
    const n = Number.isInteger(id) ? db.prepare("UPDATE network_transfers SET status = 'cancelled', decided_at = CURRENT_TIMESTAMP WHERE id = ? AND from_did = ? AND status = 'pending'").run(id, w.wallet.did).changes : 0;
    if (!n) return res.status(404).json({ error: 'no pending transfer by that id' });
    res.json({ ok: true, id, status: 'cancelled' });
  });

  // ── Top-up asks: an agent asks its fleet owner for DD ─────────────────────
  // body: { amount_cents, note? }. One open ask per agent; the owner sees it in its wallet (and gets a short mail) and
  // answers by sending DD (POST /api/network/transfers, confirmed with its PIN) or declining it.
  app.post('/api/network/topups', rateLimitStandard, (req, res) => {
    const w = walletAuth(req, res); if (!w) return;
    const me = w.wallet.did;
    const b = req.body || {};
    const amount = Number(b.amount_cents);
    if (!Number.isInteger(amount) || amount < 1 || amount > MAX_TRANSFER) return res.status(400).json({ error: `amount_cents: a whole number of DD, 1 to ${MAX_TRANSFER}` });
    expireOld();
    const mf = memberFleet(me);
    if (!mf) return res.status(409).json({ error: 'this wallet is not an agent in a fleet; only an agent asks its fleet owner for a top-up' });
    const owner = db.prepare('SELECT username, email, status FROM identity_wallets WHERE did = ?').get(mf.owner_did);
    if (!owner || owner.status !== 'active') return res.status(409).json({ error: 'the fleet owner\'s wallet is not active' });
    const open = db.prepare("SELECT * FROM network_topups WHERE agent_did = ? AND status = 'pending'").get(me);
    if (open) return res.status(409).json({ error: 'you already asked; it is waiting for your fleet owner (withdraw it to ask again)', topup: topupView(open, me) });
    const declined = db.prepare(`SELECT 1 FROM network_topups WHERE agent_did = ? AND status = 'declined' AND decided_at > datetime('now', ?)`)
      .get(me, `-${TOPUP_DECLINE_COOLDOWN_HOURS} hours`);
    if (declined) return res.status(429).json({ error: `your last ask was declined; ask again after ${TOPUP_DECLINE_COOLDOWN_HOURS} hour` });
    if (db.prepare("SELECT COUNT(*) AS n FROM network_topups WHERE agent_did = ? AND created_at > datetime('now', '-1 day')").get(me).n >= TOPUP_MAX_PER_DAY) {
      return res.status(429).json({ error: `at most ${TOPUP_MAX_PER_DAY} top-up asks a day` });
    }
    const id = db.prepare('INSERT INTO network_topups (agent_did, owner_did, amount_cents, note, expires_at) VALUES (?, ?, ?, ?, ?)')
      .run(me, mf.owner_did, amount, cleanText(b.note, 200), later(TOPUP_TTL_DAYS * 86400)).lastInsertRowid;
    const row = db.prepare('SELECT * FROM network_topups WHERE id = ?').get(id);
    // Like a connection request, the mail carries no free text: the note is read in the wallet.
    if (sendMail) {
      sendMail({ to: owner.email, subject: `DemiPass: your agent ${w.wallet.username} asks for ${amount} DD`,
        text: `Your agent ${w.wallet.username} (@${mf.handle}) asks for a top-up of ${amount} DD. It has ${billing.getDerivedBalance(db, me)} DD.\n\n`
          + `Open your wallet at https://demipass.com/vault-mobile.html to see why and send it DD, or decline. The ask expires in ${TOPUP_TTL_DAYS} days.` });
    }
    log(`topup ${id}: ${w.wallet.username} asks ${owner.username} for ${amount} DD`);
    res.status(201).json({ ok: true, topup: topupView(row, me) });
  });
  function topupFor(req, res, me) {
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id < 1) { res.status(400).json({ error: 'invalid top-up id' }); return null; }
    expireOld();
    const t = db.prepare('SELECT * FROM network_topups WHERE id = ? AND (agent_did = ? OR owner_did = ?)').get(id, me, me);
    if (!t) { res.status(404).json({ error: 'top-up ask not found' }); return null; }
    if (t.status !== 'pending') { res.status(409).json({ error: `this ask is already ${t.status}` }); return null; }
    return t;
  }
  app.post('/api/network/topups/:id/decline', rateLimitStandard, (req, res) => {
    const w = walletAuth(req, res); if (!w) return;
    const t = topupFor(req, res, w.wallet.did); if (!t) return;
    if (t.owner_did !== w.wallet.did) return res.status(403).json({ error: 'only the fleet owner can decline; withdraw your own ask instead' });
    db.prepare("UPDATE network_topups SET status = 'declined', decided_at = CURRENT_TIMESTAMP WHERE id = ? AND status = 'pending'").run(t.id);
    res.json({ ok: true, id: t.id, status: 'declined' });
  });
  app.post('/api/network/topups/:id/withdraw', rateLimitStandard, (req, res) => {
    const w = walletAuth(req, res); if (!w) return;
    const t = topupFor(req, res, w.wallet.did); if (!t) return;
    if (t.agent_did !== w.wallet.did) return res.status(403).json({ error: 'only the agent that asked can withdraw' });
    db.prepare("UPDATE network_topups SET status = 'withdrawn', decided_at = CURRENT_TIMESTAMP WHERE id = ? AND status = 'pending'").run(t.id);
    res.json({ ok: true, id: t.id, status: 'withdrawn' });
  });

  return { connected };
};
