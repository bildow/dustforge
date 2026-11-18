'use strict';
// ── Fund asks (Aaron 2026-11-18) ────────────────────────────────────────────────────────────────────────────────────
// A service refused a payment because the paying wallet is short (Fleetgate's door: `payment.ask.kind = 'fund'`). The
// work waits and resumes by itself once the wallet is funded, but nothing told the owner in a way that stayed: the
// pane was handed a sentence ("fund it in the DemiPass app"), the app had no card, and a notification tapped away
// left no trace (Aaron: "The app doesn't hold the request anywhere ... it is as if it vanished").
//
// A fund ask is a wallet notice (wallet_notices.js, kind fund_ask) on the wallet that must pay:
//   - filed by any token of that wallet (the pane holding the owner's session met the refusal), never by an agent
//     wallet for itself (an agent asks its fleet owner with POST /api/network/topups);
//   - a card above every page of the app: Grant (wallets allowed operator grants: files the grant the owner approves
//     with the PIN, then collects it), else Deposit prefilled with the shortfall; and Dismiss;
//   - the phone's alerts poll lists it beside the approvals (an id in its own numeric range), so the app notifies about
//     it as it does about any request waiting on the owner;
//   - it closes by itself once the balance covers what the work needs ('covered'), or when the work's own wait lapses
//     ('lapsed'); the Requests page keeps it, closed, for 30 days.
// It moves no DD and grants nothing: it is the owner's to act on.

const notices = require('./wallet_notices');

const ALERT_ID_BASE = 300000000000;      // the phone keys notifications by a 1-12 digit id; agent token requests use 1e11+
const NEED_MAX = 1000000;                // DD
const OPEN_MAX = 3;                      // open fund asks per wallet
const DAY_MAX = 10;                      // fund asks filed per wallet in 24 h
const LAPSE_DEFAULT_SEC = 24 * 3600;
const LAPSE_MAX_SEC = 7 * 86400;
const GRANT_STEP = 500, GRANT_MAX = 100000;
const SERVICE_RE = /^[a-z0-9][a-z0-9-]{0,31}$/;
const SUBJECT_RE = /^[A-Za-z0-9][A-Za-z0-9._:/#@+-]{0,79}$/;

const cleanLabel = (s) => String(s || '').replace(/[^A-Za-z0-9 ._@-]/g, '').trim().slice(0, 40);
const dataOf = (r) => { try { return JSON.parse(r.data || '{}'); } catch (_) { return {}; } };
// What the owner is offered to grant: the shortfall rounded up to GRANT_STEP (headroom for the next step), capped.
const grantFor = (short) => Math.min(GRANT_MAX, Math.max(GRANT_STEP, Math.ceil(short / GRANT_STEP) * GRANT_STEP));

module.exports = function registerFundAsks({ app, db, rateLimitStandard, getBearerIdentity, balanceOf, grantAllowed, sendMail, now = () => Date.now() }) {
  const iso = (t = now()) => new Date(t).toISOString();
  const openRows = (did) => db.prepare("SELECT * FROM wallet_notices WHERE did = ? AND kind = 'fund_ask' AND closed_at IS NULL ORDER BY id DESC").all(did);
  const close = (id, why) => db.prepare('UPDATE wallet_notices SET closed_at = ?, closed_why = ? WHERE id = ? AND closed_at IS NULL').run(iso(), why, id).changes;

  // Close what no longer waits: the balance covers the need, or the work's wait lapsed. Runs wherever fund asks are
  // read (the card, the alerts poll, the pane's status check), so a funded wallet's card is gone by the next poll.
  function sweep(did) {
    let rows; try { rows = openRows(did); } catch (_) { return; }
    if (!rows.length) return;
    const bal = Number(balanceOf(did)) || 0, t = now();
    for (const r of rows) {
      const f = dataOf(r).fund || {};
      if (bal >= Number(f.need_dd || 0)) close(r.id, 'covered');
      else if (f.lapses_at && Date.parse(f.lapses_at) <= t) close(r.id, 'lapsed');
    }
  }

  // The card's fund block, with what is short NOW and what the owner may grant (if this wallet may grant at all).
  function decorate(did, list) {
    const bal = Number(balanceOf(did)) || 0, mayGrant = (() => { try { return !!grantAllowed(did); } catch (_) { return false; } })();
    return list.map(n => {
      if (n.kind !== 'fund_ask' || !n.fund) return n;
      const short = Math.max(0, Number(n.fund.need_dd || 0) - bal);
      return { ...n, fund: { ...n.fund, balance_dd: bal, short_dd: short, ...(mayGrant && !n.closed_at ? { grant_dd: grantFor(short) } : {}) },
        ...(n.closed_at ? {} : { deposit: { amount_dd: short, why: n.fund.service + ' ' + n.fund.subject } }) };
    });
  }

  // For the phone's alerts poll (account_holds.js): open fund asks as approval-like entries.
  function alertsFor(did) {
    sweep(did);
    const bal = Number(balanceOf(did)) || 0;
    return openRows(did).slice(0, 10).map(r => {
      const f = dataOf(r).fund || {}, short = Math.max(0, Number(f.need_dd || 0) - bal);
      return { id: ALERT_ID_BASE + r.id, title: `fund your wallet: ${short} DD short`, requester: f.requester || '',
        summary: `${f.service} ${f.subject} waits for ${f.need_dd} DD`, depth: 'standard', kind: 'fund' };
    });
  }

  function statusView(r, did) {
    const f = dataOf(r).fund || {}, bal = Number(balanceOf(did)) || 0;
    return { notice_id: r.id, status: r.closed_at ? r.closed_why : 'open', need_dd: f.need_dd, balance_dd: bal,
      short_dd: Math.max(0, Number(f.need_dd || 0) - bal), service: f.service, subject: f.subject, lapses_at: f.lapses_at,
      created_at: r.created_at, ...(r.closed_at ? { closed_at: r.closed_at } : {}) };
  }

  // POST /api/billing/fund-asks {need_dd, service, subject, lapses_at?, from?}
  //   need_dd: the balance the work needs (the refusal's needed_dd), service + subject: what waits (e.g. fleetgate,
  //   review id), lapses_at: when that wait ends (default 24 h, at most 7 days), from: a label for the pane (shown as
  //   such, never trusted). → 202 {notice_id, status: 'open'}, or 200 {covered: true} when nothing is short.
  app.post('/api/billing/fund-asks', rateLimitStandard, (req, res) => {
    const auth = getBearerIdentity(req); if (!auth.ok) return res.status(auth.status || 401).json({ error: auth.error });
    const did = auth.did, b = req.body || {};
    const agentWallet = db.prepare("SELECT 1 FROM fleet_silicons WHERE member_did = ? AND status = 'active'").get(did);
    if (agentWallet) return res.status(409).json({ error: 'this wallet is an agent in a fleet: ask the fleet owner for a top-up instead', use: 'POST /api/network/topups {amount_cents, note}' });
    const need = Number(b.need_dd);
    if (!Number.isInteger(need) || need < 1 || need > NEED_MAX) return res.status(400).json({ error: `need_dd: a whole number of DD, 1 to ${NEED_MAX} (the balance the work needs)` });
    const service = String(b.service || ''), subject = String(b.subject || '');
    if (!SERVICE_RE.test(service)) return res.status(400).json({ error: 'service: lowercase letters, digits and hyphens (e.g. fleetgate)' });
    if (!SUBJECT_RE.test(subject)) return res.status(400).json({ error: 'subject: what waits, e.g. a review id (letters, digits and . _ : / # @ + -, at most 80)' });
    let lapses = iso(now() + LAPSE_DEFAULT_SEC * 1000);
    if (b.lapses_at !== undefined) {
      const t = Date.parse(String(b.lapses_at));
      if (!Number.isFinite(t) || t <= now()) return res.status(400).json({ error: 'lapses_at: a time in the future (ISO 8601)' });
      lapses = iso(Math.min(t, now() + LAPSE_MAX_SEC * 1000));
    }
    sweep(did);
    const bal = Number(balanceOf(did)) || 0;
    if (bal >= need) return res.json({ ok: true, covered: true, balance_dd: bal, need_dd: need });
    const said = cleanLabel(b.from);
    const who = cleanLabel((auth.decoded && (auth.decoded.agent_label || auth.decoded.label)) || auth.agent_name || '') || 'a session of yours';
    const requester = who + (said && said !== who ? ` (says: ${said})` : '');
    const key = `fund:${service}:${subject}`;
    const short = need - bal;
    const fund = { need_dd: need, service, subject, requester, lapses_at: lapses };
    const title = `Fund your wallet: ${short} DD short`;
    const text = `${service} ${subject} waits for a balance of ${need} DD; the wallet holds ${bal} DD. Asked by ${requester}. The work resumes by itself once the wallet is funded.`;

    // The same work asking again: the open card is brought up to date, not doubled.
    const same = db.prepare("SELECT * FROM wallet_notices WHERE did = ? AND nkey = ? AND kind = 'fund_ask' AND closed_at IS NULL").get(did, key);
    if (same) {
      // A re-file that names no pane keeps the label the first filing gave.
      const prev = dataOf(same).fund || {};
      if (!said && prev.requester) { fund.requester = prev.requester; }
      const t2 = `${service} ${subject} waits for a balance of ${need} DD; the wallet holds ${bal} DD. Asked by ${fund.requester}. The work resumes by itself once the wallet is funded.`;
      db.prepare('UPDATE wallet_notices SET title = ?, text = ?, data = ? WHERE id = ?').run(title, t2, JSON.stringify({ fund }), same.id);
      return res.status(202).json({ ok: true, notice_id: same.id, status: 'open', already: true, short_dd: short, next: 'The owner funds the wallet in the DemiPass app. Check GET /api/billing/fund-asks/' + same.id + '; do not file it again.' });
    }
    if (openRows(did).length >= OPEN_MAX) return res.status(429).json({ error: `at most ${OPEN_MAX} fund asks wait on a wallet at once` });
    if (db.prepare("SELECT COUNT(*) AS n FROM wallet_notices WHERE did = ? AND kind = 'fund_ask' AND created_at > ?").get(did, iso(now() - 86400000)).n >= DAY_MAX) {
      return res.status(429).json({ error: `at most ${DAY_MAX} fund asks a day per wallet` });
    }
    const row = notices.raise(db, did, { kind: 'fund_ask', key, title, text, data: { fund } }, { now: now(), mailer: sendMail });
    if (!row) return res.status(409).json({ error: 'the owner dismissed this ask in the last 24 hours; it is not filed again', dismissed: true });
    res.status(202).json({ ok: true, notice_id: row.id, status: 'open', short_dd: short,
      next: 'The owner funds the wallet in the DemiPass app (a card waits there and on the phone). The work resumes by itself; check GET /api/billing/fund-asks/' + row.id + '.' });
  });

  // GET /api/billing/fund-asks/:id — what became of an ask this wallet filed: open, covered, dismissed, lapsed.
  app.get('/api/billing/fund-asks/:id', rateLimitStandard, (req, res) => {
    const auth = getBearerIdentity(req); if (!auth.ok) return res.status(auth.status || 401).json({ error: auth.error });
    if (!/^\d{1,12}$/.test(String(req.params.id))) return res.status(400).json({ error: 'fund ask id' });
    sweep(auth.did);
    const r = db.prepare("SELECT * FROM wallet_notices WHERE id = ? AND did = ? AND kind = 'fund_ask'").get(Number(req.params.id), auth.did);
    if (!r) return res.status(404).json({ error: 'no fund ask by that id on this wallet' });
    res.json({ ok: true, fund_ask: statusView(r, auth.did) });
  });

  return { sweep, decorate, alertsFor, ALERT_ID_BASE, grantFor };
};
module.exports.ALERT_ID_BASE = ALERT_ID_BASE;
module.exports.grantFor = grantFor;
