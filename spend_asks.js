'use strict';
// ── Spend plans (Aaron 2026-11-18: "build the multi-step funding request") ─────────────────────────────────────────
// A pane about to spend DD across several steps (provision an agent wallet, consent to a service, one charge…) asks
// ONCE: a spend plan is one approval card on the phone of the person who answers for the paying wallet, listing every
// step with its cost and the total; the PIN approves it (critical). Approved, it is a standing allowance the pane
// follows and the listed steps draw on:
//   - a `consent` step covers POST /api/services/consent {spend_ask_id}: the same service and a cap no higher than the
//     step's are accepted on the plan's approval, with no second card (the card the owner approved named them);
//   - every other step (provision, charge, other) is listed and tracked: the pane records progress on it, and the
//     step's own gate (agent creation is its own critical card; a charge is the service's) still applies.
// Before this, a planned spend that fit no request type was a chat question, answered in whatever pane the owner
// happened to be in (the Conduit wave-5 pane waited a day on "may I spend 1,002 DD?").
// A plan never moves DD by itself. It lapses VALID_DAYS after approval; a pane with a plan it no longer needs closes it.

const KINDS = new Set(['provision', 'consent', 'charge', 'grant', 'other']);
const STEPS_MAX = 12;
const TOTAL_MAX = 1000000;           // DD
const CONSENT_CAP_MAX_DD = 100000;    // as service_tenants.js: a consent step never lists more than a consent may hold (#135 review)
const LABEL_RE = /^[A-Za-z0-9][A-Za-z0-9 _#+@().,:/-]{0,79}$/;
const PURPOSE_RE = /^[A-Za-z0-9][A-Za-z0-9 _#+@().,:/-]{0,119}$/;
const SERVICE_RE = /^[a-z0-9][a-z0-9-]{0,31}$/;
const HANDLE_RE = /^[a-z0-9][a-z0-9-]{1,30}$/;
const VALID_DAYS_DEFAULT = 7, VALID_DAYS_MAX = 30;
const OPEN_MAX = 5;                  // approved plans per payer at once
const DAY_MAX = 20;                  // filings per payer in 24 h

const nowIso = () => new Date().toISOString();
const later = (days) => new Date(Date.now() + days * 86400000).toISOString();
const parse = (s, d) => { try { return JSON.parse(s); } catch (_) { return d; } };

function init(db) {
  db.exec(`CREATE TABLE IF NOT EXISTS spend_asks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    payer_did TEXT NOT NULL,
    approver_did TEXT NOT NULL,
    requester_did TEXT NOT NULL,
    requester_label TEXT NOT NULL DEFAULT '',
    purpose TEXT NOT NULL,
    steps TEXT NOT NULL,
    total_dd INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'approved',
    approval_id INTEGER,
    progress TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    closed_at TEXT,
    closed_why TEXT
  )`);
  db.exec('CREATE INDEX IF NOT EXISTS idx_spend_asks_payer ON spend_asks(payer_did, status)');
}

// One step, checked: {kind, dd, label, service?, daily_cap_dd?, on_request_cap_dd?, handle?}. Returns {step} or {error}.
function checkStep(s, i) {
  if (!s || typeof s !== 'object') return { error: `steps[${i}]: an object` };
  const kind = String(s.kind || '');
  if (!KINDS.has(kind)) return { error: `steps[${i}].kind: ${[...KINDS].join(' | ')}` };
  const dd = Number(s.dd);
  if (!Number.isInteger(dd) || dd < 0 || dd > TOTAL_MAX) return { error: `steps[${i}].dd: a whole number of DD, 0 to ${TOTAL_MAX}` };
  const label = String(s.label || '');
  if (!LABEL_RE.test(label)) return { error: `steps[${i}].label: what the step is, 1-80 plain characters` };
  const out = { kind, dd, label };
  if (kind === 'consent') {
    if (!SERVICE_RE.test(String(s.service || ''))) return { error: `steps[${i}].service: the service slug the consent is for` };
    const cap = Number(s.daily_cap_dd);
    if (!Number.isInteger(cap) || cap < 1 || cap > CONSENT_CAP_MAX_DD) return { error: `steps[${i}].daily_cap_dd: 1 to ${CONSENT_CAP_MAX_DD}` };
    out.service = String(s.service); out.daily_cap_dd = cap;
    if (s.on_request_cap_dd !== undefined && s.on_request_cap_dd !== null) {
      const orc = Number(s.on_request_cap_dd);
      if (!Number.isInteger(orc) || orc < 1 || orc > cap) return { error: `steps[${i}].on_request_cap_dd: 1 to daily_cap_dd` };
      out.on_request_cap_dd = orc;
    }
  } else if (s.service !== undefined) {
    if (!SERVICE_RE.test(String(s.service || ''))) return { error: `steps[${i}].service: a service slug` };
    out.service = String(s.service);
  }
  if (kind === 'provision') {
    if (!HANDLE_RE.test(String(s.handle || ''))) return { error: `steps[${i}].handle: the agent handle to be created` };
    out.handle = String(s.handle);
  }
  return { step: out };
}

module.exports = function registerSpendAsks({ app, db, rateLimitStandard, getBearerIdentity, approvals, approverFor, scopeAtLeast }) {
  init(db);
  const sweep = () => db.prepare("UPDATE spend_asks SET status = 'expired', closed_at = ?, closed_why = 'expired' WHERE status = 'approved' AND expires_at <= ?").run(nowIso(), nowIso());
  const view = (r) => ({ spend_ask_id: r.id, status: r.status, purpose: r.purpose, total_dd: r.total_dd, approval_id: r.approval_id,
    payer: r.payer_did, approver: r.approver_did, requester_label: r.requester_label || '',
    steps: parse(r.steps, []).map((s, i) => ({ n: i + 1, ...s, ...(parse(r.progress, {})[i + 1] || {}) })),
    created_at: r.created_at, expires_at: r.expires_at, ...(r.closed_at ? { closed_at: r.closed_at, closed_why: r.closed_why } : {}) });
  // Whose token may act on a plan: the payer's own, or its approver's (the fleet owner reading or closing an agent's).
  const own = (r, did) => r && (r.payer_did === did || r.approver_did === did);
  const load = (req, res, auth) => {
    if (!/^\d{1,12}$/.test(String(req.params.id))) { res.status(400).json({ error: 'spend ask id' }); return null; }
    sweep();
    const r = db.prepare('SELECT * FROM spend_asks WHERE id = ?').get(Number(req.params.id));
    if (!own(r, auth.did)) { res.status(404).json({ error: 'no spend plan by that id for this wallet' }); return null; }
    return r;
  };
  const refuseAgentToken = (auth, res) => {
    if (auth.silicon || (auth.decoded && (auth.decoded.wrk || auth.decoded.auth_method === 'worker'))) { res.status(403).json({ error: 'a spend plan is filed with the paying wallet\'s own token, not a worker or legacy silicon token' }); return true; }
    return false;
  };

  // POST /api/billing/spend-asks {purpose, steps:[…], valid_days?, approval_id?} → 202 (the card is on the phone),
  // then the same call with approval_id → 201 {spend_ask_id, status: 'approved', steps}.
  app.post('/api/billing/spend-asks', rateLimitStandard, (req, res) => {
    const auth = getBearerIdentity(req); if (!auth.ok) return res.status(auth.status || 401).json({ error: auth.error });
    if (refuseAgentToken(auth, res)) return;
    if (scopeAtLeast && !scopeAtLeast(auth.scope, 'transact')) return res.status(403).json({ error: 'transact scope required to file a spend plan' });
    const b = req.body || {};
    const purpose = String(b.purpose || '');
    if (!PURPOSE_RE.test(purpose)) return res.status(400).json({ error: 'purpose: what the spend is for, 1-120 plain characters' });
    if (!Array.isArray(b.steps) || !b.steps.length || b.steps.length > STEPS_MAX) return res.status(400).json({ error: `steps: 1 to ${STEPS_MAX} steps, each {kind, dd, label, …}` });
    const steps = [];
    for (let i = 0; i < b.steps.length; i++) { const c = checkStep(b.steps[i], i); if (c.error) return res.status(400).json({ error: c.error }); steps.push(c.step); }
    const total = steps.reduce((n, s) => n + s.dd, 0);
    if (total < 1 || total > TOTAL_MAX) return res.status(400).json({ error: `the steps must add up to 1 to ${TOTAL_MAX} DD` });
    let days = VALID_DAYS_DEFAULT;
    if (b.valid_days !== undefined) { days = Number(b.valid_days); if (!Number.isInteger(days) || days < 1 || days > VALID_DAYS_MAX) return res.status(400).json({ error: `valid_days: 1 to ${VALID_DAYS_MAX}` }); }
    const approver = approverFor(auth.did);
    if (!approver) return res.status(403).json({ error: 'no person answers for this wallet' });
    sweep();
    if (db.prepare("SELECT COUNT(*) AS n FROM spend_asks WHERE payer_did = ? AND status = 'approved'").get(auth.did).n >= OPEN_MAX) return res.status(429).json({ error: `at most ${OPEN_MAX} approved spend plans at once; close one first` });
    if (db.prepare("SELECT COUNT(*) AS n FROM spend_asks WHERE payer_did = ? AND created_at > ?").get(auth.did, new Date(Date.now() - 86400000).toISOString()).n >= DAY_MAX) return res.status(429).json({ error: `at most ${DAY_MAX} spend plans a day` });
    const A = approvals();
    if (!A || !A.gateService) return res.status(503).json({ error: 'approvals unavailable' });
    const label = String((auth.decoded && (auth.decoded.agent_label || auth.decoded.label)) || '').slice(0, 40);
    // The whole plan is what the owner approves: purpose, every step with its cost, the total, the payer and how long
    // the allowance lasts are all in the bound parameters (the card lists them; the PIN opens it).
    const params = { purpose, total_dd: total, valid_days: days, payer: auth.did, steps: steps.map((s, i) => ({ n: i + 1, ...s })) };
    const g = A.gateService({ key: 'svc:demipass:spend-plan', name: `spend plan: ${total} DD`, approverDid: approver, depth: 'critical' },
      { did: auth.did, label }, { action: 'spend-plan', targetHost: 'demipass', params }, b);
    if (!g.ok) {
      const body = { ...(g.body || {}) }; delete body.owner;
      if (g.status === 202) body.next = `Park this. ${approver === auth.did ? 'The owner' : 'The fleet owner'} approves the plan in the DemiPass app (one card, PIN); then make the same call once more with approval_id ${body.approval_id}. Do not ask in chat.`;
      return res.status(g.status).json(body);
    }
    const id = Number(db.prepare(`INSERT INTO spend_asks (payer_did, approver_did, requester_did, requester_label, purpose, steps, total_dd, status, approval_id, created_at, expires_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, 'approved', ?, ?, ?)`).run(auth.did, approver, auth.did, label, purpose, JSON.stringify(steps), total, g.approval_id, nowIso(), later(days)).lastInsertRowid);
    const r = db.prepare('SELECT * FROM spend_asks WHERE id = ?').get(id);
    res.status(201).json({ ok: true, ...view(r), next: `Approved. Run the steps. A consent step: POST /api/services/consent with spend_ask_id ${id} (no second card). Record the others with POST /api/billing/spend-asks/${id}/progress {step, note}; close the plan when done.` });
  });

  app.get('/api/billing/spend-asks', rateLimitStandard, (req, res) => {
    const auth = getBearerIdentity(req); if (!auth.ok) return res.status(auth.status || 401).json({ error: auth.error });
    sweep();
    const rows = db.prepare("SELECT * FROM spend_asks WHERE (payer_did = ? OR approver_did = ?) AND (status = 'approved' OR created_at > ?) ORDER BY id DESC LIMIT 50")
      .all(auth.did, auth.did, new Date(Date.now() - 30 * 86400000).toISOString());
    res.json({ ok: true, spend_asks: rows.map(view) });
  });
  app.get('/api/billing/spend-asks/:id', rateLimitStandard, (req, res) => {
    const auth = getBearerIdentity(req); if (!auth.ok) return res.status(auth.status || 401).json({ error: auth.error });
    const r = load(req, res, auth); if (!r) return;
    res.json({ ok: true, ...view(r) });
  });
  // The pane records what it did on a step (a provision request id, a charge id): the plan's own log.
  app.post('/api/billing/spend-asks/:id/progress', rateLimitStandard, (req, res) => {
    const auth = getBearerIdentity(req); if (!auth.ok) return res.status(auth.status || 401).json({ error: auth.error });
    const r = load(req, res, auth); if (!r) return;
    if (r.status !== 'approved') return res.status(409).json({ error: `this plan is ${r.status}` });
    const b = req.body || {}, n = Number(b.step), steps = parse(r.steps, []);
    if (!Number.isInteger(n) || n < 1 || n > steps.length) return res.status(400).json({ error: `step: 1 to ${steps.length}` });
    const note = String(b.note || '').replace(/[^\x20-\x7e]/g, '').slice(0, 160);
    const p = parse(r.progress, {}); p[n] = { done_at: nowIso(), ...(note ? { note } : {}), ...(p[n] && p[n].covered_at ? { covered_at: p[n].covered_at } : {}) };
    db.prepare('UPDATE spend_asks SET progress = ? WHERE id = ?').run(JSON.stringify(p), r.id);
    res.json({ ok: true, ...view(db.prepare('SELECT * FROM spend_asks WHERE id = ?').get(r.id)) });
  });
  app.post('/api/billing/spend-asks/:id/close', rateLimitStandard, (req, res) => {
    const auth = getBearerIdentity(req); if (!auth.ok) return res.status(auth.status || 401).json({ error: auth.error });
    const r = load(req, res, auth); if (!r) return;
    if (r.status !== 'approved') return res.status(409).json({ error: `this plan is already ${r.status}` });
    db.prepare("UPDATE spend_asks SET status = 'closed', closed_at = ?, closed_why = ? WHERE id = ?").run(nowIso(), auth.did === r.payer_did ? 'done' : 'closed by the approver', r.id);
    res.json({ ok: true, ...view(db.prepare('SELECT * FROM spend_asks WHERE id = ?').get(r.id)) });
  });

  // A listed step drawing on the plan (service_tenants.js consent): the payer's own token, an approved unexpired plan,
  // a step of that kind for that service not yet used, and figures no higher than the step's. Checks only: the caller
  // marks the step with markCovered() inside the same transaction that grants the consent (#135 review: a step must
  // not be burned when the grant then fails). → {ok, approval_id, approver, spend_ask_id, step} or {error}.
  function cover(did, spendAskId, { kind, service, daily_cap_dd, on_request_cap_dd }) {
    if (!/^\d{1,12}$/.test(String(spendAskId))) return { error: 'spend_ask_id' };
    sweep();
    const r = db.prepare('SELECT * FROM spend_asks WHERE id = ?').get(Number(spendAskId));
    if (!r || r.payer_did !== did) return { error: 'no spend plan by that id for this wallet' };
    if (r.status !== 'approved') return { error: `the spend plan is ${r.status}` };
    const steps = parse(r.steps, []), p = parse(r.progress, {});
    const i = steps.findIndex((s, k) => s.kind === kind && s.service === service && !(p[k + 1] && p[k + 1].covered_at));
    if (i < 0) return { error: `the spend plan lists no unused ${kind} step for ${service}` };
    const s = steps[i];
    if (kind === 'consent') {
      if (Number(daily_cap_dd) > s.daily_cap_dd) return { error: `the plan's consent step for ${service} allows at most ${s.daily_cap_dd} DD a day` };
      if (on_request_cap_dd !== null && on_request_cap_dd !== undefined && !(s.on_request_cap_dd >= Number(on_request_cap_dd))) return { error: `the plan's consent step for ${service} ${s.on_request_cap_dd ? `allows at most ${s.on_request_cap_dd} DD per Conduit request` : 'has no Conduit request opt-in'}` };
    }
    return { ok: true, approval_id: r.approval_id, approver: r.approver_did, spend_ask_id: r.id, step: i + 1 };
  }
  function markCovered(spendAskId, step, note) {
    const r = db.prepare("SELECT progress FROM spend_asks WHERE id = ? AND status = 'approved'").get(Number(spendAskId));
    if (!r) throw new Error('spend plan no longer approved');
    const p = parse(r.progress, {});
    if (p[step] && p[step].covered_at) throw new Error('spend plan step already used');
    p[step] = { ...(p[step] || {}), covered_at: nowIso(), note: String(note || '').slice(0, 160) };
    db.prepare('UPDATE spend_asks SET progress = ? WHERE id = ?').run(JSON.stringify(p), Number(spendAskId));
  }
  return { cover, markCovered, view, KINDS };
};
module.exports.init = init;
module.exports.checkStep = checkStep;
