'use strict';
// ── Fleet billing: silicon subpages, hashed silicon ids, refill rules,
//    attributed billing (who pays for a call), tick-scoped work links.
//
// Pure functions over a better-sqlite3 handle. The host (server.js) passes in
// the `billing` module (deductBalance / creditBalance / getDerivedBalance) so
// this file never requires it and stays unit-testable in isolation.
//
// Money model (unchanged): identity_transactions is the ledger of truth.
// This module adds *who pays* (billing_attributions) and *who refills whom*
// (wallet_refill_rules, fleet_silicons.refill_*). It never mints DD except
// through an explicit operator-grant refill rule.

const crypto = require('crypto');

const INITIATORS = new Set(['self', 'operator', 'autonomous', 'work_link']);
const CADENCES = { daily: 1, weekly: 7, monthly: 30 };          // days
const OWNER_REFILL_MAX = 100000;   // DD a scheduled operator-grant run (the same cap as a one-off grant, #82)
const REFILL_COOLDOWN_MS = 10 * 60 * 1000;                       // one threshold refill per silicon per 10 min
const WORK_LINK_MAX_TTL_TICKS = 100000;
const WORK_LINK_DEFAULT_TTL_SECONDS = 7 * 86400;                 // wall-clock cap on top of the tick window
const TOKEN_WARN_HOURS = 24;
const TOKEN_WARN_DAYS = TOKEN_WARN_HOURS / 24;   // kept for older readers
const PROJECT_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const HANDLE_RE = /^[a-z0-9][a-z0-9-]{1,30}$/;

function nowIso() { return new Date().toISOString(); }
function sqlNow(d) { return (d || new Date()).toISOString().replace('T', ' ').slice(0, 19); }

// ── Schema ───────────────────────────────────────────────────────────────────
function initSchema(db) {
  db.exec(`CREATE TABLE IF NOT EXISTS fleet_silicons (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fleet_id INTEGER NOT NULL,
    member_did TEXT NOT NULL,
    handle TEXT NOT NULL,
    display_name TEXT DEFAULT '',
    contact_email TEXT DEFAULT '',
    silicon_id TEXT NOT NULL UNIQUE,
    refill_enabled INTEGER DEFAULT 0,
    refill_threshold_cents INTEGER DEFAULT 0,
    refill_amount_cents INTEGER DEFAULT 0,
    refill_source TEXT DEFAULT 'owner',
    last_refill_at TEXT,
    last_refill_error TEXT DEFAULT '',
    token_warned_at TEXT,
    status TEXT DEFAULT 'active',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(fleet_id, handle),
    UNIQUE(fleet_id, member_did)
  )`);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_fs_member ON fleet_silicons(member_did)`);

  db.exec(`CREATE TABLE IF NOT EXISTS wallet_refill_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    did TEXT NOT NULL UNIQUE,
    cadence TEXT DEFAULT 'weekly',
    amount_cents INTEGER NOT NULL DEFAULT 0,
    funding TEXT DEFAULT 'operator_grant',
    enabled INTEGER DEFAULT 0,
    next_run_at TEXT,
    last_run_at TEXT,
    last_error TEXT DEFAULT '',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
  )`);
  // Rules saved before the per-run cap (#83) are brought down to it, so the stored rule matches what a run pays.
  try { db.prepare('UPDATE wallet_refill_rules SET amount_cents = ? WHERE amount_cents > ?').run(OWNER_REFILL_MAX, OWNER_REFILL_MAX); } catch (_) {}

  db.exec(`CREATE TABLE IF NOT EXISTS billing_attributions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tx_id INTEGER,
    payer_did TEXT NOT NULL,
    actor_did TEXT NOT NULL,
    fleet_id INTEGER,
    project TEXT DEFAULT '',
    initiator TEXT DEFAULT 'self',
    work_link_id INTEGER,
    agent TEXT DEFAULT '',
    action_type TEXT NOT NULL,
    cost_cents INTEGER NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  )`);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_ba_payer ON billing_attributions(payer_did, created_at)`);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_ba_actor ON billing_attributions(actor_did, created_at)`);

  db.exec(`CREATE TABLE IF NOT EXISTS fleet_work_links (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    requester_did TEXT NOT NULL,
    provider_did TEXT NOT NULL,
    project TEXT DEFAULT '',
    note TEXT DEFAULT '',
    ttl_ticks INTEGER NOT NULL,
    ttl_seconds INTEGER NOT NULL,
    start_tick INTEGER,
    end_tick INTEGER,
    expires_at TEXT,
    status TEXT DEFAULT 'pending',
    token_hash TEXT,
    use_count INTEGER DEFAULT 0,
    spent_cents INTEGER DEFAULT 0,
    max_spend_cents INTEGER DEFAULT 0,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    accepted_at TEXT,
    revoked_at TEXT,
    revoked_by TEXT
  )`);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_fwl_token ON fleet_work_links(token_hash)`);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_fwl_parties ON fleet_work_links(requester_did, provider_did)`);

  // Subordinate workers: a silicon scopes tokens for its own sub-agents / test environments.
  // The token is minted for the PARENT's DID with a `wrk` claim; the registry row says what the
  // worker may touch (secret allow-list), its scope cap, spend cap, and whether it is revoked.
  db.exec(`CREATE TABLE IF NOT EXISTS fleet_workers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    worker_id TEXT NOT NULL UNIQUE,
    parent_did TEXT NOT NULL,
    name TEXT NOT NULL,
    purpose TEXT DEFAULT '',
    allowed_secrets TEXT DEFAULT '[]',
    scope_cap TEXT DEFAULT 'transact',
    max_spend_cents INTEGER DEFAULT 0,
    spent_cents INTEGER DEFAULT 0,
    use_count INTEGER DEFAULT 0,
    status TEXT DEFAULT 'active',
    last_jti TEXT DEFAULT '',
    token_expires_at TEXT,
    created_by TEXT DEFAULT '',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    revoked_at TEXT,
    revoked_by TEXT,
    UNIQUE(parent_did, name)
  )`);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_fw_parent ON fleet_workers(parent_did)`);
  try { db.exec(`ALTER TABLE billing_attributions ADD COLUMN worker_id TEXT DEFAULT ''`); } catch (_) {}

  // Per-project billing mode on the existing fleet board:
  //   owner          — the fleet owner's wallet pays, the project is a cost tag (default)
  //   project_wallet — the project's own wallet pays when it can, else overflow to the owner
  try { db.exec(`ALTER TABLE fleet_projects ADD COLUMN bill_mode TEXT DEFAULT 'owner'`); } catch (_) {}
  // Linking an EXISTING identity into a fleet needs consent: a token of that identity,
  // the platform admin key, or a one-time claim link sent to its mailbox.
  try { db.exec(`ALTER TABLE fleet_silicons ADD COLUMN claim_code TEXT DEFAULT ''`); } catch (_) {}
  try { db.exec(`ALTER TABLE fleet_silicons ADD COLUMN claim_expires_at TEXT DEFAULT ''`); } catch (_) {}
  // Tokens a fleet owner minted for a member (auth_method fleet_owner_mint, claim `fleet`) die when the member
  // leaves or is removed: billing.checkTokenRevocation refuses any minted before revoke_before (unix seconds).
  // How a silicon joined: 'owner' (the owner created it, or linked it with its token / the admin key / a claim
  // link: the owner holds its key and may mint its tokens and workers) or 'network' (the wallet accepted a network
  // request: it keeps its own key; the owner refills it, delegates to it and sees its spend, and mints nothing).
  try { db.exec(`ALTER TABLE fleet_silicons ADD COLUMN joined_via TEXT DEFAULT 'owner'`); } catch (_) {}
  // Owned outright: a wallet this fleet created (it holds the key; nobody outside signs in as it). Only these take the
  // owner's secrets and DD on the owner's token alone; a linked or network-joined wallet is someone's own, so
  // delegating to it, refilling it and arming its auto-refill take the owner's PIN (red team items 15, 16; #48).
  try { db.exec(`ALTER TABLE fleet_silicons ADD COLUMN created_by_fleet INTEGER DEFAULT 0`); } catch (_) {}
  try { db.exec(`ALTER TABLE fleet_silicons ADD COLUMN refill_confirmed INTEGER DEFAULT 0`); } catch (_) {}
  // The token the owner was last told about (its 24 h notice, or its lapse if the pass missed that): once per token.
  try { db.exec(`ALTER TABLE fleet_silicons ADD COLUMN token_owner_warned_jti TEXT`); } catch (_) {}
  // Backfill: provisioned by THIS row's fleet (the slug is in the account-creation entry), not by any fleet (#48 L).
  try { db.exec(`UPDATE fleet_silicons SET created_by_fleet = 1 WHERE created_by_fleet = 0 AND EXISTS (
      SELECT 1 FROM identity_transactions t JOIN fleets f ON f.id = fleet_silicons.fleet_id
      WHERE t.did = fleet_silicons.member_did AND t.type = 'account_created' AND t.provenance = 'fleet_provisioned'
        AND t.description = 'Fleet-provisioned by ' || f.slug)`); } catch (_) {}
  // Who created a wallet, for good (#68 review: clearStaleSiliconRows deletes a wallet's removed rows when it joins
  // another fleet, which erased the created_by_fleet row fleetExitRefusal and the service consents rely on). The first
  // fleet to create a wallet holds its password; that never changes, so the first record stays (INSERT OR IGNORE),
  // written by triggers on every path that marks or deletes a created row, and backfilled from today's rows.
  try {
    db.exec(`CREATE TABLE IF NOT EXISTS wallet_creators (did TEXT PRIMARY KEY, owner_did TEXT NOT NULL, fleet_id INTEGER NOT NULL, recorded_at TEXT NOT NULL)`);
    db.exec(`INSERT OR IGNORE INTO wallet_creators (did, owner_did, fleet_id, recorded_at)
      SELECT s.member_did, f.owner_did, s.fleet_id, datetime('now') FROM fleet_silicons s JOIN fleets f ON f.id = s.fleet_id
      WHERE s.created_by_fleet = 1 ORDER BY s.id`);
    // Also from provenance: a fleet-provisioned wallet whose created row was deleted before this table existed (it
    // re-joined another fleet earlier) is recorded from its account_created entry (#68 round-4 review).
    db.exec(`INSERT OR IGNORE INTO wallet_creators (did, owner_did, fleet_id, recorded_at)
      SELECT t.did, f.owner_did, f.id, datetime('now') FROM identity_transactions t JOIN fleets f ON t.description = 'Fleet-provisioned by ' || f.slug
      WHERE t.type = 'account_created' AND t.provenance = 'fleet_provisioned' ORDER BY t.id`);
    for (const [name, when, row] of [['wc_ins', 'AFTER INSERT', 'NEW'], ['wc_upd', 'AFTER UPDATE OF created_by_fleet, fleet_id', 'NEW'], ['wc_del', 'BEFORE DELETE', 'OLD']]) {
      db.exec(`CREATE TRIGGER IF NOT EXISTS ${name} ${when} ON fleet_silicons WHEN ${row}.created_by_fleet = 1 BEGIN
        INSERT OR IGNORE INTO wallet_creators (did, owner_did, fleet_id, recorded_at)
          SELECT ${row}.member_did, f.owner_did, ${row}.fleet_id, datetime('now') FROM fleets f WHERE f.id = ${row}.fleet_id; END`);
    }
  } catch (e) { console.error('[fleet] wallet_creators:', e.message); }
  // Threshold refills may be capped per rolling 24 h (0 = no cap). When a silicon is below its threshold and the
  // refill can't run (cap reached, or the source is short), refill_alert_email is told, once per 24 h.
  try { db.exec(`ALTER TABLE fleet_silicons ADD COLUMN refill_daily_cap_cents INTEGER DEFAULT 0`); } catch (_) {}
  try { db.exec(`ALTER TABLE fleet_silicons ADD COLUMN refill_alert_email TEXT DEFAULT ''`); } catch (_) {}
  try { db.exec(`ALTER TABLE fleet_silicons ADD COLUMN refill_alerted_at TEXT`); } catch (_) {}
  db.exec(`CREATE TABLE IF NOT EXISTS fleet_token_cuts (
    did TEXT NOT NULL,
    fleet TEXT NOT NULL,
    revoke_before INTEGER NOT NULL,
    PRIMARY KEY (did, fleet)
  )`);
}

// ── Fleet membership rules ──────────────────────────────────────────────────
// A wallet is an agent of at most one fleet; an agent owns no fleet with agents (else a fleet owner could reach,
// through a member's minted token, the agents of the member's own fleet). pending_claim rows count: a claim link
// may still be opened.
function activeFleetOf(db, did) {
  return db.prepare(`SELECT f.*, s.handle FROM fleet_silicons s JOIN fleets f ON f.id = s.fleet_id
                     WHERE s.member_did = ? AND s.status = 'active' AND f.status = 'active'`).get(did) || null;
}
function ownsFleetWithAgents(db, did) {
  return Boolean(db.prepare(`SELECT 1 FROM fleets f JOIN fleet_silicons s ON s.fleet_id = f.id
                             WHERE f.owner_did = ? AND f.status = 'active' AND s.status IN ('active', 'pending_claim') LIMIT 1`).get(did));
}
// Why `memberDid` cannot become an agent of fleet `fleet` now, or null.
function joinBlocker(db, fleet, memberDid) {
  if (memberDid === fleet.owner_did) return 'the fleet owner is not an agent of their own fleet';
  const mf = activeFleetOf(db, memberDid);
  if (mf && mf.id !== fleet.id) return 'that wallet is already an agent in another fleet; it has to leave it first';
  if (ownsFleetWithAgents(db, memberDid)) return 'that wallet runs its own fleet of agents, so it cannot join one';
  const of = activeFleetOf(db, fleet.owner_did);
  if (of) return 'the fleet owner is an agent in a fleet, so it cannot take agents';
  return null;
}
// Before a wallet joins a fleet: rows it left in other fleets give way — its silicon id is unique across fleets.
// Removed rows always; claims never opened only when the wallet itself consents here (withPending), never when
// some owner merely names it.
function clearStaleSiliconRows(db, memberDid, fleetId, { withPending = false } = {}) {
  db.prepare(`DELETE FROM fleet_silicons WHERE member_did = ? AND fleet_id != ? AND status ${withPending ? "!= 'active'" : "= 'removed'"}`).run(memberDid, fleetId);
}
// "Change the locks": every token of this wallet issued so far dies — its own, owner-minted ones, worker tokens,
// device-flow tokens — and so do its refresh tokens and workers. Used when a wallet leaves a fleet: whatever the
// owner obtained while it held the key stops working.
function signOutEverywhere(db, did) {
  // iat has whole seconds: the cut is this second (a sign-in right after still works), and every token issued so far
  // — the same second included — is also revoked by its jti (all tokens are recorded in issued_tokens).
  const cut = Math.floor(Date.now() / 1000);
  db.prepare('INSERT INTO token_revocations (did, revoke_before) VALUES (?, ?) ON CONFLICT(did) DO UPDATE SET revoke_before = excluded.revoke_before').run(did, cut);
  db.prepare("UPDATE issued_tokens SET revoked = 1, revoked_at = datetime('now') WHERE did = ? AND revoked = 0").run(did);
  try { db.prepare('UPDATE refresh_tokens SET revoked = 1 WHERE did = ? AND revoked = 0').run(did); } catch (_) {}
  try { db.prepare("UPDATE device_auth SET status = 'denied' WHERE approved_did = ? AND status = 'approved'").run(did); } catch (_) {}
  try { db.prepare("UPDATE fleet_workers SET status = 'revoked', revoked_at = datetime('now'), revoked_by = ? WHERE parent_did = ? AND status = 'active'").run(did, did); } catch (_) {}
  try { db.prepare("UPDATE silicon_agents SET status = 'revoked' WHERE carbon_did = ? AND status = 'active'").run(did); } catch (_) {}
}
// The owner's workers for a member (created through the owner route) end with the membership.
function revokeOwnerWorkers(db, memberDid, ownerDid) {
  const rows = db.prepare("SELECT worker_id FROM fleet_workers WHERE parent_did = ? AND created_by = ? AND status = 'active'").all(memberDid, ownerDid);
  for (const r of rows) revokeWorker(db, { wid: r.worker_id, byDid: ownerDid });
  return rows.length;
}
// Kill every token the owner of `slug` minted for `did` so far.
function cutFleetTokens(db, did, slug) {
  db.prepare(`INSERT INTO fleet_token_cuts (did, fleet, revoke_before) VALUES (?, ?, ?)
              ON CONFLICT(did, fleet) DO UPDATE SET revoke_before = excluded.revoke_before`).run(did, slug, Math.floor(Date.now() / 1000) + 1);
}

// ── Hashed silicon id ────────────────────────────────────────────────────────
// Stable, non-reversible alias for a DID. A counterparty can address a silicon
// by this id without ever handling the DID itself; only the platform resolves it.
function siliconId(did, secret) {
  const key = secret || process.env.FLEET_ID_SECRET || process.env.IDENTITY_MASTER_KEY || 'dustforge-fleet-id';
  return 'sil_' + crypto.createHmac('sha256', key).update(String(did)).digest('hex').slice(0, 16);
}

function currentTick(db) {
  try { return db.prepare('SELECT COALESCE(MAX(id), 0) AS t FROM ticks').get().t; } catch (_) { return 0; }
}

// ── Attribution parsing ──────────────────────────────────────────────────────
// Header:  X-DemiPass-Billing: {"project":"brain","initiator":"operator"}
// or body: { billing: { project, initiator, work_link } }
// Plus:    X-DemiPass-Agent: brain-dyadic-handler/1.0  (free text, reporting only)
function parseAttribution(req) {
  const out = { project: '', initiator: '', work_link: '', agent: '' };
  if (!req) return out;
  let raw = null;
  const h = req.headers && (req.headers['x-demipass-billing'] || req.headers['X-DemiPass-Billing']);
  if (h) { try { raw = JSON.parse(String(h)); } catch (_) { raw = null; } }
  if (!raw && req.body && req.body.billing && typeof req.body.billing === 'object') raw = req.body.billing;
  if (raw && typeof raw === 'object') {
    if (typeof raw.project === 'string' && PROJECT_RE.test(raw.project)) out.project = raw.project;
    if (typeof raw.initiator === 'string' && INITIATORS.has(raw.initiator)) out.initiator = raw.initiator;
    if (typeof raw.work_link === 'string' && raw.work_link.length <= 200) out.work_link = raw.work_link;
  }
  const a = req.headers && req.headers['x-demipass-agent'];
  if (a) out.agent = String(a).slice(0, 100);
  const wrk = req.identity && req.identity.decoded && req.identity.decoded.wrk;
  if (wrk) out.worker = String(wrk);
  return out;
}

// ── Project lookup (who may spend on a project) ──────────────────────────────
function findProjectForCaller(db, project, callerDid) {
  const rows = db.prepare(`SELECT p.id, p.fleet_id, p.project, p.owner_did AS project_owner_did, p.wallet_did,
                                  COALESCE(p.bill_mode, 'owner') AS bill_mode,
                                  f.owner_did AS fleet_owner_did, f.slug AS fleet_slug
                           FROM fleet_projects p JOIN fleets f ON f.id = p.fleet_id
                           WHERE p.project = ?`).all(project);
  for (const r of rows) {
    if (r.fleet_owner_did === callerDid) return { ...r, authorized_as: 'owner' };
    const op = db.prepare('SELECT 1 FROM fleet_project_operators WHERE project_id = ? AND operator_did = ?').get(r.id, callerDid);
    if (op) return { ...r, authorized_as: 'operator' };
    const adm = db.prepare("SELECT 1 FROM fleet_members WHERE fleet_id = ? AND member_did = ? AND role IN ('owner','admin')").get(r.fleet_id, callerDid);
    if (adm) return { ...r, authorized_as: 'admin' };
  }
  return null;
}

// ── Payer resolution ─────────────────────────────────────────────────────────
// Returns { ok:true, payer_did, initiator, project, fleet_id, work_link, reason }
//      or { ok:false, status, error }
function resolvePayer(db, billing, { callerDid, attribution = {}, cost = 0 }) {
  const a = attribution || {};
  let worker = null;
  if (a.worker) {
    const w = resolveWorker(db, { wrk: a.worker, sub: callerDid });
    if (!w.ok) return { ok: false, status: w.status || 403, error: w.error };
    worker = w.worker;
    if (worker.max_spend_cents > 0 && worker.spent_cents + cost > worker.max_spend_cents) {
      return { ok: false, status: 402, error: `worker ${worker.worker_id} spend cap reached`, worker_id: worker.worker_id };
    }
  }
  const base = _resolvePayerBase(db, billing, { callerDid, a, cost });
  if (!base.ok) return base;
  return { ...base, worker };
}

function _resolvePayerBase(db, billing, { callerDid, a, cost }) {
  if (a.work_link) {
    const v = validateWorkLink(db, a.work_link, callerDid);
    if (!v.ok) return { ok: false, status: 403, error: `work link rejected: ${v.error}` };
    const link = v.link;
    if (link.max_spend_cents > 0 && link.spent_cents + cost > link.max_spend_cents) {
      return { ok: false, status: 402, error: 'work link spend cap reached', work_link_id: link.id };
    }
    return { ok: true, payer_did: link.requester_did, initiator: 'work_link', project: link.project || '',
             fleet_id: null, work_link: link, reason: 'work link' };
  }
  if (a.project) {
    const p = findProjectForCaller(db, a.project, callerDid);
    if (!p) return { ok: false, status: 403, error: `not an operator on project '${a.project}'` };
    if (a.initiator === 'operator') {
      let payer = p.fleet_owner_did;
      let reason = 'operator-requested work on project; fleet owner pays';
      if (p.bill_mode === 'project_wallet' && p.wallet_did && p.wallet_did !== p.fleet_owner_did) {
        const bal = billing.getDerivedBalance(db, p.wallet_did);
        if (bal >= cost) { payer = p.wallet_did; reason = 'project wallet pays'; }
        else reason = 'project wallet short; overflow to fleet owner';
      }
      return { ok: true, payer_did: payer, initiator: 'operator', project: p.project, fleet_id: p.fleet_id, work_link: null, reason };
    }
    return { ok: true, payer_did: callerDid, initiator: 'autonomous', project: p.project, fleet_id: p.fleet_id, work_link: null,
             reason: 'autonomous work on project; caller pays, project recorded' };
  }
  return { ok: true, payer_did: callerDid, initiator: 'self', project: '', fleet_id: null, work_link: null, reason: 'caller pays' };
}

// ── Attributed charge ────────────────────────────────────────────────────────
// Deducts `cost` from the resolved payer and records the attribution row in the
// same transaction. After a successful charge, a silicon with a threshold rule
// is refilled inline so it never stalls mid-task.
function chargeAttributed(db, billing, { callerDid, cost, actionType, description = '', attribution = {}, ledger = null, tokenJti = null }) {
  const r = resolvePayer(db, billing, { callerDid, attribution, cost });
  if (!r.ok) return r;
  if (!(cost > 0)) return { ok: true, payer_did: r.payer_did, initiator: r.initiator, project: r.project, deducted: 0, balance_after: null };

  const txn = db.transaction(() => {
    const d = billing.deductBalance(db, r.payer_did, cost, actionType, description || `API call: ${actionType}`, { tokenJti });
    if (!d.ok) return { ...d, ok: false, payer_did: r.payer_did, initiator: r.initiator, project: r.project };
    const tx = db.prepare('SELECT id FROM identity_transactions WHERE did = ? ORDER BY id DESC LIMIT 1').get(r.payer_did);
    const ins = db.prepare(`INSERT INTO billing_attributions (tx_id, payer_did, actor_did, fleet_id, project, initiator, work_link_id, agent, action_type, cost_cents, worker_id)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .run(tx ? tx.id : null, r.payer_did, callerDid, r.fleet_id, r.project || '', r.initiator,
           r.work_link ? r.work_link.id : null, (attribution && attribution.agent) || '', actionType, cost,
           r.worker ? r.worker.worker_id : '');
    if (r.work_link) {
      db.prepare('UPDATE fleet_work_links SET use_count = use_count + 1, spent_cents = spent_cents + ? WHERE id = ?').run(cost, r.work_link.id);
    }
    if (r.worker) {
      db.prepare('UPDATE fleet_workers SET use_count = use_count + 1, spent_cents = spent_cents + ? WHERE id = ?').run(cost, r.worker.id);
    }
    return { ...d, payer_did: r.payer_did, initiator: r.initiator, project: r.project, attribution_id: Number(ins.lastInsertRowid), reason: r.reason,
             worker_id: r.worker ? r.worker.worker_id : undefined };
  });
  const out = txn();
  if (out.ok) {
    try { maybeThresholdRefill(db, billing, r.payer_did, { ledger }); } catch (_) { /* never break the billed call */ }
  }
  return out;
}

// ── Silicons ─────────────────────────────────────────────────────────────────
function getSilicon(db, fleetId, handleOrDid) {
  return db.prepare('SELECT * FROM fleet_silicons WHERE fleet_id = ? AND (handle = ? OR member_did = ? OR silicon_id = ?)')
    .get(fleetId, handleOrDid, handleOrDid, handleOrDid);
}

function upsertSilicon(db, { fleetId, memberDid, handle, displayName = '', contactEmail = '', refill = {} }) {
  if (!HANDLE_RE.test(handle || '')) throw Object.assign(new Error('handle must be 2-31 chars, lowercase alphanumeric and hyphens'), { statusCode: 400 });
  const sid = siliconId(memberDid);
  db.prepare(`INSERT INTO fleet_silicons (fleet_id, member_did, handle, display_name, contact_email, silicon_id,
                refill_enabled, refill_threshold_cents, refill_amount_cents)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
              ON CONFLICT(fleet_id, member_did) DO UPDATE SET
                handle = excluded.handle, display_name = excluded.display_name, contact_email = excluded.contact_email,
                status = 'active', updated_at = CURRENT_TIMESTAMP`)
    .run(fleetId, memberDid, handle, displayName, contactEmail, sid,
         refill.enabled ? 1 : 0, Number(refill.threshold_cents || 0), Number(refill.amount_cents || 0));
  return getSilicon(db, fleetId, memberDid);
}

function updateSiliconSettings(db, siliconRow, patch) {
  const fields = [];
  const vals = [];
  if (patch.display_name !== undefined) { fields.push('display_name = ?'); vals.push(String(patch.display_name).slice(0, 100)); }
  if (patch.contact_email !== undefined) { fields.push('contact_email = ?'); vals.push(String(patch.contact_email).slice(0, 200)); }
  if (patch.refill_enabled !== undefined) { fields.push('refill_enabled = ?'); vals.push(patch.refill_enabled ? 1 : 0); }
  if (patch.refill_threshold_cents !== undefined) {
    const n = Number(patch.refill_threshold_cents);
    if (!Number.isInteger(n) || n < 0 || n > 10000000) throw Object.assign(new Error('refill_threshold_cents: integer 0-10000000'), { statusCode: 400 });
    fields.push('refill_threshold_cents = ?'); vals.push(n);
  }
  if (patch.refill_amount_cents !== undefined) {
    const n = Number(patch.refill_amount_cents);
    if (!Number.isInteger(n) || n < 0 || n > 10000000) throw Object.assign(new Error('refill_amount_cents: integer 0-10000000'), { statusCode: 400 });
    fields.push('refill_amount_cents = ?'); vals.push(n);
  }
  if (patch.refill_daily_cap_cents !== undefined) {
    const n = Number(patch.refill_daily_cap_cents);
    if (!Number.isInteger(n) || n < 0 || n > 10000000) throw Object.assign(new Error('refill_daily_cap_cents: integer 0-10000000'), { statusCode: 400 });
    fields.push('refill_daily_cap_cents = ?'); vals.push(n);
  }
  if (patch.refill_alert_email !== undefined) {
    const e = String(patch.refill_alert_email || '').trim();
    if (e && !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(e)) throw Object.assign(new Error('refill_alert_email: an email address, or empty'), { statusCode: 400 });
    fields.push('refill_alert_email = ?'); vals.push(e.slice(0, 200));
  }
  if (patch.refill_source !== undefined) {
    if (!['owner', 'fleet'].includes(patch.refill_source)) throw Object.assign(new Error("refill_source: 'owner' or 'fleet'"), { statusCode: 400 });
    fields.push('refill_source = ?'); vals.push(patch.refill_source);
  }
  if (!fields.length) return siliconRow;
  fields.push('updated_at = CURRENT_TIMESTAMP');
  vals.push(siliconRow.id);
  db.prepare(`UPDATE fleet_silicons SET ${fields.join(', ')} WHERE id = ?`).run(...vals);
  return db.prepare('SELECT * FROM fleet_silicons WHERE id = ?').get(siliconRow.id);
}

// The agent's newest token that it holds: a renewal still sealed in token_deliveries (silicon_renew.js), not yet picked
// up or refused, is not counted — the card would otherwise say "token ok" while the agent runs on the old one (PR #100
// review M1).
function latestToken(db, did) {
  try {
    return db.prepare(`SELECT jti, scope, issued_at, expires_at, revoked FROM issued_tokens
                       WHERE did = ? AND revoked = 0
                         AND jti NOT IN (SELECT token_jti FROM token_deliveries WHERE did = ? AND COALESCE(ack, '') != 'used')
                       ORDER BY expires_at DESC LIMIT 1`).get(did, did) || null;
  } catch (_) {
    try {   // a database without token_deliveries
      return db.prepare(`SELECT jti, scope, issued_at, expires_at, revoked FROM issued_tokens
                         WHERE did = ? AND revoked = 0 ORDER BY expires_at DESC LIMIT 1`).get(did) || null;
    } catch (_) { return null; }
  }
}
// A renewal sealed for the agent and not picked up yet (newest), if any.
function awaitingPickup(db, did, now = Date.now()) {
  try {
    const r = db.prepare(`SELECT created_at, expires_at FROM token_deliveries WHERE did = ? AND acked_at IS NULL AND expires_at > ?
                          ORDER BY id DESC LIMIT 1`).get(did, new Date(now).toISOString());
    return r ? { since: r.created_at, until: r.expires_at } : null;
  } catch (_) { return null; }
}
// The newest renewal was declined by the agent (it kept a newer or broader token): the card says so (round-3 L5).
function renewalDeclined(db, did, now = Date.now()) {
  try {
    const r = db.prepare('SELECT ack, acked_at FROM token_deliveries WHERE did = ? AND expires_at > ? ORDER BY id DESC LIMIT 1').get(did, new Date(now).toISOString());
    return r && r.ack === 'declined' ? { at: r.acked_at } : null;
  } catch (_) { return null; }
}

// 'expiring' in the last TOKEN_WARN_HOURS (Aaron 2026-11-12: "an expiry warning 24 h before lapse"); the card shows
// hours then. days_left stays for older readers. awaiting_pickup: a renewal the agent has not picked up yet; the status
// is still the token it holds.
function tokenStatus(db, did, now = Date.now()) {
  const t = latestToken(db, did);
  const waiting = awaitingPickup(db, did, now), declined = waiting ? null : renewalDeclined(db, did, now);
  const extra = { ...(waiting ? { awaiting_pickup: waiting } : {}), ...(declined ? { renewal_declined: declined } : {}) };
  if (!t) return { status: 'none', scope: null, expires_at: null, days_left: null, hours_left: null, ...extra };
  const expMs = Number(t.expires_at) * 1000;
  const hoursLeft = (expMs - now) / 3600000;
  const status = hoursLeft <= 0 ? 'expired' : (hoursLeft <= TOKEN_WARN_HOURS ? 'expiring' : 'valid');
  return { status, scope: t.scope, expires_at: new Date(expMs).toISOString(), days_left: Math.floor(hoursLeft / 24 * 10) / 10,
           hours_left: Math.floor(hoursLeft * 10) / 10, jti: t.jti, ...extra };
}

// The agent's delivery key (silicon_renew.js): where an owner's renewal is sealed to. Fingerprint only. `changed_at`
// when it replaced an earlier key; `previous` while that change can still be undone; `pending` a key waiting for the
// owner (the first one too), with who asked: the asking token's kind and address (PR #100 review rounds 2-3). An ask
// whose token was revoked since (its jti, revoke-all, a fleet cut) is not shown.
function deliveryKeyFingerprint(raw) { return crypto.createHash('sha256').update(raw).digest('hex').slice(0, 16); }
// silicon_renew.js registers the routes' own check (billing.checkTokenRevocation over the asking token): the card shows
// exactly the asks the owner could approve (round-4 review L3). Without it, the SQL below approximates it.
let askRevokedCheck = null;
function setAskRevokedCheck(fn) { askRevokedCheck = fn; }
function deliveryKeyView(db, did) {
  let pending = null;
  try {
    const p = db.prepare(`SELECT c.* FROM delivery_key_changes c
                           WHERE c.did = ? AND c.status = 'pending' AND c.expires_at > ?
                             AND NOT EXISTS (SELECT 1 FROM issued_tokens t WHERE t.jti = c.ask_jti AND c.ask_jti != '' AND t.revoked = 1)
                             AND NOT EXISTS (SELECT 1 FROM token_revocations r WHERE r.did = c.did AND c.ask_iat > 0 AND c.ask_iat < r.revoke_before)
                             AND NOT EXISTS (SELECT 1 FROM fleet_token_cuts x WHERE x.did = c.did AND c.auth_method = 'fleet_owner_mint' AND x.fleet = c.ask_fleet AND c.ask_iat < x.revoke_before)
                           ORDER BY c.id DESC LIMIT 1`).get(did, nowIso());
    if (p && askRevokedCheck && askRevokedCheck(p)) { /* dead ask: not shown */ }
    else if (p) pending = { id: p.id, fingerprint: p.fingerprint, requested_at: p.requested_at, expires_at: p.expires_at, auth_method: p.auth_method || '', ip: p.ip || '', first: Boolean(p.first_key) };
  } catch (_) {}
  try {
    const w = db.prepare('SELECT * FROM identity_wallets WHERE did = ?').get(did);
    if (!w || !w.delivery_public_key) return { set: false, pending };
    const prev = w.delivery_key_previous && w.delivery_key_previous_until && Date.parse(w.delivery_key_previous_until) > Date.now()
      ? { fingerprint: deliveryKeyFingerprint(Buffer.from(w.delivery_key_previous, 'base64url')), until: w.delivery_key_previous_until } : null;
    return { set: true, fingerprint: deliveryKeyFingerprint(Buffer.from(w.delivery_public_key, 'base64url')), set_at: w.delivery_key_set_at || null,
             changed_at: w.delivery_key_changed_at || null, previous: prev, pending };
  } catch (_) { return { set: false, pending }; }   // a database without the columns (before silicon_renew.js ran)
}

function siliconView(db, billing, s, { fleet } = {}) {
  // Not confirmed yet: the owner named a wallet, the wallet has not agreed. Show nothing of it.
  if (s.status !== 'active') {
    return { handle: s.handle, display_name: s.display_name, did: null, silicon_id: null, username: null, email: null, wallet_status: null,
             balance_cents: null, last_active: null,
             refill: { enabled: !!s.refill_enabled, threshold_cents: s.refill_threshold_cents, amount_cents: s.refill_amount_cents, source: s.refill_source, last_refill_at: null, last_error: '' },
             token: { status: 'none' }, fleet: fleet ? { slug: fleet.slug, name: fleet.name } : undefined, status: s.status, created_at: s.created_at };
  }
  const w = db.prepare('SELECT username, email, status, balance_cents, updated_at FROM identity_wallets WHERE did = ?').get(s.member_did) || {};
  const balance = billing.getDerivedBalance(db, s.member_did);
  const lastTx = db.prepare('SELECT created_at FROM identity_transactions WHERE did = ? ORDER BY id DESC LIMIT 1').get(s.member_did);
  return {
    handle: s.handle, display_name: s.display_name, contact_email: s.contact_email,
    did: s.member_did, silicon_id: s.silicon_id, username: w.username || null, email: w.email || null,
    wallet_status: w.status || null, balance_cents: balance, last_active: lastTx ? lastTx.created_at : null,
    refill: { enabled: !!s.refill_enabled, threshold_cents: s.refill_threshold_cents, amount_cents: s.refill_amount_cents,
              source: s.refill_source, last_refill_at: s.last_refill_at, last_error: s.last_refill_error || '',
              daily_cap_cents: s.refill_daily_cap_cents || 0, auto_last_24h_cents: autoRefilledLast24h(db, s.member_did),
              alert_email: s.refill_alert_email || '',
              // A wallet the fleet did not create refills automatically only once its owner confirmed the rule with
              // the PIN (thresholdRefill); the card says so instead of failing silently.
              owned: ownedOutright(s), confirmed: ownedOutright(s) || !!Number(s.refill_confirmed) },
    token: tokenStatus(db, s.member_did),
    delivery_key: deliveryKeyView(db, s.member_did),
    fleet: fleet ? { slug: fleet.slug, name: fleet.name } : undefined,
    status: s.status, created_at: s.created_at, joined_via: s.joined_via || 'owner',
  };
}

// ── Refills ──────────────────────────────────────────────────────────────────
function refillSourceDid(db, s) {
  const f = db.prepare('SELECT owner_did, wallet_did FROM fleets WHERE id = ?').get(s.fleet_id);
  if (!f) return null;
  if (s.refill_source === 'fleet' && f.wallet_did) return f.wallet_did;
  return f.owner_did;
}

// Moves `amount` from the source wallet into the silicon wallet as a transfer
// (lineage-preserving: the DD lots move, they are not spent).
function transferRefill(db, billing, { fromDid, toDid, amount, description, ledger }) {
  const txn = db.transaction(() => {
    const d = billing.deductBalance(db, fromDid, amount, 'fleet_transfer_refill_out', description);
    if (!d.ok) throw Object.assign(new Error(d.error || 'insufficient balance'), { statusCode: 402, body: d });
    const c = billing.creditBalance(db, toDid, amount, 'fleet_transfer_refill_in', description.replace(/\bto\b/, 'from'));
    if (!c.ok) throw Object.assign(new Error(c.error || 'credit failed'), { statusCode: 500, body: c });
    return { ok: true, from_balance_after: d.balance_after, to_balance_after: c.balance_after, amount };
  });
  const out = txn();
  if (ledger && typeof ledger.recordTransfer === 'function') { try { ledger.recordTransfer(db, fromDid, toDid, amount); } catch (_) {} }
  return out;
}

// ── Removing a project (Aaron 2026-11-09) ───────────────────────────────────────
// Whether a project's own wallet is the fleet owner's to empty when the project is removed. Only a wallet this fleet
// made: the board's own project wallet (minted for this board as project-<name>, the row's owner and wallet, a member
// of this fleet), or a wallet this fleet created (wallet_creators). A wallet that is someone's own account — a linked
// or network-joined silicon, a person — is never swept: its balance is its own.
function projectWalletOwned(db, fleet, p) {
  if (!p || !p.wallet_did || p.wallet_did === fleet.owner_did) return false;
  const w = db.prepare('SELECT username FROM identity_wallets WHERE did = ?').get(p.wallet_did);
  if (!w) return false;
  const member = db.prepare('SELECT 1 FROM fleet_members WHERE fleet_id = ? AND member_did = ?').get(fleet.id, p.wallet_did);
  if (mintedProjectWallet(db, fleet, p, w, member)) return true;
  return Boolean(db.prepare('SELECT 1 FROM wallet_creators WHERE did = ? AND owner_did = ? AND fleet_id = ?').get(p.wallet_did, fleet.owner_did, fleet.id));
}
// The board's own wallet, as bin/mint-project-owners.js makes it: project-<name>, the row's owner and wallet, a member
// of this fleet, and no password (nobody signs in as it). A username alone is not enough: anyone can register
// project-<anything> (#86 review M1), and such an account has a password.
function mintedProjectWallet(db, fleet, p, w, member) {
  if (!w) w = db.prepare('SELECT username FROM identity_wallets WHERE did = ?').get(p.wallet_did);
  if (member === undefined) member = db.prepare('SELECT 1 FROM fleet_members WHERE fleet_id = ? AND member_did = ?').get(fleet.id, p.wallet_did);
  if (!w || !member || p.owner_did !== p.wallet_did || w.username !== 'project-' + p.project) return false;
  const pw = db.prepare('SELECT password_hash FROM identity_wallets WHERE did = ?').get(p.wallet_did);
  return !(pw && pw.password_hash);
}
// Removes a project from the board. Whatever its own wallet holds goes back to the fleet owner first, in the same
// transaction (all or nothing): the sweep, the board row, its operators, and the wallet's fleet membership and refill
// rule when the board minted it. Returns { swept, owner_balance_after }.
function removeProject(db, billing, { fleet, project, ledger }) {
  const txn = db.transaction(() => {
    const p = db.prepare('SELECT * FROM fleet_projects WHERE fleet_id = ? AND project = ?').get(fleet.id, project);
    if (!p) throw Object.assign(new Error('project not found on this fleet board'), { statusCode: 404 });
    const separate = Boolean(p.wallet_did && p.wallet_did !== fleet.owner_did);
    const shared = separate && db.prepare('SELECT COUNT(*) AS n FROM fleet_projects WHERE wallet_did = ? AND id <> ?').get(p.wallet_did, p.id).n > 0;
    const owned = separate && !shared && projectWalletOwned(db, fleet, p);
    const bal = separate ? billing.getDerivedBalance(db, p.wallet_did) : 0;
    // A wallet in debt (a clawback after it spent) is not dropped from the board: the debt would sit on a wallet
    // nobody tracks (#86 review M2).
    if (bal < 0) throw Object.assign(new Error(`project ${p.project}'s wallet owes ${-bal} DD; settle that before removing it`), { statusCode: 409 });
    if (bal > 0 && !owned) {
      throw Object.assign(new Error(shared
        ? `project ${p.project}'s wallet also pays for another project, so its ${bal} DD stay there; remove that project's link first`
        : `project ${p.project}'s wallet is an account of its own (not one this fleet made), so its ${bal} DD are not yours to take back; ask it to send them, then remove the project`),
        { statusCode: 409 });
    }
    let swept = 0, ownerAfter = null;
    if (bal > 0) {
      const desc = `Project ${p.project} removed: its ${bal} DD returned to the fleet owner (fleet ${fleet.slug})`;
      const d = billing.deductBalance(db, p.wallet_did, bal, 'fleet_project_removed_transfer_out', desc);
      if (!d.ok) throw Object.assign(new Error(d.error || 'could not empty the project wallet'), { statusCode: 409, body: d });
      const c = billing.creditBalance(db, fleet.owner_did, bal, 'fleet_project_removed_transfer_in', desc);
      if (!c.ok) throw Object.assign(new Error(c.error || 'credit failed'), { statusCode: 500, body: c });
      swept = bal; ownerAfter = c.balance_after;
    }
    db.prepare('DELETE FROM fleet_project_operators WHERE project_id = ?').run(p.id);
    db.prepare('DELETE FROM fleet_projects WHERE id = ?').run(p.id);
    // The board's own wallet leaves the fleet with its project, and no rule keeps refilling it. Only that wallet: an
    // agent this fleet created stays an agent (its membership and refills are its silicon row's business; #86 L1).
    if (owned && mintedProjectWallet(db, fleet, p)) {
      db.prepare("DELETE FROM fleet_members WHERE fleet_id = ? AND member_did = ? AND role = 'agent'").run(fleet.id, p.wallet_did);
      db.prepare('UPDATE wallet_refill_rules SET enabled = 0, updated_at = CURRENT_TIMESTAMP WHERE did = ?').run(p.wallet_did);
    }
    return { project: p.project, wallet_did: p.wallet_did || null, swept, owner_balance_after: ownerAfter };
  });
  const out = txn();
  if (out.swept > 0 && ledger && typeof ledger.recordTransfer === 'function') { try { ledger.recordTransfer(db, out.wallet_did, fleet.owner_did, out.swept); } catch (_) {} }
  return out;
}

// ── Top-up asks (network_routes.js) ─────────────────────────────────────────
// The fleet owner a wallet is an active agent of, or null.
function agentFleetOwner(db, did) {
  const r = db.prepare(`SELECT f.owner_did FROM fleet_silicons s JOIN fleets f ON f.id = s.fleet_id
                        WHERE s.member_did = ? AND s.status = 'active' AND f.status = 'active'`).get(did);
  return r ? r.owner_did : null;
}
// DD reaching an agent from its fleet (the owner, or the fleet wallet on a refill) answers the agent's open top-up
// ask, whatever the route: a network send, /api/wallet/transfer, a manual or threshold refill. Returns rows closed.
const _hasTopups = new WeakSet();
function answerTopups(db, agentDid, sentCents) {
  if (!_hasTopups.has(db)) {
    if (!db.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'network_topups'").get()) return 0;
    _hasTopups.add(db);
  }
  return db.prepare(`UPDATE network_topups SET status = 'sent', sent_cents = ?, decided_at = CURRENT_TIMESTAMP
                     WHERE agent_did = ? AND status = 'pending'`).run(sentCents, agentDid).changes;
}
function fromItsFleet(db, fromDid, agentDid) {
  const r = db.prepare(`SELECT f.owner_did, f.wallet_did FROM fleet_silicons s JOIN fleets f ON f.id = s.fleet_id
                        WHERE s.member_did = ? AND s.status = 'active' AND f.status = 'active'`).get(agentDid);
  return Boolean(r && (r.owner_did === fromDid || (r.wallet_did && r.wallet_did === fromDid)));
}

// Automatic (threshold) refills are told apart from manual ones by their description, so the daily cap
// counts only what the rule moved, never what the owner sent by hand.
const AUTO_REFILL_PREFIX = 'Auto refill ';
function autoRefilledLast24h(db, did, now = Date.now()) {
  const r = db.prepare(`SELECT COALESCE(SUM(amount_cents), 0) AS c FROM identity_transactions
                        WHERE did = ? AND type = 'fleet_transfer_refill_in' AND description LIKE ? AND created_at >= ?`)
    .get(did, AUTO_REFILL_PREFIX + '%', sqlNow(new Date(now - 86400000)));
  return r ? r.c : 0;
}

// A wallet its fleet created moves DD only inside that fleet: to its owner or another agent the fleet created. It has no
// PIN and its owner mints its tokens, so DD leaving it is the owner's DD leaving on a token alone (#48 review: network
// sends, escrow). Returns the refusal text, or null when the move is allowed.
// The fleet that created a wallet and its owner, for good: wallet_creators first (it survives row deletion), else today's
// rows. → {fleet_id, owner_did} | null
function creatorOf(db, did) {
  try { const w = db.prepare('SELECT fleet_id, owner_did FROM wallet_creators WHERE did = ?').get(did); if (w) return w; } catch (_) {}
  return db.prepare(`SELECT s.fleet_id, f.owner_did FROM fleet_silicons s JOIN fleets f ON f.id = s.fleet_id
      WHERE s.member_did = ? AND s.created_by_fleet = 1 ORDER BY s.id DESC LIMIT 1`).get(did) || null;
}
function fleetExitRefusal(db, fromDid, toDid) {
  // Whatever its row's status now: leaving or being removed does not free a wallet a fleet created (its creator holds
  // its password) — its DD can go back to that owner and nowhere else (#48 review: leave-fleet was an exit).
  const own = creatorOf(db, fromDid);
  if (!own || !toDid || toDid === own.owner_did) return null;
  if (db.prepare("SELECT 1 FROM fleet_silicons WHERE fleet_id = ? AND member_did = ? AND status = 'active' AND created_by_fleet = 1").get(own.fleet_id, toDid)) return null;
  return 'an agent your fleet created moves DD only to its owner or another agent the fleet created';
}
// When an agent leaves or is removed: every delegation of the owner's secrets to it ends (#48 review).
function endOwnerDelegations(db, ownerDid, memberDid) {
  return db.prepare("UPDATE demipass_delegations SET status = 'revoked', revoked_at = datetime('now') WHERE owner_did = ? AND delegate_did = ? AND status = 'active'").run(ownerDid, memberDid).changes;
}
function ownedOutright(s) { return Boolean(s) && Number(s.created_by_fleet) === 1 && (s.joined_via || 'owner') !== 'network'; }
function thresholdRefill(db, billing, s, { force = false, amount = null, now = Date.now(), ledger = null } = {}) {
  let amt = Number(amount != null ? amount : s.refill_amount_cents);
  if (!force) {
    if (!s.refill_enabled || !(s.refill_threshold_cents > 0) || !(amt > 0)) return { ok: false, skipped: 'rule disabled' };
    if (!ownedOutright(s) && !Number(s.refill_confirmed)) return { ok: false, skipped: 'auto-refill to a wallet the fleet did not create needs the owner\'s PIN confirmation' };
    const bal = billing.getDerivedBalance(db, s.member_did);
    if (bal >= s.refill_threshold_cents) return { ok: false, skipped: 'above threshold', balance_cents: bal };
    if (s.last_refill_at && now - new Date(s.last_refill_at + 'Z').getTime() < REFILL_COOLDOWN_MS) return { ok: false, skipped: 'cooldown' };
    if (s.refill_daily_cap_cents > 0) {
      const room = s.refill_daily_cap_cents - autoRefilledLast24h(db, s.member_did, now);
      if (room <= 0) return { ok: false, skipped: 'daily cap reached', balance_cents: bal, daily_cap_cents: s.refill_daily_cap_cents };
      amt = Math.min(amt, room);
    }
  }
  if (!(amt > 0)) return { ok: false, error: 'amount required' };
  const from = refillSourceDid(db, s);
  if (!from) return { ok: false, error: 'fleet not found' };
  if (from === s.member_did) return { ok: false, error: 'refill source is the silicon itself' };
  const fleet = db.prepare('SELECT slug FROM fleets WHERE id = ?').get(s.fleet_id) || { slug: '?' };
  try {
    const r = transferRefill(db, billing, { fromDid: from, toDid: s.member_did, amount: amt,
      description: `${force ? 'Refill ' : AUTO_REFILL_PREFIX}${amt} DD to ${s.handle} (fleet ${fleet.slug})`, ledger });
    db.prepare("UPDATE fleet_silicons SET last_refill_at = datetime('now'), last_refill_error = '', updated_at = CURRENT_TIMESTAMP WHERE id = ?").run(s.id);
    // The DD already moved: closing the ask is bookkeeping and never turns the refill into a failure.
    try { if (fromItsFleet(db, from, s.member_did)) answerTopups(db, s.member_did, amt); }
    catch (e) { console.error('[topups] closing an ask failed:', e.message); }
    return { ok: true, ...r, from_did: from };
  } catch (e) {
    const msg = (e.body && e.body.error) || e.message;
    db.prepare("UPDATE fleet_silicons SET last_refill_error = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?").run(String(msg).slice(0, 200), s.id);
    return { ok: false, error: msg, from_did: from };
  }
}

function maybeThresholdRefill(db, billing, did, { ledger = null, now = Date.now() } = {}) {
  const rows = db.prepare("SELECT * FROM fleet_silicons WHERE member_did = ? AND refill_enabled = 1 AND status = 'active'").all(did);
  const out = [];
  for (const s of rows) out.push(thresholdRefill(db, billing, s, { now, ledger }));
  return out;
}

function nextRunAfter(cadence, fromIso, now = Date.now()) {
  const days = CADENCES[cadence] || 7;
  let t = fromIso ? new Date(fromIso + (fromIso.endsWith('Z') || fromIso.includes('T') ? '' : 'Z')).getTime() : now;
  if (!Number.isFinite(t)) t = now;
  t += days * 86400000;
  while (t <= now) t += days * 86400000;
  return new Date(t).toISOString();
}

function setOwnerRefillRule(db, did, { cadence = 'weekly', amount_cents = 0, funding = 'operator_grant', enabled = false, next_run_at = null }) {
  if (!CADENCES[cadence]) throw Object.assign(new Error('cadence: daily | weekly | monthly'), { statusCode: 400 });
  const amt = Number(amount_cents);
  if (!Number.isInteger(amt) || amt < 0 || amt > OWNER_REFILL_MAX) throw Object.assign(new Error(`amount_cents: integer 0-${OWNER_REFILL_MAX}`), { statusCode: 400 });
  if (!['operator_grant', 'stripe'].includes(funding)) throw Object.assign(new Error("funding: 'operator_grant' or 'stripe'"), { statusCode: 400 });
  const next = next_run_at || nextRunAfter(cadence, null);
  db.prepare(`INSERT INTO wallet_refill_rules (did, cadence, amount_cents, funding, enabled, next_run_at)
              VALUES (?, ?, ?, ?, ?, ?)
              ON CONFLICT(did) DO UPDATE SET cadence = excluded.cadence, amount_cents = excluded.amount_cents,
                funding = excluded.funding, enabled = excluded.enabled,
                next_run_at = COALESCE(wallet_refill_rules.next_run_at, excluded.next_run_at), updated_at = CURRENT_TIMESTAMP`)
    .run(did, cadence, amt, funding, enabled ? 1 : 0, next);
  return getOwnerRefillRule(db, did);
}

function getOwnerRefillRule(db, did) {
  return db.prepare('SELECT * FROM wallet_refill_rules WHERE did = ?').get(did) || null;
}

function operatorGrantAllowed(did, opts = {}) {
  if (Array.isArray(opts.grantDids)) return opts.grantDids.includes(did);
  const env = (process.env.OPERATOR_GRANT_DIDS || '').split(',').map(s => s.trim()).filter(Boolean);
  return env.includes(did);
}

function runOwnerRefills(db, billing, { now = Date.now(), grantDids } = {}) {
  const due = db.prepare("SELECT * FROM wallet_refill_rules WHERE enabled = 1 AND amount_cents > 0 AND next_run_at IS NOT NULL AND next_run_at <= ?")
    .all(new Date(now).toISOString());
  const out = [];
  for (const rule of due) {
    let result;
    if (rule.funding === 'operator_grant') {
      if (!operatorGrantAllowed(rule.did, { grantDids })) {
        result = { ok: false, error: 'operator grant not permitted for this wallet (OPERATOR_GRANT_DIDS)' };
      } else {
        const key = `auto_refill_${rule.id}_${rule.next_run_at}`;
        // Clamped at run time too: a rule saved before the cap (#83) never credits more than OWNER_REFILL_MAX a run.
        result = billing.creditBalance(db, rule.did, Math.min(rule.amount_cents, OWNER_REFILL_MAX), 'auto_refill_grant', `Scheduled ${rule.cadence} refill (operator grant)`, key);
      }
    } else {
      result = { ok: false, error: 'stripe-funded auto refill is not available yet' };
    }
    const next = nextRunAfter(rule.cadence, rule.next_run_at, now);
    if (result.ok) {
      db.prepare("UPDATE wallet_refill_rules SET last_run_at = ?, next_run_at = ?, last_error = '', updated_at = CURRENT_TIMESTAMP WHERE id = ?")
        .run(new Date(now).toISOString(), next, rule.id);
    } else {
      // Keep the rule due but record why; retried every scheduler pass until fixed.
      db.prepare("UPDATE wallet_refill_rules SET last_error = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?").run(String(result.error).slice(0, 200), rule.id);
    }
    out.push({ did: rule.did, ...result, next_run_at: result.ok ? next : rule.next_run_at });
  }
  return out;
}

function runSiliconRefills(db, billing, { now = Date.now(), ledger = null, mailer = null } = {}) {
  const rows = db.prepare("SELECT * FROM fleet_silicons WHERE refill_enabled = 1 AND status = 'active' AND refill_threshold_cents > 0 AND refill_amount_cents > 0").all();
  return rows.map(s => {
    const r = thresholdRefill(db, billing, s, { now, ledger });
    const alerted = (r.skipped === 'daily cap reached' || (!r.ok && r.error)) ? refillAlert(db, billing, s, r, { now, mailer }) : false;
    return { handle: s.handle, did: s.member_did, ...r, ...(alerted ? { alerted: s.refill_alert_email } : {}) };
  });
}

// A silicon below its threshold whose refill can't run: tell refill_alert_email, once per 24 h.
function refillAlert(db, billing, s, r, { now = Date.now(), mailer = null } = {}) {
  if (!s.refill_alert_email || !mailer) return false;
  if (s.refill_alerted_at && now - new Date(s.refill_alerted_at + 'Z').getTime() < 86400000) return false;
  const bal = billing.getDerivedBalance(db, s.member_did);
  const why = r.skipped === 'daily cap reached'
    ? `its automatic refills reached the daily cap of ${s.refill_daily_cap_cents} DD in the last 24 hours`
    : `the refill failed: ${r.error}`;
  const text = [
    `@${s.handle} is low on DD: ${bal} DD, below its refill threshold of ${s.refill_threshold_cents} DD.`,
    `It was not refilled because ${why}.`,
    `Each DemiPass /use costs ${require('./billing').RATE_TABLE.api_call_compute} DD; at 0 DD its calls return 402 payment required.`,
    `The fleet owner can refill it by hand from the Fleet tab, or raise the cap.`,
  ].join('\n');
  try { mailer({ to: s.refill_alert_email, subject: `DemiPass: ${s.handle} is low on DD (${bal} DD)`, text }); } catch (_) {}
  db.prepare("UPDATE fleet_silicons SET refill_alerted_at = datetime('now') WHERE id = ?").run(s.id);
  return true;
}

// Email when an agent's newest token is in its last TOKEN_WARN_HOURS (or has lapsed, or there is none). The silicon's
// contact hears of every state, at most once per 24 h, as before. The fleet owner hears once per token: at the 24 h
// mark, or — if the pass missed that window — when it has lapsed (within OWNER_LAPSE_NOTICE_DAYS), with the Renew token
// button that fixes it (Aaron 2026-11-12; PR #100 review L5). A renewal picked up starts the notices over.
const OWNER_LAPSE_NOTICE_DAYS = 7;
function runTokenWarnings(db, { now = Date.now(), mailer = null } = {}) {
  // Network agents sign in themselves: the fleet mints nothing for them, so it does not warn about its tokens.
  const rows = db.prepare(`SELECT s.*, f.slug AS fleet_slug, f.name AS fleet_name, w.email AS owner_email FROM fleet_silicons s
                             JOIN fleets f ON f.id = s.fleet_id LEFT JOIN identity_wallets w ON w.did = f.owner_did
                            WHERE s.status = 'active' AND COALESCE(s.joined_via, 'owner') != 'network'`).all();
  const out = [];
  for (const s of rows) {
    const t = tokenStatus(db, s.member_did, now);
    if (t.status === 'valid') continue;
    const text = tokenWarningEmail({ silicon: s, token: t });
    const subject = `DemiPass: ${s.handle} token is ${t.status}`;
    let sent = false;
    if (s.contact_email && !(s.token_warned_at && now - new Date(s.token_warned_at + 'Z').getTime() < 86400000)) {
      if (mailer) { try { mailer({ to: s.contact_email, subject, text }); } catch (_) {} }
      db.prepare("UPDATE fleet_silicons SET token_warned_at = datetime('now') WHERE id = ?").run(s.id);
      sent = true;
    }
    const lapsedRecently = t.status === 'expired' && t.hours_left > -24 * OWNER_LAPSE_NOTICE_DAYS;
    if (s.owner_email && t.jti && (t.status === 'expiring' || lapsedRecently) && s.token_owner_warned_jti !== t.jti) {
      if (s.owner_email !== s.contact_email || !sent) { if (mailer) { try { mailer({ to: s.owner_email, subject, text }); } catch (_) {} } }
      db.prepare('UPDATE fleet_silicons SET token_owner_warned_jti = ? WHERE id = ?').run(t.jti, s.id);
      sent = true;
    }
    if (sent) out.push({ handle: s.handle, status: t.status });
  }
  return out;
}

function runRefills(db, billing, opts = {}) {
  const now = opts.now || Date.now();
  return {
    owner: runOwnerRefills(db, billing, { now, grantDids: opts.grantDids }),
    silicons: runSiliconRefills(db, billing, { now, ledger: opts.ledger, mailer: opts.mailer }),
    token_warnings: runTokenWarnings(db, { now, mailer: opts.mailer }),
    work_links_expired: expireWorkLinks(db, { now }),
  };
}

// ── Reporting ────────────────────────────────────────────────────────────────
function attributionReport(db, { payerDids = [], actorDids = [], sinceDays = 30 } = {}) {
  const since = sqlNow(new Date(Date.now() - sinceDays * 86400000));
  const conds = ['created_at >= ?'];
  const vals = [since];
  if (payerDids.length || actorDids.length) {
    const parts = [];
    if (payerDids.length) { parts.push(`payer_did IN (${payerDids.map(() => '?').join(',')})`); vals.push(...payerDids); }
    if (actorDids.length) { parts.push(`actor_did IN (${actorDids.map(() => '?').join(',')})`); vals.push(...actorDids); }
    conds.push('(' + parts.join(' OR ') + ')');
  }
  const rows = db.prepare(`SELECT payer_did, actor_did, project, initiator, COUNT(*) AS calls, SUM(cost_cents) AS cents
                           FROM billing_attributions WHERE ${conds.join(' AND ')}
                           GROUP BY payer_did, actor_did, project, initiator ORDER BY cents DESC`).all(...vals);
  return { since, rows };
}

function recentSpend(db, did, limit = 30) {
  return db.prepare(`SELECT t.id, t.amount_cents, t.type, t.description, t.balance_after, t.created_at,
                            a.project, a.initiator, a.payer_did, a.actor_did
                     FROM identity_transactions t LEFT JOIN billing_attributions a ON a.tx_id = t.id
                     WHERE t.did = ? ORDER BY t.id DESC LIMIT ?`).all(did, limit);
}

// ── Work links (silicon ↔ silicon, tick-scoped, revocable) ──────────────────
function hashToken(t) { return crypto.createHash('sha256').update(String(t)).digest('hex'); }

function createWorkLink(db, { requesterDid, providerDid, ttlTicks, ttlSeconds = WORK_LINK_DEFAULT_TTL_SECONDS, project = '', note = '', maxSpendCents = 0 }) {
  if (!requesterDid || !providerDid) throw Object.assign(new Error('requester and provider required'), { statusCode: 400 });
  if (requesterDid === providerDid) throw Object.assign(new Error('cannot link a silicon to itself'), { statusCode: 400 });
  const ttl = Number(ttlTicks);
  if (!Number.isInteger(ttl) || ttl < 1 || ttl > WORK_LINK_MAX_TTL_TICKS) throw Object.assign(new Error(`ttl_ticks: integer 1-${WORK_LINK_MAX_TTL_TICKS}`), { statusCode: 400 });
  const secs = Number(ttlSeconds);
  if (!Number.isInteger(secs) || secs < 60 || secs > 90 * 86400) throw Object.assign(new Error('ttl_seconds: integer 60-7776000'), { statusCode: 400 });
  if (project && !PROJECT_RE.test(project)) throw Object.assign(new Error('project: lowercase slug'), { statusCode: 400 });
  const cap = Number(maxSpendCents || 0);
  if (!Number.isInteger(cap) || cap < 0) throw Object.assign(new Error('max_spend_cents: integer >= 0'), { statusCode: 400 });
  const r = db.prepare(`INSERT INTO fleet_work_links (requester_did, provider_did, project, note, ttl_ticks, ttl_seconds, max_spend_cents)
                        VALUES (?, ?, ?, ?, ?, ?, ?)`).run(requesterDid, providerDid, project || '', String(note || '').slice(0, 300), ttl, secs, cap);
  return db.prepare('SELECT * FROM fleet_work_links WHERE id = ?').get(r.lastInsertRowid);
}

function acceptWorkLink(db, { id, providerDid, now = Date.now() }) {
  const link = db.prepare('SELECT * FROM fleet_work_links WHERE id = ?').get(id);
  if (!link) throw Object.assign(new Error('work link not found'), { statusCode: 404 });
  if (link.provider_did !== providerDid) throw Object.assign(new Error('only the provider can accept'), { statusCode: 403 });
  if (link.status !== 'pending') throw Object.assign(new Error(`work link is ${link.status}`), { statusCode: 409 });
  const token = 'dpw_' + crypto.randomBytes(24).toString('base64url');
  const start = currentTick(db);
  const end = start + link.ttl_ticks;
  const expiresAt = new Date(now + link.ttl_seconds * 1000).toISOString();
  db.prepare(`UPDATE fleet_work_links SET status = 'active', token_hash = ?, start_tick = ?, end_tick = ?, expires_at = ?, accepted_at = datetime('now') WHERE id = ?`)
    .run(hashToken(token), start, end, expiresAt, id);
  return { token, link: db.prepare('SELECT * FROM fleet_work_links WHERE id = ?').get(id) };
}

function declineWorkLink(db, { id, providerDid }) {
  const link = db.prepare('SELECT * FROM fleet_work_links WHERE id = ?').get(id);
  if (!link) throw Object.assign(new Error('work link not found'), { statusCode: 404 });
  if (link.provider_did !== providerDid) throw Object.assign(new Error('only the provider can decline'), { statusCode: 403 });
  if (link.status !== 'pending') throw Object.assign(new Error(`work link is ${link.status}`), { statusCode: 409 });
  db.prepare("UPDATE fleet_work_links SET status = 'declined', revoked_at = datetime('now'), revoked_by = ? WHERE id = ?").run(providerDid, id);
  return db.prepare('SELECT * FROM fleet_work_links WHERE id = ?').get(id);
}

function revokeWorkLink(db, { id, byDid }) {
  const link = db.prepare('SELECT * FROM fleet_work_links WHERE id = ?').get(id);
  if (!link) throw Object.assign(new Error('work link not found'), { statusCode: 404 });
  if (link.requester_did !== byDid && link.provider_did !== byDid) throw Object.assign(new Error('not a party to this work link'), { statusCode: 403 });
  if (!['pending', 'active'].includes(link.status)) throw Object.assign(new Error(`work link is already ${link.status}`), { statusCode: 409 });
  db.prepare("UPDATE fleet_work_links SET status = 'revoked', revoked_at = datetime('now'), revoked_by = ? WHERE id = ?").run(byDid, id);
  return db.prepare('SELECT * FROM fleet_work_links WHERE id = ?').get(id);
}

function validateWorkLink(db, token, providerDid, now = Date.now()) {
  if (!token) return { ok: false, error: 'missing' };
  const link = db.prepare('SELECT * FROM fleet_work_links WHERE token_hash = ?').get(hashToken(token));
  if (!link) return { ok: false, error: 'unknown token' };
  if (link.provider_did !== providerDid) return { ok: false, error: 'token belongs to another provider' };
  if (link.status !== 'active') return { ok: false, error: `link is ${link.status}` };
  const tick = currentTick(db);
  if (link.end_tick != null && tick > link.end_tick) {
    db.prepare("UPDATE fleet_work_links SET status = 'expired' WHERE id = ?").run(link.id);
    return { ok: false, error: `tick window closed (tick ${tick} > ${link.end_tick})` };
  }
  if (link.expires_at && new Date(link.expires_at).getTime() < now) {
    db.prepare("UPDATE fleet_work_links SET status = 'expired' WHERE id = ?").run(link.id);
    return { ok: false, error: 'wall-clock cap passed' };
  }
  return { ok: true, link, current_tick: tick };
}

function expireWorkLinks(db, { now = Date.now() } = {}) {
  const tick = currentTick(db);
  const r = db.prepare(`UPDATE fleet_work_links SET status = 'expired'
                        WHERE status = 'active' AND ((end_tick IS NOT NULL AND ? > end_tick) OR (expires_at IS NOT NULL AND expires_at < ?))`)
    .run(tick, new Date(now).toISOString());
  return r.changes;
}

function listWorkLinks(db, did) {
  return db.prepare(`SELECT id, requester_did, provider_did, project, note, ttl_ticks, ttl_seconds, start_tick, end_tick, expires_at,
                            status, use_count, spent_cents, max_spend_cents, created_at, accepted_at, revoked_at, revoked_by
                     FROM fleet_work_links WHERE requester_did = ? OR provider_did = ? ORDER BY id DESC LIMIT 100`).all(did, did);
}

// Resolve a hashed silicon id to a DID (platform-internal; callers decide what to expose).
function resolveSiliconId(db, sid) {
  const s = db.prepare('SELECT * FROM fleet_silicons WHERE silicon_id = ?').get(sid);
  if (s) return { did: s.member_did, handle: s.handle, display_name: s.display_name, fleet_id: s.fleet_id, silicon: s };
  return null;
}

// ── Subordinate workers ──────────────────────────────────────────────────────
const WORKER_NAME_RE = /^[a-z0-9][a-z0-9-]{1,30}$/;
const SCOPE_ORDER = ['read', 'write', 'transact'];

function workerId(parentDid, name, secret) {
  const key = secret || process.env.FLEET_ID_SECRET || process.env.IDENTITY_MASTER_KEY || 'dustforge-fleet-id';
  return 'wrk_' + crypto.createHmac('sha256', key).update(`${parentDid}:${name}`).digest('hex').slice(0, 16);
}

function _normalizeAllowed(list) {
  if (!list) return [];
  const arr = Array.isArray(list) ? list : String(list).split(',');
  return [...new Set(arr.map(x => String(x).trim()).filter(Boolean).map(x => x.slice(0, 120)))].slice(0, 50);
}

function createWorker(db, { parentDid, name, purpose = '', allowedSecrets = [], scopeCap = 'transact', maxSpendCents = 0, createdBy = '' }) {
  if (!WORKER_NAME_RE.test(name || '')) throw Object.assign(new Error('name: 2-31 chars, lowercase alphanumeric and hyphens'), { statusCode: 400 });
  if (!SCOPE_ORDER.includes(scopeCap)) throw Object.assign(new Error('scope_cap: read | write | transact'), { statusCode: 400 });
  const cap = Number(maxSpendCents || 0);
  if (!Number.isInteger(cap) || cap < 0 || cap > 10000000) throw Object.assign(new Error('max_spend_cents: integer 0-10000000'), { statusCode: 400 });
  const existing = db.prepare('SELECT * FROM fleet_workers WHERE parent_did = ? AND name = ?').get(parentDid, name);
  if (existing && existing.status === 'active') throw Object.assign(new Error('worker name already in use'), { statusCode: 409 });
  if (existing) db.prepare('DELETE FROM fleet_workers WHERE id = ?').run(existing.id);
  const wid = workerId(parentDid, name);
  db.prepare(`INSERT INTO fleet_workers (worker_id, parent_did, name, purpose, allowed_secrets, scope_cap, max_spend_cents, created_by)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
    .run(wid, parentDid, name, String(purpose || '').slice(0, 200), JSON.stringify(_normalizeAllowed(allowedSecrets)), scopeCap, cap, createdBy || parentDid);
  return getWorker(db, wid);
}

function getWorker(db, wid) {
  const w = db.prepare('SELECT * FROM fleet_workers WHERE worker_id = ?').get(wid);
  if (!w) return null;
  try { w.allowed = JSON.parse(w.allowed_secrets || '[]'); } catch (_) { w.allowed = []; }
  return w;
}

function listWorkers(db, parentDid) {
  return db.prepare('SELECT * FROM fleet_workers WHERE parent_did = ? ORDER BY id DESC').all(parentDid).map(w => {
    try { w.allowed = JSON.parse(w.allowed_secrets || '[]'); } catch (_) { w.allowed = []; }
    return w;
  });
}

function revokeWorker(db, { wid, byDid }) {
  const w = getWorker(db, wid);
  if (!w) throw Object.assign(new Error('worker not found'), { statusCode: 404 });
  if (w.status !== 'active') return w;
  db.prepare("UPDATE fleet_workers SET status = 'revoked', revoked_at = datetime('now'), revoked_by = ? WHERE id = ?").run(byDid || '', w.id);
  try { db.prepare("UPDATE issued_tokens SET revoked = 1, revoked_at = datetime('now') WHERE jti = ? AND revoked = 0").run(w.last_jti || ''); } catch (_) {}
  return getWorker(db, wid);
}

// Claims to mint for a worker token: scope capped, TTL capped at 30 days (identity.js clamps per scope too).
function workerTokenClaims(worker, { scope = 'transact', expiresIn = '24h' } = {}) {
  if (!SCOPE_ORDER.includes(scope)) throw Object.assign(new Error('scope: read | write | transact'), { statusCode: 400 });
  const capIdx = SCOPE_ORDER.indexOf(worker.scope_cap);
  const effScope = SCOPE_ORDER[Math.min(SCOPE_ORDER.indexOf(scope), capIdx)];
  if (!/^\d+[smhd]$/.test(String(expiresIn))) throw Object.assign(new Error('expires_in: e.g. 1h, 24h, 7d (max 30d)'), { statusCode: 400 });
  const m = String(expiresIn).match(/^(\d+)([smhd])$/);
  const secs = Number(m[1]) * ({ s: 1, m: 60, h: 3600, d: 86400 })[m[2]];
  const eff = Math.min(secs, 30 * 86400);
  return { scope: effScope, expiresIn: `${eff}s`, metadata: { wrk: worker.worker_id, wname: worker.name, auth_method: 'worker' } };
}

function recordWorkerToken(db, worker, claims) {
  db.prepare('UPDATE fleet_workers SET last_jti = ?, token_expires_at = ? WHERE id = ?')
    .run(claims.jti || '', claims.exp ? new Date(claims.exp * 1000).toISOString() : null, worker.id);
}

// A decoded token with a `wrk` claim must match a live worker whose parent is the token subject.
function resolveWorker(db, decoded) {
  if (!decoded || !decoded.wrk) return { ok: true, worker: null };
  const w = getWorker(db, String(decoded.wrk));
  if (!w) return { ok: false, status: 401, error: 'unknown worker' };
  if (w.parent_did !== decoded.sub) return { ok: false, status: 401, error: 'worker/parent mismatch' };
  if (w.status !== 'active') return { ok: false, status: 401, error: `worker ${w.worker_id} is ${w.status}` };
  return { ok: true, worker: w };
}

// Worker tokens may only touch the secrets on their allow-list (by ref code or name); an empty list means
// "whatever the parent may use".
function workerMayUseSecret(db, decoded, secret) {
  const r = resolveWorker(db, decoded);
  if (!r.ok) return r;
  if (!r.worker) return { ok: true };
  const allowed = r.worker.allowed || [];
  if (!allowed.length) return { ok: true, worker: r.worker };
  const ok = allowed.includes(secret.ref_code) || allowed.includes(secret.name);
  return ok ? { ok: true, worker: r.worker } : { ok: false, status: 403, error: `worker ${r.worker.worker_id} may not use secret '${secret.name}'`, worker: r.worker };
}

function workerView(w) {
  return { worker_id: w.worker_id, name: w.name, purpose: w.purpose, allowed_secrets: w.allowed || [], scope_cap: w.scope_cap,
           max_spend_cents: w.max_spend_cents, spent_cents: w.spent_cents, use_count: w.use_count, status: w.status,
           token_expires_at: w.token_expires_at, created_at: w.created_at, created_by: w.created_by, revoked_at: w.revoked_at };
}

// Secrets a silicon uses: its own stored secrets + the ones delegated to it.
function siliconSecrets(db, did) {
  const own = db.prepare(`SELECT id, name, ref_code, secret_type, status, use_count, last_used_at, category, created_at
                          FROM blindkey_secrets WHERE did = ? AND status IN ('active','frozen') ORDER BY name`).all(did);
  const delegated = db.prepare(`SELECT d.id AS delegation_id, d.status, d.max_uses, d.use_count, d.granted_at, d.expires_at, d.owner_did,
                                       b.name AS secret_name, b.ref_code, b.secret_type, b.last_used_at
                                FROM demipass_delegations d JOIN blindkey_secrets b ON b.id = d.secret_id
                                WHERE d.delegate_did = ? ORDER BY d.granted_at DESC LIMIT 100`).all(did);
  return { own, delegated };
}

// ── Claims (mailbox-consent link for existing identities) ───────────────────
function issueClaim(db, siliconRow, { ttlHours = 72 } = {}) {
  const code = 'clm_' + crypto.randomBytes(18).toString('base64url');
  const exp = new Date(Date.now() + ttlHours * 3600000).toISOString();
  db.prepare("UPDATE fleet_silicons SET status = 'pending_claim', claim_code = ?, claim_expires_at = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?")
    .run(hashToken(code), exp, siliconRow.id);
  return { code, expires_at: exp };
}

function redeemClaim(db, code) {
  const row = db.prepare("SELECT * FROM fleet_silicons WHERE claim_code = ? AND status = 'pending_claim'").get(hashToken(code || ''));
  if (!row) return { ok: false, error: 'unknown or already used claim' };
  if (row.claim_expires_at && new Date(row.claim_expires_at).getTime() < Date.now()) return { ok: false, error: 'claim expired' };
  const fleet = db.prepare('SELECT * FROM fleets WHERE id = ?').get(row.fleet_id);
  const why = fleet ? joinBlocker(db, fleet, row.member_did) : 'fleet not found';
  if (why) return { ok: false, error: why };
  const txn = db.transaction(() => {
    db.prepare("UPDATE fleet_silicons SET status = 'active', claim_code = '', claim_expires_at = '', updated_at = CURRENT_TIMESTAMP WHERE id = ?").run(row.id);
    db.prepare("INSERT OR IGNORE INTO fleet_members (fleet_id, member_did, role) VALUES (?, ?, 'agent')").run(row.fleet_id, row.member_did);
  });
  txn();
  return { ok: true, silicon: db.prepare('SELECT * FROM fleet_silicons WHERE id = ?').get(row.id) };
}

function claimEmail({ silicon, fleet, claimUrl }) {
  return [
    `The DemiPass fleet "${fleet.name}" (${fleet.slug}) wants to add this identity as "${silicon.handle}".`,
    ``,
    `DID: ${silicon.member_did}`,
    ``,
    `Joining lets the fleet owner mint tokens for this wallet (acting as it, up to 30 days each), see its balance`,
    `and spend, refill it, and delegate secrets to it.`,
    `If that is expected, confirm with this one-time link (valid 72 hours):`,
    ``,
    `  ${claimUrl}`,
    ``,
    `If you did not expect this, ignore it; nothing changes.`,
  ].join('\n');
}

// ── Mail bodies ──────────────────────────────────────────────────────────────
function didRecordEmail({ silicon, fleet, wallet, apiBase = 'https://api.dustforge.com' }) {
  return [
    `This is the identity record for "${silicon.display_name || silicon.handle}" in the DemiPass fleet "${fleet.name}" (${fleet.slug}).`,
    ``,
    `Handle:       ${silicon.handle}`,
    `Silicon id:   ${silicon.silicon_id}   (hashed alias; share this instead of the DID)`,
    `DID:          ${silicon.member_did}`,
    `Username:     ${wallet.username || '-'}`,
    `Mailbox:      ${wallet.email || '-'}`,
    `Fleet owner:  ${fleet.owner_username || fleet.owner_did}`,
    ``,
    `What this means:`,
    `  - Calls you make with your own token are billed to your own Diamond Dust wallet.`,
    `  - Work the fleet owner asks of you can be billed to the owner by sending the header`,
    `    X-DemiPass-Billing: {"project":"<project>","initiator":"operator"}  (you must be an operator on that project).`,
    `  - Autonomous work on a project: send "initiator":"autonomous"; it stays on your wallet, the project is recorded.`,
    `  - Another silicon can ask you to work for them through a work link; their wallet pays while the link is live.`,
    `  - If the owner enabled auto-refill for you, your wallet is topped up from theirs when it drops below the threshold.`,
    ``,
    `Mint a token:  POST ${apiBase}/api/identity/auth-fingerprint  {"username":"${wallet.username || '<username>'}","password":"<password>","scope":"transact","expires_in":"30d"}`,
    `Your balance:  GET  ${apiBase}/api/identity/balance`,
    `Fleet page:    https://demipass.com/vault-mobile.html  (owner view, Fleet tab)`,
    ``,
    `Keep this message: it is your record of the DID that was issued to you.`,
  ].join('\n');
}

// Time left, said plainly: hours in the last day (never "0 hours" or "1 days"), days before that.
function timeLeftText(token) {
  const h = token.hours_left;
  if (h != null && h <= 24) return h < 1 ? 'less than an hour left' : `${Math.floor(h)} hour${Math.floor(h) === 1 ? '' : 's'} left`;
  return `${token.days_left} days left`;
}
function tokenWarningEmail({ silicon, token }) {
  const line = token.status === 'none' ? 'has no live access token on record'
    : token.status === 'expired' ? `token expired at ${token.expires_at}`
    : `token expires at ${token.expires_at} (${timeLeftText(token)})`;
  return [
    `DemiPass fleet notice for "${silicon.display_name || silicon.handle}" (${silicon.fleet_slug}):`,
    ``,
    `  ${silicon.handle} ${line}.`,
    ...(token.awaiting_pickup ? [``, `A renewal is waiting for ${silicon.handle} since ${token.awaiting_pickup.since}: it has not picked it up yet.`] : []),
    ``,
    `The fleet owner can renew it: DemiPass app → Fleet → @${silicon.handle} → "Renew token" (your PIN).`,
    `The new token is sealed to the agent's delivery key and nobody sees it; the agent picks it up with`,
    `  node bin/token-pickup.js <dir>      (once registered with: node bin/token-pickup.js --init <dir>)`,
    `which writes <dir>/token (0600).`,
    ``,
    `You get at most one of these per day.`,
  ].join('\n');
}

// ── Daily spend per wallet, read from the ledger (Aaron 2026-11-14: "a per-wallet daily spend line (calls, DD, by
// action)"). Spend = the wallet's debits, net of their refunds; DD moved to another wallet (transfers, refills, fleet
// funding, escrow) is not spend. Days are UTC. Actions: a /use is `use`; a service charge is `<tenant>/<action>` and a
// meter charge `meter:<tenant>/<sku>` (read from the row's description, which the server writes); anything else is
// the ledger type. A refund row counts against its action: its DD comes back and the call is counted as refunded.
const NOT_SPEND_TYPES = ['transfer_out', 'fleet_transfer_refill_out', 'fleet_project_removed_transfer_out', 'fleet_fund',
  'escrow_lock', 'fleet_provision', 'fleet_bulk_provision'];
const DAILY_SPEND_MAX_DAYS = 31;
function dailySpend(db, did, days = 7) {
  const n = Math.min(DAILY_SPEND_MAX_DAYS, Math.max(1, parseInt(days, 10) || 7));
  const since = new Date(Date.now() - (n - 1) * 86400000).toISOString().slice(0, 10);   // UTC midnight, n days incl. today
  const rows = db.prepare(`
    SELECT date(created_at) AS day,
           CASE
             WHEN type IN ('api_call_compute', 'api_call_compute_refund') AND (description LIKE 'API call:%' OR description LIKE 'Refund:%') THEN 'use'
             WHEN type = 'service_transfer_out' AND description LIKE 'service %/% %'
               THEN substr(description, 9, instr(substr(description, 9), ' ') - 1)
             WHEN type = 'meter_charge' AND description LIKE 'meter %/% %'
               THEN 'meter:' || substr(description, 7, instr(substr(description, 7), ' ') - 1)
             WHEN substr(type, -7) = '_refund' THEN substr(type, 1, length(type) - 7)
             ELSE type
           END AS action,
           SUM(CASE WHEN amount_cents < 0 THEN 1 ELSE 0 END) AS calls,
           SUM(CASE WHEN amount_cents > 0 THEN 1 ELSE 0 END) AS refunded,
           -SUM(amount_cents) AS dd
    FROM identity_transactions
    WHERE did = ? AND date(created_at) >= ?
      AND ((amount_cents < 0 AND type NOT IN (${NOT_SPEND_TYPES.map(() => '?').join(',')}))
           OR (amount_cents > 0 AND substr(type, -7) = '_refund'))
    GROUP BY day, action ORDER BY day DESC, dd DESC`).all(did, since, ...NOT_SPEND_TYPES);
  const byDay = new Map();
  for (const r of rows) {
    const d = byDay.get(r.day) || { date: r.day, calls: 0, refunded: 0, dd: 0, by_action: {} };
    d.calls += r.calls; d.refunded += r.refunded; d.dd += r.dd;
    d.by_action[r.action] = { calls: r.calls, refunded: r.refunded, dd: r.dd };
    byDay.set(r.day, d);
  }
  return { since, days: [...byDay.values()] };
}

module.exports = {
  dailySpend, NOT_SPEND_TYPES, DAILY_SPEND_MAX_DAYS,
  ownedOutright, fleetExitRefusal, endOwnerDelegations, creatorOf, operatorGrantAllowed, OWNER_REFILL_MAX,
  initSchema, siliconId, currentTick, parseAttribution, findProjectForCaller, resolvePayer, chargeAttributed,
  getSilicon, upsertSilicon, updateSiliconSettings, siliconView, tokenStatus, latestToken, awaitingPickup, deliveryKeyFingerprint, deliveryKeyView, setAskRevokedCheck,
  thresholdRefill, maybeThresholdRefill, autoRefilledLast24h, agentFleetOwner, answerTopups, fromItsFleet, transferRefill, projectWalletOwned, removeProject, setOwnerRefillRule, getOwnerRefillRule, nextRunAfter,
  runOwnerRefills, runSiliconRefills, runTokenWarnings, runRefills,
  attributionReport, recentSpend,
  createWorkLink, acceptWorkLink, declineWorkLink, revokeWorkLink, validateWorkLink, expireWorkLinks, listWorkLinks, resolveSiliconId,
  issueClaim, redeemClaim, claimEmail, hashToken,
  activeFleetOf, ownsFleetWithAgents, joinBlocker, clearStaleSiliconRows, cutFleetTokens, signOutEverywhere, revokeOwnerWorkers,
  workerId, createWorker, getWorker, listWorkers, revokeWorker, workerTokenClaims, recordWorkerToken, resolveWorker, workerMayUseSecret, workerView, siliconSecrets,
  didRecordEmail, tokenWarningEmail, timeLeftText,
  HANDLE_RE, PROJECT_RE, INITIATORS, TOKEN_WARN_DAYS, TOKEN_WARN_HOURS, REFILL_COOLDOWN_MS,
};
