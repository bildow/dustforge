'use strict';
// ── Security depth on use: per-use human approval (docs/approvals.md) ─────────────────────────────────────────────
// A secret's owner sets its depth (standard / elevated / critical, the existing security_depth). It is a property of
// the secret, so every share and delegation inherits it and no recipient can lower it (only the owner sets depth).
//   standard  — a delegation is enough, as before.
//   elevated  — every /use needs the owner's approval of THAT use. The call that finds none creates a pending request
//               (id, requester, secret ref, purpose, the exact action/target/params it binds, TTL 5 min), the owner is
//               notified, and the caller gets 202 approval_pending with the request id: it parks the task, no retry
//               loop. Opening the request screen starts a 6-digit code bound to that request id, rotating every 30 s
//               until approved or expired. Either the owner taps Approve (the app sends the code server-side; nobody
//               types it) or reads the code to the agent in another channel and the agent sends it with its /use.
//               One use per approval. Three wrong codes cancel the request (critical event).
//   critical  — the same, plus the owner's PIN to open the request screen at all; reveal also takes PIN + code.
//
// The code binding is channel-independent: code = HMAC(code_key of the request, "dp-approval:<id>:<30 s step>").
// A channel only DELIVERS it — today the app screen (`open`); later SMS via Riley — so adding a channel changes
// nothing about what a code proves: this request, this 30-second window, nothing else. A code seen in a transcript
// opens no other request, and is dead within a minute.

const crypto = require('crypto');

const TTL_SEC = 5 * 60;           // an approved request waiting to be used (and the code window: item 4c)
// How long a request waits for the owner (Aaron 2026-11-08: "every wait is a request I approve in the app"). A use of a
// secret waits an hour: the phone checks every 15 minutes and on open, so a 5-minute request expired before it was
// seen (approvals 17-20, 26). DemiPass's own grants (svc:demipass:* — consent, registration,
// weakening a gate) wait a day. Codes still rotate every 30 s and an approval is still used within 5 minutes.
const PENDING_TTL_SEC = 60 * 60;
const GRANT_PENDING_TTL_SEC = 24 * 3600;
const GRANT_APPROVED_TTL_SEC = 60 * 60;    // the requester collects a grant when it next polls
const isGrantKey = (k) => typeof k === 'string' && k.startsWith('svc:demipass:');
const MAX_PENDING_GRANTS_OWN = 10;   // the owner's own DID's grant requests waiting at once, across all its labels
const STEP_SEC = 30;              // code rotation
const MAX_WRONG = 3;
const MAX_PENDING_PER_OWNER = 30;
const MAIL_PER_OWNER_PER_HOUR = 20;
const DEPTHS = new Set(['elevated', 'critical']);
// Keys that steer the approval itself, never part of what it binds.
// The raw request body is bound as sent (top level and `params` both, never a merged view — /use paths read from
// either), minus only the per-call token and these steering fields.
const META_KEYS = new Set(['use_token', 'approval_id', 'approval_code', 'purpose', 'admin_key']);
const MAX_BOUND_JSON = 4096;      // a call the owner cannot read in full is not offered for approval
const MAX_PENDING_PER_REQUESTER = 5;
const DENY_COOLDOWN_SEC = 10 * 60;  // after the owner denies a requester, it may not ask that owner again for 10 minutes

module.exports = function registerUseApprovals(deps) {
  const { app, db, rateLimitStandard, rateLimitFill, getBearerIdentity, gateSession, gateFresh, gateMissing, spendSingleUse,
          logSecurityEvent, cleanLabel, billing, sendMail, deviceKeys, cryptoDepth } = deps;
  // ref_code too: the phone refuses an unwrap whose ref is not the secret's own (crypto_depth approvalView → DeviceBridge.unwrap;
  // missing, every wrapped approval failed on the phone with "which secret this is for is missing" — Aaron 2026-11-08, approval 34).
  const secretOf = (id) => db.prepare('SELECT id, name, ref_code, did, wrap_state, wrapped_value, security_depth FROM blindkey_secrets WHERE id = ?').get(id);
  const limiter = rateLimitFill || rateLimitStandard;

  db.exec(`CREATE TABLE IF NOT EXISTS use_approvals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL DEFAULT 'use',            -- 'use' | 'reveal'
    secret_id INTEGER NOT NULL,
    owner_did TEXT NOT NULL,
    requester_did TEXT NOT NULL,
    requester_label TEXT DEFAULT '',
    delegation_id INTEGER,
    depth TEXT NOT NULL,
    purpose TEXT DEFAULT '',
    summary TEXT DEFAULT '',
    binding TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',      -- pending | approved | used | denied | expired | cancelled
    code_key TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    opened_at TEXT, opened_session TEXT, opened_via TEXT,
    approved_at TEXT, approved_via TEXT,
    used_at TEXT, decided_at TEXT,
    wrong_codes INTEGER DEFAULT 0,
    notified_at TEXT,
    bound_call TEXT DEFAULT ''
  )`);
  try { db.exec("ALTER TABLE use_approvals ADD COLUMN bound_call TEXT DEFAULT ''"); } catch (_) {}
  // Item 1 (crypto_depth.js): a wrapped secret's one-use public key, and the phone's unwrap between Approve and use.
  for (const c of ['eph_pub TEXT DEFAULT NULL', 'unwrap_blob TEXT DEFAULT NULL']) { try { db.exec('ALTER TABLE use_approvals ADD COLUMN ' + c); } catch (_) {} }
  // Service tenants (service_tenants.js): an elevated service action is approved like an elevated secret's use. Its row
  // has secret_id 0 and service_key 'svc:<tenant>:<action>' (no secret exists; /use never matches it: secret ids are > 0).
  try { db.exec('ALTER TABLE use_approvals ADD COLUMN service_key TEXT DEFAULT NULL'); } catch (_) {}
  db.exec('CREATE INDEX IF NOT EXISTS idx_ua_owner ON use_approvals(owner_did, status)');
  db.exec('CREATE INDEX IF NOT EXISTS idx_ua_requester ON use_approvals(requester_did, status)');
  // A wrapped secret's request needs its one-use key, which lives only in this process's memory (crypto_depth.js). At
  // start there are none, so every such request still waiting (or approved, its unwrap made to a key now gone) can never
  // be used: end it here, so the requester can ask again at once instead of being handed the dead one back as
  // already_pending until it times out (Aaron 2026-11-08, approval 34 after the #80 deploy).
  try {
    // A scope change (kind 'scope') uses no value and no key: it survives a restart whatever the secret's wrap state.
    const dead = db.prepare(`SELECT a.id, a.requester_did, a.secret_id FROM use_approvals a JOIN blindkey_secrets s ON s.id = a.secret_id
        WHERE a.status IN ('pending', 'approved') AND a.kind != 'scope' AND (a.eph_pub IS NOT NULL OR s.wrap_state = 'device')`).all();
    const end = db.prepare("UPDATE use_approvals SET status = 'expired', decided_at = ?, unwrap_blob = NULL WHERE id = ? AND status IN ('pending', 'approved')");
    for (const r of dead) {
      end.run(new Date().toISOString(), r.id);
      try { db.prepare('INSERT INTO blindkey_events (event_type, actor, secret_id, context_name, detail) VALUES (?, ?, ?, ?, ?)')
        .run('approval_expired', 'server', r.secret_id, '*', JSON.stringify({ approval_id: r.id, reason: 'server restart: its one-use key is gone; ask again' })); } catch (_) {}
    }
    if (dead.length) console.log(`[approvals] ${dead.length} wrapped-secret request(s) ended at start (one-use keys do not survive a restart)`);
  } catch (_) { /* no wrap columns yet: nothing is wrapped */ }

  const nowIso = () => new Date().toISOString();
  const later = (sec) => new Date(Date.now() + sec * 1000).toISOString();
  const isPast = (iso) => !iso || Date.parse(iso) <= Date.now();
  const usernameOf = (did) => (db.prepare('SELECT username FROM identity_wallets WHERE did = ?').get(did) || {}).username || null;
  const event = (type, actor, secretId, detail) => db.prepare('INSERT INTO blindkey_events (event_type, actor, secret_id, context_name, detail) VALUES (?, ?, ?, ?, ?)')
    .run(type, actor, secretId, '*', JSON.stringify(detail));

  // ── depth and binding ──────────────────────────────────────────────────────────────────────────────────────────
  function depthOf(secret) {
    const d = secret && secret.security_depth;
    return DEPTHS.has(d) ? d : 'standard';
  }
  const BAD_KEYS = new Set(['__proto__', 'constructor', 'prototype']);
  function canonical(v) {
    if (Array.isArray(v)) return v.map(canonical);
    if (v && typeof v === 'object') { const o = Object.create(null); for (const k of Object.keys(v).sort()) o[k] = canonical(v[k]); return o; }
    return v;
  }
  // A call the owner could misread is refused before it is offered: the same key at the top level and inside
  // `params` with different values (paths read one or the other), or keys that do not survive as plain data.
  function ambiguity(body) {
    const walk = (v) => { if (v && typeof v === 'object') { for (const k of Object.keys(v)) { if (BAD_KEYS.has(k)) return k; const r = walk(v[k]); if (r) return r; } } return null; };
    const bad = walk(body);
    if (bad) return `the call carries a '${bad}' key — not accepted on an elevated/critical secret`;
    const p = body && body.params;
    if (p && typeof p === 'object' && !Array.isArray(p)) {
      for (const k of Object.keys(p)) if (Object.prototype.hasOwnProperty.call(body, k) && k !== 'params' && JSON.stringify(canonical(body[k])) !== JSON.stringify(canonical(p[k]))) {
        return `ambiguous call: '${k}' differs between the top level and params — send it once (or the same in both)`;
      }
    }
    return null;
  }
  // What an approval binds: this secret, this action, this target, these exact parameters (the command, the body).
  function boundCall({ kind = 'use', action = '', targetHost = '', targetUrl = '', params = {} }) {
    const p = {};
    for (const [k, v] of Object.entries(params || {})) if (!META_KEYS.has(k)) p[k] = v;
    return canonical({ kind, action, target_host: targetHost || '', target_url: targetUrl || '', body: p });
  }
  function bindingOf({ secretId, ...use }) {
    return crypto.createHash('sha256').update(JSON.stringify({ secretId, call: boundCall(use) })).digest('hex');
  }
  // A one-line headline for the card. The owner approves the full bound call (`call`, shown as JSON), never this alone.
  function summaryOf({ kind, action, targetHost, targetUrl, params }) {
    if (kind === 'reveal') return 'reveal the value';
    if (kind === 'scope') {
      // A change to what the secret reaches (server.js scopeChangeGate): the card names the scope, the methods and
      // the agent it is handed to; the owner approves the full bound change below it.
      const q = params || {};
      const who = (d) => String(d || '').replace(/^did:key:/, '').slice(0, 12) + '…';
      // A GitHub App scope (github_app.js): repositories and permissions are what the owner is approving.
      const g = q.github_app && typeof q.github_app === 'object' ? q.github_app : null;
      // Permissions first, so they stay on the card when a long repository list is cut (#104 review L7).
      const ghHead = (lead) => {
        const perms = g.permissions && typeof g.permissions === 'object' ? Object.entries(g.permissions).map(([k, l]) => `${k}:${l}`).join(', ') : '?';
        const repos = Array.isArray(g.repositories) ? g.repositories.join(', ') : '?';
        const head = `${lead}${perms} on `, room = 120 - head.length;
        return head + (repos.length <= room ? repos : repos.slice(0, Math.max(0, room - 1)) + '…');
      };
      const gh = g ? true : null;
      const methods = Array.isArray(q.allowed_methods) ? (q.allowed_methods.length ? q.allowed_methods.map(m => String(m).toUpperCase()).join('/') + ' only' : 'no method') : null;
      const what = action === 'delegate' ? `hand it to agent ${who(q.delegate_did)}${q.context_name ? ` for scope '${q.context_name}'` : ' for every scope'}`
        : action === 'context-add' && gh ? ghHead(`new GitHub scope '${String(q.context_name).slice(0, 30)}'${q.delegate_did ? ` for agent ${who(q.delegate_did)}` : ''}: `)
        : action === 'context-add' ? `new scope '${q.context_name}': ${q.action_type}${methods ? ' ' + methods : ''} on ${targetUrl || targetHost || 'any host'}${q.delegate_did ? `, handed to agent ${who(q.delegate_did)}` : ''}`
        : action === 'context-edit' && gh ? ghHead(`change GitHub scope${q.status ? ` (${q.status})` : ''}: `)
        : action === 'context-edit' ? `change scope: ${methods ? methods + ' on ' : ''}${targetUrl || targetHost || 'any host'}${q.status ? ` (${q.status})` : ''}`
        : `${action}: ${targetUrl || targetHost || ''}`;
      return cleanLabel(what, 120);
    }
    if (kind === 'service') {
      // Name what is granted, so two requests never look alike on the card (#77 review L2).
      const q = params || {};
      const what = action === 'consent' ? `let ${String(q.wallet || '').slice(0, 24)}… pay ${q.service} up to ${q.daily_cap_dd} DD a day`
        : action === 'register' ? `register service ${q.slug} (${q.name})`
        : action === 'owner-refill' ? `scheduled refill of ${q.amount_cents} DD ${q.cadence} to your own wallet`
        : action === 'owner-grant' ? `operator grant of ${q.amount_cents} DD to your own wallet`
        : action === 'weaken' ? `weaken ${q.service}: ${(q.changes || []).map(c => c.action + (c.follow_ups ? ` (then bills ${c.follow_ups.join('/')} later)` : '')).join(', ')}`
        : action === 'mail-webhook' ? `let Resend report delivered/bounced/complained to ${q.endpoint}`
        : action === 'outside-ask' ? `your agent asks @${q.person} (your in-person contact) for ${q.secret || 'a secret'}: "${String(q.reason || '').slice(0, 60)}"`
        : action === 'rotate-blind' ? `rotate the password of ${q.target_user}@${targetHost || ''} blind (a new random one, stored in your vault)`
        : action === 'delegation-widen' ? `widen agent delegation #${q.delegation_id}: ${[q.may_rotate === true ? 'it may rotate the password' : '', q.timeout_seconds ? `calls may wait up to ${q.timeout_seconds} s` : ''].filter(Boolean).join('; ')}`
        : action === 'rotate-forgejo' ? `rotate the Forgejo login of ${q.username} blind (a new random one, stored in your vault)`
        : action === 'margin' ? `${q.service}: margin ${q.was}% → ${q.margin_pct}% over cost on every call`
        : action === 'connect' ? `point callers of ${q.service} at ${q.endpoint || '(nothing)'}; agents run ${q.mcp_server || '(no MCP server)'}`
        : `${targetHost || ''}: ${action}`;
      return cleanLabel(what, 120);
    }
    const p = params || {};
    const cmd = (p.params && p.params.command) || p.command || '';
    const what = action === 'ssh_exec' ? `ssh ${targetHost || ''}: ${JSON.stringify(String(cmd)).slice(1, -1)}` : `${action} ${targetUrl || targetHost || ''}`;
    return cleanLabel(what, 120) + (what.length > 120 ? ' …(see the full call)' : '');
  }

  // ── codes ──────────────────────────────────────────────────────────────────────────────────────────────────────
  const stepNow = () => Math.floor(Date.now() / 1000 / STEP_SEC);
  function codeAt(row, step) {
    // Bound to the request id, its secret and its requester (red team item 4c), and the 30-s step.
    const mac = crypto.createHmac('sha256', Buffer.from(row.code_key, 'hex')).update(`dp-approval:${row.id}:${row.secret_id}:${row.requester_did}:${step}`).digest();
    return String(mac.readUInt32BE(0) % 1000000).padStart(6, '0');
  }
  // The current code or the one just before it (a code read aloud may cross a 30-s boundary). Constant-time compare.
  function codeMatches(row, code) {
    if (typeof code !== 'string' || !/^\d{6}$/.test(code) || !row.opened_at) return false;
    const s = stepNow();
    return [s, s - 1].some(st => crypto.timingSafeEqual(Buffer.from(codeAt(row, st)), Buffer.from(code)));
  }

  // ── lifecycle ──────────────────────────────────────────────────────────────────────────────────────────────────
  function expireOld() {
    // A request that ends takes its one-use key with it (item 1: no private half outside an active window).
    const gone = db.prepare("SELECT id FROM use_approvals WHERE status IN ('pending', 'approved') AND expires_at <= ? AND eph_pub IS NOT NULL").all(nowIso());
    db.prepare("UPDATE use_approvals SET status = 'expired', decided_at = ?, unwrap_blob = NULL WHERE status IN ('pending', 'approved') AND expires_at <= ?").run(nowIso(), nowIso());
    if (cryptoDepth && cryptoDepth.dropEphemeral) for (const r of gone) cryptoDepth.dropEphemeral('a:' + r.id);
  }
  function view(row, me) {
    const owner = row.owner_did === me;
    const s = row.service_key ? { name: String(row.service_key).replace(/^svc:/, '').replace(':', ' · ') } : (db.prepare('SELECT name, ref_code FROM blindkey_secrets WHERE id = ?').get(row.secret_id) || {});
    return {
      id: row.id, kind: row.kind, status: row.status, depth: row.depth,
      secret: { name: s.name || null, ref: s.ref_code || null }, ...(row.service_key ? { service: row.service_key } : {}),
      owner: usernameOf(row.owner_did), requester: usernameOf(row.requester_did), requester_label: row.requester_label || null,
      purpose: row.purpose || '', summary: row.summary || '',
      ...(owner ? { call: row.bound_call ? JSON.parse(row.bound_call) : null, binding: row.binding } : {}),   // binding: what the phone signs
      created_at: row.created_at, expires_at: row.expires_at,
      ...(owner ? { opened: Boolean(row.opened_at), needs_pin_to_open: true } : {}),
      ...(owner && cryptoDepth && row.eph_pub ? (() => { const u = cryptoDepth.approvalView(row, secretOf(row.secret_id)); return u ? { unwrap: u } : {}; })() : {}),
      ...(row.approved_at ? { approved_at: row.approved_at, approved_via: row.approved_via } : {}),
      ...(row.used_at ? { used_at: row.used_at } : {}), ...(row.wrong_codes ? { wrong_codes: row.wrong_codes } : {}),
    };
  }
  // The owner's notice: that an approval is pending, nothing else (it may show on a locked phone).
  function notifyOwner(row) {
    if (!sendMail) return;
    try {
      const sent = db.prepare("SELECT COUNT(*) AS n FROM use_approvals WHERE owner_did = ? AND notified_at > ?").get(row.owner_did, new Date(Date.now() - 3600000).toISOString()).n;
      if (sent >= MAIL_PER_OWNER_PER_HOUR) return;
      const w = db.prepare('SELECT email, recovery_email FROM identity_wallets WHERE did = ?').get(row.owner_did) || {};
      const to = w.recovery_email || w.email;
      if (!to) return;
      db.prepare('UPDATE use_approvals SET notified_at = ? WHERE id = ?').run(nowIso(), row.id);
      Promise.resolve(sendMail({ to, subject: 'DemiPass: an approval is pending',
        text: 'An approval is pending in your DemiPass app.\n\nhttps://demipass.com/app\n' })).catch(() => {});
    } catch (_) {}
  }
  function createRequest({ secret, kind, requesterDid, label, delegationId, purpose, binding, summary, call }) {
    const callJson = JSON.stringify(call);
    if (Buffer.byteLength(callJson) > MAX_BOUND_JSON) return { error: `this call is too large to show the owner in full for approval (${Buffer.byteLength(callJson)} bytes > ${MAX_BOUND_JSON}); send a smaller one`, status: 413 };
    // An owner's own agents all request as the owner's DID: split by agent label only then. Anyone else gets 5 per DID,
    // whatever labels it signs in under (labels are self-chosen).
    const own = requesterDid === secret.did;
    const mine = own
      ? db.prepare("SELECT COUNT(*) AS n FROM use_approvals WHERE requester_did = ? AND owner_did = ? AND requester_label = ? AND status = 'pending'").get(requesterDid, secret.did, cleanLabel(label || '', 80)).n
      : db.prepare("SELECT COUNT(*) AS n FROM use_approvals WHERE requester_did = ? AND owner_did = ? AND status = 'pending'").get(requesterDid, secret.did).n;
    if (mine >= MAX_PENDING_PER_REQUESTER) return { error: `you already have ${mine} requests waiting on this owner; wait for them`, status: 429 };
    // A denial is an answer (red team item 4a): the requester waits before asking this owner again.
    // Keyed like the pending cap: the owner's own agents per label (one denied agent does not lock out the others or
    // the owner's own reveals), anyone else per DID.
    const since = new Date(Date.now() - DENY_COOLDOWN_SEC * 1000).toISOString();
    const denied = own
      ? db.prepare("SELECT decided_at FROM use_approvals WHERE requester_did = ? AND owner_did = ? AND requester_label = ? AND status = 'denied' AND decided_at > ? ORDER BY decided_at DESC LIMIT 1")
          .get(requesterDid, secret.did, cleanLabel(label || '', 80), since)
      : db.prepare("SELECT decided_at FROM use_approvals WHERE requester_did = ? AND owner_did = ? AND status = 'denied' AND decided_at > ? ORDER BY decided_at DESC LIMIT 1")
          .get(requesterDid, secret.did, since);
    if (denied) {
      const until = new Date(Date.parse(denied.decided_at) + DENY_COOLDOWN_SEC * 1000).toISOString();
      return { error: `the owner denied your last request — you can ask again after ${until}`, status: 429, extra: { cooldown_until: until } };
    }
    // DemiPass grants wait a day, so they have their own queue (#77 review M3): they cannot crowd out uses of secrets,
    // and the owner's own DID — whatever labels it signs in under — holds at most MAX_PENDING_GRANTS_OWN of them.
    const grant = isGrantKey(secret.service_key) || kind === 'scope';   // a scope change waits a day too (the owner's own grant)
    const GRANT_SQL = "(COALESCE(service_key, '') LIKE 'svc:demipass:%' OR kind = 'scope')";   // NULL keys count as ordinary
    const pending = db.prepare(`SELECT COUNT(*) AS n FROM use_approvals WHERE owner_did = ? AND status = 'pending' AND ${grant ? GRANT_SQL : 'NOT ' + GRANT_SQL}`).get(secret.did).n;
    if (pending >= MAX_PENDING_PER_OWNER) return { error: 'too many approvals are waiting on this owner; try again later', status: 429 };
    if (grant && own && db.prepare(`SELECT COUNT(*) AS n FROM use_approvals WHERE owner_did = ? AND requester_did = ? AND status = 'pending' AND ${GRANT_SQL}`).get(secret.did, requesterDid).n >= MAX_PENDING_GRANTS_OWN) {
      return { error: `at most ${MAX_PENDING_GRANTS_OWN} of your own grant requests can wait at once`, status: 429 };
    }
    const id = Number(db.prepare(`INSERT INTO use_approvals (kind, secret_id, owner_did, requester_did, requester_label, delegation_id, depth, purpose, summary,
                                  binding, code_key, created_at, expires_at, bound_call, service_key) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .run(kind, secret.id, secret.did, requesterDid, cleanLabel(label || '', 80), delegationId || null, depthOf(secret), cleanLabel(purpose || '', 200).trim(),
           summary, binding, crypto.randomBytes(32).toString('hex'), nowIso(), later(grant ? GRANT_PENDING_TTL_SEC : PENDING_TTL_SEC), callJson, secret.service_key || null).lastInsertRowid);
    // Item 1: a wrapped secret's request gets a one-use key (private half in memory only) the phone unwraps to.
    if (cryptoDepth) cryptoDepth.onRequestCreated({ id }, secret);
    const row = db.prepare('SELECT * FROM use_approvals WHERE id = ?').get(id);
    event('approval_requested', requesterDid, secret.id, { approval_id: id, kind, owner_did: secret.did, depth: row.depth, summary });
    logSecurityEvent('approval_requested', 'info', { caller_did: requesterDid, capability: kind, target: secret.name, context: { approval_id: id, owner_did: secret.did } });
    notifyOwner(row);
    return { row };
  }
  function pendingReply(row, me, extra = {}) {
    return { ok: false, status: 'approval_pending', approval_id: row.id, expires_at: row.expires_at, owner: usernameOf(row.owner_did), depth: row.depth,
      ...extra,
      next: `Park this task. ${usernameOf(row.owner_did)} approves it in the DemiPass app. Then make the same call once more with approval_id ${row.id} — or, if they read you the 6-digit code, with approval_id and approval_code. Do not retry in a loop: check GET /api/demipass/approvals/${row.id} when you resume.` };
  }

  // The gate /use calls before it acts with a secret. Returns { ok:true } to proceed, or { status, body } to answer.
  // `caller` = { did, label }, `use` = { kind, action, targetHost, targetUrl, params, delegationId }.
  // `peek`: report whether an approved request is there without spending it (reveal checks the PIN in between).
  function gate(secret, caller, use, body = {}, { peek = false } = {}) {
    if (depthOf(secret) === 'standard') return { ok: true };
    // A wrapped secret (item 1) is never revealed by the host — not the owner's reveal, not a share's emergency reveal:
    // refused before a request (and its one-use key) exists (#56 review L1).
    if ((use.kind || 'use') === 'reveal' && cryptoDepth && cryptoDepth.isWrapped(secret)) {
      return { status: 409, body: { error: 'this secret is wrapped to its owner\'s phone, so the server cannot reveal it — the owner lowers it to standard first (the phone unwraps it)', wrapped: true } };
    }
    const amb = ambiguity(use.params);
    if (amb) return { status: 400, body: { error: amb } };
    expireOld();
    const kind = use.kind || 'use';
    const binding = bindingOf({ secretId: secret.service_key || secret.id, kind, action: use.action, targetHost: use.targetHost, targetUrl: use.targetUrl, params: use.params });
    const aid = body.approval_id;
    if (aid !== undefined && aid !== null && aid !== '') {
      const id = Number(aid);
      const row = Number.isInteger(id) && id > 0 ? db.prepare('SELECT * FROM use_approvals WHERE id = ?').get(id) : null;
      // The same refusal for a missing, foreign or differently-bound request: nothing about other requests leaks.
      if (!row || row.requester_did !== caller.did || row.secret_id !== secret.id || (row.service_key || null) !== (secret.service_key || null) || row.kind !== kind) return { status: 404, body: { error: 'approval request not found for this caller and secret' } };
      if (row.binding !== binding) return { status: 409, body: { error: 'this approval was for a different call (action, target or parameters); make the approved call exactly, or ask anew without approval_id', approval_id: row.id } };
      if (row.status === 'approved') {
        if (peek) return { ok: true, approval_id: row.id, peeked: true };
        const took = db.prepare("UPDATE use_approvals SET status = 'used', used_at = ? WHERE id = ? AND status = 'approved'").run(nowIso(), row.id).changes;
        if (took !== 1) return { status: 410, body: { error: 'this approval was already used' } };
        event('approval_used', caller.did, secret.id, { approval_id: row.id, via: row.approved_via });
        return { ok: true, approval_id: row.id, call: row.bound_call || null };
      }
      if (row.status === 'pending') {
        const code = body.approval_code;
        if (code === undefined || code === null || code === '') return { status: 202, body: pendingReply(row, caller.did, { already_pending: true }) };
        if (!row.opened_at) return { status: 409, body: { error: 'the owner has not opened this request yet — no code exists for it', approval_id: row.id } };
        if (cryptoDepth && cryptoDepth.isWrapped(secret)) return { status: 409, body: { error: 'this secret is wrapped to its owner\'s phone: a code cannot open it — the owner taps Approve in the app on that phone', approval_id: row.id, wrapped: true } };
        if (codeMatches(row, String(code))) {
          if (peek) return { ok: true, approval_id: row.id, peeked: true };
          const took = db.prepare("UPDATE use_approvals SET status = 'used', approved_at = ?, approved_via = 'code', used_at = ?, decided_at = ? WHERE id = ? AND status = 'pending'")
            .run(nowIso(), nowIso(), nowIso(), row.id).changes;
          if (took !== 1) return { status: 410, body: { error: 'this request was decided meanwhile' } };
          event('approval_used', caller.did, secret.id, { approval_id: row.id, via: 'code' });
          logSecurityEvent('approval_code_accepted', 'info', { caller_did: caller.did, capability: kind, target: secret.name, context: { approval_id: row.id, owner_did: row.owner_did } });
          return { ok: true, approval_id: row.id, call: row.bound_call || null };
        }
        const wrong = db.prepare('UPDATE use_approvals SET wrong_codes = wrong_codes + 1 WHERE id = ? RETURNING wrong_codes').get(row.id).wrong_codes;
        event('approval_code_wrong', caller.did, secret.id, { approval_id: row.id, wrong_codes: wrong });
        if (wrong >= MAX_WRONG) {
          db.prepare("UPDATE use_approvals SET status = 'cancelled', decided_at = ? WHERE id = ? AND status = 'pending'").run(nowIso(), row.id);
          logSecurityEvent('approval_cancelled_wrong_codes', 'critical', { caller_did: caller.did, capability: kind, target: secret.name, context: { approval_id: row.id, owner_did: row.owner_did, wrong_codes: wrong } });
          event('approval_cancelled', caller.did, secret.id, { approval_id: row.id, reason: 'wrong codes', wrong_codes: wrong });
          return { status: 403, body: { error: `wrong code — ${MAX_WRONG} wrong codes cancelled this request`, cancelled: true } };
        }
        return { status: 403, body: { error: 'wrong or expired code', attempts_left: MAX_WRONG - wrong, approval_id: row.id } };
      }
      return { status: 410, body: { error: `this approval request is ${row.status}`, approval_id: row.id } };
    }
    // No approval named: the same caller asking for the same call while one waits gets that one back, not a new one.
    const same = db.prepare("SELECT * FROM use_approvals WHERE requester_did = ? AND secret_id = ? AND COALESCE(service_key, '') = ? AND binding = ? AND status IN ('pending', 'approved') ORDER BY id DESC LIMIT 1")
      .get(caller.did, secret.id, secret.service_key || '', binding);
    if (same) return { status: 202, body: pendingReply(same, caller.did, { already_pending: true, ...(same.status === 'approved' ? { approved: true } : {}) }) };
    const made = createRequest({ secret, kind, requesterDid: caller.did, label: caller.label, delegationId: use.delegationId, purpose: body.purpose,
      binding, call: boundCall({ kind, action: use.action, targetHost: use.targetHost, targetUrl: use.targetUrl, params: use.params }),
      summary: summaryOf({ kind, action: use.action, targetHost: use.targetHost, targetUrl: use.targetUrl, params: use.params }) });
    if (made.error) return { status: made.status, body: { error: made.error, ...(made.extra || {}) } };
    return { status: 202, body: pendingReply(made.row, caller.did) };
  }

  // ── routes ─────────────────────────────────────────────────────────────────────────────────────────────────────
  // The owner, acting as a person in their own session (not an agent token).
  function ownerAuth(req, res) {
    const auth = getBearerIdentity(req);
    if (!auth.ok) { res.status(auth.status || 401).json({ error: auth.error }); return null; }
    if (auth.silicon || (auth.decoded && (auth.decoded.wrk || auth.decoded.auth_method === 'fleet_owner_mint'))) { res.status(403).json({ error: 'approvals are decided by the owner in their own session, not by an agent token' }); return null; }
    if (!gateSession(auth)) { res.status(403).json({ error: 'this token cannot hold a session — sign in again' }); return null; }
    return auth;
  }
  function ownRow(req, res, auth) {
    const id = Number(req.params.id);
    const row = Number.isInteger(id) && id > 0 ? db.prepare('SELECT * FROM use_approvals WHERE id = ? AND owner_did = ?').get(id, auth.did) : null;
    if (!row) { res.status(404).json({ error: 'approval request not found' }); return null; }
    return row;
  }

  // GET /api/blindkey/approvals — incoming (waiting on you), outgoing (yours), recent (decided, both sides): the audit.
  app.get('/api/blindkey/approvals', rateLimitFill || rateLimitStandard, (req, res) => {
    const auth = getBearerIdentity(req);
    if (!auth.ok) return res.status(auth.status || 401).json({ error: auth.error });
    expireOld();
    const incoming = db.prepare("SELECT * FROM use_approvals WHERE owner_did = ? AND status = 'pending' ORDER BY id DESC LIMIT 50").all(auth.did);
    const outgoing = db.prepare("SELECT * FROM use_approvals WHERE requester_did = ? ORDER BY id DESC LIMIT 20").all(auth.did);
    // An agent token (a silicon, a worker, a fleet-owner mint) resolves to its owner's DID: it sees neither what waits on
    // the owner nor the owner's decided history (#99 review M1). ?limit= (20–200) is for the owner's own session: the
    // app's Requests page lists decided requests so one can be found by number (Aaron 2026-11-12).
    const agent = !!(auth.silicon || (auth.decoded && (auth.decoded.wrk || auth.decoded.auth_method === 'fleet_owner_mint')));
    const lim = agent ? 0 : Math.min(200, Math.max(20, Number.parseInt(req.query.limit, 10) || 20));
    const recent = lim ? db.prepare("SELECT * FROM use_approvals WHERE owner_did = ? AND status != 'pending' ORDER BY id DESC LIMIT ?").all(auth.did, lim) : [];
    // An agent's own requests are filed under its owner's DID, so outgoing holds every agent's: without the bound call
    // and binding for an agent token, one agent cannot read another's request details (#99 re-review L1).
    // Nor the phone-wrap material, whether it was opened, what it does or why: an agent reads its own request in full
    // with GET /approvals/:id.
    const lean = (v) => { const { call, binding, unwrap, opened, summary, purpose, ...rest } = v; return rest; };
    res.json({ ok: true, incoming: agent ? [] : incoming.map(r => view(r, auth.did)), outgoing: outgoing.map(r => agent ? lean(view(r, auth.did)) : view(r, auth.did)), recent: recent.map(r => view(r, auth.did)) });
  });

  // GET /api/blindkey/approvals/:id — status for the owner or the requester (never a code).
  app.get('/api/blindkey/approvals/:id', rateLimitStandard, (req, res) => {
    const auth = getBearerIdentity(req);
    if (!auth.ok) return res.status(auth.status || 401).json({ error: auth.error });
    expireOld();
    const id = Number(req.params.id);
    const row = Number.isInteger(id) && id > 0 ? db.prepare('SELECT * FROM use_approvals WHERE id = ?').get(id) : null;
    if (!row || (row.owner_did !== auth.did && row.requester_did !== auth.did)) return res.status(404).json({ error: 'approval request not found' });
    res.json({ ok: true, approval: view(row, auth.did) });
  });

  // POST /api/blindkey/approvals/:id/open — the request screen. Starts (and then returns) the current code.
  // Critical: the owner's PIN (intent approval-open:<id>) the first time each session opens it.
  app.post('/api/blindkey/approvals/:id/open', limiter, (req, res) => {
    const auth = ownerAuth(req, res); if (!auth) return;
    expireOld();
    const row = ownRow(req, res, auth); if (!row) return;
    if (row.status !== 'pending') return res.status(409).json({ error: `this request is ${row.status}`, approval: view(row, auth.did) });
    const session = gateSession(auth);
    // The PIN (or the phone's biometric, which mints the same proof) opens every request screen: it is the one factor
    // an agent signed in as the owner (device login, refreshed token) never holds. An elevated request is covered by a
    // fresh unlock of this session (the app's dormancy lock, unlocked by PIN or biometric within the owner's lock
    // time); a critical one asks again every time (red team item 8).
    // Only with a linked phone: without one, the PIN still opens each request (#47 review M3).
    const coveredByUnlock = row.depth === 'elevated' && deviceKeys && deviceKeys.hasDevice(auth.did) && deviceKeys.unlockFresh(auth);
    const needPin = row.opened_session !== session && !coveredByUnlock;
    const intent = `approval-open:${row.id}`;
    if (needPin && !gateFresh(auth.did, 'pin', auth, intent)) return res.status(403).json(gateMissing('approval-open', ['pin'], ['pin'], intent));
    // The code IS the approval (an agent redeems it): once a phone is linked, every fetch of it — the first open and
    // each 5-s refresh — is signed by that phone, so a laptop with the PIN or a token copied off the phone gets no code
    // (#47 re-review: approval-code bypass). Checked before the PIN proof is spent.
    if (deviceKeys) { const r = deviceKeys.approvalRefusal(auth, 'approval-open', row.id, row.binding, req.body); if (r) return res.status(r.status).json(r.body); }
    if (needPin) {
      const refused = spendSingleUse(auth.did, 'approval-open', ['pin'], auth, intent);
      if (refused) return res.status(refused.status || 403).json(refused);
    }
    if (!row.opened_at || row.opened_session !== session) {
      db.prepare("UPDATE use_approvals SET opened_at = COALESCE(opened_at, ?), opened_session = ?, opened_via = 'app' WHERE id = ?").run(nowIso(), session, row.id);
      event('approval_opened', auth.did, row.secret_id, { approval_id: row.id, via: 'app' });
    }
    const fresh = db.prepare('SELECT * FROM use_approvals WHERE id = ?').get(row.id);
    const s = stepNow();
    res.json({ ok: true, approval: view(fresh, auth.did), code: codeAt(fresh, s), code_valid_until: new Date((s + 1) * STEP_SEC * 1000).toISOString(), step_seconds: STEP_SEC,
      note: 'Approve sends this code for you. Read it to the agent only if it is waiting in another channel.' });
  });

  // POST /api/blindkey/approvals/:id/approve — the screen's button. The app sends the code it shows; nobody types it.
  app.post('/api/blindkey/approvals/:id/approve', limiter, (req, res) => {
    const auth = ownerAuth(req, res); if (!auth) return;
    expireOld();
    const row = ownRow(req, res, auth); if (!row) return;
    if (row.status !== 'pending') return res.status(409).json({ error: `this request is ${row.status}` });
    if (!row.opened_at) return res.status(409).json({ error: 'open the request first' });
    // Approved only from the session that opened it with the PIN.
    if (row.opened_session !== gateSession(auth)) return res.status(403).json({ error: 'open this request with your PIN in this session first' });
    if (!codeMatches(row, String((req.body || {}).code || ''))) return res.status(409).json({ error: 'the code on the screen has rotated; try again' });
    // Bound to the phone (red team item 4b): once the owner has a device enrolled, its device key signs this decision
    // (the request id and the exact call's binding); a session token alone approves nothing.
    if (deviceKeys) { const r = deviceKeys.approvalRefusal(auth, 'approval', row.id, row.binding, req.body); if (r) return res.status(r.status).json(r.body); }
    // Item 1: a wrapped secret's approval carries the phone's unwrap (the data key, re-encrypted to the one-use key).
    // A scope change (kind 'scope') uses no value, so a wrapped secret's scope is approved without one.
    const sec = secretOf(row.secret_id);
    if (cryptoDepth && row.kind !== 'scope') { const r = cryptoDepth.approveRefusal(row, sec, req.body); if (r) return res.status(r.status).json(r.body); }
    if (cryptoDepth && row.kind !== 'scope' && cryptoDepth.isWrapped(sec)) cryptoDepth.storeUnwrap(row.id, req.body);
    const took = db.prepare("UPDATE use_approvals SET status = 'approved', approved_at = ?, approved_via = 'app', decided_at = ?, expires_at = ? WHERE id = ? AND status = 'pending'")
      .run(nowIso(), nowIso(), later(isGrantKey(row.service_key) || row.kind === 'scope' ? GRANT_APPROVED_TTL_SEC : TTL_SEC), row.id).changes;
    if (took !== 1) return res.status(409).json({ error: 'this request was decided meanwhile' });
    event('approval_approved', auth.did, row.secret_id, { approval_id: row.id, requester_did: row.requester_did, via: 'app' });
    logSecurityEvent('approval_approved', 'info', { caller_did: auth.did, capability: row.kind, context: { approval_id: row.id, requester_did: row.requester_did } });
    res.json({ ok: true, approval: view(db.prepare('SELECT * FROM use_approvals WHERE id = ?').get(row.id), auth.did) });
  });

  // POST /api/blindkey/approvals/:id/deny
  app.post('/api/blindkey/approvals/:id/deny', limiter, (req, res) => {
    const auth = ownerAuth(req, res); if (!auth) return;
    const row = ownRow(req, res, auth); if (!row) return;
    if (!['pending', 'approved'].includes(row.status)) return res.status(409).json({ error: `this request is ${row.status}` });
    db.prepare("UPDATE use_approvals SET status = 'denied', decided_at = ?, unwrap_blob = NULL WHERE id = ? AND status IN ('pending', 'approved')").run(nowIso(), row.id);
    if (cryptoDepth) cryptoDepth.dropEphemeral('a:' + row.id);
    event('approval_denied', auth.did, row.secret_id, { approval_id: row.id, requester_did: row.requester_did });
    logSecurityEvent('approval_denied', 'info', { caller_did: auth.did, capability: row.kind, context: { approval_id: row.id, requester_did: row.requester_did } });
    res.json({ ok: true, approval: view(db.prepare('SELECT * FROM use_approvals WHERE id = ?').get(row.id), auth.did) });
  });

  // An elevated/critical service action (service_tenants.js): the same request, code and phone approval as a secret's
  // use, approved by `approverDid` (the person whose authority the call uses). `subject` = {key, name, approverDid, depth}.
  function gateService(subject, caller, use, body = {}) {
    if (!/^svc:[a-z0-9-]+:[a-z0-9_.-]+$/.test(String(subject.key || ''))) return { status: 500, body: { error: 'bad service key' } };
    const pseudo = { id: 0, did: subject.approverDid, name: subject.name, security_depth: subject.depth, service_key: subject.key, wrap_state: null };
    // The approver is part of what is approved: a request made while one person answered for the caller never redeems
    // after someone else does (#68 re-review).
    return gate(pseudo, caller, { kind: 'service', action: use.action, targetHost: use.targetHost, targetUrl: '',
      params: { ...(use.params || {}), approver_did: subject.approverDid }, delegationId: use.delegationId }, body);
  }

  // What the owner's phone is told about (account_holds alerts, signed by the phone's D): pending requests, newest first,
  // headline only — the full call is shown after the PIN opens it.
  function pendingFor(ownerDid) {
    expireOld();
    return db.prepare("SELECT * FROM use_approvals WHERE owner_did = ? AND status = 'pending' ORDER BY id DESC LIMIT 20").all(ownerDid)
      .map(r => { const v = view(r, ownerDid); return { id: r.id, title: v.secret.name || '', requester: v.requester || v.requester_label || '', summary: v.summary || '', depth: r.depth, expires_at: r.expires_at }; });
  }

  return { gate, gateService, depthOf, bindingOf, pendingFor, _codeAt: codeAt, STEP_SEC, TTL_SEC, PENDING_TTL_SEC };
};
