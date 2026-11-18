'use strict';
// ── Per-wallet settings the person sets in the app (Aaron 2026-11-18) ──────────────────────────────────────────────
// agent_rules_write: "DemiPass may write to my agent instruction files (AGENTS.md, CLAUDE.md) in the projects I onboard
// panes and agents into." Asked in the app the first time a new wallet opens Fleet, onboards a pane or any agent; it
// must be enabled to use that feature: demipass-onboard reads it (GET /api/identity/pane-rules) and refuses to attach a
// pane or agent until it is on. Set only by the person's own session, never by an agent token; an agent wallet's answer
// is its creator's. Each change is a security event.

const KEYS = new Set(['agent_rules_write']);
const nowIso = () => new Date().toISOString();

function init(db) {
  db.exec(`CREATE TABLE IF NOT EXISTS wallet_settings (
    did TEXT NOT NULL,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    set_at TEXT NOT NULL,
    PRIMARY KEY (did, key)
  )`);
}
function get(db, did, key) { return db.prepare('SELECT value, set_at FROM wallet_settings WHERE did = ? AND key = ?').get(did, key) || null; }
function set(db, did, key, value) {
  db.prepare('INSERT INTO wallet_settings (did, key, value, set_at) VALUES (?, ?, ?, ?) ON CONFLICT(did, key) DO UPDATE SET value = excluded.value, set_at = excluded.set_at')
    .run(did, key, String(value), nowIso());
}
const view = (r) => ({ enabled: !!r && r.value === '1', set_at: r ? r.set_at : null });

module.exports = function registerWalletSettings({ app, db, rateLimitStandard, getBearerIdentity, logSecurityEvent, personFor, isAgentAuth, deviceSession }) {
  init(db);
  // Only the person's own sign-in sets it: never an agent token, and never a device-flow session (that is how a pane
  // holds the person's wallet, so a pane could otherwise grant the permission to itself; #136 review H1).
  const agentToken = (auth) => (isAgentAuth ? isAgentAuth(auth) : !!auth.silicon) || !!(deviceSession && deviceSession(auth.decoded || {}));

  // The person's own settings (the app's Settings page).
  app.get('/api/identity/settings', rateLimitStandard, (req, res) => {
    const auth = getBearerIdentity(req); if (!auth.ok) return res.status(auth.status || 401).json({ error: auth.error });
    res.json({ ok: true, settings: { agent_rules_write: view(get(db, auth.did, 'agent_rules_write')) } });
  });
  app.post('/api/identity/settings/agent-rules-write', rateLimitStandard, (req, res) => {
    const auth = getBearerIdentity(req); if (!auth.ok) return res.status(auth.status || 401).json({ error: auth.error });
    if (agentToken(auth)) return res.status(403).json({ error: 'the person sets this in the DemiPass app, not an agent token' });
    // A refresh lineage from before origin tracking cannot show it began as the person's own sign-in: as the
    // rate-reset and secret-edit routes, it fails closed (#136 re-review).
    const d0 = auth.decoded || {};
    if (d0.auth_method === 'refresh' && !d0.src_auth) return res.status(403).json({ error: 'sign in again in the DemiPass app to change this (this session cannot show it began as a person\'s sign-in)', sign_in_again: true });
    const on = (req.body || {}).enabled;
    if (typeof on !== 'boolean') return res.status(400).json({ error: 'enabled: true or false' });
    set(db, auth.did, 'agent_rules_write', on ? '1' : '0');
    try { logSecurityEvent(on ? 'agent_rules_write_enabled' : 'agent_rules_write_disabled', 'info', { caller_did: auth.did, capability: 'settings', ip: req.ip }); } catch (_) {}
    res.json({ ok: true, agent_rules_write: view(get(db, auth.did, 'agent_rules_write')) });
  });

  // What a pane's onboarding asks before it writes instruction files: is the person behind this wallet's session (the
  // wallet itself, or its creator for an agent wallet) consenting? Any live token of the wallet may ask.
  app.get('/api/identity/pane-rules', rateLimitStandard, (req, res) => {
    const auth = getBearerIdentity(req); if (!auth.ok) return res.status(auth.status || 401).json({ error: auth.error });
    // An agent wallet nobody created has no person to answer for it: not enabled, and not its own row (#136 review M1).
    const person = personFor ? personFor(auth.did) : auth.did;
    if (!person) return res.json({ ok: true, enabled: false, set_at: null, person: null, next: 'this wallet has no person to answer for it; a fleet owner must adopt it first' });
    const r = get(db, person, 'agent_rules_write');
    res.json({ ok: true, ...view(r), person: person === auth.did ? 'you' : 'your fleet owner',
      ...(r && r.value === '1' ? {} : { next: 'Enable "Write agent instruction files" in the DemiPass app (it is asked when Fleet is first opened, or in Settings); onboarding panes and agents needs it.' }) });
  });

  return { get: (did, key) => (KEYS.has(key) ? view(get(db, did, key)) : null) };
};
module.exports.init = init;
