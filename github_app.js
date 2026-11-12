'use strict';
// ── DemiPass as a GitHub App (Aaron 2026-11-12) ────────────────────────────────────────────────────────────────────
// Agents held GitHub PATs, and a PAT can only be minted by a person in GitHub's UI (Brain's expired silently after 180
// days). A GitHub App is GitHub's own shape of DemiPass's model: one long-lived secret in custody — the app's private
// key, a vault entry of type github_app_key that is never shown, never wrapped to a phone and never leaves the server —
// and short-lived uses handed out per call: installation tokens (one hour at most, named repositories and permissions,
// revocable).
//
//   scope (blindkey_contexts row, action_type github_app_token; its `github_app` column, JSON):
//     { installation_id: "12345678", repositories: ["owner/name", ...], permissions: { contents: "write", ... },
//       max_ttl_seconds: 60..3600 }
//   use: POST /api/demipass/use { ref, action: "github_app_token", params: { repositories?, permissions?, ttl_seconds? } }
//     → a subset of the scope (left out = the scope's own), checked before anything connects; then a JWT signed here
//       with the custody key (RS256, iat −60 s, exp +9 min, iss = app id; never returned, never logged) mints
//       POST /app/installations/{id}/access_tokens with those exact repositories and permissions. The caller gets the
//       installation token, its expiry and what it covers. GitHub's own answer is checked against the request: a token
//       wider than asked is revoked at once and not handed out.
//   Every mint is a metered /use and a security event (wallet, scope, repositories, permissions, expiry); the token's
//   expiry is recorded (github_app_tokens) so GET /api/demipass/expiring lists live tokens.
//   Revocation: the token is kept host-encrypted until it expires — only so it can be revoked (DELETE /installation/token
//   authenticates with the token itself). Deleting the scope, the delegation or the key, or the scope's own TTL running
//   out before GitHub's hour, revokes it; a sweep catches every other way a grant ends (expiry, fleet exit) within a
//   minute. When the revoke cannot reach GitHub the token still dies at GitHub's expiry (≤ 1 h).
// The installation's own permissions are the ceiling: GitHub refuses a mint wider than the installation (422), and the
// answer then is a reinstall by the owner, never a wider scope.
const crypto = require('crypto');

const GITHUB_API = 'https://api.github.com';
const TTL_MIN_S = 60, TTL_MAX_S = 3600;            // GitHub's installation tokens live one hour
const JWT_BACKDATE_S = 60, JWT_AHEAD_S = 540;      // iat −60 s (clock drift), exp +9 min: within GitHub's 10-minute cap
const MAX_REPOS = 100, MAX_PERMS = 30;
const LEVELS = { read: 1, write: 2 };
const REPO_RE = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})\/[A-Za-z0-9._-]{1,100}$/;
const PERM_RE = /^[a-z][a-z_]{1,49}$/;
const SWEEP_MS = 60 * 1000;

const isAppKey = (secret) => Boolean(secret) && secret.secret_type === 'github_app_key';
const appIdOf = (secret) => { try { const m = JSON.parse((secret && secret.metadata) || '{}'); return m && /^\d{1,12}$/.test(String(m.github_app_id || '')) ? String(m.github_app_id) : null; } catch (_) { return null; } };

// A GitHub App private key as GitHub hands it out: an RSA private key PEM (PKCS#1 "BEGIN RSA PRIVATE KEY", or PKCS#8).
// The value is never echoed: errors say what is wrong, not what was sent.
function pemRefusal(value) {
  const v = String(value || '').trim();
  if (!/^-----BEGIN (RSA )?PRIVATE KEY-----[\s\S]+-----END (RSA )?PRIVATE KEY-----$/.test(v)) {
    return 'a GitHub App private key is the whole .pem file GitHub downloads (-----BEGIN RSA PRIVATE KEY----- … -----END RSA PRIVATE KEY-----)';
  }
  let key;
  try { key = crypto.createPrivateKey(v); } catch (_) { return 'that .pem is not a readable private key (an encrypted or damaged file?) — download a fresh one from the app\'s settings'; }
  if (key.asymmetricKeyType !== 'rsa') return 'a GitHub App key is an RSA key; this .pem holds another kind';
  if ((key.asymmetricKeyDetails && key.asymmetricKeyDetails.modulusLength || 0) < 2048) return 'that RSA key is shorter than 2048 bits; GitHub App keys are 2048 bits or more';
  return null;
}
function appIdRefusal(v) {
  return /^\d{1,12}$/.test(String(v === undefined || v === null ? '' : v).trim()) ? null : "github_app_id: the app's numeric App ID (GitHub → the app's settings → General → App ID)";
}

// A scope's GitHub part, from a request body: { value: canonical JSON } or { error }.
function parseScope(v) {
  if (!v || typeof v !== 'object' || Array.isArray(v)) return { error: 'github_app: { installation_id, repositories: ["owner/name", …], permissions: { contents: "read"|"write", … }, max_ttl_seconds? }' };
  const inst = String(v.installation_id === undefined || v.installation_id === null ? '' : v.installation_id).trim();
  if (!/^\d{1,15}$/.test(inst)) return { error: 'github_app.installation_id: the number at the end of the installation\'s settings URL (github.com/settings/installations/<id>)' };
  const repos = v.repositories;
  if (!Array.isArray(repos) || !repos.length || repos.length > MAX_REPOS || repos.some(r => typeof r !== 'string' || !REPO_RE.test(r.trim()))) {
    return { error: `github_app.repositories: 1–${MAX_REPOS} exact names "owner/name" (no wildcards)` };
  }
  const list = [...new Set(repos.map(r => r.trim().toLowerCase()))].sort();
  if (new Set(list.map(r => r.split('/')[0])).size !== 1) return { error: 'github_app.repositories: one owner per scope (an installation belongs to one account)' };
  const perms = permsOf(v.permissions);
  if (perms.error) return { error: 'github_app.' + perms.error };
  if (!Object.keys(perms.value).length) return { error: 'github_app.permissions: at least one, e.g. { "contents": "read" }' };
  let ttl = v.max_ttl_seconds === undefined || v.max_ttl_seconds === null ? TTL_MAX_S : v.max_ttl_seconds;
  if (!Number.isInteger(ttl) || ttl < TTL_MIN_S || ttl > TTL_MAX_S) return { error: `github_app.max_ttl_seconds: a whole number from ${TTL_MIN_S} to ${TTL_MAX_S}` };
  return { value: JSON.stringify({ installation_id: inst, repositories: list, permissions: perms.value, max_ttl_seconds: ttl }) };
}
function permsOf(p) {
  if (!p || typeof p !== 'object' || Array.isArray(p)) return { error: 'permissions: an object of name → "read" or "write"' };
  const keys = Object.keys(p);
  if (keys.length > MAX_PERMS) return { error: `permissions: at most ${MAX_PERMS}` };
  const out = {};
  for (const k of keys.sort()) {
    const level = typeof p[k] === 'string' ? p[k].trim().toLowerCase() : '';
    if (!PERM_RE.test(k) || !LEVELS[level]) return { error: `permissions: "${String(k).slice(0, 50)}" must be a GitHub permission name with "read" or "write"` };
    out[k] = level;
  }
  return { value: out };
}
const scopeOf = (raw) => { if (!raw) return null; try { const s = JSON.parse(raw); return s && s.installation_id ? s : null; } catch (_) { return null; } };

// Is `next` (canonical JSON) no wider than `cur`? Same installation, repositories a subset, every permission held at the
// same or a lower level, the same or a shorter TTL. Anything else is a widening: the owner's approval (PR #97 path).
function isNarrowing(nextRaw, curRaw) {
  if (nextRaw === curRaw) return true;
  const n = scopeOf(nextRaw), c = scopeOf(curRaw);
  if (!n || !c || n.installation_id !== c.installation_id) return false;
  if (!n.repositories.every(r => c.repositories.includes(r))) return false;
  if (!Object.entries(n.permissions).every(([k, l]) => c.permissions[k] && LEVELS[l] <= LEVELS[c.permissions[k]])) return false;
  return n.max_ttl_seconds <= c.max_ttl_seconds;
}
function describe(raw) {
  const s = scopeOf(raw);
  if (!s) return 'GitHub App token (no configuration)';
  return `installation ${s.installation_id}: ${s.repositories.join(', ')}; ${Object.entries(s.permissions).map(([k, l]) => `${k}:${l}`).join(', ')}; ≤ ${s.max_ttl_seconds} s`;
}

// What one /use asks for, checked against the scope before anything connects: { value: { repositories, permissions,
// ttl } } or { error }. Left out = the scope's own (all its repositories, all its permissions, its longest TTL).
function requestFor(scopeRaw, params) {
  const s = scopeOf(scopeRaw);
  if (!s) return { error: 'this scope has no GitHub App configuration; its owner sets one (installation, repositories, permissions)' };
  const p = params || {};
  let repos = s.repositories;
  if (p.repositories !== undefined && p.repositories !== null) {
    if (!Array.isArray(p.repositories) || !p.repositories.length || p.repositories.length > MAX_REPOS || p.repositories.some(r => typeof r !== 'string')) {
      return { error: 'repositories: a non-empty list of exact names "owner/name"' };
    }
    repos = [...new Set(p.repositories.map(r => r.trim().toLowerCase()))].sort();
    const off = repos.filter(r => !s.repositories.includes(r));
    if (off.length) return { error: `repository ${off.map(r => `'${r.slice(0, 141)}'`).join(', ')} is not in this scope (it covers ${s.repositories.join(', ')}) — its owner widens the scope in the DemiPass app` };
  }
  let perms = s.permissions;
  if (p.permissions !== undefined && p.permissions !== null) {
    const asked = permsOf(p.permissions);
    if (asked.error) return { error: asked.error };
    if (!Object.keys(asked.value).length) return { error: 'permissions: at least one' };
    const off = Object.entries(asked.value).filter(([k, l]) => !s.permissions[k] || LEVELS[l] > LEVELS[s.permissions[k]]);
    if (off.length) return { error: `permission ${off.map(([k, l]) => `${k}:${l}`).join(', ')} is beyond this scope (${Object.entries(s.permissions).map(([k, l]) => `${k}:${l}`).join(', ')}) — its owner widens the scope in the DemiPass app` };
    perms = asked.value;
  }
  let ttl = s.max_ttl_seconds;
  if (p.ttl_seconds !== undefined && p.ttl_seconds !== null) {
    if (!Number.isInteger(p.ttl_seconds) || p.ttl_seconds < TTL_MIN_S) return { error: `ttl_seconds: a whole number from ${TTL_MIN_S} to ${s.max_ttl_seconds}` };
    if (p.ttl_seconds > s.max_ttl_seconds) return { error: `ttl_seconds: this scope's tokens live at most ${s.max_ttl_seconds} s` };
    ttl = p.ttl_seconds;
  }
  return { value: { installation_id: s.installation_id, repositories: repos, permissions: perms, ttl } };
}

// The app's JWT: RS256, iat 60 s back, exp 9 min ahead, iss = the App ID. Lives only for the mint call.
function appJwt(pem, appId, now = Math.floor(Date.now() / 1000)) {
  const enc = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const signing = enc({ alg: 'RS256', typ: 'JWT' }) + '.' + enc({ iat: now - JWT_BACKDATE_S, exp: now + JWT_AHEAD_S, iss: Number(appId) });
  return signing + '.' + crypto.sign('RSA-SHA256', Buffer.from(signing), crypto.createPrivateKey(pem)).toString('base64url');
}

// The rebuild that lets a scope be github_app_token: blindkey_contexts was made with CHECK(action_type IN (…)) and a
// CHECK cannot be altered in place. Runs once, at boot, on a database made before this branch: the table is copied
// into one whose CHECK also admits github_app_token (same columns, same ids, same indexes), in one transaction, with
// foreign keys off for the swap (demipass_delegations and blindkey_use_tokens refer to it by id) and checked after.
function widenContextActionCheck(db, log = () => {}) {
  const row = db.prepare("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'blindkey_contexts'").get();
  if (!row || !row.sql) return { rebuilt: false };
  const m = row.sql.match(/CHECK\s*\(\s*action_type\s+IN\s*\(([^)]*)\)\s*\)/i);
  if (!m || /'github_app_token'/.test(m[1])) return { rebuilt: false };
  const newSql = row.sql
    .replace(m[0], m[0].replace(m[1], m[1].replace(/\s*$/, '') + ", 'github_app_token'"))
    .replace(/^CREATE TABLE\s+("blindkey_contexts"|blindkey_contexts)/i, 'CREATE TABLE blindkey_contexts_gha');
  if (!/^CREATE TABLE blindkey_contexts_gha/.test(newSql)) throw new Error('blindkey_contexts: unexpected schema, not rebuilt');
  const extras = db.prepare("SELECT type, name, sql FROM sqlite_master WHERE tbl_name = 'blindkey_contexts' AND type IN ('index', 'trigger') AND sql IS NOT NULL").all();
  const before = db.prepare('SELECT COUNT(*) AS n FROM blindkey_contexts').get().n;
  const fk = db.pragma('foreign_keys', { simple: true });
  db.pragma('foreign_keys = OFF');
  db.pragma('legacy_alter_table = ON');   // the rename touches nothing else: references by name resolve to the new table
  try {
    db.transaction(() => {
      db.exec('DROP TABLE IF EXISTS blindkey_contexts_gha');
      db.exec(newSql);
      db.exec('INSERT INTO blindkey_contexts_gha SELECT * FROM blindkey_contexts');
      db.exec('DROP TABLE blindkey_contexts');
      db.exec('ALTER TABLE blindkey_contexts_gha RENAME TO blindkey_contexts');
      for (const x of extras) db.exec(x.sql);
      const after = db.prepare('SELECT COUNT(*) AS n FROM blindkey_contexts').get().n;
      if (after !== before) throw new Error(`blindkey_contexts rebuild: ${before} rows before, ${after} after`);
      const broken = db.pragma('foreign_key_check');
      if (broken.length) throw new Error(`blindkey_contexts rebuild: ${broken.length} foreign key problems`);
    })();
  } finally {
    db.pragma('legacy_alter_table = OFF');
    if (fk) db.pragma('foreign_keys = ON');
  }
  log(`[github-app] blindkey_contexts rebuilt to admit github_app_token (${before} scopes kept)`);
  return { rebuilt: true, rows: before };
}

function register(deps) {
  const { db, blindkeyEncrypt, blindkeyDecrypt, logSecurityEvent, secretFetch, readCapped } = deps;

  db.exec(`CREATE TABLE IF NOT EXISTS github_app_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    secret_id INTEGER NOT NULL,
    context_id INTEGER,
    delegation_id INTEGER,
    owner_did TEXT NOT NULL,
    caller_did TEXT NOT NULL,
    installation_id TEXT NOT NULL,
    repositories TEXT NOT NULL,          -- JSON, what the token covers (as GitHub answered)
    permissions TEXT NOT NULL,           -- JSON
    token_enc TEXT,                      -- host-encrypted, ONLY to revoke it; erased when it expires or is revoked
    github_expires_at TEXT NOT NULL,     -- GitHub's own expiry (≤ 1 h)
    expires_at TEXT NOT NULL,            -- ours: the scope's TTL, ≤ GitHub's (revoked then)
    status TEXT NOT NULL DEFAULT 'live', -- live | revoked | expired
    revoke_wanted TEXT,                  -- why it should be revoked (scope deleted, delegation revoked, …)
    revoked_at TEXT,
    revoke_note TEXT,
    created_at TEXT NOT NULL
  )`);
  db.exec('CREATE INDEX IF NOT EXISTS idx_gat_live ON github_app_tokens(status, expires_at)');
  db.exec('CREATE INDEX IF NOT EXISTS idx_gat_owner ON github_app_tokens(owner_did)');
  db.exec('CREATE INDEX IF NOT EXISTS idx_gat_caller ON github_app_tokens(caller_did)');

  const nowIso = () => new Date().toISOString();
  const ghHeaders = (auth) => ({ Authorization: 'Bearer ' + auth, Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'DemiPass' });
  const scrub = (text, ...secrets) => { let t = String(text || ''); for (const s of secrets) if (s) t = t.split(s).join('[REDACTED]'); return t; };

  // Mint one installation token. `request` is requestFor()'s value. Never returns or logs the key or the JWT.
  // { ok, token, row } or { ok:false, status, body, connected }.
  async function mint({ secret, pem, contextId, delegationId, callerDid, request, timeoutMs, egress }) {
    const appId = appIdOf(secret);
    if (!appId) return { ok: false, status: 409, body: { error: "this GitHub App key has no App ID; its owner stores it again with the app's App ID" } };
    let jwt;
    try { jwt = appJwt(pem, appId); } catch (_) { return { ok: false, status: 500, body: { error: 'the stored GitHub App key could not sign (store the .pem again)' } }; }
    const url = `${GITHUB_API}/app/installations/${request.installation_id}/access_tokens`;
    // GitHub takes repository names without the owner: the installation is on one account (parseScope keeps one owner).
    const names = request.repositories.map(r => r.split('/')[1]);
    if (egress) egress(url);   // the outbound log, before the connection
    let res, text;
    try {
      res = await secretFetch(url, { method: 'POST', headers: { ...ghHeaders(jwt), 'Content-Type': 'application/json' },
        body: JSON.stringify({ repositories: names, permissions: request.permissions }), signal: AbortSignal.timeout(timeoutMs) });
      text = await readCapped(res, 256 * 1024);
    } catch (e) { jwt = null; throw e; }
    let body = null; try { body = JSON.parse(text); } catch (_) {}
    if (res.status !== 201 || !body || typeof body.token !== 'string' || !body.token) {
      const msg = scrub(body && body.message ? String(body.message) : '', jwt).slice(0, 300);
      jwt = null;
      const ceiling = res.status === 422 && /permission|not granted|repositor/i.test(msg);
      return { ok: false, connected: true, status: res.status === 404 || res.status === 401 ? 502 : (ceiling ? 403 : 502),
        body: { error: ceiling ? `GitHub refused: ${msg} — the app's installation does not grant this; its owner reinstalls the app with more (a scope never exceeds the installation)`
                              : `GitHub did not mint a token (HTTP ${res.status}${msg ? ': ' + msg : ''})`, github_status: res.status } };
    }
    jwt = null;
    const token = body.token;
    // GitHub's answer must be no wider than the request; a wider token is revoked at once, never handed out.
    const gotRepos = Array.isArray(body.repositories) ? body.repositories.map(r => String((r && r.full_name) || '').toLowerCase()) : null;
    const gotPerms = body.permissions && typeof body.permissions === 'object' ? body.permissions : {};
    const wider = !gotRepos || body.repository_selection === 'all' || gotRepos.some(r => !request.repositories.includes(r))
      || Object.entries(gotPerms).some(([k, l]) => !(k === 'metadata' && l === 'read') && !(request.permissions[k] && LEVELS[l] && LEVELS[l] <= LEVELS[request.permissions[k]]));
    const ghExp = Date.parse(body.expires_at);
    const ghExpIso = Number.isFinite(ghExp) ? new Date(ghExp).toISOString() : new Date(Date.now() + TTL_MAX_S * 1000).toISOString();
    const ourExp = new Date(Math.min(Number.isFinite(ghExp) ? ghExp : Infinity, Date.now() + request.ttl * 1000)).toISOString();
    const id = Number(db.prepare(`INSERT INTO github_app_tokens (secret_id, context_id, delegation_id, owner_did, caller_did, installation_id, repositories, permissions,
                                   token_enc, github_expires_at, expires_at, status, revoke_wanted, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'live', ?, ?)`)
      .run(secret.id, contextId || null, delegationId || null, secret.did, callerDid, request.installation_id,
           JSON.stringify(gotRepos || []), JSON.stringify(gotPerms), blindkeyEncrypt(token), ghExpIso, ourExp, wider ? 'wider than asked' : null, nowIso()).lastInsertRowid);
    if (wider) {
      logSecurityEvent('github_app_token_too_wide', 'critical', { caller_did: callerDid, capability: 'github_app_token', target: `installation:${request.installation_id}`,
        context: { secret: secret.name, scope_id: contextId, asked: { repositories: request.repositories, permissions: request.permissions }, got: { repositories: gotRepos, permissions: gotPerms, selection: body.repository_selection } } });
      await revokeRow(db.prepare('SELECT * FROM github_app_tokens WHERE id = ?').get(id));
      return { ok: false, connected: true, status: 502, body: { error: 'GitHub answered with a token wider than asked; DemiPass revoked it and did not hand it out' } };
    }
    return { ok: true, token, row: db.prepare('SELECT id, repositories, permissions, expires_at, github_expires_at FROM github_app_tokens WHERE id = ?').get(id) };
  }

  // DELETE /installation/token with the token itself. The row ends 'revoked' (or 'expired' past GitHub's expiry) and
  // its ciphertext is erased; a revoke GitHub did not confirm stays wanted and is retried by the sweep.
  async function revokeRow(row, why) {
    if (!row || row.status !== 'live') return;
    const now = Date.now();
    if (!row.token_enc || Date.parse(row.github_expires_at) <= now) {
      db.prepare("UPDATE github_app_tokens SET status = 'expired', token_enc = NULL WHERE id = ? AND status = 'live'").run(row.id);
      return;
    }
    let token; try { token = blindkeyDecrypt(row.token_enc); } catch (_) { token = null; }
    if (!token) { db.prepare("UPDATE github_app_tokens SET status = 'expired', token_enc = NULL, revoke_note = 'unreadable' WHERE id = ? AND status = 'live'").run(row.id); return; }
    let status = 0;
    try {
      const r = await secretFetch(`${GITHUB_API}/installation/token`, { method: 'DELETE', headers: ghHeaders(token), signal: AbortSignal.timeout(15000) });
      status = r.status; try { await r.arrayBuffer(); } catch (_) {}
    } catch (_) { status = 0; }
    token = null;
    const reason = why || row.revoke_wanted || 'expired (scope TTL)';
    if (status === 204 || status === 401) {   // 401: GitHub no longer knows it — dead either way
      db.prepare("UPDATE github_app_tokens SET status = 'revoked', token_enc = NULL, revoked_at = ?, revoke_wanted = ?, revoke_note = ? WHERE id = ? AND status = 'live'")
        .run(nowIso(), reason, `github ${status}`, row.id);
      logSecurityEvent('github_app_token_revoked', 'info', { caller_did: row.caller_did, capability: 'github_app_token', target: `installation:${row.installation_id}`,
        context: { token_id: row.id, scope_id: row.context_id, delegation_id: row.delegation_id, reason } });
    } else {
      db.prepare('UPDATE github_app_tokens SET revoke_wanted = ?, revoke_note = ? WHERE id = ? AND status = \'live\'').run(reason, `revoke failed (${status || 'no answer'}); retried, else it dies at GitHub's expiry`, row.id);
    }
  }

  // Every live token whose grant has ended — revoke wanted, our TTL passed, scope gone or not active, delegation not
  // active, key deleted or revoked — is revoked; past GitHub's own expiry it is just marked expired.
  let sweeping = null, again = false;
  async function sweep() {
    if (sweeping) { again = true; return sweeping; }
    sweeping = (async () => {
      do {
        again = false;
        const now = nowIso();
        const rows = db.prepare(`SELECT t.* FROM github_app_tokens t
            LEFT JOIN blindkey_contexts c ON c.id = t.context_id
            LEFT JOIN demipass_delegations d ON d.id = t.delegation_id
            LEFT JOIN blindkey_secrets s ON s.id = t.secret_id
          WHERE t.status = 'live' AND (t.revoke_wanted IS NOT NULL OR t.expires_at <= ? OR t.github_expires_at <= ?
            OR c.id IS NULL OR c.status != 'active'
            OR (t.delegation_id IS NOT NULL AND (d.id IS NULL OR d.status != 'active' OR (d.expires_at IS NOT NULL AND datetime(d.expires_at) <= datetime('now'))))
            OR s.id IS NULL OR s.status IN ('deleted', 'revoked'))`).all(now, now);
        for (const r of rows) {
          const why = r.revoke_wanted || (r.expires_at <= now ? 'expired (scope TTL)' : 'its grant ended');
          try { await revokeRow(r, why); } catch (_) {}
        }
      } while (again);
    })().finally(() => { sweeping = null; });
    return sweeping;
  }
  // A scope, delegation or key ended by one of the routes: mark its live tokens and revoke them now (not awaited).
  function revokeFor({ contextId, delegationId, secretId }, reason) {
    const where = contextId ? ['context_id = ?', contextId] : delegationId ? ['delegation_id = ?', delegationId] : secretId ? ['secret_id = ?', secretId] : null;
    if (!where) return 0;
    const n = db.prepare(`UPDATE github_app_tokens SET revoke_wanted = COALESCE(revoke_wanted, ?) WHERE status = 'live' AND ${where[0]}`).run(reason, where[1]).changes;
    if (n) sweep().catch(() => {});
    return n;
  }
  const timer = setInterval(() => { sweep().catch(() => {}); }, Number(process.env.GITHUB_TOKEN_SWEEP_MS) || SWEEP_MS);
  if (timer.unref) timer.unref();

  // Live tokens for GET /api/demipass/expiring: minted on the caller's keys, or by the caller.
  function liveTokens(did) {
    return db.prepare(`SELECT t.id, t.caller_did, t.owner_did, t.installation_id, t.repositories, t.permissions, t.expires_at, t.github_expires_at, t.created_at,
                              s.name AS secret_name, s.ref_code AS ref, c.context_name AS scope
        FROM github_app_tokens t LEFT JOIN blindkey_secrets s ON s.id = t.secret_id LEFT JOIN blindkey_contexts c ON c.id = t.context_id
        WHERE t.status = 'live' AND t.expires_at > ? AND (t.owner_did = ? OR t.caller_did = ?) ORDER BY t.expires_at ASC LIMIT 200`).all(nowIso(), did, did)
      .map(r => ({ ...r, repositories: JSON.parse(r.repositories || '[]'), permissions: JSON.parse(r.permissions || '{}'),
                   expires_in_seconds: Math.max(0, Math.round((Date.parse(r.expires_at) - Date.now()) / 1000)) }));
  }

  return { mint, revokeRow, revokeFor, sweep, liveTokens };
}

module.exports = { register, widenContextActionCheck, isAppKey, appIdOf, pemRefusal, appIdRefusal, parseScope, scopeOf, isNarrowing, requestFor, describe, appJwt,
  TTL_MIN_S, TTL_MAX_S, GITHUB_API };
