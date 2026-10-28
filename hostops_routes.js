'use strict';
// DemiPass host operations — HTTP surface (docs/host-operations.md). Registered from server.js:
// require('./hostops_routes')({ app, db, ... }). The pure core (shapes, matching, quoting) is ./hostops.
//
// An agent runs an argv on a host it may not log in to itself: the stored password stays in DemiPass, the host
// key is pinned, and the argv runs only when it fits a shape inside an open window. Anything not covered becomes a
// request the owner approves on the phone with the vault PIN (intent `hostop:<request id>`, the fill pattern).
const fs = require('fs');
const path = require('path');
const { execFile } = require('child_process');
const dns = require('dns').promises;
const hostops = require('./hostops');

module.exports = function registerHostopsRoutes(deps) {
  const { app, db, billing, getBearerIdentity, gateSession, gateFresh, gateMissing, spendSingleUse, logSecurityEvent,
    blindkeyDecrypt, siliconHasPermission, cleanLabel, REDEEMABLE_STATUS_SQL } = deps;
  const limit = deps.rateLimitStandard;
  const pollLimit = deps.rateLimitPoll || deps.rateLimitStandard;
  const knownHostsDir = path.join(deps.dataDir, 'hostops-known-hosts');
  const sshBin = deps.sshBin || 'sshpass';
  const keyscanBin = deps.keyscanBin || 'ssh-keyscan';
  const MAX_PENDING = 20;          // per owner: a stolen token cannot bury the wallet in cards
  const MAX_JOBS_PER_HOST = 4;
  const MAX_WINDOW_HOURS = 720;    // 30 days
  const REQUEST_TTL_HOURS = 24;
  const ONCE_HOURS = 1;
  const POLL_CACHE_MS = 5000;
  const scanFailures = new Map();   // requester DID → times of failed host-key scans (an hour's worth)

  // ── schema ───────────────────────────────────────────────────────────────────────────────────────
  db.exec(`CREATE TABLE IF NOT EXISTS hostops_hosts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_did TEXT NOT NULL,
    address TEXT NOT NULL,
    port INTEGER NOT NULL DEFAULT 22,
    ssh_user TEXT NOT NULL,
    known_hosts TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(owner_did, address, port, ssh_user)
  )`);
  db.exec(`CREATE TABLE IF NOT EXISTS hostops_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_did TEXT NOT NULL,
    requester_did TEXT NOT NULL,
    requester_session TEXT,
    secret_id INTEGER NOT NULL,
    address TEXT NOT NULL,
    port INTEGER NOT NULL DEFAULT 22,
    ssh_user TEXT NOT NULL,
    host_id INTEGER,
    scanned_known_hosts TEXT,
    scanned_fingerprint TEXT,
    kind TEXT NOT NULL CHECK(kind IN ('run', 'window')),
    argv TEXT,
    shapes TEXT,
    label TEXT DEFAULT '',
    reason TEXT DEFAULT '',
    duration_hours INTEGER,
    status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending', 'approved', 'denied', 'withdrawn')),
    window_id INTEGER,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    expires_at TEXT NOT NULL,
    decided_at TEXT,
    decided_session TEXT
  )`);
  db.exec('CREATE INDEX IF NOT EXISTS idx_hostops_req_owner ON hostops_requests(owner_did, status)');
  db.exec(`CREATE TABLE IF NOT EXISTS hostops_windows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_did TEXT NOT NULL,
    grantee_did TEXT NOT NULL,
    secret_id INTEGER NOT NULL,
    host_id INTEGER NOT NULL,
    label TEXT DEFAULT '',
    shapes TEXT NOT NULL,
    closes_at TEXT NOT NULL,
    max_runs INTEGER NOT NULL DEFAULT 0,
    run_count INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open', 'closed')),
    request_id INTEGER,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    closed_at TEXT,
    closed_by TEXT
  )`);
  db.exec('CREATE INDEX IF NOT EXISTS idx_hostops_win ON hostops_windows(grantee_did, secret_id, host_id, status)');
  db.exec(`CREATE TABLE IF NOT EXISTS hostops_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    window_id INTEGER NOT NULL,
    owner_did TEXT NOT NULL,
    caller_did TEXT NOT NULL,
    secret_id INTEGER NOT NULL,
    host_id INTEGER NOT NULL,
    shape_name TEXT NOT NULL,
    argv TEXT NOT NULL,
    mode TEXT NOT NULL,
    status TEXT NOT NULL,
    exit_code INTEGER,
    stdout TEXT DEFAULT '',
    stderr TEXT DEFAULT '',
    unit TEXT,
    max_seconds INTEGER,
    started_at TEXT DEFAULT CURRENT_TIMESTAMP,
    finished_at TEXT,
    polled_at INTEGER
  )`);
  db.exec('CREATE INDEX IF NOT EXISTS idx_hostops_runs_caller ON hostops_runs(caller_did, id)');
  db.exec('CREATE INDEX IF NOT EXISTS idx_hostops_runs_owner ON hostops_runs(owner_did, id)');

  // ── helpers ──────────────────────────────────────────────────────────────────────────────────────
  const nowIso = () => new Date().toISOString();
  const plusHours = h => new Date(Date.now() + h * 3600 * 1000).toISOString();
  const json = s => { try { return JSON.parse(s); } catch (_) { return null; } };
  const nameOf = did => (db.prepare('SELECT username FROM identity_wallets WHERE did = ?').get(did) || {}).username || did.slice(0, 24) + '…';

  function hostopsAuth(req, res) {
    const auth = getBearerIdentity(req);
    if (!auth.ok) { res.status(auth.status || 401).json({ error: auth.error }); return null; }
    if (auth.decoded && auth.decoded.wrk) { res.status(403).json({ error: 'worker tokens cannot use host operations' }); return null; }
    // Silicon agent tokens are not supported yet: billing and window grants are per identity, and a silicon token
    // acts as its owner's identity. Agents use their own DID (a delegation), as Brain does.
    if (auth.silicon) { res.status(403).json({ error: 'silicon agent tokens cannot use host operations yet; use an identity token with a delegation' }); return null; }
    if (!gateSession(auth)) { res.status(403).json({ error: 'this token cannot hold host operations — sign in again' }); return null; }
    return auth;
  }

  // The credential named by `ref`, if the caller owns it or holds an active delegation for it.
  function resolveCredential(auth, ref) {
    if (typeof ref !== 'string' || !/^DP-[A-Za-z0-9-]{4,64}$/.test(ref)) return { status: 400, error: 'ref required (a DP-… reference)' };
    const secret = db.prepare(`SELECT * FROM blindkey_secrets WHERE ref_code = ? AND ${REDEEMABLE_STATUS_SQL}`).get(ref);
    if (!secret) return { status: 403, error: 'access denied' };
    if (secret.frozen) return { status: 423, error: 'this credential is frozen' };
    if (secret.secret_type !== 'password') return { status: 400, error: 'host operations use a stored SSH password (secret type password)' };
    if (auth.silicon && (!siliconHasPermission(auth.agent_name, 'secret:use', secret.name) || !siliconHasPermission(auth.agent_name, 'action:ssh_exec', '*'))) {
      return { status: 403, error: 'silicon agent lacks secret:use or action:ssh_exec for this credential' };
    }
    if (secret.did === auth.did) return { secret, owner_did: secret.did };
    const del = db.prepare("SELECT * FROM demipass_delegations WHERE secret_id = ? AND delegate_did = ? AND status = 'active'").get(secret.id, auth.did);
    if (!del || (del.expires_at && new Date(del.expires_at) < new Date())) return { status: 403, error: 'access denied' };
    return { secret, owner_did: secret.did, delegation_id: del.id };
  }

  // The registered host of `owner` at address/port (and user, when given or needed to disambiguate).
  function findHost(owner, address, port, user) {
    const rows = db.prepare('SELECT * FROM hostops_hosts WHERE owner_did = ? AND address = ? AND port = ?').all(owner, address, port);
    if (user) return { host: rows.find(r => r.ssh_user === user) || null };
    if (rows.length > 1) return { error: `several logins are registered on ${address}; say which with user` };
    return { host: rows[0] || null };
  }

  function knownHostsFile(host) {
    fs.mkdirSync(knownHostsDir, { recursive: true, mode: 0o700 });
    const f = path.join(knownHostsDir, String(host.id));
    fs.writeFileSync(f, host.known_hosts, { mode: 0o600 });
    return f;
  }

  // Run one remote command on a pinned host with the stored password. Never a local shell; the password travels
  // in the environment only. Resolves { code, stdout, stderr, timedOut }.
  // The password as ssh will type it (sshpass sends one line): what runs, and what must be redacted.
  function usablePassword(p) { return typeof p === 'string' ? p.replace(/\r?\n$/, '') : p; }
  function ssh(host, password, remote, timeoutMs) {
    return new Promise(resolve => {
      password = usablePassword(password);
      if (typeof password !== 'string' || /[\0\r\n]/.test(password)) return resolve({ code: 255, stdout: '', stderr: 'this stored password cannot be used for ssh', timedOut: false });
      const args = ['-e', 'ssh', '-F', '/dev/null', '-p', String(host.port),
        '-o', 'StrictHostKeyChecking=yes', '-o', `UserKnownHostsFile=${knownHostsFile(host)}`, '-o', 'GlobalKnownHostsFile=/dev/null',
        '-o', 'ConnectTimeout=10', '-o', 'PubkeyAuthentication=no', '-o', 'NumberOfPasswordPrompts=1',
        '--', `${host.ssh_user}@${host.address}`, remote];
      execFile(sshBin, args, { env: { PATH: process.env.PATH, SSHPASS: password }, timeout: timeoutMs, killSignal: 'SIGKILL', maxBuffer: 4 * 1024 * 1024, encoding: 'utf8' },
        (err, stdout, stderr) => {
          const timedOut = Boolean(err && err.killed);
          const code = err ? (typeof err.code === 'number' ? err.code : 255) : 0;
          resolve({ code, stdout: stdout || '', stderr: stderr || (err && !timedOut && typeof err.code !== 'number' ? String(err.message) : ''), timedOut });
        });
    });
  }

  // Resolve a host name and refuse it when any address it resolves to is loopback, link-local or metadata.
  // Checked before a scan and before every connection (a name can be repointed after it was approved).
  async function reachable(address) {
    let ips;
    try { ips = await dns.lookup(address, { all: true }); } catch (_) { return { ok: false, error: `${address} does not resolve` }; }
    if (!ips.length || ips.some(r => hostops.blockedIp(r.address))) return { ok: false, error: `${address} points at a local or metadata address; it cannot be a host` };
    return { ok: true };
  }
  function keyscan(address, port) {
    return new Promise(resolve => {
      execFile(keyscanBin, ['-T', '5', '-p', String(port), '-t', 'ed25519,ecdsa,rsa', address], { timeout: 15000, encoding: 'utf8', env: { PATH: process.env.PATH } },
        (err, stdout) => resolve(hostops.parseKeyscan(stdout, address, port)));
    });
  }

  // Charge one compute call through the normal attributed billing. false = a refusal (402) was already sent.
  function charge(req, res) {
    return new Promise(resolve => {
      let done = false;
      res.once('finish', () => { if (!done) { done = true; resolve(false); } });
      billing.billingMiddleware(db, 'api_call_compute')(req, res, () => { if (!done) { done = true; resolve(true); } });
    });
  }

  function decryptFor(secretId) {
    const s = db.prepare('SELECT * FROM blindkey_secrets WHERE id = ?').get(secretId);
    if (!s) return null;
    try { return blindkeyDecrypt(s.encrypted_value); } catch (_) { return null; }
  }
  // Redact every form the password can take in output (as stored, and as typed).
  const redactor = password => s => hostops.tail(hostops.redact(s, [password, usablePassword(password)]));

  function openWindows(owner, grantee, secretId, hostId) {
    return db.prepare(`SELECT * FROM hostops_windows WHERE owner_did = ? AND grantee_did = ? AND secret_id = ? AND host_id = ? AND status = 'open'
                       AND closes_at > ? AND (max_runs = 0 OR run_count < max_runs) ORDER BY id`).all(owner, grantee, secretId, hostId, nowIso())
      .map(w => ({ ...w, shapes: (json(w.shapes) || []).map(s => hostops.validateShape(s)).filter(v => v.ok).map(v => v.shape) }));
  }

  function publicRun(r) {
    return { id: r.id, window_id: r.window_id, shape: r.shape_name, argv: json(r.argv), mode: r.mode, status: r.status, exit_code: r.exit_code,
      stdout: r.stdout, stderr: r.stderr, started_at: r.started_at, finished_at: r.finished_at, max_seconds: r.max_seconds,
      caller: nameOf(r.caller_did), host_id: r.host_id };
  }
  function publicWindow(w) {
    const host = db.prepare('SELECT address, port, ssh_user, fingerprint FROM hostops_hosts WHERE id = ?').get(w.host_id) || {};
    return { id: w.id, label: w.label, grantee: nameOf(w.grantee_did), host: host.address, user: host.ssh_user, fingerprint: host.fingerprint,
      shapes: json(w.shapes) || [], closes_at: w.closes_at, max_runs: w.max_runs, run_count: w.run_count, status: w.status, created_at: w.created_at };
  }
  function publicRequest(r, auth) {
    const pinned = r.host_id ? db.prepare('SELECT fingerprint FROM hostops_hosts WHERE id = ?').get(r.host_id) : null;
    return { id: r.id, intent: `hostop:${r.id}`, kind: r.kind, status: r.status, label: r.label, reason: r.reason,
      requester: nameOf(r.requester_did), host: r.address, port: r.port, user: r.ssh_user,
      fingerprint: pinned ? pinned.fingerprint : r.scanned_fingerprint, host_is_new: !r.host_id,
      argv: json(r.argv), shapes: json(r.shapes), duration_hours: r.duration_hours, window_id: r.window_id,
      created_at: r.created_at, expires_at: r.expires_at,
      own_session: auth ? r.requester_session === gateSession(auth) : undefined };
  }
  const pendingCount = owner => db.prepare("SELECT COUNT(*) AS n FROM hostops_requests WHERE owner_did = ? AND status = 'pending' AND expires_at > ?").get(owner, nowIso()).n;

  // Resolve body.host/user/port to a target: { address, port, user, host } or { status, error }.
  function target(owner, body) {
    const address = body.host;
    const port = body.port === undefined ? 22 : body.port;
    if (!hostops.validAddress(address)) return { status: 400, error: 'host must be an address or hostname' };
    if (!hostops.validPort(port)) return { status: 400, error: 'port must be 1-65535' };
    if (body.user !== undefined && !hostops.validLogin(body.user)) return { status: 400, error: 'user must be a login name (a-z 0-9 _ . -)' };
    const f = findHost(owner, address, port, body.user);
    if (f.error) return { status: 400, error: f.error };
    return { address, port, user: f.host ? f.host.ssh_user : body.user, host: f.host };
  }

  // File (or reuse) a pending request. Scans the host key when the host is not registered yet.
  async function fileRequest(auth, cred, t, fields) {
    if (!t.user) return { status: 400, error: 'this host is not registered yet: say which login to use with user' };
    const dup = fields.kind === 'run' && db.prepare(`SELECT * FROM hostops_requests WHERE requester_did = ? AND secret_id = ? AND address = ? AND port = ? AND ssh_user = ?
      AND kind = 'run' AND argv = ? AND status = 'pending' AND expires_at > ?`).get(auth.did, cred.secret.id, t.address, t.port, t.user, fields.argv, nowIso());
    if (dup) return { request: dup };
    if (pendingCount(cred.owner_did) >= MAX_PENDING) return { status: 429, error: `the owner already has ${MAX_PENDING} host-operation requests waiting` };
    let scan = null;
    if (!t.host) {
      const where = await reachable(t.address);
      if (!where.ok) return { status: 400, error: where.error };
      const recent = (scanFailures.get(auth.did) || []).filter(ts => Date.now() - ts < 3600e3);
      if (recent.length >= 10) return { status: 429, error: 'too many hosts that could not be reached in the last hour' };
      scan = await keyscan(t.address, t.port);
      if (!scan) { scanFailures.set(auth.did, [...recent, Date.now()]); return { status: 502, error: `could not read ${t.address}'s SSH host key` }; }
    }
    if (pendingCount(cred.owner_did) >= MAX_PENDING) return { status: 429, error: `the owner already has ${MAX_PENDING} host-operation requests waiting` };
    const id = db.prepare(`INSERT INTO hostops_requests (owner_did, requester_did, requester_session, secret_id, address, port, ssh_user, host_id,
        scanned_known_hosts, scanned_fingerprint, kind, argv, shapes, label, reason, duration_hours, expires_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(cred.owner_did, auth.did, gateSession(auth), cred.secret.id, t.address, t.port, t.user,
      t.host ? t.host.id : null, scan ? scan.known_hosts : null, scan ? scan.fingerprint : null, fields.kind, fields.argv || null, fields.shapes || null,
      fields.label || '', fields.reason || '', fields.duration_hours || null, plusHours(REQUEST_TTL_HOURS)).lastInsertRowid;
    return { request: db.prepare('SELECT * FROM hostops_requests WHERE id = ?').get(id) };
  }

  // ── run ──────────────────────────────────────────────────────────────────────────────────────────
  // POST hostops/run { ref, host, user?, port?, argv[], mode?, sudo?, reason? }
  app.post('/api/blindkey/hostops/run', limit, async (req, res) => {
    const auth = hostopsAuth(req, res); if (!auth) return;
    const body = req.body || {};
    const cred = resolveCredential(auth, body.ref);
    if (cred.error) return res.status(cred.status).json({ error: cred.error });
    const argvErr = hostops.validateArgv(body.argv);
    if (argvErr) return res.status(400).json({ error: argvErr });
    if (body.mode !== undefined && body.mode !== 'run' && body.mode !== 'job') return res.status(400).json({ error: 'mode must be run or job' });
    if (body.sudo !== undefined && typeof body.sudo !== 'boolean') return res.status(400).json({ error: 'sudo must be true or false' });
    const t = target(cred.owner_did, body);
    if (t.error) return res.status(t.status).json({ error: t.error });

    const windows = t.host ? openWindows(cred.owner_did, auth.did, cred.secret.id, t.host.id) : [];
    const cover = hostops.findCover(windows, body.argv);
    if (!cover || (body.mode && body.mode !== cover.shape.mode)) {
      const explain = t.host ? hostops.explainRefusal(windows, body.argv) : { covered: false, host_registered: false, open_windows: [], nearest: null };
      if (cover) explain.nearest = { window_id: cover.window.id, shape: cover.shape.name, reason: `shape ${cover.shape.name} runs as a ${cover.shape.mode}` };
      // A one-time request needs a shape the owner can approve as-is: the exact argv, sudo and mode as asked.
      const once = hostops.literalShape(body.argv, { sudo: Boolean(body.sudo) || body.mode === 'job', mode: body.mode || 'run' });
      if (!once.ok) return res.status(400).json({ error: once.error, explain });
      const filed = await fileRequest(auth, cred, t, { kind: 'run', argv: JSON.stringify(body.argv), shapes: JSON.stringify([once.shape]), reason: cleanLabel(body.reason, 300), duration_hours: ONCE_HOURS });
      if (filed.error) return res.status(filed.status).json({ error: filed.error, explain });
      logSecurityEvent('hostop_needs_approval', 'info', { caller_did: auth.did, target: t.address, capability: 'hostop', context: { request_id: filed.request.id, argv0: body.argv[0] } });
      return res.status(202).json({ status: 'needs_approval', request_id: filed.request.id, explain,
        next: `the owner approves request ${filed.request.id} on the phone vault; poll GET /api/demipass/hostops/requests/${filed.request.id}, then call run again` });
    }

    const shape = cover.shape;
    if (shape.mode === 'job') {
      const running = db.prepare("SELECT COUNT(*) AS n FROM hostops_runs WHERE host_id = ? AND mode = 'job' AND status = 'running'").get(t.host.id).n;
      if (running >= MAX_JOBS_PER_HOST) return res.status(429).json({ error: `${MAX_JOBS_PER_HOST} jobs are already running on this host` });
    }
    const password = decryptFor(cred.secret.id);
    if (password === null) return res.status(500).json({ error: 'could not open the stored credential' });
    // Render first: a command that cannot be rendered costs nothing and leaves no run behind.
    try { hostops.renderRemote(shape, body.argv, { unit: 'dp-hostop-999999999999' }); } catch (e) { return res.status(400).json({ error: e.message }); }
    const where = await reachable(t.host.address);
    if (!where.ok) return res.status(400).json({ error: where.error });
    if (!(await charge(req, res))) return;
    // Take one run from the window, or refuse if it closed, expired or ran out meanwhile.
    const took = db.prepare(`UPDATE hostops_windows SET run_count = run_count + 1 WHERE id = ? AND status = 'open' AND closes_at > ?
                             AND (max_runs = 0 OR run_count < max_runs)`).run(cover.window.id, nowIso()).changes;
    if (took !== 1) return res.status(409).json({ error: 'the window closed or ran out of runs; try again' });
    db.prepare("UPDATE hostops_windows SET status = 'closed', closed_at = CURRENT_TIMESTAMP, closed_by = 'used' WHERE id = ? AND max_runs > 0 AND run_count >= max_runs").run(cover.window.id);
    const runId = db.prepare(`INSERT INTO hostops_runs (window_id, owner_did, caller_did, secret_id, host_id, shape_name, argv, mode, status, max_seconds)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'running', ?)`).run(cover.window.id, cred.owner_did, auth.did, cred.secret.id, t.host.id, shape.name,
      JSON.stringify(body.argv), shape.mode, shape.max_seconds).lastInsertRowid;
    db.prepare('INSERT INTO blindkey_events (event_type, actor, secret_id, context_name, detail) VALUES (?, ?, ?, ?, ?)').run('hostop_run', auth.did, cred.secret.id, null,
      JSON.stringify({ run_id: runId, window_id: cover.window.id, shape: shape.name, host: t.address, argv: body.argv }));

    const clean = redactor(password);
    if (shape.mode === 'job') {
      const unit = `dp-hostop-${runId}`;
      const r = await ssh(t.host, password, hostops.renderRemote(shape, body.argv, { unit }), 30000);
      // Started, or no answer in time (it may have started): keep the unit and let the next poll find out.
      if (r.code === 0 || r.timedOut) db.prepare('UPDATE hostops_runs SET unit = ?, stdout = ?, polled_at = ? WHERE id = ?').run(unit, clean(r.stdout || (r.timedOut ? 'no answer while starting; checking on the next poll' : '')), r.timedOut ? 0 : Date.now(), runId);
      else db.prepare("UPDATE hostops_runs SET status = 'error', exit_code = ?, stdout = ?, stderr = ?, finished_at = CURRENT_TIMESTAMP WHERE id = ?")
        .run(r.code, clean(r.stdout), clean(r.stderr || (r.timedOut ? 'the job did not start within 30 s' : '')), runId);
    } else {
      const r = await ssh(t.host, password, hostops.renderRemote(shape, body.argv), shape.max_seconds * 1000);
      const status = r.timedOut ? 'timed_out' : r.code === 0 ? 'succeeded' : 'failed';
      db.prepare('UPDATE hostops_runs SET status = ?, exit_code = ?, stdout = ?, stderr = ?, finished_at = CURRENT_TIMESTAMP WHERE id = ?')
        .run(status, r.timedOut ? null : r.code, clean(r.stdout), clean(r.stderr), runId);
    }
    res.json({ ok: true, run: publicRun(db.prepare('SELECT * FROM hostops_runs WHERE id = ?').get(runId)) });
  });

  // A run its caller or the credential's owner may see.
  function visibleRun(req, res, auth) {
    const id = Number(req.params.id);
    const r = Number.isInteger(id) && id > 0 ? db.prepare('SELECT * FROM hostops_runs WHERE id = ?').get(id) : null;
    if (!r || (r.caller_did !== auth.did && r.owner_did !== auth.did)) { res.status(404).json({ error: 'run not found' }); return null; }
    return r;
  }

  // Refresh a running job from the host (at most every POLL_CACHE_MS); a finished unit is read once, then stopped.
  async function refreshJob(r) {
    if (r.mode !== 'job' || r.status !== 'running' || !r.unit || (r.polled_at && Date.now() - r.polled_at < POLL_CACHE_MS)) return r;
    const host = db.prepare('SELECT * FROM hostops_hosts WHERE id = ?').get(r.host_id);
    const password = host ? decryptFor(r.secret_id) : null;
    if (!host || password === null) return r;
    db.prepare('UPDATE hostops_runs SET polled_at = ? WHERE id = ?').run(Date.now(), r.id);
    const probe = await ssh(host, password, hostops.jobProbe(r.unit), 30000);
    if (probe.code !== 0 && !probe.stdout) return db.prepare('SELECT * FROM hostops_runs WHERE id = ?').get(r.id);
    const st = hostops.parseJobProbe(probe.stdout);
    const log = redactor(password)(st.journal);
    if (st.status === 'running') {
      db.prepare("UPDATE hostops_runs SET stdout = ? WHERE id = ? AND status = 'running'").run(log, r.id);
    } else {
      db.prepare("UPDATE hostops_runs SET status = ?, exit_code = ?, stdout = ?, finished_at = CURRENT_TIMESTAMP WHERE id = ? AND status = 'running'")
        .run(st.status, st.exit_code, log, r.id);
      if (st.status !== 'lost') await ssh(host, password, hostops.jobStop(r.unit), 30000);   // collect the finished unit
    }
    return db.prepare('SELECT * FROM hostops_runs WHERE id = ?').get(r.id);
  }

  app.get('/api/blindkey/hostops/runs/:id', pollLimit, async (req, res) => {
    const auth = hostopsAuth(req, res); if (!auth) return;
    const r = visibleRun(req, res, auth); if (!r) return;
    res.json({ ok: true, run: publicRun(await refreshJob(r)) });
  });

  app.post('/api/blindkey/hostops/runs/:id/cancel', limit, async (req, res) => {
    const auth = hostopsAuth(req, res); if (!auth) return;
    const r = visibleRun(req, res, auth); if (!r) return;
    if (r.mode !== 'job' || r.status !== 'running' || !r.unit) return res.status(409).json({ error: `this run is ${r.status}; only a running job can be cancelled` });
    const host = db.prepare('SELECT * FROM hostops_hosts WHERE id = ?').get(r.host_id);
    const password = host ? decryptFor(r.secret_id) : null;
    if (!host || password === null) return res.status(500).json({ error: 'could not reach the job' });
    const stop = await ssh(host, password, hostops.jobStop(r.unit), 30000);
    if (stop.code !== 0) return res.status(502).json({ error: 'the host did not stop the job', detail: redactor(password)(stop.stderr).slice(0, 500) });
    db.prepare("UPDATE hostops_runs SET status = 'cancelled', finished_at = CURRENT_TIMESTAMP WHERE id = ? AND status = 'running'").run(r.id);
    res.json({ ok: true, run: publicRun(db.prepare('SELECT * FROM hostops_runs WHERE id = ?').get(r.id)) });
  });

  app.get('/api/blindkey/hostops/runs', pollLimit, (req, res) => {
    const auth = hostopsAuth(req, res); if (!auth) return;
    const n = Math.min(Math.max(Number(req.query.limit) || 20, 1), 100);
    const rows = db.prepare('SELECT * FROM hostops_runs WHERE caller_did = ? OR owner_did = ? ORDER BY id DESC LIMIT ?').all(auth.did, auth.did, n);
    res.json({ ok: true, runs: rows.map(publicRun) });
  });

  // ── requests ─────────────────────────────────────────────────────────────────────────────────────
  // POST hostops/requests { kind:'window', ref, host, user?, port?, label, reason, duration_hours, shapes[] }
  app.post('/api/blindkey/hostops/requests', limit, async (req, res) => {
    const auth = hostopsAuth(req, res); if (!auth) return;
    const body = req.body || {};
    if (body.kind !== 'window') return res.status(400).json({ error: "kind must be 'window' (one-time runs are requested by calling run)" });
    const cred = resolveCredential(auth, body.ref);
    if (cred.error) return res.status(cred.status).json({ error: cred.error });
    const v = hostops.validateShapes(body.shapes);
    if (!v.ok) return res.status(400).json({ error: v.error });
    const hours = body.duration_hours;
    if (!Number.isInteger(hours) || hours < 1 || hours > MAX_WINDOW_HOURS) return res.status(400).json({ error: `duration_hours must be 1 to ${MAX_WINDOW_HOURS}` });
    const label = cleanLabel(body.label, 120).trim();
    if (!label) return res.status(400).json({ error: 'label required: what the window is for' });
    const t = target(cred.owner_did, body);
    if (t.error) return res.status(t.status).json({ error: t.error });
    const filed = await fileRequest(auth, cred, t, { kind: 'window', shapes: JSON.stringify(v.shapes), label, reason: cleanLabel(body.reason, 1000), duration_hours: hours });
    if (filed.error) return res.status(filed.status).json({ error: filed.error });
    res.status(202).json({ status: 'pending', request_id: filed.request.id, intent: `hostop:${filed.request.id}` });
  });

  app.get('/api/blindkey/hostops/requests/:id', pollLimit, (req, res) => {
    const auth = hostopsAuth(req, res); if (!auth) return;
    const id = Number(req.params.id);
    const r = Number.isInteger(id) && id > 0 ? db.prepare('SELECT * FROM hostops_requests WHERE id = ?').get(id) : null;
    if (!r || (r.requester_did !== auth.did && r.owner_did !== auth.did)) return res.status(404).json({ error: 'request not found' });
    const out = publicRequest(r, auth);
    if (r.status === 'pending' && r.expires_at <= nowIso()) out.status = 'expired';
    res.json({ ok: true, request: out });
  });

  // The wallet's list: requests waiting for this owner, open windows, recent runs (carbon only).
  app.get('/api/blindkey/hostops/pending', pollLimit, (req, res) => {
    const auth = hostopsAuth(req, res); if (!auth) return;
    if (auth.silicon) return res.status(403).json({ error: 'only the owner decides host operations' });
    const requests = db.prepare("SELECT * FROM hostops_requests WHERE owner_did = ? AND status = 'pending' AND expires_at > ? ORDER BY id").all(auth.did, nowIso())
      .map(r => publicRequest(r, auth));
    const windows = db.prepare("SELECT * FROM hostops_windows WHERE owner_did = ? AND status = 'open' AND closes_at > ? ORDER BY id").all(auth.did, nowIso()).map(publicWindow);
    const runs = db.prepare('SELECT * FROM hostops_runs WHERE owner_did = ? ORDER BY id DESC LIMIT 10').all(auth.did).map(publicRun);
    res.json({ ok: true, requests, windows, runs });
  });

  function decision(req, res, auth) {
    if (auth.silicon) { res.status(403).json({ error: 'only the owner decides host operations' }); return null; }
    const id = Number(req.params.id);
    const r = Number.isInteger(id) && id > 0 ? db.prepare('SELECT * FROM hostops_requests WHERE id = ? AND owner_did = ?').get(id, auth.did) : null;
    if (!r) { res.status(404).json({ error: 'request not found' }); return null; }
    if (r.status !== 'pending') { res.status(409).json({ error: `this request is already ${r.status}` }); return null; }
    if (r.expires_at <= nowIso()) { res.status(410).json({ error: 'expired' }); return null; }
    return r;
  }

  // POST hostops/requests/:id/approve { duration_hours? } — the vault PIN, typed for intent hostop:<id>, is spent
  // here. Never from the session that asked. Registers the host (pinning the scanned key) and opens the window.
  app.post('/api/blindkey/hostops/requests/:id/approve', limit, (req, res) => {
    const auth = hostopsAuth(req, res); if (!auth) return;
    const r = decision(req, res, auth); if (!r) return;
    const session = gateSession(auth);
    if (r.requester_session === session) return res.status(409).json({ error: 'approve this from your phone vault, not from the session that asked for it' });
    const secret = db.prepare(`SELECT id FROM blindkey_secrets WHERE id = ? AND did = ? AND ${REDEEMABLE_STATUS_SQL}`).get(r.secret_id, auth.did);
    if (!secret) return res.status(404).json({ error: 'the credential was deleted or revoked since the request' });
    let hours = r.duration_hours || ONCE_HOURS;
    const want = (req.body || {}).duration_hours;
    if (want !== undefined) {
      if (!Number.isInteger(want) || want < 1 || want > hours) return res.status(400).json({ error: `duration_hours must be 1 to ${hours} (the requested length)` });
      hours = want;
    }
    const shapes = hostops.validateShapes(json(r.shapes));
    if (!shapes.ok) return res.status(400).json({ error: 'the request no longer validates: ' + shapes.error });
    const intent = `hostop:${r.id}`;
    if (!gateFresh(auth.did, 'pin', auth, intent)) return res.status(403).json(gateMissing('hostop', ['pin'], ['pin'], intent));
    let windowId, conflict = null;
    try {
      db.transaction(() => {
        // Host checks first: a refused approval must not spend the PIN.
        let hostId = r.host_id, existing = null;
        if (hostId) {
          if (!db.prepare('SELECT 1 FROM hostops_hosts WHERE id = ? AND owner_did = ?').get(hostId, auth.did)) { conflict = { status: 409, error: 'the host registration was removed since the request' }; return; }
        } else {
          existing = db.prepare('SELECT * FROM hostops_hosts WHERE owner_did = ? AND address = ? AND port = ? AND ssh_user = ?').get(auth.did, r.address, r.port, r.ssh_user);
          if (existing && existing.fingerprint !== r.scanned_fingerprint) { conflict = { status: 409, error: `${r.address}'s host key changed since it was pinned (${existing.fingerprint} → ${r.scanned_fingerprint}); deny this and check the host` }; return; }
        }
        const refused = spendSingleUse(auth.did, 'hostop', ['pin'], auth, intent);
        if (refused) { conflict = refused; return; }
        if (!hostId) {
          hostId = existing ? existing.id : db.prepare('INSERT INTO hostops_hosts (owner_did, address, port, ssh_user, known_hosts, fingerprint) VALUES (?, ?, ?, ?, ?, ?)')
            .run(auth.did, r.address, r.port, r.ssh_user, r.scanned_known_hosts, r.scanned_fingerprint).lastInsertRowid;
        }
        windowId = db.prepare(`INSERT INTO hostops_windows (owner_did, grantee_did, secret_id, host_id, label, shapes, closes_at, max_runs, request_id)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(auth.did, r.requester_did, r.secret_id, hostId, r.label || (r.kind === 'run' ? 'one-time run' : ''),
          JSON.stringify(shapes.shapes), plusHours(hours), r.kind === 'run' ? 1 : 0, r.id).lastInsertRowid;
        const changed = db.prepare("UPDATE hostops_requests SET status = 'approved', window_id = ?, host_id = ?, decided_at = CURRENT_TIMESTAMP, decided_session = ? WHERE id = ? AND status = 'pending'")
          .run(windowId, hostId, session, r.id).changes;
        if (changed !== 1) throw new Error('decided meanwhile');
      })();
    } catch (e) {
      return res.status(e.message === 'decided meanwhile' ? 409 : 503).json({ error: e.message === 'decided meanwhile' ? 'this request was decided meanwhile' : 'could not record the approval; nothing changed — try again' });
    }
    if (conflict) return res.status(conflict.status || 403).json(conflict);
    logSecurityEvent('hostop_window_opened', 'alert', { caller_did: auth.did, target: r.address, capability: 'hostop', context: { request_id: r.id, window_id: windowId, grantee: r.requester_did, hours } });
    res.json({ ok: true, request_id: r.id, status: 'approved', window: publicWindow(db.prepare('SELECT * FROM hostops_windows WHERE id = ?').get(windowId)) });
  });

  app.post('/api/blindkey/hostops/requests/:id/deny', limit, (req, res) => {
    const auth = hostopsAuth(req, res); if (!auth) return;
    const r = decision(req, res, auth); if (!r) return;
    db.prepare("UPDATE hostops_requests SET status = 'denied', decided_at = CURRENT_TIMESTAMP, decided_session = ? WHERE id = ? AND status = 'pending'").run(gateSession(auth), r.id);
    res.json({ ok: true, request_id: r.id, status: 'denied' });
  });

  // ── windows ──────────────────────────────────────────────────────────────────────────────────────
  app.get('/api/blindkey/hostops/windows', pollLimit, (req, res) => {
    const auth = hostopsAuth(req, res); if (!auth) return;
    const rows = db.prepare('SELECT * FROM hostops_windows WHERE owner_did = ? OR grantee_did = ? ORDER BY id DESC LIMIT 50').all(auth.did, auth.did);
    res.json({ ok: true, windows: rows.map(w => { const p = publicWindow(w); if (p.status === 'open' && w.closes_at <= nowIso()) p.status = 'expired'; return p; }) });
  });

  // Closing only removes authority: the owner or the grantee may, no PIN.
  app.post('/api/blindkey/hostops/windows/:id/close', limit, (req, res) => {
    const auth = hostopsAuth(req, res); if (!auth) return;
    const id = Number(req.params.id);
    const w = Number.isInteger(id) && id > 0 ? db.prepare('SELECT * FROM hostops_windows WHERE id = ?').get(id) : null;
    if (!w || (w.owner_did !== auth.did && w.grantee_did !== auth.did)) return res.status(404).json({ error: 'window not found' });
    db.prepare("UPDATE hostops_windows SET status = 'closed', closed_at = CURRENT_TIMESTAMP, closed_by = ? WHERE id = ? AND status = 'open'").run(auth.did === w.owner_did ? 'owner' : 'grantee', id);
    res.json({ ok: true, window: publicWindow(db.prepare('SELECT * FROM hostops_windows WHERE id = ?').get(id)) });
  });

  return { hostops };
};
