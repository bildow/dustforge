'use strict';
// ── Cryptographic depth (red team item 1): elevated and critical secrets the host cannot read ──────────────────────
// Before: depth was a policy gate — every value at every depth was decryptable with the host's IDENTITY_MASTER_KEY, so
// root on the host had every secret. Now, once the owner has a phone with a wrap key, raising a secret to elevated or
// critical WRAPS it:
//   - the value is encrypted under a fresh data key (AES-256-GCM, `wrapped_value`); the data key is encrypted to each of
//     the owner's phones' wrap keys W (RSA-2048 OAEP, private half in the Android Keystore, user presence on every use,
//     never leaves the phone) — `secret_wraps`, one row per wrap key fingerprint;
//   - the server-decryptable copy is replaced by a marker that decrypts to nothing (secure_delete zeroes the old bytes),
//     so every path that decrypts with the host key (reveal, fill, key_name, rotate-blind, share-reveal, the leak
//     scanner, Rowen delivery) now refuses this secret on its own: it fails closed.
//   - the only way back to the value is an approval: when a request for a wrapped secret is created, the server makes a
//     one-use RSA key pair for it whose private half lives only in this process's memory; on Approve the phone unwraps
//     the data key inside its Keystore and re-encrypts it to that one-use public key (the vault page never sees the data
//     key); the redeeming /use decrypts once, acts once, and the one-use key is dropped. Outside an approval window
//     neither the database nor the process holds the value. A restart drops pending one-use keys: those requests are
//     asked again.
// Lowering a wrapped secret to standard is the owner re-exposing it to the host: the phone unwraps it the same way (an
// owner unwrap session) and the value is re-encrypted with the host key.
// Losing every phone that holds a wrap loses the secret — stated to the owner. The wrap key survives re-linking the same
// phone (one Keystore alias), and wraps are keyed by its fingerprint, so a PIN reset that revokes devices does not.

const crypto = require('crypto');

const MARKER = 'dpwrap:v1';                 // what encrypted_value holds once wrapped (never decrypts)
const EPHEMERAL_TTL_MS = 15 * 60 * 1000;    // longer than an approval's life (5 min pending + 5 min approved)
const OAEP = { padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha1' };   // Android Keystore OAEP: MGF1 is SHA-1

module.exports = function registerCryptoDepth(deps) {
  const { app, db, rateLimitStandard, getBearerIdentity, gateSession, logSecurityEvent, blindkeyDecrypt, blindkeyEncrypt } = deps;

  db.exec(`CREATE TABLE IF NOT EXISTS device_wrap_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    did TEXT NOT NULL,
    device_id TEXT NOT NULL,
    public_key TEXT NOT NULL,               -- SPKI DER, base64
    fp TEXT NOT NULL UNIQUE,                -- sha256 of the SPKI, hex
    enrolled_at TEXT NOT NULL,
    revoked_at TEXT DEFAULT NULL
  )`);
  db.exec(`CREATE TABLE IF NOT EXISTS secret_wraps (
    secret_id INTEGER NOT NULL,
    key_fp TEXT NOT NULL,
    wrapped_dek TEXT NOT NULL,              -- the data key, RSA-OAEP to that wrap key, base64
    created_at TEXT NOT NULL,
    PRIMARY KEY (secret_id, key_fp)
  )`);
  for (const c of ['wrapped_value TEXT DEFAULT NULL', 'wrap_state TEXT DEFAULT NULL']) { try { db.exec('ALTER TABLE blindkey_secrets ADD COLUMN ' + c); } catch (_) {} }
  for (const c of ['eph_pub TEXT DEFAULT NULL', 'unwrap_blob TEXT DEFAULT NULL']) { try { db.exec('ALTER TABLE use_approvals ADD COLUMN ' + c); } catch (_) {} }

  const nowIso = () => new Date().toISOString();
  const fpOf = (spkiB64) => crypto.createHash('sha256').update(Buffer.from(spkiB64, 'base64')).digest('hex');
  const isWrapped = (secret) => Boolean(secret && secret.wrap_state === 'device');
  // What a wrap is FOR, sealed inside it with the data key: the phone shows "<name> (<ref>)" in its own prompt and,
  // after decrypting, refuses unless the wrap names that same secret — so a host serving a doctored page cannot get
  // secret B unwrapped under a prompt for secret A (#56 review H1).
  const bindingOf = (did, ref, name) => crypto.createHash('sha256').update(`dp-wrap:v1|${did}|${ref}|${name}`).digest();

  // ── one-use keys, in memory only ────────────────────────────────────────────────────────────────────────────────
  const eph = new Map();   // tag → { priv: KeyObject, pub: base64 SPKI, exp }
  function sweep() { const t = Date.now(); for (const [k, v] of eph) if (v.exp <= t) eph.delete(k); }
  const sweeper = setInterval(sweep, 60000); if (sweeper.unref) sweeper.unref();
  // Generated off the event loop (#56 review M3: RSA-2048 keygen blocked every other request).
  const genRsa = () => new Promise((ok, no) => crypto.generateKeyPair('rsa', { modulusLength: 2048 }, (e, pub, priv) => (e ? no(e) : ok({ pub, priv }))));
  async function ephemeralFor(tag) {
    sweep();
    const have = eph.get(tag); if (have) return have.pub;
    const { pub: publicKey, priv: privateKey } = await genRsa();
    const pub = publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
    if (!eph.has(tag)) eph.set(tag, { priv: privateKey, pub, exp: Date.now() + EPHEMERAL_TTL_MS });
    return eph.get(tag).pub;
  }
  const openSessions = (did) => { sweep(); let n = 0; for (const k of eph.keys()) if (k.startsWith(`s:${did}:`)) n++; return n; };
  const hasEphemeral = (tag) => { sweep(); return eph.has(tag); };
  function dropEphemeral(tag) { eph.delete(tag); }

  // The owner's wrap keys on phones that are linked now (an active device key D on the same device).
  function activeWrapKeys(did) {
    return db.prepare(`SELECT w.* FROM device_wrap_keys w WHERE w.did = ? AND w.revoked_at IS NULL
                       AND EXISTS (SELECT 1 FROM device_keys d WHERE d.did = w.did AND d.device_id = w.device_id AND d.kind = 'D' AND d.revoked_at IS NULL)`).all(did);
  }
  function wrapsOf(secretId) {
    const out = {};
    for (const r of db.prepare('SELECT key_fp, wrapped_dek FROM secret_wraps WHERE secret_id = ?').all(secretId)) out[r.key_fp] = r.wrapped_dek;
    return out;
  }

  // Wrap one secret to the owner's phones. { ok, wrapped_for } or { ok:false, error }.
  function wrapSecret(secret) {
    if (isWrapped(secret)) return { ok: true, already: true, wrapped_for: Object.keys(wrapsOf(secret.id)).length };
    const keys = activeWrapKeys(secret.did);
    if (!keys.length) return { ok: false, error: 'no linked phone with a wrap key (DemiPass app 1.5+): this secret is protected by approval only, and the host can still read it' };
    let value;
    try { value = blindkeyDecrypt(secret.encrypted_value); } catch (_) { return { ok: false, error: 'could not read the value to wrap it' }; }
    const dek = crypto.randomBytes(32), iv = crypto.randomBytes(12);
    try {
      const c = crypto.createCipheriv('aes-256-gcm', dek, iv);
      const ct = Buffer.concat([c.update(value, 'utf8'), c.final()]);
      const blob = ['v1', iv.toString('base64'), c.getAuthTag().toString('base64'), ct.toString('base64')].join(':');
      const sealedKey = Buffer.concat([dek, bindingOf(secret.did, secret.ref_code, secret.name)]);
      const wraps = keys.map(k => ({ fp: k.fp, dek: crypto.publicEncrypt({ key: Buffer.from(k.public_key, 'base64'), format: 'der', type: 'spki', ...OAEP }, sealedKey).toString('base64') }));
      sealedKey.fill(0);
      db.transaction(() => {
        const n = db.prepare("UPDATE blindkey_secrets SET wrapped_value = ?, wrap_state = 'device', encrypted_value = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND wrap_state IS NULL").run(blob, MARKER, secret.id).changes;
        if (n !== 1) throw new Error('the secret changed meanwhile');
        const ins = db.prepare('INSERT OR REPLACE INTO secret_wraps (secret_id, key_fp, wrapped_dek, created_at) VALUES (?, ?, ?, ?)');
        for (const w of wraps) ins.run(secret.id, w.fp, w.dek, nowIso());
      })();
    } finally { dek.fill(0); value = null; }
    // The pre-wrap host-key ciphertext must not linger in the WAL (#56 review L2). Backups made before wrapping still
    // hold it: wrapping protects from this point on (docs/trust-model.md).
    try { db.pragma('wal_checkpoint(TRUNCATE)'); } catch (_) {}
    logSecurityEvent('secret_wrapped', 'info', { caller_did: secret.did, capability: 'wrap', target: secret.name, context: { phones: keys.length } });
    return { ok: true, wrapped_for: keys.length };
  }

  // The data key, re-encrypted by the phone to the one-use key `tag` → the value. One use: the key is dropped.
  function recover(secret, tag, rewrappedB64) {
    const e = eph.get(tag);
    if (!e) throw Object.assign(new Error('the one-use key for this approval is gone (server restart or expiry) — ask again'), { status: 409 });
    eph.delete(tag);
    let dek;
    try { dek = crypto.privateDecrypt({ key: e.priv, ...OAEP }, Buffer.from(String(rewrappedB64 || ''), 'base64')); }
    catch (_) { throw Object.assign(new Error('the phone\'s unwrap did not open (a different phone, or a damaged reply) — ask again'), { status: 409 }); }
    try {
      const [v, ivB, tagB, ctB] = String(secret.wrapped_value || '').split(':');
      if (v !== 'v1') throw new Error('unknown wrap format');
      const d = crypto.createDecipheriv('aes-256-gcm', dek, Buffer.from(ivB, 'base64'));
      d.setAuthTag(Buffer.from(tagB, 'base64'));
      return Buffer.concat([d.update(Buffer.from(ctB, 'base64')), d.final()]).toString('utf8');
    } catch (_) { throw Object.assign(new Error('the unwrapped key does not open this secret — ask again'), { status: 409 }); }
    finally { dek.fill(0); }
  }

  // The value for a /use that an approval allowed: wrapped → from the phone's unwrap stored on the approval; otherwise
  // the host key, as before. The unwrap is cleared from the row whatever happens.
  function plaintextFor(secret, approvalId) {
    if (!isWrapped(secret)) return blindkeyDecrypt(secret.encrypted_value);
    const row = approvalId ? db.prepare('SELECT unwrap_blob FROM use_approvals WHERE id = ? AND secret_id = ?').get(Number(approvalId), secret.id) : null;
    if (approvalId) db.prepare('UPDATE use_approvals SET unwrap_blob = NULL WHERE id = ?').run(Number(approvalId));
    if (!row || !row.unwrap_blob) throw Object.assign(new Error('this secret is wrapped to its owner\'s phone: it is used only through an approval made in the app on that phone'), { status: 409 });
    return recover(secret, 'a:' + Number(approvalId), row.unwrap_blob);
  }

  // ── hooks for use_approvals.js ──────────────────────────────────────────────────────────────────────────────────
  function onRequestCreated(row, secret) {
    if (!isWrapped(secret)) return;
    ephemeralFor('a:' + row.id).then(pub => db.prepare('UPDATE use_approvals SET eph_pub = ? WHERE id = ?').run(pub, row.id))
      .catch(e => console.error('[crypto-depth] one-use key:', e.message));
  }
  // What the owner's phone needs to approve: the one-use key and the wraps (it uses the one for its own wrap key).
  function approvalView(row, secret) {
    if (!isWrapped(secret) || row.status !== 'pending' || !row.eph_pub) return null;
    return { eph_pub: row.eph_pub, wraps: wrapsOf(secret.id), live: hasEphemeral('a:' + row.id), did: secret.did, ref: secret.ref_code, name: secret.name };
  }
  // On Approve: a wrapped secret needs the phone's unwrap with it. Returns null or { status, body }.
  function approveRefusal(row, secret, body) {
    if (!isWrapped(secret)) return null;
    if (!hasEphemeral('a:' + row.id)) return { status: 409, body: { error: 'this request outlived a server restart; deny it and let the agent ask again', ask_again: true } };
    const u = (body || {}).unwrap;
    if (typeof u !== 'string' || !/^[A-Za-z0-9+/=]{100,1024}$/.test(u)) return { status: 428, body: { error: 'this secret is wrapped to your phone: approve it in the DemiPass app on that phone (it unwraps the key)', unwrap_required: true } };
    return null;
  }
  function storeUnwrap(rowId, body) { db.prepare('UPDATE use_approvals SET unwrap_blob = ? WHERE id = ?').run(String(body.unwrap), rowId); }

  // ── routes ──────────────────────────────────────────────────────────────────────────────────────────────────────
  function ownerAuth(req, res) {
    const auth = getBearerIdentity(req);
    if (!auth.ok) { res.status(auth.status || 401).json({ error: auth.error }); return null; }
    if (auth.silicon || (auth.decoded && (auth.decoded.wrk || auth.decoded.auth_method === 'fleet_owner_mint'))) { res.status(403).json({ error: 'only the owner, in their own session' }); return null; }
    if (!gateSession(auth)) { res.status(403).json({ error: 'sign in again' }); return null; }
    return auth;
  }
  const dk = () => deps.devices && deps.devices();
  function ownSecret(did, pick) {
    if (!pick || typeof pick !== 'string' || pick.length > 100) return null;
    return db.prepare("SELECT * FROM blindkey_secrets WHERE did = ? AND (ref_code = ? OR name = ?) AND status = 'active' ORDER BY version DESC LIMIT 1").get(did, pick, pick) || null;
  }

  // POST /api/identity/device/wrap-key {device_id, key_w} — the phone registers its wrap key; its device key D signs it
  // (428 challenge, bind = the key's fingerprint). The same key re-registered after re-linking keeps its wraps.
  app.post('/api/identity/device/wrap-key', rateLimitStandard, (req, res) => {
    const auth = ownerAuth(req, res); if (!auth) return;
    const { device_id, key_w } = req.body || {};
    if (typeof device_id !== 'string' || !/^[A-Za-z0-9_-]{8,64}$/.test(device_id)) return res.status(400).json({ error: 'device_id' });
    if (typeof key_w !== 'string' || key_w.length > 1200) return res.status(400).json({ error: 'key_w: the wrap key, SPKI DER base64' });
    let k;
    try { k = crypto.createPublicKey({ key: Buffer.from(key_w, 'base64'), format: 'der', type: 'spki' }); } catch (_) { return res.status(400).json({ error: 'key_w is not a public key' }); }
    if (k.asymmetricKeyType !== 'rsa' || (k.asymmetricKeyDetails && k.asymmetricKeyDetails.modulusLength < 2048)) return res.status(400).json({ error: 'key_w: RSA, 2048 bits or more' });
    if (!db.prepare("SELECT 1 FROM device_keys WHERE did = ? AND device_id = ? AND kind = 'D' AND revoked_at IS NULL").get(auth.did, device_id)) return res.status(404).json({ error: 'that phone is not linked to this wallet' });
    const fp = fpOf(key_w);
    const d = dk();
    const refused = d ? d.approvalRefusal(auth, 'wrap-key', 0, fp, req.body) : { status: 503, body: { error: 'device keys unavailable' } };
    if (refused) return res.status(refused.status).json(refused.body);
    const other = db.prepare('SELECT did FROM device_wrap_keys WHERE fp = ?').get(fp);
    if (other && other.did !== auth.did) return res.status(409).json({ error: 'that wrap key belongs to another wallet' });
    db.prepare(`INSERT INTO device_wrap_keys (did, device_id, public_key, fp, enrolled_at) VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(fp) DO UPDATE SET device_id = excluded.device_id, revoked_at = NULL`).run(auth.did, device_id, key_w, fp, nowIso());
    logSecurityEvent('wrap_key_registered', 'info', { caller_did: auth.did, capability: 'wrap-key', context: { device_id, fp: fp.slice(0, 16) } });
    res.json({ ok: true, fp, wrapped_secrets: db.prepare('SELECT COUNT(*) AS n FROM secret_wraps WHERE key_fp = ?').get(fp).n });
  });

  // GET /api/blindkey/wrap — the owner's wrap keys, and which elevated/critical secrets are wrapped or not yet.
  app.get('/api/blindkey/wrap', rateLimitStandard, (req, res) => {
    const auth = getBearerIdentity(req); if (!auth.ok) return res.status(auth.status || 401).json({ error: auth.error });
    const keys = activeWrapKeys(auth.did).map(k => ({ device_id: k.device_id, fp: k.fp.slice(0, 16), enrolled_at: k.enrolled_at,
      wrapped_secrets: db.prepare('SELECT COUNT(*) AS n FROM secret_wraps WHERE key_fp = ?').get(k.fp).n }));
    const secrets = db.prepare("SELECT id, name, ref_code, security_depth, wrap_state FROM blindkey_secrets WHERE did = ? AND status = 'active' AND security_depth IN ('elevated','critical')").all(auth.did)
      .map(s => ({ name: s.name, ref: s.ref_code, depth: s.security_depth, wrapped: s.wrap_state === 'device', phones: s.wrap_state === 'device' ? db.prepare('SELECT COUNT(*) AS n FROM secret_wraps WHERE secret_id = ?').get(s.id).n : 0 }));
    res.json({ ok: true, keys, secrets, note: 'a wrapped secret can be read only through an approval on a phone that holds its wrap; losing every such phone loses the secret' });
  });

  // POST /api/blindkey/wrap {secret} — wrap an elevated/critical secret now (e.g. one raised before this phone could).
  // No PIN: it only takes the host's ability to read it away.
  app.post('/api/blindkey/wrap', rateLimitStandard, (req, res) => {
    const auth = ownerAuth(req, res); if (!auth) return;
    const s = ownSecret(auth.did, (req.body || {}).secret);
    if (!s) return res.status(404).json({ error: 'secret: name or ref of one of your active secrets' });
    if (!['elevated', 'critical'].includes(s.security_depth)) return res.status(409).json({ error: 'only elevated or critical secrets are wrapped — raise its depth first' });
    const r = wrapSecret(s);
    if (!r.ok) return res.status(409).json({ error: r.error });
    res.json({ ok: true, name: s.name, wrapped_for: r.wrapped_for, already: Boolean(r.already) });
  });

  // POST /api/blindkey/wrap/unwrap-session {secret} — the owner's phone asks to unwrap one (to lower its depth): a
  // one-use key for it, and the wraps. Then the depth change carries {unwrap_session, unwrap}.
  app.post('/api/blindkey/wrap/unwrap-session', rateLimitStandard, async (req, res) => {
    const auth = ownerAuth(req, res); if (!auth) return;
    const s = ownSecret(auth.did, (req.body || {}).secret);
    if (!s || !isWrapped(s)) return res.status(404).json({ error: 'no wrapped secret by that name' });
    if (openSessions(auth.did) >= 3) return res.status(429).json({ error: 'at most 3 unwrap sessions open at once — finish or wait for one (15 min)' });
    const sid = crypto.randomBytes(12).toString('hex');
    try {
      const pub = await ephemeralFor(`s:${auth.did}:${s.id}:${sid}`);
      res.json({ ok: true, unwrap_session: sid, eph_pub: pub, wraps: wrapsOf(s.id), did: s.did, ref: s.ref_code, name: s.name });
    } catch (e) { res.status(503).json({ error: 'could not start an unwrap session; try again' }); }
  });
  // The value of a wrapped secret, for the owner lowering it (gate-policy calls this). Throws {status} on failure.
  function unwrapForOwner(did, secret, body) {
    const sid = String((body || {}).unwrap_session || '');
    if (!/^[0-9a-f]{24}$/.test(sid) || typeof (body || {}).unwrap !== 'string') throw Object.assign(new Error('lowering a wrapped secret needs your phone to unwrap it (unwrap_session + unwrap)'), { status: 428, unwrap_required: true });
    return recover(secret, `s:${did}:${secret.id}:${sid}`, body.unwrap);
  }
  // Re-expose to the host: the value back under the host key, the wraps gone.
  function unwrapToHost(secret, value) {
    db.transaction(() => {
      db.prepare('UPDATE blindkey_secrets SET encrypted_value = ?, wrapped_value = NULL, wrap_state = NULL, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(blindkeyEncrypt(value), secret.id);
      db.prepare('DELETE FROM secret_wraps WHERE secret_id = ?').run(secret.id);
    })();
    logSecurityEvent('secret_unwrapped', 'warn', { caller_did: secret.did, capability: 'unwrap', target: secret.name });
  }

  return { MARKER, bindingOf, isWrapped, wrapSecret, plaintextFor, onRequestCreated, approvalView, approveRefusal, storeUnwrap, dropEphemeral,
           unwrapForOwner, unwrapToHost, activeWrapKeys, _hasEphemeral: hasEphemeral };
};
