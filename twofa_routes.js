'use strict';
// ── Vault second factor: enrollment, status, email codes, trusted devices.
// The login gate itself lives in /api/identity/auth-fingerprint (server.js) and the
// password-reset gate in /api/identity/reset-password; both call twofa.gate().

module.exports = function registerTwofaRoutes({ app, db, identity, twofa, createEmailTransport, rateLimitStandard, rateLimitStrict, verifyWalletPassword, log }) {
  const say = log || ((...a) => console.log('[2fa]', ...a));
  const decryptSecret = s => identity.decryptPrivateKey(s).toString('utf8');
  const encryptSecret = s => identity.encryptPrivateKey(Buffer.from(String(s), 'utf8'));

  function bearer(req, res, minScope = 'read') {
    const h = req.headers.authorization || '';
    const token = h.startsWith('Bearer ') ? h.slice(7) : null;
    if (!token) { res.status(401).json({ error: 'Bearer token required' }); return null; }
    const v = identity.verifyTokenStandalone(token);
    if (!v.valid) { res.status(401).json({ error: v.error }); return null; }
    if (!identity.scopeAtLeast(v.decoded.scope || 'read', minScope)) { res.status(403).json({ error: `scope '${v.decoded.scope}' insufficient`, required_scope: minScope }); return null; }
    const wallet = db.prepare('SELECT * FROM identity_wallets WHERE did = ?').get(v.decoded.sub);
    if (!wallet) { res.status(404).json({ error: 'identity not found' }); return null; }
    return { did: v.decoded.sub, scope: v.decoded.scope, decoded: v.decoded, wallet };
  }
  function maskEmail(e) {
    if (!e || !e.includes('@')) return null;
    const [u, d] = e.split('@');
    return (u.length <= 2 ? u[0] + '•' : u.slice(0, 2) + '•••') + '@' + d;
  }
  function recoveryLeft(w) { try { return JSON.parse(w.recovery_codes || '[]').length; } catch (_) { return 0; } }
  function status(w) {
    return {
      enabled: !!w.twofa_enabled, methods: w.twofa_enabled ? twofa.methodsFor(w) : [],
      totp: !!w.totp_secret && !!w.totp_confirmed_at, totp_pending: !!w.totp_secret && !w.totp_confirmed_at,
      recovery_codes_left: recoveryLeft(w), enabled_at: w.twofa_enabled_at || null,
      recovery_email_set: !!w.recovery_email, email_hint: maskEmail(w.recovery_email || w.email),
      trusted_devices: twofa.listDevices(db, w.did),
    };
  }
  async function sendCode({ to, code }) {
    const t = createEmailTransport();
    await t.sendMail({ from: 'DemiPass <noreply@dustforge.com>', to, subject: `${code} is your DemiPass sign-in code`,
      text: `Your DemiPass sign-in code is ${code}. It expires in ${twofa.EMAIL_CODE_TTL_MIN} minutes.\n\nIf you did not try to sign in, change your password now: https://demipass.com/reset-password.html` });
  }

  app.get('/api/identity/2fa/status', rateLimitStandard, (req, res) => {
    const a = bearer(req, res); if (!a) return;
    res.json({ ok: true, ...status(a.wallet) });
  });

  // Step 1: mint a secret (stored encrypted, not yet enabled). Step 2 confirms with a live code.
  app.post('/api/identity/2fa/totp/setup', rateLimitStandard, (req, res) => {
    const a = bearer(req, res, 'transact'); if (!a) return;
    if (a.wallet.twofa_enabled && a.wallet.totp_confirmed_at) return res.status(409).json({ error: 'authenticator already enabled; disable it first to re-enroll' });
    const secret = twofa.generateSecret();
    db.prepare("UPDATE identity_wallets SET totp_secret = ?, totp_confirmed_at = NULL, totp_last_step = 0 WHERE did = ?").run(encryptSecret(secret), a.did);
    res.json({ ok: true, secret, otpauth_uri: twofa.otpauthUri({ account: a.wallet.username, secret }), issuer: 'DemiPass', account: a.wallet.username,
               note: 'Add this to an authenticator app (manual key or the otpauth link), then confirm with a current code.' });
  });

  app.post('/api/identity/2fa/totp/confirm', rateLimitStandard, (req, res) => {
    const a = bearer(req, res, 'transact'); if (!a) return;
    const { code } = req.body || {};
    if (!a.wallet.totp_secret) return res.status(400).json({ error: 'run setup first' });
    const v = twofa.verifyTotp(decryptSecret(a.wallet.totp_secret), code, { lastStep: a.wallet.totp_last_step || 0 });
    if (!v.ok) return res.status(401).json({ error: v.error });
    const { codes, hashes } = twofa.generateRecoveryCodes();
    db.prepare("UPDATE identity_wallets SET twofa_enabled = 1, totp_confirmed_at = datetime('now'), totp_last_step = ?, recovery_codes = ?, twofa_enabled_at = COALESCE(twofa_enabled_at, datetime('now')) WHERE did = ?")
      .run(v.step, JSON.stringify(hashes), a.did);
    say(`enabled for ${a.wallet.username}`);
    res.json({ ok: true, enabled: true, recovery_codes: codes, note: 'Store these recovery codes now; they are shown once. Each works one time if the authenticator is lost.' });
  });

  // Turning it off or regenerating recovery codes needs a live factor (not a trusted device).
  function liveFactor(req, res, a) {
    const b = req.body || {};
    const g = twofa.gate(db, a.wallet, { otp: b.otp, email_code: b.email_code, recovery_code: b.recovery_code }, { decryptSecret });
    if (!g.ok) { res.status(401).json({ error: '2fa_required', detail: g.error, methods: g.methods }); return null; }
    return g;
  }
  app.post('/api/identity/2fa/disable', rateLimitStandard, (req, res) => {
    const a = bearer(req, res, 'transact'); if (!a) return;
    if (!a.wallet.twofa_enabled) return res.json({ ok: true, enabled: false });
    if (!liveFactor(req, res, a)) return;
    db.prepare("UPDATE identity_wallets SET twofa_enabled = 0, totp_secret = '', totp_confirmed_at = NULL, totp_last_step = 0, recovery_codes = '[]' WHERE did = ?").run(a.did);
    twofa.revokeAllDevices(db, a.did);
    say(`disabled for ${a.wallet.username}`);
    res.json({ ok: true, enabled: false });
  });
  app.post('/api/identity/2fa/recovery-codes', rateLimitStandard, (req, res) => {
    const a = bearer(req, res, 'transact'); if (!a) return;
    if (!a.wallet.twofa_enabled) return res.status(400).json({ error: 'two-factor is not enabled' });
    if (!liveFactor(req, res, a)) return;
    const { codes, hashes } = twofa.generateRecoveryCodes();
    db.prepare('UPDATE identity_wallets SET recovery_codes = ? WHERE did = ?').run(JSON.stringify(hashes), a.did);
    res.json({ ok: true, recovery_codes: codes });
  });

  // Fallback factor: a code to the recovery email. Needs the password first so it cannot be used to spam a mailbox.
  app.post('/api/identity/2fa/email/send', rateLimitStrict, async (req, res) => {
    const { username, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: 'username and password required' });
    const wallet = db.prepare('SELECT * FROM identity_wallets WHERE username = ?').get(String(username));
    if (!wallet) return res.status(401).json({ error: 'invalid username or password' });
    const pw = await verifyWalletPassword(wallet, String(password));
    if (pw === null) return res.status(503).json({ error: 'password verification temporarily unavailable' });
    if (!pw) return res.status(401).json({ error: 'invalid username or password' });
    if (!wallet.twofa_enabled) return res.status(400).json({ error: 'two-factor is not enabled on this account' });
    const to = wallet.recovery_email || wallet.email;
    const { code, expiresAt } = twofa.issueEmailCode(db, wallet.did);
    try { await sendCode({ to, code }); } catch (e) { say(`email code to ${to} failed: ${e.message}`); return res.status(502).json({ error: 'could not send the email code; use your authenticator or a recovery code' }); }
    res.json({ ok: true, sent_to: maskEmail(to), expires_at: expiresAt });
  });

  app.get('/api/identity/2fa/devices', rateLimitStandard, (req, res) => {
    const a = bearer(req, res); if (!a) return;
    res.json({ ok: true, devices: twofa.listDevices(db, a.did) });
  });
  app.delete('/api/identity/2fa/devices/:id', rateLimitStandard, (req, res) => {
    const a = bearer(req, res, 'transact'); if (!a) return;
    const ok = twofa.revokeDevice(db, a.did, Number(req.params.id));
    res.json({ ok, revoked: ok });
  });

  return { maskEmail, decryptSecret };
};
