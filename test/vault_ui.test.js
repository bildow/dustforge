'use strict';
// node --test test/vault_ui.test.js — the phone vault's sign-in → PIN gate flow, run as the REAL page script
// (public/vault-mobile.html's inline <script>) inside a vm with a fake DOM, storage and fetch. No browser.
// Covers the mandatory-PIN entry gate: it fails closed when the PIN status is unknown, blocks until a PIN is
// set, and sign-out ends everything (sheets, typed password, pending promises, in-flight continuations). Then the
// unlock flow (codes first, the PIN last with the server's intent, one check per tap, Escape = cancel), the
// background refresh, the sign-out sweep, and inline handlers that stay inert with hostile secret names.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const vm = require('vm');
const path = require('path');

const html = fs.readFileSync(path.join(__dirname, '..', 'public', 'vault-mobile.html'), 'utf8');
const script = html.slice(html.indexOf('<script>') + '<script>'.length, html.lastIndexOf('</script>'));
const tick = () => new Promise(r => setTimeout(r, 0));
const settle = async (n = 6) => { for (let i = 0; i < n; i++) await tick(); };

// A page instance: fake document (elements materialise on first lookup), localStorage, fetch router.
function page({ storage = {}, routes, abortable = false, coldLock = false } = {}) {
  const els = new Map();
  const el = (id) => {
    if (!els.has(id)) {
      const classes = new Set(id.startsWith('modal-') ? ['modal-bg'] : []);
      els.set(id, {
        id, style: {}, value: '', textContent: '', innerHTML: '', dataset: {},
        get className() { return [...classes].join(' '); }, set className(v) { classes.clear(); for (const c of String(v).split(/\s+/).filter(Boolean)) classes.add(c); },
        classList: { add: c => classes.add(c), remove: c => classes.delete(c), contains: c => classes.has(c), toggle: (c, f) => (f ? classes.add(c) : classes.delete(c)) },
        addEventListener() {}, focus() {}, scrollIntoView() {}, querySelectorAll: () => [],
      });
    }
    return els.get(id);
  };
  const store = new Map(Object.entries(storage));
  const calls = [], intervals = [], listeners = {}, qsa = {}, timers = [];
  const ctx = {
    console, clearTimeout,
    setTimeout: (f, ms, ...a) => (ms > 5000 ? (timers.push(f), 0) : setTimeout(f, ms, ...a)),   // long timers fire only when a test runs them
    setInterval: (f) => { intervals.push(f); return 0; }, clearInterval() {},
    alert: () => {}, confirm: () => true, prompt: () => null,
    localStorage: { getItem: k => (store.has(k) ? store.get(k) : null), setItem: (k, v) => store.set(k, String(v)), removeItem: k => store.delete(k) },
    document: {
      getElementById: el,
      querySelectorAll: sel => (sel === '.modal-bg' ? [...els.values()].filter(e => e.id.startsWith('modal-')) : (qsa[sel] || [])),
      addEventListener: (type, f) => { (listeners[type] = listeners[type] || []).push(f); }, createElement: () => ({ set textContent(v) { this.innerHTML = String(v).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]); }, innerHTML: '' }),
    },
    location: { href: '' }, navigator: {},
    fetch: async (url, o = {}) => {
      const p = url.replace(/^https?:\/\/[^/]+/, '');
      const body = o.body ? JSON.parse(o.body) : null;
      calls.push({ method: o.method || 'GET', path: p, body, auth: (o.headers || {}).Authorization || null });
      const routed = routes(p, body, o);
      const r = o.signal ? await new Promise((resolve, reject) => {   // a fetch the page aborts rejects like a browser's
        const abort = () => reject(Object.assign(new Error('The operation was aborted.'), { name: 'AbortError' }));
        if (o.signal.aborted) abort(); else o.signal.addEventListener('abort', abort);
        Promise.resolve(routed).then(resolve, reject);
      }) : await routed;
      // cut: the connection dropped mid-reply, so the body is not JSON (a phone switching Wi-Fi ↔ mobile data)
      return { status: r.status || 200, json: async () => { if (r.cut) throw new SyntaxError('Unexpected end of JSON input'); return r.json === undefined ? {} : r.json; } };
    },
  };
  if (abortable) ctx.AbortController = AbortController;   // an older WebView: AbortController, no AbortSignal.timeout
  vm.createContext(ctx);
  // Most tests start from a stored session and are about what comes after the lock: they open as if unlocked. The lock
  // tests pass coldLock: true and get the page's own rule (every start with a stored session is locked).
  const script2 = coldLock ? script : script.replace('function startsLocked(freshLogin){ return !freshLogin; }', 'function startsLocked(freshLogin){ return false; }');
  if (!coldLock && script2 === script) throw new Error('startsLocked not found in the page script');
  vm.runInContext(script2, ctx, { filename: 'vault-mobile.inline.js' });
  // Vault contents are not under test here (the real loader stays reachable for the rendering test).
  ctx.__realLoadVault = ctx.loadVault;
  ctx.loadVault = async () => { ctx.__loads = (ctx.__loads || 0) + 1; };
  ctx.loadSiliconAgents = () => {};
  ctx.loadSmsStatus = async () => {};
  const key = k => { for (const f of listeners.keydown || []) f({ key: k }); };
  const fire = type => { for (const f of listeners[type] || []) f({}); };
  return { ctx, el, calls, store, intervals, qsa, key, timers, fire, shown: id => el(id).classList.contains('show'), appOpen: () => el('app').style.display === 'block', authOpen: () => el('auth').style.display === 'flex' };
}
const signedIn = { dp_token: 'fixture.token.a', dp_did: 'did:key:zFixture', dp_user: 'fixture', dp_token_at: String(Date.now()) };
const trustOk = { recovery_email: 'fixture@example.invalid' };

test('PIN status unreachable → vault stays closed, error sheet with retry', async () => {
  let statusFails = true;
  const pg = page({ storage: signedIn, routes: async (p) => {
    if (p.startsWith('/api/identity/trust')) return { json: trustOk };
    if (p === '/api/identity/gate/status') { if (statusFails) throw new Error('network down'); return { json: { pin_set: true } }; }
    throw new Error('unexpected ' + p);
  } });
  await settle();
  assert.equal(pg.appOpen(), false, 'app hidden');
  assert.equal(pg.shown('modal-pin-error'), true, 'error sheet shown');
  assert.equal(pg.ctx.__loads || 0, 0, 'vault not loaded');
  assert.match(pg.el('pin-error-why').textContent, /network down/);
  statusFails = false;
  pg.ctx.retryPinCheck();
  await settle();
  assert.equal(pg.shown('modal-pin-error'), false);
  assert.equal(pg.appOpen(), true, 'open after a successful retry');
  assert.equal(pg.ctx.__loads, 1);
});

test('PIN status without a boolean pin_set → closed, no setup, no vault', async () => {
  for (const reply of [{}, { pin_set: 'yes' }, null]) {
    const pg = page({ storage: signedIn, routes: async (p) => {
      if (p.startsWith('/api/identity/trust')) return { json: trustOk };
      if (p === '/api/identity/gate/status') return { json: reply };
      throw new Error('unexpected ' + p);
    } });
    await settle();
    assert.equal(pg.appOpen(), false, JSON.stringify(reply));
    assert.equal(pg.shown('modal-pin-error'), true);
    assert.equal(pg.shown('modal-pin-setup'), false);
    assert.equal(pg.ctx.__loads || 0, 0);
  }
});

test('PIN set → vault opens, no sheets', async () => {
  const pg = page({ storage: signedIn, routes: async (p) => {
    if (p.startsWith('/api/identity/trust')) return { json: trustOk };
    if (p === '/api/identity/gate/status') return { json: { pin_set: true } };
    throw new Error('unexpected ' + p);
  } });
  await settle();
  assert.equal(pg.appOpen(), true);
  assert.equal(pg.shown('modal-pin-setup'), false);
  assert.equal(pg.shown('modal-pin-error'), false);
  assert.equal(pg.ctx.__loads, 1);
});

// Signs in through the real login(): the typed password is held in the page's own `let loginPw` for the
// setup sheet. (A `let` inside the vm script is not a context property, so the tests only ever observe it
// through page functions, never by reaching in.)
async function signIn(pg) {
  pg.el('auth-user').value = 'fixture'; pg.el('auth-pass').value = 'pw-typed-at-login';
  await pg.ctx.login();
  await settle();
}
const loginRoute = (p) => (p === '/api/identity/auth-fingerprint' ? { json: { token: 'fixture.token.a', did: 'did:key:zFixture' } } : null);

test('no PIN yet → blocking setup sheet; vault opens only after the PIN is saved', async () => {
  let pinSet = false;
  const pg = page({ routes: async (p, body) => {
    if (loginRoute(p)) return loginRoute(p);
    if (p.startsWith('/api/identity/trust')) return { json: trustOk };
    if (p === '/api/identity/gate/status') return { json: { pin_set: pinSet } };
    if (p === '/api/identity/pin') { assert.equal(body.pin, '4821'); assert.equal(body.password, 'pw-typed-at-login', 'reuses the password typed at sign-in'); pinSet = true; return { json: { ok: true, pin_set: true } }; }
    throw new Error('unexpected ' + p);
  } });
  await signIn(pg);
  assert.equal(pg.el('auth-pass').value, '', 'password field cleared at sign-in');
  assert.equal(pg.shown('modal-pin-setup'), true, 'setup sheet shown');
  assert.equal(pg.el('pin-setup-pw-row').style.display, 'none', 'password known from sign-in: not asked twice');
  assert.equal(pg.appOpen(), false, 'vault closed behind it');
  // Mismatched PINs never leave the page
  pg.el('pin-new').value = '4821'; pg.el('pin-confirm').value = '4822';
  await pg.ctx.savePinSetup();
  assert.match(pg.el('pin-setup-msg').textContent, /differ/);
  assert.equal(pg.calls.some(c => c.path === '/api/identity/pin'), false);
  pg.el('pin-confirm').value = '4821';
  await pg.ctx.savePinSetup();
  await settle();
  assert.equal(pg.shown('modal-pin-setup'), false);
  assert.equal(pg.appOpen(), true, 'vault open once the PIN exists');
  assert.equal(pg.el('pin-new').value, '');
  assert.equal(pg.ctx.__loads, 1);
  // The typed password is gone: a later setup sheet would have to ask for it.
  pg.ctx.requirePinSetup();
  assert.equal(pg.el('pin-setup-pw-row').style.display, 'block', 'sign-in password forgotten after setup');
  pg.ctx.logout();
});

test('sign out during PIN setup closes the sheet, forgets the password, settles the flow, keeps the vault shut', async () => {
  const pg = page({ routes: async (p) => {
    if (loginRoute(p)) return loginRoute(p);
    if (p.startsWith('/api/identity/trust')) return { json: trustOk };
    if (p === '/api/identity/gate/status') return { json: { pin_set: false } };
    throw new Error('unexpected ' + p);
  } });
  let settled = 'pending';
  const realRequire = pg.ctx.requirePinSetup;
  pg.ctx.requirePinSetup = () => { const pr = realRequire(); pr.then(v => { settled = v; }); return pr; };   // observe the page's own promise
  await signIn(pg);
  assert.equal(pg.shown('modal-pin-setup'), true);
  assert.equal(pg.el('pin-setup-pw-row').style.display, 'none', 'password held for the setup');
  pg.el('pin-new').value = '1111';
  pg.ctx.logout();
  await settle();
  assert.equal(pg.shown('modal-pin-setup'), false, 'sheet closed');
  assert.equal(pg.el('pin-new').value, '', 'typed digits cleared');
  assert.equal(settled, false, 'pending setup resolved false');
  assert.equal(pg.authOpen(), true);
  assert.equal(pg.appOpen(), false);
  assert.equal(pg.ctx.__loads || 0, 0, 'vault never loaded');
  assert.equal(pg.store.has('dp_token'), false, 'token gone');
  // the password typed at sign-in is forgotten: a new setup sheet has to ask for it
  realRequire();
  assert.equal(pg.el('pin-setup-pw-row').style.display, 'block', 'password cleared by sign-out');
  pg.ctx.logout();
});

test('sign out while the PIN status is still loading: the late reply cannot reopen the vault', async () => {
  let release;
  const pg = page({ storage: signedIn, routes: async (p) => {
    if (p.startsWith('/api/identity/trust')) return { json: trustOk };
    if (p === '/api/identity/gate/status') return new Promise(r => { release = () => r({ json: { pin_set: true } }); });
    throw new Error('unexpected ' + p);
  } });
  await settle();
  assert.ok(release, 'status request in flight');
  pg.ctx.logout();
  release();
  await settle();
  assert.equal(pg.appOpen(), false, 'stale continuation stopped');
  assert.equal(pg.authOpen(), true);
  assert.equal(pg.ctx.__loads || 0, 0);
  assert.equal(pg.shown('modal-pin-error'), false);
});

test('401 on the PIN status = session over: back to sign-in, no error sheet', async () => {
  const pg = page({ storage: signedIn, routes: async (p) => {
    if (p.startsWith('/api/identity/trust')) return { json: trustOk };
    if (p === '/api/identity/gate/status') return { status: 401, json: { error: 'expired' } };
    throw new Error('unexpected ' + p);
  } });
  await settle();
  assert.equal(pg.appOpen(), false);
  assert.equal(pg.authOpen(), true);
  assert.equal(pg.shown('modal-pin-error'), false);
  assert.match(pg.el('auth-err').textContent, /expired/i);
});

test('lowering a credential\'s depth walks the PIN gate; wrong PIN shows tries left and keeps the sheet', async () => {
  let pinFresh = false, details = 0;
  const pg = page({ storage: signedIn, routes: async (p, body) => {
    if (p.startsWith('/api/identity/trust')) return { json: trustOk };
    if (p === '/api/identity/gate/status') return { json: { pin_set: true } };
    if (p === '/api/demipass/gate-policy') {
      if (body.security_depth === 'standard' && !pinFresh) return { status: 403, json: { error: 'lowering needs pin', missing: ['pin'], required: ['pin'], weakens: ['reveal'], intent: 'gate-policy:7' } };
      pinFresh = false; return { json: { ok: true } };
    }
    if (p === '/api/identity/gate/verify') {
      assert.equal(body.intent, 'gate-policy:7', 'the PIN check names the action the 403 asked for');
      if (body.pin === '2468') { pinFresh = true; return { json: { ok: true } }; } return { status: 403, json: { error: 'incorrect PIN (4 tries left)', attempts_left: 4 } };
    }
    throw new Error('unexpected ' + p);
  } });
  await settle();
  pg.ctx.showDetail = () => { details++; };
  const done = pg.ctx.setDepth('sightless', 'standard');
  await settle();
  assert.equal(pg.shown('modal-pin'), true, 'PIN sheet opened by the 403');
  assert.match(pg.el('pin-unlock-what').textContent, /Lowering the protection on sightless/);
  pg.el('pin-unlock').value = '0000';
  await pg.ctx.submitPin();
  assert.equal(pg.shown('modal-pin'), true, 'still open after a wrong PIN');
  assert.match(pg.el('pin-unlock-msg').textContent, /4 tries left/);
  pg.el('pin-unlock').value = '2468';
  await pg.ctx.submitPin();
  await done;
  assert.equal(pg.shown('modal-pin'), false);
  assert.equal(details, 1, 'detail view refreshed after the change');
  const policyCalls = pg.calls.filter(c => c.path === '/api/demipass/gate-policy');
  assert.equal(policyCalls.length, 2, 'refused once, retried once after the PIN');
});

// ── replies from an ended session ──────────────────────────────────────────────────────────────────────
// Account-scoped login route: tokens and DIDs differ per username, so A's and B's sessions are distinct.
const loginFor = (p, body) => (p === '/api/identity/auth-fingerprint' ? { json: { token: 'fixture.token.' + body.username, did: 'did:key:z' + body.username } } : null);
async function signInAs(pg, name) {
  pg.el('auth-user').value = name; pg.el('auth-pass').value = 'pw-' + name;
  await pg.ctx.login();
  await settle();
}

test('A\'s late PIN-setup reply cannot finish B\'s setup: B stays on the sheet, vault shut, no stray text', async () => {
  let releaseA, setupWrites = 0;
  const pg = page({ routes: async (p, body) => {
    if (loginFor(p, body)) return loginFor(p, body);
    if (p.startsWith('/api/identity/trust')) return { json: trustOk };
    if (p === '/api/identity/gate/status') return { json: { pin_set: false } };
    if (p === '/api/identity/pin') { setupWrites++; return new Promise(r => { releaseA = () => r({ json: { ok: true, pin_set: true } }); }); }
    throw new Error('unexpected ' + p);
  } });
  await signInAs(pg, 'accountA');
  assert.equal(pg.shown('modal-pin-setup'), true);
  pg.el('pin-new').value = '4821'; pg.el('pin-confirm').value = '4821';
  const aSave = pg.ctx.savePinSetup();
  await settle();
  assert.ok(releaseA, 'A\'s setup request is in flight');
  pg.ctx.logout();
  await signInAs(pg, 'accountB');
  assert.equal(pg.shown('modal-pin-setup'), true, 'B must set a PIN');
  assert.equal(pg.appOpen(), false);
  pg.el('pin-new').value = '77';   // B is mid-typing
  releaseA();
  await aSave;
  await settle();
  assert.equal(pg.shown('modal-pin-setup'), true, 'B\'s sheet still up after A\'s reply');
  assert.equal(pg.appOpen(), false, 'B\'s vault still shut');
  assert.equal(pg.ctx.__loads || 0, 0);
  assert.equal(pg.el('pin-new').value, '77', 'B\'s typing untouched');
  assert.equal(pg.el('pin-setup-msg').textContent, '', 'no error text from A\'s flow on B\'s sheet');
  assert.equal(setupWrites, 1, 'only A ever submitted');
  assert.equal(pg.calls.filter(c => c.path === '/api/identity/pin')[0].auth, 'Bearer fixture.token.accountA');
  pg.ctx.logout();
});

test('A\'s late PIN-unlock reply cannot unlock for B, and a failed one shows B nothing', async () => {
  for (const outcome of ['ok', 'wrong']) {
    let releaseA;
    let pinOk = false;
    const pg = page({ routes: async (p, body) => {
      if (loginFor(p, body)) return loginFor(p, body);
      if (p.startsWith('/api/identity/trust')) return { json: trustOk };
      if (p === '/api/identity/gate/status') return { json: { pin_set: true } };
      if (p === '/api/demipass/gate-policy') return pinOk ? { json: { ok: true } } : { status: 403, json: { error: 'lowering needs pin', missing: ['pin'], required: ['pin'] } };
      if (p === '/api/identity/gate/verify') return new Promise(r => { releaseA = () => r(outcome === 'ok' ? { json: { ok: true } } : { status: 403, json: { error: 'incorrect PIN (4 tries left)' } }); });
      throw new Error('unexpected ' + p);
    } });
    await signInAs(pg, 'accountA');
    pg.ctx.showDetail = () => {};
    const aDepth = pg.ctx.setDepth('sightless', 'standard');   // A: 403 → PIN sheet
    await settle();
    assert.equal(pg.shown('modal-pin'), true);
    pg.el('pin-unlock').value = '2468';
    const aSubmit = pg.ctx.submitPin();
    await settle();
    assert.ok(releaseA, 'A\'s verify in flight');
    pg.ctx.logout();
    await signInAs(pg, 'accountB');
    assert.equal(pg.appOpen(), true, 'B signed in (B has a PIN)');
    const bDepth = pg.ctx.setDepth('other', 'standard');        // B: own PIN sheet, own pending unlock
    await settle();
    assert.equal(pg.shown('modal-pin'), true, 'B\'s PIN sheet up');
    pg.el('pin-unlock').value = '13';
    releaseA();
    await aSubmit;
    await aDepth.catch(() => {});
    await settle();
    assert.equal(pg.shown('modal-pin'), true, `B's sheet still up (A ${outcome})`);
    assert.equal(pg.el('pin-unlock').value, '13', 'B\'s typing untouched');
    assert.equal(pg.el('pin-unlock-msg').textContent, '', 'no message from A\'s attempt');
    const policyCalls = pg.calls.filter(c => c.path === '/api/demipass/gate-policy');
    assert.equal(policyCalls.filter(c => c.auth === 'Bearer fixture.token.accountB').length, 1, 'B\'s policy change was not retried on A\'s proof');
    pg.ctx.cancelPin();
    await bDepth.catch(() => {});
    pg.ctx.logout();
  }
});

// ── the unlock flow ────────────────────────────────────────────────────────────────────────────────────
const vaultRoutes = (extra) => async (p, body) => {
  if (p.startsWith('/api/identity/trust')) return { json: trustOk };
  if (p === '/api/identity/gate/status') return { json: { pin_set: true } };
  const r = await extra(p, body);
  if (r) return r;
  throw new Error('unexpected ' + p);
};
const needPin = (intent = 'reveal:7') => ({ status: 403, json: { error: 'needs pin', missing: ['pin'], required: ['pin'], intent } });

test('elevated reveal: email code first, PIN last with the 403\'s intent; a cancelled code step mints no PIN proof', async () => {
  let twofa = false, pin = false, prompts = 0;
  const pg = page({ storage: signedIn, routes: vaultRoutes((p, body) => {
    if (p === '/api/blindkey/reveal') return twofa && pin ? { json: { value: 'the-value' } } : { status: 403, json: { error: 'needs pin + twofa', missing: ['pin', 'twofa'], required: ['pin', 'twofa'], intent: 'reveal:42' } };
    if (p === '/api/identity/request-2fa') return { json: { ok: true } };
    if (p === '/api/identity/gate/verify' && body.gate === 'twofa') { assert.equal(pin, false, 'code verified before any PIN'); twofa = true; return { json: { ok: true } }; }
    if (p === '/api/identity/gate/verify' && body.gate === 'pin') { assert.equal(body.intent, 'reveal:42'); pin = true; return { json: { ok: true, intent: body.intent } }; }
  }) });
  await settle();
  pg.ctx.prompt = () => { prompts++; return null; };   // the user backs out of the emailed-code step
  await pg.ctx.revealSecret('sightless');
  assert.equal(prompts, 1);
  assert.equal(pg.shown('modal-pin'), false, 'the PIN sheet never opened');
  assert.equal(pg.calls.some(c => c.path === '/api/identity/gate/verify' && c.body.gate === 'pin'), false, 'no PIN proof minted');
  assert.equal(pg.el('reveal-btn').textContent, 'Reveal');
  assert.equal(pg.el('reveal-btn').disabled, false);
  pg.ctx.prompt = () => '424242';
  const done = pg.ctx.revealSecret('sightless');
  await settle();
  assert.equal(twofa, true);
  assert.equal(pg.shown('modal-pin'), true, 'PIN asked after the code');
  pg.el('pin-unlock').value = '2468';
  await pg.ctx.submitPin();
  await done;
  assert.equal(pg.el('reveal-value').textContent, 'the-value');
  assert.equal(pg.calls.filter(c => c.path === '/api/blindkey/reveal').length, 3, 'refused, refused, revealed');
});

test('double-tap Unlock sends one PIN check; Cancel cancels at once and hands back the proof a late check minted', async () => {
  let release, verifies = 0; const discards = [];
  const pg = page({ storage: signedIn, routes: vaultRoutes((p, body) => {
    if (p === '/api/blindkey/reveal') return needPin('reveal:7');
    if (p === '/api/identity/gate/verify') { verifies++; return new Promise(r => { release = () => r({ json: { ok: true } }); }); }
    if (p === '/api/identity/gate/discard') { discards.push(body); return { json: { ok: true, discarded: 1 } }; }
  }) });
  await settle();
  const done = pg.ctx.revealSecret('sightless');
  await settle();
  pg.el('pin-unlock').value = '2468';
  const a = pg.ctx.submitPin(), b = pg.ctx.submitPin();
  await settle();
  assert.equal(verifies, 1, 'the second tap sent nothing');
  pg.ctx.cancelPin();
  await done;
  assert.equal(pg.shown('modal-pin'), false, 'Cancel closes at once');
  assert.equal(pg.el('reveal-btn').textContent, 'Reveal', 'the reveal settled as cancelled');
  release(); await a; await b; await settle();
  assert.equal(pg.calls.filter(c => c.path === '/api/blindkey/reveal').length, 1, 'no retry on the late proof');
  assert.equal(discards.length, 2, 'handed back at Cancel and again when the late check answered');
  assert.ok(discards.every(d => d.gate === 'pin' && d.intent === 'reveal:7'));
});

test('a hung PIN check times out (AbortController fallback, no AbortSignal.timeout); Cancel then hands back', async () => {
  const discards = [];
  const pg = page({ storage: signedIn, abortable: true, routes: vaultRoutes((p, body) => {
    if (p === '/api/blindkey/reveal') return needPin('reveal:9');
    if (p === '/api/identity/gate/verify') return new Promise(() => {});   // never answers
    if (p === '/api/identity/gate/discard') { discards.push(body); return { json: { ok: true } }; }
  }) });
  await settle();
  const done = pg.ctx.revealSecret('sightless');
  await settle();
  pg.el('pin-unlock').value = '2468';
  const sub = pg.ctx.submitPin();
  await settle();
  assert.ok(pg.timers.length >= 1, 'a 15 s timeout was armed');
  for (const f of pg.timers.splice(0)) f();   // 15 s pass
  await sub; await settle();
  assert.match(pg.el('pin-unlock-msg').textContent, /No answer from the server/);
  assert.equal(pg.shown('modal-pin'), true, 'the sheet is usable again');
  pg.ctx.cancelPin();
  await done; await settle();
  assert.deepEqual(discards.map(d => d.intent), ['reveal:9'], 'a proof the lost check may have minted is handed back');
});

test('Cancel during the PIN check of a delete stops the delete and hands back the proof', async () => {
  let release; const deletes = [], discards = [];
  const pg = page({ storage: signedIn, routes: vaultRoutes((p, body) => {
    if (p === '/api/demipass/delete') { deletes.push(body); return needPin('delete:5'); }
    if (p === '/api/identity/gate/verify') return new Promise(r => { release = () => r({ json: { ok: true } }); });
    if (p === '/api/identity/gate/discard') { discards.push(body); return { json: { ok: true } }; }
  }) });
  await settle();
  pg.ctx.closeDetail = () => {};
  const del = pg.ctx.revokeSecret('sightless');
  await settle();
  assert.match(pg.el('pin-unlock-what').textContent, /Deleting sightless/);
  pg.el('pin-unlock').value = '2468';
  const sub = pg.ctx.submitPin();
  await settle();
  pg.key('Escape');
  await del;
  release(); await sub; await settle();
  assert.equal(deletes.length, 1, 'the delete was never retried');
  assert.ok(discards.length >= 1 && discards.every(d => d.intent === 'delete:5'));
});

test('store: a depth the server refuses is reported and the sheet stays open', async () => {
  const pg = page({ storage: signedIn, routes: vaultRoutes((p) => {
    if (p === '/api/demipass/store') return { json: { ok: true, ref: 'DP-PWD-x-1' } };
    if (p === '/api/demipass/gate-policy') return { status: 400, json: { error: "this account can't prove an SMS code (SMS is not set up on this server) — choose protection without it" } };
  }) });
  await settle();
  pg.ctx.openModal('store');
  pg.el('s-name').value = 'x'; pg.el('s-type').value = 'password'; pg.el('s-value').value = 'v'; pg.el('s-depth').value = 'critical';
  await pg.ctx.storeSecret();
  assert.match(pg.el('s-msg').textContent, /Stored — ref: DP-PWD-x-1 — kept at Standard: .*SMS is not set up/);
  assert.equal(pg.el('s-msg').className, 'modal-msg err');
  await new Promise(r => setTimeout(r, 1300));
  assert.equal(pg.shown('modal-store'), true, 'not auto-closed over the error');
});

test('Escape: the blocking PIN sheets stay; on the unlock sheet it cancels the waiting action', async () => {
  const setup = page({ storage: signedIn, routes: async (p) => {
    if (p.startsWith('/api/identity/trust')) return { json: trustOk };
    if (p === '/api/identity/gate/status') return { json: { pin_set: false } };
    throw new Error('unexpected ' + p);
  } });
  await settle();
  setup.key('Escape');
  assert.equal(setup.shown('modal-pin-setup'), true, 'setup sheet stays');
  assert.equal(setup.appOpen(), false);
  setup.ctx.logout();
  const broken = page({ storage: signedIn, routes: async (p) => {
    if (p.startsWith('/api/identity/trust')) return { json: trustOk };
    throw new Error('network down');
  } });
  await settle();
  broken.key('Escape');
  assert.equal(broken.shown('modal-pin-error'), true, 'status-error sheet stays');
  broken.ctx.logout();
  const pg = page({ storage: signedIn, routes: vaultRoutes((p) => (p === '/api/blindkey/reveal' ? needPin() : null)) });
  await settle();
  const done = pg.ctx.revealSecret('sightless');
  await settle();
  assert.equal(pg.shown('modal-pin'), true);
  pg.key('Escape');
  await done;
  assert.equal(pg.shown('modal-pin'), false);
  assert.equal(pg.el('reveal-btn').textContent, 'Reveal');
  assert.equal(pg.el('reveal-btn').disabled, false);
});

test('a late "PIN changed" reply closes only its own sheet, never an unlock sheet opened meanwhile', async () => {
  let releaseChange;
  const pg = page({ storage: signedIn, routes: vaultRoutes((p) => {
    if (p === '/api/identity/pin') return new Promise(r => { releaseChange = () => r({ json: { ok: true, changed: true } }); });
    if (p === '/api/blindkey/reveal') return needPin();
  }) });
  await settle();
  pg.ctx.openPinChange();
  pg.el('pin-cur').value = '2468'; pg.el('pin-change-new').value = '1357'; pg.el('pin-change-confirm').value = '1357';
  const change = pg.ctx.savePinChange();
  await settle();
  pg.ctx.closeModal();   // backdrop tap while the change is in flight
  const reveal = pg.ctx.revealSecret('sightless');
  await settle();
  assert.equal(pg.shown('modal-pin'), true);
  releaseChange(); await change; await settle();
  assert.equal(pg.shown('modal-pin'), true, 'unlock sheet still up');
  pg.ctx.cancelPin();
  await reveal;
});

test('401 on a gated call = session over: back to sign-in, no popup', async () => {
  const pg = page({ storage: signedIn, routes: vaultRoutes((p) => (p === '/api/demipass/gate-policy' ? { status: 401, json: { error: 'token revoked' } } : null)) });
  await settle();
  assert.equal(pg.appOpen(), true);
  let alerts = 0; pg.ctx.alert = () => { alerts++; };
  await pg.ctx.setDepth('sightless', 'elevated');
  assert.equal(pg.authOpen(), true);
  assert.equal(pg.appOpen(), false);
  assert.match(pg.el('auth-err').textContent, /expired/i);
  assert.equal(alerts, 0);
  assert.equal(pg.store.has('dp_token'), false);
});

test('a mistyped email code (403) keeps the session', async () => {
  const pg = page({ storage: signedIn, routes: vaultRoutes((p, body) => {
    if (p === '/api/blindkey/reveal') return { status: 403, json: { error: 'needs twofa', missing: ['twofa'], required: ['twofa'], intent: 'reveal:7' } };
    if (p === '/api/identity/request-2fa') return { json: { ok: true } };
    if (p === '/api/identity/gate/verify' && body.gate === 'twofa') return { status: 403, json: { error: 'invalid or expired twofa code' } };
  }) });
  await settle();
  const alerts = []; pg.ctx.alert = m => alerts.push(m); pg.ctx.prompt = () => '000000';
  await pg.ctx.revealSecret('sightless');
  assert.equal(pg.appOpen(), true, 'still signed in');
  assert.equal(pg.store.has('dp_token'), true);
  assert.match(alerts.join(' '), /email code verification failed: invalid or expired/);
});

test('the 30 s refresh never loads the vault behind a closed PIN gate, and stops at sign-out', async () => {
  const unset = page({ storage: signedIn, routes: async (p) => {
    if (p.startsWith('/api/identity/trust')) return { json: trustOk };
    if (p === '/api/identity/gate/status') return { json: { pin_set: false } };
    throw new Error('unexpected ' + p);
  } });
  await settle();
  for (const f of unset.intervals) f();
  await settle();
  assert.equal(unset.ctx.__loads || 0, 0, 'no refresh behind the setup sheet');
  unset.ctx.logout();
  let statusFails = true;
  const pg = page({ storage: signedIn, routes: async (p) => {
    if (p.startsWith('/api/identity/trust')) return { json: trustOk };
    if (p === '/api/identity/gate/status') { if (statusFails) throw new Error('network down'); return { json: { pin_set: true } }; }
    throw new Error('unexpected ' + p);
  } });
  await settle();
  for (const f of pg.intervals) f();
  await settle();
  assert.equal(pg.ctx.__loads || 0, 0, 'no refresh behind the status-error sheet');
  statusFails = false; pg.ctx.retryPinCheck(); await settle();
  assert.equal(pg.ctx.__loads, 1);
  for (const f of pg.intervals) f();
  await settle();
  assert.equal(pg.ctx.__loads, 2, 'refreshes once open');
  pg.ctx.logout();
  for (const f of pg.intervals) f();
  assert.equal(pg.ctx.__loads, 2, 'stops at sign-out');
});

test('sign-out leaves nothing of the session on screen for the next account', async () => {
  const pg = page({ storage: signedIn, routes: vaultRoutes(() => null) });
  await settle();
  const areas = ['detail-content', 'silicon-content', 'fleet-content', 'secret-list', 'activity-list', 'settings-output', 'df-rules'];
  for (const id of areas) pg.el(id).innerHTML = '<div>revealed: hunter2</div>';
  pg.el('bal').textContent = '1200';
  pg.el('onboarding-wizard').style.display = 'flex';
  pg.el('panic').style.display = 'block';
  const typed = { id: 'wk-name', type: 'text', value: 'brain2', defaultValue: '' };
  const box = { id: 'sil-refill-enabled', type: 'checkbox', checked: false, defaultChecked: true };
  const kept = { id: 'auth-user', type: 'text', value: 'fixture', defaultValue: '' };
  pg.qsa['input, textarea, select'] = [typed, box, kept];
  pg.ctx.logout();
  for (const id of areas) assert.equal(pg.el(id).innerHTML, '', id);
  assert.equal(pg.el('bal').textContent, '');
  assert.equal(pg.el('onboarding-wizard').style.display, 'none', 'wizard gone');
  assert.equal(pg.el('panic').style.display, 'none');
  assert.equal(typed.value, '', 'typed input cleared');
  assert.equal(box.checked, true, 'checkbox back to its default');
  assert.equal(kept.value, 'fixture', 'sign-in username kept');
  assert.equal(pg.authOpen(), true);
});

test('setup: a refused password (403) is not resent; the sheet asks for it', async () => {
  const bodies = [];
  const pg = page({ routes: async (p, body) => {
    if (loginRoute(p)) return loginRoute(p);
    if (p.startsWith('/api/identity/trust')) return { json: trustOk };
    if (p === '/api/identity/gate/status') return { json: { pin_set: false } };
    if (p === '/api/identity/pin') { bodies.push(body); return body.password === 'right-pw' ? { json: { ok: true, pin_set: true } } : { status: 403, json: { error: 'invalid password' } }; }
    throw new Error('unexpected ' + p);
  } });
  await signIn(pg);
  assert.equal(pg.el('pin-setup-pw-row').style.display, 'none');
  pg.el('pin-new').value = '4821'; pg.el('pin-confirm').value = '4821';
  await pg.ctx.savePinSetup();
  assert.equal(bodies[0].password, 'pw-typed-at-login');
  assert.equal(pg.el('pin-setup-pw-row').style.display, 'block', 'password row shown');
  assert.match(pg.el('pin-setup-msg').textContent, /invalid password/);
  await pg.ctx.savePinSetup();
  assert.equal(bodies.length, 1, 'the refused password was not sent again');
  pg.el('pin-setup-pw').value = 'right-pw';
  await pg.ctx.savePinSetup();
  await settle();
  assert.equal(bodies[1].password, 'right-pw');
  assert.equal(pg.appOpen(), true);
  pg.ctx.logout();
});

test('hostile secret names stay inert: handlers get JSON string literals, data never becomes markup', async () => {
  const evil = `x');alert(1);//"><img src=x onerror=alert(2)>`;
  const pg = page({ storage: signedIn, routes: vaultRoutes((p) => (p === '/api/demipass/dashboard' ? { json: { balance_dd: 1, health_summary: {}, secrets: [
    { name: evil, type: 'password', use_count: 0, health: 'red', frozen: false, recommendation: '<i>r</i>', ownership: '<b>o</b>',
      recent_outcomes: [{ outcome: '<u>x</u>', agent_name: '<s>a</s>', action_type: 'use', created_at: new Date().toISOString() }] },
  ] } } : null)) });
  await settle();
  await pg.ctx.__realLoadVault();
  const list = pg.el('secret-list').innerHTML;
  pg.ctx.showDetail(evil);
  const detail = pg.el('detail-content').innerHTML;
  const decode = v => v.replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');
  const handlers = html => [...html.matchAll(/\son\w+="([^"]*)"/g)].map(m => decode(m[1]));
  const hs = [...handlers(list), ...handlers(detail)], lit = JSON.stringify(evil);
  assert.ok(hs.includes(`event.stopPropagation();if(!poolDrag.justDropped)showDetail(${lit})`), 'list row');
  assert.ok(hs.includes(`revealSecret(${lit})`));
  assert.ok(hs.includes(`revokeSecret(${lit})`));
  assert.ok(hs.includes(`toggleFreeze(${lit},true)`));
  assert.ok(hs.includes(`setDepth(${lit},'elevated')`));
  for (const h of hs) assert.doesNotThrow(() => new Function(h), h);   // each handler parses whole: nothing broke out
  for (const html of [list, detail]) assert.doesNotMatch(html, /<img|<i>|<b>|<u>|<s>/, 'no markup from data');
});

// ── follow-ups from the b615065 UI audit ───────────────────────────────────────────────────────────────
test('Trip All Breakers stops at sign-out: nothing is revoked with the next account\'s token, no banner for it', async () => {
  let releaseFirst; const revokes = [];
  const pg = page({ routes: async (p, body, o) => {
    if (loginFor(p, body)) return loginFor(p, body);
    if (p.startsWith('/api/identity/trust')) return { json: trustOk };
    if (p === '/api/identity/gate/status') return { json: { pin_set: true } };
    if (p === '/api/demipass/dashboard') return { json: { balance_dd: 1, health_summary: {}, secrets: [{ name: 'openai', status: 'active', use_count: 0 }, { name: 'racknerd', status: 'active', use_count: 0 }] } };
    if (p === '/api/demipass/revoke') { revokes.push({ name: body.name, auth: o.headers.Authorization }); if (revokes.length === 1) return new Promise(r => { releaseFirst = () => r({ json: { ok: true } }); }); return { json: { ok: true } }; }
    throw new Error('unexpected ' + p);
  } });
  await signInAs(pg, 'accountA');
  await pg.ctx.__realLoadVault();
  pg.ctx.confirmPanic();
  await settle();
  assert.equal(revokes.length, 1, 'A\'s loop started');
  pg.ctx.logout();
  await signInAs(pg, 'accountB');
  releaseFirst();
  await settle(12);
  assert.deepEqual(revokes.map(r => r.auth), ['Bearer fixture.token.accountA'], 'no revoke ever ran with B\'s token');
  assert.notEqual(pg.el('panic').style.display, 'block', 'B sees no breaker banner');
  pg.ctx.logout();
});

test('a worker token minted before sign-out never lands on the next account\'s screen', async () => {
  let releaseSilicon;
  const pg = page({ routes: async (p, body) => {
    if (loginFor(p, body)) return loginFor(p, body);
    if (p.startsWith('/api/identity/trust')) return { json: trustOk };
    if (p === '/api/identity/gate/status') return { json: { pin_set: true } };
    if (/\/workers$/.test(p)) return { json: { minted: { token: 'dpw_A_WORKER_SECRET' } } };
    if (/\/silicons\/[^/]+$/.test(p)) return new Promise(r => { releaseSilicon = () => r({ status: 500, json: { error: 'late' } }); });
    throw new Error('unexpected ' + p);
  } });
  await signInAs(pg, 'accountA');
  pg.el('wk-name').value = 'brain2';
  const minting = pg.ctx.createWorker();
  await settle();
  assert.ok(releaseSilicon, 'A\'s silicon page re-fetch is in flight');
  pg.ctx.logout();
  await signInAs(pg, 'accountB');
  releaseSilicon(); await minting; await settle();
  assert.equal(pg.el('wk-token-text').value, '', 'A\'s worker token is not shown to B');
  assert.notEqual(pg.el('wk-token-out').style.display, 'block');
  pg.ctx.logout();
});

test('sign-out also clears sheet messages and re-syncs the store/silicon field sets', async () => {
  const pg = page({ storage: signedIn, routes: vaultRoutes(() => null) });
  await settle();
  pg.el('s-msg').textContent = 'Stored — ref: DP-PWD-racknerd-1234'; pg.el('phone-msg').textContent = 'Saved: •••4567'; pg.el('sil-msg').textContent = 'Working…';
  pg.el('s-type').value = 'password'; pg.el('s-login-fields').style.display = 'none'; pg.el('s-key-fields').style.display = 'block';   // A left "API key" up; the reset put the dropdown back
  pg.el('sil-mode').value = 'existing'; pg.el('sil-create-fields').style.display = 'block';
  pg.ctx.logout();
  for (const id of ['s-msg', 'phone-msg', 'sil-msg']) assert.equal(pg.el(id).textContent, '', id);
  assert.equal(pg.el('s-login-fields').style.display, 'block', 'store sheet shows the login fields again');
  assert.equal(pg.el('s-key-fields').style.display, 'none');
  assert.equal(pg.el('sil-create-fields').style.display, 'none', 'silicon sheet matches "existing"');
});

test('Change PIN: a double tap sends one change (a second would send the old PIN as current)', async () => {
  let release; const changes = [];
  const pg = page({ storage: signedIn, routes: vaultRoutes((p, body) => {
    if (p === '/api/identity/pin') { changes.push(body); return new Promise(r => { release = () => r({ json: { ok: true, changed: true } }); }); }
  }) });
  await settle();
  pg.ctx.openPinChange();
  pg.el('pin-cur').value = '2468'; pg.el('pin-change-new').value = '1357'; pg.el('pin-change-confirm').value = '1357';
  const a = pg.ctx.savePinChange(), b = pg.ctx.savePinChange();
  await settle();
  assert.equal(changes.length, 1, 'one request');
  assert.match(pg.el('pin-change-msg').textContent, /still being saved/, 'the second tap says why nothing happened');
  release(); await a; await b; await settle();
  assert.equal(pg.shown('modal-pin-change'), false);
  const setupTaps = [];
  const fresh = page({ routes: async (p, body) => {
    if (loginRoute(p)) return loginRoute(p);
    if (p.startsWith('/api/identity/trust')) return { json: trustOk };
    if (p === '/api/identity/gate/status') return { json: { pin_set: false } };
    if (p === '/api/identity/pin') { setupTaps.push(body); return new Promise(() => {}); }
    throw new Error('unexpected ' + p);
  } });
  await signIn(fresh);
  fresh.el('pin-new').value = '4821'; fresh.el('pin-confirm').value = '4821';
  fresh.ctx.savePinSetup(); fresh.ctx.savePinSetup();
  await settle();
  assert.equal(setupTaps.length, 1, 'PIN setup: a double tap sends one save');
  fresh.ctx.logout();
});

// ── attempt-scoped cancels ─────────────────────────────────────────────────────────────────────────────
test('each PIN check carries an attempt id; Cancel discards exactly that attempt (also after a network error)', async () => {
  let fail; const verifies = [], discards = [];
  const pg = page({ storage: signedIn, routes: vaultRoutes((p, body) => {
    if (p === '/api/blindkey/reveal') return needPin('reveal:3');
    if (p === '/api/identity/gate/verify') { verifies.push(body); return new Promise((_, rej) => { fail = () => rej(new TypeError('Failed to fetch')); }); }
    if (p === '/api/identity/gate/discard') { discards.push(body); return { json: { ok: true } }; }
  }) });
  await settle();
  const done = pg.ctx.revealSecret('sightless');
  await settle();
  pg.el('pin-unlock').value = '2468';
  const sub = pg.ctx.submitPin();
  await settle();
  assert.match(verifies[0].attempt || '', /^[A-Za-z0-9_-]{8,64}$/, 'the check names its attempt');
  pg.ctx.cancelPin();
  await done;
  fail(); await sub; await settle();   // the check's answer is lost to a network error (no HTTP status)
  assert.equal(discards.length, 2, 'cancelled at Cancel, and again when the check failed without an answer');
  assert.ok(discards.every(d => d.attempt === verifies[0].attempt && d.intent === 'reveal:3'), 'always that one attempt');
});

test('a check that times out after sign-out sends no discard under the next account', async () => {
  const discards = [];
  const pg = page({ abortable: true, routes: async (p, body, o) => {
    if (loginFor(p, body)) return loginFor(p, body);
    if (p.startsWith('/api/identity/trust')) return { json: trustOk };
    if (p === '/api/identity/gate/status') return { json: { pin_set: true } };
    if (p === '/api/demipass/gate-policy') return { status: 403, json: { error: 'needs pin', missing: ['pin'], required: ['pin'], intent: 'gate-policy:4' } };
    if (p === '/api/identity/gate/verify') return new Promise(() => {});
    if (p === '/api/identity/gate/discard') { discards.push({ body, auth: o.headers.Authorization }); return { json: { ok: true } }; }
    throw new Error('unexpected ' + p);
  } });
  await signInAs(pg, 'accountA');
  pg.ctx.showDetail = () => {};
  const depth = pg.ctx.setDepth('sightless', 'standard');
  await settle();
  pg.el('pin-unlock').value = '2468';
  const sub = pg.ctx.submitPin();
  await settle();
  pg.ctx.logout();
  await depth.catch(() => {});
  await signInAs(pg, 'accountB');
  for (const f of pg.timers.splice(0)) f();   // A's 15 s timeout fires while B is signed in
  await sub; await settle();
  assert.equal(discards.filter(d => d.auth === 'Bearer fixture.token.accountB').length, 0, 'nothing sent with B\'s token');
  pg.ctx.logout();
});

test('a check that timed out is cancelled once a later attempt in the same flow succeeds', async () => {
  const verifies = [], discards = []; let n = 0;
  const pg = page({ storage: signedIn, abortable: true, routes: vaultRoutes((p, body) => {
    if (p === '/api/blindkey/reveal') return n >= 2 ? { json: { value: 'the-value' } } : needPin('reveal:6');
    if (p === '/api/identity/gate/verify') { verifies.push(body); n++; return n === 1 ? new Promise(() => {}) : { json: { ok: true } }; }
    if (p === '/api/identity/gate/discard') { discards.push(body); return { json: { ok: true } }; }
  }) });
  await settle();
  const done = pg.ctx.revealSecret('sightless');
  await settle();
  pg.el('pin-unlock').value = '2468';
  const first = pg.ctx.submitPin();
  await settle();
  for (const f of pg.timers.splice(0)) f();   // attempt 1 times out (it may still reach the server later)
  await first; await settle();
  pg.el('pin-unlock').value = '2468';
  await pg.ctx.submitPin();                   // attempt 2 succeeds
  await done; await settle();
  assert.equal(pg.el('reveal-value').textContent, 'the-value');
  assert.deepEqual(discards.map(d => d.attempt), [verifies[0].attempt], 'only the timed-out attempt is cancelled, never the winner');
});

// ── browser fill approvals ─────────────────────────────────────────────────────────────────────────────
// The extension asks; the wallet shows the request and approves it with the PIN for intent fill:<id>.
function fillRoutes(state) {
  return async (p, body) => {
    if (p.startsWith('/api/identity/trust')) return { json: trustOk };
    if (p === '/api/identity/gate/status') return { json: { pin_set: true } };
    if (p === '/api/blindkey/fill/pending') return { json: { ok: true, requests: state.requests, grants: state.grants || [] } };
    if (p === '/api/blindkey/silicon/grants/5/approve') {
      if (!state.pinFresh) return { status: 403, json: { error: 'needs pin', missing: ['pin'], required: ['pin'], intent: 'grant:5' } };
      state.pinFresh = false; state.grants = []; return { json: { ok: true, status: 'approved' } };
    }
    if (p === '/api/blindkey/silicon/grants/5/deny') { state.grants = []; return { json: { ok: true, status: 'denied' } }; }
    if (p === '/api/blindkey/fill/12/approve') {
      if (!state.pinFresh) return { status: 403, json: { error: 'needs pin', missing: ['pin'], required: ['pin'], intent: 'fill:12' } };
      state.pinFresh = false; state.requests = state.requests.filter(q => q.id !== 12); return { json: { ok: true, status: 'approved' } };
    }
    if (p === '/api/blindkey/fill/12/deny') { state.requests = state.requests.filter(q => q.id !== 12); return { json: { ok: true, status: 'denied' } }; }
    if (p === '/api/identity/gate/verify') { assert.equal(body.intent, state.intent || 'fill:12', 'the PIN opens this one action'); state.pinFresh = body.pin === '2468'; return state.pinFresh ? { json: { ok: true } } : { status: 403, json: { error: 'incorrect PIN' } }; }
    throw new Error('unexpected ' + p);
  };
}
const fillReq = (over = {}) => ({ id: 12, intent: 'fill:12', name: 'example-login', ref: 'DP-PWD-x', username: 'me@example.com', origin: 'https://login.example.com', client_label: 'Chrome on flimflam', own_session: false, ...over });

test('a pending browser fill shows its origin and is approved with the PIN for fill:<id>', async () => {
  const state = { requests: [fillReq(), fillReq({ id: 13, own_session: true })] };
  const pg = page({ storage: signedIn, routes: fillRoutes(state) });
  await settle();
  const card = pg.el('fill-requests').innerHTML;
  assert.match(card, /https:\/\/login\.example\.com/);
  assert.match(card, /me@example\.com/);
  assert.equal((card.match(/class="fill-req"/g) || []).length, 1, 'the wallet\'s own request is not offered for approval');
  const done = pg.ctx.decideFill(12, true);
  await settle();
  assert.equal(pg.shown('modal-pin'), true, 'PIN sheet opened by the 403');
  assert.match(pg.el('pin-unlock-what').textContent, /login\.example\.com/);
  pg.el('pin-unlock').value = '2468';
  await pg.ctx.submitPin();
  await done;
  assert.equal(pg.calls.filter(c => c.path === '/api/blindkey/fill/12/approve').length, 2, 'refused once, approved after the PIN');
  assert.doesNotMatch(pg.el('fill-requests').innerHTML, /fill-req/, 'card gone once approved');
});

test('deny needs no PIN; cancelling the PIN sheet approves nothing', async () => {
  const state = { requests: [fillReq()] };
  const pg = page({ storage: signedIn, routes: fillRoutes(state) });
  await settle();
  const done = pg.ctx.decideFill(12, true);
  await settle();
  pg.ctx.cancelPin();
  await done;
  assert.equal(pg.calls.filter(c => c.path === '/api/blindkey/fill/12/approve').length, 1, 'no retry after Cancel');
  await pg.ctx.decideFill(12, false);
  assert.equal(pg.calls.filter(c => c.path === '/api/identity/gate/verify').length, 0, 'deny asked for no PIN');
  assert.equal(pg.calls.filter(c => c.path === '/api/blindkey/fill/12/deny').length, 1);
});

test('fill requests: hostile fields stay inert, polling stops at sign-out and the cards are cleared', async () => {
  const evil = `x');alert(1);//"><img src=x onerror=alert(2)>`;
  const state = { requests: [fillReq({ name: evil, username: evil, origin: 'https://a.example', client_label: evil })] };
  const pg = page({ storage: signedIn, routes: fillRoutes(state) });
  await settle();
  const html = pg.el('fill-requests').innerHTML;
  assert.doesNotMatch(html, /<img/);
  for (const m of html.matchAll(/\son\w+="([^"]*)"/g)) assert.match(m[1], /^decideFill\(12,(true|false)\)$/, 'handlers carry only the numeric id');
  const polls = () => pg.calls.filter(c => c.path === '/api/blindkey/fill/pending').length;
  const before = polls();
  for (const f of pg.intervals) f();
  await settle();
  assert.ok(polls() > before, 'polls while open');
  pg.ctx.logout();
  assert.equal(pg.el('fill-requests').innerHTML, '', 'cards cleared at sign-out');
  const atLogout = polls();
  for (const f of pg.intervals) f();
  await settle();
  assert.equal(polls(), atLogout, 'no polling after sign-out');
});

const grantReq = (over = {}) => ({ id: 5, intent: 'grant:5', agent_name: 'fleet-a1', permission: 'action:browser_fill', resource: 'DP-PWD-x', label: 'example-login (bot@example.com) on https://login.example.com', ...over });

test('an agent fill grant shows the agent and the login, is allowed with the PIN for grant:<id>, and denied without one', async () => {
  const evil = `x');alert(1);//"><img src=x onerror=alert(2)>`;
  const state = { requests: [], grants: [grantReq({ agent_name: evil })], intent: 'grant:5' };
  const pg = page({ storage: signedIn, routes: fillRoutes(state) });
  await settle();
  const html = pg.el('fill-requests').innerHTML;
  assert.match(html, /bot@example\.com/);
  assert.doesNotMatch(html, /<img/);
  for (const m of html.matchAll(/\son\w+="([^"]*)"/g)) assert.match(m[1], /^decideGrant\(5,(true|false)\)$/, 'handlers carry only the numeric id');
  const done = pg.ctx.decideGrant(5, true);
  await settle();
  assert.equal(pg.shown('modal-pin'), true, 'PIN sheet opened by the 403');
  pg.el('pin-unlock').value = '2468';
  await pg.ctx.submitPin();
  await done;
  assert.equal(pg.calls.filter(c => c.path === '/api/blindkey/silicon/grants/5/approve').length, 2, 'refused once, approved after the PIN');
  assert.doesNotMatch(pg.el('fill-requests').innerHTML, /fill-req/, 'card gone once allowed');
  state.grants = [grantReq()];
  for (const f of pg.intervals) f();
  await settle();
  await pg.ctx.decideGrant(5, false);
  assert.equal(pg.calls.filter(c => c.path === '/api/identity/gate/verify').length, 1, 'deny asked for no PIN');
  assert.equal(pg.calls.filter(c => c.path === '/api/blindkey/silicon/grants/5/deny').length, 1);
});

// ── network: requests, agents joining a fleet, sending DD ─────────────────────────────────────────────
function netRoutes(state) {
  return async (p, body) => {
    if (p.startsWith('/api/identity/trust')) return { json: trustOk };
    if (p === '/api/identity/gate/status') return { json: { pin_set: true } };
    if (p === '/api/blindkey/fill/pending') return { json: { ok: true, requests: [], grants: [] } };
    if (p === '/api/fleets/mine') return { json: { ok: true, fleets: [] } };
    if (p === '/api/network') return { json: { ok: true, me: { did: 'did:key:zFixture', username: 'fixture', pin_set: true, balance_cents: 900 }, fleet: null, member_of: state.member_of || null,
                                               people: state.people || [], agents: [], incoming: state.incoming || [], outgoing: [],
                                               topups: { incoming: state.topupsIn || [], outgoing: state.topupsOut || [] } } };
    if (p === '/api/network/topups') { state.asked = body; state.topupsOut = [{ id: 9, direction: 'outgoing', owner: 'aaron', amount_cents: body.amount_cents, note: body.note }]; return { status: 201, json: { ok: true } }; }
    if (p === '/api/network/topups/9/decline') { state.topupsIn = []; return { json: { ok: true } }; }
    if (p === '/api/network/topups/9/withdraw') { state.topupsOut = []; return { json: { ok: true } }; }
    if (p === '/api/network/requests/4/accept') {
      if (!state.pinFresh) return { status: 403, json: { error: 'joining a fleet needs your PIN', missing: ['pin'], required: ['pin'], intent: 'join:4' } };
      state.pinFresh = false; state.incoming = []; return { json: { ok: true, kind: 'agent' } };
    }
    if (p === '/api/network/requests/4/decline') { state.incoming = []; return { json: { ok: true } }; }
    if (p === '/api/network/transfers') { state.created = body; return { status: 201, json: { ok: true, transfer: { id: 7, intent: 'send:7', to: body.to, amount_cents: body.amount_cents, needs_pin: true } } }; }
    if (p === '/api/network/transfers/7/confirm') {
      if (!state.pinFresh) return { status: 403, json: { error: 'sending needs your PIN', missing: ['pin'], required: ['pin'], intent: 'send:7' } };
      state.pinFresh = false; return { json: { ok: true, status: 'sent', to: 'kylemayor', amount_cents: state.created.amount_cents } };
    }
    if (p === '/api/network/transfers/7/cancel') { state.cancelled = (state.cancelled || 0) + 1; return { json: { ok: true } }; }
    if (p === '/api/identity/gate/verify') { assert.equal(body.intent, state.intent, 'the PIN opens this one action'); state.pinFresh = body.pin === '2468'; return state.pinFresh ? { json: { ok: true } } : { status: 403, json: { error: 'incorrect PIN' } }; }
    throw new Error('unexpected ' + p);
  };
}
const netReq = (over = {}) => ({ id: 4, kind: 'agent', direction: 'incoming', other: 'aaron', other_did: 'did:key:zAaron', note: '', needs_pin: true, intent: 'join:4',
                                 effect: "You join aaron's fleet as an agent. aaron can then mint tokens for your wallet, refill it, and give it secrets.", ...over });

test('an incoming fleet invite shows on the vault home with a badge; accepting walks the PIN for join:<id>', async () => {
  const evil = `x');alert(1);//"><img src=x onerror=alert(2)>`;
  const state = { incoming: [netReq({ other: evil, note: evil })], intent: 'join:4' };
  const pg = page({ storage: signedIn, routes: netRoutes(state) });
  await settle();
  const html = pg.el('net-requests').innerHTML;
  assert.match(html, /mint tokens for your wallet/);
  assert.doesNotMatch(html, /<img/);
  for (const m of html.matchAll(/\son\w+="([^"]*)"/g)) assert.match(m[1], /^decideNet\(4,(true|false)\)$/, 'handlers carry only the numeric id');
  assert.equal(pg.el('net-badge').textContent, 'Fleet · 1 request ›');
  const done = pg.ctx.decideNet(4, true);
  await settle();
  assert.equal(pg.shown('modal-pin'), true, 'PIN sheet opened by the 403');
  pg.el('pin-unlock').value = '2468';
  await pg.ctx.submitPin();
  await done; await settle();
  assert.equal(pg.calls.filter(c => c.path === '/api/network/requests/4/accept').length, 2, 'refused once, accepted after the PIN');
  assert.equal(pg.el('net-requests').innerHTML, '', 'card gone once accepted');
  assert.equal(pg.el('net-badge').textContent, 'Fleet ›');
});

test('declining an invite asks for no PIN; sign-out clears the cards and the badge', async () => {
  const state = { incoming: [netReq({ kind: 'person', needs_pin: false })], intent: 'none' };
  const pg = page({ storage: signedIn, routes: netRoutes(state) });
  await settle();
  state.incoming = [netReq()];
  await pg.ctx.loadNetwork();
  pg.ctx.logout();
  assert.equal(pg.el('net-requests').innerHTML, '');
  assert.equal(pg.el('net-badge').textContent, 'Fleet ›');
  const pg2 = page({ storage: signedIn, routes: netRoutes(state) });
  await settle();
  await pg2.ctx.decideNet(4, false);
  assert.equal(pg2.calls.filter(c => c.path === '/api/identity/gate/verify').length, 0, 'decline asked for no PIN');
  assert.equal(pg2.calls.filter(c => c.path === '/api/network/requests/4/decline').length, 1);
});

test('Send DD: the transfer is created, then confirmed with the PIN for send:<id>; a cancelled PIN cancels the transfer', async () => {
  const state = { people: [{ kind: 'person', did: 'did:key:zKyle', username: 'kylemayor' }], intent: 'send:7' };
  const pg = page({ storage: signedIn, routes: netRoutes(state) });
  await settle();
  await pg.ctx.loadFleet();
  assert.match(pg.el('fleet-content').innerHTML, /kylemayor/);
  assert.match(pg.el('fleet-content').innerHTML, /No agents yet/);
  pg.ctx.openSend('kylemayor');
  assert.equal(pg.el('send-to-name').textContent, 'kylemayor');
  assert.equal(pg.el('send-balance').textContent, '900');
  pg.el('send-amount').value = '2.5';
  await pg.ctx.sendDD();
  assert.equal(state.created, undefined, 'a fractional amount is refused before anything is sent');
  pg.el('send-amount').value = '150'; pg.el('send-note').value = 'for the box';
  const done = pg.ctx.sendDD();
  await settle();
  assert.deepEqual({ ...state.created }, { to: 'kylemayor', amount_cents: 150, note: 'for the box' });
  assert.equal(pg.shown('modal-pin'), true);
  assert.match(pg.el('pin-unlock-what').textContent, /150 DD to kylemayor/);
  pg.el('pin-unlock').value = '2468';
  await pg.ctx.submitPin();
  await done; await settle();
  assert.equal(pg.calls.filter(c => c.path === '/api/network/transfers/7/confirm').length, 2, 'refused once, sent after the PIN');
  assert.equal(state.cancelled || 0, 0, 'a sent transfer is not cancelled');
  pg.ctx.openSend('kylemayor'); pg.el('send-amount').value = '5';
  const second = pg.ctx.sendDD();
  await settle();
  pg.ctx.cancelPin();
  await second; await settle();
  assert.equal(pg.calls.filter(c => c.path === '/api/network/transfers/7/confirm').length, 3, 'no retry after Cancel');
  assert.equal(state.cancelled, 1, 'the waiting transfer is cancelled on the server');
});

// ── top-up asks: an agent asks its fleet owner for DD ─────────────────────────────────────────────────
test('an agent\'s top-up ask shows on the owner\'s home; Send DD opens prefilled, Decline posts once', async () => {
  const evil = `x');alert(1);//"><img src=x onerror=alert(2)>`;
  const state = { topupsIn: [{ id: 9, direction: 'incoming', agent: 'felixbaakmk', amount_cents: 200, note: evil, agent_balance_cents: 0 }],
                  incoming: [netReq()], intent: 'send:7' };
  const pg = page({ storage: signedIn, routes: netRoutes(state) });
  await settle();
  const html = pg.el('net-requests').innerHTML;
  assert.match(html, /<b>felixbaakmk<\/b> asks for <b>200 DD<\/b>/);
  assert.match(html, /It has 0 DD/);
  assert.doesNotMatch(html, /<img/);
  assert.equal(pg.el('net-badge').textContent, 'Fleet · 2 requests ›', 'asks count with connection requests');
  pg.ctx.openSend('felixbaakmk', 200);
  assert.equal(pg.el('send-to-name').textContent, 'felixbaakmk');
  assert.equal(pg.el('send-amount').value, '200');
  assert.equal(pg.el('send-note').value, 'Top-up');
  pg.ctx.closeModal();
  pg.ctx.openSend('kylemayor');
  assert.equal(pg.el('send-amount').value, '', 'a plain Send DD is not prefilled');
  pg.ctx.closeModal();
  const d1 = pg.ctx.declineTopup(9), d2 = pg.ctx.declineTopup(9);
  await d1; await d2; await settle();
  assert.equal(pg.calls.filter(c => c.path === '/api/network/topups/9/decline').length, 1, 'a double tap declines once');
  assert.equal(pg.calls.filter(c => c.path === '/api/identity/gate/verify').length, 0, 'decline asks for no PIN');
  assert.equal(pg.el('net-badge').textContent, 'Fleet · 1 request ›');
});

test('an agent wallet asks its fleet owner for DD with a note, and can withdraw the ask', async () => {
  const state = { member_of: { slug: 'aaron', name: "aaron's fleet", owner: 'aaron', owner_did: 'did:key:zAaron', handle: 'felixbaakmk' }, intent: 'none' };
  const pg = page({ storage: signedIn, routes: netRoutes(state) });
  await settle();
  await pg.ctx.loadFleet();
  assert.match(pg.el('fleet-content').innerHTML, /Ask for DD/);
  pg.ctx.openTopup();
  assert.equal(pg.el('topup-owner').textContent, 'aaron');
  assert.equal(pg.shown('modal-topup'), true);
  pg.el('topup-amount').value = '0';
  await pg.ctx.askTopup();
  assert.equal(state.asked, undefined, 'a zero amount is refused before anything is sent');
  pg.el('topup-amount').value = '120'; pg.el('topup-note').value = ' out of DD mid-task ';
  const t1 = pg.ctx.askTopup(), t2 = pg.ctx.askTopup();
  await t1; await t2; await settle();
  assert.equal(pg.calls.filter(c => c.path === '/api/network/topups').length, 1, 'a double tap asks once');
  assert.deepEqual({ ...state.asked }, { amount_cents: 120, note: 'out of DD mid-task' });
  assert.equal(pg.shown('modal-topup'), false, 'sheet closes once asked');
  assert.match(pg.el('fleet-content').innerHTML, /You asked <b>aaron<\/b> for <b>120 DD<\/b>/);
  await pg.ctx.withdrawTopup(9); await settle();
  assert.equal(pg.calls.filter(c => c.path === '/api/network/topups/9/withdraw').length, 1);
  await pg.ctx.loadFleet();   // the fleet tab is not the active page in this harness
  assert.doesNotMatch(pg.el('fleet-content').innerHTML, /You asked/);
  pg.ctx.openTopup(); pg.el('topup-amount').value = '7'; pg.el('topup-note').value = 'draft';
  pg.ctx.logout();
  for (const i of ['topup-owner', 'topup-msg']) assert.equal(pg.el(i).textContent, '', i + ' cleared on sign-out');
  for (const i of ['topup-amount', 'topup-note']) assert.equal(pg.el(i).value, '', i + ' cleared on sign-out');
});

// Changing the recovery email takes the account password (the server refuses a token alone).
test('recovery wizard sends the password typed at sign-in; a refused one is asked for on the wizard', async () => {
  let recovery = null, refuse = true;
  const pg = page({ routes: async (p, body) => {
    const l = loginRoute(p); if (l) return l;
    if (p.startsWith('/api/identity/trust')) return { json: { recovery_email: recovery } };
    if (p === '/api/identity/set-recovery-email') {
      if (refuse) { refuse = false; return { status: 403, json: { error: 'invalid password' } }; }
      recovery = body.recovery_email; return { json: { ok: true } };
    }
    if (p === '/api/identity/gate/status') return { json: { pin_set: true } };
    throw new Error('unexpected ' + p);
  } });
  await signIn(pg);
  assert.equal(pg.el('onboarding-wizard').style.display, 'flex', 'wizard shown');
  assert.equal(pg.el('wizard-pw-row').style.display, 'none', 'no password field while the sign-in password is held');
  pg.el('wizard-recovery-email').value = 'me@example.com';
  await pg.ctx.completeOnboarding(); await settle();
  let sent = pg.calls.filter(c => c.path === '/api/identity/set-recovery-email');
  assert.deepEqual(sent[0].body, { recovery_email: 'me@example.com', password: 'pw-typed-at-login' });
  assert.equal(pg.el('wizard-pw-row').style.display, 'block', 'refused: the wizard asks for the password');
  await pg.ctx.completeOnboarding(); await settle();
  assert.equal(pg.calls.filter(c => c.path === '/api/identity/set-recovery-email').length, 1, 'refused password not resent');
  assert.match(pg.el('wizard-msg').textContent, /password/i);
  pg.el('wizard-pw').value = 'pw-typed-again';
  await pg.ctx.completeOnboarding(); await settle();
  sent = pg.calls.filter(c => c.path === '/api/identity/set-recovery-email');
  assert.deepEqual(sent[1].body, { recovery_email: 'me@example.com', password: 'pw-typed-again' });
  assert.equal(pg.el('wizard-pw').value, '', 'password field cleared');
  assert.equal(pg.el('onboarding-wizard').style.display, 'none');
  assert.equal(pg.appOpen(), true);
});

test('settings: saving a recovery email needs the password, sends it once and clears it', async () => {
  const pg = page({ storage: signedIn, routes: async (p) => {
    if (p.startsWith('/api/identity/trust')) return { json: trustOk };
    if (p === '/api/identity/gate/status') return { json: { pin_set: true } };
    if (p === '/api/identity/set-recovery-email') return { json: { ok: true } };
    throw new Error('unexpected ' + p);
  } });
  await settle();
  pg.el('recovery-email').value = 'new@example.com';
  await pg.ctx.setRecoveryEmail();
  assert.equal(pg.calls.filter(c => c.path === '/api/identity/set-recovery-email').length, 0, 'nothing sent without the password');
  assert.match(pg.el('recovery-msg').textContent, /password/i);
  pg.el('recovery-pw').value = 'acct-pw';
  await pg.ctx.setRecoveryEmail();
  const sent = pg.calls.filter(c => c.path === '/api/identity/set-recovery-email');
  assert.deepEqual(sent.map(c => c.body), [{ recovery_email: 'new@example.com', password: 'acct-pw' }]);
  assert.equal(pg.el('recovery-pw').value, '');
  assert.equal(pg.el('recovery-msg').textContent, 'Recovery email saved');
});

// ── Session renewal: the vault no longer signs out every 24 h ──
const DAY = 24 * 3600 * 1000;
const renewRoutes = (extra) => async (p, body) => {
  if (p.startsWith('/api/identity/trust')) return { json: trustOk };
  if (p === '/api/identity/gate/status') return { json: { pin_set: true } };
  const r = extra && await extra(p, body); if (r) return r;
  throw new Error('unexpected ' + p);
};

test('an expired access token is renewed with the refresh token at start: vault opens, new token used and kept', async () => {
  const pg = page({ storage: { ...signedIn, dp_token_at: String(Date.now() - DAY - 1000), dp_refresh: 'dpr_old' },
    routes: renewRoutes(p => p === '/api/identity/refresh' ? { json: { token: 'fixture.token.b', refresh_token: 'dpr_new' } } : null) });
  await settle(10);
  assert.equal(pg.appOpen(), true);
  const ref = pg.calls.find(c => c.path === '/api/identity/refresh');
  assert.equal(ref.body.refresh_token, 'dpr_old');
  assert.equal(pg.store.get('dp_token'), 'fixture.token.b');
  assert.equal(pg.store.get('dp_refresh'), 'dpr_new');
  assert.ok(pg.calls.filter(c => c.path === '/api/identity/gate/status').every(c => c.auth === 'Bearer fixture.token.b'));
});

test('a token in its last hour is renewed before the next call; concurrent calls share one refresh', async () => {
  let refreshes = 0;
  const pg = page({ storage: { ...signedIn, dp_token_at: String(Date.now() - DAY + 30 * 60 * 1000), dp_refresh: 'dpr_old' },
    routes: renewRoutes(p => {
      if (p === '/api/identity/refresh') { refreshes++; return { json: { token: 'fixture.token.b', refresh_token: 'dpr_new' } }; }
      if (p === '/api/x') return { json: { ok: true } };
    }) });
  await settle(10);
  await Promise.all([pg.ctx.api('GET', '/api/x'), pg.ctx.api('GET', '/api/x')]);
  assert.equal(refreshes, 1);
  assert.ok(pg.calls.filter(c => c.path === '/api/x').every(c => c.auth === 'Bearer fixture.token.b'));
});

test('a 401 is retried once after renewing; a second 401 signs out', async () => {
  let n = 0;
  const pg = page({ storage: { ...signedIn, dp_refresh: 'dpr_old' }, routes: renewRoutes(p => {
    if (p === '/api/identity/refresh') return { json: { token: 'fixture.token.b', refresh_token: 'dpr_new' } };
    if (p === '/api/x') { n++; return n === 1 ? { status: 401, json: { error: 'expired' } } : { json: { ok: true } }; }
    if (p === '/api/y') return { status: 401, json: { error: 'revoked' } };
  }) });
  await settle(10);
  assert.deepEqual(await pg.ctx.api('GET', '/api/x'), { ok: true });
  assert.equal(pg.calls.filter(c => c.path === '/api/x')[1].auth, 'Bearer fixture.token.b');
  await assert.rejects(pg.ctx.api('GET', '/api/y'), /session expired/);
  assert.equal(pg.authOpen(), true);
});

test('a refused refresh token ends the session; sign-out revokes the refresh token and forgets it', async () => {
  const pg = page({ storage: { ...signedIn, dp_token_at: String(Date.now() - DAY - 1000), dp_refresh: 'dpr_dead' },
    routes: renewRoutes(p => p === '/api/identity/refresh' ? { status: 401, json: { error: 'invalid' } } : (p === '/api/identity/refresh/revoke' ? { json: { ok: true } } : null)) });
  await settle(10);
  assert.equal(pg.appOpen(), false);
  assert.equal(pg.authOpen(), true);
  assert.equal(pg.store.get('dp_refresh'), undefined);
  assert.equal(pg.calls.find(c => c.path === '/api/identity/refresh/revoke').body.refresh_token, 'dpr_dead');
});

test('sign-in keeps the refresh token the server returns', async () => {
  const pg = page({ routes: renewRoutes(p => p === '/api/identity/auth-fingerprint' ? { json: { token: 'fixture.token.a', did: 'did:key:zFixture', refresh_token: 'dpr_login' } } : null) });
  await signIn(pg);
  assert.equal(pg.store.get('dp_refresh'), 'dpr_login');
});

// ── Access requests: an agent in your fleet asks for a secret ──
test('access request card: hostile names stay inert, the owner picks a secret, Share walks the PIN gate', async () => {
  const req = { id: 7, intent: 'access:7', requester: '<img src=x onerror=alert(1)>', secret_hint: 'x"><b>', reason: '</div><script>1</script>', match: null };
  let approveBody = null, approves = 0;
  const pg = page({ storage: signedIn, routes: renewRoutes((p, body) => {
    if (p === '/api/blindkey/fill/pending') return { json: { ok: true, requests: [], grants: [], access_requests: [req] } };
    if (p === '/api/blindkey/access-requests/7/approve') { approves++; approveBody = body; return approves === 1 ? { status: 403, json: { error: 'pin', missing: ['pin'], required: ['pin'], intent: 'access:7' } } : { json: { ok: true } }; }
    if (p === '/api/identity/gate/verify') return { json: { ok: true } };
  }) });
  await settle();
  vm.runInContext("secrets = [{ name: 'felix-stringline', ref: 'DP-API-felixstr-1', status: 'active' }]; vaultOpen = true;", pg.ctx);
  await pg.ctx.loadFillRequests();
  const html = pg.el('fill-requests').innerHTML;
  assert.ok(!html.includes('<img') && !html.includes('<script>') && !html.includes('"><b>'), html);
  assert.match(html, /decideAccess\(7,true\)/);
  vm.runInContext("accessPick[7] = 'DP-API-felixstr-1'", pg.ctx);
  pg.el('ar-secret-7').value = 'DP-API-felixstr-1';
  const done = pg.ctx.decideAccess(7, true);
  await settle(10);
  pg.el('pin-unlock').value = '4321';
  await pg.ctx.submitPin();
  await settle(10);
  await done;
  assert.equal(approveBody.secret, 'DP-API-felixstr-1');
  assert.equal(pg.calls.find(c => c.path === '/api/identity/gate/verify').body.intent, 'access:7');
});

// ── Shares from people: the recipient's one step is Accept, with their PIN ──
test('share offer card: hostile names stay inert; Accept walks the PIN gate with intent share-accept:<id>', async () => {
  const offer = { id: 12, state: 'offered', role: 'recipient', owner: '<img src=x onerror=alert(1)>', recipient: 'kyle',
    secret: { name: 'x"><b>', ref: 'DP-PWD-racknerd-1', type: 'password' }, note: '</div><script>1</script>', expires_at: '2027-01-01T00:00:00Z' };
  let accepts = 0;
  const pg = page({ storage: signedIn, routes: renewRoutes((p) => {
    if (p === '/api/blindkey/shares') return { json: { ok: true, given: [], received: [offer], waiting_for_you: 1 } };
    if (p === '/api/blindkey/shares/12/accept') { accepts++; return accepts === 1 ? { status: 403, json: { error: 'pin', missing: ['pin'], required: ['pin'], intent: 'share-accept:12' } } : { json: { ok: true, share: { ...offer, state: 'active' } } }; }
    if (p === '/api/identity/gate/verify') return { json: { ok: true } };
  }) });
  await settle();
  vm.runInContext('vaultOpen = true;', pg.ctx);
  await pg.ctx.loadShares();
  const html = pg.el('share-requests').innerHTML;
  assert.ok(!html.includes('<img') && !html.includes('<script>') && !html.includes('"><b>'), html);
  assert.match(html, /shareAct\(12,'accept'\)/);
  const done = pg.ctx.shareAct(12, 'accept');
  await settle(10);
  pg.el('pin-unlock').value = '8765';
  await pg.ctx.submitPin();
  await settle(10);
  await done;
  assert.equal(accepts, 2);
  assert.equal(pg.calls.find(c => c.path === '/api/identity/gate/verify').body.intent, 'share-accept:12');
});

// ── Approval requests (security depth): Open walks the PIN gate on critical; Approve sends the code on the screen ──
test('approval card: hostile text stays inert; Open (critical) asks the PIN; Approve sends the code shown, nobody types it', async () => {
  const req = { id: 41, kind: 'use', status: 'pending', depth: 'critical', secret: { name: 'x"><b>', ref: 'DP-PWD-r-1' }, requester: '<img src=x onerror=alert(1)>',
    requester_label: 'agent', purpose: '</div><script>1</script>', summary: 'ssh root@192.0.2.1: hostname', expires_at: '2027-01-01T00:00:00Z', opened: false, needs_pin_to_open: true };
  let opens = 0, approveBody = null;
  const pg = page({ storage: signedIn, routes: renewRoutes((p, body) => {
    if (p === '/api/blindkey/approvals') return { json: { ok: true, incoming: [req], outgoing: [], recent: [] } };
    if (p === '/api/blindkey/approvals/41/open') { opens++; return opens === 1 ? { status: 403, json: { error: 'pin', missing: ['pin'], required: ['pin'], intent: 'approval-open:41' } }
      : { json: { ok: true, approval: { ...req, opened: true }, code: '048213', code_valid_until: '2027-01-01T00:00:30Z', step_seconds: 30 } }; }
    if (p === '/api/blindkey/approvals/41/approve') { approveBody = body; return { json: { ok: true, approval: { ...req, status: 'approved' } } }; }
    if (p === '/api/identity/gate/verify') return { json: { ok: true } };
  }) });
  await settle();
  vm.runInContext('vaultOpen = true;', pg.ctx);
  await pg.ctx.loadApprovals();
  const html = pg.el('approval-requests').innerHTML;
  assert.ok(!html.includes('<img') && !html.includes('<script>') && !html.includes('"><b>'), html);
  assert.match(html, /openApproval\(41\)/);
  const done = pg.ctx.openApproval(41);
  await settle(10);
  pg.el('pin-unlock').value = '4321';
  await pg.ctx.submitPin();
  await settle(10);
  assert.equal(pg.el('ap-code').textContent, '048213');
  assert.equal(pg.calls.find(c => c.path === '/api/identity/gate/verify').body.intent, 'approval-open:41');
  await pg.ctx.approveApproval();
  await settle(10);
  assert.equal(approveBody.code, '048213');
  pg.ctx.closeApproval();
  assert.equal(await done, false);   // closed by hand after approving in this test: the promise settles either way
});

test('another window signed in as a different account: this one signs out, never renews or adopts that session', async () => {
  const pg = page({ storage: { ...signedIn, dp_refresh: 'dpr_mine' }, routes: renewRoutes(p => {
    if (p === '/api/x') return { status: 401, json: { error: 'expired' } };
    if (p === '/api/identity/refresh' || p === '/api/identity/refresh/revoke') return { json: { token: 'fixture.token.other', refresh_token: 'dpr_x' } };
  }) });
  await settle(10);
  assert.equal(pg.appOpen(), true);
  // the other window: signs out (revoking ours) and signs in as user2
  pg.store.set('dp_did', 'did:key:zOther'); pg.store.set('dp_user', 'other'); pg.store.set('dp_token', 'other.token.z'); pg.store.set('dp_refresh', 'dpr_other');
  const before = pg.calls.length;
  await assert.rejects(pg.ctx.api('GET', '/api/x'), /session expired/);
  const after = pg.calls.slice(before).map(c => c.path);
  assert.ok(!after.includes('/api/identity/refresh'), JSON.stringify(after));
  assert.ok(!after.includes('/api/x'), 'no call is made with the other account');
  assert.equal(pg.authOpen(), true);
  assert.match(pg.el('auth-err').textContent, /another account/);
  assert.ok(!after.includes('/api/identity/refresh/revoke'), 'the other account\'s refresh token is not revoked');
  assert.equal(pg.store.get('dp_refresh'), 'dpr_other');
  assert.equal(pg.store.get('dp_token'), 'other.token.z');
  assert.equal(pg.store.get('dp_did'), 'did:key:zOther');
});

// ── A reply cut off by a network change is a dropped connection, never an empty vault or a sign-out ──
const dash = { balance_dd: 42, secrets: [{ name: 'fixture-secret', type: 'api_key', status: 'active', health: 'green', labels: [], contexts: [], silicons: [] }], health_summary: { green: 1 } };

test('a cut-off dashboard reply keeps the last vault and balance on screen and says it is offline', async () => {
  let cut = false;
  const pg = page({ storage: signedIn, routes: renewRoutes(p => p === '/api/demipass/dashboard' ? (cut ? { cut: true } : { json: dash }) : null) });
  await settle(10);
  pg.ctx.loadVault = pg.ctx.__realLoadVault;
  await pg.ctx.loadVault();
  assert.equal(pg.el('bal').textContent, 42);
  const list = pg.el('secret-list').innerHTML;
  assert.match(list, /fixture-secret/);
  cut = true;
  await pg.ctx.loadVault();
  assert.equal(pg.el('bal').textContent, 42, 'balance not zeroed');
  assert.equal(pg.el('secret-list').innerHTML, list, 'secrets not wiped');
  assert.match(pg.el('vault-note').textContent, /^Offline/);
  assert.equal(pg.authOpen(), false);
  cut = false;
  await pg.ctx.loadVault();
  assert.equal(pg.el('vault-note').textContent, '');
});

test('a cut-off first dashboard reply is an error, not "0 DD, no secrets"', async () => {
  const pg = page({ storage: signedIn, routes: renewRoutes(p => p === '/api/demipass/dashboard' ? { cut: true } : null) });
  await settle(10);
  pg.ctx.loadVault = pg.ctx.__realLoadVault;
  await pg.ctx.loadVault();
  assert.notEqual(pg.el('bal').textContent, 0);
  assert.doesNotMatch(pg.el('secret-list').innerHTML, /No secrets/);
  assert.match(pg.el('secret-list').innerHTML, /Connection dropped/);
});

test('a cut-off renewal reply keeps the session: no sign-out, the refresh token is kept', async () => {
  const pg = page({ storage: { ...signedIn, dp_token_at: String(Date.now() - DAY + 30 * 60 * 1000), dp_refresh: 'dpr_old' },
    routes: renewRoutes(p => p === '/api/identity/refresh' ? { cut: true } : (p === '/api/x' ? { json: { ok: true } } : null)) });
  await settle(10);
  assert.deepEqual(await pg.ctx.api('GET', '/api/x'), { ok: true });
  assert.equal(pg.authOpen(), false);
  assert.equal(pg.store.get('dp_refresh'), 'dpr_old');
  assert.equal(pg.store.get('dp_token'), 'fixture.token.a');
});

test('a PIN-gated action renews once on 401 instead of signing out', async () => {
  let n = 0;
  const pg = page({ storage: { ...signedIn, dp_refresh: 'dpr_old' }, routes: renewRoutes(p => {
    if (p === '/api/identity/refresh') return { json: { token: 'fixture.token.b', refresh_token: 'dpr_new' } };
    if (p === '/api/g') { n++; return n === 1 ? { status: 401, json: { error: 'expired' } } : { json: { ok: true } }; }
  }) });
  await settle(10);
  assert.deepEqual(await pg.ctx.apiGated('POST', '/api/g', {}, 'x'), { ok: true });
  assert.equal(pg.calls.filter(c => c.path === '/api/g')[1].auth, 'Bearer fixture.token.b');
  assert.equal(pg.authOpen(), false);
});

test('a rate-limited renewal (429) and a 401 whose renewal is offline keep the session', async () => {
  let refresh = { status: 429, json: { error: 'Rate limit exceeded' } };
  const pg = page({ storage: { ...signedIn, dp_token_at: String(Date.now() - DAY + 30 * 60 * 1000), dp_refresh: 'dpr_old' },
    routes: renewRoutes(p => p === '/api/identity/refresh' ? refresh : (p === '/api/x' ? { json: { ok: true } } : (p === '/api/y' ? { status: 401, json: { error: 'expired' } } : null))) });
  await settle(10);
  assert.deepEqual(await pg.ctx.api('GET', '/api/x'), { ok: true });
  assert.equal(pg.authOpen(), false, '429 is not a sign-out');
  refresh = { cut: true };
  await assert.rejects(pg.ctx.api('POST', '/api/y', {}), /check whether it went through/);
  assert.equal(pg.authOpen(), false, 'a 401 with an offline renewal is not a sign-out');
  assert.equal(pg.store.get('dp_refresh'), 'dpr_old');
});

test('a cut-off reply to a change says to check it went through; to a read, that it retries', async () => {
  const pg = page({ storage: signedIn, routes: renewRoutes(p => (p === '/api/x' ? { cut: true } : null)) });
  await settle(10);
  await assert.rejects(pg.ctx.api('GET', '/api/x'), /retrying/);
  await assert.rejects(pg.ctx.api('POST', '/api/x', {}), /check whether it went through/);
  await assert.rejects(pg.ctx.apiGated('DELETE', '/api/x', {}, 'x'), /check whether it went through/);
});

test('only the newest dashboard load writes the screen', async () => {
  const replies = [];
  const pg = page({ storage: signedIn, routes: renewRoutes(p => p === '/api/demipass/dashboard' ? new Promise(r => replies.push(r)) : null) });
  await settle(10);
  pg.ctx.loadVault = pg.ctx.__realLoadVault;
  const first = pg.ctx.loadVault(); await settle(); const second = pg.ctx.loadVault(); await settle();
  replies[1]({ json: dash }); await second;
  replies[0]({ cut: true }); await first;
  assert.equal(pg.el('bal').textContent, 42);
  assert.equal(pg.el('vault-note').textContent, '', 'an older cut-off load leaves no false Offline note');
});

// ── dormancy lock + device keys (red team items 4b, 8) ─────────────────────────────────────────────────────────
const fakePhone = (ctx, log) => ({
  status: () => JSON.stringify({ ok: true, enrolled: true, device_id: 'phone-1' }),
  sign: (id, kind, message) => { log.push({ kind, message }); setTimeout(() => ctx.DemiPassDeviceCb(id, JSON.stringify({ ok: true, signature: 'SIG-' + kind })), 0); },
});

test('idle past the lock time → locked on open; the phone\'s biometric unlocks (unlock:0), no PIN typed', async () => {
  const signs = [];
  const pg = page({ coldLock: true, storage: { ...signedIn, dp_last_active: String(Date.now() - 10 * 60 * 1000) }, routes: async (p, b) => {
    if (p.startsWith('/api/identity/trust')) return { json: trustOk };
    if (p === '/api/identity/gate/status') return { json: { pin_set: true } };
    if (p === '/api/identity/lock') return { json: { lock_after_sec: 300 } };
    if (p === '/api/identity/lock/now' || p === '/api/identity/lock/ping') return { json: { ok: true } };
    if (p === '/api/identity/device/challenge') return { json: { challenge_id: 5, message: 'demipass:gate:x:' + b.intent } };
    if (p === '/api/identity/gate/verify') return { json: { ok: true } };
    return { json: {} };
  } });
  let phoneAnswers = false;   // the phone holds its answer until the test has looked at the locked screen
  const phone = fakePhone(pg.ctx, signs), sign = phone.sign;
  phone.sign = (...a) => { const go = () => (phoneAnswers ? sign(...a) : setTimeout(go, 1)); go(); };
  pg.ctx.DemiPassDevice = phone;
  await settle(12);
  assert.equal(pg.el('lock-screen').style.display, 'flex', 'opens locked after 10 idle minutes');
  assert.equal(pg.appOpen(), false, 'vault hidden while locked');
  assert.ok(pg.calls.some(c => c.path === '/api/identity/lock/now'), 'the server is told the session locked');
  assert.equal(signs.length === 0 || signs[0].kind === 'P', true, 'the biometric prompt is up (presence key)');
  phoneAnswers = true; await new Promise(r => setTimeout(r, 20)); await settle(8);
  const v = pg.calls.find(c => c.path === '/api/identity/gate/verify');
  assert.deepEqual([v.body.gate, v.body.intent, v.body.signature], ['device', 'unlock:0', 'SIG-P'], 'presence key signed unlock:0');
  assert.equal(signs[0].kind, 'P');
  assert.equal(pg.el('lock-screen').style.display, 'none'); assert.equal(pg.appOpen(), true, 'unlocked');
});

test('item 8: a cold start with a stored session is locked even 30 s after the last activity (force-stop + relaunch)', async () => {
  const pg = page({ coldLock: true, storage: { ...signedIn, dp_last_active: String(Date.now() - 30 * 1000) }, routes: async (p) => {
    if (p.startsWith('/api/identity/trust')) return { json: trustOk };
    if (p === '/api/identity/gate/status') return { json: { pin_set: true } };
    if (p === '/api/identity/lock') return { json: { lock_after_sec: 300 } };
    return { json: { ok: true } };
  } });
  await settle(12);
  assert.equal(pg.appOpen(), false, 'nothing rendered');
  assert.equal(pg.el('lock-screen').style.display, 'flex', 'locked on a cold start');
  assert.ok(pg.calls.some(c => c.path === '/api/identity/lock/now'), 'the server is told');
});

test('item 8: a password sign-in on this page opens unlocked; coming back within the lock time stays open, past it locks', async () => {
  const pg = page({ coldLock: true, routes: async (p) => {
    if (p === '/api/identity/auth-fingerprint') return { json: { token: 'fixture.token.b', did: 'did:key:zFixture' } };
    if (p.startsWith('/api/identity/trust')) return { json: trustOk };
    if (p === '/api/identity/gate/status') return { json: { pin_set: true } };
    if (p === '/api/identity/lock') return { json: { lock_after_sec: 300 } };
    return { json: { ok: true } };
  } });
  pg.el('auth-user').value = 'fixture'; pg.el('auth-pass').value = 'hunter22';
  await pg.ctx.login(); await settle(12);
  assert.equal(pg.appOpen(), true, 'a fresh sign-in is not locked');
  pg.ctx.idleCheck(); assert.equal(pg.appOpen(), true, 'within the grace period');
  pg.store.set('dp_last_active', String(Date.now() - 10 * 60 * 1000));
  // As if the app sat in the background past the lock time: the last activity is old.
  vm.runInContext('lockState.last = Date.now() - 10 * 60 * 1000; idleCheck();', pg.ctx);
  assert.equal(pg.el('lock-screen').style.display, 'flex', 'locked on return past the grace period');
});

test('428 device_required on an approval → the linked phone signs it (D) and the call is retried with the signature', async () => {
  const signs = []; let approves = 0;
  const pg = page({ storage: signedIn, routes: async (p, b) => {
    if (p.startsWith('/api/identity/trust')) return { json: trustOk };
    if (p === '/api/identity/gate/status') return { json: { pin_set: true } };
    if (p === '/api/identity/device/challenge') { assert.deepEqual([b.purpose, b.intent, b.bind], ['approve', 'fill:9', 'https://login.example.com']); return { json: { challenge_id: 7, message: 'demipass:approve:x:fill:9:n:https://login.example.com' } }; }
    if (p === '/api/blindkey/fill/9/approve') {
      approves++;
      if (!b || !b.device_signature) return { status: 428, json: { error: 'approve from your phone', device_required: true, challenge: { purpose: 'approve', intent: 'fill:9', bind: 'https://login.example.com' } } };
      assert.deepEqual([b.device_challenge_id, b.device_signature], [7, 'SIG-D']);
      return { json: { ok: true, status: 'approved' } };
    }
    return { json: { ok: true } };
  } });
  pg.ctx.DemiPassDevice = fakePhone(pg.ctx, signs);
  await settle();
  const d = await pg.ctx.apiGated('POST', '/api/blindkey/fill/9/approve', null, 'Fill?');
  assert.equal(d.status, 'approved'); assert.equal(approves, 2); assert.equal(signs[0].kind, 'D');
  assert.match(signs[0].message, /login\.example\.com$/, 'the phone signed text naming what is approved');
});

test('428 with no linked phone in this browser → a clear refusal, nothing signed', async () => {
  const pg = page({ storage: signedIn, routes: async (p) => {
    if (p.startsWith('/api/identity/trust')) return { json: trustOk };
    if (p === '/api/identity/gate/status') return { json: { pin_set: true } };
    if (p === '/api/blindkey/fill/9/approve') return { status: 428, json: { device_required: true, challenge: { purpose: 'approve', intent: 'fill:9', bind: '' } } };
    return { json: { ok: true } };
  } });
  await settle();
  await assert.rejects(pg.ctx.apiGated('POST', '/api/blindkey/fill/9/approve', null, 'Fill?'), /linked phone/);
});

test('locking closes an open approval sheet and refuses approvals until unlocked (#47 review H2)', async () => {
  const pg = page({ storage: signedIn, routes: async (p) => {
    if (p.startsWith('/api/identity/trust')) return { json: trustOk };
    if (p === '/api/identity/gate/status') return { json: { pin_set: true } };
    return { json: { ok: true } };
  } });
  await settle();
  pg.el('modal-approval').classList.add('show');
  pg.ctx.lockNow(); await settle();
  assert.equal(pg.shown('modal-approval'), false, 'approval sheet closed');
  assert.equal(pg.el('lock-screen').style.display, 'flex');
  await assert.rejects(pg.ctx.apiGated('POST', '/api/blindkey/approvals/1/approve', { code: '123456' }, 'x'), /locked/);
  assert.ok(!pg.calls.some(c => c.path === '/api/blindkey/approvals/1/approve'), 'nothing sent while locked');
});

test('423 locked from the server → the phone unlocks (biometric) and the approval is retried', async () => {
  const signs = []; let approves = 0;
  const pg = page({ storage: signedIn, routes: async (p, b) => {
    if (p.startsWith('/api/identity/trust')) return { json: trustOk };
    if (p === '/api/identity/gate/status') return { json: { pin_set: true } };
    if (p === '/api/identity/device/challenge') return { json: { challenge_id: 3, message: 'demipass:' + b.purpose + ':' + b.intent } };
    if (p === '/api/identity/gate/verify') return { json: { ok: true } };
    if (p === '/api/blindkey/approvals/4/approve') { approves++; return approves === 1 ? { status: 423, json: { locked: true, error: 'unlock DemiPass on your phone first' } } : { json: { ok: true } }; }
    return { json: { ok: true } };
  } });
  pg.ctx.DemiPassDevice = fakePhone(pg.ctx, signs);
  await settle();
  const d = await pg.ctx.apiGated('POST', '/api/blindkey/approvals/4/approve', { code: '1' }, 'Approve');
  assert.equal(d.ok, true); assert.equal(approves, 2);
  assert.equal(signs[0].kind, 'P'); assert.match(signs[0].message, /unlock:0/);
});

// ── Pair in person (QR, red team item 6) ──
test('a scanned pairing URL joins and asks for the code on their screen (the scanner is never shown one)', async () => {
  const pg = page({ storage: signedIn, routes: async (p, b) => {
    if (p.startsWith('/api/identity/trust')) return { json: trustOk };
    if (p === '/api/identity/gate/status') return { json: { pin_set: true } };
    if (p === '/api/network/pair/join') { assert.equal(b.token, 'https://demipass.com/pair#123456789012.AAAAAAAAAAAAAAAAAAAAAA'); return { json: { ok: true, pair_id: 123456789012, status: 'joined', role: 'scanned', other: 'kyle', code: null, type_code: true, you_confirmed: false, they_confirmed: false } }; }
    return { json: { ok: true } };
  } });
  await settle();
  await pg.ctx.handleScannedData('https://demipass.com/pair#123456789012.AAAAAAAAAAAAAAAAAAAAAA');
  await settle();
  const body = pg.el('pair-body').innerHTML;
  assert.match(body, /<b>kyle<\/b>/); assert.match(body, /id="pair-code"/); assert.match(body, /Type the 6-digit code/);
  assert.ok(pg.shown('modal-pair'));
  assert.ok(!pg.calls.some(c => c.path === '/api/demipass/store'), 'a pairing QR is never treated as a deposit');
});

test('the shower sees the code and is told to show it, not read it out', async () => {
  const pg = page({ storage: signedIn, routes: async (p) => {
    if (p.startsWith('/api/identity/trust')) return { json: trustOk };
    if (p === '/api/identity/gate/status') return { json: { pin_set: true } };
    return { json: { ok: true } };
  } });
  await settle();
  vm.runInContext("pairState={pair_id:12,status:'joined',role:'shown',other:'kyle',code:'037654',you_confirmed:false,they_confirmed:false}; pairRender()", pg.ctx);
  const body = pg.el('pair-body').innerHTML;
  assert.match(body, /037 654/); assert.match(body, /they type it on their phone/); assert.doesNotMatch(body, /id="pair-code"/);
});

test('the scanner confirms with the typed code; it goes through the PIN/phone gate and ends on "paired"', async () => {
  let sent = null;
  const pg = page({ storage: signedIn, routes: async (p, b) => {
    if (p.startsWith('/api/identity/trust')) return { json: trustOk };
    if (p === '/api/identity/gate/status') return { json: { pin_set: true } };
    if (p === '/api/network/pair/12/confirm') { sent = b; return { json: { ok: true, pair_id: 12, status: 'confirmed', role: 'scanned', other: 'kyle', you_confirmed: true, they_confirmed: true, connected: true } }; }
    return { json: { ok: true } };
  } });
  await settle();
  vm.runInContext("pairState={pair_id:12,status:'joined',role:'scanned',other:'kyle',code:null,type_code:true,you_confirmed:false,they_confirmed:false}; pairRender()", pg.ctx);
  pg.el('pair-code').value = '12';
  await pg.ctx.pairConfirm(); await settle();
  assert.equal(sent, null, 'fewer than 6 digits is not sent');
  assert.match(pg.el('pair-msg').textContent, /6 digits/);
  pg.el('pair-code').value = '037 654';
  await pg.ctx.pairConfirm(); await settle();
  assert.deepEqual(sent, { code: '037654' });
  assert.match(pg.el('pair-msg').textContent, /Paired/);
});

test('the share picker lists only people paired in person', async () => {
  const pg = page({ storage: signedIn, routes: async (p) => {
    if (p.startsWith('/api/identity/trust')) return { json: trustOk };
    if (p === '/api/identity/gate/status') return { json: { pin_set: true } };
    if (p === '/api/network') return { json: { ok: true, me: {}, people: [{ username: 'kyle', confirmed: true }, { username: 'k-y-l-e', confirmed: false }], agents: [], incoming: [], outgoing: [], topups: {} } };
    return { json: { ok: true } };
  } });
  await settle();
  vm.runInContext('netData=null', pg.ctx);
  await pg.ctx.openShare('wifi', 'share');
  const opts = pg.el('sh-to').innerHTML;
  assert.match(opts, /kyle/); assert.doesNotMatch(opts, /k-y-l-e/);
});

test('a closed pairing scan does not leave the deposit scanner in pairing mode (#52 review)', async () => {
  const pg = page({ storage: signedIn, routes: async (p) => {
    if (p.startsWith('/api/identity/trust')) return { json: trustOk };
    if (p === '/api/identity/gate/status') return { json: { pin_set: true } };
    return { json: { ok: true } };
  } });
  await settle();
  pg.ctx.navigator.mediaDevices = { getUserMedia: async () => { throw new Error('no camera here'); } };
  await pg.ctx.pairScan(); await settle();
  assert.equal(pg.el('scan-title').textContent, 'Scan their pairing code');
  pg.ctx.stopScan(); pg.ctx.closeModal();
  await pg.ctx.startScan(); await settle();
  assert.equal(pg.el('scan-title').textContent, 'Scan QR Deposit');
  assert.equal(vm.runInContext('scanFor', pg.ctx), 'deposit');
});

// ── Delayed transfers (red team item 6) ──
test('a waiting transfer is listed with Cancel for both sides; Cancel calls the cancel route', async () => {
  let cancelled = null;
  const pg = page({ storage: signedIn, routes: async (p) => {
    if (p.startsWith('/api/identity/trust')) return { json: trustOk };
    if (p === '/api/identity/gate/status') return { json: { pin_set: true } };
    if (p === '/api/blindkey/shares') return { json: { ok: true, given: [], received: [] } };
    if (p === '/api/blindkey/transfers') return { json: { ok: true, transfers: [
      { id: 7, direction: 'incoming', secret: 'wifi', from: 'kyle', to: 'me', status: 'pending', execute_at: '2026-11-07T01:00:00Z', can_cancel: true },
      { id: 8, direction: 'outgoing', secret: 'panel', from: 'me', to: 'kyle', status: 'done', execute_at: '2026-11-06T01:00:00Z' } ] } };
    if (p === '/api/blindkey/transfers/7/cancel') { cancelled = 7; return { json: { ok: true } }; }
    return { json: { ok: true } };
  } });
  await settle();
  vm.runInContext('vaultOpen = true', pg.ctx);
  await pg.ctx.loadShares(); await settle();
  const h = pg.el('share-requests').innerHTML;
  assert.match(h, /<b>@kyle<\/b> is transferring <b>wifi<\/b> to you/); assert.match(h, /Cancel transfer/); assert.doesNotMatch(h, /panel/, 'finished transfers are not listed as waiting');
  await pg.ctx.cancelTransfer(7); await settle();
  assert.equal(cancelled, 7);
});

// ── Vouching (red team item 6) ──
test('an introduction shows the voucher and the other person; Accept goes through the PIN gate', async () => {
  let accepted = null;
  const pg = page({ storage: signedIn, routes: async (p) => {
    if (p.startsWith('/api/identity/trust')) return { json: trustOk };
    if (p === '/api/identity/gate/status') return { json: { pin_set: true } };
    if (p === '/api/network/vouches/4/accept') { accepted = 4; return { json: { ok: true, connected: false } }; }
    return { json: { ok: true } };
  } });
  await settle();
  vm.runInContext("vouchData={vouches:[{id:4,role:'introduced',voucher:'cara',other:'<img src=x onerror=alert(1)>',note:'',status:'pending',you_accepted:false}]}", pg.ctx);
  const h = pg.ctx.networkSection({ people: [], agents: [], incoming: [], outgoing: [], topups: {}, me: {} });
  assert.match(h, /<b>@cara<\/b> introduces/); assert.doesNotMatch(h, /<img/, 'names are escaped');
  await pg.ctx.vouchAct(4, true); await settle();
  assert.equal(accepted, 4);
});

// ── Leak scanner token requests (red team item 5) ──
test('a scan-token request shows its labels (escaped) and Approve goes through the PIN gate', async () => {
  let approved = null;
  const pg = page({ storage: signedIn, routes: async (p) => {
    if (p.startsWith('/api/identity/trust')) return { json: trustOk };
    if (p === '/api/identity/gate/status') return { json: { pin_set: true } };
    if (p === '/api/blindkey/leak-scan/token-requests') return { json: { ok: true, requests: [{ id: 3, labels: ['ci-dustforge', '<b>x</b>'], requested_by: 'pane', status: 'pending' }] } };
    if (p === '/api/blindkey/leak-scan/token-requests/3/approve') { approved = 3; return { json: { ok: true } }; }
    return { json: { ok: true } };
  } });
  await settle();
  await pg.ctx.loadScanRequests();
  const h = pg.el('scan-requests').innerHTML;
  assert.match(h, /ci-dustforge/); assert.doesNotMatch(h, /<b>x<\/b>/, 'labels are escaped');
  await pg.ctx.scanDecide(3, true); await settle();
  assert.equal(approved, 3);
});

// ── Waiting changes to the wallet (red team item 9) ──
test('waiting changes are listed; on the linked phone Cancel signs with P and posts the challenge nonce, no session', async () => {
  const signs = [], posts = [];
  const pg = page({ storage: signedIn, routes: async (p, b, o) => {
    if (p.startsWith('/api/identity/trust')) return { json: trustOk };
    if (p === '/api/identity/gate/status') return { json: { pin_set: true } };
    if (p === '/api/identity/holds') return { json: { ok: true, holds: [
      { id: '123456789012', kind: 'pin-reset', status: 'pending', created_at: '2026-11-07T01:00:00Z', ready_at: '2026-11-09T01:00:00Z', what: 'a PIN reset with your account password' },
      { id: '210987654321', kind: 'enrol', status: 'pending', created_at: '2026-11-07T01:00:00Z', ready_at: '2026-11-09T01:00:00Z', what: 'a new phone', label: '<img src=x onerror=alert(1)>', fingerprint: '0123456789abcdef' } ] } };
    if (p === '/api/identity/holds/challenge') { posts.push({ p, b, auth: (o.headers || {}).Authorization || null }); return { json: { ok: true, challenge: 'N'.repeat(32), message: 'demipass:recovery-cancel:did:key:zX:pin-reset:' + b.hold_id + ':' + 'N'.repeat(32) } }; }
    if (p.endsWith('/cancel')) { posts.push({ p, b, auth: (o.headers || {}).Authorization || null }); return { json: { ok: true } }; }
    return { json: { ok: true } };
  } });
  pg.ctx.DemiPassDevice = fakePhone(pg.ctx, signs);
  await settle();
  await pg.ctx.loadHolds(); await settle();
  const h = pg.el('holds').innerHTML;
  assert.equal(pg.el('holds-wrap').style.display, 'block');
  assert.match(h, /a PIN reset with your account password/); assert.match(h, /Cancel it/); assert.match(h, /let it in now/);
  assert.match(h, /code 0123456789abcdef/); assert.doesNotMatch(h, /<img src=x/, 'the new phone\'s label is escaped');
  await pg.ctx.cancelHold('123456789012'); await settle();
  assert.equal(signs.length, 1); assert.equal(signs[0].kind, 'P', 'a cancel is signed by the presence key');
  const cancel = posts.find(x => x.p === '/api/identity/holds/123456789012/cancel');
  assert.ok(cancel, 'the cancel route was called');
  assert.equal(cancel.b.challenge, 'N'.repeat(32)); assert.equal(cancel.b.device_id, 'phone-1'); assert.equal(cancel.b.signature, 'SIG-P');
  assert.equal(cancel.auth, null, 'the cancel carries no session (it must work when the session was ended)');
});

test('in a browser without the app, waiting changes say to cancel on a linked phone (no Cancel button)', async () => {
  const pg = page({ storage: signedIn, routes: async (p) => {
    if (p.startsWith('/api/identity/trust')) return { json: trustOk };
    if (p === '/api/identity/gate/status') return { json: { pin_set: true } };
    if (p === '/api/identity/holds') return { json: { ok: true, holds: [{ id: '123456789012', kind: 'recovery', status: 'pending', created_at: 'x', what: 'a recovery of your wallet' }] } };
    return { json: { ok: true } };
  } });
  await settle(); await pg.ctx.loadHolds(); await settle();
  assert.match(pg.el('holds').innerHTML, /Cancel it in the DemiPass app on a linked phone/); assert.doesNotMatch(pg.el('holds').innerHTML, /cancelHold\(/);
});

test('signed out, the linked phone asks with D (no session) and shows what waits on the sign-in screen', async () => {
  const signs = [];
  const pg = page({ storage: {}, routes: async (p, b) => {
    if (p === '/api/identity/holds/challenge') return { json: { ok: true, challenge: 'A'.repeat(32), message: 'demipass:alerts:did:key:zX:phone-1:' + 'A'.repeat(32) } };
    if (p === '/api/identity/holds/alerts') return { json: { ok: true, holds: [{ id: '123456789012', kind: 'recovery', status: 'pending', created_at: 'x', what: 'a recovery of your wallet by your guardians' }] } };
    return { json: {} };
  } });
  pg.ctx.DemiPassDevice = fakePhone(pg.ctx, signs);
  await pg.ctx.checkLoginHolds(); await settle();
  assert.equal(signs[0].kind, 'D', 'the alerts check is signed by the device key (no prompt)');
  assert.match(pg.el('auth-holds').innerHTML, /a recovery of your wallet by your guardians/); assert.match(pg.el('auth-holds').innerHTML, /Cancel it/);
});

test('signed out, a new mail forwarding rule shows on the sign-in screen from the alerts call (item 6b, #70 M3), escaped', async () => {
  const pg = page({ storage: {}, routes: async (p) => {
    if (p === '/api/identity/holds/challenge') return { json: { ok: true, challenge: 'A'.repeat(32), message: 'demipass:alerts:did:key:zX:phone-1:' + 'A'.repeat(32) } };
    if (p === '/api/identity/holds/alerts') return { json: { ok: true, holds: [], notices: [{ kind: 'forward', rule_id: 3, forward_to: 'x<img src=y>@evil.example', filter_from: '*', since: '2026-11-07 12:00:00' }] } };
    return { json: {} };
  } });
  pg.ctx.DemiPassDevice = fakePhone(pg.ctx, []);
  await pg.ctx.checkLoginHolds(); await settle();
  const h = pg.el('auth-holds').innerHTML;
  assert.match(h, /Mail forwarding turned on/); assert.match(h, /x&lt;img src=y&gt;@evil\.example/); assert.doesNotMatch(h, /<img/);
});

test('a PIN reset with the password on a linked phone asks the phone first; declined → it waits (202) and says until when', async () => {
  const sent = []; let alerted = '';
  const pg = page({ storage: signedIn, routes: async (p, b) => {
    if (p.startsWith('/api/identity/trust')) return { json: trustOk };
    if (p === '/api/identity/gate/status') return { json: { pin_set: true } };
    if (p === '/api/identity/device/challenge') return { json: { challenge_id: 9, message: 'demipass:gate:x:pin-reset:0' } };
    if (p === '/api/identity/pin') { sent.push(b); return { status: 202, json: { ok: true, pending: true, hold_id: '123456789012', ready_at: '2026-11-09T01:00:00Z' } }; }
    return { json: { ok: true, holds: [] } };
  } });
  pg.ctx.DemiPassDevice = { status: () => JSON.stringify({ ok: true, enrolled: true, device_id: 'phone-1' }),
    sign: (id) => setTimeout(() => pg.ctx.DemiPassDeviceCb(id, JSON.stringify({ ok: false, error: 'cancelled' })), 0) };
  pg.ctx.alert = (m) => { alerted = String(m); };
  await settle();
  pg.el('pin-cur').value = ''; pg.el('pin-change-pw').value = 'hunter22'; pg.el('pin-change-new').value = '5555'; pg.el('pin-change-confirm').value = '5555';
  await pg.ctx.savePinChange(); await settle();
  assert.equal(sent.length, 1); assert.equal(sent[0].device_challenge_id, undefined, 'declined on the phone: sent without a phone proof');
  assert.match(alerted, /waits 48 hours/); assert.doesNotMatch(alerted, /^PIN changed/);
});

// ── Guardian recovery (red team item 9, step 3) ──
test('a guardian sees the recovery ask (owner escaped) and Approve sends the typed code through the PIN/phone gate', async () => {
  const sent = [];
  const pg = page({ storage: signedIn, routes: async (p, b) => {
    if (p.startsWith('/api/identity/trust')) return { json: trustOk };
    if (p === '/api/identity/gate/status') return { json: { pin_set: true } };
    if (p === '/api/identity/guardians') return { json: { ok: true, active: false, guardians: [], guarding: [{ id: 4, owner: 'kyle', status: 'active' }] } };
    if (p === '/api/identity/recovery/asks') return { json: { ok: true, asks: [{ id: '123456789012', owner: '<b>kyle</b>', status: 'pending', new_phone: { fingerprint: 'aabbccddeeff0011' }, i_approved: false }] } };
    if (p.endsWith('/approve')) { sent.push(b); return { json: { ok: true, status: 'pending' } }; }
    return { json: { ok: true } };
  } });
  await settle(); await pg.ctx.loadGuardians(); await settle();
  const h = pg.el('guardians-box').innerHTML;
  assert.match(h, /asks to recover their wallet/); assert.match(h, /aabbccddeeff0011/); assert.doesNotMatch(h, /<b>kyle<\/b> asks/, 'the owner name is escaped');
  assert.match(h, /told you the 6-digit code themselves/); assert.match(h, /Decline — stop it/);
  pg.el('rc-123456789012').value = '482913';
  await pg.ctx.recoveryApprove('123456789012'); await settle();
  assert.equal(sent.length, 1); assert.equal(sent[0].code, '482913');
});

test('the recovering phone: start makes recovery keys, shows the code; finish signs with them, commits them, signs in', async () => {
  const calls = [];
  const store = {};
  const pg = page({ storage: store, routes: async (p, b) => {
    calls.push(p);
    if (p === '/api/identity/recovery/challenge') return { json: { ok: true, challenge: 'C'.repeat(32), message: 'demipass:recovery-start:aaron:' + 'C'.repeat(32) } };
    if (p === '/api/identity/recovery/start') return { status: 202, json: { ok: true, request_id: '123456789012', code: '482913', fingerprint: '0011223344556677' } };
    if (p.startsWith('/api/identity/recovery/status')) return { json: { ok: true, status: 'quorum', approvals: 2, needed: 2, ready_at: '2020-01-01T00:00:00Z' } };
    if (p.endsWith('/complete-challenge')) return { json: { ok: true, challenge: 'D'.repeat(32), message: 'demipass:recovery-complete:did:key:zX:123456789012:' + 'D'.repeat(32) } };
    if (p.endsWith('/complete')) return { json: { ok: true, completed: true } };
    if (p === '/api/identity/auth-fingerprint') return { json: { ok: true, token: 'new.token', did: 'did:key:zX' } };
    return { json: {} };
  } });
  const bridged = [];
  pg.ctx.DemiPassDevice = {
    status: () => JSON.stringify({ ok: true, enrolled: false }),
    recoveryKeys: (id, msg) => { bridged.push(['keys', msg]); setTimeout(() => pg.ctx.DemiPassDeviceCb(id, JSON.stringify({ ok: true, device_id: 'newdevice01', key_d: 'KD', key_p: 'KP', sig_d: 'SD', sig_p: 'SP', label: 'Pixel' })), 0); },
    recoverySign: (id, msg) => { bridged.push(['sign', msg]); setTimeout(() => pg.ctx.DemiPassDeviceCb(id, JSON.stringify({ ok: true, sig_d: 'SD2', sig_p: 'SP2' })), 0); },
    commitRecovery: () => { bridged.push(['commit']); return '{"ok":true}'; }, abandonRecovery: () => '{"ok":true}',
  };
  await pg.ctx.openRecover(); await settle();
  pg.el('rec-user').value = 'Aaron';
  await pg.ctx.startRecover(); await settle();
  assert.equal(bridged[0][0], 'keys'); assert.match(bridged[0][1], /^demipass:recovery-start:aaron:/);
  assert.match(pg.el('recover-box').innerHTML, /482913/); assert.match(pg.el('recover-box').innerHTML, /Finish/);
  pg.el('rec-pw').value = 'newpassword1'; pg.el('rec-pw2').value = 'newpassword1';
  await pg.ctx.finishRecover(); await settle();
  assert.deepEqual(bridged.map(x => x[0]), ['keys', 'sign', 'commit']);
  assert.ok(calls.includes('/api/identity/recovery/123456789012/complete'));
  assert.equal(pg.ctx.localStorage.getItem('dp_recovery'), null, 'the finished recovery is forgotten');
});

test('a newer page on the server: reload with ?v=<stamp> on return, never in the middle of a step, once per stamp', async () => {
  const pg = page({ storage: signedIn, routes: async (p) => {
    if (p.startsWith('/api/identity/trust')) return { json: trustOk };
    if (p === '/api/identity/gate/status') return { json: { pin_set: true } };
    return { json: { ok: true } };
  } });
  await settle(12);
  const replaced = [];
  let serverLm = 'Sat, 07 Nov 2026 20:23:44 GMT';
  pg.ctx.document.lastModified = new Date('2026-11-07T20:23:44Z').toString();
  Object.assign(pg.ctx.location, { pathname: '/vault-mobile.html', hash: '', replace: u => replaced.push(u) });
  const realFetch = pg.ctx.fetch;
  pg.ctx.fetch = async (url, o = {}) => (o.method === 'HEAD' ? { status: 200, headers: { get: k => (k === 'last-modified' ? serverLm : null) } } : realFetch(url, o));
  const store = new Map(); pg.ctx.sessionStorage = { getItem: k => (store.has(k) ? store.get(k) : null), setItem: (k, v) => store.set(k, String(v)) };

  assert.equal(await pg.ctx.reloadIfStale(), false, 'same page: nothing');
  serverLm = 'Sat, 07 Nov 2026 21:00:00 GMT';
  pg.el('modal-pin-change').classList.add('show');
  assert.equal(await pg.ctx.reloadIfStale(), false, 'a sheet is open: wait');
  pg.el('modal-pin-change').classList.remove('show');
  assert.equal(await pg.ctx.reloadIfStale(), true, 'newer and idle: reload');
  assert.deepEqual(replaced, ['/vault-mobile.html?v=' + Date.parse(serverLm)]);
  assert.equal(await pg.ctx.reloadIfStale(), false, 'once per stamp: a cache that still answers old cannot loop');
  // Locked: nothing is open behind the lock, so even with a sheet flag it reloads (next stamp).
  serverLm = 'Sat, 07 Nov 2026 22:00:00 GMT';
  pg.el('modal-pin-change').classList.add('show');
  vm.runInContext('lockState.locked = true;', pg.ctx);
  assert.equal(await pg.ctx.reloadIfStale(), true, 'locked: reload');
});

test('a PIN step in progress blocks the reload until it settles', async () => {
  const pg = page({ storage: signedIn, routes: async (p) => {
    if (p.startsWith('/api/identity/trust')) return { json: trustOk };
    if (p === '/api/identity/gate/status') return { json: { pin_set: true } };
    return { json: { ok: true } };
  } });
  await settle(12);
  pg.ctx.document.lastModified = new Date('2026-11-07T20:00:00Z').toString();
  Object.assign(pg.ctx.location, { pathname: '/vault-mobile.html', hash: '', replace: () => {} });
  const realFetch = pg.ctx.fetch;
  pg.ctx.fetch = async (url, o = {}) => (o.method === 'HEAD' ? { status: 200, headers: { get: () => 'Sat, 07 Nov 2026 21:00:00 GMT' } } : realFetch(url, o));
  pg.ctx.unlockWithPin('Do the thing', 'refill:1');   // a PIN sheet waits for the owner
  await settle();
  assert.equal(await pg.ctx.reloadIfStale(), false, 'PIN sheet pending');
});

test('item 8 (#73 review): the lock screen signs out to the password; a session ending while locked leaves no lock behind', async () => {
  const pg = page({ coldLock: true, storage: signedIn, routes: async (p) => {
    if (p.startsWith('/api/identity/trust')) return { json: trustOk };
    if (p === '/api/identity/gate/status') return { json: { pin_set: true } };
    if (p === '/api/identity/lock') return { json: { lock_after_sec: 300 } };
    return { json: { ok: true } };
  } });
  await settle(12);
  assert.equal(pg.el('lock-screen').style.display, 'flex');
  pg.ctx.logout(); await settle();
  assert.equal(pg.el('lock-screen').style.display, 'none', 'no lock screen over the sign-in');
  assert.equal(pg.authOpen(), true, 'sign-in shown');
  assert.equal(vm.runInContext('lockState.locked', pg.ctx), false);
});

test('item 8 (#73 review): background covers the vault; back within the grace period uncovers, past it locks first', async () => {
  let vis = 'visible';
  const pg = page({ storage: signedIn, routes: async (p) => {
    if (p.startsWith('/api/identity/trust')) return { json: trustOk };
    if (p === '/api/identity/gate/status') return { json: { pin_set: true } };
    if (p === '/api/identity/lock') return { json: { lock_after_sec: 300 } };
    return { json: { ok: true } };
  } });
  Object.defineProperty(pg.ctx.document, 'visibilityState', { get: () => vis, configurable: true });
  await settle(12);
  assert.equal(pg.appOpen(), true);
  vis = 'hidden'; pg.fire('visibilitychange');
  assert.equal(pg.el('privacy-cover').style.display, 'block', 'covered in the background');
  vis = 'visible'; pg.fire('visibilitychange');
  assert.equal(pg.el('privacy-cover').style.display, 'none', 'back within the grace period: uncovered');
  assert.notEqual(pg.el('lock-screen').style.display, 'flex', '…and not locked');
  vis = 'hidden'; pg.fire('visibilitychange');
  vm.runInContext('lockState.last = Date.now() - 10 * 60 * 1000;', pg.ctx);   // away past "Lock after"
  vis = 'visible'; pg.fire('visibilitychange');
  assert.equal(pg.el('lock-screen').style.display, 'flex', 'past the grace period: locked');
  assert.equal(pg.appOpen(), false, 'vault hidden behind the lock');
});
