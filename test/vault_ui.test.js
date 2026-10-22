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
function page({ storage = {}, routes } = {}) {
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
  const calls = [], intervals = [], listeners = {}, qsa = {};
  const ctx = {
    console, clearTimeout,
    setTimeout: (f, ms, ...a) => (ms > 5000 ? 0 : setTimeout(f, ms, ...a)),   // the 30 s reveal auto-hide never fires here
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
      const r = await routes(p, body, o);
      return { status: r.status || 200, json: async () => (r.json === undefined ? {} : r.json) };
    },
  };
  vm.createContext(ctx);
  vm.runInContext(script, ctx, { filename: 'vault-mobile.inline.js' });
  // Vault contents are not under test here (the real loader stays reachable for the rendering test).
  ctx.__realLoadVault = ctx.loadVault;
  ctx.loadVault = async () => { ctx.__loads = (ctx.__loads || 0) + 1; };
  ctx.loadSiliconAgents = () => {};
  ctx.loadSmsStatus = async () => {};
  const key = k => { for (const f of listeners.keydown || []) f({ key: k }); };
  return { ctx, el, calls, store, intervals, qsa, key, shown: id => el(id).classList.contains('show'), appOpen: () => el('app').style.display === 'block', authOpen: () => el('auth').style.display === 'flex' };
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

test('double-tap Unlock sends one PIN check; Cancel while it is in flight settles the reveal, no retry on the late proof', async () => {
  let release, verifies = 0;
  const pg = page({ storage: signedIn, routes: vaultRoutes((p) => {
    if (p === '/api/blindkey/reveal') return needPin();
    if (p === '/api/identity/gate/verify') { verifies++; return new Promise(r => { release = () => r({ json: { ok: true } }); }); }
  }) });
  await settle();
  const done = pg.ctx.revealSecret('sightless');
  await settle();
  assert.equal(pg.shown('modal-pin'), true);
  pg.el('pin-unlock').value = '2468';
  const a = pg.ctx.submitPin(), b = pg.ctx.submitPin();
  await settle();
  assert.equal(verifies, 1, 'the second tap sent nothing');
  pg.ctx.cancelPin();
  await done;
  assert.equal(pg.el('reveal-btn').textContent, 'Reveal', 'reveal settled, not stuck on Verifying');
  release(); await a; await b; await settle();
  assert.equal(pg.calls.filter(c => c.path === '/api/blindkey/reveal').length, 1, 'the late proof triggered no retry');
  assert.equal(pg.shown('modal-pin'), false);
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
  assert.ok(hs.includes(`event.stopPropagation();showDetail(${lit})`), 'list row');
  assert.ok(hs.includes(`revealSecret(${lit})`));
  assert.ok(hs.includes(`revokeSecret(${lit})`));
  assert.ok(hs.includes(`toggleFreeze(${lit},true)`));
  assert.ok(hs.includes(`setDepth(${lit},'elevated')`));
  for (const h of hs) assert.doesNotThrow(() => new Function(h), h);   // each handler parses whole: nothing broke out
  for (const html of [list, detail]) assert.doesNotMatch(html, /<img|<i>|<b>|<u>|<s>/, 'no markup from data');
});
