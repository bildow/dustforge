'use strict';
// node --test test/vault_ui.test.js — the phone vault's sign-in → PIN gate flow, run as the REAL page script
// (public/vault-mobile.html's inline <script>) inside a vm with a fake DOM, storage and fetch. No browser.
// Covers the mandatory-PIN entry gate: it fails closed when the PIN status is unknown, blocks until a PIN is
// set, and sign-out ends everything (sheets, typed password, pending promises, in-flight continuations).
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
  const calls = [];
  const ctx = {
    console, setTimeout, clearTimeout, setInterval: () => 0, clearInterval() {},
    alert: () => {}, confirm: () => true, prompt: () => null,
    localStorage: { getItem: k => (store.has(k) ? store.get(k) : null), setItem: (k, v) => store.set(k, String(v)), removeItem: k => store.delete(k) },
    document: {
      getElementById: el,
      querySelectorAll: sel => (sel === '.modal-bg' ? [...els.values()].filter(e => e.id.startsWith('modal-')) : []),
      addEventListener() {}, createElement: () => ({ set textContent(v) { this.innerHTML = String(v).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]); }, innerHTML: '' }),
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
  // Vault contents are not under test here.
  ctx.loadVault = async () => { ctx.__loads = (ctx.__loads || 0) + 1; };
  ctx.loadSiliconAgents = () => {};
  ctx.loadSmsStatus = async () => {};
  return { ctx, el, calls, store, shown: id => el(id).classList.contains('show'), appOpen: () => el('app').style.display === 'block', authOpen: () => el('auth').style.display === 'flex' };
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
      if (body.security_depth === 'standard' && !pinFresh) return { status: 403, json: { error: 'lowering needs pin', missing: ['pin'], required: ['pin'], weakens: ['reveal'] } };
      pinFresh = false; return { json: { ok: true } };
    }
    if (p === '/api/identity/gate/verify') { if (body.pin === '2468') { pinFresh = true; return { json: { ok: true } }; } return { status: 403, json: { error: 'incorrect PIN (4 tries left)', attempts_left: 4 } }; }
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
