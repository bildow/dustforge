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
function page({ storage = {}, routes, abortable = false } = {}) {
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
      return { status: r.status || 200, json: async () => (r.json === undefined ? {} : r.json) };
    },
  };
  if (abortable) ctx.AbortController = AbortController;   // an older WebView: AbortController, no AbortSignal.timeout
  vm.createContext(ctx);
  vm.runInContext(script, ctx, { filename: 'vault-mobile.inline.js' });
  // Vault contents are not under test here (the real loader stays reachable for the rendering test).
  ctx.__realLoadVault = ctx.loadVault;
  ctx.loadVault = async () => { ctx.__loads = (ctx.__loads || 0) + 1; };
  ctx.loadSiliconAgents = () => {};
  ctx.loadSmsStatus = async () => {};
  const key = k => { for (const f of listeners.keydown || []) f({ key: k }); };
  return { ctx, el, calls, store, intervals, qsa, key, timers, shown: id => el(id).classList.contains('show'), appOpen: () => el('app').style.display === 'block', authOpen: () => el('auth').style.display === 'flex' };
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
  assert.ok(hs.includes(`event.stopPropagation();showDetail(${lit})`), 'list row');
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
