// Browser check of the extension install page (public/extension.html): which path the page picks in real browsers,
// headed under a virtual display so user-agent data is a normal desktop browser's. Starts server.js on a throwaway DB.
//
//   xvfb-run -a node test/extension_page_e2e.mjs [--browser=firefox,zen,chrome,brave]
//
//   firefox  FIREFOX_BIN (~/.local/opt/firefox-*/firefox), GECKODRIVER (~/.local/opt/geckodriver-*/geckodriver)
//   zen      ZEN_BIN     (~/.local/opt/zen-*/zen)
//   chrome   CHROME_BIN  (/usr/bin/google-chrome, branded), PLAYWRIGHT_CORE (path to playwright-core)
//   chromium CHROMIUM_BIN (~/.local/opt/chrome-for-testing-*/chrome: reports only the Chromium brand)
//   brave    BRAVE_BIN   (/usr/bin/brave-browser)
//
// Firefox/Zen: the Firefox section only, its one button points at the signed .xpi, and that URL answers
// application/x-xpinstall in the browser. Chrome/Brave: the Chrome section only, titled for the browser, "Pending
// store review" and no store link, and the waitlist form stores the address (its API call is routed to the local
// server). Screenshots go to $SHOTS when set. Each browser gets a fresh temporary profile.
// Edge, Opera and Android Chrome are covered by emulated client hints in the branded Chrome run.
// Not covered here: clicking through the browser's own add-on install prompts (a manual check).

import { spawn } from 'node:child_process';
import { existsSync, readdirSync, mkdtempSync, rmSync, readFileSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const W = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const OPT = path.join(os.homedir(), '.local/opt');
const SHOTS = process.env.SHOTS || '';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const newest = (re, bin) => {
  if (!existsSync(OPT)) return null;
  const d = readdirSync(OPT).filter((n) => re.test(n)).sort().pop();
  return d && existsSync(path.join(OPT, d, bin)) ? path.join(OPT, d, bin) : null;
};
const BROWSERS = {
  firefox: { family: 'gecko', bin: () => process.env.FIREFOX_BIN || newest(/^firefox-/, 'firefox') },
  zen: { family: 'gecko', bin: () => process.env.ZEN_BIN || newest(/^zen-/, 'zen') },
  chrome: { family: 'chromium', name: 'Chrome', bin: () => process.env.CHROME_BIN || (existsSync('/usr/bin/google-chrome') ? '/usr/bin/google-chrome' : null) },
  chromium: { family: 'chromium', name: 'Chromium', bin: () => process.env.CHROMIUM_BIN || newest(/^chrome-for-testing-/, 'chrome') },
  brave: { family: 'chromium', name: 'Brave', bin: () => process.env.BRAVE_BIN || (existsSync('/usr/bin/brave-browser') ? '/usr/bin/brave-browser' : null) },
};
const want = (process.argv.find((a) => a.startsWith('--browser=')) || '--browser=firefox,zen,chrome,brave,chromium').split('=')[1].split(',');
const freePort = () => new Promise((resolve, reject) => {
  const s = net.createServer(); s.once('error', reject);
  s.listen(0, '127.0.0.1', () => { const { port } = s.address(); s.close(() => resolve(port)); });
});

let fails = 0;
const summary = [];
const check = (b, cond, m, detail = '') => {
  console.log(`${cond ? 'ok  ' : 'FAIL'} [${b}] ${m}${!cond && detail ? ` — ${detail}` : ''}`);
  if (!cond) fails++;
};

// ── server on a throwaway DB ──
const tmp = mkdtempSync(path.join(os.tmpdir(), 'dustforge-extpage-e2e-'));
const port = await freePort();
const BASE = `http://127.0.0.1:${port}`;
const env = { ...process.env, PORT: String(port), DB_PATH: path.join(tmp, 'dustforge.db'),
  IDENTITY_MASTER_KEY: Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString('hex'),
  STALWART_HOST: '127.0.0.1', STALWART_PORT: '1', SMTP_RELAY_HOST: '', SMTP_HOST: '127.0.0.1', SMTP_PORT: '9' };
if (!existsSync(path.join(W, 'node_modules'))) env.NODE_PATH = env.NODE_PATH || '/home/flimflam/project/dustforge/node_modules';
const srv = spawn(process.execPath, ['server.js'], { cwd: W, env, stdio: 'ignore' });
for (let i = 0; i < 80; i++) { try { await fetch(BASE + '/'); break; } catch { await sleep(250); } }
const RELEASE = JSON.parse(/<script type="application\/json" id="release">([\s\S]*?)<\/script>/
  .exec(readFileSync(path.join(W, 'public/extension.html'), 'utf8'))[1]);
const waitlistRows = () => {
  const Database = createRequire(path.join(W, 'server.js'))('better-sqlite3');
  const db = new Database(env.DB_PATH, { readonly: true });
  try { return db.prepare('SELECT email, browser FROM extension_waitlist').all(); } finally { db.close(); }
};

// What the page decided, read from the live DOM (a function body, run in the page).
const STATE = `
  var vis = function (id) { var e = document.getElementById(id); return !!e && !e.hidden && e.offsetParent !== null; };
  return { target: document.documentElement.dataset.target || null, ua: navigator.userAgent,
    brands: navigator.userAgentData ? navigator.userAgentData.brands.map(function (b) { return b.brand; }) : null,
    firefox: vis('sec-firefox'), chrome: vis('sec-chrome'), other: vis('sec-other'),
    ffTitle: document.getElementById('ff-title').textContent, ffHref: document.getElementById('ff-btn').getAttribute('href'),
    crTitle: document.getElementById('cr-title').textContent, pending: vis('cr-pending'), listed: vis('cr-listed'),
    storeLinks: Array.prototype.filter.call(document.querySelectorAll('a'), function (x) {
      return /chromewebstore|webstore/.test(x.href) && x.offsetParent !== null; }).length };`;
const XPI_TYPE = `return fetch(arguments[0]).then(function (r) { return r.headers.get('content-type'); });`;

async function gecko(name, binary) {
  const gdBin = process.env.GECKODRIVER || newest(/^geckodriver-/, 'geckodriver');
  if (!gdBin) { check(name, false, 'geckodriver found'); return; }
  const gport = await freePort();
  const gd = spawn(gdBin, ['--port', String(gport)], { env: { ...process.env, TMPDIR: mkdtempSync(path.join(tmp, name + '-')) }, stdio: 'ignore' });
  const gbase = `http://127.0.0.1:${gport}`;
  for (let i = 0; i < 100; i++) { try { await fetch(gbase + '/status'); break; } catch { await sleep(100); } }
  let sid = '';
  const cmd = async (method, p, body) => {
    const r = await fetch(gbase + p.replace('{sid}', sid), { method, headers: { 'content-type': 'application/json' }, body: body ? JSON.stringify(body) : undefined });
    const j = await r.json();
    if (j.value && j.value.error) throw new Error(`${p}: ${j.value.error}: ${j.value.message}`);
    return j.value;
  };
  try {
    const s = await cmd('POST', '/session', { capabilities: { alwaysMatch: { browserName: 'firefox', 'moz:firefoxOptions': { binary } } } });
    sid = s.sessionId;
    const version = `${s.capabilities.browserName} ${s.capabilities.browserVersion}`;
    await cmd('POST', '/session/{sid}/url', { url: BASE + '/extension' });
    let st = null;
    for (let i = 0; i < 40 && !(st && st.target); i++) { st = await cmd('POST', '/session/{sid}/execute/sync', { script: STATE, args: [] }); await sleep(100); }
    check(name, st.target === 'firefox', 'the page picks the Firefox path', JSON.stringify(st));
    check(name, st.firefox && !st.chrome && !st.other, 'only the Firefox section shows', JSON.stringify(st));
    check(name, st.ffTitle === 'Firefox and Zen', 'titled "Firefox and Zen"', st.ffTitle);
    check(name, st.ffHref === RELEASE.firefox.xpi, 'its one button points at the signed .xpi', st.ffHref);
    const ct = await cmd('POST', '/session/{sid}/execute/async', { script: `var done = arguments[1]; (function () { ${XPI_TYPE} }).apply(null, arguments).then(done, function (e) { done('error ' + e); });`, args: [st.ffHref] });
    check(name, ct === 'application/x-xpinstall', 'the .xpi answers application/x-xpinstall in the browser', ct);
    if (SHOTS) {
      try { writeFileSync(path.join(SHOTS, `extension-page-${name}.png`), Buffer.from(await cmd('GET', '/session/{sid}/screenshot'), 'base64')); }
      catch (e) { console.log(`note [${name}] no screenshot: ${e.message.slice(0, 90)}`); }
    }
    summary.push({ browser: name, version, ua: st.ua, target: st.target });
  } catch (e) {
    check(name, false, 'gecko run', e.message);
  } finally {
    if (sid) await cmd('DELETE', '/session/{sid}').catch(() => {});
    gd.kill();
  }
}

async function chromium(name, binary, expectName) {
  let chromiumLib;
  try { ({ chromium: chromiumLib } = createRequire(import.meta.url)(process.env.PLAYWRIGHT_CORE || 'playwright-core')); }
  catch { check(name, false, 'playwright-core found (set PLAYWRIGHT_CORE)'); return; }
  const ctx = await chromiumLib.launchPersistentContext(mkdtempSync(path.join(tmp, name + '-')), {
    executablePath: binary, headless: false, args: ['--no-first-run', '--no-default-browser-check'] });
  try {
    const p = ctx.pages()[0] || await ctx.newPage();
    // The page posts to the production API; send that one call to the local server instead.
    await p.route(RELEASE.waitlist_api, async (route) => {
      const req = route.request();
      if (req.method() === 'OPTIONS') return route.fulfill({ status: 204, headers: { 'access-control-allow-origin': '*', 'access-control-allow-headers': 'content-type', 'access-control-allow-methods': 'POST' } });
      const r = await fetch(BASE + '/api/extension/waitlist', { method: req.method(), headers: { 'content-type': 'application/json' }, body: req.postData() });
      return route.fulfill({ status: r.status, headers: { 'content-type': 'application/json', 'access-control-allow-origin': '*' }, body: await r.text() });
    });
    await p.goto(BASE + '/extension');
    await p.waitForFunction(() => document.documentElement.dataset.target);
    const st = await p.evaluate(new Function(STATE));
    const version = `${name} ${(/Chrome\/([\d.]+)/.exec(st.ua) || [])[1]}`;
    check(name, st.target === 'chrome', 'the page picks the Chrome Web Store path', JSON.stringify(st));
    check(name, st.chrome && !st.firefox && !st.other, 'only the Chrome section shows', JSON.stringify(st));
    check(name, st.crTitle.startsWith(expectName), `titled for ${expectName}`, st.crTitle);
    check(name, st.pending && !st.listed && st.storeLinks === 0, '"Pending store review" and no store link while pending', JSON.stringify(st));
    const email = `${name}-e2e@example.com`;
    await p.fill('#wait-email', email);
    await p.click('#wait-form button');
    await p.waitForFunction(() => /ok|err/.test(document.getElementById('wait-msg').className));
    const msg = await p.textContent('#wait-msg');
    check(name, /We.ll email you once/.test(msg), 'the waitlist form confirms', msg);
    const row = waitlistRows().find((r) => r.email === email);
    check(name, row && row.browser === expectName.toLowerCase(), `the address is stored for ${expectName.toLowerCase()}`, JSON.stringify(row));
    if (SHOTS) await p.screenshot({ path: path.join(SHOTS, `extension-page-${name}.png`), fullPage: true });
    summary.push({ browser: name, version, ua: st.ua, brands: st.brands, target: st.target });
    // Branded Chrome only: emulated client hints for browsers not installed here (Edge, Opera, Android Chrome).
    if (name === 'chrome') {
      const cdp = await ctx.newCDPSession(p);
      const V = '157.0.0.0';
      const cases = [
        { as: 'edge', ua: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${V} Safari/537.36 Edg/${V}`,
          brands: ['Microsoft Edge', 'Chromium'], mobile: false, platform: 'Windows', target: 'chrome', title: 'Edge' },
        { as: 'opera', ua: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${V} Safari/537.36 OPR/120.0.0.0`,
          brands: ['Opera', 'Chromium'], mobile: false, platform: 'Windows', target: 'other' },
        { as: 'android-chrome', ua: `Mozilla/5.0 (Linux; Android 15) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${V} Mobile Safari/537.36`,
          brands: ['Google Chrome', 'Chromium'], mobile: true, platform: 'Android', target: 'other', why: /do not run extensions/ },
        { as: 'android-tablet-desktop-site', ua: `Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${V} Safari/537.36`,
          brands: ['Google Chrome', 'Chromium'], mobile: false, platform: 'Android', target: 'other', why: /do not run extensions/ },
        { as: 'webview2', ua: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${V} Safari/537.36 Edg/${V}`,
          brands: ['Microsoft Edge WebView2', 'Microsoft Edge', 'Chromium'], mobile: false, platform: 'Windows', target: 'other' },
      ];
      for (const c of cases) {
        await cdp.send('Emulation.setUserAgentOverride', { userAgent: c.ua, userAgentMetadata: {
          brands: c.brands.map((b) => ({ brand: b, version: '157' })), fullVersion: V, platform: c.platform, platformVersion: '', architecture: 'x86', model: '', mobile: c.mobile } });
        await p.goto(BASE + '/extension');
        await p.waitForFunction(() => document.documentElement.dataset.target);
        const e = await p.evaluate(new Function(STATE));
        const why = await p.textContent('#other-why');
        const good = e.target === c.target && (!c.title || e.crTitle.startsWith(c.title)) && (!c.why || c.why.test(why)) && (c.target !== 'other' || (e.other && !e.chrome && !e.firefox));
        check(name, good, `emulated ${c.as} → ${c.target}${c.title ? ' (' + c.title + ')' : ''}`, JSON.stringify({ e, why }));
      }
      await cdp.send('Emulation.setUserAgentOverride', { userAgent: '' }).catch(() => {});
    }
  } catch (e) {
    check(name, false, 'chromium run', e.message);
  } finally {
    await ctx.close();
  }
}

try {
  for (const name of want) {
    const b = BROWSERS[name];
    if (!b) { check(name, false, 'known browser'); continue; }
    const bin = b.bin();
    if (!bin) { check(name, false, 'binary found'); continue; }
    if (b.family === 'gecko') await gecko(name, bin); else await chromium(name, bin, b.name);
  }
} finally {
  srv.kill();
  rmSync(tmp, { recursive: true, force: true });
}
console.log(JSON.stringify(summary, null, 1));
console.log(`${fails} failure(s)`);
process.exit(fails ? 1 : 0);
