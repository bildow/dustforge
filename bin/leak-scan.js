#!/usr/bin/env node
'use strict';
// leak-scan — does any of my DemiPass vault values appear in these files? (red team item 5)
//   node bin/leak-scan.js [--strict] [--incremental <state.json>] <path>...
//        exit 0 clean, 1 a value was found, 2 the scan could not run (or, with --strict, a file could not be scanned)
//        --strict       the deploy gate and CI: nothing is skipped (no directory but .git; a file too large → exit 2)
//        --incremental  only the bytes appended since the last run (append-only logs such as transcripts); offsets
//                       are kept in <state.json> and advanced only after a clean scan
//   node bin/leak-scan.js --request <dir> <label>...
//        ask for one scan token per label; the owner approves in the DemiPass app; each token is written to
//        <dir>/<label>.token (0600) and never printed. Asks with the owner's DemiPass session (DEMIPASS_TOKEN, or the
//        SDK credentials file ~/.config/demipass/credentials.json); waits up to 15 minutes.
// The server does the matching (only it holds the values) and answers one bit — leak or clean. Which secret and where
// go to the owner only (mail and the app). This program never receives, holds or prints a value. Zero dependencies (Node ≥ 18), so CI and pane hooks can copy it as is.
// Scanning takes a scan token: DEMIPASS_SCAN_TOKEN, or DEMIPASS_SCAN_TOKEN_FILE (a 0600 file). A session token is
// refused by the server (no oracle for agents). A hit revokes the token: fix the leak, then request a new one.
// DEMIPASS_URL overrides the server.
const fs = require('fs'), path = require('path');

const API = (process.env.DEMIPASS_URL || 'https://api.dustforge.com').replace(/\/$/, '');
const CHUNK_BYTES = 256 * 1024, BATCH_BYTES = 1536 * 1024, MAX_FILE = 200 * 1024 * 1024;
const SKIP_DIRS = new Set(['.git', 'node_modules', '.cache', '__pycache__', '.venv', 'dist', 'build']);

// The scan token ("Scan <token>").
function authHeader() {
  if (process.env.DEMIPASS_SCAN_TOKEN) return 'Scan ' + process.env.DEMIPASS_SCAN_TOKEN.trim();
  const f = process.env.DEMIPASS_SCAN_TOKEN_FILE;
  if (f) {
    const st = fs.statSync(f);
    if (st.mode & 0o077) throw new Error(`${f} must not be readable by group/other (chmod 600)`);
    return 'Scan ' + fs.readFileSync(f, 'utf8').trim();
  }
  throw new Error('set DEMIPASS_SCAN_TOKEN or DEMIPASS_SCAN_TOKEN_FILE (get one with --request)');
}
// The owner's session, only to ASK for tokens.
function sessionHeader() {
  if (process.env.DEMIPASS_TOKEN) return 'Bearer ' + process.env.DEMIPASS_TOKEN.trim();
  const creds = process.env.DEMIPASS_CREDENTIALS || path.join(process.env.XDG_CONFIG_HOME || path.join(require('os').homedir(), '.config'), 'demipass', 'credentials.json');
  try { const c = JSON.parse(fs.readFileSync(creds, 'utf8')); if (c && c.token) return 'Bearer ' + c.token; } catch (_) {}
  throw new Error('sign in with the DemiPass SDK (or set DEMIPASS_TOKEN) to ask for scan tokens');
}
async function requestTokens(dir, labels) {
  if (!dir || !labels.length || labels.some(l => !/^[A-Za-z0-9._-]{1,60}$/.test(l))) { console.error('usage: leak-scan --request <dir> <label>... (labels: letters, digits, . _ -)'); process.exit(2); }
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const r = await fetch(API + '/api/demipass/leak-scan/token-requests', { method: 'POST', headers: { 'content-type': 'application/json', authorization: sessionHeader() }, body: JSON.stringify({ labels }) });
  const d = await r.json().catch(() => ({}));
  if (r.status !== 202) throw new Error(`request refused: HTTP ${r.status}: ${d.error || ''}`);
  console.log(`leak-scan: asked for ${labels.length} scan token(s) (request ${d.request_id}) — approve it in the DemiPass app (Settings → Leak scanner)`);
  const until = Date.now() + 15 * 60 * 1000;
  while (Date.now() < until) {
    await new Promise(ok => setTimeout(ok, 4000));
    const c = await fetch(API + `/api/demipass/leak-scan/token-requests/${d.request_id}/claim`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ claim_secret: d.claim_secret }) });
    const cd = await c.json().catch(() => ({}));
    if (c.status === 202) continue;
    if (!c.ok) throw new Error(`not approved: ${cd.error || c.status}`);
    for (const t of cd.tokens || []) {
      const out = path.join(dir, t.label + '.token');
      fs.writeFileSync(out, t.token + '\n', { mode: 0o600 }); fs.chmodSync(out, 0o600);
      console.log(`leak-scan: wrote ${out} (0600)`);
    }
    return;
  }
  throw new Error('the request expired before it was approved');
}
let STRICT = false;
const skipped = [];
function* files(p) {
  let st; try { st = fs.lstatSync(p); } catch (_) { return; }
  if (st.isSymbolicLink()) return;   // what it points at is scanned where it lives (or is outside what was asked)
  if (st.isDirectory()) { const b = path.basename(p); if (b === '.git' || (!STRICT && SKIP_DIRS.has(b))) return; for (const e of fs.readdirSync(p).sort()) yield* files(path.join(p, e)); return; }
  if (!st.isFile() || st.size === 0) return;
  if (st.size > MAX_FILE) { skipped.push(`${p} (${st.size} bytes, too large)`); return; }
  yield p;
}
// Chunks with a label: "file:first-last" (lines) for text, "file@offset" (bytes) for binary or incremental reads. A
// binary file is scanned too, byte for byte as latin1 (an ASCII value in it is found as it is; #45 review M2). A value
// split across a chunk border is caught by the 512-byte overlap each chunk carries from the one before.
function* chunks(file, from = 0) {
  let buf = fs.readFileSync(file);
  // An incremental read starts 512 bytes before the last offset, so a value split across it is still whole.
  if (from > 0) { from = Math.max(0, Math.min(from, buf.length) - 512); buf = buf.subarray(from); }
  const binary = buf.subarray(0, 8192).includes(0);
  if (binary || from > 0) {
    for (let o = 0; o < buf.length; o += CHUNK_BYTES) {
      const start = Math.max(0, o - 512);
      const part = buf.subarray(start, o + CHUNK_BYTES);
      // Binary: byte for byte (latin1), and as UTF-16LE too, so a value written in UTF-16 is found.
      yield { id: `${file}@${from + o}`, text: binary ? part.toString('latin1') + '\n' + part.toString('utf16le') : part.toString('utf8') };
    }
    return;
  }
  const lines = buf.toString('utf8').split('\n');
  let cur = [], size = 0, first = 1, carry = '';
  for (let i = 0; i < lines.length; i++) {
    cur.push(lines[i]); size += Buffer.byteLength(lines[i]) + 1;
    if (size >= CHUNK_BYTES || i === lines.length - 1) {
      const body = cur.join('\n');
      yield { id: `${file}:${first}-${i + 1}`, text: carry + body };
      carry = body.slice(-512); cur = []; size = 0; first = i + 2;
    }
  }
}
let leak = false, revokedNote = null;
async function post(auth, batch) {
  const r = await fetch(API + '/api/demipass/leak-scan', { method: 'POST', headers: { 'content-type': 'application/json', authorization: auth }, body: JSON.stringify({ chunks: batch }) });
  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(`scan refused: HTTP ${r.status}: ${d.error || ''}`);
  if (d.leak) { leak = true; revokedNote = d.note || 'a vault value was found; the owner has the details'; }
}
(async () => {
  if (process.argv[2] === '--request') return requestTokens(process.argv[3], process.argv.slice(4));
  const args = process.argv.slice(2);
  let stateFile = null;
  for (;;) {
    if (args[0] === '--strict') { STRICT = true; args.shift(); continue; }
    if (args[0] === '--incremental') { args.shift(); stateFile = args.shift(); continue; }
    break;
  }
  const targets = args;
  if (!targets.length || (stateFile !== null && !stateFile)) { console.error('usage: leak-scan [--strict] [--incremental <state.json>] <path>...'); process.exit(2); }
  const tok = authHeader();
  let state = {};
  if (stateFile) { try { state = JSON.parse(fs.readFileSync(stateFile, 'utf8')) || {}; } catch (_) { state = {}; } }
  const next = {};
  let batch = [], bytes = 0, nfiles = 0, total = 0, done = [];
  // Offsets are saved as soon as a file's last chunk has been scanned clean, so a run stopped by the daily budget
  // picks up where it stopped the next day.
  const saveState = () => { if (!stateFile || leak || !done.length) return; for (const f of done) state[f] = next[f]; done = [];
    fs.writeFileSync(stateFile + '.tmp', JSON.stringify(state), { mode: 0o600 }); fs.renameSync(stateFile + '.tmp', stateFile); };
  let ending = [];
  const flush = async () => { if (batch.length) { await post(tok, batch); batch = []; bytes = 0; done.push(...ending); ending = []; saveState(); } };
  scan: for (const t of targets) for (const f of files(path.resolve(t))) {
    if (leak) break scan;   // a hit revoked the token: stop
    let from = 0;
    if (stateFile) {
      const size = fs.statSync(f).size, seen = Number(state[f]) || 0;
      from = seen <= size ? seen : 0;   // a file that shrank was replaced: scan it whole
      next[f] = size;
      if (from === size) continue;
    }
    nfiles++;
    for (const c of chunks(f, from)) {
      if (leak) break scan;
      const b = Buffer.byteLength(c.text);
      if (bytes + b > BATCH_BYTES || batch.length >= 150) await flush();
      batch.push(c); bytes += b; total += b;
    }
    if (stateFile) ending.push(f);
  }
  if (!leak) await flush();
  if (stateFile && !leak) { for (const f of Object.keys(next)) if (!(f in state) || state[f] !== next[f]) { if (!ending.includes(f) && !done.includes(f)) done.push(f); } saveState(); }
  for (const k of skipped) console.log(`SKIPPED  ${k}`);
  console.log(`leak-scan: ${nfiles} files, ${total} bytes, ${leak ? 'LEAK — ' + revokedNote : 'clean'}`);
  process.exit(leak ? 1 : (STRICT && skipped.length) ? 2 : 0);
})().catch(e => { console.error('leak-scan: ' + e.message); process.exit(2); });
