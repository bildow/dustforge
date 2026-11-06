#!/usr/bin/env node
'use strict';
// leak-scan — does any of my DemiPass vault values appear in these files? (red team item 5)
//   node bin/leak-scan.js <path>...      exit 0 clean, 1 a value was found, 2 the scan could not run
//   node bin/leak-scan.js --request <dir> <label>...
//        ask for one scan token per label; the owner approves in the DemiPass app; each token is written to
//        <dir>/<label>.token (0600) and never printed. Asks with the owner's DemiPass session (DEMIPASS_TOKEN, or the
//        SDK credentials file ~/.config/demipass/credentials.json); waits up to 15 minutes.
// The server does the matching (only it holds the values) and answers with refs, names and file:lines — this program
// never receives, holds or prints a value. Zero dependencies (Node ≥ 18), so CI and pane hooks can copy it as is.
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
function* files(p) {
  let st; try { st = fs.lstatSync(p); } catch (_) { return; }
  if (st.isSymbolicLink()) return;
  if (st.isDirectory()) { if (SKIP_DIRS.has(path.basename(p))) return; for (const e of fs.readdirSync(p).sort()) yield* files(path.join(p, e)); return; }
  if (st.isFile() && st.size > 0 && st.size <= MAX_FILE) yield p;
}
// Line-bounded chunks with a "file:first-last" label. A value split across a chunk border is caught by the 512-byte
// overlap each chunk carries from the one before.
function* chunks(file) {
  const buf = fs.readFileSync(file);
  if (buf.subarray(0, 8192).includes(0)) return;   // binary
  const text = buf.toString('utf8');
  const lines = text.split('\n');
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
let revokedNote = null;
async function post(auth, batch) {
  const r = await fetch(API + '/api/demipass/leak-scan', { method: 'POST', headers: { 'content-type': 'application/json', authorization: auth }, body: JSON.stringify({ chunks: batch }) });
  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(`scan refused: HTTP ${r.status}: ${d.error || ''}`);
  if (d.token_revoked) revokedNote = d.note;
  return d.hits || [];
}
(async () => {
  if (process.argv[2] === '--request') return requestTokens(process.argv[3], process.argv.slice(4));
  const targets = process.argv.slice(2);
  if (!targets.length) { console.error('usage: leak-scan <path>...'); process.exit(2); }
  const tok = authHeader();
  let batch = [], bytes = 0, nfiles = 0, total = 0;
  const hits = [];
  const flush = async () => { if (batch.length) { hits.push(...await post(tok, batch)); batch = []; bytes = 0; } };
  scan: for (const t of targets) for (const f of files(path.resolve(t))) {
    if (revokedNote) break scan;   // a hit revoked the token: report what was found, stop
    nfiles++;
    for (const c of chunks(f)) {
      if (revokedNote) break scan;
      const b = Buffer.byteLength(c.text);
      if (bytes + b > BATCH_BYTES || batch.length >= 150) await flush();
      batch.push(c); bytes += b; total += b;
    }
  }
  if (!revokedNote) await flush();
  for (const h of hits) console.log(`LEAK  ${h.ref || '(no ref)'}  ${h.name}  at ${h.chunk}  ×${h.count}`);
  console.log(`leak-scan: ${nfiles} files, ${total} bytes, ${hits.length} hit${hits.length === 1 ? '' : 's'}`);
  if (revokedNote) console.log('leak-scan: ' + revokedNote);
  process.exit(hits.length ? 1 : 0);
})().catch(e => { console.error('leak-scan: ' + e.message); process.exit(2); });
