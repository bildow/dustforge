#!/usr/bin/env node
'use strict';
// leak-scan — does any of my DemiPass vault values appear in these files? (red team item 5)
//   node bin/leak-scan.js [--strict] [--incremental <state.json>] <path>...
//        exit 0 clean, 1 a value was found, 2 the scan could not run (or, with --strict, a file could not be scanned)
//        --strict       the deploy gate and CI: nothing is skipped (no directory but .git; a file too large → exit 2)
//        --incremental  only the bytes appended since the last run (append-only logs such as transcripts); offsets
//                       are kept in <state.json> and advanced only after a clean scan
//   node bin/leak-scan.js --request [--no-wait] <dir> <label>...
//        ask for one scan token per label; the owner approves in the DemiPass app; each token is written to
//        <dir>/<label>.token (0600) and never printed. Asks with the owner's DemiPass session (DEMIPASS_TOKEN, or the
//        SDK credentials file ~/.config/demipass/credentials.json). The request is kept in <dir>/.pending-<id>.json
//        (0600) and waits a day for the owner: this waits up to 15 minutes (--no-wait: not at all), and any later
//        --claim picks the tokens up once approved. Exit 3: still waiting for the owner.
//   node bin/leak-scan.js --claim <dir>
//        claim every pending request in <dir> the owner has approved (the daily timer runs this first).
//   node bin/leak-scan.js --scrub-request [--no-wait] <dir> <ref>
//        ask for a scrub token for ONE vault entry (approved in the app like a scan token; written to
//        <dir>/scrub-<ref>.token). For a leaked value that is kept, not rotated: "contained".
//   node bin/leak-scan.js --scrub [--dry-run] [--all] <path>...
//        with a scrub token (DEMIPASS_SCAN_TOKEN_FILE): find that entry's value in these files and overwrite each copy
//        in place with '*' of the same length — the file keeps its size, layout and inode, so a log or transcript
//        another process is appending to stays whole. Text files only (a binary copy is reported, never written).
//        Before writing, the bytes on disk are compared with what was read; a changed file is left and counted. At the
//        end the server is told the counts; with nothing left, the entry shows as contained. Prints paths and counts,
//        never a value. --dry-run: find and count, write nothing, do not finish. --all: also enter node_modules, .cache …
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
// One claim attempt for a pending request file: 'done' (tokens written, file removed), 'waiting', or 'gone' (denied or
// expired: file removed).
async function claimOne(dir, file) {
  const p = JSON.parse(fs.readFileSync(file, 'utf8'));
  const c = await fetch(API + `/api/demipass/leak-scan/token-requests/${p.request_id}/claim`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ claim_secret: p.claim_secret }) });
  const cd = await c.json().catch(() => ({}));
  if (c.status === 202) return 'waiting';
  // Only an answer that the request is over ends it; a busy or broken server keeps it for the next run (#92 review M3).
  if (c.status === 404 || c.status === 410) {
    fs.rmSync(file, { force: true });
    if (/denied/i.test(cd.error || '')) for (const l of p.labels || []) fs.writeFileSync(path.join(dir, `.denied-${l}`), new Date().toISOString() + '\n', { mode: 0o600 });
    console.error(`leak-scan: request ${p.request_id} ended without tokens: ${cd.error || c.status}`); return 'gone';
  }
  if (!c.ok) { console.error(`leak-scan: request ${p.request_id}: claim answered ${c.status}; kept for the next run`); return 'waiting'; }
  for (const t of cd.tokens || []) {
    const out = path.join(dir, t.label + '.token');
    fs.writeFileSync(out, t.token + '\n', { mode: 0o600 }); fs.chmodSync(out, 0o600);
    console.log(`leak-scan: wrote ${out} (0600)`);
  }
  fs.rmSync(file, { force: true });
  return 'done';
}
const pendingFiles = (dir) => { try { return fs.readdirSync(dir).filter(f => /^\.pending-\d+\.json$/.test(f)).map(f => path.join(dir, f)); } catch (_) { return []; } };
async function claimPending(dir) {
  let waiting = 0;
  for (const f of pendingFiles(dir)) if (await claimOne(dir, f) === 'waiting') waiting++;
  return waiting;
}
async function requestTokens(dir, labels, { wait = true, scrubRef = null } = {}) {
  if (scrubRef !== null) { if (!dir || !/^[A-Za-z0-9-]{4,80}$/.test(scrubRef)) { console.error('usage: leak-scan --scrub-request [--no-wait] <dir> <ref>'); process.exit(2); } labels = ['scrub-' + scrubRef]; }
  else if (!dir || !labels.length || labels.some(l => !/^[A-Za-z0-9._-]{1,60}$/.test(l))) { console.error('usage: leak-scan --request [--no-wait] <dir> <label>... (labels: letters, digits, . _ -)'); process.exit(2); }
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const r = await fetch(API + '/api/demipass/leak-scan/token-requests', { method: 'POST', headers: { 'content-type': 'application/json', authorization: sessionHeader() }, body: JSON.stringify(scrubRef !== null ? { scrub_ref: scrubRef } : { labels }) });
  const d = await r.json().catch(() => ({}));
  if (r.status !== 202) throw new Error(`request refused: HTTP ${r.status}: ${d.error || ''}`);
  const file = path.join(dir, `.pending-${d.request_id}.json`);
  fs.writeFileSync(file, JSON.stringify({ request_id: d.request_id, claim_secret: d.claim_secret, labels, asked_at: new Date().toISOString() }) + '\n', { mode: 0o600 }); fs.chmodSync(file, 0o600);
  console.log(`leak-scan: asked for ${labels.length} scan token(s) (request ${d.request_id}) — approve it in the DemiPass app (Settings → Leak scanner); it waits a day`);
  const until = Date.now() + (wait ? 15 * 60 * 1000 : 0);
  do {
    if (wait) await new Promise(ok => setTimeout(ok, 4000));
    const st = await claimOne(dir, file);
    if (st === 'done') return;
    if (st === 'gone') throw new Error('the request was denied or expired');
  } while (Date.now() < until);
  console.log('leak-scan: still waiting for the owner; the next run (or --claim) picks the tokens up once approved');
  process.exit(3);
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
// After a hit the server lets the token finish the run ("draining"): the rest is scanned so the owner's "where?" names
// every copy, and the answer no longer depends on what is sent. An older server answers 401 after a hit: then stop.
let leak = false, revokedNote = null, draining = false, drainedFromStart = null;
async function post(auth, batch) {
  const r = await fetch(API + '/api/demipass/leak-scan', { method: 'POST', headers: { 'content-type': 'application/json', authorization: auth }, body: JSON.stringify({ chunks: batch }) });
  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(`scan refused: HTTP ${r.status}: ${d.error || ''}`);
  if (drainedFromStart === null) drainedFromStart = Boolean(d.already_found);   // the token's hit was before this run
  if (d.leak) { leak = true; revokedNote = d.note || 'a vault value was found; the owner has the details'; }
  draining = Boolean(d.draining);
}
// ── scrub ────────────────────────────────────────────────────────────────────────────────────────────────────────────
// Windows of CHUNK_BYTES with a 1 KiB overlap, cut on UTF-8 character boundaries, so the text sent decodes back to the
// same bytes and the server's byte offsets land exactly. A file that is not valid UTF-8 is still sent; every write is
// checked against the bytes read, so an offset that does not fit is never written.
function* scrubWindows(buf) {
  const OVER = 1024;
  let start = 0;
  while (start < buf.length) {
    let end = Math.min(buf.length, start + CHUNK_BYTES);
    while (end < buf.length && end > start && (buf[end] & 0xC0) === 0x80) end--;
    yield { start, end };
    if (end >= buf.length) break;
    let next = Math.max(start + 1, end - OVER);
    while (next < end && (buf[next] & 0xC0) === 0x80) next++;
    start = next;
  }
}
async function scrubPost(auth, batch) {
  for (let attempt = 0; ; attempt++) {
    const r = await fetch(API + '/api/demipass/leak-scan/scrub', { method: 'POST', headers: { 'content-type': 'application/json', authorization: auth }, body: JSON.stringify({ chunks: batch }) });
    const d = await r.json().catch(() => ({}));
    if (r.status === 429 && /Rate limit/.test(d.error || '') && attempt < 20) { await new Promise(ok => setTimeout(ok, 60000)); continue; }
    if (!r.ok) throw new Error(`scrub refused: HTTP ${r.status}: ${d.error || ''}`);
    return d.matches || [];
  }
}
async function scrub(args) {
  let dry = false;
  for (;;) { if (args[0] === '--dry-run') { dry = true; args.shift(); continue; } if (args[0] === '--all') { STRICT = true; args.shift(); continue; } break; }
  if (!args.length) { console.error('usage: leak-scan --scrub [--dry-run] [--all] <path>...'); process.exit(2); }
  const auth = authHeader();
  let filesRead = 0, filesChanged = 0, masked = 0, left = 0, bytesRead = 0;
  for (const t of args) for (const f of files(path.resolve(t))) {
    let buf; try { buf = fs.readFileSync(f); } catch (e) { skipped.push(`${f} (${e.code || e.message})`); continue; }
    filesRead++; bytesRead += buf.length;
    const binary = buf.subarray(0, 8192).includes(0);
    const wins = [...scrubWindows(buf)];
    const spans = new Map();   // absolute start → length (text files: these are written)
    const binHits = { u: new Set(), l: new Set() };   // binary files: only counted, never written
    for (let i = 0; i < wins.length;) {
      const batch = []; let size = 0;
      while (i < wins.length && batch.length < 140 && (size === 0 || size + (wins[i].end - wins[i].start) * (binary ? 2 : 1) <= BATCH_BYTES)) {
        const w = wins[i]; const part = buf.subarray(w.start, w.end);
        batch.push({ id: String(i), text: part.toString('utf8') });
        // A binary file is also sent byte for byte (latin1), so an ASCII value between invalid UTF-8 is found too.
        if (binary) batch.push({ id: i + ':l', text: part.toString('latin1') });
        size += part.length * (binary ? 2 : 1); i++;
      }
      for (const m of await scrubPost(auth, batch)) {
        const [wi, form] = String(m.chunk).split(':'); const w = wins[Number(wi)]; if (!w) continue;
        for (const [off, len] of m.at || []) {
          if (binary) { binHits[form === 'l' ? 'l' : 'u'].add(w.start + off); continue; }
          const s0 = w.start + off; const prev = spans.get(s0); if (prev === undefined || len > prev) spans.set(s0, len);
        }
      }
    }
    if (binary) {
      const n = Math.max(binHits.u.size, binHits.l.size);
      if (n) { left += n; console.log(`FOUND    ${f}: ${n} cop${n === 1 ? 'y' : 'ies'} in a binary file — not written (remove the file or rotate)`); }
      continue;
    }
    if (!spans.size) continue;
    if (dry) { masked += spans.size; console.log(`FOUND    ${f}: ${spans.size} cop${spans.size === 1 ? 'y' : 'ies'} (dry run)`); continue; }
    let fd; try { fd = fs.openSync(f, 'r+'); } catch (e) { left += spans.size; console.log(`LEFT     ${f}: ${spans.size} — cannot write (${e.code || e.message})`); continue; }
    let n = 0, stale = 0;
    try {
      for (const [s0, l0] of [...spans].sort((a, b) => a[0] - b[0])) {
        const now = Buffer.alloc(l0);
        const got = fs.readSync(fd, now, 0, l0, s0);
        // Only bytes that are still exactly what was read (and sent) are overwritten.
        if (got !== l0 || !now.equals(buf.subarray(s0, s0 + l0))) { stale++; continue; }
        fs.writeSync(fd, Buffer.alloc(l0, '*'), 0, l0, s0); n++;
      }
      fs.fsyncSync(fd);
    } finally { fs.closeSync(fd); }
    masked += n; left += stale; if (n) filesChanged++;
    console.log(`MASKED   ${f}: ${n} cop${n === 1 ? 'y' : 'ies'}${stale ? `, ${stale} left (the file changed there since it was read: run again)` : ''}`);
  }
  for (const k of skipped) console.log(`SKIPPED  ${k}`);
  console.log(`leak-scan: scrub ${dry ? '(dry run) ' : ''}read ${filesRead} files, ${bytesRead} bytes; ${dry ? 'found' : 'masked'} ${masked}, left ${left}${skipped.length ? `, ${skipped.length} files not read` : ''}`);
  if (dry) process.exit(masked || left ? 1 : 0);
  const r = await fetch(API + '/api/demipass/leak-scan/scrub/finish', { method: 'POST', headers: { 'content-type': 'application/json', authorization: auth },
    body: JSON.stringify({ files_read: filesRead, files_changed: filesChanged, copies_masked: masked, copies_left: left + skipped.length }) });
  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(`finish refused: HTTP ${r.status}: ${d.error || ''}`);
  console.log(d.contained ? `leak-scan: ${d.entry ? d.entry.name : 'the entry'} is contained (not rotated; backups still hold old copies)` : 'leak-scan: copies were left or files not read — the entry is not marked contained; this scrub token is spent');
  process.exit(left || skipped.length ? 1 : 0);
}
(async () => {
  if (process.argv[2] === '--scrub-request') {
    const noWait = process.argv[3] === '--no-wait';
    return requestTokens(process.argv[noWait ? 4 : 3], [], { wait: !noWait, scrubRef: process.argv[noWait ? 5 : 4] || '' });
  }
  if (process.argv[2] === '--scrub') return scrub(process.argv.slice(3));
  if (process.argv[2] === '--request') {
    const noWait = process.argv[3] === '--no-wait';
    return requestTokens(process.argv[noWait ? 4 : 3], process.argv.slice(noWait ? 5 : 4), { wait: !noWait });
  }
  if (process.argv[2] === '--claim') { const w = await claimPending(process.argv[3]); if (w) { console.log(`leak-scan: ${w} request(s) still waiting for the owner`); process.exit(3); } return; }
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
    if (leak && !draining) break scan;   // a hit revoked the token and the server will not finish the run: stop
    let from = 0;
    if (stateFile) {
      const size = fs.statSync(f).size, seen = Number(state[f]) || 0;
      from = seen <= size ? seen : 0;   // a file that shrank was replaced: scan it whole
      next[f] = size;
      if (from === size) continue;
    }
    nfiles++;
    for (const c of chunks(f, from)) {
      if (leak && !draining) break scan;
      const b = Buffer.byteLength(c.text);
      if (bytes + b > BATCH_BYTES || batch.length >= 150) await flush();
      batch.push(c); bytes += b; total += b;
    }
    if (stateFile) ending.push(f);
  }
  if (!leak || draining) await flush();
  if (stateFile && !leak) { for (const f of Object.keys(next)) if (!(f in state) || state[f] !== next[f]) { if (!ending.includes(f) && !done.includes(f)) done.push(f); } saveState(); }
  for (const k of skipped) console.log(`SKIPPED  ${k}`);
  // A run on a token that was already draining says nothing about this tree: the owner reads "where?" instead.
  const what = !leak ? 'clean' : drainedFromStart ? 'NOT CHECKED — this token found a leak earlier and only records copies for the owner now (DemiPass app → Settings → Leak scanner → "where?"); approve a new token to check this tree'
    : 'LEAK — ' + revokedNote + (draining ? ' (the rest of the run was scanned; every copy is listed for the owner)' : '');
  console.log(`leak-scan: ${nfiles} files, ${total} bytes, ${what}`);
  process.exit(leak ? 1 : (STRICT && skipped.length) ? 2 : 0);
})().catch(e => { console.error('leak-scan: ' + e.message); process.exit(2); });
