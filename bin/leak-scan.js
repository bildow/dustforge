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
// Windows cut on UTF-8 character boundaries, overlapping by more than the longest form the server looks for (it says how
// long: max_form_bytes), so no copy is split unseen. Every window is sent as UTF-8 with each byte that is not part of
// valid UTF-8 replaced by one 0x1A — the same length, so the server's byte offsets are exact (#98 review H2, re-review).
// A window that had such bytes is also sent byte for byte (latin1, mapped back exactly) to find a copy written in
// Latin-1. A window too big for one request is split. Every write checks the bytes on disk are still the ones read.
const SCRUB_TEXT_WINDOW = 192 * 1024, SCRUB_BIN_WINDOW = 96 * 1024;   // JSON escaping at most ×6: a window fits a request
const SCRUB_BODY_MAX = 1400 * 1024;                                    // under nginx's and the server's body limits
function* scrubWindows(buf, size, overlap, from = 0, to = buf.length) {
  let start = from;
  while (start < to) {
    let end = Math.min(to, start + size);
    const cut = end;
    while (end < to && end > start && (buf[end] & 0xC0) === 0x80) end--;
    if (end <= start + overlap) end = cut;   // no character boundary near: cut where the window ends (re-review L)
    yield { start, end };
    if (end >= to) break;
    let next = Math.max(start + 1, end - overlap);
    while (next < end && (buf[next] & 0xC0) === 0x80) next++;
    start = next;
  }
}
// Bytes that are not part of valid UTF-8 → 0x1A, one for one (so offsets in the text are offsets in the file).
function utf8Clean(raw) {
  const out = Buffer.from(raw); let bad = 0; const at = [];
  for (let i = 0; i < out.length;) {
    const b = out[i];
    if (b < 0x80) { i++; continue; }
    const n = b >= 0xC2 && b <= 0xDF ? 2 : b >= 0xE0 && b <= 0xEF ? 3 : b >= 0xF0 && b <= 0xF4 ? 4 : 0;
    let ok = n > 0 && i + n <= out.length;
    for (let k = 1; ok && k < n; k++) if ((out[i + k] & 0xC0) !== 0x80) ok = false;
    if (ok && n === 3) { const c = out[i + 1]; if ((b === 0xE0 && c < 0xA0) || (b === 0xED && c > 0x9F)) ok = false; }
    if (ok && n === 4) { const c = out[i + 1]; if ((b === 0xF0 && c < 0x90) || (b === 0xF4 && c > 0x8F)) ok = false; }
    if (ok) { i += n; continue; }
    out[i] = 0x1A; bad++; at.push(i); i++;
  }
  return { out, bad, at };
}
// Compressed or packed data: a copy inside cannot be seen, so the file is not "read" (#98 re-review N4).
function packed(p, head) {
  // Git objects in a work tree's .git or a bare repo (name.git/objects, Forgejo's layout), loose or packed (#98 round 3 R1).
  if (/(^|[\/])[^\/]*\.git[\/]objects[\/]/.test(p) || /[\/]objects[\/]([0-9a-f]{2}[\/][0-9a-f]{38}|pack[\/])/.test(p)) return 'git object';
  const m = (sig) => head.length >= sig.length && sig.every((x, i) => head[i] === x);
  if (m([0x1f, 0x8b])) return 'gzip'; if (m([0x28, 0xb5, 0x2f, 0xfd])) return 'zstd'; if (m([0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00])) return 'xz';
  if (m([0x42, 0x5a, 0x68])) return 'bzip2'; if (m([0x50, 0x4b, 0x03, 0x04])) return 'zip'; if (m([0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c])) return '7z';
  if (m([0x04, 0x22, 0x4d, 0x18])) return 'lz4'; if (m([0x50, 0x41, 0x43, 0x4b])) return 'git pack';
  if (head.length >= 2 && head[0] === 0x78 && ((head[0] << 8) | head[1]) % 31 === 0) return 'zlib';
  if (m([0x25, 0x50, 0x44, 0x46])) return 'pdf (deflated)'; if (m([0x89, 0x50, 0x4e, 0x47])) return 'png (deflated)'; if (m([0x4c, 0x50, 0x4b, 0x53, 0x48, 0x48, 0x52, 0x48])) return 'journal';
  return null;
}
// The server counts UTF-8 bytes of the text it got; for latin1 text each raw byte ≥ 0x80 was two of them.
function latin1Offset(raw, utf8Bytes) {
  let b = 0, i = 0;
  while (i < raw.length && b < utf8Bytes) { b += raw[i] < 0x80 ? 1 : 2; i++; }
  return i;
}
let maxFormBytes = 0;
async function scrubPost(auth, batch) {
  for (let attempt = 0; ; attempt++) {
    const r = await fetch(API + '/api/demipass/leak-scan/scrub', { method: 'POST', headers: { 'content-type': 'application/json', authorization: auth }, body: JSON.stringify({ chunks: batch }) });
    const d = await r.json().catch(() => ({}));
    if (r.status === 429 && /Rate limit/.test(d.error || '') && attempt < 20) { await new Promise(ok => setTimeout(ok, 60000)); continue; }
    if (!r.ok) throw new Error(`scrub refused: HTTP ${r.status}: ${d.error || ''}`);
    if (d.max_form_bytes) maxFormBytes = Math.max(maxFormBytes, d.max_form_bytes);
    return d.matches || [];
  }
}
// What a scrub reads: every regular file under the roots (with --all, node_modules, .cache … and .git too). Whatever it
// does not read is counted, so the run cannot claim "contained" over it (#98 review M2): a skipped directory, a file
// too large, a symlink to something outside the roots.
function scrubFiles(roots, all) {
  const out = [], notRead = [];
  const real = roots.map(r => { try { return fs.realpathSync(r); } catch (_) { return path.resolve(r); } });
  const inside = (p) => real.some(r => p === r || p.startsWith(r + path.sep));
  const walk = (p) => {
    let st; try { st = fs.lstatSync(p); } catch (_) { return; }
    if (st.isSymbolicLink()) { let t = null; try { t = fs.realpathSync(p); } catch (_) {} if (!t || !inside(t)) notRead.push(`${p} (a link to outside what was asked)`); return; }
    if (st.isDirectory()) { if (!all && SKIP_DIRS.has(path.basename(p))) { notRead.push(`${p} (skipped: --all reads it)`); return; } let es; try { es = fs.readdirSync(p).sort(); } catch (e) { notRead.push(`${p} (${e.code || e.message})`); return; } for (const e of es) walk(path.join(p, e)); return; }
    if (!st.isFile() || st.size === 0) return;
    if (st.size > MAX_FILE) { notRead.push(`${p} (${st.size} bytes, too large)`); return; }
    out.push(p);
  };
  for (const r of roots) walk(path.resolve(r));
  return { out, notRead };
}
async function scrub(args) {
  let dry = false, all = false;
  for (;;) { if (args[0] === '--dry-run') { dry = true; args.shift(); continue; } if (args[0] === '--all') { all = true; args.shift(); continue; } break; }
  if (!args.length) { console.error('usage: leak-scan --scrub [--dry-run] [--all] <path>...'); process.exit(2); }
  const auth = authHeader();
  await scrubPost(auth, [{ id: '-', text: '' }]);   // learns max_form_bytes (and that the token works) before reading anything
  const overlap = Math.max(1024, maxFormBytes + 16);
  if (overlap * 2 > SCRUB_BIN_WINDOW) throw new Error('the value is too long to look for in windows');
  const { out: list, notRead } = scrubFiles(args, all);
  let filesRead = 0, filesChanged = 0, masked = 0, left = 0, bytesRead = 0;
  for (const f of list) {
    let fd, st, buf;
    try {
      fd = fs.openSync(f, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW); st = fs.fstatSync(fd);
      buf = Buffer.alloc(st.size); let got = 0; while (got < st.size) { const n = fs.readSync(fd, buf, got, st.size - got, got); if (!n) break; got += n; } buf = buf.subarray(0, got);
    } catch (e) { notRead.push(`${f} (${e.code || e.message})`); continue; } finally { if (fd !== undefined) fs.closeSync(fd); }
    filesRead++; bytesRead += buf.length;
    const kind = packed(f, buf.subarray(0, 16));
    if (kind) { filesRead--; bytesRead -= buf.length; notRead.push(`${f} (${kind}: compressed or packed, copies inside cannot be seen)`); continue; }
    const binary = buf.subarray(0, 8192).includes(0);
    // Windows, each with its texts; one too big for a request is split (the overlap keeps every copy whole in a half).
    const wins = [];
    const add = (a, b) => {
      const raw = buf.subarray(a, b), { out, bad, at: badAt } = utf8Clean(raw);
      const parts = [{ view: 'u', text: out.toString('utf8') }];
      if (bad) parts.push({ view: 'l', text: raw.toString('latin1') });
      const bytes = parts.reduce((n, p) => n + Buffer.byteLength(JSON.stringify(p.text)) + 32, 0);
      if (bytes > SCRUB_BODY_MAX && b - a > 4 * overlap) {
        const half = a + Math.floor((b - a) / 2); let mid = half;
        while (mid > a + overlap && (buf[mid] & 0xC0) === 0x80) mid--;
        if (mid <= a + overlap) mid = half;   // no character boundary near: cut in the middle anyway
        add(a, Math.min(b, mid + overlap)); add(mid, b); return;
      }
      if (bytes > SCRUB_BODY_MAX) throw new Error(`${f}: a piece of it does not fit one request`);
      wins.push({ start: a, end: b, parts, bytes, badAt });
    };
    try { for (const w of scrubWindows(buf, binary ? SCRUB_BIN_WINDOW : SCRUB_TEXT_WINDOW, overlap)) add(w.start, w.end); }
    catch (e) { filesRead--; bytesRead -= buf.length; notRead.push(`${f} (${e.message.replace(f + ': ', '')})`); continue; }   // round 3 L1: that file is not read; the run goes on
    const spans = new Map();                 // exact spans (absolute start → length): written, in a text file
    const binSeen = new Set();
    let batch = [], size = 0;
    const flush = async () => {
      if (!batch.length) return;
      const res = await scrubPost(auth, batch); batch = []; size = 0;
      for (const m of res) {
        const [wi, view] = String(m.chunk).split(':'); const w = wins[Number(wi)]; if (!w) continue;
        const raw = buf.subarray(w.start, w.end);
        for (const [off, len] of m.at || []) {
          // A match over a byte that was replaced (0x1A) is not the value as written: never masked (round 3 L2).
          if (view !== 'l' && w.badAt.length && w.badAt.some(x => x >= off && x < off + len)) continue;
          const a = view === 'l' ? latin1Offset(raw, off) : off;
          const l = view === 'l' ? latin1Offset(raw.subarray(a), len) : len;
          if (binary) { binSeen.add(w.start + a); continue; }
          const s0 = w.start + a, prev = spans.get(s0); if (prev === undefined || l > prev) spans.set(s0, l);
        }
      }
    };
    for (let i = 0; i < wins.length; i++) {
      const w = wins[i];
      if (size && (size + w.bytes > SCRUB_BODY_MAX || batch.length + w.parts.length > 150)) await flush();
      for (const p of w.parts) batch.push({ id: i + ':' + p.view, text: p.text });
      size += w.bytes;
    }
    await flush();
    if (binary) {
      const n = binSeen.size;
      if (n) { left += n; console.log(`FOUND    ${f}: ${n} cop${n === 1 ? 'y' : 'ies'} in a binary file — not written (remove the file or rotate)`); }
      continue;
    }
    // Overlapping or touching spans become one, so a write never invalidates the check for the next (#98 review L2).
    const merged = [];
    for (const [a, l] of [...spans].sort((x, y) => x[0] - y[0])) { const last = merged[merged.length - 1]; if (last && a <= last[0] + last[1]) last[1] = Math.max(last[1], a + l - last[0]); else merged.push([a, l]); }
    if (!merged.length) continue;
    if (dry) { masked += merged.length; console.log(`FOUND    ${f}: ${merged.length} cop${merged.length === 1 ? 'y' : 'ies'} (dry run)`); continue; }
    let n = 0, stale = 0, wfd;
    try {
      wfd = fs.openSync(f, fs.constants.O_RDWR | fs.constants.O_NOFOLLOW);
      const ws = fs.fstatSync(wfd);
      // The same file that was read (not one swapped in since: #98 review L3).
      if (ws.ino !== st.ino || ws.dev !== st.dev) throw Object.assign(new Error('replaced since it was read'), { code: 'REPLACED' });
      for (const [s0, l0] of merged) {
        const now = Buffer.alloc(l0);
        const got = fs.readSync(wfd, now, 0, l0, s0);
        if (got !== l0 || !now.equals(buf.subarray(s0, s0 + l0))) { stale++; continue; }
        fs.writeSync(wfd, Buffer.alloc(l0, '*'), 0, l0, s0); n++;
      }
      fs.fsyncSync(wfd);
    } catch (e) { stale = merged.length - n; console.log(`LEFT     ${f}: cannot write (${e.code || e.message})`); }
    finally { if (wfd !== undefined) fs.closeSync(wfd); }
    masked += n; left += stale; if (n) filesChanged++;
    if (n || stale) console.log(`MASKED   ${f}: ${n} cop${n === 1 ? 'y' : 'ies'}${stale ? `, ${stale} left (the file changed there since it was read: run again)` : ''}`);
  }
  for (const k of notRead) console.log(`NOT READ ${k}`);
  console.log(`leak-scan: scrub ${dry ? '(dry run) ' : ''}read ${filesRead} files, ${bytesRead} bytes; ${dry ? 'found' : 'masked'} ${masked}, left ${left}${notRead.length ? `, ${notRead.length} paths not read` : ''}`);
  if (dry) process.exit(masked || left ? 1 : 0);
  const r = await fetch(API + '/api/demipass/leak-scan/scrub/finish', { method: 'POST', headers: { 'content-type': 'application/json', authorization: auth },
    body: JSON.stringify({ files_read: filesRead, files_changed: filesChanged, copies_masked: masked, copies_left: left, paths_not_read: notRead.length }) });
  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(`finish refused: HTTP ${r.status}: ${d.error || ''}`);
  console.log(d.contained ? `leak-scan: ${d.entry ? d.entry.name : 'the entry'} is contained (not rotated; backups still hold old copies)` : `leak-scan: not marked contained (${d.why || 'copies left'}); this scrub token is spent`);
  process.exit(d.contained ? 0 : 1);
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
