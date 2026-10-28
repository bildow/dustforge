'use strict';
// DemiPass host operations: the pure core (no db, no I/O), unit-tested in test/hostops.test.js.
// A host operation is an argv run on a registered host with a stored credential, allowed only when it fits a
// shape (a command template of literal words and typed slots) inside an open window. Nothing here builds a
// shell line from caller text: slot values are typed and charset-checked, and every word is single-quoted for
// the remote shell, so the remote side only ever sees literal words. See docs/host-operations.md.
const crypto = require('crypto');

const SAFE_VALUE = /^[A-Za-z0-9._:@=+,/-]+$/;      // slot values: no spaces, quotes or shell characters
const SAFE_WORD = /^[\x21-\x7e]+$/;                 // a literal word / an argv element: printable ASCII, no spaces
const COMMAND = /^(\/[A-Za-z0-9._/-]+|[A-Za-z0-9._-]+)$/;
const SHAPE_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const SLOT_NAME = /^[a-z][a-z0-9_]{0,31}$/;
const MAX_ELEMENTS = 32;
const MAX_RENDERED = 4096;
const MAX_RUN_SECONDS = 60;
const MAX_JOB_SECONDS = 86400;
const MAX_SHAPES = 20;

// ── shapes ───────────────────────────────────────────────────────────────────────────────────────────

function normalizedPrefix(p) {
  return typeof p === 'string' && p.startsWith('/') && p.endsWith('/') && SAFE_VALUE.test(p) && normalPath(p.slice(0, -1) || '/') !== null;
}
// An absolute path with no empty, '.' or '..' segments; returns it, or null.
function normalPath(p) {
  if (typeof p !== 'string' || !p.startsWith('/') || p.length > 512 || !SAFE_VALUE.test(p)) return null;
  if (p === '/') return p;
  const parts = p.slice(1).split('/');
  if (parts.some(s => s === '' || s === '.' || s === '..')) return null;
  return p;
}

// Validate one shape (as submitted by an agent or stored in a window). Returns { ok:true, shape } with every
// field normalised, or { ok:false, error }.
function validateShape(input) {
  const s = input && typeof input === 'object' && !Array.isArray(input) ? input : null;
  if (!s) return { ok: false, error: 'a shape must be an object' };
  if (typeof s.name !== 'string' || !SHAPE_NAME.test(s.name)) return { ok: false, error: 'shape name: 1-64 of A-Z a-z 0-9 . _ - (starting with a letter or digit)' };
  const mode = s.mode === undefined ? 'run' : s.mode;
  if (mode !== 'run' && mode !== 'job') return { ok: false, error: `shape ${s.name}: mode must be run or job` };
  const sudo = s.sudo === undefined ? false : s.sudo;
  if (typeof sudo !== 'boolean') return { ok: false, error: `shape ${s.name}: sudo must be true or false` };
  if (mode === 'job' && !sudo) return { ok: false, error: `shape ${s.name}: a job runs as a system unit, so it needs sudo: true` };
  const cap = mode === 'job' ? MAX_JOB_SECONDS : MAX_RUN_SECONDS;
  const max_seconds = s.max_seconds === undefined ? (mode === 'job' ? 3600 : MAX_RUN_SECONDS) : s.max_seconds;
  if (!Number.isInteger(max_seconds) || max_seconds < 1 || max_seconds > cap) return { ok: false, error: `shape ${s.name}: max_seconds must be 1 to ${cap} for a ${mode}` };
  if (!Array.isArray(s.argv) || s.argv.length < 1 || s.argv.length > MAX_ELEMENTS) return { ok: false, error: `shape ${s.name}: argv must have 1 to ${MAX_ELEMENTS} elements` };
  const argv = [];
  const slots = new Set();
  for (let i = 0; i < s.argv.length; i++) {
    const e = s.argv[i];
    const where = `shape ${s.name}, argv[${i}]`;
    if (typeof e === 'string') {
      if (!SAFE_WORD.test(e) || e.length > 256) return { ok: false, error: `${where}: a literal is one word of printable characters (no spaces), at most 256` };
      argv.push({ literal: e });
      continue;
    }
    if (!e || typeof e !== 'object' || Array.isArray(e)) return { ok: false, error: `${where}: must be a string or an object` };
    const optional = e.optional === undefined ? false : e.optional;
    if (typeof optional !== 'boolean') return { ok: false, error: `${where}: optional must be true or false` };
    if (e.literal !== undefined) {
      if (Object.keys(e).some(k => !['literal', 'optional'].includes(k))) return { ok: false, error: `${where}: a literal takes only literal and optional` };
      if (typeof e.literal !== 'string' || !SAFE_WORD.test(e.literal) || e.literal.length > 256) return { ok: false, error: `${where}: literal must be one printable word` };
      argv.push({ literal: e.literal, optional });
      continue;
    }
    if (typeof e.slot !== 'string' || !SLOT_NAME.test(e.slot)) return { ok: false, error: `${where}: slot name must be a-z 0-9 _ (starting with a letter)` };
    if (slots.has(e.slot)) return { ok: false, error: `${where}: slot ${e.slot} is used twice` };
    slots.add(e.slot);
    const kinds = ['type', 'enum', 'match'].filter(k => e[k] !== undefined);
    if (kinds.length !== 1) return { ok: false, error: `${where}: a slot needs exactly one of type, enum, match` };
    const el = { slot: e.slot, optional };
    if (e.prefix !== undefined) {
      if (typeof e.prefix !== 'string' || !SAFE_WORD.test(e.prefix) || e.prefix.length > 64) return { ok: false, error: `${where}: prefix must be one printable word, at most 64` };
      el.prefix = e.prefix;
    }
    if (e.type !== undefined) {
      if (!['word', 'int', 'path'].includes(e.type)) return { ok: false, error: `${where}: type must be word, int or path` };
      el.type = e.type;
      if (e.type === 'path') {
        if (!Array.isArray(e.under) || e.under.length < 1 || e.under.length > 8 || !e.under.every(normalizedPrefix)) {
          return { ok: false, error: `${where}: a path slot needs under: 1-8 absolute directory prefixes ending in /` };
        }
        el.under = [...e.under];
      } else if (e.under !== undefined) return { ok: false, error: `${where}: under is only for path slots` };
    } else if (e.enum !== undefined) {
      if (!Array.isArray(e.enum) || e.enum.length < 1 || e.enum.length > 64 || !e.enum.every(v => typeof v === 'string' && v.length <= 128 && SAFE_VALUE.test(v) && !v.startsWith('-'))) {
        return { ok: false, error: `${where}: enum must be 1-64 safe values (no spaces or shell characters, not starting with -)` };
      }
      el.enum = [...new Set(e.enum)];
    } else {
      if (typeof e.match !== 'string' || e.match.length > 200 || !e.match.startsWith('^') || !e.match.endsWith('$')) {
        return { ok: false, error: `${where}: match must be an anchored regex (^...$), at most 200 characters` };
      }
      try { new RegExp(e.match); } catch (_) { return { ok: false, error: `${where}: match is not a valid regex` }; }
      el.match = e.match;
    }
    argv.push(el);
  }
  if (argv[0].optional || argv[0].literal === undefined || !COMMAND.test(argv[0].literal)) {
    return { ok: false, error: `shape ${s.name}: argv[0] must be a required literal command name or absolute path` };
  }
  return { ok: true, shape: { name: s.name, mode, sudo, max_seconds, argv } };
}

function validateShapes(list) {
  if (!Array.isArray(list) || list.length < 1 || list.length > MAX_SHAPES) return { ok: false, error: `shapes must be a list of 1 to ${MAX_SHAPES}` };
  const out = [];
  const names = new Set();
  for (const s of list) {
    const v = validateShape(s);
    if (!v.ok) return v;
    if (names.has(v.shape.name)) return { ok: false, error: `shape name ${v.shape.name} is used twice` };
    names.add(v.shape.name);
    out.push(v.shape);
  }
  return { ok: true, shapes: out };
}

// An argv as sent by a caller: 1-32 words of printable ASCII without spaces, each at most 512 characters.
function validateArgv(argv) {
  if (!Array.isArray(argv) || argv.length < 1 || argv.length > MAX_ELEMENTS) return `argv must be a list of 1 to ${MAX_ELEMENTS} words`;
  for (let i = 0; i < argv.length; i++) {
    if (typeof argv[i] !== 'string' || argv[i].length < 1 || argv[i].length > 512 || !SAFE_WORD.test(argv[i])) {
      return `argv[${i}] must be one word of printable characters (no spaces), at most 512`;
    }
  }
  return null;
}

// A one-time approval: the exact argv as an all-literal shape.
function literalShape(argv, { mode = 'run', sudo = false, max_seconds } = {}) {
  return validateShape({ name: 'once', mode, sudo, max_seconds, argv: [...argv] });
}

// ── matching ─────────────────────────────────────────────────────────────────────────────────────────

function describe(el) {
  if (el.literal !== undefined) return JSON.stringify(el.literal);
  const p = el.prefix ? JSON.stringify(el.prefix) + ' + ' : '';
  if (el.enum) return `${p}one of ${el.enum.join('|')}`;
  if (el.match) return `${p}a value matching ${el.match}`;
  if (el.type === 'path') return `${p}a path under ${el.under.join(' or ')}`;
  return `${p}a ${el.type}`;
}

// Why a slot value is refused, or null when it fits.
function slotRefusal(el, v) {
  if (typeof v !== 'string' || v.length < 1) return 'is empty';
  if (v.length > (el.type === 'path' ? 512 : 128)) return 'is too long';
  if (v.startsWith('-')) return 'starts with -';
  if (!SAFE_VALUE.test(v)) return 'has characters outside A-Z a-z 0-9 . _ : @ = + , / -';
  if (el.enum && !el.enum.includes(v)) return `is not one of ${el.enum.join('|')}`;
  if (el.match && !new RegExp(el.match).test(v)) return `does not match ${el.match}`;
  if (el.type === 'int' && !/^[0-9]{1,12}$/.test(v)) return 'is not a whole number';
  if (el.type === 'path') {
    const p = normalPath(v);
    if (!p) return 'is not a normalised absolute path';
    if (!el.under.some(u => p.startsWith(u))) return `is not under ${el.under.join(' or ')}`;
  }
  return null;
}

// Match argv against a validated shape: { ok:true, values } or { ok:false, index, reason } (the furthest point
// reached, for explaining a refusal). Optional elements may be skipped; first fit wins.
function matchShape(shape, argv) {
  let best = { ok: false, index: -1, reason: 'no match' };
  const note = (i, reason) => { if (i > best.index) best = { ok: false, index: i, reason }; };
  const walk = (t, a, values) => {
    if (t === shape.argv.length) {
      if (a === argv.length) return values;
      note(a, `argument ${a + 1} ${JSON.stringify(argv[a])} is one too many`);
      return null;
    }
    const el = shape.argv[t];
    if (a < argv.length) {
      const word = argv[a];
      if (el.literal !== undefined) {
        if (word === el.literal) { const r = walk(t + 1, a + 1, values); if (r) return r; }
        else note(a, `argument ${a + 1} ${JSON.stringify(word)} should be ${JSON.stringify(el.literal)}`);
      } else {
        const prefix = el.prefix || '';
        if (!word.startsWith(prefix)) note(a, `argument ${a + 1} ${JSON.stringify(word)} should start with ${JSON.stringify(prefix)}`);
        else {
          const why = slotRefusal(el, word.slice(prefix.length));
          if (why) note(a, `argument ${a + 1} ${JSON.stringify(word)} ${why}`);
          else { const r = walk(t + 1, a + 1, { ...values, [el.slot]: word.slice(prefix.length) }); if (r) return r; }
        }
      }
    } else if (!el.optional) note(a, `missing argument ${a + 1}: ${describe(el)}`);
    if (el.optional) return walk(t + 1, a, values);
    return null;
  };
  const values = walk(0, 0, {});
  return values ? { ok: true, values } : best;
}

// First (window, shape) that covers argv, or null. `windows`: [{ id, shapes:[validated] }].
function findCover(windows, argv) {
  for (const w of windows) for (const s of w.shapes) if (matchShape(s, argv).ok) return { window: w, shape: s };
  return null;
}

// Why nothing covers argv: the open windows and the nearest shape with its first mismatch.
function explainRefusal(windows, argv) {
  let nearest = null;
  for (const w of windows) {
    for (const s of w.shapes) {
      const m = matchShape(s, argv);
      if (!nearest || m.index > nearest.index) nearest = { window_id: w.id, shape: s.name, index: m.index, reason: m.reason };
    }
  }
  return {
    covered: false,
    open_windows: windows.map(w => ({ id: w.id, label: w.label, closes_at: w.closes_at, shapes: w.shapes.map(s => s.name) })),
    nearest: nearest ? { window_id: nearest.window_id, shape: nearest.shape, reason: nearest.reason } : null,
  };
}

// ── rendering ────────────────────────────────────────────────────────────────────────────────────────

// POSIX single-quoting: the remote shell sees exactly this word, whatever it contains.
function quote(word) { return "'" + String(word).replace(/'/g, "'\\''") + "'"; }

// The remote command line for a covered argv. A job runs as a transient system unit so it outlives the
// SSH call, is capped by RuntimeMaxSec, and keeps its result until it is collected.
function renderRemote(shape, argv, { unit } = {}) {
  const words = argv.map(quote).join(' ');
  let line;
  if (shape.mode === 'job') {
    if (!/^dp-hostop-[0-9]{1,12}$/.test(unit || '')) throw new Error('job unit name required');
    line = `sudo -n systemd-run --unit=${unit} --remain-after-exit --quiet --property=RuntimeMaxSec=${shape.max_seconds} -- ${words}`;
  } else {
    line = (shape.sudo ? 'sudo -n -- ' : '') + words;
  }
  if (line.length > MAX_RENDERED) throw new Error(`the rendered command is longer than ${MAX_RENDERED} characters`);
  return line;
}

// Remote commands DemiPass itself issues for a job (unit names are digits only, so these are fixed strings).
function jobProbe(unit) {
  if (!/^dp-hostop-[0-9]{1,12}$/.test(unit)) throw new Error('bad unit');
  return `sudo -n systemctl show ${unit} -p LoadState -p ActiveState -p SubState -p Result -p ExecMainStatus; echo ---journal---; sudo -n journalctl -u ${unit} -n 40 --no-pager -o cat`;
}
function jobStop(unit) {
  if (!/^dp-hostop-[0-9]{1,12}$/.test(unit)) throw new Error('bad unit');
  return `sudo -n systemctl stop ${unit}`;
}

// Read `systemctl show` + journal output into a run state.
function parseJobProbe(text) {
  const [head, journal = ''] = String(text || '').split('\n---journal---\n');
  const p = {};
  for (const line of head.split('\n')) { const i = line.indexOf('='); if (i > 0) p[line.slice(0, i)] = line.slice(i + 1).trim(); }
  const code = /^-?[0-9]+$/.test(p.ExecMainStatus || '') ? Number(p.ExecMainStatus) : null;
  let status;
  if (p.LoadState === 'not-found') status = 'lost';
  else if (p.ActiveState === 'activating' || (p.ActiveState === 'active' && p.SubState === 'running') || p.ActiveState === 'deactivating') status = 'running';
  else if (p.Result === 'timeout') status = 'timed_out';
  else if (p.ActiveState === 'active' && p.SubState === 'exited') status = code === 0 ? 'succeeded' : 'failed';
  else if (p.ActiveState === 'failed') status = 'failed';
  else if (p.ActiveState === 'inactive') status = code === 0 && p.Result === 'success' ? 'succeeded' : 'failed';
  else status = 'running';
  return { status, exit_code: code, result: p.Result || null, journal: journal.trimEnd() };
}

// ── hosts ────────────────────────────────────────────────────────────────────────────────────────────

const ADDRESS = /^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$/;
const LOGIN = /^[a-z_][a-z0-9_.-]{0,31}$/;
function validAddress(a) { return typeof a === 'string' && ADDRESS.test(a); }
function validLogin(u) { return typeof u === 'string' && LOGIN.test(u); }
function validPort(p) { return Number.isInteger(p) && p >= 1 && p <= 65535; }

// Parse ssh-keyscan output into known_hosts lines for one host and the fingerprint of its preferred key.
function parseKeyscan(text, address, port = 22) {
  const hostField = port === 22 ? address : `[${address}]:${port}`;
  const keys = [];
  for (const line of String(text || '').split('\n')) {
    const t = line.trim();
    if (!t || t.startsWith('#')) continue;
    const [, type, blob] = t.split(/\s+/);
    if (!/^(ssh-ed25519|ecdsa-sha2-nistp(256|384|521)|ssh-rsa)$/.test(type || '') || !/^[A-Za-z0-9+/]+={0,2}$/.test(blob || '')) continue;
    keys.push({ type, blob });
  }
  if (!keys.length) return null;
  const rank = t => (t === 'ssh-ed25519' ? 0 : t.startsWith('ecdsa') ? 1 : 2);
  keys.sort((a, b) => rank(a.type) - rank(b.type));
  const fp = 'SHA256:' + crypto.createHash('sha256').update(Buffer.from(keys[0].blob, 'base64')).digest('base64').replace(/=+$/, '');
  return { known_hosts: keys.map(k => `${hostField} ${k.type} ${k.blob}`).join('\n') + '\n', fingerprint: fp, key_type: keys[0].type };
}

// ── output ───────────────────────────────────────────────────────────────────────────────────────────

function redact(text, secrets) {
  let out = String(text || '');
  for (const s of secrets) if (s) out = out.split(s).join('[REDACTED]');
  return out;
}
function tail(text, max = 16384) { const s = String(text || ''); return s.length > max ? '…' + s.slice(-max) : s; }

module.exports = {
  SAFE_VALUE, MAX_ELEMENTS, MAX_RUN_SECONDS, MAX_JOB_SECONDS, MAX_SHAPES,
  validateShape, validateShapes, validateArgv, literalShape, matchShape, findCover, explainRefusal, describe,
  quote, renderRemote, jobProbe, jobStop, parseJobProbe,
  normalPath, validAddress, validLogin, validPort, parseKeyscan, redact, tail,
};
