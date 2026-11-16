'use strict';
// ── Mail as untrusted input: the code-derived form of a message, and its visible text (pane mailboxes, phase 1) ─────
// SPEC 2026-11-16 pane mailboxes v0.2, "Reading mail safely": mail is data, never instruction. Every message is first
// reduced by code; no model runs here (the reader service is phase 2 and sits behind its own interface).
//   formOf(email)      → the fields a pane gets in a list: from, to, date, subject (codes masked), internal/external,
//                        the SPF/DKIM/DMARC results Stalwart wrote, codes found (length only), link hosts (checked
//                        against the sender's domain), attachment names and types.
//   visibleText(email) → the body as a person would see it: HTML reduced to visible text (comments, script/style/head,
//                        closed <details>, elements hidden by attribute, inline style or a <style> rule dropped), then
//                        zero-width, bidi and control characters stripped.
//   maskSecrets(text)  → the text with code-like runs masked and links cut to their host: what a pane is given.
//   quoted(text)       → that text as a quotation ("> " on every line), capped: it is handed over as data.
// Nothing here fetches remote content, follows links or renders.
//
// Cost (#129 review H1): every pass is linear. The HTML is cut to MAX_HTML before it is looked at, and it is read by a
// single-pass scanner (indexOf and character loops, no backtracking regular expressions over the document). A tag
// left unterminated, or a quote left open inside one, ends the scan: the rest is dropped (fails closed).

const INTERNAL_DOMAINS = new Set(['dustforge.com', 'dustanvil.com', 'dustroot.com']);
const MAX_HTML = 64 * 1024;       // characters of HTML looked at
const MAX_TEXT = 200000;          // characters of a plain part looked at
const MAX_QUOTED = 20000;         // characters of body handed over on an explicit read
const MAX_DEPTH = 512;            // open elements kept; deeper nesting hides the rest

// Zero-width, bidi controls, soft hyphen and other invisible formatting characters; C0/C1 controls except tab and LF.
const INVISIBLE_RE = /[­͏؜ᅟᅠ឴឵᠋-᠏​-‏‪-‮⁠-⁯ㅤ︀-️﻿ﾠ]|[\u{e0000}-\u{e007f}]/gu;
const CONTROL_RE = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/g;

function stripInvisible(s) {
  return String(s == null ? '' : s).replace(/\r\n?/g, '\n').replace(INVISIBLE_RE, '').replace(CONTROL_RE, '');
}
// Collapse spaces and trim lines without a backtracking pattern: per line, trimEnd/trimStart.
function tidy(s) {
  const lines = String(s).replace(/[ \t ]+/g, ' ').split('\n').map((l) => l.trim());
  const out = [];
  let blank = 0;
  for (const l of lines) { if (!l) { if (++blank <= 1 && out.length) out.push(''); continue; } blank = 0; out.push(l); }
  while (out.length && !out[out.length - 1]) out.pop();
  return out.join('\n');
}

const NAMED = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ', ensp: ' ', emsp: ' ', thinsp: ' ', zwj: '', zwnj: '',
  lrm: '', rlm: '', shy: '', copy: '©', reg: '®', hellip: '…', mdash: '—', ndash: '–', lsquo: '‘', rsquo: '’', ldquo: '“', rdquo: '”', bull: '•', middot: '·' };
function decodeEntities(s) {
  return String(s).replace(/&(#x[0-9a-f]{1,6}|#\d{1,7}|[a-z][a-z0-9]{1,15});?/gi, (m, e) => {
    if (e[0] === '#') {
      const n = e[1] === 'x' || e[1] === 'X' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
      return Number.isFinite(n) && n > 0 && n <= 0x10ffff ? String.fromCodePoint(n) : '';
    }
    const v = NAMED[e.toLowerCase()];
    return v === undefined ? m : v;
  });
}

// ── CSS: is this declaration block hiding its text? ─────────────────────────────────────────────────────────────────
// Comments are removed and escapes (\6e, \:) decoded first, so "display:\6e one" reads as "display:none".
function cssClean(raw) {
  const s = String(raw || '');
  let out = '', i = 0;
  while (i < s.length) {
    const a = s.indexOf('/*', i);
    if (a < 0) { out += s.slice(i); break; }
    out += s.slice(i, a);
    const b = s.indexOf('*/', a + 2);
    if (b < 0) break;
    i = b + 2;
  }
  return out.replace(/\\([0-9a-fA-F]{1,6})\s?/g, (m, h) => { const n = parseInt(h, 16); return n > 0 && n <= 0x10ffff ? String.fromCodePoint(n) : ''; })
    .replace(/\\(.)/g, '$1').toLowerCase();
}
function cssDecls(clean) {
  const d = {};
  for (const part of clean.split(';')) {
    const c = part.indexOf(':');
    if (c < 0) continue;
    const k = part.slice(0, c).replace(/\s+/g, '');
    const v = part.slice(c + 1).replace(/!important/g, '').replace(/\s+/g, ' ').trim();
    if (k) d[k] = v;
  }
  return d;
}
const num = (v) => { const m = /^(-?\d*\.?\d+)\s*([a-z%]*)/.exec(String(v || '').trim()); return m ? { n: parseFloat(m[1]), u: m[2] || '' } : null; };
function lightColour(v) {
  const s = String(v || '').replace(/\s+/g, '');
  if (!s) return false;
  if (/^(transparent|white|snow|ivory|ghostwhite|whitesmoke|floralwhite|azure|mintcream|honeydew|seashell|aliceblue)$/.test(s)) return true;
  let r, g, b, a = 1, m;
  if ((m = /^#([0-9a-f]{3,4})$/.exec(s))) { [r, g, b] = [...m[1].slice(0, 3)].map((x) => parseInt(x + x, 16)); if (m[1].length === 4) a = parseInt(m[1][3] + m[1][3], 16) / 255; }
  else if ((m = /^#([0-9a-f]{6})([0-9a-f]{2})?$/.exec(s))) { r = parseInt(m[1].slice(0, 2), 16); g = parseInt(m[1].slice(2, 4), 16); b = parseInt(m[1].slice(4, 6), 16); if (m[2]) a = parseInt(m[2], 16) / 255; }
  else if ((m = /^rgba?\(([\d.]+)%?,([\d.]+)%?,([\d.]+)%?(?:,([\d.]+))?\)$/.exec(s))) { [r, g, b] = [m[1], m[2], m[3]].map(Number); if (m[4] !== undefined) a = Number(m[4]); }
  else return false;
  return a < 0.2 || (r >= 235 && g >= 235 && b >= 235);
}
// Conservative: a declaration block that could make its text unreadable to a person hides it.
function cssHides(raw) {
  const d = cssDecls(cssClean(raw));
  const small = (v) => { const x = num(v); if (!x) return false; if (x.n <= 0) return true;
    return (x.u === 'px' && x.n <= 4) || (x.u === 'pt' && x.n <= 3) || ((x.u === 'em' || x.u === 'rem') && x.n <= 0.35) || (x.u === '%' && x.n <= 35) || (x.u === '' && x.n <= 0); };
  const tiny = (v) => { const x = num(v); return Boolean(x) && x.n <= 1; };
  const far = (v) => { const x = num(v); return Boolean(x) && x.n <= -50; };
  if (d.display === 'none' || /^(hidden|collapse)/.test(d.visibility || '')) return true;
  if (d['mso-hide'] === 'all' || d['content-visibility'] === 'hidden') return true;
  if (d.opacity !== undefined && (num(d.opacity) || { n: 1 }).n < 0.3) return true;
  if (d['font-size'] !== undefined && small(d['font-size'])) return true;
  if (d.font !== undefined && /^0(\D|$)/.test(d.font.replace(/^(italic|bold|normal|oblique|small-caps|\d00)\s+/g, ''))) return true;
  if (d.color !== undefined && lightColour(d.color)) return true;
  if (d.color !== undefined && (d['background-color'] || d.background) && d.color.replace(/\s+/g, '') === String(d['background-color'] || d.background).replace(/\s+/g, '')) return true;
  if (['height', 'max-height', 'width', 'max-width', 'line-height'].some((k) => d[k] !== undefined && tiny(d[k])) && /hidden|clip/.test(d.overflow || d['overflow-x'] || d['overflow-y'] || '')) return true;
  if (['text-indent', 'left', 'top', 'margin-left', 'margin-top', 'right'].some((k) => d[k] !== undefined && far(d[k]))) return true;
  if (/rect\(0/.test(d.clip || '') || /inset\(50%|circle\(0/.test(d['clip-path'] || '')) return true;
  if (/scale\(0[,)]|scale\(0\.0|scalex\(0\)|scaley\(0\)/.test((d.transform || '').replace(/\s+/g, ''))) return true;
  return false;
}
// <style> blocks: selectors whose rules hide → the classes, ids and tag names they name. Linear: split on braces.
function hidingSelectors(css) {
  const out = { classes: new Set(), ids: new Set(), tags: new Set(), all: false };
  const clean = cssClean(css);
  for (const chunk of clean.split('}')) {
    const open = chunk.lastIndexOf('{');
    if (open < 0) continue;
    if (!cssHides(chunk.slice(open + 1))) continue;
    const sel = chunk.slice(0, open);
    for (const m of sel.matchAll(/([.#])([a-z0-9_-]+)/g)) (m[1] === '.' ? out.classes : out.ids).add(m[2]);
    for (const m of sel.matchAll(/(?:^|[\s,>+~{(])([a-z][a-z0-9]*)/g)) out.tags.add(m[1]);
    if (/(^|[\s,{])\*/.test(sel)) out.all = true;
  }
  return out;
}

// ── the scanner ─────────────────────────────────────────────────────────────────────────────────────────────────
const SKIP_TAGS = new Set(['script', 'style', 'head', 'title', 'template', 'noscript', 'svg', 'math', 'iframe', 'object', 'embed', 'canvas', 'select', 'option', 'textarea', 'button', 'audio', 'video', 'map', 'frameset', 'xml', 'datalist', 'dialog']);
const RAW_TAGS = new Set(['script', 'style', 'title', 'textarea', 'xmp', 'iframe', 'noembed', 'noframes']);
const VOID_TAGS = new Set(['area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link', 'meta', 'param', 'source', 'track', 'wbr', 'basefont', 'frame', 'keygen']);
const BLOCK_TAGS = new Set(['p', 'div', 'br', 'tr', 'li', 'ul', 'ol', 'table', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'blockquote', 'pre', 'hr', 'section', 'article', 'header', 'footer', 'center', 'dd', 'dt', 'dl', 'address', 'form', 'fieldset', 'summary', 'details']);
const isWs = (c) => c === 32 || c === 9 || c === 10 || c === 13 || c === 12;
const isAlpha = (c) => (c >= 65 && c <= 90) || (c >= 97 && c <= 122);
const isNameCh = (c) => isAlpha(c) || (c >= 48 && c <= 57) || c === 45 || c === 58 || c === 95;

// One pass over s. on.text(str), on.open(name, attrs, selfClosing), on.close(name), on.raw(name, content). Returns
// 'end' or 'cut' (an unterminated construct: the rest was not read).
function scan(s, on) {
  const n = s.length;
  let i = 0;
  while (i < n) {
    const lt = s.indexOf('<', i);
    if (lt < 0) { on.text(s.slice(i)); return 'end'; }
    if (lt > i) on.text(s.slice(i, lt));
    const c1 = s.charCodeAt(lt + 1);
    if (c1 === 33 /* ! */) {
      if (s.startsWith('<!--', lt)) { const e = s.indexOf('-->', lt + 4); if (e < 0) return 'cut'; i = e + 3; continue; }
      if (s.startsWith('<![CDATA[', lt)) { const e = s.indexOf(']]>', lt + 9); if (e < 0) return 'cut'; i = e + 3; continue; }
      const e = s.indexOf('>', lt + 2); if (e < 0) return 'cut'; i = e + 1; continue;
    }
    if (c1 === 63 /* ? */) { const e = s.indexOf('>', lt + 2); if (e < 0) return 'cut'; i = e + 1; continue; }
    let j = lt + 1, closing = false;
    if (c1 === 47 /* / */) { closing = true; j++; }
    if (!isAlpha(s.charCodeAt(j))) { on.text('<'); i = lt + 1; continue; }
    let k = j;
    while (k < n && isNameCh(s.charCodeAt(k))) k++;
    const name = s.slice(j, k).toLowerCase();
    const attrs = {};
    let q = k, done = false, selfClosing = false;
    while (q < n) {
      const c = s.charCodeAt(q);
      if (c === 62 /* > */) { done = true; q++; break; }
      if (isWs(c)) { q++; continue; }
      if (c === 47 /* / */) { if (s.charCodeAt(q + 1) === 62) selfClosing = true; q++; continue; }
      const a = q;
      while (q < n) { const d = s.charCodeAt(q); if (isWs(d) || d === 61 || d === 62 || d === 47) break; q++; }
      if (q === a) q++;                                 // a stray character: step over it
      const an = s.slice(a, q).toLowerCase();
      let p = q; while (p < n && isWs(s.charCodeAt(p))) p++;
      let val = '';
      if (s.charCodeAt(p) === 61 /* = */) {
        p++; while (p < n && isWs(s.charCodeAt(p))) p++;
        const qc = s.charCodeAt(p);
        if (qc === 34 || qc === 39) { const e = s.indexOf(qc === 34 ? '"' : "'", p + 1); if (e < 0) return 'cut'; val = s.slice(p + 1, e); p = e + 1; }
        else { const b = p; while (p < n) { const d = s.charCodeAt(p); if (isWs(d) || d === 62) break; p++; } val = s.slice(b, p); }
        q = p;
      }
      if (an && !(an in attrs)) attrs[an] = decodeEntities(val);
    }
    if (!done) return 'cut';
    i = q;
    if (closing) { on.close(name); continue; }
    on.open(name, attrs, selfClosing);
    if (RAW_TAGS.has(name) && !selfClosing) {
      const re = new RegExp('</' + name + '[\\s/>]', 'ig'); re.lastIndex = i;
      const m = re.exec(s);
      on.raw(name, m ? s.slice(i, m.index) : s.slice(i));
      if (!m) return 'cut';
      i = m.index;
    }
  }
  return 'end';
}

function hiddenByAttrs(name, a, css) {
  if ('hidden' in a) return true;
  if (String(a['aria-hidden'] || '').toLowerCase() === 'true') return true;
  if (String(a.type || '').toLowerCase() === 'hidden') return true;
  if (name === 'details' && !('open' in a)) return true;       // closed <details>: its content is not shown
  if (name === 'font' && a.color && lightColour(String(a.color).toLowerCase())) return true;
  if (a.style && cssHides(a.style)) return true;
  if (css) {
    if (css.all || css.tags.has(name)) return true;
    if (a.id && css.ids.has(String(a.id).toLowerCase())) return true;
    if (a.class) for (const c of String(a.class).toLowerCase().split(/\s+/)) if (c && css.classes.has(c)) return true;
  }
  return false;
}

// HTML → { text, links, hidden, cut }: the visible text, every link target (href/src/action), how many elements were
// dropped as hidden, and whether the scan stopped at an unterminated construct.
function reduceHtml(html) {
  const s = String(html == null ? '' : html).slice(0, MAX_HTML);
  // Pass 1: the <style> blocks (they apply to the whole document, wherever they sit).
  let styles = '';
  scan(s, { text() {}, open() {}, close() {}, raw(name, content) { if (name === 'style') styles += content + '}'; } });
  const css = styles ? hidingSelectors(styles) : null;
  // Pass 2: the visible text.
  const out = [], links = [], stack = [], openCount = new Map();
  let hiddenDepth = 0, hidden = 0, overflow = false;
  const scanned = scan(s, {
    text(t) { if (!hiddenDepth && !overflow) out.push(t); },
    raw() {},
    open(name, attrs, selfClosing) {
      for (const k of ['href', 'src', 'action', 'background']) if (attrs[k]) links.push(attrs[k]);
      if (!hiddenDepth && !overflow && BLOCK_TAGS.has(name)) out.push('\n');
      if (VOID_TAGS.has(name) || selfClosing) return;
      if (stack.length >= MAX_DEPTH) { overflow = true; return; }
      const h = SKIP_TAGS.has(name) || hiddenByAttrs(name, attrs, css);
      if (h) { hiddenDepth++; if (!SKIP_TAGS.has(name)) hidden++; }
      stack.push({ name, h });
      openCount.set(name, (openCount.get(name) || 0) + 1);
    },
    close(name) {
      if (!openCount.get(name)) return;               // nothing of that name is open: ignored (no stack walk)
      while (stack.length) {
        const top = stack.pop();
        openCount.set(top.name, openCount.get(top.name) - 1);
        if (top.h) hiddenDepth--;
        if (top.name === name) break;
      }
      if (!hiddenDepth && !overflow && BLOCK_TAGS.has(name)) out.push('\n');
    },
  });
  return { text: tidy(decodeEntities(out.join(''))), links, hidden, cut: scanned === 'cut' || overflow || String(html || '').length > MAX_HTML };
}
const htmlToVisibleText = (html) => reduceHtml(html).text;

// The text parts of a JMAP Email (bodyValues + textBody/htmlBody), as { html, text }.
function partsOf(email) {
  const values = (email && email.bodyValues) || {};
  const pick = (list) => (Array.isArray(list) ? list : []).map((p) => (p && values[p.partId] ? String(values[p.partId].value || '') : '')).join('\n');
  const htmlParts = (email.htmlBody || []).filter((p) => /html/i.test(String(p.type || '')));
  const textParts = (email.textBody || []).filter((p) => !/html/i.test(String(p.type || '')));
  return { html: pick(htmlParts), text: pick(textParts).slice(0, MAX_TEXT) };
}

// The visible body: the HTML part reduced (what a person sees, so text hidden from them is gone), else the plain part.
function visibleText(email) {
  const { html, text } = partsOf(email || {});
  if (html.trim()) {
    const r = reduceHtml(html);
    return { source: 'html', text: tidy(stripInvisible(r.text)), hidden_elements: r.hidden, cut: r.cut };
  }
  return { source: 'text', text: tidy(stripInvisible(text)), hidden_elements: 0, cut: false };
}

// What a pane is handed of a body or subject (#129 review H2): links cut to scheme and host, code-like runs masked —
// digit runs of 4–10 (spaces or dashes between), letter-and-digit tokens of 6+, and any token of 20+ (a reset or
// sign-in token). A year alone (19xx/20xx) is kept.
function maskSecrets(text) {
  return String(text || '')
    .replace(/\b(https?):\/\/([^\s\/?#<>"'()\[\]{}]+)[^\s<>"'()\[\]{}]*/gi, (m, sch, host) => {
      const h = host.replace(/^[^@]*@/, '');
      return m.length > sch.length + 3 + host.length ? `${sch.toLowerCase()}://${h}/…` : `${sch.toLowerCase()}://${h}`;
    })
    .replace(/[A-Za-z0-9_-]{20,}/g, (m) => '•'.repeat(Math.min(m.length, 24)))
    .replace(/\b(?=[A-Za-z]*\d)(?=\d*[A-Za-z])[A-Za-z0-9]{6,}\b/g, (m) => '•'.repeat(m.length))
    .replace(/(?<![\w•])\d(?:[ -]?\d){3,9}(?![\w•])/g, (m) => (/^(19|20)\d\d$/.test(m) ? m : m.replace(/\d/g, '•')));
}

function quoted(text, max = MAX_QUOTED) {
  const t = String(text || '');
  const cut = t.length > max;
  return { quoted: (cut ? t.slice(0, max) : t).split('\n').map((l) => '> ' + l).join('\n'), truncated: cut, chars: t.length };
}

// ── form fields ────────────────────────────────────────────────────────────────────────────────────────────────────
const addr = (a) => (a && a.email ? String(a.email).toLowerCase() : '');
const domainOf = (e) => { const i = String(e).lastIndexOf('@'); return i >= 0 ? String(e).slice(i + 1).toLowerCase() : ''; };

// Authentication-Results / Received-SPF as Stalwart wrote them (JMAP header:…:asText; all instances).
function authResults(email) {
  const take = (k) => { const v = email && email[k]; return (Array.isArray(v) ? v.filter(Boolean) : v ? [v] : []).slice(0, 10).map((x) => String(x).slice(0, 2000)); };
  const ar = take('header:Authentication-Results:asText:all').concat(take('header:Authentication-Results:asText'));
  const rspf = take('header:Received-SPF:asText:all').concat(take('header:Received-SPF:asText'));
  const out = { spf: null, dkim: null, dmarc: null };
  const all = ar.join(' ; ');
  for (const k of ['spf', 'dkim', 'dmarc']) {
    const m = new RegExp(`\\b${k}=([a-z]+)`, 'i').exec(all.replace(/\s*=\s*/g, '='));
    if (m) out[k] = m[1].toLowerCase();
  }
  if (!out.spf && rspf.length) { const m = /^\s*([a-z]+)/i.exec(rspf[0]); if (m) out.spf = m[1].toLowerCase(); }
  out.exposed = ar.length > 0 || rspf.length > 0;
  return out;
}

// Codes: a run of 4–8 digits (spaces or dashes allowed between groups) near a word that names a code. Masked: only the
// length is returned.
const CODE_WORD = /(code|otp|one[- ]time|passcode|pin|verif|confirm|security|token|2fa|two[- ]factor|sign[- ]?in|log[- ]?in|password|reset|kod|c[oó]digo)/i;
function codesIn(text) {
  const t = String(text || '').slice(0, MAX_TEXT);
  const out = [];
  const re = /(?<![\d\w])(\d{3,4}[ -]\d{3,4}|\d{4,8})(?![\d\w])/g;
  let m;
  while ((m = re.exec(t)) && out.length < 5) {
    const digits = m[1].replace(/\D/g, '');
    if (digits.length < 4 || digits.length > 8) continue;
    if (/^(19|20)\d\d$/.test(digits)) continue;   // a year
    const near = t.slice(Math.max(0, m.index - 60), m.index + m[0].length + 30);
    if (!CODE_WORD.test(near)) continue;
    out.push({ masked: '•'.repeat(digits.length), length: digits.length });
  }
  return out;
}

// Link hosts from the scanned link targets and bare URLs, each checked against the sender's domain.
function linkHosts(links, text, senderDomain) {
  const hosts = new Map();
  const add = (u) => {
    let h = '';
    try { h = new URL(String(u).trim()).hostname.toLowerCase(); } catch (_) { return; }
    if (!h || hosts.size >= 20 || hosts.has(h)) return;
    const sd = String(senderDomain || '');
    hosts.set(h, { host: h, sender_domain: Boolean(sd) && (h === sd || h.endsWith('.' + sd)) });
  };
  for (const u of links || []) { if (/^\s*https?:\/\//i.test(u)) add(u); if (hosts.size >= 20) break; }
  const urlRe = /\bhttps?:\/\/[^\s<>"'()\[\]{}]+/gi;
  let m;
  const t = String(text || '').slice(0, MAX_TEXT);
  while ((m = urlRe.exec(t)) && hosts.size < 20) add(m[0]);
  return [...hosts.values()];
}

// The list form of one message. `inFolders` names which of the caller's readable mailboxes hold it.
function formOf(email, { inFolders = [] } = {}) {
  const e = email || {};
  const from = (e.from || []).map(addr).filter(Boolean);
  const auth = authResults(e);
  const fromDomain = from.length ? domainOf(from[0]) : '';
  // Internal only when the sender's domain is ours AND the message authenticated as it (DKIM or DMARC pass): a forged
  // From: …@dustforge.com from outside stays external.
  const authenticated = auth.dkim === 'pass' || auth.dmarc === 'pass';
  const internal = INTERNAL_DOMAINS.has(fromDomain) && authenticated;
  const { html, text } = partsOf(e);
  const r = html.trim() ? reduceHtml(html) : { text, links: [] };
  const vis = stripInvisible(r.text);
  return {
    id: e.id,
    from: from[0] || null,
    to: (e.to || []).map(addr).filter(Boolean).slice(0, 20),
    cc: (e.cc || []).map(addr).filter(Boolean).slice(0, 20),
    date: e.receivedAt || e.sentAt || null,
    subject: maskSecrets(stripInvisible(e.subject || '').replace(/\n/g, ' ').slice(0, 300)),
    origin: internal ? 'internal' : 'external',
    auth: { spf: auth.spf, dkim: auth.dkim, dmarc: auth.dmarc, ...(auth.exposed ? {} : { note: 'the mail server wrote no authentication results' }) },
    unread: !((e.keywords || {})['$seen']),
    flagged: Boolean((e.keywords || {})['$flagged']),
    codes: codesIn(stripInvisible(e.subject || '') + '\n' + vis),
    link_hosts: linkHosts(r.links, html.trim() ? vis : text, fromDomain),
    attachments: (e.attachments || []).slice(0, 20).map((a) => ({ name: maskSecrets(stripInvisible(a.name || '').slice(0, 120)) || null, type: String(a.type || '').slice(0, 80), size: Number(a.size) || 0 })),
    size: Number(e.size) || null,
    in: inFolders,
  };
}

// What Email/get must ask for to build a form (and the body, on a read).
const FORM_PROPERTIES = ['id', 'mailboxIds', 'keywords', 'from', 'to', 'cc', 'subject', 'receivedAt', 'sentAt', 'size', 'attachments',
  'textBody', 'htmlBody', 'bodyValues', 'header:Authentication-Results:asText:all', 'header:Received-SPF:asText:all'];

module.exports = { formOf, visibleText, quoted, maskSecrets, htmlToVisibleText, reduceHtml, stripInvisible, codesIn, linkHosts, authResults, cssHides,
  FORM_PROPERTIES, INTERNAL_DOMAINS, MAX_HTML };
