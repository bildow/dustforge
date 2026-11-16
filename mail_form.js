'use strict';
// ── Mail as untrusted input: the code-derived form of a message, and its visible text (pane mailboxes, phase 1) ─────
// SPEC 2026-11-16 pane mailboxes v0.2, "Reading mail safely": mail is data, never instruction. Every message is first
// reduced by code; no model runs here (the reader service is phase 2 and sits behind its own interface).
//   formOf(email)      → the fields a pane gets in a list: from, to, date, subject (codes masked), internal/external,
//                        the SPF/DKIM/DMARC results Stalwart wrote, codes found (length only), link hosts (checked
//                        against the sender's domain), attachment names and types.
//   visibleText(email) → the body as a person would see it: HTML reduced to visible text (comments, script/style/head,
//                        closed <details>, elements hidden by attribute, inline style or a <style> rule dropped, text
//                        under 8px or below 1.5:1 contrast dropped), then zero-width, bidi and control characters
//                        stripped. `hidden_unresolved`: the HTML carries a styling construct (phase 1's strict pane gate:
//                        a pane gets the body only of plain-text mail or of HTML with no styling at all; the owner's view
//                        is unchanged).
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

// ── CSS: mail_css.js decides, failing closed (#129 round-4): what it cannot account for marks the message unresolved.
const mailCss = require('./mail_css');

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

// HTML → { text, links, hidden, cut, unresolved, why }: the visible text, every link target (href/src/action), how
// many elements were dropped as hidden, whether the scan stopped at an unterminated construct, and whether anything in
// the message's CSS falls outside what mail_css.js accounts for (`why` says what, first).
// ── The pane gate (#129 round-5: strict for phase 1) ────────────────────────────────────────────────────────────────
// Modelling a browser is an arms race (round after round found another way to hide text), so in phase 1 a pane gets
// the body of an HTML message only when it carries NO styling construct at all; everything else is form-only until the
// phase-2 reader. mail_css.js still shapes the owner's text, but no longer gates panes.
const STYLED_REASON = 'styled mail: form only until the reader (phase 2)';
const STYLED_TAGS = new Set(['style', 'link', 'font', 'small', 'sub', 'sup', 'big', 'center', 'marquee', 'blink', 'basefont', 'details', 'dialog']);
const STYLED_ATTRS = ['style', 'bgcolor', 'background', 'color', 'text', 'size', 'face', 'link', 'vlink', 'alink', 'hidden', 'aria-hidden',
  'cellpadding', 'cellspacing', 'hspace', 'vspace', 'nowrap', 'clear', 'leftmargin', 'topmargin', 'marginwidth', 'marginheight'];
const SIZED_OK = new Set(['img', 'table', 'td', 'th', 'tr', 'col', 'colgroup']);   // width/height that cannot clip text
function styledBy(name, attrs) {
  if (STYLED_TAGS.has(name)) return `<${name}>`;
  for (const a of STYLED_ATTRS) if (a in attrs) return `a ${a} attribute on <${name}>`;
  if (('width' in attrs || 'height' in attrs) && !SIZED_OK.has(name)) return `width/height on <${name}>`;
  if (String(attrs.type || '').toLowerCase() === 'hidden') return `a hidden <${name}>`;
  return null;
}

function reduceHtml(html) {
  const s = String(html == null ? '' : html).slice(0, MAX_HTML);
  // unresolved: the pane gate (any styling construct). cssWhy: what mail_css.js could not account for (information for
  // the phase-2 reader; it no longer gates panes).
  let unresolved = false, why = null, styledDetail = null, cssWhy = null;
  const styled = (detail) => { if (!unresolved) { unresolved = true; why = STYLED_REASON; styledDetail = detail; } };
  const flag = (w) => { if (!cssWhy) cssWhy = w; };
  // Pass 1: the <style> blocks (they apply to the whole document, wherever they sit); a media attribute other than
  // all/screen makes its block conditional.
  let styles = '', pendingMedia = null;
  scan(s, { text() {}, close() {},
    open(name, attrs) {
      const st = styledBy(name, attrs);
      if (st) styled(st);
      if (name === 'style') pendingMedia = attrs.media ? String(attrs.media).toLowerCase().trim() : null;
      if (name === 'link' && /stylesheet/i.test(String(attrs.rel || ''))) flag('an external stylesheet (<link rel=stylesheet>)');
    },
    raw(name, content) {
      if (name !== 'style') return;
      const plain = !pendingMedia || /^(only\s+)?(all|screen)$/.test(pendingMedia);
      styles += plain ? content + '\n' : `@media ${pendingMedia.replace(/[{}]/g, '')}{${content}}\n`;
    } });
  const sheet = styles.trim() ? mailCss.compileSheet(styles) : null;
  if (sheet && sheet.bad) flag(sheet.why);
  // Pass 2: the visible text.
  const out = [], links = [], stack = [], openCount = new Map();
  const budget = { left: mailCss.MATCH_BUDGET };
  let hiddenDepth = 0, hidden = 0, overflow = false;
  const scanned = scan(s, {
    text(t) {
      if (hiddenDepth || overflow) return;
      if (t.trim()) {
        const c = stack.length ? stack[stack.length - 1].computed : mailCss.ROOT;
        const v = mailCss.textVerdict(c);
        if (v === 'hide') { hidden++; return; }
        if (v === 'unresolved') flag('a text colour over a background that cannot be determined');
      }
      out.push(t);
    },
    raw() {},
    open(name, attrs, selfClosing) {
      for (const k of ['href', 'src', 'action', 'background']) if (attrs[k]) links.push(attrs[k]);
      if (name === 'link' && /stylesheet/i.test(String(attrs.rel || ''))) flag('an external stylesheet (<link rel=stylesheet>)');
      if (!hiddenDepth && !overflow && BLOCK_TAGS.has(name)) out.push('\n');
      if (VOID_TAGS.has(name) || selfClosing) return;
      if (stack.length >= MAX_DEPTH) { overflow = true; return; }
      const node = { tag: name, classes: attrs.class ? String(attrs.class).toLowerCase().split(/[\s]+/).filter(Boolean) : [], id: attrs.id ? String(attrs.id).toLowerCase() : null, attrs };
      const parent = stack.length ? stack[stack.length - 1].computed : mailCss.ROOT;
      stack.push(node);                                                  // the element, after its ancestors
      let st;
      if (hiddenDepth) st = { hide: false, computed: parent };          // inside something hidden already: no work
      else {
        st = mailCss.styleOf(sheet, stack, parent, budget);
        if (st.bad) flag(st.why);
      }
      const attrHidden = 'hidden' in attrs || String(attrs['aria-hidden'] || '').toLowerCase() === 'true' || String(attrs.type || '').toLowerCase() === 'hidden'
        || (name === 'details' && !('open' in attrs));
      const h = SKIP_TAGS.has(name) || attrHidden || st.hide;
      if (h) { hiddenDepth++; if (!SKIP_TAGS.has(name)) hidden++; }
      node.h = h; node.computed = st.computed;
      openCount.set(name, (openCount.get(name) || 0) + 1);
    },
    close(name) {
      if (!openCount.get(name)) return;               // nothing of that name is open: ignored (no stack walk)
      while (stack.length) {
        const top = stack.pop();
        openCount.set(top.tag, openCount.get(top.tag) - 1);
        if (top.h) hiddenDepth--;
        if (top.tag === name) break;
      }
      if (!hiddenDepth && !overflow && BLOCK_TAGS.has(name)) out.push('\n');
    },
  });
  return { text: tidy(decodeEntities(out.join(''))), links, hidden, unresolved, why, styled_by: styledDetail, css_why: cssWhy,
    cut: scanned === 'cut' || overflow || String(html || '').length > MAX_HTML };
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

// Do the two parts say materially different things? Share of the plain part's words (3+ letters) the HTML text lacks.
function partsDiffer(htmlText, plainText) {
  const words = (t) => new Set((String(t).toLowerCase().slice(0, MAX_TEXT).match(/[\p{L}\p{N}]{3,}/gu) || []));
  const a = words(htmlText), b = words(plainText);
  if (!b.size) return false;
  let missing = 0;
  for (const w of b) if (!a.has(w)) missing++;
  return missing / b.size > 0.2 && missing >= 3;
}
// The visible body: the HTML part reduced (what a person sees, so text hidden from them is gone), else the plain part.
// The plain part stands in only when the HTML reduces to nothing; HTML that was cut short still gives its own text,
// marked cut (#129 round-3: a trailing "<b" must not hand the reader the sender-chosen plain part). `parts_differ`
// says the plain part says materially different things; `hidden_unresolved` that a hiding rule could not be placed.
function visibleText(email) {
  const { html, text } = partsOf(email || {});
  const plain = tidy(stripInvisible(text));
  if (html.trim()) {
    const r = reduceHtml(html);
    const t = tidy(stripInvisible(r.text));
    if (!t && plain) return { source: 'text', text: plain, hidden_elements: r.hidden, cut: false, html_fallback: 'empty', hidden_unresolved: r.unresolved, unresolved_why: r.why, styled_by: r.styled_by, parts_differ: false };
    return { source: 'html', text: t, hidden_elements: r.hidden, cut: r.cut, hidden_unresolved: r.unresolved, unresolved_why: r.why, styled_by: r.styled_by, parts_differ: Boolean(plain) && partsDiffer(t, plain) };
  }
  return { source: 'text', text: plain, hidden_elements: 0, cut: false, hidden_unresolved: false, parts_differ: false };
}

// Digits as ASCII: NFKC (fullwidth and other compatibility forms), then any remaining decimal digit (Arabic-Indic,
// Devanagari, …) by its place in its run of ten.
function normDigits(s) {
  return String(s || '').normalize('NFKC').replace(/\p{Nd}/gu, (d) => {
    if (d >= '0' && d <= '9') return d;
    const cp = d.codePointAt(0);
    let v = 0;
    while (v < 9 && /\p{Nd}/u.test(String.fromCodePoint(cp - v - 1))) v++;
    return String(v % 10);
  });
}
const CODE_WORDS_RE = /\b(codes?|verification|verify|otp|pin|passcode|one[- ]time|sign[- ]?in|log[- ]?in|reset|confirm(?:ation)?|2fa)\b/gi;
const KEEP_WORD = /^(codes?|verification|verify|passcode|signin|login|reset|confirm(ation)?|password)$/i;
// Links, whether or not they say https://: a token that is a host followed by a path or query keeps only the host.
function cutLinks(t) {
  return t.replace(/\S+/g, (tok) => {
    const lead = /^[("'<\[{]*/.exec(tok)[0];
    let rest = tok.slice(lead.length);
    let e = rest.length;
    while (e > 0 && ')]}>"\'.,;:!'.includes(rest[e - 1])) e--;      // a loop, not a pattern: no backtracking
    const trail = rest.slice(e);
    rest = rest.slice(0, e);
    const m = /^(https?):\/\/([^\/?#]+)(.*)$/i.exec(rest);
    if (m) { const host = m[2].replace(/^[^@]*@/, ''); return lead + m[1].toLowerCase() + '://' + host + (m[3] && m[3] !== '/' ? '/…' : '') + trail; }
    const at = rest.search(/[\/?#]/);
    if (at > 0 && at < rest.length - 1) {
      const host = rest.slice(0, at);
      if (/^[a-z0-9-]+(\.[a-z0-9-]+)*\.[a-z]{2,24}$/i.test(host) && !host.includes('@')) return lead + host + '/…' + trail;
    }
    return tok;
  });
}
// Near a code word (code, verification, OTP, PIN, passcode, one-time, sign-in, login, reset, confirm): every digit,
// and every run of 6+ capitals and digits (a letters-only code too), masked — so a code split across lines or by
// dots or spaces is masked whole.
function maskNearCodeWords(t) {
  const ranges = [];
  CODE_WORDS_RE.lastIndex = 0;
  let m;
  while ((m = CODE_WORDS_RE.exec(t))) {
    const a = Math.max(0, m.index - 60), b = Math.min(t.length, m.index + m[0].length + 120);
    const last = ranges[ranges.length - 1];
    if (last && a <= last[1]) last[1] = Math.max(last[1], b); else ranges.push([a, b]);
  }
  if (!ranges.length) return t;
  let out = '', pos = 0;
  for (const [a, b] of ranges) {
    out += t.slice(pos, a) + t.slice(a, b).replace(/\b[A-Z0-9]{6,}\b/g, (x) => (KEEP_WORD.test(x) ? x : '•'.repeat(x.length)))
      .replace(/\b[A-Za-z0-9]*[0-9][A-Za-z0-9]*\b/g, (x) => '•'.repeat(x.length))
      // Lower-case letter codes (#129 round-3 d): the word right after "code is" / "code:", a 6–10 letter word alone on its
      // line, and a 6–10 letter word with no vowels. Ordinary words elsewhere in the window are left readable.
      .replace(/\b(codes?|otp|pin|passcode)\b([ \t]*(?:is[ \t]*:?|:|=)[ \t]*)([a-z]{6,10})\b/gi, (m, w, gap, c) => (KEEP_WORD.test(c) ? m : w + gap + '•'.repeat(c.length)))
      .replace(/^([ \t]*)([a-z]{6,10})([ \t]*)$/gm, (m, l, c, r) => (KEEP_WORD.test(c) ? m : l + '•'.repeat(c.length) + r))
      .replace(/\b[b-df-hj-np-tv-xz]{6,10}\b/g, (x) => '•'.repeat(x.length));
    pos = b;
  }
  return out + t.slice(pos);
}
// What a pane is handed of a body or subject (#129 review H2, re-audit): digits normalised; links cut to their host;
// near code words every digit and capital-letter code masked; anywhere, digit runs of 4–10 (spaces, line breaks, dots
// or dashes between), letter-and-digit tokens of 6+, and any token of 20+ (a reset or sign-in token) masked. A year
// alone (19xx/20xx) is kept.
// ISO dates (and date-times), clock times and currency amounts are kept (#129 round-3 d): each valid one is set aside
// under a placeholder (\uE000 + letters + \uE001, which no mask touches) and put back after masking.
const PH = (i) => '\uE000' + String.fromCharCode(97 + Math.floor(i / 676) % 26, 97 + Math.floor(i / 26) % 26, 97 + (i % 26)) + '\uE001';
function protectSpans(t, kept) {
  const keep = (m) => { if (kept.length >= 17576) return m; kept.push(m); return PH(kept.length - 1); };
  const okTime = (h, mi, se) => Number(h) < 24 && Number(mi) < 60 && (se === undefined || Number(se) < 61);
  return t
    .replace(/(?<![\d:.\-])(\d{4})-(\d{2})-(\d{2})(?:[T ](\d{2}):(\d{2})(?::(\d{2})(?:\.\d{1,6})?)?(?:Z|[+-]\d{2}:?\d{2})?)?(?![\d:])/g,
      (m, y, mo, d, h, mi, se) => (Number(mo) >= 1 && Number(mo) <= 12 && Number(d) >= 1 && Number(d) <= 31 && (h === undefined || okTime(h, mi, se)) ? keep(m) : m))
    .replace(/(?<![\d:.])(\d{1,2}):(\d{2})(?::(\d{2}))?(?:\s?[ap]\.?m\.?)?(?![\d:])/gi, (m, h, mi, se) => (okTime(h, mi, se) ? keep(m) : m))
    .replace(/[$€£¥₹]\s?\d{1,3}(?:[,.]\d{3})*(?:[.,]\d{1,2})?(?![\d,.]\d)/g, keep)
    .replace(/(?<![\d.,])\d{1,3}(?:[,.]\d{3})*(?:[.,]\d{2})?\s?(?:USD|EUR|GBP|CAD|AUD|JPY|CHF|DD)\b/g, keep);
}
function maskSecrets(text) {
  const kept = [];
  const masked = maskNearCodeWords(protectSpans(cutLinks(normDigits(text)), kept))
    .replace(/[A-Za-z0-9_-]{20,}/g, (m) => '•'.repeat(Math.min(m.length, 24)))
    .replace(/\b(?=[A-Za-z]*\d)(?=\d*[A-Za-z])[A-Za-z0-9]{6,}\b/g, (m) => '•'.repeat(m.length))
    .replace(/(?<![\w•])\d(?:[\s.\-]?\d){3,9}(?![\w•])/g, (m) => (/^(19|20)\d\d$/.test(m) ? m : m.replace(/\d/g, '•')));
  return kept.length ? masked.replace(/\uE000([a-z]{3})\uE001/g, (m, k) => { const i = (k.charCodeAt(0) - 97) * 676 + (k.charCodeAt(1) - 97) * 26 + (k.charCodeAt(2) - 97); return kept[i] !== undefined ? kept[i] : m; }) : masked;
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
  const t = normDigits(String(text || '').slice(0, MAX_TEXT));
  const out = [];
  const re = /(?<![\d\w])(\d(?:[\s.\-]?\d){3,9})(?![\d\w])/g;
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
    ...(r.unresolved ? { hidden_unresolved: true } : {}),
    attachments: (e.attachments || []).slice(0, 20).map((a) => ({ name: maskSecrets(stripInvisible(a.name || '').slice(0, 120)) || null, type: String(a.type || '').slice(0, 80), size: Number(a.size) || 0 })),
    size: Number(e.size) || null,
    in: inFolders,
  };
}

// What Email/get must ask for to build a form (and the body, on a read).
const FORM_PROPERTIES = ['id', 'mailboxIds', 'keywords', 'from', 'to', 'cc', 'subject', 'receivedAt', 'sentAt', 'size', 'attachments',
  'textBody', 'htmlBody', 'bodyValues', 'header:Authentication-Results:asText:all', 'header:Received-SPF:asText:all'];

module.exports = { formOf, visibleText, quoted, maskSecrets, normDigits, htmlToVisibleText, reduceHtml, stripInvisible, codesIn, linkHosts, authResults,
  FORM_PROPERTIES, INTERNAL_DOMAINS, MAX_HTML };
