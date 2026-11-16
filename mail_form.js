'use strict';
// ── Mail as untrusted input: the code-derived form of a message, and its visible text (pane mailboxes, phase 1) ─────
// SPEC 2026-11-16 pane mailboxes v0.2, "Reading mail safely": mail is data, never instruction. Every message is first
// reduced by code; no model runs here (the reader service is phase 2 and sits behind its own interface).
//   formOf(email)      → the fields a pane gets in a list: from, to, date, subject, internal/external, the SPF/DKIM/DMARC
//                        results Stalwart wrote (Authentication-Results, Received-SPF), codes found (masked: length
//                        only), link hosts (checked against the sender's domain), attachment names and types.
//   visibleText(email) → the body as a person would see it: HTML reduced to visible text (comments, script/style/head,
//                        hidden elements dropped), then zero-width, bidi and control characters stripped.
//   quoted(text)       → that text as a quotation ("> " on every line), capped: it is handed over as data.
// Nothing here fetches remote content, follows links or renders.

const INTERNAL_DOMAINS = new Set(['dustforge.com', 'dustanvil.com', 'dustroot.com']);
const MAX_SCAN = 200000;          // characters of body looked at for codes and links
const MAX_QUOTED = 20000;         // characters of body handed to a pane on an explicit read

// Zero-width, bidi controls, soft hyphen and other invisible formatting characters; C0/C1 controls except tab and LF.
const INVISIBLE_RE = /[­͏؜ᅟᅠ឴឵᠋-᠏​-‏‪-‮⁠-⁯ㅤ︀-️﻿ﾠ]|[\u{e0000}-\u{e007f}]/gu;
const CONTROL_RE = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/g;

function stripInvisible(s) {
  return String(s == null ? '' : s).replace(/\r\n?/g, '\n').replace(INVISIBLE_RE, '').replace(CONTROL_RE, '');
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

// Elements whose content is never visible text.
const SKIP_TAGS = new Set(['script', 'style', 'head', 'title', 'template', 'noscript', 'svg', 'math', 'iframe', 'object', 'embed', 'canvas', 'select', 'option', 'textarea', 'button', 'audio', 'video', 'map', 'frameset', 'xml']);
const VOID_TAGS = new Set(['area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link', 'meta', 'param', 'source', 'track', 'wbr', 'basefont', 'frame', 'keygen']);
const BLOCK_TAGS = new Set(['p', 'div', 'br', 'tr', 'li', 'ul', 'ol', 'table', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'blockquote', 'pre', 'hr', 'section', 'article', 'header', 'footer', 'center', 'dd', 'dt', 'dl', 'address', 'form', 'fieldset']);

function attrsOf(raw) {
  const out = {};
  const re = /([^\s=\/>"']+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+)))?/g;
  let m;
  while ((m = re.exec(raw))) out[m[1].toLowerCase()] = decodeEntities(m[2] !== undefined ? m[2] : m[3] !== undefined ? m[3] : m[4] !== undefined ? m[4] : '');
  return out;
}
// An element a reader would not see: hidden, aria-hidden, or styled out of sight (display:none, visibility:hidden,
// opacity 0, zero font size, zero size with overflow hidden, transparent text, pushed far off screen).
function hiddenByAttrs(a) {
  if ('hidden' in a) return true;
  if (String(a['aria-hidden'] || '').toLowerCase() === 'true') return true;
  if (String(a.type || '').toLowerCase() === 'hidden') return true;
  const st = String(a.style || '').toLowerCase().replace(/\s+/g, '');
  if (!st) return false;
  if (/(^|;)display:none/.test(st) || /(^|;)visibility:(hidden|collapse)/.test(st) || /(^|;)mso-hide:all/.test(st)) return true;
  if (/(^|;)opacity:0*(\.0+)?(;|$|!)/.test(st)) return true;
  if (/(^|;)font-size:0*(\.0+)?(px|pt|em|rem|%)?(;|$|!)/.test(st)) return true;
  if (/(^|;)(max-)?(height|width):0*(\.0+)?(px|pt|em|rem|%)?(;|$|!)/.test(st) && /overflow:hidden/.test(st)) return true;
  if (/(^|;)color:(transparent|rgba\([^)]*,0*(\.0+)?\))/.test(st)) return true;
  if (/(^|;)(text-indent|left|top|margin-left|margin-top):-\d{3,}/.test(st)) return true;
  if (/(^|;)clip:rect\(0(px)?,0(px)?,0(px)?,0(px)?\)/.test(st) || /clip-path:inset\(50%\)/.test(st)) return true;
  return false;
}

// HTML → the text a person would see. A tokenizer, not a full parser: an element left open that hides its content hides
// everything after it (fails closed: hidden text never leaks out through broken markup).
function htmlToVisibleText(html) {
  let s = String(html == null ? '' : html).slice(0, MAX_SCAN * 2);
  s = s.replace(/<!--[\s\S]*?(-->|$)/g, ' ')            // comments, including unterminated ones and IE conditionals
       .replace(/<!\[CDATA\[[\s\S]*?(\]\]>|$)/g, ' ')
       .replace(/<![^>]*>/g, ' ')                         // doctype and other declarations
       .replace(/<\?[\s\S]*?(\?>|$)/g, ' ');              // processing instructions
  const out = [];
  const stack = [];          // open elements: { tag, hidden }
  let hiddenDepth = 0;       // > 0 while inside a hidden or skipped element
  const re = /<(\/?)([a-zA-Z][a-zA-Z0-9:-]*)((?:[^>"']|"[^"]*"|'[^']*')*)>/g;
  let last = 0, m;
  while ((m = re.exec(s))) {
    if (!hiddenDepth) out.push(s.slice(last, m.index));
    last = re.lastIndex;
    const closing = m[1] === '/', tag = m[2].toLowerCase(), raw = m[3] || '';
    const selfClosing = /\/\s*$/.test(raw);
    if (closing) {
      // Pop to the nearest open element of that name; unmatched closers are ignored.
      for (let i = stack.length - 1; i >= 0; i--) {
        if (stack[i].tag === tag) {
          for (let j = stack.length - 1; j >= i; j--) if (stack[j].hidden) hiddenDepth--;
          stack.length = i;
          break;
        }
      }
      if (!hiddenDepth && BLOCK_TAGS.has(tag)) out.push('\n');
      continue;
    }
    if (!hiddenDepth && BLOCK_TAGS.has(tag)) out.push('\n');
    if (VOID_TAGS.has(tag) || selfClosing) continue;
    const hidden = SKIP_TAGS.has(tag) || hiddenByAttrs(attrsOf(raw));
    stack.push({ tag, hidden });
    if (hidden) hiddenDepth++;
  }
  if (!hiddenDepth) out.push(s.slice(last).replace(/<[^>]*$/, ''));
  return decodeEntities(out.join(''))
    .replace(/[ \t ]+/g, ' ')
    .replace(/ *\n */g, '\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

// The text parts of a JMAP Email (bodyValues + textBody/htmlBody), as { html, text }.
function partsOf(email) {
  const values = (email && email.bodyValues) || {};
  const pick = (list) => (Array.isArray(list) ? list : []).map((p) => (p && values[p.partId] ? String(values[p.partId].value || '') : '')).join('\n');
  const htmlParts = (email.htmlBody || []).filter((p) => /html/i.test(String(p.type || '')));
  const textParts = (email.textBody || []).filter((p) => !/html/i.test(String(p.type || '')));
  return { html: pick(htmlParts), text: pick(textParts) };
}

// The visible body: the HTML part reduced (what a person sees, so text hidden from them is gone), else the plain part.
function visibleText(email) {
  const { html, text } = partsOf(email || {});
  const source = html.trim() ? 'html' : 'text';
  const body = source === 'html' ? htmlToVisibleText(html) : text;
  return { source, text: stripInvisible(body).replace(/[ \t]+\n/g, '\n').trim() };
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
  const take = (k) => { const v = email && email[k]; return Array.isArray(v) ? v.filter(Boolean).map(String) : v ? [String(v)] : []; };
  const ar = take('header:Authentication-Results:asText:all').concat(take('header:Authentication-Results:asText'));
  const rspf = take('header:Received-SPF:asText:all').concat(take('header:Received-SPF:asText'));
  const out = { spf: null, dkim: null, dmarc: null };
  const all = ar.join(' ; ');
  for (const k of ['spf', 'dkim', 'dmarc']) {
    const m = new RegExp(`\\b${k}\\s*=\\s*([a-z]+)`, 'i').exec(all);
    if (m) out[k] = m[1].toLowerCase();
  }
  if (!out.spf && rspf.length) { const m = /^\s*([a-z]+)/i.exec(rspf[0]); if (m) out.spf = m[1].toLowerCase(); }
  out.exposed = ar.length > 0 || rspf.length > 0;
  return out;
}

// Codes: a run of 4–8 digits (spaces or dashes allowed between groups) near a word that names a code. Masked: only the
// length is returned, so a code never reaches a pane through a list (the Secure folder and code asks are phase 2).
const CODE_WORD = /(code|otp|one[- ]time|passcode|pin|verif|confirm|security|token|2fa|two[- ]factor|sign[- ]?in|log[- ]?in|password|reset|kod|c[oó]digo)/i;
function codesIn(text) {
  const t = String(text || '').slice(0, MAX_SCAN);
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

// Link hosts from hrefs and bare URLs, each checked against the sender's domain (a link elsewhere is worth knowing).
function linkHosts(html, text, senderDomain) {
  const hosts = new Map();
  const add = (u) => {
    let h = '';
    try { h = new URL(u).hostname.toLowerCase(); } catch (_) { return; }
    if (!h || hosts.size >= 20) return;
    const sd = String(senderDomain || '');
    hosts.set(h, { host: h, sender_domain: Boolean(sd) && (h === sd || h.endsWith('.' + sd)) });
  };
  const src = String(html || '').slice(0, MAX_SCAN);
  const hrefRe = /\b(?:href|src|action)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/gi;
  let m;
  while ((m = hrefRe.exec(src))) { const u = decodeEntities(m[1] || m[2] || m[3] || '').trim(); if (/^https?:\/\//i.test(u)) add(u); }
  const urlRe = /\bhttps?:\/\/[^\s<>"'()\[\]{}]+/gi;
  for (const body of [String(text || '').slice(0, MAX_SCAN), stripInvisible(src)]) { while ((m = urlRe.exec(body))) add(m[0]); }
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
  const vis = html.trim() ? htmlToVisibleText(html) : text;
  return {
    id: e.id,
    from: from[0] || null,
    to: (e.to || []).map(addr).filter(Boolean).slice(0, 20),
    cc: (e.cc || []).map(addr).filter(Boolean).slice(0, 20),
    date: e.receivedAt || e.sentAt || null,
    subject: stripInvisible(e.subject || '').replace(/\n/g, ' ').slice(0, 300),
    origin: internal ? 'internal' : 'external',
    auth: { spf: auth.spf, dkim: auth.dkim, dmarc: auth.dmarc, ...(auth.exposed ? {} : { note: 'the mail server wrote no authentication results' }) },
    unread: !((e.keywords || {})['$seen']),
    flagged: Boolean((e.keywords || {})['$flagged']),
    codes: codesIn(stripInvisible(vis)),
    link_hosts: linkHosts(html, text, fromDomain),
    attachments: (e.attachments || []).slice(0, 20).map((a) => ({ name: stripInvisible(a.name || '').slice(0, 120) || null, type: String(a.type || '').slice(0, 80), size: Number(a.size) || 0 })),
    size: Number(e.size) || null,
    in: inFolders,
  };
}

// What Email/get must ask for to build a form (and the body, on a read).
const FORM_PROPERTIES = ['id', 'mailboxIds', 'keywords', 'from', 'to', 'cc', 'subject', 'receivedAt', 'sentAt', 'size', 'attachments',
  'textBody', 'htmlBody', 'bodyValues', 'header:Authentication-Results:asText:all', 'header:Received-SPF:asText:all'];

module.exports = { formOf, visibleText, quoted, htmlToVisibleText, stripInvisible, codesIn, linkHosts, authResults, FORM_PROPERTIES, INTERNAL_DOMAINS };
