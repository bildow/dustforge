'use strict';
// ── STATUS (#129 round-5): NOT A PANE GATE. ─────────────────────────────────────────────────────────────────────────────
// Phase 1 gives a pane the body only of plain-text mail or of HTML with no styling construct at all (mail_form.js,
// styledBy). This module still shapes the owner's reduced text and is kept as the starting point for the phase-2
// reader's preprocessing. Its known gaps, from the round-5 probes (tome scratch r7/r8/r9), each a way text it judged
// visible was in fact hidden (or the reverse):
//   Cascade / specificity
//     - attribute selectors are scored as classes but [class="x y z"] matches exactly, and [class=x] does not match
//       class="x y"; repeated ids (#a#a) add specificity that is not counted; :link is dropped, losing its specificity;
//     - "none + later block !important": a display:none moot-ing other properties ignores a later !important override.
//   Browser defaults not modelled
//     - the UA link colour (#0000ee) against a matching background; nested <small>/<sub>/<sup> (×10) and <font size=1>
//       inside <small> shrinking text; heading em nesting (h6 inside h6).
//   Backgrounds
//     - bgcolor attribute vs a CSS background on the same element; bg-image with white text; a dark background with an
//       image and the DEFAULT text colour (no colour set, so not treated as unresolved); td background="…" (image) dark.
//   Clipping and pushing geometry
//     - overflow:hidden with ANY width (2px, 0.1%), not only ≤1px; huge padding/margin/border (100000px) pushing text out
//       of view; vertical-align:-99999px; large positive letter-spacing; line-height:0 with height:0; max-width:0 with
//       white-space:nowrap (no overflow).
//   Elements
//     - svg <text>, foreignObject, template, noscript, object content, img alt and title attributes are dropped (safe),
//       and a hidden <input> value; the selector budget (deep descendant chains) must stay bounded.
// The phase-2 reader should treat these as open, not solved.
// ── The CSS a pane's body read may carry: an ALLOWLIST, failing closed (#129 round-4 re-audit) ─────────────────────────
// Every round of review found another way to hide text from the person while a reader still sees it. So instead of
// chasing hiding tricks, a message's CSS is checked against what this module can account for; anything else marks the
// message `unresolved`, and a pane gets the form only (pane_mail.js). The owner's view is unchanged.
//
// Accounted for:
//   - <style> rules whose selectors are compounds of a type, ASCII [a-z0-9_-] classes and ids (and [class=…],
//     [class~=…], [id=…]), joined by descendant or child combinators. They are matched exactly against the element's
//     ancestors (within a step budget). A hiding declaration also hides every element its rightmost compound matches
//     (over-hiding is the safe direction).
//   - Pseudo-classes: a positive :hover/:focus/:active/:visited rule is ignored (it applies only on interaction); :link
//     and :any-link match links. Anything else — :not(), :nth-child(), pseudo-elements, sibling combinators, other
//     attributes, escapes, non-ASCII names — is unresolved when its declarations could hide text, and ignored when
//     they could not (`*{margin:0}`, `[x-apple-data-detectors]{color:inherit}`).
//   - At-rules: @media, @supports, @layer, @container (their rules apply); @charset. Colours and backgrounds inside a
//     conditional at-rule are unresolved (the condition decides what the person sees); a conditional font-size may
//     only grow text. @import, @font-face and every other at-rule are unresolved, as is <link rel=stylesheet>.
//   - Properties, inline or in rules: an inert list (text-decoration, font-family/-weight/-style, text-align,
//     vertical-align, padding*, border*, list-style, border-collapse, table-layout, white-space, word-break, direction,
//     mso-* layout hints, …); margin and letter-spacing unless strongly negative; width/height unless combined with a
//     clipping overflow; line-height; display and visibility (none/hidden/collapse hide); font-size (below 8px, as
//     computed through em/rem/% nesting, hides); color, background, background-color, bgcolor (below 1.5:1 WCAG
//     contrast against the nearest background, in either direction, hides; a colour over a background that cannot be
//     determined is unresolved). ANY other property with a non-trivial value is unresolved (transform, filter, clip,
//     clip-path, mask, scale, zoom, opacity < 1, position other than static/relative, offsets, text-indent,
//     -webkit-text-fill-color, content, …) — unless the same block hides the element anyway (display:none) — as is a
//     backslash anywhere in the CSS or a comment inside a selector or declaration. Sibling combinators (+, ~) are not
//     matched exactly: a rule through one may only hide (by its rightmost compound); colour or size through one is
//     unresolved. Font size and contrast are judged per text run, so a font-size:0 wrapper whose children set their own
//     size stays readable.
// Cost: linear in the CSS for compiling; matching is bounded by MAX_RULES and a per-document step budget (exceeding
// either is unresolved).

const MAX_RULES = 2000;
const MATCH_BUDGET = 200000;
const MIN_FONT_PX = 8;
const MIN_CONTRAST = 1.5;

// ── colours ────────────────────────────────────────────────────────────────────────────────────────────────────────
const NAMED = Object.fromEntries('aliceblue:f0f8ff antiquewhite:faebd7 aqua:00ffff aquamarine:7fffd4 azure:f0ffff beige:f5f5dc bisque:ffe4c4 black:000000 blanchedalmond:ffebcd blue:0000ff blueviolet:8a2be2 brown:a52a2a burlywood:deb887 cadetblue:5f9ea0 chartreuse:7fff00 chocolate:d2691e coral:ff7f50 cornflowerblue:6495ed cornsilk:fff8dc crimson:dc143c cyan:00ffff darkblue:00008b darkcyan:008b8b darkgoldenrod:b8860b darkgray:a9a9a9 darkgreen:006400 darkgrey:a9a9a9 darkkhaki:bdb76b darkmagenta:8b008b darkolivegreen:556b2f darkorange:ff8c00 darkorchid:9932cc darkred:8b0000 darksalmon:e9967a darkseagreen:8fbc8f darkslateblue:483d8b darkslategray:2f4f4f darkslategrey:2f4f4f darkturquoise:00ced1 darkviolet:9400d3 deeppink:ff1493 deepskyblue:00bfff dimgray:696969 dimgrey:696969 dodgerblue:1e90ff firebrick:b22222 floralwhite:fffaf0 forestgreen:228b22 fuchsia:ff00ff gainsboro:dcdcdc ghostwhite:f8f8ff gold:ffd700 goldenrod:daa520 gray:808080 green:008000 greenyellow:adff2f grey:808080 honeydew:f0fff0 hotpink:ff69b4 indianred:cd5c5c indigo:4b0082 ivory:fffff0 khaki:f0e68c lavender:e6e6fa lavenderblush:fff0f5 lawngreen:7cfc00 lemonchiffon:fffacd lightblue:add8e6 lightcoral:f08080 lightcyan:e0ffff lightgoldenrodyellow:fafad2 lightgray:d3d3d3 lightgreen:90ee90 lightgrey:d3d3d3 lightpink:ffb6c1 lightsalmon:ffa07a lightseagreen:20b2aa lightskyblue:87cefa lightslategray:778899 lightslategrey:778899 lightsteelblue:b0c4de lightyellow:ffffe0 lime:00ff00 limegreen:32cd32 linen:faf0e6 magenta:ff00ff maroon:800000 mediumaquamarine:66cdaa mediumblue:0000cd mediumorchid:ba55d3 mediumpurple:9370db mediumseagreen:3cb371 mediumslateblue:7b68ee mediumspringgreen:00fa9a mediumturquoise:48d1cc mediumvioletred:c71585 midnightblue:191970 mintcream:f5fffa mistyrose:ffe4e1 moccasin:ffe4b5 navajowhite:ffdead navy:000080 oldlace:fdf5e6 olive:808000 olivedrab:6b8e23 orange:ffa500 orangered:ff4500 orchid:da70d6 palegoldenrod:eee8aa palegreen:98fb98 paleturquoise:afeeee palevioletred:db7093 papayawhip:ffefd5 peachpuff:ffdab9 peru:cd853f pink:ffc0cb plum:dda0dd powderblue:b0e0e6 purple:800080 rebeccapurple:663399 red:ff0000 rosybrown:bc8f8f royalblue:4169e1 saddlebrown:8b4513 salmon:fa8072 sandybrown:f4a460 seagreen:2e8b57 seashell:fff5ee sienna:a0522d silver:c0c0c0 skyblue:87ceeb slateblue:6a5acd slategray:708090 slategrey:708090 snow:fffafa springgreen:00ff7f steelblue:4682b4 tan:d2b48c teal:008080 thistle:d8bfd8 tomato:ff6347 turquoise:40e0d0 violet:ee82ee wheat:f5deb3 white:ffffff whitesmoke:f5f5f5 yellow:ffff00 yellowgreen:9acd32'
  .split(' ').map((p) => p.split(':')));
const num01 = (x, pct255) => { const s = String(x).trim(); if (s.endsWith('%')) return (parseFloat(s) / 100) * pct255; return parseFloat(s); };
function hslToRgb(h, s, l) {
  h = ((h % 360) + 360) % 360 / 360; s = Math.max(0, Math.min(1, s)); l = Math.max(0, Math.min(1, l));
  if (!s) return [l * 255, l * 255, l * 255];
  const q = l < 0.5 ? l * (1 + s) : l + s - l * s, p = 2 * l - q;
  const f = (t) => { t = (t + 1) % 1; return 255 * (t < 1 / 6 ? p + (q - p) * 6 * t : t < 1 / 2 ? q : t < 2 / 3 ? p + (q - p) * (2 / 3 - t) * 6 : p); };
  return [f(h + 1 / 3), f(h), f(h - 1 / 3)];
}
// A CSS colour value → { r, g, b, a } | 'current' | 'inherit' | null (not understood).
function parseColour(v) {
  const s = String(v || '').trim().toLowerCase();
  if (!s) return null;
  if (s === 'inherit' || s === 'unset') return 'inherit';
  if (s === 'currentcolor') return 'current';
  if (s === 'transparent') return { r: 0, g: 0, b: 0, a: 0 };
  if (NAMED[s]) { const h = NAMED[s]; return { r: parseInt(h.slice(0, 2), 16), g: parseInt(h.slice(2, 4), 16), b: parseInt(h.slice(4, 6), 16), a: 1 }; }
  let m;
  if ((m = /^#([0-9a-f]{3,4})$/.exec(s))) { const d = m[1].split('').map((x) => parseInt(x + x, 16)); return { r: d[0], g: d[1], b: d[2], a: d.length === 4 ? d[3] / 255 : 1 }; }
  if ((m = /^#([0-9a-f]{6})([0-9a-f]{2})?$/.exec(s))) return { r: parseInt(m[1].slice(0, 2), 16), g: parseInt(m[1].slice(2, 4), 16), b: parseInt(m[1].slice(4, 6), 16), a: m[2] ? parseInt(m[2], 16) / 255 : 1 };
  if ((m = /^(rgba?|hsla?)\(([^()]*)\)$/.exec(s))) {
    const parts = m[2].replace(/\s*\/\s*/, ',').split(/\s*,\s*|\s+/).filter(Boolean);
    if (parts.length < 3 || parts.length > 4 || parts.some((p) => !/^-?\d*\.?\d+%?(deg)?$/.test(p))) return null;
    const a = parts[3] !== undefined ? Math.max(0, Math.min(1, num01(parts[3], 1))) : 1;
    if (m[1].startsWith('rgb')) return { r: num01(parts[0], 255), g: num01(parts[1], 255), b: num01(parts[2], 255), a };
    const [r, g, b] = hslToRgb(parseFloat(parts[0]), parseFloat(parts[1]) / 100, parseFloat(parts[2]) / 100);
    return { r, g, b, a };
  }
  return null;
}
const blend = (fg, bg) => ({ r: fg.r * fg.a + bg.r * (1 - fg.a), g: fg.g * fg.a + bg.g * (1 - fg.a), b: fg.b * fg.a + bg.b * (1 - fg.a), a: 1 });
function luminance(c) {
  const ch = (v) => { v = Math.max(0, Math.min(255, v)) / 255; return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4); };
  return 0.2126 * ch(c.r) + 0.7152 * ch(c.g) + 0.0722 * ch(c.b);
}
function contrast(a, b) { const x = luminance(a), y = luminance(b); return (Math.max(x, y) + 0.05) / (Math.min(x, y) + 0.05); }

// ── declarations ───────────────────────────────────────────────────────────────────────────────────────────────────
const INERT = new Set(['text-decoration', 'text-decoration-line', 'text-decoration-style', 'text-decoration-color', 'text-decoration-thickness',
  'text-underline-offset', 'font-family', 'font-weight', 'font-style', 'font-variant', 'font-stretch', 'font-feature-settings', 'font-kerning',
  'text-align', 'vertical-align', 'list-style', 'list-style-type', 'list-style-position', 'list-style-image', 'border-collapse',
  'border-spacing', 'table-layout', 'caption-side', 'empty-cells', 'white-space', 'word-break', 'word-wrap', 'overflow-wrap', 'hyphens',
  'direction', 'text-transform', 'cursor', 'box-sizing', 'border-radius', 'box-shadow', 'text-shadow', 'float', 'clear',
  '-webkit-text-size-adjust', '-ms-text-size-adjust', 'text-size-adjust', '-webkit-font-smoothing', '-moz-osx-font-smoothing',
  'font-smooth', 'text-rendering', 'outline', 'outline-style', 'outline-width', 'outline-color', 'outline-offset', 'quotes',
  'background-repeat', 'background-position', 'background-size', 'background-attachment', 'background-origin', 'background-clip',
  'line-height', 'width', 'min-width', 'max-width', 'height', 'min-height', 'max-height', 'overflow', 'overflow-x', 'overflow-y',
  'display', 'visibility', 'word-spacing', '-ms-interpolation-mode', 'image-rendering', 'border-image', 'object-fit']);
const isInertName = (p) => INERT.has(p) || /^padding(-(top|right|bottom|left))?$/.test(p) || /^border(-(top|right|bottom|left))?(-(width|style|color))?$/.test(p)
  || /^border-(top|bottom)-(left|right)-radius$/.test(p) || (/^mso-/.test(p) && p !== 'mso-hide');
// Values that leave a property doing nothing. A zero is trivial only for offsets (`scale:0` hides everything).
const TRIVIAL = new Set(['inherit', 'initial', 'unset', 'revert', 'normal', 'none', 'auto']);
const ZERO_OK = new Set(['text-indent', 'top', 'left', 'right', 'bottom', 'z-index', 'transition-duration', 'transition-delay']);
const FONT_KEYWORDS = { 'xx-small': 9, 'x-small': 10, small: 13, medium: 16, large: 18, 'x-large': 24, 'xx-large': 32, 'xxx-large': 48 };
const length = (v) => { const m = /^(-?\d*\.?\d+)(px|pt|em|rem|%|ex|ch)?$/.exec(String(v).trim()); return m ? { n: parseFloat(m[1]), u: m[2] || (parseFloat(m[1]) === 0 ? 'px' : '') } : null; };
// A font-size value → { abs: px } | { rel: factor of the parent } | { root: factor of 16px } | null (not understood).
function fontSizeOf(v) {
  const s = String(v).trim();
  if (FONT_KEYWORDS[s]) return { abs: FONT_KEYWORDS[s] };
  if (s === 'smaller') return { rel: 0.83 }; if (s === 'larger') return { rel: 1.2 };
  if (s === 'inherit' || s === 'unset') return { rel: 1 };
  const l = length(s);
  if (!l) return null;
  if (l.u === 'px') return { abs: l.n }; if (l.u === 'pt') return { abs: l.n * 4 / 3 };
  if (l.u === 'em') return { rel: l.n }; if (l.u === '%') return { rel: l.n / 100 }; if (l.u === 'rem') return { root: l.n };
  if (l.u === 'ex' || l.u === 'ch') return { rel: l.n / 2 };
  return null;
}
const fontPx = (fs, parentPx) => (fs.abs !== undefined ? fs.abs : fs.rel !== undefined ? parentPx * fs.rel : 16 * fs.root);
// The background shorthand → { colour } | { unknown: true } | { none: true }.
function backgroundOf(v) {
  const s = String(v).trim();
  if (/url\(|gradient\(|image\(|element\(|cross-fade\(/.test(s)) return { unknown: true };
  if (s === 'none' || s === 'transparent' || s === 'initial' || s === 'unset') return { none: true };
  if (s === 'inherit') return { unknown: true };
  const tokens = s.match(/(rgba?|hsla?)\([^()]*\)|#[0-9a-f]+|[a-z-]+|\S+/g) || [];
  let colour = null;
  for (const t of tokens) {
    const c = parseColour(t);
    if (c && typeof c === 'object') { if (colour) return { unknown: true }; colour = c; }
    else if (c === 'current') return { current: true };
    else if (!/^(no-repeat|repeat|repeat-x|repeat-y|top|bottom|left|right|center|scroll|fixed|local|\d+(px|%)?|0|auto|cover|contain|border-box|padding-box|content-box)$/.test(t)) return { unknown: true };
  }
  return colour ? { colour } : { none: true };
}

// One declaration block (inline style, or a rule's body) → { bad, why, hide, hideAbsSmall, decls: Map(prop → {value,
// important}), capable }. `capable`: it sets something that could hide text (anything but the inert list).
function parseBlock(raw) {
  // paint: it sets something that decides how text looks (colour, background, size): those need an exact match.
  const out = { bad: false, why: null, hide: false, decls: new Map(), capable: false, paint: false };
  const hard = (why) => { if (!out.bad) { out.bad = true; out.why = why; } };
  // A property this module cannot account for is moot when the same block hides the element anyway (a preheader's
  // "display:none; opacity:0; max-height:0; overflow:hidden"): those are recorded and count only if it does not.
  let softWhy = null;
  const bad = (why) => { if (!softWhy) softWhy = why; };
  for (let part of String(raw).split(';')) {
    if (!part.replace(/[\s\u0002]+/g, '')) continue;
    part = part.trim();
    if (part.includes('\u0002')) { hard('a comment inside a declaration'); continue; }
    const c = part.indexOf(':');
    if (c < 1) { hard('a declaration that does not parse'); continue; }
    const prop = part.slice(0, c).trim();
    let value = part.slice(c + 1).trim();
    const important = /!\s*important\s*$/.test(value);
    if (important) value = value.replace(/!\s*important\s*$/, '').trim();
    if (!/^-?[a-z][a-z0-9-]*$/.test(prop)) { hard(`property ${prop.slice(0, 40)}`); continue; }
    out.decls.set(prop, { value, important: important || (out.decls.get(prop) || {}).important || false });
    const trivial = TRIVIAL.has(value);
    if (prop === 'display') { if (value === 'none') out.hide = true; else if (!/^[a-z-]+( [a-z-]+)?$/.test(value)) bad('display value'); if (value === 'none') out.capable = true; continue; }
    if (prop === 'visibility') { if (value === 'hidden' || value === 'collapse') { out.hide = true; out.capable = true; } else if (!/^(visible|inherit|initial|unset)$/.test(value)) bad('visibility value'); continue; }
    if (prop === 'mso-hide') { if (value === 'all') { out.hide = true; out.capable = true; } else if (value !== 'none') bad('mso-hide value'); continue; }
    if (prop === 'font-size') { if (!/^(inherit|unset)$/.test(value)) out.capable = out.paint = true; if (!fontSizeOf(value)) bad(`font-size ${value.slice(0, 30)}`); continue; }
    if (prop === 'font') {
      out.capable = out.paint = true;
      const sz = /(^|\s)((?:\d*\.?\d+)(?:px|pt|em|rem|%)|0|xx-small|x-small|small|medium|large|x-large|xx-large)(\/|\s|$)/.exec(value);
      if (!sz) bad('a font shorthand without a size'); else out.decls.set('font-size', { value: sz[2], important });
      continue;
    }
    if (prop === 'opacity') { out.capable = true; const n = /^(\d*\.?\d+)(%)?$/.exec(value); if (!n || parseFloat(n[1]) / (n[2] ? 100 : 1) < 1) bad('opacity below 1'); continue; }
    if (prop === 'color') { if (!/^(inherit|unset|initial|currentcolor)$/.test(value)) out.capable = out.paint = true; if (parseColour(value) === null) bad(`color ${value.slice(0, 30)}`); continue; }
    if (prop === 'background-color') { out.capable = out.paint = true; if (parseColour(value) === null) bad(`background-color ${value.slice(0, 30)}`); continue; }
    if (prop === 'background' || prop === 'background-image') { if (!/^(none|inherit|initial|unset|transparent)$/.test(value)) out.capable = out.paint = true; continue; }
    if (/^margin(-(top|right|bottom|left))?$/.test(prop) || prop === 'letter-spacing' || prop === 'word-spacing') {
      for (const t of value.split(/\s+/)) { const l = length(t); if (l && l.n < 0 && ((l.u === 'px' && l.n <= (prop === 'letter-spacing' ? -2 : -20)) || (l.u !== 'px' && l.n <= -1))) bad(`${prop} ${value.slice(0, 20)}`); }
      continue;
    }
    if (isInertName(prop)) continue;
    if (prop === 'position' && (value === 'static' || value === 'relative')) continue;   // offsets are checked on their own
    if (trivial || (ZERO_OK.has(prop) && /^0(px|em|rem|%)?$/.test(value))) continue;
    out.capable = true;
    bad(`${prop} ${value.slice(0, 30)}`);
  }
  // A clipping overflow with a set height (or a near-zero width) can hide text.
  const ov = ['overflow', 'overflow-x', 'overflow-y'].map((k) => (out.decls.get(k) || {}).value).filter(Boolean);
  if (ov.some((v) => v !== 'visible')) {
    out.capable = true;
    if (['height', 'max-height'].some((k) => { const d = out.decls.get(k); return d && !/^(auto|none|inherit|initial|unset)$/.test(d.value); })) bad('overflow with a height');
    if (['width', 'max-width'].some((k) => { const d = out.decls.get(k); const l = d && length(d.value); return l && l.n <= 1 && l.u !== '%'; })) bad('overflow with a near-zero width');
  }
  if (softWhy && !out.hide) hard(softWhy);
  return out;
}

// ── stylesheets ────────────────────────────────────────────────────────────────────────────────────────────────────
// Lower-cased; comments become \u0002 (so one inside a selector or a declaration can be told apart from one between).
function cssText(raw) {
  const s = String(raw || '');
  let out = '', i = 0;
  while (i < s.length) {
    const a = s.indexOf('/*', i);
    if (a < 0) { out += s.slice(i); break; }
    out += s.slice(i, a) + '\u0002';
    const b = s.indexOf('*/', a + 2);
    if (b < 0) break;
    i = b + 2;
  }
  return out.toLowerCase();
}
function topLevelSplit(s, ch) {
  const out = []; let depth = 0, start = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === '(') depth++; else if (c === ')') depth = Math.max(0, depth - 1);
    else if (c === ch && depth === 0) { out.push(s.slice(start, i)); start = i + 1; }
  }
  out.push(s.slice(start));
  return out;
}
const STATE = /:(hover|focus|active|visited|focus-within|focus-visible)\b/;
const PSEUDO_EL = /::|:(before|after|first-line|first-letter|marker|placeholder|selection|backdrop)\b/;
// One selector → { compounds:[{tag, classes, id}], combs:[' '|'>'], spec } | { ignore } | { unresolvable: why }.
function parseSelector(sel0, attrs) {
  let sel = sel0.replace(/\s*\u0002+\s*/g, (m) => (/\s/.test(m) ? ' ' : '\u0002')).trim();
  if (!sel) return { unresolvable: 'an empty selector' };
  if (sel.includes('\u0002')) return { unresolvable: 'a comment inside a selector' };
  if (/:not\([^)]*:(hover|focus|active|visited|focus-within|focus-visible)/.test(sel)) return { unresolvable: ':not() with a state', always: true };
  if (PSEUDO_EL.test(sel)) return { unresolvable: 'a pseudo-element' };
  sel = sel.replace(/:(link|any-link)\b/g, '');
  const states = STATE.test(sel);
  if (/:/.test(sel.replace(STATE, ''))) return { unresolvable: 'a pseudo-class' };
  if (states) return { ignore: 'a state the reader brings about (hover, focus)' };
  const sibling = /[+~]/.test(sel);
  const parts = sel.split(/\s*([>+~])\s*|\s+/).filter((x) => x !== undefined && x !== '');
  const compounds = [], combs = [];
  let pending = ' ';
  for (const p of parts) {
    if (p === '>' || p === '+' || p === '~') { pending = p; continue; }
    const m = /^(\*|[a-z][a-z0-9-]*)?((?:[.#][a-z0-9_-]+|\u0001\d+\u0001)*)$/.exec(p);
    if (!m || (!m[1] && !m[2])) return { unresolvable: `selector part ${p.replace(/\u0001\d+\u0001/g, '[…]').slice(0, 30)}` };
    const comp = { tag: m[1] && m[1] !== '*' ? m[1] : null, classes: [], id: null };
    for (const t of m[2].match(/[.#][a-z0-9_-]+|\u0001\d+\u0001/g) || []) {
      if (t[0] === '.') comp.classes.push(t.slice(1));
      else if (t[0] === '#') { if (comp.id && comp.id !== t.slice(1)) return { unresolvable: 'two ids' }; comp.id = t.slice(1); }
      else {
        const a = /^\s*(class|id)\s*(~?=)\s*(?:"([a-z0-9_ -]*)"|'([a-z0-9_ -]*)'|([a-z0-9_-]+))\s*$/.exec(attrs[Number(t.slice(1, -1))] || '');
        if (!a) return { unresolvable: 'an attribute selector' };
        const val = (a[3] !== undefined ? a[3] : a[4] !== undefined ? a[4] : a[5]).trim();
        const words = val.split(/\s+/).filter(Boolean);
        if (a[1] === 'id') { if (words.length !== 1) return { unresolvable: 'an id attribute selector' }; comp.id = words[0]; }
        else if (a[2] === '~=' && words.length === 1) comp.classes.push(words[0]);
        else if (a[2] === '=' && words.length) comp.classes.push(...words);
        else return { unresolvable: 'a class attribute selector' };
      }
    }
    if (compounds.length) combs.push(pending);
    compounds.push(comp); pending = ' ';
  }
  if (!compounds.length) return { unresolvable: 'an empty selector' };
  const spec = [0, 0, 0];
  for (const c of compounds) { if (c.id) spec[0]++; spec[1] += c.classes.length; if (c.tag) spec[2]++; }
  return { compounds, combs, spec, sibling };
}
const ROOTISH = new Set(['html', 'body']);
// <style> text(s) → a sheet: { bad, why, rules, index }. Statement at-rules are skipped; @charset is harmless.
function compileSheet(css) {
  const sheet = { bad: false, why: null, rules: [], index: new Map(), seen: new Set() };
  const bad = (why) => { if (!sheet.bad) { sheet.bad = true; sheet.why = why; } };
  if (css.includes('\\')) bad('an escape in the CSS');
  const s = cssText(css);
  const stack = [];
  let start = 0, i = 0, order = 0;
  while (i < s.length) {
    const o = s.indexOf('{', i), c = s.indexOf('}', i);
    if (o < 0 && c < 0) { if (/@import/.test(s.slice(start))) bad('@import'); break; }
    if (c >= 0 && (o < 0 || c < o)) { stack.pop(); i = start = c + 1; continue; }
    let prelude = s.slice(start, o);
    const semi = prelude.lastIndexOf(';');
    if (semi >= 0) {
      for (const st of prelude.slice(0, semi).split(';')) { const t = st.replace(/[\s\u0002]+/g, ' ').trim(); if (t && !/^@charset\b/.test(t)) bad(t.startsWith('@import') ? '@import' : `${t.slice(0, 30)}`); }
      prelude = prelude.slice(semi + 1);
    }
    prelude = prelude.trim();
    if (prelude.startsWith('@')) {
      const kind = /^@([a-z-]+)/.exec(prelude);
      const name = kind ? kind[1] : '';
      if (!['media', 'supports', 'layer', 'container'].includes(name)) { bad(`@${name}`); stack.push('skip'); }
      else stack.push(name === 'media' && /^@media\s+(only\s+)?(all|screen)\s*$/.test(prelude) ? 'plain' : 'conditional');
      i = start = o + 1; continue;
    }
    const close = s.indexOf('}', o + 1);
    const body = close < 0 ? s.slice(o + 1) : s.slice(o + 1, close);
    i = start = close < 0 ? s.length : close + 1;
    if (stack.includes('skip')) continue;
    const conditional = stack.includes('conditional');
    const key = prelude + '{' + body + (conditional ? '|c' : '');
    if (sheet.seen.has(key)) continue;
    sheet.seen.add(key);
    const blk = parseBlock(body);
    if (blk.bad) { bad(blk.why); continue; }
    if (conditional) {
      for (const p of ['color', 'background', 'background-color', 'background-image']) if (blk.decls.has(p) && !TRIVIAL.has(blk.decls.get(p).value)) bad(`${p} inside a conditional at-rule`);
      const fs = blk.decls.get('font-size');
      if (fs) { const f = fontSizeOf(fs.value); if (f && ((f.rel !== undefined && f.rel < 1) || (f.root !== undefined && f.root < 1))) bad('a conditional font-size that shrinks text'); }
    }
    if (!blk.capable) continue;                        // nothing here can hide text: whatever the selector, it is inert
    const attrs = [];
    const sels = prelude.replace(/\[[^\]]*\]/g, (m) => { attrs.push(m.slice(1, -1)); return '\u0001' + (attrs.length - 1) + '\u0001'; });
    for (const sel of topLevelSplit(sels, ',')) {
      const ps = parseSelector(sel, attrs);
      if (ps.ignore) continue;
      if (ps.unresolvable) { bad(`${ps.unresolvable}: ${sel.trim().replace(/\u0001\d+\u0001/g, '[…]').slice(0, 40)}`); continue; }
      // Sibling combinators are not matched exactly: such a rule may only hide (by its rightmost compound, over-hiding).
      if (ps.sibling && blk.paint) { bad(`colour or size through a sibling combinator: ${sel.trim().slice(0, 40)}`); continue; }
      const right = ps.compounds[ps.compounds.length - 1];
      if (blk.hide && !right.tag && !right.classes.length && !right.id) { bad('a hiding rule on *'); continue; }
      if (blk.hide && right.tag && ROOTISH.has(right.tag) && !right.classes.length && !right.id) { bad(`a hiding rule on ${right.tag}`); continue; }
      if (sheet.rules.length >= MAX_RULES) { bad('too many rules'); break; }
      const rule = { ...ps, decls: blk.decls, hide: blk.hide, order: order++, conditional };
      sheet.rules.push(rule);
      const k = right.id ? 'i:' + right.id : right.classes.length ? 'c:' + right.classes[right.classes.length - 1] : right.tag ? 't:' + right.tag : '*';
      const l = sheet.index.get(k) || []; l.push(rule); sheet.index.set(k, l);
    }
  }
  return sheet;
}

// ── elements ───────────────────────────────────────────────────────────────────────────────────────────────────────
const ROOT = Object.freeze({ color: { r: 0, g: 0, b: 0, a: 1 }, colorSet: false, bg: { r: 255, g: 255, b: 255, a: 1 }, bgKnown: true, fontPx: 16 });
const compoundMatches = (c, n) => (!c.tag || c.tag === n.tag) && (!c.id || c.id === n.id) && c.classes.every((x) => n.classes.includes(x));
// Matches `rule` with its rightmost compound on nodes[k], walking ancestors (nodes[0..k-1]); budget.left counts steps.
function matchAt(rule, ci, nodes, k, budget) {
  if (--budget.left < 0) throw new Error('budget');
  if (!compoundMatches(rule.compounds[ci], nodes[k])) return false;
  if (ci === 0) return true;
  if (rule.combs[ci - 1] === '>') return k > 0 && matchAt(rule, ci - 1, nodes, k - 1, budget);
  if (rule.combs[ci - 1] !== ' ') return false;      // + and ~: not matched (hide-only rules, placed by their rightmost compound)
  for (let j = k - 1; j >= 0; j--) if (matchAt(rule, ci - 1, nodes, j, budget)) return true;
  return false;
}
const cmp = (a, b) => (a.important - b.important) || (a.inline - b.inline) || (a.spec[0] - b.spec[0]) || (a.spec[1] - b.spec[1]) || (a.spec[2] - b.spec[2]) || (a.order - b.order);
// An element's style: node = { tag, classes, id, attrs }, nodes = its ancestors then itself, parent = the parent's
// computed style. → { hide, bad, why, computed }.
function styleOf(sheet, nodes, parent, budget) {
  const n = nodes[nodes.length - 1], a = n.attrs;
  const out = { hide: false, bad: false, why: null };
  const bad = (why) => { if (!out.bad) { out.bad = true; out.why = why; } };
  const cands = [];
  if (sheet) {
    for (const k of ['t:' + n.tag, '*', ...(n.id ? ['i:' + n.id] : []), ...n.classes.map((c) => 'c:' + c)]) for (const r of sheet.index.get(k) || []) cands.push(r);
  }
  const entries = [];   // { prop, value, important, inline, spec, order }
  // Presentational hints first (lowest): <font color>, bgcolor, <font size>.
  if (n.tag === 'font' && a.color) entries.push({ prop: 'color', value: String(a.color).toLowerCase(), important: false, inline: 0, spec: [-1, 0, 0], order: -1 });
  if (a.bgcolor) entries.push({ prop: 'background-color', value: String(a.bgcolor).toLowerCase(), important: false, inline: 0, spec: [-1, 0, 0], order: -1 });
  if (n.tag === 'font' && a.size) { const sz = { 1: 10, 2: 13, 3: 16, 4: 18, 5: 24, 6: 32, 7: 48 }[String(a.size).trim()]; if (sz) entries.push({ prop: 'font-size', value: sz + 'px', important: false, inline: 0, spec: [-1, 0, 0], order: -1 }); else bad('a <font size> that does not parse'); }
  for (const r of cands) {
    let exact;
    try { exact = matchAt(r, r.compounds.length - 1, nodes, nodes.length - 1, budget); } catch (_) { bad('the selector budget ran out'); break; }
    // A hiding rule hides wherever its rightmost compound matches (over-hiding is the safe direction).
    if (r.hide && compoundMatches(r.compounds[r.compounds.length - 1], n)) out.hide = true;
    if (!exact) continue;
    for (const [prop, d] of r.decls) entries.push({ prop, value: d.value, important: d.important ? 1 : 0, inline: 0, spec: r.spec, order: r.order, conditional: r.conditional });
  }
  if (a.style) {
    const blk = parseBlock(cssText(a.style));
    if (a.style.includes('\\')) bad('an escape in a style attribute');
    if (blk.bad) bad(blk.why);
    if (blk.hide) out.hide = true;
    for (const [prop, d] of blk.decls) entries.push({ prop, value: d.value, important: d.important ? 1 : 0, inline: 1, spec: [0, 0, 0], order: 1e9 });
  }
  entries.sort(cmp);
  const win = {};
  let conditionalFont = [];
  for (const e of entries) { if (e.conditional && e.prop === 'font-size') { conditionalFont.push(e); continue; } win[e.prop] = e; }
  // Font size: the winning value, then the smallest any conditional rule could give.
  let fontPxNow = parent.fontPx;
  if (win['font-size']) { const f = fontSizeOf(win['font-size'].value); if (!f) bad('font-size'); else fontPxNow = fontPx(f, parent.fontPx); }
  for (const e of conditionalFont) { const f = fontSizeOf(e.value); if (f) fontPxNow = Math.min(fontPxNow, fontPx(f, parent.fontPx)); }
  // Colour: inherited unless set.
  let color = parent.color, colorSet = parent.colorSet;
  if (win.color) {
    const c = parseColour(win.color.value);
    if (c === null) bad('color');
    else if (c === 'inherit' || c === 'current') { /* the parent's */ }
    else { color = c; colorSet = true; }
  }
  // Background: the nearest one behind the element.
  let bg = parent.bg, bgKnown = parent.bgKnown;
  const bgDecl = [win['background-color'], win.background].filter(Boolean).sort(cmp).pop();
  if (win['background-image'] && !/^(none|initial|unset)$/.test(win['background-image'].value)) bgKnown = false;
  if (bgDecl) {
    const b = bgDecl.prop === 'background' ? backgroundOf(bgDecl.value) : (() => { const c = parseColour(bgDecl.value); return c === null ? { unknown: true } : c === 'current' ? { current: true } : c === 'inherit' ? { unknown: true } : { colour: c }; })();
    if (b.unknown) bgKnown = false;
    else if (b.current) { bg = blend({ ...color, a: color.a }, parent.bg); bgKnown = parent.bgKnown; }
    else if (b.colour) {
      if (b.colour.a >= 1) { bg = { ...b.colour, a: 1 }; bgKnown = true; }
      else if (b.colour.a > 0) { bg = blend(b.colour, parent.bg); }
    }
  }
  out.computed = { color, colorSet, bg, bgKnown, fontPx: fontPxNow };
  return out;
}
// What a text run under this computed style is: 'show', 'hide' (below 8px, or below 1.5:1 contrast) or 'unresolved'
// (a colour set over a background that cannot be determined).
function textVerdict(c) {
  if (c.fontPx < MIN_FONT_PX) return 'hide';         // per run: a font-size:0 wrapper whose children reset it stays readable
  if (c.colorSet && !c.bgKnown) return 'unresolved';
  const fg = c.color.a >= 1 ? c.color : blend(c.color, c.bg);
  return contrast(fg, c.bg) < MIN_CONTRAST ? 'hide' : 'show';
}

module.exports = { compileSheet, styleOf, textVerdict, parseBlock, parseColour, contrast, cssText, ROOT, MIN_FONT_PX, MIN_CONTRAST, MATCH_BUDGET };
