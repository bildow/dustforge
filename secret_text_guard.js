'use strict';
// ── Secret values out of descriptions ───────────────────────────────────────────────────────────────────────────────
// 2026-11-07: a vault description read "Unified to <the password> 2026-07-07 (was random <the old one>…)". Descriptions
// are returned by every list and search, so each agent that listed the vault printed the password into its own
// transcript (the pane-daily leak-scan hit of 12:36Z).
//
// Two parts, both careful not to become a guessing oracle ("is X one of the vault's values?"), which is what the leak
// scanner (leak_scan.js) is built around:
//   1. At store time, the description and note may not contain THE VALUE BEING STORED in the same request. The caller
//      supplied that value, so refusing tells them nothing they did not send.
//   2. Descriptions already stored are checked against ALL the owner's values only by the owner, in their own session,
//      with the PIN (POST /api/demipass/descriptions/check): names come back, never values, and the owner can have the
//      server cut the values out (redact: true).

const MIN_OWN = 6;       // the value being stored: refuse even short ones (PINs and codes excepted)
const MIN_VAULT = 8;     // the sweep: same floor as the leak scanner
const REDACTED = '[secret value removed]';

function forms(v) { return [...new Set([v, JSON.stringify(v).slice(1, -1)])]; }

/** True when `value` (≥ MIN_OWN chars) appears in any of `texts`, raw or JSON-escaped. */
function valueInText(value, ...texts) {
  if (typeof value !== 'string' || value.length < MIN_OWN) return false;
  // A pasted value often carries a trailing newline the description does not (#71 review L4).
  const fs = [...new Set([...forms(value), ...(value.trim().length >= MIN_OWN ? forms(value.trim()) : [])])];
  return texts.some(t => typeof t === 'string' && t.length > 0 && fs.some(f => t.includes(f)));
}

const OWN_VALUE_ERROR = "the description (or note) contains this secret's own value. Descriptions are shown to agents in every list and search: describe the secret, never quote it";

/**
 * The owner's descriptions and notes that hold any of the owner's vault values.
 * Returns { found: [{id, name, ref_code, fields, holds, updated_at, flagged}], unchecked } where `unchecked` counts
 * secrets whose value this server cannot read (wrapped to a phone: elevated/critical), so "clean" is never claimed for
 * them. With redactIds, only those rows (picked by the owner from a check) are rewritten with the values cut out:
 * redacting everything found would let whoever planted a list of guesses in a description they own learn, from
 * the list afterwards, which guess was right (#71 review M1). `flagged` marks the rows that look planted (changed in
 * the last 7 days, or holding the values of two or more secrets): the page leaves them unticked and says why.
 */
function sweepDescriptions(db, decrypt, did, { redactIds = null, now = Date.now() } = {}) {
  const cols = new Set(db.prepare("SELECT name FROM pragma_table_info('blindkey_secrets')").all().map(c => c.name));
  const sel = ['id', 'name', 'ref_code', 'description', 'encrypted_value', ...['note', 'updated_at', 'created_at', 'wrap_state'].filter(c => cols.has(c))];
  const rows = db.prepare(`SELECT ${sel.join(', ')} FROM blindkey_secrets WHERE did = ? AND status != 'deleted'`).all(did);
  const fields = ['description', ...(cols.has('note') ? ['note'] : [])];
  let needles = [];
  let unchecked = 0;
  const found = [];
  const pick = redactIds ? new Set(redactIds.map(Number)) : null;
  try {
    for (const r of rows) {
      if (!r.encrypted_value) continue;   // a retired version: its value was erased
      // Wrapped to the owner's phone (elevated/critical): this server cannot read it. Only these count as unchecked.
      if (r.wrap_state === 'device' || String(r.encrypted_value).startsWith('dpwrap:')) { unchecked++; continue; }
      let v; try { v = decrypt(r.encrypted_value); } catch (_) { continue; }
      if (typeof v !== 'string') continue;
      if (v.length >= MIN_VAULT) needles.push({ name: r.name, forms: forms(v) });
    }
    // Longest first, so a value that contains another is cut whole.
    needles.sort((a, b) => Math.max(...b.forms.map(f => f.length)) - Math.max(...a.forms.map(f => f.length)));
    for (const r of rows) {
      const hit = [];
      const holds = new Set();
      for (const f of fields) {
        const t = r[f];
        if (typeof t !== 'string' || t.length < MIN_VAULT) continue;
        const h = needles.filter(n => n.forms.some(x => t.includes(x))).map(n => n.name);
        if (h.length) { hit.push(f); h.forEach(x => holds.add(x)); }
      }
      if (!hit.length) continue;
      const changed = r.updated_at || r.created_at || null;
      const recent = changed ? (now - new Date(String(changed).replace(' ', 'T') + (/[zZ]|[+-]\d\d:?\d\d$/.test(changed) ? '' : 'Z')).getTime()) < 7 * 86400000 : false;
      // own: the row holds its OWN value (the 11-07 incident's shape). Only such rows start ticked: no write path lets
      // a row take its own value into its description any more, so a planted list of guesses never starts ticked.
      found.push({ id: r.id, name: r.name, ref_code: r.ref_code, fields: hit, holds: [...holds], updated_at: changed,
                   own: holds.has(r.name), flagged: recent || holds.size >= 2 });
      if (pick && pick.has(r.id)) {
        for (const f of hit) {
          let out = r[f];
          for (const n of needles) for (const x of n.forms) out = out.split(x).join(REDACTED);
          db.prepare(`UPDATE blindkey_secrets SET ${f} = ? WHERE id = ?`).run(out, r.id);   // f is 'description' or 'note'
        }
      }
    }
  } finally { needles = null; }
  return { found, unchecked };
}

/** `text` with every occurrence of `value` (raw and JSON-escaped, ≥ MIN_OWN chars) cut out; for rotation copies. */
function cutValue(text, value) {
  if (typeof text !== 'string' || typeof value !== 'string' || value.length < MIN_OWN) return text;
  let out = text;
  for (const f of forms(value)) out = out.split(f).join(REDACTED);
  return out;
}

module.exports = { valueInText, sweepDescriptions, cutValue, OWN_VALUE_ERROR, REDACTED, MIN_OWN, MIN_VAULT };
