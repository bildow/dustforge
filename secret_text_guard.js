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
  const fs = forms(value);
  return texts.some(t => typeof t === 'string' && t.length > 0 && fs.some(f => t.includes(f)));
}

const OWN_VALUE_ERROR = "the description (or note) contains this secret's own value. Descriptions are shown to agents in every list and search: describe the secret, never quote it";

/**
 * The owner's descriptions that hold any of the owner's vault values. Returns [{id, name, ref_code, holds:[names]}]
 * and, with redact, rewrites those descriptions with every such value cut out. Values are decrypted for this call only.
 */
function sweepDescriptions(db, decrypt, did, { redact = false } = {}) {
  const rows = db.prepare("SELECT id, name, ref_code, description, encrypted_value FROM blindkey_secrets WHERE did = ? AND status != 'deleted'").all(did);
  let needles = [];
  const found = [];
  try {
    for (const r of rows) {
      let v; try { v = decrypt(r.encrypted_value); } catch (_) { continue; }
      if (typeof v === 'string' && v.length >= MIN_VAULT) needles.push({ name: r.name, forms: forms(v) });
    }
    // Longest first, so a value that contains another is cut whole.
    needles.sort((a, b) => Math.max(...b.forms.map(f => f.length)) - Math.max(...a.forms.map(f => f.length)));
    const upd = db.prepare('UPDATE blindkey_secrets SET description = ? WHERE id = ?');
    for (const r of rows) {
      const d = r.description;
      if (typeof d !== 'string' || d.length < MIN_VAULT) continue;
      const holds = needles.filter(n => n.forms.some(f => d.includes(f))).map(n => n.name);
      if (!holds.length) continue;
      found.push({ id: r.id, name: r.name, ref_code: r.ref_code, holds: [...new Set(holds)] });
      if (redact) {
        let out = d;
        for (const n of needles) for (const f of n.forms) out = out.split(f).join(REDACTED);
        upd.run(out, r.id);
      }
    }
  } finally { needles = null; }
  return found;
}

module.exports = { valueInText, sweepDescriptions, OWN_VALUE_ERROR, REDACTED, MIN_OWN, MIN_VAULT };
