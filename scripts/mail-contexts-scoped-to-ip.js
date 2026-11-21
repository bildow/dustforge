#!/usr/bin/env node
// Read-only: which live pane-mail names hold a vault entry whose scopes (blindkey_contexts) name the retired
// Stalwart address rather than a name. Those scopes stop matching once PANE_MAIL_JMAP_URL is a name
// (pane_mail.js scopeFor). Prints counts and ids only, never a secret.
//   DB_PATH=/opt/dustforge/data/dustforge.db node scripts/mail-contexts-scoped-to-ip.js [needle]
const Database = require('better-sqlite3');
const db = new Database(process.env.DB_PATH || './data/dustforge.db', { readonly: true });
const needle = process.argv[2] || '100.83.112.88';
const names = db.prepare('SELECT id, name, secret_ref FROM mail_names WHERE ended_at IS NULL').all();
let flagged = 0;
for (const n of names) {
  const s = db.prepare('SELECT id FROM blindkey_secrets WHERE ref_code = ?').get(n.secret_ref);
  if (!s) { console.log(`name ${n.name} (#${n.id}): vault entry missing`); continue; }
  const ctxs = db.prepare('SELECT id, status, target_host_pattern, target_url_pattern, use_count, max_uses FROM blindkey_contexts WHERE secret_id = ?').all(s.id);
  const hit = ctxs.filter((c) => String(c.target_host_pattern || '').includes(needle) || String(c.target_url_pattern || '').includes(needle));
  if (hit.length) { flagged++; console.log(`name ${n.name} (#${n.id}): ${hit.length} of ${ctxs.length} scope(s) name ${needle}: ` + hit.map((c) => `ctx ${c.id} ${c.status} host=${c.target_host_pattern || '*'} url=${c.target_url_pattern || '*'} uses=${c.use_count}/${c.max_uses || '∞'}`).join('; ')); }
}
console.log(`${names.length} live name(s), ${flagged} with scopes naming ${needle}`);
