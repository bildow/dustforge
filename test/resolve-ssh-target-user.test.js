// Fixture-level verification of the account-binding resolver (server.js:2586).
// Extracts the resolver as a stand-alone function so we can test it without
// spinning up the whole app. If the resolver's signature changes, this file
// must be updated in lockstep.
//
// Invariant per tome/handoffs/2026-08-24-design-note-demipass-account-binding-invariant.md:
//   explicit → secret.username → context.target_user_default → HARD ERROR.
//   Legacy row (secret.username === '') accepts any explicit target_user without override.
//   Bound row (secret.username !== '') requires explicit === secret.username OR
//     params.override_reason present.
//   The 'claude' fallback that used to live at server.js:3638 must not survive
//   under any input path — i.e. no non-error return where effective_user === 'claude'
//   unless the caller *asked* for claude.

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

// Extract the resolver from server.js at load time — the sandbox has no deps,
// so we can't require() the file. Just parse the function block and eval it.
const src = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');
const start = src.indexOf('function resolveSshTargetUser');
assert.ok(start > 0, 'resolveSshTargetUser must exist in server.js');
// Skip past the argument-list braces (destructuring) — depth counting must start
// from the FIRST `{` after the closing `)` that ends the parameter list.
const argsClose = src.indexOf(')', start);
assert.ok(argsClose > 0, 'parameter list closes');
let i = src.indexOf('{', argsClose);
let depth = 0;
for (; i < src.length; i++) {
  if (src[i] === '{') depth++;
  else if (src[i] === '}') { depth--; if (depth === 0) { i++; break; } }
}
const fnSrc = src.slice(start, i);
// eslint-disable-next-line no-new-func
const factory = new Function(fnSrc + '\nreturn resolveSshTargetUser;');
const resolve = factory();
assert.strictEqual(typeof resolve, 'function', 'resolver extracted');
void vm; // silence unused-import warning

// ── Case tables ────────────────────────────────────────────────────────────

test('bound secret + no explicit → resolves to bound username, no override, attribution=bound', () => {
  const r = resolve({ secret: { username: 'flimflam' }, context: null });
  assert.strictEqual(r.ok, true);
  assert.strictEqual(r.effective_user, 'flimflam');
  assert.strictEqual(r.override, null);
  assert.strictEqual(r.attribution, 'bound');
});

test('bound secret + matching explicit → no override event, attribution=bound', () => {
  const r = resolve({ explicit: 'flimflam', secret: { username: 'flimflam' }, context: null });
  assert.strictEqual(r.ok, true);
  assert.strictEqual(r.effective_user, 'flimflam');
  assert.strictEqual(r.override, null);
  assert.strictEqual(r.attribution, 'bound');
});

test('bound secret + different explicit + no reason → HARD ERROR (override required)', () => {
  const r = resolve({ explicit: 'root', secret: { username: 'flimflam' }, context: null });
  assert.strictEqual(r.ok, false);
  assert.strictEqual(r.status, 400);
  assert.match(r.error, /override_reason/);
});

test('bound secret + different explicit + reason → override event emitted, attribution=override', () => {
  const r = resolve({ explicit: 'root', secret: { username: 'flimflam' }, context: null, override_reason: 'need to fix sudoers as root' });
  assert.strictEqual(r.ok, true);
  assert.strictEqual(r.effective_user, 'root');
  assert.ok(r.override, 'override object present');
  assert.strictEqual(r.override.bound_username, 'flimflam');
  assert.strictEqual(r.override.explicit, 'root');
  assert.strictEqual(r.override.reason, 'need to fix sudoers as root');
  assert.strictEqual(r.attribution, 'override');
});

test('legacy secret (username=\"\") + explicit → resolves to explicit, attribution=legacy', () => {
  const r = resolve({ explicit: 'flimflam', secret: { username: '' }, context: null });
  assert.strictEqual(r.ok, true);
  assert.strictEqual(r.effective_user, 'flimflam');
  assert.strictEqual(r.override, null);
  assert.strictEqual(r.attribution, 'legacy');
});

test('legacy secret + no explicit + no context default → HARD ERROR (no claude fallback)', () => {
  const r = resolve({ secret: { username: '' }, context: null });
  assert.strictEqual(r.ok, false);
  assert.strictEqual(r.status, 400);
  assert.match(r.error, /unresolved/);
  assert.notStrictEqual(r.effective_user, 'claude', 'the "claude" fallback must not resurface');
});

test('legacy secret + no explicit + context default → resolves to context default, attribution=legacy', () => {
  const r = resolve({ secret: { username: '' }, context: { target_user_default: 'apple' } });
  assert.strictEqual(r.ok, true);
  assert.strictEqual(r.effective_user, 'apple');
  assert.strictEqual(r.override, null);
  assert.strictEqual(r.attribution, 'legacy');
});

test('bound secret shadows context default (bound wins over context fallback)', () => {
  const r = resolve({ secret: { username: 'flimflam' }, context: { target_user_default: 'root' } });
  assert.strictEqual(r.ok, true);
  assert.strictEqual(r.effective_user, 'flimflam');
  assert.strictEqual(r.attribution, 'bound');
});

// Shadow round #2 item 1 (grammar drift): store/set-username/mobile/MCP now all
// use the same SSH-safe grammar as the resolver ([a-zA-Z0-9._-]). Previously
// @ and + were accepted at store but rejected by the resolver, producing a
// hard-error on later use with an "invalid bound username" message that
// looked like a resolver bug rather than a validation drift. Aligned.

test('SHADOW#1 GRAMMAR: @ in stored username is now rejected at store (aligned with resolver)', () => {
  // The resolver still shape-rejects @ if it somehow got persisted from a pre-fix DB;
  // that's the invariant it enforces. This test guards the resolver behavior.
  const r = resolve({ secret: { username: 'admin@example.com' }, context: null });
  assert.strictEqual(r.ok, false);
  assert.match(r.error, /invalid bound username/);
});

test('SHADOW#1 GRAMMAR: + in stored username is now rejected at store (aligned with resolver)', () => {
  const r = resolve({ secret: { username: 'user+role' }, context: null });
  assert.strictEqual(r.ok, false);
  assert.match(r.error, /invalid bound username/);
});

test('shape-invalid explicit target_user → HARD ERROR', () => {
  const r = resolve({ explicit: 'nobody; rm -rf /', secret: { username: '' }, context: null });
  assert.strictEqual(r.ok, false);
  assert.strictEqual(r.status, 400);
  assert.match(r.error, /invalid target_user/);
});

test('override_reason too long → HARD ERROR', () => {
  const r = resolve({ explicit: 'root', secret: { username: 'flimflam' }, context: null, override_reason: 'x'.repeat(129) });
  assert.strictEqual(r.ok, false);
  assert.match(r.error, /override_reason/);
});

test('override_reason with disallowed control chars → HARD ERROR', () => {
  const r = resolve({ explicit: 'root', secret: { username: 'flimflam' }, context: null, override_reason: 'sneaky\x00null' });
  assert.strictEqual(r.ok, false);
  assert.match(r.error, /override_reason/);
});

// ── Termination-condition check from the design note §9 ───────────────────
// flimflam-sudo backfilled to username: 'flimflam'; a subsequent use with no
// explicit target_user resolves to 'flimflam' (not 'claude'). This is the
// fixture the design note names as the ratifiable success condition.

test('TERMINATION: flimflam-sudo bound + no explicit ⇒ effective_user is "flimflam"', () => {
  const flimflamSudo = { username: 'flimflam' };
  const r = resolve({ secret: flimflamSudo, context: null });
  assert.strictEqual(r.ok, true);
  assert.strictEqual(r.effective_user, 'flimflam');
  assert.notStrictEqual(r.effective_user, 'claude');
});

// ── Source-level regressions for Shadow round #2 items 2, 4, 5 ─────────────
// These grep the server source directly. They can't fail on runtime input, but
// they catch the specific structural regressions Shadow flagged: accounting
// happening before resolver validation, dashboard omitting target_user_default,
// rotate-blind carrying the 'root' fallback outside the resolver.

test('SHADOW#2 ACCOUNTING: no pre-switch use_count bump in /use direct or Rowen paths', () => {
  // In BOTH the /use direct-path (~4055 area, was `// Update usage stats` before
  // `// Execute the action`) and the Rowen deliver path (~4881 area), the
  // UPDATE blindkey_secrets SET use_count must NOT appear between decryptedValue
  // being computed and the switch statement. Enforce structurally.
  const patterns = [
    // /use direct: was between the decrypt catch and `try { let result; switch`
    /decryptedValue = blindkeyDecrypt\(secret\.encrypted_value\);\s*\}\s*catch \(e\) \{\s*return[^}]*\}\s*\n\s*(?:\/\/[^\n]*\n\s*)*db\.prepare\('UPDATE blindkey_secrets SET use_count/,
    // Rowen: same structural signature
    /decryptedValue = blindkeyDecrypt\(secret\.encrypted_value\);\s*\}\s*catch \(e\) \{\s*return[^}]*\}\s*\n\s*(?:\/\/[^\n]*\n\s*)*db\.prepare\('UPDATE blindkey_secrets SET use_count/,
  ];
  for (const p of patterns) {
    assert.ok(!p.test(src), `pre-switch use_count bump reintroduced — Shadow #2 item 2 regression: ${p}`);
  }
});

test('SHADOW#2 DASHBOARD: /api/blindkey/dashboard context_list SELECT includes target_user_default', () => {
  const dashboardCtxQuery = /SELECT context_name, action_type, target_host_pattern[^"]*target_user_default[^"]*FROM blindkey_contexts WHERE secret_id = \? AND status = 'active'/;
  assert.match(src, dashboardCtxQuery, 'dashboard context_list must expose target_user_default');
});

test('SHADOW#2 ROTATE-BLIND: /rotate-blind routes through resolveSshTargetUser, no root fallback', () => {
  // Locate the rotate-blind handler and verify it invokes the resolver rather
  // than the old `target_user || 'root'` shortcut. Grep is coarse but the two
  // signatures cannot coexist for this fix to be correct.
  const rotBlindStart = src.indexOf("app.post('/api/blindkey/rotate-blind'");
  assert.ok(rotBlindStart > 0, 'rotate-blind endpoint must exist');
  // Bound rotate-blind body to the next app.post (roughly)
  const rotBlindEnd = src.indexOf("app.post('", rotBlindStart + 1);
  const body = src.slice(rotBlindStart, rotBlindEnd > 0 ? rotBlindEnd : rotBlindStart + 8000);
  assert.doesNotMatch(body, /target_user \|\| 'root'/, "rotate-blind still has the 'root' fallback — Shadow #2 item 5");
  assert.match(body, /resolveSshTargetUser\(/, 'rotate-blind must call the resolver');
});

test('SHADOW#2 ATTRIBUTION: secret_outcomes ALTER TABLE adds attribution column', () => {
  assert.match(src, /ALTER TABLE secret_outcomes ADD COLUMN attribution/, 'attribution column ALTER missing');
});
