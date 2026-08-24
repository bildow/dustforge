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

test('bound secret + no explicit → resolves to bound username, no override', () => {
  const r = resolve({ secret: { username: 'flimflam' }, context: null });
  assert.strictEqual(r.ok, true);
  assert.strictEqual(r.effective_user, 'flimflam');
  assert.strictEqual(r.override, null);
});

test('bound secret + matching explicit → no override event, resolves to explicit', () => {
  const r = resolve({ explicit: 'flimflam', secret: { username: 'flimflam' }, context: null });
  assert.strictEqual(r.ok, true);
  assert.strictEqual(r.effective_user, 'flimflam');
  assert.strictEqual(r.override, null);
});

test('bound secret + different explicit + no reason → HARD ERROR (override required)', () => {
  const r = resolve({ explicit: 'root', secret: { username: 'flimflam' }, context: null });
  assert.strictEqual(r.ok, false);
  assert.strictEqual(r.status, 400);
  assert.match(r.error, /override_reason/);
});

test('bound secret + different explicit + reason → override event emitted', () => {
  const r = resolve({ explicit: 'root', secret: { username: 'flimflam' }, context: null, override_reason: 'need to fix sudoers as root' });
  assert.strictEqual(r.ok, true);
  assert.strictEqual(r.effective_user, 'root');
  assert.ok(r.override, 'override object present');
  assert.strictEqual(r.override.bound_username, 'flimflam');
  assert.strictEqual(r.override.explicit, 'root');
  assert.strictEqual(r.override.reason, 'need to fix sudoers as root');
});

test('legacy secret (username=\"\") + explicit → resolves to explicit, no override', () => {
  const r = resolve({ explicit: 'flimflam', secret: { username: '' }, context: null });
  assert.strictEqual(r.ok, true);
  assert.strictEqual(r.effective_user, 'flimflam');
  assert.strictEqual(r.override, null);
});

test('legacy secret + no explicit + no context default → HARD ERROR (no claude fallback)', () => {
  const r = resolve({ secret: { username: '' }, context: null });
  assert.strictEqual(r.ok, false);
  assert.strictEqual(r.status, 400);
  assert.match(r.error, /unresolved/);
  assert.notStrictEqual(r.effective_user, 'claude', 'the "claude" fallback must not resurface');
});

test('legacy secret + no explicit + context default → resolves to context default', () => {
  const r = resolve({ secret: { username: '' }, context: { target_user_default: 'apple' } });
  assert.strictEqual(r.ok, true);
  assert.strictEqual(r.effective_user, 'apple');
  assert.strictEqual(r.override, null);
});

test('bound secret shadows context default (bound wins over context fallback)', () => {
  const r = resolve({ secret: { username: 'flimflam' }, context: { target_user_default: 'root' } });
  assert.strictEqual(r.ok, true);
  assert.strictEqual(r.effective_user, 'flimflam');
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
