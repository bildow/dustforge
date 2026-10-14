'use strict';
// ssh_account.js — which account an ssh_exec runs as.
//
//   explicit target_user → secret.username (binding) → context.target_user_default → HARD ERROR
//
// There is no silent default. Until 2026-10-14 /api/demipass/use fell back to
// 'claude', which exists on none of Aaron's own machines, so every call that
// omitted target_user failed with "Permission denied" and the vault showed the
// credential as FAILING. A bound secret may still be used as another account
// when the caller says why (override_reason); that is logged, never refused.
//
// Logic reviewed on branch fix/account-binding-on-secrets (dustforge PR #1,
// Shadow round #2 amendments), lifted out of server.js so it can be tested.

const USERNAME_RE = /^[a-zA-Z0-9._-]+$/;      // SSH-safe: the same grammar at store, bind, context default and use
const USERNAME_MAX = 128;

function validUsername(u) {
  return typeof u === 'string' && u.length > 0 && u.length <= USERNAME_MAX && USERNAME_RE.test(u);
}

/**
 * @param {object} args
 * @param {string} [args.explicit]        target_user the caller passed
 * @param {object} [args.secret]          row with .username ('' or absent = legacy, unbound)
 * @param {object} [args.context]         row with .target_user_default
 * @param {string} [args.override_reason] required when explicit differs from the bound username
 * @returns {{ok:true, effective_user:string, attribution:'bound'|'legacy'|'override', override:object|null}
 *         |{ok:false, status:number, error:string, detail?:string}}
 */
function resolveSshTargetUser({ explicit, secret, context, override_reason } = {}) {
  const bound = !!(secret && typeof secret.username === 'string' && secret.username !== '');
  const explicitStr = (typeof explicit === 'string' && explicit.trim() !== '') ? explicit.trim() : '';
  const ctxDefault = (context && typeof context.target_user_default === 'string' && context.target_user_default !== '')
    ? context.target_user_default : '';

  if (explicitStr) {
    if (!validUsername(explicitStr)) return { ok: false, status: 400, error: 'invalid target_user' };
    if (bound && explicitStr !== secret.username) {
      const reason = (typeof override_reason === 'string' && override_reason.trim() !== '') ? override_reason.trim() : '';
      if (!reason) {
        return {
          ok: false, status: 400,
          error: 'target_user override requires override_reason',
          detail: `secret is bound to account "${secret.username}"; explicit target_user "${explicitStr}" differs. Pass override_reason (≤128 chars) to proceed.`,
        };
      }
      if (reason.length > 128 || !/^[\w .,:;/@'"()!?-]+$/.test(reason)) {
        return { ok: false, status: 400, error: 'override_reason: max 128 chars, printable ASCII' };
      }
      return { ok: true, effective_user: explicitStr, attribution: 'override', override: { bound_username: secret.username, explicit: explicitStr, reason } };
    }
    // explicit and bound and matching = bound; explicit on an unbound secret = legacy
    return { ok: true, effective_user: explicitStr, attribution: bound ? 'bound' : 'legacy', override: null };
  }

  if (bound) {
    if (!validUsername(secret.username)) return { ok: false, status: 400, error: 'invalid bound username on secret' };
    return { ok: true, effective_user: secret.username, attribution: 'bound', override: null };
  }

  if (ctxDefault) {
    if (!validUsername(ctxDefault)) return { ok: false, status: 400, error: 'invalid target_user_default on context' };
    return { ok: true, effective_user: ctxDefault, attribution: 'legacy', override: null };
  }

  return {
    ok: false, status: 400,
    error: 'target_user unresolved',
    detail: 'no explicit target_user, no account bound to the secret, no default on the context. Bind an account in the vault (Account → Save) or pass target_user.',
  };
}

module.exports = { USERNAME_RE, USERNAME_MAX, validUsername, resolveSshTargetUser };
