'use strict';
// ssh_targets.js — where DemiPass may SSH, and how an agent may name those hosts.
//
// The whitelist is by IP. Agents (Codex, Claude panes, Brain) pass a machine's
// OS hostname or tailnet name as readily as its IP — "flimflam-All-Series", "k1" —
// and until 2026-10-13 that earned a 403 from /use AFTER a use-token had been
// issued for it. Every ssh_exec target now goes through resolveSshTarget() first,
// so the IP, the tailnet name, the OS hostname or the MagicDNS FQDN all
// canonicalise to the one whitelisted IP, and an unknown host is refused at
// request-token time with the allowed list in the error.
//
// chooseContext() is the other half of the same failure: a secret with contexts
// for several hosts (shared-kyle-ssh: phasewhip, then k1) was always resolved to
// its FIRST context, so the second host was unreachable unless the caller named
// the context by hand.

const SSH_TARGETS = [
  { ip: '192.3.84.103',  names: ['racknerd'] },
  { ip: '100.83.112.88', names: ['phasewhip'] },
  { ip: '100.94.192.51', names: ['ky7'] },
  { ip: '100.69.1.78',   names: ['k1'] },
  { ip: '100.103.90.79', names: ['flimflam', 'flimflam-all-series'] },
  { ip: '100.73.92.12',  names: ['skypie'] },   // Aaron's laptop, tailnet
];

const BLINDKEY_SSH_HOSTS = new Set(SSH_TARGETS.map(t => t.ip));
const BY_NAME = new Map();
for (const t of SSH_TARGETS) for (const n of t.names) BY_NAME.set(n, t);

const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;

/**
 * Canonicalise an agent-supplied ssh_exec target.
 * Accepts the whitelisted IP, a known name ("k1"), the OS hostname in any case
 * ("flimflam-All-Series") or a MagicDNS FQDN ("k1.taildb5a42.ts.net.").
 * @returns {{ip:string, name:string, input:string}|null} null = not an allowed host
 */
function resolveSshTarget(input) {
  if (typeof input !== 'string') return null;
  const raw = input.trim().toLowerCase().replace(/\.+$/, '');
  if (!raw) return null;
  if (IPV4.test(raw)) {
    const t = SSH_TARGETS.find(x => x.ip === raw);
    return t ? { ip: t.ip, name: t.names[0], input } : null;
  }
  if (!/^[a-z0-9.-]+$/.test(raw)) return null;
  const t = BY_NAME.get(raw) || BY_NAME.get(raw.split('.')[0]);
  return t ? { ip: t.ip, name: t.names[0], input } : null;
}

function listSshTargets() {
  return SSH_TARGETS.map(t => ({ name: t.names[0], ip: t.ip }));
}

function describeSshTargets() {
  return SSH_TARGETS.map(t => `${t.names[0]} (${t.ip})`).join(', ');
}

function sshWhitelistError(input) {
  return `host ${input} not in SSH whitelist. Allowed: ${describeSshTargets()} — pass the tailnet IP or one of these names`;
}

/**
 * Contexts store host patterns; store the whitelisted IP when a name was given
 * so later requests match whether the agent sends the name or the IP.
 * Wildcards and unknown hosts are left as written.
 */
function canonicalHostPattern(actionType, pattern) {
  if (actionType !== 'ssh_exec' || typeof pattern !== 'string') return pattern;
  if (pattern === '*' || pattern.endsWith('*')) return pattern;
  const resolved = resolveSshTarget(pattern);
  return resolved ? resolved.ip : pattern;
}

function specificity(pattern) {
  if (!pattern || pattern === '*') return 0;
  if (pattern.endsWith('*')) return 1 + pattern.length;   // prefix wildcard: longer prefix wins
  return 1000 + pattern.length;                           // exact
}

/**
 * Pick the context a use-token request runs under when the caller named none.
 * @param contexts rows from blindkey_contexts for the secret (any status)
 * @param opts.action        requested action_type
 * @param opts.targetHost    string or array of equivalents (canonical IP + what the agent typed)
 * @param opts.targetUrl     string or array
 * @param opts.patternMatch  server's blindkeyPatternMatch(pattern, value)
 * @returns {{context: object|null, matched: boolean, candidates: object[]}}
 *   context=null with candidates>0 means contexts for this action exist but none
 *   covers the target — the caller should say so and list the candidates.
 */
function chooseContext(contexts, { action, targetHost, targetUrl, patternMatch }) {
  const active = (contexts || []).filter(c => c && c.status === 'active');
  const sameAction = active.filter(c => c.action_type === action);
  if (sameAction.length === 0) {
    // historical behaviour: hand back the first active context and let
    // enforceBlindkeyContext report the action mismatch
    return { context: active[0] || null, matched: false, candidates: [] };
  }
  const isSsh = action === 'ssh_exec';
  const isHttp = action === 'http_header' || action === 'http_body';
  const targets = (isSsh ? [].concat(targetHost || []) : isHttp ? [].concat(targetUrl || []) : []).filter(Boolean);
  const patternOf = (c) => (isSsh ? c.target_host_pattern : c.target_url_pattern);
  if (targets.length === 0) return { context: sameAction[0], matched: true, candidates: sameAction };
  const matching = sameAction.filter(c => targets.some(t => patternMatch(patternOf(c), t)));
  if (matching.length === 0) return { context: null, matched: false, candidates: sameAction };
  matching.sort((a, b) => specificity(patternOf(b)) - specificity(patternOf(a)));
  return { context: matching[0], matched: true, candidates: sameAction };
}

module.exports = {
  SSH_TARGETS,
  BLINDKEY_SSH_HOSTS,
  resolveSshTarget,
  listSshTargets,
  describeSshTargets,
  sshWhitelistError,
  canonicalHostPattern,
  chooseContext,
};
