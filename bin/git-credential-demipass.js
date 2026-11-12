#!/usr/bin/env node
'use strict';
// git-credential-demipass — git's credential helper for GitHub over HTTPS, answered with a GitHub App installation
// token minted by DemiPass for this one call (github_app.js). Aaron 2026-11-12. Zero dependencies (Node ≥ 18).
//
//   git config --global credential.https://github.com.helper ''              # first: clear helpers inherited from
//                                                                            # system/global config (a store helper
//                                                                            # would otherwise write the token to disk)
//   git config --global --add credential.https://github.com.helper '!node /path/to/bin/git-credential-demipass.js'
//   git config --global credential.https://github.com.useHttpPath true      # the token then covers just that repo
//
// Environment: DEMIPASS_GITHUB_REF (the GitHub App key's ref, e.g. DP-GHA-…), DEMIPASS_TOKEN or DEMIPASS_TOKEN_FILE
// (the agent's DemiPass token), optional DEMIPASS_GITHUB_SCOPE (the scope's name when the key has several),
// DEMIPASS_GITHUB_PERMISSIONS ("contents:write,pull_requests:write"; left out = the scope's own), DEMIPASS_URL.
// Each `get` is one metered /use (one token, ≤ 1 h, the repositories and permissions of the scope or fewer) and counts
// against the wallet's request budget (500 per 15 min, #103). A busy CI sets DEMIPASS_GITHUB_CACHE_DIR (a 0700 directory
// of the agent's own): a token is then kept there (0600) for its life and reused until 5 minutes before it expires.
// Without it nothing is written anywhere. `store` and `erase` do nothing. The token goes to git on stdout and nowhere
// else, with password_expiry_utc so git drops it in time; errors go to stderr without it. Anything that is not
// https://github.com gets no answer (git asks its next helper). DEMIPASS_URL must be https (loopback excepted).
const fs = require('fs'), path = require('path'), crypto = require('crypto');

const fail = (msg) => { process.stderr.write('git-credential-demipass: ' + msg + '\n'); process.exit(1); };
const API = (process.env.DEMIPASS_URL || 'https://api.dustforge.com').replace(/\/$/, '');
{
  let u; try { u = new URL(API); } catch (_) { fail('DEMIPASS_URL is not a URL'); }
  const loopback = ['127.0.0.1', 'localhost', '[::1]', '::1'].includes(u.hostname);
  if (u.protocol !== 'https:' && !(u.protocol === 'http:' && loopback)) fail('DEMIPASS_URL must be https (http only to loopback): the DemiPass token travels with each call');
}
const op = process.argv[2];
const TOKEN_RE = /^[A-Za-z0-9_.-]{20,255}$/;   // ghs_… — never a newline, never a key=value git would read as another field
const REUSE_MARGIN_S = 300;

function demipassToken() {
  if (process.env.DEMIPASS_TOKEN) return process.env.DEMIPASS_TOKEN.trim();
  const f = process.env.DEMIPASS_TOKEN_FILE;
  if (!f) fail('set DEMIPASS_TOKEN or DEMIPASS_TOKEN_FILE');
  const st = fs.statSync(f);
  if (st.mode & 0o077) fail(`${f} must not be readable by group/other (chmod 600)`);
  return fs.readFileSync(f, 'utf8').trim();
}

async function main() {
  if (op !== 'get') return;   // store / erase: nothing is kept
  let input = '';
  for await (const chunk of process.stdin) input += chunk;
  const q = {};
  for (const line of input.split('\n')) { const i = line.indexOf('='); if (i > 0) q[line.slice(0, i)] = line.slice(i + 1); }
  if (q.protocol !== 'https' || String(q.host || '').toLowerCase() !== 'github.com') return;
  const ref = process.env.DEMIPASS_GITHUB_REF;
  if (!ref) fail('set DEMIPASS_GITHUB_REF to the GitHub App key\'s ref');
  const params = {};
  const m = String(q.path || '').match(/^\/?([A-Za-z0-9-]+\/[A-Za-z0-9._-]+?)(?:\.git)?\/?$/);
  if (m) params.repositories = [m[1].toLowerCase()];
  if (process.env.DEMIPASS_GITHUB_PERMISSIONS) {
    params.permissions = {};
    for (const p of process.env.DEMIPASS_GITHUB_PERMISSIONS.split(',').map(x => x.trim()).filter(Boolean)) {
      const [k, l] = p.split(':'); params.permissions[k] = l || 'read';
    }
  }
  const body = { ref, action: 'github_app_token', params };
  if (process.env.DEMIPASS_GITHUB_SCOPE) body.context = process.env.DEMIPASS_GITHUB_SCOPE;
  const answer = (token, expiresAt) => {
    if (!TOKEN_RE.test(token)) fail('DemiPass answered with something that is not a token; nothing given to git');
    const exp = Math.floor(Date.parse(expiresAt) / 1000);
    process.stdout.write(`username=x-access-token\npassword=${token}\n${Number.isFinite(exp) ? `password_expiry_utc=${exp}\n` : ''}`);
  };
  // the opt-in cache: one file per (ref, scope, repository, permissions), 0600 in a 0700 directory of this user
  let cacheFile = null;
  const dir = process.env.DEMIPASS_GITHUB_CACHE_DIR;
  if (dir) {
    const st = fs.statSync(dir);
    if (!st.isDirectory() || (st.mode & 0o077) || (process.getuid && st.uid !== process.getuid())) fail(`${dir} must be a directory of yours, chmod 700`);
    cacheFile = path.join(dir, 'gh-' + crypto.createHash('sha256').update(JSON.stringify([API, ref, body.context || '', params])).digest('hex').slice(0, 32) + '.json');
    try {
      const fst = fs.statSync(cacheFile);
      if (!(fst.mode & 0o077) && (!process.getuid || fst.uid === process.getuid())) {
        const c = JSON.parse(fs.readFileSync(cacheFile, 'utf8'));
        if (c && typeof c.token === 'string' && Date.parse(c.expires_at) - Date.now() > REUSE_MARGIN_S * 1000) return answer(c.token, c.expires_at);
      }
    } catch (_) {}
  }
  let res, out;
  try {
    res = await fetch(API + '/api/demipass/use', { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + demipassToken() }, body: JSON.stringify(body), signal: AbortSignal.timeout(60000) });
    out = await res.json();
  } catch (e) { fail('DemiPass did not answer: ' + (e && e.message)); }
  const token = out && out.result && out.result.token;
  if (!res.ok || typeof token !== 'string') fail(`DemiPass refused (HTTP ${res.status}): ${String((out && out.error) || 'no token').slice(0, 300).replace(/[\r\n]+/g, ' ')}`);
  if (!TOKEN_RE.test(token)) fail('DemiPass answered with something that is not a token; nothing given to git');
  if (cacheFile) {
    const tmp = cacheFile + '.' + process.pid + '.tmp';
    try { fs.writeFileSync(tmp, JSON.stringify({ token, expires_at: out.result.expires_at }), { mode: 0o600 }); fs.renameSync(tmp, cacheFile); } catch (_) { try { fs.unlinkSync(tmp); } catch (__) {} }
  }
  answer(token, out.result.expires_at);
}
main().catch((e) => fail(String(e && e.message)));
