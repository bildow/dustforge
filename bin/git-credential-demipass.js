#!/usr/bin/env node
'use strict';
// git-credential-demipass — git's credential helper for GitHub over HTTPS, answered with a GitHub App installation
// token minted by DemiPass for this one call (github_app.js). Aaron 2026-11-12. Zero dependencies (Node ≥ 18).
//
//   git config --global credential.https://github.com.helper '!node /path/to/bin/git-credential-demipass.js'
//   git config --global credential.https://github.com.useHttpPath true      # the token then covers just that repo
//
// Environment: DEMIPASS_GITHUB_REF (the GitHub App key's ref, e.g. DP-GHA-…), DEMIPASS_TOKEN or DEMIPASS_TOKEN_FILE
// (the agent's DemiPass token), optional DEMIPASS_GITHUB_SCOPE (the scope's name when the key has several),
// DEMIPASS_GITHUB_PERMISSIONS ("contents:write,pull_requests:write"; left out = the scope's own), DEMIPASS_URL.
// Each `get` is one metered /use (one token, ≤ 1 h, the repositories and permissions of the scope or fewer). `store` and
// `erase` do nothing: the token is never written anywhere. The token goes to git on stdout and nowhere else; errors go
// to stderr without it. Anything that is not https://github.com gets no answer (git asks its next helper).
const fs = require('fs');

const API = (process.env.DEMIPASS_URL || 'https://api.dustforge.com').replace(/\/$/, '');
const op = process.argv[2];
const fail = (msg) => { process.stderr.write('git-credential-demipass: ' + msg + '\n'); process.exit(1); };

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
  let res, out;
  try {
    res = await fetch(API + '/api/demipass/use', { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + demipassToken() }, body: JSON.stringify(body), signal: AbortSignal.timeout(60000) });
    out = await res.json();
  } catch (e) { fail('DemiPass did not answer: ' + (e && e.message)); }
  const token = out && out.result && out.result.token;
  if (!res.ok || typeof token !== 'string') fail(`DemiPass refused (HTTP ${res.status}): ${String((out && out.error) || 'no token').slice(0, 300)}`);
  process.stdout.write(`username=x-access-token\npassword=${token}\n`);
}
main().catch((e) => fail(String(e && e.message)));
