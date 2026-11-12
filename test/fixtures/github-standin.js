// Test only — a stand-in for api.github.com behind TEST_UPSTREAM_HOSTS (test/github_app_smoke.sh). Never the service.
//   node test/fixtures/github-standin.js <port> <dir>
// POST /app/installations/:id/access_tokens — checks the app JWT (RS256 against <dir>/app*.pub, iss = <dir>/app_id,
//   iat back-dated, exp ≤ 10 min after iat) and mints a ghs_ token for exactly the repositories and permissions asked.
//   <dir>/ceiling (permission names, one per line): those are not granted to the installation → 422, as GitHub does.
//   <dir>/wide: answer with a token wider than asked (repository_selection "all").
// DELETE /installation/token — 204 for a token it minted (then forgotten), 401 otherwise.
// Anything else — 200 JSON (the legacy http_header use).
// It writes the JWTs it saw to <dir>/jwt.seen and the tokens it minted to <dir>/tokens so the smoke can assert neither
// ever reaches the server log or the database; <dir>/upstream.log gets one line per request, never a credential.
const http = require('http'), fs = require('fs'), crypto = require('crypto'), path = require('path');
const port = +process.argv[2], dir = process.argv[3];
const log = (l) => fs.appendFileSync(path.join(dir, 'upstream.log'), l + '\n');
const live = new Set();
const pubs = () => fs.readdirSync(dir).filter(f => /^app\d*\.pub$/.test(f)).map(f => fs.readFileSync(path.join(dir, f), 'utf8'));
function jwtCheck(auth) {
  const m = /^Bearer (.+)$/.exec(auth || ''); if (!m) return 'no bearer';
  const jwt = m[1]; fs.appendFileSync(path.join(dir, 'jwt.seen'), jwt + '\n');
  const [h, p, sig] = jwt.split('.'); if (!sig) return 'not a jwt';
  let head, claims; try { head = JSON.parse(Buffer.from(h, 'base64url')); claims = JSON.parse(Buffer.from(p, 'base64url')); } catch (_) { return 'unreadable'; }
  if (head.alg !== 'RS256') return 'alg ' + head.alg;
  if (!pubs().some(k => crypto.verify('RSA-SHA256', Buffer.from(h + '.' + p), k, Buffer.from(sig, 'base64url')))) return 'bad signature';
  const now = Math.floor(Date.now() / 1000), appId = fs.readFileSync(path.join(dir, 'app_id'), 'utf8').trim();
  if (String(claims.iss) !== appId) return 'iss ' + claims.iss;
  if (!(claims.iat <= now - 50 && claims.iat >= now - 70)) return 'iat not back-dated ~60 s';
  if (!(claims.exp > now && claims.exp - claims.iat <= 600)) return 'exp beyond 10 min';
  return 'ok';
}
http.createServer((req, res) => {
  let raw = ''; req.on('data', c => { raw += c; }); req.on('end', () => {
    const send = (code, obj) => { res.writeHead(code, { 'content-type': 'application/json' }); res.end(obj === undefined ? '' : JSON.stringify(obj)); };
    const mt = /^\/app\/installations\/(\d+)\/access_tokens$/.exec(req.url);
    if (req.method === 'POST' && mt) {
      const jwt = jwtCheck(req.headers.authorization);
      let b = {}; try { b = JSON.parse(raw); } catch (_) {}
      const perms = b.permissions || {}, names = b.repositories || [];
      log(`POST ${req.url} jwt=${jwt} repos=${names.join(',')} perms=${Object.entries(perms).map(([k, l]) => k + ':' + l).join(',')} ua=${req.headers['user-agent']} api=${req.headers['x-github-api-version']}`);
      if (jwt !== 'ok') return send(401, { message: 'A JSON web token could not be decoded' });
      const ceilFile = path.join(dir, 'ceiling');
      const ceiling = fs.existsSync(ceilFile) ? fs.readFileSync(ceilFile, 'utf8').split('\n').filter(Boolean) : [];
      if (Object.keys(perms).some(k => ceiling.includes(k))) return send(422, { message: 'The permissions requested are not granted to this installation.' });
      const token = 'ghs_' + crypto.randomBytes(18).toString('base64url');
      live.add(token); fs.appendFileSync(path.join(dir, 'tokens'), token + '\n');
      const wide = fs.existsSync(path.join(dir, 'wide'));
      return send(201, { token, expires_at: new Date(Date.now() + 3600 * 1000).toISOString().replace(/\.\d+Z$/, 'Z'),
        permissions: { ...perms, metadata: 'read' }, repository_selection: wide ? 'all' : 'selected',
        repositories: (wide ? [...names, 'everything-else'] : names).map(n => ({ name: n, full_name: 'bildow/' + n })) });
    }
    if (req.method === 'DELETE' && req.url === '/installation/token') {
      const t = (/^Bearer (.+)$/.exec(req.headers.authorization || '') || [])[1];
      const known = live.delete(t);
      log(`DELETE /installation/token ${known ? 'known' : 'unknown'}`);
      return send(known ? 204 : 401, known ? undefined : { message: 'Bad credentials' });
    }
    log(`${req.method} ${req.url}`);
    send(200, { path: req.url, method: req.method });
  });
}).listen(port, '127.0.0.1');
