// Test only — loaded with `node --require` by test/use_limits_smoke.sh, never by the service.
// Sends the server's fetch() calls for https://repo.dustroot.com/... to a local stand-in
// upstream (TEST_UPSTREAM), so /use runs end to end, host allow-list included, without
// touching the real Forgejo.
// TEST_UPSTREAM_HOSTS (comma-separated, default repo.dustroot.com) names the hosts sent there.
const target = process.env.TEST_UPSTREAM;
const realFetch = globalThis.fetch;
const HOSTS = String(process.env.TEST_UPSTREAM_HOSTS || 'repo.dustroot.com').split(',').map(h => 'https://' + h.trim()).filter(h => h !== 'https://');
globalThis.fetch = (input, init) => {
  const url = typeof input === 'string' ? input : input.url;
  const host = target && HOSTS.find(h => url.startsWith(h + '/'));
  if (host) return realFetch(target + url.slice(host.length), init);
  return realFetch(input, init);
};
