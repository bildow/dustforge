// Test only — loaded with `node --require` by test/use_limits_smoke.sh, never by the service.
// Sends the server's fetch() calls for https://repo.dustroot.com/... to a local stand-in
// upstream (TEST_UPSTREAM), so /use runs end to end, host allow-list included, without
// touching the real Forgejo.
const target = process.env.TEST_UPSTREAM;
const realFetch = globalThis.fetch;
const HOST = 'https://repo.dustroot.com';
globalThis.fetch = (input, init) => {
  const url = typeof input === 'string' ? input : input.url;
  if (target && url.startsWith(HOST + '/')) return realFetch(target + url.slice(HOST.length), init);
  return realFetch(input, init);
};
