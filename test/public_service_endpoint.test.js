const {test}=require('node:test');
const assert=require('node:assert/strict');
const {assertPublicRoute}=require('../public_service_endpoint');
test('registry rejects private/VPN routes including normalized IP literals',()=>{
 for(const url of ['http://x.ts.net','https://x.ts.net','https://x.ts.net.','https://[fec0::1]','https://[64:ff9b::6453:7058]','https://[2002:6453:7058::1]','https://100.83.112.88','https://0x64537058','https://10.1.2.3','https://172.16.0.1','https://192.168.0.1','https://127.0.0.1','https://localhost','https://[fd7a:115c:a1e0::1]','https://[::ffff:100.83.112.88]','https://phasewhip']) assert.throws(()=>assertPublicRoute(url),{code:'PRIVATE_SERVICE_ROUTE'},url);
});
test('registry accepts public HTTPS and refuses plaintext or embedded credentials',()=>{
 for(const url of ['https://conduit.dustroot.com','https://repo.dustroot.com/-/fleetgate/door']) assert.equal(assertPublicRoute(url).href,new URL(url).href);
 for(const url of ['http://conduit.dustroot.com','https://user:pass@conduit.dustroot.com'])assert.throws(()=>assertPublicRoute(url));
});
