#!/usr/bin/env node
'use strict';
// token-pickup — an agent collects the token its fleet owner renewed for it (silicon_renew.js). Aaron 2026-11-12.
//   node bin/token-pickup.js --init [--rotate] <dir>
//        make this agent's delivery key: an X25519 keypair, the private key in <dir>/delivery.key (0600, never printed),
//        and ask for it with a token of the agent — DEMIPASS_TOKEN, DEMIPASS_TOKEN_FILE (0600) or an existing
//        <dir>/token. The fleet owner approves the key in the app (PIN + phone) before any renewal goes to it — the
//        first key too (or the key travels in a token request: --material/--request/--claim, see --help). A token someone else saw
//        (the owner's "Mint a token", a request another member filed) is refused. While one key waits, asking for a
//        different one answers 429; --rotate asks for a new key, renewals go to the old one until it is approved.
//   node bin/token-pickup.js [--allow-narrower] <dir>
//        fetch the newest delivery for this agent's DID, open it with <dir>/delivery.key, check the token's signature
//        against the DID (did:key, Ed25519), that it is this DID's and not expired, and write it to <dir>/token (0600,
//        replaced atomically) — only if it is newer (issued later) than the token there, or that one is expired or not
//        valid; and never a narrower scope than the one held unless --allow-narrower. Then tell the server: "used" (the
//        owner's card stops saying "awaiting pickup"), or "declined" when the held token is kept (newer, or broader
//        without --allow-narrower): the delivered one is revoked and the owner's card says so. Never prints the token.
//   node bin/token-pickup.js --material <dir> | --request <dir> <fleet> <handle> | --claim <dir> [id]
//        the way in with a token request that CARRIES the key (the owner's phone signs its fingerprint; set on claim)
//   node bin/token-pickup.js --help
//        exit 0 written / kept / already there, 3 nothing to pick up, 2 could not run.
// The server only holds the sealed blob; the owner, the app and this program's output never carry the token.
// DEMIPASS_URL overrides the server. Zero dependencies (Node ≥ 18).
const fs = require('fs'), path = require('path'), crypto = require('crypto');

const API = (process.env.DEMIPASS_URL || 'https://api.dustforge.com').replace(/\/$/, '');
const INFO_PREFIX = 'demipass-token-delivery-v1:';
const SCOPE_RANK = { read: 0, write: 1, transact: 2, admin: 3, full: 3, critical: 4 };

const die = (msg, code = 2) => { console.error('token-pickup: ' + msg); process.exit(code); };
const claimsOf = (jwt) => { try { return JSON.parse(Buffer.from(String(jwt).split('.')[1], 'base64url').toString()); } catch (_) { return null; } };

// A secret file this program owns: must not be readable by others. The delivery key is ours alone — refuse a loose one.
function readPrivate(file) {
  const st = fs.statSync(file);
  if (st.mode & 0o077) die(`${file} must not be readable by group/other (chmod 600)`);
  return fs.readFileSync(file, 'utf8').trim();
}
// The token file: a loose one is tightened, not refused — it is about to be read or replaced anyway (review L7).
function readToken(file) {
  if (!fs.existsSync(file)) return null;
  const st = fs.statSync(file);
  if (st.mode & 0o077) { fs.chmodSync(file, 0o600); console.error(`token-pickup: ${file} was readable by group/other: now 0600`); }
  return fs.readFileSync(file, 'utf8').trim();
}
// Written whole or not at all: a temp file (0600) renamed over the target.
function writeSecret(file, text) {
  const tmp = `${file}.tmp-${process.pid}-${crypto.randomBytes(4).toString('hex')}`;
  fs.writeFileSync(tmp, text, { mode: 0o600, flag: 'wx' });
  fs.chmodSync(tmp, 0o600);
  fs.renameSync(tmp, file);
}

// did:key → the Ed25519 public key (multibase z = base58btc, u = base64url; multicodec 0xed 0x01), as in identity.js.
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function base58Decode(s) {
  let n = 0n;
  for (const ch of s) { const i = B58.indexOf(ch); if (i < 0) throw new Error('bad base58'); n = n * 58n + BigInt(i); }
  const bytes = [];
  while (n > 0n) { bytes.unshift(Number(n % 256n)); n /= 256n; }
  for (const ch of s) { if (ch !== '1') break; bytes.unshift(0); }
  return Buffer.from(bytes);
}
function didPublicKey(did) {
  if (!did.startsWith('did:key:')) throw new Error('not a did:key');
  const enc = did.slice(9), mb = did[8];
  const raw = mb === 'z' ? base58Decode(enc) : mb === 'u' ? Buffer.from(enc, 'base64url') : null;
  if (!raw || raw.length !== 34 || raw[0] !== 0xed || raw[1] !== 0x01) throw new Error('not an Ed25519 did:key');
  return crypto.createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), raw.subarray(2)]), format: 'der', type: 'spki' });
}
// A live token of this DID, signed by its key: its claims, or null.
function validToken(jwt, did) {
  try {
    const [h, p, sig] = String(jwt).split('.');
    if (!h || !p || !sig) return null;
    const header = JSON.parse(Buffer.from(h, 'base64url').toString());
    if (header.alg !== 'EdDSA') return null;
    if (!crypto.verify(null, Buffer.from(`${h}.${p}`), didPublicKey(did), Buffer.from(sig, 'base64url'))) return null;
    const c = JSON.parse(Buffer.from(p, 'base64url').toString());
    if (c.sub !== did || !c.exp || c.exp * 1000 <= Date.now()) return null;
    return c;
  } catch (_) { return null; }
}

function sessionToken(dir) {
  if (process.env.DEMIPASS_TOKEN) return process.env.DEMIPASS_TOKEN.trim();
  if (process.env.DEMIPASS_TOKEN_FILE) return readPrivate(process.env.DEMIPASS_TOKEN_FILE);
  const own = readToken(path.join(dir, 'token'));
  if (own) return own;
  die('set DEMIPASS_TOKEN (or DEMIPASS_TOKEN_FILE) to the agent\'s own token to register its delivery key');
}

async function init(dir, rotate) {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const keyFile = path.join(dir, 'delivery.key');
  let priv;
  if (fs.existsSync(keyFile) && !rotate) priv = crypto.createPrivateKey(readPrivate(keyFile));
  else priv = crypto.generateKeyPairSync('x25519').privateKey;
  const pub = crypto.createPublicKey(priv).export({ format: 'jwk' }).x;
  const token = sessionToken(dir);
  const r = await fetch(API + '/api/identity/delivery-key', { method: 'POST', headers: { 'content-type': 'application/json', authorization: 'Bearer ' + token },
    body: JSON.stringify({ public_key: pub }) });
  const d = await r.json().catch(() => ({}));
  if (!r.ok || !d.did) die(`the server refused the delivery key (${r.status}): ${d.error || 'no answer'}`);
  // Kept only once the server took it (set, or waiting for the owner).
  if (!fs.existsSync(keyFile) || rotate) {
    if (d.status === 'pending' && fs.existsSync(keyFile)) writeSecret(path.join(dir, 'delivery.key.pending'), priv.export({ format: 'pem', type: 'pkcs8' }));
    else writeSecret(keyFile, priv.export({ format: 'pem', type: 'pkcs8' }));
  }
  fs.writeFileSync(path.join(dir, 'did'), d.did + '\n', { mode: 0o600 });
  if (d.status === 'pending') console.log(`token-pickup: delivery key ${d.fingerprint} asked for ${d.did}: waiting for the fleet owner to approve it in the app — tell them this fingerprint${d.first_key ? '' : ' (renewals go to the current key until then)'}`);
  else console.log(`token-pickup: delivery key ${d.fingerprint} ${d.unchanged ? 'already registered' : 'registered'} for ${d.did}; private key in ${keyFile} (0600)`);
}

// ── the way in for an agent with no token of its own to ask with: a token request that carries its key ──────────────
const fingerprintOf = (b64) => crypto.createHash('sha256').update(Buffer.from(b64, 'base64url')).digest('hex').slice(0, 16);
function keyAndSecret(dir) {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const keyFile = path.join(dir, 'delivery.key'), secFile = path.join(dir, 'claim.secret');
  let priv;
  if (fs.existsSync(keyFile)) priv = crypto.createPrivateKey(readPrivate(keyFile));
  else { priv = crypto.generateKeyPairSync('x25519').privateKey; writeSecret(keyFile, priv.export({ format: 'pem', type: 'pkcs8' })); }
  if (!fs.existsSync(secFile)) writeSecret(secFile, crypto.randomBytes(24).toString('base64url') + '\n');
  const pub = crypto.createPublicKey(priv).export({ format: 'jwk' }).x;
  const hash = crypto.createHash('sha256').update(readPrivate(secFile)).digest('hex');
  return { pub, hash, fp: fingerprintOf(pub) };
}
// Print what the owner files (nothing secret: a public key and a hash).
function material(dir) {
  const m = keyAndSecret(dir);
  console.log(JSON.stringify({ delivery_key: m.pub, claim_secret_hash: m.hash, fingerprint: m.fp }));
  console.error(`token-pickup: give the fleet owner the line above; they file POST /api/fleet/<fleet>/silicons/<handle>/token-requests with it and approve it (the phone shows key ${m.fp}). Then: node bin/token-pickup.js --claim ${dir} <request id>`);
}
// The agent files it itself, with a live token of its own (not a fleet-minted one: the server refuses those).
async function request(dir, fleet, handle) {
  const m = keyAndSecret(dir);
  const r = await fetch(`${API}/api/fleet/${encodeURIComponent(fleet)}/silicons/${encodeURIComponent(handle)}/token-requests`, { method: 'POST',
    headers: { 'content-type': 'application/json', authorization: 'Bearer ' + sessionToken(dir) },
    body: JSON.stringify({ claim_secret_hash: m.hash, delivery_key: m.pub, label: 'token-pickup' }) });
  const d = await r.json().catch(() => ({}));
  if (r.status !== 202 || !d.request_id) die(`the server refused the request (${r.status}): ${d.error || 'no answer'}`);
  fs.writeFileSync(path.join(dir, 'request'), String(d.request_id) + '\n', { mode: 0o600 });
  console.log(`token-pickup: request #${d.request_id} filed with key ${m.fp}: the owner approves it in the app; then node bin/token-pickup.js --claim ${dir}`);
}
async function claim(dir, id) {
  const secFile = path.join(dir, 'claim.secret');
  if (!fs.existsSync(secFile)) die(`no claim secret in ${dir}: run --material or --request first`);
  const rid = String(id || (fs.existsSync(path.join(dir, 'request')) ? fs.readFileSync(path.join(dir, 'request'), 'utf8') : '')).trim();
  if (!/^\d+$/.test(rid)) die('which request? token-pickup.js --claim <dir> <request id>');
  const r = await fetch(`${API}/api/silicon-token-requests/${rid}/claim`, { method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ claim_secret: readPrivate(secFile) }) });
  const d = await r.json().catch(() => ({}));
  if (r.status === 202) { console.log(`token-pickup: request #${rid} is ${d.status || 'waiting'}: the owner has not approved it yet`); process.exit(3); }
  if (!r.ok || typeof d.token !== 'string') die(`the claim failed (${r.status}): ${d.error || 'no answer'}`);
  if (!validToken(d.token, d.did)) die('the claimed token is not a live token signed for ' + d.did);
  // The request must be for this agent, and the key it set must be this directory's (round-5 L2).
  const didFile = path.join(dir, 'did');
  if (fs.existsSync(didFile) && fs.readFileSync(didFile, 'utf8').trim() !== d.did) die(`request #${rid} was for ${d.did}, not this agent (${fs.readFileSync(didFile, 'utf8').trim()}): nothing written; ask the fleet owner to revoke that token`);
  const mine = fingerprintOf(crypto.createPublicKey(crypto.createPrivateKey(readPrivate(path.join(dir, 'delivery.key')))).export({ format: 'jwk' }).x);
  if (d.delivery_key_set !== undefined && d.delivery_key_set !== mine) die(`the key request #${rid} set (${d.delivery_key_set || 'none'}) is not this agent's key ${mine}: nothing written; ask the fleet owner to undo it and revoke that token`);
  writeSecret(path.join(dir, 'token'), d.token + '\n');
  fs.writeFileSync(path.join(dir, 'did'), d.did + '\n', { mode: 0o600 });
  fs.rmSync(secFile, { force: true }); fs.rmSync(path.join(dir, 'request'), { force: true });
  console.log(`token-pickup: wrote ${path.join(dir, 'token')} (0600)${d.delivery_key_set ? `; delivery key ${d.delivery_key_set} is set` : ''}`);
}

function open(del, priv, did) {
  const mine = Buffer.from(crypto.createPublicKey(priv).export({ format: 'jwk' }).x, 'base64url');
  const epk = Buffer.from(String(del.epk), 'base64url');
  const shared = crypto.diffieHellman({ privateKey: priv, publicKey: crypto.createPublicKey({ key: { kty: 'OKP', crv: 'X25519', x: String(del.epk) }, format: 'jwk' }) });
  const key = Buffer.from(crypto.hkdfSync('sha256', shared, Buffer.concat([epk, mine]), Buffer.from(`${INFO_PREFIX}${did}:${del.id}`), 32));
  shared.fill(0);
  const tag = Buffer.from(String(del.tag), 'base64url');
  if (tag.length !== 16) throw new Error('bad tag');
  const dec = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(String(del.iv), 'base64url'), { authTagLength: 16 });
  dec.setAAD(Buffer.from(`${did}:${del.id}`));
  dec.setAuthTag(tag);
  const out = JSON.parse(Buffer.concat([dec.update(Buffer.from(String(del.ciphertext), 'base64url')), dec.final()]).toString('utf8'));
  key.fill(0);
  if (!out || out.did !== did || out.delivery_id !== del.id || typeof out.token !== 'string') throw new Error('not this delivery');
  return out;
}

async function ack(token, used) {
  try {
    const r = await fetch(API + '/api/identity/token-deliveries/ack', { method: 'POST', headers: { 'content-type': 'application/json', authorization: 'Bearer ' + token },
      body: JSON.stringify({ used }) });
    if (!r.ok) console.error(`token-pickup: the server did not take the acknowledgement (${r.status})`);
  } catch (e) { console.error('token-pickup: could not acknowledge: ' + e.message); }
}

// The key that opened a delivery becomes delivery.key; the one it replaces becomes delivery.key.prev. Crash-safe (round-4
// review L4): every step is one atomic write or rename, and at every point both keys exist in some file the next run
// tries (delivery.key, .new, .prev, .pending):
//   1. the incoming key is written to delivery.key.new;  2. the current key is written to delivery.key.prev;
//   3. delivery.key.new is renamed over delivery.key;    4. a used .pending is removed.
function swapKeys(keyFile, used, prevFile, next) {
  const incoming = fs.readFileSync(used, 'utf8'), current = fs.readFileSync(keyFile, 'utf8');
  if (used !== next) writeSecret(next, incoming);
  writeSecret(prevFile, current);
  fs.renameSync(next, keyFile);
  if (used !== prevFile && used !== next && fs.existsSync(used)) fs.unlinkSync(used);
}

async function pickup(dir, allowNarrower) {
  const keyFile = path.join(dir, 'delivery.key'), didFile = path.join(dir, 'did');
  if (!fs.existsSync(keyFile) || !fs.existsSync(didFile)) die(`no delivery key in ${dir}: run --init first`);
  const did = fs.readFileSync(didFile, 'utf8').trim();
  // The approved new key, if one was waiting, and the previous key (the owner may undo a change): tried too; the one
  // that opens becomes delivery.key, the one it replaces delivery.key.prev.
  const keys = [[keyFile, crypto.createPrivateKey(readPrivate(keyFile))]];
  const pend = path.join(dir, 'delivery.key.pending'), prevFile = path.join(dir, 'delivery.key.prev'), next = keyFile + '.new';
  // (.new: a swap interrupted after it wrote the incoming key — see below)
  for (const f of [pend, prevFile, next]) if (fs.existsSync(f)) keys.push([f, crypto.createPrivateKey(readPrivate(f))]);
  const r = await fetch(API + '/api/identity/token-deliveries?did=' + encodeURIComponent(did));
  const d = await r.json().catch(() => ({}));
  if (!r.ok) die(`the server answered ${r.status}: ${d.error || 'no answer'}`);
  const list = d.deliveries || [];
  if (!list.length) { console.log('token-pickup: nothing to pick up'); process.exit(3); }
  const del = list[0];   // the newest
  let payload = null, used = null;
  for (const [f, k] of keys) { try { payload = open(del, k, did); used = f; break; } catch (_) {} }
  if (!payload) die(`the newest delivery does not open with this agent's key (was the key rotated?)`);
  if (used !== keyFile) swapKeys(keyFile, used, prevFile, next);
  const c = validToken(payload.token, did);
  if (!c) die('the newest delivery is not a live token signed for ' + did);
  const out = path.join(dir, 'token');
  const cur = validToken(readToken(out), did);
  if (cur && cur.jti === c.jti) { console.log(`token-pickup: ${out} already holds the newest delivery`); return; }
  if (cur && !(c.iat > cur.iat)) {
    console.log(`token-pickup: ${out} holds a newer token (issued ${new Date(cur.iat * 1000).toISOString()}); kept, the delivery is declined`);
    await ack(payload.token, false); return;
  }
  if (cur && (SCOPE_RANK[c.scope] ?? -1) < (SCOPE_RANK[cur.scope] ?? -1) && !allowNarrower) {
    // Declined, not left waiting: the owner's card says so, and the token nobody will hold is revoked (round-3 L5).
    console.log(`token-pickup: the delivery is ${c.scope}, narrower than the ${cur.scope} token held; kept the held one and declined it (to take a narrower token, run with --allow-narrower after the owner renews again)`);
    await ack(payload.token, false); return;
  }
  writeSecret(out, payload.token + '\n');
  await ack(payload.token, true);
  payload.token = null;
  console.log(`token-pickup: wrote ${out} (0600): scope ${c.scope}, expires ${new Date(c.exp * 1000).toISOString()}`);
}

const HELP = `token-pickup — collect the token your fleet owner renews for this agent, sealed to its own key.

  node bin/token-pickup.js [--allow-narrower] <dir>  pick up the newest renewal into <dir>/token (0600)
  node bin/token-pickup.js --init [--rotate] <dir>   make <dir>/delivery.key (0600) and ask for it as this agent's
                                                     delivery key (token: DEMIPASS_TOKEN, DEMIPASS_TOKEN_FILE or <dir>/token)
  node bin/token-pickup.js --material <dir>          print {delivery_key, claim_secret_hash} for an owner-filed request
  node bin/token-pickup.js --request <dir> <fleet> <handle>   file that request yourself (with a token of your own)
  node bin/token-pickup.js --claim <dir> [request id]          claim it: <dir>/token, and the key set

Which key renewals go to is the fleet owner's decision. Every key waits for the owner, the first one too:
  - asked with --init: the owner approves it on the agent's page in the DemiPass app (PIN + phone). Tell the owner the
    fingerprint --init prints. If the owner DENIES the ask, the token that asked is signed out — ask with a token you
    can lose (your own sign-in), not your only renewed token;
  - or carried IN an agent token request (--material / --request): the owner's phone shows "... key <fingerprint>" when
    approving the request, and the key is set when the agent claims it (--claim).

Which tokens can ask:
  - --init needs a token only the agent has seen: its own sign-in, a claimed request it (or the owner, with its
    claim_secret_hash) filed, or a renewed token. A token whose value someone else saw is refused: the owner's
    "Mint a token" button, or a request another member filed or claimed in clear.
  - --request needs a token of the agent that is not fleet-minted (the server refuses fleet-minted tokens for filing
    requests): its own sign-in. An agent without one uses --material and the owner files the request.
  - Tokens claimed before this change carry no "agent_own" mark: they cannot ask; file a new request (--material).

DEMIPASS_URL overrides the server (https://api.dustforge.com).`;
const args = process.argv.slice(2);
if (args.includes('--help') || args.includes('-h')) { console.log(HELP); process.exit(0); }
const COMMANDS = ['--init', '--material', '--request', '--claim'];
const flags = new Set(args.filter(a => a.startsWith('--') && !COMMANDS.includes(a)));
const rest = args.filter(a => !flags.has(a));
for (const f of flags) if (!['--rotate', '--allow-narrower'].includes(f)) die(`unknown option ${f}`);
(async () => {
  if (rest[0] === '--init') { if (!rest[1]) die('usage: token-pickup.js --init [--rotate] <dir>'); await init(rest[1], flags.has('--rotate')); }
  else if (rest[0] === '--material') { if (!rest[1]) die('usage: token-pickup.js --material <dir>'); material(rest[1]); }
  else if (rest[0] === '--request') { if (rest.length !== 4) die('usage: token-pickup.js --request <dir> <fleet> <handle>'); await request(rest[1], rest[2], rest[3]); }
  else if (rest[0] === '--claim') { if (!rest[1]) die('usage: token-pickup.js --claim <dir> [request id]'); await claim(rest[1], rest[2]); }
  else if (rest.length === 1 && !rest[0].startsWith('-')) await pickup(rest[0], flags.has('--allow-narrower'));
  else die('usage: token-pickup.js --help');
})().catch(e => die(e.message));
