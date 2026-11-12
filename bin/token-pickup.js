#!/usr/bin/env node
'use strict';
// token-pickup — an agent collects the token its fleet owner renewed for it (silicon_renew.js). Aaron 2026-11-12.
//   node bin/token-pickup.js --init [--rotate] <dir>
//        make this agent's delivery key: an X25519 keypair, the private key in <dir>/delivery.key (0600, never printed),
//        and ask for it with a token of the agent — DEMIPASS_TOKEN, DEMIPASS_TOKEN_FILE (0600) or an existing
//        <dir>/token. The fleet owner approves the key in the app (PIN + phone) before any renewal goes to it — the
//        first key too — unless the token is the agent's own token request (see --help). A token someone else saw
//        (the owner's "Mint a token", a request another member filed) is refused. While one key waits, asking for a
//        different one answers 429; --rotate asks for a new key, renewals go to the old one until it is approved.
//   node bin/token-pickup.js [--allow-narrower] <dir>
//        fetch the newest delivery for this agent's DID, open it with <dir>/delivery.key, check the token's signature
//        against the DID (did:key, Ed25519), that it is this DID's and not expired, and write it to <dir>/token (0600,
//        replaced atomically) — only if it is newer (issued later) than the token there, or that one is expired or not
//        valid; and never a narrower scope than the one held unless --allow-narrower. Then tell the server: "used" (the
//        owner's card stops saying "awaiting pickup"), or "declined" when the held token is kept (newer, or broader
//        without --allow-narrower): the delivered one is revoked and the owner's card says so. Never prints the token.
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

async function pickup(dir, allowNarrower) {
  const keyFile = path.join(dir, 'delivery.key'), didFile = path.join(dir, 'did');
  if (!fs.existsSync(keyFile) || !fs.existsSync(didFile)) die(`no delivery key in ${dir}: run --init first`);
  const did = fs.readFileSync(didFile, 'utf8').trim();
  // The approved new key, if one was waiting, and the previous key (the owner may undo a change): tried too; the one
  // that opens becomes delivery.key, the one it replaces delivery.key.prev.
  const keys = [[keyFile, crypto.createPrivateKey(readPrivate(keyFile))]];
  const pend = path.join(dir, 'delivery.key.pending'), prevFile = path.join(dir, 'delivery.key.prev');
  if (fs.existsSync(pend)) keys.push([pend, crypto.createPrivateKey(readPrivate(pend))]);
  if (fs.existsSync(prevFile)) keys.push([prevFile, crypto.createPrivateKey(readPrivate(prevFile))]);
  const r = await fetch(API + '/api/identity/token-deliveries?did=' + encodeURIComponent(did));
  const d = await r.json().catch(() => ({}));
  if (!r.ok) die(`the server answered ${r.status}: ${d.error || 'no answer'}`);
  const list = d.deliveries || [];
  if (!list.length) { console.log('token-pickup: nothing to pick up'); process.exit(3); }
  const del = list[0];   // the newest
  let payload = null, used = null;
  for (const [f, k] of keys) { try { payload = open(del, k, did); used = f; break; } catch (_) {} }
  if (!payload) die(`the newest delivery does not open with this agent's key (was the key rotated?)`);
  if (used !== keyFile) {
    const tmp = `${keyFile}.swap-${process.pid}`;
    fs.renameSync(keyFile, tmp); fs.renameSync(used, keyFile); fs.renameSync(tmp, prevFile);
  }
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

  node bin/token-pickup.js --init [--rotate] <dir>   make <dir>/delivery.key (0600) and ask for it as this agent's
                                                     delivery key (token: DEMIPASS_TOKEN, DEMIPASS_TOKEN_FILE or <dir>/token)
  node bin/token-pickup.js [--allow-narrower] <dir>  pick up the newest renewal into <dir>/token (0600)

Which key renewals go to is the fleet owner's decision: a key asked with the agent's sign-in (or any token but the one
below) waits for the owner to approve it in the DemiPass app (Fleet -> @agent), PIN + phone. Tell the owner the
fingerprint --init prints.

A token whose value someone else saw is refused ("shown in clear": the owner's "Mint a token" button, or a token request
another member filed or claimed). The way in for such an agent, which also sets its first key at once:
  1. on the agent: keep a secret S (e.g. a 0600 file) and compute sha256(S) as hex;
  2. the fleet owner files POST /api/fleet/<fleet>/silicons/<handle>/token-requests {"claim_secret_hash": "<hex>"}
     (or the agent files it itself with any of its tokens) and approves it in the app;
  3. the agent claims it: POST /api/silicon-token-requests/<id>/claim {"claim_secret": "S"} -> its token, into <dir>/token;
  4. node bin/token-pickup.js --init <dir>   -> "registered" (no approval needed for this first key).

DEMIPASS_URL overrides the server (https://api.dustforge.com).`;
const args = process.argv.slice(2);
if (args.includes('--help') || args.includes('-h')) { console.log(HELP); process.exit(0); }
const flags = new Set(args.filter(a => a.startsWith('--') && a !== '--init'));
const rest = args.filter(a => !flags.has(a));
for (const f of flags) if (!['--rotate', '--allow-narrower'].includes(f)) die(`unknown option ${f}`);
(async () => {
  if (rest[0] === '--init') { if (!rest[1]) die('usage: token-pickup.js --init [--rotate] <dir>'); await init(rest[1], flags.has('--rotate')); }
  else if (rest.length === 1 && !rest[0].startsWith('-')) await pickup(rest[0], flags.has('--allow-narrower'));
  else die('usage: token-pickup.js --init [--rotate] <dir> | token-pickup.js [--allow-narrower] <dir>');
})().catch(e => die(e.message));
