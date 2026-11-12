#!/usr/bin/env node
'use strict';
// token-pickup — an agent collects the token its fleet owner renewed for it (silicon_renew.js). Aaron 2026-11-12.
//   node bin/token-pickup.js --init <dir>
//        make this agent's delivery key: an X25519 keypair, the private key in <dir>/delivery.key (0600, never printed),
//        and register its public key with the agent's own session — DEMIPASS_TOKEN, DEMIPASS_TOKEN_FILE (0600) or an
//        existing <dir>/token. Run it while the agent still has a live token. Again later: the same key is registered
//        again (--rotate makes a new one; deliveries sealed to the old key can then no longer be opened).
//   node bin/token-pickup.js <dir>
//        fetch the newest delivery for this agent's DID, open it with <dir>/delivery.key, check it is a token for this
//        DID that has not expired, and write it to <dir>/token (0600, replaced atomically). Never prints the token.
//        The newest renewal is what the owner last decided: it replaces the file. exit 0 written (or <dir>/token already
//        holds it), 3 nothing to pick up, 2 could not run.
// The server only holds the sealed blob; the owner, the app and this program's output never carry the token.
// DEMIPASS_URL overrides the server. Zero dependencies (Node ≥ 18).
const fs = require('fs'), path = require('path'), crypto = require('crypto');

const API = (process.env.DEMIPASS_URL || 'https://api.dustforge.com').replace(/\/$/, '');
const ALG = 'X25519-HKDF-SHA256-A256GCM';
const INFO_PREFIX = 'demipass-token-delivery-v1:';

const die = (msg, code = 2) => { console.error('token-pickup: ' + msg); process.exit(code); };
const claimsOf = (jwt) => { try { return JSON.parse(Buffer.from(String(jwt).split('.')[1], 'base64url').toString()); } catch (_) { return null; } };
function readPrivate(file) {
  const st = fs.statSync(file);
  if (st.mode & 0o077) die(`${file} must not be readable by group/other (chmod 600)`);
  return fs.readFileSync(file, 'utf8').trim();
}
// Written whole or not at all: a temp file (0600) renamed over the target.
function writeSecret(file, text) {
  const tmp = `${file}.tmp-${process.pid}`;
  fs.writeFileSync(tmp, text, { mode: 0o600, flag: 'wx' });
  fs.chmodSync(tmp, 0o600);
  fs.renameSync(tmp, file);
}

function sessionToken(dir) {
  if (process.env.DEMIPASS_TOKEN) return process.env.DEMIPASS_TOKEN.trim();
  if (process.env.DEMIPASS_TOKEN_FILE) return readPrivate(process.env.DEMIPASS_TOKEN_FILE);
  const own = path.join(dir, 'token');
  if (fs.existsSync(own)) return readPrivate(own);
  die('set DEMIPASS_TOKEN (or DEMIPASS_TOKEN_FILE) to the agent\'s current token to register its delivery key');
}

async function init(dir, rotate) {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const keyFile = path.join(dir, 'delivery.key');
  let priv;
  if (fs.existsSync(keyFile) && !rotate) priv = crypto.createPrivateKey(readPrivate(keyFile));
  else {
    priv = crypto.generateKeyPairSync('x25519').privateKey;
    writeSecret(keyFile, priv.export({ format: 'pem', type: 'pkcs8' }));
  }
  const pub = crypto.createPublicKey(priv).export({ format: 'jwk' }).x;
  const token = sessionToken(dir);
  const r = await fetch(API + '/api/identity/delivery-key', { method: 'POST', headers: { 'content-type': 'application/json', authorization: 'Bearer ' + token },
    body: JSON.stringify({ public_key: pub }) });
  const d = await r.json().catch(() => ({}));
  if (!r.ok || !d.did) die(`the server refused the delivery key (${r.status}): ${d.error || 'no answer'}`);
  fs.writeFileSync(path.join(dir, 'did'), d.did + '\n', { mode: 0o600 });
  console.log(`token-pickup: delivery key ${d.fingerprint} registered for ${d.did}; private key in ${keyFile} (0600)`);
}

function open(sealed, priv, did) {
  if (!sealed || sealed.alg !== ALG) throw new Error('unknown sealing');
  const epk = Buffer.from(sealed.epk, 'base64url');
  const mine = Buffer.from(crypto.createPublicKey(priv).export({ format: 'jwk' }).x, 'base64url');
  const shared = crypto.diffieHellman({ privateKey: priv, publicKey: crypto.createPublicKey({ key: { kty: 'OKP', crv: 'X25519', x: sealed.epk }, format: 'jwk' }) });
  const key = Buffer.from(crypto.hkdfSync('sha256', shared, Buffer.concat([epk, mine]), Buffer.from(INFO_PREFIX + did), 32));
  shared.fill(0);
  const dec = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(sealed.iv, 'base64url'));
  dec.setAAD(Buffer.from(did));
  dec.setAuthTag(Buffer.from(sealed.tag, 'base64url'));
  const out = Buffer.concat([dec.update(Buffer.from(sealed.ciphertext, 'base64url')), dec.final()]).toString('utf8');
  key.fill(0);
  return out;
}

async function pickup(dir) {
  const keyFile = path.join(dir, 'delivery.key'), didFile = path.join(dir, 'did');
  if (!fs.existsSync(keyFile) || !fs.existsSync(didFile)) die(`no delivery key in ${dir}: run --init first`);
  const priv = crypto.createPrivateKey(readPrivate(keyFile));
  const did = fs.readFileSync(didFile, 'utf8').trim();
  const r = await fetch(API + '/api/identity/token-deliveries?did=' + encodeURIComponent(did));
  const d = await r.json().catch(() => ({}));
  if (!r.ok) die(`the server answered ${r.status}: ${d.error || 'no answer'}`);
  const list = d.deliveries || [];
  if (!list.length) { console.log('token-pickup: nothing to pick up'); process.exit(3); }
  const del = list[0];   // the newest
  let token;
  try { token = open(del.sealed, priv, did); } catch (_) { die(`delivery #${del.id} does not open with ${keyFile} (sealed to key ${del.key_fingerprint}: was the key rotated?)`); }
  const c = claimsOf(token);
  if (!c || c.sub !== did || !c.exp || c.exp * 1000 <= Date.now()) die(`delivery #${del.id} is not a live token for ${did}`);
  const out = path.join(dir, 'token');
  if (fs.existsSync(out)) {
    const cur = claimsOf(readPrivate(out));
    if (cur && cur.sub === did && cur.jti === c.jti) { console.log(`token-pickup: ${out} already holds delivery #${del.id}`); return; }
  }
  writeSecret(out, token + '\n');
  token = null;
  console.log(`token-pickup: wrote ${out} (0600) from delivery #${del.id}: scope ${c.scope}, expires ${new Date(c.exp * 1000).toISOString()}`);
}

const args = process.argv.slice(2);
const rotate = args.includes('--rotate');
const rest = args.filter(a => a !== '--rotate');
(async () => {
  if (rest[0] === '--init') { if (!rest[1]) die('usage: token-pickup.js --init [--rotate] <dir>'); await init(rest[1], rotate); }
  else if (rest.length === 1 && !rest[0].startsWith('-')) await pickup(rest[0]);
  else die('usage: token-pickup.js --init [--rotate] <dir> | token-pickup.js <dir>');
})().catch(e => die(e.message));
