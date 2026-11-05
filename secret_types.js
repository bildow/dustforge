'use strict';
// One table for vault secret types. Every place that stores a secret (store, deposit, deposit/batch), mints its
// ref code, or picks the action a caller left out, reads it from here. Before this the store route accepted eight
// types and silently filed the rest (ssh_credential, token, passphrase, multi_string) as api_key, while ref codes
// and default actions were keyed on names the store never produced (ssh_key, cert).
//
// A type the caller names must be known (an alias counts): an unknown type is refused, never relabelled.
// A caller that names no type gets one inferred from the value's shape (and from a login username, if given);
// a value with no recognisable shape stays api_key, as before.

const TYPES = {
  api_key:           { prefix: 'API', action: 'http_header',      label: 'API key' },
  token:             { prefix: 'TKN', action: 'http_header',      label: 'Token' },
  oauth_token:       { prefix: 'TKN', action: 'http_header',      label: 'OAuth token' },
  password:          { prefix: 'PWD', action: 'ssh_exec',         label: 'Password / login' },
  passphrase:        { prefix: 'PWD', action: 'ssh_exec',         label: 'Passphrase' },
  ssh_credential:    { prefix: 'SSH', action: 'ssh_exec',         label: 'SSH key' },
  signing_key:       { prefix: 'KEY', action: 'http_header',      label: 'Signing key' },
  webhook_secret:    { prefix: 'WHK', action: 'http_header',      label: 'Webhook secret' },
  connection_string: { prefix: 'CON', action: 'database_connect', label: 'Connection string' },
  certificate:       { prefix: 'CRT', action: 'http_header',      label: 'Certificate' },
  multi_string:      { prefix: 'SEC', action: 'http_body',        label: 'Several values' },
  other:             { prefix: 'SEC', action: 'http_header',      label: 'Other' },
};

// Names older clients send. The app's type picker sent ssh_key; generateRefCode knew cert.
const ALIASES = {
  ssh_key: 'ssh_credential', ssh: 'ssh_credential', ssh_private_key: 'ssh_credential',
  cert: 'certificate', pem_certificate: 'certificate',
  oauth: 'oauth_token', bearer: 'token', jwt: 'token',
  pass: 'password', login: 'password',
  api: 'api_key', apikey: 'api_key', key: 'api_key',
  webhook: 'webhook_secret', dsn: 'connection_string', database_url: 'connection_string',
};

const TYPE_NAMES = Object.keys(TYPES);

// The canonical type for a name the caller sent, or null when it is not one we know.
function canonicalType(name) {
  if (typeof name !== 'string') return null;
  const n = name.trim().toLowerCase().replace(/[\s-]+/g, '_');
  if (TYPES[n]) return n;
  return ALIASES[n] || null;
}

// The type a value looks like. `username` (a login's account name) makes an otherwise shapeless value a password.
function inferType(value, { username = '' } = {}) {
  const v = String(value || '').trim();
  if (/^-----BEGIN (OPENSSH |RSA |EC |DSA |ENCRYPTED )?PRIVATE KEY-----/.test(v)) return 'ssh_credential';
  if (/^-----BEGIN PGP PRIVATE KEY BLOCK-----/.test(v)) return 'signing_key';
  if (/^-----BEGIN CERTIFICATE-----/.test(v)) return 'certificate';
  if (/^(postgres(ql)?|mysql|mariadb|mongodb(\+srv)?|redis|rediss|amqps?|mssql|sqlserver):\/\/\S+$/i.test(v)) return 'connection_string';
  if (/^whsec_[A-Za-z0-9+/=_-]{8,}$/.test(v)) return 'webhook_secret';
  if (/^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/.test(v)) return 'token';
  if (/^(gh[pousr]_|github_pat_|glpat-|xox[abpr]-|ya29\.)/.test(v)) return 'token';
  if (/^(sk-|sk_live_|sk_test_|rk_live_|pk_live_|AKIA|AIza|SG\.|key-)/.test(v)) return 'api_key';
  if (username && String(username).trim()) return 'password';
  return 'api_key';
}

// What a store/deposit body resolves to: { type } or { error } (a 400 the caller can act on).
function resolveType(requested, value, { username = '' } = {}) {
  if (requested === undefined || requested === null || requested === '') return { type: inferType(value, { username }), inferred: true };
  if (typeof requested !== 'string') return { error: 'secret_type: must be a string' };
  const t = canonicalType(requested);
  if (!t) return { error: `secret_type '${String(requested).slice(0, 40)}' is not a vault type`, valid_types: TYPE_NAMES, aliases: ALIASES };
  return { type: t, inferred: false };
}

const refPrefix = (type) => (TYPES[canonicalType(type)] || TYPES.other).prefix;
// The action used when a caller names none. Stored rows may still carry an old alias (ssh_key, cert).
const defaultAction = (type) => (TYPES[canonicalType(type)] || TYPES.other).action;

module.exports = { TYPES, ALIASES, TYPE_NAMES, canonicalType, inferType, resolveType, refPrefix, defaultAction };
