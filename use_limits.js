/**
 * Size limits for POST /api/demipass/use (alias /api/blindkey/use), and the
 * helpers that enforce them.
 *
 *   USE_MAX_REQUEST_BYTES   1 MiB — the JSON body a caller sends to /use (a review
 *                           body to post, a JSON payload to forward). Over it: 413
 *                           before auth or billing, so it is never charged.
 *   USE_MAX_RESPONSE_BYTES  2 MiB — the upstream response DemiPass reads on the
 *                           caller's behalf. It is read as a stream and abandoned at
 *                           the limit (or refused up front when Content-Length is
 *                           already over it). Over it: 413 naming the limit. The
 *                           upstream call was made with the secret, so it is charged
 *                           like any other upstream answer (a 404 or 500 from the
 *                           target is charged too).
 *
 * nginx in front allows 2 MB request bodies (client_max_body_size), so the server,
 * not the proxy, answers an oversize body, in JSON.
 */
const USE_MAX_REQUEST_BYTES = 1024 * 1024;
const USE_MAX_RESPONSE_BYTES = 2 * 1024 * 1024;

function mib(n) { return `${(n / 1048576).toFixed(n % 1048576 ? 2 : 0)} MiB`; }

function upstreamTooLarge(bytes, declared) {
  return Object.assign(new Error(`upstream response is over the ${mib(USE_MAX_RESPONSE_BYTES)} limit`), {
    code: 'upstream_too_large',
    statusCode: 413,
    body: {
      error: `upstream response too large: ${declared ? 'it declares' : 'more than'} ${bytes} bytes, over the ${USE_MAX_RESPONSE_BYTES}-byte (${mib(USE_MAX_RESPONSE_BYTES)}) limit for /use`,
      limit_bytes: USE_MAX_RESPONSE_BYTES,
      [declared ? 'declared_bytes' : 'read_bytes']: bytes,
      hint: 'Ask the upstream for less: a page, a range, a narrower query, or a single file instead of a whole diff.',
      charged: true,
    },
  });
}

// The body of a fetch() Response as UTF-8 text, never more than `limit` bytes.
async function readCapped(response, limit = USE_MAX_RESPONSE_BYTES) {
  const declared = Number(response.headers.get('content-length'));
  if (Number.isFinite(declared) && declared > limit) {
    try { await response.body?.cancel(); } catch (_) {}
    throw upstreamTooLarge(declared, true);
  }
  if (!response.body) return '';
  const reader = response.body.getReader();
  const chunks = [];
  let n = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    n += value.byteLength;
    if (n > limit) {
      try { await reader.cancel(); } catch (_) {}
      throw upstreamTooLarge(n, false);
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks, n).toString('utf8');
}

// Replace every occurrence of the secret, as it is and as it appears inside a JSON
// string, with [REDACTED]. Plain substring search: linear in the text, no regex.
function redactSecret(text, secret) {
  if (typeof text !== 'string' || !secret) return text;
  let out = text.split(secret).join('[REDACTED]');
  const inJson = JSON.stringify(secret).slice(1, -1);
  if (inJson !== secret) out = out.split(inJson).join('[REDACTED]');
  return out;
}

// Redact first, then parse: the result is JSON when the upstream sent JSON, else text.
function redactedBody(text, secret) {
  const clean = redactSecret(text, secret);
  try { return JSON.parse(clean); } catch (_) { return clean; }
}

module.exports = { USE_MAX_REQUEST_BYTES, USE_MAX_RESPONSE_BYTES, readCapped, redactSecret, redactedBody, mib };
