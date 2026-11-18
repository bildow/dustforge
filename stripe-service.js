/**
 * Civitasvox Stripe Service — payment gate for identity platform
 *
 * Account creation: $1 → Stripe Checkout → webhook → account created
 * Wallet topup: $5/$10/$50 → Stripe Checkout → webhook → wallet credited
 * Referral: 25¢ of $1 fee goes to referrer automatically
 */

const Stripe = require('stripe');

const WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET || '';

// The statement descriptor to set as the ACCOUNT default in the Stripe
// dashboard (Settings → Public details / Statement descriptor). Since
// 2024-02-01 Stripe REJECTS a per-transaction `statement_descriptor` on card
// PaymentIntents (400 error) — card charges use the account prefix (+ optional
// `statement_descriptor_suffix`). So this is documentation of the value to set
// in the dashboard, NOT something we send per checkout. <=22 chars, Latin only.
// Bundles both brands so the charge is recognizable whether they bought on
// demipass.com or dustforge.com; matches the "DEMIPASS DUSTFORGE" text on the
// pay-page footers.
const STATEMENT_DESCRIPTOR = 'DEMIPASS DUSTFORGE';

const { ddForUsdCents, DEPOSIT_DD_PER_USD } = require('./dd_units');

// Pricing (US cents)
const PRICES = {
  account_single: 100,    // $1.00
  account_bulk_10: 500,   // $5.00 for 10
  topup_500: 500,         // $5.00
  topup_1000: 1000,       // $10.00
  topup_5000: 5000,       // $50.00
  topup_10000: 10000,     // $100.00
};

const BASE_URL = process.env.PLATFORM_BASE_URL || 'http://100.83.112.88:3000';

let stripeClient = null;

function getStripe() {
  if (stripeClient) return stripeClient;
  if (!process.env.STRIPE_SECRET_KEY) {
    throw new Error('STRIPE_SECRET_KEY is required for Stripe operations');
  }
  stripeClient = new Stripe(process.env.STRIPE_SECRET_KEY);
  return stripeClient;
}

/**
 * Create Stripe Checkout session for account creation
 */
async function createAccountCheckout(options) {
  const { username, password, referral_code, bulk = false } = options;
  const price = bulk ? PRICES.account_bulk_10 : PRICES.account_single;
  const label = bulk ? 'DemiPass Accounts ×10 — a Dustforge product' : 'DemiPass Account — a Dustforge product';

  const session = await getStripe().checkout.sessions.create({
    payment_method_types: ['card'],
    line_items: [{
      price_data: {
        currency: 'usd',
        product_data: { name: label, description: 'Cryptographic identity (DID:key) + @dustforge.com email + prepaid service wallet. Non-refundable digital goods.' },
        unit_amount: price,
      },
      quantity: 1,
    }],
    mode: 'payment',
    success_url: `${BASE_URL}/api/stripe/success?session_id={CHECKOUT_SESSION_ID}`,
    cancel_url: `${BASE_URL}/api/stripe/cancel`,
    metadata: {
      type: 'account_creation',
      username,
      // SECURITY: password is NOT stored in Stripe metadata.
      // It is stored server-side in identity_pending_checkouts (encrypted).
      referral_code: referral_code || '',
      bulk: bulk ? 'true' : 'false',
    },
    client_reference_id: username,
  });

  return { url: session.url, session_id: session.id };
}

/**
 * Create Stripe Checkout session for wallet topup
 */
async function createTopupCheckout(did, amount_cents, username = '') {
  if (!PRICES[`topup_${amount_cents}`] && ![500, 1000, 5000, 10000].includes(amount_cents)) {
    throw new Error('Invalid topup amount. Options: $5, $10, $50, $100');
  }

  const session = await getStripe().checkout.sessions.create({
    payment_method_types: ['card'],
    line_items: [{
      price_data: {
        currency: 'usd',
        product_data: { name: `Dustforge Wallet Top-Up`, description: `${ddForUsdCents(amount_cents)} Diamond Dust ($1 = ${DEPOSIT_DD_PER_USD} DD) — prepaid, non-refundable service credit for your @dustforge.com account.` },
        unit_amount: amount_cents,
      },
      quantity: 1,
    }],
    mode: 'payment',
    // The top-up page (it shows the new balance), not the account-creation status page.
    success_url: `${BASE_URL}/api/stripe/topup-success?session_id={CHECKOUT_SESSION_ID}`,
    cancel_url: `${BASE_URL}/api/stripe/cancel`,
    metadata: {
      type: 'wallet_topup',
      did,
      amount_cents: String(amount_cents),
      ...(username ? { username: String(username) } : {}),   // the top-up page names the wallet
    },
  });

  return { url: session.url, session_id: session.id };
}

/**
 * Verify and parse Stripe webhook event. Nothing in an unverified body is trusted:
 * with a signing secret the signature is checked; without one, the event is
 * fetched from Stripe by id with our own key and that copy is used, so a forged
 * POST (any event id Stripe never sent us) is refused.
 */
async function constructWebhookEvent(rawBody, signature) {
  if (WEBHOOK_SECRET) return getStripe().webhooks.constructEvent(rawBody, signature, WEBHOOK_SECRET);
  let claimed;
  try { claimed = JSON.parse(rawBody); } catch (_) { throw new Error('webhook body is not JSON'); }
  if (!claimed || typeof claimed.id !== 'string' || !/^evt_[A-Za-z0-9]+$/.test(claimed.id)) throw new Error('webhook event has no Stripe event id');
  return getStripe().events.retrieve(claimed.id);
}

// The server's Stripe key mode: 'live' (sk_live_/rk_live_), 'test' (sk_test_/rk_test_), or 'none'.
function stripeMode() {
  const k = String(process.env.STRIPE_SECRET_KEY || '');
  if (/^(sk|rk)_live_/.test(k)) return 'live';
  if (/^(sk|rk)_test_/.test(k)) return 'test';
  return 'none';
}

// May a paid Checkout session (or its event) credit DD? Only a live-mode payment: a test-mode one is paid with
// Stripe's public test cards, so it would mint DD for nothing (found 2026-11-15: the server's key is a test key and
// /api/stripe/topup-success credited any test payment). STRIPE_TEST_CREDITS=1 allows it, for a staging box only.
function creditsAllowed(obj) {
  if (obj && obj.livemode === true) return true;
  return process.env.STRIPE_TEST_CREDITS === '1';
}

// Card deposits from the app (stub, Aaron 2026-11-15). DEPOSITS=off|test|live; on only when the key's mode matches.
const DEPOSIT_AMOUNTS_USD_CENTS = [500, 1000, 5000, 10000];
function depositConfig() {
  const want = String(process.env.DEPOSITS || 'off').toLowerCase();
  const mode = stripeMode();
  const base = { mode: want === 'test' || want === 'live' ? want : 'off', stripe_key: mode,
    amounts_usd_cents: DEPOSIT_AMOUNTS_USD_CENTS, dd_per_usd: DEPOSIT_DD_PER_USD,
    credits_dd: mode === 'live' || process.env.STRIPE_TEST_CREDITS === '1' };
  if (base.mode === 'off') return { ...base, enabled: false, reason: 'card deposits are not switched on yet (DEPOSITS=off)' };
  if (mode !== base.mode) return { ...base, enabled: false, reason: `card deposits are set to ${base.mode}, but the server's Stripe key is ${mode}` };
  return { ...base, enabled: true, reason: base.credits_dd ? '' : 'test mode: Stripe test cards work, and no DD is credited' };
}

module.exports = {
  getStripe,
  PRICES,
  STATEMENT_DESCRIPTOR,
  createAccountCheckout,
  createTopupCheckout,
  constructWebhookEvent,
  stripeMode,
  creditsAllowed,
  depositConfig,
  DEPOSIT_AMOUNTS_USD_CENTS,
};
