/**
 * Civitasvox Stripe Service — payment gate for identity platform
 *
 * Account creation: $1 → Stripe Checkout → webhook → account created
 * Wallet topup: $5/$10/$50 → Stripe Checkout → webhook → wallet credited
 * Referral: 25¢ of $1 fee goes to referrer automatically
 */

const Stripe = require('stripe');

const WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET || '';

// Pricing
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
  const label = bulk ? 'Civitasvox — 10 Silicon Accounts' : 'Civitasvox — Silicon Account';

  const session = await getStripe().checkout.sessions.create({
    payment_method_types: ['card'],
    line_items: [{
      price_data: {
        currency: 'usd',
        product_data: { name: label, description: 'DID:key identity + Dustforge email + wallet' },
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
async function createTopupCheckout(did, amount_cents) {
  if (!PRICES[`topup_${amount_cents}`] && ![500, 1000, 5000, 10000].includes(amount_cents)) {
    throw new Error('Invalid topup amount. Options: $5, $10, $50, $100');
  }

  const session = await getStripe().checkout.sessions.create({
    payment_method_types: ['card'],
    line_items: [{
      price_data: {
        currency: 'usd',
        product_data: { name: `Civitasvox Wallet Topup`, description: `Add $${(amount_cents / 100).toFixed(2)} to your wallet` },
        unit_amount: amount_cents,
      },
      quantity: 1,
    }],
    mode: 'payment',
    success_url: `${BASE_URL}/api/stripe/success?session_id={CHECKOUT_SESSION_ID}`,
    cancel_url: `${BASE_URL}/api/stripe/cancel`,
    metadata: {
      type: 'wallet_topup',
      did,
      amount_cents: String(amount_cents),
    },
  });

  return { url: session.url, session_id: session.id };
}

/**
 * Verify and parse Stripe webhook event
 */
function constructWebhookEvent(rawBody, signature) {
  if (!WEBHOOK_SECRET) {
    // No webhook secret configured — parse directly (test mode)
    return JSON.parse(rawBody);
  }
  return getStripe().webhooks.constructEvent(rawBody, signature, WEBHOOK_SECRET);
}

module.exports = {
  getStripe,
  PRICES,
  createAccountCheckout,
  createTopupCheckout,
  constructWebhookEvent,
};
