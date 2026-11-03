'use strict';
// The Stripe webhook trusts nothing in an unsigned body: without a signing secret it acts
// only on Stripe's own copy of the event, fetched by id. A forged id is refused.
const test = require('node:test');
const assert = require('node:assert/strict');

// A fake Stripe SDK: knows one real event; everything else is "No such event".
const REAL = { id: 'evt_real123', type: 'checkout.session.completed',
  data: { object: { id: 'cs_test_1', metadata: { type: 'wallet_topup', did: 'did:key:zA', amount_cents: '500' } } } };
const fetched = [];
const stripePath = require.resolve('stripe');
require.cache[stripePath] = { id: stripePath, filename: stripePath, loaded: true, exports: function FakeStripe() {
  return { events: { retrieve: async (id) => { fetched.push(id); if (id === REAL.id) return REAL; throw new Error(`No such event: '${id}'`); } } };
} };
process.env.STRIPE_SECRET_KEY = 'sk_test_fake';
delete process.env.STRIPE_WEBHOOK_SECRET;
const stripeService = require('../stripe-service');

test('an event Stripe sent is acted on as Stripe has it, not as the body claims', async () => {
  const forgedCopy = JSON.stringify({ ...REAL, data: { object: { id: 'cs_test_1', metadata: { type: 'wallet_topup', did: 'did:key:zEvil', amount_cents: '1000000' } } } });
  const ev = await stripeService.constructWebhookEvent(Buffer.from(forgedCopy), undefined);
  assert.equal(ev.data.object.metadata.did, 'did:key:zA');
  assert.equal(ev.data.object.metadata.amount_cents, '500');
});

test('a forged event id, a body with no id, and a non-JSON body are refused', async () => {
  const forged = { id: 'evt_forged', type: 'checkout.session.completed', data: { object: { metadata: { type: 'wallet_topup', did: 'did:key:zEvil', amount_cents: '10000' } } } };
  await assert.rejects(stripeService.constructWebhookEvent(Buffer.from(JSON.stringify(forged))), /No such event/);
  await assert.rejects(stripeService.constructWebhookEvent(Buffer.from(JSON.stringify({ type: 'checkout.session.completed' }))), /no Stripe event id/);
  await assert.rejects(stripeService.constructWebhookEvent(Buffer.from('{"id":"evt_x/../y"}')), /no Stripe event id/);
  await assert.rejects(stripeService.constructWebhookEvent(Buffer.from('not json')), /not JSON/);
  assert.deepEqual(fetched.filter(id => id !== REAL.id), ['evt_forged']);   // malformed ids never reach Stripe
});
