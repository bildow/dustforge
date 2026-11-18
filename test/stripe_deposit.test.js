'use strict';
// node --test test/stripe_deposit.test.js — the card-deposit switch and the live-only credit rule (2026-11-15).
const test = require('node:test');
const assert = require('node:assert/strict');
const S = require('../stripe-service');

function withEnv(env, fn) {
  const keep = {}; for (const k of Object.keys(env)) { keep[k] = process.env[k]; if (env[k] == null) delete process.env[k]; else process.env[k] = env[k]; }
  try { return fn(); } finally { for (const k of Object.keys(keep)) { if (keep[k] === undefined) delete process.env[k]; else process.env[k] = keep[k]; } }
}

test('stripeMode reads the key prefix', () => {
  withEnv({ STRIPE_SECRET_KEY: 'sk_test_x' }, () => assert.equal(S.stripeMode(), 'test'));
  withEnv({ STRIPE_SECRET_KEY: 'rk_live_x' }, () => assert.equal(S.stripeMode(), 'live'));
  withEnv({ STRIPE_SECRET_KEY: null }, () => assert.equal(S.stripeMode(), 'none'));
});

test('a checkout credits DD only when Stripe says the payment was live, unless STRIPE_TEST_CREDITS=1', () => {
  withEnv({ STRIPE_TEST_CREDITS: null }, () => {
    assert.equal(S.creditsAllowed({ livemode: true }), true);
    assert.equal(S.creditsAllowed({ livemode: false }), false);
    assert.equal(S.creditsAllowed({}), false, 'no livemode field: not trusted');
    assert.equal(S.creditsAllowed(null), false);
  });
  withEnv({ STRIPE_TEST_CREDITS: '1' }, () => assert.equal(S.creditsAllowed({ livemode: false }), true));
});

test('depositConfig: off by default; on only when DEPOSITS matches the key mode; test mode says it credits nothing', () => {
  withEnv({ DEPOSITS: null, STRIPE_SECRET_KEY: 'sk_test_x', STRIPE_TEST_CREDITS: null }, () => {
    const c = S.depositConfig(); assert.equal(c.enabled, false); assert.equal(c.mode, 'off'); assert.match(c.reason, /not switched on/);
    assert.deepEqual(c.amounts_usd_cents, [500, 1000, 5000, 10000]);
  });
  withEnv({ DEPOSITS: 'live', STRIPE_SECRET_KEY: 'sk_test_x' }, () => {
    const c = S.depositConfig(); assert.equal(c.enabled, false); assert.match(c.reason, /set to live, but the server's Stripe key is test/);
  });
  withEnv({ DEPOSITS: 'test', STRIPE_SECRET_KEY: 'sk_test_x', STRIPE_TEST_CREDITS: null }, () => {
    const c = S.depositConfig(); assert.equal(c.enabled, true); assert.equal(c.credits_dd, false); assert.match(c.reason, /no DD is credited/);
  });
  withEnv({ DEPOSITS: 'live', STRIPE_SECRET_KEY: 'sk_live_x' }, () => {
    const c = S.depositConfig(); assert.equal(c.enabled, true); assert.equal(c.credits_dd, true);
  });
});
