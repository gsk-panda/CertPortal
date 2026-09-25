'use strict';

const assert = require('assert');
const { PLANS, planForOrg, withinLimit } = require('../../src/services/billing/plans');
const { inGoodStanding } = require('../../src/services/billing/entitlements');
const { mapSubscription } = require('../../src/services/billing/service');

describe('free plan', () => {
  it('allows exactly one domain, certificate, firewall and agent', () => {
    const free = PLANS.free;
    for (const r of ['domains', 'certificates', 'firewalls', 'agents']) {
      assert.strictEqual(withinLimit(free, r, 0), true, `${r} at 0`);
      assert.strictEqual(withinLimit(free, r, 1), false, `${r} at 1`);
    }
  });

  it('is the fallback for an org with an unknown plan', () => {
    assert.strictEqual(planForOrg({ plan: 'nope' }).key, 'free');
  });

  it('is always in good standing, even after a cancelled subscription', () => {
    assert.strictEqual(inGoodStanding({ plan: 'free' }), true);
    assert.strictEqual(inGoodStanding({ plan: 'free', sub_status: 'canceled' }), true);
  });
});

describe('paid plans', () => {
  it('cap agents and grow with the tier', () => {
    assert.strictEqual(withinLimit(PLANS.starter, 'agents', 1), true);
    assert.strictEqual(withinLimit(PLANS.starter, 'agents', 2), false);
    assert.strictEqual(withinLimit(PLANS.enterprise, 'agents', 10000), true);
  });

  it('need an active subscription unless grandfathered', () => {
    assert.strictEqual(inGoodStanding({ plan: 'pro', sub_status: 'active' }), true);
    assert.strictEqual(inGoodStanding({ plan: 'pro', sub_status: 'past_due' }), false);
    assert.strictEqual(inGoodStanding({ plan: 'enterprise', sub_status: null }), true);
  });
});

describe('mapSubscription', () => {
  const sub = (status) => ({ id: 'sub_1', customer: 'cus_1', status, metadata: { plan: 'pro' }, items: { data: [] } });

  it('keeps the paid plan while the subscription is live', () => {
    assert.strictEqual(mapSubscription(sub('active')).orgPlan, 'pro');
    assert.strictEqual(mapSubscription(sub('past_due')).orgPlan, 'pro');
  });

  it('returns the org to free when the subscription is cancelled', () => {
    const m = mapSubscription(sub('canceled'));
    assert.strictEqual(m.plan, 'pro');
    assert.strictEqual(m.orgPlan, 'free');
  });
});
