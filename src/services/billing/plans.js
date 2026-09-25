'use strict';

/**
 * Flat subscription tiers. Limits and feature flags are code-defined; the
 * Stripe Price ID for each paid tier comes from the environment so the same
 * code works across test/live Stripe accounts.
 *
 * Unlimited = null (treated as "no cap"). Existing orgs are grandfathered onto
 * `enterprise` by the migration; new self-serve signups start on `free`, which
 * never expires. A cancelled paid subscription drops the org back to `free`.
 * `trial` is kept only for orgs created before the free tier existed.
 */

const { config } = require('../../config');

const UNLIMITED = null;

const PLANS = {
  free: {
    key: 'free', label: 'Free', order: 0, paid: false,
    priceId: null,
    limits: { firewalls: 1, panoramas: 0, domains: 1, certificates: 1, agents: 1 },
    features: { monitoring: false, panovision: false, change_mgmt: false },
  },
  trial: {
    key: 'trial', label: 'Trial', order: 0, paid: false,
    priceId: null,
    limits: { firewalls: 1, panoramas: 1, domains: 3, certificates: 5, agents: 1 },
    features: { monitoring: false, panovision: false, change_mgmt: false },
  },
  starter: {
    key: 'starter', label: 'Starter', order: 1, paid: true,
    priceId: config.billing.priceStarter,
    limits: { firewalls: 2, panoramas: 0, domains: 10, certificates: 25, agents: 2 },
    features: { monitoring: false, panovision: false, change_mgmt: false },
  },
  pro: {
    key: 'pro', label: 'Pro', order: 2, paid: true,
    priceId: config.billing.pricePro,
    limits: { firewalls: 10, panoramas: 2, domains: 50, certificates: 200, agents: 10 },
    features: { monitoring: true, panovision: true, change_mgmt: false },
  },
  enterprise: {
    key: 'enterprise', label: 'Enterprise', order: 3, paid: true,
    priceId: config.billing.priceEnterprise,
    limits: { firewalls: UNLIMITED, panoramas: UNLIMITED, domains: UNLIMITED, certificates: UNLIMITED, agents: UNLIMITED },
    features: { monitoring: true, panovision: true, change_mgmt: true },
  },
};

// Pseudo-plan used when billing is disabled: no limits, all features.
const UNRESTRICTED = {
  key: 'unrestricted', label: 'Unrestricted', order: 99, paid: false, priceId: null,
  limits: { firewalls: UNLIMITED, panoramas: UNLIMITED, domains: UNLIMITED, certificates: UNLIMITED, agents: UNLIMITED },
  features: { monitoring: true, panovision: true, change_mgmt: true },
};

/** The plan an org is entitled to. Billing off => unrestricted. */
function planForOrg(org) {
  if (!config.billing.enabled) return UNRESTRICTED;
  return PLANS[org && org.plan] || PLANS.free;
}

/** true if `count` existing items is below the plan's limit for `resource`. */
function withinLimit(plan, resource, count) {
  const limit = plan.limits[resource];
  if (limit === UNLIMITED || limit === undefined) return true;
  return count < limit;
}

function hasFeature(plan, feature) {
  return !!plan.features[feature];
}

/** Paid, self-selectable plans in display order. */
function purchasablePlans() {
  return Object.values(PLANS).filter((p) => p.paid).sort((a, b) => a.order - b.order);
}

/** Map a Stripe Price ID back to a plan key (webhook path). */
function planKeyForPrice(priceId) {
  const p = Object.values(PLANS).find((pl) => pl.priceId && pl.priceId === priceId);
  return p ? p.key : null;
}

module.exports = {
  PLANS, UNRESTRICTED, UNLIMITED,
  planForOrg, withinLimit, hasFeature, purchasablePlans, planKeyForPrice,
};
