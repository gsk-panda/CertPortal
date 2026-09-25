'use strict';

/**
 * Flat subscription tiers. Limits and feature flags are code-defined; the
 * Stripe Price ID for each paid tier comes from the environment so the same
 * code works across test/live Stripe accounts.
 *
 * Unlimited = null (treated as "no cap"). Existing orgs are grandfathered onto
 * `enterprise` by the migration; new self-serve signups start on `trial`.
 */

const { config } = require('../../config');

const UNLIMITED = null;

const PLANS = {
  trial: {
    key: 'trial', label: 'Trial', order: 0, paid: false,
    priceId: null,
    limits: { firewalls: 1, panoramas: 1, domains: 3, certificates: 5 },
    features: { monitoring: false, panovision: false, change_mgmt: false },
  },
  starter: {
    key: 'starter', label: 'Starter', order: 1, paid: true,
    priceId: config.billing.priceStarter,
    limits: { firewalls: 2, panoramas: 0, domains: 10, certificates: 25 },
    features: { monitoring: false, panovision: false, change_mgmt: false },
  },
  pro: {
    key: 'pro', label: 'Pro', order: 2, paid: true,
    priceId: config.billing.pricePro,
    limits: { firewalls: 10, panoramas: 2, domains: 50, certificates: 200 },
    features: { monitoring: true, panovision: true, change_mgmt: false },
  },
  enterprise: {
    key: 'enterprise', label: 'Enterprise', order: 3, paid: true,
    priceId: config.billing.priceEnterprise,
    limits: { firewalls: UNLIMITED, panoramas: UNLIMITED, domains: UNLIMITED, certificates: UNLIMITED },
    features: { monitoring: true, panovision: true, change_mgmt: true },
  },
};

// Pseudo-plan used when billing is disabled: no limits, all features.
const UNRESTRICTED = {
  key: 'unrestricted', label: 'Unrestricted', order: 99, paid: false, priceId: null,
  limits: { firewalls: UNLIMITED, panoramas: UNLIMITED, domains: UNLIMITED, certificates: UNLIMITED },
  features: { monitoring: true, panovision: true, change_mgmt: true },
};

/** The plan an org is entitled to. Billing off => unrestricted. */
function planForOrg(org) {
  if (!config.billing.enabled) return UNRESTRICTED;
  return PLANS[org && org.plan] || PLANS.trial;
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
