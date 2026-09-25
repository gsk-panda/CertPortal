-- Subscription billing. Existing orgs are grandfathered onto 'enterprise'
-- (unrestricted) so enabling billing never retroactively limits current tenants;
-- new self-serve signups start on 'trial'.
ALTER TABLE organizations
  ADD COLUMN plan text NOT NULL DEFAULT 'enterprise',
  ADD COLUMN trial_ends_at timestamptz;

CREATE TABLE subscriptions (
  id                     uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id                 uuid NOT NULL UNIQUE REFERENCES organizations(id) ON DELETE CASCADE,
  stripe_customer_id     text,
  stripe_subscription_id text,
  plan                   text NOT NULL DEFAULT 'trial',
  status                 text NOT NULL DEFAULT 'trialing'
                         CHECK (status IN ('trialing','active','past_due','canceled','incomplete','unpaid')),
  current_period_end     timestamptz,
  created_at             timestamptz NOT NULL DEFAULT now(),
  updated_at             timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX subscriptions_customer_idx ON subscriptions(stripe_customer_id);

-- idempotency for Stripe webhook delivery (events can be re-sent)
CREATE TABLE billing_events (
  id          text PRIMARY KEY,          -- Stripe event id
  type        text NOT NULL,
  received_at timestamptz NOT NULL DEFAULT now()
);
