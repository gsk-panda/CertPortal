'use strict';

// Unit tests run with billing on so plan limits apply; no Stripe keys needed.
process.env.BILLING_ENABLED = process.env.BILLING_ENABLED || 'true';
