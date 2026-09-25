'use strict';

const express = require('express');
const { config } = require('../config');
const billing = require('../services/billing/service');

const router = express.Router();

// Stripe webhook. Mounted with express.raw BEFORE the body parsers and CSRF,
// so req.body is the raw Buffer needed for signature verification.
router.post('/stripe', async (req, res) => {
  if (!config.billing.enabled) return res.status(404).end();
  let event;
  try {
    event = billing.parseWebhook(req.body, req.get('stripe-signature'));
  } catch (err) {
    console.error('[billing] webhook signature verification failed:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }
  try {
    const result = await billing.handleEvent(event);
    res.json({ received: true, ...result });
  } catch (err) {
    console.error('[billing] handleEvent error:', err.message);
    res.status(500).end();
  }
});

module.exports = router;
