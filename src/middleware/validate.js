'use strict';

/**
 * zod-based body validation. On failure re-renders are impractical
 * generically, so we flash the first error and bounce back to the referrer.
 */

function validateBody(schema) {
  return (req, res, next) => {
    const result = schema.safeParse(req.body);
    if (!result.success) {
      const issue = result.error.issues[0];
      const msg = `${issue.path.join('.') || 'input'}: ${issue.message}`;
      if (req.accepts('html') && req.get('referer')) {
        req.session.flash = { type: 'error', message: msg };
        return res.redirect(req.get('referer'));
      }
      return res.status(400).json({ error: msg });
    }
    req.body = result.data;
    next();
  };
}

module.exports = { validateBody };
