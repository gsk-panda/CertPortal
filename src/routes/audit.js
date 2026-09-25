'use strict';

const express = require('express');
const { query } = require('../db/pool');

const router = express.Router();

router.get('/', async (req, res, next) => {
  try {
    const page = Math.max(1, parseInt(req.query.page || '1', 10) || 1);
    const limit = 50;
    const { rows } = await query(
      `SELECT a.*, u.email AS user_email FROM audit_log a
       LEFT JOIN users u ON u.id = a.user_id
       WHERE a.org_id = $1 ORDER BY a.id DESC LIMIT $2 OFFSET $3`,
      [req.orgId, limit, (page - 1) * limit]);
    res.render('audit/list', { title: 'Audit log', entries: rows, page, global: false });
  } catch (err) { next(err); }
});

module.exports = router;
