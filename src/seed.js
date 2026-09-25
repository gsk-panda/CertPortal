'use strict';

const argon2 = require('argon2');
const { query } = require('./db/pool');
const { config } = require('./config');

/** Create the platform admin from env on first boot (no platform admin exists yet). */
async function seedPlatformAdmin() {
  const { rows } = await query(`SELECT count(*)::int AS n FROM users WHERE role = 'platform_admin'`);
  if (rows[0].n > 0) return;
  if (!config.adminEmail || !config.adminPassword) {
    console.warn('[seed] no platform admin exists and ADMIN_EMAIL/ADMIN_PASSWORD are not set — you will not be able to log in.');
    return;
  }
  const hash = await argon2.hash(config.adminPassword, { type: argon2.argon2id });
  await query(
    `INSERT INTO users (org_id, email, password_hash, role) VALUES (NULL, $1, $2, 'platform_admin')
     ON CONFLICT (email) DO NOTHING`,
    [config.adminEmail.toLowerCase(), hash]
  );
  console.log(`[seed] platform admin created: ${config.adminEmail}`);
}

module.exports = { seedPlatformAdmin };
