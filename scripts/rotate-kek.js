'use strict';

/**
 * MASTER_KEK rotation: re-wraps every stored secret under the current KEK.
 *
 * Procedure (see README "Rotating MASTER_KEK"):
 *   1. Generate a new key:  node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"
 *   2. Set MASTER_KEK=<new>, MASTER_KEK_PREVIOUS=<old> in the environment
 *   3. Run: node scripts/rotate-kek.js   (app may stay online; decrypt falls
 *      back to the previous KEK during the window)
 *   4. Remove MASTER_KEK_PREVIOUS and restart.
 */

const { validateConfig } = require('../src/config');
const { query, pool } = require('../src/db/pool');
const { rewrap } = require('../src/crypto/envelope');

const TARGETS = [
  ['users', 'totp_secret'],
  ['firewalls', 'api_key_encrypted'],
  ['dns_providers', 'credentials_encrypted'],
  ['certificates', 'key_pem_encrypted'],
  ['acme_accounts', 'account_key_encrypted'],
  ['notification_settings', 'smtp_encrypted'],
];

async function main() {
  validateConfig();
  if (!process.env.MASTER_KEK_PREVIOUS) {
    console.error('MASTER_KEK_PREVIOUS must be set to the old key during rotation.');
    process.exit(1);
  }
  let total = 0;
  for (const [table, column] of TARGETS) {
    const { rows } = await query(`SELECT id, ${column} AS v FROM ${table} WHERE ${column} IS NOT NULL`);
    for (const row of rows) {
      await query(`UPDATE ${table} SET ${column} = $1 WHERE id = $2`, [rewrap(row.v), row.id]);
      total++;
    }
    console.log(`[rotate-kek] ${table}.${column}: ${rows.length} record(s) re-wrapped`);
  }
  console.log(`[rotate-kek] done — ${total} secrets now under the new KEK. Remove MASTER_KEK_PREVIOUS and restart the app.`);
  await pool.end();
}

main().catch((err) => { console.error('[rotate-kek] failed:', err.message); process.exit(1); });
