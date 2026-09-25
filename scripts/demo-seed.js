'use strict';

/**
 * Seed a demo database with realistic data for screenshots / demos.
 * Usage: DATABASE_URL=...certportal_demo MASTER_KEK=... node scripts/demo-seed.js
 */

const argon2 = require('argon2');
const crypto = require('crypto');
const { runMigrations } = require('../src/db/migrate');
const { pool, query } = require('../src/db/pool');
const { encrypt } = require('../src/crypto/envelope');

const sha256 = (s) => crypto.createHash('sha256').update(String(s)).digest('hex');
const DUMMY_PEM = '-----BEGIN CERTIFICATE-----\nMIIB...demo...AB\n-----END CERTIFICATE-----';
const days = (n) => new Date(Date.now() + n * 86400e3);

async function main() {
  await runMigrations();

  await query('DELETE FROM organizations'); // fresh demo each run (cascades)
  await query(`DELETE FROM users WHERE role = 'platform_admin'`);

  const adminHash = await argon2.hash('DemoAdmin1!', { type: argon2.argon2id });
  await query(`INSERT INTO users (org_id, email, password_hash, role) VALUES (NULL,'admin@demo.local',$1,'platform_admin')`, [adminHash]);

  const org = (await query(
    `INSERT INTO organizations (name, contact_email, plan, status) VALUES ('Acme Corporation','netops@acme.example','pro','active') RETURNING id`
  )).rows[0].id;

  const aliceHash = await argon2.hash('DemoPassword1!', { type: argon2.argon2id });
  await query(`INSERT INTO users (org_id, email, password_hash, role, last_login) VALUES ($1,'alice@acme.example',$2,'client_admin', now())`, [org, aliceHash]);
  await query(`INSERT INTO users (org_id, email, password_hash, role) VALUES ($1,'bob@acme.example',$2,'client_viewer')`, [org, aliceHash]);

  // agent
  const agentId = (await query(
    `INSERT INTO agents (org_id, name, agent_secret_hash, status, version, last_seen)
     VALUES ($1,'datacenter-1',$2,'active','1.0.0', now()) RETURNING id`, [org, sha256('x')]
  )).rows[0].id;

  // DNS providers
  const cf = (await query(
    `INSERT INTO dns_providers (org_id, type, credentials_encrypted, label) VALUES ($1,'cloudflare',$2,'Corp Cloudflare') RETURNING id`,
    [org, encrypt(JSON.stringify({ api_token: 'demo' }))]
  )).rows[0].id;
  await query(`INSERT INTO dns_providers (org_id, type, label) VALUES ($1,'manual','Manual (lab)')`, [org]);

  // firewalls
  const edge = (await query(
    `INSERT INTO firewalls (org_id, name, mgmt_address, api_key_encrypted, panos_version, serial, hostname, verify_tls, agent_id, status, last_seen)
     VALUES ($1,'Edge-FW-01','fw-edge-01.acme.example',$2,'11.1.4-h7','012801008442','fw-edge-01', true, $3, 'ok', now()) RETURNING id`,
    [org, encrypt('DEMOKEY1'), agentId]
  )).rows[0].id;
  await query(
    `INSERT INTO firewalls (org_id, name, mgmt_address, api_key_encrypted, panos_version, serial, hostname, verify_tls, ha_peer_address, status, last_seen)
     VALUES ($1,'DR-FW-02','10.20.0.1',$2,'11.1.4-h7','012801009133','fw-dr-02', false, '10.20.0.2', 'ok', now())`,
    [org, encrypt('DEMOKEY2')]
  );

  // domains
  async function domain(fqdn, verified, provider) {
    return (await query(
      `INSERT INTO domains (org_id, fqdn, dns_provider_id, ownership_verified, verification_token, verified_at)
       VALUES ($1,$2,$3,$4,$5,$6) RETURNING id`,
      [org, fqdn, provider, verified, 'certportal-' + crypto.randomBytes(24).toString('hex'), verified ? new Date() : null]
    )).rows[0].id;
  }
  const dVpn = await domain('vpn.acme.example', true, cf);
  const dPortal = await domain('portal.acme.example', true, cf);
  const dRemote = await domain('remote.acme.example', false, cf);

  // certificates across states
  async function cert(domainId, sans, keyType, status, notAfterDays, failures = 0, lastError = null) {
    const serial = crypto.randomBytes(8).toString('hex').toUpperCase();
    const id = (await query(
      `INSERT INTO certificates (org_id, domain_id, san_list, key_type, status, not_before, not_after, serial, cert_pem, chain_pem, key_pem_encrypted, renewal_failures, last_error)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$9,$10,$11,$12) RETURNING id`,
      [org, domainId, JSON.stringify(sans), keyType, status,
       status === 'pending' ? null : days(-(90 - notAfterDays)), status === 'pending' ? null : days(notAfterDays),
       status === 'pending' ? null : serial, status === 'pending' ? null : DUMMY_PEM,
       status === 'pending' ? null : encrypt('demo-key'), failures, lastError]
    )).rows[0].id;
    return { id, serial };
  }

  const c1 = await cert(dVpn, ['vpn.acme.example'], 'ecdsa_p256', 'deployed', 41);
  await query(
    `INSERT INTO deployments (certificate_id, firewall_id, panos_cert_name, ssl_tls_profile, gp_portal, validate_endpoint, status, validation_ok, commit_job_id, deployed_at)
     VALUES ($1,$2,'certportal-vpn-acme-example','gp-portal-profile','GP-Portal','vpn.acme.example:443','deployed', true, '412', now())`,
    [c1.id, edge]
  );
  const c2 = await cert(dPortal, ['*.portal.acme.example', 'portal.acme.example'], 'ecdsa_p256', 'deployed', 12);
  await query(
    `INSERT INTO deployments (certificate_id, firewall_id, panos_cert_name, status, validation_ok, commit_job_id, deployed_at)
     VALUES ($1,$2,'certportal-wildcard-portal-acme-example','deployed', true, '318', now())`,
    [c2.id, edge]
  );
  await cert(dVpn, ['api.acme.example'], 'rsa_2048', 'failed', 4, 2, 'deployment failed: commit job 511 FAIL: validation error — The firewall account needs the Superuser role.');

  // timeline for c1
  for (const [action, detail] of [
    ['cert.requested', { sans: ['vpn.acme.example'], keyType: 'ecdsa_p256', firewalls: 1 }],
    ['cert.issued', { serial: c1.serial, notAfter: days(41).toISOString(), directory: 'https://acme-v02.api.letsencrypt.org/directory' }],
    ['cert.deployed', { firewall: 'Edge-FW-01', panosCertName: 'certportal-vpn-acme-example', commitJob: '412', validationOk: true, viaAgent: true }],
  ]) {
    await query(`INSERT INTO audit_log (org_id, action, target_type, target_id, detail) VALUES ($1,$2,'certificate',$3,$4)`,
      [org, action, c1.id, JSON.stringify(detail)]);
  }
  await query(`INSERT INTO notification_settings (org_id, webhook_url) VALUES ($1,'https://hooks.slack.example/certportal')`, [org]);

  console.log('demo data seeded: org Acme Corporation');
  console.log('  platform admin: admin@demo.local / DemoAdmin1!');
  console.log('  client admin:   alice@acme.example / DemoPassword1!');
  await pool.end();
}

main().catch((e) => { console.error(e); process.exit(1); });
