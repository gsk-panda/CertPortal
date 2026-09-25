'use strict';

const { config, validateConfig } = require('./config');
const { runMigrations } = require('./db/migrate');
const { seedPlatformAdmin } = require('./seed');
const { buildApp } = require('./app');

async function main() {
  validateConfig();
  await runMigrations();
  await seedPlatformAdmin();

  if (config.mockPanos) {
    const { startMockPanos } = require('./services/panos/mock-server');
    await startMockPanos(config.mockPanosPort);
    console.log(`[mock-panos] fake PAN-OS XML API listening on https://localhost:${config.mockPanosPort}`);
  }

  if (config.acmeDns.port > 0) {
    const { startAuthDns } = require('./services/dns/authdns-server');
    await startAuthDns(config.acmeDns.port);
    console.log(`[acme-dns] authoritative DNS responder for ${config.acmeDns.zone} on udp/${config.acmeDns.port}`);
  }

  const app = buildApp();
  const server = app.listen(config.port, () => {
    console.log(`[certportal] listening on :${config.port} (${config.env})`);
    console.log(`[certportal] ACME directory: ${config.acme.directoryUrl}${config.acme.isProduction ? ' (PRODUCTION)' : ''}`);
  });

  if (!config.disableScheduler) {
    const { startScheduler } = require('./services/renewal/engine');
    startScheduler();
  }

  const shutdown = () => {
    console.log('[certportal] shutting down');
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(1), 8000).unref();
  };
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
}

main().catch((err) => {
  console.error('[certportal] fatal startup error:', err.message);
  process.exit(1);
});
