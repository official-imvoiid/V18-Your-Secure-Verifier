import 'reflect-metadata';
import { createV18 } from './app.js';

async function start(): Promise<void> {
  const { app, services, close } = await createV18();
  const { config } = services;

  const server = app.listen(config.port, () => {
    const line = '====================================================';
    console.log(line);
    console.log('  V18 server (protocol v1)');
    console.log(`  Mode:        ${config.devMode ? 'DEV / TEST MODE (V18_DEV_MODE=1)' : 'PRODUCTION'}`);
    console.log(`  Listening:   http://localhost:${config.port}/v1`);
    console.log(`  Health:      http://localhost:${config.port}/v1/health`);
    console.log(`  Public URL:  ${config.publicUrl} (used in deep links)`);
    console.log(`  Key store:   ${services.keys.storeKind} (${config.keyDir})`);
    console.log(`  Database:    ${config.databaseUrl ? 'PostgreSQL (V18_DATABASE_URL)' : config.dbPath}`);
    console.log(`  Ticket keys: ${services.keys.published().map((k) => k.kid).join(', ')}`);
    const m = services.methodStatus();
    console.log(`  Methods:     ${Object.entries(m).filter(([, v]) => v === 'ready').map(([k]) => k).join(', ')}`);
    console.log(`  Not on:      ${Object.entries(m).filter(([, v]) => v !== 'ready').map(([k, v]) => `${k} (${v})`).join(', ')}`);
    console.log(`  Storage:     ${services.db.dialect}; artifacts ${services.artifacts.complete ? 'ready' : 'missing'}; catalog ${services.catalog.status()}`);
    if (services.connectorError) console.log(`  Connectors:  package not loaded (${services.connectorError})`);
    if (config.devMode) {
      console.log('  WARNING: dev mode accepts TEST identities. Never use it for real users.');
    }
    console.log(line);
  });

  const stop = () => {
    server.close(() => {
      void close().finally(() => process.exit(0));
    });
  };
  process.on('SIGINT', stop);
  process.on('SIGTERM', stop);
}

start().catch((err: unknown) => {
  console.error('V18 server failed to start:', err instanceof Error ? err.message : err);
  process.exit(1);
});
