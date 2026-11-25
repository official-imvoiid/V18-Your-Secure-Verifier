/**
 * npm run test:pg   runs the WHOLE server test suite against a real PostgreSQL.
 *
 * It starts a throw-away PostgreSQL 17 with the `embedded-postgres` npm
 * package (real PostgreSQL binaries, no Docker), runs `node --test` on the
 * built tests with V18_TEST_DB=postgres (every test server gets its own fresh
 * database), then stops and deletes the cluster. Build first (npm run build).
 */
import { spawn } from 'node:child_process';
import * as fs from 'node:fs';
import * as net from 'node:net';
import * as os from 'node:os';
import * as path from 'node:path';

async function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const s = net.createServer();
    s.once('error', reject);
    s.listen(0, '127.0.0.1', () => {
      const port = (s.address() as net.AddressInfo).port;
      s.close(() => resolve(port));
    });
  });
}

async function main(): Promise<void> {
  const { default: EmbeddedPostgres } = (await import('embedded-postgres')) as { default: new (o: Record<string, unknown>) => any };
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'v18-pg-'));
  const port = await freePort();
  const password = 'v18-test-only';
  const pg = new EmbeddedPostgres({
    databaseDir: dir,
    port,
    user: 'postgres',
    password,
    persistent: false,
    postgresFlags: ['-c', 'max_connections=400', '-c', 'fsync=off', '-c', 'synchronous_commit=off'],
    onLog: () => undefined,
  });
  process.stderr.write(`Starting PostgreSQL (embedded-postgres) on port ${port}...\n`);
  await pg.initialise();
  await pg.start();
  const version = await (async () => {
    const client = pg.getPgClient();
    await client.connect();
    const r = await client.query('SHOW server_version');
    await client.end();
    return r.rows[0].server_version as string;
  })();
  process.stderr.write(`PostgreSQL ${version} is running. Running the tests with V18_TEST_DB=postgres.\n`);

  const files = process.argv.slice(2).length > 0 ? process.argv.slice(2) : ['dist/tests/**/*.test.js'];
  const code = await new Promise<number>((resolve) => {
    const child = spawn(process.execPath, ['--test', '--test-reporter=spec', ...files], {
      stdio: 'inherit',
      env: {
        ...process.env,
        V18_TEST_DB: 'postgres',
        V18_TEST_PG_URL: `postgres://postgres:${encodeURIComponent(password)}@127.0.0.1:${port}/postgres`,
      },
    });
    child.on('exit', (c) => resolve(c ?? 1));
  });

  await pg.stop().catch(() => undefined);
  fs.rmSync(dir, { recursive: true, force: true });
  process.stderr.write(`PostgreSQL stopped. Tests exited with code ${code}.\n`);
  process.exit(code);
}

main().catch((err) => {
  process.stderr.write(`test:pg failed: ${(err as Error).stack}\n`);
  process.exit(1);
});
