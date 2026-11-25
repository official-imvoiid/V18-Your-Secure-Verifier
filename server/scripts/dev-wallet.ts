/**
 * TEST ONLY: plays a phone wallet (mdoc_wallet, PROTOCOL.md 4c.5) against a
 * RUNNING dev server, so the website widget can be tested without a phone.
 *
 *   npm run dev-wallet -- --session pair_xxx            answer with age_over_18 = true
 *   npm run dev-wallet -- --session pair_xxx --under18  answer with age_over_18 = false
 *   npm run dev-wallet -- --session pair_xxx --pid      use an EU PID instead of an mDL
 *
 * It asks the server for the wallet request (as the widget would), makes a
 * TEST mdoc signed by the dev TEST IACA in server/assets/iaca/test/ (which
 * only a dev-mode server trusts), answers, and posts the answer. The widget
 * then gets the ticket through its normal pairing poll.
 *
 * To test the widget's own navigator.credentials.get() path instead, use
 * the TEST IACA files in server/assets/iaca/test/ in the web test wallet.
 */
import 'reflect-metadata';
import * as path from 'node:path';
import { PID_DOCTYPE } from '../src/wallet/mdoc.js';
import { issueTestMdoc, loadOrCreateDevIaca, newHolderKey, testWalletAnswer } from '../src/wallet/test-wallet.js';

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(name);
  return i >= 0 ? process.argv[i + 1] : undefined;
}

async function main(): Promise<void> {
  const server = (arg('--server') ?? 'http://localhost:8080').replace(/\/v1\/?$/, '').replace(/\/+$/, '');
  let session = arg('--session');
  if (session?.startsWith('v18://')) session = new URL(session.replace('v18://', 'http://x/')).searchParams.get('session') ?? undefined;
  if (!session) throw new Error('Give --session <pairing session id or v18://verify link>');
  const pid = process.argv.includes('--pid');

  const poll = await (await fetch(`${server}/v1/pairing/${session}`)).json();
  if (!poll.origin) throw new Error(`No such session: ${JSON.stringify(poll)}`);
  const origin = poll.origin as string;
  const reqRes = await fetch(`${server}/v1/wallet/request`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Origin: origin },
    body: JSON.stringify({ sessionId: session }),
  });
  const req = await reqRes.json();
  if (!reqRes.ok) throw new Error(`wallet/request failed: ${JSON.stringify(req)}`);

  const iaca = await loadOrCreateDevIaca(path.resolve(__dirname, '..', 'assets', 'iaca'));
  const holder = newHolderKey();
  const mdoc = await issueTestMdoc({ iaca, holder, ageOver18: !process.argv.includes('--under18'), docType: pid ? PID_DOCTYPE : undefined });
  const response = await testWalletAnswer({ mdoc, holder, request: req.digital.requests[0], origin, docType: pid ? PID_DOCTYPE : undefined });
  const v = await fetch(`${server}/v1/wallet/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Origin: origin },
    body: JSON.stringify({ sessionId: session, response }),
  });
  process.stdout.write(`${v.status} ${JSON.stringify(await v.json())}\n`);
}

main().catch((err) => {
  process.stderr.write(`dev-wallet failed: ${(err as Error).message}\n`);
  process.exit(1);
});
