/**
 * TEST ONLY: a local copy of the BankID RP API v6.0 (/auth, /collect) over mutual TLS.
 * Like the real service it refuses clients without a certificate from its CA, answers
 * `pending` with hint codes, then `complete` with completionData in BankID's format, and
 * forgets an order once it is complete or failed (a later /collect gives invalidParameters).
 */
import { randomUUID } from 'node:crypto';
import { createServer, type Server } from 'node:https';
import type { AddressInfo } from 'node:net';
import type { testPki } from './keys.js';

export interface BankIdScript {
  /** What /collect answers, in order; the last entry repeats. */
  steps: Array<{ status: 'pending'; hintCode: string } | { status: 'failed'; hintCode: string } | { status: 'complete'; personalNumber: string }>;
}

export interface BankIdMock {
  apiUrl: string;
  script: BankIdScript;
  lastAuthBody?: Record<string, unknown>;
  close(): Promise<void>;
}

export async function startBankIdMock(pki: Awaited<ReturnType<typeof testPki>>): Promise<BankIdMock> {
  const orders = new Map<string, { step: number; script: BankIdScript }>();
  let server: Server;
  const mock: BankIdMock = {
    apiUrl: '',
    script: { steps: [{ status: 'complete', personalNumber: '199001012384' }] },
    close: () => new Promise<void>((r) => server.close(() => r())),
  };
  const send = (res: import('node:http').ServerResponse, status: number, body: unknown) => {
    res.writeHead(status, { 'content-type': 'application/json' });
    res.end(JSON.stringify(body));
  };
  server = createServer({ key: pki.server.keyPem, cert: pki.server.certPem, ca: pki.ca.certPem, requestCert: true, rejectUnauthorized: true }, (req, res) => {
    let raw = '';
    req.on('data', (c) => (raw += c));
    req.on('end', () => {
      let body: Record<string, unknown>;
      try {
        body = JSON.parse(raw) as Record<string, unknown>;
      } catch {
        return send(res, 400, { errorCode: 'invalidParameters', details: 'Invalid JSON' });
      }
      if (req.method === 'POST' && req.url === '/rp/v6.0/auth') {
        mock.lastAuthBody = body;
        if (typeof body.endUserIp !== 'string') return send(res, 400, { errorCode: 'invalidParameters', details: 'Invalid endUserIp' });
        const orderRef = randomUUID();
        orders.set(orderRef, { step: 0, script: mock.script });
        return send(res, 200, { orderRef, autoStartToken: randomUUID(), qrStartToken: randomUUID(), qrStartSecret: randomUUID() });
      }
      if (req.method === 'POST' && req.url === '/rp/v6.0/collect') {
        const order = orders.get(String(body.orderRef));
        if (!order) return send(res, 400, { errorCode: 'invalidParameters', details: 'No such order' });
        const step = order.script.steps[Math.min(order.step, order.script.steps.length - 1)];
        order.step++;
        if (step.status === 'pending') return send(res, 200, { orderRef: body.orderRef, status: 'pending', hintCode: step.hintCode });
        orders.delete(String(body.orderRef));
        if (step.status === 'failed') return send(res, 200, { orderRef: body.orderRef, status: 'failed', hintCode: step.hintCode });
        return send(res, 200, {
          orderRef: body.orderRef,
          status: 'complete',
          completionData: {
            user: { personalNumber: step.personalNumber, name: 'Alex Johnson', givenName: 'Alex', surname: 'Johnson' },
            device: { ipAddress: '192.0.2.10', uhi: 'OZvYM9VvyiAmG7NA5jU5zqGcVpo=' },
            bankIdIssueDate: '2023-04-01Z',
            stepUp: { mrtd: false },
            signature: Buffer.from('<signature>test</signature>').toString('base64'),
            ocspResponse: Buffer.from('ocsp-test').toString('base64'),
            risk: 'low',
          },
        });
      }
      send(res, 404, { errorCode: 'notFound', details: 'Not found' });
    });
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  mock.apiUrl = `https://127.0.0.1:${(server.address() as AddressInfo).port}/rp/v6.0`;
  return mock;
}
