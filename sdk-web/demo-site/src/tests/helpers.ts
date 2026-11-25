/** Shared helpers for the demo-site tests. */
import * as net from 'node:net';
import * as path from 'node:path';

export async function freePort(): Promise<number> {
  return new Promise((resolve) => {
    const s = net.createServer().listen(0, '127.0.0.1', () => {
      const p = (s.address() as net.AddressInfo).port;
      s.close(() => resolve(p));
    });
  });
}

/** fetch with a cookie jar, acting like a browser on the demo site (sends Origin on POST, like browsers do). */
export function browser(siteOrigin: string, sendOrigin = siteOrigin) {
  let cookie = '';
  const f = (async (input: any, init: any = {}) => {
    const url = String(input).startsWith('http') ? String(input) : siteOrigin + String(input);
    const headers = new Headers(init.headers ?? {});
    if (url.startsWith(siteOrigin) && cookie) headers.set('cookie', cookie);
    // Browsers send Origin on every cross-origin request and on same-origin POSTs.
    if ((init.method ?? 'GET').toUpperCase() !== 'GET' || !url.startsWith(siteOrigin)) headers.set('origin', sendOrigin);
    const res = await fetch(url, { ...init, headers, redirect: 'manual' });
    if (url.startsWith(siteOrigin)) {
      for (const c of res.headers.getSetCookie?.() ?? []) {
        const pair = c.split(';')[0];
        const name = pair.split('=')[0];
        cookie = [...cookie.split('; ').filter((x) => x && !x.startsWith(name + '=')), pair].join('; ');
      }
    }
    return res;
  }) as typeof fetch;
  const post = async (p: string, body?: unknown) =>
    f(p, { method: 'POST', headers: { 'content-type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) });
  return { fetch: f, post };
}

/** The widget is a sibling package; load its compiled modules at run time. */
export function widget() {
  const dist = path.resolve(__dirname, '..', '..', '..', 'widget', 'dist');
  return {
    WidgetController: require(path.join(dist, 'controller.js')).WidgetController,
    PairingClient: require(path.join(dist, 'pairing-client.js')).PairingClient,
  };
}

export const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export async function until(cond: () => boolean, ms = 8000, what = 'condition'): Promise<void> {
  const t0 = Date.now();
  while (!cond()) {
    if (Date.now() - t0 > ms) throw new Error(`timed out waiting for ${what}`);
    await sleep(20);
  }
}
