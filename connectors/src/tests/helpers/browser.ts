/**
 * TEST ONLY: plays the person's browser. Follows redirects (keeping cookies) from the
 * authorization URL until the provider sends the browser to our callback, and returns the
 * callback's query parameters.
 */
export async function followToCallback(authUrl: string, redirectUri: string, maxHops = 25): Promise<Record<string, string>> {
  const jar = new Map<string, string>();
  let url = authUrl;
  for (let i = 0; i < maxHops; i++) {
    if (url.startsWith(redirectUri)) return Object.fromEntries(new URL(url).searchParams);
    const res = await fetch(url, {
      redirect: 'manual',
      headers: jar.size ? { cookie: [...jar].map(([k, v]) => `${k}=${v}`).join('; ') } : {},
    });
    for (const sc of res.headers.getSetCookie()) {
      const pair = sc.split(';')[0];
      const eq = pair.indexOf('=');
      const name = pair.slice(0, eq).trim();
      const value = pair.slice(eq + 1).trim();
      if (value === '' || /expires=Thu, 01 Jan 1970/i.test(sc)) jar.delete(name);
      else jar.set(name, value);
    }
    const loc = res.headers.get('location');
    if (!loc) throw new Error(`login stopped with HTTP ${res.status} at ${url}: ${(await res.text()).slice(0, 400)}`);
    await res.arrayBuffer().catch(() => undefined);
    url = new URL(loc, url).href;
  }
  throw new Error('too many redirects');
}

/** Random strings like the server makes. */
export function randomToken(bytes = 32): string {
  return Buffer.from(crypto.getRandomValues(new Uint8Array(bytes))).toString('base64url');
}

export function newStart(redirectUri: string) {
  return { state: randomToken(), nonce: randomToken(), codeVerifier: randomToken(48), redirectUri };
}
