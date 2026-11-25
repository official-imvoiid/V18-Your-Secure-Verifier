/** Escapes text for safe use inside HTML text and attribute values. */
export function esc(value: unknown): string {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/** "http://localhost:8080/v1/" -> "http://localhost:8080". */
export function normalizeServerUrl(url: string): string {
  return url.trim().replace(/\/+$/, '').replace(/\/v1$/, '');
}

/** "https://example.com" -> "example.com" (what people read on screen). */
export function displayHost(origin: string): string {
  try {
    return new URL(origin).host;
  } catch {
    return origin;
  }
}

export function formatClock(seconds: number): string {
  const s = Math.max(0, Math.floor(seconds));
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`;
}

/** A site challenge we are willing to forward: printable ASCII, 16 to 256 characters. */
export function isUsableChallenge(c: unknown): c is string {
  return typeof c === 'string' && /^[\x21-\x7e]{16,256}$/.test(c);
}

/** Reads `{error, code}` from a V18 or website error reply, if there is one. */
export async function readError(res: Response): Promise<{ error: string; code?: string }> {
  try {
    const data: any = await res.json();
    if (data && typeof data.error === 'string') return { error: data.error, code: data.code };
  } catch {
    /* not JSON */
  }
  return { error: `HTTP ${res.status}` };
}
