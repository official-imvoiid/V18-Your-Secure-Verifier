// Tiny safe HTML helper. Every ${value} is escaped unless it was made by html`` or raw().
// The page also enforces Trusted Types, so only this module can write HTML into the page.

const RAW = Symbol('raw');
export interface Raw {
  [RAW]: string;
}

export function raw(s: string): Raw {
  return { [RAW]: s };
}

export function esc(v: unknown): string {
  return String(v ?? '').replace(/[&<>"'`]/g, (c) => `&#${c.charCodeAt(0)};`);
}

type Part = Raw | string | number | boolean | null | undefined | Part[];

function piece(v: Part): string {
  if (v === null || v === undefined || v === false) return '';
  if (Array.isArray(v)) return v.map(piece).join('');
  if (typeof v === 'object' && RAW in v) return v[RAW];
  return esc(v);
}

export function html(strings: TemplateStringsArray, ...values: Part[]): Raw {
  let out = strings[0];
  for (let i = 0; i < values.length; i++) out += piece(values[i]) + strings[i + 1];
  return raw(out);
}

export function text(r: Raw): string {
  return r[RAW];
}

interface TTPolicy {
  createHTML(s: string): unknown;
}
let policy: TTPolicy | null = null;
function getPolicy(): TTPolicy {
  if (!policy) {
    const tt = (window as unknown as { trustedTypes?: { createPolicy(n: string, p: { createHTML(s: string): string }): TTPolicy } }).trustedTypes;
    policy = tt ? tt.createPolicy('v18', { createHTML: (s: string) => s }) : { createHTML: (s: string) => s };
  }
  return policy;
}

export function setHtml(el: Element, r: Raw): void {
  (el as unknown as { innerHTML: unknown }).innerHTML = getPolicy().createHTML(r[RAW]);
}
