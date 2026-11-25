// Country catalog (PROTOCOL.md 4d.2): which IDs work in which country. The app never keeps its
// own list of countries: it reads GET /v1/catalog from the server, which lists only what this
// deployment really supports.
//
// What the Windows app does with each method:
//   - "pc":    done on this PC. anon_aadhaar (zero-knowledge proof built here) and login
//              connectors (connector:<id>, through the system browser).
//   - "phone": the method needs the phone (chip, QR, wallet, face). The PC lists it as
//              "with your phone", which leads into the device link (3.9).
// Methods the PC can't do and the phone can't do either are not shown.

export type Privacy = 'zero_knowledge' | 'on_device' | 'wallet' | 'login' | 'estimate';
const PRIVACY: readonly Privacy[] = ['zero_knowledge', 'on_device', 'wallet', 'login', 'estimate'];

export interface CatalogMethod {
  method: string;
  label: string;
  documents: string[];
  needs: string[];
  privacy: Privacy;
  platforms: string[];
  docTypes?: string[];
}

export interface CatalogCountry {
  code: string;
  name: string;
  region: string;
  methods: CatalogMethod[];
}

export type PcMethodKind = 'aadhaar' | 'connector' | 'phone';

export interface PcMethod {
  kind: PcMethodKind;
  method: string;
  label: string;
  documents: string[];
  privacy: Privacy;
  needs: string[];
  /** For kind "connector": the connector id (the part after "connector:"). */
  connectorId?: string;
}

const CODE_RE = /^[A-Z]{2}$/;
const METHOD_RE = /^[a-z][a-z0-9_]{1,40}(:[a-z0-9_]{1,40})?$/;
const CONNECTOR_RE = /^connector:([a-z0-9_]{2,40})$/;

function text(v: unknown, max: number): string | null {
  if (typeof v !== 'string') return null;
  const t = v.replace(/[\u0000-\u001f\u007f]/g, '').trim();
  return t.length > 0 && t.length <= max ? t : null;
}

function texts(v: unknown, max: number, maxItems = 20): string[] {
  if (!Array.isArray(v)) return [];
  return v.map((x) => text(x, max)).filter((x): x is string => x !== null).slice(0, maxItems);
}

function parseMethod(raw: unknown): CatalogMethod | null {
  if (!raw || typeof raw !== 'object') return null;
  const m = raw as Record<string, unknown>;
  const method = typeof m.method === 'string' && METHOD_RE.test(m.method) ? m.method : null;
  const label = text(m.label, 80);
  const privacy = PRIVACY.includes(m.privacy as Privacy) ? (m.privacy as Privacy) : null;
  if (!method || !label || !privacy) return null;
  const out: CatalogMethod = {
    method,
    label,
    documents: texts(m.documents, 120),
    needs: texts(m.needs, 20),
    privacy,
    platforms: texts(m.platforms, 20).map((p) => p.toLowerCase()),
  };
  const docTypes = texts(m.docTypes, 2);
  if (docTypes.length) out.docTypes = docTypes;
  return out;
}

const methodKey = (m: CatalogMethod) => `${m.method}|${m.label}`;

/** Read GET /v1/catalog defensively: bad entries are dropped, never shown half-broken. */
export function parseCatalog(data: unknown): CatalogCountry[] {
  const list = data && typeof data === 'object' && Array.isArray((data as { countries?: unknown }).countries) ? (data as { countries: unknown[] }).countries : null;
  if (!list) throw new Error('the catalog has no "countries" list');
  const out: CatalogCountry[] = [];
  const seen = new Set<string>();
  for (const raw of list.slice(0, 400)) {
    if (!raw || typeof raw !== 'object') continue;
    const c = raw as Record<string, unknown>;
    const code = typeof c.code === 'string' ? c.code.toUpperCase() : '';
    const name = text(c.name, 80);
    if (!CODE_RE.test(code) || !name || seen.has(code)) continue;
    seen.add(code);
    const methods: CatalogMethod[] = [];
    const ids = new Set<string>();
    for (const m of Array.isArray(c.methods) ? c.methods.slice(0, 50) : []) {
      const pm = parseMethod(m);
      // One method can be listed more than once with different documents, for example
      // emrtd_attested as "Passport (chip)" and as "ID card (chip)". Keep each one.
      if (pm && !ids.has(methodKey(pm))) {
        ids.add(methodKey(pm));
        methods.push(pm);
      }
    }
    out.push({ code, name, region: text(c.region, 40)?.toLowerCase() ?? 'other', methods });
  }
  return out;
}

/** Join two catalog answers (for example ?platform=windows and ?platform=android). */
export function mergeCatalogs(...lists: CatalogCountry[][]): CatalogCountry[] {
  const byCode = new Map<string, CatalogCountry>();
  for (const list of lists) {
    for (const c of list) {
      const have = byCode.get(c.code);
      if (!have) {
        byCode.set(c.code, { ...c, methods: c.methods.map((m) => ({ ...m, platforms: [...m.platforms] })) });
        continue;
      }
      for (const m of c.methods) {
        const same = have.methods.find((x) => methodKey(x) === methodKey(m));
        if (same) same.platforms = [...new Set([...same.platforms, ...m.platforms])];
        else have.methods.push({ ...m, platforms: [...m.platforms] });
      }
    }
  }
  return [...byCode.values()].sort((a, b) => a.name.localeCompare(b.name, 'en'));
}

/** What the Windows app shows for one country, most private first. */
export function pcMethods(country: CatalogCountry): PcMethod[] {
  const out: PcMethod[] = [];
  for (const m of country.methods) {
    const onPc = m.platforms.includes('windows');
    const conn = CONNECTOR_RE.exec(m.method);
    const base = { method: m.method, label: m.label, documents: m.documents, privacy: m.privacy, needs: m.needs };
    if (onPc && m.method === 'anon_aadhaar') out.push({ ...base, kind: 'aadhaar' });
    else if (onPc && conn) out.push({ ...base, kind: 'connector', connectorId: conn[1] });
    else if (m.platforms.includes('android')) out.push({ ...base, kind: 'phone' });
    // Anything else is a method this app can't use, so it isn't shown.
  }
  const rank = (p: PcMethod) => PRIVACY.indexOf(p.privacy) * 2 + (p.kind === 'phone' ? 1 : 0);
  return out.sort((a, b) => rank(a) - rank(b) || a.label.localeCompare(b.label, 'en'));
}
