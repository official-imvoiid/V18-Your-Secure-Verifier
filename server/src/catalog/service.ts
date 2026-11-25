import * as fs from 'node:fs';
import { ApiError } from '../errors.js';
import { isPlainObject } from '../util.js';

/**
 * GET /v1/catalog (PROTOCOL.md 4d.2): the country catalog from
 * catalog/countries.json, filtered to what
 * THIS deployment really supports, so apps never show a method that does not
 * work here. The file is re-read when it changes on disk.
 */

const PRIVACY = ['zero_knowledge', 'on_device', 'wallet', 'login', 'estimate'];
const NEEDS = ['camera', 'nfc', 'wallet', 'password'];
const PLATFORMS = ['android', 'windows', 'web'];

export interface CatalogMethod {
  method: string;
  label: string;
  documents: string[];
  needs: string[];
  privacy: string;
  platforms: string[];
  docTypes?: string[];
  [extra: string]: unknown;
}

export interface CatalogCountry {
  code: string;
  name: string;
  region: string;
  methods: CatalogMethod[];
  [extra: string]: unknown;
}

export interface Catalog {
  version: 1;
  countries: CatalogCountry[];
  [extra: string]: unknown;
}

/** Checks the 4d.2 schema. Returns a list of problems (empty = valid). */
export function validateCatalog(raw: unknown): string[] {
  const errs: string[] = [];
  if (!isPlainObject(raw)) return ['the catalog is not a JSON object'];
  if (raw.version !== 1) errs.push('version must be 1');
  if (!Array.isArray(raw.countries)) return [...errs, 'countries must be an array'];
  const seen = new Set<string>();
  raw.countries.forEach((c: unknown, i: number) => {
    const at = `countries[${i}]`;
    if (!isPlainObject(c)) return errs.push(`${at} is not an object`);
    if (typeof c.code !== 'string' || !/^[A-Z]{2}$/.test(c.code)) errs.push(`${at}.code must be 2 capital letters`);
    else if (seen.has(c.code)) errs.push(`${at}.code ${c.code} appears twice`);
    else seen.add(c.code);
    if (typeof c.name !== 'string' || !c.name) errs.push(`${at}.name is missing`);
    if (typeof c.region !== 'string' || !c.region) errs.push(`${at}.region is missing`);
    if (!Array.isArray(c.methods)) return errs.push(`${at}.methods must be an array`);
    c.methods.forEach((m: unknown, j: number) => {
      const mt = `${at}.methods[${j}]`;
      if (!isPlainObject(m)) return errs.push(`${mt} is not an object`);
      if (typeof m.method !== 'string' || !/^[a-z0-9_]+(:[a-z0-9_]+)?$/.test(m.method)) errs.push(`${mt}.method is not a method name`);
      if (typeof m.label !== 'string' || !m.label) errs.push(`${mt}.label is missing`);
      if (!Array.isArray(m.documents) || m.documents.some((d) => typeof d !== 'string')) errs.push(`${mt}.documents must be strings`);
      if (!Array.isArray(m.needs) || m.needs.some((d) => !NEEDS.includes(d as string))) errs.push(`${mt}.needs must come from ${NEEDS.join(', ')}`);
      if (!PRIVACY.includes(m.privacy as string)) errs.push(`${mt}.privacy must be one of ${PRIVACY.join(', ')}`);
      if (!Array.isArray(m.platforms) || m.platforms.length === 0 || m.platforms.some((p) => !PLATFORMS.includes(p as string))) {
        errs.push(`${mt}.platforms must come from ${PLATFORMS.join(', ')}`);
      }
      if (m.docTypes !== undefined && (!Array.isArray(m.docTypes) || m.docTypes.some((d) => typeof d !== 'string' || !/^[PIAC]$/.test(d)))) {
        errs.push(`${mt}.docTypes must be P, I, A or C`);
      }
      return undefined;
    });
    return undefined;
  });
  return errs;
}

export class CatalogService {
  private cached: { mtimeMs: number; size: number; catalog: Catalog } | null = null;

  constructor(
    private readonly file: string,
    /** Is this method enabled on this server? */
    private readonly enabled: (method: string) => boolean
  ) {}

  private load(): Catalog {
    let st: fs.Stats;
    try {
      st = fs.statSync(this.file);
    } catch {
      throw new ApiError(503, 'CATALOG_MISSING', 'The country catalog is not installed on this server');
    }
    if (this.cached && this.cached.mtimeMs === st.mtimeMs && this.cached.size === st.size) return this.cached.catalog;
    let raw: unknown;
    try {
      raw = JSON.parse(fs.readFileSync(this.file, 'utf8'));
    } catch {
      throw new ApiError(503, 'CATALOG_INVALID', 'The country catalog is not valid JSON');
    }
    const errs = validateCatalog(raw);
    if (errs.length > 0) {
      console.error(`[v18] catalog ${this.file} is invalid: ${errs.slice(0, 5).join('; ')}`);
      throw new ApiError(503, 'CATALOG_INVALID', `The country catalog does not follow PROTOCOL.md 4d.2 (${errs.length} problems, first: ${errs[0]})`);
    }
    this.cached = { mtimeMs: st.mtimeMs, size: st.size, catalog: raw as Catalog };
    return raw as Catalog;
  }

  /** Is the file there and valid? (for /v1/health) */
  status(): 'ready' | 'missing' | 'invalid' {
    try {
      this.load();
      return 'ready';
    } catch (err) {
      return (err as ApiError).code === 'CATALOG_MISSING' ? 'missing' : 'invalid';
    }
  }

  /** GET /v1/catalog?country=XX&platform=android|windows|web */
  get(query: { country?: unknown; platform?: unknown }) {
    const catalog = this.load();
    let country: string | null = null;
    if (query.country !== undefined) {
      if (typeof query.country !== 'string' || !/^[A-Za-z]{2}$/.test(query.country)) {
        throw new ApiError(400, 'BAD_REQUEST', 'country must be a 2-letter ISO code');
      }
      country = query.country.toUpperCase();
    }
    let platform: string | null = null;
    if (query.platform !== undefined) {
      if (typeof query.platform !== 'string' || !PLATFORMS.includes(query.platform)) {
        throw new ApiError(400, 'BAD_REQUEST', 'platform must be android, windows or web');
      }
      platform = query.platform;
    }
    const countries = catalog.countries
      .filter((c) => country === null || c.code === country)
      .map((c) => ({
        ...c,
        methods: c.methods.filter((m) => this.enabled(m.method) && (platform === null || m.platforms.includes(platform))),
      }))
      .filter((c) => c.methods.length > 0);
    return { version: 1 as const, countries };
  }
}
