/**
 * Birth date parsing and the 18+ decision.
 *
 * Cautious on purpose:
 * - The 18th birthday counts only once that date has started everywhere on Earth
 *   (we use the date in UTC-12, the last time zone to reach a new day).
 * - Born on 29 February: the birthday in a non-leap year is 1 March.
 * - Only a year (YYYY) means the last day of that year; only a year and month means the
 *   last day of that month. So nobody is called 18 too early.
 */

export interface BirthDate {
  year: number;
  /** 1-12, or undefined when only the year is known. */
  month?: number;
  /** 1-31, or undefined when the day is unknown. */
  day?: number;
}

const MIN_YEAR = 1880;

function valid(year: number, month?: number, day?: number): BirthDate | undefined {
  if (!Number.isInteger(year) || year < MIN_YEAR || year > 9999) return undefined;
  if (month === undefined) return { year };
  if (!Number.isInteger(month) || month < 1 || month > 12) return undefined;
  if (day === undefined) return { year, month };
  if (!Number.isInteger(day) || day < 1 || day > daysInMonth(year, month)) return undefined;
  return { year, month, day };
}

function daysInMonth(year: number, month: number): number {
  return new Date(Date.UTC(year, month, 0)).getUTCDate();
}

/** `YYYY-MM-DD`, `YYYY-MM`, `YYYY` (ISO 8601, as in OIDC `birthdate`). */
export function parseIsoDate(value: unknown): BirthDate | undefined {
  if (typeof value !== 'string') return undefined;
  const v = value.trim().replace(/Z$/, '');
  let m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(v);
  if (m) return valid(+m[1], +m[2], +m[3]);
  m = /^(\d{4})-(\d{2})$/.exec(v);
  if (m) return valid(+m[1], +m[2]);
  m = /^(\d{4})$/.exec(v);
  if (m) return valid(+m[1]);
  return undefined;
}

/** Day first: `DDMMYYYY`, `DD/MM/YYYY`, `DD-MM-YYYY`, `DD.MM.YYYY`. */
export function parseDayFirstDate(value: unknown): BirthDate | undefined {
  if (typeof value !== 'string') return undefined;
  const v = value.trim();
  const m = /^(\d{2})[/.-]?(\d{2})[/.-]?(\d{4})$/.exec(v);
  if (!m) return undefined;
  return valid(+m[3], +m[2], +m[1]);
}

/** The first moment (UTC ms) at which the person is surely 18 everywhere. */
function surelyAdultFrom(b: BirthDate, years: number): number {
  // Use the latest possible birth day when the date is partial.
  const month = b.month ?? 12;
  const day = b.day ?? daysInMonth(b.year, month);
  const targetYear = b.year + years;
  let tMonth = month;
  let tDay = day;
  if (tMonth === 2 && tDay === 29 && daysInMonth(targetYear, 2) === 28) {
    tMonth = 3;
    tDay = 1;
  }
  // Midnight at the start of that date in UTC-12 is 12:00 UTC on the same date.
  return Date.UTC(targetYear, tMonth - 1, tDay, 12, 0, 0);
}

export function isAtLeast(b: BirthDate, years: number, now: Date): boolean {
  return now.getTime() >= surelyAdultFrom(b, years);
}

export function isOver18(b: BirthDate, now: Date = new Date()): boolean {
  return isAtLeast(b, 18, now);
}

/**
 * A Swedish personal identity number (personnummer, 12 digits YYYYMMDDNNNN) or
 * coordination number (samordningsnummer: day + 60) to a birth date.
 */
export function birthDateFromSwedishPersonalNumber(pnr: unknown): BirthDate | undefined {
  if (typeof pnr !== 'string') return undefined;
  const m = /^(\d{4})(\d{2})(\d{2})\d{4}$/.exec(pnr.trim());
  if (!m) return undefined;
  let day = +m[3];
  if (day > 60) day -= 60;
  return valid(+m[1], +m[2], day);
}
