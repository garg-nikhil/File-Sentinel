export class DateEvaluator {
  /**
   * Normalizes arbitrary date strings into standard YYYY-MM-DD ISO format
   */
  public static parseToIso(dateStr: string): string | null {
    if (!dateStr) return null;
    const clean = dateStr.trim();

    // ISO format YYYY-MM-DD
    if (/^\d{4}-\d{2}-\d{2}$/.test(clean)) {
      return clean;
    }

    // DD/MM/YYYY or DD-MM-YYYY
    const ddmmyyyy = clean.match(/^(\d{1,2})[\/\.-](\d{1,2})[\/\.-](\d{4})$/);
    if (ddmmyyyy) {
      const day = ddmmyyyy[1].padStart(2, '0');
      const month = ddmmyyyy[2].padStart(2, '0');
      const year = ddmmyyyy[3];
      return `${year}-${month}-${day}`;
    }

    // YYYY/MM/DD
    const yyyymmdd = clean.match(/^(\d{4})[\/\.-](\d{1,2})[\/\.-](\d{1,2})$/);
    if (yyyymmdd) {
      const year = yyyymmdd[1];
      const month = yyyymmdd[2].padStart(2, '0');
      const day = yyyymmdd[3].padStart(2, '0');
      return `${year}-${month}-${day}`;
    }

    // Standard JavaScript Date parse fallback
    const timestamp = Date.parse(clean);
    if (!isNaN(timestamp)) {
      const d = new Date(timestamp);
      return d.toISOString().split('T')[0];
    }

    return null;
  }

  /**
   * Extract potential dates and issue/expiry date candidates from text
   */
  public static extractDatesFromText(text: string): {
    issueDate?: string;
    expiryDate?: string;
    allDates: string[];
  } {
    if (!text) return { allDates: [] };

    const dateRegex = /\b(\d{4}[-\/]\d{1,2}[-\/]\d{1,2}|\d{1,2}[-\/]\d{1,2}[-\/]\d{4}|\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]* \d{1,2},? \d{4})\b/gi;
    const matches = text.match(dateRegex) || [];
    const parsedDates: string[] = [];

    for (const m of matches) {
      const iso = this.parseToIso(m);
      if (iso && !parsedDates.includes(iso)) {
        parsedDates.push(iso);
      }
    }

    let issueDate: string | undefined;
    let expiryDate: string | undefined;

    // Look for contextual keywords near dates
    const lines = text.split(/[\r\n]+/);
    for (const line of lines) {
      const lineLower = line.toLowerCase();
      const lineMatches = line.match(dateRegex) || [];
      if (lineMatches.length === 0) continue;

      const lineIso = this.parseToIso(lineMatches[0]);
      if (!lineIso) continue;

      if (!expiryDate && (lineLower.includes('expir') || lineLower.includes('valid till') || lineLower.includes('valid until') || lineLower.includes('due date'))) {
        expiryDate = lineIso;
      } else if (!issueDate && (lineLower.includes('issue') || lineLower.includes('date of birth') || lineLower.includes('dated') || lineLower.includes('conducted on') || lineLower.includes('start date'))) {
        issueDate = lineIso;
      }
    }

    if (!issueDate && parsedDates.length > 0) issueDate = parsedDates[0];
    if (!expiryDate && parsedDates.length > 1) expiryDate = parsedDates[parsedDates.length - 1];

    return {
      issueDate,
      expiryDate,
      allDates: parsedDates
    };
  }

  /**
   * Checks if an expiry date is strictly earlier than the target audit date
   */
  public static isExpired(expiryDateIso: string, auditDateIso: string): boolean {
    const exp = this.parseToIso(expiryDateIso);
    const audit = this.parseToIso(auditDateIso) || new Date().toISOString().split('T')[0];
    if (!exp || !audit) return false;
    return exp < audit;
  }

  /**
   * Checks if a date is older than a specified number of years relative to the audit date
   */
  public static isOlderThanYears(dateIso: string, auditDateIso: string, years: number = 1): boolean {
    const eventDate = this.parseToIso(dateIso);
    const auditDateStr = this.parseToIso(auditDateIso) || new Date().toISOString().split('T')[0];
    if (!eventDate || !auditDateStr) return false;

    const event = new Date(eventDate);
    const audit = new Date(auditDateStr);

    const diffMs = audit.getTime() - event.getTime();
    const msInYear = years * 365.25 * 24 * 60 * 60 * 1000;

    return diffMs > msInYear;
  }
}
