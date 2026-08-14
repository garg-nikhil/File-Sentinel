import { DateSemanticType, ExtractedDateItem } from './models.js';

export interface ExtractedDatesResult {
  issueDate?: string;
  effectiveDate?: string;
  expiryDate?: string;
  reviewDate?: string;
  applicationDate?: string;
  renewalDate?: string;
  auditDate?: string;
  allDates: string[];
  dateItems: ExtractedDateItem[];
}

const MONTH_NAMES: Record<string, string> = {
  jan: '01', january: '01',
  feb: '02', february: '02',
  mar: '03', march: '03',
  apr: '04', april: '04',
  may: '05',
  jun: '06', june: '06',
  jul: '07', july: '07',
  aug: '08', august: '08',
  sep: '09', sept: '09', september: '09',
  oct: '10', october: '10',
  nov: '11', november: '11',
  dec: '12', december: '12'
};

export class DateEvaluator {
  /**
   * Normalizes arbitrary date strings into standard YYYY-MM-DD ISO format.
   * Returns null if date is ambiguous or invalid.
   */
  public static parseToIso(dateStr: string): string | null {
    if (!dateStr || typeof dateStr !== 'string') return null;
    const clean = dateStr.trim().replace(/^['"\(]+|['"\)\.\,]+$/g, '');
    if (!clean || clean.length < 6) return null;

    // 1. ISO format YYYY-MM-DD
    const isoMatch = clean.match(/^(\d{4})-(\d{1,2})-(\d{1,2})$/);
    if (isoMatch) {
      const y = parseInt(isoMatch[1], 10);
      const m = parseInt(isoMatch[2], 10);
      const d = parseInt(isoMatch[3], 10);
      if (m >= 1 && m <= 12 && d >= 1 && d <= 31 && y >= 1900 && y <= 2100) {
        return `${y.toString().padStart(4, '0')}-${m.toString().padStart(2, '0')}-${d.toString().padStart(2, '0')}`;
      }
      return null;
    }

    // 2. YYYY/MM/DD or YYYY.MM.DD
    const yyyymmdd = clean.match(/^(\d{4})[\/\.](\d{1,2})[\/\.](\d{1,2})$/);
    if (yyyymmdd) {
      const y = parseInt(yyyymmdd[1], 10);
      const m = parseInt(yyyymmdd[2], 10);
      const d = parseInt(yyyymmdd[3], 10);
      if (m >= 1 && m <= 12 && d >= 1 && d <= 31 && y >= 1900 && y <= 2100) {
        return `${y.toString().padStart(4, '0')}-${m.toString().padStart(2, '0')}-${d.toString().padStart(2, '0')}`;
      }
      return null;
    }

    // 3. Named Month: "31 March 2027", "31-Mar-2027", "10 July 2026", "1st June 2026"
    const named1 = clean.match(/^(\d{1,2})(?:st|nd|rd|th)?[\s\/\.-]+([A-Za-z]{3,15})[\s\/\.-]+(\d{4})$/);
    if (named1) {
      const d = parseInt(named1[1], 10);
      const mKey = named1[2].toLowerCase();
      const y = parseInt(named1[3], 10);
      const mStr = MONTH_NAMES[mKey];
      if (mStr && d >= 1 && d <= 31 && y >= 1900 && y <= 2100) {
        return `${y.toString().padStart(4, '0')}-${mStr}-${d.toString().padStart(2, '0')}`;
      }
    }

    // 4. Named Month: "March 31, 2027", "July 10 2026", "August 14, 2026"
    const named2 = clean.match(/^([A-Za-z]{3,15})[\s\/\.-]+(\d{1,2})(?:st|nd|rd|th)?(?:,)?[\s\/\.-]+(\d{4})$/);
    if (named2) {
      const mKey = named2[1].toLowerCase();
      const d = parseInt(named2[2], 10);
      const y = parseInt(named2[3], 10);
      const mStr = MONTH_NAMES[mKey];
      if (mStr && d >= 1 && d <= 31 && y >= 1900 && y <= 2100) {
        return `${y.toString().padStart(4, '0')}-${mStr}-${d.toString().padStart(2, '0')}`;
      }
    }

    // 5. DD/MM/YYYY or DD-MM-YYYY or DD.MM.YYYY
    const ddmmyyyy = clean.match(/^(\d{1,2})[\/\.-](\d{1,2})[\/\.-](\d{4})$/);
    if (ddmmyyyy) {
      const p1 = parseInt(ddmmyyyy[1], 10);
      const p2 = parseInt(ddmmyyyy[2], 10);
      const y = parseInt(ddmmyyyy[3], 10);

      let d: number, m: number;
      if (p1 > 12 && p2 <= 12) {
        d = p1;
        m = p2;
      } else if (p2 > 12 && p1 <= 12) {
        d = p2;
        m = p1;
      } else {
        // Standard DD/MM/YYYY Indian/European domain interpretation
        d = p1;
        m = p2;
      }

      if (m >= 1 && m <= 12 && d >= 1 && d <= 31 && y >= 1900 && y <= 2100) {
        return `${y.toString().padStart(4, '0')}-${m.toString().padStart(2, '0')}-${d.toString().padStart(2, '0')}`;
      }
      return null;
    }

    return null;
  }

  /**
   * Performs semantic date extraction and classification.
   * STRICT GUARANTEE: Never infers an expiry date unless explicit expiry context
   * or a date range context is present in the document.
   */
  public static extractDatesFromText(text: string): ExtractedDatesResult {
    if (!text) {
      return { allDates: [], dateItems: [] };
    }

    const getDateTokenRegex = () => /\b(\d{4}[-\/\.]\d{1,2}[-\/\.]\d{1,2}|\d{1,2}[-\/\.]\d{1,2}[-\/\.]\d{4}|\d{1,2}(?:st|nd|rd|th)?[\s\/\.-]+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*[\s\/\.-]+\d{4}|(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*[\s\/\.-]+\d{1,2}(?:st|nd|rd|th)?,?[\s\/\.-]+\d{4})\b/gi;

    const rawMatches = text.match(getDateTokenRegex()) || [];
    const allDates: string[] = [];
    for (const m of rawMatches) {
      const iso = this.parseToIso(m);
      if (iso && !allDates.includes(iso)) {
        allDates.push(iso);
      }
    }

    let issueDate: string | undefined;
    let effectiveDate: string | undefined;
    let expiryDate: string | undefined;
    let reviewDate: string | undefined;
    let applicationDate: string | undefined;
    let renewalDate: string | undefined;
    let auditDate: string | undefined;

    const dateItems: ExtractedDateItem[] = [];

    // Helper to find and parse date within text
    const findDate = (str: string): string | null => {
      const direct = this.parseToIso(str);
      if (direct) return direct;
      const matches = str.match(getDateTokenRegex());
      if (matches && matches.length > 0) {
        return this.parseToIso(matches[0]);
      }
      return null;
    };

    const lines = text.split(/[\r\n]+/);

    // STEP 1: Check for coverage/validity date ranges
    // e.g. "Coverage: 01/04/2026 - 31/03/2027", "Period of Insurance: 01-Apr-2026 to 31-Mar-2027"
    const rangeRegex = /(?:coverage(?:\s*period)?|period\s*of\s*insurance|insurance\s*coverage(?:\s*period)?|validity(?:\s*period)?|valid\s*from|term|tenure|policy\s*period)[:\s]+(?:from\s+)?([^\n\r]+?)(?:\s+to\s+|\s*-\s*|\s+through\s+|\s+until\s+|\s+till\s+)([^\n\r]+)/gi;
    let rangeMatch: RegExpExecArray | null;
    while ((rangeMatch = rangeRegex.exec(text)) !== null) {
      const startIso = findDate(rangeMatch[1]);
      const endIso = findDate(rangeMatch[2]);
      if (startIso) {
        effectiveDate = effectiveDate || startIso;
        dateItems.push({
          value: startIso,
          type: 'EFFECTIVE_DATE',
          sourceText: rangeMatch[1].trim(),
          context: 'Validity range start'
        });
      }
      if (endIso) {
        expiryDate = expiryDate || endIso;
        dateItems.push({
          value: endIso,
          type: 'EXPIRY_DATE',
          sourceText: rangeMatch[2].trim(),
          context: 'Validity range end'
        });
      }
    }

    // Also scan lines with multiple dates in range context
    for (const line of lines) {
      const lineLower = line.toLowerCase();
      const lineDates = line.match(getDateTokenRegex()) || [];
      if (lineDates.length >= 2 && !expiryDate) {
        const isRangeContext = /(?:coverage|period|validity|valid\s*from|term|tenure|policy\s*period|insurance)/i.test(lineLower);
        if (isRangeContext) {
          const d1 = this.parseToIso(lineDates[0]);
          const d2 = this.parseToIso(lineDates[1]);
          if (d1 && d2) {
            effectiveDate = effectiveDate || d1;
            expiryDate = expiryDate || d2;
            dateItems.push({
              value: d1,
              type: 'EFFECTIVE_DATE',
              sourceText: lineDates[0],
              context: line.trim()
            });
            dateItems.push({
              value: d2,
              type: 'EXPIRY_DATE',
              sourceText: lineDates[1],
              context: line.trim()
            });
          }
        }
      }
    }

    // STEP 2: Pattern-based labeled date extraction (matches label directly to its associated date)
    // Check Expiry Date patterns: "Expiry Date: 2027-01-10", "Next refill due 2027-01-10", "valid till 2027-01-10"
    const expiryPattern = /(?:expiry\s*date|expiration\s*date|date\s*of\s*expiry|valid\s*until|valid\s*till|valid\s*through|valid\s*upto|valid\s*up\s*to|validity\s*end|policy\s*expiry|certificate\s*expiry|cert\s*expiry|coverage\s*ends|coverage\s*until|coverage\s*through|effective\s*until|effective\s*through|expires\s*on|expired\s*on|next\s*refill(?:\s*due)?(?:\s*date)?|refill\s*due(?:\s*date)?|refill\s*expiry|next\s*inspection(?:\s*due)?(?:\s*date)?|due\s*date|\bexpiry\b)[:\s]*([^\n\r,;]+)/gi;
    let expMatch: RegExpExecArray | null;
    while ((expMatch = expiryPattern.exec(text)) !== null) {
      const parsed = findDate(expMatch[1]);
      if (parsed && !expiryDate) {
        expiryDate = parsed;
        dateItems.push({
          value: parsed,
          type: 'EXPIRY_DATE',
          sourceText: expMatch[1].trim(),
          context: expMatch[0].trim()
        });
      }
    }

    // Check Review Date patterns
    const reviewPattern = /(?:review\s*date|reviewed\s*date|reviewed\s*on|next\s*review\s*date|policy\s*review|date\s*of\s*review|annual\s*review)[:\s]*([^\n\r,;]+)/gi;
    let revMatch: RegExpExecArray | null;
    while ((revMatch = reviewPattern.exec(text)) !== null) {
      const parsed = findDate(revMatch[1]);
      if (parsed && !reviewDate) {
        reviewDate = parsed;
        dateItems.push({
          value: parsed,
          type: 'REVIEW_DATE',
          sourceText: revMatch[1].trim(),
          context: revMatch[0].trim()
        });
      }
    }

    // Check Application Date patterns
    const appPattern = /(?:application\s*date|date\s*of\s*application|applied\s*date|applied\s*on|acknowledgement\s*date)[:\s]*([^\n\r,;]+)/gi;
    let appMatch: RegExpExecArray | null;
    while ((appMatch = appPattern.exec(text)) !== null) {
      const parsed = findDate(appMatch[1]);
      if (parsed && !applicationDate) {
        applicationDate = parsed;
        dateItems.push({
          value: parsed,
          type: 'APPLICATION_DATE',
          sourceText: appMatch[1].trim(),
          context: appMatch[0].trim()
        });
      }
    }

    // Check Effective / Start Date patterns
    const effPattern = /(?:effective\s*date|effective\s*from|valid\s*from|start\s*date|commencement\s*date|period\s*start|policy\s*start)[:\s]*([^\n\r,;]+)/gi;
    let effMatch: RegExpExecArray | null;
    while ((effMatch = effPattern.exec(text)) !== null) {
      const parsed = findDate(effMatch[1]);
      if (parsed && !effectiveDate) {
        effectiveDate = parsed;
        dateItems.push({
          value: parsed,
          type: 'EFFECTIVE_DATE',
          sourceText: effMatch[1].trim(),
          context: effMatch[0].trim()
        });
      }
    }

    // Check Issue / Serviced / Drill / Last Refill Date patterns
    const issuePattern = /(?:issue\s*date|date\s*of\s*issue|issued\s*date|issued\s*on|last\s*refill(?:\s*date)?|previous\s*refill(?:\s*date)?|refill\s*date|serviced\s*date|drill\s*date|conducted\s*on|conducted\s*date|inspection\s*date|date\s*of\s*birth|dob|\bdated\b)[:\s]*([^\n\r,;]+)/gi;
    let issMatch: RegExpExecArray | null;
    while ((issMatch = issuePattern.exec(text)) !== null) {
      const parsed = findDate(issMatch[1]);
      if (parsed && !issueDate) {
        issueDate = parsed;
        dateItems.push({
          value: parsed,
          type: 'ISSUE_DATE',
          sourceText: issMatch[1].trim(),
          context: issMatch[0].trim()
        });
      }
    }

    // STEP 3: Line-by-line fallback for single dates on labeled lines
    for (const line of lines) {
      const lineLower = line.toLowerCase();
      const lineDates = line.match(getDateTokenRegex()) || [];
      if (lineDates.length === 0) continue;

      const firstDateIso = this.parseToIso(lineDates[0]);
      if (!firstDateIso) continue;

      // Check Expiry Date context
      if (
        !expiryDate &&
        /(?:expiry\s*date|expiration\s*date|date\s*of\s*expiry|valid\s*until|valid\s*till|valid\s*through|valid\s*upto|valid\s*up\s*to|validity\s*end|policy\s*expiry|certificate\s*expiry|cert\s*expiry|coverage\s*ends|coverage\s*until|coverage\s*through|effective\s*until|effective\s*through|expires\s*on|expired\s*on|next\s*refill|refill\s*date|next\s*inspection\s*due|due\s*date|\bexpiry\b)/i.test(lineLower)
      ) {
        expiryDate = firstDateIso;
        dateItems.push({
          value: firstDateIso,
          type: 'EXPIRY_DATE',
          sourceText: lineDates[0],
          context: line.trim()
        });
        continue;
      }

      // Check Review Date context (Policy review dates MUST NOT be treated as expiry)
      if (
        !reviewDate &&
        /(?:review\s*date|reviewed\s*date|reviewed\s*on|next\s*review\s*date|policy\s*review|date\s*of\s*review|annual\s*review)/i.test(lineLower)
      ) {
        reviewDate = firstDateIso;
        dateItems.push({
          value: firstDateIso,
          type: 'REVIEW_DATE',
          sourceText: lineDates[0],
          context: line.trim()
        });
        continue;
      }

      // Check Application Date context
      if (
        !applicationDate &&
        /(?:application\s*date|date\s*of\s*application|applied\s*date|applied\s*on|acknowledgement\s*date)/i.test(lineLower)
      ) {
        applicationDate = firstDateIso;
        dateItems.push({
          value: firstDateIso,
          type: 'APPLICATION_DATE',
          sourceText: lineDates[0],
          context: line.trim()
        });
        continue;
      }

      // Check Effective / Start Date context
      if (
        !effectiveDate &&
        /(?:effective\s*date|effective\s*from|valid\s*from|start\s*date|commencement\s*date|period\s*start|policy\s*start)/i.test(lineLower)
      ) {
        effectiveDate = firstDateIso;
        dateItems.push({
          value: firstDateIso,
          type: 'EFFECTIVE_DATE',
          sourceText: lineDates[0],
          context: line.trim()
        });
        continue;
      }

      // Check Issue / Drill Date context
      if (
        !issueDate &&
        /(?:issue\s*date|date\s*of\s*issue|issued\s*date|issued\s*on|drill\s*date|conducted\s*on|conducted\s*date|inspection\s*date|date\s*of\s*birth|dob|\bdated\b)/i.test(lineLower)
      ) {
        issueDate = firstDateIso;
        dateItems.push({
          value: firstDateIso,
          type: 'ISSUE_DATE',
          sourceText: lineDates[0],
          context: line.trim()
        });
        continue;
      }

      // Check Renewal Date context
      if (
        !renewalDate &&
        /(?:renewal\s*date|date\s*of\s*renewal|renewed\s*on|renewed\s*date)/i.test(lineLower)
      ) {
        renewalDate = firstDateIso;
        dateItems.push({
          value: firstDateIso,
          type: 'RENEWAL_DATE',
          sourceText: lineDates[0],
          context: line.trim()
        });
        continue;
      }

      // Check Audit Date context
      if (
        !auditDate &&
        /(?:audit\s*date|date\s*of\s*audit|audited\s*on|audited\s*date)/i.test(lineLower)
      ) {
        auditDate = firstDateIso;
        dateItems.push({
          value: firstDateIso,
          type: 'AUDIT_DATE',
          sourceText: lineDates[0],
          context: line.trim()
        });
        continue;
      }
    }

    // If issue date was not explicitly labeled, default to effectiveDate or first found date for general document timestamping
    if (!issueDate) {
      if (effectiveDate) {
        issueDate = effectiveDate;
      } else if (applicationDate) {
        issueDate = applicationDate;
      } else if (allDates.length > 0) {
        issueDate = allDates[0];
      }
    }

    // Populate remaining dates as UNKNOWN_DATE items
    for (const d of allDates) {
      if (!dateItems.some(item => item.value === d)) {
        dateItems.push({
          value: d,
          type: 'UNKNOWN_DATE',
          sourceText: d,
          context: 'Unlabeled date in document'
        });
      }
    }

    // NOTE: CRITICAL REMEDIATION 3 REQUIREMENT:
    // We strictly DO NOT fall back to assigning expiryDate = parsedDates[last].
    // If expiryDate was not explicitly identified from expiry context or date range, it remains undefined.

    return {
      issueDate,
      effectiveDate,
      expiryDate,
      reviewDate,
      applicationDate,
      renewalDate,
      auditDate,
      allDates,
      dateItems
    };
  }

  /**
   * Checks if an expiry date is strictly earlier than the target audit date.
   */
  public static isExpired(expiryDateIso: string, auditDateIso?: string): boolean {
    const exp = this.parseToIso(expiryDateIso);
    const audit = this.parseToIso(auditDateIso || '') || new Date().toISOString().split('T')[0];
    if (!exp || !audit) return false;
    return exp < audit;
  }

  /**
   * Checks if an event date is older than a specified number of days relative to the audit date.
   */
  public static isOlderThanDays(dateIso: string, auditDateIso?: string, maxDays: number = 365): boolean {
    const eventDate = this.parseToIso(dateIso);
    const auditDateStr = this.parseToIso(auditDateIso || '') || new Date().toISOString().split('T')[0];
    if (!eventDate || !auditDateStr) return false;

    const event = new Date(eventDate);
    const audit = new Date(auditDateStr);

    const diffMs = audit.getTime() - event.getTime();
    const msInDay = 24 * 60 * 60 * 1000;
    const diffDays = diffMs / msInDay;

    return diffDays > maxDays;
  }

  /**
   * Checks if a date is older than a specified number of years relative to the audit date.
   */
  public static isOlderThanYears(dateIso: string, auditDateIso?: string, years: number = 1): boolean {
    return this.isOlderThanDays(dateIso, auditDateIso, Math.round(years * 365.25));
  }
}
