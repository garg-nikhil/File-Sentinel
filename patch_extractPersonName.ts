import fs from 'fs';

let content = fs.readFileSync('backend/audit/evidenceValidator.ts', 'utf8');

const oldMethod = `  private static extractPersonName(text: string): string | undefined {
    // 1. Labeled pattern on the same line: "Agent / Employee: John Smith", "Agent Name: JOHN SMITH", "Name: Jane Doe"
    const labeledMatch = text.match(/(?:Employee(?:\\s*Name)?|Agent(?:\\s*(?:\\/|\\&)\\s*Employee)?(?:\\s*Name)?|Staff(?:\\s*Name)?|Candidate(?:\\s*Name)?|Participant(?:\\s*Name)?|Director|VP|Name|User|Officer|Person|To certify that)[:,\\s]+([A-Za-z\\.\\'\\- ]{2,35})(?=[\\r\\n]|$)/i);
    if (labeledMatch) {
      const candidate = labeledMatch[1].trim();
      if (candidate.length >= 2 && !/(?:status|passed|completed|policy|procedure|training|date|active|valid)/i.test(candidate)) {
        return candidate;
      }
    }

    // 2. CSV table column match: e.g. "Participant_Name,..."
    const csvMatch = text.match(/(?:Participant_Name|Candidate_Name|Employee_Name)[^\\n\\r]*[\\n\\r]+(?:[^\\n\\r,]+,){3}([^\\n\\r,]+)/i);
    if (csvMatch) {
      const candidate = csvMatch[1].trim();
      if (candidate.length >= 2) return candidate;
    }

    // 3. Generic Two-Word or Three-Word Capitalized Name (Title Case or ALL CAPS)
    const titleCaseMatch = text.match(/\\b([A-Z][a-z]{1,15}\\s+(?:[A-Z]\\.?\\s+)?[A-Z][a-z]{1,15})\\b/);
    if (titleCaseMatch) {
      const candidate = titleCaseMatch[1].trim();
      // Ignore common title phrases
      if (!/(?:Debt Recovery|General Liability|Police Verification|Access Control|Code of|Fire Drill|Standard Operating|Operating Procedure|Banking Financial|Financial Education|Education Trust)/i.test(candidate)) {
        return candidate;
      }
    }

    const allCapsMatch = text.match(/\\b([A-Z]{2,15}\\s+(?:[A-Z]\\.?\\s+)?[A-Z]{2,15})\\b/);
    if (allCapsMatch) {
      const candidate = allCapsMatch[1].trim();
      if (!/(?:BANKING FINANCIAL|EDUCATION TRUST|GENERAL LIABILITY|POLICE DEPARTMENT|ACCESS CONTROL|CODE OF|FIRE DRILL|STANDARD OPERATING)/i.test(candidate)) {
        return candidate;
      }
    }

    return undefined;
  }`;

const newMethod = `  private static extractPersonName(text: string): string | undefined {
    // 1. Labeled pattern on the same line: "Agent / Employee: John Smith", "Agent Name: JOHN SMITH", "Name: Jane Doe"
    const labeledMatch = text.match(/(?:Employee(?:\\s*Name)?|Agent(?:\\s*(?:\\/|\\&)\\s*Employee)?(?:\\s*Name)?|Staff(?:\\s*Name)?|Candidate(?:\\s*Name)?|Participant(?:\\s*Name)?|Director|VP|Name|User|Officer|Person|To certify that)[:,\\s]+([A-Za-z\\.\\'\\- ]{2,35})(?=[\\r\\n]|$)/i);
    if (labeledMatch) {
      const candidate = labeledMatch[1].trim();
      if (candidate.length >= 2 && !/(?:status|passed|completed|policy|procedure|training|date|active|valid)/i.test(candidate)) {
        return candidate;
      }
    }

    // 2. CSV table column match: e.g. "Participant_Name,..."
    const csvMatch = text.match(/(?:Participant_Name|Candidate_Name|Employee_Name)[^\\n\\r]*[\\n\\r]+(?:[^\\n\\r,]+,){3}([^\\n\\r,]+)/i);
    if (csvMatch) {
      const candidate = csvMatch[1].trim();
      if (candidate.length >= 2) return candidate;
    }

    // 3. Generic Two-Word or Three-Word Capitalized Name (Title Case or ALL CAPS)
    const titleCaseMatch = text.match(/\\b([A-Z][a-z]{1,15}\\s+(?:[A-Z]\\.?\\s+)?[A-Z][a-z]{1,15})\\b/);
    if (titleCaseMatch) {
      const candidate = titleCaseMatch[1].trim();
      // Ignore common title phrases
      if (!/(?:Debt Recovery|General Liability|Police Verification|Access Control|Code of|Fire Drill|Standard Operating|Operating Procedure|Banking Financial|Financial Education|Education Trust|Alternative Control|Recovery Agent)/i.test(candidate)) {
        return candidate;
      }
    }

    const allCapsMatch = text.match(/\\b([A-Z]{2,15}\\s+(?:[A-Z]\\.?\\s+)?[A-Z]{2,15})\\b/);
    if (allCapsMatch) {
      const candidate = allCapsMatch[1].trim();
      if (!/(?:BANKING FINANCIAL|EDUCATION TRUST|GENERAL LIABILITY|POLICE DEPARTMENT|ACCESS CONTROL|CODE OF|FIRE DRILL|STANDARD OPERATING|ALTERNATIVE CONTROL|GPO NAME|USB BLOCK)/i.test(candidate)) {
        return candidate;
      }
    }

    return undefined;
  }`;

content = content.replace(oldMethod, newMethod);

fs.writeFileSync('backend/audit/evidenceValidator.ts', content);
