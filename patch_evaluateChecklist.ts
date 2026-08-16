import fs from 'fs';

let content = fs.readFileSync('backend/audit/evidenceEngine.ts', 'utf8');

content = content.replace(
  "return this.evaluateChecklist(auditId, fileExtractions, activeChecklist, auditDate, agencyName, auditorName);",
  "return this.evaluateChecklist(auditId, fileExtractions, activeChecklist, auditDate, agencyName, auditorName, undefined, aiPrivacyMode);"
);

content = content.replace(
  "return this.evaluateChecklist(auditId, fileExtractions, activeChecklist, auditDate, agencyName, auditorName, scanId);",
  "return this.evaluateChecklist(auditId, fileExtractions, activeChecklist, auditDate, agencyName, auditorName, scanId);"
); // This one doesn't take aiPrivacyMode? We can default it to 'OFF'

content = content.replace(
  `  private async evaluateChecklist(
    auditId: string,
    fileExtractions: { fileId: string; filePath: string; extraction: any }[],
    activeChecklist: AuditParameter[],
    auditDate: string,
    agencyName: string,
    auditorName: string,
    scanId?: string
  ): Promise<AuditSession> {`,
  `  private async evaluateChecklist(
    auditId: string,
    fileExtractions: { fileId: string; filePath: string; extraction: any }[],
    activeChecklist: AuditParameter[],
    auditDate: string,
    agencyName: string,
    auditorName: string,
    scanId?: string,
    aiPrivacyMode: 'OFF' | 'REDACTED_SNIPPETS' | 'FULL_TEXT' = 'OFF'
  ): Promise<AuditSession> {`
);

fs.writeFileSync('backend/audit/evidenceEngine.ts', content);
