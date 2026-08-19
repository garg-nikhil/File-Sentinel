import fs from 'fs';

let content = fs.readFileSync('backend/audit/evaluator.ts', 'utf8');

// We need to pass evidenceSet down to evaluatePoliceVerification, evaluateAndSubControls, evaluateGroupSubControls
content = content.replace(
  "return this.evaluatePoliceVerification(parameter, evidenceItems, auditDate, warnings);",
  "return this.evaluatePoliceVerification(parameter, evidenceItems, auditDate, warnings, evidenceSet);"
);

content = content.replace(
  "return this.evaluateAndSubControls(parameter, evidenceItems, warnings);",
  "return this.evaluateAndSubControls(parameter, evidenceItems, warnings, evidenceSet);"
);

content = content.replace(
  "return this.evaluateGroupSubControls(parameter, evidenceItems, warnings);",
  "return this.evaluateGroupSubControls(parameter, evidenceItems, warnings, evidenceSet);"
);

content = content.replace(
  `  private evaluatePoliceVerification(
    parameter: AuditParameter,
    evidenceItems: EvidenceItem[],
    auditDate: string,
    warnings: string[]
  ): AuditParameterResult {`,
  `  private evaluatePoliceVerification(
    parameter: AuditParameter,
    evidenceItems: EvidenceItem[],
    auditDate: string,
    warnings: string[],
    evidenceSet?: any
  ): AuditParameterResult {`
);

content = content.replace(
  `  private evaluateAndSubControls(
    parameter: AuditParameter,
    evidenceItems: EvidenceItem[],
    warnings: string[]
  ): AuditParameterResult {`,
  `  private evaluateAndSubControls(
    parameter: AuditParameter,
    evidenceItems: EvidenceItem[],
    warnings: string[],
    evidenceSet?: any
  ): AuditParameterResult {`
);

content = content.replace(
  `  private evaluateGroupSubControls(
    parameter: AuditParameter,
    evidenceItems: EvidenceItem[],
    warnings: string[]
  ): AuditParameterResult {`,
  `  private evaluateGroupSubControls(
    parameter: AuditParameter,
    evidenceItems: EvidenceItem[],
    warnings: string[],
    evidenceSet?: any
  ): AuditParameterResult {`
);

content = content.replace(/evidence: evidenceItems,/g, "evidence: evidenceItems,\n      evidence_set: evidenceSet,");

fs.writeFileSync('backend/audit/evaluator.ts', content);
