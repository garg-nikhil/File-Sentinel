import fs from 'fs';

let content = fs.readFileSync('backend/audit/evaluator.ts', 'utf8');
content = `import { EvidenceAggregator } from './evidenceAggregator.js';\n` + content;

// Replace evaluateParameter core
const oldStart = `  public evaluateParameter(
    parameter: AuditParameter,
    evidenceItems: EvidenceItem[],
    auditDate: string = new Date().toISOString().split('T')[0]
  ): AuditParameterResult {
    // Sort evidence candidates by deterministic priority
    evidenceItems = [...evidenceItems].sort((a, b) => calculateEvidencePriority(b, parameter) - calculateEvidencePriority(a, parameter));`;

const newStart = `  public evaluateParameter(
    parameter: AuditParameter,
    evidenceItems: EvidenceItem[],
    auditDate: string = new Date().toISOString().split('T')[0]
  ): AuditParameterResult {
    // Sort evidence candidates by deterministic priority
    evidenceItems = [...evidenceItems].sort((a, b) => calculateEvidencePriority(b, parameter) - calculateEvidencePriority(a, parameter));
    
    const { evidenceSet, hasContradiction, hasValidated } = EvidenceAggregator.aggregate(parameter, evidenceItems);
`;

content = content.replace(oldStart, newStart);

content = content.replace(
  "evidence: evidenceItems,",
  "evidence: evidenceItems,\n        evidence_set: evidenceSet,"
);
// replace multiple occurrences
content = content.replace(/evidence: evidenceItems,/g, "evidence: evidenceItems,\n        evidence_set: evidenceSet,");

// Add contradiction check before default pass
const defaultPassCheck = `    // DEFAULT PASS STATUS
    const maxScore = this.calculateParameterMaxScore(parameter);`;

const contradictionCheck = `    if (hasContradiction) {
      const maxScore = this.calculateParameterMaxScore(parameter);
      return {
        parameter_id: parameter.id,
        parameter,
        status: 'REVIEW',
        confidence: 0.80,
        fatal: parameter.fatal,
        score_earned: 0,
        max_score: maxScore,
        evidence: evidenceItems,
        evidence_set: evidenceSet,
        reason: 'Conflicting operational evidence detected. Auditor review required.',
        missing_requirements: [],
        warnings: ['Contradictory evidence detected', ...warnings]
      };
    }

    // DEFAULT PASS STATUS
    const maxScore = this.calculateParameterMaxScore(parameter);`;

content = content.replace(defaultPassCheck, contradictionCheck);

fs.writeFileSync('backend/audit/evaluator.ts', content);
