import fs from 'fs';
let content = fs.readFileSync('backend/audit/compoundEvaluator.ts', 'utf8');

if (!content.includes("import { EvidenceAggregator }")) {
  content = "import { EvidenceAggregator } from './evidenceAggregator.js';\n" + content;
}

content = content.replace(
  `    return {
      parameter_id: parameter.id,
      parameter,
      status: finalStatus,
      confidence: Number((subResults.reduce((acc, r) => acc + r.confidence, 0) / subResults.length).toFixed(2)),
      fatal: parameter.fatal,
      score_earned: scoreEarned,
      max_score: maxScore,
      sub_control_statuses: subStatuses,
      sub_control_results: subResults,
      children: subResults,
      evidence: allEvidence,
      reason,
      missing_requirements: missingRequirements,
      warnings
    };`,
  `    const { evidenceSet } = EvidenceAggregator.aggregate(parameter, allEvidence);
    return {
      parameter_id: parameter.id,
      parameter,
      status: finalStatus,
      confidence: Number((subResults.reduce((acc, r) => acc + r.confidence, 0) / subResults.length).toFixed(2)),
      fatal: parameter.fatal,
      score_earned: scoreEarned,
      max_score: maxScore,
      sub_control_statuses: subStatuses,
      sub_control_results: subResults,
      children: subResults,
      evidence: allEvidence,
      evidence_set: evidenceSet,
      reason,
      missing_requirements: missingRequirements,
      warnings
    };`
);

fs.writeFileSync('backend/audit/compoundEvaluator.ts', content);
